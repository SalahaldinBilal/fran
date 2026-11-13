use std::collections::HashMap;

use super::{ConnectionProfile, SecretBag, SecretSlot, resolve_secrets};
use crate::error::{AppError, AppResult, ErrorDetail};
use crate::secrets::fill::{Filler, SlotSources, slot_sources};
use crate::secrets::SecretRefs;
use crate::ssh::SshAccess;
use crate::ssh::known_hosts::KnownHosts;
use crate::ssh::route::{RoutePlan, SshRoute};
use crate::ssh_store::SshStore;
use crate::vault::Vault;
use crate::vpn::manager::{VpnLeg, VpnPlan};
use crate::vpn_store::VpnFile;

/// The secrets, SSH route and VPN for one connect, resolved before the driver runs.
pub struct Prepared<'a> {
    /// The profile with its fields filled from secrets. It never leaves Rust.
    pub profile: ConnectionProfile,
    pub secrets: SecretBag,
    pub route: Option<SshRoute>,
    /// Only for a direct TCP connection. A route carries its own.
    pub vpn: Option<VpnLeg>,
    filler: Filler<'a>,
}

impl Prepared<'_> {
    pub fn access<'a>(&'a self, known_hosts: &'a KnownHosts) -> SshAccess<'a> {
        SshAccess { known_hosts, route: self.route.as_ref(), vpn: self.vpn.as_ref() }
    }

    pub fn scrub(&self, error: AppError) -> AppError {
        self.filler.scrub(error)
    }
}

/// Which secret each password slot uses, across the connection, the SSH store and the VPN store.
pub fn sources(connection: Option<(&str, &SecretRefs)>, ssh_store: &SshStore) -> AppResult<SlotSources> {
    let vpn = match crate::vpn::manager::manager() {
        Ok(manager) => manager.store().snapshot()?,
        Err(_) => VpnFile::default(),
    };
    Ok(slot_sources(connection, &ssh_store.snapshot()?, &vpn))
}

/// One prompt for every missing password and secret value. Every connect path calls it after its fills, before connecting.
pub fn resolve_slots(
    filler: &Filler,
    vault: &Vault,
    connection: Option<(&str, &SecretRefs)>,
    ssh_store: &SshStore,
    provided: HashMap<String, String>,
    mut required: Vec<SecretSlot>,
    mut optional: Vec<SecretSlot>,
) -> AppResult<SecretBag> {
    let sources = sources(connection, ssh_store)?;
    let connection_id = connection.map(|(id, _)| id).filter(|id| !id.is_empty());
    filler.redirect(&mut required, connection_id, &sources)?;
    filler.redirect(&mut optional, connection_id, &sources)?;
    let missing = filler.take_missing();
    match resolve_secrets(vault, connection_id, provided, &required, &optional) {
        Ok(_) if !missing.is_empty() => Err(AppError::secrets_required(missing)),
        Err(AppError { detail: ErrorDetail::SecretsRequired { slots }, .. }) if !missing.is_empty() => {
            let extra: Vec<SecretSlot> = slots.into_iter().filter(|slot| !missing.iter().any(|known| known.id == slot.id)).collect();
            Err(AppError::secrets_required(missing.into_iter().chain(extra).collect()))
        }
        other => other,
    }
}

/// One prompt covers the database password, the VPN login and every hop of the route.
pub fn prepare_connect<'a>(
    profile: &ConnectionProfile,
    provided: HashMap<String, String>,
    vault: &'a Vault,
    ssh_store: &SshStore,
) -> AppResult<Prepared<'a>> {
    let filler = Filler::new(vault, &provided)?;
    let filled = filler.fill(profile, &profile.live_refs(), &profile.name)?;
    let driver = &filled.driver;

    let vpn_id = filled.vpn_id.as_deref().map(str::trim).filter(|id| !id.is_empty());
    let plan = match driver.ssh_target() {
        Some((ssh, _, _)) => Some(RoutePlan::for_options(ssh, ssh_store, vpn_id, &filler)?),
        None => None,
    };
    let direct_vpn = match (&plan, driver.network_target(), vpn_id) {
        (None, Some(_), Some(id)) => Some(VpnPlan::for_profile(id, &filler)?),
        _ => None,
    };

    let mut required = driver.required_secrets();
    let mut optional = driver.optional_secrets();
    if let Some(plan) = &plan {
        required.extend(plan.required_secrets());
        optional.extend(plan.optional_secrets());
    }
    if let Some(vpn) = &direct_vpn {
        required.extend(vpn.required_secrets());
    }

    let secrets = resolve_slots(&filler, vault, Some((profile.id.as_str(), &profile.secret_refs)), ssh_store, provided, required, optional)?;
    let route = match &plan {
        Some(plan) => Some(plan.resolve(&secrets, vault)?),
        None => None,
    };
    let vpn = direct_vpn.map(|plan| plan.resolve(&secrets));
    Ok(Prepared { profile: filled, secrets, route, vpn, filler })
}
