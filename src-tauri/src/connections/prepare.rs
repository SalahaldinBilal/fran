use std::collections::HashMap;

use super::{SecretBag, resolve_secrets};
use crate::db::DriverOptions;
use crate::error::AppResult;
use crate::ssh::SshAccess;
use crate::ssh::known_hosts::KnownHosts;
use crate::ssh::route::{RoutePlan, SshRoute};
use crate::ssh_store::SshStore;
use crate::vault::Vault;
use crate::vpn::manager::{VpnLeg, VpnPlan};

/// The secrets, SSH route and VPN for one connect, resolved before the driver runs.
pub struct Prepared {
    pub secrets: SecretBag,
    pub route: Option<SshRoute>,
    /// Only for a direct TCP connection. A route carries its own.
    pub vpn: Option<VpnLeg>,
}

impl Prepared {
    pub fn access<'a>(&'a self, known_hosts: &'a KnownHosts) -> SshAccess<'a> {
        SshAccess { known_hosts, route: self.route.as_ref(), vpn: self.vpn.as_ref() }
    }
}

/// One prompt covers the database password, the VPN login and every hop of the route.
pub fn prepare_connect(
    driver: &DriverOptions,
    connection_id: Option<&str>,
    vpn_id: Option<&str>,
    provided: HashMap<String, String>,
    vault: &Vault,
    ssh_store: &SshStore,
) -> AppResult<Prepared> {
    let vpn_id = vpn_id.map(str::trim).filter(|id| !id.is_empty());
    let plan = match driver.ssh_target() {
        Some((ssh, _, _)) => Some(RoutePlan::for_options(ssh, ssh_store, vpn_id)?),
        None => None,
    };
    let direct_vpn = match (&plan, driver.network_target(), vpn_id) {
        (None, Some(_), Some(id)) => Some(VpnPlan::for_profile(id)?),
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

    let secrets = resolve_secrets(vault, connection_id, provided, &required, &optional)?;
    let route = match &plan {
        Some(plan) => Some(plan.resolve(&secrets, vault)?),
        None => None,
    };
    let vpn = direct_vpn.map(|plan| plan.resolve(&secrets));
    Ok(Prepared { secrets, route, vpn })
}
