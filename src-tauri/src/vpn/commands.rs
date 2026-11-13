use std::{collections::HashMap, sync::Arc};

use serde::Serialize;
use tauri::{State, ipc::Channel};
use zeroize::Zeroizing;

use vpn_proto::frames::Access;

use super::manager::{ComputerStart, SystemBackend, VpnManager, VpnPlan, VpnStatus};
use super::system::{
    self, OpenVpnProgram,
    setup::{self, Change, InstallHelp, ServiceStatus},
};
use crate::connections::{SecretBag, prepare::resolve_slots};
use crate::error::{AppError, AppResult};
use crate::secrets::fill::Filler;
use crate::ssh_store::SshStore;
use crate::vault::Vault;

fn planned(vault: &Vault, ssh_store: &SshStore, profile_id: &str, secrets: HashMap<String, String>) -> AppResult<(VpnPlan, SecretBag)> {
    let filler = Filler::new(vault, &secrets)?;
    let plan = VpnPlan::for_profile(profile_id, &filler)?;
    let bag = resolve_slots(&filler, vault, None, ssh_store, secrets, plan.login_slots(), Vec::new())?;
    Ok((plan, bag))
}

#[tauri::command]
pub async fn watch_vpn(manager: State<'_, Arc<VpnManager>>, channel: Channel<Vec<VpnStatus>>) -> AppResult<()> {
    manager.watch(channel);
    Ok(())
}

#[tauri::command]
pub async fn list_vpn_status(manager: State<'_, Arc<VpnManager>>) -> AppResult<Vec<VpnStatus>> {
    Ok(manager.statuses())
}

#[tauri::command]
pub async fn disconnect_vpn(manager: State<'_, Arc<VpnManager>>, profile_id: String) -> AppResult<()> {
    manager.disconnect(&profile_id).await;
    Ok(())
}

/// Logs in again even when an own tunnel is up, since the computer's VPN has its own session. `with` is the choice
/// for OpenVPN profiles in Settings > VPN. WireGuard always goes through Fran's service, and OpenVPN profiles Core
/// can't run always go to the installed OpenVPN. Fran's service not being set up is an error, never a quiet switch.
#[tauri::command]
pub async fn turn_on_vpn_system(
    manager: State<'_, Arc<VpnManager>>,
    vault: State<'_, Arc<Vault>>,
    ssh_store: State<'_, Arc<SshStore>>,
    profile_id: String,
    secrets: HashMap<String, String>,
    program: Option<String>,
    with: SystemBackend,
) -> AppResult<()> {
    let (plan, bag) = planned(&vault, &ssh_store, &profile_id, secrets)?;
    let leg = plan.resolve(&bag);
    let use_service = leg.is_wireguard() || (with == SystemBackend::Fran && !leg.needs_installed());
    if use_service && !setup::usable_service().await? {
        return Err(AppError::general(format!("Set up Fran's VPN service in Settings > VPN to turn VPN {} on for this computer", leg.label)));
    }
    let start = if use_service { ComputerStart::Fran(leg.service_start()?) } else { ComputerStart::Installed(leg.system_start(program)?) };
    manager.turn_on_system(&profile_id, start).await
}

#[tauri::command]
pub async fn vpn_service_status() -> AppResult<ServiceStatus> {
    Ok(setup::status().await)
}

/// Also updates a service that's already there, which restarts it, so VPNs on with it are turned off first.
/// Asks for admin rights once.
#[tauri::command]
pub async fn set_up_vpn_service(manager: State<'_, Arc<VpnManager>>, access: Access) -> AppResult<ServiceStatus> {
    manager.stop_backend(SystemBackend::Fran).await;
    setup::change(Change::Install(access)).await?;
    let status = setup::status().await;
    // It installs the fran-vpn next to Fran, so a mismatch here means that file is the old one.
    if matches!(status, ServiceStatus::NeedsUpdate { .. }) {
        return Err(AppError::general("The service was installed, but it still doesn't match this version of Fran. The fran-vpn file next to Fran is out of date."));
    }
    Ok(status)
}

#[tauri::command]
pub async fn set_vpn_service_access(access: Access) -> AppResult<ServiceStatus> {
    setup::change(Change::SetAccess(access)).await?;
    Ok(setup::status().await)
}

/// VPNs on with the service go down with it, so they're turned off first.
#[tauri::command]
pub async fn remove_vpn_service(manager: State<'_, Arc<VpnManager>>) -> AppResult<ServiceStatus> {
    manager.stop_backend(SystemBackend::Fran).await;
    setup::change(Change::Remove).await?;
    Ok(setup::status().await)
}

#[tauri::command]
pub async fn openvpn_install_help() -> AppResult<InstallHelp> {
    Ok(setup::install_help())
}

#[tauri::command]
pub async fn install_openvpn() -> AppResult<()> {
    setup::install_openvpn().await
}

/// Reopens the own tunnel with a new login, when the old one can't be used again (a one-time code).
#[tauri::command]
pub async fn open_vpn_tunnel(
    manager: State<'_, Arc<VpnManager>>,
    vault: State<'_, Arc<Vault>>,
    ssh_store: State<'_, Arc<SshStore>>,
    profile_id: String,
    secrets: HashMap<String, String>,
) -> AppResult<()> {
    let (plan, bag) = planned(&vault, &ssh_store, &profile_id, secrets)?;
    manager.open_own(&plan.resolve(&bag)).await
}

#[tauri::command]
pub async fn turn_off_vpn_system(manager: State<'_, Arc<VpnManager>>, profile_id: String) -> AppResult<()> {
    manager.turn_off_system(&profile_id).await;
    Ok(())
}

#[tauri::command]
pub async fn stop_system_vpns(manager: State<'_, Arc<VpnManager>>) -> AppResult<()> {
    manager.stop_systems().await;
    Ok(())
}

#[tauri::command]
pub async fn answer_vpn_prompt(manager: State<'_, Arc<VpnManager>>, profile_id: String, values: HashMap<String, String>) -> AppResult<()> {
    manager.answer_prompt(&profile_id, values.into_iter().map(|(slot, value)| (slot, Zeroizing::new(value))).collect())
}

#[cfg(windows)]
type ServiceCheck = system::win::ServiceCheck;
#[cfg(not(windows))]
type ServiceCheck = ();

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnCheck {
    pub program: Option<OpenVpnProgram>,
    pub problem: Option<String>,
    /// Windows only: the Interactive Service's program and admin group, and whether this sign-in is allowed.
    pub service: Option<ServiceCheck>,
}

#[tauri::command]
pub async fn check_openvpn(program: Option<String>) -> AppResult<OpenVpnCheck> {
    let (program, problem) = match system::find_program(program.as_deref()).await {
        Ok(program) => (Some(program), None),
        Err(error) => (None, Some(error.message)),
    };
    #[cfg(windows)]
    let service = Some(system::win::service_check().await);
    #[cfg(not(windows))]
    let service: Option<ServiceCheck> = None;
    Ok(OpenVpnCheck { program, problem, service })
}

#[tauri::command]
pub async fn set_vpn_options(manager: State<'_, Arc<VpnManager>>, idle_close_secs: u64, connect_timeout_secs: u64) -> AppResult<()> {
    manager.set_options(idle_close_secs, connect_timeout_secs);
    Ok(())
}
