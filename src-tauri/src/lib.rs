pub mod agent;
pub mod connections;
pub mod daylog;
pub mod db;
pub mod error;
pub mod forward;
pub mod json_store;
pub mod kube;
pub mod legacy;
pub mod saved_queries;
pub mod secrets;
pub mod settings;
pub mod snippets;
pub mod splash;
pub mod ssh;
pub mod ssh_store;
pub mod tab_state;
pub mod tray;
pub mod vault;
pub mod vpn;
pub mod vpn_store;

use std::sync::Arc;

use tauri::{Manager, RunEvent};

use agent::{AgentHost, CloseReason};
use connections::ConnectionStore;
use db::sessions::SessionManager;
use saved_queries::SavedQueryStore;
use settings::SettingsStore;
use snippets::SnippetStore;
use tab_state::TabStateStore;
use ssh::{
    forwards::{PortForwards, RuleForwards},
    known_hosts::KnownHosts,
    sftp::SftpManager,
    terminal::TerminalManager,
    terminal_log::TerminalLogs,
};
use ssh_store::SshStore;
use vault::Vault;
use vpn::manager::VpnManager;
use vpn_store::VpnStore;

pub fn run() {
    // Before the windows exist: on Linux the webview keeps its data in this same folder, so it would create it first.
    legacy::import_on_first_start();

    let app = tauri::Builder::default()
        // Has to be the first plugin, so a second launch exits before anything else starts.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| splash::bring_to_front(app)))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    tray::on_close_requested(window, api);
                }
            }
        })
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;

            let vault = Arc::new(Vault::new(data_dir.join("secrets.vault")));
            let store = Arc::new(ConnectionStore::load(data_dir.join("connections.json")));
            let known_hosts = Arc::new(KnownHosts::load(data_dir.join("known_hosts.json")));
            let ssh_store = Arc::new(SshStore::load(data_dir.join("ssh.json")));
            let vpn_store = Arc::new(VpnStore::load(data_dir.join("vpn.json")));
            let secrets_store = Arc::new(secrets::SecretsStore::load(data_dir.join("secrets.json")));
            secrets::install(secrets_store.clone());
            app.manage(secrets_store);
            let vpn_manager = VpnManager::new(vpn_store.clone(), vault.clone());
            vpn::manager::install(vpn_manager.clone());
            let agent = Arc::new(AgentHost::new(
                Arc::new(app.handle().clone()),
                data_dir.clone(),
                store.clone(),
                vault.clone(),
                known_hosts.clone(),
                ssh_store.clone(),
            ));

            app.manage(vault);
            app.manage(store);
            app.manage(known_hosts);
            app.manage(ssh_store);
            app.manage(vpn_store);
            app.manage(vpn_manager);
            app.manage(Arc::new(vault::reveal::RevealSession::default()));
            app.manage(Arc::new(SavedQueryStore::load(data_dir.join("saved_queries.json"))));
            app.manage(Arc::new(TabStateStore::load(data_dir.join("tab_state.json"))));
            app.manage(Arc::new(SettingsStore::load(data_dir.join("settings.json"))));
            app.manage(Arc::new(SnippetStore::load(data_dir.join("snippets.json"))));
            app.manage(SessionManager::default());
            app.manage(PortForwards::default());
            app.manage(RuleForwards::default());
            app.manage(Arc::new(TerminalManager::default()));
            app.manage(Arc::new(SftpManager::default()));
            app.manage(Arc::new(TerminalLogs::new(data_dir.join("terminal_logs"))));
            app.manage(agent.clone());
            app.manage(tray::TrayState::default());
            tray::setup(app.handle());

            agent.start_maintenance();
            tauri::async_runtime::spawn(async move { agent.apply().await });
            splash::open(app.handle())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault::commands::get_vault_status,
            vault::commands::reset_vault,
            vault::commands::enable_app_lock,
            vault::commands::disable_app_lock,
            vault::commands::change_app_lock_password,
            vault::commands::lock_app,
            vault::commands::unlock_app,
            vault::reveal::list_saved_secrets,
            vault::reveal::reveal_secret,
            vault::reveal::copy_secret,
            vault::reveal::install_os_auth,
            vault::reveal::get_os_auth_status,
            vault::reveal::unlock_secrets,
            vault::reveal::lock_secrets,
            vault::reveal::get_secrets_unlock,
            vault::reveal::reveal_all_secrets,
            secrets::commands::list_secrets,
            secrets::commands::save_secret,
            secrets::commands::delete_secret,
            connections::commands::list_connections,
            connections::commands::save_connection,
            connections::commands::save_connection_order,
            connections::commands::rename_group,
            connections::commands::duplicate_connection,
            connections::commands::delete_connection,
            connections::commands::get_stored_secrets,
            connections::commands::set_connection_secret,
            connections::commands::clear_connection_secret,
            connections::commands::get_owner_secrets,
            connections::commands::set_owner_secret,
            connections::commands::clear_owner_secret,
            ssh::known_hosts::trust_host_key,
            ssh::known_hosts::replace_host_key,
            ssh::known_hosts::list_known_hosts,
            ssh::known_hosts::forget_known_host,
            ssh_store::commands::list_ssh,
            ssh_store::commands::save_ssh_host,
            ssh_store::commands::save_ssh_host_order,
            ssh_store::commands::move_ssh_host,
            ssh_store::commands::rename_ssh_group,
            ssh_store::commands::delete_ssh_host,
            ssh_store::commands::save_identity,
            ssh_store::commands::delete_identity,
            ssh_store::commands::save_proxy,
            ssh_store::commands::delete_proxy,
            ssh_store::commands::generate_key,
            ssh_store::commands::import_key,
            ssh_store::commands::import_key_text,
            ssh_store::commands::rename_key,
            ssh_store::commands::export_key,
            ssh_store::commands::delete_key,
            ssh_store::commands::preview_ssh_config_import,
            ssh_store::commands::import_ssh_config,
            ssh::forwards::start_port_forward,
            ssh::forwards::stop_port_forward,
            ssh::forwards::list_port_forwards,
            ssh::forwards::save_forward_rule,
            ssh::forwards::delete_forward_rule,
            ssh::forwards::start_forward_rule,
            ssh::forwards::stop_forward_rule,
            ssh::forwards::list_running_forward_rules,
            ssh::terminal::open_terminal,
            ssh::terminal::open_terminal_pane,
            ssh::terminal::terminal_input,
            ssh::terminal::terminal_resize,
            ssh::terminal::close_terminal,
            ssh::terminal::terminal_type_password,
            ssh::terminal::open_link,
            ssh::terminal_log::list_terminal_logs,
            ssh::terminal_log::get_terminal_log,
            ssh::terminal_log::get_terminal_log_size,
            ssh::terminal_log::clear_terminal_logs,
            ssh::terminal_log::prune_terminal_logs,
            ssh::sftp::sftp_open,
            ssh::sftp::sftp_close,
            ssh::sftp::sftp_list,
            ssh::sftp::sftp_stat,
            ssh::sftp::sftp_mkdir,
            ssh::sftp::sftp_rename,
            ssh::sftp::sftp_remove,
            ssh::sftp::sftp_count,
            ssh::sftp::sftp_chmod,
            ssh::sftp::sftp_preview,
            ssh::sftp::sftp_transfer,
            ssh::sftp::sftp_answer_conflict,
            ssh::sftp::cancel_transfer,
            ssh::sftp::local::local_list,
            ssh::sftp::local::local_roots,
            ssh::sftp::local::local_mkdir,
            ssh::sftp::local::local_rename,
            ssh::sftp::local::local_remove,
            ssh::sftp::local::local_count,
            vpn_store::commands::list_vpn,
            vpn_store::commands::describe_vpn_certificates,
            vpn_store::commands::save_vpn_profile,
            vpn_store::commands::set_vpn_key,
            vpn_store::commands::clear_vpn_key,
            vpn_store::commands::set_vpn_tls_key,
            vpn_store::commands::set_vpn_wireguard_key,
            vpn_store::commands::generate_vpn_wireguard_key,
            vpn_store::commands::set_vpn_preshared_key,
            vpn_store::commands::delete_vpn_profile,
            vpn_store::commands::save_vpn_order,
            vpn_store::commands::move_vpn_profile,
            vpn_store::commands::rename_vpn_group,
            vpn_store::commands::import_vpn_file,
            vpn_store::commands::export_vpn_profile,
            vpn::commands::watch_vpn,
            vpn::commands::list_vpn_status,
            vpn::commands::disconnect_vpn,
            vpn::commands::turn_on_vpn_system,
            vpn::commands::turn_off_vpn_system,
            vpn::commands::open_vpn_tunnel,
            vpn::commands::stop_system_vpns,
            vpn::commands::check_openvpn,
            vpn::commands::answer_vpn_prompt,
            vpn::commands::set_vpn_options,
            vpn::commands::vpn_service_status,
            vpn::commands::set_up_vpn_service,
            vpn::commands::set_vpn_service_access,
            vpn::commands::remove_vpn_service,
            vpn::commands::openvpn_install_help,
            vpn::commands::install_openvpn,
            snippets::list_snippets,
            snippets::save_snippet,
            snippets::delete_snippet,
            kube::list_kube_contexts,
            db::commands::open_session,
            db::commands::test_connection,
            db::commands::close_session,
            db::commands::list_catalogs,
            db::commands::switch_catalog,
            db::commands::list_databases,
            db::commands::get_database_sizes,
            db::commands::list_objects,
            db::commands::get_object_structure,
            db::commands::get_primary_key,
            db::commands::get_column_choices,
            db::commands::open_query_context,
            db::commands::close_query_context,
            db::commands::execute_query,
            db::commands::cancel_query,
            db::commands::split_sql,
            db::commands::list_columns,
            db::commands::get_object_sql,
            db::commands::get_database_sql,
            db::commands::preview_row_changes,
            db::commands::get_insert_sql,
            db::commands::execute_batch,
            db::commands::get_table_design,
            db::commands::get_design_options,
            db::commands::preview_table_design,
            db::commands::get_query_history,
            db::commands::get_running_queries,
            saved_queries::list_saved_queries,
            saved_queries::save_query,
            saved_queries::delete_saved_query,
            tab_state::get_tab_state,
            tab_state::set_tab_state,
            settings::get_settings,
            settings::set_settings,
            splash::show_main_window,
            tray::set_tray_options,
            tray::tray_available,
            tray::set_tray_menu,
            tray::quit_app,
            agent::commands::get_agent_config,
            agent::commands::set_agent_config,
            agent::commands::get_agent_status,
            agent::commands::list_agent_sessions,
            agent::commands::close_agent_session,
            agent::commands::close_all_agent_sessions,
            agent::commands::list_agent_approvals,
            agent::commands::answer_agent_request,
            agent::commands::list_agent_history,
            agent::commands::get_agent_history_entry,
            agent::commands::get_agent_history_size,
            agent::commands::clear_agent_history,
        ])
        .build(tauri::generate_context!())
        .expect("error while building the app");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            app_handle.state::<Arc<SftpManager>>().close_all();
            app_handle.state::<Arc<TerminalManager>>().close_all();
            app_handle.state::<RuleForwards>().stop_all();
            app_handle.state::<PortForwards>().stop_all();
            let sessions = app_handle.state::<SessionManager>().drain();
            let agent = app_handle.state::<Arc<AgentHost>>().inner().clone();
            let vpn = app_handle.state::<Arc<VpnManager>>().inner().clone();
            tauri::async_runtime::block_on(async move {
                for open in sessions {
                    open.session.close().await;
                }
                agent.close_all(CloseReason::AppExit).await;
                vpn.stop_all().await;
            });
        }
    });
}
