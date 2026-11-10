use std::sync::atomic::{AtomicBool, Ordering};

use serde::Deserialize;
use tauri::{
    AppHandle, Emitter, Manager, Window, Wry,
    image::Image,
    menu::{CheckMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
use tauri_plugin_notification::NotificationExt;

use crate::error::{AppError, AppResult};

const TRAY_ID: &str = "main";
const MAIN: &str = "main";

/// Closing the window hides it while this is on, so VPNs, forwards, terminals and the MCP server keep running.
#[derive(Default)]
pub struct TrayState {
    keep_in_tray: AtomicBool,
    notice_shown: AtomicBool,
    /// Set by Quit, so the close that follows really closes.
    quitting: AtomicBool,
    available: AtomicBool,
    badged: AtomicBool,
    /// The window has sent its settings, so it can confirm a quit. Until then closing just closes.
    ready: AtomicBool,
}

/// One entry of the tray menu, sent by the frontend, which knows what's running.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrayItem {
    pub id: String,
    pub label: String,
    /// A check item when set.
    #[serde(default)]
    pub checked: Option<bool>,
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub separator_before: bool,
}

fn enabled() -> bool {
    true
}

fn tauri_error(error: tauri::Error) -> AppError {
    AppError::general(error.to_string())
}

pub fn show_main(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
    if let Some(main) = app.get_webview_window(MAIN) {
        let _ = main.unminimize();
        let _ = main.show();
        let _ = main.set_focus();
    }
}

fn menu_event(app: &AppHandle, id: &str) {
    match id {
        "open" => show_main(app),
        "lock" => {
            let _ = app.emit("tray-lock", ());
        }
        // These ask or confirm in the window, so it comes up first.
        "quit" => {
            show_main(app);
            let _ = app.emit("quit-requested", ());
        }
        _ => {
            if let Some(profile_id) = id.strip_prefix("vpn:") {
                show_main(app);
                let _ = app.emit("tray-vpn", profile_id);
            } else if let Some(rule_id) = id.strip_prefix("forward:") {
                let _ = app.emit("tray-forward-stop", rule_id);
            }
        }
    }
}

fn build_menu(app: &AppHandle, items: &[TrayItem]) -> tauri::Result<Menu<Wry>> {
    let mut owned: Vec<Box<dyn IsMenuItem<Wry>>> = vec![
        Box::new(MenuItem::with_id(app, "open", "Open Fran", true, None::<&str>)?),
        Box::new(PredefinedMenuItem::separator(app)?),
    ];
    for item in items {
        if item.separator_before {
            owned.push(Box::new(PredefinedMenuItem::separator(app)?));
        }
        match item.checked {
            Some(checked) => owned.push(Box::new(CheckMenuItem::with_id(app, item.id.clone(), &item.label, item.enabled, checked, None::<&str>)?)),
            None => owned.push(Box::new(MenuItem::with_id(app, item.id.clone(), &item.label, item.enabled, None::<&str>)?)),
        }
    }
    if !items.is_empty() {
        owned.push(Box::new(PredefinedMenuItem::separator(app)?));
    }
    owned.push(Box::new(MenuItem::with_id(app, "quit", "Quit Fran", true, None::<&str>)?));
    let refs: Vec<&dyn IsMenuItem<Wry>> = owned.iter().map(|item| item.as_ref()).collect();
    Menu::with_items(app, &refs)
}

/// The app icon with a green dot, for while a VPN is on for the computer.
fn badged(icon: &Image<'_>) -> Image<'static> {
    let (width, height) = (icon.width(), icon.height());
    let mut rgba = icon.rgba().to_vec();
    let radius = width.min(height) as f32 * 0.22;
    let (center_x, center_y) = (width as f32 - radius - 1.0, height as f32 - radius - 1.0);
    for y in 0..height {
        for x in 0..width {
            let distance = ((x as f32 + 0.5 - center_x).powi(2) + (y as f32 + 0.5 - center_y).powi(2)).sqrt();
            let color = if distance <= radius {
                [34, 197, 94, 255]
            } else if distance <= radius + 1.5 {
                [14, 15, 18, 255]
            } else {
                continue;
            };
            let at = ((y * width + x) * 4) as usize;
            rgba[at..at + 4].copy_from_slice(&color);
        }
    }
    Image::new_owned(rgba, width, height)
}

/// Desktops without a tray (some GNOME setups without the extension) fail here, and closing the window then quits.
pub fn setup(app: &AppHandle) {
    let Some(icon) = app.default_window_icon().cloned() else {
        return;
    };
    let built = build_menu(app, &[]).and_then(|menu| {
        TrayIconBuilder::with_id(TRAY_ID)
            .icon(icon)
            .tooltip("Fran")
            .menu(&menu)
            .show_menu_on_left_click(false)
            .on_menu_event(|app, event| menu_event(app, event.id().as_ref()))
            .on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                    show_main(tray.app_handle());
                }
            })
            .build(app)
    });
    app.state::<TrayState>().available.store(built.is_ok(), Ordering::SeqCst);
}

/// Hides the main window instead of closing it while the tray setting is on. Otherwise the window confirms
/// what stops before Fran quits.
pub fn on_close_requested(window: &Window, api: &tauri::CloseRequestApi) {
    let app = window.app_handle();
    let state = app.state::<TrayState>();
    if state.quitting.load(Ordering::SeqCst) || !state.ready.load(Ordering::SeqCst) {
        return;
    }
    api.prevent_close();
    if !state.keep_in_tray.load(Ordering::SeqCst) || !state.available.load(Ordering::SeqCst) {
        let _ = app.emit("quit-requested", ());
        return;
    }
    let _ = window.hide();
    // The Dock icon goes away with the window and comes back in show_main.
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);
    if !state.notice_shown.swap(true, Ordering::SeqCst) {
        let _ = app.notification().builder().title("Fran").body("Fran is still running in the tray. Quit it from the tray icon.").show();
        let _ = app.emit("tray-notice-shown", ());
    }
}

#[tauri::command]
pub fn set_tray_options(state: tauri::State<'_, TrayState>, keep_in_tray: bool, notice_shown: bool) {
    state.keep_in_tray.store(keep_in_tray, Ordering::SeqCst);
    state.notice_shown.store(notice_shown, Ordering::SeqCst);
    state.ready.store(true, Ordering::SeqCst);
}

#[tauri::command]
pub fn tray_available(state: tauri::State<'_, TrayState>) -> bool {
    state.available.load(Ordering::SeqCst)
}

/// The menu and tooltip, rebuilt by the frontend whenever what's running changes.
#[tauri::command]
pub fn set_tray_menu(app: AppHandle, state: tauri::State<'_, TrayState>, items: Vec<TrayItem>, tooltip: String, vpn_on: bool) -> AppResult<()> {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return Ok(());
    };
    tray.set_menu(Some(build_menu(&app, &items).map_err(tauri_error)?)).map_err(tauri_error)?;
    tray.set_tooltip(Some(tooltip)).map_err(tauri_error)?;
    if state.badged.swap(vpn_on, Ordering::SeqCst) != vpn_on {
        if let Some(icon) = app.default_window_icon() {
            let icon = if vpn_on { badged(icon) } else { Image::new_owned(icon.rgba().to_vec(), icon.width(), icon.height()) };
            tray.set_icon(Some(icon)).map_err(tauri_error)?;
        }
    }
    Ok(())
}

/// The real quit, after the window confirmed what stops.
#[tauri::command]
pub fn quit_app(app: AppHandle, state: tauri::State<'_, TrayState>) {
    state.quitting.store(true, Ordering::SeqCst);
    app.exit(0);
}
