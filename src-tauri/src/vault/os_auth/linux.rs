// polkit, so the desktop shows its own password dialog. Without it, Fran's own GTK dialog checked through PAM.

use std::{
    collections::HashMap,
    io::Write,
    path::Path,
    process::{Command, Stdio},
    sync::{OnceLock, mpsc},
    time::Duration,
};

use tauri::WebviewWindow;
use zbus::zvariant::Value;
use zeroize::Zeroizing;

use super::{Outcome, cancelled, failed};
use crate::error::{AppError, AppResult, ErrorDetail};

const ACTION: &str = "com.fran.app.reveal-secret";
const POLICY: &str = include_str!("../../../linux/com.fran.app.policy");
const POLICY_PATH: &str = "/usr/share/polkit-1/actions/com.fran.app.policy";
const MAX_TRIES: usize = 3;
// NixOS keeps setuid helpers in /run/wrappers.
const CHKPWD: &[&str] = &["/run/wrappers/bin/unix_chkpwd", "/usr/sbin/unix_chkpwd", "/sbin/unix_chkpwd", "/usr/bin/unix_chkpwd"];
const PKEXEC: &[&str] = &["/run/wrappers/bin/pkexec", "/usr/bin/pkexec", "/bin/pkexec"];
const TEE: &[&str] = &["/usr/bin/tee", "/bin/tee"];

fn first_existing(paths: &[&'static str]) -> Option<&'static str> {
    paths.iter().copied().find(|path| Path::new(path).exists())
}

fn current_user() -> AppResult<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .map_err(|_| AppError::general("Fran couldn't tell which user you are"))
}

/// Asks the system's own password helper, which PAM's failed-login counting doesn't see.
/// Accounts it can't read (LDAP, SSSD, systemd-homed) count as having a password.
fn no_password(user: &str) -> bool {
    static EMPTY: OnceLock<bool> = OnceLock::new();
    *EMPTY.get_or_init(|| {
        let Some(helper) = first_existing(CHKPWD) else {
            return false;
        };
        let Ok(mut child) = Command::new(helper).args([user, "nullok"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() else {
            return false;
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(b"\0");
        }
        child.wait().is_ok_and(|status| status.success())
    })
}

pub fn unprotected() -> bool {
    current_user().is_ok_and(|user| no_password(&user))
}

fn start_time() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    // Field 22 counted from the start, the comm field in brackets can hold spaces.
    stat.rsplit_once(')').and_then(|(_, rest)| rest.split_whitespace().nth(19)).and_then(|value| value.parse().ok()).unwrap_or(0)
}

enum Polkit {
    Authorized,
    Dismissed,
    NoAgent,
    Denied,
    NotRegistered,
    Unreachable,
}

fn ask_polkit() -> Polkit {
    let Ok(connection) = zbus::blocking::Connection::system() else {
        return Polkit::Unreachable;
    };
    let mut subject: HashMap<&str, Value> = HashMap::new();
    subject.insert("pid", Value::U32(std::process::id()));
    subject.insert("start-time", Value::U64(start_time()));
    let details: HashMap<&str, &str> = HashMap::new();
    let reply = connection.call_method(
        Some("org.freedesktop.PolicyKit1"),
        "/org/freedesktop/PolicyKit1/Authority",
        Some("org.freedesktop.PolicyKit1.Authority"),
        "CheckAuthorization",
        &(("unix-process", subject), ACTION, details, 1u32, ""),
    );
    let message = match reply {
        Ok(message) => message,
        Err(error) if error.to_string().contains("not registered") => return Polkit::NotRegistered,
        Err(_) => return Polkit::Unreachable,
    };
    match message.body().deserialize::<(bool, bool, HashMap<String, String>)>() {
        Ok((true, _, _)) => Polkit::Authorized,
        Ok((false, _, details)) if details.get("polkit.dismissed").is_some_and(|value| value == "true") => Polkit::Dismissed,
        // pkexec reads a challenge left unanswered as "no authentication agent", so this does too.
        Ok((false, true, _)) => Polkit::NoAgent,
        Ok((false, false, _)) => Polkit::Denied,
        Err(_) => Polkit::Unreachable,
    }
}

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> AppResult<T> {
    tauri::async_runtime::spawn_blocking(work).await.map_err(|error| AppError::general(error.to_string()))
}

pub async fn confirm(window: &WebviewWindow, reason: &str, password_dialog: bool) -> AppResult<Outcome> {
    let user = current_user()?;
    let probe = user.clone();
    if blocking(move || no_password(&probe)).await? {
        return Ok(Outcome::NoProtection);
    }
    if !password_dialog {
        match blocking(ask_polkit).await? {
            Polkit::Authorized => return Ok(Outcome::Confirmed),
            Polkit::Dismissed => return Err(cancelled()),
            Polkit::Denied => return Err(failed()),
            Polkit::NotRegistered => {
                return Err(AppError::new(
                    "Fran has to be registered with your system once to ask who you are",
                    ErrorDetail::OsAuthSetup { can_install: first_existing(PKEXEC).is_some() && first_existing(TEE).is_some() },
                ));
            }
            Polkit::NoAgent | Polkit::Unreachable => {}
        }
    }
    password_check(window.clone(), reason.to_string(), user).await
}

async fn password_check(window: WebviewWindow, reason: String, user: String) -> AppResult<Outcome> {
    let mut wrong = false;
    for _ in 0..MAX_TRIES {
        let asking = window.clone();
        let text = reason.clone();
        let Some(password) = blocking(move || ask_password(&asking, &text, wrong)).await?? else {
            return Err(cancelled());
        };
        let name = user.clone();
        if blocking(move || pam_check(&name, &password)).await? {
            return Ok(Outcome::Confirmed);
        }
        wrong = true;
    }
    Err(failed())
}

// libpam's own API, declared here so the build doesn't need bindgen and libclang.
mod pam {
    use std::ffi::{CStr, CString, c_char, c_int, c_void};

    const PAM_SUCCESS: c_int = 0;
    const PAM_BUF_ERR: c_int = 5;
    const PAM_CONV_ERR: c_int = 19;
    const PAM_PROMPT_ECHO_OFF: c_int = 1;
    const PAM_PROMPT_ECHO_ON: c_int = 2;

    #[repr(C)]
    struct Message {
        style: c_int,
        text: *const c_char,
    }

    #[repr(C)]
    struct Response {
        resp: *mut c_char,
        retcode: c_int,
    }

    #[repr(C)]
    struct Conversation {
        conv: unsafe extern "C" fn(c_int, *mut *const Message, *mut *mut Response, *mut c_void) -> c_int,
        data: *mut c_void,
    }

    struct Answers {
        user: CString,
        password: CString,
    }

    #[link(name = "pam")]
    unsafe extern "C" {
        fn pam_start(service: *const c_char, user: *const c_char, conversation: *const Conversation, handle: *mut *mut c_void) -> c_int;
        fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
        fn pam_acct_mgmt(handle: *mut c_void, flags: c_int) -> c_int;
        fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
    }

    unsafe extern "C" {
        fn calloc(count: usize, size: usize) -> *mut c_void;
        fn strdup(text: *const c_char) -> *mut c_char;
    }

    // PAM frees the responses itself, so they come from malloc.
    unsafe extern "C" fn converse(count: c_int, messages: *mut *const Message, responses: *mut *mut Response, data: *mut c_void) -> c_int {
        if count <= 0 || messages.is_null() || responses.is_null() || data.is_null() {
            return PAM_CONV_ERR;
        }
        let answers = unsafe { &*(data as *const Answers) };
        let replies = unsafe { calloc(count as usize, std::mem::size_of::<Response>()) } as *mut Response;
        if replies.is_null() {
            return PAM_BUF_ERR;
        }
        for index in 0..count as usize {
            let message = unsafe { &**messages.add(index) };
            let text: Option<&CStr> = match message.style {
                PAM_PROMPT_ECHO_OFF => Some(&answers.password),
                PAM_PROMPT_ECHO_ON => Some(&answers.user),
                _ => None,
            };
            if let Some(text) = text {
                unsafe { (*replies.add(index)).resp = strdup(text.as_ptr()) };
            }
        }
        unsafe { *responses = replies };
        PAM_SUCCESS
    }

    pub fn authenticate(service: &str, user: &str, password: &str) -> bool {
        let (Ok(service), Ok(user), Ok(password)) = (CString::new(service), CString::new(user), CString::new(password)) else {
            return false;
        };
        let answers = Answers { user: user.clone(), password };
        let conversation = Conversation { conv: converse, data: &answers as *const Answers as *mut c_void };
        let mut handle: *mut c_void = std::ptr::null_mut();
        if unsafe { pam_start(service.as_ptr(), user.as_ptr(), &conversation, &mut handle) } != PAM_SUCCESS {
            return false;
        }
        let mut status = unsafe { pam_authenticate(handle, 0) };
        if status == PAM_SUCCESS {
            status = unsafe { pam_acct_mgmt(handle, 0) };
        }
        unsafe { pam_end(handle, status) };
        let mut bytes = answers.password.into_bytes();
        zeroize::Zeroize::zeroize(&mut bytes);
        status == PAM_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    // Needs a real account: FRAN_PAM_USER and FRAN_PAM_PASSWORD, run with --ignored.
    #[test]
    #[ignore = "needs a Linux account set up for it"]
    fn pam_accepts_the_right_password_only() {
        let user = std::env::var("FRAN_PAM_USER").unwrap();
        let password = std::env::var("FRAN_PAM_PASSWORD").unwrap();
        assert!(super::pam_check(&user, &password));
        assert!(!super::pam_check(&user, "not the password"));
        assert!(!super::pam_check("no-such-user-here", &password));
    }
}

fn pam_check(user: &str, password: &str) -> bool {
    let service = if Path::new("/etc/pam.d/polkit-1").exists() || Path::new("/usr/lib/pam.d/polkit-1").exists() { "polkit-1" } else { "login" };
    pam::authenticate(service, user, password)
}

/// A native GTK dialog on the main thread, so the password never reaches the webview.
fn ask_password(window: &WebviewWindow, reason: &str, wrong: bool) -> AppResult<Option<Zeroizing<String>>> {
    let (sender, answer) = mpsc::channel();
    let parent_window = window.clone();
    let reason = reason.to_string();
    window
        .run_on_main_thread(move || {
            use gtk::prelude::*;
            let parent = parent_window.gtk_window().ok();
            let dialog = gtk::Dialog::with_buttons(
                Some("Fran"),
                parent.as_ref(),
                gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
                &[("Cancel", gtk::ResponseType::Cancel), ("Confirm", gtk::ResponseType::Accept)],
            );
            dialog.set_default_response(gtk::ResponseType::Accept);
            let area = dialog.content_area();
            area.set_spacing(8);
            area.set_border_width(16);
            let title = gtk::Label::new(Some(&reason));
            title.set_line_wrap(true);
            title.set_xalign(0.0);
            let hint_text = if wrong { "That password isn't right. Try again." } else { "Enter the password you sign in to this computer with." };
            let hint = gtk::Label::new(Some(hint_text));
            hint.set_xalign(0.0);
            let entry = gtk::Entry::new();
            entry.set_visibility(false);
            entry.set_input_purpose(gtk::InputPurpose::Password);
            entry.set_activates_default(true);
            area.add(&title);
            area.add(&hint);
            area.add(&entry);
            dialog.show_all();
            let response = dialog.run();
            let password = (response == gtk::ResponseType::Accept).then(|| Zeroizing::new(entry.text().to_string()));
            entry.set_text("");
            unsafe { dialog.destroy() };
            let _ = sender.send(password);
        })
        .map_err(|error| AppError::general(error.to_string()))?;
    answer.recv().map_err(|_| cancelled())
}

/// Writes the policy file as root through pkexec. The text comes from Fran's memory, not a file another program could swap.
pub fn install() -> AppResult<()> {
    let pkexec = first_existing(PKEXEC).ok_or_else(|| AppError::general("pkexec isn't installed"))?;
    let tee = first_existing(TEE).ok_or_else(|| AppError::general("tee isn't installed"))?;
    let mut child = Command::new(pkexec)
        .args([tee, POLICY_PATH])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| AppError::general(format!("pkexec didn't start: {error}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(POLICY.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    match output.status.code() {
        Some(0) => {
            // polkit notices new actions on its own, give it a moment.
            std::thread::sleep(Duration::from_secs(1));
            Ok(())
        }
        Some(126) => Err(cancelled()),
        _ => Err(AppError::general(format!(
            "The setup didn't work: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))),
    }
}
