#[cfg(target_os = "macos")]
use std::path::PathBuf;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use crate::error::AppResult;

/// The installed OpenVPN, started with admin rights. It connects to Fran's management port and quits when that closes.
pub struct Process {
    ended: Arc<Mutex<Option<String>>>,
    #[cfg(windows)]
    pub pid: u32,
    #[cfg(target_os = "linux")]
    child: tokio::process::Child,
    #[cfg(target_os = "macos")]
    log: PathBuf,
}

fn set(slot: &Mutex<Option<String>>, text: String) {
    if let Ok(mut slot) = slot.lock() {
        *slot = Some(text);
    }
}

/// The last line of what OpenVPN printed, for when it ends before the management connection says why.
#[cfg(target_os = "macos")]
fn last_line(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().map(str::trim).filter(|line| !line.is_empty()).last().map(str::to_string)
}

impl Process {
    /// Why OpenVPN ended, once that's known.
    pub fn ended(&mut self) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            let Ok(Some(status)) = self.child.try_wait() else {
                return None;
            };
            return Some(match status.code() {
                Some(126) => "The admin password prompt was cancelled".to_string(),
                Some(127) => "Your account isn't allowed to run OpenVPN as admin".to_string(),
                _ => self.ended.lock().ok().and_then(|slot| slot.clone()).unwrap_or_else(|| format!("OpenVPN stopped ({status})")),
            });
        }
        #[cfg(not(target_os = "linux"))]
        self.ended.lock().ok().and_then(|slot| slot.clone())
    }

    /// What OpenVPN printed last, on macOS where it runs in the background.
    pub fn last_output(&self) -> Option<String> {
        #[cfg(target_os = "macos")]
        return last_line(&self.log);
        #[cfg(target_os = "linux")]
        return self.ended.lock().ok().and_then(|slot| slot.clone());
        #[cfg(windows)]
        None
    }

    /// Only works where OpenVPN runs as this user (Windows). Elsewhere it runs as root and quits when Fran's management port closes.
    pub fn kill(&mut self) {
        #[cfg(windows)]
        windows_service::terminate(self.pid);
    }
}

/// `management` is what follows `--management`: Fran's port on Windows, its Unix socket elsewhere.
pub async fn start(program: &Path, dir: &Path, config: &Path, management: &[String]) -> AppResult<Process> {
    let mut args: Vec<String> = vec!["--config".to_string(), config.to_string_lossy().to_string(), "--management".to_string()];
    args.extend(management.iter().cloned());
    args.extend(
        [
        "--management-client",
        "--management-hold",
        "--management-query-passwords",
        "--auth-retry",
        "interact",
        "--verb",
        "3",
        ]
        .iter()
        .map(|arg| arg.to_string()),
    );
    let ended = Arc::new(Mutex::new(None));

    #[cfg(windows)]
    {
        let _ = program;
        let pid = windows_service::start(dir, &args, ended.clone()).await?;
        Ok(Process { ended, pid })
    }
    #[cfg(target_os = "linux")]
    {
        let child = linux::start(program, dir, &args, ended.clone())?;
        Ok(Process { ended, child })
    }
    #[cfg(target_os = "macos")]
    {
        let log = dir.join("openvpn.log");
        macos::start(program, &args, &log).await?;
        Ok(Process { ended, log })
    }
}

#[cfg(windows)]
pub mod windows_service {
    use std::{
        path::Path,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, PipeMode};
    use windows::Win32::{
        Foundation::CloseHandle,
        System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess},
    };

    use crate::error::{AppError, AppResult};

    const PIPE: &str = r"\\.\pipe\openvpn\service";
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PIPE_BUSY: i32 = 231;

    async fn open() -> AppResult<NamedPipeClient> {
        let started = Instant::now();
        loop {
            match ClientOptions::new().pipe_mode(PipeMode::Message).open(PIPE) {
                Ok(pipe) => return Ok(pipe),
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) && started.elapsed() < Duration::from_secs(3) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                    return Err(AppError::general(
                        "The OpenVPN Interactive Service isn't running. It comes with OpenVPN: start it in Services, or reinstall OpenVPN with it.",
                    ));
                }
                Err(error) => return Err(AppError::general(format!("Couldn't reach the OpenVPN Interactive Service: {error}"))),
            }
        }
    }

    async fn read_message(pipe: &mut NamedPipeClient) -> std::io::Result<Option<String>> {
        let mut buf = vec![0u8; 8192];
        let read = pipe.read(&mut buf).await?;
        if read == 0 {
            return Ok(None);
        }
        let units: Vec<u16> = buf[..read].chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        Ok(Some(String::from_utf16_lossy(&units)))
    }

    /// How `CommandLineToArgvW` reads it back.
    pub fn quote_arg(arg: &str) -> String {
        if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
            return arg.to_string();
        }
        let mut out = String::from("\"");
        let mut slashes = 0;
        for character in arg.chars() {
            match character {
                '\\' => slashes += 1,
                '"' => {
                    out.push_str(&"\\".repeat(slashes * 2 + 1));
                    out.push('"');
                    slashes = 0;
                }
                other => {
                    out.push_str(&"\\".repeat(slashes));
                    slashes = 0;
                    out.push(other);
                }
            }
        }
        out.push_str(&"\\".repeat(slashes * 2));
        out.push('"');
        out
    }

    fn reply_error(lines: &[&str]) -> AppError {
        let text: Vec<&str> = lines.iter().skip(1).map(|line| line.trim()).filter(|line| !line.is_empty()).collect();
        let mut message = format!("The OpenVPN service didn't start OpenVPN: {}", text.join(". "));
        if message.contains("group") {
            message.push_str(". Sign out of Windows and back in after adding your account.");
        }
        AppError::general(message)
    }

    /// Asks the service to start OpenVPN as this user. It replies with the process id, and later with an error if OpenVPN fails.
    pub async fn start(dir: &Path, args: &[String], ended: Arc<Mutex<Option<String>>>) -> AppResult<u32> {
        let mut pipe = open().await?;
        let options = args.iter().map(|arg| quote_arg(arg)).collect::<Vec<_>>().join(" ");
        let text = format!("{}\0{options}\0\0", dir.display());
        let message: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        pipe.write_all(&message).await?;

        let reply = read_message(&mut pipe).await?.ok_or_else(|| AppError::general("The OpenVPN service closed the connection"))?;
        let lines: Vec<&str> = reply.split('\n').collect();
        let hex = |line: &str| u32::from_str_radix(line.trim().trim_start_matches("0x"), 16).ok();
        if lines.first().and_then(|line| hex(line)) != Some(0) {
            return Err(reply_error(&lines));
        }
        let pid = lines.get(1).and_then(|line| hex(line)).ok_or_else(|| AppError::general("The OpenVPN service sent no process id"))?;

        tokio::spawn(async move {
            if let Ok(Some(later)) = read_message(&mut pipe).await {
                let lines: Vec<&str> = later.split('\n').collect();
                super::set(&ended, reply_error(&lines).message);
            }
        });
        Ok(pid)
    }

    pub fn terminate(pid: u32) {
        // The service gives this user PROCESS_TERMINATE on the OpenVPN it started.
        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                let _ = TerminateProcess(handle, 1);
                let _ = CloseHandle(handle);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::quote_arg;

        #[test]
        fn arguments_survive_command_line_parsing() {
            assert_eq!(quote_arg("--config"), "--config");
            assert_eq!(quote_arg(r"C:\Users\A B\fran\profile.ovpn"), r#""C:\Users\A B\fran\profile.ovpn""#);
            assert_eq!(quote_arg(r"C:\dir with space\"), r#""C:\dir with space\\""#);
            assert_eq!(quote_arg(""), "\"\"");
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        path::Path,
        process::Stdio,
        sync::{Arc, Mutex},
    };

    use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

    use crate::error::{AppError, AppResult};

    fn keep_last_line<R: AsyncRead + Unpin + Send + 'static>(reader: R, ended: Arc<Mutex<Option<String>>>) {
        tokio::spawn(async move {
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim().to_string();
                if !line.is_empty() {
                    super::set(&ended, line);
                }
            }
        });
    }

    /// `/proc/self` belongs to the effective user.
    fn running_as_root() -> bool {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self").is_ok_and(|meta| meta.uid() == 0)
    }

    /// pkexec asks for the admin password through the desktop's polkit agent, once per start. Fran running as root
    /// already (a container, a root session) starts OpenVPN itself.
    pub fn start(program: &Path, dir: &Path, args: &[String], ended: Arc<Mutex<Option<String>>>) -> AppResult<tokio::process::Child> {
        let mut command = if running_as_root() {
            tokio::process::Command::new(program)
        } else {
            let mut command = tokio::process::Command::new("pkexec");
            command.arg(program);
            command
        };
        let mut child = command
            .args(args)
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| AppError::general(format!("Fran needs pkexec (polkit) to run OpenVPN as admin: {error}")))?;
        if let Some(stdout) = child.stdout.take() {
            keep_last_line(stdout, ended.clone());
        }
        if let Some(stderr) = child.stderr.take() {
            keep_last_line(stderr, ended);
        }
        Ok(child)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::path::Path;

    use crate::error::{AppError, AppResult};

    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    fn applescript_string(value: &str) -> String {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }

    /// Asks for the admin password once per start. OpenVPN goes to the background, printing to a file Fran created,
    /// so osascript returns and Fran can still read why it stopped.
    pub async fn start(program: &Path, args: &[String], log: &Path) -> AppResult<()> {
        super::super::write_private(log, b"")?;
        let mut parts = vec![shell_quote(&program.to_string_lossy())];
        parts.extend(args.iter().map(|arg| shell_quote(arg)));
        let line = format!("{} >> {} 2>&1 < /dev/null &", parts.join(" "), shell_quote(&log.to_string_lossy()));
        let script = format!("do shell script {} with administrator privileges", applescript_string(&line));
        let output = tokio::process::Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(script)
            .output()
            .await
            .map_err(|error| AppError::general(format!("Couldn't ask for the admin password: {error}")))?;
        if output.status.success() {
            return Ok(());
        }
        let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if error.contains("-128") {
            return Err(AppError::general("The admin password prompt was cancelled"));
        }
        Err(AppError::general(format!("OpenVPN didn't start: {error}")))
    }
}
