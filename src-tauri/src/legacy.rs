use std::{fs, io, path::Path};

/// The app's identifier while it was called Fran DB. Its data folder and keychain entry carry this name.
pub const OLD_IDENTIFIER: &str = "com.frandb.app";

/// Copies Fran DB's data folder into a new install's empty one, so connections, settings and the vault come along.
/// The old folder is left as it was.
pub fn import_old_data(data_dir: &Path) -> io::Result<()> {
    let (Some(parent), Some(name)) = (data_dir.parent(), data_dir.file_name()) else {
        return Ok(());
    };
    let old = parent.join(OLD_IDENTIFIER);
    if data_dir.exists() || !old.is_dir() {
        return Ok(());
    }

    // Copied next to it first, so a failed copy never leaves a half-filled data folder.
    let staging = parent.join(format!("{}.importing", name.to_string_lossy()));
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    copy_dir(&old, &staging)?;
    fs::rename(&staging, data_dir)
}

fn copy_dir(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::{OLD_IDENTIFIER, import_old_data};

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn app_data_parent() -> TempDir {
        let dir = std::env::temp_dir().join(format!("fran-legacy-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(dir.join(OLD_IDENTIFIER).join("agent_history")).unwrap();
        fs::write(dir.join(OLD_IDENTIFIER).join("connections.json"), br#"{"profiles":[]}"#).unwrap();
        fs::write(dir.join(OLD_IDENTIFIER).join("secrets.vault"), b"FRDBVLT1 sealed").unwrap();
        fs::write(dir.join(OLD_IDENTIFIER).join("agent_history").join("2026-10-30.log"), b"day").unwrap();
        TempDir(dir)
    }

    #[test]
    fn a_new_install_gets_fran_db_data_and_its_folders() {
        let parent = app_data_parent();
        let data_dir = parent.0.join("com.fran.app");

        import_old_data(&data_dir).unwrap();

        assert_eq!(fs::read(data_dir.join("connections.json")).unwrap(), br#"{"profiles":[]}"#);
        assert_eq!(fs::read(data_dir.join("secrets.vault")).unwrap(), b"FRDBVLT1 sealed");
        assert_eq!(fs::read(data_dir.join("agent_history").join("2026-10-30.log")).unwrap(), b"day");
        assert!(parent.0.join(OLD_IDENTIFIER).join("secrets.vault").is_file());
    }

    #[test]
    fn data_already_there_is_never_replaced() {
        let parent = app_data_parent();
        let data_dir = parent.0.join("com.fran.app");
        fs::create_dir_all(&data_dir).unwrap();
        fs::write(data_dir.join("connections.json"), b"newer").unwrap();

        import_old_data(&data_dir).unwrap();

        assert_eq!(fs::read(data_dir.join("connections.json")).unwrap(), b"newer");
        assert!(!data_dir.join("secrets.vault").exists());
    }
}
