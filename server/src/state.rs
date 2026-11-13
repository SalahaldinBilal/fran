use std::ops::Deref;
use std::sync::{Arc, Mutex, RwLock};

use tokio::sync::{Semaphore, broadcast};

use crate::config::Config;
use crate::crypto;
use crate::db::{Db, now};
use crate::settings::{self, Effective};

const MAX_HASHES_AT_ONCE: usize = 4;

#[derive(Debug, Clone)]
pub enum Notice {
    Changed { user_id: Arc<str>, cursor: u64 },
    // Sessions of this account were removed, open sockets check theirs again.
    SessionsChanged { user_id: Arc<str> },
}

pub struct Inner {
    pub db: Db,
    pub config: Config,
    pub instance_id: String,
    pub started_at: i64,
    pub notices: broadcast::Sender<Notice>,
    pub hashing: Semaphore,
    settings: RwLock<Effective>,
    /// Only while nobody owns the server. Kept in memory, so each start makes a new one.
    setup_code: Mutex<Option<String>>,
}

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

impl Deref for AppState {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, String> {
        let db = Db::connect(&config.database_url).await?;
        let instance_id = db.instance_id().await.map_err(|error| format!("Can't read the server's id: {error}"))?;
        let saved = db.saved_settings().await.map_err(|error| format!("Can't read the server's settings: {error}"))?;
        let owned = db.has_owner().await.map_err(|error| format!("Can't read the accounts: {error}"))?;
        let (notices, _) = broadcast::channel(1024);
        Ok(Self(Arc::new(Inner {
            settings: RwLock::new(settings::effective(&config, &saved)),
            setup_code: Mutex::new((!owned).then(crypto::setup_code)),
            db,
            config,
            instance_id,
            started_at: now(),
            notices,
            hashing: Semaphore::new(MAX_HASHES_AT_ONCE),
        })))
    }

    pub fn sessions_changed(&self, user_id: &str) {
        let _ = self.notices.send(Notice::SessionsChanged { user_id: user_id.into() });
    }

    pub fn settings(&self) -> Effective {
        *self.settings.read().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub async fn reload_settings(&self) -> sqlx::Result<()> {
        let saved = self.db.saved_settings().await?;
        *self.settings.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = settings::effective(&self.config, &saved);
        Ok(())
    }

    pub fn setup_code(&self) -> Option<String> {
        self.setup_code.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    pub fn drop_setup_code(&self) {
        *self.setup_code.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}
