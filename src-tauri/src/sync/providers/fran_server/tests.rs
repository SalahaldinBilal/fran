//! The provider against the real `fran-sync-server` binary. Build it first with `cargo build` in `server/`.
//! Without the binary (or `FRAN_SYNC_SERVER_BIN`) each test prints "skipped" and passes.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::client::Client;
use super::{Account, Session, data_key, recover, sign_in, sign_up, this_device};
use crate::connections::ConnectionProfile;
use crate::error::ErrorDetail;
use crate::sync::engine::Engine;
use crate::sync::providers::{CloudKind, opener};
use crate::sync::state::{Category, SyncStore, Target};
use crate::sync::tests::{Quiet, new_folder};

const PASSWORD: &str = "correct horse battery staple";

struct Server {
    child: Child,
    url: String,
    dir: PathBuf,
    /// What the server wrote to stderr, where it prints the setup code.
    log: Arc<Mutex<String>>,
}

impl Server {
    fn setup_code(&self) -> String {
        let log = self.log.lock().unwrap();
        let code = log.split("setup code: ").nth(1).expect("the server printed a setup code");
        code.split_whitespace().next().unwrap().to_string()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn binary() -> Option<PathBuf> {
    let name = if cfg!(windows) { "fran-sync-server.exe" } else { "fran-sync-server" };
    let built = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../server/target/debug").join(name);
    let path = std::env::var_os("FRAN_SYNC_SERVER_BIN").map(PathBuf::from).unwrap_or(built);
    if path.is_file() {
        return Some(path);
    }
    eprintln!("skipped: no fran-sync-server binary at {}", path.display());
    None
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn start() -> Option<Server> {
    start_with("open").await
}

async fn start_with(signup: &str) -> Option<Server> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let binary = binary()?;
    let dir = std::env::temp_dir().join(format!("fran-sync-server-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let port = free_port();
    let mut child = Command::new(binary)
        .current_dir(&dir)
        .env("SERVER_KEY", "5a".repeat(32))
        .env("BIND", format!("127.0.0.1:{port}"))
        .env("DATABASE_URL", "sqlite:test.db")
        .env("SIGNUP", signup)
        .env_remove("FRAN_SYNC_CONFIG")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let log = Arc::new(Mutex::new(String::new()));
    let stderr = child.stderr.take().unwrap();
    let written = log.clone();
    std::thread::spawn(move || {
        for line in std::io::BufRead::lines(std::io::BufReader::new(stderr)).map_while(Result::ok) {
            written.lock().unwrap().push_str(&format!("{line}\n"));
        }
    });
    let server = Server { child, url: format!("http://127.0.0.1:{port}"), dir, log };
    let client = Client::new(&server.url).unwrap();
    for _ in 0..200 {
        if client.info().await.is_ok() {
            return Some(server);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the sync server didn't start");
}

/// Passes every connection on to the server and keeps what the app sent.
async fn recording_proxy(server_url: &str) -> (String, Arc<Mutex<Vec<u8>>>) {
    let upstream = server_url.trim_start_matches("http://").to_string();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let sent = Arc::new(Mutex::new(Vec::new()));
    let log = sent.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let Ok(server) = TcpStream::connect(&upstream).await else {
                continue;
            };
            let (mut from_client, mut to_client) = client.into_split();
            let (mut from_server, mut to_server) = server.into_split();
            let log = log.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16 * 1024];
                while let Ok(read) = from_client.read(&mut buffer).await {
                    if read == 0 || to_server.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                    log.lock().unwrap().extend_from_slice(&buffer[..read]);
                }
            });
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut from_server, &mut to_client).await;
            });
        }
    });
    (url, sent)
}

struct Computer {
    dir: PathBuf,
    engine: Arc<Engine>,
}

impl Drop for Computer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Computer {
    fn new() -> Self {
        let (dir, stores) = new_folder();
        let (vault, secrets) = (stores.vault.clone(), stores.secrets.clone());
        let engine = Engine::new(stores, Arc::new(SyncStore::load(dir.join("sync.json"))), opener(vault, secrets), Arc::new(Quiet));
        Self { dir, engine }
    }

    async fn join(&self, session: Session) -> String {
        let vault = self.engine.stores().vault.clone();
        let config = serde_json::to_value(&session.config).unwrap();
        self.engine.register_cloud(CloudKind::FranServer, "Cloud", session.config.identity(), config, |id| session.save(id, &vault)).await.unwrap()
    }

    async fn sync_connections_and_passwords_to(&self, cloud_id: &str) {
        self.engine.set_category_route(Category::Connections, Some(Target::Cloud(cloud_id.to_string()))).await.unwrap();
        self.engine.set_category_route(Category::Passwords, Some(Target::WithItem)).await.unwrap();
    }

    async fn save_connection(&self, id: &str, name: &str, password: &str) {
        let profile: ConnectionProfile =
            serde_json::from_value(json!({ "id": id, "name": name, "kind": "sqlite", "options": { "path": format!("/srv/{name}.db") } })).unwrap();
        let stores = self.engine.stores();
        stores
            .connections
            .update(|file| {
                file.connections.retain(|existing| existing.id != id);
                file.connections.push(profile);
                Ok(())
            })
            .unwrap();
        stores.vault.set(&format!("connection:{id}:password"), password).unwrap();
        self.engine.mark_dirty().await.unwrap();
    }

    fn connection_name(&self, id: &str) -> Option<String> {
        let found = self.engine.stores().connections.read(|file| file.connections.iter().find(|profile| profile.id == id).map(|profile| profile.name.clone()));
        found.unwrap()
    }

    fn password(&self, id: &str) -> Option<String> {
        self.engine.stores().vault.get(&format!("connection:{id}:password")).unwrap().map(|value| value.to_string())
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_owner_claims_a_new_server_from_the_app_and_manages_an_account() {
    let Some(server) = start_with("invite").await else { return };
    let laptop = Computer::new();
    let code = server.setup_code();
    // The printed code doubles as the first invite, since an invite-only server has no other way in yet.
    let owner_cloud = laptop.join(sign_up(&server.url, "owner@example.com", PASSWORD, Some(code.clone()), this_device("Laptop")).await.unwrap().session).await;
    let owner = Account::open(&laptop.engine.cloud(&owner_cloud).unwrap(), &laptop.engine.stores().vault).unwrap();
    assert_eq!(owner.client.account(&owner.token).await.unwrap().role, sync_proto::Role::Owner);
    assert!(owner.client.info().await.unwrap().owned);
    assert!(owner.client.claim(&owner.token, &code).await.is_err());

    let invite = owner.client.admin_create_invite(&owner.token, &sync_proto::CreateInvite { email: String::new(), expires_in_days: 7 }).await.unwrap();
    let grace = sign_up(&server.url, "grace@example.com", PASSWORD, Some(invite.code.clone()), this_device("Grace's PC")).await.unwrap();
    let invites = owner.client.admin_invites(&owner.token).await.unwrap();
    assert_eq!(invites.iter().find(|listed| listed.id == invite.invite.id).unwrap().used_by, "grace@example.com");

    let users = owner.client.admin_users(&owner.token, "grace", 0, 50).await.unwrap();
    let grace_id = users.users[0].id.clone();
    assert_eq!(grace_id, grace.session.config.account_id);
    owner.client.admin_set_quota(&owner.token, &grace_id, 4 * 1024 * 1024).await.unwrap();
    assert_eq!(owner.client.admin_user(&owner.token, &grace_id).await.unwrap().user.own_quota_bytes, 4 * 1024 * 1024);

    assert!(owner.client.admin_delete_user(&owner.token, &grace_id, &sync_proto::DeleteAccount { auth_key: owner.auth_key("not the password").await.unwrap() }).await.is_err());
    let auth_key = owner.auth_key(PASSWORD).await.unwrap();
    owner.client.admin_delete_user(&owner.token, &grace_id, &sync_proto::DeleteAccount { auth_key }).await.unwrap();
    assert_eq!(owner.client.admin_overview(&owner.token).await.unwrap().accounts, 1);
    let actions: Vec<String> = owner.client.admin_log(&owner.token).await.unwrap().into_iter().map(|entry| entry.action).collect();
    assert_eq!(actions, ["deleteUser", "quota", "inviteCreate", "claim"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_computer_signs_in_and_gets_what_the_first_one_saved() {
    let Some(server) = start().await else { return };
    let laptop = Computer::new();
    let signed_up = sign_up(&server.url, "Ada@Example.com ", PASSWORD, None, this_device("Laptop")).await.unwrap();
    let laptop_cloud = laptop.join(signed_up.session).await;
    laptop.sync_connections_and_passwords_to(&laptop_cloud).await;
    laptop.save_connection("c1", "Prod", "hunter2-prod").await;
    laptop.engine.sync_all().await.unwrap();

    assert!(sign_in(&server.url, "ada@example.com", "not the password", None, this_device("Desktop")).await.is_err());
    let desktop = Computer::new();
    let desktop_cloud = desktop.join(sign_in(&server.url, "ada@example.com", PASSWORD, None, this_device("Desktop")).await.unwrap()).await;
    desktop.engine.sync_all().await.unwrap();
    assert_eq!(desktop.connection_name("c1").as_deref(), Some("Prod"));
    assert_eq!(desktop.password("c1").as_deref(), Some("hunter2-prod"));
    // Both computers have to mean the same cloud when synced data names it.
    assert_eq!(laptop.engine.cloud(&laptop_cloud).unwrap().identity, desktop.engine.cloud(&desktop_cloud).unwrap().identity);

    // The laptop hears about the desktop's edit over the live connection, without polling.
    let stores = laptop.engine.stores();
    let provider = opener(stores.vault.clone(), stores.secrets.clone())(&laptop.engine.cloud(&laptop_cloud).unwrap()).unwrap();
    let mut events = provider.watch().await.expect("the live connection");
    tokio::time::timeout(Duration::from_secs(5), events.recv()).await.expect("the cursor sent on connect");
    desktop.save_connection("c1", "Prod (EU)", "hunter2-prod").await;
    desktop.engine.sync_all().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), events.recv()).await.expect("a notice after the desktop's push").unwrap();
    laptop.engine.sync_all().await.unwrap();
    assert_eq!(laptop.connection_name("c1").as_deref(), Some("Prod (EU)"));

    // A device signed out from another one stops syncing and says why.
    let account = Account::open(&laptop.engine.cloud(&laptop_cloud).unwrap(), &laptop.engine.stores().vault).unwrap();
    let devices = account.client.sessions(&account.token).await.unwrap();
    assert_eq!(devices.len(), 2);
    let other = devices.iter().find(|device| !device.current).unwrap();
    assert_eq!(other.device.name, "Desktop");
    account.client.revoke(&account.token, &other.id).await.unwrap();
    let refused = desktop.engine.sync_all().await.unwrap_err();
    assert!(matches!(refused.detail, ErrorDetail::SyncSignedOut), "{refused:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_readable_reaches_the_server() {
    let Some(server) = start().await else { return };
    let (proxy_url, sent) = recording_proxy(&server.url).await;
    let laptop = Computer::new();
    let signed_up = sign_up(&proxy_url, "ada@example.com", PASSWORD, None, this_device("Laptop")).await.unwrap();
    let recovery_key = signed_up.recovery_key.to_string();
    let cloud_id = laptop.join(signed_up.session).await;
    laptop.sync_connections_and_passwords_to(&cloud_id).await;
    laptop.save_connection("c1-item-id", "prod-db-internal", "hunter2-prod-pw").await;
    laptop.engine.sync_all().await.unwrap();
    laptop.save_connection("c1-item-id", "prod-db-renamed", "hunter2-prod-pw").await;
    laptop.engine.sync_all().await.unwrap();

    let sent = sent.lock().unwrap().clone();
    assert!(contains(&sent, b"POST /v1/records"), "the proxy didn't see the push");
    assert!(contains(&sent, b"authKey"), "the proxy didn't see the sign-up");

    let key = data_key(&cloud_id, &laptop.engine.stores().vault).unwrap();
    let key_base64 = serde_json::to_string(&sync_proto::Bytes::from(key.to_vec())).unwrap();
    let key_hex = hex::encode(key.as_slice());
    let secrets: [(&str, &[u8]); 10] = [
        ("the password", PASSWORD.as_bytes()),
        ("the recovery key", recovery_key.as_bytes()),
        ("the data key", key.as_slice()),
        ("the data key as hex", key_hex.as_bytes()),
        ("the data key as base64", key_base64.trim_matches('"').as_bytes()),
        ("a connection's name", b"prod-db-internal"),
        ("a connection's new name", b"prod-db-renamed"),
        ("a connection's id", b"c1-item-id"),
        ("a saved password", b"hunter2-prod-pw"),
        ("the kind of an item", b"connection:"),
    ];
    for (what, bytes) in secrets {
        assert!(!contains(&sent, bytes), "{what} was sent to the server");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_recovery_key_gets_back_in_and_the_old_password_stops_working() {
    let Some(server) = start().await else { return };
    let laptop = Computer::new();
    let signed_up = sign_up(&server.url, "ada@example.com", PASSWORD, None, this_device("Laptop")).await.unwrap();
    let recovery_key = signed_up.recovery_key.to_string();
    let laptop_cloud = laptop.join(signed_up.session).await;
    laptop.sync_connections_and_passwords_to(&laptop_cloud).await;
    laptop.save_connection("c1", "Prod", "hunter2-prod").await;
    laptop.engine.sync_all().await.unwrap();

    assert!(recover(&server.url, "ada@example.com", "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA", "a brand new password", this_device("New laptop")).await.is_err());
    let new_laptop = Computer::new();
    let typed = recovery_key.to_lowercase().replace('-', " ");
    let session = recover(&server.url, "ada@example.com", &typed, "a brand new password", this_device("New laptop")).await.unwrap();
    new_laptop.join(session).await;
    new_laptop.engine.sync_all().await.unwrap();
    assert_eq!(new_laptop.connection_name("c1").as_deref(), Some("Prod"));
    assert_eq!(new_laptop.password("c1").as_deref(), Some("hunter2-prod"));

    assert!(sign_in(&server.url, "ada@example.com", PASSWORD, None, this_device("Thief")).await.is_err());
    assert!(sign_in(&server.url, "ada@example.com", "a brand new password", None, this_device("Desktop")).await.is_ok());
    // Recovery signs every other device out.
    let refused = laptop.engine.sync_all().await.unwrap_err();
    assert!(matches!(refused.detail, ErrorDetail::SyncSignedOut), "{refused:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_keeps_the_data_and_a_new_recovery_key_replaces_the_old_one() {
    let Some(server) = start().await else { return };
    let laptop = Computer::new();
    let signed_up = sign_up(&server.url, "ada@example.com", PASSWORD, None, this_device("Laptop")).await.unwrap();
    let old_recovery_key = signed_up.recovery_key.to_string();
    let laptop_cloud = laptop.join(signed_up.session).await;
    laptop.sync_connections_and_passwords_to(&laptop_cloud).await;
    laptop.save_connection("c1", "Prod", "hunter2-prod").await;
    laptop.engine.sync_all().await.unwrap();

    let account = Account::open(&laptop.engine.cloud(&laptop_cloud).unwrap(), &laptop.engine.stores().vault).unwrap();
    assert!(account.change_password("not the password", "the second password").await.is_err());
    account.change_password(PASSWORD, "the second password").await.unwrap();
    laptop.save_connection("c1", "Prod after the change", "hunter2-prod").await;
    laptop.engine.sync_all().await.unwrap();

    assert!(sign_in(&server.url, "ada@example.com", PASSWORD, None, this_device("Desktop")).await.is_err());
    let desktop = Computer::new();
    desktop.join(sign_in(&server.url, "ada@example.com", "the second password", None, this_device("Desktop")).await.unwrap()).await;
    desktop.engine.sync_all().await.unwrap();
    assert_eq!(desktop.connection_name("c1").as_deref(), Some("Prod after the change"));

    let new_recovery_key = account.new_recovery_key("the second password").await.unwrap().to_string();
    assert_ne!(new_recovery_key, old_recovery_key);
    assert!(recover(&server.url, "ada@example.com", &old_recovery_key, "the third password", this_device("Thief")).await.is_err());
    let recovered = Computer::new();
    recovered.join(recover(&server.url, "ada@example.com", &new_recovery_key, "the third password", this_device("Tablet")).await.unwrap()).await;
    recovered.engine.sync_all().await.unwrap();
    assert_eq!(recovered.connection_name("c1").as_deref(), Some("Prod after the change"));
}

#[tokio::test(flavor = "multi_thread")]
async fn two_accounts_on_one_server_are_two_clouds_that_never_mix() {
    let Some(server) = start().await else { return };
    let laptop = Computer::new();
    let personal = laptop.join(sign_up(&server.url, "ada@example.com", PASSWORD, None, this_device("Laptop")).await.unwrap().session).await;
    let work = laptop.join(sign_up(&server.url, "ada@work.example", PASSWORD, None, this_device("Laptop")).await.unwrap().session).await;
    assert_ne!(personal, work);
    laptop.engine.set_category_route(Category::Connections, Some(Target::Cloud(personal.clone()))).await.unwrap();
    laptop.save_connection("blog", "Blog", "blog-password").await;
    laptop.save_connection("erp", "ERP", "erp-password").await;
    laptop.engine.set_item_routes(vec!["connection:erp".into()], Some(Target::Cloud(work.clone()))).await.unwrap();
    laptop.engine.mark_dirty().await.unwrap();
    laptop.engine.sync_all().await.unwrap();

    let home_pc = Computer::new();
    home_pc.join(sign_in(&server.url, "ada@example.com", PASSWORD, None, this_device("Home PC")).await.unwrap()).await;
    home_pc.engine.sync_all().await.unwrap();
    assert_eq!(home_pc.connection_name("blog").as_deref(), Some("Blog"));
    assert_eq!(home_pc.connection_name("erp"), None);

    let office_pc = Computer::new();
    office_pc.join(sign_in(&server.url, "ada@work.example", PASSWORD, None, this_device("Office PC")).await.unwrap()).await;
    office_pc.engine.sync_all().await.unwrap();
    assert_eq!(office_pc.connection_name("erp").as_deref(), Some("ERP"));
    assert_eq!(office_pc.connection_name("blog"), None);

    // Moving the blog to the work account: the home PC isn't signed in there, so it keeps a local copy.
    laptop.engine.set_item_routes(vec!["connection:blog".into()], Some(Target::Cloud(work))).await.unwrap();
    laptop.engine.mark_dirty().await.unwrap();
    laptop.engine.sync_all().await.unwrap();
    office_pc.engine.sync_all().await.unwrap();
    home_pc.engine.sync_all().await.unwrap();
    assert_eq!(office_pc.connection_name("blog").as_deref(), Some("Blog"));
    assert_eq!(home_pc.connection_name("blog").as_deref(), Some("Blog"));
    assert!(home_pc.engine.view().unwrap().moved.contains_key("connection:blog"));
}
