use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};

use super::engine::{Engine, Events, ProblemReason};
use super::items::{Stores, is_order};
use super::shared_routes::is_routes;
use super::providers::{CloudKind, Incoming, Opener, Outgoing, Provider, Pulled, Pushed};
use super::state::{Category, ReplacedReason, SyncStore, Target};
use crate::connections::{ConnectionProfile, ConnectionStore};
use crate::error::{AppError, AppResult};
use crate::saved_queries::SavedQueryStore;
use crate::secrets::SecretsStore;
use crate::settings::SettingsStore;
use crate::snippets::SnippetStore;
use crate::ssh::known_hosts::KnownHosts;
use crate::ssh_store::{SshHost, SshStore};
use crate::vault::Vault;
use crate::vpn_store::VpnStore;

/// A cloud in memory that keeps the server's rules: a push has to name the revision it's based on, and a pull returns what changed after a cursor.
#[derive(Default)]
struct MemoryCloud {
    log: Mutex<Vec<Incoming>>,
    only: Option<Category>,
    max_bytes: Option<usize>,
    down: Mutex<bool>,
}

impl MemoryCloud {
    fn latest(&self) -> BTreeMap<String, Incoming> {
        self.log.lock().unwrap().iter().map(|record| (record.key.clone(), record.clone())).collect()
    }

    /// Live items, without the list orders and shared defaults every computer keeps.
    fn live(&self) -> Vec<String> {
        let shared = |key: &str| is_order(key) || is_routes(key);
        self.latest().into_values().filter(|record| !record.deleted && !shared(&record.key)).map(|record| record.key).collect()
    }

    fn writes(&self, key: &str) -> usize {
        self.log.lock().unwrap().iter().filter(|record| record.key == key).count()
    }

    fn holds_text(&self, text: &str) -> bool {
        self.log.lock().unwrap().iter().any(|record| record.content.to_string().contains(text))
    }

    fn set_down(&self, down: bool) {
        *self.down.lock().unwrap() = down;
    }

    fn check_up(&self) -> AppResult<()> {
        if *self.down.lock().unwrap() { Err(AppError::general("The cloud can't be reached")) } else { Ok(()) }
    }
}

struct MemoryProvider(Arc<MemoryCloud>);

#[async_trait]
impl Provider for MemoryProvider {
    fn accepts(&self, category: Category) -> bool {
        self.0.only.is_none_or(|only| only == category)
    }

    async fn pull(&self, cursor: u64) -> AppResult<Pulled> {
        self.0.check_up()?;
        let log = self.0.log.lock().unwrap();
        Ok(Pulled { changes: log.iter().skip(cursor as usize).cloned().collect(), cursor: log.len() as u64, more: false, problems: Vec::new() })
    }

    async fn push(&self, changes: Vec<Outgoing>) -> AppResult<Vec<(String, Pushed)>> {
        self.0.check_up()?;
        let mut log = self.0.log.lock().unwrap();
        let mut answers = Vec::new();
        for change in changes {
            let current = log.iter().rev().find(|record| record.key == change.key).map(|record| record.revision).unwrap_or(0);
            let pushed = if self.0.max_bytes.is_some_and(|max| change.content.to_string().len() > max) {
                Pushed::TooLarge
            } else if current != change.base_revision {
                Pushed::Conflict
            } else {
                log.push(Incoming {
                    key: change.key.clone(),
                    revision: current + 1,
                    deleted: change.deleted,
                    moved_to: change.moved_to,
                    modified_at: change.modified_at,
                    refs: change.refs,
                    content: change.content,
                });
                Pushed::Accepted { revision: current + 1 }
            };
            answers.push((change.key, pushed));
        }
        Ok(answers)
    }
}

struct Computer {
    dir: PathBuf,
    engine: Arc<Engine>,
    clouds: Arc<Mutex<HashMap<String, Arc<MemoryCloud>>>>,
}

impl Drop for Computer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A computer's data folder with nothing in it yet.
pub(crate) fn new_folder() -> (PathBuf, Stores) {
    let dir = std::env::temp_dir().join(format!("fran-sync-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let stores = Stores {
        connections: Arc::new(ConnectionStore::load(dir.join("connections.json"))),
        ssh: Arc::new(SshStore::load(dir.join("ssh.json"))),
        vpn: Arc::new(VpnStore::load(dir.join("vpn.json"))),
        secrets: Arc::new(SecretsStore::load(dir.join("secrets.json"))),
        saved_queries: Arc::new(SavedQueryStore::load(dir.join("saved_queries.json"))),
        snippets: Arc::new(SnippetStore::load(dir.join("snippets.json"))),
        known_hosts: Arc::new(KnownHosts::load(dir.join("known_hosts.json"))),
        settings: Arc::new(SettingsStore::load(dir.join("settings.json"))),
        vault: Arc::new(Vault::for_tests(dir.join("secrets.vault"))),
    };
    (dir, stores)
}

pub(crate) struct Quiet;

impl Events for Quiet {
    fn changed(&self) {}
    fn applied(&self, _kinds: &[String]) {}
}

impl Computer {
    fn new() -> Self {
        let (dir, stores) = new_folder();
        let clouds: Arc<Mutex<HashMap<String, Arc<MemoryCloud>>>> = Arc::default();
        let known = clouds.clone();
        let opener: Opener = Arc::new(move |cloud| {
            let found = known.lock().unwrap().get(&cloud.identity).cloned().ok_or_else(|| AppError::general("No such cloud"))?;
            Ok(Arc::new(MemoryProvider(found)) as Arc<dyn Provider>)
        });
        let engine = Engine::new(stores, Arc::new(SyncStore::load(dir.join("sync.json"))), opener, Arc::new(Quiet));
        Self { dir, engine, clouds }
    }

    /// Signs into a cloud and returns its id on this computer.
    async fn join(&self, identity: &str, cloud: &Arc<MemoryCloud>) -> String {
        self.clouds.lock().unwrap().insert(identity.to_string(), cloud.clone());
        self.engine.register_cloud(CloudKind::FranServer, identity, identity.to_string(), Value::Null, |_| Ok(())).await.unwrap()
    }

    fn stores(&self) -> &Stores {
        self.engine.stores()
    }

    /// What the change hook does right after a save, plus a pause so the next edit anywhere is later than this one.
    async fn noticed(&self) {
        self.engine.mark_dirty().await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    async fn save_connection(&self, id: &str, name: &str, group: Option<&str>) {
        let profile: ConnectionProfile =
            serde_json::from_value(json!({ "id": id, "name": name, "group": group, "kind": "sqlite", "options": { "path": format!("/data/{id}.db") } })).unwrap();
        self.stores()
            .connections
            .update(|file| {
                file.connections.retain(|existing| existing.id != id);
                file.connections.push(profile);
                Ok(())
            })
            .unwrap();
        self.noticed().await;
    }

    async fn delete_connection(&self, id: &str) {
        self.stores()
            .connections
            .update(|file| {
                file.connections.retain(|existing| existing.id != id);
                Ok(())
            })
            .unwrap();
        self.noticed().await;
    }

    async fn save_host(&self, id: &str, label: &str, identity_id: Option<&str>) {
        let host = SshHost { id: id.to_string(), label: label.to_string(), host: format!("{label}.example.com"), identity_id: identity_id.map(str::to_string), ..SshHost::default() };
        self.stores()
            .ssh
            .update(|file| {
                file.hosts.retain(|existing| existing.id != id);
                file.hosts.push(host);
                Ok(())
            })
            .unwrap();
        self.noticed().await;
    }

    async fn save_identity(&self, id: &str, label: &str) {
        let identity = serde_json::from_value(json!({ "id": id, "label": label, "user": "deploy", "auth": { "kind": "password" } })).unwrap();
        self.stores()
            .ssh
            .update(|file| {
                file.identities.push(identity);
                Ok(())
            })
            .unwrap();
        self.noticed().await;
    }

    async fn set_password(&self, vault_id: &str, value: &str) {
        self.stores().vault.set(vault_id, value).unwrap();
        self.noticed().await;
    }

    fn connection_ids(&self) -> Vec<String> {
        self.stores().connections.read(|file| file.connections.iter().map(|profile| profile.id.clone()).collect()).unwrap()
    }

    /// What dragging in Home does.
    async fn reorder_connections(&self, ids: &[&str]) {
        self.stores()
            .connections
            .update(|file| {
                file.connections.sort_by_key(|profile| ids.iter().position(|id| *id == profile.id).unwrap_or(usize::MAX));
                Ok(())
            })
            .unwrap();
        self.noticed().await;
    }

    fn connection_name(&self, id: &str) -> Option<String> {
        self.stores().connections.read(|file| file.connections.iter().find(|profile| profile.id == id).map(|profile| profile.name.clone())).unwrap()
    }

    fn host_label(&self, id: &str) -> Option<String> {
        self.stores().ssh.read(|file| file.host(id).map(|host| host.label.clone())).unwrap()
    }

    fn password(&self, vault_id: &str) -> Option<String> {
        self.stores().vault.get(vault_id).unwrap().map(|value| value.to_string())
    }

    async fn route(&self, category: Category, cloud_id: &str) {
        self.engine.set_category_route(category, Some(Target::Cloud(cloud_id.to_string()))).await.unwrap();
        self.noticed().await;
    }

    async fn sync(&self) {
        self.engine.sync_all().await.unwrap();
    }

    fn home(&self, key: &str) -> Option<String> {
        self.engine.view().unwrap().homes.get(key).cloned()
    }
}

struct Pair {
    cloud: Arc<MemoryCloud>,
    laptop: Computer,
    desktop: Computer,
    laptop_cloud: String,
}

/// Two computers signed into one cloud, with connections routed to it on the laptop only.
async fn pair() -> Pair {
    let cloud = Arc::new(MemoryCloud::default());
    let (laptop, desktop) = (Computer::new(), Computer::new());
    let laptop_cloud = laptop.join("home", &cloud).await;
    desktop.join("home", &cloud).await;
    laptop.route(Category::Connections, &laptop_cloud).await;
    Pair { cloud, laptop, desktop, laptop_cloud }
}

#[tokio::test]
async fn a_saved_connection_reaches_the_other_computer_and_edits_come_back() {
    let Pair { laptop, desktop, .. } = pair().await;
    laptop.save_connection("c1", "Prod", None).await;
    laptop.sync().await;
    desktop.sync().await;
    assert_eq!(desktop.connection_name("c1").as_deref(), Some("Prod"));

    // The desktop never routed connections anywhere, but this one came from the cloud, so its edits go back there.
    desktop.save_connection("c1", "Prod (EU)", None).await;
    desktop.sync().await;
    laptop.sync().await;
    assert_eq!(laptop.connection_name("c1").as_deref(), Some("Prod (EU)"));
    assert!(laptop.engine.view().unwrap().replaced.is_empty());
}

#[tokio::test]
async fn a_reorder_reaches_the_other_computer_and_does_not_bounce_back() {
    let Pair { cloud, laptop, desktop, .. } = pair().await;
    laptop.save_connection("a", "A", None).await;
    laptop.save_connection("b", "B", None).await;
    laptop.sync().await;

    // The desktop joins with a connection of its own, first in its list. The order the cloud has wins over the desktop's.
    desktop.save_connection("mine", "Mine", None).await;
    desktop.engine.set_item_routes(vec!["connection:mine".into()], Some(Target::Local)).await.unwrap();
    desktop.sync().await;
    assert_eq!(desktop.connection_ids(), ["a", "b", "mine"]);
    assert_eq!(laptop.connection_ids(), ["a", "b"]);

    laptop.reorder_connections(&["b", "a"]).await;
    laptop.sync().await;
    desktop.sync().await;
    assert_eq!(desktop.connection_ids(), ["b", "a", "mine"]);

    // Each computer's list differs by the one only the desktop has. That must not keep sending the order.
    let writes = cloud.writes("order:connections");
    for _ in 0..3 {
        laptop.sync().await;
        desktop.sync().await;
    }
    assert_eq!(cloud.writes("order:connections"), writes);
    assert_eq!(laptop.connection_ids(), ["b", "a"]);
    assert!(desktop.engine.view().unwrap().replaced.is_empty());
}

#[tokio::test]
async fn a_connection_made_on_a_computer_that_syncs_nothing_stays_there() {
    let Pair { cloud, laptop, desktop, .. } = pair().await;
    desktop.save_connection("private", "Scratch", None).await;
    desktop.sync().await;
    laptop.sync().await;
    assert!(cloud.live().is_empty());
    assert_eq!(laptop.connection_name("private"), None);
}

#[tokio::test]
async fn a_delete_reaches_the_other_computer_and_can_be_undone_there() {
    let Pair { cloud, laptop, desktop, .. } = pair().await;
    laptop.save_connection("c1", "Prod", None).await;
    laptop.sync().await;
    desktop.sync().await;

    laptop.delete_connection("c1").await;
    laptop.sync().await;
    desktop.sync().await;
    assert_eq!(desktop.connection_name("c1"), None);
    assert!(cloud.live().is_empty());

    let replaced = desktop.engine.view().unwrap().replaced;
    assert_eq!(replaced.len(), 1);
    assert_eq!((replaced[0].label.as_str(), replaced[0].reason), ("Prod", ReplacedReason::Deleted));

    desktop.engine.restore_replaced(&replaced[0].id).await.unwrap();
    desktop.noticed().await;
    desktop.sync().await;
    laptop.sync().await;
    assert_eq!(laptop.connection_name("c1").as_deref(), Some("Prod"));
}

#[tokio::test]
async fn when_both_edit_offline_the_later_edit_wins_everywhere_and_the_other_is_kept() {
    let Pair { laptop, desktop, .. } = pair().await;
    laptop.save_connection("c1", "Prod", None).await;
    laptop.sync().await;
    desktop.sync().await;

    desktop.save_connection("c1", "Desktop's name", None).await;
    laptop.save_connection("c1", "Laptop's name", None).await;

    // The earlier edit reaches the cloud first. The later one still has to win.
    desktop.sync().await;
    laptop.sync().await;
    desktop.sync().await;
    assert_eq!(laptop.connection_name("c1").as_deref(), Some("Laptop's name"));
    assert_eq!(desktop.connection_name("c1").as_deref(), Some("Laptop's name"));

    let lost = laptop.engine.view().unwrap().replaced;
    assert_eq!(lost.len(), 1);
    assert_eq!((lost[0].label.as_str(), lost[0].reason), ("Desktop's name", ReplacedReason::Overwritten));
    assert!(desktop.engine.view().unwrap().replaced.is_empty());
}

#[tokio::test]
async fn the_later_edit_also_wins_when_it_reaches_the_cloud_first() {
    let Pair { laptop, desktop, .. } = pair().await;
    laptop.save_connection("c1", "Prod", None).await;
    laptop.sync().await;
    desktop.sync().await;

    desktop.save_connection("c1", "Desktop's name", None).await;
    laptop.save_connection("c1", "Laptop's name", None).await;

    laptop.sync().await;
    desktop.sync().await;
    laptop.sync().await;
    assert_eq!(laptop.connection_name("c1").as_deref(), Some("Laptop's name"));
    assert_eq!(desktop.connection_name("c1").as_deref(), Some("Laptop's name"));

    let lost = desktop.engine.view().unwrap().replaced;
    assert_eq!(lost.len(), 1);
    assert_eq!((lost[0].label.as_str(), lost[0].reason), ("Desktop's name", ReplacedReason::Replaced));
}

#[tokio::test]
async fn an_edit_made_while_the_cloud_was_down_goes_up_once_it_is_back() {
    let Pair { cloud, laptop, desktop, .. } = pair().await;
    cloud.set_down(true);
    laptop.save_connection("c1", "Prod", None).await;
    assert!(laptop.engine.sync_all().await.is_err());
    assert_eq!(laptop.connection_name("c1").as_deref(), Some("Prod"));

    cloud.set_down(false);
    laptop.sync().await;
    desktop.sync().await;
    assert_eq!(desktop.connection_name("c1").as_deref(), Some("Prod"));
}

#[tokio::test]
async fn passwords_stay_put_until_they_are_told_to_follow_their_item() {
    let Pair { cloud, laptop, desktop, laptop_cloud, .. } = pair().await;
    laptop.save_connection("c1", "Prod", None).await;
    laptop.set_password("connection:c1:password", "hunter2-prod").await;
    laptop.sync().await;
    desktop.sync().await;
    assert_eq!(desktop.connection_name("c1").as_deref(), Some("Prod"));
    assert_eq!(desktop.password("connection:c1:password"), None);
    assert!(!cloud.holds_text("hunter2-prod"));

    laptop.engine.set_category_route(Category::Passwords, Some(Target::WithItem)).await.unwrap();
    laptop.noticed().await;
    laptop.sync().await;
    desktop.sync().await;
    assert_eq!(desktop.password("connection:c1:password").as_deref(), Some("hunter2-prod"));
    assert_eq!(laptop.home("vault:connection:c1:password"), Some(laptop_cloud));

    // The hash kept next to the routes must not be a plain digest of the password.
    let state = std::fs::read_to_string(laptop.dir.join("sync.json")).unwrap();
    let plain = hex::encode(ring::digest::digest(&ring::digest::SHA256, b"hunter2-prod"));
    assert!(!state.contains("hunter2-prod") && !state.contains(&plain));
}

#[tokio::test]
async fn a_replaced_password_is_kept_in_the_vault_and_never_in_the_state_file() {
    let Pair { laptop, desktop, .. } = pair().await;
    laptop.engine.set_category_route(Category::Passwords, Some(Target::WithItem)).await.unwrap();
    laptop.save_connection("c1", "Prod", None).await;
    laptop.set_password("connection:c1:password", "first-password").await;
    laptop.sync().await;
    desktop.sync().await;

    desktop.set_password("connection:c1:password", "desktop-password").await;
    laptop.set_password("connection:c1:password", "laptop-password").await;
    laptop.sync().await;
    desktop.sync().await;
    assert_eq!(desktop.password("connection:c1:password").as_deref(), Some("laptop-password"));

    let state = std::fs::read_to_string(desktop.dir.join("sync.json")).unwrap();
    assert!(!state.contains("desktop-password") && !state.contains("laptop-password"));
    let replaced = desktop.engine.view().unwrap().replaced;
    assert_eq!(replaced.len(), 1);
    assert_eq!(replaced[0].label, "Prod");

    desktop.engine.restore_replaced(&replaced[0].id).await.unwrap();
    assert_eq!(desktop.password("connection:c1:password").as_deref(), Some("desktop-password"));
}

#[tokio::test]
async fn keep_on_this_computer_holds_against_the_category_and_against_incoming_changes() {
    let Pair { cloud, laptop, desktop, .. } = pair().await;
    laptop.save_connection("shared", "Shared", None).await;
    laptop.save_connection("mine", "Mine", None).await;
    laptop.engine.set_item_routes(vec!["connection:mine".into()], Some(Target::Local)).await.unwrap();
    laptop.sync().await;
    assert_eq!(cloud.live(), ["connection:shared"]);

    // The desktop stops following the shared one. The laptop's later edits must not touch its copy.
    desktop.sync().await;
    desktop.engine.set_item_routes(vec!["connection:shared".into()], Some(Target::Local)).await.unwrap();
    desktop.save_connection("shared", "My own copy", None).await;
    laptop.save_connection("shared", "Shared v2", None).await;
    laptop.sync().await;
    desktop.sync().await;
    laptop.sync().await;
    assert_eq!(desktop.connection_name("shared").as_deref(), Some("My own copy"));
    assert_eq!(laptop.connection_name("shared").as_deref(), Some("Shared v2"));
}

#[tokio::test]
async fn a_group_can_go_to_another_cloud_than_the_rest() {
    let (home, work) = (Arc::new(MemoryCloud::default()), Arc::new(MemoryCloud::default()));
    let laptop = Computer::new();
    let home_id = laptop.join("home", &home).await;
    let work_id = laptop.join("work", &work).await;
    laptop.route(Category::Connections, &home_id).await;
    laptop.engine.set_group_route("connection:Acme".into(), Some(Target::Cloud(work_id))).await.unwrap();

    laptop.save_connection("blog", "Blog", None).await;
    laptop.save_connection("acme-db", "Acme DB", Some("Acme")).await;
    laptop.sync().await;
    assert_eq!(home.live(), ["connection:blog"]);
    assert_eq!(work.live(), ["connection:acme-db"]);
    assert!(!home.holds_text("Acme DB"));
}

#[tokio::test]
async fn a_move_between_clouds_ends_the_same_on_every_computer() {
    let (home, work) = (Arc::new(MemoryCloud::default()), Arc::new(MemoryCloud::default()));
    let (laptop, desktop, phone) = (Computer::new(), Computer::new(), Computer::new());
    let laptop_home = laptop.join("home", &home).await;
    let laptop_work = laptop.join("work", &work).await;
    let desktop_home = desktop.join("home", &home).await;
    let desktop_work = desktop.join("work", &work).await;
    // The third computer only knows the first cloud.
    phone.join("home", &home).await;

    laptop.route(Category::Connections, &laptop_home).await;
    laptop.save_connection("c1", "Prod", None).await;
    laptop.sync().await;
    desktop.sync().await;
    phone.sync().await;
    assert_eq!(desktop.home("connection:c1"), Some(desktop_home));

    laptop.engine.set_item_routes(vec!["connection:c1".into()], Some(Target::Cloud(laptop_work.clone()))).await.unwrap();
    laptop.noticed().await;
    laptop.sync().await;
    assert!(home.live().is_empty());
    assert_eq!(work.live(), ["connection:c1"]);
    assert_eq!(home.latest()["connection:c1"].moved_to.as_deref(), Some("work"));

    desktop.sync().await;
    assert_eq!(desktop.connection_name("c1").as_deref(), Some("Prod"));
    assert_eq!(desktop.home("connection:c1"), Some(desktop_work));
    assert!(desktop.engine.view().unwrap().replaced.is_empty());

    // An edit on the desktop now travels through the new cloud only.
    desktop.save_connection("c1", "Prod (moved)", None).await;
    desktop.sync().await;
    laptop.sync().await;
    assert_eq!(laptop.connection_name("c1").as_deref(), Some("Prod (moved)"));
    assert!(home.live().is_empty());

    // The computer that isn't signed into the new cloud keeps its copy, local only, and knows where the item went.
    phone.sync().await;
    assert_eq!(phone.connection_name("c1").as_deref(), Some("Prod"));
    assert_eq!(phone.home("connection:c1"), None);
    assert_eq!(phone.engine.view().unwrap().moved.get("connection:c1").map(String::as_str), Some("work"));
}

#[tokio::test]
async fn a_computer_on_one_cloud_still_gets_items_that_point_into_another() {
    let (home, work) = (Arc::new(MemoryCloud::default()), Arc::new(MemoryCloud::default()));
    let (laptop, desktop) = (Computer::new(), Computer::new());
    let laptop_home = laptop.join("home", &home).await;
    let laptop_work = laptop.join("work", &work).await;
    desktop.join("home", &home).await;

    laptop.route(Category::SshHosts, &laptop_home).await;
    laptop.route(Category::Identities, &laptop_work).await;
    laptop.save_identity("i1", "Deploy key").await;
    laptop.save_host("h1", "bastion", Some("i1")).await;
    laptop.sync().await;

    desktop.sync().await;
    assert_eq!(desktop.host_label("h1").as_deref(), Some("bastion"));
    let missing = desktop.engine.view().unwrap().missing;
    assert_eq!(missing.len(), 1);
    assert_eq!((missing[0].item.as_str(), missing[0].target.as_str(), &missing[0].cloud), ("sshHost:h1", "identity:i1", &None));

    // Once it signs into the other cloud the identity arrives and nothing is missing.
    desktop.join("work", &work).await;
    desktop.sync().await;
    assert!(desktop.engine.view().unwrap().missing.is_empty());

    let offered = laptop.engine.move_candidates("sshHost:h1", &laptop_home).unwrap();
    assert_eq!(offered.iter().map(|candidate| candidate.key.as_str()).collect::<Vec<_>>(), ["identity:i1"]);
}

#[tokio::test]
async fn a_cloud_that_only_takes_secrets_is_refused_for_anything_else() {
    let secrets_only = Arc::new(MemoryCloud { only: Some(Category::Secrets), ..MemoryCloud::default() });
    let laptop = Computer::new();
    let id = laptop.join("secrets", &secrets_only).await;

    let refused = laptop.engine.set_category_route(Category::Connections, Some(Target::Cloud(id.clone()))).await;
    assert!(refused.is_err());
    laptop.save_connection("c1", "Prod", None).await;
    assert!(laptop.engine.set_item_routes(vec!["connection:c1".into()], Some(Target::Cloud(id.clone()))).await.is_err());

    // "Use for everything" skips what the cloud can't hold instead of failing.
    laptop.engine.use_for_everything(&id).await.unwrap();
    laptop.noticed().await;
    laptop.sync().await;
    assert!(secrets_only.live().is_empty());
}

#[tokio::test]
async fn an_item_the_cloud_refuses_is_reported_and_the_rest_still_syncs() {
    let small = Arc::new(MemoryCloud { max_bytes: Some(400), ..MemoryCloud::default() });
    let laptop = Computer::new();
    let id = laptop.join("small", &small).await;
    laptop.route(Category::Connections, &id).await;
    laptop.save_connection("big", &"x".repeat(1000), None).await;
    laptop.save_connection("ok", "Fits", None).await;
    laptop.sync().await;
    assert_eq!(small.live(), ["connection:ok"]);

    // The worker sets the status. Here only what the push recorded is checked.
    laptop.sync().await;
    let view = laptop.engine.view().unwrap();
    let problems = &view.clouds[0].status.problems;
    assert_eq!(problems.len(), 1);
    assert_eq!((problems[0].key.as_str(), problems[0].reason), ("connection:big", ProblemReason::TooLarge));

    laptop.save_connection("big", "Now it fits", None).await;
    laptop.sync().await;
    assert_eq!(small.live().len(), 2);
    assert!(laptop.engine.view().unwrap().clouds[0].status.problems.is_empty());
}

#[tokio::test]
async fn removing_a_cloud_keeps_everything_here_and_adding_it_back_merges_by_id() {
    let Pair { cloud, laptop, desktop, laptop_cloud, .. } = pair().await;
    laptop.save_connection("c1", "Prod", None).await;
    laptop.sync().await;

    laptop.engine.remove_cloud(&laptop_cloud).await.unwrap();
    assert_eq!(laptop.connection_name("c1").as_deref(), Some("Prod"));
    assert_eq!(laptop.home("connection:c1"), None);
    desktop.sync().await;
    assert_eq!(desktop.connection_name("c1").as_deref(), Some("Prod"));

    let again = laptop.join("home", &cloud).await;
    laptop.sync().await;
    assert_eq!(laptop.stores().connections.read(|file| file.connections.len()).unwrap(), 1);
    assert_eq!(laptop.home("connection:c1"), Some(again));
    assert!(laptop.engine.view().unwrap().replaced.is_empty());
}

#[tokio::test]
async fn an_identity_made_on_both_computers_is_offered_as_one_and_merging_repoints_its_hosts() {
    let cloud = Arc::new(MemoryCloud::default());
    let (laptop, desktop) = (Computer::new(), Computer::new());
    let laptop_cloud = laptop.join("home", &cloud).await;
    laptop.route(Category::Identities, &laptop_cloud).await;
    laptop.save_identity("i1", "Deploy key").await;
    laptop.sync().await;

    // The desktop had the same login set up on its own before it ever synced.
    desktop.save_identity("i-desk", "Deploy key").await;
    desktop.save_host("h-desk", "bastion", Some("i-desk")).await;
    desktop.set_password("identity:i-desk:password", "typed-on-desktop").await;
    let desktop_cloud = desktop.join("home", &cloud).await;
    desktop.route(Category::Identities, &desktop_cloud).await;
    desktop.sync().await;

    let found = desktop.engine.view().unwrap().duplicates;
    let pairs: Vec<(&str, &str)> = found.iter().map(|duplicate| (duplicate.local.as_str(), duplicate.remote.as_str())).collect();
    assert_eq!(pairs, [("identity:i-desk", "identity:i1")]);
    assert_eq!(cloud.live(), ["identity:i1"], "the desktop's copy waits until the user decides");

    desktop.engine.settle_duplicates(None, true).await.unwrap();
    desktop.sync().await;
    let ssh = desktop.stores().ssh.snapshot().unwrap();
    assert_eq!(ssh.identities.iter().map(|identity| identity.id.as_str()).collect::<Vec<_>>(), ["i1"]);
    assert_eq!(ssh.host("h-desk").unwrap().identity_id.as_deref(), Some("i1"));
    assert_eq!(desktop.password("identity:i1:password").as_deref(), Some("typed-on-desktop"));
    assert_eq!(desktop.password("identity:i-desk:password"), None);
    assert_eq!(cloud.live(), ["identity:i1"]);
    assert!(desktop.engine.view().unwrap().duplicates.is_empty());
}

#[tokio::test]
async fn category_defaults_reach_the_other_computer_and_wait_for_a_cloud_it_lacks() {
    let (home, work) = (Arc::new(MemoryCloud::default()), Arc::new(MemoryCloud::default()));
    let (laptop, desktop) = (Computer::new(), Computer::new());
    let laptop_home = laptop.join("home", &home).await;
    let laptop_work = laptop.join("work", &work).await;
    laptop.route(Category::Settings, &laptop_home).await;
    laptop.route(Category::Connections, &laptop_home).await;
    laptop.route(Category::Snippets, &laptop_work).await;
    laptop.sync().await;

    let desktop_home = desktop.join("home", &home).await;
    desktop.sync().await;
    let view = desktop.engine.view().unwrap();
    assert_eq!(view.routes.categories.get(&Category::Connections), Some(&Target::Cloud(desktop_home)));
    assert_eq!(view.routes.categories.get(&Category::Settings), None, "which cloud holds settings is up to each computer");
    assert_eq!(view.waiting_routes.get(&Category::Snippets).map(String::as_str), Some("work"));

    // Nothing was set on the desktop, and its new connection still goes up.
    desktop.save_connection("c1", "Prod", None).await;
    desktop.sync().await;
    laptop.sync().await;
    assert_eq!(laptop.connection_name("c1").as_deref(), Some("Prod"));

    let desktop_work = desktop.join("work", &work).await;
    let view = desktop.engine.view().unwrap();
    assert_eq!(view.routes.categories.get(&Category::Snippets), Some(&Target::Cloud(desktop_work.clone())));
    assert!(view.waiting_routes.is_empty());

    // Signing out of a cloud on one computer doesn't stop the others from using it.
    desktop.engine.remove_cloud(&desktop_work).await.unwrap();
    desktop.noticed().await;
    desktop.sync().await;
    laptop.sync().await;
    assert_eq!(laptop.engine.view().unwrap().routes.categories.get(&Category::Snippets), Some(&Target::Cloud(laptop_work)));
}

#[tokio::test]
async fn two_computers_changing_different_parts_of_one_setting_keep_both() {
    let Pair { laptop, desktop, laptop_cloud, .. } = pair().await;
    laptop.route(Category::Settings, &laptop_cloud).await;
    let set = |computer: &Computer, format: Value| {
        computer.stores().settings.update(|file| {
            file.settings = Some(json!({ "format": format }));
            Ok(())
        }).unwrap();
    };
    set(&laptop, json!({ "dateStyle": "iso", "nullText": "NULL" }));
    laptop.noticed().await;
    laptop.sync().await;
    desktop.sync().await;

    // Both edit offline, each a different part.
    set(&laptop, json!({ "dateStyle": "local", "nullText": "NULL" }));
    laptop.noticed().await;
    set(&desktop, json!({ "dateStyle": "iso", "nullText": "(null)" }));
    desktop.noticed().await;
    laptop.sync().await;
    desktop.sync().await;
    laptop.sync().await;

    let format = |computer: &Computer| computer.stores().settings.read(|file| file.settings.clone()).unwrap().unwrap()["format"].clone();
    assert_eq!(format(&laptop), json!({ "dateStyle": "local", "nullText": "(null)" }));
    assert_eq!(format(&desktop), json!({ "dateStyle": "local", "nullText": "(null)" }));
    assert!(desktop.engine.view().unwrap().replaced.is_empty());
}

#[tokio::test]
async fn settings_sync_without_the_ones_that_describe_one_computer() {
    let Pair { laptop, desktop, laptop_cloud, .. } = pair().await;
    laptop.route(Category::Settings, &laptop_cloud).await;
    let laptop_settings = json!({ "defaultRowLimit": 500, "features": { "database": true, "ssh": true, "vpn": false }, "vpn": { "program": "C:/vpn.exe", "idleCloseSecs": 120 } });
    laptop.stores().settings.update(|file| {
        file.settings = Some(laptop_settings);
        Ok(())
    }).unwrap();
    desktop.stores().settings.update(|file| {
        file.settings = Some(json!({ "features": { "database": true, "ssh": false, "vpn": false }, "vpn": { "program": "/usr/sbin/openvpn", "idleCloseSecs": 30 } }));
        Ok(())
    }).unwrap();
    laptop.noticed().await;
    laptop.sync().await;
    desktop.sync().await;

    let settings = desktop.stores().settings.read(|file| file.settings.clone()).unwrap().unwrap();
    assert_eq!(settings["defaultRowLimit"], 500);
    assert_eq!(settings["features"]["ssh"], false);
    assert_eq!(settings["vpn"], json!({ "program": "/usr/sbin/openvpn", "idleCloseSecs": 120 }));
}
