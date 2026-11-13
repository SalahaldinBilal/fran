//! The provider against a fake Doppler in this process. It keeps Doppler's rules that matter here: a bearer token, `project` and `config`
//! on every call, `originalValue` on a change, the default name rules, a read-only token and 429 with `retry-after`.
//! `a_real_doppler_config_behaves_like_the_fake` talks to Doppler itself and only runs with `FRAN_E2E_DOPPLER_TOKEN` set.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Value, json};

use super::client::{Client, Place};
use super::{Doppler, token_id};
use crate::connections::ConnectionProfile;
use crate::error::ErrorDetail;
use crate::secrets::{NamedSecret, SecretLink, vault_id};
use crate::sync::engine::{Engine, ProblemReason};
use crate::sync::items::secret_value_key;
use crate::sync::providers::{CloudKind, Opener, Outgoing, Provider, Pushed};
use crate::sync::state::{Category, SyncStore, Target, replaced_vault_id};
use crate::sync::tests::{Quiet, new_folder};

const TOKEN: &str = "dp.st.prd.fake-token";
const PROJECT: &str = "shop";
const CONFIG: &str = "prd";
const IDENTITY: &str = "doppler:shop:prd";

#[derive(Default)]
struct Fake {
    /// Name to raw and computed value.
    secrets: Mutex<BTreeMap<String, (String, String)>>,
    read_only: Mutex<bool>,
    /// How many of the next requests get a 429.
    limited: Mutex<u32>,
    /// A service token: the config is known without being named.
    tied_to_config: Mutex<bool>,
    /// Every `secrets=` list a read asked for, None for a read of the whole config.
    asked_for: Mutex<Vec<Option<String>>>,
}

impl Fake {
    fn put(&self, name: &str, value: &str) {
        self.secrets.lock().unwrap().insert(name.to_string(), (value.to_string(), value.to_string()));
    }

    fn put_computed(&self, name: &str, raw: &str, computed: &str) {
        self.secrets.lock().unwrap().insert(name.to_string(), (raw.to_string(), computed.to_string()));
    }

    fn raw(&self, name: &str) -> Option<String> {
        self.secrets.lock().unwrap().get(name).map(|(raw, _)| raw.clone())
    }

    fn remove(&self, name: &str) {
        self.secrets.lock().unwrap().remove(name);
    }
}

fn refusal(status: StatusCode, message: &str) -> Response {
    (status, json!({ "messages": [message], "success": false }).to_string()).into_response()
}

fn query(uri: &Uri) -> BTreeMap<String, String> {
    let url = reqwest::Url::parse(&format!("http://fake{uri}")).unwrap();
    url.query_pairs().map(|(name, value)| (name.to_string(), value.to_string())).collect()
}

/// The checks every Doppler call goes through before it does anything.
fn gate(fake: &Fake, headers: &HeaderMap) -> Option<Response> {
    let mut limited = fake.limited.lock().unwrap();
    if *limited > 0 {
        *limited -= 1;
        return Some((StatusCode::TOO_MANY_REQUESTS, [("retry-after", "1")], String::new()).into_response());
    }
    let bearer = headers.get("authorization").and_then(|value| value.to_str().ok());
    if bearer != Some(format!("Bearer {TOKEN}").as_str()) {
        return Some(refusal(StatusCode::UNAUTHORIZED, "Invalid Auth token"));
    }
    None
}

fn right_place(fake: &Fake, project: Option<&str>, config: Option<&str>) -> bool {
    match (project, config) {
        (Some(PROJECT), Some(CONFIG)) => true,
        (None, None) => *fake.tied_to_config.lock().unwrap(),
        _ => false,
    }
}

async fn list(State(fake): State<Arc<Fake>>, headers: HeaderMap, uri: Uri) -> Response {
    if let Some(refused) = gate(&fake, &headers) {
        return refused;
    }
    let query = query(&uri);
    if !right_place(&fake, query.get("project").map(String::as_str), query.get("config").map(String::as_str)) {
        return refusal(StatusCode::BAD_REQUEST, "Invalid project or config");
    }
    let wanted = query.get("secrets").cloned();
    fake.asked_for.lock().unwrap().push(wanted.clone());
    let mut all: BTreeMap<String, (String, String)> = fake.secrets.lock().unwrap().clone();
    all.insert("DOPPLER_PROJECT".into(), (PROJECT.into(), PROJECT.into()));
    all.insert("DOPPLER_CONFIG".into(), (CONFIG.into(), CONFIG.into()));
    let wanted: Option<Vec<&str>> = wanted.as_deref().map(|wanted| wanted.split(',').collect());
    let secrets: serde_json::Map<String, Value> = all
        .into_iter()
        .filter(|(name, _)| wanted.as_ref().is_none_or(|wanted| wanted.contains(&name.as_str())))
        .map(|(name, (raw, computed))| (name, json!({ "raw": raw, "computed": computed, "note": "" })))
        .collect();
    (StatusCode::OK, json!({ "secrets": secrets }).to_string()).into_response()
}

async fn names(State(fake): State<Arc<Fake>>, headers: HeaderMap, uri: Uri) -> Response {
    if let Some(refused) = gate(&fake, &headers) {
        return refused;
    }
    let query = query(&uri);
    if !right_place(&fake, query.get("project").map(String::as_str), query.get("config").map(String::as_str)) {
        return refusal(StatusCode::BAD_REQUEST, "Invalid project or config");
    }
    let names: Vec<String> = fake.secrets.lock().unwrap().keys().cloned().collect();
    (StatusCode::OK, json!({ "names": names }).to_string()).into_response()
}

fn allowed_name(name: &str) -> bool {
    let shape = name.chars().all(|character| character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_');
    shape && !name.is_empty() && name.len() <= 200 && !name.starts_with(|first: char| first.is_ascii_digit())
}

async fn change(State(fake): State<Arc<Fake>>, headers: HeaderMap, body: String) -> Response {
    if let Some(refused) = gate(&fake, &headers) {
        return refused;
    }
    let body: Value = serde_json::from_str(&body).unwrap_or_default();
    if !right_place(&fake, body["project"].as_str(), body["config"].as_str()) {
        return refusal(StatusCode::BAD_REQUEST, "Invalid project or config");
    }
    if *fake.read_only.lock().unwrap() {
        return refusal(StatusCode::FORBIDDEN, "This token does not have write access");
    }
    let mut secrets = fake.secrets.lock().unwrap();
    for request in body["change_requests"].as_array().cloned().unwrap_or_default() {
        let Some(name) = request["name"].as_str().filter(|name| allowed_name(name)) else {
            return refusal(StatusCode::BAD_REQUEST, "Secret names may only contain uppercase letters, numbers, and underscores");
        };
        let held = secrets.get(name).map(|(raw, _)| raw.clone());
        if let Some(expected) = request["originalValue"].as_str()
            && held.as_deref() != Some(expected)
        {
            return refusal(StatusCode::BAD_REQUEST, "The secret was changed by someone else");
        }
        if request["shouldDelete"].as_bool() == Some(true) {
            secrets.remove(name);
        } else if let Some(value) = request["value"].as_str() {
            secrets.insert(name.to_string(), (value.to_string(), value.to_string()));
        }
    }
    (StatusCode::OK, json!({ "secrets": {} }).to_string()).into_response()
}

async fn projects(State(fake): State<Arc<Fake>>, headers: HeaderMap) -> Response {
    if let Some(refused) = gate(&fake, &headers) {
        return refused;
    }
    if *fake.tied_to_config.lock().unwrap() {
        return refusal(StatusCode::FORBIDDEN, "Service tokens can't list projects");
    }
    (StatusCode::OK, json!({ "page": 1, "projects": [{ "id": "p1", "slug": PROJECT, "name": "Shop" }] }).to_string()).into_response()
}

async fn start() -> (Arc<Fake>, String) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fake = Arc::new(Fake::default());
    let router = Router::new()
        .route("/v3/configs/config/secrets", get(list).post(change))
        .route("/v3/configs/config/secrets/names", get(names))
        .route("/v3/projects", get(projects))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (fake, url)
}

struct Computer {
    dir: PathBuf,
    engine: Arc<Engine>,
    cloud: String,
    url: String,
}

impl Drop for Computer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Computer {
    /// A computer that has the fake's config added as a cloud, with `token` in its vault.
    async fn new(url: &str, token: &str) -> Self {
        let (dir, stores) = new_folder();
        let (vault, secrets, base) = (stores.vault.clone(), stores.secrets.clone(), url.to_string());
        let opener: Opener = Arc::new(move |cloud| {
            let client = Client::at(&base, &super::token(&cloud.id, &vault)?)?;
            Ok(Arc::new(Doppler::with(cloud, client, vault.clone(), secrets.clone())?) as Arc<dyn Provider>)
        });
        let engine = Engine::new(stores, Arc::new(SyncStore::load(dir.join("sync.json"))), opener, Arc::new(Quiet));
        let vault = engine.stores().vault.clone();
        let config = json!({ "project": PROJECT, "config": CONFIG });
        let cloud = engine.register_cloud(CloudKind::Doppler, "Doppler", IDENTITY.to_string(), config, |id| vault.set(&token_id(id), token)).await.unwrap();
        Self { dir, engine, cloud, url: url.to_string() }
    }

    async fn noticed(&self) {
        self.engine.mark_dirty().await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    /// A secret linked to a name in the fake's config. With a value it's "Store in Doppler", without one "From Doppler".
    async fn link(&self, id: &str, doppler_name: &str, value: Option<&str>) {
        let stores = self.engine.stores();
        if let Some(value) = value {
            stores.vault.set(&vault_id(id), value).unwrap();
        }
        let link = Some(SecretLink { cloud: IDENTITY.to_string(), name: doppler_name.to_string() });
        let secret = NamedSecret { id: id.to_string(), name: format!("Secret {id}"), note: String::new(), link };
        stores
            .secrets
            .update(|file| {
                file.secrets.retain(|existing| existing.id != id);
                file.secrets.push(secret);
                Ok(())
            })
            .unwrap();
        self.noticed().await;
    }

    async fn edit(&self, id: &str, value: &str) {
        self.engine.stores().vault.set(&vault_id(id), value).unwrap();
        self.noticed().await;
    }

    fn value(&self, id: &str) -> Option<String> {
        self.engine.stores().vault.get(&vault_id(id)).unwrap().map(|value| value.to_string())
    }

    fn problems(&self) -> Vec<(String, ProblemReason)> {
        let view = self.engine.view().unwrap();
        view.clouds[0].status.problems.iter().map(|problem| (problem.key.clone(), problem.reason)).collect()
    }

    /// The values sync replaced, read back from the vault where they're kept.
    fn replaced(&self) -> Vec<(String, String)> {
        let vault = &self.engine.stores().vault;
        let view = self.engine.view().unwrap();
        view.replaced.iter().map(|entry| (entry.key.clone(), vault.get(&replaced_vault_id(&entry.id)).unwrap().unwrap().to_string())).collect()
    }

    fn provider(&self) -> Doppler {
        let stores = self.engine.stores();
        let client = Client::at(&self.url, TOKEN).unwrap();
        Doppler::with(&self.engine.cloud(&self.cloud).unwrap(), client, stores.vault.clone(), stores.secrets.clone()).unwrap()
    }
}

fn place() -> Place {
    Place { project: PROJECT.to_string(), config: CONFIG.to_string() }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_linked_secret_gets_its_value_from_doppler_and_nothing_else_is_fetched() {
    let (fake, url) = start().await;
    fake.put("DB_PASSWORD", "hunter2");
    fake.put("STRIPE_KEY", "sk_live_not_ours");
    let laptop = Computer::new(&url, TOKEN).await;
    laptop.link("s1", "DB_PASSWORD", None).await;
    laptop.engine.sync_all().await.unwrap();

    assert_eq!(laptop.value("s1").as_deref(), Some("hunter2"));
    assert!(laptop.problems().is_empty());
    let asked = fake.asked_for.lock().unwrap().clone();
    assert!(!asked.is_empty());
    assert!(asked.iter().all(|names| names.as_deref() == Some("DB_PASSWORD")), "{asked:?}");
    // Reading a value from Doppler must not be taken for a local edit and written back.
    assert_eq!(fake.raw("DB_PASSWORD").as_deref(), Some("hunter2"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_secret_stored_in_doppler_is_created_there_and_later_edits_follow() {
    let (fake, url) = start().await;
    let laptop = Computer::new(&url, TOKEN).await;
    laptop.link("s1", "API_TOKEN", Some("first")).await;
    laptop.engine.sync_all().await.unwrap();
    assert_eq!(fake.raw("API_TOKEN").as_deref(), Some("first"));

    laptop.edit("s1", "second").await;
    laptop.engine.sync_all().await.unwrap();
    assert_eq!(fake.raw("API_TOKEN").as_deref(), Some("second"));
    assert!(laptop.problems().is_empty());
    assert!(laptop.replaced().is_empty());

    // A second computer with the same link and the same config resolves it on its own.
    let desktop = Computer::new(&url, TOKEN).await;
    desktop.link("s1", "API_TOKEN", None).await;
    desktop.engine.sync_all().await.unwrap();
    assert_eq!(desktop.value("s1").as_deref(), Some("second"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_rotated_in_doppler_is_picked_up_after_a_failed_login() {
    let (fake, url) = start().await;
    fake.put("DB_PASSWORD", "old");
    let laptop = Computer::new(&url, TOKEN).await;
    laptop.link("s1", "DB_PASSWORD", None).await;
    laptop.engine.sync_all().await.unwrap();
    assert!(!laptop.engine.refresh_linked().await.unwrap(), "nothing changed, so a retry would only fail again");

    fake.put("DB_PASSWORD", "rotated");
    assert!(laptop.engine.refresh_linked().await.unwrap());
    assert_eq!(laptop.value("s1").as_deref(), Some("rotated"));
    assert!(laptop.replaced().is_empty(), "the old value wasn't an edit made here");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_edit_made_in_doppler_meanwhile_wins_and_the_local_edit_is_kept_aside() {
    let (fake, url) = start().await;
    fake.put("DB_PASSWORD", "start");
    let laptop = Computer::new(&url, TOKEN).await;
    laptop.link("s1", "DB_PASSWORD", None).await;
    laptop.engine.sync_all().await.unwrap();

    laptop.edit("s1", "typed in fran").await;
    fake.put("DB_PASSWORD", "typed in doppler");
    laptop.engine.sync_all().await.unwrap();
    assert_eq!(laptop.value("s1").as_deref(), Some("typed in doppler"));
    assert_eq!(fake.raw("DB_PASSWORD").as_deref(), Some("typed in doppler"));
    assert_eq!(laptop.replaced(), [(secret_value_key("s1"), "typed in fran".to_string())]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_push_based_on_a_value_doppler_no_longer_holds_is_a_conflict_not_an_overwrite() {
    let (fake, url) = start().await;
    fake.put("DB_PASSWORD", "start");
    let laptop = Computer::new(&url, TOKEN).await;
    laptop.link("s1", "DB_PASSWORD", None).await;
    laptop.engine.sync_all().await.unwrap();

    // Doppler changes after this computer's last pull and before its push.
    fake.put("DB_PASSWORD", "changed in doppler");
    let provider = laptop.provider();
    let key = secret_value_key("s1");
    let change = Outgoing {
        key: key.clone(),
        base_revision: 1,
        deleted: false,
        moved_to: None,
        modified_at: 0,
        refs: BTreeMap::new(),
        content: json!({ "value": "typed in fran" }),
    };
    assert_eq!(provider.push(vec![change]).await.unwrap(), [(key.clone(), Pushed::Conflict)]);
    assert_eq!(fake.raw("DB_PASSWORD").as_deref(), Some("changed in doppler"));

    let pulled = laptop.provider().pull(0).await.unwrap();
    assert_eq!(pulled.changes.len(), 1);
    assert_eq!(pulled.changes[0].content, json!({ "value": "changed in doppler" }));
    assert!(pulled.changes[0].revision > 1, "the engine has to see Doppler's value as newer than what it holds");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_only_token_still_reads_and_says_so_when_asked_to_write() {
    let (fake, url) = start().await;
    fake.put("DB_PASSWORD", "hunter2");
    *fake.read_only.lock().unwrap() = true;
    let laptop = Computer::new(&url, TOKEN).await;
    laptop.link("s1", "DB_PASSWORD", None).await;
    laptop.link("s2", "NEW_ONE", Some("made here")).await;
    laptop.engine.sync_all().await.unwrap();

    assert_eq!(laptop.value("s1").as_deref(), Some("hunter2"));
    assert_eq!(fake.raw("NEW_ONE"), None);
    assert_eq!(laptop.value("s2").as_deref(), Some("made here"));
    assert!(laptop.problems().contains(&(secret_value_key("s2"), ProblemReason::ReadOnly)), "{:?}", laptop.problems());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_name_doppler_refuses_is_listed_and_the_other_secrets_still_go_up() {
    let (fake, url) = start().await;
    let laptop = Computer::new(&url, TOKEN).await;
    laptop.link("s1", "db-password", Some("kept here")).await;
    laptop.link("s2", "API_TOKEN", Some("goes up")).await;
    laptop.engine.sync_all().await.unwrap();

    assert_eq!(fake.raw("API_TOKEN").as_deref(), Some("goes up"));
    assert_eq!(laptop.value("s1").as_deref(), Some("kept here"));
    assert!(laptop.problems().contains(&(secret_value_key("s1"), ProblemReason::Refused)), "{:?}", laptop.problems());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_value_made_here_never_overwrites_a_name_doppler_already_has() {
    let (fake, url) = start().await;
    fake.put("DB_PASSWORD", "the real one");
    let laptop = Computer::new(&url, TOKEN).await;
    laptop.link("s1", "DB_PASSWORD", Some("an old saved password")).await;

    // Pushed before any pull, the way an edit made between a pull and a push would go.
    let key = secret_value_key("s1");
    let change = Outgoing { key: key.clone(), base_revision: 0, deleted: false, moved_to: None, modified_at: 0, refs: BTreeMap::new(), content: json!({ "value": "an old saved password" }) };
    assert_eq!(laptop.provider().push(vec![change]).await.unwrap(), [(key.clone(), Pushed::Conflict)]);
    assert_eq!(fake.raw("DB_PASSWORD").as_deref(), Some("the real one"));

    laptop.engine.sync_all().await.unwrap();
    assert_eq!(laptop.value("s1").as_deref(), Some("the real one"));
    assert_eq!(fake.raw("DB_PASSWORD").as_deref(), Some("the real one"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_secret_deleted_in_doppler_keeps_its_last_value_and_fran_never_deletes_there() {
    let (fake, url) = start().await;
    fake.put("DB_PASSWORD", "hunter2");
    fake.put("KEEP_ME", "still needed elsewhere");
    let laptop = Computer::new(&url, TOKEN).await;
    laptop.link("s1", "DB_PASSWORD", None).await;
    laptop.link("s2", "KEEP_ME", None).await;
    laptop.engine.sync_all().await.unwrap();

    fake.remove("DB_PASSWORD");
    laptop.engine.sync_all().await.unwrap();
    assert_eq!(laptop.value("s1").as_deref(), Some("hunter2"));
    assert_eq!(laptop.problems(), [(secret_value_key("s1"), ProblemReason::Missing)]);

    // Deleting the secret in Fran removes the link and the local value only.
    let stores = laptop.engine.stores();
    stores
        .secrets
        .update(|file| {
            file.secrets.retain(|secret| secret.id != "s2");
            Ok(())
        })
        .unwrap();
    stores.vault.remove(&vault_id("s2")).unwrap();
    laptop.noticed().await;
    laptop.engine.sync_all().await.unwrap();
    assert_eq!(fake.raw("KEEP_ME").as_deref(), Some("still needed elsewhere"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_secret_built_from_other_secrets_cant_be_changed_from_fran() {
    let (fake, url) = start().await;
    fake.put_computed("DATABASE_URL", "postgres://${DB_HOST}/shop", "postgres://db.internal/shop");
    let laptop = Computer::new(&url, TOKEN).await;
    laptop.link("s1", "DATABASE_URL", None).await;
    laptop.engine.sync_all().await.unwrap();
    assert_eq!(laptop.value("s1").as_deref(), Some("postgres://db.internal/shop"));
    assert_eq!(laptop.problems(), [(secret_value_key("s1"), ProblemReason::Computed)]);

    laptop.edit("s1", "postgres://elsewhere/shop").await;
    laptop.engine.sync_all().await.unwrap();
    assert_eq!(fake.raw("DATABASE_URL").as_deref(), Some("postgres://${DB_HOST}/shop"));
    assert_eq!(laptop.value("s1").as_deref(), Some("postgres://db.internal/shop"));
    assert_eq!(laptop.replaced(), [(secret_value_key("s1"), "postgres://elsewhere/shop".to_string())]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rate_limited_request_waits_and_goes_through() {
    let (fake, url) = start().await;
    fake.put("DB_PASSWORD", "hunter2");
    let laptop = Computer::new(&url, TOKEN).await;
    laptop.link("s1", "DB_PASSWORD", None).await;
    *fake.limited.lock().unwrap() = 1;
    laptop.engine.sync_all().await.unwrap();
    assert_eq!(laptop.value("s1").as_deref(), Some("hunter2"));
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_but_a_linked_secret_can_be_sent_to_doppler() {
    let (fake, url) = start().await;
    let laptop = Computer::new(&url, TOKEN).await;
    let doppler = Some(Target::Cloud(laptop.cloud.clone()));
    for category in Category::ALL {
        assert!(laptop.engine.set_category_route(category, doppler.clone()).await.is_err(), "{category:?}");
    }

    let stores = laptop.engine.stores();
    let profile: ConnectionProfile = serde_json::from_value(json!({ "id": "c1", "name": "Prod", "kind": "sqlite", "options": { "path": "/srv/prod.db" } })).unwrap();
    stores
        .connections
        .update(|file| {
            file.connections.push(profile);
            Ok(())
        })
        .unwrap();
    stores.vault.set("connection:c1:password", "a connection's own password").unwrap();
    stores.vault.set(&vault_id("s9"), "a secret that isn't linked").unwrap();
    laptop.noticed().await;
    let unlinked = secret_value_key("s9");
    for key in ["connection:c1", "vault:connection:c1:password", unlinked.as_str()] {
        assert!(laptop.engine.set_item_routes(vec![key.to_string()], doppler.clone()).await.is_err(), "{key}");
    }
    laptop.engine.sync_all().await.unwrap();
    assert!(fake.secrets.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_doppler_no_longer_accepts_asks_for_a_new_one() {
    let (fake, url) = start().await;
    fake.put("DB_PASSWORD", "hunter2");
    let laptop = Computer::new(&url, "dp.st.prd.revoked").await;
    laptop.link("s1", "DB_PASSWORD", None).await;
    let error = laptop.engine.sync_all().await.unwrap_err();
    assert!(matches!(error.detail, ErrorDetail::SyncSignedOut), "{error:?}");
    assert_eq!(laptop.value("s1"), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_service_token_names_its_own_config_and_other_tokens_list_projects() {
    let (fake, url) = start().await;
    let client = Client::at(&url, TOKEN).unwrap();
    assert_eq!(client.own_place().await.unwrap(), None);
    let projects = client.projects().await.unwrap();
    assert_eq!(projects.iter().map(|project| project.slug.as_str()).collect::<Vec<_>>(), [PROJECT]);

    *fake.tied_to_config.lock().unwrap() = true;
    assert_eq!(client.own_place().await.unwrap(), Some(place()));
    assert!(Client::at(&url, "dp.st.prd.revoked").unwrap().own_place().await.is_err(), "a bad token is an error, not a form asking for a project");
}

/// Needs a token with write access. `FRAN_E2E_DOPPLER_PROJECT` and `FRAN_E2E_DOPPLER_CONFIG` are only needed when the token can't name its own config.
/// It creates one secret named `FRAN_E2E_<random>` and deletes it again.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_doppler_config_behaves_like_the_fake() {
    let Ok(token) = std::env::var("FRAN_E2E_DOPPLER_TOKEN") else {
        eprintln!("skipped: FRAN_E2E_DOPPLER_TOKEN isn't set");
        return;
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = Client::new(&token).unwrap();
    let place = match client.own_place().await.unwrap() {
        Some(place) => place,
        None => Place {
            project: std::env::var("FRAN_E2E_DOPPLER_PROJECT").expect("FRAN_E2E_DOPPLER_PROJECT, since the token doesn't name its config"),
            config: std::env::var("FRAN_E2E_DOPPLER_CONFIG").expect("FRAN_E2E_DOPPLER_CONFIG, since the token doesn't name its config"),
        },
    };
    let name = format!("FRAN_E2E_{}", uuid::Uuid::new_v4().simple().to_string().to_uppercase());

    assert!(client.set(&place, &name, "first", None).await.unwrap().is_ok());
    assert!(client.names(&place).await.unwrap().contains(&name));
    let read = client.secrets(&place, std::slice::from_ref(&name)).await.unwrap();
    assert_eq!(read.keys().collect::<Vec<_>>(), [&name], "only the name asked for comes back");
    assert_eq!((read[&name].value.as_str(), read[&name].computed), ("first", false));

    assert!(client.set(&place, &name, "second", Some("first")).await.unwrap().is_ok());
    let stale = client.set(&place, &name, "third", Some("first")).await.unwrap();
    assert!(stale.is_err(), "Doppler has to refuse a change based on a value it no longer holds");
    assert_eq!(client.secrets(&place, std::slice::from_ref(&name)).await.unwrap()[&name].value, "second");

    assert!(client.delete(&place, &name).await.unwrap().is_ok());
    assert!(!client.names(&place).await.unwrap().contains(&name));
}
