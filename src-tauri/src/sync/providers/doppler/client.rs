use std::collections::BTreeMap;
use std::time::Duration;

use reqwest::{RequestBuilder, StatusCode, Url};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult, ErrorDetail};

const API: &str = "https://api.doppler.com";
const TIMEOUT: Duration = Duration::from_secs(30);
const NAMES_PER_REQUEST: usize = 100;
const PER_PAGE: usize = 100;
const MAX_PAGES: usize = 20;
const RATE_LIMIT_TRIES: usize = 3;
const LONGEST_WAIT: Duration = Duration::from_secs(20);
/// Doppler adds these to every config. They hold the project and config a token belongs to.
pub const PROJECT_SECRET: &str = "DOPPLER_PROJECT";
pub const CONFIG_SECRET: &str = "DOPPLER_CONFIG";

/// The project and config every secrets call is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    pub project: String,
    pub config: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub value: String,
    /// Built from other secrets, so it can only be edited in Doppler.
    pub computed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub slug: String,
    pub name: String,
}

pub enum Refused {
    /// The token can read but not write.
    ReadOnly,
    /// Doppler said no for another reason. Its own words, when it gave any.
    Other(String),
}

pub struct Failed {
    status: StatusCode,
    said: Option<String>,
}

impl Failed {
    fn into_error(self) -> AppError {
        match self.status {
            StatusCode::UNAUTHORIZED => AppError::new("Doppler didn't accept the token. Enter a new one.", ErrorDetail::SyncSignedOut),
            StatusCode::FORBIDDEN => AppError::general(self.said.unwrap_or_else(|| "This Doppler token isn't allowed to do that".to_string())),
            StatusCode::TOO_MANY_REQUESTS => AppError::general("Doppler is limiting requests from this token. It will be tried again."),
            status => AppError::general(self.said.map(|said| format!("Doppler: {said}")).unwrap_or_else(|| format!("Doppler answered with HTTP {status}"))),
        }
    }
}

#[derive(Deserialize)]
struct SecretBody {
    #[serde(default)]
    raw: Option<String>,
    #[serde(default)]
    computed: Option<String>,
}

#[derive(Deserialize)]
struct SecretsBody {
    #[serde(default)]
    secrets: BTreeMap<String, SecretBody>,
}

#[derive(Deserialize)]
struct NamesBody {
    #[serde(default)]
    names: Vec<String>,
}

#[derive(Deserialize)]
struct ProjectBody {
    #[serde(default)]
    slug: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct ProjectsBody {
    #[serde(default)]
    projects: Vec<ProjectBody>,
}

#[derive(Deserialize)]
struct ConfigBody {
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct ConfigsBody {
    #[serde(default)]
    configs: Vec<ConfigBody>,
}

// Doppler doesn't document its error body. This reads the shapes it's known to send and gives up quietly on anything else.
fn said(body: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(body).ok()?;
    let listed = parsed.get("messages").and_then(Value::as_array).map(|messages| messages.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "));
    let single = || parsed.get("message").or_else(|| parsed.get("error")).and_then(Value::as_str).map(str::to_string);
    listed.filter(|text| !text.is_empty()).or_else(single).map(|text| text.chars().take(300).collect())
}

fn wait_from(header: Option<&str>) -> Duration {
    let seconds = header.and_then(|value| value.trim().parse::<u64>().ok()).unwrap_or(1);
    Duration::from_secs(seconds.max(1)).min(LONGEST_WAIT)
}

/// Every request to Doppler goes through here. The host is fixed, a token is never sent anywhere else.
pub struct Client {
    http: reqwest::Client,
    base: String,
    token: Zeroizing<String>,
}

impl Client {
    pub fn new(token: &str) -> AppResult<Self> {
        Self::at(API, token)
    }

    pub(super) fn at(base: &str, token: &str) -> AppResult<Self> {
        let token = Zeroizing::new(token.trim().to_string());
        if token.is_empty() || token.chars().any(|character| character.is_control() || character.is_whitespace()) {
            return Err(AppError::general("Paste a Doppler token"));
        }
        let http = reqwest::Client::builder().timeout(TIMEOUT).build().map_err(|error| AppError::general(error.to_string()))?;
        Ok(Self { http, base: base.to_string(), token })
    }

    fn url(&self, path: &str, query: &[(&str, &str)]) -> AppResult<Url> {
        Url::parse_with_params(&format!("{}{path}", self.base), query).map_err(|_| AppError::general("Couldn't build the request to Doppler"))
    }

    async fn send(&self, build: impl Fn() -> RequestBuilder) -> AppResult<Result<String, Failed>> {
        for attempt in 1..=RATE_LIMIT_TRIES {
            let response = build().bearer_auth(self.token.as_str()).header("accept", "application/json").send().await.map_err(|error| {
                let reason = if error.is_timeout() { "it took too long to answer" } else { "it can't be reached" };
                AppError::general(format!("Couldn't reach Doppler: {reason}"))
            })?;
            let status = response.status();
            if status == StatusCode::TOO_MANY_REQUESTS && attempt < RATE_LIMIT_TRIES {
                let wait = wait_from(response.headers().get("retry-after").and_then(|value| value.to_str().ok()));
                tokio::time::sleep(wait).await;
                continue;
            }
            let body = response.text().await.map_err(|_| AppError::general("Doppler's answer was cut off"))?;
            return Ok(if status.is_success() { Ok(body) } else { Err(Failed { status, said: said(&body) }) });
        }
        Err(AppError::general("Doppler is limiting requests from this token. It will be tried again."))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str, query: &[(&str, &str)]) -> AppResult<T> {
        let url = self.url(path, query)?;
        let body = self.send(|| self.http.get(url.clone())).await?.map_err(Failed::into_error)?;
        serde_json::from_str(&body).map_err(|_| AppError::general("Doppler sent an answer this app can't read"))
    }

    /// Only the names asked for are fetched, never the rest of the config.
    pub async fn secrets(&self, place: &Place, names: &[String]) -> AppResult<BTreeMap<String, Remote>> {
        let mut found = BTreeMap::new();
        for chunk in names.chunks(NAMES_PER_REQUEST) {
            let wanted = chunk.join(",");
            let query = [("project", place.project.as_str()), ("config", place.config.as_str()), ("secrets", wanted.as_str())];
            let body: SecretsBody = self.get("/v3/configs/config/secrets", &query).await?;
            for (name, secret) in body.secrets.into_iter().filter(|(name, _)| chunk.contains(name)) {
                let Some(value) = secret.computed.clone().or_else(|| secret.raw.clone()) else {
                    continue;
                };
                let computed = matches!((&secret.raw, &secret.computed), (Some(raw), Some(computed)) if raw != computed);
                found.insert(name, Remote { value, computed });
            }
        }
        Ok(found)
    }

    /// A service token is tied to one config. Doppler's own managed secrets say which, when it lets the call through without naming one.
    pub async fn own_place(&self) -> AppResult<Option<Place>> {
        let wanted = format!("{PROJECT_SECRET},{CONFIG_SECRET}");
        let url = self.url("/v3/configs/config/secrets", &[("secrets", wanted.as_str()), ("include_managed_secrets", "true")])?;
        let body = match self.send(|| self.http.get(url.clone())).await? {
            Ok(body) => body,
            Err(failed) if failed.status == StatusCode::UNAUTHORIZED => return Err(failed.into_error()),
            Err(_) => return Ok(None),
        };
        let Ok(body) = serde_json::from_str::<SecretsBody>(&body) else {
            return Ok(None);
        };
        let value = |name: &str| body.secrets.get(name).and_then(|secret| secret.computed.clone().or_else(|| secret.raw.clone())).filter(|value| !value.is_empty());
        Ok(value(PROJECT_SECRET).zip(value(CONFIG_SECRET)).map(|(project, config)| Place { project, config }))
    }

    /// Names only. Doppler's own `DOPPLER_` secrets are left out.
    pub async fn names(&self, place: &Place) -> AppResult<Vec<String>> {
        let query = [("project", place.project.as_str()), ("config", place.config.as_str()), ("include_managed_secrets", "false")];
        let mut body: NamesBody = self.get("/v3/configs/config/secrets/names", &query).await?;
        body.names.sort();
        Ok(body.names)
    }

    pub async fn projects(&self) -> AppResult<Vec<Project>> {
        let per_page = PER_PAGE.to_string();
        let mut found = Vec::new();
        for page in 1..=MAX_PAGES {
            let page = page.to_string();
            let body: ProjectsBody = self.get("/v3/projects", &[("page", page.as_str()), ("per_page", per_page.as_str())]).await?;
            let count = body.projects.len();
            found.extend(body.projects.into_iter().filter(|project| !project.slug.is_empty()).map(|project| Project { slug: project.slug, name: project.name }));
            if count < PER_PAGE {
                break;
            }
        }
        Ok(found)
    }

    pub async fn configs(&self, project: &str) -> AppResult<Vec<String>> {
        let per_page = PER_PAGE.to_string();
        let mut found = Vec::new();
        for page in 1..=MAX_PAGES {
            let page = page.to_string();
            let body: ConfigsBody = self.get("/v3/configs", &[("project", project), ("page", page.as_str()), ("per_page", per_page.as_str())]).await?;
            let count = body.configs.len();
            found.extend(body.configs.into_iter().map(|config| config.name).filter(|name| !name.is_empty()));
            if count < PER_PAGE {
                break;
            }
        }
        Ok(found)
    }

    async fn change(&self, place: &Place, request: Value) -> AppResult<Result<(), Refused>> {
        let url = self.url("/v3/configs/config/secrets", &[])?;
        let body = json!({ "project": place.project, "config": place.config, "change_requests": [request] });
        match self.send(|| self.http.post(url.clone()).json(&body)).await? {
            Ok(_) => Ok(Ok(())),
            Err(failed) if failed.status == StatusCode::FORBIDDEN => Ok(Err(Refused::ReadOnly)),
            Err(failed) if failed.status.is_client_error() && failed.status != StatusCode::UNAUTHORIZED && failed.status != StatusCode::TOO_MANY_REQUESTS => {
                Ok(Err(Refused::Other(failed.said.unwrap_or_else(|| format!("HTTP {}", failed.status)))))
            }
            Err(failed) => Err(failed.into_error()),
        }
    }

    /// `original` is what the secret held when it was last read, None for one Doppler doesn't have yet. Doppler refuses the change when that no longer holds.
    pub async fn set(&self, place: &Place, name: &str, value: &str, original: Option<&str>) -> AppResult<Result<(), Refused>> {
        let request = match original {
            Some(original) => json!({ "name": name, "originalName": name, "value": value, "originalValue": original }),
            None => json!({ "name": name, "originalName": null, "value": value }),
        };
        self.change(place, request).await
    }

    pub async fn delete(&self, place: &Place, name: &str) -> AppResult<Result<(), Refused>> {
        self.change(place, json!({ "name": name, "originalName": name, "value": null, "shouldDelete": true })).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dopplers_own_words_are_read_from_the_error_shapes_it_sends() {
        assert_eq!(said(r#"{"messages":["Invalid Auth token"],"success":false}"#).as_deref(), Some("Invalid Auth token"));
        assert_eq!(said(r#"{"message":"Nope"}"#).as_deref(), Some("Nope"));
        assert_eq!(said("<html>502</html>"), None);
        assert_eq!(said("{}"), None);
    }

    #[test]
    fn a_rate_limit_wait_is_at_least_a_second_and_never_long() {
        assert_eq!(wait_from(Some("3")), Duration::from_secs(3));
        assert_eq!(wait_from(Some("0")), Duration::from_secs(1));
        assert_eq!(wait_from(Some("soon")), Duration::from_secs(1));
        assert_eq!(wait_from(None), Duration::from_secs(1));
        assert_eq!(wait_from(Some("3600")), LONGEST_WAIT);
    }

    #[test]
    fn a_token_with_a_line_break_is_refused_before_it_reaches_a_header() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        assert!(Client::new("dp.st.dev.abc\nx-evil: 1").is_err());
        assert!(Client::new("  ").is_err());
        assert!(Client::new(" dp.st.dev.abc ").is_ok());
    }
}
