use std::sync::Arc;

use serde::Serialize;
use tauri::State;
use zeroize::Zeroizing;

use super::client::{Client, Project};
use super::{Config, Doppler, check, token, token_id};
use crate::error::{AppError, AppResult};
use crate::sync::engine::Engine;
use crate::sync::providers::CloudKind;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenInfo {
    /// Set when the token is tied to one config and Doppler said which.
    project: Option<String>,
    config: Option<String>,
    /// What the token can see. Empty for a token that can't list projects, and then both are typed in.
    projects: Vec<Project>,
}

fn opened(engine: &Engine, cloud_id: &str) -> AppResult<Doppler> {
    let cloud = engine.cloud(cloud_id)?;
    if cloud.kind != CloudKind::Doppler {
        return Err(AppError::general("That cloud isn't a Doppler config"));
    }
    let stores = engine.stores();
    let client = Client::new(&token(cloud_id, &stores.vault)?)?;
    Doppler::with(&cloud, client, stores.vault.clone(), stores.secrets.clone())
}

/// The first step of adding a Doppler cloud: what this token is for, or what it can pick from.
#[tauri::command]
pub async fn doppler_check_token(token: String) -> AppResult<TokenInfo> {
    let token = Zeroizing::new(token);
    let client = Client::new(&token)?;
    if let Some(place) = client.own_place().await? {
        return Ok(TokenInfo { project: Some(place.project), config: Some(place.config), projects: Vec::new() });
    }
    // A token tied to one config can't list projects. That isn't an error, the form asks for both names instead.
    let projects = client.projects().await.unwrap_or_default();
    Ok(TokenInfo { project: None, config: None, projects })
}

#[tauri::command]
pub async fn doppler_configs(token: String, project: String) -> AppResult<Vec<String>> {
    let token = Zeroizing::new(token);
    Client::new(&token)?.configs(project.trim()).await
}

/// Adds the cloud, or puts a new token on one this computer already has for that project and config.
#[tauri::command]
pub async fn doppler_add(engine: State<'_, Arc<Engine>>, token: String, project: String, config: String, name: String) -> AppResult<String> {
    let token = Zeroizing::new(token);
    let checked = check(&Client::new(&token)?, &token, &project, &config).await?;
    let name = if name.trim().is_empty() { format!("Doppler {}/{}", checked.config.project, checked.config.config) } else { name.trim().to_string() };
    let vault = engine.stores().vault.clone();
    let saved = serde_json::to_value(&checked.config)?;
    engine.add_cloud(CloudKind::Doppler, &name, checked.config.identity(), saved, |cloud_id| checked.save(cloud_id, &vault)).await
}

/// Replaces the token of a cloud that's already here. It has to open the same project and config.
#[tauri::command]
pub async fn doppler_set_token(engine: State<'_, Arc<Engine>>, cloud_id: String, token: String) -> AppResult<()> {
    let token = Zeroizing::new(token);
    let cloud = engine.cloud(&cloud_id)?;
    if cloud.kind != CloudKind::Doppler {
        return Err(AppError::general("That cloud isn't a Doppler config"));
    }
    let config = Config::of(&cloud)?;
    let client = Client::new(&token)?;
    if let Some(place) = client.own_place().await?
        && place != config.place()
    {
        return Err(AppError::general(format!("That token is for {}/{}, not {}/{}", place.project, place.config, config.project, config.config)));
    }
    let checked = check(&client, &token, &config.project, &config.config).await?;
    engine.stores().vault.set(&token_id(&cloud_id), &checked.token)?;
    engine.wake(Some(&cloud_id));
    Ok(())
}

/// The names in the config, for the picker. Values never come this way.
#[tauri::command]
pub async fn doppler_names(engine: State<'_, Arc<Engine>>, cloud_id: String) -> AppResult<Vec<String>> {
    opened(&engine, &cloud_id)?.names().await
}

/// Only ever called from the tick box in the delete confirm.
#[tauri::command]
pub async fn doppler_delete_secret(engine: State<'_, Arc<Engine>>, cloud_id: String, name: String) -> AppResult<()> {
    opened(&engine, &cloud_id)?.delete(name.trim()).await
}
