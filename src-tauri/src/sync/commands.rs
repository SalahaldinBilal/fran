use std::sync::Arc;

use tauri::{AppHandle, Emitter, State};

use super::engine::{Engine, Events, MoveCandidate, SyncView};
use super::state::{Category, Target};
use crate::error::AppResult;

pub const CHANGED_EVENT: &str = "sync-changed";
pub const APPLIED_EVENT: &str = "sync-applied";

pub struct WindowEvents(pub AppHandle);

impl Events for WindowEvents {
    fn changed(&self) {
        let _ = self.0.emit(CHANGED_EVENT, ());
    }

    fn applied(&self, kinds: &[String]) {
        let _ = self.0.emit(APPLIED_EVENT, kinds);
    }
}

#[tauri::command]
pub async fn sync_get(engine: State<'_, Arc<Engine>>) -> AppResult<SyncView> {
    engine.view()
}

#[tauri::command]
pub async fn sync_now(engine: State<'_, Arc<Engine>>, cloud_id: Option<String>) -> AppResult<()> {
    engine.wake(cloud_id.as_deref());
    Ok(())
}

/// After a failed connect: fetches linked values again and says whether one changed, so the connect is worth one more try.
#[tauri::command]
pub async fn sync_refresh_linked(engine: State<'_, Arc<Engine>>) -> AppResult<bool> {
    engine.refresh_linked().await
}

#[tauri::command]
pub async fn sync_remove_cloud(engine: State<'_, Arc<Engine>>, cloud_id: String) -> AppResult<()> {
    engine.remove_cloud(&cloud_id).await
}

#[tauri::command]
pub async fn sync_rename_cloud(engine: State<'_, Arc<Engine>>, cloud_id: String, name: String) -> AppResult<()> {
    engine.rename_cloud(&cloud_id, &name).await
}

#[tauri::command]
pub async fn sync_set_category_route(engine: State<'_, Arc<Engine>>, category: Category, target: Option<Target>) -> AppResult<()> {
    engine.set_category_route(category, target).await
}

#[tauri::command]
pub async fn sync_use_for_everything(engine: State<'_, Arc<Engine>>, cloud_id: String) -> AppResult<()> {
    engine.use_for_everything(&cloud_id).await
}

#[tauri::command]
pub async fn sync_set_group_route(engine: State<'_, Arc<Engine>>, group: String, target: Option<Target>) -> AppResult<()> {
    engine.set_group_route(group, target).await
}

#[tauri::command]
pub async fn sync_set_item_routes(engine: State<'_, Arc<Engine>>, keys: Vec<String>, target: Option<Target>) -> AppResult<()> {
    engine.set_item_routes(keys, target).await
}

#[tauri::command]
pub async fn sync_move_candidates(engine: State<'_, Arc<Engine>>, key: String, cloud_id: String) -> AppResult<Vec<MoveCandidate>> {
    engine.move_candidates(&key, &cloud_id)
}

#[tauri::command]
pub async fn sync_restore_replaced(engine: State<'_, Arc<Engine>>, id: String) -> AppResult<()> {
    engine.restore_replaced(&id).await
}

#[tauri::command]
pub async fn sync_discard_replaced(engine: State<'_, Arc<Engine>>, id: Option<String>) -> AppResult<()> {
    engine.discard_replaced(id.as_deref()).await
}

/// `ids` None settles all of them.
#[tauri::command]
pub async fn sync_settle_duplicates(engine: State<'_, Arc<Engine>>, ids: Option<Vec<String>>, merge: bool) -> AppResult<()> {
    engine.settle_duplicates(ids, merge).await
}
