use std::collections::HashSet;

use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, Request, State};
use serde::Deserialize;
use sync_proto::{Limits, PushRequest, PushResponse, RecordsPage, is_record_id};

use super::push_body_bytes;
use crate::auth::{Session, signed_in_user};
use crate::db::now;
use crate::error::{AppError, AppResult};
use crate::state::{AppState, Notice};

const DEFAULT_PAGE_RECORDS: u64 = 500;
const PAGE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Deserialize)]
pub struct PullQuery {
    since: Option<u64>,
    limit: Option<u64>,
}

pub async fn pull(State(state): State<AppState>, session: Session, query: Result<Query<PullQuery>, QueryRejection>) -> AppResult<Json<RecordsPage>> {
    let Query(query) = query.map_err(|_| AppError::bad_request("since and limit must be whole numbers"))?;
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_RECORDS).clamp(1, state.settings().limits.batch_records.max(1));
    let pulled = state.db.pull(&session.user_id, query.since.unwrap_or(0), limit, PAGE_BYTES).await?;
    Ok(Json(RecordsPage { records: pulled.records, cursor: pulled.cursor, more: pulled.more }))
}

pub async fn push(State(state): State<AppState>, session: Session, request: Request) -> AppResult<Json<PushResponse>> {
    let settings = state.settings();
    let user = signed_in_user(&state, &session).await?;
    let limits = Limits { account_bytes: settings.quota_for(user.quota_bytes), ..settings.limits };
    let body = axum::body::to_bytes(request.into_body(), push_body_bytes(&limits)).await.map_err(|_| AppError::too_large("The request is too big"))?;
    let request: PushRequest = serde_json::from_slice(&body).map_err(|_| AppError::bad_request("The request isn't valid"))?;
    if request.records.len() as u64 > limits.batch_records {
        return Err(AppError::too_large("Too many records in one push"));
    }
    let mut seen = HashSet::new();
    for record in &request.records {
        if !is_record_id(&record.id) {
            return Err(AppError::bad_request("A record id isn't valid"));
        }
        if !seen.insert(record.id.as_str()) {
            return Err(AppError::bad_request("A record is in the push twice"));
        }
    }
    let pushed = state.db.push(&session.user_id, &request.records, &limits, settings.server_bytes, now()).await?;
    if pushed.changed {
        let _ = state.notices.send(Notice::Changed { user_id: session.user_id.as_str().into(), cursor: pushed.cursor });
    }
    Ok(Json(PushResponse { results: pushed.results, cursor: pushed.cursor }))
}
