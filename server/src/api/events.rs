use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use sync_proto::Event;
use tokio::sync::broadcast::error::RecvError;

use crate::auth::Session;
use crate::db::now;
use crate::state::{AppState, Notice};

const SESSION_CHECK_EVERY: Duration = Duration::from_secs(60);

pub async fn connect(State(state): State<AppState>, session: Session, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| run(state, session, socket))
}

async fn send_cursor(socket: &mut WebSocket, cursor: u64) -> bool {
    let Ok(text) = serde_json::to_string(&Event::Changed { cursor }) else {
        return false;
    };
    socket.send(Message::Text(text.into())).await.is_ok()
}

async fn send_current(state: &AppState, session: &Session, socket: &mut WebSocket) -> bool {
    match state.db.change_seq(&session.user_id).await {
        Ok(cursor) => send_cursor(socket, cursor).await,
        Err(_) => false,
    }
}

async fn still_signed_in(state: &AppState, session: &Session) -> bool {
    state.db.session_exists(&session.id, now()).await.unwrap_or(false)
}

// Only cursors go out here, never records.
async fn run(state: AppState, session: Session, mut socket: WebSocket) {
    let mut notices = state.notices.subscribe();
    let mut check = tokio::time::interval(SESSION_CHECK_EVERY);
    // Sent once at the start, so a change between the client's pull and this connection isn't missed.
    if !send_current(&state, &session, &mut socket).await {
        return;
    }
    loop {
        let open = tokio::select! {
            notice = notices.recv() => match notice {
                Ok(Notice::Changed { user_id, cursor }) if *user_id == *session.user_id => send_cursor(&mut socket, cursor).await,
                Ok(Notice::SessionsChanged { user_id }) if *user_id == *session.user_id => still_signed_in(&state, &session).await,
                Ok(_) => true,
                Err(RecvError::Lagged(_)) => send_current(&state, &session, &mut socket).await,
                Err(RecvError::Closed) => false,
            },
            message = socket.recv() => matches!(message, Some(Ok(message)) if !matches!(message, Message::Close(_))),
            _ = check.tick() => still_signed_in(&state, &session).await,
        };
        if !open {
            break;
        }
    }
    let _ = socket.send(Message::Close(None)).await;
}
