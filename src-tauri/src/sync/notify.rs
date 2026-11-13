use tokio::sync::Notify;

static CHANGED: Notify = Notify::const_new();

pub fn changed() {
    CHANGED.notify_one();
}

pub async fn wait() {
    CHANGED.notified().await;
}
