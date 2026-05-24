//! `POST /sync` + `POST /config/reload` handlers.
//!
//! Both endpoints are non-blocking signal channels: they enqueue one `()`
//! on the corresponding `mpsc::Sender` and return immediately. The actual
//! sync iteration / config reload work happens elsewhere (the daemon
//! scheduler / config watcher own the receiver halves).
//!
//! Response semantics:
//! - `202 Accepted` + `{"queued": true}` — signal accepted, listener has
//!   capacity.
//! - `503 Service Unavailable` + `{"queued": false}` — channel buffer
//!   full (back-pressure) or receiver dropped. The caller is expected to
//!   back off; we explicitly do NOT block the request so the REST surface
//!   stays responsive under load.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use tokio::sync::mpsc::error::TrySendError;

use super::{AcceptedResponse, DaemonState};

pub async fn post_sync(State(state): State<DaemonState>) -> impl IntoResponse {
    enqueue_signal(state.manual_sync_sender())
}

pub async fn post_config_reload(State(state): State<DaemonState>) -> impl IntoResponse {
    enqueue_signal(state.reload_sender())
}

fn enqueue_signal(sender: tokio::sync::mpsc::Sender<()>) -> (StatusCode, Json<AcceptedResponse>) {
    match sender.try_send(()) {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(AcceptedResponse { queued: true }),
        ),
        Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(AcceptedResponse { queued: false }),
        ),
    }
}
