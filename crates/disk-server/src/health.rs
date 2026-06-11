//! Minimal HTTP health listener for external monitoring.
//!
//! Binds to `DISK_HEALTH_BIND_ADDR` (default `0.0.0.0:9446`) and exposes a
//! single `GET /health` route that returns `200 {"status":"ok","version":"x.y.z"}`.
//!
//! This listener is intentionally plain HTTP (no TLS) because it is fronted by
//! Cloudflare proxy on port 443. The gRPC mTLS listener (`:9443`) is separate.

use std::net::SocketAddr;

use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

/// Start the health HTTP server. Returns an error if the bind fails; otherwise
/// drives the server until the provided `shutdown` future resolves.
///
/// Spawn as a parallel tokio task alongside the gRPC server alongside gRPC:
/// ```text
/// tokio::spawn(disk_server::health::serve(addr, shutdown_rx));
/// ```
pub async fn serve(
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let app = Router::new().route("/health", get(health_handler));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("health listener bind {addr}: {e}"))?;

    tracing::info!(addr = %addr, "health HTTP listener ready");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|e| anyhow::anyhow!("health server error: {e}"))
}

async fn health_handler() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    /// Bind to an ephemeral port, start the health server, query /health, verify
    /// the response is 200 with the expected JSON shape.
    #[tokio::test]
    async fn health_endpoint_returns_200() {
        // Pick an ephemeral port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener); // release so `serve` can re-bind

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            serve(addr, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });

        // Give the listener a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let url = format!("http://{addr}/health");
        let resp = reqwest::get(&url).await.expect("request failed");
        assert_eq!(resp.status(), 200, "expected HTTP 200");
        let body: serde_json::Value = resp.json().await.expect("json parse failed");
        assert_eq!(body["status"], "ok", "expected status=ok");
        assert!(
            body["version"].is_string(),
            "expected version string in response"
        );

        // Clean shutdown.
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn health_handler_returns_version() {
        let Json(body) = health_handler().await;
        assert_eq!(body["status"], "ok");
        let version = body["version"].as_str().expect("version must be a string");
        assert!(!version.is_empty(), "version must be non-empty");
    }
}
