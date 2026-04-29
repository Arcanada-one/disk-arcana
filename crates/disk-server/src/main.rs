#![forbid(unsafe_code)]

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let version = env!("CARGO_PKG_VERSION");
    tracing::info!("disk-arcana-server v{version} (Phase 3 gRPC)");
    println!("disk-arcana-server v{version} — use disk.toml to configure");
}
