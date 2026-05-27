//! `disk-arcana-server` — production gRPC server binary.
//!
//! Wires the library surfaces shipped in DISK-0005 (P4) into a single boot
//! sequence: SQLite pool + migrations, AuthStore, AuditEmitter, ACL enforcer
//! with hot-reload watcher, Ops Bot audit forwarder (F-1), publisher-key
//! tombstone sweep (F-1), Enrollment + Auth + Sync gRPC services, and tonic
//! mTLS listener with graceful shutdown.
//!
//! Configuration comes from environment variables — see [`disk_server::config`].

#![forbid(unsafe_code)]

use std::sync::Arc;

use anyhow::Context;
use disk_proto::disk::{
    auth_service_server::AuthServiceServer, enrollment_service_server::EnrollmentServiceServer,
    sync_service_server::SyncServiceServer,
};
use disk_server::acl::reload::start_reload_loop;
use disk_server::audit;
use disk_server::enrollment::ca_client::{CaClient, HttpCaClient, StubCaClient};
use disk_server::multi_node;
use disk_server::{
    AclEnforcer, AuditEmitter, AuthServiceImpl, AuthStore, EnrollmentServiceImpl, NoopVerifier,
    ServerConfig, SyncServiceImpl,
};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cfg = ServerConfig::from_env().context("load ServerConfig from env")?;
    tracing::info!(
        bind = %cfg.bind_addr,
        db = %cfg.db_path.display(),
        sync_root = %cfg.sync_root.display(),
        acl = %cfg.acl_yaml_path.display(),
        stub_ca = cfg.use_stub_ca,
        "disk-arcana-server starting"
    );

    // SQLite pool + migrations from disk-core/migrations/.
    //
    // WAL must be set via SqliteConnectOptions *before* migrations run,
    // because `PRAGMA journal_mode = WAL;` is also issued in 001_init.sql and
    // sqlx wraps each migration in a transaction — `PRAGMA journal_mode`
    // cannot change WAL mode inside a transaction. Setting it on the
    // connection makes the in-migration PRAGMA a no-op. Same pattern as
    // `disk_core::meta_db::MetaDb::open`.
    let opts = SqliteConnectOptions::new()
        .filename(&cfg.db_path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await
        .with_context(|| format!("open sqlite pool at {}", cfg.db_path.display()))?;
    sqlx::migrate!("../disk-core/migrations")
        .run(&pool)
        .await
        .context("run sqlx migrations")?;
    tracing::info!("sqlx migrations applied");

    // Identity + audit infrastructure.
    let auth_store = AuthStore::new();
    let audit_emitter = AuditEmitter::new(pool.clone());

    // ACL enforcer — cold-boot unhealthy, default-deny per fail-closed contract
    // (PRD §10 + R-DIR-5). The reload loop heals state on first successful
    // YAML load.
    let acl_enforcer = AclEnforcer::new_unhealthy();

    // ACL hot-reload watcher (filesystem + SIGHUP). NoopVerifier today; a
    // production signing-verifier (e.g. GpgVerifier) is wired in a later round
    // of DISK-0006 once the operator chooses the signing toolchain.
    let verifier = Arc::new(NoopVerifier);
    let _reload_handle = start_reload_loop(
        cfg.acl_yaml_path.clone(),
        acl_enforcer.clone(),
        audit_emitter.clone(),
        verifier,
    );
    tracing::info!("acl reload loop spawned");

    // F-1: Ops Bot audit forwarder. `spawn` returns a no-op `Forwarder` when
    // `OPS_BOT_KEY` is unset (developer / dev-net deployments) — that branch is
    // still wired into the server so prod toggle is one env var away.
    let http = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .context("build reqwest client for ops_bot forwarder")?;
    let _forwarder = audit::ops_bot::spawn(http, cfg.ops_bot_url.clone());
    tracing::info!("ops_bot forwarder spawned");

    // F-1: Publisher-key tombstone sweep — background task removes stale
    // publisher signing keys (>30 days). JoinHandle is detached; task lives
    // until tokio runtime shutdown.
    let _tombstone_task = multi_node::lifecycle::spawn_tombstone_publisher(pool.clone());
    tracing::info!("tombstone publisher spawned");

    // Enrollment service. Production wires `HttpCaClient::from_env()` (real
    // CA); `DISK_USE_STUB_CA=1` overrides with `StubCaClient::ok` for
    // bootstrap deployments where AUTH-0085 is not yet live.
    let ca: Arc<dyn CaClient> = if cfg.use_stub_ca {
        tracing::warn!("DISK_USE_STUB_CA=1 — enrollment uses StubCaClient (test-only)");
        Arc::new(StubCaClient::ok(
            b"STUB-CERT-PEM\n".to_vec(),
            b"STUB-CHAIN-PEM\n".to_vec(),
        ))
    } else {
        Arc::new(HttpCaClient::from_env().context("HttpCaClient::from_env")?)
    };
    let mut enrollment_impl = EnrollmentServiceImpl::new(pool.clone(), audit_emitter.clone(), ca);
    if let Some(tok) = cfg.admin_token.clone() {
        enrollment_impl = enrollment_impl.with_admin_token(tok);
    }

    // gRPC service wrappers. EnrollmentServiceImpl is Clone (Arc-wrapped fields)
    // so we can host the same backing service on both listeners. Admin RPCs
    // remain gated by `require_admin()` metadata check — the public listener
    // returns PermissionDenied because external clients lack `x-disk-admin-token`.
    let auth_svc = AuthServiceServer::new(AuthServiceImpl::new(auth_store.clone()));
    let sync_svc = SyncServiceServer::new(SyncServiceImpl::with_acl(
        auth_store.clone(),
        cfg.sync_root.clone(),
        acl_enforcer.clone(),
        audit_emitter.clone(),
    ));
    let enroll_svc = EnrollmentServiceServer::new(enrollment_impl.clone());
    let enroll_svc_public = EnrollmentServiceServer::new(enrollment_impl);

    // Dual TLS configs: mTLS (with client_ca_root) for the private listener,
    // TLS-only (no client_ca_root) for the public enrollment listener so cold-
    // boot nodes without client certs can call `Enroll`.
    let tls_mtls = build_tls(&cfg)?;
    let tls_public = build_tls_public_only(&cfg)?;

    // Install signal handlers BEFORE logging "listening". The async runtime
    // does not poll the shutdown future until serve_with_shutdown enters its
    // select loop; between the listening log and the first poll, a stray
    // SIGTERM would otherwise be handled by libc default and kill the process
    // ungracefully (test asserts WEXITSTATUS == 0).
    let shutdown = make_shutdown_future().await?;

    // Fan out a single shutdown event to both listeners via a watch channel.
    // tonic's `serve_with_shutdown` consumes the future by-value, so the
    // shared signal must be replicated; using `watch::channel` keeps the
    // pattern self-contained without pulling in `futures::FutureExt::shared`.
    let (shutdown_tx, _) = watch::channel(false);
    let mut rx_mtls = shutdown_tx.subscribe();
    let mut rx_public = shutdown_tx.subscribe();
    tokio::spawn(async move {
        shutdown.await;
        let _ = shutdown_tx.send(true);
    });

    tracing::info!(addr = %cfg.bind_addr, "disk-arcana-server listening");
    tracing::info!(
        addr = %cfg.enrollment_bind_addr,
        "enrollment public listener listening"
    );

    let srv_mtls = Server::builder()
        .tls_config(tls_mtls)
        .context("apply ServerTlsConfig (mTLS)")?
        .add_service(auth_svc)
        .add_service(sync_svc)
        .add_service(enroll_svc)
        .serve_with_shutdown(cfg.bind_addr, async move {
            let _ = rx_mtls.changed().await;
        });

    let srv_public = Server::builder()
        .tls_config(tls_public)
        .context("apply ServerTlsConfig (public)")?
        .add_service(enroll_svc_public)
        .serve_with_shutdown(cfg.enrollment_bind_addr, async move {
            let _ = rx_public.changed().await;
        });

    tokio::try_join!(srv_mtls, srv_public).context("tonic listeners terminated with error")?;

    tracing::info!("disk-arcana-server shutdown complete");
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // Production daemons log to stderr (systemd / launchd capture stderr into
    // their journal; stdout is reserved for app data and accidental println).
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

fn build_tls(cfg: &ServerConfig) -> anyhow::Result<ServerTlsConfig> {
    let cert_pem = std::fs::read(&cfg.tls_cert_path)
        .with_context(|| format!("read {}", cfg.tls_cert_path.display()))?;
    let key_pem = std::fs::read(&cfg.tls_key_path)
        .with_context(|| format!("read {}", cfg.tls_key_path.display()))?;
    let ca_pem = std::fs::read(&cfg.tls_ca_path)
        .with_context(|| format!("read {}", cfg.tls_ca_path.display()))?;

    let identity = Identity::from_pem(cert_pem, key_pem);
    let ca = Certificate::from_pem(ca_pem);
    Ok(ServerTlsConfig::new().identity(identity).client_ca_root(ca))
}

/// TLS-only server config (no `client_ca_root`) for the public enrollment
/// listener. Cold-boot clients without an Arcanada-issued client certificate
/// rely on `EnrollmentService.Enroll`'s opaque-token bearer for authentication,
/// not on mTLS.
fn build_tls_public_only(cfg: &ServerConfig) -> anyhow::Result<ServerTlsConfig> {
    let cert_pem = std::fs::read(&cfg.tls_cert_path)
        .with_context(|| format!("read {}", cfg.tls_cert_path.display()))?;
    let key_pem = std::fs::read(&cfg.tls_key_path)
        .with_context(|| format!("read {}", cfg.tls_key_path.display()))?;
    let identity = Identity::from_pem(cert_pem, key_pem);
    Ok(ServerTlsConfig::new().identity(identity))
}

/// Install signal handlers synchronously and return a future that resolves on
/// the first SIGTERM or SIGINT. Installation happens here (sync) so the kernel
/// queues signals into the streams before the future is awaited — closing the
/// window where a stray SIGTERM between «listening» log and the first poll of
/// the future would invoke libc's default handler and kill the process.
#[cfg(unix)]
async fn make_shutdown_future(
) -> anyhow::Result<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    Ok(Box::pin(async move {
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM received, draining"),
            _ = sigint.recv() => tracing::info!("SIGINT received, draining"),
        }
    }))
}

#[cfg(not(unix))]
async fn make_shutdown_future(
) -> anyhow::Result<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> {
    Ok(Box::pin(async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "ctrl_c handler failed; shutting down anyway");
        }
    }))
}
