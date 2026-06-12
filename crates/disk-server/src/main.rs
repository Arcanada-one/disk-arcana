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
    AclEnforcer, AuditEmitter, AuthServiceImpl, AuthStore, EnrollmentServiceImpl, GpgVerifier,
    NoopVerifier, ServerConfig, SyncServiceImpl,
};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
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

    // ACL hot-reload watcher (filesystem + SIGHUP).
    //
    // Production: `DISK_ACL_SIG_PATH` must be set to the detached `.asc`
    // signature file. When absent and `DISK_USE_STUB_CA` is not `1`, the
    // server refuses to start (fail-closed: public server must verify ACL).
    //
    // Dev/test: set `DISK_USE_STUB_CA=1` to allow NoopVerifier. Never use
    // NoopVerifier in a deployment reachable from the public internet.
    let _reload_handle = build_reload_handle(&cfg, acl_enforcer.clone(), audit_emitter.clone());
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

    // MetaDb for the sync service (DISK-0043): commit uploaded bytes + vector-clock
    // upsert. Opens a second WAL-mode connection against the same SQLite file — safe.
    let meta_db = disk_core::meta_db::MetaDb::open(&cfg.db_path)
        .await
        .with_context(|| format!("open MetaDb for sync service at {}", cfg.db_path.display()))?;

    // gRPC service wrappers.
    let auth_svc = AuthServiceServer::new(AuthServiceImpl::new(auth_store.clone()));
    let sync_svc = SyncServiceServer::new(
        SyncServiceImpl::with_acl(
            auth_store.clone(),
            cfg.sync_root.clone(),
            acl_enforcer.clone(),
            audit_emitter.clone(),
        )
        .with_meta_db(meta_db, "server"),
    );
    let enroll_svc = EnrollmentServiceServer::new(enrollment_impl);

    // mTLS: tonic-native identity + client CA root. The `tls13_mtls_server_config`
    // rustls helper remains in `disk_server::tls` for non-tonic consumers, but
    // here we prefer the tonic-native code path for graceful shutdown integration.
    let tls = build_tls(&cfg)?;

    // Install signal handlers BEFORE logging "listening". The async runtime
    // does not poll the shutdown future until serve_with_shutdown enters its
    // select loop; between the listening log and the first poll, a stray
    // SIGTERM would otherwise be handled by libc default and kill the process
    // ungracefully (test asserts WEXITSTATUS == 0).
    let (grpc_shutdown, health_shutdown) = make_shutdown_futures().await?;

    // Health HTTP server — plain HTTP on DISK_HEALTH_BIND_ADDR (default 0.0.0.0:9446).
    // Runs concurrently with the gRPC server; both shut down on SIGTERM/SIGINT.
    let health_addr = cfg.health_bind_addr;
    let _health_task = tokio::spawn(async move {
        if let Err(e) = disk_server::health::serve(health_addr, health_shutdown).await {
            tracing::error!(error = %e, "health server exited with error");
        }
    });

    // mTLS peer-cert propagation: bridge the verified client certificate from
    // the connection-level TlsConnectInfo into per-request extensions so the
    // ACL enforcer's cert-fingerprint lookup resolves a real identity. Without
    // this, CertIdentity::from_request is always None and ACL roles are never
    // enforced on the wire (fail-open). See middleware::peer_cert.
    use disk_server::middleware::propagate_peer_cert;

    tracing::info!(addr = %cfg.bind_addr, "disk-arcana-server listening");
    Server::builder()
        .tls_config(tls)
        .context("apply ServerTlsConfig")?
        .add_service(InterceptedService::new(auth_svc, propagate_peer_cert))
        .add_service(InterceptedService::new(sync_svc, propagate_peer_cert))
        .add_service(InterceptedService::new(enroll_svc, propagate_peer_cert))
        .serve_with_shutdown(cfg.bind_addr, grpc_shutdown)
        .await
        .context("tonic server terminated with error")?;

    tracing::info!("disk-arcana-server shutdown complete");
    Ok(())
}

/// Choose the ACL signature verifier based on config and start the reload loop.
///
/// - `DISK_ACL_SIG_PATH` set → GpgVerifier (production path).
/// - `DISK_ACL_SIG_PATH` absent + `DISK_USE_STUB_CA=1` → NoopVerifier (dev only).
/// - `DISK_ACL_SIG_PATH` absent + `DISK_USE_STUB_CA` unset → **panic** (fail-closed).
fn build_reload_handle(
    cfg: &ServerConfig,
    enforcer: AclEnforcer,
    audit: AuditEmitter,
) -> disk_server::ReloadHandle {
    match cfg.acl_sig_path.clone() {
        Some(sig_path) => {
            let mut v = GpgVerifier::new(sig_path);
            if let Some(ref gnupghome) = cfg.acl_gnupghome {
                v = v.with_gnupghome(gnupghome.clone());
            }
            tracing::info!(
                acl.verifier = "GpgVerifier",
                "acl signature verification active"
            );
            start_reload_loop(cfg.acl_yaml_path.clone(), enforcer, audit, Arc::new(v))
        }
        None => {
            if !cfg.use_stub_ca {
                panic!(
                    "DISK_ACL_SIG_PATH must be set in production. \
                     Set DISK_USE_STUB_CA=1 only for local development."
                );
            }
            tracing::warn!(
                acl.verifier = "NoopVerifier",
                "ACL signature verification DISABLED (dev mode)"
            );
            start_reload_loop(
                cfg.acl_yaml_path.clone(),
                enforcer,
                audit,
                Arc::new(NoopVerifier),
            )
        }
    }
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

type ShutdownFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// Install signal handlers synchronously and return two shutdown futures — one
/// for the gRPC server and one for the health HTTP server. Both resolve on the
/// first SIGTERM or SIGINT. Signal streams are installed here (sync) so the
/// kernel queues signals before the futures are awaited, closing the window
/// where a stray SIGTERM would invoke libc's default handler.
#[cfg(unix)]
async fn make_shutdown_futures() -> anyhow::Result<(ShutdownFuture, ShutdownFuture)> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("install SIGINT handler")?;

    // Broadcast the signal to both futures via a oneshot channel.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let grpc_shutdown: ShutdownFuture = Box::pin(async move {
        let _ = rx.await;
    });
    let health_shutdown: ShutdownFuture = Box::pin(async move {
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM received, draining"),
            _ = sigint.recv()  => tracing::info!("SIGINT received, draining"),
        }
        let _ = tx.send(());
    });
    Ok((grpc_shutdown, health_shutdown))
}

#[cfg(not(unix))]
async fn make_shutdown_futures() -> anyhow::Result<(ShutdownFuture, ShutdownFuture)> {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let grpc_shutdown: ShutdownFuture = Box::pin(async move {
        let _ = rx.await;
    });
    let health_shutdown: ShutdownFuture = Box::pin(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "ctrl_c handler failed; shutting down anyway");
        }
        let _ = tx.send(());
    });
    Ok((grpc_shutdown, health_shutdown))
}
