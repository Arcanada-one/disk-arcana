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
use disk_server::config::CaMode;
use disk_server::enrollment::ca_client::{CaClient, HttpCaClient, OfflineCaClient, StubCaClient};
use disk_server::multi_node;
use disk_server::{
    AclEnforcer, AuditEmitter, AuthServiceImpl, AuthStore, EnrollmentServiceImpl, GpgVerifier,
    NoopVerifier, ServerConfig, SyncServiceImpl,
};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tokio::sync::watch;
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

    // DISK-0063: ensure the sync-root exists before any request hits the
    // SyncService. `path_guard::validate` canonicalizes `self.root`, and
    // `canonicalize()` on a non-existent directory returns OutsideRoot — which
    // silently rejects EVERY `delta_upload` with `invalid_argument "path guard"`
    // on the first chunk. A freshly-provisioned host (DB reprovisioned, sync-root
    // not yet created) would otherwise have all uploads fail invisibly. Creating
    // it here (idempotent, mirrors the DB's `create_if_missing`) closes that gap.
    std::fs::create_dir_all(&cfg.sync_root)
        .with_context(|| format!("create sync_root at {}", cfg.sync_root.display()))?;

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

    // Enrollment CA client — selected by DISK_CA_MODE (or legacy DISK_USE_STUB_CA).
    //
    // - Http (default): real Auth Arcana CA. Requires AUTH_ARCANA_CA_TOKEN.
    // - Stub: fixed cert pair. Dev/test only (DISK_USE_STUB_CA=1 or DISK_CA_MODE=stub).
    // - Offline (DISK-0058): Approach A-a — leaf certs pre-provisioned offline.
    //   OfflineCaClient returns EnrollmentDisabled on any issue_cert call.
    //   The enrollment public listener is not bound in this mode (see below).
    let ca: Arc<dyn CaClient> = select_ca_client(&cfg).context("select CA client")?;
    let mut enrollment_impl = EnrollmentServiceImpl::new(pool.clone(), audit_emitter.clone(), ca);
    if let Some(tok) = cfg.admin_token.clone() {
        enrollment_impl = enrollment_impl.with_admin_token(tok);
    }

    // MetaDb for the sync service (DISK-0043): commit uploaded bytes + vector-clock
    // upsert. Opens a second WAL-mode connection against the same SQLite file — safe.
    let control_meta = disk_core::meta_db::MetaDb::open(&cfg.db_path)
        .await
        .with_context(|| format!("open MetaDb for sync service at {}", cfg.db_path.display()))?;

    let meta_router = match &cfg.tenant_db_dir {
        Some(dir) => disk_core::TenantMetaRouter::split(control_meta.clone(), dir.clone()),
        None => disk_core::TenantMetaRouter::single(control_meta.clone()),
    };

    let quota_enforcer = if cfg.billing_mode.is_active() {
        Some(
            disk_server::QuotaEnforcer::new(cfg.billing_mode, meta_router.clone())
                .context("init QuotaEnforcer")?,
        )
    } else {
        None
    };

    let webhook_state = if cfg.billing_mode == disk_server::BillingMode::Stripe {
        let require_sig = std::env::var("DISK_STRIPE_WEBHOOK_REQUIRE_SIG")
            .ok()
            .as_deref()
            != Some("0");
        if require_sig && cfg.stripe_webhook_secret.is_none() {
            anyhow::bail!(
                "DISK_STRIPE_WEBHOOK_SECRET is required when DISK_BILLING_MODE=stripe \
                 and DISK_STRIPE_WEBHOOK_REQUIRE_SIG is not 0"
            );
        }
        let tolerance = std::env::var("DISK_STRIPE_WEBHOOK_TOLERANCE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(disk_server::billing::webhook::DEFAULT_STRIPE_TOLERANCE_SECS);
        Some(Arc::new(disk_server::WebhookState {
            mode: cfg.billing_mode,
            meta_db: meta_router.control(),
            webhook_secret: cfg.stripe_webhook_secret.clone(),
            signature_tolerance_secs: tolerance,
            require_signature_header: require_sig,
        }))
    } else {
        None
    };

    let auth_state = if cfg.auth_mode.is_active() {
        let key = cfg
            .jwt_signing_key
            .clone()
            .expect("jwt key checked in ServerConfig::from_env");
        Some(Arc::new(disk_server::AuthHttpState {
            meta_db: meta_router.control(),
            signing_key: key.into_bytes(),
            token_ttl_secs: cfg.jwt_ttl_secs,
        }))
    } else {
        None
    };

    // gRPC service wrappers. EnrollmentServiceImpl is Clone (Arc-wrapped fields)
    // so we can host the same backing service on both listeners (DISK-0037).
    // Admin RPCs remain gated by `require_admin()` metadata check — the public
    // listener returns PermissionDenied because external clients lack
    // `x-disk-admin-token`.
    let auth_svc = AuthServiceServer::new({
        let mut auth_impl = AuthServiceImpl::new(auth_store.clone()).with_register_gate(
            cfg.register_node_mode,
            pool.clone(),
            cfg.admin_token.clone(),
        );
        if let Some(ref enforcer) = quota_enforcer {
            auth_impl = auth_impl.with_quota_enforcer(enforcer.clone());
        }
        auth_impl = auth_impl.with_meta_db(meta_router.control());
        auth_impl
    });
    let sync_svc = SyncServiceServer::new({
        let mut sync_impl = SyncServiceImpl::with_acl(
            auth_store.clone(),
            cfg.sync_root.clone(),
            acl_enforcer.clone(),
            audit_emitter.clone(),
        )
        .with_meta_router(meta_router, "server");
        if let Some(enforcer) = quota_enforcer {
            sync_impl = sync_impl.with_quota_enforcer(enforcer);
        }
        sync_impl
    });
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
    let (grpc_shutdown, health_shutdown) = make_shutdown_futures().await?;

    // Health HTTP server — plain HTTP on DISK_HEALTH_BIND_ADDR (default 0.0.0.0:9446).
    // Runs concurrently with the gRPC server; both shut down on SIGTERM/SIGINT.
    let health_addr = cfg.health_bind_addr;
    let _health_task = tokio::spawn(async move {
        if let Err(e) =
            disk_server::health::serve(health_addr, webhook_state, auth_state, health_shutdown)
                .await
        {
            tracing::error!(error = %e, "health server exited with error");
        }
    });

    // mTLS peer-cert propagation: bridge the verified client certificate from
    // the connection-level TlsConnectInfo into per-request extensions so the
    // ACL enforcer's cert-fingerprint lookup resolves a real identity. Without
    // this, CertIdentity::from_request is always None and ACL roles are never
    // enforced on the wire (fail-open). See middleware::peer_cert.
    use disk_server::middleware::propagate_peer_cert;

    // Fan out a single shutdown event to both gRPC listeners via a watch
    // channel. tonic's `serve_with_shutdown` consumes the future by-value, so
    // the shared signal must be replicated; using `watch::channel` keeps the
    // pattern self-contained without pulling in `futures::FutureExt::shared`.
    // `grpc_shutdown` resolves on the first SIGTERM/SIGINT (the health server's
    // `health_shutdown` future drives the same oneshot); when it fires we
    // broadcast `true` to both `rx_mtls` and `rx_public`.
    let (shutdown_tx, _) = watch::channel(false);
    let mut rx_mtls = shutdown_tx.subscribe();
    let mut rx_public = shutdown_tx.subscribe();
    tokio::spawn(async move {
        grpc_shutdown.await;
        let _ = shutdown_tx.send(true);
    });

    // Bind both listeners BEFORE logging "listening" so the log reflects a real
    // socket, not just the configured address. tonic's `serve_with_shutdown`
    // logs the configured addr before it actually binds, which makes a bind
    // failure (e.g. port already taken) invisible to anything watching the log
    // — a test that keys off the "listening" line then races a half-bound
    // server. `TcpIncoming::bind` fails synchronously here if the port is taken.
    use tonic::transport::server::TcpIncoming;
    let incoming_mtls = TcpIncoming::bind(cfg.bind_addr)
        .with_context(|| format!("bind mTLS listener on {}", cfg.bind_addr))?;

    tracing::info!(addr = %cfg.bind_addr, "disk-arcana-server listening");

    // Private mTLS listener: auth + sync + enroll, each wrapped in the
    // peer-cert propagation interceptor (DISK-0043 a027937) so the ACL
    // enforcer resolves a real client-cert fingerprint per request. Dropping
    // the interceptor here re-opens the ACL fail-open hole.
    let srv_mtls = Server::builder()
        .tls_config(tls_mtls)
        .context("apply ServerTlsConfig (mTLS)")?
        .add_service(InterceptedService::new(auth_svc, propagate_peer_cert))
        .add_service(InterceptedService::new(sync_svc, propagate_peer_cert))
        .add_service(InterceptedService::new(enroll_svc, propagate_peer_cert))
        .serve_with_incoming_shutdown(incoming_mtls, async move {
            let _ = rx_mtls.changed().await;
        });

    if cfg.ca_mode == CaMode::Offline {
        // Offline CA mode (DISK-0058, Approach A-a): enrollment endpoint is
        // disabled — leaf certs were pre-provisioned, no runtime CA contact.
        // The public enrollment listener is NOT bound to reduce attack surface.
        tracing::info!(
            "DISK_CA_MODE=offline — enrollment public listener suppressed (Approach A-a)"
        );
        // Drop the watch receiver so the channel closes cleanly.
        drop(rx_public);
        // Run only the mTLS listener.
        srv_mtls
            .await
            .context("mTLS listener terminated with error")?;
    } else {
        // Public TLS-only enrollment listener (DISK-0037): cold-boot nodes without
        // a client cert reach `Enroll` here, gated by opaque-token bearer. No ACL
        // interceptor — there is no client cert to propagate on this listener.
        let incoming_public = TcpIncoming::bind(cfg.enrollment_bind_addr)
            .with_context(|| format!("bind enrollment listener on {}", cfg.enrollment_bind_addr))?;
        tracing::info!(
            addr = %cfg.enrollment_bind_addr,
            "enrollment public listener listening"
        );
        let srv_public = Server::builder()
            .tls_config(tls_public)
            .context("apply ServerTlsConfig (public)")?
            .add_service(enroll_svc_public)
            .serve_with_incoming_shutdown(incoming_public, async move {
                let _ = rx_public.changed().await;
            });

        tokio::try_join!(srv_mtls, srv_public).context("tonic listeners terminated with error")?;
    }

    tracing::info!("disk-arcana-server shutdown complete");
    Ok(())
}

/// Select the CA client implementation based on [`ServerConfig::ca_mode`].
///
/// - `CaMode::Http`: real Auth Arcana CA — reads `AUTH_ARCANA_CA_TOKEN` from env.
/// - `CaMode::Stub`: fixed test cert — always succeeds (dev/test only).
/// - `CaMode::Offline`: no-op — returns `CaError::EnrollmentDisabled` (Approach A-a).
fn select_ca_client(cfg: &ServerConfig) -> anyhow::Result<Arc<dyn CaClient>> {
    match cfg.ca_mode {
        CaMode::Stub => {
            tracing::warn!(
                ca_mode = "stub",
                "enrollment uses StubCaClient (test-only — do not use in production)"
            );
            Ok(Arc::new(StubCaClient::ok(
                b"STUB-CERT-PEM\n".to_vec(),
                b"STUB-CHAIN-PEM\n".to_vec(),
            )))
        }
        CaMode::Offline => {
            tracing::info!(
                ca_mode = "offline",
                "enrollment disabled — using OfflineCaClient (Approach A-a, DISK-0058)"
            );
            Ok(Arc::new(OfflineCaClient))
        }
        CaMode::Http => {
            let client =
                HttpCaClient::from_env().context("HttpCaClient::from_env (DISK_CA_MODE=http)")?;
            tracing::info!(ca_mode = "http", "enrollment uses HttpCaClient");
            Ok(Arc::new(client))
        }
    }
}

/// Choose the ACL signature verifier based on config and start the reload loop.
///
/// - `DISK_ACL_SIG_PATH` set → GpgVerifier (production path).
/// - `DISK_ACL_SIG_PATH` absent + (`DISK_ACL_ALLOW_UNSIGNED=1` or
///   `DISK_USE_STUB_CA=1`) → NoopVerifier (dev/test only).
/// - `DISK_ACL_SIG_PATH` absent + neither flag set → **panic** (fail-closed).
///
/// The allow-unsigned escape hatch is orthogonal to the CA client choice so a
/// real-`HttpCaClient` integration test can skip ACL signing without forcing
/// the stub CA. Production MUST leave both flags unset and provide a signature.
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
            if !cfg.acl_allow_unsigned {
                panic!(
                    "DISK_ACL_SIG_PATH must be set in production. Set \
                     DISK_ACL_ALLOW_UNSIGNED=1 (or DISK_USE_STUB_CA=1) only \
                     for local development or tests."
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

/// TLS-only server config (no `client_ca_root`) for the public enrollment
/// listener (DISK-0037). Cold-boot clients without an Arcanada-issued client
/// certificate rely on `EnrollmentService.Enroll`'s opaque-token bearer for
/// authentication, not on mTLS.
fn build_tls_public_only(cfg: &ServerConfig) -> anyhow::Result<ServerTlsConfig> {
    let cert_pem = std::fs::read(&cfg.tls_cert_path)
        .with_context(|| format!("read {}", cfg.tls_cert_path.display()))?;
    let key_pem = std::fs::read(&cfg.tls_key_path)
        .with_context(|| format!("read {}", cfg.tls_key_path.display()))?;
    let identity = Identity::from_pem(cert_pem, key_pem);
    Ok(ServerTlsConfig::new().identity(identity))
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
