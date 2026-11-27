//! stigmerd: the Stigmer board server.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use admin::AdminCommand;
use backend::{Backend, Plan, StoreArgs};
use clap::{Args, Parser, Subcommand};
use stigmer_api::{router, AllowAll, ApiConfig, IpNet, RoleAuthorize};
use stigmer_store::{IdentityStore, Mode, Store};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

mod admin;
mod backend;
mod lock;
mod serve;
mod tls;

/// How long in-flight requests get to finish after a shutdown signal.
const DRAIN_LIMIT: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[command(name = "stigmerd", version, about = "Stigmer board server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the board over HTTP.
    Serve(ServeArgs),
    /// Administer the instance straight against its database (with SQLite, the server must not
    /// be running; with Postgres it may be).
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[derive(Args)]
struct ServeArgs {
    #[command(flatten)]
    store: StoreArgs,
    /// Address to listen on. A non-loopback address needs network mode (stigmerd admin
    /// enable-auth) and either --tls-cert/--tls-key or --trusted-proxy.
    #[arg(long, default_value = "127.0.0.1:7878")]
    bind: SocketAddr,
    /// Most connections open at once; further connections are closed without a response.
    #[arg(long, default_value_t = 1024, value_parser = clap::value_parser!(u32).range(1..))]
    max_connections: u32,
    /// Most connections open at once from one address (IPv6 counted per /64); further
    /// connections from it are closed without a response. Addresses in --trusted-proxy are
    /// exempt (only --max-connections bounds them).
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..=100_000))]
    max_connections_per_source: u32,
    /// Most event reads that may wait (timeout_s > 0) at the same time; further waiting reads get
    /// 429. Reads that do not wait are not counted.
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u32).range(1..=100_000))]
    max_waits: u32,
    /// Failed authentications allowed per source address per minute; further requests from that
    /// source get 429 until the budget refills.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=10_000))]
    auth_failures_per_minute: u32,
    /// Join attempts (POST /v1/join, successful or not) allowed per source address per minute;
    /// further attempts get 429.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=10_000))]
    join_per_minute: u32,
    /// How long a client may take to send its request headers, in ms (for tests).
    #[arg(long, default_value_t = 10_000, hide = true, value_parser = clap::value_parser!(u64).range(1..=60_000))]
    header_read_timeout_ms: u64,
    /// How long a request body may go without sending anything, in ms (for tests).
    #[arg(long, default_value_t = 10_000, hide = true, value_parser = clap::value_parser!(u64).range(1..=60_000))]
    body_read_timeout_ms: u64,
    /// Serve TLS 1.3 with this PEM certificate chain (requires --tls-key).
    #[arg(long, value_name = "PEM", requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// The PEM private key (PKCS#8, RSA or SEC1) of --tls-cert. Both files are reloaded when
    /// either changes.
    #[arg(long, value_name = "PEM", requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Address range of a reverse proxy (CIDR or a bare address; repeatable or comma separated).
    /// Its X-Forwarded-For is believed; without TLS, plain HTTP is accepted only from these
    /// ranges and other peers are dropped.
    #[arg(long = "trusted-proxy", value_name = "CIDR", value_delimiter = ',')]
    trusted_proxies: Vec<IpNet>,
    /// A host name accepted in Host and Origin besides loopback, such as the name the board is
    /// served under (repeatable). Every other name stays refused.
    #[arg(long = "allowed-host", value_name = "NAME")]
    allowed_hosts: Vec<String>,
    /// How often the TLS files are checked for changes, in ms (for tests).
    #[arg(long, default_value_t = 5_000, hide = true, value_parser = clap::value_parser!(u64).range(1..=3_600_000))]
    tls_reload_interval_ms: u64,
}

/// Why the server stopped without a clean shutdown; carries the process exit code.
/// Stringly typed on purpose: a binary only prints these, so a typed error per cause adds nothing.
pub enum Failure {
    /// The requested configuration is invalid.
    Config(String),
    /// Opening the database or binding the port failed.
    Runtime(String),
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Serve(args) => serve(args).await,
        Command::Admin { command } => admin::run(command).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Config(msg)) => {
            eprintln!("stigmerd: {msg}");
            ExitCode::from(2)
        }
        Err(Failure::Runtime(msg)) => {
            eprintln!("stigmerd: {msg}");
            ExitCode::from(1)
        }
    }
}

async fn serve(args: ServeArgs) -> Result<(), Failure> {
    // Settings first: a wrong one exits 2 before anything is opened.
    let plan = args.store.plan()?;
    let signals = Signals::install()
        .map_err(|e| Failure::Runtime(format!("cannot register signal handlers: {e}")))?;

    if args.trusted_proxies.iter().any(IpNet::covers_every_address) {
        eprintln!(
            "stigmerd: warning: trusted proxy range covers every address: \
             X-Forwarded-For can be forged by anyone, and no address has a per-source \
             connection cap"
        );
    }
    let secured = args.tls_cert.is_some() || !args.trusted_proxies.is_empty();
    // A missing data dir means local mode, so refuse before creating anything.
    if let Plan::Sqlite { data_dir } = &plan {
        if !data_dir.exists() {
            check_bind(args.bind, Mode::Local, secured)?;
        }
    }
    // Clap guarantees the two flags come together.
    let tls_files = match (args.tls_cert.clone(), args.tls_key.clone()) {
        (Some(cert), Some(key)) => Some(tls::PairFiles { cert, key }),
        _ => None,
    };
    // A bad pair is refused before the store is touched.
    let reload_every = Duration::from_millis(args.tls_reload_interval_ms);
    let tls = tls_files
        .map(|files| start_tls(files, reload_every))
        .transpose()?;
    let backend = plan.open().await?;
    backend.check_schema().await?;
    let place = backend.describe();
    match backend {
        Backend::Sqlite { store, lock, .. } => {
            // The lock is held until the server stops.
            let _lock = lock;
            serve_on(store, &place, &args, tls, signals).await
        }
        Backend::Postgres { store, .. } => serve_on(*store, &place, &args, tls, signals).await,
    }
}

/// Serves `store` until a shutdown signal, then drains; `place` says where the data is.
async fn serve_on<S: Store + IdentityStore>(
    store: S,
    place: &str,
    args: &ServeArgs,
    tls: Option<TlsAcceptor>,
    signals: Signals,
) -> Result<(), Failure> {
    let secured = args.tls_cert.is_some() || !args.trusted_proxies.is_empty();
    let mode = store
        .mode()
        .await
        .map_err(|e| Failure::Runtime(format!("cannot read instance mode: {e}")))?;
    check_bind(args.bind, mode, secured)?;

    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .map_err(|e| Failure::Runtime(format!("cannot bind {}: {e}", args.bind)))?;
    let local = listener
        .local_addr()
        .map_err(|e| Failure::Runtime(format!("cannot read bound address: {e}")))?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let store = Arc::new(store);
    let mut config = match mode {
        Mode::Local => ApiConfig::local(),
        Mode::Network => ApiConfig::network(),
    };
    config.allowed_hosts.clone_from(&args.allowed_hosts);
    config.limits.body_read_timeout = Duration::from_millis(args.body_read_timeout_ms);
    // u32 always fits a usize on the platforms Rust supports for this server.
    config.limits.max_waits = usize::try_from(args.max_waits).unwrap_or(usize::MAX);
    config.limits.auth_failures_per_minute = args.auth_failures_per_minute;
    config.limits.join_per_minute = args.join_per_minute;
    config.trusted_proxies.clone_from(&args.trusted_proxies);
    let app = match mode {
        Mode::Local => router(store, AllowAll, shutdown_rx.clone(), config),
        Mode::Network => router(store, RoleAuthorize, shutdown_rx.clone(), config),
    };

    let scheme = if tls.is_some() { "https" } else { "http" };
    println!("listening on {scheme}://{local} (data in {place})");
    std::io::stdout()
        .flush()
        .map_err(|e| Failure::Runtime(format!("cannot write to stdout: {e}")))?;

    let listen = serve::Listen {
        // u32 always fits a usize on the platforms Rust supports for this server.
        max_connections: usize::try_from(args.max_connections).unwrap_or(usize::MAX),
        max_connections_per_source: usize::try_from(args.max_connections_per_source)
            .unwrap_or(usize::MAX),
        header_read_timeout: Duration::from_millis(args.header_read_timeout_ms),
        // Every proxied client arrives from the proxy's address, TLS or not.
        per_source_exempt: args.trusted_proxies.clone(),
        // With TLS any peer may connect; without it, only the proxies (when any are listed).
        plain_from: if tls.is_some() {
            Vec::new()
        } else {
            args.trusted_proxies.clone()
        },
        tls,
    };
    let server = serve::run(listener, app, listen, shutdown_rx);
    tokio::pin!(server);
    tokio::select! {
        () = &mut server => return Ok(()),
        () = signals.wait() => {}
    }
    // Ends every pending wait and starts each connection's graceful shutdown, then gives the
    // in-flight requests a bounded time to finish.
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(DRAIN_LIMIT, server).await;
    Ok(())
}

/// Loads the certificate pair, builds the TLS acceptor that serves it and starts reloading it
/// when the files change.
fn start_tls(files: tls::PairFiles, reload_every: Duration) -> Result<TlsAcceptor, Failure> {
    let provider = tls::provider();
    let pair = tls::load_pair(&files, &provider).map_err(Failure::Runtime)?;
    tls::warn_if_key_exposed(&files.key);
    let current = Arc::new(tls::CurrentPair::new(pair));
    let config = tls::server_config(Arc::clone(&provider), Arc::clone(&current))
        .map_err(Failure::Runtime)?;
    tokio::spawn(tls::reload_on_change(
        files,
        provider,
        current,
        reload_every,
    ));
    Ok(TlsAcceptor::from(config))
}

/// Refuses a non-loopback bind unless the instance is in network mode and `secured` (TLS or a
/// trusted proxy is configured). A loopback bind is always allowed, in either mode.
fn check_bind(bind: SocketAddr, mode: Mode, secured: bool) -> Result<(), Failure> {
    if bind.ip().is_loopback() {
        return Ok(());
    }
    match (mode, secured) {
        (Mode::Network, true) => Ok(()),
        (Mode::Local, _) => Err(Failure::Config(format!(
            "refusing to bind {bind}: a non-loopback address needs network mode; \
             run stigmerd admin enable-auth first"
        ))),
        (Mode::Network, false) => Err(Failure::Config(format!(
            "refusing to bind {bind}: a non-loopback address requires TLS or a trusted proxy; \
             pass --tls-cert and --tls-key, or --trusted-proxy"
        ))),
    }
}

/// Shutdown signal streams, registered up front so a signal that arrives during
/// startup is held and not left to its default (process-killing) disposition.
#[cfg(unix)]
struct Signals {
    term: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl Signals {
    fn install() -> std::io::Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
        })
    }

    async fn wait(mut self) {
        tokio::select! {
            _ = self.term.recv() => {}
            _ = self.int.recv() => {}
        }
    }
}

#[cfg(not(unix))]
struct Signals;

#[cfg(not(unix))]
impl Signals {
    fn install() -> std::io::Result<Self> {
        Ok(Self)
    }

    async fn wait(self) {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(bind: &str, mode: Mode, secured: bool) -> bool {
        check_bind(bind.parse().unwrap(), mode, secured).is_ok()
    }

    #[test]
    fn non_loopback_binds_need_network_mode_and_tls_or_a_proxy() {
        for loopback in ["127.0.0.1:7878", "127.1.2.3:1", "[::1]:7878"] {
            for mode in [Mode::Local, Mode::Network] {
                assert!(allowed(loopback, mode, false), "{loopback}");
            }
        }
        for public in ["0.0.0.0:443", "192.0.2.1:7878", "[::]:443"] {
            assert!(!allowed(public, Mode::Local, false), "{public}");
            assert!(!allowed(public, Mode::Local, true), "{public}");
            assert!(!allowed(public, Mode::Network, false), "{public}");
            assert!(allowed(public, Mode::Network, true), "{public}");
        }
    }
}
