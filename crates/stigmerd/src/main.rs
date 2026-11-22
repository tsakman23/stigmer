//! stigmerd: the Stigmer board server.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use admin::AdminCommand;
use clap::{Args, Parser, Subcommand};
use lock::DataDir;
use stigmer_api::{router, AllowAll, ApiConfig, RoleAuthorize};
use stigmer_store::{IdentityStore, Mode};
use stigmer_store_sqlite::SqliteStore;
use tokio::sync::watch;

mod admin;
mod lock;
mod serve;

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
    /// Administer a data directory directly (the server must not be running).
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[derive(Args)]
struct ServeArgs {
    /// Directory holding the board database (created if missing).
    #[arg(long, default_value = "./.stigmer")]
    data_dir: PathBuf,
    /// Address to listen on. Must be a loopback address for now.
    #[arg(long, default_value = "127.0.0.1:7878")]
    bind: SocketAddr,
    /// Most connections open at once; further connections are closed without a response.
    #[arg(long, default_value_t = 1024, value_parser = clap::value_parser!(u32).range(1..))]
    max_connections: u32,
    /// How long a client may take to send its request headers, in ms (for tests).
    #[arg(long, default_value_t = 10_000, hide = true, value_parser = clap::value_parser!(u64).range(1..))]
    header_read_timeout_ms: u64,
}

/// Milliseconds since the Unix epoch; the only place this binary reads the clock.
fn now_ms() -> i64 {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
}

/// Why the server stopped without a clean shutdown; carries the process exit code.
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
    let ServeArgs {
        data_dir,
        bind,
        max_connections,
        header_read_timeout_ms,
    } = args;
    let signals = Signals::install()
        .map_err(|e| Failure::Runtime(format!("cannot register signal handlers: {e}")))?;

    // A missing data dir means local mode, so refuse before creating anything.
    if !data_dir.exists() {
        check_bind(bind, Mode::Local)?;
    }
    let data = DataDir::open(&data_dir)?;
    let db_path = data.db_path();
    let store = SqliteStore::open(&db_path).await.map_err(|e| {
        Failure::Runtime(format!("cannot open database {}: {e}", db_path.display()))
    })?;

    let mode = store
        .mode()
        .await
        .map_err(|e| Failure::Runtime(format!("cannot read instance mode: {e}")))?;
    check_bind(bind, mode)?;

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| Failure::Runtime(format!("cannot bind {bind}: {e}")))?;
    let local = listener
        .local_addr()
        .map_err(|e| Failure::Runtime(format!("cannot read bound address: {e}")))?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let store = Arc::new(store);
    let app = match mode {
        Mode::Local => router(store, AllowAll, shutdown_rx.clone(), ApiConfig::local()),
        Mode::Network => router(
            store,
            RoleAuthorize,
            shutdown_rx.clone(),
            ApiConfig::network(),
        ),
    };

    println!(
        "listening on http://{local} (data in {})",
        data_dir.display()
    );
    std::io::stdout()
        .flush()
        .map_err(|e| Failure::Runtime(format!("cannot write to stdout: {e}")))?;

    let listen = serve::Listen {
        // u32 always fits a usize on the platforms Rust supports for this server.
        max_connections: usize::try_from(max_connections).unwrap_or(usize::MAX),
        header_read_timeout: Duration::from_millis(header_read_timeout_ms),
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

/// Refuses a non-loopback bind. TLS and trusted-proxy support are not in this build, so
/// network mode cannot serve beyond loopback yet either.
fn check_bind(bind: SocketAddr, mode: Mode) -> Result<(), Failure> {
    if bind.ip().is_loopback() {
        return Ok(());
    }
    Err(Failure::Config(match mode {
        Mode::Local => format!(
            "refusing to bind {bind}: a non-loopback address needs network mode; \
             run stigmerd admin enable-auth first"
        ),
        Mode::Network => format!(
            "refusing to bind {bind}: a non-loopback address requires TLS or a trusted proxy \
             (--tls-cert/--tls-key/--trusted-proxy are not available yet in this build)"
        ),
    }))
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
