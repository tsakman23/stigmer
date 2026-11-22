//! stigmerd: the Stigmer board server.

use std::future::IntoFuture;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use admin::AdminCommand;
use clap::{Parser, Subcommand};
use lock::DataDir;
use stigmer_api::{require_loopback, router, AllowAll, ApiConfig, RoleAuthorize};
use stigmer_store::{IdentityStore, Mode};
use stigmer_store_sqlite::SqliteStore;
use tokio::sync::{oneshot, watch};

mod admin;
mod lock;

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
    /// Serve the board over local HTTP.
    Serve {
        /// Directory holding the board database (created if missing).
        #[arg(long, default_value = "./.stigmer")]
        data_dir: PathBuf,
        /// Address to listen on. Must be a loopback address.
        #[arg(long, default_value = "127.0.0.1:7878")]
        bind: SocketAddr,
    },
    /// Administer a data directory directly (the server must not be running).
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
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
        Command::Serve { data_dir, bind } => serve(data_dir, bind).await,
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

async fn serve(data_dir: PathBuf, bind: SocketAddr) -> Result<(), Failure> {
    require_loopback(&bind).map_err(|e| Failure::Config(e.to_string()))?;
    let signals = Signals::install()
        .map_err(|e| Failure::Runtime(format!("cannot register signal handlers: {e}")))?;

    let data = DataDir::open(&data_dir)?;
    let db_path = data.db_path();
    let store = SqliteStore::open(&db_path).await.map_err(|e| {
        Failure::Runtime(format!("cannot open database {}: {e}", db_path.display()))
    })?;

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| Failure::Runtime(format!("cannot bind {bind}: {e}")))?;
    let local = listener
        .local_addr()
        .map_err(|e| Failure::Runtime(format!("cannot read bound address: {e}")))?;

    let mode = store
        .mode()
        .await
        .map_err(|e| Failure::Runtime(format!("cannot read instance mode: {e}")))?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let store = Arc::new(store);
    let app = match mode {
        Mode::Local => router(store, AllowAll, shutdown_rx, ApiConfig::local()),
        Mode::Network => router(store, RoleAuthorize, shutdown_rx, ApiConfig::network()),
    };

    println!(
        "listening on http://{local} (data in {})",
        data_dir.display()
    );
    std::io::stdout()
        .flush()
        .map_err(|e| Failure::Runtime(format!("cannot write to stdout: {e}")))?;

    let (signalled_tx, signalled_rx) = oneshot::channel::<()>();
    let graceful = async move {
        signals.wait().await;
        // Ends every pending wait so the connections can drain.
        let _ = shutdown_tx.send(true);
        let _ = signalled_tx.send(());
    };
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(graceful)
        .into_future();
    tokio::pin!(server);

    tokio::select! {
        result = &mut server => {
            result.map_err(|e| Failure::Runtime(format!("server error: {e}")))
        }
        () = async {
            // Only start the drain clock once a signal has arrived.
            if signalled_rx.await.is_ok() {
                tokio::time::sleep(DRAIN_LIMIT).await;
            } else {
                std::future::pending::<()>().await;
            }
        } => Ok(()),
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
