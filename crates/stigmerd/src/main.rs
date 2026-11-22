//! stigmerd: the Stigmer board server.

use std::future::IntoFuture;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use stigmer_api::{require_loopback, router, AllowAll, ApiConfig, RoleAuthorize};
use stigmer_store::{IdentityStore, Mode};
use stigmer_store_sqlite::SqliteStore;
use tokio::sync::{oneshot, watch};

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
}

/// Why the server stopped without a clean shutdown; carries the process exit code.
enum Failure {
    /// The requested configuration is invalid.
    Config(String),
    /// Opening the database or binding the port failed.
    Runtime(String),
}

#[tokio::main]
async fn main() -> ExitCode {
    let Command::Serve { data_dir, bind } = Cli::parse().command;
    match serve(data_dir, bind).await {
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

    create_data_dir(&data_dir)?;
    let db_path = data_dir.join("stigmer.db");
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

/// Creates the data directory, private to the owner (0700) on unix. An existing
/// directory keeps its mode; a warning goes to stderr if others can access it.
fn create_data_dir(data_dir: &Path) -> Result<(), Failure> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(data_dir).map_err(|e| {
        Failure::Runtime(format!(
            "cannot create data dir {}: {e}",
            data_dir.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(data_dir)
            .map_err(|e| {
                Failure::Runtime(format!("cannot read data dir {}: {e}", data_dir.display()))
            })?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            eprintln!(
                "stigmerd: warning: data dir {} is accessible by group or others (mode {:o}); consider: chmod 700 {}",
                data_dir.display(),
                mode & 0o777,
                data_dir.display()
            );
        }
    }
    Ok(())
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
