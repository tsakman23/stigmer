//! `stigmerd admin`: instance administration straight against the stores, no HTTP.
//!
//! Every subcommand takes the data directory lock, so none runs while `serve` does.
//! Secrets are written to stdout only, once; they never reach stderr, the security log or disk
//! (only their hashes are stored).

use std::io::Write;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use stigmer_core::{
    generate_secret, BoardId, NewSecret, Principal, PrincipalKind, Role, SecretKind,
};
use stigmer_store::{
    ConflictKind, CredentialScope, IdentityStore, Mode, NewCredential, NewInvite, SecurityEvent,
    SecurityEventKind, StoreError,
};
use stigmer_store_sqlite::SqliteStore;

use crate::lock::DataDir;
use crate::{now_ms, Failure};

const DAY_MS: i64 = 86_400_000;
const INSTANCE_ADMIN: &str = "instance-admin";
const INSTANCE_TOKEN_DAYS: u32 = 90;
const MAIN_INVITE_HOURS: i64 = 24;

#[derive(Args)]
pub struct DataDirArg {
    /// Directory holding the board database.
    #[arg(long, default_value = "./.stigmer")]
    data_dir: PathBuf,
}

#[derive(Subcommand)]
pub enum AdminCommand {
    /// Switch the data directory to network mode (one-way) and print the instance token once.
    EnableAuth {
        /// Do not mint an admin invite into the main board.
        #[arg(long)]
        no_main_invite: bool,
        #[command(flatten)]
        dir: DataDirArg,
    },
    /// Issue a replacement instance-admin token and print it once.
    NewInstanceToken {
        /// Days until the token expires.
        #[arg(
            long,
            default_value_t = INSTANCE_TOKEN_DAYS,
            value_parser = clap::value_parser!(u32).range(1..=365)
        )]
        expires_days: u32,
        #[command(flatten)]
        dir: DataDirArg,
    },
}

/// Runs one admin subcommand to completion.
pub async fn run(command: AdminCommand) -> Result<(), Failure> {
    let dir = match &command {
        AdminCommand::EnableAuth { dir, .. } | AdminCommand::NewInstanceToken { dir, .. } => {
            &dir.data_dir
        }
    };
    let data = DataDir::open(dir)?;
    let db_path = data.db_path();
    let store = SqliteStore::open(&db_path).await.map_err(|e| {
        Failure::Runtime(format!("cannot open database {}: {e}", db_path.display()))
    })?;
    let now = now_ms();
    match command {
        AdminCommand::EnableAuth { no_main_invite, .. } => {
            let issued = enable_auth(&store, now, !no_main_invite).await?;
            let mut out = std::io::stdout().lock();
            let mut lines = format!("instance token: {}\n", issued.token);
            if let Some(invite) = issued.invite {
                lines.push_str(&format!("main admin invite: {invite}\n"));
            }
            write_once(&mut out, &lines)
        }
        AdminCommand::NewInstanceToken { expires_days, .. } => {
            require_network(&store).await?;
            let token = issue_instance_token(&store, now, expires_days).await?;
            write_once(
                &mut std::io::stdout().lock(),
                &format!("instance token: {token}\n"),
            )
        }
    }
}

/// Prints the secrets, then the note that they are shown once.
fn write_once(out: &mut impl Write, secrets: &str) -> Result<(), Failure> {
    out.write_all(secrets.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| Failure::Runtime(format!("cannot write to stdout: {e}")))?;
    eprintln!("stigmerd: the secrets above are shown once and cannot be recovered; store them now");
    Ok(())
}

struct Issued {
    token: String,
    invite: Option<String>,
}

async fn enable_auth<S: IdentityStore>(
    store: &S,
    now: i64,
    with_invite: bool,
) -> Result<Issued, Failure> {
    match store.enable_network_mode().await {
        Ok(()) => {}
        Err(StoreError::Conflict(ConflictKind::AlreadyNetwork)) => {
            return Err(Failure::Runtime("already in network mode".into()));
        }
        Err(e) => return Err(store_failure("cannot enable network mode", &e)),
    }
    // The switch is one-way, so a failure past this point is reported with the way out.
    let after = |e: Failure| match e {
        Failure::Runtime(msg) => Failure::Runtime(format!(
            "network mode is now on, but {msg}; run stigmerd admin new-instance-token"
        )),
        other => other,
    };
    log(
        store,
        now,
        SecurityEventKind::ModeEnabled,
        None,
        "network mode enabled",
    )
    .await
    .map_err(after)?;
    let token = issue_instance_token(store, now, INSTANCE_TOKEN_DAYS)
        .await
        .map_err(after)?;
    let invite = if with_invite {
        Some(issue_main_admin_invite(store, now).await.map_err(after)?)
    } else {
        None
    };
    Ok(Issued { token, invite })
}

async fn issue_instance_token<S: IdentityStore>(
    store: &S,
    now: i64,
    days: u32,
) -> Result<String, Failure> {
    let secret = new_secret(SecretKind::Token)?;
    let principal = instance_admin()?;
    store
        .create_credential(
            NewCredential {
                id: secret.id.clone(),
                secret_hash: secret.hash,
                scope: CredentialScope::Instance,
                principal,
                expires_at_ms: now + i64::from(days) * DAY_MS,
            },
            now,
        )
        .await
        .map_err(|e| store_failure("cannot store the instance token", &e))?;
    log(
        store,
        now,
        SecurityEventKind::InstanceTokenIssued,
        None,
        &format!("credential {} expires in {days} days", secret.id),
    )
    .await?;
    Ok(secret.full)
}

async fn issue_main_admin_invite<S: IdentityStore>(store: &S, now: i64) -> Result<String, Failure> {
    let secret = new_secret(SecretKind::Invite)?;
    store
        .create_invite(
            NewInvite {
                id: secret.id.clone(),
                secret_hash: secret.hash,
                board: BoardId::main(),
                role: Role::Admin,
                kind: PrincipalKind::Human,
                created_by: instance_admin()?,
                expires_at_ms: now + MAIN_INVITE_HOURS * 3_600_000,
            },
            now,
        )
        .await
        .map_err(|e| store_failure("cannot store the main admin invite", &e))?;
    log(
        store,
        now,
        SecurityEventKind::InviteCreated,
        Some(BoardId::main()),
        &format!("invite {} role admin kind human", secret.id),
    )
    .await?;
    Ok(secret.full)
}

async fn require_network<S: IdentityStore>(store: &S) -> Result<(), Failure> {
    match store
        .mode()
        .await
        .map_err(|e| store_failure("cannot read instance mode", &e))?
    {
        Mode::Network => Ok(()),
        Mode::Local => Err(Failure::Runtime(
            "requires network mode; run stigmerd admin enable-auth first".into(),
        )),
    }
}

async fn log<S: IdentityStore>(
    store: &S,
    now: i64,
    kind: SecurityEventKind,
    board: Option<BoardId>,
    detail: &str,
) -> Result<(), Failure> {
    store
        .log_security(SecurityEvent {
            at_ms: now,
            kind,
            board,
            principal: Some(INSTANCE_ADMIN.to_owned()),
            detail: detail.to_owned(),
        })
        .await
        .map_err(|e| store_failure("cannot write the security log", &e))
}

fn new_secret(kind: SecretKind) -> Result<NewSecret, Failure> {
    generate_secret(kind).map_err(|e| Failure::Runtime(format!("cannot generate a secret: {e}")))
}

fn instance_admin() -> Result<Principal, Failure> {
    Principal::new(INSTANCE_ADMIN)
        .map_err(|e| Failure::Runtime(format!("invalid built-in principal name: {e}")))
}

fn store_failure(what: &str, e: &StoreError) -> Failure {
    Failure::Runtime(format!("{what}: {e}"))
}
