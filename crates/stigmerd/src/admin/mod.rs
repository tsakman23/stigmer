//! `stigmerd admin`: instance administration straight against the stores, no HTTP.
//!
//! Every subcommand takes the data directory lock, so none runs while `serve` does.
//! Secrets are written to stdout only, once; they never reach stderr, the security log or disk
//! (only their hashes are stored).

use std::path::PathBuf;

use clap::{Args, Subcommand};
use stigmer_core::{generate_secret, BoardId, NewSecret, Principal, SecretKind};
use stigmer_store::{IdentityStore, Mode, SecurityEvent, SecurityEventKind, StoreError};
use stigmer_store_sqlite::SqliteStore;

use crate::lock::DataDir;
use crate::Failure;

mod output;
mod principals;
mod tokens;

use output::{format_security_log, print_stdout, write_once};
use principals::{map_local_principals, MappedNames};
use tokens::{enable_auth, issue_instance_token, issue_member_token, revoke_token};

const DAY_MS: i64 = 86_400_000;
const INSTANCE_ADMIN: &str = "instance-admin";
const INSTANCE_TOKEN_DAYS: u32 = 90;
const MAIN_INVITE_HOURS: i64 = 24;
const MEMBER_TOKEN_DAYS: u32 = 90;

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
        /// Also revoke every other instance token, in the same transaction as the new one is
        /// stored (board tokens are untouched).
        #[arg(long)]
        revoke_others: bool,
        #[command(flatten)]
        dir: DataDirArg,
    },
    /// Revoke any token, an instance token or a board token, by its id (the 16 hex characters
    /// after stg1_, as token list shows). Revoking a revoked token changes nothing.
    RevokeToken {
        /// The token id.
        #[arg(value_name = "ID")]
        id: String,
        #[command(flatten)]
        dir: DataDirArg,
    },
    /// Issue a token for an existing member of a board (an adopted author, or a lost token) and
    /// print it once.
    IssueMemberToken {
        /// The board the member belongs to.
        #[arg(long, value_name = "NAME")]
        board: String,
        /// The member's name on that board.
        #[arg(long, value_name = "NAME")]
        member: String,
        /// Days until the token expires.
        #[arg(
            long,
            default_value_t = MEMBER_TOKEN_DAYS,
            value_parser = clap::value_parser!(u32).range(1..=365)
        )]
        expires_days: u32,
        #[command(flatten)]
        dir: DataDirArg,
    },
    /// Turn the local authors of board main into members (dry run unless --apply).
    MapLocalPrincipals {
        /// A local author to register as a human (others become agents). Repeatable.
        #[arg(long = "human", value_name = "NAME")]
        humans: Vec<String>,
        /// A local author to make a board admin (others become members). Repeatable.
        #[arg(long = "admin", value_name = "NAME")]
        admins: Vec<String>,
        /// A local author to leave out: not adopted, its messages stay local. Repeatable.
        #[arg(long = "skip", value_name = "NAME")]
        skips: Vec<String>,
        /// Write the mapping; without it the plan is only printed.
        #[arg(long)]
        apply: bool,
        #[command(flatten)]
        dir: DataDirArg,
    },
    /// Print the security log, newest first.
    SecurityLog {
        /// How many entries to print.
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=1000))]
        limit: u32,
        #[command(flatten)]
        dir: DataDirArg,
    },
}

/// Runs one admin subcommand to completion.
pub async fn run(command: AdminCommand) -> Result<(), Failure> {
    let dir = match &command {
        AdminCommand::EnableAuth { dir, .. }
        | AdminCommand::NewInstanceToken { dir, .. }
        | AdminCommand::RevokeToken { dir, .. }
        | AdminCommand::IssueMemberToken { dir, .. }
        | AdminCommand::MapLocalPrincipals { dir, .. }
        | AdminCommand::SecurityLog { dir, .. } => &dir.data_dir,
    };
    let data = DataDir::open(dir)?;
    let db_path = data.db_path();
    let store = SqliteStore::open(&db_path).await.map_err(|e| {
        Failure::Runtime(format!("cannot open database {}: {e}", db_path.display()))
    })?;
    let now = stigmer_core::now_ms();
    match command {
        AdminCommand::EnableAuth { no_main_invite, .. } => {
            let issued = enable_auth(&store, now, !no_main_invite).await?;
            let mut out = std::io::stdout().lock();
            let mut lines = format!("instance token: {}\n", issued.token);
            if let Some(invite) = issued.invite {
                lines.push_str(&format!("main admin invite: {invite}\n"));
            }
            write_once(&mut out, &lines)?;
            issued.log_failure.map_or(Ok(()), Err)
        }
        AdminCommand::NewInstanceToken {
            expires_days,
            revoke_others,
            ..
        } => {
            require_network(&store).await?;
            let issued = issue_instance_token(&store, now, expires_days, revoke_others).await?;
            write_once(
                &mut std::io::stdout().lock(),
                &format!("instance token: {}\n", issued.token),
            )?;
            match issued.revoked {
                None => {}
                Some(0) => eprintln!("stigmerd: no other instance tokens to revoke"),
                Some(1) => eprintln!("stigmerd: revoked 1 other instance token"),
                Some(n) => eprintln!("stigmerd: revoked {n} other instance tokens"),
            }
            issued.log_failure.map_or(Ok(()), Err)
        }
        AdminCommand::RevokeToken { id, .. } => {
            require_network(&store).await?;
            let text = revoke_token(&store, now, &id).await?;
            print_stdout(&text)
        }
        AdminCommand::IssueMemberToken {
            board,
            member,
            expires_days,
            ..
        } => {
            require_network(&store).await?;
            let token = issue_member_token(&store, now, &board, &member, expires_days).await?;
            write_once(
                &mut std::io::stdout().lock(),
                &format!("member token: {token}\n"),
            )
        }
        AdminCommand::MapLocalPrincipals {
            humans,
            admins,
            skips,
            apply,
            ..
        } => {
            require_network(&store).await?;
            let names = MappedNames {
                humans: &humans,
                admins: &admins,
                skips: &skips,
            };
            let text = map_local_principals(&store, now, names, apply).await?;
            print_stdout(&text)
        }
        AdminCommand::SecurityLog { limit, .. } => {
            let events = store
                .security_log(limit)
                .await
                .map_err(|e| store_failure("cannot read the security log", &e))?;
            print_stdout(&format_security_log(&events))
        }
    }
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

/// A store error as a runtime failure prefixed with what was being done; every admin command
/// reports store errors this one way.
fn store_failure(what: &str, e: &StoreError) -> Failure {
    Failure::Runtime(format!("{what}: {e}"))
}
