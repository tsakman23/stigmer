//! `stigmerd admin`: instance administration straight against the stores, no HTTP.
//!
//! On SQLite every subcommand takes the data directory lock, so none runs while `serve` does. On
//! Postgres there is no lock: each command's changes are one store transaction, so it runs safely
//! next to running servers (which read the instance mode when they start).
//! Secrets are written to stdout only, once; they never reach stderr, the security log or disk
//! (only their hashes are stored).

use clap::Subcommand;
use stigmer_core::{generate_secret, BoardId, NewSecret, Principal, SecretKind};
use stigmer_store::{IdentityStore, Mode, SecurityEvent, SecurityEventKind, StoreError};

use crate::backend::{Backend, Plan, StoreArgs};
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

#[derive(Subcommand)]
pub enum AdminCommand {
    /// Bring a Postgres database's schema up to this version (pending migrations in one
    /// transaction; safe to repeat). SQLite migrates itself when opened: nothing to do.
    Migrate {
        #[command(flatten)]
        store: StoreArgs,
    },
    /// Switch the instance to network mode (one-way) and print the instance token once.
    EnableAuth {
        /// Do not mint an admin invite into the main board.
        #[arg(long)]
        no_main_invite: bool,
        #[command(flatten)]
        store: StoreArgs,
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
        store: StoreArgs,
    },
    /// Revoke any token, an instance token or a board token, by its id (the 16 hex characters
    /// after stg1_, as token list shows). Revoking a revoked token changes nothing.
    RevokeToken {
        /// The token id.
        #[arg(value_name = "ID")]
        id: String,
        #[command(flatten)]
        store: StoreArgs,
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
        store: StoreArgs,
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
        store: StoreArgs,
    },
    /// Print the security log, newest first.
    SecurityLog {
        /// How many entries to print.
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=1000))]
        limit: u32,
        #[command(flatten)]
        store: StoreArgs,
    },
}

/// Runs one admin subcommand to completion.
pub async fn run(command: AdminCommand) -> Result<(), Failure> {
    let plan = match &command {
        AdminCommand::Migrate { store }
        | AdminCommand::EnableAuth { store, .. }
        | AdminCommand::NewInstanceToken { store, .. }
        | AdminCommand::RevokeToken { store, .. }
        | AdminCommand::IssueMemberToken { store, .. }
        | AdminCommand::MapLocalPrincipals { store, .. }
        | AdminCommand::SecurityLog { store, .. } => store.plan()?,
    };
    if let AdminCommand::Migrate { .. } = command {
        return migrate(plan).await;
    }
    let backend = plan.open().await?;
    backend.check_schema().await?;
    match backend {
        Backend::Sqlite { store, lock, .. } => {
            // The lock is held until the command ends.
            let _lock = lock;
            run_on(&store, command).await
        }
        Backend::Postgres { store, .. } => {
            let enabling = matches!(command, AdminCommand::EnableAuth { .. });
            run_on(&*store, command).await?;
            if enabling {
                eprintln!(
                    "stigmerd: servers already running on this database keep the mode they \
                     started in; restart them to serve in network mode"
                );
            }
            Ok(())
        }
    }
}

/// `admin migrate`: applies the pending Postgres migrations, or says SQLite needs none.
async fn migrate(plan: Plan) -> Result<(), Failure> {
    let plan @ Plan::Postgres(_) = plan else {
        return print_stdout(
            "SQLite migrations are automatic: the database is migrated when stigmerd opens it; \
             nothing to do\n",
        );
    };
    let Backend::Postgres { store, target } = plan.open().await? else {
        // A Postgres plan opens a Postgres store.
        return Ok(());
    };
    let report = store
        .migrate()
        .await
        .map_err(|e| store_failure("cannot migrate the database", &e))?;
    let text = if report.applied() == 0 {
        format!("{target}: schema up to date (version {})\n", report.to)
    } else {
        format!(
            "{target}: migrated the schema from version {} to {}\n",
            report.from, report.to
        )
    };
    print_stdout(&text)
}

/// Runs a subcommand other than `migrate` against an open store.
async fn run_on<S: IdentityStore>(store: &S, command: AdminCommand) -> Result<(), Failure> {
    let now = stigmer_core::now_ms();
    match command {
        // Handled by `run` before a schema check could refuse it.
        AdminCommand::Migrate { .. } => Ok(()),
        AdminCommand::EnableAuth { no_main_invite, .. } => {
            let issued = enable_auth(store, now, !no_main_invite).await?;
            let mut out = std::io::stdout().lock();
            let mut lines = format!("instance token: {}\n", issued.token);
            if let Some(invite) = issued.invite {
                lines.push_str(&format!("main admin invite: {invite}\n"));
            }
            write_once(&mut out, &lines)
        }
        AdminCommand::NewInstanceToken {
            expires_days,
            revoke_others,
            ..
        } => {
            require_network(store).await?;
            let issued = issue_instance_token(store, now, expires_days, revoke_others).await?;
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
            Ok(())
        }
        AdminCommand::RevokeToken { id, .. } => {
            require_network(store).await?;
            let text = revoke_token(store, now, &id).await?;
            print_stdout(&text)
        }
        AdminCommand::IssueMemberToken {
            board,
            member,
            expires_days,
            ..
        } => {
            require_network(store).await?;
            let token = issue_member_token(store, now, &board, &member, expires_days).await?;
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
            require_network(store).await?;
            let names = MappedNames {
                humans: &humans,
                admins: &admins,
                skips: &skips,
            };
            let text = map_local_principals(store, now, names, apply).await?;
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

/// A security log row by the instance admin, which the command hands to the store mutation it
/// records: the store writes it in the mutation's transaction, so a command whose row cannot be
/// written fails and changes nothing.
fn event(now: i64, kind: SecurityEventKind, board: Option<BoardId>, detail: &str) -> SecurityEvent {
    SecurityEvent {
        at_ms: now,
        kind,
        board,
        principal: Some(INSTANCE_ADMIN.to_owned()),
        detail: detail.to_owned(),
    }
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
