//! `stigmerd admin`: instance administration straight against the stores, no HTTP.
//!
//! Every subcommand takes the data directory lock, so none runs while `serve` does.
//! Secrets are written to stdout only, once; they never reach stderr, the security log or disk
//! (only their hashes are stored).

use std::io::Write;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use stigmer_core::{
    generate_secret, BoardId, NewSecret, Principal, PrincipalKind, Role, SecretKind, TokenId,
};
use stigmer_store::{
    Adoption, ConflictKind, CredentialScope, IdentityStore, Mode, NewCredential, NewInvite,
    SecurityEvent, SecurityEventKind, StoreError,
};
use stigmer_store_sqlite::SqliteStore;

use crate::lock::DataDir;
use crate::{now_ms, Failure};

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
        | AdminCommand::IssueMemberToken { dir, .. }
        | AdminCommand::MapLocalPrincipals { dir, .. }
        | AdminCommand::SecurityLog { dir, .. } => &dir.data_dir,
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
            write_once(&mut out, &lines)?;
            issued.log_failure.map_or(Ok(()), Err)
        }
        AdminCommand::NewInstanceToken { expires_days, .. } => {
            require_network(&store).await?;
            let token = issue_instance_token(&store, now, expires_days).await?;
            write_once(
                &mut std::io::stdout().lock(),
                &format!("instance token: {token}\n"),
            )
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
            apply,
            ..
        } => {
            require_network(&store).await?;
            let text = map_local_principals(&store, now, &humans, &admins, apply).await?;
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

fn print_stdout(text: &str) -> Result<(), Failure> {
    let mut out = std::io::stdout().lock();
    out.write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| Failure::Runtime(format!("cannot write to stdout: {e}")))
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
    /// Set when the secrets are valid but the security log could not be written.
    log_failure: Option<Failure>,
}

/// Enables network mode without ever stranding the instance: the credential and invite are
/// stored while the instance is still local, the one-way switch comes next, and the secrets
/// are returned only then. A failure before the switch leaves local mode plus at most an
/// unused credential whose secret was never shown, so a plain retry works.
async fn enable_auth<S: IdentityStore>(
    store: &S,
    now: i64,
    with_invite: bool,
) -> Result<Issued, Failure> {
    if store
        .mode()
        .await
        .map_err(|e| store_failure("cannot read instance mode", &e))?
        == Mode::Network
    {
        return Err(already_network());
    }
    let token = store_instance_token(store, now, INSTANCE_TOKEN_DAYS).await?;
    let invite = if with_invite {
        Some(store_main_admin_invite(store, now).await?)
    } else {
        None
    };
    match store.enable_network_mode().await {
        Ok(()) => {}
        Err(StoreError::Conflict(ConflictKind::AlreadyNetwork)) => return Err(already_network()),
        Err(e) => return Err(store_failure("cannot enable network mode", &e)),
    }
    // Past the switch the secrets are valid, so a log failure must not hide them.
    let mut logged = log(
        store,
        now,
        SecurityEventKind::ModeEnabled,
        None,
        "network mode enabled",
    )
    .await;
    if logged.is_ok() {
        logged = log_token_issued(store, now, &token.id, INSTANCE_TOKEN_DAYS).await;
    }
    if let (Ok(()), Some(invite)) = (&logged, &invite) {
        logged = log_invite_created(store, now, &invite.id).await;
    }
    Ok(Issued {
        token: token.full,
        invite: invite.map(|i| i.full),
        log_failure: logged.err(),
    })
}

fn already_network() -> Failure {
    Failure::Runtime(
        "already in network mode; if you have no instance token, run stigmerd admin new-instance-token"
            .into(),
    )
}

async fn issue_instance_token<S: IdentityStore>(
    store: &S,
    now: i64,
    days: u32,
) -> Result<String, Failure> {
    let secret = store_instance_token(store, now, days).await?;
    log_token_issued(store, now, &secret.id, days).await?;
    Ok(secret.full)
}

async fn store_instance_token<S: IdentityStore>(
    store: &S,
    now: i64,
    days: u32,
) -> Result<NewSecret, Failure> {
    let secret = new_secret(SecretKind::Token)?;
    store
        .create_credential(
            NewCredential {
                id: secret.id.clone(),
                secret_hash: secret.hash,
                scope: CredentialScope::Instance,
                principal: instance_admin()?,
                expires_at_ms: now + i64::from(days) * DAY_MS,
            },
            now,
        )
        .await
        .map_err(|e| store_failure("cannot store the instance token", &e))?;
    Ok(secret)
}

async fn log_token_issued<S: IdentityStore>(
    store: &S,
    now: i64,
    id: &TokenId,
    days: u32,
) -> Result<(), Failure> {
    log(
        store,
        now,
        SecurityEventKind::InstanceTokenIssued,
        None,
        &format!("credential {id} expires in {days} days"),
    )
    .await
}

async fn log_invite_created<S: IdentityStore>(
    store: &S,
    now: i64,
    id: &TokenId,
) -> Result<(), Failure> {
    log(
        store,
        now,
        SecurityEventKind::InviteCreated,
        Some(BoardId::main()),
        &format!("invite {id} role admin kind human"),
    )
    .await
}

async fn store_main_admin_invite<S: IdentityStore>(
    store: &S,
    now: i64,
) -> Result<NewSecret, Failure> {
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
    Ok(secret)
}

/// Stores a board credential for the existing member `raw_member` of `raw_board` and returns
/// the token, which is never stored or logged (only its hash and id are).
async fn issue_member_token<S: IdentityStore>(
    store: &S,
    now: i64,
    raw_board: &str,
    raw_member: &str,
    days: u32,
) -> Result<String, Failure> {
    let not_a_member =
        || Failure::Config(format!("{raw_member} is not a member of board {raw_board}"));
    let board = BoardId::new(raw_board).map_err(|_| not_a_member())?;
    let name = Principal::new(raw_member)
        .map_err(|e| Failure::Config(format!("--member {raw_member:?}: {e}")))?;
    let member = match store.get_member(&board, &name).await {
        Ok(Some(member)) => member,
        Ok(None) | Err(StoreError::NotFound { .. }) => return Err(not_a_member()),
        Err(e) => return Err(store_failure("cannot read the member", &e)),
    };
    let secret = new_secret(SecretKind::Token)?;
    store
        .create_credential(
            NewCredential {
                id: secret.id.clone(),
                secret_hash: secret.hash,
                scope: CredentialScope::Board(board.clone()),
                principal: member.name.clone(),
                expires_at_ms: now + i64::from(days) * DAY_MS,
            },
            now,
        )
        .await
        .map_err(|e| match e {
            StoreError::Conflict(ConflictKind::BoardArchived) => {
                Failure::Runtime(format!("board {board} is archived and takes no new tokens"))
            }
            e => store_failure("cannot store the member token", &e),
        })?;
    log(
        store,
        now,
        SecurityEventKind::MemberTokenIssued,
        Some(board),
        &format!("credential {} for member {}", secret.id, member.name),
    )
    .await?;
    Ok(secret.full)
}

/// Plans, and with `apply` performs, the adoption of board main's local authors.
async fn map_local_principals<S: IdentityStore>(
    store: &S,
    now: i64,
    humans: &[String],
    admins: &[String],
    apply: bool,
) -> Result<String, Failure> {
    let main = BoardId::main();
    let authors = store
        .list_local_authors(&main)
        .await
        .map_err(|e| store_failure("cannot list local authors", &e))?;
    if authors.is_empty() {
        return Ok("nothing to map\n".into());
    }
    let humans = known_authors(humans, &authors, "--human")?;
    let admins = known_authors(admins, &authors, "--admin")?;
    if admins.is_empty() {
        return Err(Failure::Config(
            "at least one --admin is required so the board keeps an administrator".into(),
        ));
    }
    let adoptions: Vec<Adoption> = authors
        .iter()
        .map(|name| Adoption {
            name: name.clone(),
            kind: if humans.contains(name) {
                PrincipalKind::Human
            } else {
                PrincipalKind::Agent
            },
            role: if admins.contains(name) {
                Role::Admin
            } else {
                Role::Member
            },
        })
        .collect();
    if !apply {
        let mut text = plan_table(&adoptions);
        text.push_str("dry run: nothing changed; rerun with --apply to write this mapping\n");
        return Ok(text);
    }
    let messages = store
        .adopt_local_authors(&main, &adoptions, now)
        .await
        .map_err(|e| store_failure("cannot map local principals", &e))?;
    Ok(format!(
        "adopted {} authors and {messages} messages into board main\n",
        adoptions.len()
    ))
}

/// Parses `names` and checks each is one of the local `authors`.
fn known_authors(
    names: &[String],
    authors: &[Principal],
    flag: &str,
) -> Result<Vec<Principal>, Failure> {
    names
        .iter()
        .map(|raw| {
            let name =
                Principal::new(raw).map_err(|e| Failure::Config(format!("{flag} {raw:?}: {e}")))?;
            if authors.contains(&name) {
                Ok(name)
            } else {
                let known: Vec<&str> = authors.iter().map(Principal::as_str).collect();
                Err(Failure::Config(format!(
                    "{flag} {raw}: not a local author of main (authors: {})",
                    known.join(", ")
                )))
            }
        })
        .collect()
}

fn plan_table(adoptions: &[Adoption]) -> String {
    let width = adoptions
        .iter()
        .map(|a| a.name.as_str().len())
        .chain([4])
        .max()
        .unwrap_or(4);
    let mut text = format!("{:<width$}  {:<5}  ROLE\n", "NAME", "KIND");
    for a in adoptions {
        text.push_str(&format!(
            "{:<width$}  {:<5}  {}\n",
            a.name.as_str(),
            a.kind.as_str(),
            a.role.as_str()
        ));
    }
    text
}

/// One tab-separated line per entry: time, kind, board, principal, detail.
fn format_security_log(events: &[SecurityEvent]) -> String {
    let mut text = String::new();
    for e in events {
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            format_utc(e.at_ms),
            e.kind,
            e.board.as_ref().map_or("-", BoardId::as_str),
            e.principal.as_deref().unwrap_or("-"),
            e.detail.replace(['\t', '\n'], " ")
        ));
    }
    text
}

/// `ms` since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ` (civil-from-days, proleptic Gregorian).
fn format_utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400) + 719_468;
    let in_day = secs.rem_euclid(86_400);
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        in_day / 3600,
        in_day % 3600 / 60,
        in_day % 60
    )
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

#[cfg(test)]
mod tests {
    use super::format_utc;

    #[test]
    fn utc_formatting_matches_known_instants() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_700_000_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_utc(951_782_400_000), "2000-02-29T00:00:00Z");
        assert_eq!(format_utc(-1000), "1969-12-31T23:59:59Z");
    }
}
