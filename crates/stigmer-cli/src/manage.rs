//! Management commands: boards, members, invites and tokens. Every name and id is validated
//! with stigmer-core before any request; listings never contain secrets.

use clap::Subcommand;
use stigmer_core::{
    BoardSummary, BoardsResponse, CreateBoardRequest, InviteRequest, InviteResponse,
    MembersResponse, PrincipalKind, Role, TokenId, TokensResponse,
};

use crate::commands::{board_id, parse_arg, principal, Ctx};
use crate::exit::{CliError, Exit};
use crate::logins::Scope;
use crate::render::rfc3339_ms;

#[derive(Subcommand)]
pub(crate) enum BoardsCommand {
    /// List boards (the instance admin sees all; others their own).
    List,
    /// Create a board (instance admin).
    Create { name: String },
    /// Archive a board: read-only from then on, and its non-admin tokens revoked.
    Archive { name: String },
}

#[derive(Subcommand)]
pub(crate) enum MembersCommand {
    /// List the members of --board.
    List,
    /// Remove a member from --board; their tokens stop working.
    Remove { name: String },
}

#[derive(Subcommand)]
pub(crate) enum InviteCommand {
    /// Mint a single-use invite into --board; it is printed once.
    Create {
        /// human, agent or bridge.
        #[arg(long, value_parser = parse_kind)]
        kind: PrincipalKind,
        /// admin, member or bridge.
        #[arg(long, value_parser = parse_role)]
        role: Role,
        /// How long the invite lasts, such as 60m, 2h or 1d (server default when unset).
        #[arg(long, value_name = "DURATION", value_parser = parse_expires)]
        expires: Option<u32>,
    },
}

#[derive(Subcommand)]
pub(crate) enum TokenCommand {
    /// List the tokens of --board (metadata only, never the secrets).
    List,
    /// Revoke a token by its id, as printed by token list.
    Revoke { id: String },
}

/// A wire enum from its snake_case name.
fn wire_name<T: serde::de::DeserializeOwned>(raw: &str, expected: &str) -> Result<T, String> {
    serde_json::from_value(serde_json::Value::String(raw.to_owned()))
        .map_err(|_| format!("expected {expected}, got {raw:?}"))
}

fn parse_kind(raw: &str) -> Result<PrincipalKind, String> {
    wire_name(raw, "human, agent or bridge")
}

fn parse_role(raw: &str) -> Result<Role, String> {
    wire_name(raw, "admin, member or bridge")
}

/// Minutes in `60m`, `2h` or `1d`; at least one minute.
fn parse_expires(raw: &str) -> Result<u32, String> {
    let bad = || format!("expected a duration like 60m, 2h or 1d, got {raw:?}");
    let (digits, unit) = match raw.as_bytes().last() {
        Some(b'm') => (&raw[..raw.len() - 1], 1),
        Some(b'h') => (&raw[..raw.len() - 1], 60),
        Some(b'd') => (&raw[..raw.len() - 1], 24 * 60),
        _ => return Err(bad()),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let count: u32 = digits.parse().map_err(|_| bad())?;
    match count.checked_mul(unit) {
        Some(minutes) if minutes > 0 => Ok(minutes),
        _ => Err(bad()),
    }
}

/// `never`, or the time as RFC 3339.
fn seen(at_ms: Option<i64>) -> String {
    at_ms.map_or_else(|| "never".to_owned(), rfc3339_ms)
}

fn board_line(board: &BoardSummary) -> String {
    let state = if board.archived { "archived" } else { "active" };
    format!(
        "{}  {state}  created {}\n",
        board.id,
        rfc3339_ms(board.created_at_ms)
    )
}

/// `boards list|create|archive`: instance-admin routes, falling back to the board's login.
pub(crate) fn boards(ctx: &Ctx, command: BoardsCommand) -> Result<Exit, CliError> {
    match command {
        BoardsCommand::List => {
            let client = ctx.client_for(&[Scope::Instance, ctx.board_scope()])?;
            let listing: BoardsResponse = client.get(&client.root_route("boards"))?;
            let text = if listing.boards.is_empty() {
                "no boards\n".to_owned()
            } else {
                listing.boards.iter().map(board_line).collect()
            };
            ctx.emit(&listing, &text)?;
        }
        BoardsCommand::Create { name } => {
            let name = board_id(&name)?;
            let client = ctx.client_for(&[Scope::Instance])?;
            let request = CreateBoardRequest { name };
            let created: BoardSummary = client.post_json(&client.root_route("boards"), &request)?;
            ctx.emit(&created, &format!("created board {}\n", created.id))?;
        }
        BoardsCommand::Archive { name } => {
            let name = board_id(&name)?;
            let client = ctx.client_for(&[Scope::Instance, Scope::Board(name.clone())])?;
            let archived: BoardSummary =
                client.post_empty(&client.root_route(&format!("boards/{name}/archive")))?;
            ctx.emit(&archived, &format!("archived board {}\n", archived.id))?;
        }
    }
    Ok(Exit::Ok)
}

/// The credentials a board management route accepts: the board's own login first, then the
/// instance admin's.
fn board_admin_scopes(ctx: &Ctx) -> [Scope; 2] {
    [ctx.board_scope(), Scope::Instance]
}

/// `members list|remove` on --board.
pub(crate) fn members(ctx: &Ctx, command: MembersCommand) -> Result<Exit, CliError> {
    let client = ctx.client_for(&board_admin_scopes(ctx))?;
    match command {
        MembersCommand::List => {
            let listing: MembersResponse = client.get(&client.board_route("members"))?;
            let text = if listing.members.is_empty() {
                format!("no members on board {}\n", ctx.board)
            } else {
                listing
                    .members
                    .iter()
                    .map(|m| {
                        format!(
                            "{}  {}  {}  last seen {}\n",
                            m.name,
                            m.kind.as_str(),
                            m.role.as_str(),
                            seen(m.last_seen_ms)
                        )
                    })
                    .collect()
            };
            ctx.emit(&listing, &text)?;
        }
        MembersCommand::Remove { name } => {
            let name = principal(&name)?;
            client.delete(&client.board_route(&format!("members/{name}")))?;
            let output = serde_json::json!({"removed": name, "board": ctx.board});
            ctx.emit(
                &output,
                &format!("removed {name} from board {}\n", ctx.board),
            )?;
        }
    }
    Ok(Exit::Ok)
}

/// `invite create`: prints the invite once (the only copy).
pub(crate) fn invite(ctx: &Ctx, command: InviteCommand) -> Result<Exit, CliError> {
    let InviteCommand::Create {
        kind,
        role,
        expires,
    } = command;
    let client = ctx.client_for(&board_admin_scopes(ctx))?;
    let request = InviteRequest {
        kind,
        role,
        expires_in_minutes: expires,
    };
    let minted: InviteResponse = client.post_json(&client.board_route("invites"), &request)?;
    let text = format!(
        "invite: {}\nexpires: {}\n",
        minted.invite,
        rfc3339_ms(minted.expires_at_ms)
    );
    ctx.emit(&minted, &text)?;
    Ok(Exit::Ok)
}

/// `token list|revoke` on --board.
pub(crate) fn token(ctx: &Ctx, command: TokenCommand) -> Result<Exit, CliError> {
    let client = ctx.client_for(&board_admin_scopes(ctx))?;
    match command {
        TokenCommand::List => {
            let listing: TokensResponse = client.get(&client.board_route("tokens"))?;
            let text = if listing.tokens.is_empty() {
                format!("no tokens on board {}\n", ctx.board)
            } else {
                listing
                    .tokens
                    .iter()
                    .map(|t| {
                        let state = if t.revoked { "revoked" } else { "active" };
                        format!(
                            "{}  {}  {}  {state}  expires {}  last seen {}\n",
                            t.id,
                            t.principal,
                            t.role.as_str(),
                            rfc3339_ms(t.expires_at_ms),
                            seen(t.last_seen_ms)
                        )
                    })
                    .collect()
            };
            ctx.emit(&listing, &text)?;
        }
        TokenCommand::Revoke { id } => {
            let id = parse_arg(
                &id,
                TokenId::new,
                "token ids are 16 hex digits, as printed by: stigmer token list",
            )?;
            client.delete(&client.board_route(&format!("tokens/{id}")))?;
            let output = serde_json::json!({"revoked": id, "board": ctx.board});
            ctx.emit(&output, &format!("revoked token {id}\n"))?;
        }
    }
    Ok(Exit::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stigmer_core::BoardId;

    #[test]
    fn expires_accepts_minutes_hours_and_days() {
        assert_eq!(parse_expires("60m"), Ok(60));
        assert_eq!(parse_expires("2h"), Ok(120));
        assert_eq!(parse_expires("1d"), Ok(1_440));
        for bad in ["", "m", "0m", "5", "5x", "-1h", "1.5h", "99999999999d"] {
            assert!(parse_expires(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn kinds_and_roles_use_the_wire_names() {
        assert_eq!(parse_kind("bridge"), Ok(PrincipalKind::Bridge));
        assert_eq!(parse_role("member"), Ok(Role::Member));
        assert!(parse_kind("robot").is_err());
        assert!(parse_role("owner").is_err());
    }

    #[test]
    fn board_lines_show_state_and_creation_time() {
        let board = BoardSummary {
            id: BoardId::main(),
            archived: true,
            created_at_ms: 0,
        };
        assert_eq!(
            board_line(&board),
            "main  archived  created 1970-01-01T00:00:00.000Z\n"
        );
    }
}
