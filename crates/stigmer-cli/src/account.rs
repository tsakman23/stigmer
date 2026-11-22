//! Identity commands: `join` (redeem an invite), `login` (save a token read from stdin) and
//! `whoami`. Tokens are written only to the login file, never printed.

use std::io::{BufRead, IsTerminal};

use serde::Serialize;
use stigmer_core::{
    parse_secret, BoardId, JoinRequest, JoinResponse, PrincipalKind, Role, SecretKind, WhoAmI,
};

use crate::client::{Auth, Token};
use crate::commands::{principal, Ctx};
use crate::exit::{CliError, Exit};
use crate::logins::{Logins, Scope};
use crate::tls::check_credential_transport;

/// The login file for a command that writes one, read (and so checked) before any request.
fn logins(ctx: &Ctx) -> Result<Logins, CliError> {
    let path = ctx.logins_path.as_deref().ok_or_else(|| {
        CliError::new(
            Exit::Failure,
            "login_file",
            "cannot tell where to save the login: neither HOME nor XDG_CONFIG_HOME is set",
            "set HOME (or XDG_CONFIG_HOME) to an absolute path, then retry",
        )
    })?;
    Logins::load(path)
}

/// Milliseconds since the Unix epoch.
fn now_ms() -> i64 {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
}

#[derive(Serialize)]
struct Joined<'a> {
    board: &'a BoardId,
    name: &'a str,
    role: Role,
    kind: PrincipalKind,
    expires_at_ms: i64,
    login_file: String,
}

/// `join <invite> --as <name>`: redeems the invite and saves the token for its board.
pub(crate) fn join(ctx: &Ctx, invite: &str) -> Result<Exit, CliError> {
    let raw_name = ctx.who.as_deref().ok_or_else(|| {
        CliError::usage(
            "--as is required to join",
            "pass the name to take on the board: --as <name>",
        )
    })?;
    let name = principal(raw_name)?;
    if parse_secret(SecretKind::Invite, invite).is_err() {
        return Err(CliError::new(
            Exit::Invalid,
            "invalid_input",
            "that is not a stigmer invite",
            "pass the whole invite, which starts with stgi1_",
        ));
    }
    check_credential_transport(&ctx.url, ctx.insecure)?;
    let mut logins = logins(ctx)?;
    let request = JoinRequest {
        invite: invite.to_owned(),
        name: name.clone(),
    };
    let client = ctx.client_with(Auth::Local(None));
    let joined: JoinResponse = client
        .post_json(&client.root_route("join"), &request)
        .map_err(|err| match err.code {
            "conflict" => err.with_next("choose another --as name; the invite is still valid"),
            _ => err,
        })?;
    let scope = Scope::Board(joined.board.clone());
    logins
        .save(&ctx.url, &scope, name.as_str(), &joined.token, now_ms())
        .map_err(|err| {
            err.with_next("the invite is spent; ask a board admin for a new one once this is fixed")
        })?;
    let path = logins.path().display().to_string();
    let text = format!(
        "joined board {} as {name} ({})\nlogin saved to {path}\n",
        joined.board,
        joined.role.as_str()
    );
    let output = Joined {
        board: &joined.board,
        name: name.as_str(),
        role: joined.role,
        kind: joined.kind,
        expires_at_ms: joined.expires_at_ms,
        login_file: path,
    };
    ctx.emit(&output, &text)?;
    Ok(Exit::Ok)
}

/// One line from stdin, trimmed; never echoed.
fn read_token_line() -> Result<String, CliError> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprintln!("stigmer: paste the token and press Enter");
    }
    let mut line = String::new();
    stdin.lock().read_line(&mut line).map_err(|e| {
        CliError::usage(
            format!("cannot read a token from stdin: {e}"),
            "pipe the token in, for example: stigmer login < token.txt",
        )
    })?;
    let token = line.trim();
    if token.is_empty() {
        return Err(CliError::usage(
            "no token on stdin",
            "pipe the token in, for example: stigmer login < token.txt",
        ));
    }
    Ok(token.to_owned())
}

#[derive(Serialize)]
struct LoggedIn<'a> {
    principal: &'a str,
    scope: String,
    login_file: String,
}

/// `login [--instance]`: verifies a token read from stdin with `whoami` and saves it for its
/// board, or for the instance when it is the instance-admin token.
pub(crate) fn login(ctx: &Ctx, instance: bool) -> Result<Exit, CliError> {
    let token = Token::new(&read_token_line()?, "stdin")?;
    check_credential_transport(&ctx.url, ctx.insecure)?;
    let mut logins = logins(ctx)?;
    let raw = token.expose().to_owned();
    let client = ctx.client_with(Auth::Token(token));
    let who: WhoAmI = client.get(&client.root_route("whoami"))?;
    let scope = match (who.instance_admin, &who.board) {
        (true, _) => Scope::Instance,
        (false, _) if instance => {
            return Err(CliError::new(
                Exit::Invalid,
                "invalid_input",
                "this token is not the instance-admin token",
                "drop --instance to save it for its board",
            ))
        }
        (false, Some(board)) => Scope::Board(board.clone()),
        (false, None) => {
            return Err(CliError::new(
                Exit::Failure,
                "internal",
                "the server named no board for this token",
                "check that --url points at a stigmer server in network mode",
            ))
        }
    };
    logins.save(&ctx.url, &scope, who.principal.as_str(), &raw, now_ms())?;
    let path = logins.path().display().to_string();
    let text = format!("logged in as {}\nlogin saved to {path}\n", describe(&who));
    let output = LoggedIn {
        principal: who.principal.as_str(),
        scope: scope.to_string(),
        login_file: path,
    };
    ctx.emit(&output, &text)?;
    Ok(Exit::Ok)
}

/// `ann (human) on board main as admin`, `root (human) instance admin`, or local mode.
fn describe(who: &WhoAmI) -> String {
    let head = format!("{} ({})", who.principal, who.kind.as_str());
    match (who.instance_admin, &who.board, who.role) {
        (true, _, _) => format!("{head} instance admin"),
        (false, Some(board), Some(role)) => {
            format!("{head} on board {board} as {}", role.as_str())
        }
        (false, Some(board), None) => format!("{head} on board {board}"),
        (false, None, _) => format!("{head}, local mode (no credential)"),
    }
}

/// `whoami`: who the board's login (else the instance login) is.
pub(crate) fn whoami(ctx: &Ctx) -> Result<Exit, CliError> {
    let client = ctx.client_for(&[ctx.board_scope(), Scope::Instance])?;
    let who: WhoAmI = client.get(&client.root_route("whoami"))?;
    ctx.emit(&who, &format!("{}\n", describe(&who)))?;
    Ok(Exit::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stigmer_core::Principal;

    #[test]
    fn describe_names_board_role_or_instance() {
        let mut who = WhoAmI {
            principal: Principal::new("ann").unwrap(),
            kind: PrincipalKind::Human,
            board: Some(BoardId::main()),
            role: Some(Role::Admin),
            instance_admin: false,
        };
        assert_eq!(describe(&who), "ann (human) on board main as admin");
        who.board = None;
        assert_eq!(describe(&who), "ann (human), local mode (no credential)");
        who.instance_admin = true;
        assert_eq!(describe(&who), "ann (human) instance admin");
    }
}
