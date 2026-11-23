//! The global options every command sees, and the clients built from them.

use std::path::PathBuf;

use stigmer_core::{BoardId, Principal};
use ureq::tls::TlsConfig;

use crate::client::{Auth, Client, Token};
use crate::commands::{mark_untrusted, principal, print_out};
use crate::exit::{CliError, Exit};
use crate::logins::{Logins, Scope};
use crate::tls::check_credential_transport;

/// The placeholder author a write is validated with when a token names the real one.
const TOKEN_AUTHOR: &str = "token-holder";

const AS_HINT: &str = "export STIGMER_AS=<name> or pass --as <name>";

/// Global options every command sees.
pub(crate) struct Ctx {
    pub(crate) url: String,
    pub(crate) who: Option<String>,
    pub(crate) json: bool,
    pub(crate) board: BoardId,
    /// Allow a credential over plain HTTP to a host that is not loopback.
    pub(crate) insecure: bool,
    /// `STIGMER_TOKEN`, which overrides the login file.
    pub(crate) env_token: Option<String>,
    /// The login file, when HOME or XDG_CONFIG_HOME says where it is.
    pub(crate) logins_path: Option<PathBuf>,
    /// The roots https is verified against.
    pub(crate) tls: TlsConfig,
}

impl Ctx {
    /// The token to send to a route that accepts the credentials of `scopes` (first match
    /// wins): `STIGMER_TOKEN`, else the login saved for this URL and scope, else none.
    /// A token is checked for shape and for a safe transport before it is used.
    pub(crate) fn token(&self, scopes: &[Scope]) -> Result<Option<Token>, CliError> {
        let token = if let Some(raw) = &self.env_token {
            Token::new(raw, "STIGMER_TOKEN")?
        } else {
            let Some(path) = &self.logins_path else {
                return Ok(None);
            };
            let logins = Logins::load(path)?;
            match scopes
                .iter()
                .find_map(|scope| logins.token(&self.url, scope))
            {
                Some(raw) => Token::new(raw, "the saved login")?,
                None => return Ok(None),
            }
        };
        check_credential_transport(&self.url, self.insecure)?;
        Ok(Some(token))
    }

    /// The scope of this board's own credentials.
    pub(crate) fn board_scope(&self) -> Scope {
        Scope::Board(self.board.clone())
    }

    /// A client for routes that accept the credentials of `scopes`: the resolved token, else
    /// local mode with the optional `--as` name.
    pub(crate) fn client_for(&self, scopes: &[Scope]) -> Result<Client, CliError> {
        let auth = match self.token(scopes)? {
            Some(token) => Auth::Token(token),
            None => Auth::Local(self.who.as_deref().map(principal).transpose()?),
        };
        Ok(self.client_with(auth))
    }

    pub(crate) fn client_with(&self, auth: Auth) -> Client {
        Client::new(&self.url, self.board.clone(), auth, self.tls.clone())
    }

    /// A client for this board's content routes.
    pub(crate) fn client(&self) -> Result<Client, CliError> {
        self.client_for(&[self.board_scope()])
    }

    /// A client for a write and the author to validate it with. With a token the server takes
    /// the author from the credential; without one `--as` is required, as in local mode.
    pub(crate) fn writer(&self, verb: &str) -> Result<(Client, Principal), CliError> {
        if let Some(token) = self.token(&[self.board_scope()])? {
            // Only used to validate the message locally; never sent with a token.
            let author = principal(self.who.as_deref().unwrap_or(TOKEN_AUTHOR))?;
            return Ok((self.client_with(Auth::Token(token)), author));
        }
        let raw = self
            .who
            .as_deref()
            .ok_or_else(|| CliError::usage(format!("--as is required to {verb}"), AS_HINT))?;
        let author = principal(raw)?;
        Ok((self.client_with(Auth::Local(Some(author.clone()))), author))
    }

    /// Prints `value` as one JSON object with every message marked untrusted, or
    /// `text` otherwise.
    pub(crate) fn emit<T: serde::Serialize>(&self, value: &T, text: &str) -> Result<(), CliError> {
        if self.json {
            let encode_failed = |e: serde_json::Error| {
                CliError::new(
                    Exit::Failure,
                    "internal",
                    format!("cannot encode output: {e}"),
                    "report this as a bug",
                )
            };
            let mut value = serde_json::to_value(value).map_err(encode_failed)?;
            mark_untrusted(&mut value);
            let json = serde_json::to_string(&value).map_err(encode_failed)?;
            print_out(&format!("{json}\n"))
        } else {
            print_out(text)
        }
    }
}
