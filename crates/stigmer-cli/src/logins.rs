//! The login file: tokens saved by `join` and `login`, keyed by server URL and scope.
//!
//! `$XDG_CONFIG_HOME/stigmer/logins.json`, else `$HOME/.config/stigmer/logins.json`. On unix
//! the directory is made 0700 and the file is written 0600 before any secret goes in; updates go
//! through a temp file in the same directory, fsynced and renamed over the old one. A file that
//! does not parse is an error and is never rewritten. Nothing here prints a token or the file's
//! contents.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use stigmer_core::BoardId;

use crate::exit::{CliError, Exit};

/// The only file format this version reads and writes.
const VERSION: u64 = 1;

/// What a saved token is good for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Scope {
    /// One board's routes.
    Board(BoardId),
    /// The instance-admin credential.
    Instance,
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Board(board) => write!(f, "board:{board}"),
            Scope::Instance => f.write_str("instance"),
        }
    }
}

/// The server URL as logins are keyed: without trailing slashes.
pub(crate) fn normalize_url(url: &str) -> &str {
    url.trim_end_matches('/')
}

/// One saved credential. Debug output redacts the token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    url: String,
    scope: String,
    principal: String,
    token: String,
    saved_at_ms: i64,
}

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Login")
            .field("url", &self.url)
            .field("scope", &self.scope)
            .field("principal", &self.principal)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginFile {
    version: u64,
    logins: Vec<Login>,
}

/// The login file as read from disk.
#[derive(Debug)]
pub(crate) struct Logins {
    path: PathBuf,
    logins: Vec<Login>,
}

/// Where the login file lives, from the environment: `None` when neither an absolute
/// `XDG_CONFIG_HOME` nor `HOME` is set.
pub(crate) fn default_path() -> Option<PathBuf> {
    let absolute = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    let config = absolute("XDG_CONFIG_HOME")
        .or_else(|| absolute("HOME").map(|home| home.join(".config")))?;
    Some(config.join("stigmer").join("logins.json"))
}

fn corrupt(path: &Path, why: &str) -> CliError {
    CliError::new(
        Exit::Failure,
        "login_file",
        format!(
            "the login file {} is not valid ({why}); it was left unchanged",
            path.display()
        ),
        "move the file away, then run stigmer join or stigmer login again",
    )
}

fn io_failure(path: &Path, what: &str, err: &std::io::Error) -> CliError {
    CliError::new(
        Exit::Failure,
        "login_file",
        format!("cannot {what} the login file {}: {err}", path.display()),
        "check the permissions of the stigmer config directory",
    )
}

impl Logins {
    /// Reads the file at `path`; a missing file is an empty list.
    pub(crate) fn load(path: &Path) -> Result<Self, CliError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path: path.to_owned(),
                    logins: Vec::new(),
                })
            }
            Err(e) => return Err(io_failure(path, "read", &e)),
        };
        // serde's messages can quote the offending value, which may be a token, so only the
        // position is reported.
        let at = |e: &serde_json::Error| format!("line {} column {}", e.line(), e.column());
        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| corrupt(path, &format!("not JSON at {}", at(&e))))?;
        if value.get("version").and_then(serde_json::Value::as_u64) != Some(VERSION) {
            return Err(corrupt(path, &format!("not version {VERSION}")));
        }
        let file: LoginFile = serde_json::from_str(&text)
            .map_err(|e| corrupt(path, &format!("unexpected structure at {}", at(&e))))?;
        Ok(Self {
            path: path.to_owned(),
            logins: file.logins,
        })
    }

    /// The token saved for `url` and `scope`, if any.
    pub(crate) fn token(&self, url: &str, scope: &Scope) -> Option<&str> {
        let (url, scope) = (normalize_url(url), scope.to_string());
        self.logins
            .iter()
            .find(|login| normalize_url(&login.url) == url && login.scope == scope)
            .map(|login| login.token.as_str())
    }

    /// Saves `token` for `url` and `scope`, replacing any login with the same key.
    pub(crate) fn save(
        &mut self,
        url: &str,
        scope: &Scope,
        principal: &str,
        token: &str,
        saved_at_ms: i64,
    ) -> Result<(), CliError> {
        let (url, scope) = (normalize_url(url).to_owned(), scope.to_string());
        self.logins
            .retain(|login| !(normalize_url(&login.url) == url && login.scope == scope));
        self.logins.push(Login {
            url,
            scope,
            principal: principal.to_owned(),
            token: token.to_owned(),
            saved_at_ms,
        });
        let file = LoginFile {
            version: VERSION,
            logins: self.logins.clone(),
        };
        let mut body = serde_json::to_vec_pretty(&file).map_err(|e| {
            CliError::new(
                Exit::Failure,
                "internal",
                format!("cannot encode the login file: {e}"),
                "report this as a bug",
            )
        })?;
        body.push(b'\n');
        write_private(&self.path, &body).map_err(|e| io_failure(&self.path, "write", &e))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// Creates `dir` (and missing parents) owner-only, and makes `dir` itself 0700 if it existed.
fn private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        builder.mode(0o700);
        builder.create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    builder.create(dir)
}

/// Replaces `path` with `bytes` atomically: a new 0600 temp file in the same directory,
/// written and fsynced, then renamed over `path`.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("the login file path has no directory"))?;
    private_dir(dir)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let temp = dir.join(format!(".logins.json.{}.{nanos}.tmp", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options.open(&temp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    let renamed = written.and_then(|()| std::fs::rename(&temp, path));
    if renamed.is_err() {
        // Best effort: the temp file holds a secret and must not be left behind.
        let _ = std::fs::remove_file(&temp);
    }
    renamed?;
    // Persist the rename itself; some platforms cannot open a directory, which is harmless.
    if let Ok(dir) = std::fs::File::open(dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn main_scope() -> Scope {
        Scope::Board(BoardId::main())
    }

    #[test]
    fn scopes_render_as_in_the_file() {
        assert_eq!(main_scope().to_string(), "board:main");
        assert_eq!(Scope::Instance.to_string(), "instance");
    }

    #[test]
    fn save_creates_an_owner_only_file_and_reloads_it() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("cfg").join("stigmer").join("logins.json");
        let mut logins = Logins::load(&path).unwrap();
        assert_eq!(logins.token("http://h", &main_scope()), None);
        logins
            .save("http://h/", &main_scope(), "ann", "stg1_a", 5)
            .unwrap();
        logins
            .save("http://h", &Scope::Instance, "root", "stg1_b", 6)
            .unwrap();
        logins
            .save("http://h", &main_scope(), "ann", "stg1_c", 7)
            .unwrap();
        let back = Logins::load(&path).unwrap();
        assert_eq!(back.token("http://h//", &main_scope()), Some("stg1_c"));
        assert_eq!(back.token("http://h", &Scope::Instance), Some("stg1_b"));
        assert_eq!(back.logins.len(), 2, "same key replaced: {:?}", back.logins);
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["logins"][0]["url"], "http://h");
        assert_eq!(value["logins"][0]["scope"], "instance");
        assert_eq!(value["logins"][0]["saved_at_ms"], 6);
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec!["logins.json"], "no temp file is left behind");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
        }
    }

    #[cfg(unix)]
    #[test]
    fn save_tightens_an_existing_config_directory() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("stigmer");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut logins = Logins::load(&dir.join("logins.json")).unwrap();
        logins
            .save("http://h", &main_scope(), "a", "stg1_x", 1)
            .unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn debug_output_redacts_tokens() {
        let login = Login {
            url: "u".into(),
            scope: "instance".into(),
            principal: "p".into(),
            token: "stg1_SECRETVALUE".into(),
            saved_at_ms: 0,
        };
        let shown = format!("{login:?}");
        assert!(!shown.contains("SECRETVALUE"), "{shown}");
    }
}
