//! Exit codes and the failure report every command ends with.

use std::borrow::Cow;
use std::io::Write;
use std::process::ExitCode;

use stigmer_core::{CoreError, ErrorCode, ErrorDetail, MAX_MESSAGE_CHARS};

/// The process exit status of a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exit {
    Ok,
    /// Network error, server error, conflict or a bad login file.
    Failure,
    /// The command line was wrong.
    Usage,
    /// `wait` saw no matching event before its deadline.
    Timeout,
    NotFound,
    /// Invalid input, text too large or a bad cursor.
    Invalid,
    /// No valid credential (HTTP 401).
    Unauthorized,
    /// The credential's role cannot do this (HTTP 403).
    Forbidden,
    /// Too many requests (HTTP 429).
    RateLimited,
}

impl Exit {
    fn code(self) -> u8 {
        match self {
            Exit::Ok => 0,
            Exit::Failure => 1,
            Exit::Usage => 2,
            Exit::Timeout => 3,
            Exit::NotFound => 4,
            Exit::Invalid => 5,
            Exit::Unauthorized => 6,
            Exit::Forbidden => 7,
            Exit::RateLimited => 8,
        }
    }
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        ExitCode::from(exit.code())
    }
}

/// What to do about text over stigmer-core's length limit.
pub(crate) fn too_long_hint() -> String {
    format!("shorten the text to at most {MAX_MESSAGE_CHARS} characters")
}

/// A failed command: what went wrong and what to try next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliError {
    pub(crate) exit: Exit,
    /// Machine-readable kind: an API error code, or `usage`, `unavailable`, `network`,
    /// `request_timeout` (an HTTP request took too long, exit 1) or `timeout` (a wait saw no
    /// event, exit 3).
    pub(crate) code: &'static str,
    message: String,
    next: String,
    /// Extra top-level fields of the JSON report, such as a timed-out wait's `cursor`.
    fields: Vec<(&'static str, serde_json::Value)>,
}

impl CliError {
    pub(crate) fn new(
        exit: Exit,
        code: &'static str,
        message: impl Into<String>,
        next: impl Into<String>,
    ) -> Self {
        Self {
            exit,
            code,
            message: message.into(),
            next: next.into(),
            fields: Vec::new(),
        }
    }

    /// Adds a top-level field to the JSON report.
    pub(crate) fn with_field(mut self, name: &'static str, value: serde_json::Value) -> Self {
        self.fields.push((name, value));
        self
    }

    /// What went wrong, without the next step.
    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    /// A failure to reach the server that may pass: refused, reset or timed out.
    pub(crate) fn is_transient(&self) -> bool {
        crate::neterr::TRANSIENT_CODES.contains(&self.code)
    }

    pub(crate) fn usage(message: impl Into<String>, next: impl Into<String>) -> Self {
        Self::new(Exit::Usage, "usage", message, next)
    }

    /// A value rejected by stigmer-core's validation before any request was made.
    pub(crate) fn invalid(err: &CoreError, next: impl Into<String>) -> Self {
        let code = match err {
            CoreError::TooLong { .. } => "too_large",
            _ => "invalid_input",
        };
        Self::new(Exit::Invalid, code, err.to_string(), next)
    }

    /// Replaces the next step, for a command that knows better than the generic hint.
    pub(crate) fn with_next(mut self, next: impl Into<String>) -> Self {
        self.next = next.into();
        self
    }

    /// An error the server answered with; `retry_after` is the `Retry-After` header in seconds.
    pub(crate) fn api(detail: ErrorDetail, retry_after: Option<u64>) -> Self {
        let (exit, code, next): (Exit, &'static str, Cow<'static, str>) = match detail.code {
            ErrorCode::InvalidInput => (
                Exit::Invalid,
                "invalid_input",
                "fix the input; run: stigmer --help".into(),
            ),
            ErrorCode::TooLarge => (Exit::Invalid, "too_large", too_long_hint().into()),
            ErrorCode::InvalidCursor => (
                Exit::Invalid,
                "invalid_cursor",
                "pass a cursor printed by wait or tail, or drop --after".into(),
            ),
            ErrorCode::NotFound => (
                Exit::NotFound,
                "not_found",
                "check the id and --board; list threads with: stigmer read <channel>".into(),
            ),
            ErrorCode::MethodNotAllowed => (
                Exit::Failure,
                "method_not_allowed",
                "check that --url points at a stigmer server".into(),
            ),
            ErrorCode::Conflict => (
                Exit::Failure,
                "conflict",
                "retry with a different --key".into(),
            ),
            ErrorCode::Forbidden => (
                Exit::Forbidden,
                "forbidden",
                "your role cannot do this; ask a board admin".into(),
            ),
            ErrorCode::Internal => (
                Exit::Failure,
                "internal",
                "check the stigmerd logs, then retry".into(),
            ),
            ErrorCode::Unauthorized => (
                Exit::Unauthorized,
                "unauthorized",
                "run stigmer join <invite> --as <name> or stigmer login".into(),
            ),
            ErrorCode::RateLimited => (
                Exit::RateLimited,
                "rate_limited",
                match retry_after {
                    Some(secs) => format!("wait {secs} seconds and retry").into(),
                    None => "wait a few seconds and retry".into(),
                },
            ),
            ErrorCode::BoardArchived => (
                Exit::Failure,
                "board_archived",
                "the board is archived and read-only".into(),
            ),
            ErrorCode::Unknown => (
                Exit::Failure,
                "unknown",
                "this server is newer than the CLI; see the message above".into(),
            ),
        };
        let message = match &detail.raw_code {
            Some(raw) => format!("{} (server error code: {raw})", detail.message),
            None => detail.message,
        };
        Self::new(exit, code, message, next)
    }

    /// The report on stderr: two lines, or one JSON object with `--json`.
    pub(crate) fn render(&self, json: bool) -> String {
        if json {
            let mut report = serde_json::json!({
                "error": {"code": self.code, "message": self.message},
                "next": self.next,
            });
            if let Some(object) = report.as_object_mut() {
                for (name, value) in &self.fields {
                    object.insert((*name).to_owned(), value.clone());
                }
            }
            report.to_string()
        } else {
            format!("error: {}\nnext: {}", self.message, self.next)
        }
    }

    pub(crate) fn print(&self, json: bool) {
        // Nothing useful is left to do if stderr itself cannot be written.
        let _ = writeln!(std::io::stderr(), "{}", self.render(json));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stigmer_core::MAX_MESSAGE_CHARS;

    fn api(code: ErrorCode) -> CliError {
        CliError::api(
            ErrorDetail {
                code,
                raw_code: None,
                message: "m".to_owned(),
            },
            None,
        )
    }

    #[test]
    fn api_error_codes_map_to_exit_codes() {
        assert_eq!(api(ErrorCode::InvalidInput).exit.code(), 5);
        assert_eq!(api(ErrorCode::TooLarge).exit.code(), 5);
        assert_eq!(api(ErrorCode::InvalidCursor).exit.code(), 5);
        assert_eq!(api(ErrorCode::NotFound).exit.code(), 4);
        assert_eq!(api(ErrorCode::Conflict).exit.code(), 1);
        assert_eq!(api(ErrorCode::Forbidden).exit.code(), 7);
        assert_eq!(api(ErrorCode::Unauthorized).exit.code(), 6);
        assert_eq!(api(ErrorCode::RateLimited).exit.code(), 8);
        assert_eq!(api(ErrorCode::BoardArchived).exit.code(), 1);
        assert_eq!(api(ErrorCode::Internal).exit.code(), 1);
        assert_eq!(api(ErrorCode::MethodNotAllowed).exit.code(), 1);
        assert_eq!(api(ErrorCode::InvalidCursor).code, "invalid_cursor");
    }

    #[test]
    fn unknown_error_code_prints_the_raw_code() {
        let detail: ErrorDetail =
            serde_json::from_str(r#"{"code":"quota_exceeded","message":"too many"}"#).unwrap();
        let err = CliError::api(detail, None);
        assert_eq!(err.exit.code(), 1);
        assert_eq!(err.code, "unknown");
        assert!(
            err.render(false).contains("quota_exceeded"),
            "{}",
            err.render(false)
        );
        assert!(err.render(false).contains("too many"));
    }

    #[test]
    fn render_has_error_and_next_lines_or_one_json_object() {
        let err = CliError::usage("bad", "do this");
        assert_eq!(err.render(false), "error: bad\nnext: do this");
        let value: serde_json::Value = serde_json::from_str(&err.render(true)).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"error": {"code": "usage", "message": "bad"}, "next": "do this"})
        );
    }

    #[test]
    fn auth_errors_have_distinct_hints() {
        assert_eq!(
            api(ErrorCode::Unauthorized).next,
            "run stigmer join <invite> --as <name> or stigmer login"
        );
        assert_eq!(
            api(ErrorCode::Forbidden).next,
            "your role cannot do this; ask a board admin"
        );
        let limited = CliError::api(
            ErrorDetail {
                code: ErrorCode::RateLimited,
                raw_code: None,
                message: "slow down".to_owned(),
            },
            Some(42),
        );
        assert_eq!(limited.next, "wait 42 seconds and retry");
    }

    #[test]
    fn too_large_hint_quotes_the_core_limit() {
        assert_eq!(
            api(ErrorCode::TooLarge).next,
            format!("shorten the text to at most {MAX_MESSAGE_CHARS} characters")
        );
    }

    #[test]
    fn core_too_long_is_too_large() {
        let err = CliError::invalid(&CoreError::TooLong { max: 10_000 }, "shorter");
        assert_eq!((err.exit, err.code), (Exit::Invalid, "too_large"));
        let err = CliError::invalid(&CoreError::EmptyText, "text");
        assert_eq!(err.code, "invalid_input");
    }
}
