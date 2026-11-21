//! Exit codes and the failure report every command ends with.

use std::borrow::Cow;
use std::io::Write;
use std::process::ExitCode;

use stigmer_core::{CoreError, ErrorCode, ErrorDetail, MAX_MESSAGE_CHARS};

/// The process exit status of a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Ok,
    /// Network error, server error, conflict or forbidden.
    Failure,
    /// The command line was wrong.
    Usage,
    /// `wait` saw no matching event before its deadline.
    Timeout,
    NotFound,
    /// Invalid input, text too large or a bad cursor.
    Invalid,
}

impl Exit {
    pub fn code(self) -> u8 {
        match self {
            Exit::Ok => 0,
            Exit::Failure => 1,
            Exit::Usage => 2,
            Exit::Timeout => 3,
            Exit::NotFound => 4,
            Exit::Invalid => 5,
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
pub struct CliError {
    pub exit: Exit,
    /// Machine-readable kind: an API error code, or `usage`, `unavailable`, `network`,
    /// `request_timeout` (an HTTP request took too long, exit 1) or `timeout` (a wait saw no
    /// event, exit 3).
    pub code: &'static str,
    pub message: String,
    pub next: String,
}

impl CliError {
    pub fn new(
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
        }
    }

    pub fn usage(message: impl Into<String>, next: impl Into<String>) -> Self {
        Self::new(Exit::Usage, "usage", message, next)
    }

    /// A value rejected by stigmer-core's validation before any request was made.
    pub fn invalid(err: &CoreError, next: impl Into<String>) -> Self {
        let code = match err {
            CoreError::TooLong { .. } => "too_large",
            _ => "invalid_input",
        };
        Self::new(Exit::Invalid, code, err.to_string(), next)
    }

    /// An error the server answered with.
    pub fn api(detail: ErrorDetail) -> Self {
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
                "check the id; list threads with: stigmer read <channel>".into(),
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
                Exit::Failure,
                "forbidden",
                "check the identity passed with --as".into(),
            ),
            ErrorCode::Internal => (
                Exit::Failure,
                "internal",
                "check the stigmerd logs, then retry".into(),
            ),
        };
        Self::new(exit, code, detail.message, next)
    }

    /// The report on stderr: two lines, or one JSON object with `--json`.
    pub fn render(&self, json: bool) -> String {
        if json {
            serde_json::json!({
                "error": {"code": self.code, "message": self.message},
                "next": self.next,
            })
            .to_string()
        } else {
            format!("error: {}\nnext: {}", self.message, self.next)
        }
    }

    pub fn print(&self, json: bool) {
        // Nothing useful is left to do if stderr itself cannot be written.
        let _ = writeln!(std::io::stderr(), "{}", self.render(json));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stigmer_core::MAX_MESSAGE_CHARS;

    fn api(code: ErrorCode) -> CliError {
        CliError::api(ErrorDetail {
            code,
            message: "m".to_owned(),
        })
    }

    #[test]
    fn api_error_codes_map_to_exit_codes() {
        assert_eq!(api(ErrorCode::InvalidInput).exit.code(), 5);
        assert_eq!(api(ErrorCode::TooLarge).exit.code(), 5);
        assert_eq!(api(ErrorCode::InvalidCursor).exit.code(), 5);
        assert_eq!(api(ErrorCode::NotFound).exit.code(), 4);
        assert_eq!(api(ErrorCode::Conflict).exit.code(), 1);
        assert_eq!(api(ErrorCode::Forbidden).exit.code(), 1);
        assert_eq!(api(ErrorCode::Internal).exit.code(), 1);
        assert_eq!(api(ErrorCode::MethodNotAllowed).exit.code(), 1);
        assert_eq!(api(ErrorCode::InvalidCursor).code, "invalid_cursor");
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
