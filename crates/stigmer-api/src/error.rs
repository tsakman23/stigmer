//! The error type every handler returns, rendered as the shared `ErrorBody` JSON.

use axum::http::header::{RETRY_AFTER, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use stigmer_core::{CoreError, ErrorBody, ErrorCode, ErrorDetail};
use stigmer_store::{ConflictKind, StoreError};

use crate::authz::Denied;

#[derive(Debug)]
pub(crate) struct ApiError {
    code: ErrorCode,
    message: String,
    /// Seconds for the `Retry-After` header of a 429.
    retry_after: Option<u64>,
}

impl ApiError {
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retry_after: None,
        }
    }

    pub(crate) fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, message)
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    /// The one answer to every failed authentication, whatever the reason.
    pub(crate) fn unauthorized() -> Self {
        Self::new(ErrorCode::Unauthorized, "invalid or expired credentials")
    }

    /// Too many requests from this client; it may retry after `retry_after` seconds.
    pub(crate) fn rate_limited(retry_after: u64) -> Self {
        Self {
            retry_after: Some(retry_after),
            ..Self::new(ErrorCode::RateLimited, "too many requests; retry later")
        }
    }

    fn status(&self) -> StatusCode {
        match self.code {
            ErrorCode::InvalidInput | ErrorCode::InvalidCursor => StatusCode::BAD_REQUEST,
            ErrorCode::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            ErrorCode::Conflict => StatusCode::CONFLICT,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::BoardArchived => StatusCode::CONFLICT,
            // Servers never send Unknown; if one ever reaches here it is a bug.
            ErrorCode::Internal | ErrorCode::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<CoreError> for ApiError {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::TooLong { .. } => Self::new(ErrorCode::TooLarge, err.to_string()),
            _ => Self::invalid_input(err.to_string()),
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::NotFound { .. } => Self::not_found(err.to_string()),
            StoreError::InvalidCursor => Self::new(ErrorCode::InvalidCursor, err.to_string()),
            StoreError::Conflict(ConflictKind::BoardArchived) => {
                Self::new(ErrorCode::BoardArchived, err.to_string())
            }
            StoreError::Conflict(_) => Self::new(ErrorCode::Conflict, err.to_string()),
            // Backend text may carry SQL or file paths; never send it to a client.
            StoreError::Backend(_) => Self::new(ErrorCode::Internal, "internal error"),
        }
    }
}

impl From<Denied> for ApiError {
    fn from(_: Denied) -> Self {
        Self::new(ErrorCode::Forbidden, "forbidden")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = ErrorBody {
            error: ErrorDetail {
                raw_code: None,
                code: self.code,
                message: self.message,
            },
        };
        let mut response = (status, Json(body)).into_response();
        let headers = response.headers_mut();
        if let Some(secs) = self.retry_after {
            headers.insert(RETRY_AFTER, HeaderValue::from(secs));
        }
        if status == StatusCode::UNAUTHORIZED {
            headers.insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}
