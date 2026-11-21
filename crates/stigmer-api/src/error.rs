//! The error type every handler returns, rendered as the shared `ErrorBody` JSON.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use stigmer_core::{CoreError, ErrorBody, ErrorCode, ErrorDetail};
use stigmer_store::StoreError;

use crate::authz::Denied;

#[derive(Debug)]
pub(crate) struct ApiError {
    code: ErrorCode,
    message: String,
}

impl ApiError {
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub(crate) fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, message)
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    fn status(&self) -> StatusCode {
        match self.code {
            ErrorCode::InvalidInput | ErrorCode::InvalidCursor => StatusCode::BAD_REQUEST,
            ErrorCode::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            ErrorCode::Conflict => StatusCode::CONFLICT,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
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
                code: self.code,
                message: self.message,
            },
        };
        (status, Json(body)).into_response()
    }
}
