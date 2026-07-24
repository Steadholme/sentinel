//! JSON error envelope.
//!
//! Every failure maps to `{ "error": ..., "error_description": ... }` with the correct
//! status code; 401s additionally carry `WWW-Authenticate: Bearer`.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// Malformed request body.
    #[error("invalid_request: {0}")]
    InvalidRequest(String),

    /// Missing/invalid ingest bearer token on `POST /events`.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Authenticated but not permitted (non-admin SSO user, or a missing/invalid CSRF token on
    /// `POST /api/checkpoint`).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// A producer reused an idempotency key for different event content.
    #[error("idempotency_conflict: {0}")]
    IdempotencyConflict(String),

    /// Unexpected internal failure (store I/O).
    #[error("server_error: {0}")]
    Internal(String),
}

impl AppError {
    fn parts(&self) -> (StatusCode, &'static str, String, bool) {
        match self {
            AppError::InvalidRequest(d) => {
                (StatusCode::BAD_REQUEST, "invalid_request", d.clone(), false)
            }
            AppError::Unauthorized(d) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", d.clone(), true)
            }
            AppError::Forbidden(d) => (StatusCode::FORBIDDEN, "forbidden", d.clone(), false),
            AppError::IdempotencyConflict(d) => (
                StatusCode::CONFLICT,
                "idempotency_conflict",
                d.clone(),
                false,
            ),
            AppError::Internal(d) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                d.clone(),
                false,
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error, description, www_authenticate) = self.parts();
        let body = Json(serde_json::json!({
            "error": error,
            "error_description": description,
        }));
        let mut response = (status, body).into_response();
        if www_authenticate {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

/// An idempotency misuse is a stable producer-visible conflict; backend failures remain 500.
impl From<crate::store::StoreError> for AppError {
    fn from(e: crate::store::StoreError) -> Self {
        match e {
            crate::store::StoreError::IdempotencyConflict => AppError::IdempotencyConflict(
                "the same source and Idempotency-Key were already committed with different event content"
                    .to_string(),
            ),
            other => AppError::Internal(other.to_string()),
        }
    }
}
