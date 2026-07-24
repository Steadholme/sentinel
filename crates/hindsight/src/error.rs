//! Closed, redacted application errors and exact HTML/JSON surfaces.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorSurface {
    Html,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteAllow {
    Get,
    GetHead,
    Post,
}

impl RouteAllow {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::GetHead => "GET, HEAD",
            Self::Post => "POST",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCondition {
    InvalidWindow,
    VisibleForm,
    StructuralForm,
    MissingIdentity,
    BadCsrf,
    IncidentAbsent,
    RouteAbsent,
    MethodRejected,
    StaleResolve,
    PrimaryUnavailable,
    Internal,
}

impl ErrorCondition {
    pub fn status(self) -> StatusCode {
        match self {
            Self::InvalidWindow | Self::VisibleForm | Self::StructuralForm => {
                StatusCode::BAD_REQUEST
            }
            Self::MissingIdentity | Self::BadCsrf => StatusCode::UNAUTHORIZED,
            Self::IncidentAbsent | Self::RouteAbsent => StatusCode::NOT_FOUND,
            Self::MethodRejected => StatusCode::METHOD_NOT_ALLOWED,
            Self::StaleResolve => StatusCode::CONFLICT,
            Self::PrimaryUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidWindow | Self::VisibleForm | Self::StructuralForm => "invalid_request",
            Self::MissingIdentity | Self::BadCsrf => "unauthorized",
            Self::IncidentAbsent | Self::RouteAbsent => "not_found",
            Self::MethodRejected => "method_not_allowed",
            Self::StaleResolve => "stale_conflict",
            Self::PrimaryUnavailable => "unavailable",
            Self::Internal => "internal_error",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidWindow => "Window request rejected — no substitute window was applied",
            Self::VisibleForm => "Check the highlighted fields and try again",
            Self::StructuralForm => "Request form was rejected",
            Self::MissingIdentity => "Authentication context unavailable",
            Self::BadCsrf => "Request authorization could not be verified",
            Self::IncidentAbsent => "Incident not found",
            Self::RouteAbsent => "Page not found",
            Self::MethodRejected => "Method not allowed for this route",
            Self::StaleResolve => "Incident was already resolved by a different command",
            Self::PrimaryUnavailable => "Hindsight data is temporarily unavailable",
            Self::Internal => "Hindsight could not complete the request",
        }
    }

    pub fn heading(self) -> &'static str {
        match self {
            Self::InvalidWindow => "Window request rejected",
            Self::VisibleForm | Self::StructuralForm => "Request rejected",
            Self::MissingIdentity | Self::BadCsrf => "Authentication required",
            Self::IncidentAbsent => "Incident not found",
            Self::RouteAbsent => "Page not found",
            Self::MethodRejected => "Method not allowed",
            Self::StaleResolve => "Incident already resolved",
            Self::PrimaryUnavailable => "Hindsight temporarily unavailable",
            Self::Internal => "Request could not be completed",
        }
    }
}

#[derive(Debug, Error)]
pub enum AppError {
    /// Compatibility seam for the frozen `auth.rs`. The string is never
    /// rendered, serialized, logged, or included in Display.
    #[error("invalid request")]
    InvalidRequest(String),
    #[error("unauthorized")]
    Unauthorized(String),
    #[error("not found")]
    NotFound(String),
    #[error("internal error")]
    Internal(String),
    #[error("safe application error")]
    Safe(SafeError),
}

#[derive(Clone, Debug)]
pub struct SafeError {
    condition: ErrorCondition,
    surface: ErrorSurface,
    allow: Option<RouteAllow>,
    authenticated_gateway_context: bool,
}

impl AppError {
    pub fn html(condition: ErrorCondition) -> Self {
        Self::Safe(SafeError {
            condition,
            surface: ErrorSurface::Html,
            allow: None,
            authenticated_gateway_context: false,
        })
    }

    pub fn json(condition: ErrorCondition) -> Self {
        Self::Safe(SafeError {
            condition,
            surface: ErrorSurface::Json,
            allow: None,
            authenticated_gateway_context: false,
        })
    }

    pub(crate) fn method(surface: ErrorSurface, allow: RouteAllow) -> Self {
        Self::Safe(SafeError {
            condition: ErrorCondition::MethodRejected,
            surface,
            allow: Some(allow),
            authenticated_gateway_context: false,
        })
    }

    pub(crate) fn authenticated(self) -> Self {
        let mut safe = self.safe();
        safe.authenticated_gateway_context = true;
        Self::Safe(safe)
    }

    fn safe(&self) -> SafeError {
        match self {
            Self::InvalidRequest(_) => SafeError {
                condition: ErrorCondition::StructuralForm,
                surface: ErrorSurface::Html,
                allow: None,
                authenticated_gateway_context: false,
            },
            Self::Unauthorized(_) => SafeError {
                condition: ErrorCondition::MissingIdentity,
                surface: ErrorSurface::Html,
                allow: None,
                authenticated_gateway_context: false,
            },
            Self::NotFound(_) => SafeError {
                condition: ErrorCondition::IncidentAbsent,
                surface: ErrorSurface::Html,
                allow: None,
                authenticated_gateway_context: false,
            },
            Self::Internal(_) => SafeError {
                condition: ErrorCondition::Internal,
                surface: ErrorSurface::Html,
                allow: None,
                authenticated_gateway_context: false,
            },
            Self::Safe(error) => error.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonErrorEnvelope {
    error: JsonErrorBody,
}

#[derive(Serialize)]
struct JsonErrorBody {
    code: &'static str,
    message: &'static str,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let error = self.safe();
        let status = error.condition.status();
        let mut response = match error.surface {
            ErrorSurface::Html => {
                let rendered = crate::handlers::render_error_document(
                    error.condition,
                    error.authenticated_gateway_context,
                );
                match rendered {
                    Ok(body) => (status, axum::response::Html(body)).into_response(),
                    Err(_) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::response::Html(crate::view_contract::emergency_html().to_string()),
                    )
                        .into_response(),
                }
            }
            ErrorSurface::Json => {
                let rendered = serde_json::to_string(&JsonErrorEnvelope {
                    error: JsonErrorBody {
                        code: error.condition.code(),
                        message: error.condition.message(),
                    },
                });
                match rendered {
                    Ok(body) => {
                        (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
                    }
                    Err(_) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [(header::CONTENT_TYPE, "application/json")],
                        crate::view_contract::emergency_json().to_string(),
                    )
                        .into_response(),
                }
            }
        };
        if response.status() == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        if response.status() == StatusCode::METHOD_NOT_ALLOWED {
            if let Some(allow) = error.allow {
                response
                    .headers_mut()
                    .insert(header::ALLOW, HeaderValue::from_static(allow.as_str()));
            }
        }
        response
    }
}

impl From<crate::store::StoreError> for AppError {
    fn from(_: crate::store::StoreError) -> Self {
        AppError::html(ErrorCondition::Internal)
    }
}
