//! Unified API error handling

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::Serialize;
use std::fmt;

#[derive(Debug, Serialize, Clone)]
pub struct ApiError {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(skip)]
    pub status: StatusCode,
}

impl ApiError {
    /// Create a new ApiError with a kind and message
    pub fn new(kind: ApiErrorKind, message: impl Into<String>) -> Self {
        let msg = message.into();
        let status = match &kind {
            ApiErrorKind::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiErrorKind::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiErrorKind::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiErrorKind::NotFound(_) => StatusCode::NOT_FOUND,
            ApiErrorKind::Conflict(_) => StatusCode::CONFLICT,
            ApiErrorKind::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            error: msg,
            details: None,
            status,
        }
    }

    /// Create an ApiError from an ApiErrorKind
    pub fn from_kind<T: Into<String>>(kind: ApiErrorKind, message: T) -> ApiErrorKind {
        match kind {
            ApiErrorKind::BadRequest(_) => ApiErrorKind::BadRequest(message.into()),
            ApiErrorKind::Unauthorized(_) => ApiErrorKind::Unauthorized(message.into()),
            ApiErrorKind::Forbidden(_) => ApiErrorKind::Forbidden(message.into()),
            ApiErrorKind::NotFound(_) => ApiErrorKind::NotFound(message.into()),
            ApiErrorKind::Conflict(_) => ApiErrorKind::Conflict(message.into()),
            ApiErrorKind::InternalError(_) => ApiErrorKind::InternalError(message.into()),
        }
    }

    /// Create a bad request error
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(ApiErrorKind::BadRequest(String::new()), msg)
    }

    /// Create an unauthorized error
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(ApiErrorKind::Unauthorized(String::new()), msg)
    }

    /// Create a forbidden error
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(ApiErrorKind::Forbidden(String::new()), msg)
    }

    /// Create a not found error
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(ApiErrorKind::NotFound(String::new()), msg)
    }

    /// Create an internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ApiErrorKind::InternalError(String::new()), msg)
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        self.status
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status).json(self)
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        Self {
            error: err.to_string(),
            details: None,
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        Self {
            error: format!("Database error: {}", err),
            details: None,
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<ApiErrorKind> for ApiError {
    fn from(kind: ApiErrorKind) -> Self {
        let (status, message) = match kind {
            ApiErrorKind::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiErrorKind::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            ApiErrorKind::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            ApiErrorKind::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiErrorKind::Conflict(msg) => (StatusCode::CONFLICT, msg),
            ApiErrorKind::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        Self {
            error: message,
            details: None,
            status,
        }
    }
}

#[derive(Debug)]
pub enum ApiErrorKind {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    InternalError(String),
}

impl fmt::Display for ApiErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest(msg) => write!(f, "Bad Request: {}", msg),
            Self::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            Self::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            Self::NotFound(msg) => write!(f, "Not Found: {}", msg),
            Self::Conflict(msg) => write!(f, "Conflict: {}", msg),
            Self::InternalError(msg) => write!(f, "Internal Error: {}", msg),
        }
    }
}

impl ResponseError for ApiErrorKind {
    fn error_response(&self) -> HttpResponse {
        let (status, message) = match self {
            Self::BadRequest(msg) => (actix_web::http::StatusCode::BAD_REQUEST, msg),
            Self::Unauthorized(msg) => (actix_web::http::StatusCode::UNAUTHORIZED, msg),
            Self::Forbidden(msg) => (actix_web::http::StatusCode::FORBIDDEN, msg),
            Self::NotFound(msg) => (actix_web::http::StatusCode::NOT_FOUND, msg),
            Self::Conflict(msg) => (actix_web::http::StatusCode::CONFLICT, msg),
            Self::InternalError(msg) => (actix_web::http::StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        HttpResponse::build(status).json(ApiError {
            error: message.clone(),
            details: None,
            status,
        })
    }
}

impl From<anyhow::Error> for ApiErrorKind {
    fn from(err: anyhow::Error) -> Self {
        ApiErrorKind::InternalError(err.to_string())
    }
}

impl From<sqlx::Error> for ApiErrorKind {
    fn from(err: sqlx::Error) -> Self {
        ApiErrorKind::InternalError(format!("Database error: {}", err))
    }
}

// Helper functions for common responses
pub fn bad_request(msg: impl Into<String>) -> ApiErrorKind {
    ApiErrorKind::BadRequest(msg.into())
}

pub fn unauthorized(msg: impl Into<String>) -> ApiErrorKind {
    ApiErrorKind::Unauthorized(msg.into())
}

pub fn forbidden(msg: impl Into<String>) -> ApiErrorKind {
    ApiErrorKind::Forbidden(msg.into())
}

pub fn not_found(msg: impl Into<String>) -> ApiErrorKind {
    ApiErrorKind::NotFound(msg.into())
}

pub fn conflict(msg: impl Into<String>) -> ApiErrorKind {
    ApiErrorKind::Conflict(msg.into())
}

pub fn internal_error(msg: impl Into<String>) -> ApiErrorKind {
    ApiErrorKind::InternalError(msg.into())
}
