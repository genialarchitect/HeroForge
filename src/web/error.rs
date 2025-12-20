//! Unified API error handling

use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use std::fmt;

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
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
