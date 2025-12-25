//! Breach Detection API endpoints
//!
//! Provides REST API access to breach checking functionality:
//! - POST /api/recon/breach/email - Check email in breaches
//! - POST /api/recon/breach/password - Check password (hashed)
//! - POST /api/recon/breach/domain - Search breaches by domain
//! - GET /api/recon/breach/history - User's breach check history
//! - GET /api/recon/breach/status - Engine status

use actix_web::{web, HttpResponse, Result};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::breach as breach_db;
use crate::scanner::breach_detection::{
    BreachCheckResult, BreachCheckType, BreachDetectionEngine,
    BreachSeverity,
};
use crate::scanner::breach_detection::engine::BreachEngineStatus;
use crate::web::auth::Claims;

/// Email check request
#[derive(Debug, Deserialize)]
pub struct EmailCheckRequest {
    /// Email address to check
    pub email: String,
    /// Whether to include unverified breaches
    #[serde(default)]
    pub include_unverified: bool,
}

/// Domain check request
#[derive(Debug, Deserialize)]
pub struct DomainCheckRequest {
    /// Domain to check
    pub domain: String,
}

/// Password check request
#[derive(Debug, Deserialize)]
pub struct PasswordCheckRequest {
    /// Password to check (will be hashed client-side or here)
    pub password: String,
}

/// Email check response
#[derive(Debug, Serialize)]
pub struct BreachCheckResponse {
    pub success: bool,
    pub id: String,
    pub check_type: String,
    pub target: String,
    pub breach_count: usize,
    pub exposure_count: usize,
    pub password_exposures: usize,
    pub has_critical: bool,
    pub has_high: bool,
    pub sources_checked: Vec<String>,
    pub result: BreachCheckResult,
}

/// Password check response
#[derive(Debug, Serialize)]
pub struct PasswordCheckResponse {
    pub success: bool,
    pub compromised: bool,
    pub count: u64,
    // Note: We don't return the hash prefix in the response for security
}

/// Status response
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub success: bool,
    pub status: BreachEngineStatus,
}

/// History response
#[derive(Debug, Serialize)]
pub struct HistoryResponse {
    pub success: bool,
    pub entries: Vec<breach_db::BreachCheckHistoryEntry>,
    pub stats: breach_db::BreachCheckStats,
}

/// Error response
#[derive(Debug, Serialize)]
struct ErrorResponse {
    pub error: String,
    pub details: Option<String>,
}

/// Get breach detection engine status
fn create_engine() -> std::result::Result<BreachDetectionEngine, String> {
    BreachDetectionEngine::from_env().map_err(|e| e.to_string())
}

/// POST /api/recon/breach/email
/// Check an email address for breaches
pub async fn check_email(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<EmailCheckRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let email = body.email.trim().to_lowercase();

    // Validate email format
    if !email.contains('@') || email.len() < 5 {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "Invalid email format".to_string(),
            details: Some("Please provide a valid email address".to_string()),
        }));
    }

    info!("Breach check for email: {} by user {}", email, user_id);

    let engine = match create_engine() {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to create breach engine: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to initialize breach detection engine".to_string(),
                details: Some(e),
            }));
        }
    };

    match engine.check_email(&email, body.include_unverified).await {
        Ok(result) => {
            let has_critical = result
                .breaches
                .iter()
                .any(|b| b.severity == BreachSeverity::Critical);
            let has_high = result
                .breaches
                .iter()
                .any(|b| b.severity == BreachSeverity::High);

            // Save to history
            let sources: Vec<String> = result.sources_checked.iter().map(|s| s.to_string()).collect();
            let history_id = match breach_db::save_breach_check_result(
                pool.get_ref(),
                user_id,
                "email",
                &email,
                &result,
                false,
            )
            .await
            {
                Ok(id) => id,
                Err(e) => {
                    error!("Failed to save breach check to history: {}", e);
                    result.id.clone()
                }
            };

            Ok(HttpResponse::Ok().json(BreachCheckResponse {
                success: true,
                id: history_id,
                check_type: "email".to_string(),
                target: email,
                breach_count: result.stats.unique_breaches,
                exposure_count: result.stats.total_exposures,
                password_exposures: result.stats.password_exposures,
                has_critical,
                has_high,
                sources_checked: sources,
                result,
            }))
        }
        Err(e) => {
            error!("Breach check failed for {}: {}", email, e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Breach check failed".to_string(),
                details: Some(e.to_string()),
            }))
        }
    }
}

/// POST /api/recon/breach/domain
/// Check a domain for breaches (all emails at that domain)
pub async fn check_domain(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<DomainCheckRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let domain = body.domain.trim().to_lowercase();

    // Basic domain validation
    if !domain.contains('.') || domain.len() < 4 {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "Invalid domain format".to_string(),
            details: Some("Please provide a valid domain (e.g., example.com)".to_string()),
        }));
    }

    info!("Breach check for domain: {} by user {}", domain, user_id);

    let engine = match create_engine() {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to create breach engine: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to initialize breach detection engine".to_string(),
                details: Some(e),
            }));
        }
    };

    // Check if HIBP API key is configured for domain searches
    if !engine.has_hibp_key() && !engine.has_dehashed() {
        return Ok(HttpResponse::ServiceUnavailable().json(ErrorResponse {
            error: "API key required for domain searches".to_string(),
            details: Some(
                "Configure HIBP_API_KEY or DEHASHED_API_KEY environment variables".to_string(),
            ),
        }));
    }

    match engine.check_domain(&domain).await {
        Ok(result) => {
            let has_critical = result
                .breaches
                .iter()
                .any(|b| b.severity == BreachSeverity::Critical);
            let has_high = result
                .breaches
                .iter()
                .any(|b| b.severity == BreachSeverity::High);

            let sources: Vec<String> = result.sources_checked.iter().map(|s| s.to_string()).collect();

            // Save to history
            let history_id = match breach_db::save_breach_check_result(
                pool.get_ref(),
                user_id,
                "domain",
                &domain,
                &result,
                false,
            )
            .await
            {
                Ok(id) => id,
                Err(e) => {
                    error!("Failed to save breach check to history: {}", e);
                    result.id.clone()
                }
            };

            Ok(HttpResponse::Ok().json(BreachCheckResponse {
                success: true,
                id: history_id,
                check_type: "domain".to_string(),
                target: domain,
                breach_count: result.stats.unique_breaches,
                exposure_count: result.stats.total_exposures,
                password_exposures: result.stats.password_exposures,
                has_critical,
                has_high,
                sources_checked: sources,
                result,
            }))
        }
        Err(e) => {
            error!("Breach check failed for domain {}: {}", domain, e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Breach check failed".to_string(),
                details: Some(e.to_string()),
            }))
        }
    }
}

/// POST /api/recon/breach/password
/// Check if a password has been compromised using k-anonymity
pub async fn check_password(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<PasswordCheckRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Password should not be empty
    if body.password.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "Password cannot be empty".to_string(),
            details: None,
        }));
    }

    debug!("Password breach check by user {}", user_id);

    let engine = match create_engine() {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to create breach engine: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to initialize breach detection engine".to_string(),
                details: Some(e),
            }));
        }
    };

    match engine.check_password(&body.password).await {
        Ok(result) => {
            // Save to history (store "[password check]" as target, not the actual password)
            let check_result = BreachCheckResult {
                id: uuid::Uuid::new_v4().to_string(),
                check_type: BreachCheckType::Email, // Using Email type for simplicity
                target: "[password check]".to_string(),
                checked_at: chrono::Utc::now(),
                exposures: vec![],
                breaches: vec![],
                stats: crate::scanner::breach_detection::BreachCheckStats {
                    total_exposures: if result.compromised { 1 } else { 0 },
                    unique_breaches: if result.compromised { 1 } else { 0 },
                    password_exposures: if result.compromised { 1 } else { 0 },
                    ..Default::default()
                },
                errors: vec![],
                sources_checked: vec![crate::scanner::breach_detection::BreachSource::Hibp],
            };

            let _ = breach_db::save_breach_check_result(
                pool.get_ref(),
                user_id,
                "password",
                "[password check]",
                &check_result,
                false,
            )
            .await;

            Ok(HttpResponse::Ok().json(PasswordCheckResponse {
                success: true,
                compromised: result.compromised,
                count: result.count,
            }))
        }
        Err(e) => {
            error!("Password breach check failed: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Password check failed".to_string(),
                details: Some(e.to_string()),
            }))
        }
    }
}

/// GET /api/recon/breach/history
/// Get user's breach check history
pub async fn get_history(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<HistoryQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let entries = match breach_db::get_breach_check_history(
        pool.get_ref(),
        user_id,
        query.limit,
        query.offset,
    )
    .await
    {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to get breach check history: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve history".to_string(),
                details: Some(e.to_string()),
            }));
        }
    };

    let stats = match breach_db::get_breach_check_stats(pool.get_ref(), user_id).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get breach check stats: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve statistics".to_string(),
                details: Some(e.to_string()),
            }));
        }
    };

    Ok(HttpResponse::Ok().json(HistoryResponse {
        success: true,
        entries,
        stats,
    }))
}

/// History query parameters
#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// GET /api/recon/breach/history/{id}
/// Get a specific breach check result
pub async fn get_history_entry(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let id = path.into_inner();

    match breach_db::get_breach_check_result(pool.get_ref(), &id, user_id).await {
        Ok(Some(result)) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "result": result
        }))),
        Ok(None) => Ok(HttpResponse::NotFound().json(ErrorResponse {
            error: "Entry not found".to_string(),
            details: None,
        })),
        Err(e) => {
            error!("Failed to get breach check entry: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve entry".to_string(),
                details: Some(e.to_string()),
            }))
        }
    }
}

/// DELETE /api/recon/breach/history/{id}
/// Delete a breach check history entry
pub async fn delete_history_entry(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let id = path.into_inner();

    match breach_db::delete_breach_check_entry(pool.get_ref(), &id, user_id).await {
        Ok(true) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Entry deleted"
        }))),
        Ok(false) => Ok(HttpResponse::NotFound().json(ErrorResponse {
            error: "Entry not found".to_string(),
            details: None,
        })),
        Err(e) => {
            error!("Failed to delete breach check entry: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to delete entry".to_string(),
                details: Some(e.to_string()),
            }))
        }
    }
}

/// GET /api/recon/breach/status
/// Get breach detection engine status
pub async fn get_status(_claims: web::ReqData<Claims>) -> Result<HttpResponse> {
    let engine = match create_engine() {
        Ok(e) => e,
        Err(_e) => {
            return Ok(HttpResponse::Ok().json(StatusResponse {
                success: false,
                status: BreachEngineStatus {
                    hibp_available: false,
                    hibp_api_key_configured: false,
                    dehashed_available: false,
                    local_db_available: false,
                    password_check_available: false,
                },
            }));
        }
    };

    Ok(HttpResponse::Ok().json(StatusResponse {
        success: true,
        status: engine.get_status(),
    }))
}

/// Configure breach check routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/recon/breach")
            .route("/email", web::post().to(check_email))
            .route("/domain", web::post().to(check_domain))
            .route("/password", web::post().to(check_password))
            .route("/history", web::get().to(get_history))
            .route("/history/{id}", web::get().to(get_history_entry))
            .route("/history/{id}", web::delete().to(delete_history_entry))
            .route("/status", web::get().to(get_status)),
    );
}
