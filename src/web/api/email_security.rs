//! Email Security Analysis API
//!
//! Provides endpoints for analyzing email security configurations (SPF, DKIM, DMARC)
//! for domains.

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::scanner::email_security::{self, EmailSecurityResult, SpoofabilityRating};
use crate::web::auth;

/// Request body for email security analysis
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailSecurityRequest {
    /// The domain to analyze
    pub domain: String,
}

/// Response wrapper for email security analysis
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailSecurityResponse {
    /// Unique identifier for this analysis
    pub id: String,
    /// The full analysis result
    pub result: EmailSecurityResult,
}

/// List item for email security results
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailSecurityListItem {
    /// Unique identifier
    pub id: String,
    /// The domain analyzed
    pub domain: String,
    /// Spoofability rating
    pub spoofability_rating: SpoofabilityRating,
    /// Whether SPF is configured
    pub spf_configured: bool,
    /// Whether DKIM is configured
    pub dkim_configured: bool,
    /// Whether DMARC is configured
    pub dmarc_configured: bool,
    /// When the analysis was performed
    pub analyzed_at: chrono::DateTime<chrono::Utc>,
}

/// POST /api/recon/email-security - Analyze email security for a domain
///
/// Performs a comprehensive analysis of email security configurations including:
/// - SPF (Sender Policy Framework)
/// - DKIM (DomainKeys Identified Mail)
/// - DMARC (Domain-based Message Authentication, Reporting & Conformance)
///
/// Returns a spoofability rating and recommendations for improving email security.
pub async fn analyze_email_security(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    req: web::Json<EmailSecurityRequest>,
) -> Result<HttpResponse> {
    // Validate domain format
    if req.domain.is_empty() || req.domain.len() > 253 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid domain: must be 1-253 characters"
        })));
    }

    // Basic domain validation
    if !is_valid_domain(&req.domain) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid domain format"
        })));
    }

    log::info!(
        "User {} initiated email security analysis for domain: {}",
        claims.sub,
        req.domain
    );

    // Perform email security analysis
    let result = match email_security::analyze_domain(&req.domain).await {
        Ok(res) => res,
        Err(e) => {
            log::error!("Email security analysis failed for {}: {}", req.domain, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Email security analysis failed: {}", e)
            })));
        }
    };

    // Store result in database
    let result_id = uuid::Uuid::new_v4().to_string();
    let result_json = serde_json::to_string(&result).unwrap_or_default();
    let spf_record = result.spf.record.clone().unwrap_or_default();
    let dkim_selectors: String = result
        .dkim
        .selectors_found
        .iter()
        .map(|s| s.selector.clone())
        .collect::<Vec<_>>()
        .join(",");
    let dmarc_policy = result
        .dmarc
        .policy
        .as_ref()
        .map(|p| format!("{:?}", p).to_lowercase())
        .unwrap_or_default();
    let spoofability = format!("{:?}", result.spoofability_rating).to_lowercase();
    let analyzed_at = chrono::Utc::now();

    match sqlx::query(
        r#"
        INSERT INTO email_security_results
        (id, domain, spf_record, dkim_selectors, dmarc_policy, spoofability, result_json, analyzed_at, user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&result_id)
    .bind(&req.domain)
    .bind(&spf_record)
    .bind(&dkim_selectors)
    .bind(&dmarc_policy)
    .bind(&spoofability)
    .bind(&result_json)
    .bind(analyzed_at)
    .bind(&claims.sub)
    .execute(pool.as_ref())
    .await
    {
        Ok(_) => {
            log::info!("Email security result stored with ID: {}", result_id);
        }
        Err(e) => {
            log::warn!("Failed to store email security result: {}", e);
            // Don't fail the request, just log the warning
        }
    }

    Ok(HttpResponse::Ok().json(EmailSecurityResponse {
        id: result_id,
        result,
    }))
}

/// GET /api/recon/email-security/{id} - Get email security result by ID
pub async fn get_email_security_result(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let result_id = path.into_inner();

    let result = sqlx::query_as::<_, (String, String, chrono::DateTime<chrono::Utc>)>(
        r#"
        SELECT id, result_json, analyzed_at
        FROM email_security_results
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&result_id)
    .bind(&claims.sub)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        log::error!("Database error fetching email security result: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    match result {
        Some((id, result_json, _analyzed_at)) => {
            let email_result: EmailSecurityResult = serde_json::from_str(&result_json)
                .map_err(|e| {
                    log::error!("Failed to deserialize email security result: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to parse result")
                })?;

            Ok(HttpResponse::Ok().json(EmailSecurityResponse {
                id,
                result: email_result,
            }))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Email security result not found"
        }))),
    }
}

/// GET /api/recon/email-security - List all email security results for the user
pub async fn list_email_security_results(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let results = sqlx::query_as::<_, (String, String, String, chrono::DateTime<chrono::Utc>)>(
        r#"
        SELECT id, domain, result_json, analyzed_at
        FROM email_security_results
        WHERE user_id = ?
        ORDER BY analyzed_at DESC
        LIMIT 100
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        log::error!("Database error listing email security results: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    let list_items: Vec<EmailSecurityListItem> = results
        .into_iter()
        .filter_map(|(id, domain, result_json, analyzed_at)| {
            let email_result: EmailSecurityResult = serde_json::from_str(&result_json).ok()?;

            Some(EmailSecurityListItem {
                id,
                domain,
                spoofability_rating: email_result.spoofability_rating,
                spf_configured: email_result.spf.record.is_some(),
                dkim_configured: email_result.dkim.configured,
                dmarc_configured: email_result.dmarc.record.is_some(),
                analyzed_at,
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(list_items))
}

/// DELETE /api/recon/email-security/{id} - Delete email security result
pub async fn delete_email_security_result(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let result_id = path.into_inner();

    let result = sqlx::query(
        r#"
        DELETE FROM email_security_results
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&result_id)
    .bind(&claims.sub)
    .execute(pool.as_ref())
    .await
    .map_err(|e| {
        log::error!("Database error deleting email security result: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    if result.rows_affected() > 0 {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Email security result deleted"
        })))
    } else {
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Email security result not found"
        })))
    }
}

/// Validate domain format (basic validation)
fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    // Remove trailing dot if present
    let domain = domain.trim_end_matches('.');

    // Split into labels
    let labels: Vec<&str> = domain.split('.').collect();

    if labels.len() < 2 {
        return false;
    }

    // Validate each label
    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        // Label must contain only alphanumeric and hyphens
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }

        // Label must not start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("example.co.uk"));
        assert!(is_valid_domain("test-domain.com"));
        assert!(is_valid_domain("123.example.com"));

        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("example"));
        assert!(!is_valid_domain("-example.com"));
        assert!(!is_valid_domain("example-.com"));
        assert!(!is_valid_domain("example..com"));
        assert!(!is_valid_domain("example.com-"));
    }
}
