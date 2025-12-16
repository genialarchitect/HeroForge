use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::scanner::dns_recon;
use crate::types::DnsReconResult;
use crate::web::auth;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsReconRequest {
    pub domain: String,
    #[serde(default = "default_include_subdomains")]
    pub include_subdomains: bool,
    #[serde(default)]
    pub custom_wordlist: Option<Vec<String>>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_include_subdomains() -> bool {
    true
}

fn default_timeout() -> u64 {
    30
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsReconResponse {
    pub id: String,
    pub result: DnsReconResult,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsReconListItem {
    pub id: String,
    pub domain: String,
    pub scan_timestamp: chrono::DateTime<chrono::Utc>,
    pub subdomains_count: usize,
    pub zone_transfer_vulnerable: bool,
    pub dnssec_enabled: bool,
}

/// POST /api/dns/recon - Perform DNS reconnaissance
pub async fn perform_dns_recon(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    req: web::Json<DnsReconRequest>,
) -> Result<HttpResponse> {
    // Validate domain format
    if req.domain.is_empty() || req.domain.len() > 253 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid domain: must be 1-253 characters"
        })));
    }

    // Basic domain validation (simple check)
    if !is_valid_domain(&req.domain) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid domain format"
        })));
    }

    // Limit timeout to reasonable value
    let timeout_secs = req.timeout_secs.min(300); // Max 5 minutes

    log::info!(
        "User {} initiated DNS recon for domain: {}",
        claims.sub,
        req.domain
    );

    // Perform DNS reconnaissance
    let result = match dns_recon::perform_dns_recon(
        &req.domain,
        req.include_subdomains,
        req.custom_wordlist.clone(),
        timeout_secs,
    )
    .await
    {
        Ok(res) => res,
        Err(e) => {
            log::error!("DNS recon failed for {}: {}", req.domain, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("DNS reconnaissance failed: {}", e)
            })));
        }
    };

    // Store result in database
    let dns_recon_id = uuid::Uuid::new_v4().to_string();
    let result_json = serde_json::to_string(&result).unwrap_or_default();
    let created_at = chrono::Utc::now();

    match sqlx::query(
        r#"
        INSERT INTO dns_recon_results (id, user_id, domain, result_json, created_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(&dns_recon_id)
    .bind(&claims.sub)
    .bind(&req.domain)
    .bind(&result_json)
    .bind(created_at)
    .execute(pool.as_ref())
    .await
    {
        Ok(_) => {
            log::info!("DNS recon result stored with ID: {}", dns_recon_id);
        }
        Err(e) => {
            log::warn!("Failed to store DNS recon result: {}", e);
            // Don't fail the request, just log the warning
        }
    }

    Ok(HttpResponse::Ok().json(DnsReconResponse {
        id: dns_recon_id,
        result,
    }))
}

/// GET /api/dns/recon/{id} - Get DNS recon result by ID
pub async fn get_dns_recon_result(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let dns_recon_id = path.into_inner();

    let result = sqlx::query_as::<_, (String, String, String, chrono::DateTime<chrono::Utc>)>(
        r#"
        SELECT id, domain, result_json, created_at
        FROM dns_recon_results
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&dns_recon_id)
    .bind(&claims.sub)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        log::error!("Database error fetching DNS recon result: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    match result {
        Some((id, _domain, result_json, _created_at)) => {
            let dns_result: DnsReconResult = serde_json::from_str(&result_json)
                .map_err(|e| {
                    log::error!("Failed to deserialize DNS recon result: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to parse result")
                })?;

            Ok(HttpResponse::Ok().json(DnsReconResponse {
                id,
                result: dns_result,
            }))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "DNS recon result not found"
        }))),
    }
}

/// GET /api/dns/recon - List all DNS recon results for the user
pub async fn list_dns_recon_results(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let results = sqlx::query_as::<_, (String, String, String, chrono::DateTime<chrono::Utc>)>(
        r#"
        SELECT id, domain, result_json, created_at
        FROM dns_recon_results
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 100
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        log::error!("Database error listing DNS recon results: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    let list_items: Vec<DnsReconListItem> = results
        .into_iter()
        .filter_map(|(id, domain, result_json, _created_at)| {
            let dns_result: DnsReconResult = serde_json::from_str(&result_json).ok()?;

            Some(DnsReconListItem {
                id,
                domain,
                scan_timestamp: dns_result.scan_timestamp,
                subdomains_count: dns_result.subdomains_found.len(),
                zone_transfer_vulnerable: dns_result.zone_transfer_vulnerable,
                dnssec_enabled: dns_result.dnssec_enabled,
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(list_items))
}

/// DELETE /api/dns/recon/{id} - Delete DNS recon result
pub async fn delete_dns_recon_result(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let dns_recon_id = path.into_inner();

    let result = sqlx::query(
        r#"
        DELETE FROM dns_recon_results
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&dns_recon_id)
    .bind(&claims.sub)
    .execute(pool.as_ref())
    .await
    .map_err(|e| {
        log::error!("Database error deleting DNS recon result: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    if result.rows_affected() > 0 {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "DNS recon result deleted"
        })))
    } else {
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "DNS recon result not found"
        })))
    }
}

/// GET /api/dns/wordlist - Get the built-in subdomain wordlist
pub async fn get_wordlist(_claims: web::ReqData<auth::Claims>) -> Result<HttpResponse> {
    let wordlist = dns_recon::get_builtin_wordlist();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "wordlist": wordlist,
        "count": wordlist.len()
    })))
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

        // Label must start and end with alphanumeric
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }

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

        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("example"));
        assert!(!is_valid_domain("-example.com"));
        assert!(!is_valid_domain("example-.com"));
        assert!(!is_valid_domain("example..com"));
    }
}
