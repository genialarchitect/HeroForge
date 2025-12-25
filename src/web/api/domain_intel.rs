//! Domain Intelligence API endpoints
//!
//! This module provides REST API endpoints for WHOIS lookup
//! and comprehensive domain intelligence gathering.

#![allow(dead_code)]

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::scanner::{domain_intel, whois};
use crate::web::auth;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request for WHOIS lookup
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WhoisLookupRequest {
    /// Domain to look up (for POST requests)
    pub domain: Option<String>,
    /// Timeout in seconds (default: 30)
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    30
}

/// Response for WHOIS lookup
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WhoisLookupResponse {
    pub id: String,
    pub domain: String,
    pub whois: whois::WhoisData,
    pub cached: bool,
}

/// Request for full domain intelligence
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainIntelRequest {
    /// Domain to investigate (for POST requests)
    pub domain: Option<String>,
    /// Include WHOIS lookup (default: true)
    #[serde(default = "default_true")]
    pub include_whois: bool,
    /// Include DNS reconnaissance (default: true)
    #[serde(default = "default_true")]
    pub include_dns: bool,
    /// Include subdomain enumeration (default: true)
    #[serde(default = "default_true")]
    pub include_subdomains: bool,
    /// Custom subdomain wordlist
    pub subdomain_wordlist: Option<Vec<String>>,
    /// Find related domains (default: true)
    #[serde(default = "default_true")]
    pub find_related: bool,
    /// Timeout in seconds (default: 30)
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_true() -> bool {
    true
}

impl Default for DomainIntelRequest {
    fn default() -> Self {
        Self {
            domain: None,
            include_whois: true,
            include_dns: true,
            include_subdomains: true,
            subdomain_wordlist: None,
            find_related: true,
            timeout_secs: 30,
        }
    }
}

/// Response for domain intelligence
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainIntelResponse {
    pub id: String,
    pub domain: String,
    pub intel: domain_intel::DomainIntel,
    pub cached: bool,
}

/// List item for domain intel cache
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainIntelListItem {
    pub id: String,
    pub domain: String,
    pub has_whois: bool,
    pub has_dns: bool,
    pub subdomain_count: usize,
    pub risk_score: u8,
    pub gathered_at: chrono::DateTime<Utc>,
}

/// Cache entry in database
#[derive(Debug)]
struct DomainIntelCacheEntry {
    id: String,
    domain: String,
    whois_data: Option<String>,
    intel_data: Option<String>,
    last_updated: chrono::DateTime<Utc>,
}

// ============================================================================
// API Handlers
// ============================================================================

/// GET /api/recon/whois/{domain} - WHOIS lookup for a domain
pub async fn whois_lookup(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<WhoisLookupRequest>,
) -> Result<HttpResponse> {
    let domain = path.into_inner();

    // Validate domain format
    if !is_valid_domain(&domain) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid domain format"
        })));
    }

    log::info!("User {} initiated WHOIS lookup for domain: {}", claims.sub, domain);

    // Check cache first (24 hour TTL for WHOIS)
    if let Some(cached) = get_cached_whois(&pool, &domain, &claims.sub, 24 * 60).await {
        log::debug!("Returning cached WHOIS data for {}", domain);
        return Ok(HttpResponse::Ok().json(WhoisLookupResponse {
            id: cached.0,
            domain: domain.clone(),
            whois: cached.1,
            cached: true,
        }));
    }

    // Check if whois command is available
    if !whois::is_whois_available() {
        return Ok(HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "WHOIS command not available on server"
        })));
    }

    // Perform WHOIS lookup
    let timeout = query.timeout_secs.min(300); // Max 5 minutes
    let whois_data = match whois::lookup_domain_with_timeout(&domain, timeout).await {
        Ok(data) => data,
        Err(e) => {
            log::error!("WHOIS lookup failed for {}: {}", domain, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("WHOIS lookup failed: {}", e)
            })));
        }
    };

    // Cache the result
    let cache_id = uuid::Uuid::new_v4().to_string();
    let _ = cache_whois_data(&pool, &cache_id, &domain, &claims.sub, &whois_data).await;

    Ok(HttpResponse::Ok().json(WhoisLookupResponse {
        id: cache_id,
        domain,
        whois: whois_data,
        cached: false,
    }))
}

/// GET /api/recon/domain-intel/{domain} - Full domain intelligence
pub async fn domain_intelligence(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<DomainIntelRequest>,
) -> Result<HttpResponse> {
    let domain = path.into_inner();

    // Validate domain format
    if !is_valid_domain(&domain) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid domain format"
        })));
    }

    log::info!(
        "User {} initiated domain intelligence gathering for: {}",
        claims.sub,
        domain
    );

    // Check cache first (6 hour TTL for full intel)
    if let Some(cached) = get_cached_intel(&pool, &domain, &claims.sub, 6 * 60).await {
        log::debug!("Returning cached domain intel for {}", domain);
        return Ok(HttpResponse::Ok().json(DomainIntelResponse {
            id: cached.0,
            domain: domain.clone(),
            intel: cached.1,
            cached: true,
        }));
    }

    // Build configuration
    let config = domain_intel::DomainIntelConfig {
        include_whois: query.include_whois,
        include_dns: query.include_dns,
        include_subdomains: query.include_subdomains,
        subdomain_wordlist: query.subdomain_wordlist.clone(),
        timeout_secs: query.timeout_secs.min(300),
        find_related: query.find_related,
        calculate_security: true,
    };

    // Gather domain intelligence
    let intel = match domain_intel::gather_domain_intel_with_config(&domain, &config).await {
        Ok(data) => data,
        Err(e) => {
            log::error!("Domain intelligence gathering failed for {}: {}", domain, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Domain intelligence gathering failed: {}", e)
            })));
        }
    };

    // Cache the result
    let cache_id = uuid::Uuid::new_v4().to_string();
    let _ = cache_intel_data(&pool, &cache_id, &domain, &claims.sub, &intel).await;

    Ok(HttpResponse::Ok().json(DomainIntelResponse {
        id: cache_id,
        domain,
        intel,
        cached: false,
    }))
}

/// GET /api/recon/domain-intel - List cached domain intel for user
pub async fn list_domain_intel(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let results = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, String)>(
        r#"
        SELECT id, domain, whois_data, intel_data, last_updated
        FROM domain_intel_cache
        WHERE user_id = ?
        ORDER BY last_updated DESC
        LIMIT 100
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        log::error!("Database error listing domain intel: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    let list_items: Vec<DomainIntelListItem> = results
        .into_iter()
        .filter_map(|(id, domain, whois_json, intel_json, last_updated)| {
            let gathered_at = chrono::DateTime::parse_from_rfc3339(&last_updated)
                .ok()?
                .with_timezone(&Utc);

            let has_whois = whois_json.is_some();
            let mut subdomain_count = 0;
            let mut risk_score = 0;
            let has_dns;

            if let Some(ref intel_str) = intel_json {
                if let Ok(intel) = serde_json::from_str::<domain_intel::DomainIntel>(intel_str) {
                    subdomain_count = intel.subdomains.len();
                    risk_score = intel.security.risk_score;
                    has_dns = intel.dns.is_some();
                } else {
                    has_dns = false;
                }
            } else {
                has_dns = false;
            }

            Some(DomainIntelListItem {
                id,
                domain,
                has_whois,
                has_dns,
                subdomain_count,
                risk_score,
                gathered_at,
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(list_items))
}

/// GET /api/recon/domain-intel/cache/{id} - Get cached domain intel by ID
pub async fn get_cached_intel_by_id(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let cache_id = path.into_inner();

    let result = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, String)>(
        r#"
        SELECT id, domain, whois_data, intel_data, last_updated
        FROM domain_intel_cache
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&cache_id)
    .bind(&claims.sub)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        log::error!("Database error fetching cached intel: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    match result {
        Some((id, domain, whois_json, intel_json, _)) => {
            if let Some(intel_str) = intel_json {
                if let Ok(intel) = serde_json::from_str::<domain_intel::DomainIntel>(&intel_str) {
                    return Ok(HttpResponse::Ok().json(DomainIntelResponse {
                        id,
                        domain,
                        intel,
                        cached: true,
                    }));
                }
            }

            // Fall back to WHOIS-only response
            if let Some(whois_str) = whois_json {
                if let Ok(whois_data) = serde_json::from_str::<whois::WhoisData>(&whois_str) {
                    return Ok(HttpResponse::Ok().json(WhoisLookupResponse {
                        id,
                        domain,
                        whois: whois_data,
                        cached: true,
                    }));
                }
            }

            Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Cached data not found or corrupted"
            })))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Cache entry not found"
        }))),
    }
}

/// DELETE /api/recon/domain-intel/cache/{id} - Delete cached domain intel
pub async fn delete_cached_intel(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let cache_id = path.into_inner();

    let result = sqlx::query(
        r#"
        DELETE FROM domain_intel_cache
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&cache_id)
    .bind(&claims.sub)
    .execute(pool.as_ref())
    .await
    .map_err(|e| {
        log::error!("Database error deleting cached intel: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    if result.rows_affected() > 0 {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Cache entry deleted"
        })))
    } else {
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Cache entry not found"
        })))
    }
}

/// GET /api/recon/whois/status - Check WHOIS availability
pub async fn whois_status(_claims: web::ReqData<auth::Claims>) -> Result<HttpResponse> {
    let available = whois::is_whois_available();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "available": available,
        "message": if available {
            "WHOIS command is available"
        } else {
            "WHOIS command not found on system"
        }
    })))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Validate domain format
fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    let domain = domain.trim_end_matches('.');
    let labels: Vec<&str> = domain.split('.').collect();

    if labels.len() < 2 {
        return false;
    }

    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }

    true
}

/// Get cached WHOIS data if still valid
async fn get_cached_whois(
    pool: &SqlitePool,
    domain: &str,
    user_id: &str,
    max_age_minutes: i64,
) -> Option<(String, whois::WhoisData)> {
    let result = sqlx::query_as::<_, (String, String, String)>(
        r#"
        SELECT id, whois_data, last_updated
        FROM domain_intel_cache
        WHERE domain = ? AND user_id = ? AND whois_data IS NOT NULL
        ORDER BY last_updated DESC
        LIMIT 1
        "#,
    )
    .bind(domain)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()??;

    let (id, whois_json, last_updated) = result;

    // Check if cache is still valid
    let updated = chrono::DateTime::parse_from_rfc3339(&last_updated).ok()?;
    let age = Utc::now() - updated.with_timezone(&Utc);
    if age.num_minutes() > max_age_minutes {
        return None;
    }

    let whois_data: whois::WhoisData = serde_json::from_str(&whois_json).ok()?;
    Some((id, whois_data))
}

/// Get cached domain intel if still valid
async fn get_cached_intel(
    pool: &SqlitePool,
    domain: &str,
    user_id: &str,
    max_age_minutes: i64,
) -> Option<(String, domain_intel::DomainIntel)> {
    let result = sqlx::query_as::<_, (String, String, String)>(
        r#"
        SELECT id, intel_data, last_updated
        FROM domain_intel_cache
        WHERE domain = ? AND user_id = ? AND intel_data IS NOT NULL
        ORDER BY last_updated DESC
        LIMIT 1
        "#,
    )
    .bind(domain)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()??;

    let (id, intel_json, last_updated) = result;

    // Check if cache is still valid
    let updated = chrono::DateTime::parse_from_rfc3339(&last_updated).ok()?;
    let age = Utc::now() - updated.with_timezone(&Utc);
    if age.num_minutes() > max_age_minutes {
        return None;
    }

    let intel_data: domain_intel::DomainIntel = serde_json::from_str(&intel_json).ok()?;
    Some((id, intel_data))
}

/// Cache WHOIS data
async fn cache_whois_data(
    pool: &SqlitePool,
    id: &str,
    domain: &str,
    user_id: &str,
    whois: &whois::WhoisData,
) -> anyhow::Result<()> {
    let whois_json = serde_json::to_string(whois)?;
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO domain_intel_cache (id, domain, whois_data, last_updated, user_id)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(domain, user_id) DO UPDATE SET
            whois_data = excluded.whois_data,
            last_updated = excluded.last_updated
        "#,
    )
    .bind(id)
    .bind(domain)
    .bind(&whois_json)
    .bind(&now)
    .bind(user_id)
    .execute(pool)
    .await?;

    log::debug!("Cached WHOIS data for {} (id: {})", domain, id);
    Ok(())
}

/// Cache domain intel data
async fn cache_intel_data(
    pool: &SqlitePool,
    id: &str,
    domain: &str,
    user_id: &str,
    intel: &domain_intel::DomainIntel,
) -> anyhow::Result<()> {
    let intel_json = serde_json::to_string(intel)?;
    let whois_json = intel
        .whois
        .as_ref()
        .map(|w| serde_json::to_string(w).ok())
        .flatten();
    let related_json = serde_json::to_string(&intel.related_domains)?;
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO domain_intel_cache (id, domain, whois_data, intel_data, related_domains, last_updated, user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(domain, user_id) DO UPDATE SET
            whois_data = excluded.whois_data,
            intel_data = excluded.intel_data,
            related_domains = excluded.related_domains,
            last_updated = excluded.last_updated
        "#,
    )
    .bind(id)
    .bind(domain)
    .bind(&whois_json)
    .bind(&intel_json)
    .bind(&related_json)
    .bind(&now)
    .bind(user_id)
    .execute(pool)
    .await?;

    log::debug!("Cached domain intel for {} (id: {})", domain, id);
    Ok(())
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure domain intelligence routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/recon")
            // WHOIS endpoints
            .route("/whois/status", web::get().to(whois_status))
            .route("/whois/{domain}", web::get().to(whois_lookup))
            // Domain intelligence endpoints
            .route("/domain-intel", web::get().to(list_domain_intel))
            .route("/domain-intel/cache/{id}", web::get().to(get_cached_intel_by_id))
            .route("/domain-intel/cache/{id}", web::delete().to(delete_cached_intel))
            .route("/domain-intel/{domain}", web::get().to(domain_intelligence)),
    );
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
        assert!(!is_valid_domain(".example.com"));
    }

    #[test]
    fn test_domain_intel_request_default() {
        let req = DomainIntelRequest::default();
        assert!(req.include_whois);
        assert!(req.include_dns);
        assert!(req.include_subdomains);
        assert!(req.find_related);
        assert_eq!(req.timeout_secs, 30);
    }
}
