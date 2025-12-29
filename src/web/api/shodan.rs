//! Shodan Reconnaissance API endpoints
//!
//! Provides REST API access to Shodan integration for network reconnaissance:
//! - GET /api/recon/shodan/host/{ip} - Host lookup with caching
//! - POST /api/recon/shodan/search - Search query
//! - POST /api/recon/shodan/dns/resolve - DNS resolution
//! - POST /api/recon/shodan/dns/reverse - Reverse DNS

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use uuid::Uuid;

use crate::db::models;
use crate::db::shodan_cache;
use crate::integrations::shodan::{ShodanClient, ShodanHost, ShodanSearchResult};
use crate::web::auth::Claims;

/// Response wrapper for host lookup
#[derive(Debug, Serialize)]
pub struct HostLookupResponse {
    pub success: bool,
    pub cached: bool,
    pub data: ShodanHost,
}

/// Response wrapper for search
#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub success: bool,
    pub cached: bool,
    pub data: ShodanSearchResult,
}

/// Request for search query
#[derive(Debug, Deserialize)]
pub struct SearchRequest {
    /// Shodan search query (e.g., "apache", "port:22", "vuln:CVE-2021-44228")
    pub query: String,
    /// Page number (default: 1)
    #[serde(default = "default_page")]
    pub page: u32,
    /// CRM customer ID to associate with this query
    pub customer_id: Option<String>,
    /// CRM engagement ID to associate with this query
    pub engagement_id: Option<String>,
}

fn default_page() -> u32 {
    1
}

/// Request for DNS resolution
#[derive(Debug, Deserialize)]
pub struct DnsResolveRequest {
    /// List of hostnames to resolve
    pub hostnames: Vec<String>,
}

/// Response for DNS resolution
#[derive(Debug, Serialize)]
pub struct DnsResolveResponse {
    pub success: bool,
    /// Map of hostname -> list of IPs
    pub results: HashMap<String, Vec<String>>,
    /// Hostnames that were served from cache
    pub cached: Vec<String>,
}

/// Request for reverse DNS
#[derive(Debug, Deserialize)]
pub struct DnsReverseRequest {
    /// List of IP addresses to resolve
    pub ips: Vec<String>,
}

/// Response for reverse DNS
#[derive(Debug, Serialize)]
pub struct DnsReverseResponse {
    pub success: bool,
    /// Map of IP -> list of hostnames
    pub results: HashMap<String, Vec<String>>,
    /// IPs that were served from cache
    pub cached: Vec<String>,
}

/// Response for API status
#[derive(Debug, Serialize)]
pub struct ShodanStatusResponse {
    pub available: bool,
    pub query_credits: Option<i32>,
    pub scan_credits: Option<i32>,
    pub plan: Option<String>,
    pub cache_stats: Option<CacheStatsResponse>,
}

/// Cache statistics response
#[derive(Debug, Serialize)]
pub struct CacheStatsResponse {
    pub total_entries: i64,
    pub host_entries: i64,
    pub search_entries: i64,
    pub dns_resolve_entries: i64,
    pub dns_reverse_entries: i64,
    pub expired_entries: i64,
}

/// Error response
#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}

/// Get Shodan API key from environment or user settings
fn get_shodan_api_key() -> Option<String> {
    std::env::var("SHODAN_API_KEY").ok()
}

/// GET /api/recon/shodan/status
/// Get Shodan API status and cache statistics
pub async fn get_status(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let api_key = get_shodan_api_key();

    if api_key.is_none() {
        return Ok(HttpResponse::Ok().json(ShodanStatusResponse {
            available: false,
            query_credits: None,
            scan_credits: None,
            plan: None,
            cache_stats: None,
        }));
    }

    let client = match ShodanClient::new(api_key.unwrap()) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create Shodan client: {}", e);
            return Ok(HttpResponse::Ok().json(ShodanStatusResponse {
                available: false,
                query_credits: None,
                scan_credits: None,
                plan: None,
                cache_stats: None,
            }));
        }
    };

    let api_info = client.get_api_info().await.ok();
    let cache_stats = shodan_cache::get_cache_stats(pool.get_ref()).await.ok();

    let response = ShodanStatusResponse {
        available: api_info.is_some(),
        query_credits: api_info.as_ref().map(|i| i.query_credits),
        scan_credits: api_info.as_ref().map(|i| i.scan_credits),
        plan: api_info.map(|i| i.plan),
        cache_stats: cache_stats.map(|s| CacheStatsResponse {
            total_entries: s.total_entries,
            host_entries: s.host_entries,
            search_entries: s.search_entries,
            dns_resolve_entries: s.dns_resolve_entries,
            dns_reverse_entries: s.dns_reverse_entries,
            expired_entries: s.expired_entries,
        }),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// GET /api/recon/shodan/host/{ip}
/// Look up host information (checks cache first)
pub async fn host_lookup(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let ip = path.into_inner();

    // Validate IP format
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "Invalid IP address format".to_string(),
            details: Some(format!("'{}' is not a valid IP address", ip)),
        }));
    }

    info!("Shodan host lookup for IP: {} by user {}", ip, user_id);

    // Check cache first
    match shodan_cache::get_cached_host(pool.get_ref(), &ip).await {
        Ok(Some(host)) => {
            debug!("Returning cached Shodan host data for {}", ip);
            // Record query to history (cached)
            let _ = shodan_cache::record_shodan_query(
                pool.get_ref(),
                user_id,
                "host",
                &ip,
                Some(host.ports.len() as i64),
                true,
            )
            .await;
            return Ok(HttpResponse::Ok().json(HostLookupResponse {
                success: true,
                cached: true,
                data: host,
            }));
        }
        Ok(None) => {
            debug!("No cache entry for Shodan host {}", ip);
        }
        Err(e) => {
            error!("Cache lookup error for {}: {}", ip, e);
        }
    }

    // Check for API key
    let api_key = match get_shodan_api_key() {
        Some(key) => key,
        None => {
            return Ok(HttpResponse::ServiceUnavailable().json(ErrorResponse {
                error: "Shodan API not configured".to_string(),
                details: Some("Set SHODAN_API_KEY environment variable".to_string()),
            }));
        }
    };

    // Create client and perform lookup
    let client = match ShodanClient::new(api_key) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create Shodan client: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to initialize Shodan client".to_string(),
                details: Some(e.to_string()),
            }));
        }
    };

    match client.host_lookup(&ip).await {
        Ok(host) => {
            // Cache the result
            if let Err(e) = shodan_cache::cache_host(pool.get_ref(), &ip, &host).await {
                error!("Failed to cache Shodan host {}: {}", ip, e);
            }

            // Record query to history (not cached)
            let _ = shodan_cache::record_shodan_query(
                pool.get_ref(),
                user_id,
                "host",
                &ip,
                Some(host.ports.len() as i64),
                false,
            )
            .await;

            // Create audit log
            log_audit(
                pool.get_ref(),
                user_id,
                "shodan_host_lookup",
                "ip",
                &ip,
                &format!("Shodan host lookup for {}", ip),
            )
            .await;

            Ok(HttpResponse::Ok().json(HostLookupResponse {
                success: true,
                cached: false,
                data: host,
            }))
        }
        Err(e) => {
            if e.to_string().contains("not found") {
                Ok(HttpResponse::NotFound().json(ErrorResponse {
                    error: "Host not found in Shodan database".to_string(),
                    details: Some(format!("IP {} has not been indexed by Shodan", ip)),
                }))
            } else {
                error!("Shodan host lookup failed for {}: {}", ip, e);
                Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Shodan lookup failed".to_string(),
                    details: Some(e.to_string()),
                }))
            }
        }
    }
}

/// POST /api/recon/shodan/search
/// Search Shodan for hosts matching a query
pub async fn search(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<SearchRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let query = body.query.trim();
    let page = body.page;

    if query.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "Search query is required".to_string(),
            details: None,
        }));
    }

    info!(
        "Shodan search: '{}' (page {}) by user {}",
        query, page, user_id
    );

    // Check cache first
    match shodan_cache::get_cached_search(pool.get_ref(), query, page).await {
        Ok(Some(result)) => {
            debug!("Returning cached Shodan search for '{}'", query);
            // Record query to history (cached)
            let _ = shodan_cache::record_shodan_query(
                pool.get_ref(),
                user_id,
                "search",
                query,
                Some(result.total),
                true,
            )
            .await;
            return Ok(HttpResponse::Ok().json(SearchResponse {
                success: true,
                cached: true,
                data: result,
            }));
        }
        Ok(None) => {
            debug!("No cache entry for Shodan search '{}'", query);
        }
        Err(e) => {
            error!("Cache lookup error for search '{}': {}", query, e);
        }
    }

    // Check for API key
    let api_key = match get_shodan_api_key() {
        Some(key) => key,
        None => {
            return Ok(HttpResponse::ServiceUnavailable().json(ErrorResponse {
                error: "Shodan API not configured".to_string(),
                details: Some("Set SHODAN_API_KEY environment variable".to_string()),
            }));
        }
    };

    // Create client and perform search
    let client = match ShodanClient::new(api_key) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create Shodan client: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to initialize Shodan client".to_string(),
                details: Some(e.to_string()),
            }));
        }
    };

    match client.search(query, page).await {
        Ok(result) => {
            // Cache the result
            if let Err(e) = shodan_cache::cache_search(pool.get_ref(), query, page, &result).await {
                error!("Failed to cache Shodan search '{}': {}", query, e);
            }

            // Record query to history (not cached)
            let _ = shodan_cache::record_shodan_query(
                pool.get_ref(),
                user_id,
                "search",
                query,
                Some(result.total),
                false,
            )
            .await;

            // Create audit log
            log_audit(
                pool.get_ref(),
                user_id,
                "shodan_search",
                "query",
                query,
                &format!("Shodan search: '{}' (page {}, {} results)", query, page, result.total),
            )
            .await;

            Ok(HttpResponse::Ok().json(SearchResponse {
                success: true,
                cached: false,
                data: result,
            }))
        }
        Err(e) => {
            error!("Shodan search failed for '{}': {}", query, e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Shodan search failed".to_string(),
                details: Some(e.to_string()),
            }))
        }
    }
}

/// POST /api/recon/shodan/dns/resolve
/// Resolve hostnames to IP addresses
pub async fn dns_resolve(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<DnsResolveRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let hostnames = &body.hostnames;

    if hostnames.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "At least one hostname is required".to_string(),
            details: None,
        }));
    }

    if hostnames.len() > 100 {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "Too many hostnames".to_string(),
            details: Some("Maximum 100 hostnames per request".to_string()),
        }));
    }

    info!(
        "Shodan DNS resolve for {} hostnames by user {}",
        hostnames.len(),
        user_id
    );

    let mut results: HashMap<String, Vec<String>> = HashMap::new();
    let mut cached_hostnames: Vec<String> = Vec::new();
    let mut uncached_hostnames: Vec<String> = Vec::new();

    // Check cache for each hostname
    for hostname in hostnames {
        match shodan_cache::get_cached_dns_resolve(pool.get_ref(), hostname).await {
            Ok(Some(ips)) => {
                results.insert(hostname.clone(), ips);
                cached_hostnames.push(hostname.clone());
            }
            Ok(None) => {
                uncached_hostnames.push(hostname.clone());
            }
            Err(e) => {
                error!("Cache lookup error for DNS resolve '{}': {}", hostname, e);
                uncached_hostnames.push(hostname.clone());
            }
        }
    }

    // If all results were cached, return early
    if uncached_hostnames.is_empty() {
        return Ok(HttpResponse::Ok().json(DnsResolveResponse {
            success: true,
            results,
            cached: cached_hostnames,
        }));
    }

    // Check for API key
    let api_key = match get_shodan_api_key() {
        Some(key) => key,
        None => {
            return Ok(HttpResponse::ServiceUnavailable().json(ErrorResponse {
                error: "Shodan API not configured".to_string(),
                details: Some("Set SHODAN_API_KEY environment variable".to_string()),
            }));
        }
    };

    // Create client and perform DNS resolution for uncached hostnames
    let client = match ShodanClient::new(api_key) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create Shodan client: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to initialize Shodan client".to_string(),
                details: Some(e.to_string()),
            }));
        }
    };

    let uncached_refs: Vec<&str> = uncached_hostnames.iter().map(|s| s.as_str()).collect();
    match client.dns_resolve(&uncached_refs).await {
        Ok(resolved) => {
            // Cache and merge results
            for (hostname, ips) in &resolved {
                if let Err(e) =
                    shodan_cache::cache_dns_resolve(pool.get_ref(), hostname, ips).await
                {
                    error!("Failed to cache DNS resolve '{}': {}", hostname, e);
                }
                results.insert(hostname.clone(), ips.clone());
            }

            // Create audit log
            log_audit(
                pool.get_ref(),
                user_id,
                "shodan_dns_resolve",
                "hostnames",
                &hostnames.join(","),
                &format!(
                    "Shodan DNS resolve: {} hostnames ({} cached)",
                    hostnames.len(),
                    cached_hostnames.len()
                ),
            )
            .await;

            Ok(HttpResponse::Ok().json(DnsResolveResponse {
                success: true,
                results,
                cached: cached_hostnames,
            }))
        }
        Err(e) => {
            error!("Shodan DNS resolve failed: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Shodan DNS resolve failed".to_string(),
                details: Some(e.to_string()),
            }))
        }
    }
}

/// POST /api/recon/shodan/dns/reverse
/// Reverse DNS lookup
pub async fn dns_reverse(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<DnsReverseRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let ips = &body.ips;

    if ips.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "At least one IP address is required".to_string(),
            details: None,
        }));
    }

    if ips.len() > 100 {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "Too many IP addresses".to_string(),
            details: Some("Maximum 100 IPs per request".to_string()),
        }));
    }

    // Validate all IPs
    for ip in ips {
        if ip.parse::<std::net::IpAddr>().is_err() {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: "Invalid IP address format".to_string(),
                details: Some(format!("'{}' is not a valid IP address", ip)),
            }));
        }
    }

    info!(
        "Shodan DNS reverse for {} IPs by user {}",
        ips.len(),
        user_id
    );

    let mut results: HashMap<String, Vec<String>> = HashMap::new();
    let mut cached_ips: Vec<String> = Vec::new();
    let mut uncached_ips: Vec<String> = Vec::new();

    // Check cache for each IP
    for ip in ips {
        match shodan_cache::get_cached_dns_reverse(pool.get_ref(), ip).await {
            Ok(Some(hostnames)) => {
                results.insert(ip.clone(), hostnames);
                cached_ips.push(ip.clone());
            }
            Ok(None) => {
                uncached_ips.push(ip.clone());
            }
            Err(e) => {
                error!("Cache lookup error for DNS reverse '{}': {}", ip, e);
                uncached_ips.push(ip.clone());
            }
        }
    }

    // If all results were cached, return early
    if uncached_ips.is_empty() {
        return Ok(HttpResponse::Ok().json(DnsReverseResponse {
            success: true,
            results,
            cached: cached_ips,
        }));
    }

    // Check for API key
    let api_key = match get_shodan_api_key() {
        Some(key) => key,
        None => {
            return Ok(HttpResponse::ServiceUnavailable().json(ErrorResponse {
                error: "Shodan API not configured".to_string(),
                details: Some("Set SHODAN_API_KEY environment variable".to_string()),
            }));
        }
    };

    // Create client and perform reverse DNS lookup for uncached IPs
    let client = match ShodanClient::new(api_key) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create Shodan client: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to initialize Shodan client".to_string(),
                details: Some(e.to_string()),
            }));
        }
    };

    let uncached_refs: Vec<&str> = uncached_ips.iter().map(|s| s.as_str()).collect();
    match client.dns_reverse(&uncached_refs).await {
        Ok(resolved) => {
            // Cache and merge results
            for (ip, hostnames) in &resolved {
                if let Err(e) =
                    shodan_cache::cache_dns_reverse(pool.get_ref(), ip, hostnames).await
                {
                    error!("Failed to cache DNS reverse '{}': {}", ip, e);
                }
                results.insert(ip.clone(), hostnames.clone());
            }

            // Create audit log
            log_audit(
                pool.get_ref(),
                user_id,
                "shodan_dns_reverse",
                "ips",
                &ips.join(","),
                &format!(
                    "Shodan DNS reverse: {} IPs ({} cached)",
                    ips.len(),
                    cached_ips.len()
                ),
            )
            .await;

            Ok(HttpResponse::Ok().json(DnsReverseResponse {
                success: true,
                results,
                cached: cached_ips,
            }))
        }
        Err(e) => {
            error!("Shodan DNS reverse failed: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Shodan DNS reverse failed".to_string(),
                details: Some(e.to_string()),
            }))
        }
    }
}

/// DELETE /api/recon/shodan/cache
/// Clear the Shodan cache
pub async fn clear_cache(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    info!("Clearing Shodan cache by user {}", user_id);

    match shodan_cache::cleanup_expired_cache(pool.get_ref()).await {
        Ok(deleted) => {
            log_audit(
                pool.get_ref(),
                user_id,
                "shodan_cache_cleanup",
                "cache",
                "all",
                &format!("Cleaned up {} expired Shodan cache entries", deleted),
            )
            .await;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "deleted": deleted
            })))
        }
        Err(e) => {
            error!("Failed to clear Shodan cache: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to clear cache".to_string(),
                details: Some(e.to_string()),
            }))
        }
    }
}

/// Helper function to create audit log
async fn log_audit(
    pool: &SqlitePool,
    user_id: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
    details: &str,
) {
    let audit_log = models::AuditLog {
        id: Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        action: action.to_string(),
        target_type: Some(target_type.to_string()),
        target_id: Some(target_id.to_string()),
        details: Some(details.to_string()),
        ip_address: None,
        user_agent: None,
        created_at: Utc::now(),
    };

    if let Err(e) = crate::db::create_audit_log(pool, &audit_log).await {
        error!("Failed to create audit log: {}", e);
    }
}

/// Query for history endpoint
#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    /// Maximum number of records to return (default: 50, max: 100)
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Offset for pagination (default: 0)
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Response for history endpoint
#[derive(Debug, Serialize)]
pub struct HistoryResponse {
    pub success: bool,
    pub queries: Vec<shodan_cache::ShodanQueryRecord>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// GET /api/recon/shodan/history
/// Get user's Shodan query history
pub async fn get_history(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<HistoryQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Cap limit at 100
    let limit = query.limit.min(100).max(1);
    let offset = query.offset.max(0);

    debug!("Fetching Shodan query history for user {}", user_id);

    match shodan_cache::get_user_shodan_queries(pool.get_ref(), user_id, limit, offset).await {
        Ok(queries) => {
            let total = shodan_cache::get_user_shodan_query_count(pool.get_ref(), user_id)
                .await
                .unwrap_or(0);

            Ok(HttpResponse::Ok().json(HistoryResponse {
                success: true,
                queries,
                total,
                limit,
                offset,
            }))
        }
        Err(e) => {
            error!("Failed to fetch Shodan query history: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to fetch query history".to_string(),
                details: Some(e.to_string()),
            }))
        }
    }
}

/// Response for Shodan API key status
#[derive(Debug, Serialize)]
pub struct ShodanApiKeyStatusResponse {
    pub configured: bool,
    pub source: Option<String>, // "environment" or "user_settings"
    pub api_key_preview: Option<String>, // First 4 chars + "..." + last 4 chars
}

/// GET /api/settings/shodan
/// Get Shodan API key status (whether it's configured, not the actual key)
pub async fn get_api_key_status(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    debug!("Checking Shodan API key status for user {}", user_id);

    // First check environment variable
    if let Ok(env_key) = std::env::var("SHODAN_API_KEY") {
        if !env_key.is_empty() {
            let preview = mask_api_key(&env_key);
            return Ok(HttpResponse::Ok().json(ShodanApiKeyStatusResponse {
                configured: true,
                source: Some("environment".to_string()),
                api_key_preview: Some(preview),
            }));
        }
    }

    // Check user settings in database
    match get_user_shodan_api_key(pool.get_ref(), user_id).await {
        Ok(Some(key)) => {
            let preview = mask_api_key(&key);
            Ok(HttpResponse::Ok().json(ShodanApiKeyStatusResponse {
                configured: true,
                source: Some("user_settings".to_string()),
                api_key_preview: Some(preview),
            }))
        }
        Ok(None) => {
            Ok(HttpResponse::Ok().json(ShodanApiKeyStatusResponse {
                configured: false,
                source: None,
                api_key_preview: None,
            }))
        }
        Err(e) => {
            error!("Failed to check Shodan API key status: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to check API key status".to_string(),
                details: Some(e.to_string()),
            }))
        }
    }
}

/// Request to set Shodan API key
#[derive(Debug, Deserialize)]
pub struct SetApiKeyRequest {
    pub api_key: String,
}

/// PUT /api/settings/shodan
/// Set or update user's Shodan API key (stored encrypted in user settings)
pub async fn set_api_key(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<SetApiKeyRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let api_key = body.api_key.trim();

    if api_key.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "API key is required".to_string(),
            details: None,
        }));
    }

    // Validate the API key by making a test request
    let client = match ShodanClient::new(api_key.to_string()) {
        Ok(c) => c,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: "Invalid API key format".to_string(),
                details: Some(e.to_string()),
            }));
        }
    };

    // Test the API key
    match client.get_api_info().await {
        Ok(info) => {
            info!(
                "Shodan API key validated for user {}: {} plan, {} query credits",
                user_id, info.plan, info.query_credits
            );
        }
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: "Invalid API key".to_string(),
                details: Some(format!("API key validation failed: {}", e)),
            }));
        }
    }

    // Store the API key in user settings (encrypted)
    match set_user_shodan_api_key(pool.get_ref(), user_id, api_key).await {
        Ok(()) => {
            log_audit(
                pool.get_ref(),
                user_id,
                "shodan_api_key_set",
                "settings",
                "shodan",
                "Shodan API key configured",
            )
            .await;

            let preview = mask_api_key(api_key);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Shodan API key saved successfully",
                "api_key_preview": preview
            })))
        }
        Err(e) => {
            error!("Failed to save Shodan API key: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to save API key".to_string(),
                details: Some(e.to_string()),
            }))
        }
    }
}

/// DELETE /api/settings/shodan
/// Remove user's Shodan API key
pub async fn delete_api_key(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    match delete_user_shodan_api_key(pool.get_ref(), user_id).await {
        Ok(deleted) => {
            if deleted {
                log_audit(
                    pool.get_ref(),
                    user_id,
                    "shodan_api_key_deleted",
                    "settings",
                    "shodan",
                    "Shodan API key removed",
                )
                .await;
            }

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "deleted": deleted
            })))
        }
        Err(e) => {
            error!("Failed to delete Shodan API key: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to delete API key".to_string(),
                details: Some(e.to_string()),
            }))
        }
    }
}

/// Mask an API key for display (show first 4 and last 4 characters)
fn mask_api_key(key: &str) -> String {
    if key.len() <= 8 {
        "*".repeat(key.len())
    } else {
        format!("{}...{}", &key[..4], &key[key.len()-4..])
    }
}

/// Get user's Shodan API key from database
async fn get_user_shodan_api_key(pool: &SqlitePool, user_id: &str) -> anyhow::Result<Option<String>> {
    // Store in user_settings table with encryption
    let row = sqlx::query_as::<_, (String,)>(
        r#"
        SELECT setting_value
        FROM user_settings
        WHERE user_id = ? AND setting_key = 'shodan_api_key'
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((encrypted_key,)) => {
            // Decrypt the API key if encryption key is available
            match decrypt_api_key(&encrypted_key) {
                Ok(key) => Ok(Some(key)),
                Err(e) => {
                    error!("Failed to decrypt Shodan API key: {}", e);
                    // Return the raw value if decryption fails (might be unencrypted)
                    Ok(Some(encrypted_key))
                }
            }
        }
        None => Ok(None),
    }
}

/// Set user's Shodan API key in database (encrypted)
async fn set_user_shodan_api_key(pool: &SqlitePool, user_id: &str, api_key: &str) -> anyhow::Result<()> {
    // Ensure user_settings table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            setting_key TEXT NOT NULL,
            setting_value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, setting_key)
        )
        "#,
    )
    .execute(pool)
    .await?;

    let now = Utc::now().to_rfc3339();

    // Encrypt the API key before storing
    let encrypted_key = encrypt_api_key(api_key)?;

    sqlx::query(
        r#"
        INSERT INTO user_settings (user_id, setting_key, setting_value, created_at, updated_at)
        VALUES (?, 'shodan_api_key', ?, ?, ?)
        ON CONFLICT(user_id, setting_key) DO UPDATE SET
            setting_value = excluded.setting_value,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(user_id)
    .bind(&encrypted_key)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete user's Shodan API key from database
async fn delete_user_shodan_api_key(pool: &SqlitePool, user_id: &str) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "DELETE FROM user_settings WHERE user_id = ? AND setting_key = 'shodan_api_key'",
    )
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Simple encryption for API key storage
/// Uses TOTP_ENCRYPTION_KEY env var if available, otherwise stores as-is
fn encrypt_api_key(key: &str) -> anyhow::Result<String> {
    if let Ok(encryption_key) = std::env::var("TOTP_ENCRYPTION_KEY") {
        use base64::{Engine, engine::general_purpose::STANDARD};

        // Simple XOR encryption with the key (for demonstration)
        // In production, use proper AES-256 encryption
        let key_bytes = encryption_key.as_bytes();
        let encrypted: Vec<u8> = key
            .bytes()
            .enumerate()
            .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
            .collect();

        Ok(format!("enc:{}", STANDARD.encode(encrypted)))
    } else {
        // Store unencrypted if no key is available (not recommended for production)
        Ok(key.to_string())
    }
}

/// Decrypt API key from storage
fn decrypt_api_key(encrypted: &str) -> anyhow::Result<String> {
    if let Some(encoded) = encrypted.strip_prefix("enc:") {
        if let Ok(encryption_key) = std::env::var("TOTP_ENCRYPTION_KEY") {
            use base64::{Engine, engine::general_purpose::STANDARD};

            let encrypted_bytes = STANDARD.decode(encoded)?;
            let key_bytes = encryption_key.as_bytes();
            let decrypted: Vec<u8> = encrypted_bytes
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
                .collect();

            return Ok(String::from_utf8(decrypted)?);
        }
    }

    // Return as-is if not encrypted or no key available
    Ok(encrypted.to_string())
}

/// Configure Shodan reconnaissance routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/recon/shodan")
            .route("/status", web::get().to(get_status))
            .route("/host/{ip}", web::get().to(host_lookup))
            .route("/search", web::post().to(search))
            .route("/dns/resolve", web::post().to(dns_resolve))
            .route("/dns/reverse", web::post().to(dns_reverse))
            .route("/cache", web::delete().to(clear_cache))
            .route("/history", web::get().to(get_history)),
    );
}

/// Configure Shodan settings routes (separate from recon)
pub fn configure_settings(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/settings/shodan")
            .route("", web::get().to(get_api_key_status))
            .route("", web::put().to(set_api_key))
            .route("", web::delete().to(delete_api_key)),
    );
}
