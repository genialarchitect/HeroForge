//! Passive Reconnaissance API
//!
//! REST API endpoints for passive reconnaissance using external data sources
//! like crt.sh, Wayback Machine, GitHub, and SecurityTrails.

use actix_web::{web, HttpResponse, Scope};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::passive_recon::{
    aggregator::{PassiveReconAggregator, PassiveReconConfig, PassiveReconResult, ReconSource},
    crtsh::CrtshClient,
    github_search::GitHubCodeSearch,
    securitytrails::SecurityTrailsClient,
    wayback::WaybackClient,
};
use crate::web::auth::jwt::Claims;

/// Configure passive recon routes
pub fn configure() -> Scope {
    web::scope("/passive-recon")
        .route("/run", web::post().to(run_passive_recon))
        .route("/subdomains", web::post().to(discover_subdomains))
        .route("/crtsh", web::post().to(query_crtsh))
        .route("/wayback", web::post().to(query_wayback))
        .route("/wayback/sensitive", web::post().to(find_sensitive_paths))
        .route("/github", web::post().to(search_github))
        .route("/github/secrets", web::post().to(search_github_secrets))
        .route("/securitytrails", web::post().to(query_securitytrails))
        .route("/results/{id}", web::get().to(get_result))
        .route("/results", web::get().to(list_results))
}

/// Run passive recon request
#[derive(Debug, Deserialize)]
pub struct RunReconRequest {
    pub domain: String,
    pub sources: Option<Vec<String>>,
    pub github_token: Option<String>,
    pub securitytrails_key: Option<String>,
    pub wayback_url_limit: Option<usize>,
}

/// Run full passive reconnaissance
async fn run_passive_recon(
    pool: web::Data<SqlitePool>,
    body: web::Json<RunReconRequest>,
    claims: Claims,
) -> HttpResponse {
    let domain = body.domain.trim().to_lowercase();

    if domain.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Domain is required"
        }));
    }

    // Build configuration
    let mut config = PassiveReconConfig::default();

    if let Some(ref sources) = body.sources {
        config.use_crtsh = sources.iter().any(|s| s.to_lowercase() == "crtsh");
        config.use_wayback = sources.iter().any(|s| s.to_lowercase() == "wayback");
        config.use_github = sources.iter().any(|s| s.to_lowercase() == "github");
        config.use_securitytrails = sources.iter().any(|s| s.to_lowercase() == "securitytrails");
    }

    config.github_token = body.github_token.clone();
    config.securitytrails_key = body.securitytrails_key.clone();
    config.wayback_url_limit = body.wayback_url_limit;

    let aggregator = PassiveReconAggregator::new(config);

    match aggregator.run(&domain).await {
        Ok(result) => {
            // Store result in database
            let result_id = uuid::Uuid::new_v4().to_string();
            let _ = store_recon_result(pool.get_ref(), &result_id, &claims.sub, &result).await;

            log::info!(
                "User {} ran passive recon on {}: {} subdomains found",
                claims.sub, domain, result.statistics.unique_subdomains
            );

            HttpResponse::Ok().json(ReconResultResponse {
                id: result_id,
                result,
            })
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Passive recon failed: {}", e)
        })),
    }
}

/// Discover subdomains request
#[derive(Debug, Deserialize)]
pub struct DiscoverSubdomainsRequest {
    pub domain: String,
    pub sources: Option<Vec<String>>,
    pub securitytrails_key: Option<String>,
}

/// Discover subdomains only
async fn discover_subdomains(
    body: web::Json<DiscoverSubdomainsRequest>,
    _claims: Claims,
) -> HttpResponse {
    let domain = body.domain.trim().to_lowercase();

    if domain.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Domain is required"
        }));
    }

    let mut config = PassiveReconConfig::default();
    config.use_github = false; // Skip GitHub for subdomain discovery

    if let Some(ref sources) = body.sources {
        config.use_crtsh = sources.iter().any(|s| s.to_lowercase() == "crtsh");
        config.use_wayback = sources.iter().any(|s| s.to_lowercase() == "wayback");
        config.use_securitytrails = sources.iter().any(|s| s.to_lowercase() == "securitytrails");
    }

    config.securitytrails_key = body.securitytrails_key.clone();

    let aggregator = PassiveReconAggregator::new(config);

    match aggregator.discover_subdomains(&domain).await {
        Ok(subdomains) => HttpResponse::Ok().json(serde_json::json!({
            "domain": domain,
            "subdomains": subdomains,
            "count": subdomains.len(),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Subdomain discovery failed: {}", e)
        })),
    }
}

/// Query crt.sh request
#[derive(Debug, Deserialize)]
pub struct CrtshRequest {
    pub domain: String,
}

/// Query crt.sh for certificates
async fn query_crtsh(
    body: web::Json<CrtshRequest>,
    _claims: Claims,
) -> HttpResponse {
    let domain = body.domain.trim().to_lowercase();

    if domain.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Domain is required"
        }));
    }

    match CrtshClient::new() {
        Ok(client) => match client.find_subdomains(&domain).await {
            Ok(results) => HttpResponse::Ok().json(serde_json::json!({
                "source": "crt.sh",
                "domain": domain,
                "results": results,
                "count": results.len(),
            })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("crt.sh query failed: {}", e)
            })),
        },
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create crt.sh client: {}", e)
        })),
    }
}

/// Query Wayback Machine request
#[derive(Debug, Deserialize)]
pub struct WaybackRequest {
    pub domain: String,
    pub limit: Option<usize>,
}

/// Query Wayback Machine for historical URLs
async fn query_wayback(
    body: web::Json<WaybackRequest>,
    _claims: Claims,
) -> HttpResponse {
    let domain = body.domain.trim().to_lowercase();

    if domain.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Domain is required"
        }));
    }

    match WaybackClient::new() {
        Ok(client) => match client.get_urls(&domain, body.limit).await {
            Ok(urls) => HttpResponse::Ok().json(serde_json::json!({
                "source": "Wayback Machine",
                "domain": domain,
                "urls": urls,
                "count": urls.len(),
            })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Wayback query failed: {}", e)
            })),
        },
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create Wayback client: {}", e)
        })),
    }
}

/// Find sensitive paths in Wayback Machine
async fn find_sensitive_paths(
    body: web::Json<WaybackRequest>,
    _claims: Claims,
) -> HttpResponse {
    let domain = body.domain.trim().to_lowercase();

    if domain.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Domain is required"
        }));
    }

    match WaybackClient::new() {
        Ok(client) => match client.find_sensitive_paths(&domain).await {
            Ok(paths) => HttpResponse::Ok().json(serde_json::json!({
                "source": "Wayback Machine",
                "domain": domain,
                "sensitive_paths": paths,
                "count": paths.len(),
            })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Sensitive path search failed: {}", e)
            })),
        },
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create Wayback client: {}", e)
        })),
    }
}

/// GitHub search request
#[derive(Debug, Deserialize)]
pub struct GitHubSearchRequest {
    pub domain: String,
    pub token: Option<String>,
}

/// Search GitHub for domain references
async fn search_github(
    body: web::Json<GitHubSearchRequest>,
    _claims: Claims,
) -> HttpResponse {
    let domain = body.domain.trim().to_lowercase();

    if domain.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Domain is required"
        }));
    }

    match GitHubCodeSearch::new(body.token.clone()) {
        Ok(client) => match client.search_domain(&domain).await {
            Ok(results) => HttpResponse::Ok().json(serde_json::json!({
                "source": "GitHub",
                "domain": domain,
                "code_references": results,
                "count": results.len(),
            })),
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("token required") || error_msg.contains("authentication") {
                    HttpResponse::Unauthorized().json(serde_json::json!({
                        "error": "GitHub API token required for code search"
                    }))
                } else if error_msg.contains("rate limit") {
                    HttpResponse::TooManyRequests().json(serde_json::json!({
                        "error": "GitHub API rate limit exceeded"
                    }))
                } else {
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": format!("GitHub search failed: {}", e)
                    }))
                }
            }
        },
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create GitHub client: {}", e)
        })),
    }
}

/// Search GitHub for exposed secrets
async fn search_github_secrets(
    body: web::Json<GitHubSearchRequest>,
    _claims: Claims,
) -> HttpResponse {
    let domain = body.domain.trim().to_lowercase();

    if domain.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Domain is required"
        }));
    }

    match GitHubCodeSearch::new(body.token.clone()) {
        Ok(client) => match client.search_secrets(&domain).await {
            Ok(findings) => HttpResponse::Ok().json(serde_json::json!({
                "source": "GitHub",
                "domain": domain,
                "secret_findings": findings,
                "count": findings.len(),
                "severity_breakdown": count_by_severity(&findings),
            })),
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("token required") || error_msg.contains("authentication") {
                    HttpResponse::Unauthorized().json(serde_json::json!({
                        "error": "GitHub API token required for secret search"
                    }))
                } else {
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": format!("GitHub secret search failed: {}", e)
                    }))
                }
            }
        },
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create GitHub client: {}", e)
        })),
    }
}

/// SecurityTrails request
#[derive(Debug, Deserialize)]
pub struct SecurityTrailsRequest {
    pub domain: String,
    pub api_key: String,
    pub include_dns_history: Option<bool>,
    pub include_whois: Option<bool>,
}

/// Query SecurityTrails
async fn query_securitytrails(
    body: web::Json<SecurityTrailsRequest>,
    _claims: Claims,
) -> HttpResponse {
    let domain = body.domain.trim().to_lowercase();

    if domain.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Domain is required"
        }));
    }

    if body.api_key.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "SecurityTrails API key is required"
        }));
    }

    match SecurityTrailsClient::new(body.api_key.clone()) {
        Ok(client) => {
            let mut response = serde_json::json!({
                "source": "SecurityTrails",
                "domain": domain,
            });

            // Get subdomains
            match client.get_subdomains(&domain).await {
                Ok(subs) => {
                    response["subdomains"] = serde_json::json!(subs);
                    response["subdomain_count"] = serde_json::json!(subs.len());
                }
                Err(e) => {
                    response["subdomain_error"] = serde_json::json!(e.to_string());
                }
            }

            // Get DNS history if requested
            if body.include_dns_history.unwrap_or(false) {
                match client.get_full_dns_history(&domain).await {
                    Ok(history) => {
                        response["dns_history"] = serde_json::json!(history);
                        response["dns_record_count"] = serde_json::json!(history.len());
                    }
                    Err(e) => {
                        response["dns_history_error"] = serde_json::json!(e.to_string());
                    }
                }
            }

            // Get WHOIS if requested
            if body.include_whois.unwrap_or(false) {
                match client.get_whois(&domain).await {
                    Ok(whois) => {
                        response["whois"] = serde_json::json!(whois);
                    }
                    Err(e) => {
                        response["whois_error"] = serde_json::json!(e.to_string());
                    }
                }
            }

            HttpResponse::Ok().json(response)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create SecurityTrails client: {}", e)
        })),
    }
}

/// Get a stored recon result
async fn get_result(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: Claims,
) -> HttpResponse {
    let result_id = path.into_inner();

    let row = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, domain, result_json, created_at FROM passive_recon_results WHERE id = ?"
    )
    .bind(&result_id)
    .fetch_optional(pool.get_ref())
    .await;

    match row {
        Ok(Some((id, domain, result_json, created_at))) => {
            let result: PassiveReconResult = serde_json::from_str(&result_json)
                .unwrap_or_else(|_| PassiveReconResult {
                    domain: domain.clone(),
                    started_at: chrono::Utc::now(),
                    completed_at: chrono::Utc::now(),
                    sources_queried: vec![],
                    sources_succeeded: vec![],
                    sources_failed: std::collections::HashMap::new(),
                    subdomains: vec![],
                    historical_urls: vec![],
                    sensitive_paths: vec![],
                    code_exposures: vec![],
                    secret_findings: vec![],
                    dns_history: vec![],
                    statistics: Default::default(),
                });

            HttpResponse::Ok().json(serde_json::json!({
                "id": id,
                "domain": domain,
                "result": result,
                "created_at": created_at,
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Result not found"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// List stored recon results
async fn list_results(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> HttpResponse {
    let rows = sqlx::query_as::<_, (String, String, String, i64, String)>(
        "SELECT id, domain, user_id, subdomain_count, created_at
         FROM passive_recon_results
         ORDER BY created_at DESC
         LIMIT 100"
    )
    .fetch_all(pool.get_ref())
    .await;

    match rows {
        Ok(rows) => {
            let results: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|(id, domain, user_id, count, created_at)| {
                    serde_json::json!({
                        "id": id,
                        "domain": domain,
                        "user_id": user_id,
                        "subdomain_count": count,
                        "created_at": created_at,
                    })
                })
                .collect();

            HttpResponse::Ok().json(serde_json::json!({
                "results": results,
                "count": results.len(),
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to list results: {}", e)
        })),
    }
}

// Helper functions

async fn store_recon_result(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    result: &PassiveReconResult,
) -> Result<(), sqlx::Error> {
    let result_json = serde_json::to_string(result).unwrap_or_default();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO passive_recon_results
         (id, domain, user_id, result_json, subdomain_count, created_at)
         VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(id)
    .bind(&result.domain)
    .bind(user_id)
    .bind(&result_json)
    .bind(result.statistics.unique_subdomains as i64)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

fn count_by_severity(findings: &[crate::passive_recon::github_search::SecretFinding]) -> serde_json::Value {
    use crate::passive_recon::github_search::Severity;
    use std::collections::HashMap;

    let mut counts: HashMap<String, usize> = HashMap::new();

    for finding in findings {
        let sev = match finding.severity {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        };
        *counts.entry(sev.to_string()).or_insert(0) += 1;
    }

    serde_json::json!(counts)
}

/// Response with result ID
#[derive(Debug, Serialize)]
struct ReconResultResponse {
    id: String,
    result: PassiveReconResult,
}
