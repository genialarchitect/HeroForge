//! DNS Analysis API Endpoints
//!
//! This module provides REST API endpoints for DNS threat detection:
//! - POST /api/detection/dns/analyze - Analyze DNS queries
//! - POST /api/detection/dns/check-domain - Check single domain
//! - POST /api/detection/dns/check-dga - DGA detection
//! - POST /api/detection/dns/check-tunneling - Tunneling detection
//! - GET /api/detection/dns/threats - List detected threats
//! - POST /api/detection/dns/blocklist - Add to blocklist
//! - GET /api/detection/dns/blocklist - List blocklist entries
//! - DELETE /api/detection/dns/blocklist/{id} - Remove from blocklist
//! - GET /api/detection/dns/jobs - List analysis jobs
//! - GET /api/detection/dns/jobs/{id} - Get job details

#![allow(dead_code)]

use actix_web::{web, HttpResponse, Result};
use chrono::{DateTime, Utc};
use log::{error, info};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::net::IpAddr;

use crate::scanner::dns_analysis::{
    DnsAnalyzer, DnsAnalyzerConfig,
    DnsQueryLog, DnsQueryType, DnsRecord, DnsResponse, DnsResponseCode, DnsThreat,
    ThreatSeverity, ThreatType,
};
use crate::scanner::dns_analysis::dga::DgaResult;
use crate::scanner::dns_analysis::reputation::ReputationResult;
use crate::web::auth::Claims;

// =============================================================================
// Request/Response Types
// =============================================================================

/// Request to analyze DNS queries
#[derive(Debug, Deserialize)]
pub struct AnalyzeQueriesRequest {
    /// DNS query logs to analyze
    pub queries: Vec<DnsQueryInput>,
    /// Optional configuration overrides
    #[serde(default)]
    pub config: Option<AnalysisConfig>,
    /// CRM customer ID
    pub customer_id: Option<String>,
    /// CRM engagement ID
    pub engagement_id: Option<String>,
}

/// Individual DNS query input
#[derive(Debug, Deserialize)]
pub struct DnsQueryInput {
    /// Timestamp (ISO 8601 format)
    pub timestamp: String,
    /// Domain name queried
    pub query_name: String,
    /// Query type (A, AAAA, TXT, etc.)
    pub query_type: String,
    /// Client IP address
    pub client_ip: String,
    /// Response code (optional)
    #[serde(default)]
    pub response_code: Option<String>,
    /// Response records (optional)
    #[serde(default)]
    pub response_records: Option<Vec<DnsRecordInput>>,
    /// Response time in ms (optional)
    #[serde(default)]
    pub response_time_ms: Option<u64>,
}

/// DNS record input
#[derive(Debug, Deserialize)]
pub struct DnsRecordInput {
    pub name: String,
    pub record_type: String,
    pub data: String,
    pub ttl: u32,
}

/// Analysis configuration overrides
#[derive(Debug, Deserialize, Default)]
pub struct AnalysisConfig {
    /// DGA confidence threshold (0.0-1.0)
    #[serde(default)]
    pub dga_threshold: Option<f64>,
    /// Tunneling confidence threshold (0.0-1.0)
    #[serde(default)]
    pub tunneling_threshold: Option<f64>,
    /// Enable fast-flux detection
    #[serde(default)]
    pub enable_fast_flux: Option<bool>,
    /// Enable reputation checking
    #[serde(default)]
    pub enable_reputation: Option<bool>,
}

/// Request to check a single domain
#[derive(Debug, Deserialize)]
pub struct CheckDomainRequest {
    /// Domain to check
    pub domain: String,
    /// Check for DGA
    #[serde(default = "default_true")]
    pub check_dga: bool,
    /// Check reputation
    #[serde(default = "default_true")]
    pub check_reputation: bool,
    /// Check for typosquatting
    #[serde(default = "default_true")]
    pub check_typosquatting: bool,
    /// Check for homograph attacks
    #[serde(default = "default_true")]
    pub check_homograph: bool,
}

fn default_true() -> bool {
    true
}

/// Request to check for DGA
#[derive(Debug, Deserialize)]
pub struct CheckDgaRequest {
    /// Domain to check
    pub domain: String,
}

/// Request to check for tunneling
#[derive(Debug, Deserialize)]
pub struct CheckTunnelingRequest {
    /// DNS queries to analyze for tunneling
    pub queries: Vec<DnsQueryInput>,
}

/// Request to add to blocklist
#[derive(Debug, Deserialize)]
pub struct AddBlocklistRequest {
    /// Domain to block
    pub domain: String,
    /// Reason for blocking
    pub reason: String,
    /// Block all subdomains
    #[serde(default)]
    pub include_subdomains: bool,
}

/// Domain check response
#[derive(Debug, Serialize)]
pub struct DomainCheckResponse {
    pub domain: String,
    pub is_suspicious: bool,
    pub risk_score: u8,
    pub dga_result: Option<DgaResult>,
    pub reputation_result: Option<ReputationResult>,
    pub threats: Vec<DnsThreat>,
    pub recommendations: Vec<String>,
}

/// Blocklist entry response
#[derive(Debug, Serialize)]
pub struct BlocklistEntry {
    pub id: String,
    pub domain: String,
    pub reason: String,
    pub include_subdomains: bool,
    pub added_by: String,
    pub created_at: DateTime<Utc>,
}

/// Threat list response
#[derive(Debug, Serialize)]
pub struct ThreatListResponse {
    pub threats: Vec<StoredThreat>,
    pub total_count: i64,
    pub page: u32,
    pub page_size: u32,
}

/// Stored threat
#[derive(Debug, Serialize)]
pub struct StoredThreat {
    pub id: String,
    pub domain: String,
    pub threat_type: String,
    pub severity: String,
    pub confidence: f64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub occurrence_count: i64,
}

/// Analysis job response
#[derive(Debug, Serialize)]
pub struct AnalysisJob {
    pub id: String,
    pub user_id: String,
    pub query_count: i64,
    pub threats_found: i64,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Query parameters for threats list
#[derive(Debug, Deserialize)]
pub struct ThreatListQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub threat_type: Option<String>,
    pub severity: Option<String>,
    pub domain: Option<String>,
}

/// Query parameters for blocklist
#[derive(Debug, Deserialize)]
pub struct BlocklistQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub search: Option<String>,
}

/// Error response
#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}

// =============================================================================
// API Endpoints
// =============================================================================

/// POST /api/detection/dns/analyze
/// Analyze DNS queries for threats
pub async fn analyze_queries(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    body: web::Json<AnalyzeQueriesRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    info!("DNS analysis request from user {} with {} queries", user_id, body.queries.len());

    if body.queries.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "No queries provided".to_string(),
            details: None,
        }));
    }

    if body.queries.len() > 10000 {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "Too many queries".to_string(),
            details: Some("Maximum 10,000 queries per request".to_string()),
        }));
    }

    // Convert input queries to internal format
    let queries: Vec<DnsQueryLog> = match convert_queries(&body.queries) {
        Ok(q) => q,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: "Invalid query format".to_string(),
                details: Some(e),
            }));
        }
    };

    // Build analyzer config
    let mut config = DnsAnalyzerConfig::default();
    if let Some(ref custom_config) = body.config {
        if let Some(threshold) = custom_config.dga_threshold {
            config.dga_confidence_threshold = threshold;
        }
        if let Some(threshold) = custom_config.tunneling_threshold {
            config.tunneling_confidence_threshold = threshold;
        }
        if let Some(enable) = custom_config.enable_fast_flux {
            config.enable_fast_flux_detection = enable;
        }
        if let Some(enable) = custom_config.enable_reputation {
            config.enable_reputation_check = enable;
        }
    }

    let analyzer = DnsAnalyzer::with_config(config);

    // Run analysis
    let result = match analyzer.analyze_queries(&queries) {
        Ok(r) => r,
        Err(e) => {
            error!("DNS analysis failed: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Analysis failed".to_string(),
                details: Some(e.to_string()),
            }));
        }
    };

    // Store job record
    let job_id = uuid::Uuid::new_v4().to_string();
    let threats_found = result.threats.len() as i64;

    if let Err(e) = save_analysis_job(
        pool.get_ref(),
        &job_id,
        user_id,
        queries.len() as i64,
        threats_found,
        body.customer_id.as_deref(),
        body.engagement_id.as_deref(),
    ).await {
        error!("Failed to save analysis job: {}", e);
    }

    // Store detected threats
    for threat in &result.threats {
        if let Err(e) = save_threat(pool.get_ref(), threat).await {
            error!("Failed to save threat: {}", e);
        }
    }

    Ok(HttpResponse::Ok().json(result))
}

/// POST /api/detection/dns/check-domain
/// Check a single domain for threats
pub async fn check_domain(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    body: web::Json<CheckDomainRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    info!("Domain check request from user {}: {}", user_id, body.domain);

    let domain = body.domain.trim().to_lowercase();
    if domain.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "Domain is required".to_string(),
            details: None,
        }));
    }

    let analyzer = DnsAnalyzer::new();
    let mut threats = Vec::new();
    let mut recommendations = Vec::new();
    let mut risk_score = 0u8;

    // DGA check
    let dga_result = if body.check_dga {
        let result = analyzer.detect_dga(&domain);
        if result.is_dga {
            risk_score = risk_score.max((result.confidence * 100.0) as u8);
            recommendations.push(format!(
                "Domain exhibits DGA characteristics (confidence: {:.0}%)",
                result.confidence * 100.0
            ));
            threats.push(DnsThreat::new(
                ThreatType::DGA,
                severity_from_confidence(result.confidence),
                result.confidence,
                domain.clone(),
                format!("DGA detected: {}", result.reason),
            ));
        }
        Some(result)
    } else {
        None
    };

    // Reputation check
    let reputation_result = if body.check_reputation {
        let reputation = crate::scanner::dns_analysis::DomainReputation::new();
        let result = reputation.check(&domain);

        if !result.is_clean {
            risk_score = risk_score.max((result.confidence * 100.0) as u8);

            for category in &result.categories {
                let threat_type = match category {
                    crate::scanner::dns_analysis::ReputationCategory::Malware => ThreatType::Malware,
                    crate::scanner::dns_analysis::ReputationCategory::Phishing => ThreatType::Phishing,
                    crate::scanner::dns_analysis::ReputationCategory::C2 => ThreatType::C2,
                    crate::scanner::dns_analysis::ReputationCategory::Spam => ThreatType::Blocklisted,
                    crate::scanner::dns_analysis::ReputationCategory::Suspicious => ThreatType::Blocklisted,
                };

                threats.push(DnsThreat::new(
                    threat_type,
                    severity_from_confidence(result.confidence),
                    result.confidence,
                    domain.clone(),
                    format!("Reputation check: {:?}", category),
                ));
            }

            if result.is_typosquat {
                recommendations.push(format!(
                    "Possible typosquatting of '{}'",
                    result.typosquat_target.as_ref().unwrap_or(&"unknown".to_string())
                ));
            }

            if result.is_homograph {
                recommendations.push(format!(
                    "IDN homograph attack targeting '{}'",
                    result.homograph_target.as_ref().unwrap_or(&"unknown".to_string())
                ));
            }
        }

        Some(result)
    } else {
        None
    };

    // Check blocklist
    if is_domain_blocklisted(pool.get_ref(), &domain).await.unwrap_or(false) {
        risk_score = 100;
        recommendations.push("Domain is on your blocklist".to_string());
        threats.push(DnsThreat::new(
            ThreatType::Blocklisted,
            ThreatSeverity::High,
            1.0,
            domain.clone(),
            "Domain is blocklisted".to_string(),
        ));
    }

    let is_suspicious = !threats.is_empty();

    // Add general recommendations
    if is_suspicious {
        recommendations.push("Consider adding to blocklist".to_string());
        recommendations.push("Investigate traffic to this domain".to_string());
    }

    Ok(HttpResponse::Ok().json(DomainCheckResponse {
        domain,
        is_suspicious,
        risk_score,
        dga_result,
        reputation_result,
        threats,
        recommendations,
    }))
}

/// POST /api/detection/dns/check-dga
/// Check domain for DGA patterns
pub async fn check_dga(
    _claims: web::ReqData<Claims>,
    body: web::Json<CheckDgaRequest>,
) -> Result<HttpResponse> {
    let domain = body.domain.trim().to_lowercase();
    if domain.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "Domain is required".to_string(),
            details: None,
        }));
    }

    let analyzer = DnsAnalyzer::new();
    let result = analyzer.detect_dga(&domain);

    Ok(HttpResponse::Ok().json(result))
}

/// POST /api/detection/dns/check-tunneling
/// Check for DNS tunneling patterns
pub async fn check_tunneling(
    _claims: web::ReqData<Claims>,
    body: web::Json<CheckTunnelingRequest>,
) -> Result<HttpResponse> {
    if body.queries.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "No queries provided".to_string(),
            details: None,
        }));
    }

    let queries: Vec<DnsQueryLog> = match convert_queries(&body.queries) {
        Ok(q) => q,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: "Invalid query format".to_string(),
                details: Some(e),
            }));
        }
    };

    let detector = crate::scanner::dns_analysis::TunnelingDetector::new();
    let result = detector.detect(&queries);

    Ok(HttpResponse::Ok().json(result))
}

/// GET /api/detection/dns/threats
/// List detected threats
pub async fn list_threats(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<Claims>,
    query: web::Query<ThreatListQuery>,
) -> Result<HttpResponse> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).min(200);
    let offset = (page - 1) * page_size;

    let mut sql = String::from(
        "SELECT id, domain, threat_type, severity, confidence, first_seen, last_seen, occurrence_count
         FROM dns_threats WHERE 1=1"
    );

    if let Some(ref threat_type) = query.threat_type {
        sql.push_str(&format!(" AND threat_type = '{}'", threat_type.replace('\'', "''")));
    }
    if let Some(ref severity) = query.severity {
        sql.push_str(&format!(" AND severity = '{}'", severity.replace('\'', "''")));
    }
    if let Some(ref domain) = query.domain {
        sql.push_str(&format!(" AND domain LIKE '%{}%'", domain.replace('\'', "''")));
    }

    // Count total
    let count_sql = sql.replace(
        "SELECT id, domain, threat_type, severity, confidence, first_seen, last_seen, occurrence_count",
        "SELECT COUNT(*)"
    );

    sql.push_str(" ORDER BY last_seen DESC");
    sql.push_str(&format!(" LIMIT {} OFFSET {}", page_size, offset));

    let rows: Vec<ThreatRow> = sqlx::query_as(&sql)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    let total: (i64,) = sqlx::query_as(&count_sql)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    let threats: Vec<StoredThreat> = rows.into_iter().map(|r| r.into()).collect();

    Ok(HttpResponse::Ok().json(ThreatListResponse {
        threats,
        total_count: total.0,
        page,
        page_size,
    }))
}

/// POST /api/detection/dns/blocklist
/// Add domain to blocklist
pub async fn add_to_blocklist(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    body: web::Json<AddBlocklistRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let domain = body.domain.trim().to_lowercase();

    if domain.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "Domain is required".to_string(),
            details: None,
        }));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO dns_blocklist (id, domain, reason, include_subdomains, added_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&domain)
    .bind(&body.reason)
    .bind(body.include_subdomains)
    .bind(user_id)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to add to blocklist: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to add to blocklist")
    })?;

    info!("User {} added {} to DNS blocklist", user_id, domain);

    Ok(HttpResponse::Created().json(BlocklistEntry {
        id,
        domain,
        reason: body.reason.clone(),
        include_subdomains: body.include_subdomains,
        added_by: user_id.clone(),
        created_at: now,
    }))
}

/// GET /api/detection/dns/blocklist
/// List blocklist entries
pub async fn list_blocklist(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<Claims>,
    query: web::Query<BlocklistQuery>,
) -> Result<HttpResponse> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).min(200);
    let offset = (page - 1) * page_size;

    let mut sql = String::from(
        "SELECT id, domain, reason, include_subdomains, added_by, created_at
         FROM dns_blocklist WHERE 1=1"
    );

    if let Some(ref search) = query.search {
        sql.push_str(&format!(
            " AND (domain LIKE '%{}%' OR reason LIKE '%{}%')",
            search.replace('\'', "''"),
            search.replace('\'', "''")
        ));
    }

    sql.push_str(" ORDER BY created_at DESC");
    sql.push_str(&format!(" LIMIT {} OFFSET {}", page_size, offset));

    let rows: Vec<BlocklistRow> = sqlx::query_as(&sql)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    let entries: Vec<BlocklistEntry> = rows.into_iter().map(|r| r.into()).collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "entries": entries,
        "page": page,
        "page_size": page_size
    })))
}

/// DELETE /api/detection/dns/blocklist/{id}
/// Remove from blocklist
pub async fn remove_from_blocklist(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let user_id = &claims.sub;

    let result = sqlx::query("DELETE FROM dns_blocklist WHERE id = ?")
        .bind(&id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            error!("Failed to remove from blocklist: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to remove from blocklist")
        })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(ErrorResponse {
            error: "Entry not found".to_string(),
            details: None,
        }));
    }

    info!("User {} removed blocklist entry {}", user_id, id);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Entry removed from blocklist"
    })))
}

/// GET /api/detection/dns/jobs
/// List analysis jobs
pub async fn list_jobs(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let rows: Vec<JobRow> = sqlx::query_as(
        "SELECT id, user_id, query_count, threats_found, status, created_at, completed_at
         FROM dns_analysis_jobs
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT 100"
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let jobs: Vec<AnalysisJob> = rows.into_iter().map(|r| r.into()).collect();

    Ok(HttpResponse::Ok().json(jobs))
}

/// GET /api/detection/dns/jobs/{id}
/// Get job details
pub async fn get_job(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let user_id = &claims.sub;

    let row: Option<JobRow> = sqlx::query_as(
        "SELECT id, user_id, query_count, threats_found, status, created_at, completed_at
         FROM dns_analysis_jobs
         WHERE id = ? AND user_id = ?"
    )
    .bind(&id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None);

    match row {
        Some(r) => {
            let job: AnalysisJob = r.into();
            Ok(HttpResponse::Ok().json(job))
        }
        None => Ok(HttpResponse::NotFound().json(ErrorResponse {
            error: "Job not found".to_string(),
            details: None,
        })),
    }
}

// =============================================================================
// Route Configuration
// =============================================================================

/// Configure DNS analysis routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/detection/dns")
            .route("/analyze", web::post().to(analyze_queries))
            .route("/check-domain", web::post().to(check_domain))
            .route("/check-dga", web::post().to(check_dga))
            .route("/check-tunneling", web::post().to(check_tunneling))
            .route("/threats", web::get().to(list_threats))
            .route("/blocklist", web::post().to(add_to_blocklist))
            .route("/blocklist", web::get().to(list_blocklist))
            .route("/blocklist/{id}", web::delete().to(remove_from_blocklist))
            .route("/jobs", web::get().to(list_jobs))
            .route("/jobs/{id}", web::get().to(get_job)),
    );
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert input queries to internal format
fn convert_queries(inputs: &[DnsQueryInput]) -> std::result::Result<Vec<DnsQueryLog>, String> {
    let mut queries = Vec::with_capacity(inputs.len());

    for input in inputs {
        let timestamp = chrono::DateTime::parse_from_rfc3339(&input.timestamp)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| format!("Invalid timestamp '{}': {}", input.timestamp, e))?;

        let client_ip: IpAddr = input
            .client_ip
            .parse()
            .map_err(|e| format!("Invalid client IP '{}': {}", input.client_ip, e))?;

        let query_type = parse_query_type(&input.query_type);
        let response_code = parse_response_code(input.response_code.as_deref());

        let response = input.response_records.as_ref().map(|records| {
            DnsResponse {
                records: records
                    .iter()
                    .map(|r| DnsRecord {
                        name: r.name.clone(),
                        record_type: parse_query_type(&r.record_type),
                        data: r.data.clone(),
                        ttl: r.ttl,
                    })
                    .collect(),
                ttl: records.first().map(|r| r.ttl),
                truncated: false,
                recursion_available: true,
            }
        });

        queries.push(DnsQueryLog {
            timestamp,
            query_name: input.query_name.clone(),
            query_type,
            response,
            client_ip,
            dns_server: None,
            response_code,
            query_id: None,
            response_time_ms: input.response_time_ms,
        });
    }

    Ok(queries)
}

fn parse_query_type(s: &str) -> DnsQueryType {
    match s.to_uppercase().as_str() {
        "A" => DnsQueryType::A,
        "AAAA" => DnsQueryType::AAAA,
        "CNAME" => DnsQueryType::CNAME,
        "MX" => DnsQueryType::MX,
        "NS" => DnsQueryType::NS,
        "PTR" => DnsQueryType::PTR,
        "SOA" => DnsQueryType::SOA,
        "SRV" => DnsQueryType::SRV,
        "TXT" => DnsQueryType::TXT,
        "CAA" => DnsQueryType::CAA,
        "DNSKEY" => DnsQueryType::DNSKEY,
        "DS" => DnsQueryType::DS,
        "NULL" => DnsQueryType::NULL,
        "ANY" => DnsQueryType::ANY,
        "AXFR" => DnsQueryType::AXFR,
        "IXFR" => DnsQueryType::IXFR,
        _ => {
            if let Ok(n) = s.parse::<u16>() {
                DnsQueryType::Other(n)
            } else {
                DnsQueryType::A
            }
        }
    }
}

fn parse_response_code(s: Option<&str>) -> DnsResponseCode {
    match s {
        Some("NOERROR") | Some("0") => DnsResponseCode::NoError,
        Some("FORMERR") | Some("1") => DnsResponseCode::FormErr,
        Some("SERVFAIL") | Some("2") => DnsResponseCode::ServFail,
        Some("NXDOMAIN") | Some("3") => DnsResponseCode::NxDomain,
        Some("NOTIMP") | Some("4") => DnsResponseCode::NotImp,
        Some("REFUSED") | Some("5") => DnsResponseCode::Refused,
        _ => DnsResponseCode::NoError,
    }
}

fn severity_from_confidence(confidence: f64) -> ThreatSeverity {
    if confidence >= 0.9 {
        ThreatSeverity::Critical
    } else if confidence >= 0.75 {
        ThreatSeverity::High
    } else if confidence >= 0.5 {
        ThreatSeverity::Medium
    } else if confidence >= 0.3 {
        ThreatSeverity::Low
    } else {
        ThreatSeverity::Info
    }
}

/// Save analysis job to database
async fn save_analysis_job(
    pool: &SqlitePool,
    job_id: &str,
    user_id: &str,
    query_count: i64,
    threats_found: i64,
    customer_id: Option<&str>,
    engagement_id: Option<&str>,
) -> anyhow::Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO dns_analysis_jobs (id, user_id, query_count, threats_found, status, created_at, completed_at, customer_id, engagement_id)
        VALUES (?, ?, ?, ?, 'completed', ?, ?, ?, ?)
        "#,
    )
    .bind(job_id)
    .bind(user_id)
    .bind(query_count)
    .bind(threats_found)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(customer_id)
    .bind(engagement_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Save threat to database
async fn save_threat(pool: &SqlitePool, threat: &DnsThreat) -> anyhow::Result<()> {
    // Check if threat already exists for this domain and type
    let existing: Option<(String, i64)> = sqlx::query_as(
        "SELECT id, occurrence_count FROM dns_threats WHERE domain = ? AND threat_type = ?"
    )
    .bind(&threat.domain)
    .bind(format!("{:?}", threat.threat_type))
    .fetch_optional(pool)
    .await?;

    if let Some((id, count)) = existing {
        // Update existing threat
        sqlx::query(
            "UPDATE dns_threats SET last_seen = ?, occurrence_count = ?, confidence = MAX(confidence, ?) WHERE id = ?"
        )
        .bind(threat.last_seen.to_rfc3339())
        .bind(count + 1)
        .bind(threat.confidence)
        .bind(&id)
        .execute(pool)
        .await?;
    } else {
        // Insert new threat
        sqlx::query(
            r#"
            INSERT INTO dns_threats (id, domain, threat_type, severity, confidence, first_seen, last_seen, occurrence_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&threat.id)
        .bind(&threat.domain)
        .bind(format!("{:?}", threat.threat_type))
        .bind(format!("{}", threat.severity))
        .bind(threat.confidence)
        .bind(threat.first_seen.to_rfc3339())
        .bind(threat.last_seen.to_rfc3339())
        .bind(threat.occurrence_count as i64)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Check if domain is blocklisted
async fn is_domain_blocklisted(pool: &SqlitePool, domain: &str) -> anyhow::Result<bool> {
    let domain = domain.to_lowercase();

    // Check exact match
    let exact: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM dns_blocklist WHERE domain = ?"
    )
    .bind(&domain)
    .fetch_optional(pool)
    .await?;

    if exact.is_some() {
        return Ok(true);
    }

    // Check subdomain match
    let parent_domains: Vec<String> = get_parent_domains(&domain);
    for parent in parent_domains {
        let result: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM dns_blocklist WHERE domain = ? AND include_subdomains = 1"
        )
        .bind(&parent)
        .fetch_optional(pool)
        .await?;

        if result.is_some() {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Get parent domains (e.g., "sub.example.com" -> ["example.com", "com"])
fn get_parent_domains(domain: &str) -> Vec<String> {
    let parts: Vec<&str> = domain.split('.').collect();
    let mut parents = Vec::new();

    for i in 1..parts.len() {
        parents.push(parts[i..].join("."));
    }

    parents
}

// =============================================================================
// Database Row Types
// =============================================================================

#[derive(sqlx::FromRow)]
struct ThreatRow {
    id: String,
    domain: String,
    threat_type: String,
    severity: String,
    confidence: f64,
    first_seen: String,
    last_seen: String,
    occurrence_count: i64,
}

impl From<ThreatRow> for StoredThreat {
    fn from(row: ThreatRow) -> Self {
        StoredThreat {
            id: row.id,
            domain: row.domain,
            threat_type: row.threat_type,
            severity: row.severity,
            confidence: row.confidence,
            first_seen: chrono::DateTime::parse_from_rfc3339(&row.first_seen)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_seen: chrono::DateTime::parse_from_rfc3339(&row.last_seen)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            occurrence_count: row.occurrence_count,
        }
    }
}

#[derive(sqlx::FromRow)]
struct BlocklistRow {
    id: String,
    domain: String,
    reason: String,
    include_subdomains: bool,
    added_by: String,
    created_at: String,
}

impl From<BlocklistRow> for BlocklistEntry {
    fn from(row: BlocklistRow) -> Self {
        BlocklistEntry {
            id: row.id,
            domain: row.domain,
            reason: row.reason,
            include_subdomains: row.include_subdomains,
            added_by: row.added_by,
            created_at: chrono::DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(sqlx::FromRow)]
struct JobRow {
    id: String,
    user_id: String,
    query_count: i64,
    threats_found: i64,
    status: String,
    created_at: String,
    completed_at: Option<String>,
}

impl From<JobRow> for AnalysisJob {
    fn from(row: JobRow) -> Self {
        AnalysisJob {
            id: row.id,
            user_id: row.user_id,
            query_count: row.query_count,
            threats_found: row.threats_found,
            status: row.status,
            created_at: chrono::DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            completed_at: row.completed_at.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .ok()
            }),
        }
    }
}
