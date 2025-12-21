#![allow(dead_code)]
//! Threat Intelligence API endpoints
//!
//! Provides REST API access to threat intelligence data including:
//! - IP threat lookups (Shodan, CVE correlation)
//! - Enriched CVE data with exploit information
//! - Threat alerts from scan correlation
//! - Scan result enrichment

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::models;
use crate::threat_intel::{ThreatIntelConfig, ThreatIntelManager};
use crate::web::auth::Claims;

/// Response for API status
#[derive(Debug, Serialize)]
pub struct ApiStatusResponse {
    pub shodan_available: bool,
    pub shodan_credits: Option<i32>,
    pub nvd_api_configured: bool,
    pub cache_ttl_hours: i64,
}

/// Response for IP lookup
#[derive(Debug, Serialize)]
pub struct IpLookupResponse {
    pub ip: String,
    pub threat_score: u8,
    pub risk_factors: Vec<String>,
    pub shodan_info: Option<serde_json::Value>,
    pub associated_cves: Vec<serde_json::Value>,
    pub available_exploits: Vec<serde_json::Value>,
    pub last_updated: String,
}

/// Response for CVE lookup
#[derive(Debug, Serialize)]
pub struct CveLookupResponse {
    pub cve_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub cvss_v3_score: Option<f32>,
    pub cvss_v2_score: Option<f32>,
    pub in_cisa_kev: bool,
    pub kev_due_date: Option<String>,
    pub exploits: Vec<serde_json::Value>,
    pub affected_products: Vec<serde_json::Value>,
    pub references: Vec<String>,
    pub attack_vector: Option<String>,
    pub attack_complexity: Option<String>,
}

/// Request for scan enrichment
#[derive(Debug, Deserialize)]
pub struct EnrichScanRequest {
    pub enable_shodan: Option<bool>,
    pub enable_exploit_db: Option<bool>,
    pub enable_cve_enrichment: Option<bool>,
}

/// Response for scan enrichment
#[derive(Debug, Serialize)]
pub struct EnrichmentResponse {
    pub scan_id: String,
    pub alerts_count: usize,
    pub enriched_hosts: usize,
    pub total_exploits_found: usize,
    pub critical_findings: usize,
    pub kev_matches: usize,
    pub enriched_at: String,
    pub alerts: Vec<serde_json::Value>,
}

/// Response for alerts list
#[derive(Debug, Serialize)]
pub struct AlertsResponse {
    pub alerts: Vec<serde_json::Value>,
    pub total: usize,
}

/// Query parameters for alerts
#[derive(Debug, Deserialize)]
pub struct AlertsQuery {
    pub limit: Option<i32>,
    pub scan_id: Option<String>,
    pub severity: Option<String>,
}

/// GET /api/threat-intel/status
/// Get API configuration status and quotas
pub async fn get_status(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let config = ThreatIntelConfig::default();
    let manager = ThreatIntelManager::new(Arc::new(pool.get_ref().clone()), config.clone());

    let status = manager.get_api_status().await.map_err(|e| {
        error!("Failed to get API status: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get API status")
    })?;

    let response = ApiStatusResponse {
        shodan_available: status.shodan_api_key_configured,
        shodan_credits: status.shodan.map(|s| s.query_credits),
        nvd_api_configured: status.nvd_api_key_configured,
        cache_ttl_hours: config.cache_ttl_hours,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// GET /api/threat-intel/lookup/{ip}
/// Look up threat intelligence for an IP address
pub async fn lookup_ip(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let ip = path.into_inner();

    info!("Threat intel lookup for IP: {}", ip);

    // Validate IP format
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid IP address format"
        })));
    }

    let config = ThreatIntelConfig::default();
    let manager = ThreatIntelManager::new(Arc::new(pool.get_ref().clone()), config);

    let intel = manager.lookup_ip(&ip).await.map_err(|e| {
        error!("IP lookup failed: {}", e);
        actix_web::error::ErrorInternalServerError(format!("IP lookup failed: {}", e))
    })?;

    let response = IpLookupResponse {
        ip: intel.ip,
        threat_score: intel.threat_score,
        risk_factors: intel.risk_factors,
        shodan_info: intel.shodan_info.map(|s| serde_json::to_value(s).unwrap_or_default()),
        associated_cves: intel
            .associated_cves
            .into_iter()
            .map(|c| serde_json::to_value(c).unwrap_or_default())
            .collect(),
        available_exploits: intel
            .available_exploits
            .into_iter()
            .map(|e| serde_json::to_value(e).unwrap_or_default())
            .collect(),
        last_updated: intel.last_updated.to_rfc3339(),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// GET /api/threat-intel/cve/{cve_id}
/// Get enriched CVE data with exploit information
pub async fn lookup_cve(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let cve_id = path.into_inner();

    info!("CVE lookup: {}", cve_id);

    // Validate CVE format
    if !cve_id.starts_with("CVE-") {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid CVE ID format (expected CVE-YYYY-NNNNN)"
        })));
    }

    let config = ThreatIntelConfig::default();
    let manager = ThreatIntelManager::new(Arc::new(pool.get_ref().clone()), config);

    let cve = manager.get_enriched_cve(&cve_id).await.map_err(|e| {
        error!("CVE lookup failed: {}", e);
        actix_web::error::ErrorNotFound(format!("CVE not found: {}", e))
    })?;

    let response = CveLookupResponse {
        cve_id: cve.cve_id,
        title: cve.title,
        description: cve.description,
        severity: cve.severity.to_string(),
        cvss_v3_score: cve.cvss_v3_score,
        cvss_v2_score: cve.cvss_v2_score,
        in_cisa_kev: cve.in_cisa_kev,
        kev_due_date: cve.kev_due_date,
        exploits: cve
            .exploits
            .into_iter()
            .map(|e| serde_json::to_value(e).unwrap_or_default())
            .collect(),
        affected_products: cve
            .affected_products
            .into_iter()
            .map(|p| serde_json::to_value(p).unwrap_or_default())
            .collect(),
        references: cve.references,
        attack_vector: cve.attack_vector,
        attack_complexity: cve.attack_complexity,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// GET /api/threat-intel/alerts
/// Get recent threat alerts
pub async fn get_alerts(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<AlertsQuery>,
) -> Result<HttpResponse> {
    let limit = query.limit.unwrap_or(50);

    debug!("Fetching threat alerts (limit: {})", limit);

    let alerts = if let Some(ref scan_id) = query.scan_id {
        crate::db::threat_intel::get_alerts_for_scan(pool.get_ref(), scan_id).await
    } else {
        crate::db::threat_intel::get_recent_alerts(pool.get_ref(), limit).await
    }
    .map_err(|e| {
        error!("Failed to get alerts: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get alerts")
    })?;

    // Filter by severity if specified
    let alerts: Vec<_> = if let Some(ref severity) = query.severity {
        alerts
            .into_iter()
            .filter(|a| a.severity.to_string() == *severity)
            .collect()
    } else {
        alerts
    };

    let total = alerts.len();
    let alerts_json: Vec<serde_json::Value> = alerts
        .into_iter()
        .map(|a| serde_json::to_value(a).unwrap_or_default())
        .collect();

    let response = AlertsResponse {
        alerts: alerts_json,
        total,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// POST /api/threat-intel/enrich/{scan_id}
/// Enrich scan results with threat intelligence
pub async fn enrich_scan(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: Option<web::Json<EnrichScanRequest>>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let scan_id = path.into_inner();

    info!("Enriching scan {} with threat intel", scan_id);

    // Verify scan exists and belongs to user
    let scan = crate::db::get_scan_by_id(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| {
            error!("Failed to get scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get scan")
        })?;

    let scan = match scan {
        Some(s) => s,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            })));
        }
    };

    // Check ownership (allow admin override via has_permission if needed)
    if scan.user_id != *user_id {
        if let Ok(false) = crate::db::has_permission(pool.get_ref(), user_id, "can_view_all_scans").await {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "You don't have permission to access this scan"
            })));
        }
    }

    // Parse scan results
    let hosts: Vec<crate::types::HostInfo> = scan
        .results
        .as_ref()
        .and_then(|r| serde_json::from_str(r).ok())
        .unwrap_or_default();

    if hosts.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Scan has no results to enrich"
        })));
    }

    // Configure enrichment options
    let request = body.map(|b| b.into_inner());
    let mut config = ThreatIntelConfig::default();

    if let Some(ref req) = request {
        config.enable_shodan = req.enable_shodan.unwrap_or(true);
        config.enable_exploit_db = req.enable_exploit_db.unwrap_or(true);
    }

    let manager = ThreatIntelManager::new(Arc::new(pool.get_ref().clone()), config);

    let result = manager.enrich_scan(&scan_id, &hosts).await.map_err(|e| {
        error!("Scan enrichment failed: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Enrichment failed: {}", e))
    })?;

    let response = EnrichmentResponse {
        scan_id: result.scan_id,
        alerts_count: result.alerts_generated.len(),
        enriched_hosts: result.enriched_hosts,
        total_exploits_found: result.total_exploits_found,
        critical_findings: result.critical_findings,
        kev_matches: result.kev_matches,
        enriched_at: result.enriched_at.to_rfc3339(),
        alerts: result
            .alerts_generated
            .into_iter()
            .map(|a| serde_json::to_value(a).unwrap_or_default())
            .collect(),
    };

    // Create audit log
    let audit_log = models::AuditLog {
        id: Uuid::new_v4().to_string(),
        user_id: user_id.clone(),
        action: "threat_intel_enrich".to_string(),
        target_type: Some("scan".to_string()),
        target_id: Some(scan_id.clone()),
        details: Some(format!("Enriched scan with {} alerts generated", response.alerts_count)),
        ip_address: None,
        user_agent: None,
        created_at: Utc::now(),
    };
    if let Err(e) = crate::db::create_audit_log(pool.get_ref(), &audit_log).await {
        error!("Failed to create audit log: {}", e);
    }

    Ok(HttpResponse::Ok().json(response))
}

/// POST /api/threat-intel/alerts/{alert_id}/acknowledge
/// Acknowledge a threat alert
pub async fn acknowledge_alert(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let alert_id = path.into_inner();

    debug!("Acknowledging alert: {}", alert_id);

    let acknowledged = crate::db::threat_intel::acknowledge_alert(pool.get_ref(), &alert_id, user_id)
        .await
        .map_err(|e| {
            error!("Failed to acknowledge alert: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to acknowledge alert")
        })?;

    if !acknowledged {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Alert not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Alert acknowledged"
    })))
}

/// GET /api/threat-intel/scan/{scan_id}/enrichment
/// Get enrichment results for a scan
pub async fn get_scan_enrichment(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let scan_id = path.into_inner();

    // Verify scan access
    let scan = crate::db::get_scan_by_id(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| {
            error!("Failed to get scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get scan")
        })?;

    let scan = match scan {
        Some(s) => s,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            })));
        }
    };

    if scan.user_id != *user_id {
        if let Ok(false) = crate::db::has_permission(pool.get_ref(), user_id, "can_view_all_scans").await {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "You don't have permission to access this scan"
            })));
        }
    }

    let result = crate::db::threat_intel::get_enrichment_result(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| {
            error!("Failed to get enrichment result: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get enrichment result")
        })?;

    match result {
        Some(enrichment) => {
            let response = EnrichmentResponse {
                scan_id: enrichment.scan_id,
                alerts_count: enrichment.alerts_generated.len(),
                enriched_hosts: enrichment.enriched_hosts,
                total_exploits_found: enrichment.total_exploits_found,
                critical_findings: enrichment.critical_findings,
                kev_matches: enrichment.kev_matches,
                enriched_at: enrichment.enriched_at.to_rfc3339(),
                alerts: enrichment
                    .alerts_generated
                    .into_iter()
                    .map(|a| serde_json::to_value(a).unwrap_or_default())
                    .collect(),
            };
            Ok(HttpResponse::Ok().json(response))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "No enrichment data found for this scan. Run POST /api/threat-intel/enrich/{scan_id} first."
        }))),
    }
}

/// Configure threat intel routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/threat-intel")
            .route("/status", web::get().to(get_status))
            .route("/lookup/{ip}", web::get().to(lookup_ip))
            .route("/cve/{cve_id}", web::get().to(lookup_cve))
            .route("/alerts", web::get().to(get_alerts))
            .route("/alerts/{alert_id}/acknowledge", web::post().to(acknowledge_alert))
            .route("/enrich/{scan_id}", web::post().to(enrich_scan))
            .route("/scan/{scan_id}/enrichment", web::get().to(get_scan_enrichment)),
    );
}
