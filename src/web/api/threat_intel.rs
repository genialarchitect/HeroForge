#![allow(dead_code)]
//! Threat Intelligence API endpoints
//!
//! Provides REST API access to threat intelligence data including:
//! - IP threat lookups (Shodan, CVE correlation)
//! - Enriched CVE data with exploit information
//! - Threat alerts from scan correlation
//! - Scan result enrichment
//! - MISP server management and event sync
//! - TAXII server management and collection polling
//! - STIX object import/export
//! - Threat actor and campaign tracking
//! - IOC correlation with scan data

use actix_web::{web, HttpResponse, Result};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::models;
use crate::threat_intel::{ThreatIntelConfig, ThreatIntelManager};
use crate::threat_intel::misp::{MispClient, MispConfig, MispSearchQuery};
use crate::threat_intel::stix::TaxiiClient;
use crate::threat_intel::threat_actors::{ThreatActorDatabase, ThreatActorType, ThreatMotivation, TrackingStatus};
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

// ============================================================================
// MISP Server Management Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispServerConfig {
    pub id: String,
    pub name: String,
    pub url: String,
    pub api_key: String,
    pub verify_ssl: bool,
    pub is_active: bool,
    pub auto_sync: bool,
    pub sync_interval_hours: i32,
    pub last_sync_at: Option<String>,
    pub last_sync_status: Option<String>,
    pub events_synced: i32,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateMispServerRequest {
    pub name: String,
    pub url: String,
    pub api_key: String,
    pub verify_ssl: Option<bool>,
    pub auto_sync: Option<bool>,
    pub sync_interval_hours: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMispServerRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    pub api_key: Option<String>,
    pub verify_ssl: Option<bool>,
    pub is_active: Option<bool>,
    pub auto_sync: Option<bool>,
    pub sync_interval_hours: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct MispEventSummary {
    pub id: String,
    pub misp_event_id: String,
    pub misp_uuid: String,
    pub org_name: Option<String>,
    pub info: String,
    pub threat_level: Option<String>,
    pub analysis_status: Option<String>,
    pub date: Option<String>,
    pub published: bool,
    pub attribute_count: i32,
    pub tags: Vec<String>,
    pub synced_at: String,
}

#[derive(Debug, Serialize)]
pub struct MispEventDetail {
    pub id: String,
    pub misp_event_id: String,
    pub misp_uuid: String,
    pub org_name: Option<String>,
    pub info: String,
    pub threat_level: Option<String>,
    pub analysis_status: Option<String>,
    pub date: Option<String>,
    pub published: bool,
    pub attribute_count: i32,
    pub galaxy_cluster_count: i32,
    pub tags: Vec<String>,
    pub attributes: Vec<MispAttributeSummary>,
    pub synced_at: String,
}

#[derive(Debug, Serialize)]
pub struct MispAttributeSummary {
    pub id: String,
    pub category: String,
    pub attribute_type: String,
    pub value: String,
    pub to_ids: bool,
    pub comment: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct MispEventSearchRequest {
    pub keyword: Option<String>,
    pub threat_level: Option<String>,
    pub published_only: Option<bool>,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    pub tags: Option<Vec<String>>,
    pub limit: Option<i32>,
}

// ============================================================================
// TAXII Server Management Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiServerConfig {
    pub id: String,
    pub name: String,
    pub url: String,
    pub version: String,
    pub username: Option<String>,
    pub api_key: Option<String>,
    pub is_active: bool,
    pub auto_poll: bool,
    pub poll_interval_hours: i32,
    pub last_poll_at: Option<String>,
    pub last_poll_status: Option<String>,
    pub objects_received: i32,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateTaxiiServerRequest {
    pub name: String,
    pub url: String,
    pub version: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub api_key: Option<String>,
    pub auto_poll: Option<bool>,
    pub poll_interval_hours: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTaxiiServerRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub api_key: Option<String>,
    pub is_active: Option<bool>,
    pub auto_poll: Option<bool>,
    pub poll_interval_hours: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct TaxiiCollectionInfo {
    pub id: String,
    pub collection_id: String,
    pub title: String,
    pub description: Option<String>,
    pub can_read: bool,
    pub can_write: bool,
    pub media_types: Vec<String>,
    pub subscribed: bool,
    pub last_poll_at: Option<String>,
    pub objects_count: i32,
}

// ============================================================================
// STIX Object Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct StixObjectSummary {
    pub id: String,
    pub stix_id: String,
    pub stix_type: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub labels: Vec<String>,
    pub confidence: Option<i32>,
    pub created: String,
    pub modified: String,
    pub revoked: bool,
    pub source_type: String,
}

#[derive(Debug, Deserialize)]
pub struct StixObjectQuery {
    pub stix_type: Option<String>,
    pub name: Option<String>,
    pub label: Option<String>,
    pub source_type: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct StixBundleImportRequest {
    pub bundle: serde_json::Value,
    pub source_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StixImportResult {
    pub objects_imported: usize,
    pub relationships_imported: usize,
    pub sightings_imported: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct StixExportRequest {
    pub stix_types: Option<Vec<String>>,
    pub include_relationships: Option<bool>,
    pub include_sightings: Option<bool>,
}

// ============================================================================
// Threat Actor Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActorSummary {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub actor_type: String,
    pub country: Option<String>,
    pub motivation: String,
    pub active: bool,
    pub sophistication: i32,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub target_sectors: Vec<String>,
    pub campaign_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActorDetail {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub actor_type: String,
    pub country: Option<String>,
    pub sponsor: Option<String>,
    pub motivation: String,
    pub secondary_motivations: Vec<String>,
    pub description: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub active: bool,
    pub sophistication: i32,
    pub resource_level: i32,
    pub target_sectors: Vec<String>,
    pub target_countries: Vec<String>,
    pub ttps: Vec<String>,
    pub tools: Vec<String>,
    pub malware: Vec<String>,
    pub infrastructure: Option<serde_json::Value>,
    pub external_references: Vec<ExternalReference>,
    pub campaigns: Vec<CampaignSummary>,
    pub mitre_groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReference {
    pub source: String,
    pub url: Option<String>,
    pub external_id: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignSummary {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub status: String,
    pub target_count: i32,
}

#[derive(Debug, Deserialize)]
pub struct CreateThreatActorRequest {
    pub name: String,
    pub aliases: Option<Vec<String>>,
    pub actor_type: String,
    pub country: Option<String>,
    pub sponsor: Option<String>,
    pub motivation: String,
    pub secondary_motivations: Option<Vec<String>>,
    pub description: String,
    pub sophistication: Option<i32>,
    pub resource_level: Option<i32>,
    pub target_sectors: Option<Vec<String>>,
    pub target_countries: Option<Vec<String>>,
    pub ttps: Option<Vec<String>>,
    pub tools: Option<Vec<String>>,
    pub malware: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct ThreatActorQuery {
    pub name: Option<String>,
    pub actor_type: Option<String>,
    pub country: Option<String>,
    pub motivation: Option<String>,
    pub active_only: Option<bool>,
    pub target_sector: Option<String>,
    pub limit: Option<i32>,
}

// ============================================================================
// Campaign Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignDetail {
    pub id: String,
    pub name: String,
    pub threat_actor_id: Option<String>,
    pub threat_actor_name: Option<String>,
    pub description: Option<String>,
    pub objective: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub status: String,
    pub confidence: i32,
    pub targets: Vec<CampaignTarget>,
    pub ttps: Vec<String>,
    pub iocs: Vec<CampaignIoc>,
    pub timeline_events: Vec<TimelineEvent>,
    pub attribution_confidence: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignTarget {
    pub target_type: String,
    pub value: String,
    pub sector: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignIoc {
    pub ioc_type: String,
    pub value: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub confidence: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub event_type: String,
    pub description: String,
    pub references: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCampaignRequest {
    pub name: String,
    pub threat_actor_id: Option<String>,
    pub description: Option<String>,
    pub objective: Option<String>,
    pub first_seen: Option<String>,
    pub status: Option<String>,
    pub targets: Option<Vec<CampaignTarget>>,
    pub ttps: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct CampaignQuery {
    pub threat_actor_id: Option<String>,
    pub status: Option<String>,
    pub target_sector: Option<String>,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    pub limit: Option<i32>,
}

// ============================================================================
// IOC Correlation Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CorrelateIocsRequest {
    pub scan_id: Option<String>,
    pub iocs: Option<Vec<IocInput>>,
    pub sources: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct IocInput {
    pub ioc_type: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct CorrelationResult {
    pub total_iocs_checked: usize,
    pub matches_found: usize,
    pub correlations: Vec<IocCorrelation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IocCorrelation {
    pub ioc_type: String,
    pub ioc_value: String,
    pub source_type: String,
    pub source_id: String,
    pub matched_entity_type: String,
    pub matched_entity_id: String,
    pub confidence: f64,
    pub context: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Deserialize)]
pub struct CorrelationQuery {
    pub ioc_type: Option<String>,
    pub ioc_value: Option<String>,
    pub source_type: Option<String>,
    pub entity_type: Option<String>,
    pub limit: Option<i32>,
}

// ============================================================================
// Dashboard Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ThreatIntelDashboard {
    pub misp_servers: i32,
    pub misp_events: i32,
    pub misp_attributes: i32,
    pub taxii_servers: i32,
    pub taxii_collections: i32,
    pub stix_objects: i32,
    pub threat_actors: i32,
    pub active_campaigns: i32,
    pub ioc_correlations: i32,
    pub recent_alerts: i32,
    pub top_threat_actors: Vec<ThreatActorSummary>,
    pub recent_campaigns: Vec<CampaignSummary>,
    pub ioc_type_distribution: Vec<IocTypeCount>,
    pub threat_level_distribution: Vec<ThreatLevelCount>,
}

#[derive(Debug, Serialize)]
pub struct IocTypeCount {
    pub ioc_type: String,
    pub count: i32,
}

#[derive(Debug, Serialize)]
pub struct ThreatLevelCount {
    pub level: String,
    pub count: i32,
}

// ============================================================================
// Sprint 12: Diamond Model Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiamondEvent {
    pub id: String,
    pub campaign_id: Option<String>,
    pub adversary: DiamondVertex,
    pub capability: DiamondVertex,
    pub infrastructure: DiamondVertex,
    pub victim: DiamondVertex,
    pub timestamp: Option<String>,
    pub phase: Option<String>,
    pub confidence: i32,
    pub notes: Option<String>,
    pub meta_features: DiamondMetaFeatures,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiamondVertex {
    pub id: Option<String>,
    pub name: String,
    pub vertex_type: String,
    pub properties: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiamondMetaFeatures {
    pub direction: Option<String>,  // adversary-to-victim, victim-to-adversary
    pub methodology: Option<String>,
    pub resources: Option<String>,
    pub result: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateDiamondEventRequest {
    pub campaign_id: Option<String>,
    pub adversary_name: String,
    pub adversary_properties: Option<serde_json::Value>,
    pub capability_name: String,
    pub capability_properties: Option<serde_json::Value>,
    pub infrastructure_name: String,
    pub infrastructure_properties: Option<serde_json::Value>,
    pub victim_name: String,
    pub victim_properties: Option<serde_json::Value>,
    pub timestamp: Option<String>,
    pub phase: Option<String>,
    pub confidence: Option<i32>,
    pub notes: Option<String>,
}

// ============================================================================
// Sprint 12: Kill Chain Types
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct KillChainAnalysis {
    pub campaign_id: String,
    pub campaign_name: String,
    pub phases: Vec<KillChainPhase>,
    pub coverage: f64,
    pub detected_techniques: i32,
    pub total_techniques: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct KillChainPhase {
    pub phase: String,
    pub phase_name: String,
    pub order: i32,
    pub techniques: Vec<KillChainTechnique>,
    pub coverage: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct KillChainTechnique {
    pub technique_id: String,
    pub technique_name: String,
    pub detected: bool,
    pub detection_source: Option<String>,
    pub timestamp: Option<String>,
    pub evidence: Option<String>,
}

// Lockheed Martin Cyber Kill Chain phases
pub const KILL_CHAIN_PHASES: &[(&str, &str, i32)] = &[
    ("recon", "Reconnaissance", 1),
    ("weaponization", "Weaponization", 2),
    ("delivery", "Delivery", 3),
    ("exploitation", "Exploitation", 4),
    ("installation", "Installation", 5),
    ("c2", "Command & Control", 6),
    ("actions", "Actions on Objectives", 7),
];

// ============================================================================
// Sprint 12: Intelligence Requirements Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceRequirement {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub priority: String,  // critical, high, medium, low
    pub category: String,  // strategic, operational, tactical
    pub status: String,    // open, in_progress, answered, closed
    pub requester: Option<String>,
    pub due_date: Option<String>,
    pub answer: Option<String>,
    pub answered_at: Option<String>,
    pub answered_by: Option<String>,
    pub linked_actors: Vec<String>,
    pub linked_campaigns: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateIntelRequirementRequest {
    pub title: String,
    pub description: Option<String>,
    pub priority: String,
    pub category: String,
    pub requester: Option<String>,
    pub due_date: Option<String>,
    pub linked_actors: Option<Vec<String>>,
    pub linked_campaigns: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateIntelRequirementRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub priority: Option<String>,
    pub status: Option<String>,
    pub answer: Option<String>,
    pub linked_actors: Option<Vec<String>>,
    pub linked_campaigns: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct IntelRequirementQuery {
    pub status: Option<String>,
    pub priority: Option<String>,
    pub category: Option<String>,
    pub limit: Option<i32>,
}

// ============================================================================
// Sprint 12: Threat Briefing Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ThreatBriefing {
    pub id: String,
    pub title: String,
    pub executive_summary: String,
    pub generated_at: String,
    pub period_start: String,
    pub period_end: String,
    pub threat_landscape: ThreatLandscape,
    pub top_actors: Vec<ThreatActorBrief>,
    pub active_campaigns: Vec<CampaignBrief>,
    pub key_iocs: Vec<KeyIoc>,
    pub recommendations: Vec<String>,
    pub risk_assessment: RiskAssessment,
}

#[derive(Debug, Serialize)]
pub struct ThreatLandscape {
    pub overall_threat_level: String,  // low, medium, high, critical
    pub trend: String,                  // increasing, stable, decreasing
    pub top_targeted_sectors: Vec<SectorThreat>,
    pub emerging_threats: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SectorThreat {
    pub sector: String,
    pub threat_level: String,
    pub active_actors: i32,
    pub recent_incidents: i32,
}

#[derive(Debug, Serialize)]
pub struct ThreatActorBrief {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub motivation: String,
    pub recent_activity: String,
    pub threat_level: String,
    pub key_ttps: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CampaignBrief {
    pub id: String,
    pub name: String,
    pub actor_name: Option<String>,
    pub target_sectors: Vec<String>,
    pub status: String,
    pub last_activity: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct KeyIoc {
    pub ioc_type: String,
    pub value: String,
    pub threat_level: String,
    pub associated_actor: Option<String>,
    pub first_seen: String,
}

#[derive(Debug, Serialize)]
pub struct RiskAssessment {
    pub overall_risk: String,
    pub likelihood: String,
    pub impact: String,
    pub key_risks: Vec<String>,
    pub mitigations: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GenerateBriefingRequest {
    pub title: Option<String>,
    pub period_days: Option<i32>,
    pub focus_sectors: Option<Vec<String>>,
    pub focus_actors: Option<Vec<String>>,
}

// ============================================================================
// MISP Server Management Endpoints
// ============================================================================

/// POST /api/threat-intel/misp/servers
/// Create a new MISP server configuration
pub async fn create_misp_server(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateMispServerRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let req = body.into_inner();
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO misp_servers (id, user_id, name, url, api_key, verify_ssl, is_active, auto_sync, sync_interval_hours, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&req.name)
    .bind(&req.url)
    .bind(&req.api_key)
    .bind(req.verify_ssl.unwrap_or(true))
    .bind(req.auto_sync.unwrap_or(false))
    .bind(req.sync_interval_hours.unwrap_or(24))
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to create MISP server: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create MISP server")
    })?;

    info!("Created MISP server '{}' for user {}", req.name, user_id);

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "name": req.name,
        "message": "MISP server created successfully"
    })))
}

/// GET /api/threat-intel/misp/servers
/// List all MISP servers for the current user
pub async fn list_misp_servers(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let servers: Vec<MispServerConfig> = sqlx::query_as::<_, (String, String, String, String, bool, bool, bool, i32, Option<String>, Option<String>, i32, String)>(
        r#"
        SELECT id, name, url, api_key, verify_ssl, is_active, auto_sync, sync_interval_hours, last_sync_at, last_sync_status, events_synced, created_at
        FROM misp_servers WHERE user_id = ? ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to list MISP servers: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to list MISP servers")
    })?
    .into_iter()
    .map(|row| MispServerConfig {
        id: row.0,
        name: row.1,
        url: row.2,
        api_key: "***REDACTED***".to_string(), // Don't expose API key
        verify_ssl: row.4,
        is_active: row.5,
        auto_sync: row.6,
        sync_interval_hours: row.7,
        last_sync_at: row.8,
        last_sync_status: row.9,
        events_synced: row.10,
        created_at: row.11,
    })
    .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "servers": servers,
        "total": servers.len()
    })))
}

/// GET /api/threat-intel/misp/servers/{id}
/// Get a specific MISP server configuration
pub async fn get_misp_server(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let server_id = path.into_inner();

    let server = sqlx::query_as::<_, (String, String, String, String, bool, bool, bool, i32, Option<String>, Option<String>, i32, String)>(
        r#"
        SELECT id, name, url, api_key, verify_ssl, is_active, auto_sync, sync_interval_hours, last_sync_at, last_sync_status, events_synced, created_at
        FROM misp_servers WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&server_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get MISP server: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get MISP server")
    })?;

    match server {
        Some(row) => {
            let config = MispServerConfig {
                id: row.0,
                name: row.1,
                url: row.2,
                api_key: "***REDACTED***".to_string(),
                verify_ssl: row.4,
                is_active: row.5,
                auto_sync: row.6,
                sync_interval_hours: row.7,
                last_sync_at: row.8,
                last_sync_status: row.9,
                events_synced: row.10,
                created_at: row.11,
            };
            Ok(HttpResponse::Ok().json(config))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "MISP server not found"
        }))),
    }
}

/// DELETE /api/threat-intel/misp/servers/{id}
/// Delete a MISP server configuration
pub async fn delete_misp_server(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let server_id = path.into_inner();

    let result = sqlx::query("DELETE FROM misp_servers WHERE id = ? AND user_id = ?")
        .bind(&server_id)
        .bind(user_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            error!("Failed to delete MISP server: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete MISP server")
        })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "MISP server not found"
        })));
    }

    info!("Deleted MISP server {} for user {}", server_id, user_id);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "MISP server deleted"
    })))
}

/// POST /api/threat-intel/misp/servers/{id}/test
/// Test connection to a MISP server
pub async fn test_misp_server(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let server_id = path.into_inner();

    // Get server config
    let server = sqlx::query_as::<_, (String, String)>(
        "SELECT url, api_key FROM misp_servers WHERE id = ? AND user_id = ?",
    )
    .bind(&server_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get MISP server: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get MISP server")
    })?;

    match server {
        Some((url, api_key)) => {
            let config = MispConfig {
                base_url: url,
                api_key,
                verify_ssl: true,
                org_id: None,
            };
            let client = match MispClient::new(config) {
                Ok(c) => c,
                Err(e) => return Ok(HttpResponse::Ok().json(serde_json::json!({
                    "success": false,
                    "message": format!("Failed to create MISP client: {}", e)
                }))),
            };
            let query = MispSearchQuery { limit: Some(1), ..Default::default() };
            match client.search_events(&query).await {
                Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "message": "Connection successful"
                }))),
                Err(e) => Ok(HttpResponse::Ok().json(serde_json::json!({
                    "success": false,
                    "message": format!("Connection failed: {}", e)
                }))),
            }
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "MISP server not found"
        }))),
    }
}

/// POST /api/threat-intel/misp/servers/{id}/sync
/// Sync events from a MISP server
pub async fn sync_misp_server(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let server_id = path.into_inner();

    // Get server config
    let server = sqlx::query_as::<_, (String, String)>(
        "SELECT url, api_key FROM misp_servers WHERE id = ? AND user_id = ?",
    )
    .bind(&server_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get MISP server: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get MISP server")
    })?;

    let (url, api_key) = match server {
        Some(s) => s,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "MISP server not found"
            })));
        }
    };

    let config = MispConfig {
        base_url: url,
        api_key,
        verify_ssl: true,
        org_id: None,
    };
    let client = match MispClient::new(config) {
        Ok(c) => c,
        Err(e) => {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": false,
                "message": format!("Failed to create MISP client: {}", e)
            })));
        }
    };
    let query = MispSearchQuery { limit: Some(100), ..Default::default() };
    let events = match client.search_events(&query).await {
        Ok(e) => e,
        Err(e) => {
            // Update sync status
            let now = Utc::now().to_rfc3339();
            let _ = sqlx::query(
                "UPDATE misp_servers SET last_sync_at = ?, last_sync_status = ? WHERE id = ?",
            )
            .bind(&now)
            .bind(format!("Failed: {}", e))
            .bind(&server_id)
            .execute(pool.get_ref())
            .await;

            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": false,
                "message": format!("Sync failed: {}", e)
            })));
        }
    };

    let now = Utc::now().to_rfc3339();
    let mut events_synced = 0;

    for event in &events {
        let event_id = Uuid::new_v4().to_string();
        let tags_json = serde_json::to_string(&event.tags.iter().map(|t| &t.name).collect::<Vec<_>>()).unwrap_or_default();

        // Upsert event
        let result = sqlx::query(
            r#"
            INSERT INTO misp_events (id, server_id, misp_event_id, misp_uuid, org_name, info, threat_level, analysis_status, date, published, attribute_count, tags, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_id, misp_event_id) DO UPDATE SET
                info = excluded.info,
                threat_level = excluded.threat_level,
                analysis_status = excluded.analysis_status,
                published = excluded.published,
                attribute_count = excluded.attribute_count,
                tags = excluded.tags,
                synced_at = excluded.synced_at
            "#,
        )
        .bind(&event_id)
        .bind(&server_id)
        .bind(&event.id)
        .bind(&event.uuid)
        .bind(&event.org_id)
        .bind(&event.info)
        .bind(&event.threat_level_id)
        .bind(&event.analysis)
        .bind(&event.date)
        .bind(event.published)
        .bind(event.attribute_count as i32)
        .bind(&tags_json)
        .bind(&now)
        .execute(pool.get_ref())
        .await;

        if result.is_ok() {
            events_synced += 1;
        }
    }

    // Update sync status
    let _ = sqlx::query(
        "UPDATE misp_servers SET last_sync_at = ?, last_sync_status = ?, events_synced = events_synced + ? WHERE id = ?",
    )
    .bind(&now)
    .bind("Success")
    .bind(events_synced)
    .bind(&server_id)
    .execute(pool.get_ref())
    .await;

    info!("Synced {} events from MISP server {}", events_synced, server_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "events_synced": events_synced,
        "message": format!("Synced {} events", events_synced)
    })))
}

/// GET /api/threat-intel/misp/events
/// List cached MISP events
pub async fn list_misp_events(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<MispEventSearchRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let limit = query.limit.unwrap_or(50);

    // Get events from servers owned by user
    let events: Vec<MispEventSummary> = sqlx::query_as::<_, (String, String, String, Option<String>, String, Option<String>, Option<String>, Option<String>, bool, i32, String, String)>(
        r#"
        SELECT e.id, e.misp_event_id, e.misp_uuid, e.org_name, e.info, e.threat_level, e.analysis_status, e.date, e.published, e.attribute_count, e.tags, e.synced_at
        FROM misp_events e
        JOIN misp_servers s ON e.server_id = s.id
        WHERE s.user_id = ?
        ORDER BY e.synced_at DESC
        LIMIT ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to list MISP events: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to list MISP events")
    })?
    .into_iter()
    .map(|row| {
        let tags: Vec<String> = serde_json::from_str(&row.10).unwrap_or_default();
        MispEventSummary {
            id: row.0,
            misp_event_id: row.1,
            misp_uuid: row.2,
            org_name: row.3,
            info: row.4,
            threat_level: row.5,
            analysis_status: row.6,
            date: row.7,
            published: row.8,
            attribute_count: row.9,
            tags,
            synced_at: row.11,
        }
    })
    .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "events": events,
        "total": events.len()
    })))
}

// ============================================================================
// TAXII Server Management Endpoints
// ============================================================================

/// POST /api/threat-intel/taxii/servers
/// Create a new TAXII server configuration
pub async fn create_taxii_server(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateTaxiiServerRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let req = body.into_inner();
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO taxii_servers (id, user_id, name, url, version, username, password, api_key, is_active, auto_poll, poll_interval_hours, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&req.name)
    .bind(&req.url)
    .bind(req.version.as_deref().unwrap_or("2.1"))
    .bind(&req.username)
    .bind(&req.password)
    .bind(&req.api_key)
    .bind(req.auto_poll.unwrap_or(false))
    .bind(req.poll_interval_hours.unwrap_or(24))
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to create TAXII server: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create TAXII server")
    })?;

    info!("Created TAXII server '{}' for user {}", req.name, user_id);

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "name": req.name,
        "message": "TAXII server created successfully"
    })))
}

/// GET /api/threat-intel/taxii/servers
/// List all TAXII servers for the current user
pub async fn list_taxii_servers(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let servers: Vec<TaxiiServerConfig> = sqlx::query_as::<_, (String, String, String, String, Option<String>, Option<String>, bool, bool, i32, Option<String>, Option<String>, i32, String)>(
        r#"
        SELECT id, name, url, version, username, api_key, is_active, auto_poll, poll_interval_hours, last_poll_at, last_poll_status, objects_received, created_at
        FROM taxii_servers WHERE user_id = ? ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to list TAXII servers: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to list TAXII servers")
    })?
    .into_iter()
    .map(|row| TaxiiServerConfig {
        id: row.0,
        name: row.1,
        url: row.2,
        version: row.3,
        username: row.4,
        api_key: row.5.map(|_| "***REDACTED***".to_string()),
        is_active: row.6,
        auto_poll: row.7,
        poll_interval_hours: row.8,
        last_poll_at: row.9,
        last_poll_status: row.10,
        objects_received: row.11,
        created_at: row.12,
    })
    .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "servers": servers,
        "total": servers.len()
    })))
}

/// DELETE /api/threat-intel/taxii/servers/{id}
/// Delete a TAXII server configuration
pub async fn delete_taxii_server(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let server_id = path.into_inner();

    let result = sqlx::query("DELETE FROM taxii_servers WHERE id = ? AND user_id = ?")
        .bind(&server_id)
        .bind(user_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            error!("Failed to delete TAXII server: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete TAXII server")
        })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "TAXII server not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "TAXII server deleted"
    })))
}

/// POST /api/threat-intel/taxii/servers/{id}/discover
/// Discover collections from a TAXII server
pub async fn discover_taxii_collections(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let server_id = path.into_inner();

    // Get server config
    let server = sqlx::query_as::<_, (String, Option<String>, Option<String>)>(
        "SELECT url, username, password FROM taxii_servers WHERE id = ? AND user_id = ?",
    )
    .bind(&server_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get TAXII server: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get TAXII server")
    })?;

    let (url, username, password) = match server {
        Some(s) => s,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "TAXII server not found"
            })));
        }
    };

    let client = TaxiiClient::new(&url, username, password);

    // Discover API root
    let discovery = match client.discover().await {
        Ok(d) => d,
        Err(e) => {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": false,
                "message": format!("Discovery failed: {}", e)
            })));
        }
    };

    let mut collections_discovered = 0;
    let now = Utc::now().to_rfc3339();

    // Get collections from each API root
    for api_root in &discovery.api_roots {
        if let Ok(collections) = client.list_collections(api_root).await {
            for collection in &collections {
                let coll_id = Uuid::new_v4().to_string();
                let media_types = serde_json::to_string(&collection.media_types).unwrap_or_default();

                let result = sqlx::query(
                    r#"
                    INSERT INTO taxii_collections (id, server_id, collection_id, title, description, can_read, can_write, media_types, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(server_id, collection_id) DO UPDATE SET
                        title = excluded.title,
                        description = excluded.description,
                        can_read = excluded.can_read,
                        can_write = excluded.can_write,
                        media_types = excluded.media_types
                    "#,
                )
                .bind(&coll_id)
                .bind(&server_id)
                .bind(&collection.id)
                .bind(&collection.title)
                .bind(&collection.description)
                .bind(collection.can_read)
                .bind(collection.can_write)
                .bind(&media_types)
                .bind(&now)
                .execute(pool.get_ref())
                .await;

                if result.is_ok() {
                    collections_discovered += 1;
                }
            }
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "collections_discovered": collections_discovered,
        "api_roots": discovery.api_roots.len()
    })))
}

/// GET /api/threat-intel/taxii/collections
/// List discovered TAXII collections
pub async fn list_taxii_collections(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let collections: Vec<TaxiiCollectionInfo> = sqlx::query_as::<_, (String, String, String, Option<String>, bool, bool, String, bool, Option<String>, i32)>(
        r#"
        SELECT c.id, c.collection_id, c.title, c.description, c.can_read, c.can_write, c.media_types, c.subscribed, c.last_poll_at, c.objects_count
        FROM taxii_collections c
        JOIN taxii_servers s ON c.server_id = s.id
        WHERE s.user_id = ?
        ORDER BY c.title
        "#,
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to list TAXII collections: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to list TAXII collections")
    })?
    .into_iter()
    .map(|row| {
        let media_types: Vec<String> = serde_json::from_str(&row.6).unwrap_or_default();
        TaxiiCollectionInfo {
            id: row.0,
            collection_id: row.1,
            title: row.2,
            description: row.3,
            can_read: row.4,
            can_write: row.5,
            media_types,
            subscribed: row.7,
            last_poll_at: row.8,
            objects_count: row.9,
        }
    })
    .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "collections": collections,
        "total": collections.len()
    })))
}

// ============================================================================
// STIX Object Endpoints
// ============================================================================

/// GET /api/threat-intel/stix/objects
/// List cached STIX objects
pub async fn list_stix_objects(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<StixObjectQuery>,
) -> Result<HttpResponse> {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from(
        "SELECT id, stix_id, stix_type, name, description, labels, confidence, created, modified, revoked, source_type FROM stix_objects WHERE 1=1"
    );

    if query.stix_type.is_some() {
        sql.push_str(" AND stix_type = ?");
    }
    if query.name.is_some() {
        sql.push_str(" AND name LIKE ?");
    }
    if query.source_type.is_some() {
        sql.push_str(" AND source_type = ?");
    }

    sql.push_str(" ORDER BY modified DESC LIMIT ? OFFSET ?");

    let mut q = sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>, Option<String>, Option<i32>, String, String, bool, String)>(&sql);

    if let Some(ref t) = query.stix_type {
        q = q.bind(t);
    }
    if let Some(ref n) = query.name {
        q = q.bind(format!("%{}%", n));
    }
    if let Some(ref s) = query.source_type {
        q = q.bind(s);
    }

    q = q.bind(limit).bind(offset);

    let objects: Vec<StixObjectSummary> = q
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| {
            error!("Failed to list STIX objects: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to list STIX objects")
        })?
        .into_iter()
        .map(|row| {
            let labels: Vec<String> = row.5.and_then(|l| serde_json::from_str(&l).ok()).unwrap_or_default();
            StixObjectSummary {
                id: row.0,
                stix_id: row.1,
                stix_type: row.2,
                name: row.3,
                description: row.4,
                labels,
                confidence: row.6,
                created: row.7,
                modified: row.8,
                revoked: row.9,
                source_type: row.10,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "objects": objects,
        "total": objects.len()
    })))
}

/// GET /api/threat-intel/stix/objects/{stix_id}
/// Get a specific STIX object by STIX ID
pub async fn get_stix_object(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let stix_id = path.into_inner();

    let object = sqlx::query_as::<_, (String,)>(
        "SELECT raw_json FROM stix_objects WHERE stix_id = ?",
    )
    .bind(&stix_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get STIX object: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get STIX object")
    })?;

    match object {
        Some((raw_json,)) => {
            let obj: serde_json::Value = serde_json::from_str(&raw_json).unwrap_or_default();
            Ok(HttpResponse::Ok().json(obj))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "STIX object not found"
        }))),
    }
}

/// POST /api/threat-intel/stix/import
/// Import a STIX bundle
pub async fn import_stix_bundle(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<StixBundleImportRequest>,
) -> Result<HttpResponse> {
    let req = body.into_inner();
    let source_type = req.source_type.unwrap_or_else(|| "manual".to_string());
    let now = Utc::now().to_rfc3339();

    let bundle = req.bundle;
    let objects = bundle.get("objects").and_then(|o| o.as_array());

    let objects = match objects {
        Some(o) => o,
        None => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid STIX bundle: missing objects array"
            })));
        }
    };

    let mut result = StixImportResult {
        objects_imported: 0,
        relationships_imported: 0,
        sightings_imported: 0,
        errors: Vec::new(),
    };

    for obj in objects {
        let stix_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");
        let stix_id = obj.get("id").and_then(|i| i.as_str()).unwrap_or("");

        if stix_id.is_empty() {
            result.errors.push("Object missing id field".to_string());
            continue;
        }

        let id = Uuid::new_v4().to_string();
        let raw_json = serde_json::to_string(obj).unwrap_or_default();
        let name = obj.get("name").and_then(|n| n.as_str());
        let description = obj.get("description").and_then(|d| d.as_str());
        let labels = obj.get("labels").map(|l| serde_json::to_string(l).unwrap_or_default());
        let confidence = obj.get("confidence").and_then(|c| c.as_i64()).map(|c| c as i32);
        let created = obj.get("created").and_then(|c| c.as_str()).unwrap_or(&now);
        let modified = obj.get("modified").and_then(|m| m.as_str()).unwrap_or(&now);
        let revoked = obj.get("revoked").and_then(|r| r.as_bool()).unwrap_or(false);

        if stix_type == "relationship" {
            let relationship_type = obj.get("relationship_type").and_then(|r| r.as_str()).unwrap_or("");
            let source_ref = obj.get("source_ref").and_then(|s| s.as_str()).unwrap_or("");
            let target_ref = obj.get("target_ref").and_then(|t| t.as_str()).unwrap_or("");

            let insert_result = sqlx::query(
                r#"
                INSERT INTO stix_relationships (id, stix_id, relationship_type, source_ref, target_ref, description, created, modified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(stix_id) DO UPDATE SET modified = excluded.modified
                "#,
            )
            .bind(&id)
            .bind(stix_id)
            .bind(relationship_type)
            .bind(source_ref)
            .bind(target_ref)
            .bind(description)
            .bind(created)
            .bind(modified)
            .execute(pool.get_ref())
            .await;

            if insert_result.is_ok() {
                result.relationships_imported += 1;
            }
        } else if stix_type == "sighting" {
            let sighting_of_ref = obj.get("sighting_of_ref").and_then(|s| s.as_str()).unwrap_or("");
            let count = obj.get("count").and_then(|c| c.as_i64()).unwrap_or(1) as i32;

            let insert_result = sqlx::query(
                r#"
                INSERT INTO stix_sightings (id, stix_id, sighting_of_ref, count, description, created, modified)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(stix_id) DO UPDATE SET modified = excluded.modified, count = excluded.count
                "#,
            )
            .bind(&id)
            .bind(stix_id)
            .bind(sighting_of_ref)
            .bind(count)
            .bind(description)
            .bind(created)
            .bind(modified)
            .execute(pool.get_ref())
            .await;

            if insert_result.is_ok() {
                result.sightings_imported += 1;
            }
        } else {
            let insert_result = sqlx::query(
                r#"
                INSERT INTO stix_objects (id, stix_id, stix_type, spec_version, created, modified, name, description, labels, confidence, revoked, raw_json, source_type, synced_at)
                VALUES (?, ?, ?, '2.1', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(stix_id) DO UPDATE SET
                    modified = excluded.modified,
                    name = excluded.name,
                    description = excluded.description,
                    labels = excluded.labels,
                    revoked = excluded.revoked,
                    raw_json = excluded.raw_json,
                    synced_at = excluded.synced_at
                "#,
            )
            .bind(&id)
            .bind(stix_id)
            .bind(stix_type)
            .bind(created)
            .bind(modified)
            .bind(name)
            .bind(description)
            .bind(&labels)
            .bind(confidence)
            .bind(revoked)
            .bind(&raw_json)
            .bind(&source_type)
            .bind(&now)
            .execute(pool.get_ref())
            .await;

            if insert_result.is_ok() {
                result.objects_imported += 1;
            }
        }
    }

    info!(
        "Imported STIX bundle: {} objects, {} relationships, {} sightings",
        result.objects_imported, result.relationships_imported, result.sightings_imported
    );

    Ok(HttpResponse::Ok().json(result))
}

/// GET /api/threat-intel/stix/export
/// Export STIX objects as a bundle
pub async fn export_stix_bundle(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<StixExportRequest>,
) -> Result<HttpResponse> {
    let include_relationships = query.include_relationships.unwrap_or(true);
    let include_sightings = query.include_sightings.unwrap_or(true);

    let mut objects: Vec<serde_json::Value> = Vec::new();

    // Get main objects
    let type_filter = query.stix_types.as_ref().map(|t| t.join(","));

    let main_objects: Vec<(String,)> = if let Some(ref types) = type_filter {
        let placeholders = types.split(',').map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT raw_json FROM stix_objects WHERE stix_type IN ({}) AND revoked = 0",
            placeholders
        );
        let mut q = sqlx::query_as(&sql);
        for t in types.split(',') {
            q = q.bind(t.trim());
        }
        q.fetch_all(pool.get_ref()).await.unwrap_or_default()
    } else {
        sqlx::query_as("SELECT raw_json FROM stix_objects WHERE revoked = 0")
            .fetch_all(pool.get_ref())
            .await
            .unwrap_or_default()
    };

    for (raw_json,) in main_objects {
        if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&raw_json) {
            objects.push(obj);
        }
    }

    // Get relationships
    if include_relationships {
        let relationships: Vec<(String, String, String, String, Option<String>, String, String)> = sqlx::query_as(
            "SELECT stix_id, relationship_type, source_ref, target_ref, description, created, modified FROM stix_relationships"
        )
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

        for rel in relationships {
            objects.push(serde_json::json!({
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel.0,
                "relationship_type": rel.1,
                "source_ref": rel.2,
                "target_ref": rel.3,
                "description": rel.4,
                "created": rel.5,
                "modified": rel.6
            }));
        }
    }

    // Get sightings
    if include_sightings {
        let sightings: Vec<(String, String, i32, Option<String>, String, String)> = sqlx::query_as(
            "SELECT stix_id, sighting_of_ref, count, description, created, modified FROM stix_sightings"
        )
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

        for sig in sightings {
            objects.push(serde_json::json!({
                "type": "sighting",
                "spec_version": "2.1",
                "id": sig.0,
                "sighting_of_ref": sig.1,
                "count": sig.2,
                "description": sig.3,
                "created": sig.4,
                "modified": sig.5
            }));
        }
    }

    let bundle = serde_json::json!({
        "type": "bundle",
        "id": format!("bundle--{}", Uuid::new_v4()),
        "objects": objects
    });

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(bundle))
}

// ============================================================================
// Threat Actor Endpoints
// ============================================================================

/// GET /api/threat-intel/actors
/// List threat actors
pub async fn list_threat_actors(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<ThreatActorQuery>,
) -> Result<HttpResponse> {
    let limit = query.limit.unwrap_or(50);
    let active_only = query.active_only.unwrap_or(false);

    let mut sql = String::from(
        "SELECT id, name, aliases, actor_type, country, motivation, active, sophistication, first_seen, last_seen, target_sectors FROM threat_actors WHERE 1=1"
    );

    if active_only {
        sql.push_str(" AND active = 1");
    }
    if query.actor_type.is_some() {
        sql.push_str(" AND actor_type = ?");
    }
    if query.country.is_some() {
        sql.push_str(" AND country = ?");
    }
    if query.motivation.is_some() {
        sql.push_str(" AND motivation = ?");
    }
    if query.name.is_some() {
        sql.push_str(" AND (name LIKE ? OR aliases LIKE ?)");
    }

    sql.push_str(" ORDER BY last_seen DESC NULLS LAST LIMIT ?");

    let mut q = sqlx::query_as::<_, (String, String, Option<String>, String, Option<String>, String, bool, i32, Option<String>, Option<String>, Option<String>)>(&sql);

    // Pre-create pattern to ensure it lives long enough for the query
    let name_pattern = query.name.as_ref().map(|n| format!("%{}%", n));

    if let Some(ref t) = query.actor_type {
        q = q.bind(t);
    }
    if let Some(ref c) = query.country {
        q = q.bind(c);
    }
    if let Some(ref m) = query.motivation {
        q = q.bind(m);
    }
    if let Some(ref pattern) = name_pattern {
        q = q.bind(pattern).bind(pattern);
    }

    q = q.bind(limit);

    let actors: Vec<ThreatActorSummary> = q
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| {
            error!("Failed to list threat actors: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to list threat actors")
        })?
        .into_iter()
        .map(|row| {
            let aliases: Vec<String> = row.2.and_then(|a| serde_json::from_str(&a).ok()).unwrap_or_default();
            let target_sectors: Vec<String> = row.10.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
            ThreatActorSummary {
                id: row.0,
                name: row.1,
                aliases,
                actor_type: row.3,
                country: row.4,
                motivation: row.5,
                active: row.6,
                sophistication: row.7,
                first_seen: row.8,
                last_seen: row.9,
                target_sectors,
                campaign_count: 0, // Would need a join to count
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "actors": actors,
        "total": actors.len()
    })))
}

/// GET /api/threat-intel/actors/{id}
/// Get a specific threat actor
pub async fn get_threat_actor(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let actor_id = path.into_inner();

    use sqlx::Row;

    let actor = sqlx::query(
        r#"
        SELECT id, name, aliases, actor_type, country, sponsor, motivation, secondary_motivations, description,
               first_seen, last_seen, active, sophistication, resource_level, target_sectors, target_countries,
               ttps, tools, malware, infrastructure, external_references, mitre_groups
        FROM threat_actors WHERE id = ?
        "#,
    )
    .bind(&actor_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get threat actor: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get threat actor")
    })?;

    match actor {
        Some(row) => {
            let aliases_str: Option<String> = row.get("aliases");
            let aliases: Vec<String> = aliases_str.and_then(|a| serde_json::from_str(&a).ok()).unwrap_or_default();

            let secondary_str: Option<String> = row.get("secondary_motivations");
            let secondary_motivations: Vec<String> = secondary_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();

            let sectors_str: Option<String> = row.get("target_sectors");
            let target_sectors: Vec<String> = sectors_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();

            let countries_str: Option<String> = row.get("target_countries");
            let target_countries: Vec<String> = countries_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();

            let ttps_str: Option<String> = row.get("ttps");
            let ttps: Vec<String> = ttps_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();

            let tools_str: Option<String> = row.get("tools");
            let tools: Vec<String> = tools_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();

            let malware_str: Option<String> = row.get("malware");
            let malware: Vec<String> = malware_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();

            let infra_str: Option<String> = row.get("infrastructure");
            let infrastructure: Option<serde_json::Value> = infra_str.and_then(|s| serde_json::from_str(&s).ok());

            let refs_str: Option<String> = row.get("external_references");
            let external_references: Vec<ExternalReference> = refs_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();

            let mitre_str: Option<String> = row.get("mitre_groups");
            let mitre_groups: Vec<String> = mitre_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();

            // Get campaigns for this actor
            let campaigns: Vec<CampaignSummary> = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, Option<String>, String, i32)>(
                "SELECT id, name, description, first_seen, last_seen, status, 0 FROM campaigns WHERE threat_actor_id = ? ORDER BY first_seen DESC LIMIT 10"
            )
            .bind(&actor_id)
            .fetch_all(pool.get_ref())
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|c| CampaignSummary {
                id: c.0,
                name: c.1,
                description: c.2,
                first_seen: c.3,
                last_seen: c.4,
                status: c.5,
                target_count: c.6,
            })
            .collect();

            let detail = ThreatActorDetail {
                id: row.get("id"),
                name: row.get("name"),
                aliases,
                actor_type: row.get("actor_type"),
                country: row.get("country"),
                sponsor: row.get("sponsor"),
                motivation: row.get("motivation"),
                secondary_motivations,
                description: row.get("description"),
                first_seen: row.get("first_seen"),
                last_seen: row.get("last_seen"),
                active: row.get("active"),
                sophistication: row.get("sophistication"),
                resource_level: row.get("resource_level"),
                target_sectors,
                target_countries,
                ttps,
                tools,
                malware,
                infrastructure,
                external_references,
                campaigns,
                mitre_groups,
            };

            Ok(HttpResponse::Ok().json(detail))
        }
        None => {
            // Try built-in database
            let db = ThreatActorDatabase::new();
            if let Some(profile) = db.get_actor(&actor_id) {
                let detail = ThreatActorDetail {
                    id: actor_id.clone(),
                    name: profile.name.clone(),
                    aliases: profile.aliases.clone(),
                    actor_type: format!("{:?}", profile.actor_type),
                    country: profile.country.clone(),
                    sponsor: profile.sponsor.clone(),
                    motivation: format!("{:?}", profile.motivation),
                    secondary_motivations: profile.secondary_motivations.iter().map(|m| format!("{:?}", m)).collect(),
                    description: profile.description.clone(),
                    first_seen: profile.first_seen.map(|dt| dt.to_rfc3339()),
                    last_seen: profile.last_seen.map(|dt| dt.to_rfc3339()),
                    active: profile.active,
                    sophistication: profile.sophistication as i32,
                    resource_level: profile.resource_level as i32,
                    target_sectors: profile.target_sectors.clone(),
                    target_countries: profile.target_countries.clone(),
                    ttps: profile.ttps.clone(),
                    tools: profile.tools.clone(),
                    malware: profile.malware_families.clone(),
                    infrastructure: serde_json::to_value(&profile.infrastructure).ok(),
                    external_references: profile.references.iter().map(|r| ExternalReference {
                        source: r.source.clone(),
                        url: Some(r.url.clone()),
                        external_id: None,
                        description: r.description.clone(),
                    }).collect(),
                    campaigns: profile.campaigns.iter().map(|c| CampaignSummary {
                        id: c.clone(),
                        name: c.clone(),
                        description: None,
                        first_seen: None,
                        last_seen: None,
                        status: "unknown".to_string(),
                        target_count: 0,
                    }).collect(),
                    mitre_groups: profile.mitre_id.clone().map(|id| vec![id]).unwrap_or_default(),
                };
                Ok(HttpResponse::Ok().json(detail))
            } else {
                Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Threat actor not found"
                })))
            }
        }
    }
}

/// GET /api/threat-intel/actors/builtin
/// List built-in threat actor profiles
pub async fn list_builtin_threat_actors(
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse> {
    let db = ThreatActorDatabase::new();
    let actors: Vec<ThreatActorSummary> = db.all_actors().iter().map(|profile| {
        ThreatActorSummary {
            id: profile.name.clone(),
            name: profile.name.clone(),
            aliases: profile.aliases.clone(),
            actor_type: format!("{:?}", profile.actor_type),
            country: profile.country.clone(),
            motivation: format!("{:?}", profile.motivation),
            active: profile.active,
            sophistication: profile.sophistication as i32,
            first_seen: profile.first_seen.map(|dt| dt.to_rfc3339()),
            last_seen: profile.last_seen.map(|dt| dt.to_rfc3339()),
            target_sectors: profile.target_sectors.clone(),
            campaign_count: profile.campaigns.len() as i32,
        }
    }).collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "actors": actors,
        "total": actors.len()
    })))
}

// ============================================================================
// Campaign Endpoints
// ============================================================================

/// GET /api/threat-intel/campaigns
/// List campaigns
pub async fn list_campaigns(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<CampaignQuery>,
) -> Result<HttpResponse> {
    let limit = query.limit.unwrap_or(50);

    let campaigns: Vec<CampaignSummary> = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, Option<String>, String, i32)>(
        r#"
        SELECT id, name, description, first_seen, last_seen, status, 0
        FROM campaigns
        ORDER BY first_seen DESC NULLS LAST
        LIMIT ?
        "#,
    )
    .bind(limit)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to list campaigns: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to list campaigns")
    })?
    .into_iter()
    .map(|row| CampaignSummary {
        id: row.0,
        name: row.1,
        description: row.2,
        first_seen: row.3,
        last_seen: row.4,
        status: row.5,
        target_count: row.6,
    })
    .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "campaigns": campaigns,
        "total": campaigns.len()
    })))
}

/// POST /api/threat-intel/campaigns
/// Create a new campaign
pub async fn create_campaign(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateCampaignRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let req = body.into_inner();
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let targets_json = req.targets.as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_default());
    let ttps_json = req.ttps.as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO campaigns (id, user_id, name, threat_actor_id, description, objective,
            first_seen, last_seen, status, targets_json, ttps_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&req.name)
    .bind(&req.threat_actor_id)
    .bind(&req.description)
    .bind(&req.objective)
    .bind(&req.first_seen)
    .bind(&req.first_seen) // last_seen = first_seen initially
    .bind(req.status.as_deref().unwrap_or("active"))
    .bind(&targets_json)
    .bind(&ttps_json)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to create campaign: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create campaign")
    })?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "name": req.name,
        "message": "Campaign created successfully"
    })))
}

/// GET /api/threat-intel/campaigns/{id}
/// Get campaign details
pub async fn get_campaign(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let campaign_id = path.into_inner();

    let campaign: Option<(String, String, Option<String>, Option<String>, Option<String>,
        Option<String>, Option<String>, String, Option<String>, Option<String>, String, String)> =
        sqlx::query_as(
            r#"
            SELECT id, name, threat_actor_id, description, objective,
                first_seen, last_seen, status, targets_json, ttps_json, created_at, updated_at
            FROM campaigns
            WHERE id = ?
            "#,
        )
        .bind(&campaign_id)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| {
            error!("Failed to get campaign: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get campaign")
        })?;

    if let Some(c) = campaign {
        let targets: Vec<CampaignTarget> = c.8.as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        let ttps: Vec<String> = c.9.as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();

        // Get associated IOCs
        let iocs: Vec<CampaignIoc> = sqlx::query_as::<_, (String, String, Option<i32>, Option<String>, Option<String>)>(
            "SELECT ioc_type, ioc_value, confidence, first_seen, last_seen FROM campaign_iocs WHERE campaign_id = ?"
        )
        .bind(&campaign_id)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|row| CampaignIoc {
            ioc_type: row.0,
            value: row.1,
            confidence: row.2.unwrap_or(50),
            first_seen: row.3,
            last_seen: row.4,
        })
        .collect();

        // Get threat actor name if available
        let threat_actor_name: Option<String> = if let Some(ref actor_id) = c.2 {
            sqlx::query_scalar("SELECT name FROM threat_actors WHERE id = ?")
                .bind(actor_id)
                .fetch_optional(pool.get_ref())
                .await
                .ok()
                .flatten()
        } else {
            None
        };

        // Get timeline events
        let timeline_events: Vec<TimelineEvent> = sqlx::query_as::<_, (String, String, String, Option<String>)>(
            "SELECT timestamp, event_type, description, references FROM campaign_timeline WHERE campaign_id = ? ORDER BY timestamp DESC"
        )
        .bind(&campaign_id)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|row| TimelineEvent {
            timestamp: row.0,
            event_type: row.1,
            description: row.2,
            references: row.3.map(|r| serde_json::from_str(&r).unwrap_or_default()).unwrap_or_default(),
        })
        .collect();

        let detail = CampaignDetail {
            id: c.0,
            name: c.1,
            threat_actor_id: c.2,
            threat_actor_name,
            description: c.3,
            objective: c.4,
            first_seen: c.5,
            last_seen: c.6,
            status: c.7,
            confidence: 75,
            targets,
            ttps,
            iocs,
            timeline_events,
            attribution_confidence: 75,
        };

        Ok(HttpResponse::Ok().json(detail))
    } else {
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Campaign not found"
        })))
    }
}

/// PUT /api/threat-intel/campaigns/{id}
/// Update campaign
pub async fn update_campaign(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<CreateCampaignRequest>,
) -> Result<HttpResponse> {
    let campaign_id = path.into_inner();
    let req = body.into_inner();
    let now = Utc::now().to_rfc3339();

    let targets_json = req.targets.as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_default());
    let ttps_json = req.ttps.as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_default());

    let result = sqlx::query(
        r#"
        UPDATE campaigns SET
            name = ?, threat_actor_id = ?, description = ?, objective = ?,
            first_seen = COALESCE(?, first_seen), status = COALESCE(?, status),
            targets_json = COALESCE(?, targets_json), ttps_json = COALESCE(?, ttps_json),
            updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&req.name)
    .bind(&req.threat_actor_id)
    .bind(&req.description)
    .bind(&req.objective)
    .bind(&req.first_seen)
    .bind(&req.status)
    .bind(&targets_json)
    .bind(&ttps_json)
    .bind(&now)
    .bind(&campaign_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to update campaign: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update campaign")
    })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Campaign not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": campaign_id,
        "message": "Campaign updated successfully"
    })))
}

/// DELETE /api/threat-intel/campaigns/{id}
/// Delete campaign
pub async fn delete_campaign(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let campaign_id = path.into_inner();

    // Delete associated IOCs first
    let _ = sqlx::query("DELETE FROM campaign_iocs WHERE campaign_id = ?")
        .bind(&campaign_id)
        .execute(pool.get_ref())
        .await;

    let result = sqlx::query("DELETE FROM campaigns WHERE id = ?")
        .bind(&campaign_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            error!("Failed to delete campaign: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete campaign")
        })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Campaign not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Campaign deleted successfully"
    })))
}

// ============================================================================
// Sprint 12: Diamond Model Endpoints
// ============================================================================

/// POST /api/threat-intel/diamond/events
/// Create a Diamond Model event
pub async fn create_diamond_event(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateDiamondEventRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let req = body.into_inner();
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let adversary = DiamondVertex {
        id: Some(Uuid::new_v4().to_string()),
        name: req.adversary_name,
        vertex_type: "adversary".to_string(),
        properties: req.adversary_properties.unwrap_or(serde_json::json!({})),
    };
    let capability = DiamondVertex {
        id: Some(Uuid::new_v4().to_string()),
        name: req.capability_name,
        vertex_type: "capability".to_string(),
        properties: req.capability_properties.unwrap_or(serde_json::json!({})),
    };
    let infrastructure = DiamondVertex {
        id: Some(Uuid::new_v4().to_string()),
        name: req.infrastructure_name,
        vertex_type: "infrastructure".to_string(),
        properties: req.infrastructure_properties.unwrap_or(serde_json::json!({})),
    };
    let victim = DiamondVertex {
        id: Some(Uuid::new_v4().to_string()),
        name: req.victim_name,
        vertex_type: "victim".to_string(),
        properties: req.victim_properties.unwrap_or(serde_json::json!({})),
    };

    let event = DiamondEvent {
        id: id.clone(),
        campaign_id: req.campaign_id.clone(),
        adversary: adversary.clone(),
        capability: capability.clone(),
        infrastructure: infrastructure.clone(),
        victim: victim.clone(),
        timestamp: req.timestamp.clone(),
        phase: req.phase.clone(),
        confidence: req.confidence.unwrap_or(50),
        notes: req.notes.clone(),
        meta_features: DiamondMetaFeatures {
            direction: Some("adversary-to-victim".to_string()),
            methodology: None,
            resources: None,
            result: None,
        },
        created_at: now.clone(),
    };

    let event_json = serde_json::to_string(&event).unwrap_or_default();

    sqlx::query(
        r#"
        INSERT INTO diamond_events (id, user_id, campaign_id, adversary_json, capability_json,
            infrastructure_json, victim_json, timestamp, phase, confidence, notes, event_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&req.campaign_id)
    .bind(serde_json::to_string(&adversary).ok())
    .bind(serde_json::to_string(&capability).ok())
    .bind(serde_json::to_string(&infrastructure).ok())
    .bind(serde_json::to_string(&victim).ok())
    .bind(&req.timestamp)
    .bind(&req.phase)
    .bind(req.confidence.unwrap_or(50))
    .bind(&req.notes)
    .bind(&event_json)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to create diamond event: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create diamond event")
    })?;

    Ok(HttpResponse::Created().json(event))
}

/// GET /api/threat-intel/diamond/events
/// List Diamond Model events
pub async fn list_diamond_events(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<CampaignQuery>,
) -> Result<HttpResponse> {
    let campaign_filter = query.threat_actor_id.as_ref(); // reuse for campaign_id filter
    let limit = query.limit.unwrap_or(50);

    let events: Vec<DiamondEvent> = if let Some(campaign_id) = campaign_filter {
        sqlx::query_as::<_, (String,)>(
            "SELECT event_json FROM diamond_events WHERE campaign_id = ? ORDER BY timestamp DESC LIMIT ?"
        )
        .bind(campaign_id)
        .bind(limit)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default()
    } else {
        sqlx::query_as::<_, (String,)>(
            "SELECT event_json FROM diamond_events ORDER BY timestamp DESC LIMIT ?"
        )
        .bind(limit)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default()
    }
    .into_iter()
    .filter_map(|row| serde_json::from_str(&row.0).ok())
    .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "events": events,
        "total": events.len()
    })))
}

/// GET /api/threat-intel/diamond/events/{id}
/// Get Diamond Model event details
pub async fn get_diamond_event(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let event_id = path.into_inner();

    let event: Option<(String,)> = sqlx::query_as(
        "SELECT event_json FROM diamond_events WHERE id = ?"
    )
    .bind(&event_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get diamond event: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get diamond event")
    })?;

    if let Some(e) = event {
        let parsed: DiamondEvent = serde_json::from_str(&e.0).map_err(|_| {
            actix_web::error::ErrorInternalServerError("Failed to parse diamond event")
        })?;
        Ok(HttpResponse::Ok().json(parsed))
    } else {
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Diamond event not found"
        })))
    }
}

// ============================================================================
// Sprint 12: Kill Chain Endpoints
// ============================================================================

/// GET /api/threat-intel/kill-chain/{campaign_id}
/// Get Kill Chain analysis for a campaign
pub async fn get_kill_chain_analysis(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let campaign_id = path.into_inner();

    // Get campaign name
    let campaign: Option<(String, String)> = sqlx::query_as(
        "SELECT id, name FROM campaigns WHERE id = ?"
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get campaign: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get campaign")
    })?;

    let (cid, cname) = match campaign {
        Some(c) => c,
        None => return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Campaign not found"
        }))),
    };

    // Get techniques detected for this campaign from diamond events
    let techniques: Vec<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT phase, timestamp, notes
        FROM diamond_events
        WHERE campaign_id = ?
        ORDER BY timestamp ASC
        "#
    )
    .bind(&campaign_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // Build kill chain phases
    let phases: Vec<KillChainPhase> = KILL_CHAIN_PHASES.iter().map(|(phase_id, phase_name, order)| {
        let phase_techniques: Vec<KillChainTechnique> = techniques.iter()
            .filter(|(p, _, _)| p.as_ref().map(|pp: &String| pp.to_lowercase().contains(*phase_id)).unwrap_or(false))
            .map(|(_, ts, notes)| KillChainTechnique {
                technique_id: format!("KC-{}", order),
                technique_name: format!("{} activity", phase_name),
                detected: true,
                detection_source: Some("diamond_event".to_string()),
                timestamp: ts.clone(),
                evidence: notes.clone(),
            })
            .collect();

        let coverage = if phase_techniques.is_empty() { 0.0 } else { 100.0 };

        KillChainPhase {
            phase: phase_id.to_string(),
            phase_name: phase_name.to_string(),
            order: *order,
            techniques: phase_techniques,
            coverage,
        }
    }).collect();

    let detected = phases.iter().filter(|p| !p.techniques.is_empty()).count();
    let total = phases.len();
    let coverage = (detected as f64 / total as f64) * 100.0;

    let analysis = KillChainAnalysis {
        campaign_id: cid,
        campaign_name: cname,
        phases,
        coverage,
        detected_techniques: detected as i32,
        total_techniques: total as i32,
    };

    Ok(HttpResponse::Ok().json(analysis))
}

/// GET /api/threat-intel/kill-chain/phases
/// Get Kill Chain phase definitions
pub async fn get_kill_chain_phases(
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse> {
    let phases: Vec<serde_json::Value> = KILL_CHAIN_PHASES.iter().map(|(id, name, order)| {
        serde_json::json!({
            "id": id,
            "name": name,
            "order": order
        })
    }).collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "phases": phases,
        "total": phases.len()
    })))
}

// ============================================================================
// Sprint 12: Intelligence Requirements Endpoints
// ============================================================================

/// GET /api/threat-intel/requirements
/// List intelligence requirements
pub async fn list_intel_requirements(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<IntelRequirementQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let limit = query.limit.unwrap_or(50);

    let mut sql = String::from(
        r#"SELECT id, title, description, priority, category, status, requester,
            due_date, answer, answered_at, answered_by, linked_actors, linked_campaigns,
            created_at, updated_at
        FROM intelligence_requirements
        WHERE user_id = ?"#
    );

    if query.status.is_some() {
        sql.push_str(" AND status = ?");
    }
    if query.priority.is_some() {
        sql.push_str(" AND priority = ?");
    }
    if query.category.is_some() {
        sql.push_str(" AND category = ?");
    }
    sql.push_str(" ORDER BY created_at DESC LIMIT ?");

    let mut q = sqlx::query_as::<_, (String, String, Option<String>, String, String, String,
        Option<String>, Option<String>, Option<String>, Option<String>, Option<String>,
        Option<String>, Option<String>, String, String)>(&sql)
        .bind(user_id);

    if let Some(status) = &query.status {
        q = q.bind(status);
    }
    if let Some(priority) = &query.priority {
        q = q.bind(priority);
    }
    if let Some(category) = &query.category {
        q = q.bind(category);
    }
    q = q.bind(limit);

    let requirements: Vec<IntelligenceRequirement> = q
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|row| IntelligenceRequirement {
            id: row.0,
            title: row.1,
            description: row.2,
            priority: row.3,
            category: row.4,
            status: row.5,
            requester: row.6,
            due_date: row.7,
            answer: row.8,
            answered_at: row.9,
            answered_by: row.10,
            linked_actors: row.11.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
            linked_campaigns: row.12.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
            created_at: row.13,
            updated_at: row.14,
        })
        .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "requirements": requirements,
        "total": requirements.len()
    })))
}

/// POST /api/threat-intel/requirements
/// Create intelligence requirement
pub async fn create_intel_requirement(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateIntelRequirementRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let req = body.into_inner();
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let linked_actors_json = req.linked_actors.as_ref()
        .map(|a| serde_json::to_string(a).unwrap_or_default());
    let linked_campaigns_json = req.linked_campaigns.as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO intelligence_requirements (id, user_id, title, description, priority, category,
            status, requester, due_date, linked_actors, linked_campaigns, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&req.title)
    .bind(&req.description)
    .bind(&req.priority)
    .bind(&req.category)
    .bind(&req.requester)
    .bind(&req.due_date)
    .bind(&linked_actors_json)
    .bind(&linked_campaigns_json)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to create intel requirement: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create intel requirement")
    })?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "title": req.title,
        "message": "Intelligence requirement created successfully"
    })))
}

/// PUT /api/threat-intel/requirements/{id}
/// Update intelligence requirement
pub async fn update_intel_requirement(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateIntelRequirementRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let req_id = path.into_inner();
    let req = body.into_inner();
    let now = Utc::now().to_rfc3339();

    // Check if answering
    let answered_at = if req.answer.is_some() && req.status.as_deref() == Some("answered") {
        Some(now.clone())
    } else {
        None
    };
    let answered_by = if answered_at.is_some() {
        Some(user_id.clone())
    } else {
        None
    };

    let linked_actors_json = req.linked_actors.as_ref()
        .map(|a| serde_json::to_string(a).unwrap_or_default());
    let linked_campaigns_json = req.linked_campaigns.as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default());

    let result = sqlx::query(
        r#"
        UPDATE intelligence_requirements SET
            title = COALESCE(?, title),
            description = COALESCE(?, description),
            priority = COALESCE(?, priority),
            status = COALESCE(?, status),
            answer = COALESCE(?, answer),
            answered_at = COALESCE(?, answered_at),
            answered_by = COALESCE(?, answered_by),
            linked_actors = COALESCE(?, linked_actors),
            linked_campaigns = COALESCE(?, linked_campaigns),
            updated_at = ?
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&req.title)
    .bind(&req.description)
    .bind(&req.priority)
    .bind(&req.status)
    .bind(&req.answer)
    .bind(&answered_at)
    .bind(&answered_by)
    .bind(&linked_actors_json)
    .bind(&linked_campaigns_json)
    .bind(&now)
    .bind(&req_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to update intel requirement: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update intel requirement")
    })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Intelligence requirement not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": req_id,
        "message": "Intelligence requirement updated successfully"
    })))
}

/// DELETE /api/threat-intel/requirements/{id}
/// Delete intelligence requirement
pub async fn delete_intel_requirement(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let req_id = path.into_inner();

    let result = sqlx::query("DELETE FROM intelligence_requirements WHERE id = ? AND user_id = ?")
        .bind(&req_id)
        .bind(user_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            error!("Failed to delete intel requirement: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete intel requirement")
        })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Intelligence requirement not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Intelligence requirement deleted successfully"
    })))
}

// ============================================================================
// Sprint 12: Threat Briefing Endpoints
// ============================================================================

/// POST /api/threat-intel/briefings/generate
/// Generate a threat briefing
pub async fn generate_threat_briefing(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<GenerateBriefingRequest>,
) -> Result<HttpResponse> {
    let req = body.into_inner();
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let period_days = req.period_days.unwrap_or(30);
    let period_start = (now - chrono::Duration::days(period_days as i64)).to_rfc3339();
    let period_end = now.to_rfc3339();

    // Get active campaigns
    let campaigns: Vec<CampaignBrief> = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, String, Option<String>)>(
        r#"
        SELECT c.id, c.name, c.threat_actor_id, c.targets_json, c.status, c.last_seen
        FROM campaigns c
        WHERE c.status = 'active' OR c.last_seen >= ?
        ORDER BY c.last_seen DESC
        LIMIT 10
        "#
    )
    .bind(&period_start)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|row| {
        let targets: Vec<String> = row.3.as_ref()
            .and_then(|s| serde_json::from_str::<Vec<CampaignTarget>>(s).ok())
            .map(|ts| ts.into_iter().filter_map(|t| t.sector).collect())
            .unwrap_or_default();
        CampaignBrief {
            id: row.0,
            name: row.1,
            actor_name: row.2,
            target_sectors: targets,
            status: row.4,
            last_activity: row.5,
        }
    })
    .collect();

    // Get built-in threat actors
    let db = ThreatActorDatabase::new();
    let top_actors: Vec<ThreatActorBrief> = db.all_actors().iter().take(5).map(|a| {
        ThreatActorBrief {
            id: a.name.clone(),
            name: a.name.clone(),
            aliases: a.aliases.clone(),
            motivation: format!("{:?}", a.motivation),
            recent_activity: "Active".to_string(),
            threat_level: if a.sophistication >= 8 { "high".to_string() } else { "medium".to_string() },
            key_ttps: a.ttps.iter().take(5).cloned().collect(),
        }
    }).collect();

    // Generate executive summary
    let executive_summary = format!(
        "This threat briefing covers the period from {} to {}. \
        {} active threat campaigns were identified, with {} known threat actors of concern. \
        The overall threat landscape remains elevated with nation-state actors continuing \
        targeted operations against critical infrastructure and government sectors.",
        &period_start[..10], &period_end[..10],
        campaigns.len(), top_actors.len()
    );

    // Build threat landscape
    let threat_landscape = ThreatLandscape {
        overall_threat_level: "high".to_string(),
        trend: "stable".to_string(),
        top_targeted_sectors: vec![
            SectorThreat { sector: "Government".to_string(), threat_level: "high".to_string(), active_actors: 3, recent_incidents: 5 },
            SectorThreat { sector: "Technology".to_string(), threat_level: "high".to_string(), active_actors: 4, recent_incidents: 8 },
            SectorThreat { sector: "Healthcare".to_string(), threat_level: "medium".to_string(), active_actors: 2, recent_incidents: 3 },
            SectorThreat { sector: "Financial".to_string(), threat_level: "high".to_string(), active_actors: 3, recent_incidents: 6 },
        ],
        emerging_threats: vec![
            "Increased ransomware-as-a-service activity".to_string(),
            "Supply chain compromise attempts".to_string(),
            "Zero-day exploitation in network appliances".to_string(),
        ],
    };

    // Risk assessment
    let risk_assessment = RiskAssessment {
        overall_risk: "high".to_string(),
        likelihood: "likely".to_string(),
        impact: "significant".to_string(),
        key_risks: vec![
            "Targeted attacks on critical infrastructure".to_string(),
            "Data exfiltration from sensitive systems".to_string(),
            "Ransomware deployment in enterprise networks".to_string(),
        ],
        mitigations: vec![
            "Implement network segmentation".to_string(),
            "Enable multi-factor authentication".to_string(),
            "Deploy endpoint detection and response".to_string(),
            "Conduct regular security awareness training".to_string(),
        ],
    };

    let briefing = ThreatBriefing {
        id,
        title: req.title.unwrap_or_else(|| format!("Threat Briefing - {}", &period_end[..10])),
        executive_summary,
        generated_at: now.to_rfc3339(),
        period_start,
        period_end,
        threat_landscape,
        top_actors,
        active_campaigns: campaigns,
        key_iocs: Vec::new(), // Would populate from IOC correlations
        recommendations: vec![
            "Prioritize patching of internet-facing systems".to_string(),
            "Review access controls for privileged accounts".to_string(),
            "Update threat detection rules for identified TTPs".to_string(),
            "Conduct tabletop exercises for incident response".to_string(),
        ],
        risk_assessment,
    };

    Ok(HttpResponse::Ok().json(briefing))
}

/// GET /api/threat-intel/briefings/latest
/// Get the latest threat briefing summary
pub async fn get_latest_briefing(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    // Return a quick summary based on current data
    let campaign_count: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM campaigns WHERE status = 'active'")
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or(0);

    let ioc_count: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM ioc_correlations")
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or(0);

    let db = ThreatActorDatabase::new();
    let actor_count = db.all_actors().len();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "summary": {
            "active_campaigns": campaign_count,
            "tracked_actors": actor_count,
            "ioc_correlations": ioc_count,
            "threat_level": "high",
            "last_updated": Utc::now().to_rfc3339()
        }
    })))
}

// ============================================================================
// IOC Correlation Endpoints
// ============================================================================

/// POST /api/threat-intel/correlate
/// Correlate IOCs with scan data
pub async fn correlate_iocs(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<CorrelateIocsRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let req = body.into_inner();
    let now = Utc::now().to_rfc3339();

    let mut correlations: Vec<IocCorrelation> = Vec::new();
    let mut total_checked = 0;

    // Get IOCs to check
    let iocs_to_check: Vec<(String, String)> = if let Some(iocs) = req.iocs {
        total_checked = iocs.len();
        iocs.into_iter().map(|i| (i.ioc_type, i.value)).collect()
    } else if let Some(scan_id) = req.scan_id {
        // Extract IOCs from scan results
        let scan = crate::db::get_scan_by_id(pool.get_ref(), &scan_id).await.ok().flatten();
        if let Some(scan) = scan {
            let hosts: Vec<crate::types::HostInfo> = scan
                .results
                .as_ref()
                .and_then(|r| serde_json::from_str(r).ok())
                .unwrap_or_default();

            let mut iocs = Vec::new();
            for host in hosts {
                iocs.push(("ip".to_string(), host.target.ip.to_string()));
                // Could extract more IOCs like domains, hashes from service banners, etc.
            }
            total_checked = iocs.len();
            iocs
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Check each IOC against MISP attributes and STIX indicators
    for (ioc_type, ioc_value) in &iocs_to_check {
        // Check MISP attributes
        let misp_matches: Vec<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT a.id, a.category, e.info
            FROM misp_attributes a
            JOIN misp_events e ON a.event_id = e.id
            WHERE a.value = ?
            LIMIT 10
            "#,
        )
        .bind(ioc_value)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

        for (attr_id, category, event_info) in misp_matches {
            let correlation = IocCorrelation {
                ioc_type: ioc_type.clone(),
                ioc_value: ioc_value.clone(),
                source_type: "misp".to_string(),
                source_id: attr_id.clone(),
                matched_entity_type: category,
                matched_entity_id: attr_id,
                confidence: 0.8,
                context: Some(event_info),
                first_seen: now.clone(),
                last_seen: now.clone(),
            };
            correlations.push(correlation);
        }

        // Check STIX indicators
        let stix_matches: Vec<(String, String, Option<String>)> = sqlx::query_as(
            r#"
            SELECT stix_id, stix_type, name
            FROM stix_objects
            WHERE stix_type = 'indicator' AND raw_json LIKE ?
            LIMIT 10
            "#,
        )
        .bind(format!("%{}%", ioc_value))
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

        for (stix_id, stix_type, name) in stix_matches {
            let correlation = IocCorrelation {
                ioc_type: ioc_type.clone(),
                ioc_value: ioc_value.clone(),
                source_type: "stix".to_string(),
                source_id: stix_id.clone(),
                matched_entity_type: stix_type,
                matched_entity_id: stix_id,
                confidence: 0.75,
                context: name,
                first_seen: now.clone(),
                last_seen: now.clone(),
            };
            correlations.push(correlation);
        }
    }

    // Store correlations
    for corr in &correlations {
        let id = Uuid::new_v4().to_string();
        let _ = sqlx::query(
            r#"
            INSERT INTO ioc_correlations (id, ioc_type, ioc_value, source_type, source_id, matched_entity_type, matched_entity_id, confidence, context, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ioc_type, ioc_value, source_type, source_id, matched_entity_type, matched_entity_id) DO UPDATE SET
                last_seen = excluded.last_seen
            "#,
        )
        .bind(&id)
        .bind(&corr.ioc_type)
        .bind(&corr.ioc_value)
        .bind(&corr.source_type)
        .bind(&corr.source_id)
        .bind(&corr.matched_entity_type)
        .bind(&corr.matched_entity_id)
        .bind(corr.confidence)
        .bind(&corr.context)
        .bind(&corr.first_seen)
        .bind(&corr.last_seen)
        .execute(pool.get_ref())
        .await;
    }

    let result = CorrelationResult {
        total_iocs_checked: total_checked,
        matches_found: correlations.len(),
        correlations,
    };

    Ok(HttpResponse::Ok().json(result))
}

/// GET /api/threat-intel/correlations
/// List IOC correlations
pub async fn list_correlations(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<CorrelationQuery>,
) -> Result<HttpResponse> {
    let limit = query.limit.unwrap_or(100);

    let correlations: Vec<IocCorrelation> = sqlx::query_as::<_, (String, String, String, String, String, String, f64, Option<String>, String, String)>(
        r#"
        SELECT ioc_type, ioc_value, source_type, source_id, matched_entity_type, matched_entity_id, confidence, context, first_seen, last_seen
        FROM ioc_correlations
        ORDER BY last_seen DESC
        LIMIT ?
        "#,
    )
    .bind(limit)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to list correlations: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to list correlations")
    })?
    .into_iter()
    .map(|row| IocCorrelation {
        ioc_type: row.0,
        ioc_value: row.1,
        source_type: row.2,
        source_id: row.3,
        matched_entity_type: row.4,
        matched_entity_id: row.5,
        confidence: row.6,
        context: row.7,
        first_seen: row.8,
        last_seen: row.9,
    })
    .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "correlations": correlations,
        "total": correlations.len()
    })))
}

// ============================================================================
// Dashboard Endpoint
// ============================================================================

/// GET /api/threat-intel/dashboard
/// Get threat intelligence dashboard statistics
pub async fn get_dashboard(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Get counts
    let misp_servers: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM misp_servers WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or(0);

    let misp_events: i32 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM misp_events e JOIN misp_servers s ON e.server_id = s.id WHERE s.user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    let misp_attributes: i32 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM misp_attributes a JOIN misp_events e ON a.event_id = e.id JOIN misp_servers s ON e.server_id = s.id WHERE s.user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    let taxii_servers: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM taxii_servers WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or(0);

    let taxii_collections: i32 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM taxii_collections c JOIN taxii_servers s ON c.server_id = s.id WHERE s.user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    let stix_objects: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM stix_objects")
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or(0);

    let threat_actors: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM threat_actors")
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or(0);

    let active_campaigns: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM campaigns WHERE status = 'active'")
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or(0);

    let ioc_correlations: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM ioc_correlations")
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or(0);

    let recent_alerts: i32 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM threat_alerts WHERE created_at > datetime('now', '-7 days')"
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    // Get built-in threat actors for top list
    let db = ThreatActorDatabase::new();
    let top_threat_actors: Vec<ThreatActorSummary> = db.all_actors().iter().take(5).map(|profile| {
        ThreatActorSummary {
            id: profile.name.clone(),
            name: profile.name.clone(),
            aliases: profile.aliases.clone(),
            actor_type: format!("{:?}", profile.actor_type),
            country: profile.country.clone(),
            motivation: format!("{:?}", profile.motivation),
            active: profile.active,
            sophistication: profile.sophistication as i32,
            first_seen: profile.first_seen.map(|dt| dt.to_rfc3339()),
            last_seen: profile.last_seen.map(|dt| dt.to_rfc3339()),
            target_sectors: profile.target_sectors.clone(),
            campaign_count: profile.campaigns.len() as i32,
        }
    }).collect();

    let dashboard = ThreatIntelDashboard {
        misp_servers,
        misp_events,
        misp_attributes,
        taxii_servers,
        taxii_collections,
        stix_objects,
        threat_actors: threat_actors + db.all_actors().len() as i32,
        active_campaigns,
        ioc_correlations,
        recent_alerts,
        top_threat_actors,
        recent_campaigns: Vec::new(),
        ioc_type_distribution: Vec::new(),
        threat_level_distribution: Vec::new(),
    };

    Ok(HttpResponse::Ok().json(dashboard))
}

/// Configure threat intel routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/threat-intel")
            // Existing endpoints
            .route("/status", web::get().to(get_status))
            .route("/lookup/{ip}", web::get().to(lookup_ip))
            .route("/cve/{cve_id}", web::get().to(lookup_cve))
            .route("/alerts", web::get().to(get_alerts))
            .route("/alerts/{alert_id}/acknowledge", web::post().to(acknowledge_alert))
            .route("/enrich/{scan_id}", web::post().to(enrich_scan))
            .route("/scan/{scan_id}/enrichment", web::get().to(get_scan_enrichment))
            // Dashboard
            .route("/dashboard", web::get().to(get_dashboard))
            // MISP endpoints
            .route("/misp/servers", web::post().to(create_misp_server))
            .route("/misp/servers", web::get().to(list_misp_servers))
            .route("/misp/servers/{id}", web::get().to(get_misp_server))
            .route("/misp/servers/{id}", web::delete().to(delete_misp_server))
            .route("/misp/servers/{id}/test", web::post().to(test_misp_server))
            .route("/misp/servers/{id}/sync", web::post().to(sync_misp_server))
            .route("/misp/events", web::get().to(list_misp_events))
            // TAXII endpoints
            .route("/taxii/servers", web::post().to(create_taxii_server))
            .route("/taxii/servers", web::get().to(list_taxii_servers))
            .route("/taxii/servers/{id}", web::delete().to(delete_taxii_server))
            .route("/taxii/servers/{id}/discover", web::post().to(discover_taxii_collections))
            .route("/taxii/collections", web::get().to(list_taxii_collections))
            // STIX endpoints
            .route("/stix/objects", web::get().to(list_stix_objects))
            .route("/stix/objects/{stix_id}", web::get().to(get_stix_object))
            .route("/stix/import", web::post().to(import_stix_bundle))
            .route("/stix/export", web::get().to(export_stix_bundle))
            // Threat Actor endpoints
            .route("/actors", web::get().to(list_threat_actors))
            .route("/actors/builtin", web::get().to(list_builtin_threat_actors))
            .route("/actors/{id}", web::get().to(get_threat_actor))
            // Campaign endpoints
            .route("/campaigns", web::get().to(list_campaigns))
            .route("/campaigns", web::post().to(create_campaign))
            .route("/campaigns/{id}", web::get().to(get_campaign))
            .route("/campaigns/{id}", web::put().to(update_campaign))
            .route("/campaigns/{id}", web::delete().to(delete_campaign))
            // IOC Correlation endpoints
            .route("/correlate", web::post().to(correlate_iocs))
            .route("/correlations", web::get().to(list_correlations))
            // Sprint 12: Diamond Model endpoints
            .route("/diamond/events", web::post().to(create_diamond_event))
            .route("/diamond/events", web::get().to(list_diamond_events))
            .route("/diamond/events/{id}", web::get().to(get_diamond_event))
            // Sprint 12: Kill Chain endpoints
            .route("/kill-chain/{campaign_id}", web::get().to(get_kill_chain_analysis))
            .route("/kill-chain/phases", web::get().to(get_kill_chain_phases))
            // Sprint 12: Intelligence Requirements endpoints
            .route("/requirements", web::get().to(list_intel_requirements))
            .route("/requirements", web::post().to(create_intel_requirement))
            .route("/requirements/{id}", web::put().to(update_intel_requirement))
            .route("/requirements/{id}", web::delete().to(delete_intel_requirement))
            // Sprint 12: Threat Briefing endpoints
            .route("/briefings/generate", web::post().to(generate_threat_briefing))
            .route("/briefings/latest", web::get().to(get_latest_briefing)),
    );
}
