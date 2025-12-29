//! DNS Analytics API endpoints
//!
//! Provides REST API for DNS analytics features including:
//! - Passive DNS records management
//! - DGA detection and analysis
//! - DNS tunneling detection
//! - Fast-flux detection
//! - Newly Observed Domain (NOD) tracking
//! - DNS threat intelligence

use actix_web::{web, HttpResponse, Scope};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::dns_analytics::{
    DnsAnalyticsEngine, DgaAnalysis, DnsAnomaly, DnsAnomalySeverity, DnsAnomalyStatus,
    DnsAnomalyType, DnsDashboard, DnsQuery, DnsRecordType, DnsResponseCode, DnsStats,
    FastFluxIndicators, NewlyObservedDomain, NodAlert, NodAlertSeverity, NodStats, NodStatus,
    PassiveDnsRecord, TunnelIndicators,
};
use crate::web::auth;

/// DNS Analytics application state
pub struct DnsAnalyticsState {
    pub engine: Arc<DnsAnalyticsEngine>,
}

impl DnsAnalyticsState {
    pub fn new() -> Self {
        Self {
            engine: Arc::new(DnsAnalyticsEngine::new()),
        }
    }
}

impl Default for DnsAnalyticsState {
    fn default() -> Self {
        Self::new()
    }
}

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
pub struct AnalyzeDomainRequest {
    pub domain: String,
}

#[derive(Debug, Serialize)]
pub struct AnalyzeDomainResponse {
    pub domain: String,
    pub dga_analysis: Option<DgaAnalysis>,
    pub is_dga: bool,
    pub dga_probability: Option<f64>,
    pub entropy: Option<f64>,
    pub threat_indicators: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitQueryRequest {
    pub query_name: String,
    pub query_type: String,
    pub response_data: Vec<String>,
    pub source_ip: String,
    pub ttl: Option<i32>,
    pub response_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubmitQueryResponse {
    pub processed: bool,
    pub is_dga: bool,
    pub is_tunneling: bool,
    pub is_fast_flux: bool,
    pub is_nod: bool,
    pub anomalies_detected: usize,
    pub risk_score: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct PassiveDnsQuery {
    pub domain: Option<String>,
    pub query_type: Option<String>,
    pub response_data: Option<String>,
    pub is_suspicious: Option<bool>,
    pub threat_type: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AnomaliesQuery {
    pub anomaly_type: Option<String>,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub domain: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAnomalyRequest {
    pub status: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NodsQuery {
    pub domain: Option<String>,
    pub tld: Option<String>,
    pub status: Option<String>,
    pub threat_type: Option<String>,
    pub min_risk_score: Option<i32>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateNodRequest {
    pub status: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NodAlertsQuery {
    pub acknowledged: Option<bool>,
    pub severity: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct BatchAnalyzeRequest {
    pub domains: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct BatchAnalyzeResponse {
    pub results: Vec<AnalyzeDomainResponse>,
    pub dga_count: usize,
    pub high_risk_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct WhitelistRequest {
    pub domain: String,
    pub domain_type: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WhitelistEntry {
    pub id: String,
    pub domain: String,
    pub domain_type: String,
    pub reason: Option<String>,
    pub is_global: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ThreatIntelQuery {
    pub domain: Option<String>,
    pub is_malicious: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ThreatIntelEntry {
    pub id: String,
    pub domain: String,
    pub is_malicious: bool,
    pub threat_types: Vec<String>,
    pub confidence: f64,
    pub sources: Vec<String>,
    pub first_reported: Option<String>,
    pub last_reported: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DgaFamilyQuery {
    pub family_name: Option<String>,
    pub is_builtin: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct DgaFamilyEntry {
    pub id: String,
    pub family_name: String,
    pub description: Option<String>,
    pub tld_patterns: Vec<String>,
    pub length_range: (i32, i32),
    pub entropy_range: (f64, f64),
    pub example_domains: Option<String>,
    pub is_builtin: bool,
}

// ============ API Handlers ============

/// Get DNS analytics dashboard
pub async fn get_dashboard(
    pool: web::Data<SqlitePool>,
    state: web::Data<DnsAnalyticsState>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;
    let dashboard = state.engine.get_dashboard().await;

    // Augment with database stats
    let db_stats = get_db_stats(pool.get_ref(), user_id).await;

    HttpResponse::Ok().json(serde_json::json!({
        "dashboard": dashboard,
        "db_stats": db_stats,
    }))
}

/// Get DNS statistics
pub async fn get_stats(
    _pool: web::Data<SqlitePool>,
    state: web::Data<DnsAnalyticsState>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let stats = state.engine.passive_dns.get_stats().await;
    let nod_stats = state.engine.nod_tracker.get_stats().await;

    HttpResponse::Ok().json(serde_json::json!({
        "dns_stats": stats,
        "nod_stats": nod_stats,
    }))
}

/// Analyze a single domain for DGA and other threats
pub async fn analyze_domain(
    state: web::Data<DnsAnalyticsState>,
    body: web::Json<AnalyzeDomainRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let dga = state.engine.dga_detector.read().await;
    let analysis = dga.analyze(&body.domain);

    let mut threat_indicators = Vec::new();
    if analysis.is_dga {
        threat_indicators.push(format!(
            "DGA probability: {:.1}%",
            analysis.probability * 100.0
        ));
        if let Some(family) = &analysis.detected_family {
            threat_indicators.push(format!("DGA family: {}", family));
        }
    }
    if analysis.entropy > 4.0 {
        threat_indicators.push(format!("High entropy: {:.2}", analysis.entropy));
    }
    if analysis.consonant_ratio > 0.7 {
        threat_indicators.push("Unusual consonant pattern".to_string());
    }

    HttpResponse::Ok().json(AnalyzeDomainResponse {
        domain: body.domain.clone(),
        dga_analysis: Some(analysis.clone()),
        is_dga: analysis.is_dga,
        dga_probability: Some(analysis.probability),
        entropy: Some(analysis.entropy),
        threat_indicators,
    })
}

/// Batch analyze multiple domains
pub async fn batch_analyze(
    state: web::Data<DnsAnalyticsState>,
    body: web::Json<BatchAnalyzeRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let dga = state.engine.dga_detector.read().await;

    let mut results = Vec::new();
    let mut dga_count = 0;
    let mut high_risk_count = 0;

    for domain in &body.domains {
        let analysis = dga.analyze(domain);

        let mut threat_indicators = Vec::new();
        if analysis.is_dga {
            dga_count += 1;
            threat_indicators.push(format!(
                "DGA probability: {:.1}%",
                analysis.probability * 100.0
            ));
            if analysis.probability >= 0.8 {
                high_risk_count += 1;
            }
        }
        if analysis.entropy > 4.0 {
            threat_indicators.push(format!("High entropy: {:.2}", analysis.entropy));
        }

        results.push(AnalyzeDomainResponse {
            domain: domain.clone(),
            dga_analysis: Some(analysis.clone()),
            is_dga: analysis.is_dga,
            dga_probability: Some(analysis.probability),
            entropy: Some(analysis.entropy),
            threat_indicators,
        });
    }

    HttpResponse::Ok().json(BatchAnalyzeResponse {
        results,
        dga_count,
        high_risk_count,
    })
}

/// Submit a DNS query for analysis
pub async fn submit_query(
    pool: web::Data<SqlitePool>,
    state: web::Data<DnsAnalyticsState>,
    body: web::Json<SubmitQueryRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let source_ip = match body.source_ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid source IP address"
            }))
        }
    };

    let query = DnsQuery {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        source_ip,
        source_port: 0,
        query_name: body.query_name.clone(),
        query_type: DnsRecordType::from(body.query_type.as_str()),
        response_code: body
            .response_code
            .as_ref()
            .map(|c| match c.as_str() {
                "NOERROR" | "0" => DnsResponseCode::NoError,
                "NXDOMAIN" | "3" => DnsResponseCode::NXDomain,
                "SERVFAIL" | "2" => DnsResponseCode::ServFail,
                "REFUSED" | "5" => DnsResponseCode::Refused,
                _ => DnsResponseCode::NoError,
            })
            .unwrap_or(DnsResponseCode::NoError),
        response_data: body.response_data.clone(),
        ttl: body.ttl,
        latency_ms: None,
        server_ip: None,
        is_recursive: true,
        is_dnssec: false,
    };

    let result = state.engine.process_query(&query).await;

    // Store in database if significant
    if result.dga_detected || result.tunneling_detected || result.fast_flux_detected || result.is_nod
    {
        if let Err(e) = store_anomaly(pool.get_ref(), &claims.sub, &query, &result).await {
            log::error!("Failed to store DNS anomaly: {}", e);
        }
    }

    HttpResponse::Ok().json(SubmitQueryResponse {
        processed: true,
        is_dga: result.dga_detected,
        is_tunneling: result.tunneling_detected,
        is_fast_flux: result.fast_flux_detected,
        is_nod: result.is_nod,
        anomalies_detected: result.anomalies.len(),
        risk_score: result.nod.as_ref().map(|n| n.risk_score),
    })
}

/// Get passive DNS records
pub async fn get_passive_dns(
    pool: web::Data<SqlitePool>,
    query: web::Query<PassiveDnsQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);
    let user_id = &claims.sub;

    let mut sql = String::from(
        "SELECT * FROM passive_dns_records WHERE user_id = ?"
    );
    let mut params: Vec<String> = vec![user_id.clone()];

    if let Some(domain) = &query.domain {
        sql.push_str(" AND query_name LIKE ?");
        params.push(format!("%{}%", domain));
    }
    if let Some(qt) = &query.query_type {
        sql.push_str(" AND query_type = ?");
        params.push(qt.clone());
    }
    if let Some(resp) = &query.response_data {
        sql.push_str(" AND response_data LIKE ?");
        params.push(format!("%{}%", resp));
    }
    if let Some(suspicious) = query.is_suspicious {
        sql.push_str(" AND is_suspicious = ?");
        params.push(if suspicious { "1".to_string() } else { "0".to_string() });
    }
    if let Some(threat) = &query.threat_type {
        sql.push_str(" AND threat_type = ?");
        params.push(threat.clone());
    }

    sql.push_str(" ORDER BY last_seen DESC LIMIT ? OFFSET ?");

    let records: Vec<PassiveDnsRow> = match sqlx::query_as::<_, PassiveDnsRow>(&sql)
        .bind(user_id)
        .fetch_all(pool.get_ref())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            log::error!("Failed to fetch passive DNS records: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch records"
            }));
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "records": records,
        "total": records.len(),
        "limit": limit,
        "offset": offset,
    }))
}

/// Get DNS anomalies
pub async fn get_anomalies(
    pool: web::Data<SqlitePool>,
    query: web::Query<AnomaliesQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);

    let records: Vec<DnsAnomalyRow> = match sqlx::query_as::<_, DnsAnomalyRow>(
        "SELECT * FROM dns_anomalies WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?"
    )
    .bind(&claims.sub)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await
    {
        Ok(r) => r,
        Err(e) => {
            log::error!("Failed to fetch DNS anomalies: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch anomalies"
            }));
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "anomalies": records,
        "total": records.len(),
        "limit": limit,
        "offset": offset,
    }))
}

/// Update anomaly status
pub async fn update_anomaly(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateAnomalyRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let anomaly_id = path.into_inner();
    let _now = Utc::now().to_rfc3339();

    let mut updates = Vec::new();
    let mut values = Vec::new();

    if let Some(status) = &body.status {
        updates.push("status = ?");
        values.push(status.clone());
    }
    if let Some(notes) = &body.notes {
        updates.push("notes = ?");
        values.push(notes.clone());
    }

    if updates.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No updates provided"
        }));
    }

    let sql = format!(
        "UPDATE dns_anomalies SET {} WHERE id = ? AND user_id = ?",
        updates.join(", ")
    );

    let mut query = sqlx::query(&sql);
    for v in values {
        query = query.bind(v);
    }
    query = query.bind(&anomaly_id).bind(&claims.sub);

    match query.execute(pool.get_ref()).await {
        Ok(result) => {
            if result.rows_affected() == 0 {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Anomaly not found"
                }))
            } else {
                HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "anomaly_id": anomaly_id,
                }))
            }
        }
        Err(e) => {
            log::error!("Failed to update anomaly: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update anomaly"
            }))
        }
    }
}

/// Get newly observed domains
pub async fn get_nods(
    pool: web::Data<SqlitePool>,
    query: web::Query<NodsQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);

    let records: Vec<NodRow> = match sqlx::query_as::<_, NodRow>(
        "SELECT * FROM newly_observed_domains WHERE user_id = ? ORDER BY first_seen DESC LIMIT ? OFFSET ?"
    )
    .bind(&claims.sub)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await
    {
        Ok(r) => r,
        Err(e) => {
            log::error!("Failed to fetch NODs: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch NODs"
            }));
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "nods": records,
        "total": records.len(),
        "limit": limit,
        "offset": offset,
    }))
}

/// Get high-risk NODs
pub async fn get_high_risk_nods(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let records: Vec<NodRow> = match sqlx::query_as::<_, NodRow>(
        "SELECT * FROM newly_observed_domains WHERE user_id = ? AND risk_score >= 70 ORDER BY risk_score DESC LIMIT 100"
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    {
        Ok(r) => r,
        Err(e) => {
            log::error!("Failed to fetch high-risk NODs: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch high-risk NODs"
            }));
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "high_risk_nods": records,
        "total": records.len(),
    }))
}

/// Update NOD status
pub async fn update_nod(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateNodRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let nod_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    let mut updates = vec!["updated_at = ?"];
    let mut values = vec![now];

    if let Some(status) = &body.status {
        updates.push("status = ?");
        values.push(status.clone());
    }
    if let Some(notes) = &body.notes {
        updates.push("notes = ?");
        values.push(notes.clone());
    }

    let sql = format!(
        "UPDATE newly_observed_domains SET {} WHERE id = ? AND user_id = ?",
        updates.join(", ")
    );

    let mut query = sqlx::query(&sql);
    for v in values {
        query = query.bind(v);
    }
    query = query.bind(&nod_id).bind(&claims.sub);

    match query.execute(pool.get_ref()).await {
        Ok(result) => {
            if result.rows_affected() == 0 {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "NOD not found"
                }))
            } else {
                HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "nod_id": nod_id,
                }))
            }
        }
        Err(e) => {
            log::error!("Failed to update NOD: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update NOD"
            }))
        }
    }
}

/// Get NOD alerts
pub async fn get_nod_alerts(
    pool: web::Data<SqlitePool>,
    query: web::Query<NodAlertsQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from(
        "SELECT * FROM nod_alerts WHERE user_id = ?"
    );

    if let Some(ack) = query.acknowledged {
        sql.push_str(&format!(" AND acknowledged = {}", if ack { 1 } else { 0 }));
    }
    if let Some(sev) = &query.severity {
        sql.push_str(&format!(" AND severity = '{}'", sev));
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

    let alerts: Vec<NodAlertRow> = match sqlx::query_as::<_, NodAlertRow>(&sql)
        .bind(&claims.sub)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await
    {
        Ok(a) => a,
        Err(e) => {
            log::error!("Failed to fetch NOD alerts: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch alerts"
            }));
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "alerts": alerts,
        "total": alerts.len(),
        "limit": limit,
        "offset": offset,
    }))
}

/// Acknowledge a NOD alert
pub async fn acknowledge_alert(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let alert_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    match sqlx::query(
        "UPDATE nod_alerts SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ? WHERE id = ? AND user_id = ?"
    )
    .bind(&claims.sub)
    .bind(&now)
    .bind(&alert_id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await
    {
        Ok(result) => {
            if result.rows_affected() == 0 {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Alert not found"
                }))
            } else {
                HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "alert_id": alert_id,
                }))
            }
        }
        Err(e) => {
            log::error!("Failed to acknowledge alert: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to acknowledge alert"
            }))
        }
    }
}

/// Get whitelist entries
pub async fn get_whitelist(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let entries: Vec<WhitelistRow> = match sqlx::query_as::<_, WhitelistRow>(
        "SELECT * FROM dns_whitelist WHERE user_id = ? OR is_global = 1 ORDER BY domain"
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    {
        Ok(e) => e,
        Err(e) => {
            log::error!("Failed to fetch whitelist: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch whitelist"
            }));
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "whitelist": entries,
        "total": entries.len(),
    }))
}

/// Add domain to whitelist
pub async fn add_to_whitelist(
    pool: web::Data<SqlitePool>,
    body: web::Json<WhitelistRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    match sqlx::query(
        "INSERT INTO dns_whitelist (id, user_id, domain, domain_type, reason, is_global, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)"
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&body.domain)
    .bind(body.domain_type.as_deref().unwrap_or("exact"))
    .bind(&body.reason)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "success": true,
            "id": id,
            "domain": body.domain,
        })),
        Err(e) => {
            log::error!("Failed to add to whitelist: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to add to whitelist"
            }))
        }
    }
}

/// Remove domain from whitelist
pub async fn remove_from_whitelist(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let entry_id = path.into_inner();

    match sqlx::query(
        "DELETE FROM dns_whitelist WHERE id = ? AND user_id = ? AND is_global = 0"
    )
    .bind(&entry_id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await
    {
        Ok(result) => {
            if result.rows_affected() == 0 {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Entry not found or cannot be deleted"
                }))
            } else {
                HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "id": entry_id,
                }))
            }
        }
        Err(e) => {
            log::error!("Failed to remove from whitelist: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to remove from whitelist"
            }))
        }
    }
}

/// Get DGA family signatures
pub async fn get_dga_families(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let families: Vec<DgaFamilyRow> = match sqlx::query_as::<_, DgaFamilyRow>(
        "SELECT * FROM dga_family_signatures ORDER BY family_name"
    )
    .fetch_all(pool.get_ref())
    .await
    {
        Ok(f) => f,
        Err(e) => {
            log::error!("Failed to fetch DGA families: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch DGA families"
            }));
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "families": families,
        "total": families.len(),
    }))
}

/// Get threat intelligence entries
pub async fn get_threat_intel(
    pool: web::Data<SqlitePool>,
    query: web::Query<ThreatIntelQuery>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(100).min(1000);
    let offset = query.offset.unwrap_or(0);

    let entries: Vec<ThreatIntelRow> = match sqlx::query_as::<_, ThreatIntelRow>(
        "SELECT * FROM dns_threat_intel ORDER BY last_reported DESC LIMIT ? OFFSET ?"
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await
    {
        Ok(e) => e,
        Err(e) => {
            log::error!("Failed to fetch threat intel: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch threat intel"
            }));
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "entries": entries,
        "total": entries.len(),
        "limit": limit,
        "offset": offset,
    }))
}

/// Check domain against threat intel
pub async fn check_threat_intel(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let domain = path.into_inner();

    let entry: Option<ThreatIntelRow> = match sqlx::query_as::<_, ThreatIntelRow>(
        "SELECT * FROM dns_threat_intel WHERE domain = ?"
    )
    .bind(&domain)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(e) => e,
        Err(e) => {
            log::error!("Failed to check threat intel: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to check threat intel"
            }));
        }
    };

    match entry {
        Some(e) => HttpResponse::Ok().json(serde_json::json!({
            "found": true,
            "entry": e,
        })),
        None => HttpResponse::Ok().json(serde_json::json!({
            "found": false,
            "domain": domain,
        })),
    }
}

// ============ Database Row Types ============

#[derive(Debug, sqlx::FromRow, Serialize)]
struct PassiveDnsRow {
    id: String,
    user_id: String,
    query_name: String,
    query_type: String,
    response_data: String,
    ttl: Option<i32>,
    first_seen: String,
    last_seen: String,
    query_count: i64,
    source_ips: Option<String>,
    is_suspicious: i32,
    threat_type: Option<String>,
    threat_score: i32,
    customer_id: Option<String>,
    engagement_id: Option<String>,
    created_at: String,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
struct DnsAnomalyRow {
    id: String,
    user_id: String,
    anomaly_type: String,
    domain: String,
    severity: String,
    description: String,
    indicators: Option<String>,
    entropy_score: Option<f64>,
    dga_probability: Option<f64>,
    tunnel_indicators: Option<String>,
    fast_flux_indicators: Option<String>,
    first_seen: String,
    last_seen: String,
    query_count: i64,
    status: String,
    source_ips: Option<String>,
    customer_id: Option<String>,
    engagement_id: Option<String>,
    notes: Option<String>,
    resolved_by: Option<String>,
    resolved_at: Option<String>,
    created_at: String,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
struct NodRow {
    id: String,
    user_id: String,
    domain: String,
    tld: String,
    first_seen: String,
    last_seen: Option<String>,
    first_query_ip: Option<String>,
    querying_ips: Option<String>,
    registrar: Option<String>,
    registration_date: Option<String>,
    whois_data: Option<String>,
    risk_score: i32,
    threat_indicators: Option<String>,
    threat_type: Option<String>,
    status: String,
    resolved_ips: Option<String>,
    query_count: i64,
    notes: Option<String>,
    customer_id: Option<String>,
    engagement_id: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
struct NodAlertRow {
    id: String,
    user_id: String,
    nod_id: String,
    domain: String,
    risk_score: i32,
    severity: String,
    threat_type: Option<String>,
    indicators: Option<String>,
    first_seen: String,
    source_ip: Option<String>,
    acknowledged: i32,
    acknowledged_by: Option<String>,
    acknowledged_at: Option<String>,
    created_at: String,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
struct WhitelistRow {
    id: String,
    user_id: Option<String>,
    domain: String,
    domain_type: String,
    reason: Option<String>,
    is_global: i32,
    created_at: String,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
struct DgaFamilyRow {
    id: String,
    family_name: String,
    description: Option<String>,
    tld_patterns: Option<String>,
    length_min: Option<i32>,
    length_max: Option<i32>,
    entropy_min: Option<f64>,
    entropy_max: Option<f64>,
    example_domains: Option<String>,
    associated_malware: Option<String>,
    is_builtin: i32,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
struct ThreatIntelRow {
    id: String,
    domain: String,
    is_malicious: i32,
    threat_types: Option<String>,
    confidence: f64,
    sources: Option<String>,
    first_reported: Option<String>,
    last_reported: Option<String>,
    associated_malware: Option<String>,
    associated_campaigns: Option<String>,
    iocs: Option<String>,
    created_at: String,
    updated_at: String,
}

// ============ Helper Functions ============

async fn get_db_stats(pool: &SqlitePool, user_id: &str) -> serde_json::Value {
    let passive_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM passive_dns_records WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let anomaly_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM dns_anomalies WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let nod_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM newly_observed_domains WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let alert_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM nod_alerts WHERE user_id = ? AND acknowledged = 0"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    serde_json::json!({
        "passive_dns_records": passive_count,
        "anomalies": anomaly_count,
        "newly_observed_domains": nod_count,
        "unacknowledged_alerts": alert_count,
    })
}

async fn store_anomaly(
    pool: &SqlitePool,
    user_id: &str,
    query: &DnsQuery,
    result: &crate::dns_analytics::AnalysisResult,
) -> Result<(), sqlx::Error> {
    let now = Utc::now().to_rfc3339();

    // Store NOD if detected
    if let Some(nod) = &result.nod {
        let _ = sqlx::query(
            r#"INSERT OR REPLACE INTO newly_observed_domains
               (id, user_id, domain, tld, first_seen, last_seen, first_query_ip, risk_score,
                threat_indicators, threat_type, status, query_count, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#
        )
        .bind(&nod.id)
        .bind(user_id)
        .bind(&nod.domain)
        .bind(&nod.tld)
        .bind(nod.first_seen.to_rfc3339())
        .bind(nod.last_seen.map(|d| d.to_rfc3339()))
        .bind(nod.first_query_ip.map(|ip| ip.to_string()))
        .bind(nod.risk_score)
        .bind(serde_json::to_string(&nod.threat_indicators).ok())
        .bind(nod.threat_type.map(|t| t.to_string()))
        .bind(nod.status.to_string())
        .bind(nod.query_count)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await;
    }

    // Store anomalies
    for anomaly in &result.anomalies {
        let _ = sqlx::query(
            r#"INSERT INTO dns_anomalies
               (id, user_id, anomaly_type, domain, severity, description, indicators,
                entropy_score, dga_probability, first_seen, last_seen, query_count, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)"#
        )
        .bind(&anomaly.id)
        .bind(user_id)
        .bind(anomaly.anomaly_type.to_string())
        .bind(&anomaly.domain)
        .bind(anomaly.severity.to_string())
        .bind(&anomaly.description)
        .bind(anomaly.indicators.to_string())
        .bind(anomaly.entropy_score)
        .bind(anomaly.dga_probability)
        .bind(anomaly.first_seen.to_rfc3339())
        .bind(anomaly.last_seen.to_rfc3339())
        .bind(anomaly.query_count)
        .bind(&now)
        .execute(pool)
        .await;
    }

    Ok(())
}

// ============ Route Configuration ============

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/dns-analytics")
            .app_data(web::Data::new(DnsAnalyticsState::new()))
            // Dashboard & Stats
            .route("/dashboard", web::get().to(get_dashboard))
            .route("/stats", web::get().to(get_stats))
            // Domain Analysis
            .route("/analyze", web::post().to(analyze_domain))
            .route("/analyze/batch", web::post().to(batch_analyze))
            .route("/query", web::post().to(submit_query))
            // Passive DNS
            .route("/passive-dns", web::get().to(get_passive_dns))
            // Anomalies
            .route("/anomalies", web::get().to(get_anomalies))
            .route("/anomalies/{id}", web::put().to(update_anomaly))
            // NODs
            .route("/nods", web::get().to(get_nods))
            .route("/nods/high-risk", web::get().to(get_high_risk_nods))
            .route("/nods/{id}", web::put().to(update_nod))
            // NOD Alerts
            .route("/alerts", web::get().to(get_nod_alerts))
            .route("/alerts/{id}/acknowledge", web::post().to(acknowledge_alert))
            // Whitelist
            .route("/whitelist", web::get().to(get_whitelist))
            .route("/whitelist", web::post().to(add_to_whitelist))
            .route("/whitelist/{id}", web::delete().to(remove_from_whitelist))
            // DGA Families
            .route("/dga-families", web::get().to(get_dga_families))
            // Threat Intel
            .route("/threat-intel", web::get().to(get_threat_intel))
            .route("/threat-intel/{domain}", web::get().to(check_threat_intel))
    );
}
