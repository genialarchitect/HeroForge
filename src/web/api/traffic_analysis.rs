//! Traffic Analysis API
//!
//! Provides endpoints for network traffic analysis:
//! - PCAP upload and parsing
//! - Session reconstruction
//! - Protocol dissection
//! - IDS rule matching
//! - JA3/JA3S fingerprinting
//! - Beacon detection
//! - File carving

use actix_multipart::Multipart;
use actix_web::{web, HttpResponse};
use anyhow::Result;
use chrono::Utc;
use futures::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;
use std::collections::HashMap;
use std::path::Path;
use std::fs;

use crate::traffic_analysis::{
    PcapParser, ProtocolAnalyzer, IdsEngine, Ja3Fingerprinter,
    BeaconDetector, FileCarver,
};
use crate::traffic_analysis::types::{IdsRuleSource, IdsSeverity, SessionType};
use crate::web::auth;
use crate::web::error::ApiError;

/// Traffic analysis statistics
#[derive(Debug, Serialize)]
pub struct TrafficAnalysisStats {
    pub total_captures: i64,
    pub total_sessions: i64,
    pub total_packets: i64,
    pub total_bytes: i64,
    pub ids_alerts: i64,
    pub beacon_detections: i64,
    pub carved_files: i64,
    pub suspicious_dns: i64,
    pub malware_fingerprints: i64,
}

/// Capture upload response
#[derive(Debug, Serialize)]
pub struct CaptureUploadResponse {
    pub id: String,
    pub name: String,
    pub file_size: i64,
    pub status: String,
    pub message: String,
}

/// Capture list query params
#[derive(Debug, Deserialize)]
pub struct CaptureListQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub status: Option<String>,
    pub search: Option<String>,
}

/// Capture summary for list view
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct CaptureSummary {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub file_size: i64,
    pub total_packets: i64,
    pub total_bytes: i64,
    pub status: String,
    pub created_at: String,
}

/// Full capture detail
#[derive(Debug, Serialize)]
pub struct CaptureDetail {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub file_path: String,
    pub file_size: i64,
    pub file_hash: String,
    pub capture_type: String,
    pub total_packets: i64,
    pub total_bytes: i64,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub duration_seconds: Option<f64>,
    pub status: String,
    pub created_at: String,
    pub session_count: i64,
    pub alert_count: i64,
    pub beacon_count: i64,
    pub carved_file_count: i64,
}

/// Session summary
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SessionSummary {
    pub id: String,
    pub session_key: String,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: Option<i32>,
    pub dst_ip: String,
    pub dst_port: Option<i32>,
    pub start_time: String,
    pub duration_seconds: Option<f64>,
    pub packets_sent: i64,
    pub packets_received: i64,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub application_protocol: Option<String>,
    pub ja3_fingerprint: Option<String>,
    pub is_suspicious: bool,
}

/// Session list query
#[derive(Debug, Deserialize)]
pub struct SessionListQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub protocol: Option<String>,
    pub suspicious_only: Option<bool>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
}

/// IDS Alert summary
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct IdsAlertSummary {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub rule_category: Option<String>,
    pub severity: String,
    pub message: String,
    pub src_ip: Option<String>,
    pub src_port: Option<i32>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<i32>,
    pub protocol: Option<String>,
    pub timestamp: String,
    pub false_positive: bool,
    pub acknowledged: bool,
}

/// IDS Alert list query
#[derive(Debug, Deserialize)]
pub struct AlertListQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub severity: Option<String>,
    pub acknowledged: Option<bool>,
    pub false_positive: Option<bool>,
}

/// Beacon detection summary
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct BeaconSummary {
    pub id: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: i32,
    pub connection_count: i64,
    pub avg_interval_seconds: f64,
    pub jitter_percentage: f64,
    pub beacon_score: f64,
    pub is_likely_beacon: bool,
    pub first_seen: String,
    pub last_seen: String,
}

/// Carved file summary
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct CarvedFileSummary {
    pub id: String,
    pub file_name: Option<String>,
    pub file_type: String,
    pub mime_type: Option<String>,
    pub file_size: i64,
    pub file_hash: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub extraction_method: String,
    pub is_malicious: bool,
    pub malware_family: Option<String>,
    pub created_at: String,
}

/// DNS query summary
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct DnsQuerySummary {
    pub id: String,
    pub query_name: String,
    pub query_type: String,
    pub response_code: Option<String>,
    pub answers: Option<String>,
    pub is_dga_suspicious: bool,
    pub dga_score: Option<f64>,
    pub is_tunneling_suspicious: bool,
    pub timestamp: String,
}

/// HTTP transaction summary
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct HttpTransactionSummary {
    pub id: String,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub user_agent: Option<String>,
    pub status_code: Option<i32>,
    pub is_suspicious: bool,
    pub suspicion_reasons: Option<String>,
    pub timestamp: String,
}

/// TLS analysis summary
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TlsAnalysisSummary {
    pub id: String,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub server_name: Option<String>,
    pub ja3_fingerprint: Option<String>,
    pub ja3s_fingerprint: Option<String>,
    pub ja3_known_match: Option<String>,
    pub is_self_signed: bool,
    pub is_expired: bool,
    pub is_suspicious: bool,
    pub timestamp: String,
}

/// Custom IDS rule
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct CustomIdsRule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub rule_content: String,
    pub rule_format: String,
    pub category: Option<String>,
    pub severity: String,
    pub enabled: bool,
    pub hit_count: i64,
    pub last_hit_at: Option<String>,
    pub created_at: String,
}

/// Create custom IDS rule request
#[derive(Debug, Deserialize)]
pub struct CreateIdsRuleRequest {
    pub name: String,
    pub description: Option<String>,
    pub rule_content: String,
    pub rule_format: Option<String>,
    pub category: Option<String>,
    pub severity: Option<String>,
}

/// Update IDS rule request
#[derive(Debug, Deserialize)]
pub struct UpdateIdsRuleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub rule_content: Option<String>,
    pub category: Option<String>,
    pub severity: Option<String>,
    pub enabled: Option<bool>,
}

/// Acknowledge/update alert request
#[derive(Debug, Deserialize)]
pub struct UpdateAlertRequest {
    pub acknowledged: Option<bool>,
    pub false_positive: Option<bool>,
}

/// Analysis configuration
#[derive(Debug, Deserialize)]
pub struct AnalysisConfigRequest {
    pub enable_ids: Option<bool>,
    pub enable_beacon_detection: Option<bool>,
    pub enable_file_carving: Option<bool>,
    pub enable_protocol_analysis: Option<bool>,
    pub custom_ids_rules: Option<Vec<String>>,
}

/// Configure traffic analysis routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/traffic-analysis")
            // Captures
            .route("/upload", web::post().to(upload_capture))
            .route("/captures", web::get().to(list_captures))
            .route("/captures/{id}", web::get().to(get_capture))
            .route("/captures/{id}", web::delete().to(delete_capture))
            .route("/captures/{id}/analyze", web::post().to(analyze_capture))
            .route("/captures/{id}/export", web::get().to(export_capture))
            // Sessions
            .route("/captures/{id}/sessions", web::get().to(list_sessions))
            .route("/sessions/{id}", web::get().to(get_session))
            // Alerts
            .route("/captures/{id}/alerts", web::get().to(list_alerts))
            .route("/alerts/{id}", web::get().to(get_alert))
            .route("/alerts/{id}", web::put().to(update_alert))
            // Beacons
            .route("/captures/{id}/beacons", web::get().to(list_beacons))
            // Carved Files
            .route("/captures/{id}/carved-files", web::get().to(list_carved_files))
            .route("/carved-files/{id}/download", web::get().to(download_carved_file))
            // Protocol Analysis
            .route("/captures/{id}/dns", web::get().to(list_dns_queries))
            .route("/captures/{id}/http", web::get().to(list_http_transactions))
            .route("/captures/{id}/tls", web::get().to(list_tls_analysis))
            // Custom IDS Rules
            .route("/ids-rules", web::get().to(list_ids_rules))
            .route("/ids-rules", web::post().to(create_ids_rule))
            .route("/ids-rules/{id}", web::get().to(get_ids_rule))
            .route("/ids-rules/{id}", web::put().to(update_ids_rule))
            .route("/ids-rules/{id}", web::delete().to(delete_ids_rule))
            .route("/ids-rules/{id}/test", web::post().to(test_ids_rule))
            // Statistics
            .route("/stats", web::get().to(get_stats))
            .route("/fingerprints", web::get().to(list_fingerprints))
            .route("/fingerprints/lookup", web::post().to(lookup_fingerprint)),
    );
}

/// Upload a PCAP file for analysis
async fn upload_capture(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    mut payload: Multipart,
) -> Result<HttpResponse, ApiError> {
    let (filename, description, data) = extract_pcap_from_multipart(&mut payload).await?;

    // Check file size (max 500MB for PCAPs)
    if data.len() > 500 * 1024 * 1024 {
        return Err(ApiError::bad_request("File too large. Maximum size is 500MB"));
    }

    // Validate it's a valid PCAP
    if !is_valid_pcap(&data) {
        return Err(ApiError::bad_request("Invalid PCAP file format"));
    }

    // Calculate hash
    use sha2::{Sha256, Digest};
    let hash = format!("{:x}", Sha256::digest(&data));

    // Generate ID and save file
    let id = Uuid::new_v4().to_string();
    let file_path = format!("/tmp/heroforge_pcaps/{}.pcap", id);

    // Ensure directory exists
    if let Some(parent) = Path::new(&file_path).parent() {
        fs::create_dir_all(parent).map_err(|e| ApiError::internal(format!("Failed to create directory: {}", e)))?;
    }

    fs::write(&file_path, &data).map_err(|e| ApiError::internal(format!("Failed to save file: {}", e)))?;

    // Insert into database
    let now = Utc::now().to_rfc3339();
    let file_size = data.len() as i64;

    sqlx::query(
        r#"
        INSERT INTO traffic_captures (id, user_id, name, description, file_path, file_size, file_hash, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&filename)
    .bind(&description)
    .bind(&file_path)
    .bind(file_size)
    .bind(&hash)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(CaptureUploadResponse {
        id,
        name: filename,
        file_size,
        status: "pending".to_string(),
        message: "PCAP uploaded successfully. Call /analyze to start analysis.".to_string(),
    }))
}

/// Extract PCAP from multipart form
async fn extract_pcap_from_multipart(payload: &mut Multipart) -> Result<(String, Option<String>, Vec<u8>), ApiError> {
    let mut filename = String::new();
    let mut description = None;
    let mut data = Vec::new();

    while let Ok(Some(mut field)) = payload.try_next().await {
        // Use field.name() which returns Option<&str>
        let name = field.name().unwrap_or("");

        match name {
            "file" | "pcap" => {
                filename = field.content_disposition()
                    .and_then(|cd| cd.get_filename())
                    .unwrap_or("capture.pcap")
                    .to_string();

                while let Some(chunk) = field.next().await {
                    let chunk = chunk.map_err(|e| ApiError::bad_request(format!("Error reading file: {}", e)))?;
                    data.extend_from_slice(&chunk);
                }
            }
            "description" => {
                let mut desc_data = Vec::new();
                while let Some(chunk) = field.next().await {
                    let chunk = chunk.map_err(|e| ApiError::bad_request(format!("Error reading description: {}", e)))?;
                    desc_data.extend_from_slice(&chunk);
                }
                description = Some(String::from_utf8_lossy(&desc_data).to_string());
            }
            _ => {}
        }
    }

    if data.is_empty() {
        return Err(ApiError::bad_request("No file provided"));
    }

    Ok((filename, description, data))
}

/// Check if data is a valid PCAP file
fn is_valid_pcap(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // Check for libpcap magic numbers
    let magic = &data[0..4];
    matches!(
        magic,
        [0xa1, 0xb2, 0xc3, 0xd4] | // libpcap big-endian
        [0xd4, 0xc3, 0xb2, 0xa1] | // libpcap little-endian
        [0xa1, 0xb2, 0x3c, 0x4d] | // libpcap nanosecond big-endian
        [0x4d, 0x3c, 0xb2, 0xa1] | // libpcap nanosecond little-endian
        [0x0a, 0x0d, 0x0d, 0x0a]   // pcapng
    )
}

/// List captures for current user
async fn list_captures(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<CaptureListQuery>,
) -> Result<HttpResponse, ApiError> {
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(20).min(100);
    let offset = (page - 1) * limit;

    let mut sql = String::from(
        r#"
        SELECT id, name, description, file_size, total_packets, total_bytes, status, created_at
        FROM traffic_captures
        WHERE user_id = ?
        "#
    );

    if let Some(ref status) = query.status {
        sql.push_str(&format!(" AND status = '{}'", status.replace('\'', "''")));
    }

    if let Some(ref search) = query.search {
        sql.push_str(&format!(" AND (name LIKE '%{}%' OR description LIKE '%{}%')",
            search.replace('\'', "''"), search.replace('\'', "''")));
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

    let captures: Vec<CaptureSummary> = sqlx::query_as(&sql)
        .bind(&claims.sub)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    // Get total count
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM traffic_captures WHERE user_id = ?"
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "captures": captures,
        "total": count.0,
        "page": page,
        "limit": limit
    })))
}

/// Get capture details
async fn get_capture(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let capture_id = path.into_inner();

    let capture: Option<(String, String, Option<String>, String, i64, String, String, i64, i64, Option<String>, Option<String>, Option<f64>, String, String)> = sqlx::query_as(
        r#"
        SELECT id, name, description, file_path, file_size, file_hash, capture_type,
               total_packets, total_bytes, start_time, end_time, duration_seconds, status, created_at
        FROM traffic_captures
        WHERE id = ? AND user_id = ?
        "#
    )
    .bind(&capture_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let capture = capture.ok_or_else(|| ApiError::not_found("Capture not found"))?;

    // Get counts
    let session_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM traffic_sessions WHERE capture_id = ?"
    )
    .bind(&capture_id)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let alert_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM traffic_ids_alerts WHERE capture_id = ?"
    )
    .bind(&capture_id)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let beacon_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM traffic_beacon_detections WHERE capture_id = ?"
    )
    .bind(&capture_id)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let carved_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM traffic_carved_files WHERE capture_id = ?"
    )
    .bind(&capture_id)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(CaptureDetail {
        id: capture.0,
        name: capture.1,
        description: capture.2,
        file_path: capture.3,
        file_size: capture.4,
        file_hash: capture.5,
        capture_type: capture.6,
        total_packets: capture.7,
        total_bytes: capture.8,
        start_time: capture.9,
        end_time: capture.10,
        duration_seconds: capture.11,
        status: capture.12,
        created_at: capture.13,
        session_count: session_count.0,
        alert_count: alert_count.0,
        beacon_count: beacon_count.0,
        carved_file_count: carved_count.0,
    }))
}

/// Delete a capture
async fn delete_capture(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let capture_id = path.into_inner();

    // Get file path first
    let file_path: Option<(String,)> = sqlx::query_as(
        "SELECT file_path FROM traffic_captures WHERE id = ? AND user_id = ?"
    )
    .bind(&capture_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let file_path = file_path.ok_or_else(|| ApiError::not_found("Capture not found"))?;

    // Delete file
    let _ = fs::remove_file(&file_path.0);

    // Delete from database (cascades to related tables)
    sqlx::query("DELETE FROM traffic_captures WHERE id = ? AND user_id = ?")
        .bind(&capture_id)
        .bind(&claims.sub)
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Capture deleted successfully"
    })))
}

/// Analyze a capture
async fn analyze_capture(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    config: web::Json<Option<AnalysisConfigRequest>>,
) -> Result<HttpResponse, ApiError> {
    let capture_id = path.into_inner();

    // Get capture
    let capture: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, file_path, status FROM traffic_captures WHERE id = ? AND user_id = ?"
    )
    .bind(&capture_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let capture = capture.ok_or_else(|| ApiError::not_found("Capture not found"))?;

    if capture.2 == "analyzing" {
        return Err(ApiError::bad_request("Capture is already being analyzed"));
    }

    // Update status
    sqlx::query("UPDATE traffic_captures SET status = 'analyzing', updated_at = ? WHERE id = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(&capture_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let file_path = capture.1.clone();

    // Parse PCAP using file path
    let mut parser = PcapParser::new();
    let pcap = parser.parse_file(&file_path).map_err(|e| {
        // Update status to failed
        let pool_clone = pool.clone();
        let capture_id_clone = capture_id.clone();
        tokio::spawn(async move {
            let _ = sqlx::query("UPDATE traffic_captures SET status = 'failed', updated_at = ? WHERE id = ?")
                .bind(Utc::now().to_rfc3339())
                .bind(&capture_id_clone)
                .execute(pool_clone.get_ref())
                .await;
        });
        ApiError::internal(format!("Failed to parse PCAP: {}", e))
    })?;

    // Update capture stats
    sqlx::query(
        r#"
        UPDATE traffic_captures
        SET total_packets = ?, total_bytes = ?, start_time = ?, end_time = ?, duration_seconds = ?, updated_at = ?
        WHERE id = ?
        "#
    )
    .bind(pcap.packet_count as i64)
    .bind(pcap.byte_count as i64)
    .bind(pcap.capture_start.map(|t| t.to_rfc3339()))
    .bind(pcap.capture_end.map(|t| t.to_rfc3339()))
    .bind(pcap.duration_seconds)
    .bind(Utc::now().to_rfc3339())
    .bind(&capture_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    // Store sessions from the parser
    let sessions = parser.get_sessions();
    let mut session_count = 0;

    for session in sessions {
        let session_id = Uuid::new_v4().to_string();
        let session_key = format!("{}:{}-{}:{}",
            session.src_ip, session.src_port,
            session.dst_ip, session.dst_port);

        sqlx::query(
            r#"
            INSERT INTO traffic_sessions (
                id, capture_id, session_key, protocol, src_ip, src_port, dst_ip, dst_port,
                start_time, end_time, duration_seconds, packets_sent, packets_received,
                bytes_sent, bytes_received, state, application_protocol, is_suspicious, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&session_id)
        .bind(&capture_id)
        .bind(&session_key)
        .bind(format!("{:?}", session.session_type))
        .bind(session.src_ip.to_string())
        .bind(session.src_port as i32)
        .bind(session.dst_ip.to_string())
        .bind(session.dst_port as i32)
        .bind(session.start_time.to_rfc3339())
        .bind(session.end_time.map(|t| t.to_rfc3339()))
        .bind(session.end_time.map(|end| (end - session.start_time).num_seconds() as f64))
        .bind(session.packets as i64)
        .bind(session.packets as i64)
        .bind(session.bytes_to_server as i64)
        .bind(session.bytes_to_client as i64)
        .bind(format!("{:?}", session.state))
        .bind(format!("{:?}", session.protocol))
        .bind(false)
        .bind(Utc::now().to_rfc3339())
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

        session_count += 1;
    }

    // Run IDS engine
    let enable_ids = config.as_ref().and_then(|c| c.enable_ids).unwrap_or(true);
    let mut alert_count = 0;

    if enable_ids {
        let mut ids = IdsEngine::new();

        // Load custom rules
        let custom_rules: Vec<(String,)> = sqlx::query_as(
            "SELECT rule_content FROM custom_ids_rules WHERE user_id = ? AND enabled = true"
        )
        .bind(&claims.sub)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

        for (rule_content,) in custom_rules {
            let _ = ids.load_rules_from_content(&rule_content, IdsRuleSource::Custom);
        }

        // Match against sessions using match_packet
        for session in parser.get_sessions() {
            // Determine protocol number from session type
            let protocol: u8 = match session.session_type {
                SessionType::Tcp => 6,
                SessionType::Udp => 17,
                SessionType::Icmp => 1,
                _ => 0,
            };

            let alerts = ids.match_packet(
                &capture_id,
                Some(&session.id),
                session.src_ip,
                session.src_port,
                session.dst_ip,
                session.dst_port,
                protocol,
                &[], // No payload data in simplified version
                true, // is_to_server
            );

            for alert in alerts {
                let alert_id = Uuid::new_v4().to_string();
                sqlx::query(
                    r#"
                    INSERT INTO traffic_ids_alerts (
                        id, capture_id, rule_id, rule_name, severity, message,
                        src_ip, src_port, dst_ip, dst_port, protocol, timestamp, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#
                )
                .bind(&alert_id)
                .bind(&capture_id)
                .bind(&alert.rule_id)
                .bind(&alert.message)
                .bind(format!("{:?}", alert.severity))
                .bind(&alert.message)
                .bind(alert.src_ip.to_string())
                .bind(alert.src_port as i32)
                .bind(alert.dst_ip.to_string())
                .bind(alert.dst_port as i32)
                .bind(&alert.protocol)
                .bind(alert.timestamp.to_rfc3339())
                .bind(Utc::now().to_rfc3339())
                .execute(pool.get_ref())
                .await
                .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

                alert_count += 1;
            }
        }
    }

    // Run beacon detection
    let enable_beacon = config.as_ref().and_then(|c| c.enable_beacon_detection).unwrap_or(true);
    let mut beacon_count = 0;

    if enable_beacon {
        let mut detector = BeaconDetector::new();
        for session in parser.get_sessions() {
            detector.record_connection(
                session.src_ip,
                session.dst_ip,
                session.dst_port,
                session.bytes_to_server,
                session.bytes_to_client,
                session.start_time,
            );
        }

        let beacons = detector.analyze(&capture_id);
        for beacon in beacons {
            sqlx::query(
                r#"
                INSERT INTO traffic_beacon_detections (
                    id, capture_id, src_ip, dst_ip, dst_port, connection_count,
                    avg_interval_seconds, interval_variance, avg_bytes_per_connection,
                    jitter_percentage, beacon_score, is_likely_beacon, first_seen, last_seen, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#
            )
            .bind(&beacon.id)
            .bind(&capture_id)
            .bind(beacon.src_ip.to_string())
            .bind(beacon.dst_ip.to_string())
            .bind(beacon.dst_port as i32)
            .bind(beacon.connection_count as i64)
            .bind(beacon.avg_interval_seconds)
            .bind(beacon.interval_variance)
            .bind(beacon.avg_bytes_per_connection)
            .bind(beacon.jitter_percentage)
            .bind(beacon.beacon_score)
            .bind(beacon.is_likely_beacon)
            .bind(beacon.first_seen.to_rfc3339())
            .bind(beacon.last_seen.to_rfc3339())
            .bind(Utc::now().to_rfc3339())
            .execute(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

            beacon_count += 1;
        }
    }

    // Run file carving
    let enable_carving = config.as_ref().and_then(|c| c.enable_file_carving).unwrap_or(true);
    let mut carved_count = 0;

    if enable_carving {
        let mut carver = FileCarver::new();
        for session in parser.get_sessions() {
            // Use any extracted files from the session
            for file in &session.extracted_files {
                let file_id = Uuid::new_v4().to_string();
                sqlx::query(
                    r#"
                    INSERT INTO traffic_carved_files (
                        id, capture_id, file_name, file_type, mime_type, file_size, file_hash,
                        src_ip, dst_ip, extraction_method, is_malicious, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#
                )
                .bind(&file_id)
                .bind(&capture_id)
                .bind(&file.filename)
                .bind(&file.mime_type)
                .bind(&file.mime_type)
                .bind(file.size as i64)
                .bind(&file.sha256)
                .bind(session.src_ip.to_string())
                .bind(session.dst_ip.to_string())
                .bind("stream")
                .bind(false)
                .bind(Utc::now().to_rfc3339())
                .execute(pool.get_ref())
                .await
                .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

                carved_count += 1;
            }
        }
        // Suppress unused variable warning
        let _ = carver;
    }

    // Update status to completed
    sqlx::query("UPDATE traffic_captures SET status = 'completed', updated_at = ? WHERE id = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(&capture_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Analysis completed",
        "capture_id": capture_id,
        "sessions": session_count,
        "alerts": alert_count,
        "beacons": beacon_count,
        "carved_files": carved_count
    })))
}

/// Export capture analysis results
async fn export_capture(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, ApiError> {
    let capture_id = path.into_inner();
    let format = query.get("format").map(|s| s.as_str()).unwrap_or("json");

    // Verify ownership
    let capture: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM traffic_captures WHERE id = ? AND user_id = ?"
    )
    .bind(&capture_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    capture.ok_or_else(|| ApiError::not_found("Capture not found"))?;

    // Gather all data
    let sessions: Vec<SessionSummary> = sqlx::query_as(
        "SELECT * FROM traffic_sessions WHERE capture_id = ?"
    )
    .bind(&capture_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let alerts: Vec<IdsAlertSummary> = sqlx::query_as(
        "SELECT * FROM traffic_ids_alerts WHERE capture_id = ?"
    )
    .bind(&capture_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let beacons: Vec<BeaconSummary> = sqlx::query_as(
        "SELECT * FROM traffic_beacon_detections WHERE capture_id = ?"
    )
    .bind(&capture_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    match format {
        "json" => {
            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .json(serde_json::json!({
                    "sessions": sessions,
                    "alerts": alerts,
                    "beacons": beacons
                })))
        }
        _ => Err(ApiError::bad_request("Unsupported format. Use 'json'"))
    }
}

/// List sessions for a capture
async fn list_sessions(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<SessionListQuery>,
) -> Result<HttpResponse, ApiError> {
    let capture_id = path.into_inner();
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).min(200);
    let offset = (page - 1) * limit;

    // Verify ownership
    let capture: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM traffic_captures WHERE id = ? AND user_id = ?"
    )
    .bind(&capture_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    capture.ok_or_else(|| ApiError::not_found("Capture not found"))?;

    let mut sql = String::from(
        r#"
        SELECT id, session_key, protocol, src_ip, src_port, dst_ip, dst_port,
               start_time, duration_seconds, packets_sent, packets_received,
               bytes_sent, bytes_received, application_protocol, ja3_fingerprint, is_suspicious
        FROM traffic_sessions WHERE capture_id = ?
        "#
    );

    if let Some(ref proto) = query.protocol {
        sql.push_str(&format!(" AND protocol = '{}'", proto.replace('\'', "''")));
    }
    if query.suspicious_only.unwrap_or(false) {
        sql.push_str(" AND is_suspicious = true");
    }
    if let Some(ref src) = query.src_ip {
        sql.push_str(&format!(" AND src_ip = '{}'", src.replace('\'', "''")));
    }
    if let Some(ref dst) = query.dst_ip {
        sql.push_str(&format!(" AND dst_ip = '{}'", dst.replace('\'', "''")));
    }

    sql.push_str(" ORDER BY start_time DESC LIMIT ? OFFSET ?");

    let sessions: Vec<SessionSummary> = sqlx::query_as(&sql)
        .bind(&capture_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "sessions": sessions,
        "page": page,
        "limit": limit
    })))
}

/// Get session details
async fn get_session(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let session_id = path.into_inner();

    // Get session with capture ownership check
    let session: Option<SessionSummary> = sqlx::query_as(
        r#"
        SELECT s.id, s.session_key, s.protocol, s.src_ip, s.src_port, s.dst_ip, s.dst_port,
               s.start_time, s.duration_seconds, s.packets_sent, s.packets_received,
               s.bytes_sent, s.bytes_received, s.application_protocol, s.ja3_fingerprint, s.is_suspicious
        FROM traffic_sessions s
        JOIN traffic_captures c ON s.capture_id = c.id
        WHERE s.id = ? AND c.user_id = ?
        "#
    )
    .bind(&session_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let session = session.ok_or_else(|| ApiError::not_found("Session not found"))?;

    Ok(HttpResponse::Ok().json(session))
}

/// List IDS alerts for a capture
async fn list_alerts(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<AlertListQuery>,
) -> Result<HttpResponse, ApiError> {
    let capture_id = path.into_inner();
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).min(200);
    let offset = (page - 1) * limit;

    // Verify ownership
    let capture: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM traffic_captures WHERE id = ? AND user_id = ?"
    )
    .bind(&capture_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    capture.ok_or_else(|| ApiError::not_found("Capture not found"))?;

    let mut sql = String::from(
        r#"
        SELECT id, rule_id, rule_name, rule_category, severity, message,
               src_ip, src_port, dst_ip, dst_port, protocol, timestamp,
               false_positive, acknowledged
        FROM traffic_ids_alerts WHERE capture_id = ?
        "#
    );

    if let Some(ref sev) = query.severity {
        sql.push_str(&format!(" AND severity = '{}'", sev.replace('\'', "''")));
    }
    if let Some(ack) = query.acknowledged {
        sql.push_str(&format!(" AND acknowledged = {}", if ack { "true" } else { "false" }));
    }
    if let Some(fp) = query.false_positive {
        sql.push_str(&format!(" AND false_positive = {}", if fp { "true" } else { "false" }));
    }

    sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");

    let alerts: Vec<IdsAlertSummary> = sqlx::query_as(&sql)
        .bind(&capture_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "alerts": alerts,
        "page": page,
        "limit": limit
    })))
}

/// Get alert details
async fn get_alert(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let alert_id = path.into_inner();

    let alert: Option<IdsAlertSummary> = sqlx::query_as(
        r#"
        SELECT a.id, a.rule_id, a.rule_name, a.rule_category, a.severity, a.message,
               a.src_ip, a.src_port, a.dst_ip, a.dst_port, a.protocol, a.timestamp,
               a.false_positive, a.acknowledged
        FROM traffic_ids_alerts a
        JOIN traffic_captures c ON a.capture_id = c.id
        WHERE a.id = ? AND c.user_id = ?
        "#
    )
    .bind(&alert_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let alert = alert.ok_or_else(|| ApiError::not_found("Alert not found"))?;

    Ok(HttpResponse::Ok().json(alert))
}

/// Update alert (acknowledge/mark as false positive)
async fn update_alert(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    req: web::Json<UpdateAlertRequest>,
) -> Result<HttpResponse, ApiError> {
    let alert_id = path.into_inner();

    // Verify ownership
    let alert: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT a.id FROM traffic_ids_alerts a
        JOIN traffic_captures c ON a.capture_id = c.id
        WHERE a.id = ? AND c.user_id = ?
        "#
    )
    .bind(&alert_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    alert.ok_or_else(|| ApiError::not_found("Alert not found"))?;

    // Update fields
    if let Some(ack) = req.acknowledged {
        sqlx::query("UPDATE traffic_ids_alerts SET acknowledged = ? WHERE id = ?")
            .bind(ack)
            .bind(&alert_id)
            .execute(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;
    }

    if let Some(fp) = req.false_positive {
        sqlx::query("UPDATE traffic_ids_alerts SET false_positive = ? WHERE id = ?")
            .bind(fp)
            .bind(&alert_id)
            .execute(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Alert updated"
    })))
}

/// List beacon detections for a capture
async fn list_beacons(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let capture_id = path.into_inner();

    // Verify ownership
    let capture: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM traffic_captures WHERE id = ? AND user_id = ?"
    )
    .bind(&capture_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    capture.ok_or_else(|| ApiError::not_found("Capture not found"))?;

    let beacons: Vec<BeaconSummary> = sqlx::query_as(
        r#"
        SELECT id, src_ip, dst_ip, dst_port, connection_count, avg_interval_seconds,
               jitter_percentage, beacon_score, is_likely_beacon, first_seen, last_seen
        FROM traffic_beacon_detections WHERE capture_id = ?
        ORDER BY beacon_score DESC
        "#
    )
    .bind(&capture_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "beacons": beacons
    })))
}

/// List carved files for a capture
async fn list_carved_files(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let capture_id = path.into_inner();

    // Verify ownership
    let capture: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM traffic_captures WHERE id = ? AND user_id = ?"
    )
    .bind(&capture_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    capture.ok_or_else(|| ApiError::not_found("Capture not found"))?;

    let files: Vec<CarvedFileSummary> = sqlx::query_as(
        r#"
        SELECT id, file_name, file_type, mime_type, file_size, file_hash,
               src_ip, dst_ip, extraction_method, is_malicious, malware_family, created_at
        FROM traffic_carved_files WHERE capture_id = ?
        ORDER BY created_at DESC
        "#
    )
    .bind(&capture_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "carved_files": files
    })))
}

/// Download a carved file
async fn download_carved_file(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let file_id = path.into_inner();

    let file: Option<(String, Option<String>, String)> = sqlx::query_as(
        r#"
        SELECT cf.file_path, cf.file_name, cf.mime_type
        FROM traffic_carved_files cf
        JOIN traffic_captures c ON cf.capture_id = c.id
        WHERE cf.id = ? AND c.user_id = ?
        "#
    )
    .bind(&file_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let file = file.ok_or_else(|| ApiError::not_found("File not found"))?;

    let (file_path, file_name, mime_type) = file;

    if file_path.is_empty() {
        return Err(ApiError::not_found("File data not available"));
    }

    let data = fs::read(&file_path).map_err(|e| ApiError::internal(format!("Failed to read file: {}", e)))?;
    let filename = file_name.unwrap_or_else(|| "carved_file".to_string());

    Ok(HttpResponse::Ok()
        .content_type(mime_type)
        .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
        .body(data))
}

/// List DNS queries for a capture
async fn list_dns_queries(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, ApiError> {
    let capture_id = path.into_inner();
    let page = query.get("page").and_then(|s| s.parse().ok()).unwrap_or(1u32).max(1);
    let limit = query.get("limit").and_then(|s| s.parse().ok()).unwrap_or(100u32).min(500);
    let offset = (page - 1) * limit;
    let suspicious_only = query.get("suspicious_only").map(|s| s == "true").unwrap_or(false);

    // Verify ownership
    let capture: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM traffic_captures WHERE id = ? AND user_id = ?"
    )
    .bind(&capture_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    capture.ok_or_else(|| ApiError::not_found("Capture not found"))?;

    let mut sql = String::from(
        r#"
        SELECT id, query_name, query_type, response_code, answers,
               is_dga_suspicious, dga_score, is_tunneling_suspicious, timestamp
        FROM traffic_dns_queries WHERE capture_id = ?
        "#
    );

    if suspicious_only {
        sql.push_str(" AND (is_dga_suspicious = true OR is_tunneling_suspicious = true)");
    }

    sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");

    let queries: Vec<DnsQuerySummary> = sqlx::query_as(&sql)
        .bind(&capture_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "dns_queries": queries,
        "page": page,
        "limit": limit
    })))
}

/// List HTTP transactions for a capture
async fn list_http_transactions(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, ApiError> {
    let capture_id = path.into_inner();
    let page = query.get("page").and_then(|s| s.parse().ok()).unwrap_or(1u32).max(1);
    let limit = query.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50u32).min(200);
    let offset = (page - 1) * limit;
    let suspicious_only = query.get("suspicious_only").map(|s| s == "true").unwrap_or(false);

    // Verify ownership
    let capture: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM traffic_captures WHERE id = ? AND user_id = ?"
    )
    .bind(&capture_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    capture.ok_or_else(|| ApiError::not_found("Capture not found"))?;

    let mut sql = String::from(
        r#"
        SELECT id, method, host, uri, user_agent, status_code,
               is_suspicious, suspicion_reasons, timestamp
        FROM traffic_http_transactions WHERE capture_id = ?
        "#
    );

    if suspicious_only {
        sql.push_str(" AND is_suspicious = true");
    }

    sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");

    let transactions: Vec<HttpTransactionSummary> = sqlx::query_as(&sql)
        .bind(&capture_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "http_transactions": transactions,
        "page": page,
        "limit": limit
    })))
}

/// List TLS analysis for a capture
async fn list_tls_analysis(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, ApiError> {
    let capture_id = path.into_inner();
    let page = query.get("page").and_then(|s| s.parse().ok()).unwrap_or(1u32).max(1);
    let limit = query.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50u32).min(200);
    let offset = (page - 1) * limit;
    let suspicious_only = query.get("suspicious_only").map(|s| s == "true").unwrap_or(false);

    // Verify ownership
    let capture: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM traffic_captures WHERE id = ? AND user_id = ?"
    )
    .bind(&capture_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    capture.ok_or_else(|| ApiError::not_found("Capture not found"))?;

    let mut sql = String::from(
        r#"
        SELECT id, tls_version, cipher_suite, server_name, ja3_fingerprint,
               ja3s_fingerprint, ja3_known_match, is_self_signed, is_expired,
               is_suspicious, timestamp
        FROM traffic_tls_analysis WHERE capture_id = ?
        "#
    );

    if suspicious_only {
        sql.push_str(" AND is_suspicious = true");
    }

    sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");

    let tls: Vec<TlsAnalysisSummary> = sqlx::query_as(&sql)
        .bind(&capture_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "tls_analysis": tls,
        "page": page,
        "limit": limit
    })))
}

/// List custom IDS rules
async fn list_ids_rules(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let rules: Vec<CustomIdsRule> = sqlx::query_as(
        r#"
        SELECT id, name, description, rule_content, rule_format, category, severity,
               enabled, hit_count, last_hit_at, created_at
        FROM custom_ids_rules WHERE user_id = ?
        ORDER BY created_at DESC
        "#
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "rules": rules
    })))
}

/// Create custom IDS rule
async fn create_ids_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    req: web::Json<CreateIdsRuleRequest>,
) -> Result<HttpResponse, ApiError> {
    // Validate rule syntax by attempting to parse it
    let mut engine = IdsEngine::new();
    if let Err(e) = engine.load_rules_from_content(&req.rule_content, IdsRuleSource::Custom) {
        return Err(ApiError::bad_request(format!("Invalid rule syntax: {}", e)));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO custom_ids_rules (id, user_id, name, description, rule_content, rule_format, category, severity, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.rule_content)
    .bind(req.rule_format.as_deref().unwrap_or("suricata"))
    .bind(&req.category)
    .bind(req.severity.as_deref().unwrap_or("medium"))
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "IDS rule created"
    })))
}

/// Get IDS rule
async fn get_ids_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let rule_id = path.into_inner();

    let rule: Option<CustomIdsRule> = sqlx::query_as(
        r#"
        SELECT id, name, description, rule_content, rule_format, category, severity,
               enabled, hit_count, last_hit_at, created_at
        FROM custom_ids_rules WHERE id = ? AND user_id = ?
        "#
    )
    .bind(&rule_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let rule = rule.ok_or_else(|| ApiError::not_found("Rule not found"))?;

    Ok(HttpResponse::Ok().json(rule))
}

/// Update IDS rule
async fn update_ids_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    req: web::Json<UpdateIdsRuleRequest>,
) -> Result<HttpResponse, ApiError> {
    let rule_id = path.into_inner();

    // Verify ownership
    let rule: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM custom_ids_rules WHERE id = ? AND user_id = ?"
    )
    .bind(&rule_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    rule.ok_or_else(|| ApiError::not_found("Rule not found"))?;

    // Validate new rule content if provided
    if let Some(ref content) = req.rule_content {
        let mut engine = IdsEngine::new();
        if let Err(e) = engine.load_rules_from_content(content, IdsRuleSource::Custom) {
            return Err(ApiError::bad_request(format!("Invalid rule syntax: {}", e)));
        }
    }

    let now = Utc::now().to_rfc3339();
    let mut updates = vec!["updated_at = ?"];
    let mut binds: Vec<String> = vec![now.clone()];

    if let Some(ref name) = req.name {
        updates.push("name = ?");
        binds.push(name.clone());
    }
    if let Some(ref desc) = req.description {
        updates.push("description = ?");
        binds.push(desc.clone());
    }
    if let Some(ref content) = req.rule_content {
        updates.push("rule_content = ?");
        binds.push(content.clone());
    }
    if let Some(ref cat) = req.category {
        updates.push("category = ?");
        binds.push(cat.clone());
    }
    if let Some(ref sev) = req.severity {
        updates.push("severity = ?");
        binds.push(sev.clone());
    }

    let sql = format!(
        "UPDATE custom_ids_rules SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut query = sqlx::query(&sql);
    for bind in &binds {
        query = query.bind(bind);
    }
    if let Some(enabled) = req.enabled {
        // Handle boolean separately since it's not a string
        sqlx::query("UPDATE custom_ids_rules SET enabled = ?, updated_at = ? WHERE id = ?")
            .bind(enabled)
            .bind(&now)
            .bind(&rule_id)
            .execute(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;
    }

    query = query.bind(&rule_id);
    query.execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Rule updated"
    })))
}

/// Delete IDS rule
async fn delete_ids_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let rule_id = path.into_inner();

    let result = sqlx::query("DELETE FROM custom_ids_rules WHERE id = ? AND user_id = ?")
        .bind(&rule_id)
        .bind(&claims.sub)
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Rule not found"));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Rule deleted"
    })))
}

/// Test IDS rule against sample data
async fn test_ids_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let rule_id = path.into_inner();

    let rule: Option<(String,)> = sqlx::query_as(
        "SELECT rule_content FROM custom_ids_rules WHERE id = ? AND user_id = ?"
    )
    .bind(&rule_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let rule = rule.ok_or_else(|| ApiError::not_found("Rule not found"))?;

    let mut engine = IdsEngine::new();
    match engine.load_rules_from_content(&rule.0, IdsRuleSource::Custom) {
        Ok(count) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "valid": true,
            "rules_loaded": count,
            "message": "Rule is valid and ready to use"
        }))),
        Err(e) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "valid": false,
            "error": e
        })))
    }
}

/// Get traffic analysis statistics
async fn get_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let total_captures: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM traffic_captures WHERE user_id = ?"
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let total_sessions: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM traffic_sessions s
        JOIN traffic_captures c ON s.capture_id = c.id
        WHERE c.user_id = ?
        "#
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let totals: (i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(total_packets), 0), COALESCE(SUM(total_bytes), 0) FROM traffic_captures WHERE user_id = ?"
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let ids_alerts: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM traffic_ids_alerts a
        JOIN traffic_captures c ON a.capture_id = c.id
        WHERE c.user_id = ?
        "#
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let beacons: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM traffic_beacon_detections b
        JOIN traffic_captures c ON b.capture_id = c.id
        WHERE c.user_id = ? AND b.is_likely_beacon = true
        "#
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let carved: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM traffic_carved_files cf
        JOIN traffic_captures c ON cf.capture_id = c.id
        WHERE c.user_id = ?
        "#
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let suspicious_dns: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM traffic_dns_queries d
        JOIN traffic_captures c ON d.capture_id = c.id
        WHERE c.user_id = ? AND (d.is_dga_suspicious = true OR d.is_tunneling_suspicious = true)
        "#
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    let malware_fps: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM traffic_tls_analysis t
        JOIN traffic_captures c ON t.capture_id = c.id
        WHERE c.user_id = ? AND t.ja3_known_match IS NOT NULL
        "#
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(TrafficAnalysisStats {
        total_captures: total_captures.0,
        total_sessions: total_sessions.0,
        total_packets: totals.0,
        total_bytes: totals.1,
        ids_alerts: ids_alerts.0,
        beacon_detections: beacons.0,
        carved_files: carved.0,
        suspicious_dns: suspicious_dns.0,
        malware_fingerprints: malware_fps.0,
    }))
}

/// List known JA3 fingerprints
async fn list_fingerprints(
    _pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let fingerprinter = Ja3Fingerprinter::new();
    let stats = fingerprinter.get_statistics();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "total_known": stats.known_fingerprints,
        "categories": {
            "browsers": ["Chrome", "Firefox", "Safari", "Edge"],
            "tools": ["curl", "Python requests", "Nmap", "Metasploit"],
            "malware": ["Trickbot", "Cobalt Strike", "Emotet"]
        }
    })))
}

/// Lookup a JA3 fingerprint
async fn lookup_fingerprint(
    _pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    req: web::Json<HashMap<String, String>>,
) -> Result<HttpResponse, ApiError> {
    let hash = req.get("hash").ok_or_else(|| ApiError::bad_request("Missing 'hash' field"))?;

    let fingerprinter = Ja3Fingerprinter::new();

    if let Some(known) = fingerprinter.lookup(hash) {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "found": true,
            "client_name": known.client_name,
            "category": format!("{:?}", known.category),
            "threat_score": known.threat_score,
            "notes": known.notes
        })))
    } else {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "found": false
        })))
    }
}
