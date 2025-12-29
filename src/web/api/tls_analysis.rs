#![allow(dead_code)]
//! TLS Analysis API Endpoints
//!
//! Provides REST API access to TLS fingerprinting and threat detection:
//! - JA3/JA3S fingerprint calculation
//! - Known fingerprint lookup
//! - TLS handshake analysis
//! - Threat detection
//! - Custom fingerprint management

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::db::models;
use crate::scanner::tls_analysis::{
    self, detection::TlsThreatLevel,
    TlsAnalysisResult,
};
use crate::web::auth::Claims;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to analyze a TLS handshake
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AnalyzeTlsRequest {
    /// Base64-encoded TLS ClientHello bytes
    pub client_hello: Option<String>,
    /// Base64-encoded TLS ServerHello bytes
    pub server_hello: Option<String>,
    /// Source IP address (for logging)
    pub src_ip: Option<String>,
    /// Destination IP address (for logging)
    pub dst_ip: Option<String>,
    /// Source port (for logging)
    pub src_port: Option<u16>,
    /// Destination port (for logging)
    pub dst_port: Option<u16>,
    /// CRM customer ID
    pub customer_id: Option<String>,
    /// CRM engagement ID
    pub engagement_id: Option<String>,
}

/// Request to calculate JA3 from ClientHello
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CalculateJa3Request {
    /// Base64-encoded TLS ClientHello bytes
    pub client_hello: String,
}

/// Request to calculate JA3S from ServerHello
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CalculateJa3sRequest {
    /// Base64-encoded TLS ServerHello bytes
    pub server_hello: String,
}

/// Request to lookup a fingerprint hash
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct LookupFingerprintRequest {
    /// JA3 or JA3S hash to lookup
    pub hash: String,
    /// Type of fingerprint (ja3 or ja3s)
    pub fingerprint_type: String,
}

/// Request to add a custom fingerprint
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AddFingerprintRequest {
    /// The JA3 or JA3S hash
    pub hash: String,
    /// Type: "ja3" or "ja3s"
    pub fingerprint_type: String,
    /// Human-readable description
    pub description: String,
    /// Category: "malware", "legitimate", "bot", "tor", "suspicious", "c2_server"
    pub category: String,
    /// Whether this is known malicious
    pub is_malicious: bool,
    /// Malware family name if applicable
    pub malware_family: Option<String>,
    /// Confidence level (0-100)
    pub confidence: Option<u8>,
    /// Additional notes
    pub notes: Option<String>,
}

/// Query parameters for fingerprints list
#[derive(Debug, Deserialize)]
pub struct FingerprintsQuery {
    /// Filter by category
    pub category: Option<String>,
    /// Filter by malicious status
    pub is_malicious: Option<bool>,
    /// Limit results
    pub limit: Option<usize>,
}

/// Query parameters for threats list
#[derive(Debug, Deserialize)]
pub struct ThreatsQuery {
    /// Filter by minimum threat level
    pub min_level: Option<String>,
    /// Limit results
    pub limit: Option<i32>,
    /// Filter by time range (hours)
    pub hours: Option<i32>,
}

/// Response for TLS analysis
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TlsAnalysisResponse {
    /// JA3 fingerprint if client hello was analyzed
    pub ja3: Option<Ja3FingerprintResponse>,
    /// JA3S fingerprint if server hello was analyzed
    pub ja3s: Option<Ja3sFingerprintResponse>,
    /// Detected threats
    pub threats: Vec<ThreatResponse>,
    /// Overall threat level
    pub threat_level: String,
    /// Whether any known fingerprints matched
    pub has_known_matches: bool,
    /// Analysis timestamp
    pub analyzed_at: String,
}

/// JA3 fingerprint response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Ja3FingerprintResponse {
    pub hash: String,
    pub raw_string: String,
    pub tls_version: Option<String>,
    pub cipher_suite_count: usize,
    pub extension_count: usize,
    pub potential_client: Option<String>,
    pub has_grease: bool,
}

/// JA3S fingerprint response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Ja3sFingerprintResponse {
    pub hash: String,
    pub raw_string: String,
    pub tls_version: Option<String>,
    pub selected_cipher: Option<String>,
    pub extension_count: usize,
    pub potential_server: Option<String>,
}

/// Threat response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ThreatResponse {
    pub threat_type: String,
    pub level: String,
    pub description: String,
    pub details: Option<String>,
    pub related_hash: Option<String>,
    pub malware_family: Option<String>,
    pub confidence: u8,
    pub recommendation: String,
    pub mitre_techniques: Vec<String>,
}

/// Known fingerprint response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct KnownFingerprintResponse {
    pub hash: String,
    pub description: String,
    pub category: String,
    pub is_malicious: bool,
    pub malware_family: Option<String>,
    pub confidence: u8,
    pub notes: Option<String>,
}

/// Fingerprint lookup response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FingerprintLookupResponse {
    pub hash: String,
    pub found: bool,
    pub matches: Vec<KnownFingerprintResponse>,
}

/// Fingerprints list response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FingerprintsListResponse {
    pub ja3_count: usize,
    pub ja3s_count: usize,
    pub fingerprints: Vec<KnownFingerprintResponse>,
}

/// TLS threats list response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TlsThreatsListResponse {
    pub total: usize,
    pub threats: Vec<TlsThreatRecord>,
}

/// TLS threat record from database
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TlsThreatRecord {
    pub id: String,
    pub ja3_hash: Option<String>,
    pub ja3s_hash: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub threat_level: String,
    pub threats_json: Option<String>,
    pub detected_at: String,
}

// ============================================================================
// API Handlers
// ============================================================================

/// POST /api/detection/tls/analyze
/// Analyze TLS handshake data for fingerprinting and threat detection
pub async fn analyze_tls(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<AnalyzeTlsRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    debug!("TLS analysis request from user {}", user_id);

    // Decode and parse handshake data
    let client_hello_data = if let Some(ref b64) = body.client_hello {
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64) {
            Ok(data) => Some(data),
            Err(e) => {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("Invalid base64 for client_hello: {}", e)
                })));
            }
        }
    } else {
        None
    };

    let server_hello_data = if let Some(ref b64) = body.server_hello {
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64) {
            Ok(data) => Some(data),
            Err(e) => {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("Invalid base64 for server_hello: {}", e)
                })));
            }
        }
    } else {
        None
    };

    if client_hello_data.is_none() && server_hello_data.is_none() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one of client_hello or server_hello must be provided"
        })));
    }

    // Perform analysis
    let result = match tls_analysis::analyze_tls_handshake(
        client_hello_data.as_deref(),
        server_hello_data.as_deref(),
    ) {
        Ok(r) => r,
        Err(e) => {
            error!("TLS analysis failed: {}", e);
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Failed to parse TLS data: {}", e)
            })));
        }
    };

    // Save analysis result to database if threats were detected
    if result.threat_level != TlsThreatLevel::None {
        if let Err(e) = save_tls_analysis_result(
            pool.get_ref(),
            &result,
            body.src_ip.as_deref(),
            body.dst_ip.as_deref(),
            body.customer_id.as_deref(),
            body.engagement_id.as_deref(),
        )
        .await
        {
            error!("Failed to save TLS analysis result: {}", e);
        }
    }

    // Build response
    let response = TlsAnalysisResponse {
        ja3: result.ja3.map(|j| Ja3FingerprintResponse {
            hash: j.hash,
            raw_string: j.raw_string,
            tls_version: j.client_info.tls_version,
            cipher_suite_count: j.client_info.cipher_suite_count,
            extension_count: j.client_info.extension_count,
            potential_client: j.client_info.potential_client,
            has_grease: j.client_info.has_grease,
        }),
        ja3s: result.ja3s.map(|j| Ja3sFingerprintResponse {
            hash: j.hash,
            raw_string: j.raw_string,
            tls_version: j.server_info.tls_version,
            selected_cipher: j.server_info.selected_cipher,
            extension_count: j.server_info.extension_count,
            potential_server: j.server_info.potential_server,
        }),
        threats: result
            .threats
            .iter()
            .map(|t| ThreatResponse {
                threat_type: t.threat_type.to_string(),
                level: t.level.to_string(),
                description: t.description.clone(),
                details: t.details.clone(),
                related_hash: t.related_hash.clone(),
                malware_family: t.malware_family.clone(),
                confidence: t.confidence,
                recommendation: t.recommendation.clone(),
                mitre_techniques: t.mitre_techniques.clone(),
            })
            .collect(),
        threat_level: result.threat_level.to_string(),
        has_known_matches: !result.fingerprint_matches.is_empty(),
        analyzed_at: result.analyzed_at.to_rfc3339(),
    };

    // Log audit
    let audit_log = models::AuditLog {
        id: Uuid::new_v4().to_string(),
        user_id: user_id.clone(),
        action: "tls_analysis".to_string(),
        target_type: Some("tls_handshake".to_string()),
        target_id: None,
        details: Some(format!(
            "Analyzed TLS handshake, threat_level: {}",
            response.threat_level
        )),
        ip_address: body.src_ip.clone(),
        user_agent: None,
        created_at: Utc::now(),
    };
    if let Err(e) = crate::db::create_audit_log(pool.get_ref(), &audit_log).await {
        error!("Failed to create audit log: {}", e);
    }

    Ok(HttpResponse::Ok().json(response))
}

/// POST /api/detection/tls/ja3
/// Calculate JA3 fingerprint from ClientHello data
pub async fn calculate_ja3(
    _claims: web::ReqData<Claims>,
    body: web::Json<CalculateJa3Request>,
) -> Result<HttpResponse> {
    // Decode base64
    let data = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body.client_hello) {
        Ok(d) => d,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid base64: {}", e)
            })));
        }
    };

    // Parse ClientHello
    let client_hello = match tls_analysis::parser::parse_client_hello(&data) {
        Ok(ch) => ch,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Failed to parse ClientHello: {}", e)
            })));
        }
    };

    // Calculate JA3
    let ja3 = tls_analysis::calculate_ja3(&client_hello);

    let response = Ja3FingerprintResponse {
        hash: ja3.hash,
        raw_string: ja3.raw_string,
        tls_version: ja3.client_info.tls_version,
        cipher_suite_count: ja3.client_info.cipher_suite_count,
        extension_count: ja3.client_info.extension_count,
        potential_client: ja3.client_info.potential_client,
        has_grease: ja3.client_info.has_grease,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// POST /api/detection/tls/ja3s
/// Calculate JA3S fingerprint from ServerHello data
pub async fn calculate_ja3s(
    _claims: web::ReqData<Claims>,
    body: web::Json<CalculateJa3sRequest>,
) -> Result<HttpResponse> {
    // Decode base64
    let data = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body.server_hello) {
        Ok(d) => d,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid base64: {}", e)
            })));
        }
    };

    // Parse ServerHello
    let server_hello = match tls_analysis::parser::parse_server_hello(&data) {
        Ok(sh) => sh,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Failed to parse ServerHello: {}", e)
            })));
        }
    };

    // Calculate JA3S
    let ja3s = tls_analysis::calculate_ja3s(&server_hello);

    let response = Ja3sFingerprintResponse {
        hash: ja3s.hash,
        raw_string: ja3s.raw_string,
        tls_version: ja3s.server_info.tls_version,
        selected_cipher: ja3s.server_info.selected_cipher,
        extension_count: ja3s.server_info.extension_count,
        potential_server: ja3s.server_info.potential_server,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// POST /api/detection/tls/lookup
/// Lookup a JA3/JA3S hash in the known fingerprints database
pub async fn lookup_fingerprint(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<LookupFingerprintRequest>,
) -> Result<HttpResponse> {
    let hash = body.hash.to_lowercase();

    // Lookup in built-in database
    let matches = match body.fingerprint_type.to_lowercase().as_str() {
        "ja3" => tls_analysis::fingerprints::lookup_ja3(&hash),
        "ja3s" => tls_analysis::fingerprints::lookup_ja3s(&hash),
        _ => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "fingerprint_type must be 'ja3' or 'ja3s'"
            })));
        }
    };

    // Also check custom fingerprints in database
    let custom_matches = lookup_custom_fingerprint(pool.get_ref(), &hash, &body.fingerprint_type)
        .await
        .unwrap_or_default();

    let mut all_matches: Vec<KnownFingerprintResponse> = matches
        .iter()
        .map(|m| KnownFingerprintResponse {
            hash: m.fingerprint.hash.clone(),
            description: m.fingerprint.description.clone(),
            category: format!("{:?}", m.fingerprint.category),
            is_malicious: m.fingerprint.is_malicious,
            malware_family: m.fingerprint.malware_family.clone(),
            confidence: m.fingerprint.confidence,
            notes: m.fingerprint.notes.clone(),
        })
        .collect();

    all_matches.extend(custom_matches);

    let response = FingerprintLookupResponse {
        hash: hash.clone(),
        found: !all_matches.is_empty(),
        matches: all_matches,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// GET /api/detection/tls/fingerprints
/// List known TLS fingerprints
pub async fn list_fingerprints(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<FingerprintsQuery>,
) -> Result<HttpResponse> {
    let (ja3_count, ja3s_count) = tls_analysis::fingerprints::fingerprint_count();

    // Get built-in fingerprints
    let mut fingerprints: Vec<KnownFingerprintResponse> = Vec::new();

    // Filter and collect JA3 fingerprints
    for fp in tls_analysis::fingerprints::get_all_ja3_fingerprints() {
        if let Some(ref cat) = query.category {
            let cat_match = format!("{:?}", fp.category).to_lowercase() == cat.to_lowercase();
            if !cat_match {
                continue;
            }
        }
        if let Some(mal) = query.is_malicious {
            if fp.is_malicious != mal {
                continue;
            }
        }

        fingerprints.push(KnownFingerprintResponse {
            hash: fp.hash.clone(),
            description: fp.description.clone(),
            category: format!("{:?}", fp.category),
            is_malicious: fp.is_malicious,
            malware_family: fp.malware_family.clone(),
            confidence: fp.confidence,
            notes: fp.notes.clone(),
        });
    }

    // Add JA3S fingerprints
    for fp in tls_analysis::fingerprints::get_all_ja3s_fingerprints() {
        if let Some(ref cat) = query.category {
            let cat_match = format!("{:?}", fp.category).to_lowercase() == cat.to_lowercase();
            if !cat_match {
                continue;
            }
        }
        if let Some(mal) = query.is_malicious {
            if fp.is_malicious != mal {
                continue;
            }
        }

        fingerprints.push(KnownFingerprintResponse {
            hash: fp.hash.clone(),
            description: fp.description.clone(),
            category: format!("{:?}", fp.category),
            is_malicious: fp.is_malicious,
            malware_family: fp.malware_family.clone(),
            confidence: fp.confidence,
            notes: fp.notes.clone(),
        });
    }

    // Add custom fingerprints from database
    if let Ok(custom) = get_custom_fingerprints(pool.get_ref()).await {
        fingerprints.extend(custom);
    }

    // Apply limit
    if let Some(limit) = query.limit {
        fingerprints.truncate(limit);
    }

    let response = FingerprintsListResponse {
        ja3_count,
        ja3s_count,
        fingerprints,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// POST /api/detection/tls/fingerprints
/// Add a custom fingerprint to the database
pub async fn add_fingerprint(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<AddFingerprintRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Validate fingerprint type
    if body.fingerprint_type != "ja3" && body.fingerprint_type != "ja3s" {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "fingerprint_type must be 'ja3' or 'ja3s'"
        })));
    }

    // Validate hash format (should be 32 hex chars for MD5)
    if body.hash.len() != 32 || !body.hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "hash must be a 32-character hex string (MD5)"
        })));
    }

    let id = Uuid::new_v4().to_string();
    let confidence = body.confidence.unwrap_or(80);

    let result = sqlx::query(
        r#"
        INSERT INTO ja3_fingerprints (id, hash, fingerprint_type, description, category,
                                       is_malicious, malware_family, confidence, notes, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&body.hash.to_lowercase())
    .bind(&body.fingerprint_type)
    .bind(&body.description)
    .bind(&body.category)
    .bind(body.is_malicious)
    .bind(&body.malware_family)
    .bind(confidence as i32)
    .bind(&body.notes)
    .bind(user_id)
    .bind(Utc::now().to_rfc3339())
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => {
            info!("Custom fingerprint added by {}: {}", user_id, body.hash);

            // Audit log
            let audit_log = models::AuditLog {
                id: Uuid::new_v4().to_string(),
                user_id: user_id.clone(),
                action: "add_tls_fingerprint".to_string(),
                target_type: Some("tls_fingerprint".to_string()),
                target_id: Some(id.clone()),
                details: Some(format!(
                    "Added {} fingerprint: {} ({})",
                    body.fingerprint_type, body.hash, body.description
                )),
                ip_address: None,
                user_agent: None,
                created_at: Utc::now(),
            };
            let _ = crate::db::create_audit_log(pool.get_ref(), &audit_log).await;

            Ok(HttpResponse::Created().json(serde_json::json!({
                "id": id,
                "hash": body.hash,
                "message": "Fingerprint added successfully"
            })))
        }
        Err(e) => {
            if e.to_string().contains("UNIQUE") {
                Ok(HttpResponse::Conflict().json(serde_json::json!({
                    "error": "Fingerprint with this hash already exists"
                })))
            } else {
                error!("Failed to add fingerprint: {}", e);
                Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to add fingerprint"
                })))
            }
        }
    }
}

/// GET /api/detection/tls/threats
/// List detected TLS threats
pub async fn list_threats(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<ThreatsQuery>,
) -> Result<HttpResponse> {
    let limit = query.limit.unwrap_or(100);
    let hours = query.hours.unwrap_or(24);

    let cutoff = Utc::now() - chrono::Duration::hours(hours as i64);

    let results = sqlx::query_as::<_, (String, Option<String>, Option<String>, Option<String>, Option<String>, String, Option<String>, String)>(
        r#"
        SELECT id, ja3_hash, ja3s_hash, src_ip, dst_ip, threat_level, threats_json, detected_at
        FROM tls_analysis_results
        WHERE detected_at > ?
        ORDER BY detected_at DESC
        LIMIT ?
        "#,
    )
    .bind(cutoff.to_rfc3339())
    .bind(limit)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to query TLS threats: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to query threats")
    })?;

    let threats: Vec<TlsThreatRecord> = results
        .into_iter()
        .filter(|(_, _, _, _, _, level, _, _)| {
            if let Some(ref min_level) = query.min_level {
                level.to_lowercase() >= min_level.to_lowercase()
            } else {
                true
            }
        })
        .map(|(id, ja3_hash, ja3s_hash, src_ip, dst_ip, threat_level, threats_json, detected_at)| {
            TlsThreatRecord {
                id,
                ja3_hash,
                ja3s_hash,
                src_ip,
                dst_ip,
                threat_level,
                threats_json,
                detected_at,
            }
        })
        .collect();

    let response = TlsThreatsListResponse {
        total: threats.len(),
        threats,
    };

    Ok(HttpResponse::Ok().json(response))
}

// ============================================================================
// Database Helper Functions
// ============================================================================

/// Save TLS analysis result to database
async fn save_tls_analysis_result(
    pool: &SqlitePool,
    result: &TlsAnalysisResult,
    src_ip: Option<&str>,
    dst_ip: Option<&str>,
    customer_id: Option<&str>,
    engagement_id: Option<&str>,
) -> anyhow::Result<()> {
    let id = Uuid::new_v4().to_string();
    let ja3_hash = result.ja3.as_ref().map(|j| j.hash.clone());
    let ja3s_hash = result.ja3s.as_ref().map(|j| j.hash.clone());
    let threat_level = result.threat_level.to_string();
    let threats_json = serde_json::to_string(&result.threats)?;

    sqlx::query(
        r#"
        INSERT INTO tls_analysis_results (id, ja3_hash, ja3s_hash, src_ip, dst_ip,
                                          threat_level, threats_json, detected_at,
                                          customer_id, engagement_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&ja3_hash)
    .bind(&ja3s_hash)
    .bind(src_ip)
    .bind(dst_ip)
    .bind(&threat_level)
    .bind(&threats_json)
    .bind(result.analyzed_at.to_rfc3339())
    .bind(customer_id)
    .bind(engagement_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Lookup custom fingerprint in database
async fn lookup_custom_fingerprint(
    pool: &SqlitePool,
    hash: &str,
    fingerprint_type: &str,
) -> anyhow::Result<Vec<KnownFingerprintResponse>> {
    let results = sqlx::query_as::<_, (String, String, String, bool, Option<String>, i32, Option<String>)>(
        r#"
        SELECT hash, description, category, is_malicious, malware_family, confidence, notes
        FROM ja3_fingerprints
        WHERE hash = ? AND fingerprint_type = ?
        "#,
    )
    .bind(hash)
    .bind(fingerprint_type)
    .fetch_all(pool)
    .await?;

    Ok(results
        .into_iter()
        .map(|(hash, description, category, is_malicious, malware_family, confidence, notes)| {
            KnownFingerprintResponse {
                hash,
                description,
                category,
                is_malicious,
                malware_family,
                confidence: confidence as u8,
                notes,
            }
        })
        .collect())
}

/// Get all custom fingerprints from database
async fn get_custom_fingerprints(pool: &SqlitePool) -> anyhow::Result<Vec<KnownFingerprintResponse>> {
    let results = sqlx::query_as::<_, (String, String, String, bool, Option<String>, i32, Option<String>)>(
        r#"
        SELECT hash, description, category, is_malicious, malware_family, confidence, notes
        FROM ja3_fingerprints
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(results
        .into_iter()
        .map(|(hash, description, category, is_malicious, malware_family, confidence, notes)| {
            KnownFingerprintResponse {
                hash,
                description,
                category,
                is_malicious,
                malware_family,
                confidence: confidence as u8,
                notes,
            }
        })
        .collect())
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure TLS analysis routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/detection/tls")
            .route("/analyze", web::post().to(analyze_tls))
            .route("/ja3", web::post().to(calculate_ja3))
            .route("/ja3s", web::post().to(calculate_ja3s))
            .route("/lookup", web::post().to(lookup_fingerprint))
            .route("/fingerprints", web::get().to(list_fingerprints))
            .route("/fingerprints", web::post().to(add_fingerprint))
            .route("/threats", web::get().to(list_threats)),
    );
}
