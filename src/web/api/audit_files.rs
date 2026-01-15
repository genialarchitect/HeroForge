//! Audit File Library API Endpoints
//!
//! Provides API endpoints for managing audit files (CKL, ARF, XCCDF, OVAL),
//! version history, chain of custody tracking, and retention policies.

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::web::auth::Claims;
use crate::reports::formats::ckl::{parse_ckl, generate_ckl as generate_ckl_xml, CklStatus};
use crate::scap::arf::ArfGenerator;
use crate::scanner::windows_audit::types::{StigCheckResult, StigCheckStatus, StigCategory};

// ============================================================================
// Types
// ============================================================================

/// Audit file response
#[derive(Debug, Serialize)]
pub struct AuditFileResponse {
    pub id: String,
    pub file_type: String,
    pub filename: String,
    pub file_size: i64,
    pub sha256_hash: String,
    pub version: i32,
    pub system_id: Option<String>,
    pub asset_id: Option<String>,
    pub framework: Option<String>,
    pub profile_id: Option<String>,
    pub scan_id: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub retention_until: Option<String>,
    pub is_archived: bool,
    pub notes: Option<String>,
}

/// Query parameters for listing audit files
#[derive(Debug, Deserialize)]
pub struct AuditFileQueryParams {
    pub file_type: Option<String>,
    pub framework: Option<String>,
    pub system_id: Option<String>,
    pub include_archived: Option<bool>,
    pub archived_only: Option<bool>,
    pub limit: Option<i32>,
}

/// Generate CKL request
#[derive(Debug, Deserialize)]
pub struct GenerateCklRequest {
    pub scan_id: String,
    pub stig_profile: Option<String>,
    pub system_name: Option<String>,
    pub asset_id: Option<String>,
}

/// Generate ARF request
#[derive(Debug, Deserialize)]
pub struct GenerateArfRequest {
    pub scap_execution_id: String,
    pub asset_id: Option<String>,
}

/// Import CKL request
#[derive(Debug, Deserialize)]
pub struct ImportCklRequest {
    pub filename: String,
    pub content: String, // Base64 encoded
    pub system_id: Option<String>,
    pub asset_id: Option<String>,
}

/// Import ARF request
#[derive(Debug, Deserialize)]
pub struct ImportArfRequest {
    pub filename: String,
    pub content: String, // Base64 encoded
    pub system_id: Option<String>,
    pub asset_id: Option<String>,
}

/// Audit file version
#[derive(Debug, Serialize)]
pub struct AuditFileVersion {
    pub id: String,
    pub file_id: String,
    pub version: i32,
    pub sha256_hash: String,
    pub file_size: i64,
    pub created_by: String,
    pub created_at: String,
    pub change_notes: Option<String>,
}

/// Custody event
#[derive(Debug, Serialize)]
pub struct CustodyEvent {
    pub id: String,
    pub file_id: String,
    pub event_type: String,
    pub actor: String,
    pub description: Option<String>,
    pub ip_address: Option<String>,
    pub timestamp: String,
}

/// Retention policy
#[derive(Debug, Serialize)]
pub struct RetentionPolicy {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub framework: Option<String>,
    pub retention_days: i32,
    pub is_default: bool,
}

/// Create retention policy request
#[derive(Debug, Deserialize)]
pub struct CreateRetentionPolicyRequest {
    pub name: String,
    pub description: Option<String>,
    pub framework: Option<String>,
    pub retention_days: i32,
    pub is_default: Option<bool>,
}

// ============================================================================
// Handlers
// ============================================================================

/// List audit files
pub async fn list_audit_files(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    query: web::Query<AuditFileQueryParams>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let limit = query.limit.unwrap_or(100);
    let include_archived = query.include_archived.unwrap_or(false);
    let archived_only = query.archived_only.unwrap_or(false);

    // Build dynamic query based on filters
    let mut sql = String::from(
        r#"
        SELECT id, file_type, filename, file_size, sha256_hash, version, system_id,
               asset_id, framework, profile_id, scan_id, created_by, created_at,
               retention_until, is_archived, notes
        FROM audit_files WHERE 1=1
        "#
    );

    if let Some(ref file_type) = query.file_type {
        sql.push_str(&format!(" AND file_type = '{}'", file_type));
    }
    if let Some(ref framework) = query.framework {
        sql.push_str(&format!(" AND framework = '{}'", framework));
    }
    if let Some(ref system_id) = query.system_id {
        sql.push_str(&format!(" AND system_id = '{}'", system_id));
    }
    if archived_only {
        sql.push_str(" AND is_archived = 1");
    } else if !include_archived {
        sql.push_str(" AND is_archived = 0");
    }

    sql.push_str(&format!(" ORDER BY created_at DESC LIMIT {}", limit));

    let files = sqlx::query_as::<_, (String, String, String, i64, String, i32, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, String, String, Option<String>, bool, Option<String>)>(&sql)
        .fetch_all(pool.get_ref())
        .await;

    match files {
        Ok(rows) => {
            let files: Vec<AuditFileResponse> = rows
                .into_iter()
                .map(|r| AuditFileResponse {
                    id: r.0,
                    file_type: r.1,
                    filename: r.2,
                    file_size: r.3,
                    sha256_hash: r.4,
                    version: r.5,
                    system_id: r.6,
                    asset_id: r.7,
                    framework: r.8,
                    profile_id: r.9,
                    scan_id: r.10,
                    created_by: r.11,
                    created_at: r.12,
                    retention_until: r.13,
                    is_archived: r.14,
                    notes: r.15,
                })
                .collect();
            HttpResponse::Ok().json(files)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Get audit file by ID
pub async fn get_audit_file(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let file_id = path.into_inner();

    let file = sqlx::query_as::<_, (String, String, String, i64, String, i32, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, String, String, Option<String>, bool, Option<String>)>(
        r#"
        SELECT id, file_type, filename, file_size, sha256_hash, version, system_id,
               asset_id, framework, profile_id, scan_id, created_by, created_at,
               retention_until, is_archived, notes
        FROM audit_files WHERE id = ?
        "#
    )
    .bind(&file_id)
    .fetch_optional(pool.get_ref())
    .await;

    match file {
        Ok(Some(r)) => HttpResponse::Ok().json(AuditFileResponse {
            id: r.0,
            file_type: r.1,
            filename: r.2,
            file_size: r.3,
            sha256_hash: r.4,
            version: r.5,
            system_id: r.6,
            asset_id: r.7,
            framework: r.8,
            profile_id: r.9,
            scan_id: r.10,
            created_by: r.11,
            created_at: r.12,
            retention_until: r.13,
            is_archived: r.14,
            notes: r.15,
        }),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "File not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Generate CKL file from scan
pub async fn generate_ckl(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<GenerateCklRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let file_id = uuid::Uuid::new_v4().to_string();

    // Fetch STIG results from the scan
    let stig_results = sqlx::query_as::<_, (String, String, String, String, String, Option<String>, String, String, Option<String>)>(
        r#"
        SELECT stig_id, rule_id, title, category, status, finding_details, expected, actual, remediation
        FROM scan_stig_results WHERE scan_id = ?
        "#
    )
    .bind(&body.scan_id)
    .fetch_all(pool.get_ref())
    .await;

    // Fetch scan target info
    let scan_info = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT target, name FROM scan_results WHERE id = ?"
    )
    .bind(&body.scan_id)
    .fetch_optional(pool.get_ref())
    .await;

    let (hostname, ip_address) = match scan_info {
        Ok(Some((target, name))) => {
            let hostname = body.system_name.clone().or(name).unwrap_or_else(|| target.clone());
            (hostname, target)
        }
        _ => {
            let hostname = body.system_name.clone().unwrap_or_else(|| "Unknown".to_string());
            (hostname.clone(), hostname)
        }
    };

    // Convert database results to StigCheckResult
    let results: Vec<StigCheckResult> = match stig_results {
        Ok(rows) => rows.into_iter().map(|r| StigCheckResult {
            stig_id: r.0,
            rule_id: r.1,
            title: r.2,
            category: match r.3.as_str() {
                "CatI" | "CAT I" | "high" => StigCategory::CatI,
                "CatII" | "CAT II" | "medium" => StigCategory::CatII,
                _ => StigCategory::CatIII,
            },
            status: match r.4.as_str() {
                "NotAFinding" | "pass" => StigCheckStatus::NotAFinding,
                "Open" | "fail" => StigCheckStatus::Open,
                "NotApplicable" => StigCheckStatus::NotApplicable,
                _ => StigCheckStatus::NotReviewed,
            },
            finding_details: r.5,
            expected: r.6,
            actual: r.7,
            remediation: r.8,
        }).collect(),
        Err(_) => Vec::new(),
    };

    let stig_profile = body.stig_profile.as_deref().unwrap_or("Windows STIG");

    // Generate CKL using the actual generator
    let ckl_content = match generate_ckl_xml(&results, &hostname, &ip_address, stig_profile, "V1R1") {
        Ok(content) => content,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to generate CKL: {}", e)
        })),
    };

    let sha256_hash = format!("{:x}", Sha256::digest(ckl_content.as_bytes()));
    let filename = format!("scan_{}.ckl", body.scan_id);

    let result = sqlx::query(
        r#"
        INSERT INTO audit_files (id, file_type, filename, file_content, file_size, sha256_hash,
                                 version, scan_id, asset_id, created_by, created_at, is_archived)
        VALUES (?, 'ckl', ?, ?, ?, ?, 1, ?, ?, ?, datetime('now'), 0)
        "#
    )
    .bind(&file_id)
    .bind(&filename)
    .bind(&ckl_content)
    .bind(ckl_content.len() as i64)
    .bind(&sha256_hash)
    .bind(&body.scan_id)
    .bind(&body.asset_id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": file_id,
            "filename": filename,
            "file_type": "ckl",
            "stig_checks_count": results.len(),
            "message": "CKL file generated successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Generate ARF file from SCAP execution
pub async fn generate_arf(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<GenerateArfRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let file_id = uuid::Uuid::new_v4().to_string();

    // Generate ARF using the actual generator
    let arf_generator = ArfGenerator::new(pool.get_ref());
    let arf_content = match arf_generator.generate(&body.scap_execution_id).await {
        Ok(content) => content,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to generate ARF: {}", e)
        })),
    };

    let sha256_hash = format!("{:x}", Sha256::digest(arf_content.as_bytes()));
    let filename = format!("scap_exec_{}.xml", body.scap_execution_id);

    let result = sqlx::query(
        r#"
        INSERT INTO audit_files (id, file_type, filename, file_content, file_size, sha256_hash,
                                 version, scan_id, asset_id, framework, created_by, created_at, is_archived)
        VALUES (?, 'arf', ?, ?, ?, ?, 1, ?, ?, 'SCAP', ?, datetime('now'), 0)
        "#
    )
    .bind(&file_id)
    .bind(&filename)
    .bind(&arf_content)
    .bind(arf_content.len() as i64)
    .bind(&sha256_hash)
    .bind(&body.scap_execution_id)
    .bind(&body.asset_id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": file_id,
            "filename": filename,
            "file_type": "arf",
            "message": "ARF file generated successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Import existing CKL file
pub async fn import_ckl(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<ImportCklRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let file_id = uuid::Uuid::new_v4().to_string();

    // Decode base64 content
    use base64::Engine;
    let content_bytes = match base64::engine::general_purpose::STANDARD.decode(&body.content) {
        Ok(bytes) => bytes,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid base64 content: {}", e)
        })),
    };

    let sha256_hash = format!("{:x}", Sha256::digest(&content_bytes));
    let content_str = String::from_utf8_lossy(&content_bytes).to_string();

    // Parse CKL XML and extract metadata
    let (hostname, ip_address, vuln_count, open_count, not_finding_count) = match parse_ckl(&content_str) {
        Ok(doc) => {
            let vuln_count = doc.stigs.iter().map(|s| s.vulnerabilities.len()).sum::<usize>();
            let open_count = doc.stigs.iter()
                .flat_map(|s| &s.vulnerabilities)
                .filter(|v| v.status == CklStatus::Open)
                .count();
            let not_finding_count = doc.stigs.iter()
                .flat_map(|s| &s.vulnerabilities)
                .filter(|v| v.status == CklStatus::NotAFinding)
                .count();
            (doc.asset.host_name, doc.asset.host_ip, vuln_count, open_count, not_finding_count)
        }
        Err(e) => {
            log::warn!("Failed to parse CKL for metadata extraction: {}", e);
            (String::new(), String::new(), 0, 0, 0)
        }
    };

    let result = sqlx::query(
        r#"
        INSERT INTO audit_files (id, file_type, filename, file_content, file_size, sha256_hash,
                                 version, system_id, asset_id, created_by, created_at, is_archived, notes)
        VALUES (?, 'ckl', ?, ?, ?, ?, 1, ?, ?, ?, datetime('now'), 0, ?)
        "#
    )
    .bind(&file_id)
    .bind(&body.filename)
    .bind(&content_str)
    .bind(content_bytes.len() as i64)
    .bind(&sha256_hash)
    .bind(&body.system_id)
    .bind(&body.asset_id)
    .bind(&claims.sub)
    .bind(format!(
        "Imported CKL for host: {} ({}). Total checks: {}, Open: {}, Not a Finding: {}",
        hostname, ip_address, vuln_count, open_count, not_finding_count
    ))
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": file_id,
            "hostname": hostname,
            "ip_address": ip_address,
            "vulnerability_count": vuln_count,
            "open_count": open_count,
            "not_a_finding_count": not_finding_count,
            "message": "CKL file imported successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Import existing ARF file
pub async fn import_arf(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<ImportArfRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let file_id = uuid::Uuid::new_v4().to_string();

    // Decode base64 content
    use base64::Engine;
    let content_bytes = match base64::engine::general_purpose::STANDARD.decode(&body.content) {
        Ok(bytes) => bytes,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid base64 content: {}", e)
        })),
    };

    let sha256_hash = format!("{:x}", Sha256::digest(&content_bytes));
    let content_str = String::from_utf8_lossy(&content_bytes).to_string();

    // Parse ARF XML and extract metadata
    let (asset_count, report_count, hostname) = parse_arf_metadata(&content_str);

    let result = sqlx::query(
        r#"
        INSERT INTO audit_files (id, file_type, filename, file_content, file_size, sha256_hash,
                                 version, system_id, asset_id, framework, created_by, created_at, is_archived, notes)
        VALUES (?, 'arf', ?, ?, ?, ?, 1, ?, ?, 'SCAP', ?, datetime('now'), 0, ?)
        "#
    )
    .bind(&file_id)
    .bind(&body.filename)
    .bind(&content_str)
    .bind(content_bytes.len() as i64)
    .bind(&sha256_hash)
    .bind(&body.system_id)
    .bind(&body.asset_id)
    .bind(&claims.sub)
    .bind(format!(
        "Imported ARF with {} assets and {} reports. Primary host: {}",
        asset_count, report_count, hostname
    ))
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": file_id,
            "asset_count": asset_count,
            "report_count": report_count,
            "primary_hostname": hostname,
            "message": "ARF file imported successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Parse ARF XML metadata without full deserialization
fn parse_arf_metadata(xml: &str) -> (usize, usize, String) {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut asset_count = 0;
    let mut report_count = 0;
    let mut hostname = String::new();
    let mut in_hostname = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name.ends_with("asset") || name == "arf:asset" {
                    asset_count += 1;
                } else if name.ends_with("report") || name == "arf:report" {
                    report_count += 1;
                } else if name.ends_with("hostname") || name == "ai:hostname" {
                    in_hostname = true;
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_hostname && hostname.is_empty() {
                    hostname = String::from_utf8_lossy(e.as_ref()).to_string();
                }
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name.ends_with("hostname") || name == "ai:hostname" {
                    in_hostname = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    (asset_count, report_count, hostname)
}

/// Download audit file
pub async fn download_file(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let file_id = path.into_inner();

    let file = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, filename, file_type, file_content FROM audit_files WHERE id = ?"
    )
    .bind(&file_id)
    .fetch_optional(pool.get_ref())
    .await;

    match file {
        Ok(Some(r)) => {
            // Log custody event
            let _ = sqlx::query(
                r#"
                INSERT INTO audit_custody_events (id, file_id, event_type, actor, description, timestamp)
                VALUES (?, ?, 'download', ?, 'File downloaded', datetime('now'))
                "#
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&file_id)
            .bind(&claims.sub)
            .execute(pool.get_ref())
            .await;

            let content_type = match r.2.as_str() {
                "ckl" | "arf" | "xccdf" | "oval" => "application/xml",
                _ => "application/octet-stream",
            };

            HttpResponse::Ok()
                .content_type(content_type)
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", r.1)))
                .body(r.3)
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "File not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Get version history for an audit file
pub async fn get_version_history(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let file_id = path.into_inner();

    let versions = sqlx::query_as::<_, (String, String, i32, String, i64, String, String, Option<String>)>(
        r#"
        SELECT id, file_id, version, sha256_hash, file_size, created_by, created_at, change_notes
        FROM audit_file_versions WHERE file_id = ?
        ORDER BY version DESC
        "#
    )
    .bind(&file_id)
    .fetch_all(pool.get_ref())
    .await;

    match versions {
        Ok(rows) => {
            let versions: Vec<AuditFileVersion> = rows
                .into_iter()
                .map(|r| AuditFileVersion {
                    id: r.0,
                    file_id: r.1,
                    version: r.2,
                    sha256_hash: r.3,
                    file_size: r.4,
                    created_by: r.5,
                    created_at: r.6,
                    change_notes: r.7,
                })
                .collect();
            HttpResponse::Ok().json(versions)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Get custody chain for an audit file
pub async fn get_custody_chain(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let file_id = path.into_inner();

    let events = sqlx::query_as::<_, (String, String, String, String, Option<String>, Option<String>, String)>(
        r#"
        SELECT id, file_id, event_type, actor, description, ip_address, timestamp
        FROM audit_custody_events WHERE file_id = ?
        ORDER BY timestamp DESC
        "#
    )
    .bind(&file_id)
    .fetch_all(pool.get_ref())
    .await;

    match events {
        Ok(rows) => {
            let events: Vec<CustodyEvent> = rows
                .into_iter()
                .map(|r| CustodyEvent {
                    id: r.0,
                    file_id: r.1,
                    event_type: r.2,
                    actor: r.3,
                    description: r.4,
                    ip_address: r.5,
                    timestamp: r.6,
                })
                .collect();
            HttpResponse::Ok().json(events)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Archive audit file
pub async fn archive_file(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let file_id = path.into_inner();

    let result = sqlx::query("UPDATE audit_files SET is_archived = 1 WHERE id = ?")
        .bind(&file_id)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            // Log custody event
            let _ = sqlx::query(
                r#"
                INSERT INTO audit_custody_events (id, file_id, event_type, actor, description, timestamp)
                VALUES (?, ?, 'archive', ?, 'File archived', datetime('now'))
                "#
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&file_id)
            .bind(&claims.sub)
            .execute(pool.get_ref())
            .await;

            HttpResponse::Ok().json(serde_json::json!({
                "message": "File archived successfully"
            }))
        }
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "File not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Restore archived audit file
pub async fn restore_file(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let file_id = path.into_inner();

    let result = sqlx::query("UPDATE audit_files SET is_archived = 0 WHERE id = ?")
        .bind(&file_id)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            // Log custody event
            let _ = sqlx::query(
                r#"
                INSERT INTO audit_custody_events (id, file_id, event_type, actor, description, timestamp)
                VALUES (?, ?, 'restore', ?, 'File restored from archive', datetime('now'))
                "#
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&file_id)
            .bind(&claims.sub)
            .execute(pool.get_ref())
            .await;

            HttpResponse::Ok().json(serde_json::json!({
                "message": "File restored successfully"
            }))
        }
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "File not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// List retention policies
pub async fn list_retention_policies(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let policies = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, i32, bool)>(
        r#"
        SELECT id, name, description, framework, retention_days, is_default
        FROM audit_retention_policies
        ORDER BY name
        "#
    )
    .fetch_all(pool.get_ref())
    .await;

    match policies {
        Ok(rows) => {
            let policies: Vec<RetentionPolicy> = rows
                .into_iter()
                .map(|r| RetentionPolicy {
                    id: r.0,
                    name: r.1,
                    description: r.2,
                    framework: r.3,
                    retention_days: r.4,
                    is_default: r.5,
                })
                .collect();
            HttpResponse::Ok().json(policies)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Create retention policy
pub async fn create_retention_policy(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateRetentionPolicyRequest>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let policy_id = uuid::Uuid::new_v4().to_string();
    let is_default = body.is_default.unwrap_or(false);

    let result = sqlx::query(
        r#"
        INSERT INTO audit_retention_policies (id, name, description, framework, retention_days, is_default)
        VALUES (?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&policy_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.framework)
    .bind(body.retention_days)
    .bind(is_default)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": policy_id,
            "message": "Retention policy created successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configure Audit Files API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/audit-files")
            // File management
            .route("", web::get().to(list_audit_files))
            .route("/{id}", web::get().to(get_audit_file))
            .route("/{id}/download", web::get().to(download_file))
            .route("/{id}/versions", web::get().to(get_version_history))
            .route("/{id}/custody", web::get().to(get_custody_chain))
            .route("/{id}/archive", web::post().to(archive_file))
            .route("/{id}/restore", web::post().to(restore_file))
            // Generation
            .route("/generate/ckl", web::post().to(generate_ckl))
            .route("/generate/arf", web::post().to(generate_arf))
            // Import
            .route("/import/ckl", web::post().to(import_ckl))
            .route("/import/arf", web::post().to(import_arf))
            // Retention policies
            .route("/retention-policies", web::get().to(list_retention_policies))
            .route("/retention-policies", web::post().to(create_retention_policy))
    );
}
