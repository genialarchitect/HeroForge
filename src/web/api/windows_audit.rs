//! Windows Audit API Endpoints
//!
//! Provides API endpoints for Windows credentialed scanning,
//! STIG compliance checks, and Windows system state collection.

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::web::auth::Claims;

// ============================================================================
// Encryption Helpers
// ============================================================================

/// Encrypt sensitive field for storage
fn encrypt_sensitive(value: &str) -> String {
    if let Ok(encryption_key) = std::env::var("TOTP_ENCRYPTION_KEY") {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let key_bytes = encryption_key.as_bytes();
        let encrypted: Vec<u8> = value
            .bytes()
            .enumerate()
            .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
            .collect();
        format!("enc:{}", STANDARD.encode(encrypted))
    } else {
        value.to_string()
    }
}

/// Decrypt sensitive field from storage
#[allow(dead_code)]
fn decrypt_sensitive(encrypted: &str) -> String {
    if let Some(encoded) = encrypted.strip_prefix("enc:") {
        if let Ok(encryption_key) = std::env::var("TOTP_ENCRYPTION_KEY") {
            use base64::{Engine, engine::general_purpose::STANDARD};
            if let Ok(encrypted_bytes) = STANDARD.decode(encoded) {
                let key_bytes = encryption_key.as_bytes();
                let decrypted: Vec<u8> = encrypted_bytes
                    .iter()
                    .enumerate()
                    .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
                    .collect();
                if let Ok(s) = String::from_utf8(decrypted) {
                    return s;
                }
            }
        }
    }
    encrypted.to_string()
}

// ============================================================================
// Types
// ============================================================================

/// Windows audit scan response
#[derive(Debug, Serialize)]
pub struct WindowsAuditScan {
    pub id: String,
    pub target_host: String,
    pub target_ip: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub stig_profile: Option<String>,
    pub status: String,
    pub total_checks: i32,
    pub passed: i32,
    pub failed: i32,
    pub cat1_findings: i32,
    pub cat2_findings: i32,
    pub cat3_findings: i32,
    pub score_percent: Option<f64>,
    pub created_at: String,
}

/// Windows audit scan request
#[derive(Debug, Deserialize)]
pub struct StartWindowsAuditRequest {
    pub target_host: String,
    pub target_ip: Option<String>,
    pub credential_id: String,
    pub stig_profile: Option<String>,
    pub engagement_id: Option<String>,
    pub customer_id: Option<String>,
}

/// Windows audit check result
#[derive(Debug, Serialize)]
pub struct WindowsAuditResult {
    pub id: String,
    pub scan_id: String,
    pub check_id: String,
    pub stig_id: Option<String>,
    pub title: String,
    pub category: String,
    pub status: String,
    pub actual_value: Option<String>,
    pub expected_value: Option<String>,
    pub remediation: Option<String>,
}

/// Windows credential for scanning
#[derive(Debug, Serialize)]
pub struct WindowsCredential {
    pub id: String,
    pub name: String,
    pub username: String,
    pub domain: Option<String>,
    pub auth_type: String, // password, kerberos, ntlm
    pub is_active: bool,
    pub created_at: String,
}

/// Create Windows credential request
#[derive(Debug, Deserialize)]
pub struct CreateWindowsCredentialRequest {
    pub name: String,
    pub username: String,
    pub password: String,
    pub domain: Option<String>,
    pub auth_type: Option<String>,
}

/// STIG profile
#[derive(Debug, Serialize)]
pub struct StigProfile {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub os_type: String,
    pub version: String,
    pub total_checks: i32,
    pub cat1_checks: i32,
    pub cat2_checks: i32,
    pub cat3_checks: i32,
    pub is_default: bool,
}

// ============================================================================
// Handlers
// ============================================================================

/// List Windows audit scans
pub async fn list_windows_audit_scans(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let scans = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, Option<String>, Option<String>, String, i32, i32, i32, i32, i32, i32, Option<f64>, String)>(
        r#"
        SELECT id, target_host, target_ip, os_name, os_version, stig_profile, status,
               total_checks, passed, failed, cat1_findings, cat2_findings, cat3_findings,
               score_percent, created_at
        FROM windows_audit_scans
        ORDER BY created_at DESC
        LIMIT 100
        "#
    )
    .fetch_all(pool.get_ref())
    .await;

    match scans {
        Ok(rows) => {
            let scans: Vec<WindowsAuditScan> = rows
                .into_iter()
                .map(|r| WindowsAuditScan {
                    id: r.0,
                    target_host: r.1,
                    target_ip: r.2,
                    os_name: r.3,
                    os_version: r.4,
                    stig_profile: r.5,
                    status: r.6,
                    total_checks: r.7,
                    passed: r.8,
                    failed: r.9,
                    cat1_findings: r.10,
                    cat2_findings: r.11,
                    cat3_findings: r.12,
                    score_percent: r.13,
                    created_at: r.14,
                })
                .collect();
            HttpResponse::Ok().json(scans)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Get Windows audit scan by ID
pub async fn get_windows_audit_scan(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let scan_id = path.into_inner();

    let scan = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, Option<String>, Option<String>, String, i32, i32, i32, i32, i32, i32, Option<f64>, String)>(
        r#"
        SELECT id, target_host, target_ip, os_name, os_version, stig_profile, status,
               total_checks, passed, failed, cat1_findings, cat2_findings, cat3_findings,
               score_percent, created_at
        FROM windows_audit_scans WHERE id = ?
        "#
    )
    .bind(&scan_id)
    .fetch_optional(pool.get_ref())
    .await;

    match scan {
        Ok(Some(r)) => HttpResponse::Ok().json(WindowsAuditScan {
            id: r.0,
            target_host: r.1,
            target_ip: r.2,
            os_name: r.3,
            os_version: r.4,
            stig_profile: r.5,
            status: r.6,
            total_checks: r.7,
            passed: r.8,
            failed: r.9,
            cat1_findings: r.10,
            cat2_findings: r.11,
            cat3_findings: r.12,
            score_percent: r.13,
            created_at: r.14,
        }),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Scan not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Start Windows audit scan
pub async fn start_windows_audit_scan(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<StartWindowsAuditRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let scan_id = uuid::Uuid::new_v4().to_string();

    let result = sqlx::query(
        r#"
        INSERT INTO windows_audit_scans (id, target_host, target_ip, stig_profile, status,
                                         total_checks, passed, failed, cat1_findings, cat2_findings,
                                         cat3_findings, created_by, created_at)
        VALUES (?, ?, ?, ?, 'pending', 0, 0, 0, 0, 0, 0, ?, datetime('now'))
        "#
    )
    .bind(&scan_id)
    .bind(&body.target_host)
    .bind(&body.target_ip)
    .bind(&body.stig_profile)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => {
            // TODO: Spawn async task to run the Windows audit scan
            HttpResponse::Created().json(serde_json::json!({
                "id": scan_id,
                "status": "pending",
                "message": "Windows audit scan started"
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Get STIG results for a scan
pub async fn get_stig_results(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let scan_id = path.into_inner();

    let results = sqlx::query_as::<_, (String, String, String, Option<String>, String, String, String, Option<String>, Option<String>, Option<String>)>(
        r#"
        SELECT id, scan_id, check_id, stig_id, title, category, status,
               actual_value, expected_value, remediation
        FROM windows_audit_results WHERE scan_id = ?
        ORDER BY category DESC, title
        "#
    )
    .bind(&scan_id)
    .fetch_all(pool.get_ref())
    .await;

    match results {
        Ok(rows) => {
            let results: Vec<WindowsAuditResult> = rows
                .into_iter()
                .map(|r| WindowsAuditResult {
                    id: r.0,
                    scan_id: r.1,
                    check_id: r.2,
                    stig_id: r.3,
                    title: r.4,
                    category: r.5,
                    status: r.6,
                    actual_value: r.7,
                    expected_value: r.8,
                    remediation: r.9,
                })
                .collect();
            HttpResponse::Ok().json(results)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// List Windows credentials
pub async fn list_credentials(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let credentials = sqlx::query_as::<_, (String, String, String, Option<String>, String, bool, String)>(
        r#"
        SELECT id, name, username, domain, auth_type, is_active, created_at
        FROM windows_audit_credentials
        ORDER BY name
        "#
    )
    .fetch_all(pool.get_ref())
    .await;

    match credentials {
        Ok(rows) => {
            let credentials: Vec<WindowsCredential> = rows
                .into_iter()
                .map(|r| WindowsCredential {
                    id: r.0,
                    name: r.1,
                    username: r.2,
                    domain: r.3,
                    auth_type: r.4,
                    is_active: r.5,
                    created_at: r.6,
                })
                .collect();
            HttpResponse::Ok().json(credentials)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Create Windows credential
pub async fn create_credential(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateWindowsCredentialRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let credential_id = uuid::Uuid::new_v4().to_string();
    let auth_type = body.auth_type.as_deref().unwrap_or("password");

    // Encrypt password before storing
    let encrypted_password = encrypt_sensitive(&body.password);

    let result = sqlx::query(
        r#"
        INSERT INTO windows_audit_credentials (id, name, username, password_encrypted, domain,
                                               auth_type, is_active, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, datetime('now'))
        "#
    )
    .bind(&credential_id)
    .bind(&body.name)
    .bind(&body.username)
    .bind(&encrypted_password)
    .bind(&body.domain)
    .bind(auth_type)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": credential_id,
            "message": "Credential created successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Delete Windows credential
pub async fn delete_credential(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let credential_id = path.into_inner();

    let result = sqlx::query("DELETE FROM windows_audit_credentials WHERE id = ?")
        .bind(&credential_id)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => HttpResponse::Ok().json(serde_json::json!({
            "message": "Credential deleted successfully"
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "Credential not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// List STIG profiles
pub async fn list_stig_profiles(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let profiles = sqlx::query_as::<_, (String, String, Option<String>, String, String, i32, i32, i32, i32, bool)>(
        r#"
        SELECT id, name, description, os_type, version, total_checks,
               cat1_checks, cat2_checks, cat3_checks, is_default
        FROM windows_stig_profiles
        ORDER BY os_type, name
        "#
    )
    .fetch_all(pool.get_ref())
    .await;

    match profiles {
        Ok(rows) => {
            let profiles: Vec<StigProfile> = rows
                .into_iter()
                .map(|r| StigProfile {
                    id: r.0,
                    name: r.1,
                    description: r.2,
                    os_type: r.3,
                    version: r.4,
                    total_checks: r.5,
                    cat1_checks: r.6,
                    cat2_checks: r.7,
                    cat3_checks: r.8,
                    is_default: r.9,
                })
                .collect();
            HttpResponse::Ok().json(profiles)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Generate CKL for a scan
pub async fn generate_ckl(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let scan_id = path.into_inner();

    // Verify scan exists
    let scan = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT id, target_host, stig_profile FROM windows_audit_scans WHERE id = ?"
    )
    .bind(&scan_id)
    .fetch_optional(pool.get_ref())
    .await;

    match scan {
        Ok(Some(_s)) => {
            // TODO: Generate actual CKL XML using the ckl module
            let ckl_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
    <ASSET>
        <ROLE>None</ROLE>
        <ASSET_TYPE>Computing</ASSET_TYPE>
    </ASSET>
    <STIGS>
        <iSTIG>
            <STIG_INFO>
            </STIG_INFO>
        </iSTIG>
    </STIGS>
</CHECKLIST>"#;

            HttpResponse::Ok()
                .content_type("application/xml")
                .insert_header(("Content-Disposition", format!("attachment; filename=\"scan_{}.ckl\"", scan_id)))
                .body(ckl_xml)
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Scan not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configure Windows Audit API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/windows-audit")
            // Scans
            .route("/scans", web::get().to(list_windows_audit_scans))
            .route("/scans", web::post().to(start_windows_audit_scan))
            .route("/scans/{id}", web::get().to(get_windows_audit_scan))
            .route("/scans/{id}/stig-results", web::get().to(get_stig_results))
            .route("/scans/{id}/ckl", web::get().to(generate_ckl))
            // Credentials
            .route("/credentials", web::get().to(list_credentials))
            .route("/credentials", web::post().to(create_credential))
            .route("/credentials/{id}", web::delete().to(delete_credential))
            // STIG profiles
            .route("/stig-profiles", web::get().to(list_stig_profiles))
    );
}
