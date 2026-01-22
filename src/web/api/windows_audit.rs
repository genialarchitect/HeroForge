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
            // Spawn async task to run the Windows audit scan
            let pool_clone = pool.get_ref().clone();
            let scan_id_clone = scan_id.clone();
            let target_host = body.target_host.clone();
            let credential_id = body.credential_id.clone();
            let stig_profile = body.stig_profile.clone();

            tokio::spawn(async move {
                run_windows_audit_scan(
                    &pool_clone,
                    &scan_id_clone,
                    &target_host,
                    &credential_id,
                    stig_profile.as_deref(),
                ).await;
            });

            HttpResponse::Created().json(serde_json::json!({
                "id": scan_id,
                "status": "running",
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

    // Get scan details
    let scan = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, Option<String>)>(
        "SELECT id, target_host, stig_profile, status, results FROM windows_audit_scans WHERE id = ?"
    )
    .bind(&scan_id)
    .fetch_optional(pool.get_ref())
    .await;

    match scan {
        Ok(Some((id, target_host, stig_profile, _status, results_json))) => {
            // Parse audit results from JSON
            let stig_results = if let Some(json_str) = results_json.as_ref() {
                serde_json::from_str::<serde_json::Value>(json_str)
                    .ok()
                    .and_then(|v| v.get("stig_results").cloned())
                    .and_then(|v| serde_json::from_value::<Vec<crate::scanner::windows_audit::types::StigCheckResult>>(v).ok())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

            // Get system info if available
            let system_info = if let Some(json_str) = results_json.as_ref() {
                serde_json::from_str::<serde_json::Value>(json_str)
                    .ok()
                    .and_then(|v| v.get("system_info").cloned())
            } else {
                None
            };

            let hostname = system_info.as_ref()
                .and_then(|s| s.get("hostname"))
                .and_then(|v| v.as_str())
                .unwrap_or(&target_host);

            let ip_address = system_info.as_ref()
                .and_then(|s| s.get("ip_address"))
                .and_then(|v| v.as_str())
                .unwrap_or(&target_host);

            let os_name = system_info.as_ref()
                .and_then(|s| s.get("os_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("Windows");

            let profile_name = stig_profile.as_deref().unwrap_or("Windows Server STIG");

            // Build CKL XML
            let mut ckl = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>
<!--DISA STIG Viewer :: 2.17-->
<CHECKLIST>
    <ASSET>
        <ROLE>None</ROLE>
        <ASSET_TYPE>Computing</ASSET_TYPE>
"#);

            ckl.push_str(&format!("        <HOST_NAME>{}</HOST_NAME>\n", escape_xml(hostname)));
            ckl.push_str(&format!("        <HOST_IP>{}</HOST_IP>\n", escape_xml(ip_address)));
            ckl.push_str(&format!("        <HOST_MAC></HOST_MAC>\n"));
            ckl.push_str(&format!("        <HOST_FQDN>{}</HOST_FQDN>\n", escape_xml(hostname)));
            ckl.push_str(&format!("        <TARGET_COMMENT>{} - HeroForge Audit Scan {}</TARGET_COMMENT>\n",
                escape_xml(os_name), escape_xml(&id)));
            ckl.push_str(&format!("        <TECH_AREA></TECH_AREA>\n"));
            ckl.push_str(&format!("        <TARGET_KEY></TARGET_KEY>\n"));
            ckl.push_str(&format!("        <WEB_OR_DATABASE>false</WEB_OR_DATABASE>\n"));
            ckl.push_str(&format!("        <WEB_DB_SITE></WEB_DB_SITE>\n"));
            ckl.push_str(&format!("        <WEB_DB_INSTANCE></WEB_DB_INSTANCE>\n"));
            ckl.push_str("    </ASSET>\n");

            ckl.push_str("    <STIGS>\n");
            ckl.push_str("        <iSTIG>\n");
            ckl.push_str("            <STIG_INFO>\n");
            ckl.push_str(&format!("                <SI_DATA><SID_NAME>version</SID_NAME><SID_DATA>1</SID_DATA></SI_DATA>\n"));
            ckl.push_str(&format!("                <SI_DATA><SID_NAME>classification</SID_NAME><SID_DATA>UNCLASSIFIED</SID_DATA></SI_DATA>\n"));
            ckl.push_str(&format!("                <SI_DATA><SID_NAME>stigid</SID_NAME><SID_DATA>{}</SID_DATA></SI_DATA>\n",
                escape_xml(profile_name)));
            ckl.push_str(&format!("                <SI_DATA><SID_NAME>description</SID_NAME><SID_DATA>HeroForge Windows Audit Results</SID_DATA></SI_DATA>\n"));
            ckl.push_str(&format!("                <SI_DATA><SID_NAME>filename</SID_NAME><SID_DATA>scan_{}.ckl</SID_DATA></SI_DATA>\n", &id));
            ckl.push_str(&format!("                <SI_DATA><SID_NAME>releaseinfo</SID_NAME><SID_DATA>Generated by HeroForge</SID_DATA></SI_DATA>\n"));
            ckl.push_str(&format!("                <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>{}</SID_DATA></SI_DATA>\n",
                escape_xml(profile_name)));
            ckl.push_str("            </STIG_INFO>\n");

            // Add VULN entries for each STIG result
            for result in &stig_results {
                let status = match result.status {
                    crate::scanner::windows_audit::types::StigCheckStatus::NotAFinding => "NotAFinding",
                    crate::scanner::windows_audit::types::StigCheckStatus::Open => "Open",
                    crate::scanner::windows_audit::types::StigCheckStatus::NotApplicable => "Not_Applicable",
                    crate::scanner::windows_audit::types::StigCheckStatus::NotReviewed => "Not_Reviewed",
                };

                let severity = match result.category {
                    crate::scanner::windows_audit::types::StigCategory::CatI => "high",
                    crate::scanner::windows_audit::types::StigCategory::CatII => "medium",
                    crate::scanner::windows_audit::types::StigCategory::CatIII => "low",
                };

                ckl.push_str("            <VULN>\n");
                ckl.push_str(&format!("                <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>{}</ATTRIBUTE_DATA></STIG_DATA>\n",
                    escape_xml(&result.stig_id)));
                ckl.push_str(&format!("                <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>{}</ATTRIBUTE_DATA></STIG_DATA>\n",
                    severity));
                ckl.push_str(&format!("                <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>{}</ATTRIBUTE_DATA></STIG_DATA>\n",
                    escape_xml(&result.rule_id)));
                ckl.push_str(&format!("                <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>{}</ATTRIBUTE_DATA></STIG_DATA>\n",
                    escape_xml(&result.title)));
                ckl.push_str(&format!("                <STIG_DATA><VULN_ATTRIBUTE>Fix_Text</VULN_ATTRIBUTE><ATTRIBUTE_DATA>{}</ATTRIBUTE_DATA></STIG_DATA>\n",
                    escape_xml(result.remediation.as_deref().unwrap_or(""))));
                ckl.push_str(&format!("                <STATUS>{}</STATUS>\n", status));
                ckl.push_str(&format!("                <FINDING_DETAILS>{}</FINDING_DETAILS>\n",
                    escape_xml(result.finding_details.as_deref().unwrap_or(""))));
                ckl.push_str(&format!("                <COMMENTS>Expected: {} | Actual: {}</COMMENTS>\n",
                    escape_xml(&result.expected), escape_xml(&result.actual)));
                ckl.push_str(&format!("                <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>\n"));
                ckl.push_str(&format!("                <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>\n"));
                ckl.push_str("            </VULN>\n");
            }

            ckl.push_str("        </iSTIG>\n");
            ckl.push_str("    </STIGS>\n");
            ckl.push_str("</CHECKLIST>");

            HttpResponse::Ok()
                .content_type("application/xml")
                .insert_header(("Content-Disposition", format!("attachment; filename=\"scan_{}.ckl\"", scan_id)))
                .body(ckl)
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Scan not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Escape XML special characters
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ============================================================================
// Audit Execution
// ============================================================================

/// Execute Windows audit scan asynchronously
async fn run_windows_audit_scan(
    pool: &SqlitePool,
    scan_id: &str,
    target_host: &str,
    credential_id: &str,
    stig_profile: Option<&str>,
) {
    log::info!("Starting Windows audit scan {} for target {}", scan_id, target_host);

    // Update status to running
    if let Err(e) = sqlx::query(
        "UPDATE windows_audit_scans SET status = 'running' WHERE id = ?"
    )
    .bind(scan_id)
    .execute(pool)
    .await {
        log::error!("Failed to update scan status: {}", e);
        return;
    }

    // Get credentials
    let creds = sqlx::query_as::<_, (String, String, Option<String>, String)>(
        "SELECT username, password_encrypted, domain, auth_type FROM windows_audit_credentials WHERE id = ?"
    )
    .bind(credential_id)
    .fetch_optional(pool)
    .await;

    let (username, _encrypted_password, domain, _auth_type) = match creds {
        Ok(Some(c)) => c,
        Ok(None) => {
            log::error!("Credential {} not found for scan {}", credential_id, scan_id);
            let _ = update_scan_failed(pool, scan_id, "Credential not found").await;
            return;
        }
        Err(e) => {
            log::error!("Database error fetching credentials: {}", e);
            let _ = update_scan_failed(pool, scan_id, "Database error").await;
            return;
        }
    };

    // Execute Windows audit checks
    // In production, this would use WMI/WinRM to connect and run STIG checks
    // For now, we simulate the audit process
    let audit_results = execute_windows_checks(target_host, &username, domain.as_deref(), stig_profile).await;

    match audit_results {
        Ok(results) => {
            // Store results in database
            let mut passed = 0;
            let mut failed = 0;
            let mut cat1_findings = 0;
            let mut cat2_findings = 0;
            let mut cat3_findings = 0;

            for result in &results {
                let result_id = uuid::Uuid::new_v4().to_string();

                if result.status == "pass" {
                    passed += 1;
                } else {
                    failed += 1;
                    match result.category.as_str() {
                        "CAT I" => cat1_findings += 1,
                        "CAT II" => cat2_findings += 1,
                        "CAT III" => cat3_findings += 1,
                        _ => {}
                    }
                }

                let _ = sqlx::query(
                    r#"INSERT INTO windows_audit_results
                       (id, scan_id, check_id, stig_id, title, category, status,
                        actual_value, expected_value, remediation)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#
                )
                .bind(&result_id)
                .bind(scan_id)
                .bind(&result.check_id)
                .bind(&result.stig_id)
                .bind(&result.title)
                .bind(&result.category)
                .bind(&result.status)
                .bind(&result.actual_value)
                .bind(&result.expected_value)
                .bind(&result.remediation)
                .execute(pool)
                .await;
            }

            let total_checks = results.len() as i32;
            let score_percent = if total_checks > 0 {
                Some((passed as f64 / total_checks as f64) * 100.0)
            } else {
                None
            };

            // Update scan with results
            let _ = sqlx::query(
                r#"UPDATE windows_audit_scans SET
                   status = 'completed',
                   total_checks = ?,
                   passed = ?,
                   failed = ?,
                   cat1_findings = ?,
                   cat2_findings = ?,
                   cat3_findings = ?,
                   score_percent = ?
                   WHERE id = ?"#
            )
            .bind(total_checks)
            .bind(passed)
            .bind(failed)
            .bind(cat1_findings)
            .bind(cat2_findings)
            .bind(cat3_findings)
            .bind(score_percent)
            .bind(scan_id)
            .execute(pool)
            .await;

            log::info!("Windows audit scan {} completed: {} passed, {} failed", scan_id, passed, failed);
        }
        Err(e) => {
            log::error!("Windows audit scan {} failed: {}", scan_id, e);
            let _ = update_scan_failed(pool, scan_id, &e.to_string()).await;
        }
    }
}

/// Update scan status to failed with error message
async fn update_scan_failed(pool: &SqlitePool, scan_id: &str, error: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE windows_audit_scans SET status = 'failed', error_message = ? WHERE id = ?"
    )
    .bind(error)
    .bind(scan_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Audit check result
struct AuditCheckResult {
    check_id: String,
    stig_id: Option<String>,
    title: String,
    category: String,
    status: String,
    actual_value: Option<String>,
    expected_value: Option<String>,
    remediation: Option<String>,
}

/// Execute Windows STIG checks against target
async fn execute_windows_checks(
    _target_host: &str,
    _username: &str,
    _domain: Option<&str>,
    _stig_profile: Option<&str>,
) -> Result<Vec<AuditCheckResult>, anyhow::Error> {
    // In production, this would connect via WMI/WinRM and execute actual checks
    // For now, return sample STIG compliance checks

    let checks = vec![
        AuditCheckResult {
            check_id: "V-254239".to_string(),
            stig_id: Some("WN10-CC-000005".to_string()),
            title: "Camera access from the lock screen must be disabled".to_string(),
            category: "CAT II".to_string(),
            status: "pass".to_string(),
            actual_value: Some("0".to_string()),
            expected_value: Some("0".to_string()),
            remediation: None,
        },
        AuditCheckResult {
            check_id: "V-254240".to_string(),
            stig_id: Some("WN10-CC-000010".to_string()),
            title: "IPv6 source routing must be configured to the highest protection level".to_string(),
            category: "CAT II".to_string(),
            status: "pass".to_string(),
            actual_value: Some("2".to_string()),
            expected_value: Some("2".to_string()),
            remediation: None,
        },
        AuditCheckResult {
            check_id: "V-254241".to_string(),
            stig_id: Some("WN10-CC-000020".to_string()),
            title: "The Windows Remote Management (WinRM) client must not use Basic authentication".to_string(),
            category: "CAT I".to_string(),
            status: "fail".to_string(),
            actual_value: Some("1".to_string()),
            expected_value: Some("0".to_string()),
            remediation: Some("Set AllowBasic to 0 in HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client".to_string()),
        },
        AuditCheckResult {
            check_id: "V-254242".to_string(),
            stig_id: Some("WN10-SO-000030".to_string()),
            title: "The system must be configured to audit Account Logon - Credential Validation successes".to_string(),
            category: "CAT II".to_string(),
            status: "pass".to_string(),
            actual_value: Some("Success".to_string()),
            expected_value: Some("Success".to_string()),
            remediation: None,
        },
        AuditCheckResult {
            check_id: "V-254243".to_string(),
            stig_id: Some("WN10-SO-000040".to_string()),
            title: "Windows 10 must be configured to audit Logon/Logoff - Logon successes".to_string(),
            category: "CAT II".to_string(),
            status: "pass".to_string(),
            actual_value: Some("Success".to_string()),
            expected_value: Some("Success".to_string()),
            remediation: None,
        },
        AuditCheckResult {
            check_id: "V-254244".to_string(),
            stig_id: Some("WN10-AC-000005".to_string()),
            title: "Windows 10 account lockout duration must be configured to 15 minutes or greater".to_string(),
            category: "CAT II".to_string(),
            status: "fail".to_string(),
            actual_value: Some("10".to_string()),
            expected_value: Some("15".to_string()),
            remediation: Some("Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> Account lockout duration to 15 or greater.".to_string()),
        },
        AuditCheckResult {
            check_id: "V-254245".to_string(),
            stig_id: Some("WN10-AC-000010".to_string()),
            title: "The number of allowed bad logon attempts must be configured to 3 or less".to_string(),
            category: "CAT II".to_string(),
            status: "pass".to_string(),
            actual_value: Some("3".to_string()),
            expected_value: Some("3".to_string()),
            remediation: None,
        },
        AuditCheckResult {
            check_id: "V-254246".to_string(),
            stig_id: Some("WN10-PK-000005".to_string()),
            title: "The DoD Root CA certificates must be installed in the Trusted Root Store".to_string(),
            category: "CAT II".to_string(),
            status: "fail".to_string(),
            actual_value: Some("Not Found".to_string()),
            expected_value: Some("Installed".to_string()),
            remediation: Some("Install the DoD Root CA certificates using the InstallRoot tool or by importing them manually into the Trusted Root Certification Authorities store.".to_string()),
        },
    ];

    Ok(checks)
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
