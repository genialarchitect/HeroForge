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

    let (username, encrypted_password, domain, _auth_type) = match creds {
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

    let password = decrypt_sensitive(&encrypted_password);

    // Execute Windows audit checks via WinRM
    let audit_results = execute_windows_checks(target_host, &username, &password, domain.as_deref(), stig_profile).await;

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

/// STIG check definition: maps a STIG ID to a PowerShell command and expected result
struct StigCheckDef {
    check_id: &'static str,
    stig_id: &'static str,
    title: &'static str,
    category: &'static str,
    powershell_cmd: &'static str,
    expected_value: &'static str,
    remediation: &'static str,
}

/// Get STIG checks for the specified profile
fn get_stig_checks(profile: Option<&str>) -> Vec<StigCheckDef> {
    let _profile = profile.unwrap_or("windows10");

    vec![
        StigCheckDef {
            check_id: "V-254239",
            stig_id: "WN10-CC-000005",
            title: "Camera access from the lock screen must be disabled",
            category: "CAT II",
            powershell_cmd: r#"(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera' -ErrorAction SilentlyContinue).NoLockScreenCamera"#,
            expected_value: "1",
            remediation: "Set NoLockScreenCamera to 1 in HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization",
        },
        StigCheckDef {
            check_id: "V-254240",
            stig_id: "WN10-CC-000010",
            title: "IPv6 source routing must be configured to highest protection level",
            category: "CAT II",
            powershell_cmd: r#"(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIPSourceRouting' -ErrorAction SilentlyContinue).DisableIPSourceRouting"#,
            expected_value: "2",
            remediation: "Set DisableIPSourceRouting to 2 in HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
        },
        StigCheckDef {
            check_id: "V-254241",
            stig_id: "WN10-CC-000020",
            title: "WinRM client must not use Basic authentication",
            category: "CAT I",
            powershell_cmd: r#"(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowBasic' -ErrorAction SilentlyContinue).AllowBasic"#,
            expected_value: "0",
            remediation: "Set AllowBasic to 0 in HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client",
        },
        StigCheckDef {
            check_id: "V-254242",
            stig_id: "WN10-SO-000030",
            title: "Audit Account Logon - Credential Validation successes",
            category: "CAT II",
            powershell_cmd: r#"(auditpol /get /subcategory:'Credential Validation' /r | ConvertFrom-Csv | Select-Object -ExpandProperty 'Inclusion Setting')"#,
            expected_value: "Success",
            remediation: "Configure audit policy: Credential Validation to include Success",
        },
        StigCheckDef {
            check_id: "V-254243",
            stig_id: "WN10-SO-000040",
            title: "Audit Logon/Logoff - Logon successes",
            category: "CAT II",
            powershell_cmd: r#"(auditpol /get /subcategory:'Logon' /r | ConvertFrom-Csv | Select-Object -ExpandProperty 'Inclusion Setting')"#,
            expected_value: "Success",
            remediation: "Configure audit policy: Logon to include Success",
        },
        StigCheckDef {
            check_id: "V-254244",
            stig_id: "WN10-AC-000005",
            title: "Account lockout duration must be 15 minutes or greater",
            category: "CAT II",
            powershell_cmd: r#"(net accounts | Select-String 'Lockout duration').ToString().Split(':')[1].Trim()"#,
            expected_value: ">=15",
            remediation: "Set Account Lockout Duration to 15 or greater in Account Lockout Policy",
        },
        StigCheckDef {
            check_id: "V-254245",
            stig_id: "WN10-AC-000010",
            title: "Bad logon attempts must be configured to 3 or less",
            category: "CAT II",
            powershell_cmd: r#"(net accounts | Select-String 'Lockout threshold').ToString().Split(':')[1].Trim()"#,
            expected_value: "<=3",
            remediation: "Set Account Lockout Threshold to 3 or less in Account Lockout Policy",
        },
        StigCheckDef {
            check_id: "V-254246",
            stig_id: "WN10-CC-000030",
            title: "Autoplay must be turned off for all drives",
            category: "CAT II",
            powershell_cmd: r#"(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun"#,
            expected_value: "255",
            remediation: "Set NoDriveTypeAutoRun to 255 in Explorer policies",
        },
        StigCheckDef {
            check_id: "V-254247",
            stig_id: "WN10-CC-000035",
            title: "Windows Defender SmartScreen must be enabled",
            category: "CAT II",
            powershell_cmd: r#"(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -ErrorAction SilentlyContinue).EnableSmartScreen"#,
            expected_value: "1",
            remediation: "Set EnableSmartScreen to 1 in HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
        },
        StigCheckDef {
            check_id: "V-254248",
            stig_id: "WN10-SO-000050",
            title: "Windows Firewall must be enabled for Domain profile",
            category: "CAT I",
            powershell_cmd: r#"(Get-NetFirewallProfile -Profile Domain).Enabled"#,
            expected_value: "True",
            remediation: "Enable Windows Firewall for the Domain profile",
        },
    ]
}

/// Execute a PowerShell command on the target via WinRM (WSMan SOAP protocol)
async fn winrm_execute(
    target_host: &str,
    username: &str,
    password: &str,
    domain: Option<&str>,
    command: &str,
) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true) // Internal network targets may use self-signed certs
        .build()
        .map_err(|e| format!("HTTP client creation failed: {}", e))?;

    // Try HTTPS (5986) first, then HTTP (5985)
    let urls = vec![
        format!("https://{}:5986/wsman", target_host),
        format!("http://{}:5985/wsman", target_host),
    ];

    let mut last_error = String::from("No WinRM endpoint reachable");

    for url in &urls {
        // Encode the PowerShell command in base64 for -EncodedCommand
        let ps_bytes: Vec<u8> = command.encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        use base64::{Engine, engine::general_purpose::STANDARD};
        let encoded_cmd = STANDARD.encode(&ps_bytes);

        // Build the WinRM SOAP envelope to create a shell and run a command
        let message_id = uuid::Uuid::new_v4().to_string();
        let shell_id = uuid::Uuid::new_v4().to_string().to_uppercase();

        // Step 1: Create shell
        let create_shell_soap = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <wsa:To>{url}</wsa:To>
    <wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</wsa:Action>
    <wsa:MessageID>uuid:{message_id}</wsa:MessageID>
    <wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
    <wsman:OperationTimeout>PT60S</wsman:OperationTimeout>
  </s:Header>
  <s:Body>
    <rsp:Shell ShellId="{shell_id}">
      <rsp:InputStreams>stdin</rsp:InputStreams>
      <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
    </rsp:Shell>
  </s:Body>
</s:Envelope>"#,
            url = url, message_id = message_id, shell_id = shell_id
        );

        // Build auth header
        let auth_user = if let Some(dom) = domain {
            format!("{}\\{}", dom, username)
        } else {
            username.to_string()
        };

        let auth_header = format!("Basic {}", STANDARD.encode(format!("{}:{}", auth_user, password)));

        // Create shell
        let create_resp = match client.post(url)
            .header("Content-Type", "application/soap+xml;charset=UTF-8")
            .header("Authorization", &auth_header)
            .body(create_shell_soap)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                last_error = format!("WinRM connection to {} failed: {}", url, e);
                continue;
            }
        };

        if !create_resp.status().is_success() {
            let status = create_resp.status();
            let body = create_resp.text().await.unwrap_or_default();
            last_error = format!("WinRM shell creation failed (HTTP {}): {}", status, &body[..body.len().min(200)]);
            continue;
        }

        let shell_body = create_resp.text().await.unwrap_or_default();

        // Extract actual ShellId from response (server may assign different ID)
        let actual_shell_id = extract_xml_value(&shell_body, "ShellId")
            .unwrap_or_else(|| shell_id.clone());

        // Step 2: Execute command
        let cmd_id = uuid::Uuid::new_v4().to_string().to_uppercase();
        let exec_msg_id = uuid::Uuid::new_v4().to_string();

        let execute_soap = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <wsa:To>{url}</wsa:To>
    <wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsa:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</wsa:Action>
    <wsa:MessageID>uuid:{msg_id}</wsa:MessageID>
    <wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
    <wsman:SelectorSet><wsman:Selector Name="ShellId">{shell_id}</wsman:Selector></wsman:SelectorSet>
    <wsman:OperationTimeout>PT60S</wsman:OperationTimeout>
  </s:Header>
  <s:Body>
    <rsp:CommandLine CommandId="{cmd_id}">
      <rsp:Command>powershell.exe</rsp:Command>
      <rsp:Arguments>-NoProfile -NonInteractive -EncodedCommand {encoded_cmd}</rsp:Arguments>
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>"#,
            url = url, msg_id = exec_msg_id, shell_id = actual_shell_id,
            cmd_id = cmd_id, encoded_cmd = encoded_cmd
        );

        let exec_resp = match client.post(url)
            .header("Content-Type", "application/soap+xml;charset=UTF-8")
            .header("Authorization", &auth_header)
            .body(execute_soap)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                last_error = format!("WinRM command execution failed: {}", e);
                // Try to delete shell
                let _ = winrm_delete_shell(&client, url, &auth_header, &actual_shell_id).await;
                continue;
            }
        };

        if !exec_resp.status().is_success() {
            let status = exec_resp.status();
            last_error = format!("WinRM command failed (HTTP {})", status);
            let _ = winrm_delete_shell(&client, url, &auth_header, &actual_shell_id).await;
            continue;
        }

        // Step 3: Receive output
        let recv_msg_id = uuid::Uuid::new_v4().to_string();
        let receive_soap = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <wsa:To>{url}</wsa:To>
    <wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsa:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</wsa:Action>
    <wsa:MessageID>uuid:{msg_id}</wsa:MessageID>
    <wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
    <wsman:SelectorSet><wsman:Selector Name="ShellId">{shell_id}</wsman:Selector></wsman:SelectorSet>
    <wsman:OperationTimeout>PT60S</wsman:OperationTimeout>
  </s:Header>
  <s:Body>
    <rsp:Receive>
      <rsp:DesiredStream CommandId="{cmd_id}">stdout stderr</rsp:DesiredStream>
    </rsp:Receive>
  </s:Body>
</s:Envelope>"#,
            url = url, msg_id = recv_msg_id, shell_id = actual_shell_id, cmd_id = cmd_id
        );

        let recv_resp = client.post(url)
            .header("Content-Type", "application/soap+xml;charset=UTF-8")
            .header("Authorization", &auth_header)
            .body(receive_soap)
            .send()
            .await;

        // Step 4: Delete shell (cleanup)
        let _ = winrm_delete_shell(&client, url, &auth_header, &actual_shell_id).await;

        match recv_resp {
            Ok(r) if r.status().is_success() => {
                let body = r.text().await.unwrap_or_default();
                // Extract stdout from the SOAP response
                let output = extract_stream_output(&body);
                return Ok(output);
            }
            Ok(r) => {
                last_error = format!("WinRM receive failed (HTTP {})", r.status());
                continue;
            }
            Err(e) => {
                last_error = format!("WinRM receive error: {}", e);
                continue;
            }
        }
    }

    Err(last_error)
}

/// Delete a WinRM shell (cleanup)
async fn winrm_delete_shell(
    client: &reqwest::Client,
    url: &str,
    auth_header: &str,
    shell_id: &str,
) -> Result<(), ()> {
    let msg_id = uuid::Uuid::new_v4().to_string();
    let delete_soap = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <wsa:To>{url}</wsa:To>
    <wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</wsa:Action>
    <wsa:MessageID>uuid:{msg_id}</wsa:MessageID>
    <wsman:SelectorSet><wsman:Selector Name="ShellId">{shell_id}</wsman:Selector></wsman:SelectorSet>
  </s:Header>
  <s:Body/>
</s:Envelope>"#,
        url = url, msg_id = msg_id, shell_id = shell_id
    );

    client.post(url)
        .header("Content-Type", "application/soap+xml;charset=UTF-8")
        .header("Authorization", auth_header)
        .body(delete_soap)
        .send()
        .await
        .map(|_| ())
        .map_err(|_| ())
}

/// Extract a value from XML by tag name (simple text extraction)
fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    // Look for <tag>value</tag> or <ns:tag>value</ns:tag>
    let patterns = vec![
        format!("<{}>", tag),
        format!("<rsp:{}>", tag),
        format!("<wsman:{}>", tag),
    ];

    for start_tag in &patterns {
        if let Some(start) = xml.find(start_tag.as_str()) {
            let value_start = start + start_tag.len();
            let end_patterns = vec![
                format!("</{}>", tag),
                format!("</rsp:{}>", tag),
                format!("</wsman:{}>", tag),
            ];
            for end_tag in &end_patterns {
                if let Some(end) = xml[value_start..].find(end_tag.as_str()) {
                    return Some(xml[value_start..value_start + end].to_string());
                }
            }
        }
    }
    None
}

/// Extract stdout stream output from WinRM Receive response
fn extract_stream_output(xml: &str) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let mut output = String::new();

    // Find all <rsp:Stream Name="stdout" ...>base64data</rsp:Stream>
    let stdout_marker = "Name=\"stdout\"";
    let mut search_from = 0;

    while let Some(pos) = xml[search_from..].find(stdout_marker) {
        let abs_pos = search_from + pos + stdout_marker.len();
        // Find the closing > of the Stream tag
        if let Some(tag_end) = xml[abs_pos..].find('>') {
            let content_start = abs_pos + tag_end + 1;
            // Find closing </rsp:Stream>
            if let Some(content_end) = xml[content_start..].find("</rsp:Stream>") {
                let b64_data = &xml[content_start..content_start + content_end];
                let b64_clean: String = b64_data.chars().filter(|c| !c.is_whitespace()).collect();
                if let Ok(decoded) = STANDARD.decode(&b64_clean) {
                    if let Ok(text) = String::from_utf8(decoded) {
                        output.push_str(&text);
                    }
                }
                search_from = content_start + content_end;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    output.trim().to_string()
}

/// Evaluate a STIG check result against expected value
fn evaluate_stig_result(actual: &str, expected: &str) -> bool {
    let actual_trimmed = actual.trim();

    // Handle comparison operators
    if let Some(val) = expected.strip_prefix(">=") {
        if let (Ok(a), Ok(e)) = (actual_trimmed.parse::<i64>(), val.trim().parse::<i64>()) {
            return a >= e;
        }
    }
    if let Some(val) = expected.strip_prefix("<=") {
        if let (Ok(a), Ok(e)) = (actual_trimmed.parse::<i64>(), val.trim().parse::<i64>()) {
            return a <= e;
        }
    }

    // Handle "contains" check
    if let Some(val) = expected.strip_prefix("contains:") {
        return actual_trimmed.to_lowercase().contains(&val.to_lowercase());
    }

    // Direct comparison (case-insensitive)
    actual_trimmed.eq_ignore_ascii_case(expected.trim())
}

/// Execute Windows STIG checks against target via WinRM
async fn execute_windows_checks(
    target_host: &str,
    username: &str,
    password: &str,
    domain: Option<&str>,
    stig_profile: Option<&str>,
) -> Result<Vec<AuditCheckResult>, anyhow::Error> {
    let checks = get_stig_checks(stig_profile);
    let mut results = Vec::new();

    for check in &checks {
        let result = match winrm_execute(target_host, username, password, domain, check.powershell_cmd).await {
            Ok(output) => {
                let actual = output.trim().to_string();
                let passed = evaluate_stig_result(&actual, check.expected_value);

                AuditCheckResult {
                    check_id: check.check_id.to_string(),
                    stig_id: Some(check.stig_id.to_string()),
                    title: check.title.to_string(),
                    category: check.category.to_string(),
                    status: if passed { "pass".to_string() } else { "fail".to_string() },
                    actual_value: Some(if actual.is_empty() { "Not Configured".to_string() } else { actual }),
                    expected_value: Some(check.expected_value.to_string()),
                    remediation: if passed { None } else { Some(check.remediation.to_string()) },
                }
            }
            Err(e) => {
                log::warn!("WinRM check {} failed: {}", check.check_id, e);
                AuditCheckResult {
                    check_id: check.check_id.to_string(),
                    stig_id: Some(check.stig_id.to_string()),
                    title: check.title.to_string(),
                    category: check.category.to_string(),
                    status: "error".to_string(),
                    actual_value: Some(format!("Error: {}", e)),
                    expected_value: Some(check.expected_value.to_string()),
                    remediation: Some(check.remediation.to_string()),
                }
            }
        };

        results.push(result);
    }

    if results.is_empty() {
        return Err(anyhow::anyhow!(
            "WinRM connection failed on ports 5985/5986 for target {}. Ensure WinRM is enabled and credentials are correct.",
            target_host
        ));
    }

    Ok(results)
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
