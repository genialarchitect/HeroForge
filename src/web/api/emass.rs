//! eMASS Integration API Endpoints
//!
//! Provides API endpoints for eMASS connection management, system mappings,
//! control synchronization, and POA&M lifecycle management.

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::web::auth::Claims;

// ============================================================================
// Encryption Helpers
// ============================================================================

/// Encrypt sensitive field for storage
/// Uses TOTP_ENCRYPTION_KEY env var if available
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

/// eMASS connection settings response
#[derive(Debug, Serialize)]
pub struct EmassSettings {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub base_url: String,
    pub use_cac: bool,
    pub timeout_seconds: i32,
    pub is_active: bool,
    pub last_connected: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
}

/// Create/update eMASS settings request
#[derive(Debug, Deserialize)]
pub struct CreateEmassSettingsRequest {
    pub name: String,
    pub description: Option<String>,
    pub base_url: String,
    pub api_key: Option<String>,
    pub cert_path: Option<String>,
    pub cert_password: Option<String>,
    pub use_cac: Option<bool>,
    pub ca_bundle_path: Option<String>,
    pub timeout_seconds: Option<i32>,
}

/// eMASS system mapping
#[derive(Debug, Serialize)]
pub struct EmassSystemMapping {
    pub id: String,
    pub settings_id: String,
    pub emass_system_id: String,
    pub emass_system_name: String,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub is_active: bool,
    pub last_sync: Option<String>,
    pub created_at: String,
}

/// Create system mapping request
#[derive(Debug, Deserialize)]
pub struct CreateSystemMappingRequest {
    pub settings_id: String,
    pub emass_system_id: String,
    pub emass_system_name: String,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Sync history entry
#[derive(Debug, Serialize)]
pub struct EmaSyncHistory {
    pub id: String,
    pub mapping_id: String,
    pub sync_type: String,
    pub direction: String,
    pub status: String,
    pub controls_synced: i32,
    pub poams_created: i32,
    pub poams_updated: i32,
    pub error_message: Option<String>,
    pub started_at: String,
    pub completed_at: Option<String>,
}

/// POA&M cache entry
#[derive(Debug, Serialize)]
pub struct EmassPoamCache {
    pub id: String,
    pub mapping_id: String,
    pub poam_id: String,
    pub control_acronym: String,
    pub status: String,
    pub weakness_description: String,
    pub scheduled_completion_date: Option<String>,
    pub last_synced: String,
}

/// Close POA&M request
#[derive(Debug, Deserialize)]
pub struct ClosePoamRequest {
    pub completion_comments: String,
    pub evidence_ids: Option<Vec<String>>,
}

// ============================================================================
// Handlers
// ============================================================================

/// List eMASS settings
pub async fn list_emass_settings(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let settings = sqlx::query_as::<_, (String, String, Option<String>, String, bool, i32, bool, Option<String>, Option<String>, String)>(
        r#"
        SELECT id, name, description, base_url, use_cac, timeout_seconds, is_active,
               last_connected, last_error, created_at
        FROM emass_settings
        ORDER BY name
        "#
    )
    .fetch_all(pool.get_ref())
    .await;

    match settings {
        Ok(rows) => {
            let settings: Vec<EmassSettings> = rows
                .into_iter()
                .map(|r| EmassSettings {
                    id: r.0,
                    name: r.1,
                    description: r.2,
                    base_url: r.3,
                    use_cac: r.4,
                    timeout_seconds: r.5,
                    is_active: r.6,
                    last_connected: r.7,
                    last_error: r.8,
                    created_at: r.9,
                })
                .collect();
            HttpResponse::Ok().json(settings)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Get eMASS settings by ID
pub async fn get_emass_settings(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let settings_id = path.into_inner();

    let settings = sqlx::query_as::<_, (String, String, Option<String>, String, bool, i32, bool, Option<String>, Option<String>, String)>(
        r#"
        SELECT id, name, description, base_url, use_cac, timeout_seconds, is_active,
               last_connected, last_error, created_at
        FROM emass_settings WHERE id = ?
        "#
    )
    .bind(&settings_id)
    .fetch_optional(pool.get_ref())
    .await;

    match settings {
        Ok(Some(r)) => HttpResponse::Ok().json(EmassSettings {
            id: r.0,
            name: r.1,
            description: r.2,
            base_url: r.3,
            use_cac: r.4,
            timeout_seconds: r.5,
            is_active: r.6,
            last_connected: r.7,
            last_error: r.8,
            created_at: r.9,
        }),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Settings not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Create eMASS settings
pub async fn create_emass_settings(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateEmassSettingsRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let settings_id = uuid::Uuid::new_v4().to_string();
    let use_cac = body.use_cac.unwrap_or(false);
    let timeout = body.timeout_seconds.unwrap_or(30);

    // Encrypt sensitive fields before storage
    let encrypted_api_key = body.api_key.as_ref().map(|k| encrypt_sensitive(k));
    let encrypted_cert_password = body.cert_password.as_ref().map(|p| encrypt_sensitive(p));

    let result = sqlx::query(
        r#"
        INSERT INTO emass_settings (id, name, description, base_url, api_key_encrypted,
                                    cert_path, cert_password_encrypted, use_cac, ca_bundle_path,
                                    timeout_seconds, is_active, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, datetime('now'))
        "#
    )
    .bind(&settings_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.base_url)
    .bind(&encrypted_api_key)
    .bind(&body.cert_path)
    .bind(&encrypted_cert_password)
    .bind(use_cac)
    .bind(&body.ca_bundle_path)
    .bind(timeout)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": settings_id,
            "message": "eMASS settings created successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Update eMASS settings
pub async fn update_emass_settings(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<CreateEmassSettingsRequest>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let settings_id = path.into_inner();
    let use_cac = body.use_cac.unwrap_or(false);
    let timeout = body.timeout_seconds.unwrap_or(30);

    let result = sqlx::query(
        r#"
        UPDATE emass_settings SET name = ?, description = ?, base_url = ?, api_key_encrypted = ?,
                                  cert_path = ?, cert_password_encrypted = ?, use_cac = ?,
                                  ca_bundle_path = ?, timeout_seconds = ?, updated_at = datetime('now')
        WHERE id = ?
        "#
    )
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.base_url)
    .bind(&body.api_key)
    .bind(&body.cert_path)
    .bind(&body.cert_password)
    .bind(use_cac)
    .bind(&body.ca_bundle_path)
    .bind(timeout)
    .bind(&settings_id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => HttpResponse::Ok().json(serde_json::json!({
            "message": "Settings updated successfully"
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "Settings not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Delete eMASS settings
pub async fn delete_emass_settings(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let settings_id = path.into_inner();

    let result = sqlx::query("DELETE FROM emass_settings WHERE id = ?")
        .bind(&settings_id)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => HttpResponse::Ok().json(serde_json::json!({
            "message": "Settings deleted successfully"
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "Settings not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Test eMASS connection
pub async fn test_connection(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let settings_id = path.into_inner();

    // Get full settings including credentials
    let settings = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, bool, i32)>(
        "SELECT id, base_url, api_key_encrypted, cert_path, use_cac, timeout_seconds FROM emass_settings WHERE id = ?"
    )
    .bind(&settings_id)
    .fetch_optional(pool.get_ref())
    .await;

    match settings {
        Ok(Some(s)) => {
            let (_id, base_url, api_key_encrypted, cert_path, use_cac, timeout_secs) = s;

            // Decrypt API key if present
            let api_key = api_key_encrypted.map(|k| decrypt_sensitive(&k));

            // Perform actual connection test
            let test_result = test_emass_connection_impl(
                &base_url,
                api_key.as_deref(),
                cert_path.as_deref(),
                use_cac,
                timeout_secs as u64,
            ).await;

            match test_result {
                Ok(response_info) => {
                    // Update last_connected timestamp
                    let _ = sqlx::query(
                        "UPDATE emass_settings SET last_connected = datetime('now'), last_error = NULL WHERE id = ?"
                    )
                    .bind(&settings_id)
                    .execute(pool.get_ref())
                    .await;

                    HttpResponse::Ok().json(serde_json::json!({
                        "status": "success",
                        "message": "Connection test passed",
                        "details": response_info
                    }))
                }
                Err(error_msg) => {
                    // Update last_error
                    let _ = sqlx::query(
                        "UPDATE emass_settings SET last_error = ? WHERE id = ?"
                    )
                    .bind(&error_msg)
                    .bind(&settings_id)
                    .execute(pool.get_ref())
                    .await;

                    HttpResponse::Ok().json(serde_json::json!({
                        "status": "failed",
                        "message": "Connection test failed",
                        "error": error_msg
                    }))
                }
            }
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Settings not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Implementation of eMASS connection test
async fn test_emass_connection_impl(
    base_url: &str,
    api_key: Option<&str>,
    cert_path: Option<&str>,
    use_cac: bool,
    timeout_secs: u64,
) -> Result<serde_json::Value, String> {
    use reqwest::Client;
    use std::time::Duration;

    // Build HTTP client with appropriate configuration
    let mut client_builder = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(false); // Enforce certificate validation

    // If using CAC/certificate authentication, configure the client
    if use_cac {
        if let Some(cert) = cert_path {
            // Read certificate file
            let cert_data = match tokio::fs::read(cert).await {
                Ok(data) => data,
                Err(e) => return Err(format!("Failed to read certificate: {}", e)),
            };

            // Try to parse as PKCS#12 identity
            match reqwest::Identity::from_pkcs12_der(&cert_data, "") {
                Ok(identity) => {
                    client_builder = client_builder.identity(identity);
                }
                Err(e) => {
                    return Err(format!("Failed to parse certificate: {}", e));
                }
            }
        }
    }

    let client = match client_builder.build() {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to build HTTP client: {}", e)),
    };

    // Build request to eMASS system endpoint
    // eMASS API typically has a /api/systems endpoint for listing available systems
    let url = format!("{}/api/systems", base_url.trim_end_matches('/'));

    let mut request = client.get(&url);

    // Add API key header if provided
    if let Some(key) = api_key {
        request = request.header("api-key", key);
    }

    // Add standard headers
    request = request
        .header("Accept", "application/json")
        .header("Content-Type", "application/json");

    // Execute request
    match request.send().await {
        Ok(response) => {
            let status = response.status();
            let status_code = status.as_u16();

            if status.is_success() {
                // Try to parse response
                match response.json::<serde_json::Value>().await {
                    Ok(body) => {
                        // Extract useful info from response
                        let system_count = body.get("data")
                            .and_then(|d| d.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);

                        Ok(serde_json::json!({
                            "status_code": status_code,
                            "systems_accessible": system_count,
                            "api_version": body.get("meta").and_then(|m| m.get("version")),
                        }))
                    }
                    Err(_) => {
                        // Response was successful but couldn't parse body
                        Ok(serde_json::json!({
                            "status_code": status_code,
                            "note": "Connected successfully but response format unexpected"
                        }))
                    }
                }
            } else if status_code == 401 || status_code == 403 {
                Err(format!("Authentication failed (HTTP {}): Check API key or certificate credentials", status_code))
            } else if status_code == 404 {
                Err(format!("eMASS API endpoint not found (HTTP 404): Verify base URL is correct"))
            } else {
                let error_body = response.text().await.unwrap_or_default();
                Err(format!("eMASS returned HTTP {}: {}", status_code, error_body))
            }
        }
        Err(e) => {
            if e.is_timeout() {
                Err(format!("Connection timed out after {} seconds", timeout_secs))
            } else if e.is_connect() {
                Err(format!("Failed to connect to {}: {}", base_url, e))
            } else {
                Err(format!("Request failed: {}", e))
            }
        }
    }
}

/// Perform eMASS sync operation asynchronously
async fn perform_emass_sync(
    pool: &SqlitePool,
    sync_id: &str,
    mapping_id: &str,
    emass_system_id: &str,
) {
    use reqwest::Client;
    use std::time::Duration;

    let mut controls_synced = 0i32;
    let mut poams_created = 0i32;
    let mut poams_updated = 0i32;

    // Get the settings associated with this mapping
    let settings = sqlx::query_as::<_, (String, Option<String>, Option<String>, bool, i32)>(
        r#"
        SELECT s.base_url, s.api_key_encrypted, s.cert_path, s.use_cac, s.timeout_seconds
        FROM emass_settings s
        JOIN emass_system_mappings m ON m.settings_id = s.id
        WHERE m.id = ?
        "#
    )
    .bind(mapping_id)
    .fetch_optional(pool)
    .await;

    let (base_url, api_key_encrypted, _cert_path, _use_cac, timeout_secs) = match settings {
        Ok(Some(s)) => s,
        Ok(None) => {
            update_sync_failed(pool, sync_id, "Settings not found for mapping").await;
            return;
        }
        Err(e) => {
            update_sync_failed(pool, sync_id, &format!("Database error: {}", e)).await;
            return;
        }
    };

    let api_key = api_key_encrypted.map(|k| decrypt_sensitive(&k));

    // Build HTTP client
    let client = match Client::builder()
        .timeout(Duration::from_secs(timeout_secs as u64))
        .build() {
        Ok(c) => c,
        Err(e) => {
            update_sync_failed(pool, sync_id, &format!("Failed to build HTTP client: {}", e)).await;
            return;
        }
    };

    // Step 1: Fetch POA&Ms from eMASS
    let poams_url = format!("{}/api/systems/{}/poams", base_url.trim_end_matches('/'), emass_system_id);

    let mut request = client.get(&poams_url);
    if let Some(key) = &api_key {
        request = request.header("api-key", key);
    }
    request = request.header("Accept", "application/json");

    match request.send().await {
        Ok(response) if response.status().is_success() => {
            if let Ok(body) = response.json::<serde_json::Value>().await {
                // Process POA&Ms from response
                if let Some(poams) = body.get("data").and_then(|d| d.as_array()) {
                    for poam in poams {
                        let poam_id = poam.get("poamId").and_then(|v| v.as_i64()).unwrap_or(0).to_string();
                        let control_acronym = poam.get("controlAcronym").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
                        let status = poam.get("status").and_then(|v| v.as_str()).unwrap_or("Open").to_string();
                        let weakness_desc = poam.get("weaknessDescription").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let scheduled_completion = poam.get("scheduledCompletionDate").and_then(|v| v.as_str()).map(|s| s.to_string());

                        // Check if POA&M already exists in cache
                        let existing = sqlx::query_as::<_, (String,)>(
                            "SELECT id FROM emass_poam_cache WHERE mapping_id = ? AND poam_id = ?"
                        )
                        .bind(mapping_id)
                        .bind(&poam_id)
                        .fetch_optional(pool)
                        .await;

                        match existing {
                            Ok(Some((cache_id,))) => {
                                // Update existing POA&M
                                let _ = sqlx::query(
                                    r#"
                                    UPDATE emass_poam_cache
                                    SET control_acronym = ?, status = ?, weakness_description = ?,
                                        scheduled_completion_date = ?, last_synced = datetime('now')
                                    WHERE id = ?
                                    "#
                                )
                                .bind(&control_acronym)
                                .bind(&status)
                                .bind(&weakness_desc)
                                .bind(&scheduled_completion)
                                .bind(&cache_id)
                                .execute(pool)
                                .await;

                                poams_updated += 1;
                            }
                            Ok(None) => {
                                // Insert new POA&M
                                let cache_id = uuid::Uuid::new_v4().to_string();
                                let _ = sqlx::query(
                                    r#"
                                    INSERT INTO emass_poam_cache (id, mapping_id, poam_id, control_acronym, status,
                                                                  weakness_description, scheduled_completion_date, last_synced)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                                    "#
                                )
                                .bind(&cache_id)
                                .bind(mapping_id)
                                .bind(&poam_id)
                                .bind(&control_acronym)
                                .bind(&status)
                                .bind(&weakness_desc)
                                .bind(&scheduled_completion)
                                .execute(pool)
                                .await;

                                poams_created += 1;
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        }
        Ok(response) => {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            update_sync_failed(pool, sync_id, &format!("Failed to fetch POA&Ms: HTTP {} - {}", status, error_body)).await;
            return;
        }
        Err(e) => {
            update_sync_failed(pool, sync_id, &format!("Failed to connect to eMASS: {}", e)).await;
            return;
        }
    }

    // Step 2: Fetch controls from eMASS
    let controls_url = format!("{}/api/systems/{}/controls", base_url.trim_end_matches('/'), emass_system_id);

    let mut request = client.get(&controls_url);
    if let Some(key) = &api_key {
        request = request.header("api-key", key);
    }
    request = request.header("Accept", "application/json");

    match request.send().await {
        Ok(response) if response.status().is_success() => {
            if let Ok(body) = response.json::<serde_json::Value>().await {
                if let Some(controls) = body.get("data").and_then(|d| d.as_array()) {
                    controls_synced = controls.len() as i32;
                }
            }
        }
        Ok(_) | Err(_) => {
            // Controls sync failure is non-fatal, POA&Ms are more important
            log::warn!("Failed to sync controls for mapping {}", mapping_id);
        }
    }

    // Update mapping last_sync timestamp
    let _ = sqlx::query(
        "UPDATE emass_system_mappings SET last_sync = datetime('now') WHERE id = ?"
    )
    .bind(mapping_id)
    .execute(pool)
    .await;

    // Mark sync as completed
    let _ = sqlx::query(
        r#"
        UPDATE emass_sync_history
        SET status = 'completed', controls_synced = ?, poams_created = ?, poams_updated = ?,
            completed_at = datetime('now')
        WHERE id = ?
        "#
    )
    .bind(controls_synced)
    .bind(poams_created)
    .bind(poams_updated)
    .bind(sync_id)
    .execute(pool)
    .await;

    log::info!(
        "eMASS sync {} completed: {} controls, {} POA&Ms created, {} POA&Ms updated",
        sync_id, controls_synced, poams_created, poams_updated
    );
}

/// Update sync history with failure status
async fn update_sync_failed(pool: &SqlitePool, sync_id: &str, error_message: &str) {
    let _ = sqlx::query(
        r#"
        UPDATE emass_sync_history
        SET status = 'failed', error_message = ?, completed_at = datetime('now')
        WHERE id = ?
        "#
    )
    .bind(error_message)
    .bind(sync_id)
    .execute(pool)
    .await;

    log::error!("eMASS sync {} failed: {}", sync_id, error_message);
}

/// List system mappings
pub async fn list_system_mappings(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let mappings = sqlx::query_as::<_, (String, String, String, String, Option<String>, Option<String>, bool, Option<String>, String)>(
        r#"
        SELECT id, settings_id, emass_system_id, emass_system_name, customer_id,
               engagement_id, is_active, last_sync, created_at
        FROM emass_system_mappings
        ORDER BY emass_system_name
        "#
    )
    .fetch_all(pool.get_ref())
    .await;

    match mappings {
        Ok(rows) => {
            let mappings: Vec<EmassSystemMapping> = rows
                .into_iter()
                .map(|r| EmassSystemMapping {
                    id: r.0,
                    settings_id: r.1,
                    emass_system_id: r.2,
                    emass_system_name: r.3,
                    customer_id: r.4,
                    engagement_id: r.5,
                    is_active: r.6,
                    last_sync: r.7,
                    created_at: r.8,
                })
                .collect();
            HttpResponse::Ok().json(mappings)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Create system mapping
pub async fn create_system_mapping(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateSystemMappingRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let mapping_id = uuid::Uuid::new_v4().to_string();

    let result = sqlx::query(
        r#"
        INSERT INTO emass_system_mappings (id, settings_id, emass_system_id, emass_system_name,
                                           customer_id, engagement_id, is_active, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, datetime('now'))
        "#
    )
    .bind(&mapping_id)
    .bind(&body.settings_id)
    .bind(&body.emass_system_id)
    .bind(&body.emass_system_name)
    .bind(&body.customer_id)
    .bind(&body.engagement_id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": mapping_id,
            "message": "System mapping created successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Trigger sync for a mapping
pub async fn trigger_sync(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let mapping_id = path.into_inner();

    // Verify mapping exists
    let mapping = sqlx::query_as::<_, (String, String)>(
        "SELECT id, emass_system_id FROM emass_system_mappings WHERE id = ?"
    )
    .bind(&mapping_id)
    .fetch_optional(pool.get_ref())
    .await;

    match mapping {
        Ok(Some(m)) => {
            let (_, emass_system_id) = m;

            // Create sync history entry
            let sync_id = uuid::Uuid::new_v4().to_string();
            let _ = sqlx::query(
                r#"
                INSERT INTO emass_sync_history (id, mapping_id, sync_type, direction, status,
                                                controls_synced, poams_created, poams_updated,
                                                created_by, started_at)
                VALUES (?, ?, 'full', 'bidirectional', 'running', 0, 0, 0, ?, datetime('now'))
                "#
            )
            .bind(&sync_id)
            .bind(&mapping_id)
            .bind(&claims.sub)
            .execute(pool.get_ref())
            .await;

            // Spawn async task to perform the actual sync
            let pool_clone = pool.get_ref().clone();
            let sync_id_clone = sync_id.clone();
            let mapping_id_clone = mapping_id.clone();

            tokio::spawn(async move {
                perform_emass_sync(&pool_clone, &sync_id_clone, &mapping_id_clone, &emass_system_id).await;
            });

            HttpResponse::Accepted().json(serde_json::json!({
                "sync_id": sync_id,
                "status": "running",
                "message": "Sync started"
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Mapping not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Get sync history
pub async fn get_sync_history(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let mapping_id = path.into_inner();

    let history = sqlx::query_as::<_, (String, String, String, String, String, i32, i32, i32, Option<String>, String, Option<String>)>(
        r#"
        SELECT id, mapping_id, sync_type, direction, status, controls_synced,
               poams_created, poams_updated, error_message, started_at, completed_at
        FROM emass_sync_history WHERE mapping_id = ?
        ORDER BY started_at DESC
        LIMIT 50
        "#
    )
    .bind(&mapping_id)
    .fetch_all(pool.get_ref())
    .await;

    match history {
        Ok(rows) => {
            let history: Vec<EmaSyncHistory> = rows
                .into_iter()
                .map(|r| EmaSyncHistory {
                    id: r.0,
                    mapping_id: r.1,
                    sync_type: r.2,
                    direction: r.3,
                    status: r.4,
                    controls_synced: r.5,
                    poams_created: r.6,
                    poams_updated: r.7,
                    error_message: r.8,
                    started_at: r.9,
                    completed_at: r.10,
                })
                .collect();
            HttpResponse::Ok().json(history)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// List POA&Ms for a mapping
pub async fn list_poams(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let mapping_id = path.into_inner();

    let poams = sqlx::query_as::<_, (String, String, String, String, String, String, Option<String>, String)>(
        r#"
        SELECT id, mapping_id, poam_id, control_acronym, status, weakness_description,
               scheduled_completion_date, last_synced
        FROM emass_poam_cache WHERE mapping_id = ?
        ORDER BY control_acronym
        "#
    )
    .bind(&mapping_id)
    .fetch_all(pool.get_ref())
    .await;

    match poams {
        Ok(rows) => {
            let poams: Vec<EmassPoamCache> = rows
                .into_iter()
                .map(|r| EmassPoamCache {
                    id: r.0,
                    mapping_id: r.1,
                    poam_id: r.2,
                    control_acronym: r.3,
                    status: r.4,
                    weakness_description: r.5,
                    scheduled_completion_date: r.6,
                    last_synced: r.7,
                })
                .collect();
            HttpResponse::Ok().json(poams)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Close POA&M
pub async fn close_poam(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<ClosePoamRequest>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let poam_cache_id = path.into_inner();

    // Get POA&M details along with eMASS settings
    let poam_data = sqlx::query_as::<_, (String, String, String, String, String, Option<String>, i32)>(
        r#"
        SELECT p.id, p.poam_id, p.mapping_id, m.emass_system_id, s.base_url, s.api_key_encrypted, s.timeout_seconds
        FROM emass_poam_cache p
        JOIN emass_system_mappings m ON p.mapping_id = m.id
        JOIN emass_settings s ON m.settings_id = s.id
        WHERE p.id = ?
        "#
    )
    .bind(&poam_cache_id)
    .fetch_optional(pool.get_ref())
    .await;

    match poam_data {
        Ok(Some((cache_id, poam_id, mapping_id, system_id, base_url, api_key_encrypted, timeout_secs))) => {
            use reqwest::Client;
            use std::time::Duration;

            let api_key = api_key_encrypted.map(|k| decrypt_sensitive(&k));

            // Build HTTP client
            let client = match Client::builder()
                .timeout(Duration::from_secs(timeout_secs as u64))
                .build() {
                Ok(c) => c,
                Err(e) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": format!("Failed to build HTTP client: {}", e)
                    }));
                }
            };

            // Build the close request to eMASS
            // eMASS API uses PUT to /api/systems/{systemId}/poams/{poamId} to update
            let url = format!(
                "{}/api/systems/{}/poams/{}",
                base_url.trim_end_matches('/'),
                system_id,
                poam_id
            );

            let close_payload = serde_json::json!({
                "status": "Completed",
                "completionDate": chrono::Utc::now().format("%Y-%m-%d").to_string(),
                "comments": body.completion_comments,
                "milestones": [{
                    "description": "POA&M closed via HeroForge",
                    "scheduledCompletionDate": chrono::Utc::now().format("%Y-%m-%d").to_string()
                }]
            });

            let mut request = client.put(&url)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .json(&close_payload);

            if let Some(key) = &api_key {
                request = request.header("api-key", key);
            }

            // Execute request to close POA&M in eMASS
            match request.send().await {
                Ok(response) if response.status().is_success() => {
                    // Update local cache to reflect closure
                    let _ = sqlx::query(
                        r#"
                        UPDATE emass_poam_cache
                        SET status = 'Completed', last_synced = datetime('now')
                        WHERE id = ?
                        "#
                    )
                    .bind(&cache_id)
                    .execute(pool.get_ref())
                    .await;

                    // Upload evidence if provided
                    if let Some(evidence_ids) = &body.evidence_ids {
                        if !evidence_ids.is_empty() {
                            // Get evidence files and upload them
                            for evidence_id in evidence_ids {
                                let evidence_result = upload_evidence_to_emass(
                                    &client,
                                    &base_url,
                                    api_key.as_deref(),
                                    &system_id,
                                    &poam_id,
                                    evidence_id,
                                    pool.get_ref(),
                                ).await;

                                if let Err(e) = evidence_result {
                                    log::warn!("Failed to upload evidence {}: {}", evidence_id, e);
                                }
                            }
                        }
                    }

                    HttpResponse::Ok().json(serde_json::json!({
                        "status": "success",
                        "message": "POA&M closed successfully in eMASS",
                        "poam_id": poam_id
                    }))
                }
                Ok(response) => {
                    let status = response.status();
                    let error_body = response.text().await.unwrap_or_default();
                    HttpResponse::BadGateway().json(serde_json::json!({
                        "status": "failed",
                        "message": "Failed to close POA&M in eMASS",
                        "error": format!("HTTP {}: {}", status, error_body)
                    }))
                }
                Err(e) => {
                    HttpResponse::BadGateway().json(serde_json::json!({
                        "status": "failed",
                        "message": "Failed to connect to eMASS",
                        "error": e.to_string()
                    }))
                }
            }
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "POA&M not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Upload evidence file to eMASS for a POA&M
async fn upload_evidence_to_emass(
    client: &reqwest::Client,
    base_url: &str,
    api_key: Option<&str>,
    system_id: &str,
    poam_id: &str,
    evidence_id: &str,
    pool: &SqlitePool,
) -> Result<(), String> {
    // Get evidence file details from database
    let evidence = sqlx::query_as::<_, (String, String, Vec<u8>)>(
        "SELECT filename, mime_type, content FROM evidence_files WHERE id = ?"
    )
    .bind(evidence_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("Database error: {}", e))?;

    let (filename, mime_type, content) = match evidence {
        Some(e) => e,
        None => return Err(format!("Evidence file {} not found", evidence_id)),
    };

    // Build multipart form for file upload
    let part = reqwest::multipart::Part::bytes(content)
        .file_name(filename.clone())
        .mime_str(&mime_type)
        .map_err(|e| format!("Invalid MIME type: {}", e))?;

    let form = reqwest::multipart::Form::new()
        .part("file", part)
        .text("category", "Other")
        .text("description", format!("Evidence uploaded via HeroForge for POA&M {}", poam_id));

    // Upload to eMASS artifacts endpoint
    let url = format!(
        "{}/api/systems/{}/poams/{}/artifacts",
        base_url.trim_end_matches('/'),
        system_id,
        poam_id
    );

    let mut request = client.post(&url)
        .multipart(form);

    if let Some(key) = api_key {
        request = request.header("api-key", key);
    }

    match request.send().await {
        Ok(response) if response.status().is_success() => {
            log::info!("Evidence {} uploaded successfully for POA&M {}", filename, poam_id);
            Ok(())
        }
        Ok(response) => {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            Err(format!("HTTP {}: {}", status, error_body))
        }
        Err(e) => Err(e.to_string())
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configure eMASS API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/emass")
            // Settings
            .route("/settings", web::get().to(list_emass_settings))
            .route("/settings", web::post().to(create_emass_settings))
            .route("/settings/{id}", web::get().to(get_emass_settings))
            .route("/settings/{id}", web::put().to(update_emass_settings))
            .route("/settings/{id}", web::delete().to(delete_emass_settings))
            .route("/settings/{id}/test", web::post().to(test_connection))
            // System mappings
            .route("/mappings", web::get().to(list_system_mappings))
            .route("/mappings", web::post().to(create_system_mapping))
            .route("/mappings/{id}/sync", web::post().to(trigger_sync))
            .route("/mappings/{id}/history", web::get().to(get_sync_history))
            .route("/mappings/{id}/poams", web::get().to(list_poams))
            // POA&M operations
            .route("/poams/{id}/close", web::post().to(close_poam))
    );
}
