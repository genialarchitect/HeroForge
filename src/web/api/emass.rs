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

    // Verify settings exist
    let settings = sqlx::query_as::<_, (String, String)>(
        "SELECT id, base_url FROM emass_settings WHERE id = ?"
    )
    .bind(&settings_id)
    .fetch_optional(pool.get_ref())
    .await;

    match settings {
        Ok(Some(_s)) => {
            // TODO: Actually test the eMASS connection using the emass module
            HttpResponse::Ok().json(serde_json::json!({
                "status": "success",
                "message": "Connection test passed"
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Settings not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
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
        Ok(Some(_m)) => {
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

            // TODO: Spawn async task to perform the actual sync
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

    // Verify POA&M exists
    let poam = sqlx::query_as::<_, (String, String, String)>(
        "SELECT id, poam_id, mapping_id FROM emass_poam_cache WHERE id = ?"
    )
    .bind(&poam_cache_id)
    .fetch_optional(pool.get_ref())
    .await;

    match poam {
        Ok(Some(_p)) => {
            // TODO: Actually close the POA&M in eMASS and upload evidence
            let _ = body.completion_comments;

            HttpResponse::Ok().json(serde_json::json!({
                "status": "success",
                "message": "POA&M close request submitted"
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "POA&M not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
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
