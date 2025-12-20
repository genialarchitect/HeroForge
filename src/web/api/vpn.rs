//! VPN configuration and connection API endpoints

use actix_web::{web, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::path::PathBuf;
use uuid::Uuid;

use crate::db;
use crate::db::models::AuditLog;
use crate::vpn::{
    config::VpnConfigValidator,
    credentials::{encrypt_vpn_credentials, is_vpn_encryption_configured, VpnCredentials},
    types::{ConnectionMode, VpnConfigResponse, VpnStatusResponse, VpnType},
    VpnManager,
};
use crate::web::auth;

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct UploadVpnConfigRequest {
    pub name: String,
    pub vpn_type: String,           // "openvpn" or "wireguard"
    pub config_data: String,        // Base64-encoded config file
    pub filename: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub set_as_default: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateVpnConfigRequest {
    pub name: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub is_default: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ConnectVpnRequest {
    pub config_id: String,
    pub mode: String,               // "per_scan" or "persistent"
    pub scan_id: Option<String>,    // Required for per_scan mode
}

#[derive(Debug, Serialize)]
pub struct TestConnectionResponse {
    pub success: bool,
    pub message: String,
    pub assigned_ip: Option<String>,
}

// ============================================================================
// VPN Configuration Endpoints
// ============================================================================

/// Upload a new VPN configuration
/// POST /api/vpn/configs
pub async fn upload_vpn_config(
    pool: web::Data<SqlitePool>,
    request: web::Json<UploadVpnConfigRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let req = request.into_inner();

    // Parse VPN type
    let vpn_type: VpnType = match req.vpn_type.parse() {
        Ok(t) => t,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid VPN type. Use 'openvpn' or 'wireguard'"
            }));
        }
    };

    // Decode base64 config data
    use base64::Engine;
    let config_bytes = match base64::engine::general_purpose::STANDARD.decode(&req.config_data) {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid base64-encoded config data"
            }));
        }
    };

    let config_content = match String::from_utf8(config_bytes.clone()) {
        Ok(s) => s,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Config file must be valid UTF-8 text"
            }));
        }
    };

    // Validate config
    let validation = VpnConfigValidator::validate(&config_content, &req.filename);
    if !validation.is_valid {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid VPN configuration",
            "errors": validation.errors,
            "warnings": validation.warnings
        }));
    }

    // Check if credentials are required but not provided
    if validation.requires_credentials && (req.username.is_none() || req.password.is_none()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "This VPN configuration requires username and password credentials"
        }));
    }

    // Encrypt credentials if provided
    let encrypted_credentials = if let (Some(username), Some(password)) = (&req.username, &req.password) {
        if !is_vpn_encryption_configured() {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "VPN credential encryption not configured. Set VPN_ENCRYPTION_KEY environment variable."
            }));
        }

        let creds = VpnCredentials::new(username, password);
        match encrypt_vpn_credentials(&creds) {
            Ok(encrypted) => Some(encrypted),
            Err(e) => {
                log::error!("Failed to encrypt VPN credentials: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to encrypt credentials"
                }));
            }
        }
    } else {
        None
    };

    // Generate config ID and save file
    let config_id = uuid::Uuid::new_v4().to_string();
    let manager = VpnManager::global();

    let config_file_path = match manager
        .save_config_file(
            &claims.sub,
            &config_id,
            &config_bytes,
            vpn_type.file_extension(),
        )
        .await
    {
        Ok(path) => path,
        Err(e) => {
            log::error!("Failed to save VPN config file: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to save configuration file"
            }));
        }
    };

    // Create database record
    let sanitized_filename = VpnConfigValidator::sanitize_filename(&req.filename);
    let config = match db::create_vpn_config(
        pool.get_ref(),
        &claims.sub,
        &req.name,
        vpn_type.display_name(),
        config_file_path.to_string_lossy().as_ref(),
        &sanitized_filename,
        encrypted_credentials.as_deref(),
        validation.requires_credentials,
    )
    .await
    {
        Ok(config) => config,
        Err(e) => {
            // Clean up file on database error
            let _ = tokio::fs::remove_file(&config_file_path).await;
            log::error!("Failed to create VPN config record: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to save configuration"
            }));
        }
    };

    // Set as default if requested
    if req.set_as_default {
        let _ = db::update_vpn_config(pool.get_ref(), &config.id, None, None, Some(true)).await;
    }

    // Log audit
    let audit_log = AuditLog {
        id: Uuid::new_v4().to_string(),
        user_id: claims.sub.clone(),
        action: "vpn_config_created".to_string(),
        target_type: Some("vpn_config".to_string()),
        target_id: Some(config.id.clone()),
        details: Some(format!("Created VPN config: {} ({})", req.name, vpn_type)),
        ip_address: None,
        user_agent: None,
        created_at: Utc::now(),
    };
    let _ = db::create_audit_log(pool.get_ref(), &audit_log).await;

    HttpResponse::Created().json(VpnConfigResponse {
        id: config.id,
        name: config.name,
        vpn_type: config.vpn_type,
        requires_credentials: config.requires_credentials,
        has_credentials: encrypted_credentials.is_some(),
        is_default: req.set_as_default,
        created_at: config.created_at,
        last_used_at: None,
    })
}

/// List all VPN configurations for the current user
/// GET /api/vpn/configs
pub async fn list_vpn_configs(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match db::get_user_vpn_configs(pool.get_ref(), &claims.sub).await {
        Ok(configs) => {
            let responses: Vec<VpnConfigResponse> = configs
                .into_iter()
                .map(|c| VpnConfigResponse {
                    id: c.id,
                    name: c.name,
                    vpn_type: c.vpn_type,
                    requires_credentials: c.requires_credentials,
                    has_credentials: c.encrypted_credentials.is_some(),
                    is_default: c.is_default,
                    created_at: c.created_at,
                    last_used_at: c.last_used_at,
                })
                .collect();
            HttpResponse::Ok().json(responses)
        }
        Err(e) => {
            log::error!("Failed to list VPN configs: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve VPN configurations"
            }))
        }
    }
}

/// Get a specific VPN configuration
/// GET /api/vpn/configs/{id}
pub async fn get_vpn_config(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let config_id = path.into_inner();

    match db::get_vpn_config_by_id(pool.get_ref(), &config_id).await {
        Ok(Some(config)) => {
            // Verify ownership
            if config.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                }));
            }

            HttpResponse::Ok().json(VpnConfigResponse {
                id: config.id,
                name: config.name,
                vpn_type: config.vpn_type,
                requires_credentials: config.requires_credentials,
                has_credentials: config.encrypted_credentials.is_some(),
                is_default: config.is_default,
                created_at: config.created_at,
                last_used_at: config.last_used_at,
            })
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "VPN configuration not found"
        })),
        Err(e) => {
            log::error!("Failed to get VPN config: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve VPN configuration"
            }))
        }
    }
}

/// Update a VPN configuration
/// PUT /api/vpn/configs/{id}
pub async fn update_vpn_config(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    request: web::Json<UpdateVpnConfigRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let config_id = path.into_inner();
    let req = request.into_inner();

    // Verify ownership
    match db::get_vpn_config_by_id(pool.get_ref(), &config_id).await {
        Ok(Some(config)) => {
            if config.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                }));
            }
        }
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "VPN configuration not found"
            }));
        }
        Err(e) => {
            log::error!("Failed to get VPN config: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve VPN configuration"
            }));
        }
    }

    // Encrypt new credentials if provided
    let encrypted_credentials = if let (Some(username), Some(password)) = (&req.username, &req.password) {
        if !is_vpn_encryption_configured() {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "VPN credential encryption not configured"
            }));
        }

        let creds = VpnCredentials::new(username, password);
        match encrypt_vpn_credentials(&creds) {
            Ok(encrypted) => Some(encrypted),
            Err(e) => {
                log::error!("Failed to encrypt VPN credentials: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to encrypt credentials"
                }));
            }
        }
    } else {
        None
    };

    // Update config
    if let Err(e) = db::update_vpn_config(
        pool.get_ref(),
        &config_id,
        req.name.as_deref(),
        encrypted_credentials.as_deref(),
        req.is_default,
    )
    .await
    {
        log::error!("Failed to update VPN config: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to update VPN configuration"
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "VPN configuration updated"
    }))
}

/// Delete a VPN configuration
/// DELETE /api/vpn/configs/{id}
pub async fn delete_vpn_config(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let config_id = path.into_inner();

    // Get config and verify ownership
    let config = match db::get_vpn_config_by_id(pool.get_ref(), &config_id).await {
        Ok(Some(config)) => {
            if config.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                }));
            }
            config
        }
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "VPN configuration not found"
            }));
        }
        Err(e) => {
            log::error!("Failed to get VPN config: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve VPN configuration"
            }));
        }
    };

    // Delete config file
    let manager = VpnManager::global();
    let _ = manager.delete_config_file(&claims.sub, &config_id).await;

    // Delete database record
    if let Err(e) = db::delete_vpn_config(pool.get_ref(), &config_id).await {
        log::error!("Failed to delete VPN config: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to delete VPN configuration"
        }));
    }

    // Log audit
    let audit_log = AuditLog {
        id: Uuid::new_v4().to_string(),
        user_id: claims.sub.clone(),
        action: "vpn_config_deleted".to_string(),
        target_type: Some("vpn_config".to_string()),
        target_id: Some(config_id.clone()),
        details: Some(format!("Deleted VPN config: {}", config.name)),
        ip_address: None,
        user_agent: None,
        created_at: Utc::now(),
    };
    let _ = db::create_audit_log(pool.get_ref(), &audit_log).await;

    HttpResponse::Ok().json(serde_json::json!({
        "message": "VPN configuration deleted"
    }))
}

/// Test VPN connection
/// POST /api/vpn/configs/{id}/test
pub async fn test_vpn_connection(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let config_id = path.into_inner();

    // Get config and verify ownership
    let config = match db::get_vpn_config_by_id(pool.get_ref(), &config_id).await {
        Ok(Some(config)) => {
            if config.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                }));
            }
            config
        }
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "VPN configuration not found"
            }));
        }
        Err(e) => {
            log::error!("Failed to get VPN config: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve VPN configuration"
            }));
        }
    };

    // Parse VPN type
    let vpn_type: VpnType = match config.vpn_type.parse() {
        Ok(t) => t,
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Invalid VPN type in configuration"
            }));
        }
    };

    // Attempt connection
    let manager = VpnManager::global();
    let config_path = PathBuf::from(&config.config_file_path);

    match manager
        .connect(
            &claims.sub,
            &config_id,
            &config.name,
            vpn_type,
            &config_path,
            config.encrypted_credentials.as_deref(),
            ConnectionMode::PerScan, // Test uses per-scan mode
            None,
        )
        .await
    {
        Ok(info) => {
            // Immediately disconnect after successful test
            let _ = manager.disconnect_user(&claims.sub).await;

            HttpResponse::Ok().json(TestConnectionResponse {
                success: true,
                message: "VPN connection test successful".to_string(),
                assigned_ip: info.assigned_ip,
            })
        }
        Err(e) => {
            // Ensure cleanup
            let _ = manager.disconnect_user(&claims.sub).await;

            HttpResponse::Ok().json(TestConnectionResponse {
                success: false,
                message: format!("VPN connection failed: {}", e),
                assigned_ip: None,
            })
        }
    }
}

// ============================================================================
// VPN Connection Endpoints
// ============================================================================

/// Connect to VPN (persistent mode)
/// POST /api/vpn/connect
pub async fn connect_vpn(
    pool: web::Data<SqlitePool>,
    request: web::Json<ConnectVpnRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let req = request.into_inner();

    // Parse connection mode
    let mode: ConnectionMode = match req.mode.parse() {
        Ok(m) => m,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid connection mode. Use 'per_scan' or 'persistent'"
            }));
        }
    };

    // Get config and verify ownership
    let config = match db::get_vpn_config_by_id(pool.get_ref(), &req.config_id).await {
        Ok(Some(config)) => {
            if config.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                }));
            }
            config
        }
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "VPN configuration not found"
            }));
        }
        Err(e) => {
            log::error!("Failed to get VPN config: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve VPN configuration"
            }));
        }
    };

    // Parse VPN type
    let vpn_type: VpnType = match config.vpn_type.parse() {
        Ok(t) => t,
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Invalid VPN type in configuration"
            }));
        }
    };

    // Connect
    let manager = VpnManager::global();
    let config_path = PathBuf::from(&config.config_file_path);

    match manager
        .connect(
            &claims.sub,
            &req.config_id,
            &config.name,
            vpn_type,
            &config_path,
            config.encrypted_credentials.as_deref(),
            mode,
            req.scan_id,
        )
        .await
    {
        Ok(info) => {
            // Update last used
            let _ = db::update_vpn_config_last_used(pool.get_ref(), &req.config_id).await;

            // Create connection record in database
            let _ = db::create_vpn_connection(
                pool.get_ref(),
                &req.config_id,
                &claims.sub,
                &mode.to_string(),
                info.scan_id.as_deref(),
            )
            .await;

            // Log audit
            let audit_log = AuditLog {
                id: Uuid::new_v4().to_string(),
                user_id: claims.sub.clone(),
                action: "vpn_connected".to_string(),
                target_type: Some("vpn_connection".to_string()),
                target_id: Some(info.id.clone()),
                details: Some(format!(
                    "Connected to VPN: {} (IP: {})",
                    config.name,
                    info.assigned_ip.as_deref().unwrap_or("unknown")
                )),
                ip_address: None,
                user_agent: None,
                created_at: Utc::now(),
            };
            let _ = db::create_audit_log(pool.get_ref(), &audit_log).await;

            HttpResponse::Ok().json(VpnStatusResponse {
                connected: true,
                config_id: Some(req.config_id),
                config_name: Some(config.name),
                connection_mode: Some(mode.to_string()),
                assigned_ip: info.assigned_ip,
                connected_since: info.connected_at.map(|t| t.to_rfc3339()),
                interface_name: info.interface_name,
            })
        }
        Err(e) => {
            log::error!("VPN connection failed: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("VPN connection failed: {}", e)
            }))
        }
    }
}

/// Disconnect VPN
/// POST /api/vpn/disconnect
pub async fn disconnect_vpn(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let manager = VpnManager::global();

    // Get current connection info before disconnecting
    let info = manager.get_user_status(&claims.sub).await;

    match manager.disconnect_user(&claims.sub).await {
        Ok(()) => {
            // Log audit
            if let Some(info) = info {
                let audit_log = AuditLog {
                    id: Uuid::new_v4().to_string(),
                    user_id: claims.sub.clone(),
                    action: "vpn_disconnected".to_string(),
                    target_type: Some("vpn_connection".to_string()),
                    target_id: Some(info.id.clone()),
                    details: Some(format!("Disconnected from VPN: {}", info.config_name)),
                    ip_address: None,
                    user_agent: None,
                    created_at: Utc::now(),
                };
                let _ = db::create_audit_log(pool.get_ref(), &audit_log).await;
            }

            HttpResponse::Ok().json(serde_json::json!({
                "message": "VPN disconnected"
            }))
        }
        Err(e) => {
            log::error!("Failed to disconnect VPN: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to disconnect VPN: {}", e)
            }))
        }
    }
}

/// Get current VPN status
/// GET /api/vpn/status
pub async fn get_vpn_status(
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let manager = VpnManager::global();

    match manager.get_user_status(&claims.sub).await {
        Some(info) => HttpResponse::Ok().json(VpnStatusResponse {
            connected: true,
            config_id: Some(info.config_id),
            config_name: Some(info.config_name),
            connection_mode: Some(info.mode.to_string()),
            assigned_ip: info.assigned_ip,
            connected_since: info.connected_at.map(|t| t.to_rfc3339()),
            interface_name: info.interface_name,
        }),
        None => HttpResponse::Ok().json(VpnStatusResponse {
            connected: false,
            config_id: None,
            config_name: None,
            connection_mode: None,
            assigned_ip: None,
            connected_since: None,
            interface_name: None,
        }),
    }
}

/// Get VPN connection history
/// GET /api/vpn/connections
pub async fn get_vpn_connections(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match db::get_vpn_connection_history(pool.get_ref(), &claims.sub, 50).await {
        Ok(connections) => HttpResponse::Ok().json(connections),
        Err(e) => {
            log::error!("Failed to get VPN connection history: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve connection history"
            }))
        }
    }
}
