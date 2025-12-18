use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;

use crate::db::{self, models};
use crate::web::auth;

/// Create a new scan template
pub async fn create_template(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<models::CreateTemplateRequest>,
) -> Result<HttpResponse> {
    let template = db::create_template(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to create template: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    Ok(HttpResponse::Ok().json(template))
}

/// Get all templates for the current user
pub async fn get_templates(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let templates = db::get_user_templates(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch templates: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    Ok(HttpResponse::Ok().json(templates))
}

/// Get a specific template by ID
pub async fn get_template(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    template_id: web::Path<String>,
) -> Result<HttpResponse> {
    let template = db::get_template_by_id(&pool, &template_id)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch template: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    match template {
        Some(t) => {
            // Verify the template belongs to the user
            if t.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
            Ok(HttpResponse::Ok().json(t))
        }
        None => Err(actix_web::error::ErrorNotFound("Template not found")),
    }
}

/// Update a template
pub async fn update_template(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    template_id: web::Path<String>,
    request: web::Json<models::UpdateTemplateRequest>,
) -> Result<HttpResponse> {
    // First check if template exists and belongs to user
    let existing = db::get_template_by_id(&pool, &template_id)
        .await
        .map_err(|e| {
            log::error!("Database error in update_template: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    match existing {
        Some(t) => {
            if t.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
        }
        None => return Err(actix_web::error::ErrorNotFound("Template not found")),
    }

    let updated = db::update_template(&pool, &template_id, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to update template: {}", e);
            actix_web::error::ErrorInternalServerError("Update failed. Please try again.")
        })?;

    Ok(HttpResponse::Ok().json(updated))
}

/// Delete a template
pub async fn delete_template(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    template_id: web::Path<String>,
) -> Result<HttpResponse> {
    // First check if template exists and belongs to user
    let existing = db::get_template_by_id(&pool, &template_id)
        .await
        .map_err(|e| {
            log::error!("Database error in delete_template: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    match existing {
        Some(t) => {
            if t.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
        }
        None => return Err(actix_web::error::ErrorNotFound("Template not found")),
    }

    db::delete_template(&pool, &template_id)
        .await
        .map_err(|e| {
            log::error!("Failed to delete template: {}", e);
            actix_web::error::ErrorInternalServerError("Delete failed. Please try again.")
        })?;

    Ok(HttpResponse::NoContent().finish())
}

/// Create a scan from a template
pub async fn create_scan_from_template(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    template_id: web::Path<String>,
    scan_request: web::Json<CreateScanFromTemplateRequest>,
) -> Result<HttpResponse> {
    use crate::scanner;
    use crate::types::ScanConfig;

    // Fetch the template
    let template = db::get_template_by_id(&pool, &template_id)
        .await
        .map_err(|e| {
            log::error!("Database error in create_scan_from_template: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    let template = match template {
        Some(t) => {
            if t.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
            t
        }
        None => return Err(actix_web::error::ErrorNotFound("Template not found")),
    };

    // Parse the template config
    let template_config: models::ScanTemplateConfig = serde_json::from_str(&template.config)
        .map_err(|e| {
            log::error!("Invalid template config: {}", e);
            actix_web::error::ErrorInternalServerError("Invalid template configuration.")
        })?;

    // Create scan record in database
    let scan = db::create_scan(&pool, &claims.sub, &scan_request.name, &scan_request.targets)
        .await
        .map_err(|e| {
            log::error!("Failed to create scan from template: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create scan. Please try again.")
        })?;

    // Start scan in background
    let scan_id = scan.id.clone();
    let pool_clone = pool.get_ref().clone();

    // Parse enumeration depth from template config
    let enum_depth = template_config
        .enum_depth
        .as_ref()
        .map(|d| parse_enum_depth(d))
        .unwrap_or(crate::scanner::enumeration::types::EnumDepth::Light);

    // Parse enumeration services from template config
    let enum_services = template_config
        .enum_services
        .as_ref()
        .map(|services| {
            services
                .iter()
                .filter_map(|s| parse_service_type(s))
                .collect()
        })
        .unwrap_or_default();

    // Parse scan type from template config
    let scan_type = template_config
        .scan_type
        .as_ref()
        .map(|s| parse_scan_type(s))
        .unwrap_or(crate::types::ScanType::TCPConnect);

    let config = ScanConfig {
        targets: scan_request.targets.clone(),
        port_range: template_config.port_range,
        threads: template_config.threads,
        timeout: std::time::Duration::from_secs(3),
        scan_type,
        enable_os_detection: template_config.enable_os_detection,
        enable_service_detection: template_config.enable_service_detection,
        enable_vuln_scan: template_config.enable_vuln_scan,
        enable_enumeration: template_config.enable_enumeration,
        enum_depth,
        enum_wordlist_path: None,
        enum_services,
        output_format: crate::types::OutputFormat::Json,
        udp_port_range: template_config.udp_port_range,
        udp_retries: template_config.udp_retries,
        skip_host_discovery: false,
        // Use defaults for scanner-specific timeouts
        service_detection_timeout: None,
        dns_timeout: None,
        syn_timeout: None,
        udp_timeout: None,
        // Template scans don't support VPN (use regular scan API with vpn_config_id)
        vpn_config_id: None,
    };

    tokio::spawn(async move {
        // Create broadcast channel for this scan
        let tx = crate::web::broadcast::create_scan_channel(scan_id.clone()).await;

        // Send scan started message
        let _ = tx.send(crate::types::ScanProgressMessage::ScanStarted {
            scan_id: scan_id.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });

        // Update status to running
        let _ = db::update_scan_status(&pool_clone, &scan_id, "running", None, None).await;

        // Run the scan with progress tracking
        let start_time = std::time::Instant::now();
        match scanner::run_scan(&config, Some(tx.clone())).await {
            Ok(results) => {
                let duration = start_time.elapsed();
                let results_json = serde_json::to_string(&results).unwrap_or_default();

                // Send completion message
                let _ = tx.send(crate::types::ScanProgressMessage::ScanCompleted {
                    scan_id: scan_id.clone(),
                    duration: duration.as_secs_f64(),
                    total_hosts: results.len(),
                });

                let _ = db::update_scan_status(
                    &pool_clone,
                    &scan_id,
                    "completed",
                    Some(&results_json),
                    None,
                )
                .await;
            }
            Err(e) => {
                let error_msg = format!("Scan failed: {}", e);
                let _ = tx.send(crate::types::ScanProgressMessage::Error {
                    message: error_msg.clone(),
                });
                let _ = db::update_scan_status(&pool_clone, &scan_id, "failed", None, Some(&error_msg))
                    .await;
            }
        }

        // Clean up broadcast channel after a delay
        tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
        crate::web::broadcast::remove_scan_channel(&scan_id).await;
    });

    Ok(HttpResponse::Ok().json(scan))
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateScanFromTemplateRequest {
    pub name: String,
    pub targets: Vec<String>,
}

// Helper functions to parse enum values

fn parse_enum_depth(depth: &str) -> crate::scanner::enumeration::types::EnumDepth {
    match depth.to_lowercase().as_str() {
        "passive" => crate::scanner::enumeration::types::EnumDepth::Passive,
        "light" => crate::scanner::enumeration::types::EnumDepth::Light,
        "aggressive" => crate::scanner::enumeration::types::EnumDepth::Aggressive,
        _ => crate::scanner::enumeration::types::EnumDepth::Light,
    }
}

fn parse_service_type(service: &str) -> Option<crate::scanner::enumeration::types::ServiceType> {
    use crate::scanner::enumeration::types::{ServiceType, DbType};
    match service.to_lowercase().as_str() {
        "http" => Some(ServiceType::Http),
        "https" => Some(ServiceType::Https),
        "dns" => Some(ServiceType::Dns),
        "smb" => Some(ServiceType::Smb),
        "ftp" => Some(ServiceType::Ftp),
        "ssh" => Some(ServiceType::Ssh),
        "smtp" => Some(ServiceType::Smtp),
        "ldap" => Some(ServiceType::Ldap),
        "mysql" => Some(ServiceType::Database(DbType::MySQL)),
        "postgresql" => Some(ServiceType::Database(DbType::PostgreSQL)),
        "mongodb" => Some(ServiceType::Database(DbType::MongoDB)),
        "redis" => Some(ServiceType::Database(DbType::Redis)),
        "elasticsearch" => Some(ServiceType::Database(DbType::Elasticsearch)),
        _ => None,
    }
}

fn parse_scan_type(scan_type: &str) -> crate::types::ScanType {
    match scan_type.to_lowercase().as_str() {
        "tcp_connect" => crate::types::ScanType::TCPConnect,
        "udp" => crate::types::ScanType::UDPScan,
        "comprehensive" => crate::types::ScanType::Comprehensive,
        _ => crate::types::ScanType::TCPConnect,
    }
}

/// Export a template as JSON file
pub async fn export_template(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    template_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Fetch the template
    let template = db::get_template_by_id(&pool, &template_id)
        .await
        .map_err(|e| {
            log::error!("Database error in export_template: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    let template = match template {
        Some(t) => {
            if t.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
            t
        }
        None => return Err(actix_web::error::ErrorNotFound("Template not found")),
    };

    // Create exportable template structure
    #[derive(serde::Serialize)]
    struct ExportableTemplate {
        name: String,
        description: Option<String>,
        config: serde_json::Value,
        is_default: bool,
        export_version: String,
    }

    let config_json: serde_json::Value = serde_json::from_str(&template.config)
        .map_err(|e| {
            log::error!("Invalid template config: {}", e);
            actix_web::error::ErrorInternalServerError("Invalid template configuration.")
        })?;

    let exportable = ExportableTemplate {
        name: template.name.clone(),
        description: template.description.clone(),
        config: config_json,
        is_default: template.is_default,
        export_version: "1.0".to_string(),
    };

    let json_data = serde_json::to_string_pretty(&exportable)
        .map_err(|e| {
            log::error!("Failed to serialize template: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to export template.")
        })?;

    let filename = format!("template_{}.json", template.name.replace(" ", "_"));

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
        .body(json_data))
}

/// Import a template from JSON file
pub async fn import_template(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    payload: web::Json<ImportTemplateRequest>,
) -> Result<HttpResponse> {
    // Validate the imported template structure
    let template_data = &payload.template;

    // Validate name
    if template_data.name.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Template name cannot be empty"
        })));
    }

    if template_data.name.len() > 255 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Template name too long (max 255 characters)"
        })));
    }

    // Validate config structure
    let config: models::ScanTemplateConfig = serde_json::from_value(template_data.config.clone())
        .map_err(|e| {
            log::error!("Invalid template config structure: {}", e);
            actix_web::error::ErrorBadRequest(format!("Invalid template configuration: {}", e))
        })?;

    // Validate port ranges
    if config.port_range.0 == 0 || config.port_range.0 > config.port_range.1 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid port range"
        })));
    }

    if let Some(udp_range) = config.udp_port_range {
        if udp_range.0 == 0 || udp_range.0 > udp_range.1 {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid UDP port range"
            })));
        }
    }

    // Validate thread count
    if config.threads == 0 || config.threads > 1000 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Thread count must be between 1 and 1000"
        })));
    }

    // Create the template
    let create_request = models::CreateTemplateRequest {
        name: template_data.name.clone(),
        description: template_data.description.clone(),
        config,
        is_default: template_data.is_default.unwrap_or(false),
    };

    let created_template = db::create_template(&pool, &claims.sub, &create_request)
        .await
        .map_err(|e| {
            log::error!("Failed to create imported template: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to import template. Please try again.")
        })?;

    Ok(HttpResponse::Ok().json(created_template))
}

#[derive(Debug, serde::Deserialize)]
pub struct ImportTemplateRequest {
    pub template: ImportedTemplate,
}

#[derive(Debug, serde::Deserialize)]
pub struct ImportedTemplate {
    pub name: String,
    pub description: Option<String>,
    pub config: serde_json::Value,
    pub is_default: Option<bool>,
}
