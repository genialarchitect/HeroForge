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
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create template"))?;

    Ok(HttpResponse::Ok().json(template))
}

/// Get all templates for the current user
pub async fn get_templates(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let templates = db::get_user_templates(&pool, &claims.sub)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch templates"))?;

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
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch template"))?;

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
        .map_err(|_| actix_web::error::ErrorInternalServerError("Database error"))?;

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
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to update template"))?;

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
        .map_err(|_| actix_web::error::ErrorInternalServerError("Database error"))?;

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
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to delete template"))?;

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
        .map_err(|_| actix_web::error::ErrorInternalServerError("Database error"))?;

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
        .map_err(|_| actix_web::error::ErrorInternalServerError("Invalid template config"))?;

    // Create scan record in database
    let scan = db::create_scan(&pool, &claims.sub, &scan_request.name, &scan_request.targets)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create scan"))?;

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
