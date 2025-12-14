use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::db::{self, models};
use crate::types::ScanConfig;
use crate::web::auth;
use crate::scanner;

pub async fn create_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_request: web::Json<models::CreateScanRequest>,
) -> Result<HttpResponse> {
    // Create scan record in database
    let scan = db::create_scan(
        &pool,
        &claims.sub,
        &scan_request.name,
        &scan_request.targets,
    )
    .await
    .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create scan"))?;

    // Start scan in background
    let scan_id = scan.id.clone();
    let pool_clone = pool.get_ref().clone();

    // Parse enumeration depth from string
    let enum_depth = scan_request
        .enum_depth
        .as_ref()
        .map(|d| parse_enum_depth(d))
        .unwrap_or(crate::scanner::enumeration::types::EnumDepth::Light);

    // Parse enumeration services from strings
    let enum_services = scan_request
        .enum_services
        .as_ref()
        .map(|services| {
            services
                .iter()
                .filter_map(|s| parse_service_type(s))
                .collect()
        })
        .unwrap_or_default();

    // Parse scan type from request
    let scan_type = scan_request
        .scan_type
        .as_ref()
        .map(|s| parse_scan_type(s))
        .unwrap_or(crate::types::ScanType::TCPConnect);

    let config = ScanConfig {
        targets: scan_request.targets.clone(),
        port_range: scan_request.port_range,
        threads: scan_request.threads,
        timeout: std::time::Duration::from_secs(3),
        scan_type,
        enable_os_detection: scan_request.enable_os_detection,
        enable_service_detection: scan_request.enable_service_detection,
        enable_vuln_scan: scan_request.enable_vuln_scan,
        enable_enumeration: scan_request.enable_enumeration,
        enum_depth,
        enum_wordlist_path: None,
        enum_services,
        output_format: crate::types::OutputFormat::Json,
        udp_port_range: scan_request.udp_port_range,
        udp_retries: scan_request.udp_retries,
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
                let error_msg = e.to_string();

                // Send error message
                let _ = tx.send(crate::types::ScanProgressMessage::Error {
                    message: error_msg.clone(),
                });

                let _ = db::update_scan_status(
                    &pool_clone,
                    &scan_id,
                    "failed",
                    None,
                    Some(&error_msg),
                )
                .await;
            }
        }

        // Clean up broadcast channel after scan completes
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        crate::web::broadcast::remove_scan_channel(&scan_id).await;
    });

    Ok(HttpResponse::Ok().json(scan))
}

pub async fn get_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let scans = db::get_user_scans(&pool, &claims.sub)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch scans"))?;

    Ok(HttpResponse::Ok().json(scans))
}

pub async fn get_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    let scan = db::get_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch scan"))?;

    match scan {
        Some(scan) => {
            // Verify ownership
            if scan.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }
            Ok(HttpResponse::Ok().json(scan))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        }))),
    }
}

pub async fn get_scan_results(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    let scan = db::get_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch scan"))?;

    match scan {
        Some(scan) => {
            // Verify ownership
            if scan.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            if let Some(results) = scan.results {
                let results_json: serde_json::Value = serde_json::from_str(&results)
                    .unwrap_or(serde_json::json!([]));
                Ok(HttpResponse::Ok().json(results_json))
            } else {
                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "status": scan.status,
                    "message": "Scan results not yet available"
                })))
            }
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        }))),
    }
}

/// Parse enumeration depth from string
fn parse_enum_depth(s: &str) -> crate::scanner::enumeration::types::EnumDepth {
    match s.to_lowercase().as_str() {
        "passive" => crate::scanner::enumeration::types::EnumDepth::Passive,
        "aggressive" => crate::scanner::enumeration::types::EnumDepth::Aggressive,
        _ => crate::scanner::enumeration::types::EnumDepth::Light,
    }
}

/// Parse service type from string
fn parse_service_type(s: &str) -> Option<crate::scanner::enumeration::types::ServiceType> {
    use crate::scanner::enumeration::types::{DbType, ServiceType};

    match s.to_lowercase().as_str() {
        "http" => Some(ServiceType::Http),
        "https" => Some(ServiceType::Https),
        "smb" => Some(ServiceType::Smb),
        "dns" => Some(ServiceType::Dns),
        "ftp" => Some(ServiceType::Ftp),
        "ssh" => Some(ServiceType::Ssh),
        "smtp" => Some(ServiceType::Smtp),
        "ldap" => Some(ServiceType::Ldap),
        "mysql" => Some(ServiceType::Database(DbType::MySQL)),
        "postgresql" | "postgres" => Some(ServiceType::Database(DbType::PostgreSQL)),
        "mongodb" | "mongo" => Some(ServiceType::Database(DbType::MongoDB)),
        "redis" => Some(ServiceType::Database(DbType::Redis)),
        "elasticsearch" | "elastic" => Some(ServiceType::Database(DbType::Elasticsearch)),
        _ => None,
    }
}

/// Parse scan type from string
fn parse_scan_type(s: &str) -> crate::types::ScanType {
    match s.to_lowercase().as_str() {
        "tcp_connect" | "tcp-connect" | "tcp" => crate::types::ScanType::TCPConnect,
        "udp" | "udp_scan" | "udp-scan" => crate::types::ScanType::UDPScan,
        "comprehensive" | "full" | "all" => crate::types::ScanType::Comprehensive,
        "syn" | "tcp_syn" | "tcp-syn" => crate::types::ScanType::TCPSyn,
        _ => crate::types::ScanType::TCPConnect,
    }
}
