use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;
use std::net::IpAddr;
use ipnetwork::IpNetwork;
use std::io::Write;

use crate::db::{self, models};
use crate::types::{ScanConfig, HostInfo};
use crate::web::auth;
use crate::scanner;

/// Configuration for target validation
struct ValidationConfig {
    allow_private: bool,
    allow_localhost: bool,
    max_hosts: usize,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            allow_private: false,
            allow_localhost: false,
            max_hosts: 256,
        }
    }
}

/// Validate scan targets
fn validate_scan_targets(targets: &[String], config: &ValidationConfig) -> Result<(), String> {
    if targets.is_empty() {
        return Err("At least one target must be specified".to_string());
    }

    let mut total_hosts = 0;

    for target in targets {
        let target = target.trim();

        if target.is_empty() {
            return Err("Target cannot be empty".to_string());
        }

        // Try parsing as IP network (CIDR notation)
        if let Ok(network) = target.parse::<IpNetwork>() {
            // Calculate number of hosts in this network
            let host_count = match network {
                IpNetwork::V4(net) => {
                    let prefix = net.prefix();
                    if prefix < 32 {
                        (1u64 << (32 - prefix)) as usize
                    } else {
                        1
                    }
                }
                IpNetwork::V6(net) => {
                    let prefix = net.prefix();
                    if prefix < 64 {
                        // For IPv6, limit to reasonable size to prevent overflow
                        config.max_hosts + 1 // Will trigger the limit check
                    } else if prefix < 128 {
                        (1u64 << (128 - prefix).min(63)) as usize
                    } else {
                        1
                    }
                }
            };
            total_hosts += host_count;

            // Validate IP address
            validate_ip_address(&network.network(), config)?;

            // For large networks, check broadcast address too
            if host_count > 1 {
                validate_ip_address(&network.broadcast(), config)?;
            }
        }
        // Try parsing as single IP address
        else if let Ok(ip) = target.parse::<IpAddr>() {
            total_hosts += 1;
            validate_ip_address(&ip, config)?;
        }
        // Try parsing as hostname
        else if is_valid_hostname(target) {
            total_hosts += 1;
            // Hostnames are allowed, but we can't validate their resolved IPs here
        }
        // Invalid format
        else {
            return Err(format!(
                "Invalid target format: '{}'. Must be an IP address, CIDR range, or valid hostname",
                target
            ));
        }

        // Check if we've exceeded the host limit
        if total_hosts > config.max_hosts {
            return Err(format!(
                "Total number of hosts ({}) exceeds maximum allowed ({})",
                total_hosts, config.max_hosts
            ));
        }
    }

    Ok(())
}

/// Validate a single IP address against security policies
fn validate_ip_address(ip: &IpAddr, config: &ValidationConfig) -> Result<(), String> {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();

            // Check for localhost (127.0.0.0/8)
            if octets[0] == 127 {
                if !config.allow_localhost {
                    return Err(format!(
                        "Localhost addresses (127.0.0.0/8) are not allowed: {}",
                        ip
                    ));
                }
            }

            // Check for link-local (169.254.0.0/16)
            if octets[0] == 169 && octets[1] == 254 {
                return Err(format!(
                    "Link-local addresses (169.254.0.0/16) are not allowed: {}",
                    ip
                ));
            }

            // Check for private IP ranges
            if !config.allow_private {
                // 10.0.0.0/8
                if octets[0] == 10 {
                    return Err(format!(
                        "Private IP addresses (10.0.0.0/8) are not allowed: {}. Enable private scanning if authorized.",
                        ip
                    ));
                }

                // 172.16.0.0/12
                if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
                    return Err(format!(
                        "Private IP addresses (172.16.0.0/12) are not allowed: {}. Enable private scanning if authorized.",
                        ip
                    ));
                }

                // 192.168.0.0/16
                if octets[0] == 192 && octets[1] == 168 {
                    return Err(format!(
                        "Private IP addresses (192.168.0.0/16) are not allowed: {}. Enable private scanning if authorized.",
                        ip
                    ));
                }
            }

            // Check for broadcast address (255.255.255.255)
            if octets == [255, 255, 255, 255] {
                return Err(format!(
                    "Broadcast address is not allowed: {}",
                    ip
                ));
            }

            // Check for zero address (0.0.0.0)
            if octets == [0, 0, 0, 0] {
                return Err(format!(
                    "Zero address is not allowed: {}",
                    ip
                ));
            }
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();

            // Check for localhost (::1)
            if ipv6.is_loopback() {
                if !config.allow_localhost {
                    return Err(format!(
                        "Localhost addresses (::1) are not allowed: {}",
                        ip
                    ));
                }
            }

            // Check for link-local (fe80::/10)
            if segments[0] >= 0xfe80 && segments[0] <= 0xfebf {
                return Err(format!(
                    "Link-local addresses (fe80::/10) are not allowed: {}",
                    ip
                ));
            }

            // Check for unique local addresses (fc00::/7) - IPv6 equivalent of private IPs
            if !config.allow_private {
                if segments[0] >= 0xfc00 && segments[0] <= 0xfdff {
                    return Err(format!(
                        "Unique local addresses (fc00::/7) are not allowed: {}. Enable private scanning if authorized.",
                        ip
                    ));
                }
            }

            // Check for unspecified address (::)
            if ipv6.is_unspecified() {
                return Err(format!(
                    "Unspecified address is not allowed: {}",
                    ip
                ));
            }
        }
    }

    Ok(())
}

/// Validate hostname format (basic validation)
fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    // Split into labels
    let labels: Vec<&str> = hostname.split('.').collect();

    for label in labels {
        // Each label must be 1-63 characters
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        // Each label must start and end with alphanumeric
        if !label.chars().next().unwrap().is_alphanumeric()
            || !label.chars().last().unwrap().is_alphanumeric() {
            return false;
        }

        // Each label can only contain alphanumeric and hyphens
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

/// Validate port range
fn validate_port_range(port_range: (u16, u16)) -> Result<(), String> {
    let (start, end) = port_range;

    if start == 0 {
        return Err("Port range start must be at least 1".to_string());
    }

    if start > end {
        return Err(format!(
            "Invalid port range: start ({}) is greater than end ({})",
            start, end
        ));
    }

    Ok(())
}

/// Validate thread count
fn validate_threads(threads: usize) -> Result<(), String> {
    if threads == 0 {
        return Err("Thread count must be at least 1".to_string());
    }

    if threads > 1000 {
        return Err(format!(
            "Thread count ({}) exceeds maximum allowed (1000)",
            threads
        ));
    }

    Ok(())
}

/// Validate scan name
fn validate_scan_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("Scan name cannot be empty".to_string());
    }

    if name.len() > 255 {
        return Err(format!(
            "Scan name too long ({} characters). Maximum is 255 characters",
            name.len()
        ));
    }

    Ok(())
}

/// Create a new network scan
#[utoipa::path(
    post,
    path = "/api/scans",
    tag = "Scans",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = openapi::CreateScanRequestSchema,
        description = "Scan configuration"
    ),
    responses(
        (status = 200, description = "Scan created and started", body = openapi::ScanResultSchema),
        (status = 400, description = "Invalid scan parameters", body = openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = openapi::ErrorResponse)
    )
)]
pub async fn create_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_request: web::Json<models::CreateScanRequest>,
) -> Result<HttpResponse> {
    // Validate scan name
    if let Err(e) = validate_scan_name(&scan_request.name) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": e
        })));
    }

    // Validate targets
    let validation_config = ValidationConfig::default();
    if let Err(e) = validate_scan_targets(&scan_request.targets, &validation_config) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": e
        })));
    }

    // Validate port range
    if let Err(e) = validate_port_range(scan_request.port_range) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": e
        })));
    }

    // Validate UDP port range if provided
    if let Some(udp_range) = scan_request.udp_port_range {
        if let Err(e) = validate_port_range(udp_range) {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("UDP port range invalid: {}", e)
            })));
        }
    }

    // Validate thread count
    if let Err(e) = validate_threads(scan_request.threads) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": e
        })));
    }

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
    let scan_name = scan.name.clone();
    let pool_clone = pool.get_ref().clone();
    let user_id = claims.sub.clone();

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
        skip_host_discovery: false, // Web API always performs discovery
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

                // Update asset inventory from scan results
                for host in &results {
                    // Upsert asset
                    let asset_result = db::assets::upsert_asset(
                        &pool_clone,
                        &user_id,
                        &host.target.ip.to_string(),
                        host.target.hostname.as_deref(),
                        None, // mac_address not available in HostInfo
                        host.os_guess.as_ref().map(|os| os.os_family.as_str()),
                        host.os_guess.as_ref().and_then(|os| os.os_version.as_deref()),
                        &scan_id,
                    )
                    .await;

                    if let Ok(asset) = asset_result {
                        // Upsert ports for this asset
                        for port_info in &host.ports {
                            let protocol_str = match port_info.protocol {
                                crate::types::Protocol::TCP => "TCP",
                                crate::types::Protocol::UDP => "UDP",
                            };
                            let state_str = match port_info.state {
                                crate::types::PortState::Open => "Open",
                                crate::types::PortState::Closed => "Closed",
                                crate::types::PortState::Filtered => "Filtered",
                                crate::types::PortState::OpenFiltered => "OpenFiltered",
                            };
                            let _ = db::assets::upsert_asset_port(
                                &pool_clone,
                                &asset.id,
                                port_info.port as i32,
                                protocol_str,
                                port_info.service.as_ref().map(|s| s.name.as_str()),
                                port_info.service.as_ref().and_then(|s| s.version.as_deref()),
                                state_str,
                            )
                            .await;
                        }
                    }
                }

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

                // Send notifications asynchronously (don't block on completion)
                let pool_for_notifications = pool_clone.clone();
                let user_id_for_notifications = user_id.clone();
                let scan_name_for_notifications = scan_name.clone();
                let results_for_notifications = results.clone();

                tokio::spawn(async move {
                    // Send scan completion notification
                    crate::notifications::sender::send_scan_completion_notification(
                        &pool_for_notifications,
                        &user_id_for_notifications,
                        &scan_name_for_notifications,
                        &results_for_notifications,
                    )
                    .await;

                    // Send critical vulnerability notifications
                    crate::notifications::sender::send_critical_vulnerability_notifications(
                        &pool_for_notifications,
                        &user_id_for_notifications,
                        &scan_name_for_notifications,
                        &results_for_notifications,
                    )
                    .await;
                });
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

/// Get all scans for the authenticated user
#[utoipa::path(
    get,
    path = "/api/scans",
    tag = "Scans",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "List of scans", body = Vec<openapi::ScanResultSchema>),
        (status = 401, description = "Unauthorized", body = openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = openapi::ErrorResponse)
    )
)]
pub async fn get_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let scans = db::get_user_scans(&pool, &claims.sub)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch scans"))?;

    Ok(HttpResponse::Ok().json(scans))
}

/// Get a specific scan by ID
#[utoipa::path(
    get,
    path = "/api/scans/{id}",
    tag = "Scans",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    responses(
        (status = 200, description = "Scan details", body = openapi::ScanResultSchema),
        (status = 401, description = "Unauthorized", body = openapi::ErrorResponse),
        (status = 403, description = "Access denied", body = openapi::ErrorResponse),
        (status = 404, description = "Scan not found", body = openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = openapi::ErrorResponse)
    )
)]
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

/// Get scan results (hosts, ports, vulnerabilities)
#[utoipa::path(
    get,
    path = "/api/scans/{id}/results",
    tag = "Scans",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    responses(
        (status = 200, description = "Scan results"),
        (status = 401, description = "Unauthorized", body = openapi::ErrorResponse),
        (status = 403, description = "Access denied", body = openapi::ErrorResponse),
        (status = 404, description = "Scan not found", body = openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = openapi::ErrorResponse)
    )
)]
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

/// Delete a scan (user-level, verifies ownership)
#[utoipa::path(
    delete,
    path = "/api/scans/{id}",
    tag = "Scans",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    responses(
        (status = 200, description = "Scan deleted successfully", body = openapi::SuccessResponse),
        (status = 401, description = "Unauthorized", body = openapi::ErrorResponse),
        (status = 404, description = "Scan not found or access denied", body = openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = openapi::ErrorResponse)
    )
)]
pub async fn delete_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    let deleted = db::delete_scan(&pool, &scan_id, &claims.sub)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to delete scan"))?;

    if deleted {
        log::info!("User {} deleted scan {}", claims.username, scan_id.as_str());
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Scan deleted successfully"
        })))
    } else {
        // Either scan doesn't exist or user doesn't own it
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found or access denied"
        })))
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

/// Request body for bulk scan delete
#[derive(Debug, serde::Deserialize)]
pub struct BulkDeleteRequest {
    pub scan_ids: Vec<String>,
}

/// Request body for bulk scan export
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct BulkExportRequest {
    pub scan_ids: Vec<String>,
    pub format: String, // "json", "csv", "pdf"
    #[serde(default = "default_true")]
    pub include_vulnerabilities: bool,
    #[serde(default = "default_true")]
    pub include_services: bool,
}

fn default_true() -> bool {
    true
}

/// Export a single scan in CSV format
pub async fn export_scan_csv(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Fetch scan and verify ownership
    let scan = db::get_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch scan"))?;

    let scan = match scan {
        Some(s) => {
            if s.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }
            s
        }
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            })));
        }
    };

    // Parse results
    let results_json = scan.results.ok_or_else(|| {
        actix_web::error::ErrorBadRequest("Scan has no results yet")
    })?;

    let hosts: Vec<HostInfo> = serde_json::from_str(&results_json)
        .map_err(|e| {
            log::error!("Failed to parse scan results: {}", e);
            actix_web::error::ErrorInternalServerError("Invalid scan results format")
        })?;

    // Generate CSV in memory
    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join(format!("scan_{}.csv", scan_id));
    let temp_path_str = temp_path.to_string_lossy().to_string();

    crate::reports::formats::csv::generate(&hosts, &temp_path_str)
        .await
        .map_err(|e| {
            log::error!("Failed to generate CSV: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to generate CSV export")
        })?;

    // Read file and return as response
    let csv_data = tokio::fs::read(&temp_path)
        .await
        .map_err(|e| {
            log::error!("Failed to read CSV file: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to read export file")
        })?;

    // Clean up temp file
    let _ = tokio::fs::remove_file(&temp_path).await;

    let filename = format!("scan_{}.csv", scan.name.replace(" ", "_"));

    Ok(HttpResponse::Ok()
        .content_type("text/csv")
        .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
        .body(csv_data))
}

/// Bulk export multiple scans as ZIP archive
#[utoipa::path(
    post,
    path = "/api/scans/bulk-export",
    tag = "Scans",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = inline(BulkExportRequest),
        description = "List of scan IDs and export format. Body: {\"scan_ids\": [\"id1\", \"id2\"], \"format\": \"json|csv\", \"include_vulnerabilities\": true, \"include_services\": true}"
    ),
    responses(
        (status = 200, description = "ZIP archive of exported scans", content_type = "application/zip"),
        (status = 400, description = "Invalid request", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 403, description = "Access denied to one or more scans", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "One or more scans not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn bulk_export_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<BulkExportRequest>,
) -> Result<HttpResponse> {
    // Validate request
    if request.scan_ids.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one scan ID must be specified"
        })));
    }

    if request.scan_ids.len() > 100 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Maximum 100 scans per export request"
        })));
    }

    let format = request.format.to_lowercase();
    if !["json", "csv", "pdf"].contains(&format.as_str()) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid format. Must be 'json', 'csv', or 'pdf'"
        })));
    }

    // Fetch all scans and verify ownership
    let mut scans = Vec::new();
    for scan_id in &request.scan_ids {
        let scan = db::get_scan_by_id(&pool, scan_id)
            .await
            .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch scan"))?;

        match scan {
            Some(s) => {
                if s.user_id != claims.sub {
                    return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                        "error": format!("Access denied to scan {}", scan_id)
                    })));
                }
                scans.push(s);
            }
            None => {
                return Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": format!("Scan {} not found", scan_id)
                })));
            }
        }
    }

    // Create ZIP archive
    let temp_dir = std::env::temp_dir();
    let zip_path = temp_dir.join(format!("scans_export_{}.zip", uuid::Uuid::new_v4()));
    let zip_file = std::fs::File::create(&zip_path)
        .map_err(|e| {
            log::error!("Failed to create ZIP file: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create export archive")
        })?;

    let mut zip = zip::ZipWriter::new(zip_file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);

    // Add each scan to the ZIP
    for scan in scans {
        if let Some(results_json) = scan.results {
            let hosts: Vec<HostInfo> = serde_json::from_str(&results_json)
                .map_err(|e| {
                    log::error!("Failed to parse scan results: {}", e);
                    actix_web::error::ErrorInternalServerError("Invalid scan results format")
                })?;

            let safe_name = scan.name.replace(" ", "_").replace("/", "_");
            let filename = match format.as_str() {
                "csv" => {
                    // Generate CSV
                    let csv_temp = temp_dir.join(format!("temp_{}.csv", uuid::Uuid::new_v4()));
                    let csv_temp_str = csv_temp.to_string_lossy().to_string();
                    crate::reports::formats::csv::generate(&hosts, &csv_temp_str)
                        .await
                        .map_err(|e| {
                            log::error!("Failed to generate CSV: {}", e);
                            actix_web::error::ErrorInternalServerError("Failed to generate CSV")
                        })?;

                    let csv_data = tokio::fs::read(&csv_temp).await
                        .map_err(|e| {
                            log::error!("Failed to read CSV: {}", e);
                            actix_web::error::ErrorInternalServerError("Failed to read CSV")
                        })?;

                    let _ = tokio::fs::remove_file(&csv_temp).await;

                    let name = format!("{}_{}.csv", safe_name, scan.id);
                    zip.start_file(&name, options)
                        .map_err(|e| {
                            log::error!("Failed to add file to ZIP: {}", e);
                            actix_web::error::ErrorInternalServerError("Failed to add file to archive")
                        })?;
                    zip.write_all(&csv_data)
                        .map_err(|e| {
                            log::error!("Failed to write to ZIP: {}", e);
                            actix_web::error::ErrorInternalServerError("Failed to write to archive")
                        })?;
                    name
                }
                "json" => {
                    // Export as JSON
                    let json_data = if request.include_vulnerabilities && request.include_services {
                        serde_json::to_string_pretty(&hosts)
                    } else {
                        // Filter data based on flags
                        let filtered: Vec<_> = hosts.iter().map(|host| {
                            let mut h = host.clone();
                            if !request.include_vulnerabilities {
                                h.vulnerabilities.clear();
                            }
                            if !request.include_services {
                                for port in &mut h.ports {
                                    port.service = None;
                                }
                            }
                            h
                        }).collect();
                        serde_json::to_string_pretty(&filtered)
                    }.map_err(|e| {
                        log::error!("Failed to serialize JSON: {}", e);
                        actix_web::error::ErrorInternalServerError("Failed to generate JSON")
                    })?;

                    let name = format!("{}_{}.json", safe_name, scan.id);
                    zip.start_file(&name, options)
                        .map_err(|e| {
                            log::error!("Failed to add file to ZIP: {}", e);
                            actix_web::error::ErrorInternalServerError("Failed to add file to archive")
                        })?;
                    zip.write_all(json_data.as_bytes())
                        .map_err(|e| {
                            log::error!("Failed to write to ZIP: {}", e);
                            actix_web::error::ErrorInternalServerError("Failed to write to archive")
                        })?;
                    name
                }
                _ => {
                    return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                        "error": "PDF export not yet implemented for bulk operations"
                    })));
                }
            };

            log::info!("Added {} to export archive", filename);
        }
    }

    zip.finish()
        .map_err(|e| {
            log::error!("Failed to finalize ZIP: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to finalize archive")
        })?;

    // Read ZIP file and return as response
    let zip_data = tokio::fs::read(&zip_path)
        .await
        .map_err(|e| {
            log::error!("Failed to read ZIP file: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to read export archive")
        })?;

    // Clean up temp file
    let _ = tokio::fs::remove_file(&zip_path).await;

    Ok(HttpResponse::Ok()
        .content_type("application/zip")
        .insert_header(("Content-Disposition", "attachment; filename=\"scans_export.zip\""))
        .body(zip_data))
}

/// Bulk delete multiple scans
#[utoipa::path(
    post,
    path = "/api/scans/bulk-delete",
    tag = "Scans",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = openapi::BulkDeleteRequestSchema,
        description = "List of scan IDs to delete"
    ),
    responses(
        (status = 200, description = "Scans deleted"),
        (status = 400, description = "Invalid request", body = openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = openapi::ErrorResponse)
    )
)]
pub async fn bulk_delete_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<BulkDeleteRequest>,
) -> Result<HttpResponse> {
    // Validate request
    if request.scan_ids.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one scan ID must be specified"
        })));
    }

    if request.scan_ids.len() > 100 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Maximum 100 scans per delete request"
        })));
    }

    let mut deleted_count = 0;
    let mut failed_ids = Vec::new();

    // Delete each scan (verifies ownership)
    for scan_id in &request.scan_ids {
        match db::delete_scan(&pool, scan_id, &claims.sub).await {
            Ok(true) => {
                deleted_count += 1;
                log::info!("User {} deleted scan {} via bulk operation", claims.username, scan_id);
            }
            Ok(false) => {
                // Scan doesn't exist or user doesn't own it
                failed_ids.push(scan_id.clone());
            }
            Err(e) => {
                log::error!("Failed to delete scan {}: {}", scan_id, e);
                failed_ids.push(scan_id.clone());
            }
        }
    }

    if failed_ids.is_empty() {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "deleted": deleted_count,
            "message": format!("Successfully deleted {} scan(s)", deleted_count)
        })))
    } else {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "deleted": deleted_count,
            "failed": failed_ids.len(),
            "failed_ids": failed_ids,
            "message": format!("Deleted {} scan(s), {} failed", deleted_count, failed_ids.len())
        })))
    }
}

/// Get aggregated statistics for all active scans
pub async fn get_aggregated_stats(
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let stats = crate::web::websocket::aggregator::get_aggregated_stats().await;

    Ok(HttpResponse::Ok().json(stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_scan_name() {
        // Valid names
        assert!(validate_scan_name("Test Scan").is_ok());
        assert!(validate_scan_name("Network Scan 123").is_ok());

        // Empty name
        assert!(validate_scan_name("").is_err());
        assert!(validate_scan_name("   ").is_err());

        // Too long name
        let long_name = "a".repeat(256);
        assert!(validate_scan_name(&long_name).is_err());

        // Maximum valid length
        let max_name = "a".repeat(255);
        assert!(validate_scan_name(&max_name).is_ok());
    }

    #[test]
    fn test_validate_port_range() {
        // Valid ranges
        assert!(validate_port_range((1, 100)).is_ok());
        assert!(validate_port_range((80, 80)).is_ok());
        assert!(validate_port_range((1, 65535)).is_ok());

        // Invalid ranges
        assert!(validate_port_range((0, 100)).is_err());
        assert!(validate_port_range((100, 50)).is_err());
    }

    #[test]
    fn test_validate_threads() {
        // Valid thread counts
        assert!(validate_threads(1).is_ok());
        assert!(validate_threads(100).is_ok());
        assert!(validate_threads(1000).is_ok());

        // Invalid thread counts
        assert!(validate_threads(0).is_err());
        assert!(validate_threads(1001).is_err());
    }

    #[test]
    fn test_validate_ip_address_localhost() {
        let config = ValidationConfig::default();

        // Localhost should be rejected
        let localhost_v4: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(validate_ip_address(&localhost_v4, &config).is_err());

        let localhost_v6: IpAddr = "::1".parse().unwrap();
        assert!(validate_ip_address(&localhost_v6, &config).is_err());

        // Allow localhost when configured
        let allow_config = ValidationConfig {
            allow_localhost: true,
            ..Default::default()
        };
        assert!(validate_ip_address(&localhost_v4, &allow_config).is_ok());
    }

    #[test]
    fn test_validate_ip_address_private() {
        let config = ValidationConfig::default();

        // Private IPs should be rejected
        let private_10: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(validate_ip_address(&private_10, &config).is_err());

        let private_172: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(validate_ip_address(&private_172, &config).is_err());

        let private_192: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(validate_ip_address(&private_192, &config).is_err());

        // Allow private when configured
        let allow_config = ValidationConfig {
            allow_private: true,
            ..Default::default()
        };
        assert!(validate_ip_address(&private_10, &allow_config).is_ok());
        assert!(validate_ip_address(&private_172, &allow_config).is_ok());
        assert!(validate_ip_address(&private_192, &allow_config).is_ok());
    }

    #[test]
    fn test_validate_ip_address_link_local() {
        let config = ValidationConfig::default();

        // Link-local should always be rejected
        let link_local_v4: IpAddr = "169.254.1.1".parse().unwrap();
        assert!(validate_ip_address(&link_local_v4, &config).is_err());

        let link_local_v6: IpAddr = "fe80::1".parse().unwrap();
        assert!(validate_ip_address(&link_local_v6, &config).is_err());
    }

    #[test]
    fn test_validate_ip_address_public() {
        let config = ValidationConfig::default();

        // Public IPs should be allowed
        let google_dns: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(validate_ip_address(&google_dns, &config).is_ok());

        let cloudflare_dns: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(validate_ip_address(&cloudflare_dns, &config).is_ok());
    }

    #[test]
    fn test_is_valid_hostname() {
        // Valid hostnames
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("sub.example.com"));
        assert!(is_valid_hostname("my-server.example.org"));
        assert!(is_valid_hostname("server123.example.net"));

        // Invalid hostnames
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("-example.com"));
        assert!(!is_valid_hostname("example-.com"));
        assert!(!is_valid_hostname("exam ple.com"));
        assert!(!is_valid_hostname("example..com"));

        // Too long hostname
        let long_hostname = format!("{}.com", "a".repeat(250));
        assert!(!is_valid_hostname(&long_hostname));

        // Too long label
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(!is_valid_hostname(&long_label));
    }

    #[test]
    fn test_validate_scan_targets_empty() {
        let config = ValidationConfig::default();

        // Empty targets
        let targets: Vec<String> = vec![];
        assert!(validate_scan_targets(&targets, &config).is_err());

        // Empty string
        let targets = vec!["".to_string()];
        assert!(validate_scan_targets(&targets, &config).is_err());
    }

    #[test]
    fn test_validate_scan_targets_single_ip() {
        let config = ValidationConfig {
            allow_private: false,
            allow_localhost: false,
            max_hosts: 256,
        };

        // Valid public IP
        let targets = vec!["8.8.8.8".to_string()];
        assert!(validate_scan_targets(&targets, &config).is_ok());

        // Private IP (rejected)
        let targets = vec!["192.168.1.1".to_string()];
        assert!(validate_scan_targets(&targets, &config).is_err());

        // Private IP (allowed with config)
        let allow_config = ValidationConfig {
            allow_private: true,
            ..config
        };
        let targets = vec!["192.168.1.1".to_string()];
        assert!(validate_scan_targets(&targets, &allow_config).is_ok());
    }

    #[test]
    fn test_validate_scan_targets_cidr() {
        let config = ValidationConfig {
            allow_private: true,
            allow_localhost: false,
            max_hosts: 256,
        };

        // Valid CIDR
        let targets = vec!["192.168.1.0/24".to_string()];
        assert!(validate_scan_targets(&targets, &config).is_ok());

        // CIDR too large
        let targets = vec!["192.168.0.0/16".to_string()]; // 65536 hosts
        assert!(validate_scan_targets(&targets, &config).is_err());

        // Small CIDR within limit
        let targets = vec!["192.168.1.0/25".to_string()]; // 128 hosts
        assert!(validate_scan_targets(&targets, &config).is_ok());
    }

    #[test]
    fn test_validate_scan_targets_hostname() {
        let config = ValidationConfig::default();

        // Valid hostname
        let targets = vec!["example.com".to_string()];
        assert!(validate_scan_targets(&targets, &config).is_ok());

        // Invalid hostname
        let targets = vec!["invalid..hostname".to_string()];
        assert!(validate_scan_targets(&targets, &config).is_err());
    }

    #[test]
    fn test_validate_scan_targets_multiple() {
        let config = ValidationConfig {
            allow_private: true,
            allow_localhost: false,
            max_hosts: 256,
        };

        // Multiple valid targets
        let targets = vec![
            "192.168.1.1".to_string(),
            "192.168.1.2".to_string(),
            "example.com".to_string(),
        ];
        assert!(validate_scan_targets(&targets, &config).is_ok());

        // Too many hosts total
        let targets = vec![
            "192.168.1.0/24".to_string(),  // 256 hosts
            "192.168.2.1".to_string(),      // +1 = 257 hosts
        ];
        assert!(validate_scan_targets(&targets, &config).is_err());
    }

    #[test]
    fn test_validate_scan_targets_invalid_format() {
        let config = ValidationConfig::default();

        // Invalid format
        let targets = vec!["not-an-ip-or-hostname!@#".to_string()];
        assert!(validate_scan_targets(&targets, &config).is_err());

        // Invalid CIDR
        let targets = vec!["192.168.1.0/33".to_string()]; // Invalid prefix
        assert!(validate_scan_targets(&targets, &config).is_err());
    }
}
