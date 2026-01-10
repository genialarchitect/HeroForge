use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;
use std::net::IpAddr;
use ipnetwork::IpNetwork;
use std::io::Write;

use crate::db::{self, models, quotas::{self, QuotaType}};
use crate::types::{ScanConfig, HostInfo, ScanProgressMessage};
use crate::web::auth;
use crate::web::auth::org_context::OrganizationContext;
use crate::scanner;
use crate::vpn::{VpnManager, ConnectionMode, VpnType};

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
        // Note: We already verified label is non-empty above, but use match for safety
        let first_char = match label.chars().next() {
            Some(c) => c,
            None => return false,
        };
        let last_char = match label.chars().last() {
            Some(c) => c,
            None => return false,
        };
        if !first_char.is_alphanumeric() || !last_char.is_alphanumeric() {
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
        content = crate::web::openapi::CreateScanRequestSchema,
        description = "Scan configuration"
    ),
    responses(
        (status = 200, description = "Scan created and started", body = crate::web::openapi::ScanResultSchema),
        (status = 400, description = "Invalid scan parameters", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn create_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    org_context: OrganizationContext,
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

    // Check organization quota for scans per day
    if let Some(org_id) = org_context.org_id() {
        match quotas::check_quota(&pool, org_id, QuotaType::ScansPerDay).await {
            Ok(quota_check) => {
                if !quota_check.allowed {
                    return Ok(HttpResponse::TooManyRequests().json(serde_json::json!({
                        "error": "Daily scan limit reached for your organization",
                        "quota_type": "scans_per_day",
                        "current": quota_check.current,
                        "limit": quota_check.limit
                    })));
                }
            }
            Err(e) => {
                log::warn!("Failed to check scan quota for org {}: {}", org_id, e);
                // Continue anyway - don't block scans on quota check failures
            }
        }
    }

    // Create scan record in database
    let scan = db::create_scan(
        &pool,
        &claims.sub,
        &scan_request.name,
        &scan_request.targets,
        scan_request.customer_id.as_deref(),
        scan_request.engagement_id.as_deref(),
    )
    .await
    .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create scan"))?;

    // Increment organization quota usage for scans
    if let Some(org_id) = org_context.org_id() {
        if let Err(e) = quotas::increment_quota_usage(&pool, org_id, QuotaType::ScansPerDay, 1).await {
            log::warn!("Failed to increment scan quota for org {}: {}", org_id, e);
            // Don't fail the scan if quota tracking fails
        }
    }

    // Add tags to scan if provided
    if !scan_request.tag_ids.is_empty() {
        if let Err(e) = db::scans::add_tags_to_scan(&pool, &scan.id, &scan_request.tag_ids).await {
            log::warn!("Failed to add tags to scan {}: {}", scan.id, e);
            // Don't fail scan creation if tagging fails
        }
    }

    // Load exclusions for this scan
    let mut exclusion_rules: Vec<crate::db::exclusions::ExclusionRule> = Vec::new();

    // Load global exclusions unless explicitly skipped
    if !scan_request.skip_global_exclusions {
        match db::get_global_exclusions(&pool, &claims.sub).await {
            Ok(global_exclusions) => {
                for exc in &global_exclusions {
                    exclusion_rules.push(exc.into());
                }
                if !global_exclusions.is_empty() {
                    log::info!(
                        "Loaded {} global exclusion(s) for scan",
                        global_exclusions.len()
                    );
                }
            }
            Err(e) => {
                log::warn!("Failed to load global exclusions: {}", e);
                // Continue without global exclusions
            }
        }
    }

    // Load per-scan exclusions if specified
    if !scan_request.exclusion_ids.is_empty() {
        match db::get_exclusions_by_ids(&pool, &claims.sub, &scan_request.exclusion_ids).await {
            Ok(scan_exclusions) => {
                for exc in &scan_exclusions {
                    exclusion_rules.push(exc.into());
                }
                log::info!(
                    "Loaded {} per-scan exclusion(s)",
                    scan_exclusions.len()
                );
            }
            Err(e) => {
                log::warn!("Failed to load per-scan exclusions: {}", e);
                // Continue without per-scan exclusions
            }
        }
    }

    // Start scan in background - clone only what's needed for the spawned task
    let scan_id = scan.id.clone();
    let scan_name = scan.name.clone();
    let pool_clone = pool.get_ref().clone();
    let user_id = claims.sub.clone();
    let targets = scan_request.targets.clone(); // Clone once, use in config

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

    // Extract vpn_config_id before creating config (avoid double clone)
    let vpn_config_id = scan_request.vpn_config_id.clone();

    let config = ScanConfig {
        targets, // Use pre-cloned targets
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
        // Use defaults for scanner-specific timeouts
        service_detection_timeout: None,
        dns_timeout: None,
        syn_timeout: None,
        udp_timeout: None,
        vpn_config_id: vpn_config_id.clone(), // Clone for config, original used in spawned task
        exclusions: exclusion_rules,
    };

    tokio::spawn(async move {
        // Create broadcast channel for this scan
        let tx = crate::web::broadcast::create_scan_channel(scan_id.clone()).await;

        // Send scan started message
        let _ = tx.send(ScanProgressMessage::ScanStarted {
            scan_id: scan_id.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });

        // Update status to running
        let _ = db::update_scan_status(&pool_clone, &scan_id, "running", None, None).await;

        // Dispatch webhook for scan started
        {
            let pool_for_webhook = pool_clone.clone();
            let user_id_for_webhook = user_id.clone();
            let scan_id_for_webhook = scan_id.clone();
            let scan_name_for_webhook = scan_name.clone();
            let targets_for_webhook = config.targets.clone();

            tokio::spawn(async move {
                if let Err(e) = crate::webhooks::dispatch_scan_started(
                    &pool_for_webhook,
                    &user_id_for_webhook,
                    &scan_id_for_webhook,
                    &scan_name_for_webhook,
                    &targets_for_webhook,
                )
                .await
                {
                    log::error!("Failed to dispatch scan.started webhooks: {}", e);
                }
            });
        }

        // Connect to VPN if configured for this scan
        let mut vpn_connection_id: Option<String> = None;
        let mut vpn_config_name: Option<String> = None;

        if let Some(vpn_id) = &vpn_config_id {
            // Get VPN config for connection
            if let Ok(Some(vpn_config)) = crate::db::vpn::get_vpn_config_by_id(&pool_clone, vpn_id).await {
                // Clone name once and reuse via vpn_config_name
                let config_name = vpn_config.name.clone();
                vpn_config_name = Some(config_name.clone());

                // Parse VPN type from config
                let vpn_type = match vpn_config.vpn_type.parse::<VpnType>() {
                    Ok(t) => t,
                    Err(e) => {
                        log::error!("Invalid VPN type for config {}: {}", vpn_id, e);
                        let _ = tx.send(ScanProgressMessage::VpnError {
                            config_name,
                            message: format!("Invalid VPN type: {}", e),
                        });
                        let _ = db::update_scan_status(
                            &pool_clone,
                            &scan_id,
                            "failed",
                            None,
                            Some(&format!("Invalid VPN type: {}", e)),
                        )
                        .await;
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        crate::web::broadcast::remove_scan_channel(&scan_id).await;
                        return;
                    }
                };

                // Send VPN connecting message (use vpn_config_name which is already cloned)
                if let Some(ref name) = vpn_config_name {
                    let _ = tx.send(ScanProgressMessage::VpnConnecting {
                        config_name: name.clone(),
                    });
                }

                // Connect to VPN
                let config_file_path = std::path::Path::new(&vpn_config.config_file_path);
                match VpnManager::global()
                    .connect(
                        &user_id,
                        vpn_id,
                        vpn_config_name.as_deref().unwrap_or_default(),
                        vpn_type,
                        config_file_path,
                        vpn_config.encrypted_credentials.as_deref(),
                        ConnectionMode::PerScan,
                        Some(scan_id.clone()),
                    )
                    .await
                {
                    Ok(conn_info) => {
                        vpn_connection_id = Some(conn_info.id.clone());
                        if let Some(ref name) = vpn_config_name {
                            let _ = tx.send(ScanProgressMessage::VpnConnected {
                                config_name: name.clone(),
                                assigned_ip: conn_info.assigned_ip.clone(),
                            });
                            log::info!(
                                "VPN connected for scan {}: {} (IP: {:?})",
                                scan_id,
                                name,
                                conn_info.assigned_ip
                            );
                        }

                        // Update last_used_at for the VPN config
                        let _ = crate::db::vpn::update_vpn_config_last_used(&pool_clone, vpn_id).await;
                    }
                    Err(e) => {
                        log::error!("Failed to connect VPN for scan {}: {}", scan_id, e);
                        if let Some(ref name) = vpn_config_name {
                            let _ = tx.send(ScanProgressMessage::VpnError {
                                config_name: name.clone(),
                                message: e.to_string(),
                            });
                        }
                        let _ = tx.send(ScanProgressMessage::Error {
                            message: format!("VPN connection failed: {}", e),
                        });
                        let _ = db::update_scan_status(
                            &pool_clone,
                            &scan_id,
                            "failed",
                            None,
                            Some(&format!("VPN connection failed: {}", e)),
                        )
                        .await;

                        // Clean up broadcast channel
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        crate::web::broadcast::remove_scan_channel(&scan_id).await;
                        return;
                    }
                }
            }
        }

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
                // Use Arc to avoid expensive deep clone of results
                let pool_for_notifications = pool_clone.clone();
                let user_id_for_notifications = user_id.clone();
                let scan_name_for_notifications = scan_name.clone();
                let scan_id_for_notifications = scan_id.clone();
                let targets_for_notifications = config.targets.clone();
                let results_for_notifications = std::sync::Arc::new(results);

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

                    // Dispatch webhooks for scan completion
                    let hosts_discovered = results_for_notifications.len();
                    let open_ports: usize = results_for_notifications
                        .iter()
                        .map(|h| h.ports.iter().filter(|p| matches!(p.state, crate::types::PortState::Open)).count())
                        .sum();
                    let (total_vulns, critical, high, medium, low) = {
                        let mut total = 0usize;
                        let mut crit = 0usize;
                        let mut hi = 0usize;
                        let mut med = 0usize;
                        let mut lo = 0usize;
                        for host in results_for_notifications.iter() {
                            for vuln in &host.vulnerabilities {
                                total += 1;
                                match vuln.severity {
                                    crate::types::Severity::Critical => crit += 1,
                                    crate::types::Severity::High => hi += 1,
                                    crate::types::Severity::Medium => med += 1,
                                    crate::types::Severity::Low => lo += 1,
                                }
                            }
                        }
                        (total, crit, hi, med, lo)
                    };

                    if let Err(e) = crate::webhooks::dispatch_scan_completed(
                        &pool_for_notifications,
                        &user_id_for_notifications,
                        &scan_id_for_notifications,
                        &scan_name_for_notifications,
                        &targets_for_notifications,
                        hosts_discovered,
                        open_ports,
                        (total_vulns, critical, high, medium, low),
                    )
                    .await
                    {
                        log::error!("Failed to dispatch scan.completed webhooks: {}", e);
                    }

                    // Run automatic scan processing pipeline
                    let pool_for_processing = pool_for_notifications.clone();
                    let scan_id_for_processing = scan_id_for_notifications.clone();
                    tokio::spawn(async move {
                        log::info!("Starting automatic scan processing for {}", scan_id_for_processing);
                        let processor = crate::scan_processor::ScanProcessor::minimal(
                            std::sync::Arc::new(pool_for_processing)
                        );
                        match processor.process_completed_scan(&scan_id_for_processing).await {
                            Ok(result) => {
                                log::info!(
                                    "Scan processing complete for {}: {} vulns extracted, {} enriched, {} AI scores",
                                    scan_id_for_processing,
                                    result.vulns_extracted,
                                    result.vulns_enriched,
                                    result.ai_scores_calculated
                                );
                            }
                            Err(e) => {
                                log::error!("Scan processing failed for {}: {}", scan_id_for_processing, e);
                            }
                        }
                    });
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

                // Dispatch webhook for scan failure
                let pool_for_webhook = pool_clone.clone();
                let user_id_for_webhook = user_id.clone();
                let scan_id_for_webhook = scan_id.clone();
                let scan_name_for_webhook = scan_name.clone();
                let error_for_webhook = error_msg.clone();

                tokio::spawn(async move {
                    if let Err(e) = crate::webhooks::dispatch_scan_failed(
                        &pool_for_webhook,
                        &user_id_for_webhook,
                        &scan_id_for_webhook,
                        &scan_name_for_webhook,
                        &error_for_webhook,
                    )
                    .await
                    {
                        log::error!("Failed to dispatch scan.failed webhooks: {}", e);
                    }
                });
            }
        }

        // Disconnect VPN if it was connected for this scan
        if let Some(conn_id) = vpn_connection_id {
            if let Some(config_name) = &vpn_config_name {
                let _ = tx.send(ScanProgressMessage::VpnDisconnecting {
                    config_name: config_name.clone(),
                });
            }

            if let Err(e) = VpnManager::global().disconnect_scan(&scan_id).await {
                log::error!("Failed to disconnect VPN after scan {}: {}", scan_id, e);
                if let Some(config_name) = &vpn_config_name {
                    let _ = tx.send(ScanProgressMessage::VpnError {
                        config_name: config_name.clone(),
                        message: format!("Failed to disconnect: {}", e),
                    });
                }
            } else {
                if let Some(config_name) = &vpn_config_name {
                    let _ = tx.send(ScanProgressMessage::VpnDisconnected {
                        config_name: config_name.clone(),
                    });
                }
                log::info!("VPN disconnected after scan {} (connection {})", scan_id, conn_id);
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
        (status = 200, description = "List of scans", body = Vec<crate::web::openapi::ScanResultSchema>),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn get_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    log::info!("get_scans called for user: {}", claims.sub);
    let scans = db::get_user_scans(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch scans: {:?}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch scans")
        })?;

    log::info!("Returning {} scans", scans.len());
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
        (status = 200, description = "Scan details", body = crate::web::openapi::ScanResultSchema),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 403, description = "Access denied", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Scan not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn get_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    log::info!("get_scan called for scan_id: {}, user: {}", scan_id.as_str(), claims.sub);
    let scan = db::get_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch scan {}: {:?}", scan_id.as_str(), e);
            actix_web::error::ErrorInternalServerError("Failed to fetch scan")
        })?;

    log::info!("get_scan result: {:?}", scan.as_ref().map(|s| &s.id));
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
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 403, description = "Access denied", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Scan not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
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
        (status = 200, description = "Scan deleted successfully", body = crate::web::openapi::SuccessResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Scan not found or access denied", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
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

/// Export a single scan in Markdown format
#[utoipa::path(
    get,
    path = "/api/scans/{id}/export/markdown",
    tag = "Scans",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    responses(
        (status = 200, description = "Markdown report", content_type = "text/markdown"),
        (status = 400, description = "Scan has no results", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 403, description = "Access denied", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Scan not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn export_scan_markdown(
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
    let results_json = scan.results.clone().ok_or_else(|| {
        actix_web::error::ErrorBadRequest("Scan has no results yet")
    })?;

    let hosts: Vec<HostInfo> = serde_json::from_str(&results_json)
        .map_err(|e| {
            log::error!("Failed to parse scan results: {}", e);
            actix_web::error::ErrorInternalServerError("Invalid scan results format")
        })?;

    // Generate Markdown report
    let markdown = crate::reports::formats::markdown::generate_markdown_report(&scan, &hosts);

    let filename = format!("scan-{}.md", scan.id);

    Ok(HttpResponse::Ok()
        .content_type("text/markdown; charset=utf-8")
        .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
        .body(markdown))
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
                "pdf" => {
                    // Generate PDF report for this scan
                    use crate::reports::types::{
                        ReportData, ReportTemplate, ReportOptions,
                        ReportSummary, FindingDetail, RemediationRecommendation,
                    };
                    use crate::reports::formats::{html, pdf};

                    // Build report data from scan
                    let report_id = uuid::Uuid::new_v4().to_string();
                    let template = ReportTemplate::technical();
                    let sections = template.default_sections.clone();
                    let summary = ReportSummary::from_hosts(&hosts);
                    let findings = FindingDetail::from_vulnerabilities(&hosts);
                    let remediation = RemediationRecommendation::from_findings(&findings);

                    // Fetch secret findings for this scan
                    let secrets = crate::db::secret_findings::get_findings_by_scan(&pool, &scan.id)
                        .await
                        .unwrap_or_default();

                    let report_data = ReportData {
                        id: report_id.clone(),
                        name: scan.name.clone(),
                        description: Some(format!("Export of scan {}", scan.id)),
                        scan_id: scan.id.clone(),
                        scan_name: scan.name.clone(),
                        created_at: chrono::Utc::now(),
                        scan_date: scan.completed_at.unwrap_or(scan.created_at),
                        template,
                        sections,
                        options: ReportOptions::default(),
                        hosts: hosts.clone(),
                        summary,
                        findings,
                        secrets,
                        remediation,
                        screenshots: Vec::new(),
                    };

                    // Generate HTML content first (same as single PDF generation)
                    let html_content = html::generate_html(&report_data);

                    // Write temporary HTML file
                    let temp_html_path = temp_dir.join(format!("temp_{}.html", report_id));
                    tokio::fs::write(&temp_html_path, &html_content).await
                        .map_err(|e| {
                            log::error!("Failed to write temp HTML: {}", e);
                            actix_web::error::ErrorInternalServerError("Failed to write temp HTML")
                        })?;

                    // Generate PDF from HTML
                    let pdf_temp_path = temp_dir.join(format!("temp_{}.pdf", report_id));

                    // Try wkhtmltopdf first, then chromium
                    let pdf_result = pdf::try_wkhtmltopdf(&temp_html_path, &pdf_temp_path).await;
                    if pdf_result.is_err() {
                        log::warn!("wkhtmltopdf failed for scan {}, trying chromium...", scan.id);
                        pdf::try_chromium(&temp_html_path, &pdf_temp_path).await
                            .map_err(|e| {
                                log::error!("PDF generation failed for scan {}: {}", scan.id, e);
                                actix_web::error::ErrorInternalServerError(
                                    "PDF generation failed. Please ensure wkhtmltopdf or chromium is installed."
                                )
                            })?;
                    }

                    // Clean up temp HTML
                    let _ = tokio::fs::remove_file(&temp_html_path).await;

                    // Read the generated PDF
                    let pdf_data = tokio::fs::read(&pdf_temp_path).await
                        .map_err(|e| {
                            log::error!("Failed to read generated PDF: {}", e);
                            actix_web::error::ErrorInternalServerError("Failed to read generated PDF")
                        })?;

                    // Clean up temp PDF
                    let _ = tokio::fs::remove_file(&pdf_temp_path).await;

                    // Add PDF to ZIP archive
                    let name = format!("{}_{}.pdf", safe_name, scan.id);
                    zip.start_file(&name, options)
                        .map_err(|e| {
                            log::error!("Failed to add PDF to ZIP: {}", e);
                            actix_web::error::ErrorInternalServerError("Failed to add PDF to archive")
                        })?;
                    zip.write_all(&pdf_data)
                        .map_err(|e| {
                            log::error!("Failed to write PDF to ZIP: {}", e);
                            actix_web::error::ErrorInternalServerError("Failed to write PDF to archive")
                        })?;
                    name
                }
                _ => {
                    return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                        "error": "Invalid format. Must be 'json', 'csv', or 'pdf'"
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
        content = crate::web::openapi::BulkDeleteRequestSchema,
        description = "List of scan IDs to delete"
    ),
    responses(
        (status = 200, description = "Scans deleted"),
        (status = 400, description = "Invalid request", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
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

// ============================================================================
// SSL/TLS Report API
// ============================================================================

/// SSL Report response structure
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct SslReportEntry {
    pub host: String,
    pub port: u16,
    pub service: Option<String>,
    pub grade: String,
    pub overall_score: u8,
    pub protocol_score: u8,
    pub cipher_score: u8,
    pub certificate_score: u8,
    pub key_exchange_score: u8,
    pub vulnerabilities_count: usize,
    pub recommendations_count: usize,
    #[serde(flatten)]
    pub ssl_info: crate::types::SslInfo,
}

/// SSL Report summary
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct SslReportSummary {
    pub scan_id: String,
    pub scan_name: String,
    pub total_ssl_services: usize,
    pub grade_distribution: std::collections::HashMap<String, usize>,
    pub average_score: u8,
    pub services_with_critical_issues: usize,
    pub services_with_high_issues: usize,
    pub entries: Vec<SslReportEntry>,
}

/// Get SSL/TLS report for a scan
/// Returns detailed SSL/TLS grading information for all services with SSL detected
#[utoipa::path(
    get,
    path = "/api/scans/{id}/ssl-report",
    tag = "Scans",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    responses(
        (status = 200, description = "SSL report generated successfully", body = SslReportSummary),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Scan not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn get_ssl_report(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Fetch scan and verify ownership
    let scan = db::get_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch scan"))?;

    let scan = match scan {
        Some(s) => s,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            })));
        }
    };

    // Verify ownership
    if scan.user_id != claims.sub {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })));
    }

    // Parse scan results
    let hosts: Vec<HostInfo> = if let Some(ref results) = scan.results {
        serde_json::from_str(results).unwrap_or_default()
    } else {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "error": "Scan has no results yet",
            "status": scan.status
        })));
    };

    // Collect all SSL entries
    let mut entries = Vec::new();
    let mut grade_distribution: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut total_score: u32 = 0;
    let mut services_with_critical = 0;
    let mut services_with_high = 0;

    for host in &hosts {
        for port in &host.ports {
            if let Some(ref service) = port.service {
                if let Some(ref ssl_info) = service.ssl_info {
                    // Get grade information
                    let (grade_str, overall_score, protocol_score, cipher_score, cert_score, key_score, vuln_count, rec_count, has_critical, has_high) =
                        if let Some(ref grade) = ssl_info.ssl_grade {
                            let has_critical = grade.vulnerabilities_found.iter().any(|v|
                                matches!(v.severity, crate::scanner::ssl_scanner::SslVulnerabilitySeverity::Critical)
                            );
                            let has_high = grade.vulnerabilities_found.iter().any(|v|
                                matches!(v.severity, crate::scanner::ssl_scanner::SslVulnerabilitySeverity::High)
                            );
                            (
                                grade.grade.to_string(),
                                grade.overall_score,
                                grade.protocol_score,
                                grade.cipher_score,
                                grade.certificate_score,
                                grade.key_exchange_score,
                                grade.vulnerabilities_found.len(),
                                grade.recommendations.len(),
                                has_critical,
                                has_high,
                            )
                        } else {
                            // If no grade computed, compute it now
                            let grade = crate::scanner::ssl_scanner::calculate_ssl_grade(ssl_info);
                            let has_critical = grade.vulnerabilities_found.iter().any(|v|
                                matches!(v.severity, crate::scanner::ssl_scanner::SslVulnerabilitySeverity::Critical)
                            );
                            let has_high = grade.vulnerabilities_found.iter().any(|v|
                                matches!(v.severity, crate::scanner::ssl_scanner::SslVulnerabilitySeverity::High)
                            );
                            (
                                grade.grade.to_string(),
                                grade.overall_score,
                                grade.protocol_score,
                                grade.cipher_score,
                                grade.certificate_score,
                                grade.key_exchange_score,
                                grade.vulnerabilities_found.len(),
                                grade.recommendations.len(),
                                has_critical,
                                has_high,
                            )
                        };

                    if has_critical {
                        services_with_critical += 1;
                    }
                    if has_high {
                        services_with_high += 1;
                    }

                    *grade_distribution.entry(grade_str.clone()).or_insert(0) += 1;
                    total_score += overall_score as u32;

                    entries.push(SslReportEntry {
                        host: host.target.ip.to_string(),
                        port: port.port,
                        service: Some(service.name.clone()),
                        grade: grade_str,
                        overall_score,
                        protocol_score,
                        cipher_score,
                        certificate_score: cert_score,
                        key_exchange_score: key_score,
                        vulnerabilities_count: vuln_count,
                        recommendations_count: rec_count,
                        ssl_info: ssl_info.clone(),
                    });
                }
            }
        }
    }

    // Calculate average score
    let average_score = if entries.is_empty() {
        0
    } else {
        (total_score / entries.len() as u32) as u8
    };

    // Sort entries by grade (worst first)
    entries.sort_by(|a, b| {
        // Sort by overall_score ascending (lower = worse)
        a.overall_score.cmp(&b.overall_score)
    });

    let summary = SslReportSummary {
        scan_id: scan.id,
        scan_name: scan.name,
        total_ssl_services: entries.len(),
        grade_distribution,
        average_score,
        services_with_critical_issues: services_with_critical,
        services_with_high_issues: services_with_high,
        entries,
    };

    Ok(HttpResponse::Ok().json(summary))
}

// ============================================================================
// Scan Tags API
// ============================================================================

/// Get all scan tags
#[utoipa::path(
    get,
    path = "/api/scans/tags",
    tag = "Scan Tags",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "List of all scan tags"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn get_scan_tags(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let tags = db::scans::get_all_scan_tags(&pool)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch scan tags: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch scan tags")
        })?;

    Ok(HttpResponse::Ok().json(tags))
}

/// Create a new scan tag
#[utoipa::path(
    post,
    path = "/api/scans/tags",
    tag = "Scan Tags",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = models::CreateScanTagRequest,
        description = "Tag name and color"
    ),
    responses(
        (status = 201, description = "Tag created successfully"),
        (status = 400, description = "Invalid request", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 409, description = "Tag already exists", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn create_scan_tag(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    request: web::Json<models::CreateScanTagRequest>,
) -> Result<HttpResponse> {
    // Validate name
    let name = request.name.trim();
    if name.is_empty() || name.len() > 50 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Tag name must be between 1 and 50 characters"
        })));
    }

    // Validate color format (hex color)
    let color = request.color.trim();
    if !color.starts_with('#') || color.len() != 7 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Color must be a valid hex color (e.g., #06b6d4)"
        })));
    }

    match db::scans::create_scan_tag(&pool, name, color).await {
        Ok(tag) => Ok(HttpResponse::Created().json(tag)),
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("UNIQUE constraint failed") {
                Ok(HttpResponse::Conflict().json(serde_json::json!({
                    "error": "A tag with this name already exists"
                })))
            } else {
                log::error!("Failed to create scan tag: {}", e);
                Err(actix_web::error::ErrorInternalServerError("Failed to create scan tag"))
            }
        }
    }
}

/// Delete a scan tag
#[utoipa::path(
    delete,
    path = "/api/scans/tags/{id}",
    tag = "Scan Tags",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Tag ID")
    ),
    responses(
        (status = 200, description = "Tag deleted successfully"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Tag not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn delete_scan_tag(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    tag_id: web::Path<String>,
) -> Result<HttpResponse> {
    let deleted = db::scans::delete_scan_tag(&pool, &tag_id)
        .await
        .map_err(|e| {
            log::error!("Failed to delete scan tag: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete scan tag")
        })?;

    if deleted {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Tag deleted successfully"
        })))
    } else {
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Tag not found"
        })))
    }
}

/// Predefined tag suggestion for common categorization
#[derive(Debug, serde::Serialize)]
pub struct TagSuggestion {
    pub name: String,
    pub color: String,
    pub category: String,
}

/// Get predefined tag suggestions for common scan categorizations
#[utoipa::path(
    get,
    path = "/api/scans/tags/suggestions",
    tag = "Scan Tags",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Predefined tag suggestions"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn get_tag_suggestions(
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let suggestions = vec![
        // Environment tags
        TagSuggestion { name: "production".to_string(), color: "#ef4444".to_string(), category: "Environment".to_string() },
        TagSuggestion { name: "staging".to_string(), color: "#f59e0b".to_string(), category: "Environment".to_string() },
        TagSuggestion { name: "development".to_string(), color: "#10b981".to_string(), category: "Environment".to_string() },
        TagSuggestion { name: "qa".to_string(), color: "#8b5cf6".to_string(), category: "Environment".to_string() },
        // Type tags
        TagSuggestion { name: "internal".to_string(), color: "#3b82f6".to_string(), category: "Type".to_string() },
        TagSuggestion { name: "external".to_string(), color: "#06b6d4".to_string(), category: "Type".to_string() },
        TagSuggestion { name: "web-app".to_string(), color: "#ec4899".to_string(), category: "Type".to_string() },
        TagSuggestion { name: "infrastructure".to_string(), color: "#84cc16".to_string(), category: "Type".to_string() },
        TagSuggestion { name: "api".to_string(), color: "#a855f7".to_string(), category: "Type".to_string() },
        TagSuggestion { name: "cloud".to_string(), color: "#14b8a6".to_string(), category: "Type".to_string() },
        // Compliance tags
        TagSuggestion { name: "pci".to_string(), color: "#f97316".to_string(), category: "Compliance".to_string() },
        TagSuggestion { name: "hipaa".to_string(), color: "#0ea5e9".to_string(), category: "Compliance".to_string() },
        TagSuggestion { name: "sox".to_string(), color: "#6366f1".to_string(), category: "Compliance".to_string() },
        TagSuggestion { name: "gdpr".to_string(), color: "#22c55e".to_string(), category: "Compliance".to_string() },
        TagSuggestion { name: "nist".to_string(), color: "#eab308".to_string(), category: "Compliance".to_string() },
        // Priority tags
        TagSuggestion { name: "critical".to_string(), color: "#dc2626".to_string(), category: "Priority".to_string() },
        TagSuggestion { name: "high".to_string(), color: "#ea580c".to_string(), category: "Priority".to_string() },
        TagSuggestion { name: "routine".to_string(), color: "#64748b".to_string(), category: "Priority".to_string() },
        // Schedule tags
        TagSuggestion { name: "quarterly".to_string(), color: "#0891b2".to_string(), category: "Schedule".to_string() },
        TagSuggestion { name: "monthly".to_string(), color: "#7c3aed".to_string(), category: "Schedule".to_string() },
        TagSuggestion { name: "weekly".to_string(), color: "#059669".to_string(), category: "Schedule".to_string() },
    ];

    Ok(HttpResponse::Ok().json(suggestions))
}

/// Get tags for a specific scan
#[utoipa::path(
    get,
    path = "/api/scans/{id}/tags",
    tag = "Scan Tags",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    responses(
        (status = 200, description = "Tags for the scan"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Scan not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn get_tags_for_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Verify scan exists and user has access
    let scan = db::get_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch scan"))?;

    match scan {
        Some(scan) => {
            if scan.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            let tags = db::scans::get_scan_tags(&pool, &scan_id)
                .await
                .map_err(|e| {
                    log::error!("Failed to fetch tags for scan: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to fetch tags")
                })?;

            Ok(HttpResponse::Ok().json(tags))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        }))),
    }
}

/// Add tags to a scan
#[utoipa::path(
    post,
    path = "/api/scans/{id}/tags",
    tag = "Scan Tags",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    request_body(
        content = models::AddTagsToScanRequest,
        description = "List of tag IDs to add"
    ),
    responses(
        (status = 200, description = "Tags added successfully"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Scan not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn add_tags_to_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
    request: web::Json<models::AddTagsToScanRequest>,
) -> Result<HttpResponse> {
    // Verify scan exists and user has access
    let scan = db::get_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch scan"))?;

    match scan {
        Some(scan) => {
            if scan.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            db::scans::add_tags_to_scan(&pool, &scan_id, &request.tag_ids)
                .await
                .map_err(|e| {
                    log::error!("Failed to add tags to scan: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to add tags")
                })?;

            // Return updated tags list
            let tags = db::scans::get_scan_tags(&pool, &scan_id)
                .await
                .map_err(|e| {
                    log::error!("Failed to fetch updated tags: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to fetch updated tags")
                })?;

            Ok(HttpResponse::Ok().json(tags))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        }))),
    }
}

/// Remove a tag from a scan
#[utoipa::path(
    delete,
    path = "/api/scans/{id}/tags/{tag_id}",
    tag = "Scan Tags",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Scan ID"),
        ("tag_id" = String, Path, description = "Tag ID to remove")
    ),
    responses(
        (status = 200, description = "Tag removed successfully"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Scan or tag not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn remove_tag_from_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse> {
    let (scan_id, tag_id) = path.into_inner();

    // Verify scan exists and user has access
    let scan = db::get_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch scan"))?;

    match scan {
        Some(scan) => {
            if scan.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            let removed = db::scans::remove_tag_from_scan(&pool, &scan_id, &tag_id)
                .await
                .map_err(|e| {
                    log::error!("Failed to remove tag from scan: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to remove tag")
                })?;

            if removed {
                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "message": "Tag removed successfully"
                })))
            } else {
                Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Tag not found on this scan"
                })))
            }
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        }))),
    }
}

/// Get all scans with their tags
#[utoipa::path(
    get,
    path = "/api/scans/with-tags",
    tag = "Scan Tags",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "List of scans with their tags"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn get_scans_with_tags(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let scans_with_tags = db::scans::get_user_scans_with_tags(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch scans with tags: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch scans with tags")
        })?;

    Ok(HttpResponse::Ok().json(scans_with_tags))
}

// ============================================================================
// Duplicate Scan API
// ============================================================================

/// Duplicate an existing scan configuration
#[utoipa::path(
    post,
    path = "/api/scans/{id}/duplicate",
    tag = "Scans",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Scan ID to duplicate")
    ),
    request_body(
        content = models::DuplicateScanRequest,
        description = "Optional new name for the duplicated scan"
    ),
    responses(
        (status = 201, description = "Scan duplicated successfully"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Scan not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn duplicate_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
    request: web::Json<models::DuplicateScanRequest>,
) -> Result<HttpResponse> {
    // Verify the original scan exists and user has access
    let original_scan = db::get_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch scan"))?;

    match original_scan {
        Some(scan) => {
            if scan.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            // Validate new name if provided
            if let Some(ref name) = request.name {
                if let Err(e) = validate_scan_name(name) {
                    return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                        "error": e
                    })));
                }
            }

            let new_scan = db::scans::duplicate_scan(
                &pool,
                &scan_id,
                &claims.sub,
                request.name.as_deref(),
            )
            .await
            .map_err(|e| {
                log::error!("Failed to duplicate scan: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to duplicate scan")
            })?;

            log::info!(
                "User {} duplicated scan {} as {}",
                claims.username,
                scan_id.as_str(),
                new_scan.id
            );

            Ok(HttpResponse::Created().json(new_scan))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        }))),
    }
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
