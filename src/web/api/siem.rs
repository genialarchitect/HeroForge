use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;

use crate::db::{self, models};
use crate::web::auth;
use crate::integrations::siem::{self, SiemConfig, SiemType, SiemEvent};

/// Get all SIEM settings for the current user
pub async fn get_siem_settings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let settings = db::get_siem_settings(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch SIEM settings: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    Ok(HttpResponse::Ok().json(settings))
}

/// Create new SIEM settings
pub async fn create_siem_settings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<models::CreateSiemSettingsRequest>,
) -> Result<HttpResponse> {
    // Validate SIEM type
    let siem_type = SiemType::from_str(&request.siem_type).ok_or_else(|| {
        actix_web::error::ErrorBadRequest(format!(
            "Invalid SIEM type: {}. Must be 'syslog', 'splunk', or 'elasticsearch'",
            request.siem_type
        ))
    })?;

    // Validate required fields based on SIEM type
    match siem_type {
        SiemType::Syslog => {
            if request.protocol.is_none() {
                return Err(actix_web::error::ErrorBadRequest(
                    "Protocol (tcp or udp) is required for Syslog"
                ));
            }
        }
        SiemType::Splunk => {
            if request.api_key.is_none() {
                return Err(actix_web::error::ErrorBadRequest(
                    "API key is required for Splunk HEC"
                ));
            }
        }
        SiemType::Elasticsearch => {
            // API key is optional for Elasticsearch
        }
    }

    let settings = db::create_siem_settings(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to create SIEM settings: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create settings. Please try again.")
        })?;

    Ok(HttpResponse::Created().json(settings))
}

/// Update SIEM settings
pub async fn update_siem_settings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    settings_id: web::Path<String>,
    request: web::Json<models::UpdateSiemSettingsRequest>,
) -> Result<HttpResponse> {
    // Verify settings belongs to user
    let _existing = db::get_siem_settings_by_id(&pool, &settings_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch SIEM settings: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred.")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("SIEM settings not found"))?;

    let updated_settings = db::update_siem_settings(&pool, &settings_id, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to update SIEM settings: {}", e);
            actix_web::error::ErrorInternalServerError("Update failed. Please try again.")
        })?;

    Ok(HttpResponse::Ok().json(updated_settings))
}

/// Delete SIEM settings
pub async fn delete_siem_settings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    settings_id: web::Path<String>,
) -> Result<HttpResponse> {
    let deleted = db::delete_siem_settings(&pool, &settings_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete SIEM settings: {}", e);
            actix_web::error::ErrorInternalServerError("Delete failed. Please try again.")
        })?;

    if !deleted {
        return Err(actix_web::error::ErrorNotFound("SIEM settings not found"));
    }

    Ok(HttpResponse::NoContent().finish())
}

/// Test SIEM connection
pub async fn test_siem_connection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    settings_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Get settings
    let settings = db::get_siem_settings_by_id(&pool, &settings_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch SIEM settings: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred.")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("SIEM settings not found"))?;

    // Parse SIEM type
    let siem_type = SiemType::from_str(&settings.siem_type).ok_or_else(|| {
        actix_web::error::ErrorBadRequest("Invalid SIEM type")
    })?;

    // Create SIEM exporter
    let config = SiemConfig {
        siem_type,
        endpoint_url: settings.endpoint_url.clone(),
        api_key: settings.api_key.clone(),
        protocol: settings.protocol.clone(),
    };

    let exporter = siem::create_exporter(config)
        .await
        .map_err(|e| {
            log::error!("Failed to create SIEM exporter: {}", e);
            actix_web::error::ErrorBadRequest(format!("Configuration error: {}", e))
        })?;

    // Test connection
    exporter.test_connection()
        .await
        .map_err(|e| {
            log::error!("SIEM connection test failed: {}", e);
            actix_web::error::ErrorBadRequest(format!("Connection test failed: {}", e))
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Connection test successful"
    })))
}

/// Manually export a scan to SIEM
pub async fn export_scan_to_siem(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Get scan results
    let scan = db::get_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch scan: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred.")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Scan not found"))?;

    // Verify ownership
    if scan.user_id != claims.sub {
        return Err(actix_web::error::ErrorForbidden("Access denied"));
    }

    // Get enabled SIEM settings for user
    let all_settings = db::get_siem_settings(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch SIEM settings: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred.")
        })?;

    let enabled_settings: Vec<_> = all_settings
        .into_iter()
        .filter(|s| s.enabled)
        .collect();

    if enabled_settings.is_empty() {
        return Err(actix_web::error::ErrorBadRequest(
            "No enabled SIEM integrations found"
        ));
    }

    // Parse scan results
    let results_json: Vec<crate::types::HostInfo> = if let Some(results_str) = &scan.results {
        serde_json::from_str(results_str).map_err(|e| {
            log::error!("Failed to parse scan results: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to parse scan results")
        })?
    } else {
        return Err(actix_web::error::ErrorBadRequest("Scan has no results"));
    };

    // Convert scan results to SIEM events
    let mut events = Vec::new();

    // Add scan completion event
    events.push(SiemEvent {
        timestamp: scan.completed_at.unwrap_or_else(|| chrono::Utc::now()),
        severity: "info".to_string(),
        event_type: "scan_complete".to_string(),
        source_ip: None,
        destination_ip: None,
        port: None,
        protocol: None,
        message: format!("Scan '{}' completed", scan.name),
        details: serde_json::json!({
            "scan_id": scan.id,
            "scan_name": scan.name,
            "targets": scan.targets,
            "total_hosts": results_json.len(),
        }),
        cve_ids: vec![],
        cvss_score: None,
        scan_id: scan.id.clone(),
        user_id: claims.sub.clone(),
    });

    // Add events for each host and vulnerability
    for host in &results_json {
        let host_ip = host.target.ip.to_string();

        // Add vulnerability events (vulnerabilities are at host level, not port level)
        for vuln in &host.vulnerabilities {
            // Convert Severity enum to string and SIEM severity level
            let severity_str = match vuln.severity {
                crate::types::Severity::Critical => "critical",
                crate::types::Severity::High => "high",
                crate::types::Severity::Medium => "medium",
                crate::types::Severity::Low => "low",
            };

            events.push(SiemEvent {
                timestamp: scan.completed_at.unwrap_or_else(|| chrono::Utc::now()),
                severity: severity_str.to_string(),
                event_type: "vulnerability_found".to_string(),
                source_ip: None,
                destination_ip: Some(host_ip.clone()),
                port: None, // Vulnerabilities are at host level, not tied to specific port
                protocol: None,
                message: vuln.title.clone(),
                details: serde_json::json!({
                    "description": vuln.description,
                    "affected_service": vuln.affected_service,
                    "severity": severity_str,
                }),
                cve_ids: vuln.cve_id.as_ref().map(|id| vec![id.clone()]).unwrap_or_default(),
                cvss_score: None, // CVSS score not currently tracked in Vulnerability struct
                scan_id: scan.id.clone(),
                user_id: claims.sub.clone(),
            });
        }
    }

    // Export to all enabled SIEM systems
    let mut export_count = 0;
    let mut errors = Vec::new();

    for settings in enabled_settings {
        let siem_type = match SiemType::from_str(&settings.siem_type) {
            Some(t) => t,
            None => continue,
        };

        let config = SiemConfig {
            siem_type,
            endpoint_url: settings.endpoint_url.clone(),
            api_key: settings.api_key.clone(),
            protocol: settings.protocol.clone(),
        };

        match siem::create_exporter(config).await {
            Ok(exporter) => {
                match exporter.export_events(&events).await {
                    Ok(_) => export_count += 1,
                    Err(e) => {
                        log::error!("Failed to export to {}: {}", settings.siem_type, e);
                        errors.push(format!("{}: {}", settings.siem_type, e));
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to create exporter for {}: {}", settings.siem_type, e);
                errors.push(format!("{}: {}", settings.siem_type, e));
            }
        }
    }

    if export_count == 0 {
        return Err(actix_web::error::ErrorInternalServerError(
            format!("All exports failed: {}", errors.join(", "))
        ));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "exported_to": export_count,
        "events_count": events.len(),
        "errors": errors,
    })))
}
