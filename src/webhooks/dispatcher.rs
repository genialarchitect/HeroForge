//! Webhook event dispatcher
//!
//! This module provides functions to dispatch webhook events to all
//! subscribed webhooks for a user.

use anyhow::Result;
use sqlx::SqlitePool;

use crate::db;
use super::sender::{send_webhook, DeliveryResult, MAX_FAILURE_COUNT};
use super::types::{WebhookEventType, WebhookPayload};

/// Dispatch a webhook event to all subscribed webhooks for a user
///
/// This function:
/// 1. Finds all active webhooks for the user that subscribe to this event type
/// 2. Sends the payload to each webhook
/// 3. Logs the delivery attempt
/// 4. Updates webhook status (last triggered, failure count)
/// 5. Disables webhooks that exceed the failure threshold
pub async fn dispatch_event(
    pool: &SqlitePool,
    user_id: &str,
    event_type: WebhookEventType,
    data: serde_json::Value,
) -> Result<Vec<DispatchResult>> {
    let event_str = event_type.as_str();

    // Find webhooks subscribed to this event
    let webhooks = db::get_webhooks_for_event(pool, user_id, event_str).await?;

    if webhooks.is_empty() {
        log::debug!("No webhooks subscribed to event '{}' for user {}", event_str, user_id);
        return Ok(vec![]);
    }

    // Create the payload
    let payload = WebhookPayload::new(event_type, data);
    let payload_json = serde_json::to_string(&payload)?;

    let mut results = Vec::new();

    for webhook in webhooks {
        log::info!(
            "Dispatching {} event to webhook '{}' ({})",
            event_str,
            webhook.name,
            webhook.id
        );

        // Send the webhook
        let delivery_result = send_webhook(&webhook, &payload_json).await;

        // Log the delivery
        let _ = db::log_delivery(
            pool,
            &webhook.id,
            event_str,
            &payload_json,
            delivery_result.status_code.map(|s| s as i32),
            delivery_result.response_body.as_deref(),
            delivery_result.error.as_deref(),
        )
        .await;

        // Update webhook status
        let _ = db::update_webhook_status(
            pool,
            &webhook.id,
            delivery_result.status_code.map(|s| s as i32),
            delivery_result.success,
        )
        .await;

        // Check if we should disable the webhook due to too many failures
        if !delivery_result.success {
            // Re-fetch to get updated failure count
            if let Ok(Some(updated_webhook)) = db::get_webhook_by_id_internal(pool, &webhook.id).await {
                if updated_webhook.failure_count >= MAX_FAILURE_COUNT {
                    log::warn!(
                        "Disabling webhook '{}' ({}) due to {} consecutive failures",
                        webhook.name,
                        webhook.id,
                        updated_webhook.failure_count
                    );
                    let _ = db::disable_webhook(pool, &webhook.id).await;
                }
            }
        }

        results.push(DispatchResult {
            webhook_id: webhook.id.clone(),
            webhook_name: webhook.name.clone(),
            success: delivery_result.success,
            status_code: delivery_result.status_code,
            error: delivery_result.error,
            attempts: delivery_result.attempts,
        });
    }

    Ok(results)
}

/// Result of dispatching to a single webhook
#[derive(Debug)]
pub struct DispatchResult {
    pub webhook_id: String,
    pub webhook_name: String,
    pub success: bool,
    pub status_code: Option<u16>,
    pub error: Option<String>,
    pub attempts: u32,
}

/// Helper function to dispatch a scan started event
pub async fn dispatch_scan_started(
    pool: &SqlitePool,
    user_id: &str,
    scan_id: &str,
    scan_name: &str,
    targets: &[String],
) -> Result<()> {
    let data = serde_json::json!({
        "scan_id": scan_id,
        "name": scan_name,
        "targets": targets,
        "started_at": chrono::Utc::now(),
    });

    let _ = dispatch_event(pool, user_id, WebhookEventType::ScanStarted, data).await?;
    Ok(())
}

/// Helper function to dispatch a scan completed event
pub async fn dispatch_scan_completed(
    pool: &SqlitePool,
    user_id: &str,
    scan_id: &str,
    scan_name: &str,
    targets: &[String],
    hosts_discovered: usize,
    open_ports: usize,
    vulns: (usize, usize, usize, usize, usize), // total, critical, high, medium, low
) -> Result<()> {
    let (total, critical, high, medium, low) = vulns;

    let data = serde_json::json!({
        "scan_id": scan_id,
        "name": scan_name,
        "targets": targets,
        "completed_at": chrono::Utc::now(),
        "hosts_discovered": hosts_discovered,
        "open_ports": open_ports,
        "vulnerabilities_found": total,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
    });

    let _ = dispatch_event(pool, user_id, WebhookEventType::ScanCompleted, data).await?;

    // Also dispatch critical vulnerability event if any critical vulns found
    if critical > 0 {
        let critical_data = serde_json::json!({
            "scan_id": scan_id,
            "scan_name": scan_name,
            "critical_count": critical,
            "message": format!("{} critical vulnerabilities found in scan '{}'", critical, scan_name),
        });
        let _ = dispatch_event(pool, user_id, WebhookEventType::VulnerabilityCritical, critical_data).await?;
    }

    Ok(())
}

/// Helper function to dispatch a scan failed event
pub async fn dispatch_scan_failed(
    pool: &SqlitePool,
    user_id: &str,
    scan_id: &str,
    scan_name: &str,
    error: &str,
) -> Result<()> {
    let data = serde_json::json!({
        "scan_id": scan_id,
        "name": scan_name,
        "error": error,
        "failed_at": chrono::Utc::now(),
    });

    let _ = dispatch_event(pool, user_id, WebhookEventType::ScanFailed, data).await?;
    Ok(())
}

/// Helper function to dispatch a vulnerability found event
pub async fn dispatch_vulnerability_found(
    pool: &SqlitePool,
    user_id: &str,
    scan_id: &str,
    vuln_id: &str,
    host_ip: &str,
    port: Option<u16>,
    service: Option<&str>,
    severity: &str,
    title: &str,
    description: Option<&str>,
    cve_ids: &[String],
) -> Result<()> {
    let data = serde_json::json!({
        "scan_id": scan_id,
        "vulnerability_id": vuln_id,
        "host_ip": host_ip,
        "port": port,
        "service": service,
        "severity": severity,
        "title": title,
        "description": description,
        "cve_ids": cve_ids,
    });

    let data_clone = data.clone();
    let _ = dispatch_event(pool, user_id, WebhookEventType::VulnerabilityFound, data).await?;

    // Also dispatch critical event if severity is critical
    if severity.to_lowercase() == "critical" {
        let _ = dispatch_event(pool, user_id, WebhookEventType::VulnerabilityCritical, data_clone).await?;
    }

    Ok(())
}

/// Helper function to dispatch a vulnerability resolved event
pub async fn dispatch_vulnerability_resolved(
    pool: &SqlitePool,
    user_id: &str,
    vuln_id: &str,
    scan_id: &str,
    host_ip: &str,
    severity: &str,
    title: &str,
    resolved_by: Option<&str>,
) -> Result<()> {
    let data = serde_json::json!({
        "vulnerability_id": vuln_id,
        "scan_id": scan_id,
        "host_ip": host_ip,
        "severity": severity,
        "title": title,
        "resolved_by": resolved_by,
        "resolved_at": chrono::Utc::now(),
    });

    let _ = dispatch_event(pool, user_id, WebhookEventType::VulnerabilityResolved, data).await?;
    Ok(())
}

/// Helper function to dispatch an asset discovered event
pub async fn dispatch_asset_discovered(
    pool: &SqlitePool,
    user_id: &str,
    asset_id: &str,
    ip_address: &str,
    hostname: Option<&str>,
    os: Option<&str>,
    open_ports: &[u16],
) -> Result<()> {
    let data = serde_json::json!({
        "asset_id": asset_id,
        "ip_address": ip_address,
        "hostname": hostname,
        "os": os,
        "open_ports": open_ports,
        "discovered_at": chrono::Utc::now(),
    });

    let _ = dispatch_event(pool, user_id, WebhookEventType::AssetDiscovered, data).await?;
    Ok(())
}

/// Helper function to dispatch a compliance violation event
pub async fn dispatch_compliance_violation(
    pool: &SqlitePool,
    user_id: &str,
    scan_id: &str,
    framework: &str,
    control_id: &str,
    control_name: &str,
    severity: &str,
    description: &str,
    affected_hosts: &[String],
) -> Result<()> {
    let data = serde_json::json!({
        "scan_id": scan_id,
        "framework": framework,
        "control_id": control_id,
        "control_name": control_name,
        "severity": severity,
        "description": description,
        "affected_hosts": affected_hosts,
    });

    let _ = dispatch_event(pool, user_id, WebhookEventType::ComplianceViolation, data).await?;
    Ok(())
}

/// Send a test webhook payload
pub async fn send_test_webhook(
    pool: &SqlitePool,
    webhook_id: &str,
    user_id: &str,
) -> Result<DeliveryResult> {
    let webhook = db::get_webhook_by_id(pool, webhook_id, user_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Webhook not found"))?;

    let data = serde_json::json!({
        "message": "This is a test webhook from HeroForge",
        "webhook_id": webhook_id,
        "webhook_name": webhook.name,
        "timestamp": chrono::Utc::now(),
    });

    let payload = WebhookPayload {
        event: "test".to_string(),
        timestamp: chrono::Utc::now(),
        data,
    };

    let payload_json = serde_json::to_string(&payload)?;
    let result = send_webhook(&webhook, &payload_json).await;

    // Log the test delivery
    let _ = db::log_delivery(
        pool,
        webhook_id,
        "test",
        &payload_json,
        result.status_code.map(|s| s as i32),
        result.response_body.as_deref(),
        result.error.as_deref(),
    )
    .await;

    Ok(result)
}
