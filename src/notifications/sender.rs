use anyhow::Result;
use sqlx::SqlitePool;

use super::{NotificationEvent, Notifier, SlackNotifier, TeamsNotifier};
use crate::db;
use crate::types::{HostInfo, Severity};

/// Send scan completion notification if user has it enabled
pub async fn send_scan_completion_notification(
    pool: &SqlitePool,
    user_id: &str,
    scan_name: &str,
    results: &[HostInfo],
) {
    // Get user's notification settings
    let settings = match db::get_notification_settings(pool, user_id).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to get notification settings for user {}: {}", user_id, e);
            return;
        }
    };

    // Calculate statistics from scan results
    let hosts_discovered = results.len();
    let open_ports = results
        .iter()
        .flat_map(|h| &h.ports)
        .filter(|p| matches!(p.state, crate::types::PortState::Open))
        .count();

    let mut critical_vulns = 0;
    let mut high_vulns = 0;
    let mut medium_vulns = 0;
    let mut low_vulns = 0;

    for host in results {
        for vuln in &host.vulnerabilities {
            match vuln.severity {
                Severity::Critical => critical_vulns += 1,
                Severity::High => high_vulns += 1,
                Severity::Medium => medium_vulns += 1,
                Severity::Low => low_vulns += 1,
            }
        }
    }

    let total_vulns = critical_vulns + high_vulns + medium_vulns + low_vulns;

    // Create notification event
    let event = NotificationEvent::ScanCompleted {
        scan_name: scan_name.to_string(),
        hosts_discovered,
        open_ports,
        vulnerabilities_found: total_vulns,
        critical_vulns,
        high_vulns,
        medium_vulns,
        low_vulns,
    };

    // Send to Slack if webhook is configured
    if let Some(slack_url) = &settings.slack_webhook_url {
        if !slack_url.is_empty() {
            let notifier = SlackNotifier::new(slack_url.clone());
            if let Err(e) = notifier.send_notification(&event).await {
                log::error!("Failed to send Slack notification for scan '{}': {}", scan_name, e);
            } else {
                log::info!("Sent Slack notification for completed scan '{}'", scan_name);
            }
        }
    }

    // Send to Teams if webhook is configured
    if let Some(teams_url) = &settings.teams_webhook_url {
        if !teams_url.is_empty() {
            let notifier = TeamsNotifier::new(teams_url.clone());
            if let Err(e) = notifier.send_notification(&event).await {
                log::error!("Failed to send Teams notification for scan '{}': {}", scan_name, e);
            } else {
                log::info!("Sent Teams notification for completed scan '{}'", scan_name);
            }
        }
    }
}

/// Send critical vulnerability notification for each critical/high vulnerability found
pub async fn send_critical_vulnerability_notifications(
    pool: &SqlitePool,
    user_id: &str,
    scan_name: &str,
    results: &[HostInfo],
) {
    // Get user's notification settings
    let settings = match db::get_notification_settings(pool, user_id).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to get notification settings for user {}: {}", user_id, e);
            return;
        }
    };

    // Check if user wants critical vuln notifications
    if !settings.email_on_critical_vuln {
        return;
    }

    // Collect critical and high vulnerabilities
    let mut critical_vulns = Vec::new();

    for host in results {
        for vuln in &host.vulnerabilities {
            // Only notify for Critical and High severity
            if matches!(vuln.severity, Severity::Critical | Severity::High) {
                critical_vulns.push((host, vuln));
            }
        }
    }

    if critical_vulns.is_empty() {
        return;
    }

    log::info!(
        "Found {} critical/high vulnerabilities in scan '{}', sending notifications",
        critical_vulns.len(),
        scan_name
    );

    // Send notification for each critical/high vulnerability
    for (host, vuln) in critical_vulns {
        let severity_str = match vuln.severity {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
        };

        // Find the port this vulnerability is associated with
        let port_info = host.ports.iter()
            .find(|p| {
                // Match based on service or just use first port if no match
                vuln.affected_service.as_ref()
                    .map(|c| p.service.as_ref().map(|s| s.name.as_str()) == Some(c.as_str()))
                    .unwrap_or(false)
            })
            .or_else(|| host.ports.first());

        let port_str = port_info
            .map(|p| format!("{}/{}", p.port, match p.protocol {
                crate::types::Protocol::TCP => "tcp",
                crate::types::Protocol::UDP => "udp",
            }))
            .unwrap_or_else(|| "unknown".to_string());

        let service_str = port_info
            .and_then(|p| p.service.as_ref())
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let event = NotificationEvent::CriticalVulnerability {
            scan_name: scan_name.to_string(),
            host: host.target.ip.to_string(),
            port: port_str,
            service: service_str,
            severity: severity_str.to_string(),
            title: vuln.title.clone(),
            description: vuln.description.clone(),
        };

        // Send to Slack if configured
        if let Some(slack_url) = &settings.slack_webhook_url {
            if !slack_url.is_empty() {
                let notifier = SlackNotifier::new(slack_url.clone());
                if let Err(e) = notifier.send_notification(&event).await {
                    log::error!("Failed to send Slack critical vuln notification: {}", e);
                } else {
                    log::debug!("Sent Slack notification for critical vulnerability");
                }
            }
        }

        // Send to Teams if configured
        if let Some(teams_url) = &settings.teams_webhook_url {
            if !teams_url.is_empty() {
                let notifier = TeamsNotifier::new(teams_url.clone());
                if let Err(e) = notifier.send_notification(&event).await {
                    log::error!("Failed to send Teams critical vuln notification: {}", e);
                } else {
                    log::debug!("Sent Teams notification for critical vulnerability");
                }
            }
        }
    }
}
