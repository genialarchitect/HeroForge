use super::{NotificationEvent, Notifier};
use anyhow::{Context, Result};
use serde_json::json;

/// Slack webhook notifier
pub struct SlackNotifier {
    webhook_url: String,
    client: reqwest::Client,
}

impl SlackNotifier {
    /// Create a new Slack notifier with the given webhook URL
    pub fn new(webhook_url: String) -> Self {
        Self {
            webhook_url,
            client: reqwest::Client::new(),
        }
    }

    /// Get color for severity level
    fn get_severity_color(severity: &str) -> &'static str {
        match severity.to_lowercase().as_str() {
            "critical" => "#DC2626", // Red
            "high" => "#EA580C",     // Orange
            "medium" => "#CA8A04",   // Yellow
            "low" => "#65A30D",      // Green
            _ => "#6B7280",          // Gray
        }
    }

    /// Send a message to Slack webhook
    async fn send_message(&self, payload: serde_json::Value) -> Result<()> {
        let response = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send Slack webhook request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Slack webhook request failed: {} - {}", status, body);
        }

        Ok(())
    }
}

impl Notifier for SlackNotifier {
    async fn send_notification(&self, event: &NotificationEvent) -> Result<()> {
        let payload = match event {
            NotificationEvent::ScanCompleted {
                scan_name,
                hosts_discovered,
                open_ports,
                vulnerabilities_found,
                critical_vulns,
                high_vulns,
                medium_vulns,
                low_vulns,
            } => {
                let color = if *critical_vulns > 0 {
                    "#DC2626"
                } else if *high_vulns > 0 {
                    "#EA580C"
                } else if *medium_vulns > 0 {
                    "#CA8A04"
                } else {
                    "#22C55E"
                };

                json!({
                    "attachments": [{
                        "color": color,
                        "title": format!("Scan Completed: {}", scan_name),
                        "fields": [
                            {
                                "title": "Hosts Discovered",
                                "value": hosts_discovered.to_string(),
                                "short": true
                            },
                            {
                                "title": "Open Ports",
                                "value": open_ports.to_string(),
                                "short": true
                            },
                            {
                                "title": "Total Vulnerabilities",
                                "value": vulnerabilities_found.to_string(),
                                "short": true
                            },
                            {
                                "title": "Severity Breakdown",
                                "value": format!(
                                    "Critical: {} | High: {} | Medium: {} | Low: {}",
                                    critical_vulns, high_vulns, medium_vulns, low_vulns
                                ),
                                "short": false
                            }
                        ],
                        "footer": "HeroForge Security Scanner",
                        "ts": chrono::Utc::now().timestamp()
                    }]
                })
            }

            NotificationEvent::CriticalVulnerability {
                scan_name,
                host,
                port,
                service,
                severity,
                title,
                description,
            } => {
                json!({
                    "attachments": [{
                        "color": Self::get_severity_color(severity),
                        "title": format!("CRITICAL VULNERABILITY DETECTED"),
                        "text": format!("*{}*\n{}", title, description),
                        "fields": [
                            {
                                "title": "Scan",
                                "value": scan_name,
                                "short": true
                            },
                            {
                                "title": "Severity",
                                "value": severity,
                                "short": true
                            },
                            {
                                "title": "Host",
                                "value": host,
                                "short": true
                            },
                            {
                                "title": "Port",
                                "value": port,
                                "short": true
                            },
                            {
                                "title": "Service",
                                "value": service,
                                "short": true
                            }
                        ],
                        "footer": "HeroForge Security Scanner",
                        "ts": chrono::Utc::now().timestamp()
                    }]
                })
            }

            NotificationEvent::ScheduledScanStarted { scan_name, targets } => {
                json!({
                    "attachments": [{
                        "color": "#3B82F6",
                        "title": format!("Scheduled Scan Started: {}", scan_name),
                        "fields": [
                            {
                                "title": "Targets",
                                "value": targets,
                                "short": false
                            }
                        ],
                        "footer": "HeroForge Security Scanner",
                        "ts": chrono::Utc::now().timestamp()
                    }]
                })
            }

            NotificationEvent::ScheduledScanCompleted {
                scan_name,
                status,
                duration_secs,
            } => {
                let color = if status == "completed" {
                    "#22C55E"
                } else {
                    "#EF4444"
                };

                let duration_min = *duration_secs / 60;
                let duration_sec = *duration_secs % 60;

                json!({
                    "attachments": [{
                        "color": color,
                        "title": format!("Scheduled Scan {}: {}", if status == "completed" { "Completed" } else { "Failed" }, scan_name),
                        "fields": [
                            {
                                "title": "Status",
                                "value": status,
                                "short": true
                            },
                            {
                                "title": "Duration",
                                "value": format!("{}m {}s", duration_min, duration_sec),
                                "short": true
                            }
                        ],
                        "footer": "HeroForge Security Scanner",
                        "ts": chrono::Utc::now().timestamp()
                    }]
                })
            }
        };

        self.send_message(payload).await
    }

    async fn send_test_message(&self) -> Result<()> {
        let payload = json!({
            "attachments": [{
                "color": "#3B82F6",
                "title": "HeroForge Slack Integration Test",
                "text": "Your Slack webhook is configured correctly! You will receive notifications here for scan events.",
                "footer": "HeroForge Security Scanner",
                "ts": chrono::Utc::now().timestamp()
            }]
        });

        self.send_message(payload).await
    }
}
