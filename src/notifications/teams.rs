use super::{NotificationEvent, Notifier};
use anyhow::{Context, Result};
use serde_json::json;

/// Microsoft Teams webhook notifier
pub struct TeamsNotifier {
    webhook_url: String,
    client: reqwest::Client,
}

impl TeamsNotifier {
    /// Create a new Teams notifier with the given webhook URL
    pub fn new(webhook_url: String) -> Self {
        Self {
            webhook_url,
            client: reqwest::Client::new(),
        }
    }

    /// Get theme color for severity level (hex color without #)
    fn get_severity_color(severity: &str) -> &'static str {
        match severity.to_lowercase().as_str() {
            "critical" => "DC2626", // Red
            "high" => "EA580C",     // Orange
            "medium" => "CA8A04",   // Yellow
            "low" => "65A30D",      // Green
            _ => "6B7280",          // Gray
        }
    }

    /// Send a message to Teams webhook
    async fn send_message(&self, payload: serde_json::Value) -> Result<()> {
        let response = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send Teams webhook request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Teams webhook request failed: {} - {}", status, body);
        }

        Ok(())
    }
}

impl Notifier for TeamsNotifier {
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
                let theme_color = if *critical_vulns > 0 {
                    "DC2626"
                } else if *high_vulns > 0 {
                    "EA580C"
                } else if *medium_vulns > 0 {
                    "CA8A04"
                } else {
                    "22C55E"
                };

                json!({
                    "@type": "MessageCard",
                    "@context": "https://schema.org/extensions",
                    "summary": format!("Scan Completed: {}", scan_name),
                    "themeColor": theme_color,
                    "title": format!("Scan Completed: {}", scan_name),
                    "sections": [{
                        "facts": [
                            {
                                "name": "Hosts Discovered:",
                                "value": hosts_discovered.to_string()
                            },
                            {
                                "name": "Open Ports:",
                                "value": open_ports.to_string()
                            },
                            {
                                "name": "Total Vulnerabilities:",
                                "value": vulnerabilities_found.to_string()
                            },
                            {
                                "name": "Critical:",
                                "value": critical_vulns.to_string()
                            },
                            {
                                "name": "High:",
                                "value": high_vulns.to_string()
                            },
                            {
                                "name": "Medium:",
                                "value": medium_vulns.to_string()
                            },
                            {
                                "name": "Low:",
                                "value": low_vulns.to_string()
                            }
                        ]
                    }],
                    "text": "HeroForge Security Scanner"
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
                    "@type": "MessageCard",
                    "@context": "https://schema.org/extensions",
                    "summary": "CRITICAL VULNERABILITY DETECTED",
                    "themeColor": Self::get_severity_color(severity),
                    "title": "CRITICAL VULNERABILITY DETECTED",
                    "sections": [{
                        "activityTitle": title,
                        "activitySubtitle": description,
                        "facts": [
                            {
                                "name": "Scan:",
                                "value": scan_name
                            },
                            {
                                "name": "Severity:",
                                "value": severity
                            },
                            {
                                "name": "Host:",
                                "value": host
                            },
                            {
                                "name": "Port:",
                                "value": port
                            },
                            {
                                "name": "Service:",
                                "value": service
                            }
                        ]
                    }],
                    "text": "HeroForge Security Scanner"
                })
            }

            NotificationEvent::ScheduledScanStarted { scan_name, targets } => {
                json!({
                    "@type": "MessageCard",
                    "@context": "https://schema.org/extensions",
                    "summary": format!("Scheduled Scan Started: {}", scan_name),
                    "themeColor": "3B82F6",
                    "title": format!("Scheduled Scan Started: {}", scan_name),
                    "sections": [{
                        "facts": [
                            {
                                "name": "Targets:",
                                "value": targets
                            }
                        ]
                    }],
                    "text": "HeroForge Security Scanner"
                })
            }

            NotificationEvent::ScheduledScanCompleted {
                scan_name,
                status,
                duration_secs,
            } => {
                let theme_color = if status == "completed" { "22C55E" } else { "EF4444" };

                let duration_min = *duration_secs / 60;
                let duration_sec = *duration_secs % 60;

                json!({
                    "@type": "MessageCard",
                    "@context": "https://schema.org/extensions",
                    "summary": format!("Scheduled Scan {}: {}", if status == "completed" { "Completed" } else { "Failed" }, scan_name),
                    "themeColor": theme_color,
                    "title": format!("Scheduled Scan {}: {}", if status == "completed" { "Completed" } else { "Failed" }, scan_name),
                    "sections": [{
                        "facts": [
                            {
                                "name": "Status:",
                                "value": status
                            },
                            {
                                "name": "Duration:",
                                "value": format!("{}m {}s", duration_min, duration_sec)
                            }
                        ]
                    }],
                    "text": "HeroForge Security Scanner"
                })
            }
        };

        self.send_message(payload).await
    }

    async fn send_test_message(&self) -> Result<()> {
        let payload = json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "HeroForge Teams Integration Test",
            "themeColor": "3B82F6",
            "title": "HeroForge Teams Integration Test",
            "text": "Your Microsoft Teams webhook is configured correctly! You will receive notifications here for scan events.",
            "sections": [{
                "text": "HeroForge Security Scanner"
            }]
        });

        self.send_message(payload).await
    }
}
