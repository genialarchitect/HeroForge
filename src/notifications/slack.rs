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
        Self::with_client(webhook_url, reqwest::Client::new())
    }

    /// Create a new Slack notifier with a custom HTTP client (useful for testing)
    pub fn with_client(webhook_url: String, client: reqwest::Client) -> Self {
        Self {
            webhook_url,
            client,
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

    /// Send a raw JSON message to Slack webhook (public method for custom messages)
    pub async fn send_raw_message(&self, payload: &serde_json::Value) -> Result<()> {
        self.send_message(payload.clone()).await
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
                        "footer": "Genial Architect Scanner",
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
                        "footer": "Genial Architect Scanner",
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
                        "footer": "Genial Architect Scanner",
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
                        "footer": "Genial Architect Scanner",
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
                "footer": "Genial Architect Scanner",
                "ts": chrono::Utc::now().timestamp()
            }]
        });

        self.send_message(payload).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;

    #[test]
    fn test_severity_color_mapping() {
        assert_eq!(SlackNotifier::get_severity_color("critical"), "#DC2626");
        assert_eq!(SlackNotifier::get_severity_color("CRITICAL"), "#DC2626");
        assert_eq!(SlackNotifier::get_severity_color("high"), "#EA580C");
        assert_eq!(SlackNotifier::get_severity_color("HIGH"), "#EA580C");
        assert_eq!(SlackNotifier::get_severity_color("medium"), "#CA8A04");
        assert_eq!(SlackNotifier::get_severity_color("low"), "#65A30D");
        assert_eq!(SlackNotifier::get_severity_color("unknown"), "#6B7280");
        assert_eq!(SlackNotifier::get_severity_color(""), "#6B7280");
    }

    #[tokio::test]
    async fn test_send_test_message_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = SlackNotifier::with_client(webhook_url, Client::new());

        let result = notifier.send_test_message().await;
        assert!(result.is_ok());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_send_test_message_failure() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .with_status(400)
            .with_body("invalid_payload")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = SlackNotifier::with_client(webhook_url, Client::new());

        let result = notifier.send_test_message().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("400"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_send_scan_completed_notification_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = SlackNotifier::with_client(webhook_url, Client::new());

        let event = NotificationEvent::ScanCompleted {
            scan_name: "Weekly Security Scan".to_string(),
            hosts_discovered: 15,
            open_ports: 42,
            vulnerabilities_found: 7,
            critical_vulns: 1,
            high_vulns: 2,
            medium_vulns: 3,
            low_vulns: 1,
        };

        let result = notifier.send_notification(&event).await;
        assert!(result.is_ok());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_send_critical_vulnerability_notification() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = SlackNotifier::with_client(webhook_url, Client::new());

        let event = NotificationEvent::CriticalVulnerability {
            scan_name: "Production Scan".to_string(),
            host: "192.168.1.100".to_string(),
            port: "443".to_string(),
            service: "HTTPS".to_string(),
            severity: "critical".to_string(),
            title: "Remote Code Execution".to_string(),
            description: "CVE-2024-1234 allows unauthenticated RCE".to_string(),
        };

        let result = notifier.send_notification(&event).await;
        assert!(result.is_ok());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_send_scheduled_scan_started_notification() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = SlackNotifier::with_client(webhook_url, Client::new());

        let event = NotificationEvent::ScheduledScanStarted {
            scan_name: "Daily Network Scan".to_string(),
            targets: "10.0.0.0/24, 192.168.1.0/24".to_string(),
        };

        let result = notifier.send_notification(&event).await;
        assert!(result.is_ok());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_send_scheduled_scan_completed_notification() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = SlackNotifier::with_client(webhook_url, Client::new());

        let event = NotificationEvent::ScheduledScanCompleted {
            scan_name: "Daily Network Scan".to_string(),
            status: "completed".to_string(),
            duration_secs: 3725, // 1h 2m 5s
        };

        let result = notifier.send_notification(&event).await;
        assert!(result.is_ok());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_send_scheduled_scan_failed_notification() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = SlackNotifier::with_client(webhook_url, Client::new());

        let event = NotificationEvent::ScheduledScanCompleted {
            scan_name: "Nightly Compliance Check".to_string(),
            status: "failed".to_string(),
            duration_secs: 120,
        };

        let result = notifier.send_notification(&event).await;
        assert!(result.is_ok());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_webhook_unauthorized() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .with_status(401)
            .with_body("invalid_token")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = SlackNotifier::with_client(webhook_url, Client::new());

        let result = notifier.send_test_message().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("401"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_webhook_server_error() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .with_status(500)
            .with_body("internal_error")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = SlackNotifier::with_client(webhook_url, Client::new());

        let result = notifier.send_test_message().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("500"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_payload_contains_required_fields() {
        let mut server = mockito::Server::new_async().await;

        // Check that the payload contains expected Slack attachment structure
        let mock = server
            .mock("POST", "/webhook")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::Regex(r#""attachments""#.to_string()),
                mockito::Matcher::Regex(r#""color""#.to_string()),
                mockito::Matcher::Regex(r#""title""#.to_string()),
                mockito::Matcher::Regex(r#""footer":\s*"Genial Architect Scanner""#.to_string()),
            ]))
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = SlackNotifier::with_client(webhook_url, Client::new());

        let _ = notifier.send_test_message().await;

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_scan_completed_color_priority() {
        // Test that critical vulnerabilities result in red color
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .match_body(mockito::Matcher::Regex(r##""color":\s*"#DC2626""##.to_string()))
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = SlackNotifier::with_client(webhook_url, Client::new());

        let event = NotificationEvent::ScanCompleted {
            scan_name: "Test".to_string(),
            hosts_discovered: 1,
            open_ports: 1,
            vulnerabilities_found: 1,
            critical_vulns: 1,
            high_vulns: 0,
            medium_vulns: 0,
            low_vulns: 0,
        };

        let _ = notifier.send_notification(&event).await;

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_scan_completed_green_when_no_vulns() {
        // Test that no critical/high/medium vulnerabilities result in green color
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .match_body(mockito::Matcher::Regex(r##""color":\s*"#22C55E""##.to_string()))
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = SlackNotifier::with_client(webhook_url, Client::new());

        let event = NotificationEvent::ScanCompleted {
            scan_name: "Clean Scan".to_string(),
            hosts_discovered: 5,
            open_ports: 10,
            vulnerabilities_found: 2,
            critical_vulns: 0,
            high_vulns: 0,
            medium_vulns: 0,
            low_vulns: 2,
        };

        let _ = notifier.send_notification(&event).await;

        mock.assert_async().await;
    }
}
