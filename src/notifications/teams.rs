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
        Self::with_client(webhook_url, reqwest::Client::new())
    }

    /// Create a new Teams notifier with a custom HTTP client (useful for testing)
    pub fn with_client(webhook_url: String, client: reqwest::Client) -> Self {
        Self {
            webhook_url,
            client,
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

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;

    #[test]
    fn test_severity_color_mapping() {
        // Teams colors are without # prefix
        assert_eq!(TeamsNotifier::get_severity_color("critical"), "DC2626");
        assert_eq!(TeamsNotifier::get_severity_color("CRITICAL"), "DC2626");
        assert_eq!(TeamsNotifier::get_severity_color("high"), "EA580C");
        assert_eq!(TeamsNotifier::get_severity_color("HIGH"), "EA580C");
        assert_eq!(TeamsNotifier::get_severity_color("medium"), "CA8A04");
        assert_eq!(TeamsNotifier::get_severity_color("low"), "65A30D");
        assert_eq!(TeamsNotifier::get_severity_color("unknown"), "6B7280");
        assert_eq!(TeamsNotifier::get_severity_color(""), "6B7280");
    }

    #[tokio::test]
    async fn test_send_test_message_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .with_status(200)
            .with_body("1") // Teams returns "1" on success
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = TeamsNotifier::with_client(webhook_url, Client::new());

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
            .with_body("Bad Request")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = TeamsNotifier::with_client(webhook_url, Client::new());

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
            .with_body("1")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = TeamsNotifier::with_client(webhook_url, Client::new());

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
            .with_body("1")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = TeamsNotifier::with_client(webhook_url, Client::new());

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
            .with_body("1")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = TeamsNotifier::with_client(webhook_url, Client::new());

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
            .with_body("1")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = TeamsNotifier::with_client(webhook_url, Client::new());

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
            .with_body("1")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = TeamsNotifier::with_client(webhook_url, Client::new());

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
            .with_body("Unauthorized")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = TeamsNotifier::with_client(webhook_url, Client::new());

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
            .with_body("Internal Server Error")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = TeamsNotifier::with_client(webhook_url, Client::new());

        let result = notifier.send_test_message().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("500"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_payload_contains_message_card_format() {
        let mut server = mockito::Server::new_async().await;

        // Check that the payload contains expected Teams MessageCard structure
        let mock = server
            .mock("POST", "/webhook")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::Regex(r#""@type":\s*"MessageCard""#.to_string()),
                mockito::Matcher::Regex(r#""@context":\s*"https://schema.org/extensions""#.to_string()),
                mockito::Matcher::Regex(r#""themeColor""#.to_string()),
                mockito::Matcher::Regex(r#""title""#.to_string()),
            ]))
            .with_status(200)
            .with_body("1")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = TeamsNotifier::with_client(webhook_url, Client::new());

        let _ = notifier.send_test_message().await;

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_scan_completed_color_priority() {
        // Test that critical vulnerabilities result in red color (DC2626)
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .match_body(mockito::Matcher::Regex(r#""themeColor":\s*"DC2626""#.to_string()))
            .with_status(200)
            .with_body("1")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = TeamsNotifier::with_client(webhook_url, Client::new());

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
    async fn test_scan_completed_green_when_no_serious_vulns() {
        // Test that no critical/high/medium vulnerabilities result in green color
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .match_body(mockito::Matcher::Regex(r#""themeColor":\s*"22C55E""#.to_string()))
            .with_status(200)
            .with_body("1")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = TeamsNotifier::with_client(webhook_url, Client::new());

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

    #[tokio::test]
    async fn test_scheduled_scan_completed_green_color() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .match_body(mockito::Matcher::Regex(r#""themeColor":\s*"22C55E""#.to_string()))
            .with_status(200)
            .with_body("1")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = TeamsNotifier::with_client(webhook_url, Client::new());

        let event = NotificationEvent::ScheduledScanCompleted {
            scan_name: "Success Scan".to_string(),
            status: "completed".to_string(),
            duration_secs: 60,
        };

        let _ = notifier.send_notification(&event).await;

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_scheduled_scan_failed_red_color() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/webhook")
            .match_body(mockito::Matcher::Regex(r#""themeColor":\s*"EF4444""#.to_string()))
            .with_status(200)
            .with_body("1")
            .create_async()
            .await;

        let webhook_url = format!("{}/webhook", server.url());
        let notifier = TeamsNotifier::with_client(webhook_url, Client::new());

        let event = NotificationEvent::ScheduledScanCompleted {
            scan_name: "Failed Scan".to_string(),
            status: "failed".to_string(),
            duration_secs: 30,
        };

        let _ = notifier.send_notification(&event).await;

        mock.assert_async().await;
    }
}
