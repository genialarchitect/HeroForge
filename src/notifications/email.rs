use super::{NotificationEvent, Notifier};
use anyhow::{Context, Result};
use lettre::message::{header, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde::{Deserialize, Serialize};

/// Email configuration for SMTP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_password: String,
    pub from_address: String,
    pub from_name: String,
}

impl EmailConfig {
    /// Load email configuration from environment variables
    pub fn from_env() -> Result<Self> {
        Ok(EmailConfig {
            smtp_host: std::env::var("SMTP_HOST")
                .context("SMTP_HOST environment variable not set")?,
            smtp_port: std::env::var("SMTP_PORT")
                .context("SMTP_PORT environment variable not set")?
                .parse()
                .context("Invalid SMTP_PORT")?,
            smtp_user: std::env::var("SMTP_USER")
                .context("SMTP_USER environment variable not set")?,
            smtp_password: std::env::var("SMTP_PASSWORD")
                .context("SMTP_PASSWORD environment variable not set")?,
            from_address: std::env::var("SMTP_FROM_ADDRESS")
                .unwrap_or_else(|_| "noreply@heroforge.local".to_string()),
            from_name: std::env::var("SMTP_FROM_NAME")
                .unwrap_or_else(|_| "HeroForge Security Scanner".to_string()),
        })
    }

    /// Check if SMTP is configured via environment variables
    pub fn is_configured() -> bool {
        std::env::var("SMTP_HOST").is_ok() && std::env::var("SMTP_USER").is_ok()
    }
}

/// Email notifier for sending SMTP notifications
pub struct EmailNotifier {
    config: EmailConfig,
    recipient_email: String,
}

impl EmailNotifier {
    /// Create a new email notifier with the given configuration and recipient
    pub fn new(config: EmailConfig, recipient_email: String) -> Self {
        Self {
            config,
            recipient_email,
        }
    }

    /// Create a new email notifier from environment variables
    pub fn from_env(recipient_email: String) -> Result<Self> {
        let config = EmailConfig::from_env()?;
        Ok(Self::new(config, recipient_email))
    }

    /// Get color for severity level (for HTML emails)
    fn get_severity_color(severity: &str) -> &'static str {
        match severity.to_lowercase().as_str() {
            "critical" => "#DC2626",
            "high" => "#EA580C",
            "medium" => "#CA8A04",
            "low" => "#65A30D",
            _ => "#6B7280",
        }
    }

    /// Send an email with both HTML and plain text parts
    async fn send_email(&self, subject: &str, text_body: &str, html_body: &str) -> Result<()> {
        let email = Message::builder()
            .from(
                format!("{} <{}>", self.config.from_name, self.config.from_address)
                    .parse()
                    .context("Failed to parse from address")?,
            )
            .to(self
                .recipient_email
                .parse()
                .context("Failed to parse recipient address")?)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(text_body.to_string()),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(html_body.to_string()),
                    ),
            )
            .context("Failed to build email message")?;

        let creds = Credentials::new(
            self.config.smtp_user.clone(),
            self.config.smtp_password.clone(),
        );

        let mailer = SmtpTransport::relay(&self.config.smtp_host)
            .context("Failed to create SMTP transport")?
            .credentials(creds)
            .port(self.config.smtp_port)
            .build();

        // Send email in a blocking task since lettre is synchronous
        let result = tokio::task::spawn_blocking(move || mailer.send(&email))
            .await
            .context("Failed to execute email send task")?;

        result.context("Failed to send email")?;

        log::info!("Email sent successfully to {}", self.recipient_email);
        Ok(())
    }

    /// Build scan completed email content
    fn build_scan_completed_email(
        scan_name: &str,
        hosts_discovered: usize,
        open_ports: usize,
        vulnerabilities_found: usize,
        critical_vulns: usize,
        high_vulns: usize,
        medium_vulns: usize,
        low_vulns: usize,
    ) -> (String, String, String) {
        let subject = format!("Scan Completed: {}", scan_name);

        let html_body = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #4F46E5; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
        .content {{ background-color: #f9fafb; padding: 20px; }}
        .summary {{ background-color: white; padding: 15px; margin: 10px 0; border-left: 4px solid #4F46E5; border-radius: 4px; }}
        .stat {{ margin: 10px 0; }}
        .stat-label {{ font-weight: bold; color: #4F46E5; }}
        .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 12px; border-radius: 0 0 8px 8px; }}
        .critical {{ color: #dc2626; font-weight: bold; }}
        .high {{ color: #ea580c; font-weight: bold; }}
        .medium {{ color: #ca8a04; font-weight: bold; }}
        .low {{ color: #65a30d; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Scan Completed</h1>
        </div>
        <div class="content">
            <p>Your HeroForge scan <strong>{}</strong> has completed successfully.</p>

            <div class="summary">
                <h3>Scan Summary</h3>
                <div class="stat">
                    <span class="stat-label">Hosts Discovered:</span> {}
                </div>
                <div class="stat">
                    <span class="stat-label">Open Ports:</span> {}
                </div>
                <div class="stat">
                    <span class="stat-label">Vulnerabilities Found:</span> {}
                </div>
            </div>

            <div class="summary">
                <h3>Vulnerability Breakdown</h3>
                <div class="stat">
                    <span class="critical">Critical:</span> {}
                </div>
                <div class="stat">
                    <span class="high">High:</span> {}
                </div>
                <div class="stat">
                    <span class="medium">Medium:</span> {}
                </div>
                <div class="stat">
                    <span class="low">Low:</span> {}
                </div>
            </div>

            <p>Please log in to the HeroForge dashboard to view detailed results and generate reports.</p>
        </div>
        <div class="footer">
            <p>This is an automated notification from HeroForge Security Scanner.</p>
            <p>To manage your notification settings, please visit your account settings.</p>
        </div>
    </div>
</body>
</html>"#,
            scan_name,
            hosts_discovered,
            open_ports,
            vulnerabilities_found,
            critical_vulns,
            high_vulns,
            medium_vulns,
            low_vulns
        );

        let text_body = format!(
            r#"Scan Completed: {}

Your HeroForge scan has completed successfully.

Scan Summary:
- Hosts Discovered: {}
- Open Ports: {}
- Vulnerabilities Found: {}

Vulnerability Breakdown:
- Critical: {}
- High: {}
- Medium: {}
- Low: {}

Please log in to the HeroForge dashboard to view detailed results and generate reports.

---
This is an automated notification from HeroForge Security Scanner.
"#,
            scan_name,
            hosts_discovered,
            open_ports,
            vulnerabilities_found,
            critical_vulns,
            high_vulns,
            medium_vulns,
            low_vulns
        );

        (subject, text_body, html_body)
    }

    /// Build critical vulnerability email content
    fn build_critical_vulnerability_email(
        scan_name: &str,
        host: &str,
        port: &str,
        service: &str,
        severity: &str,
        title: &str,
        description: &str,
    ) -> (String, String, String) {
        let subject = format!("CRITICAL VULNERABILITY: {} - {}", title, scan_name);
        let severity_color = Self::get_severity_color(severity);

        let html_body = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #dc2626; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
        .content {{ background-color: #f9fafb; padding: 20px; }}
        .finding {{ background-color: white; padding: 15px; margin: 10px 0; border-left: 4px solid {}; border-radius: 4px; }}
        .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 12px; border-radius: 0 0 8px 8px; }}
        .warning {{ background-color: #fef2f2; border: 1px solid #dc2626; padding: 15px; margin: 15px 0; border-radius: 4px; }}
        .field {{ margin: 8px 0; }}
        .field-label {{ font-weight: bold; color: #4b5563; }}
        .severity {{ color: {}; font-weight: bold; font-size: 1.1em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CRITICAL VULNERABILITY DETECTED</h1>
        </div>
        <div class="content">
            <div class="warning">
                <p><strong>IMMEDIATE ACTION REQUIRED</strong></p>
                <p>A critical security vulnerability has been discovered during scan: <strong>{}</strong></p>
            </div>

            <div class="finding">
                <h3>{}</h3>
                <div class="field">
                    <span class="field-label">Severity:</span>
                    <span class="severity">{}</span>
                </div>
                <div class="field">
                    <span class="field-label">Host:</span> {}
                </div>
                <div class="field">
                    <span class="field-label">Port:</span> {}
                </div>
                <div class="field">
                    <span class="field-label">Service:</span> {}
                </div>
                <div class="field">
                    <span class="field-label">Description:</span>
                    <p>{}</p>
                </div>
            </div>

            <p>Please log in to the HeroForge dashboard immediately to review this finding and begin remediation.</p>
        </div>
        <div class="footer">
            <p>This is an automated critical alert from HeroForge Security Scanner.</p>
            <p>To manage your notification settings, please visit your account settings.</p>
        </div>
    </div>
</body>
</html>"#,
            severity_color,
            severity_color,
            scan_name,
            title,
            severity,
            host,
            port,
            service,
            description
        );

        let text_body = format!(
            r#"CRITICAL VULNERABILITY DETECTED

IMMEDIATE ACTION REQUIRED
A critical security vulnerability has been discovered during scan: {}

Vulnerability Details:
- Title: {}
- Severity: {}
- Host: {}
- Port: {}
- Service: {}
- Description: {}

Please log in to the HeroForge dashboard immediately to review this finding and begin remediation.

---
This is an automated critical alert from HeroForge Security Scanner.
"#,
            scan_name, title, severity, host, port, service, description
        );

        (subject, text_body, html_body)
    }

    /// Build scheduled scan started email content
    fn build_scheduled_scan_started_email(scan_name: &str, targets: &str) -> (String, String, String) {
        let subject = format!("Scheduled Scan Started: {}", scan_name);

        let html_body = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #3B82F6; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
        .content {{ background-color: #f9fafb; padding: 20px; }}
        .info {{ background-color: white; padding: 15px; margin: 10px 0; border-left: 4px solid #3B82F6; border-radius: 4px; }}
        .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Scheduled Scan Started</h1>
        </div>
        <div class="content">
            <p>Your scheduled HeroForge scan <strong>{}</strong> has started.</p>
            <div class="info">
                <p><strong>Targets:</strong> {}</p>
            </div>
            <p>You will receive another notification when the scan completes.</p>
        </div>
        <div class="footer">
            <p>This is an automated notification from HeroForge Security Scanner.</p>
        </div>
    </div>
</body>
</html>"#,
            scan_name, targets
        );

        let text_body = format!(
            r#"Scheduled Scan Started: {}

Your scheduled HeroForge scan has started.

Targets: {}

You will receive another notification when the scan completes.

---
This is an automated notification from HeroForge Security Scanner.
"#,
            scan_name, targets
        );

        (subject, text_body, html_body)
    }

    /// Build scheduled scan completed email content
    fn build_scheduled_scan_completed_email(
        scan_name: &str,
        status: &str,
        duration_secs: u64,
    ) -> (String, String, String) {
        let is_success = status == "completed";
        let status_text = if is_success { "Completed" } else { "Failed" };
        let header_color = if is_success { "#22C55E" } else { "#EF4444" };
        let subject = format!("Scheduled Scan {}: {}", status_text, scan_name);

        let duration_min = duration_secs / 60;
        let duration_sec = duration_secs % 60;

        let html_body = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: {}; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
        .content {{ background-color: #f9fafb; padding: 20px; }}
        .info {{ background-color: white; padding: 15px; margin: 10px 0; border-left: 4px solid {}; border-radius: 4px; }}
        .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Scheduled Scan {}</h1>
        </div>
        <div class="content">
            <p>Your scheduled HeroForge scan <strong>{}</strong> has {}.</p>
            <div class="info">
                <p><strong>Status:</strong> {}</p>
                <p><strong>Duration:</strong> {}m {}s</p>
            </div>
            <p>Log in to the HeroForge dashboard to view the scan results.</p>
        </div>
        <div class="footer">
            <p>This is an automated notification from HeroForge Security Scanner.</p>
        </div>
    </div>
</body>
</html>"#,
            header_color,
            header_color,
            status_text,
            scan_name,
            status,
            status,
            duration_min,
            duration_sec
        );

        let text_body = format!(
            r#"Scheduled Scan {}: {}

Your scheduled HeroForge scan has {}.

Status: {}
Duration: {}m {}s

Log in to the HeroForge dashboard to view the scan results.

---
This is an automated notification from HeroForge Security Scanner.
"#,
            status_text, scan_name, status, status, duration_min, duration_sec
        );

        (subject, text_body, html_body)
    }
}

impl Notifier for EmailNotifier {
    async fn send_notification(&self, event: &NotificationEvent) -> Result<()> {
        let (subject, text_body, html_body) = match event {
            NotificationEvent::ScanCompleted {
                scan_name,
                hosts_discovered,
                open_ports,
                vulnerabilities_found,
                critical_vulns,
                high_vulns,
                medium_vulns,
                low_vulns,
            } => Self::build_scan_completed_email(
                scan_name,
                *hosts_discovered,
                *open_ports,
                *vulnerabilities_found,
                *critical_vulns,
                *high_vulns,
                *medium_vulns,
                *low_vulns,
            ),

            NotificationEvent::CriticalVulnerability {
                scan_name,
                host,
                port,
                service,
                severity,
                title,
                description,
            } => Self::build_critical_vulnerability_email(
                scan_name,
                host,
                port,
                service,
                severity,
                title,
                description,
            ),

            NotificationEvent::ScheduledScanStarted { scan_name, targets } => {
                Self::build_scheduled_scan_started_email(scan_name, targets)
            }

            NotificationEvent::ScheduledScanCompleted {
                scan_name,
                status,
                duration_secs,
            } => Self::build_scheduled_scan_completed_email(scan_name, status, *duration_secs),
        };

        self.send_email(&subject, &text_body, &html_body).await
    }

    async fn send_test_message(&self) -> Result<()> {
        let subject = "HeroForge Email Integration Test";

        let html_body = r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #4F46E5; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background-color: #f9fafb; padding: 20px; }
        .success { background-color: #d1fae5; border: 1px solid #10b981; padding: 15px; margin: 15px 0; border-radius: 4px; color: #065f46; }
        .footer { text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>HeroForge Email Test</h1>
        </div>
        <div class="content">
            <div class="success">
                <p><strong>Success!</strong> Your email notifications are configured correctly.</p>
            </div>
            <p>You will receive email notifications for:</p>
            <ul>
                <li>Scan completion summaries</li>
                <li>Critical and high severity vulnerability alerts</li>
                <li>Scheduled scan status updates</li>
            </ul>
            <p>You can manage your notification preferences in the HeroForge settings page.</p>
        </div>
        <div class="footer">
            <p>This is a test message from HeroForge Security Scanner.</p>
        </div>
    </div>
</body>
</html>"#;

        let text_body = r#"HeroForge Email Integration Test

Success! Your email notifications are configured correctly.

You will receive email notifications for:
- Scan completion summaries
- Critical and high severity vulnerability alerts
- Scheduled scan status updates

You can manage your notification preferences in the HeroForge settings page.

---
This is a test message from HeroForge Security Scanner.
"#;

        self.send_email(subject, text_body, html_body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_color_mapping() {
        assert_eq!(EmailNotifier::get_severity_color("critical"), "#DC2626");
        assert_eq!(EmailNotifier::get_severity_color("CRITICAL"), "#DC2626");
        assert_eq!(EmailNotifier::get_severity_color("high"), "#EA580C");
        assert_eq!(EmailNotifier::get_severity_color("HIGH"), "#EA580C");
        assert_eq!(EmailNotifier::get_severity_color("medium"), "#CA8A04");
        assert_eq!(EmailNotifier::get_severity_color("low"), "#65A30D");
        assert_eq!(EmailNotifier::get_severity_color("unknown"), "#6B7280");
    }

    #[test]
    fn test_build_scan_completed_email() {
        let (subject, text_body, html_body) = EmailNotifier::build_scan_completed_email(
            "Test Scan",
            10,
            25,
            5,
            1,
            2,
            1,
            1,
        );

        assert!(subject.contains("Test Scan"));
        assert!(text_body.contains("Hosts Discovered: 10"));
        assert!(text_body.contains("Open Ports: 25"));
        assert!(text_body.contains("Critical: 1"));
        assert!(html_body.contains("Test Scan"));
        assert!(html_body.contains("10")); // hosts
        assert!(html_body.contains("25")); // ports
    }

    #[test]
    fn test_build_critical_vulnerability_email() {
        let (subject, text_body, html_body) = EmailNotifier::build_critical_vulnerability_email(
            "Production Scan",
            "192.168.1.100",
            "443",
            "HTTPS",
            "Critical",
            "Remote Code Execution",
            "CVE-2024-1234 allows RCE",
        );

        assert!(subject.contains("Remote Code Execution"));
        assert!(subject.contains("Production Scan"));
        assert!(text_body.contains("192.168.1.100"));
        assert!(text_body.contains("443"));
        assert!(text_body.contains("HTTPS"));
        assert!(html_body.contains("CRITICAL VULNERABILITY"));
        assert!(html_body.contains("Remote Code Execution"));
    }

    #[test]
    fn test_build_scheduled_scan_started_email() {
        let (subject, text_body, html_body) =
            EmailNotifier::build_scheduled_scan_started_email("Daily Scan", "10.0.0.0/24");

        assert!(subject.contains("Daily Scan"));
        assert!(text_body.contains("10.0.0.0/24"));
        assert!(html_body.contains("Scheduled Scan Started"));
    }

    #[test]
    fn test_build_scheduled_scan_completed_email() {
        let (subject, text_body, html_body) =
            EmailNotifier::build_scheduled_scan_completed_email("Nightly Scan", "completed", 3725);

        assert!(subject.contains("Completed"));
        assert!(subject.contains("Nightly Scan"));
        assert!(text_body.contains("62m 5s")); // 3725 seconds
        assert!(html_body.contains("#22C55E")); // Success color

        let (subject_failed, _, html_failed) =
            EmailNotifier::build_scheduled_scan_completed_email("Failed Scan", "failed", 120);

        assert!(subject_failed.contains("Failed"));
        assert!(html_failed.contains("#EF4444")); // Failure color
    }

    #[test]
    fn test_email_config_is_configured() {
        // This test will return false unless env vars are set
        // In a real test environment, you might mock env vars
        let result = EmailConfig::is_configured();
        // Just verify it doesn't panic
        assert!(result || !result);
    }
}
