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
}

/// Email service for sending notifications
pub struct EmailService {
    config: EmailConfig,
}

impl EmailService {
    /// Create a new email service with the given configuration
    pub fn new(config: EmailConfig) -> Self {
        Self { config }
    }

    /// Send an email notification when a scan completes
    pub async fn send_scan_completed(
        &self,
        user_email: &str,
        scan_name: &str,
        summary: &ScanSummary,
    ) -> Result<()> {
        let subject = format!("Scan Completed: {}", scan_name);

        let html_body = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #4F46E5; color: white; padding: 20px; text-align: center; }}
        .content {{ background-color: #f9fafb; padding: 20px; }}
        .summary {{ background-color: white; padding: 15px; margin: 10px 0; border-left: 4px solid #4F46E5; }}
        .stat {{ margin: 10px 0; }}
        .stat-label {{ font-weight: bold; color: #4F46E5; }}
        .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }}
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
                    <span class="stat-label">Services Identified:</span> {}
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
            summary.hosts_discovered,
            summary.open_ports,
            summary.services_identified,
            summary.vulnerabilities_found,
            summary.critical_vulns,
            summary.high_vulns,
            summary.medium_vulns,
            summary.low_vulns
        );

        let text_body = format!(
            r#"Scan Completed: {}

Your HeroForge scan has completed successfully.

Scan Summary:
- Hosts Discovered: {}
- Open Ports: {}
- Services Identified: {}
- Vulnerabilities Found: {}

Vulnerability Breakdown:
- Critical: {}
- High: {}
- Medium: {}
- Low: {}

Please log in to the HeroForge dashboard to view detailed results and generate reports.
"#,
            scan_name,
            summary.hosts_discovered,
            summary.open_ports,
            summary.services_identified,
            summary.vulnerabilities_found,
            summary.critical_vulns,
            summary.high_vulns,
            summary.medium_vulns,
            summary.low_vulns
        );

        self.send_email(user_email, &subject, &text_body, &html_body)
            .await
    }

    /// Send an email notification for critical vulnerabilities
    pub async fn send_critical_findings(
        &self,
        user_email: &str,
        scan_name: &str,
        findings: &[CriticalFinding],
    ) -> Result<()> {
        let subject = format!("CRITICAL VULNERABILITIES FOUND: {}", scan_name);

        let findings_html = findings
            .iter()
            .map(|f| {
                format!(
                    r#"<div class="finding">
                    <h4>{}</h4>
                    <p><strong>Host:</strong> {}</p>
                    <p><strong>Port:</strong> {}</p>
                    <p><strong>Service:</strong> {}</p>
                    <p><strong>Severity:</strong> <span class="critical">{}</span></p>
                    <p><strong>Description:</strong> {}</p>
                </div>"#,
                    f.title, f.host, f.port, f.service, f.severity, f.description
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let html_body = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #dc2626; color: white; padding: 20px; text-align: center; }}
        .content {{ background-color: #f9fafb; padding: 20px; }}
        .finding {{ background-color: white; padding: 15px; margin: 10px 0; border-left: 4px solid #dc2626; }}
        .critical {{ color: #dc2626; font-weight: bold; }}
        .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }}
        .warning {{ background-color: #fef2f2; border: 1px solid #dc2626; padding: 15px; margin: 15px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CRITICAL VULNERABILITIES DETECTED</h1>
        </div>
        <div class="content">
            <div class="warning">
                <p><strong>ATTENTION:</strong> Critical security vulnerabilities have been discovered in your scan: <strong>{}</strong></p>
                <p>Immediate action is recommended to address these issues.</p>
            </div>

            <h3>Critical Findings ({})</h3>
            {}

            <p>Please log in to the HeroForge dashboard immediately to review these findings and generate remediation reports.</p>
        </div>
        <div class="footer">
            <p>This is an automated critical alert from HeroForge Security Scanner.</p>
            <p>To manage your notification settings, please visit your account settings.</p>
        </div>
    </div>
</body>
</html>"#,
            scan_name,
            findings.len(),
            findings_html
        );

        let findings_text = findings
            .iter()
            .enumerate()
            .map(|(i, f)| {
                format!(
                    "{}. {}\n   Host: {}\n   Port: {}\n   Service: {}\n   Severity: {}\n   Description: {}\n",
                    i + 1,
                    f.title,
                    f.host,
                    f.port,
                    f.service,
                    f.severity,
                    f.description
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let text_body = format!(
            r#"CRITICAL VULNERABILITIES DETECTED: {}

ATTENTION: Critical security vulnerabilities have been discovered.
Immediate action is recommended to address these issues.

Critical Findings ({}):
{}

Please log in to the HeroForge dashboard immediately to review these findings and generate remediation reports.
"#,
            scan_name,
            findings.len(),
            findings_text
        );

        self.send_email(user_email, &subject, &text_body, &html_body)
            .await
    }

    /// Send a generic email with both HTML and text parts
    async fn send_email(
        &self,
        to_email: &str,
        subject: &str,
        text_body: &str,
        html_body: &str,
    ) -> Result<()> {
        let email = Message::builder()
            .from(
                format!("{} <{}>", self.config.from_name, self.config.from_address)
                    .parse()
                    .context("Failed to parse from address")?,
            )
            .to(to_email.parse().context("Failed to parse recipient address")?)
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

        log::info!("Email sent successfully to {}", to_email);
        Ok(())
    }
}

/// Summary of scan results for email notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub hosts_discovered: usize,
    pub open_ports: usize,
    pub services_identified: usize,
    pub vulnerabilities_found: usize,
    pub critical_vulns: usize,
    pub high_vulns: usize,
    pub medium_vulns: usize,
    pub low_vulns: usize,
}

/// Critical finding for email notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalFinding {
    pub title: String,
    pub host: String,
    pub port: String,
    pub service: String,
    pub severity: String,
    pub description: String,
}
