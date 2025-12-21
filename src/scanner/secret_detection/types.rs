#![allow(dead_code)]
//! Types for secret detection scanner
//!
//! This module provides data structures for detecting exposed secrets such as
//! API keys, passwords, tokens, and private keys in scan results.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity level for detected secrets
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SecretSeverity {
    /// Low severity - potential false positive or low-risk exposure
    Low,
    /// Medium severity - credential that may have limited access
    Medium,
    /// High severity - credential with significant access potential
    High,
    /// Critical severity - highly privileged credential requiring immediate action
    Critical,
}

impl std::fmt::Display for SecretSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretSeverity::Low => write!(f, "low"),
            SecretSeverity::Medium => write!(f, "medium"),
            SecretSeverity::High => write!(f, "high"),
            SecretSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl Default for SecretSeverity {
    fn default() -> Self {
        SecretSeverity::Medium
    }
}

/// Type of secret detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    // API Keys & Tokens
    AwsAccessKey,
    AwsSecretKey,
    GitHubToken,
    GitHubOAuth,
    GitLabToken,
    SlackToken,
    SlackWebhook,
    GoogleApiKey,
    GoogleOAuth,
    StripeKey,
    StripePublishableKey,
    TwilioApiKey,
    TwilioAccountSid,
    SendGridKey,
    MailgunKey,
    MailchimpKey,
    HerokuApiKey,
    DigitalOceanToken,
    NpmToken,
    PyPiToken,
    DockerHubToken,
    AzureSubscriptionKey,
    AzureStorageKey,
    GcpServiceAccount,
    FirebaseKey,
    Auth0Token,
    OktaToken,
    JwtToken,
    GenericApiKey,
    GenericApiToken,
    GenericBearerToken,
    GenericSecretKey,

    // Private Keys
    RsaPrivateKey,
    SshPrivateKey,
    SshPrivateKeyOpenssh,
    PgpPrivateKey,
    EcPrivateKey,
    DsaPrivateKey,
    Pkcs8PrivateKey,

    // Passwords & Credentials
    PasswordInUrl,
    PasswordInConfig,
    BasicAuthCredentials,
    HardcodedPassword,

    // Database Connection Strings
    MongoDbUri,
    PostgresUri,
    MySqlUri,
    RedisUri,
    MsSqlConnectionString,

    // Cloud & Infrastructure
    KubernetesToken,
    ConsulToken,
    VaultToken,

    // Other
    Unknown,
}

impl SecretType {
    /// Get the display name for this secret type
    pub fn display_name(&self) -> &'static str {
        match self {
            SecretType::AwsAccessKey => "AWS Access Key",
            SecretType::AwsSecretKey => "AWS Secret Key",
            SecretType::GitHubToken => "GitHub Personal Access Token",
            SecretType::GitHubOAuth => "GitHub OAuth Token",
            SecretType::GitLabToken => "GitLab Personal Access Token",
            SecretType::SlackToken => "Slack Token",
            SecretType::SlackWebhook => "Slack Webhook URL",
            SecretType::GoogleApiKey => "Google API Key",
            SecretType::GoogleOAuth => "Google OAuth Credentials",
            SecretType::StripeKey => "Stripe Secret Key",
            SecretType::StripePublishableKey => "Stripe Publishable Key",
            SecretType::TwilioApiKey => "Twilio API Key",
            SecretType::TwilioAccountSid => "Twilio Account SID",
            SecretType::SendGridKey => "SendGrid API Key",
            SecretType::MailgunKey => "Mailgun API Key",
            SecretType::MailchimpKey => "Mailchimp API Key",
            SecretType::HerokuApiKey => "Heroku API Key",
            SecretType::DigitalOceanToken => "DigitalOcean Token",
            SecretType::NpmToken => "NPM Token",
            SecretType::PyPiToken => "PyPI Token",
            SecretType::DockerHubToken => "Docker Hub Token",
            SecretType::AzureSubscriptionKey => "Azure Subscription Key",
            SecretType::AzureStorageKey => "Azure Storage Key",
            SecretType::GcpServiceAccount => "GCP Service Account",
            SecretType::FirebaseKey => "Firebase Key",
            SecretType::Auth0Token => "Auth0 Token",
            SecretType::OktaToken => "Okta Token",
            SecretType::JwtToken => "JWT Token",
            SecretType::GenericApiKey => "Generic API Key",
            SecretType::GenericApiToken => "Generic API Token",
            SecretType::GenericBearerToken => "Bearer Token",
            SecretType::GenericSecretKey => "Generic Secret Key",
            SecretType::RsaPrivateKey => "RSA Private Key",
            SecretType::SshPrivateKey => "SSH Private Key",
            SecretType::SshPrivateKeyOpenssh => "OpenSSH Private Key",
            SecretType::PgpPrivateKey => "PGP Private Key",
            SecretType::EcPrivateKey => "EC Private Key",
            SecretType::DsaPrivateKey => "DSA Private Key",
            SecretType::Pkcs8PrivateKey => "PKCS#8 Private Key",
            SecretType::PasswordInUrl => "Password in URL",
            SecretType::PasswordInConfig => "Password in Configuration",
            SecretType::BasicAuthCredentials => "Basic Auth Credentials",
            SecretType::HardcodedPassword => "Hardcoded Password",
            SecretType::MongoDbUri => "MongoDB Connection URI",
            SecretType::PostgresUri => "PostgreSQL Connection URI",
            SecretType::MySqlUri => "MySQL Connection URI",
            SecretType::RedisUri => "Redis Connection URI",
            SecretType::MsSqlConnectionString => "MSSQL Connection String",
            SecretType::KubernetesToken => "Kubernetes Token",
            SecretType::ConsulToken => "Consul Token",
            SecretType::VaultToken => "Vault Token",
            SecretType::Unknown => "Unknown Secret",
        }
    }

    /// Get the default severity for this secret type
    pub fn default_severity(&self) -> SecretSeverity {
        match self {
            // Critical - Full account/system access
            SecretType::AwsAccessKey |
            SecretType::AwsSecretKey |
            SecretType::GitHubToken |
            SecretType::GitHubOAuth |
            SecretType::GitLabToken |
            SecretType::StripeKey |
            SecretType::GcpServiceAccount |
            SecretType::AzureStorageKey |
            SecretType::RsaPrivateKey |
            SecretType::SshPrivateKey |
            SecretType::SshPrivateKeyOpenssh |
            SecretType::PgpPrivateKey |
            SecretType::EcPrivateKey |
            SecretType::DsaPrivateKey |
            SecretType::Pkcs8PrivateKey |
            SecretType::VaultToken |
            SecretType::MongoDbUri |
            SecretType::PostgresUri |
            SecretType::MySqlUri |
            SecretType::MsSqlConnectionString |
            SecretType::KubernetesToken |
            SecretType::HerokuApiKey |
            SecretType::DigitalOceanToken => SecretSeverity::Critical,

            // High - Significant access potential
            SecretType::SlackToken |
            SecretType::TwilioApiKey |
            SecretType::TwilioAccountSid |
            SecretType::SendGridKey |
            SecretType::MailgunKey |
            SecretType::MailchimpKey |
            SecretType::NpmToken |
            SecretType::PyPiToken |
            SecretType::DockerHubToken |
            SecretType::AzureSubscriptionKey |
            SecretType::FirebaseKey |
            SecretType::Auth0Token |
            SecretType::OktaToken |
            SecretType::GenericApiKey |
            SecretType::GenericSecretKey |
            SecretType::PasswordInUrl |
            SecretType::PasswordInConfig |
            SecretType::BasicAuthCredentials |
            SecretType::HardcodedPassword |
            SecretType::RedisUri |
            SecretType::ConsulToken => SecretSeverity::High,

            // Medium - Limited or scoped access
            SecretType::GoogleApiKey |
            SecretType::GoogleOAuth |
            SecretType::SlackWebhook |
            SecretType::GenericApiToken |
            SecretType::GenericBearerToken |
            SecretType::JwtToken => SecretSeverity::Medium,

            // Low - Public/Publishable keys
            SecretType::StripePublishableKey |
            SecretType::Unknown => SecretSeverity::Low,
        }
    }

    /// Get remediation advice for this secret type
    pub fn remediation(&self) -> &'static str {
        match self {
            SecretType::AwsAccessKey | SecretType::AwsSecretKey => {
                "CRITICAL: Immediately rotate this AWS credential in the IAM console. \
                 Delete the exposed key and generate new credentials. Review CloudTrail \
                 logs for unauthorized access. Use AWS Secrets Manager or environment \
                 variables for credential storage."
            }
            SecretType::GitHubToken | SecretType::GitHubOAuth => {
                "CRITICAL: Revoke this token immediately in GitHub Settings > Developer Settings > \
                 Personal Access Tokens. Generate a new token with minimal required scopes. \
                 Review repository access logs for unauthorized actions."
            }
            SecretType::GitLabToken => {
                "CRITICAL: Revoke this token in GitLab User Settings > Access Tokens. \
                 Generate a new token with minimal required scopes."
            }
            SecretType::SlackToken | SecretType::SlackWebhook => {
                "Regenerate this Slack token/webhook in your Slack app settings. \
                 Review Slack audit logs for unauthorized message access."
            }
            SecretType::GoogleApiKey | SecretType::GoogleOAuth => {
                "Regenerate API credentials in Google Cloud Console. Apply API key restrictions \
                 (HTTP referrers, IP addresses, or API restrictions) to limit exposure."
            }
            SecretType::StripeKey => {
                "CRITICAL: Roll this Stripe key immediately in the Stripe Dashboard. \
                 Stripe secret keys provide full API access including payment processing. \
                 Review recent API activity for unauthorized transactions."
            }
            SecretType::StripePublishableKey => {
                "While publishable keys are designed to be public, consider rotating if \
                 combined with other exposed credentials."
            }
            SecretType::RsaPrivateKey |
            SecretType::SshPrivateKey |
            SecretType::SshPrivateKeyOpenssh |
            SecretType::EcPrivateKey |
            SecretType::DsaPrivateKey |
            SecretType::Pkcs8PrivateKey => {
                "CRITICAL: This private key is compromised. Immediately remove it from all \
                 authorized_keys files and certificate authorities. Generate new key pairs \
                 and update all systems that depend on this key."
            }
            SecretType::PgpPrivateKey => {
                "CRITICAL: This PGP private key is compromised. Revoke the key on key servers \
                 and generate a new keypair. Update all encrypted communications."
            }
            SecretType::PasswordInUrl |
            SecretType::PasswordInConfig |
            SecretType::BasicAuthCredentials |
            SecretType::HardcodedPassword => {
                "Remove hardcoded credentials immediately. Use environment variables, \
                 secrets management systems (Vault, AWS Secrets Manager), or secure \
                 configuration files with appropriate permissions."
            }
            SecretType::MongoDbUri |
            SecretType::PostgresUri |
            SecretType::MySqlUri |
            SecretType::RedisUri |
            SecretType::MsSqlConnectionString => {
                "CRITICAL: Database credentials are exposed. Change passwords immediately \
                 and rotate connection strings. Use secure credential storage and ensure \
                 databases are not publicly accessible."
            }
            SecretType::JwtToken => {
                "If this is a long-lived token, consider invalidating it. Implement token \
                 refresh mechanisms and use short-lived tokens where possible."
            }
            SecretType::KubernetesToken |
            SecretType::VaultToken |
            SecretType::ConsulToken => {
                "CRITICAL: Infrastructure tokens provide privileged access. Rotate immediately \
                 and audit all recent cluster/infrastructure activity."
            }
            _ => {
                "Rotate this credential immediately. Store secrets using environment variables \
                 or a secrets management solution. Never commit credentials to source code."
            }
        }
    }
}

impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Source location where a secret was found
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretSource {
    /// Found in HTTP response body
    HttpResponseBody {
        url: String,
        content_type: Option<String>,
    },
    /// Found in HTTP response headers
    HttpResponseHeader {
        url: String,
        header_name: String,
    },
    /// Found in service banner
    ServiceBanner {
        port: u16,
        service_name: Option<String>,
    },
    /// Found in JavaScript file
    JavaScriptFile {
        url: String,
    },
    /// Found in configuration file
    ConfigFile {
        path: String,
    },
    /// Found in HTML comment
    HtmlComment {
        url: String,
    },
    /// Found in API response
    ApiResponse {
        url: String,
        method: String,
    },
    /// Found in error message
    ErrorMessage {
        url: String,
    },
    /// Generic source
    Unknown {
        description: String,
    },
}

impl SecretSource {
    /// Get a short description of the source
    pub fn description(&self) -> String {
        match self {
            SecretSource::HttpResponseBody { url, .. } => {
                format!("HTTP response body: {}", url)
            }
            SecretSource::HttpResponseHeader { url, header_name } => {
                format!("HTTP header '{}': {}", header_name, url)
            }
            SecretSource::ServiceBanner { port, service_name } => {
                if let Some(name) = service_name {
                    format!("Service banner ({}:{})", name, port)
                } else {
                    format!("Service banner (port {})", port)
                }
            }
            SecretSource::JavaScriptFile { url } => {
                format!("JavaScript file: {}", url)
            }
            SecretSource::ConfigFile { path } => {
                format!("Configuration file: {}", path)
            }
            SecretSource::HtmlComment { url } => {
                format!("HTML comment: {}", url)
            }
            SecretSource::ApiResponse { url, method } => {
                format!("API response ({} {})", method, url)
            }
            SecretSource::ErrorMessage { url } => {
                format!("Error message: {}", url)
            }
            SecretSource::Unknown { description } => {
                description.clone()
            }
        }
    }
}

/// A detected secret finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    /// Type of secret detected
    pub secret_type: SecretType,
    /// Severity of the finding
    pub severity: SecretSeverity,
    /// Redacted version of the matched value (e.g., "AKIA****XXXX")
    pub redacted_value: String,
    /// Location where the secret was found
    pub source: SecretSource,
    /// Line number within the content (if applicable)
    pub line_number: Option<u32>,
    /// Context around the match (redacted)
    pub context: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl SecretFinding {
    /// Create a new secret finding
    pub fn new(
        secret_type: SecretType,
        matched_value: &str,
        source: SecretSource,
        confidence: f32,
    ) -> Self {
        let severity = secret_type.default_severity();
        let redacted_value = Self::redact_value(matched_value);

        Self {
            secret_type,
            severity,
            redacted_value,
            source,
            line_number: None,
            context: String::new(),
            confidence,
            metadata: HashMap::new(),
        }
    }

    /// Create a new finding with context
    pub fn with_context(mut self, context: &str, line_number: Option<u32>) -> Self {
        self.context = Self::redact_context(context);
        self.line_number = line_number;
        self
    }

    /// Add metadata to the finding
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Override the severity level
    pub fn with_severity(mut self, severity: SecretSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Redact a secret value, showing only first and last few characters
    /// SECURITY: This function ensures secrets are never fully exposed
    fn redact_value(value: &str) -> String {
        let len = value.len();

        if len <= 8 {
            // Very short - show only type indicator
            return "*".repeat(len.min(8));
        }

        if len <= 16 {
            // Short - show first 2 and last 2 characters
            let prefix = &value[..2];
            let suffix = &value[len - 2..];
            return format!("{}{}{}",
                prefix,
                "*".repeat((len - 4).min(8)),
                suffix
            );
        }

        // Normal length - show first 4 and last 4 characters
        let prefix = &value[..4];
        let suffix = &value[len - 4..];
        let hidden_len = (len - 8).min(12);

        format!("{}{}{}", prefix, "*".repeat(hidden_len), suffix)
    }

    /// Redact context text while preserving structure
    /// SECURITY: Removes any potential secret values from surrounding text
    fn redact_context(context: &str) -> String {
        let mut redacted = context.to_string();

        // Truncate to reasonable length
        if redacted.len() > 200 {
            redacted = format!("{}...", &redacted[..200]);
        }

        // Replace potential secret patterns with placeholder
        // This is a secondary safety measure
        let patterns = [
            (r"[A-Za-z0-9+/=]{32,}", "[REDACTED_BASE64]"),
            (r"[a-f0-9]{32,}", "[REDACTED_HEX]"),
            (r"-----BEGIN[^-]+-----", "[REDACTED_KEY_BEGIN]"),
        ];

        for (pattern, replacement) in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                redacted = re.replace_all(&redacted, replacement).to_string();
            }
        }

        redacted
    }

    /// Get remediation advice for this finding
    pub fn remediation(&self) -> &'static str {
        self.secret_type.remediation()
    }
}

/// Configuration for secret detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretDetectionConfig {
    /// Whether secret detection is enabled
    pub enabled: bool,
    /// Minimum confidence threshold (0.0 - 1.0)
    pub min_confidence: f32,
    /// Secret types to scan for (empty = all)
    pub secret_types: Vec<SecretType>,
    /// Maximum content size to scan (bytes)
    pub max_content_size: usize,
    /// Whether to scan JavaScript files
    pub scan_javascript: bool,
    /// Whether to scan HTML comments
    pub scan_html_comments: bool,
    /// Whether to scan service banners
    pub scan_service_banners: bool,
}

impl Default for SecretDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_confidence: 0.7,
            secret_types: Vec::new(), // Empty = scan for all types
            max_content_size: 10 * 1024 * 1024, // 10 MB
            scan_javascript: true,
            scan_html_comments: true,
            scan_service_banners: true,
        }
    }
}

/// Summary of secret detection results
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretDetectionSummary {
    /// Total number of secrets found
    pub total_findings: usize,
    /// Count by severity
    pub by_severity: HashMap<SecretSeverity, usize>,
    /// Count by secret type
    pub by_type: HashMap<SecretType, usize>,
    /// Whether any critical secrets were found
    pub has_critical: bool,
}

impl SecretDetectionSummary {
    /// Create a summary from findings
    pub fn from_findings(findings: &[SecretFinding]) -> Self {
        let mut summary = Self {
            total_findings: findings.len(),
            by_severity: HashMap::new(),
            by_type: HashMap::new(),
            has_critical: false,
        };

        for finding in findings {
            *summary.by_severity.entry(finding.severity.clone()).or_insert(0) += 1;
            *summary.by_type.entry(finding.secret_type.clone()).or_insert(0) += 1;

            if finding.severity == SecretSeverity::Critical {
                summary.has_critical = true;
            }
        }

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_value_short() {
        let redacted = SecretFinding::redact_value("12345678");
        assert_eq!(redacted, "********");
    }

    #[test]
    fn test_redact_value_medium() {
        let redacted = SecretFinding::redact_value("1234567890123456");
        assert_eq!(redacted, "12********56");
    }

    #[test]
    fn test_redact_value_long() {
        let redacted = SecretFinding::redact_value("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(redacted, "AKIA************MPLE");
    }

    #[test]
    fn test_secret_type_severity() {
        assert_eq!(SecretType::AwsAccessKey.default_severity(), SecretSeverity::Critical);
        assert_eq!(SecretType::JwtToken.default_severity(), SecretSeverity::Medium);
        assert_eq!(SecretType::StripePublishableKey.default_severity(), SecretSeverity::Low);
    }

    #[test]
    fn test_secret_finding_creation() {
        let finding = SecretFinding::new(
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE",
            SecretSource::HttpResponseBody {
                url: "https://example.com".to_string(),
                content_type: Some("text/html".to_string()),
            },
            0.95,
        );

        assert_eq!(finding.severity, SecretSeverity::Critical);
        assert!(finding.redacted_value.contains("****"));
        assert!(!finding.redacted_value.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_secret_source_description() {
        let source = SecretSource::ServiceBanner {
            port: 80,
            service_name: Some("http".to_string()),
        };
        assert_eq!(source.description(), "Service banner (http:80)");
    }

    #[test]
    fn test_summary_from_findings() {
        let findings = vec![
            SecretFinding::new(
                SecretType::AwsAccessKey,
                "test",
                SecretSource::Unknown { description: "test".to_string() },
                0.9,
            ),
            SecretFinding::new(
                SecretType::JwtToken,
                "test",
                SecretSource::Unknown { description: "test".to_string() },
                0.9,
            ),
        ];

        let summary = SecretDetectionSummary::from_findings(&findings);
        assert_eq!(summary.total_findings, 2);
        assert!(summary.has_critical);
        assert_eq!(*summary.by_severity.get(&SecretSeverity::Critical).unwrap_or(&0), 1);
    }
}
