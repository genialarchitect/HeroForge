#![allow(dead_code)]
//! Secret detection patterns
//!
//! This module defines regex patterns for detecting various types of secrets
//! such as API keys, tokens, passwords, and private keys.

use once_cell::sync::Lazy;
use regex::Regex;

use super::types::{SecretSeverity, SecretType};

/// A pattern for detecting a specific type of secret
pub struct SecretPattern {
    /// Name of the pattern for logging
    pub name: &'static str,
    /// Type of secret this pattern detects
    pub secret_type: SecretType,
    /// Compiled regex pattern
    pub regex: Regex,
    /// Default confidence for matches (can be adjusted based on context)
    pub base_confidence: f32,
    /// Severity override (if different from SecretType default)
    pub severity_override: Option<SecretSeverity>,
    /// Whether this pattern is prone to false positives
    pub high_false_positive_rate: bool,
}

impl SecretPattern {
    /// Create a new secret pattern
    fn new(
        name: &'static str,
        secret_type: SecretType,
        pattern: &str,
        base_confidence: f32,
    ) -> Option<Self> {
        Regex::new(pattern).ok().map(|regex| Self {
            name,
            secret_type,
            regex,
            base_confidence,
            severity_override: None,
            high_false_positive_rate: false,
        })
    }

    /// Create a pattern marked as high false positive rate
    fn new_hfp(
        name: &'static str,
        secret_type: SecretType,
        pattern: &str,
        base_confidence: f32,
    ) -> Option<Self> {
        Self::new(name, secret_type, pattern, base_confidence).map(|mut p| {
            p.high_false_positive_rate = true;
            p
        })
    }

    /// Create a pattern with severity override
    fn new_with_severity(
        name: &'static str,
        secret_type: SecretType,
        pattern: &str,
        base_confidence: f32,
        severity: SecretSeverity,
    ) -> Option<Self> {
        Self::new(name, secret_type, pattern, base_confidence).map(|mut p| {
            p.severity_override = Some(severity);
            p
        })
    }
}

/// All secret detection patterns
pub static SECRET_PATTERNS: Lazy<Vec<SecretPattern>> = Lazy::new(|| {
    let mut patterns = Vec::new();

    // ============================================================================
    // AWS Credentials
    // ============================================================================

    // AWS Access Key ID (starts with AKIA, ABIA, ACCA, ASIA)
    if let Some(p) = SecretPattern::new(
        "AWS Access Key ID",
        SecretType::AwsAccessKey,
        r"(?i)\b(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b",
        0.95,
    ) {
        patterns.push(p);
    }

    // AWS Secret Access Key (40 characters, base64-like)
    if let Some(p) = SecretPattern::new(
        "AWS Secret Access Key",
        SecretType::AwsSecretKey,
        r#"(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['">\s]"#,
        0.85,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // GitHub Tokens
    // ============================================================================

    // GitHub Personal Access Token (new format)
    if let Some(p) = SecretPattern::new(
        "GitHub Personal Access Token",
        SecretType::GitHubToken,
        r"\bghp_[A-Za-z0-9]{36}\b",
        0.98,
    ) {
        patterns.push(p);
    }

    // GitHub OAuth Token
    if let Some(p) = SecretPattern::new(
        "GitHub OAuth Token",
        SecretType::GitHubOAuth,
        r"\bgho_[A-Za-z0-9]{36}\b",
        0.98,
    ) {
        patterns.push(p);
    }

    // GitHub App Token
    if let Some(p) = SecretPattern::new(
        "GitHub App Token",
        SecretType::GitHubToken,
        r"\b(ghu|ghs)_[A-Za-z0-9]{36}\b",
        0.98,
    ) {
        patterns.push(p);
    }

    // GitHub Refresh Token
    if let Some(p) = SecretPattern::new(
        "GitHub Refresh Token",
        SecretType::GitHubToken,
        r"\bghr_[A-Za-z0-9]{36}\b",
        0.98,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // GitLab Tokens
    // ============================================================================

    if let Some(p) = SecretPattern::new(
        "GitLab Personal Access Token",
        SecretType::GitLabToken,
        r"\bglpat-[A-Za-z0-9\-_]{20,}\b",
        0.98,
    ) {
        patterns.push(p);
    }

    // GitLab Pipeline Token
    if let Some(p) = SecretPattern::new(
        "GitLab Pipeline Token",
        SecretType::GitLabToken,
        r"\bglptt-[A-Za-z0-9]{40}\b",
        0.98,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Slack Tokens
    // ============================================================================

    // Slack Bot Token
    if let Some(p) = SecretPattern::new(
        "Slack Bot Token",
        SecretType::SlackToken,
        r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b",
        0.95,
    ) {
        patterns.push(p);
    }

    // Slack User Token
    if let Some(p) = SecretPattern::new(
        "Slack User Token",
        SecretType::SlackToken,
        r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}\b",
        0.95,
    ) {
        patterns.push(p);
    }

    // Slack App Token
    if let Some(p) = SecretPattern::new(
        "Slack App Token",
        SecretType::SlackToken,
        r"\bxoxr-[0-9A-Za-z\-]+\b",
        0.90,
    ) {
        patterns.push(p);
    }

    // Slack Webhook URL
    if let Some(p) = SecretPattern::new(
        "Slack Webhook URL",
        SecretType::SlackWebhook,
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        0.98,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Google API Keys
    // ============================================================================

    if let Some(p) = SecretPattern::new(
        "Google API Key",
        SecretType::GoogleApiKey,
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
        0.95,
    ) {
        patterns.push(p);
    }

    // Google OAuth Client ID
    if let Some(p) = SecretPattern::new_hfp(
        "Google OAuth Client ID",
        SecretType::GoogleOAuth,
        r"\b[0-9]+-[A-Za-z0-9_]+\.apps\.googleusercontent\.com\b",
        0.80,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Stripe Keys
    // ============================================================================

    // Stripe Secret Key (live)
    if let Some(p) = SecretPattern::new(
        "Stripe Live Secret Key",
        SecretType::StripeKey,
        r"\bsk_live_[A-Za-z0-9]{24,}\b",
        0.98,
    ) {
        patterns.push(p);
    }

    // Stripe Secret Key (test)
    if let Some(p) = SecretPattern::new_with_severity(
        "Stripe Test Secret Key",
        SecretType::StripeKey,
        r"\bsk_test_[A-Za-z0-9]{24,}\b",
        0.90,
        SecretSeverity::Medium,
    ) {
        patterns.push(p);
    }

    // Stripe Publishable Key (live) - lower severity as it's meant to be public
    if let Some(p) = SecretPattern::new(
        "Stripe Live Publishable Key",
        SecretType::StripePublishableKey,
        r"\bpk_live_[A-Za-z0-9]{24,}\b",
        0.70,
    ) {
        patterns.push(p);
    }

    // Stripe Restricted Key
    if let Some(p) = SecretPattern::new(
        "Stripe Restricted Key",
        SecretType::StripeKey,
        r"\brk_live_[A-Za-z0-9]{24,}\b",
        0.98,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Twilio
    // ============================================================================

    if let Some(p) = SecretPattern::new(
        "Twilio API Key",
        SecretType::TwilioApiKey,
        r"\bSK[a-f0-9]{32}\b",
        0.90,
    ) {
        patterns.push(p);
    }

    if let Some(p) = SecretPattern::new(
        "Twilio Account SID",
        SecretType::TwilioAccountSid,
        r"\bAC[a-f0-9]{32}\b",
        0.90,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // SendGrid
    // ============================================================================

    if let Some(p) = SecretPattern::new(
        "SendGrid API Key",
        SecretType::SendGridKey,
        r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b",
        0.98,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Mailgun
    // ============================================================================

    if let Some(p) = SecretPattern::new(
        "Mailgun API Key",
        SecretType::MailgunKey,
        r"\bkey-[A-Za-z0-9]{32}\b",
        0.85,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Mailchimp
    // ============================================================================

    if let Some(p) = SecretPattern::new(
        "Mailchimp API Key",
        SecretType::MailchimpKey,
        r"\b[a-f0-9]{32}-us[0-9]{1,2}\b",
        0.85,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Heroku
    // ============================================================================

    if let Some(p) = SecretPattern::new(
        "Heroku API Key",
        SecretType::HerokuApiKey,
        r#"(?i)heroku[_\-]?api[_\-]?key['"]?\s*[:=]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"#,
        0.85,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // DigitalOcean
    // ============================================================================

    if let Some(p) = SecretPattern::new(
        "DigitalOcean Personal Access Token",
        SecretType::DigitalOceanToken,
        r"\bdop_v1_[a-f0-9]{64}\b",
        0.98,
    ) {
        patterns.push(p);
    }

    // DigitalOcean OAuth Token
    if let Some(p) = SecretPattern::new(
        "DigitalOcean OAuth Token",
        SecretType::DigitalOceanToken,
        r"\bdoo_v1_[a-f0-9]{64}\b",
        0.98,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // NPM
    // ============================================================================

    if let Some(p) = SecretPattern::new(
        "NPM Token",
        SecretType::NpmToken,
        r"\bnpm_[A-Za-z0-9]{36}\b",
        0.95,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // PyPI
    // ============================================================================

    if let Some(p) = SecretPattern::new(
        "PyPI Token",
        SecretType::PyPiToken,
        r"\bpypi-[A-Za-z0-9\-_]{100,}\b",
        0.95,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Docker Hub
    // ============================================================================

    if let Some(p) = SecretPattern::new(
        "Docker Hub Token",
        SecretType::DockerHubToken,
        r"\bdckr_pat_[A-Za-z0-9\-_]{50,}\b",
        0.95,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Azure
    // ============================================================================

    if let Some(p) = SecretPattern::new_hfp(
        "Azure Storage Account Key",
        SecretType::AzureStorageKey,
        r"(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{86}==",
        0.85,
    ) {
        patterns.push(p);
    }

    if let Some(p) = SecretPattern::new_hfp(
        "Azure Subscription Key",
        SecretType::AzureSubscriptionKey,
        r#"(?i)(?:subscription[_-]?key|ocp-apim-subscription-key)\s*[:=]\s*['"]?([a-f0-9]{32})['"]?"#,
        0.80,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Firebase
    // ============================================================================

    if let Some(p) = SecretPattern::new_hfp(
        "Firebase Cloud Messaging Key",
        SecretType::FirebaseKey,
        r#"(?i)(?:firebase|fcm)[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9\-_]{40})['"]?"#,
        0.75,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // JWT Tokens
    // ============================================================================

    if let Some(p) = SecretPattern::new_hfp(
        "JWT Token",
        SecretType::JwtToken,
        r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*\b",
        0.85,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Private Keys
    // ============================================================================

    if let Some(p) = SecretPattern::new(
        "RSA Private Key",
        SecretType::RsaPrivateKey,
        r"-----BEGIN RSA PRIVATE KEY-----",
        0.99,
    ) {
        patterns.push(p);
    }

    if let Some(p) = SecretPattern::new(
        "OpenSSH Private Key",
        SecretType::SshPrivateKeyOpenssh,
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
        0.99,
    ) {
        patterns.push(p);
    }

    if let Some(p) = SecretPattern::new(
        "SSH Private Key",
        SecretType::SshPrivateKey,
        r"-----BEGIN (?:DSA |EC )?PRIVATE KEY-----",
        0.99,
    ) {
        patterns.push(p);
    }

    if let Some(p) = SecretPattern::new(
        "PGP Private Key Block",
        SecretType::PgpPrivateKey,
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        0.99,
    ) {
        patterns.push(p);
    }

    if let Some(p) = SecretPattern::new(
        "EC Private Key",
        SecretType::EcPrivateKey,
        r"-----BEGIN EC PRIVATE KEY-----",
        0.99,
    ) {
        patterns.push(p);
    }

    if let Some(p) = SecretPattern::new(
        "PKCS#8 Private Key",
        SecretType::Pkcs8PrivateKey,
        r"-----BEGIN PRIVATE KEY-----",
        0.99,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Database Connection Strings
    // ============================================================================

    if let Some(p) = SecretPattern::new(
        "MongoDB URI",
        SecretType::MongoDbUri,
        r#"mongodb(?:\+srv)?://[^\s'"<>]+:[^\s'"<>]+@[^\s'"<>]+"#,
        0.90,
    ) {
        patterns.push(p);
    }

    if let Some(p) = SecretPattern::new(
        "PostgreSQL URI",
        SecretType::PostgresUri,
        r#"postgres(?:ql)?://[^\s'"<>]+:[^\s'"<>]+@[^\s'"<>]+"#,
        0.90,
    ) {
        patterns.push(p);
    }

    if let Some(p) = SecretPattern::new(
        "MySQL URI",
        SecretType::MySqlUri,
        r#"mysql://[^\s'"<>]+:[^\s'"<>]+@[^\s'"<>]+"#,
        0.90,
    ) {
        patterns.push(p);
    }

    if let Some(p) = SecretPattern::new(
        "Redis URI",
        SecretType::RedisUri,
        r#"redis://[^\s'"<>]+:[^\s'"<>]+@[^\s'"<>]+"#,
        0.85,
    ) {
        patterns.push(p);
    }

    if let Some(p) = SecretPattern::new_hfp(
        "MSSQL Connection String",
        SecretType::MsSqlConnectionString,
        r"(?i)(?:Server|Data Source)=[^;]+;.*(?:Password|PWD)=[^;]+",
        0.80,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Passwords in Code/URLs
    // ============================================================================

    // Password in URL
    if let Some(p) = SecretPattern::new(
        "Password in URL",
        SecretType::PasswordInUrl,
        r"://[^/:@\s]+:([^/@\s]{4,})@[^/\s]+",
        0.85,
    ) {
        patterns.push(p);
    }

    // Password in configuration
    if let Some(p) = SecretPattern::new_hfp(
        "Password in Configuration",
        SecretType::PasswordInConfig,
        r#"(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*['"]+([^'"]{4,})['"]+(?:\s|,|;|$)"#,
        0.75,
    ) {
        patterns.push(p);
    }

    // Basic Auth Header
    if let Some(p) = SecretPattern::new(
        "Basic Auth Credentials",
        SecretType::BasicAuthCredentials,
        r#"(?i)(?:Authorization|auth)\s*[:=]\s*['"]?Basic\s+([A-Za-z0-9+/=]{8,})['"]?"#,
        0.85,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Generic API Keys and Tokens
    // ============================================================================

    // Generic API Key pattern
    if let Some(p) = SecretPattern::new_hfp(
        "Generic API Key",
        SecretType::GenericApiKey,
        r#"(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*['"]*([A-Za-z0-9\-_]{20,})['"]*"#,
        0.70,
    ) {
        patterns.push(p);
    }

    // Generic API Token
    if let Some(p) = SecretPattern::new_hfp(
        "Generic API Token",
        SecretType::GenericApiToken,
        r#"(?i)(?:api[_\-]?token|access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['"]*([A-Za-z0-9\-_]{20,})['"]*"#,
        0.70,
    ) {
        patterns.push(p);
    }

    // Bearer Token
    if let Some(p) = SecretPattern::new_hfp(
        "Bearer Token",
        SecretType::GenericBearerToken,
        r"(?i)Bearer\s+([A-Za-z0-9\-_\.]{20,})",
        0.75,
    ) {
        patterns.push(p);
    }

    // Generic Secret Key
    if let Some(p) = SecretPattern::new_hfp(
        "Generic Secret Key",
        SecretType::GenericSecretKey,
        r#"(?i)(?:secret[_\-]?key|private[_\-]?key|encryption[_\-]?key)\s*[:=]\s*['"]*([A-Za-z0-9\-_+/=]{16,})['"]*"#,
        0.65,
    ) {
        patterns.push(p);
    }

    // ============================================================================
    // Infrastructure Tokens
    // ============================================================================

    // Kubernetes Service Account Token
    if let Some(p) = SecretPattern::new(
        "Kubernetes Token",
        SecretType::KubernetesToken,
        r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        0.70, // Lower confidence as it overlaps with JWT
    ) {
        patterns.push(p);
    }

    // HashiCorp Vault Token
    if let Some(p) = SecretPattern::new(
        "Vault Token",
        SecretType::VaultToken,
        r"\bhvs\.[A-Za-z0-9]{24,}\b",
        0.95,
    ) {
        patterns.push(p);
    }

    // Consul Token
    if let Some(p) = SecretPattern::new_hfp(
        "Consul Token",
        SecretType::ConsulToken,
        r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b",
        0.50, // Low confidence as UUIDs are common
    ) {
        patterns.push(p);
    }

    patterns
});

/// Get all patterns that match a specific secret type
pub fn patterns_for_type(secret_type: &SecretType) -> Vec<&'static SecretPattern> {
    SECRET_PATTERNS
        .iter()
        .filter(|p| &p.secret_type == secret_type)
        .collect()
}

/// Get all high-confidence patterns (confidence >= 0.9)
pub fn high_confidence_patterns() -> Vec<&'static SecretPattern> {
    SECRET_PATTERNS
        .iter()
        .filter(|p| p.base_confidence >= 0.90)
        .collect()
}

/// Get patterns excluding those with high false positive rates
pub fn low_noise_patterns() -> Vec<&'static SecretPattern> {
    SECRET_PATTERNS
        .iter()
        .filter(|p| !p.high_false_positive_rate)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patterns_loaded() {
        assert!(!SECRET_PATTERNS.is_empty());
        println!("Loaded {} secret detection patterns", SECRET_PATTERNS.len());
    }

    #[test]
    fn test_aws_access_key_pattern() {
        let pattern = SECRET_PATTERNS
            .iter()
            .find(|p| matches!(p.secret_type, SecretType::AwsAccessKey))
            .expect("AWS Access Key pattern should exist");

        assert!(pattern.regex.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(pattern.regex.is_match("Here is key: AKIAIOSFODNN7EXAMPLE"));
        assert!(!pattern.regex.is_match("INVALID1234567890123"));
    }

    #[test]
    fn test_github_token_patterns() {
        let pattern = SECRET_PATTERNS
            .iter()
            .find(|p| p.name == "GitHub Personal Access Token")
            .expect("GitHub PAT pattern should exist");

        assert!(pattern.regex.is_match("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        assert!(!pattern.regex.is_match("ghp_short"));
    }

    #[test]
    fn test_slack_token_pattern() {
        let pattern = SECRET_PATTERNS
            .iter()
            .find(|p| p.name == "Slack Bot Token")
            .expect("Slack Bot Token pattern should exist");

        // Pattern requires 24 characters at the end
        assert!(pattern.regex.is_match("xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"));
    }

    #[test]
    fn test_stripe_key_patterns() {
        let live_pattern = SECRET_PATTERNS
            .iter()
            .find(|p| p.name == "Stripe Live Secret Key")
            .expect("Stripe Live Secret Key pattern should exist");

        assert!(live_pattern.regex.is_match("sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"));

        let test_pattern = SECRET_PATTERNS
            .iter()
            .find(|p| p.name == "Stripe Test Secret Key")
            .expect("Stripe Test Secret Key pattern should exist");

        assert!(test_pattern.regex.is_match("sk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        // Test key should have lower severity
        assert_eq!(test_pattern.severity_override, Some(SecretSeverity::Medium));
    }

    #[test]
    fn test_private_key_patterns() {
        let rsa_pattern = SECRET_PATTERNS
            .iter()
            .find(|p| matches!(p.secret_type, SecretType::RsaPrivateKey))
            .expect("RSA Private Key pattern should exist");

        assert!(rsa_pattern.regex.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert_eq!(rsa_pattern.base_confidence, 0.99);
    }

    #[test]
    fn test_database_uri_patterns() {
        let mongo_pattern = SECRET_PATTERNS
            .iter()
            .find(|p| matches!(p.secret_type, SecretType::MongoDbUri))
            .expect("MongoDB URI pattern should exist");

        assert!(mongo_pattern.regex.is_match("mongodb://user:password@host:27017/db"));
        assert!(mongo_pattern.regex.is_match("mongodb+srv://user:pass@cluster.mongodb.net/db"));

        let postgres_pattern = SECRET_PATTERNS
            .iter()
            .find(|p| matches!(p.secret_type, SecretType::PostgresUri))
            .expect("PostgreSQL URI pattern should exist");

        assert!(postgres_pattern.regex.is_match("postgres://user:pass@localhost:5432/mydb"));
        assert!(postgres_pattern.regex.is_match("postgresql://admin:secret@db.example.com/prod"));
    }

    #[test]
    fn test_jwt_pattern() {
        let jwt_pattern = SECRET_PATTERNS
            .iter()
            .find(|p| matches!(p.secret_type, SecretType::JwtToken))
            .expect("JWT pattern should exist");

        // Valid JWT structure
        assert!(jwt_pattern.regex.is_match(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        ));
    }

    #[test]
    fn test_password_in_url_pattern() {
        let pattern = SECRET_PATTERNS
            .iter()
            .find(|p| matches!(p.secret_type, SecretType::PasswordInUrl))
            .expect("Password in URL pattern should exist");

        assert!(pattern.regex.is_match("https://user:secret123@example.com/api"));
        // Note: passwords with @ in them won't be fully captured by this pattern
        assert!(pattern.regex.is_match("ftp://admin:passw0rd@ftp.example.com"));
    }

    #[test]
    fn test_sendgrid_pattern() {
        let pattern = SECRET_PATTERNS
            .iter()
            .find(|p| matches!(p.secret_type, SecretType::SendGridKey))
            .expect("SendGrid pattern should exist");

        // SendGrid API key format: SG.{22 chars}.{43 chars}
        assert!(pattern.regex.is_match(
            "SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        ));
    }

    #[test]
    fn test_high_confidence_patterns() {
        let high_conf = high_confidence_patterns();
        assert!(!high_conf.is_empty());

        for pattern in high_conf {
            assert!(pattern.base_confidence >= 0.90);
        }
    }

    #[test]
    fn test_low_noise_patterns() {
        let low_noise = low_noise_patterns();
        assert!(!low_noise.is_empty());

        for pattern in low_noise {
            assert!(!pattern.high_false_positive_rate);
        }
    }
}
