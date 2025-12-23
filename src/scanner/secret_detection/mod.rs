#![allow(dead_code)]
//! Secret Detection Scanner
//!
//! This module provides comprehensive secret detection capabilities for identifying
//! exposed API keys, passwords, tokens, and private keys in scan results.
//!
//! # Security Considerations
//!
//! - Secrets are NEVER stored in full - only redacted versions are persisted
//! - All log output redacts secret values
//! - Context around secrets is also redacted before storage
//!
//! # Usage
//!
//! ```rust,ignore
//! use heroforge::scanner::secret_detection::{detect_secrets, SecretDetectionConfig};
//!
//! let config = SecretDetectionConfig::default();
//! let findings = detect_secrets(content, source, &config);
//!
//! for finding in findings {
//!     println!("Found {} ({}): {}", finding.secret_type, finding.severity, finding.redacted_value);
//! }
//! ```

pub mod config_scanner;
pub mod entropy;
pub mod filesystem_scanner;
pub mod git_scanner;
pub mod patterns;
pub mod types;

pub use config_scanner::{ConfigFileType, ConfigScanner, ConfigSecretFinding};
pub use entropy::{EntropyConfig, EntropyResult, analyze_entropy, find_high_entropy_strings};
pub use filesystem_scanner::{FilesystemScanConfig, FilesystemScanner, FilesystemSecretFinding};
pub use git_scanner::{GitScanConfig, GitSecretFinding, GitSecretScanner};
pub use patterns::SECRET_PATTERNS;
pub use types::{
    SecretDetectionConfig, SecretDetectionSummary, SecretFinding, SecretSeverity, SecretSource,
};

use log::{debug, info};
use std::collections::HashSet;

/// Detect secrets in the given content
///
/// # Arguments
///
/// * `content` - The text content to scan for secrets
/// * `source` - Where this content came from (for reporting)
/// * `config` - Detection configuration
///
/// # Returns
///
/// Vector of secret findings. Secrets are automatically redacted.
///
/// # Security
///
/// This function never logs or returns the full secret value.
/// All matched content is redacted before being included in findings.
pub fn detect_secrets(
    content: &str,
    source: SecretSource,
    config: &SecretDetectionConfig,
) -> Vec<SecretFinding> {
    if !config.enabled {
        return Vec::new();
    }

    // Check content size limit
    if content.len() > config.max_content_size {
        debug!(
            "Content exceeds max size ({} > {}), truncating",
            content.len(),
            config.max_content_size
        );
    }

    let content_to_scan = if content.len() > config.max_content_size {
        &content[..config.max_content_size]
    } else {
        content
    };

    let mut findings = Vec::new();
    let mut seen_values: HashSet<String> = HashSet::new();

    // Get patterns to use
    let patterns_to_use: Vec<_> = if config.secret_types.is_empty() {
        // Use all patterns
        SECRET_PATTERNS.iter().collect()
    } else {
        // Filter to only requested types
        SECRET_PATTERNS
            .iter()
            .filter(|p| config.secret_types.contains(&p.secret_type))
            .collect()
    };

    for pattern in patterns_to_use {
        for captures in pattern.regex.captures_iter(content_to_scan) {
            // Get the full match or the first capture group
            let matched_text = captures
                .get(1)
                .or_else(|| captures.get(0))
                .map(|m| m.as_str())
                .unwrap_or("");

            if matched_text.is_empty() {
                continue;
            }

            // Skip if we've already found this exact value
            if seen_values.contains(matched_text) {
                continue;
            }
            seen_values.insert(matched_text.to_string());

            // Calculate confidence based on pattern and context
            let confidence = calculate_confidence(pattern, matched_text, content_to_scan);

            if confidence < config.min_confidence {
                debug!(
                    "Skipping low-confidence match for {}: {:.2}",
                    pattern.name, confidence
                );
                continue;
            }

            // Find line number
            let line_number = find_line_number(content_to_scan, matched_text);

            // Extract context around the match
            let context = extract_context(content_to_scan, matched_text, 50);

            // Create finding with redacted values
            let mut finding =
                SecretFinding::new(pattern.secret_type.clone(), matched_text, source.clone())
                    .with_context(&context, line_number)
                    .with_detection_method(&format!("pattern:{}", pattern.name));

            // Apply severity override if present
            if let Some(ref severity) = pattern.severity_override {
                finding = finding.with_severity(severity.clone());
            }

            findings.push(finding);
        }
    }

    // Sort by severity (critical first)
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    if !findings.is_empty() {
        info!(
            "Secret detection found {} potential secrets in {}",
            findings.len(),
            source.description()
        );
    }

    findings
}

/// Detect secrets in an HTTP response body
///
/// This is a convenience function that creates an appropriate SecretSource
/// and applies HTTP-specific filtering.
pub fn detect_secrets_in_http_response(
    content: &str,
    url: &str,
    content_type: Option<&str>,
    config: &SecretDetectionConfig,
) -> Vec<SecretFinding> {
    let source = SecretSource::HttpResponseBody {
        url: url.to_string(),
        content_type: content_type.map(|s| s.to_string()),
    };

    let mut findings = detect_secrets(content, source, config);

    // Additional check for JavaScript-specific patterns if content is JS
    if let Some(ct) = content_type {
        if ct.contains("javascript") || ct.contains("json") {
            findings.extend(detect_secrets_in_javascript(content, url, config));
        }
    }

    // Deduplicate by redacted_value + source
    deduplicate_findings(&mut findings);

    findings
}

/// Detect secrets in JavaScript content
pub fn detect_secrets_in_javascript(
    content: &str,
    url: &str,
    config: &SecretDetectionConfig,
) -> Vec<SecretFinding> {
    if !config.scan_javascript {
        return Vec::new();
    }

    let source = SecretSource::JavaScriptFile {
        url: url.to_string(),
    };

    // JavaScript often has higher false positive rates for generic patterns
    // So we use slightly higher confidence threshold
    let mut js_config = config.clone();
    js_config.min_confidence = (config.min_confidence + 0.1).min(1.0);

    detect_secrets(content, source, &js_config)
}

/// Detect secrets in HTML comments
pub fn detect_secrets_in_html_comments(
    content: &str,
    url: &str,
    config: &SecretDetectionConfig,
) -> Vec<SecretFinding> {
    if !config.scan_html_comments {
        return Vec::new();
    }

    let mut findings = Vec::new();

    // Extract HTML comments
    let comment_regex = regex::Regex::new(r"<!--([\s\S]*?)-->").unwrap();

    for captures in comment_regex.captures_iter(content) {
        if let Some(comment) = captures.get(1) {
            let comment_text = comment.as_str();

            let source = SecretSource::HtmlComment {
                url: url.to_string(),
            };

            findings.extend(detect_secrets(comment_text, source, config));
        }
    }

    findings
}

/// Detect secrets in a service banner
pub fn detect_secrets_in_banner(
    banner: &str,
    port: u16,
    service_name: Option<&str>,
    config: &SecretDetectionConfig,
) -> Vec<SecretFinding> {
    if !config.scan_service_banners {
        return Vec::new();
    }

    let source = SecretSource::ServiceBanner {
        port,
        service_name: service_name.map(|s| s.to_string()),
    };

    detect_secrets(banner, source, config)
}

/// Detect secrets in an HTTP header value
pub fn detect_secrets_in_header(
    header_value: &str,
    header_name: &str,
    url: &str,
    config: &SecretDetectionConfig,
) -> Vec<SecretFinding> {
    // Skip common non-sensitive headers
    let safe_headers = [
        "content-type",
        "content-length",
        "date",
        "server",
        "cache-control",
        "etag",
        "last-modified",
        "accept",
        "accept-encoding",
        "accept-language",
        "connection",
        "host",
        "user-agent",
    ];

    let header_lower = header_name.to_lowercase();
    if safe_headers.contains(&header_lower.as_str()) {
        return Vec::new();
    }

    let source = SecretSource::HttpResponseHeader {
        url: url.to_string(),
        header_name: header_name.to_string(),
    };

    detect_secrets(header_value, source, config)
}

/// Calculate confidence score for a match based on context
fn calculate_confidence(
    pattern: &patterns::SecretPattern,
    matched_text: &str,
    content: &str,
) -> f32 {
    let mut confidence = pattern.base_confidence;

    // Reduce confidence for very short matches
    if matched_text.len() < 16 {
        confidence -= 0.1;
    }

    // Reduce confidence if the match appears in what looks like example/documentation
    let context_lower = content.to_lowercase();
    let example_indicators = ["example", "sample", "test", "demo", "dummy", "placeholder", "fake"];

    for indicator in &example_indicators {
        if context_lower.contains(indicator) {
            confidence -= 0.15;
            break;
        }
    }

    // Increase confidence if near sensitive keywords
    let sensitive_keywords = ["secret", "password", "private", "credential", "key", "token"];
    let match_start = content.find(matched_text).unwrap_or(0);
    let context_start = match_start.saturating_sub(50);
    let context_end = (match_start + matched_text.len() + 50).min(content.len());
    let surrounding = &content[context_start..context_end].to_lowercase();

    for keyword in &sensitive_keywords {
        if surrounding.contains(keyword) {
            confidence += 0.05;
            break;
        }
    }

    // Reduce confidence for high false positive patterns
    if pattern.high_false_positive_rate {
        confidence -= 0.1;
    }

    // Clamp to valid range
    confidence.clamp(0.0, 1.0)
}

/// Find the line number where a match occurs
fn find_line_number(content: &str, matched_text: &str) -> Option<usize> {
    content.find(matched_text).map(|pos| {
        content[..pos].chars().filter(|&c| c == '\n').count() + 1
    })
}

/// Extract context around a match, redacting the match itself
fn extract_context(content: &str, matched_text: &str, context_size: usize) -> String {
    if let Some(pos) = content.find(matched_text) {
        let start = pos.saturating_sub(context_size);
        let end = (pos + matched_text.len() + context_size).min(content.len());

        let before = &content[start..pos];
        let after = &content[pos + matched_text.len()..end];

        // Replace the matched text with a placeholder
        let redacted = "[REDACTED]";

        let mut context = String::new();
        if start > 0 {
            context.push_str("...");
        }
        context.push_str(before.trim_start());
        context.push_str(redacted);
        context.push_str(after.trim_end());
        if end < content.len() {
            context.push_str("...");
        }

        // Clean up whitespace
        context
            .lines()
            .map(|l| l.trim())
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        String::new()
    }
}

/// Remove duplicate findings based on redacted value and source
fn deduplicate_findings(findings: &mut Vec<SecretFinding>) {
    let mut seen = HashSet::new();

    findings.retain(|f| {
        let key = format!("{}|{}", f.redacted_value, f.source.description());
        seen.insert(key)
    });
}

/// Scan multiple content sources and combine results
pub fn scan_multiple_sources(
    sources: Vec<(&str, SecretSource)>,
    config: &SecretDetectionConfig,
) -> Vec<SecretFinding> {
    let mut all_findings = Vec::new();

    for (content, source) in sources {
        all_findings.extend(detect_secrets(content, source, config));
    }

    deduplicate_findings(&mut all_findings);
    all_findings
}

/// Create a summary of findings
pub fn summarize_findings(findings: &[SecretFinding]) -> SecretDetectionSummary {
    SecretDetectionSummary::from_findings(findings)
}

/// Check if content likely contains secrets (quick pre-filter)
///
/// This is a fast check that can be used to avoid expensive regex matching
/// on content that is unlikely to contain secrets.
pub fn might_contain_secrets(content: &str) -> bool {
    // Check for common secret indicators
    let indicators = [
        "-----BEGIN",
        "AKIA",
        "ghp_",
        "gho_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "sk_live",
        "sk_test",
        "SG.",
        "AIza",
        "Bearer",
        "password",
        "secret",
        "api_key",
        "apikey",
        "token",
        "mongodb://",
        "postgres://",
        "mysql://",
    ];

    let content_lower = content.to_lowercase();

    for indicator in &indicators {
        if content.contains(indicator) || content_lower.contains(&indicator.to_lowercase()) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::types::SecretType;

    fn default_config() -> SecretDetectionConfig {
        SecretDetectionConfig::default()
    }

    #[test]
    fn test_detect_aws_key() {
        let content = r#"
            const config = {
                aws_access_key: "AKIAIOSFODNN7EXAMPLE",
                region: "us-east-1"
            };
        "#;

        let source = SecretSource::JavaScriptFile {
            url: "https://example.com/config.js".to_string(),
        };

        let findings = detect_secrets(content, source, &default_config());

        assert!(!findings.is_empty());
        assert!(matches!(
            findings[0].secret_type,
            SecretType::AwsAccessKey
        ));
        assert!(findings[0].redacted_value.contains("****"));
        assert!(!findings[0].redacted_value.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_detect_github_token() {
        let content = "Authorization: token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

        let source = SecretSource::HttpResponseBody {
            url: "https://example.com".to_string(),
            content_type: Some("text/plain".to_string()),
        };

        let findings = detect_secrets(content, source, &default_config());

        assert!(!findings.is_empty());
        assert!(matches!(findings[0].secret_type, SecretType::GitHubToken));
    }

    #[test]
    fn test_detect_private_key() {
        let content = r#"
            -----BEGIN RSA PRIVATE KEY-----
            MIIEowIBAAKCAQEA...
            -----END RSA PRIVATE KEY-----
        "#;

        let source = SecretSource::HttpResponseBody {
            url: "https://example.com/key".to_string(),
            content_type: None,
        };

        let findings = detect_secrets(content, source, &default_config());

        assert!(!findings.is_empty());
        assert!(matches!(
            findings[0].secret_type,
            SecretType::RsaPrivateKey
        ));
        assert_eq!(findings[0].severity, SecretSeverity::Critical);
    }

    #[test]
    fn test_detect_database_uri() {
        let content = r#"
            DATABASE_URL=postgres://admin:secretpass123@db.example.com:5432/production
        "#;

        let source = SecretSource::ConfigFile {
            path: ".env".to_string(),
        };

        let findings = detect_secrets(content, source, &default_config());

        assert!(!findings.is_empty());
        assert!(matches!(
            findings[0].secret_type,
            SecretType::PostgresUri
        ));
    }

    #[test]
    fn test_detect_secrets_in_banner() {
        let banner = "SSH-2.0-OpenSSH_8.2 password=admin123";

        let findings =
            detect_secrets_in_banner(banner, 22, Some("ssh"), &default_config());

        // Might detect password pattern
        // Note: This depends on exact pattern matching
        for finding in &findings {
            assert!(finding.redacted_value.contains("****") || finding.redacted_value.len() <= 8);
        }
    }

    #[test]
    fn test_detect_jwt_token() {
        let content = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

        let source = SecretSource::HttpResponseHeader {
            url: "https://example.com".to_string(),
            header_name: "Authorization".to_string(),
        };

        let findings = detect_secrets(content, source, &default_config());

        assert!(!findings.is_empty());
    }

    #[test]
    fn test_html_comment_secrets() {
        let html = r#"
            <html>
            <!-- TODO: Remove before production
                 API_KEY=sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
            -->
            <body>Content</body>
            </html>
        "#;

        let findings =
            detect_secrets_in_html_comments(html, "https://example.com", &default_config());

        assert!(!findings.is_empty());
    }

    #[test]
    fn test_min_confidence_filter() {
        let content = "api_key = testvalue12345678901234567890";

        let mut config = default_config();
        config.min_confidence = 0.99; // Very high threshold

        let source = SecretSource::Unknown {
            description: "test".to_string(),
        };

        let findings = detect_secrets(content, source, &config);

        // Generic patterns have lower base confidence and may be filtered out
        // This tests the confidence filtering mechanism
        for finding in &findings {
            assert!(finding.confidence >= 0.99);
        }
    }

    #[test]
    fn test_disabled_detection() {
        let content = "AKIAIOSFODNN7EXAMPLE";

        let mut config = default_config();
        config.enabled = false;

        let source = SecretSource::Unknown {
            description: "test".to_string(),
        };

        let findings = detect_secrets(content, source, &config);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_specific_secret_types() {
        let content = r#"
            AKIAIOSFODNN7EXAMPLE
            ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
            sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
        "#;

        let mut config = default_config();
        config.secret_types = vec![SecretType::AwsAccessKey]; // Only look for AWS keys

        let source = SecretSource::Unknown {
            description: "test".to_string(),
        };

        let findings = detect_secrets(content, source, &config);

        // Should only find AWS key, not GitHub or Stripe
        for finding in &findings {
            assert!(matches!(finding.secret_type, SecretType::AwsAccessKey));
        }
    }

    #[test]
    fn test_summary_creation() {
        let findings = vec![
            SecretFinding::new(
                SecretType::AwsAccessKey,
                "AKIAIOSFODNN7EXAMPLE",
                SecretSource::Unknown {
                    description: "test".to_string(),
                },
                0.95,
            ),
            SecretFinding::new(
                SecretType::GitHubToken,
                "ghp_test",
                SecretSource::Unknown {
                    description: "test".to_string(),
                },
                0.90,
            ),
        ];

        let summary = summarize_findings(&findings);

        assert_eq!(summary.total_findings, 2);
        assert!(summary.has_critical);
        assert_eq!(
            *summary.by_type.get(&SecretType::AwsAccessKey).unwrap_or(&0),
            1
        );
    }

    #[test]
    fn test_might_contain_secrets() {
        assert!(might_contain_secrets("AKIAIOSFODNN7EXAMPLE"));
        assert!(might_contain_secrets("ghp_xxxxx"));
        assert!(might_contain_secrets("-----BEGIN RSA"));
        assert!(might_contain_secrets("password: secret"));
        assert!(might_contain_secrets("mongodb://user:pass@host"));

        assert!(!might_contain_secrets("Hello, world!"));
        assert!(!might_contain_secrets("Just some normal text"));
    }

    #[test]
    fn test_line_number_detection() {
        let content = "line 1\nline 2\nAKIAIOSFODNN7EXAMPLE\nline 4";

        let source = SecretSource::Unknown {
            description: "test".to_string(),
        };

        let findings = detect_secrets(content, source, &default_config());

        assert!(!findings.is_empty());
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn test_context_extraction() {
        let content = "before AKIAIOSFODNN7EXAMPLE after";

        let source = SecretSource::Unknown {
            description: "test".to_string(),
        };

        let findings = detect_secrets(content, source, &default_config());

        assert!(!findings.is_empty());
        assert!(findings[0].context.contains("[REDACTED]"));
        assert!(findings[0].context.contains("before"));
        assert!(findings[0].context.contains("after"));
        assert!(!findings[0].context.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_deduplication() {
        let content = "AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE";

        let source = SecretSource::Unknown {
            description: "test".to_string(),
        };

        let findings = detect_secrets(content, source, &default_config());

        // Should only find one unique instance
        let aws_findings: Vec<_> = findings
            .iter()
            .filter(|f| matches!(f.secret_type, SecretType::AwsAccessKey))
            .collect();

        assert_eq!(aws_findings.len(), 1);
    }
}
