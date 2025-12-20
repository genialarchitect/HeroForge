//! Secret detection for web application scanning
//!
//! This module provides enhanced secret detection during webapp scans,
//! checking response bodies, JavaScript files, and HTML comments for
//! exposed credentials and API keys.

use anyhow::Result;
use log::{debug, info};
use reqwest::Client;
use url::Url;

use crate::scanner::secret_detection::{
    detect_secrets_in_html_comments, detect_secrets_in_http_response,
    detect_secrets_in_javascript, SecretDetectionConfig,
};
use crate::types::{FindingType, Severity, WebAppFinding};

/// Check pages for exposed secrets
///
/// This function scans the response bodies of discovered pages for:
/// - API keys (AWS, GitHub, Stripe, etc.)
/// - Database connection strings
/// - Private keys
/// - Passwords in configuration
/// - JWT tokens
pub async fn check_secrets(client: &Client, urls: &[Url]) -> Result<Vec<WebAppFinding>> {
    let mut findings = Vec::new();
    let config = SecretDetectionConfig::default();

    info!(
        "Scanning {} pages for exposed secrets",
        urls.len()
    );

    for url in urls {
        debug!("Checking secrets in: {}", url);

        match client.get(url.as_str()).send().await {
            Ok(response) => {
                let content_type = response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let url_str = url.to_string();

                if let Ok(body) = response.text().await {
                    // Check for secrets in response body
                    let secrets = detect_secrets_in_http_response(
                        &body,
                        &url_str,
                        content_type.as_deref(),
                        &config,
                    );

                    for secret in secrets {
                        findings.push(WebAppFinding {
                            finding_type: FindingType::SensitiveInfoDisclosure,
                            url: url_str.clone(),
                            parameter: Some(secret.secret_type.to_string()),
                            evidence: format!(
                                "{} found: {}",
                                secret.secret_type.display_name(),
                                secret.redacted_value
                            ),
                            severity: convert_severity(&secret.severity),
                            remediation: secret.remediation().to_string(),
                        });
                    }

                    // Also check HTML comments
                    let comment_secrets = detect_secrets_in_html_comments(&body, &url_str, &config);

                    for secret in comment_secrets {
                        findings.push(WebAppFinding {
                            finding_type: FindingType::SensitiveInfoDisclosure,
                            url: url_str.clone(),
                            parameter: Some(format!("html_comment:{}", secret.secret_type)),
                            evidence: format!(
                                "{} in HTML comment: {}",
                                secret.secret_type.display_name(),
                                secret.redacted_value
                            ),
                            severity: convert_severity(&secret.severity),
                            remediation: format!(
                                "{}. Additionally, remove HTML comments containing sensitive data before deployment.",
                                secret.remediation()
                            ),
                        });
                    }

                    // Check JavaScript content
                    if is_javascript_content(content_type.as_deref(), &url_str) {
                        let js_secrets = detect_secrets_in_javascript(&body, &url_str, &config);

                        for secret in js_secrets {
                            findings.push(WebAppFinding {
                                finding_type: FindingType::SensitiveInfoDisclosure,
                                url: url_str.clone(),
                                parameter: Some(format!("javascript:{}", secret.secret_type)),
                                evidence: format!(
                                    "{} in JavaScript: {}",
                                    secret.secret_type.display_name(),
                                    secret.redacted_value
                                ),
                                severity: convert_severity(&secret.severity),
                                remediation: format!(
                                    "{}. Credentials should never be embedded in client-side JavaScript.",
                                    secret.remediation()
                                ),
                            });
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Failed to fetch {}: {}", url, e);
            }
        }
    }

    // Deduplicate findings by evidence (redacted value is unique enough)
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.evidence.clone()));

    if !findings.is_empty() {
        info!(
            "Found {} exposed secrets across scanned pages",
            findings.len()
        );
    }

    Ok(findings)
}

/// Check if content is JavaScript based on content-type or URL
fn is_javascript_content(content_type: Option<&str>, url: &str) -> bool {
    if let Some(ct) = content_type {
        if ct.contains("javascript") || ct.contains("ecmascript") {
            return true;
        }
    }

    // Check file extension
    let url_lower = url.to_lowercase();
    url_lower.ends_with(".js") || url_lower.ends_with(".mjs")
}

/// Convert our SecretSeverity to webapp Severity
fn convert_severity(severity: &crate::scanner::secret_detection::SecretSeverity) -> Severity {
    use crate::scanner::secret_detection::SecretSeverity;

    match severity {
        SecretSeverity::Critical => Severity::Critical,
        SecretSeverity::High => Severity::High,
        SecretSeverity::Medium => Severity::Medium,
        SecretSeverity::Low => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_javascript_content() {
        assert!(is_javascript_content(Some("application/javascript"), "https://example.com/app.js"));
        assert!(is_javascript_content(Some("text/javascript"), "https://example.com/file"));
        assert!(is_javascript_content(None, "https://example.com/app.js"));
        assert!(is_javascript_content(None, "https://example.com/module.mjs"));
        assert!(!is_javascript_content(Some("text/html"), "https://example.com/page.html"));
        assert!(!is_javascript_content(None, "https://example.com/page.html"));
    }

    #[test]
    fn test_convert_severity() {
        use crate::scanner::secret_detection::SecretSeverity;

        assert!(matches!(convert_severity(&SecretSeverity::Critical), Severity::Critical));
        assert!(matches!(convert_severity(&SecretSeverity::High), Severity::High));
        assert!(matches!(convert_severity(&SecretSeverity::Medium), Severity::Medium));
        assert!(matches!(convert_severity(&SecretSeverity::Low), Severity::Low));
    }
}
