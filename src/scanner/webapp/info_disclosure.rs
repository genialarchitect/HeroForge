use anyhow::Result;
use log::debug;
use regex::Regex;
use reqwest::Client;
use url::Url;

use crate::types::{WebAppFinding, FindingType, Severity};

/// Patterns for detecting sensitive information
struct InfoPattern {
    name: &'static str,
    regex: Regex,
    severity: Severity,
}

impl InfoPattern {
    fn new(name: &'static str, pattern: &str, severity: Severity) -> Option<Self> {
        Regex::new(pattern).ok().map(|regex| InfoPattern {
            name,
            regex,
            severity,
        })
    }
}

/// Get patterns for sensitive information detection
fn get_info_patterns() -> Vec<InfoPattern> {
    let mut patterns = Vec::new();

    // Email addresses
    if let Some(p) = InfoPattern::new(
        "Email Address",
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        Severity::Low,
    ) {
        patterns.push(p);
    }

    // IP addresses (private ranges)
    if let Some(p) = InfoPattern::new(
        "Private IP Address",
        r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
        Severity::Low,
    ) {
        patterns.push(p);
    }

    // Stack traces (various languages)
    if let Some(p) = InfoPattern::new(
        "Stack Trace",
        r"(at\s+[\w\.<>]+\([\w\.]+:\d+\)|Traceback \(most recent call last\)|Exception in thread|Fatal error:)",
        Severity::Medium,
    ) {
        patterns.push(p);
    }

    // Database connection strings
    if let Some(p) = InfoPattern::new(
        "Database Connection String",
        r"(mongodb://|mysql://|postgresql://|Server=.*Database=|Data Source=)",
        Severity::High,
    ) {
        patterns.push(p);
    }

    // API keys and tokens (generic patterns)
    if let Some(p) = InfoPattern::new(
        "Potential API Key",
        r#"(?i)(api[_-]?key|apikey|api[_-]?token|access[_-]?token|auth[_-]?token)[\s]*[:=][\s]*['\"]?([a-zA-Z0-9_-]{20,})['\"]?"#,
        Severity::Critical,
    ) {
        patterns.push(p);
    }

    // AWS keys
    if let Some(p) = InfoPattern::new(
        "AWS Access Key",
        r"AKIA[0-9A-Z]{16}",
        Severity::Critical,
    ) {
        patterns.push(p);
    }

    // Private keys
    if let Some(p) = InfoPattern::new(
        "Private Key",
        r"-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----",
        Severity::Critical,
    ) {
        patterns.push(p);
    }

    // Password in code/comments
    if let Some(p) = InfoPattern::new(
        "Hardcoded Password",
        r#"(?i)(password|passwd|pwd)[\s]*[:=][\s]*['\"]([^'\"]{4,})['\"]"#,
        Severity::High,
    ) {
        patterns.push(p);
    }

    // JWT tokens
    if let Some(p) = InfoPattern::new(
        "JWT Token",
        r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
        Severity::Medium,
    ) {
        patterns.push(p);
    }

    // Common sensitive file paths
    if let Some(p) = InfoPattern::new(
        "Sensitive File Path",
        r"(/etc/passwd|/etc/shadow|web\.config|\.env|\.git/config|id_rsa)",
        Severity::Medium,
    ) {
        patterns.push(p);
    }

    patterns
}

/// Check for information disclosure in responses
pub async fn check_info_disclosure(
    client: &Client,
    urls: &[Url],
) -> Result<Vec<WebAppFinding>> {
    let mut findings = Vec::new();
    let patterns = get_info_patterns();

    for url in urls {
        debug!("Checking information disclosure: {}", url);

        match client.get(url.as_str()).send().await {
            Ok(response) => {
                let response_text = response.text().await.unwrap_or_default();

                // Check response against all patterns
                for pattern in &patterns {
                    if let Some(captures) = pattern.regex.captures(&response_text) {
                        let matched_text = captures.get(0).map(|m| m.as_str()).unwrap_or("");

                        // Limit evidence length for readability
                        let evidence = if matched_text.len() > 100 {
                            format!("{}...", &matched_text[..100])
                        } else {
                            matched_text.to_string()
                        };

                        findings.push(WebAppFinding {
                            finding_type: FindingType::SensitiveInfoDisclosure,
                            url: url.to_string(),
                            parameter: None,
                            evidence: format!("{} found: {}", pattern.name, evidence),
                            severity: pattern.severity.clone(),
                            remediation: get_remediation(pattern.name),
                        });
                    }
                }

                // Check for common sensitive paths (directory listing)
                check_directory_listing(&mut findings, url, &response_text);

                // Check for debug information
                check_debug_info(&mut findings, url, &response_text);

                // Check for comments with sensitive info
                check_html_comments(&mut findings, url, &response_text);
            }
            Err(e) => {
                debug!("Failed to fetch {}: {}", url, e);
            }
        }
    }

    Ok(findings)
}

/// Check for directory listing vulnerabilities
fn check_directory_listing(findings: &mut Vec<WebAppFinding>, url: &Url, response: &str) {
    // Common indicators of directory listings
    let directory_indicators = [
        "Index of /",
        "Directory listing for",
        "Parent Directory",
        "<title>Index of",
    ];

    for indicator in &directory_indicators {
        if response.contains(indicator) {
            findings.push(WebAppFinding {
                finding_type: FindingType::DirectoryListing,
                url: url.to_string(),
                parameter: None,
                evidence: format!("Directory listing detected: {}", indicator),
                severity: Severity::Medium,
                remediation: "Disable directory listing on the web server. Configure the server to show a custom error page or redirect when a directory is accessed without an index file.".to_string(),
            });
            break;
        }
    }
}

/// Check for debug information in responses
fn check_debug_info(findings: &mut Vec<WebAppFinding>, url: &Url, response: &str) {
    let debug_indicators = [
        "DEBUG = True",
        "debug mode",
        "development mode",
        "SQLSTATE[",
        "Warning: ",
        "Notice: ",
        "Deprecated: ",
    ];

    for indicator in &debug_indicators {
        if response.contains(indicator) {
            findings.push(WebAppFinding {
                finding_type: FindingType::SensitiveInfoDisclosure,
                url: url.to_string(),
                parameter: None,
                evidence: format!("Debug information exposed: {}", indicator),
                severity: Severity::Medium,
                remediation: "Disable debug mode in production. Configure the application to show generic error messages to users while logging detailed errors server-side.".to_string(),
            });
            break;
        }
    }
}

/// Check HTML comments for sensitive information
fn check_html_comments(findings: &mut Vec<WebAppFinding>, url: &Url, response: &str) {
    if let Ok(comment_regex) = Regex::new(r"<!--(.*?)-->") {
        for captures in comment_regex.captures_iter(response) {
            if let Some(comment) = captures.get(1) {
                let comment_text = comment.as_str();

                // Check if comment contains potentially sensitive keywords
                let sensitive_keywords = [
                    "password", "secret", "key", "token", "api", "admin",
                    "todo", "fixme", "hack", "temporary", "debug",
                ];

                for keyword in &sensitive_keywords {
                    if comment_text.to_lowercase().contains(keyword) {
                        let evidence = if comment_text.len() > 100 {
                            format!("{}...", &comment_text[..100])
                        } else {
                            comment_text.to_string()
                        };

                        findings.push(WebAppFinding {
                            finding_type: FindingType::SensitiveInfoDisclosure,
                            url: url.to_string(),
                            parameter: None,
                            evidence: format!("Sensitive information in HTML comment: {}", evidence.trim()),
                            severity: Severity::Low,
                            remediation: "Remove HTML comments containing sensitive information from production code. Use build tools to strip comments before deployment.".to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }
}

/// Get remediation advice for different types of information disclosure
fn get_remediation(pattern_name: &str) -> String {
    match pattern_name {
        "Email Address" => "Avoid exposing email addresses in HTML. Use contact forms or obfuscation techniques to prevent harvesting by spammers.".to_string(),
        "Private IP Address" => "Remove internal IP addresses from public responses. These can reveal information about internal network topology.".to_string(),
        "Stack Trace" => "Disable detailed error messages in production. Show generic error pages to users while logging details server-side.".to_string(),
        "Database Connection String" => "CRITICAL: Remove database connection strings from code immediately. Use environment variables and secure configuration management.".to_string(),
        "Potential API Key" | "AWS Access Key" => "CRITICAL: Revoke exposed API keys immediately. Use environment variables and secrets management solutions. Never commit credentials to code.".to_string(),
        "Private Key" => "CRITICAL: Revoke exposed private key immediately and generate new key pair. Never store private keys in application code or public repositories.".to_string(),
        "Hardcoded Password" => "Remove hardcoded passwords. Use secure credential storage, environment variables, or secrets management systems.".to_string(),
        "JWT Token" => "Ensure JWT tokens are not logged or exposed in URLs. Use short expiration times and implement token refresh mechanisms.".to_string(),
        "Sensitive File Path" => "Restrict access to sensitive files. Ensure proper file permissions and web server configuration to prevent unauthorized access.".to_string(),
        _ => "Remove or obfuscate sensitive information from public responses.".to_string(),
    }
}
