use anyhow::Result;
use log::debug;
use reqwest::Client;
use url::Url;

use crate::types::{WebAppFinding, FindingType, Severity};

/// Check for missing or insecure security headers
pub async fn check_security_headers(client: &Client, url: &Url) -> Result<Vec<WebAppFinding>> {
    let mut findings = Vec::new();

    debug!("Checking security headers for: {}", url);

    let response = client.get(url.as_str()).send().await?;
    let headers = response.headers();

    // Check for Content-Security-Policy
    if !headers.contains_key("content-security-policy") {
        findings.push(WebAppFinding {
            finding_type: FindingType::MissingSecurityHeader,
            url: url.to_string(),
            parameter: None,
            evidence: "Missing Content-Security-Policy header".to_string(),
            severity: Severity::Medium,
            remediation: "Implement a Content-Security-Policy header to prevent XSS attacks. Example: Content-Security-Policy: default-src 'self'; script-src 'self'".to_string(),
        });
    } else if let Some(csp) = headers.get("content-security-policy") {
        let csp_value = csp.to_str().unwrap_or("");
        // Check for unsafe CSP directives
        if csp_value.contains("'unsafe-inline'") || csp_value.contains("'unsafe-eval'") {
            findings.push(WebAppFinding {
                finding_type: FindingType::InsecureHeader,
                url: url.to_string(),
                parameter: Some("Content-Security-Policy".to_string()),
                evidence: format!("CSP contains unsafe directives: {}", csp_value),
                severity: Severity::Medium,
                remediation: "Remove 'unsafe-inline' and 'unsafe-eval' from CSP directives. Use nonces or hashes for inline scripts.".to_string(),
            });
        }
    }

    // Check for X-Frame-Options
    if !headers.contains_key("x-frame-options") {
        findings.push(WebAppFinding {
            finding_type: FindingType::MissingSecurityHeader,
            url: url.to_string(),
            parameter: None,
            evidence: "Missing X-Frame-Options header".to_string(),
            severity: Severity::Medium,
            remediation: "Add X-Frame-Options header to prevent clickjacking. Recommended: X-Frame-Options: DENY or SAMEORIGIN".to_string(),
        });
    }

    // Check for Strict-Transport-Security (HSTS)
    if url.scheme() == "https" && !headers.contains_key("strict-transport-security") {
        findings.push(WebAppFinding {
            finding_type: FindingType::MissingSecurityHeader,
            url: url.to_string(),
            parameter: None,
            evidence: "Missing Strict-Transport-Security header on HTTPS site".to_string(),
            severity: Severity::Medium,
            remediation: "Add HSTS header to enforce HTTPS. Example: Strict-Transport-Security: max-age=31536000; includeSubDomains".to_string(),
        });
    } else if let Some(hsts) = headers.get("strict-transport-security") {
        let hsts_value = hsts.to_str().unwrap_or("");
        // Check for short max-age
        if let Some(max_age_str) = extract_max_age(hsts_value) {
            if let Ok(max_age) = max_age_str.parse::<u64>() {
                if max_age < 31536000 {
                    // Less than 1 year
                    findings.push(WebAppFinding {
                        finding_type: FindingType::InsecureHeader,
                        url: url.to_string(),
                        parameter: Some("Strict-Transport-Security".to_string()),
                        evidence: format!("HSTS max-age is too short: {}", max_age),
                        severity: Severity::Low,
                        remediation: "Increase HSTS max-age to at least 31536000 (1 year)".to_string(),
                    });
                }
            }
        }
    }

    // Check for X-Content-Type-Options
    if !headers.contains_key("x-content-type-options") {
        findings.push(WebAppFinding {
            finding_type: FindingType::MissingSecurityHeader,
            url: url.to_string(),
            parameter: None,
            evidence: "Missing X-Content-Type-Options header".to_string(),
            severity: Severity::Low,
            remediation: "Add X-Content-Type-Options: nosniff to prevent MIME type sniffing".to_string(),
        });
    }

    // Check for X-XSS-Protection
    if let Some(xss_protection) = headers.get("x-xss-protection") {
        let value = xss_protection.to_str().unwrap_or("");
        if value == "0" {
            findings.push(WebAppFinding {
                finding_type: FindingType::InsecureHeader,
                url: url.to_string(),
                parameter: Some("X-XSS-Protection".to_string()),
                evidence: "X-XSS-Protection is disabled (set to 0)".to_string(),
                severity: Severity::Low,
                remediation: "Enable XSS protection: X-XSS-Protection: 1; mode=block".to_string(),
            });
        }
    }

    // Check for Referrer-Policy
    if !headers.contains_key("referrer-policy") {
        findings.push(WebAppFinding {
            finding_type: FindingType::MissingSecurityHeader,
            url: url.to_string(),
            parameter: None,
            evidence: "Missing Referrer-Policy header".to_string(),
            severity: Severity::Low,
            remediation: "Add Referrer-Policy header to control referrer information. Example: Referrer-Policy: strict-origin-when-cross-origin".to_string(),
        });
    }

    // Check for Permissions-Policy (formerly Feature-Policy)
    if !headers.contains_key("permissions-policy") && !headers.contains_key("feature-policy") {
        findings.push(WebAppFinding {
            finding_type: FindingType::MissingSecurityHeader,
            url: url.to_string(),
            parameter: None,
            evidence: "Missing Permissions-Policy header".to_string(),
            severity: Severity::Low,
            remediation: "Add Permissions-Policy header to control browser features. Example: Permissions-Policy: geolocation=(), microphone=()".to_string(),
        });
    }

    // Check for Server header disclosure
    if let Some(server) = headers.get("server") {
        let server_value = server.to_str().unwrap_or("");
        if !server_value.is_empty() && server_value != "HeroForge" {
            findings.push(WebAppFinding {
                finding_type: FindingType::SensitiveInfoDisclosure,
                url: url.to_string(),
                parameter: Some("Server".to_string()),
                evidence: format!("Server header discloses version: {}", server_value),
                severity: Severity::Low,
                remediation: "Remove or obfuscate Server header to avoid disclosing server version information".to_string(),
            });
        }
    }

    // Check for X-Powered-By header disclosure
    if let Some(powered_by) = headers.get("x-powered-by") {
        let value = powered_by.to_str().unwrap_or("");
        findings.push(WebAppFinding {
            finding_type: FindingType::SensitiveInfoDisclosure,
            url: url.to_string(),
            parameter: Some("X-Powered-By".to_string()),
            evidence: format!("X-Powered-By header discloses technology: {}", value),
            severity: Severity::Low,
            remediation: "Remove X-Powered-By header to avoid technology disclosure".to_string(),
        });
    }

    Ok(findings)
}

/// Extract max-age value from HSTS header
fn extract_max_age(hsts_value: &str) -> Option<String> {
    for directive in hsts_value.split(';') {
        let directive = directive.trim();
        if directive.to_lowercase().starts_with("max-age=") {
            return directive.split('=').nth(1).map(|s| s.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_max_age_basic() {
        assert_eq!(
            extract_max_age("max-age=31536000"),
            Some("31536000".to_string())
        );
    }

    #[test]
    fn test_extract_max_age_with_directives() {
        assert_eq!(
            extract_max_age("max-age=31536000; includeSubDomains; preload"),
            Some("31536000".to_string())
        );
    }

    #[test]
    fn test_extract_max_age_case_insensitive() {
        assert_eq!(
            extract_max_age("Max-Age=15768000"),
            Some("15768000".to_string())
        );
    }

    #[test]
    fn test_extract_max_age_with_directive_spaces() {
        // Spaces around semicolon separators are handled, but = must be adjacent
        assert_eq!(
            extract_max_age("max-age=31536000 ; includeSubDomains"),
            Some("31536000".to_string())
        );
    }

    #[test]
    fn test_extract_max_age_missing() {
        assert_eq!(extract_max_age("includeSubDomains"), None);
    }
}
