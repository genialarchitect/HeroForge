//! Comprehensive input validation

use anyhow::{anyhow, Result};
use regex::Regex;
use std::net::IpAddr;

/// Dangerous URL schemes that could lead to SSRF or other attacks
const DANGEROUS_SCHEMES: &[&str] = &[
    "file", "gopher", "dict", "ldap", "ldaps", "ftp", "sftp", "tftp",
];

/// Private IP address ranges for SSRF detection
const PRIVATE_IP_PATTERNS: &[&str] = &[
    r"^10\.",                               // 10.0.0.0/8
    r"^172\.(1[6-9]|2[0-9]|3[01])\.",      // 172.16.0.0/12
    r"^192\.168\.",                         // 192.168.0.0/16
    r"^127\.",                              // 127.0.0.0/8 (localhost)
    r"^0\.",                                // 0.0.0.0/8
    r"^169\.254\.",                         // Link-local
    r"^::1$",                               // IPv6 localhost
    r"^fc00:",                              // IPv6 unique local
    r"^fe80:",                              // IPv6 link-local
];

/// SQL injection patterns
const SQL_INJECTION_PATTERNS: &[&str] = &[
    r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\b)",
    r"(?i)(\bOR\b\s+\d+\s*=\s*\d+)",        // OR 1=1 style
    r"(?i)(\bAND\b\s+\d+\s*=\s*\d+)",       // AND 1=1 style
    r"--\s*$",                               // SQL comment
    r";\s*--",                               // Semicolon followed by comment
    r"'\s*(OR|AND)\s*'",                    // Quote-based injection
    r"(?i)(EXEC|EXECUTE)\s*\(",             // Stored procedure execution
    r"(?i)xp_\w+",                           // Extended stored procedures
    r"(?i)WAITFOR\s+DELAY",                 // Time-based injection
    r"(?i)BENCHMARK\s*\(",                  // MySQL time-based injection
    r"(?i)SLEEP\s*\(",                      // MySQL sleep function
];

/// HTML tags that are always dangerous and should be removed
const DANGEROUS_HTML_TAGS: &[&str] = &[
    "script", "iframe", "object", "embed", "form", "input", "button",
    "link", "meta", "style", "base", "svg", "math",
];

/// Dangerous HTML attributes
const DANGEROUS_HTML_ATTRS: &[&str] = &[
    "onclick", "onload", "onerror", "onmouseover", "onmouseout", "onkeydown",
    "onkeyup", "onkeypress", "onfocus", "onblur", "onchange", "onsubmit",
    "onmouseenter", "onmouseleave", "ondrag", "ondrop", "onscroll",
    "javascript:", "vbscript:", "data:",
];

pub struct InputValidator {
    email_regex: Regex,
    url_regex: Regex,
    private_ip_patterns: Vec<Regex>,
    sql_patterns: Vec<Regex>,
    html_tag_regex: Regex,
    html_attr_regex: Regex,
}

impl InputValidator {
    pub fn new() -> Self {
        // Compile regex patterns for email validation (RFC 5322 compliant)
        let email_regex = Regex::new(
            r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        ).expect("Invalid email regex");

        // URL regex pattern
        let url_regex = Regex::new(
            r"^(https?|ftp)://[^\s/$.?#].[^\s]*$"
        ).expect("Invalid URL regex");

        // Compile private IP patterns
        let private_ip_patterns: Vec<Regex> = PRIVATE_IP_PATTERNS
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        // Compile SQL injection patterns
        let sql_patterns: Vec<Regex> = SQL_INJECTION_PATTERNS
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        // HTML tag regex for removal
        let html_tag_regex = Regex::new(
            &format!(r"(?i)<\s*/?({})(?:\s[^>]*)?>", DANGEROUS_HTML_TAGS.join("|"))
        ).expect("Invalid HTML tag regex");

        // HTML attribute regex for dangerous attributes
        let html_attr_regex = Regex::new(
            &format!(r#"(?i)\s({})\s*=\s*["'][^"']*["']"#, DANGEROUS_HTML_ATTRS.join("|"))
        ).expect("Invalid HTML attr regex");

        Self {
            email_regex,
            url_regex,
            private_ip_patterns,
            sql_patterns,
            html_tag_regex,
            html_attr_regex,
        }
    }

    /// Validate email format according to RFC 5322
    pub fn validate_email(&self, email: &str) -> Result<()> {
        // Check length limits
        if email.is_empty() {
            return Err(anyhow!("Email address cannot be empty"));
        }
        if email.len() > 254 {
            return Err(anyhow!("Email address exceeds maximum length of 254 characters"));
        }

        // Check local part length (before @)
        if let Some(at_pos) = email.find('@') {
            let local_part = &email[..at_pos];
            if local_part.len() > 64 {
                return Err(anyhow!("Email local part exceeds maximum length of 64 characters"));
            }
            if local_part.is_empty() {
                return Err(anyhow!("Email local part cannot be empty"));
            }
        } else {
            return Err(anyhow!("Email address must contain an @ symbol"));
        }

        // Validate with regex
        if !self.email_regex.is_match(email) {
            return Err(anyhow!("Invalid email format"));
        }

        // Check for consecutive dots
        if email.contains("..") {
            return Err(anyhow!("Email address cannot contain consecutive dots"));
        }

        Ok(())
    }

    /// Validate URL format and check for SSRF vulnerabilities
    pub fn validate_url(&self, url: &str) -> Result<()> {
        // Check for empty URL
        if url.is_empty() {
            return Err(anyhow!("URL cannot be empty"));
        }

        // Parse the URL
        let parsed = url::Url::parse(url)
            .map_err(|e| anyhow!("Invalid URL format: {}", e))?;

        // Check scheme
        let scheme = parsed.scheme().to_lowercase();
        if DANGEROUS_SCHEMES.contains(&scheme.as_str()) {
            return Err(anyhow!("URL scheme '{}' is not allowed", scheme));
        }

        // Only allow http and https
        if scheme != "http" && scheme != "https" {
            return Err(anyhow!("Only HTTP and HTTPS URLs are allowed"));
        }

        // Check for SSRF by examining the host
        if let Some(host) = parsed.host_str() {
            // Check for private IP addresses
            if let Ok(ip) = host.parse::<IpAddr>() {
                let ip_str = ip.to_string();
                for pattern in &self.private_ip_patterns {
                    if pattern.is_match(&ip_str) {
                        return Err(anyhow!("URLs pointing to private/internal IP addresses are not allowed"));
                    }
                }
            }

            // Check for localhost variants
            let host_lower = host.to_lowercase();
            if host_lower == "localhost" || host_lower.ends_with(".localhost") {
                return Err(anyhow!("URLs pointing to localhost are not allowed"));
            }

            // Check for internal DNS names
            if host_lower.ends_with(".local") || host_lower.ends_with(".internal") {
                return Err(anyhow!("URLs pointing to internal DNS names are not allowed"));
            }

            // Check for IP in decimal form (e.g., 2130706433 = 127.0.0.1)
            if host.chars().all(|c| c.is_ascii_digit()) {
                return Err(anyhow!("Decimal IP addresses are not allowed in URLs"));
            }

            // Check for octal IP notation (e.g., 0177.0.0.1)
            if host.contains('0') && host.split('.').any(|part| part.starts_with('0') && part.len() > 1) {
                return Err(anyhow!("Octal IP notation is not allowed in URLs"));
            }
        } else {
            return Err(anyhow!("URL must have a valid host"));
        }

        // Check for data URIs in the path
        if parsed.path().to_lowercase().starts_with("/data:") {
            return Err(anyhow!("Data URIs are not allowed in URL paths"));
        }

        Ok(())
    }

    /// Sanitize HTML to prevent XSS attacks
    pub fn sanitize_html(&self, html: &str) -> String {
        let mut result = html.to_string();

        // Remove dangerous HTML tags
        result = self.html_tag_regex.replace_all(&result, "").to_string();

        // Remove dangerous attributes from remaining tags
        result = self.html_attr_regex.replace_all(&result, "").to_string();

        // Encode remaining potentially dangerous characters
        result = result
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;");

        // Remove null bytes
        result = result.replace('\0', "");

        // Remove any javascript: or vbscript: protocol handlers that might be obfuscated
        let js_pattern = Regex::new(r"(?i)j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:").unwrap();
        result = js_pattern.replace_all(&result, "").to_string();

        let vbs_pattern = Regex::new(r"(?i)v\s*b\s*s\s*c\s*r\s*i\s*p\s*t\s*:").unwrap();
        result = vbs_pattern.replace_all(&result, "").to_string();

        result
    }

    /// Check for SQL injection patterns
    pub fn validate_sql_input(&self, input: &str) -> Result<()> {
        // Check for empty input
        if input.is_empty() {
            return Ok(());
        }

        // Check against SQL injection patterns
        for pattern in &self.sql_patterns {
            if pattern.is_match(input) {
                return Err(anyhow!("Potential SQL injection detected"));
            }
        }

        // Check for null bytes (can be used to bypass validation)
        if input.contains('\0') {
            return Err(anyhow!("Null bytes are not allowed in input"));
        }

        // Check for excessive escaping that might indicate an attack
        let quote_count = input.chars().filter(|&c| c == '\'' || c == '"').count();
        if quote_count > 10 && quote_count as f64 / input.len() as f64 > 0.1 {
            return Err(anyhow!("Suspicious quote usage pattern detected"));
        }

        Ok(())
    }

    /// Validate and sanitize a file path to prevent path traversal
    pub fn validate_path(&self, path: &str) -> Result<()> {
        // Check for path traversal attempts
        if path.contains("..") {
            return Err(anyhow!("Path traversal sequences are not allowed"));
        }

        // Check for null bytes
        if path.contains('\0') {
            return Err(anyhow!("Null bytes are not allowed in paths"));
        }

        // Check for absolute paths when not expected
        if path.starts_with('/') || path.starts_with('\\') {
            return Err(anyhow!("Absolute paths are not allowed"));
        }

        // Check for Windows-style paths with drive letters
        if path.len() >= 2 && path.chars().nth(1) == Some(':') {
            return Err(anyhow!("Windows drive letters are not allowed"));
        }

        Ok(())
    }

    /// Validate command-line input to prevent command injection
    pub fn validate_command_input(&self, input: &str) -> Result<()> {
        // Check for command injection characters
        let dangerous_chars = ['|', ';', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '\n', '\r'];

        for ch in dangerous_chars {
            if input.contains(ch) {
                return Err(anyhow!("Character '{}' is not allowed in command input", ch));
            }
        }

        // Check for null bytes
        if input.contains('\0') {
            return Err(anyhow!("Null bytes are not allowed"));
        }

        Ok(())
    }
}

impl Default for InputValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        let validator = InputValidator::new();
        assert!(validator.validate_email("test@example.com").is_ok());
        assert!(validator.validate_email("user.name+tag@example.co.uk").is_ok());
        assert!(validator.validate_email("user123@subdomain.example.org").is_ok());
    }

    #[test]
    fn test_invalid_emails() {
        let validator = InputValidator::new();
        assert!(validator.validate_email("").is_err());
        assert!(validator.validate_email("notanemail").is_err());
        assert!(validator.validate_email("@example.com").is_err());
        assert!(validator.validate_email("test@").is_err());
        assert!(validator.validate_email("test..user@example.com").is_err());
    }

    #[test]
    fn test_valid_urls() {
        let validator = InputValidator::new();
        assert!(validator.validate_url("https://example.com").is_ok());
        assert!(validator.validate_url("http://example.com/path").is_ok());
        assert!(validator.validate_url("https://sub.example.com:8080/path?query=1").is_ok());
    }

    #[test]
    fn test_ssrf_blocked() {
        let validator = InputValidator::new();
        assert!(validator.validate_url("http://localhost/admin").is_err());
        assert!(validator.validate_url("http://127.0.0.1/admin").is_err());
        assert!(validator.validate_url("http://192.168.1.1/").is_err());
        assert!(validator.validate_url("http://10.0.0.1/").is_err());
        assert!(validator.validate_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_html_sanitization() {
        let validator = InputValidator::new();

        let result = validator.sanitize_html("<script>alert('xss')</script>");
        assert!(!result.contains("<script>"));
        assert!(!result.contains("alert"));

        let result = validator.sanitize_html("<img src=x onerror=alert(1)>");
        assert!(!result.to_lowercase().contains("onerror"));
    }

    #[test]
    fn test_sql_injection_detection() {
        let validator = InputValidator::new();
        assert!(validator.validate_sql_input("normal input").is_ok());
        assert!(validator.validate_sql_input("Robert'); DROP TABLE users;--").is_err());
        assert!(validator.validate_sql_input("1 OR 1=1").is_err());
        assert!(validator.validate_sql_input("admin'--").is_err());
    }

    #[test]
    fn test_path_traversal() {
        let validator = InputValidator::new();
        assert!(validator.validate_path("normal/path/file.txt").is_ok());
        assert!(validator.validate_path("../../../etc/passwd").is_err());
        assert!(validator.validate_path("/etc/passwd").is_err());
    }
}
