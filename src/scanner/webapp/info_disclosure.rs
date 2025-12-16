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

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== InfoPattern Tests ====================

    #[test]
    fn test_info_pattern_new_valid() {
        let pattern = InfoPattern::new("Test", r"\d+", Severity::Low);
        assert!(pattern.is_some());
    }

    #[test]
    fn test_info_pattern_new_invalid_regex() {
        let pattern = InfoPattern::new("Test", r"[invalid", Severity::Low);
        assert!(pattern.is_none());
    }

    #[test]
    fn test_get_info_patterns_not_empty() {
        let patterns = get_info_patterns();
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_get_info_patterns_has_critical_patterns() {
        let patterns = get_info_patterns();
        let critical_count = patterns.iter()
            .filter(|p| matches!(p.severity, Severity::Critical))
            .count();
        assert!(critical_count > 0, "Should have critical severity patterns");
    }

    // ==================== Email Detection Tests ====================

    #[test]
    fn test_email_pattern_matches() {
        let patterns = get_info_patterns();
        let email_pattern = patterns.iter().find(|p| p.name == "Email Address").unwrap();

        assert!(email_pattern.regex.is_match("contact@example.com"));
        assert!(email_pattern.regex.is_match("user.name+tag@subdomain.example.co.uk"));
        assert!(email_pattern.regex.is_match("test123@test.org"));
    }

    #[test]
    fn test_email_pattern_no_false_positives() {
        let patterns = get_info_patterns();
        let email_pattern = patterns.iter().find(|p| p.name == "Email Address").unwrap();

        assert!(!email_pattern.regex.is_match("not an email"));
        assert!(!email_pattern.regex.is_match("@example.com"));
        assert!(!email_pattern.regex.is_match("test@"));
    }

    // ==================== Private IP Detection Tests ====================

    #[test]
    fn test_private_ip_pattern_class_a() {
        let patterns = get_info_patterns();
        let ip_pattern = patterns.iter().find(|p| p.name == "Private IP Address").unwrap();

        // 10.0.0.0/8
        assert!(ip_pattern.regex.is_match("10.0.0.1"));
        assert!(ip_pattern.regex.is_match("10.255.255.255"));
        assert!(ip_pattern.regex.is_match("Server: 10.1.2.3"));
    }

    #[test]
    fn test_private_ip_pattern_class_b() {
        let patterns = get_info_patterns();
        let ip_pattern = patterns.iter().find(|p| p.name == "Private IP Address").unwrap();

        // 172.16.0.0/12
        assert!(ip_pattern.regex.is_match("172.16.0.1"));
        assert!(ip_pattern.regex.is_match("172.31.255.255"));
    }

    #[test]
    fn test_private_ip_pattern_class_c() {
        let patterns = get_info_patterns();
        let ip_pattern = patterns.iter().find(|p| p.name == "Private IP Address").unwrap();

        // 192.168.0.0/16
        assert!(ip_pattern.regex.is_match("192.168.0.1"));
        assert!(ip_pattern.regex.is_match("192.168.255.255"));
    }

    #[test]
    fn test_private_ip_no_public_ips() {
        let patterns = get_info_patterns();
        let ip_pattern = patterns.iter().find(|p| p.name == "Private IP Address").unwrap();

        // Public IPs should not match
        assert!(!ip_pattern.regex.is_match("8.8.8.8"));
        assert!(!ip_pattern.regex.is_match("1.1.1.1"));
        assert!(!ip_pattern.regex.is_match("203.0.113.1"));
    }

    // ==================== Stack Trace Detection Tests ====================

    #[test]
    fn test_stack_trace_java() {
        let patterns = get_info_patterns();
        let trace_pattern = patterns.iter().find(|p| p.name == "Stack Trace").unwrap();

        let java_trace = "at com.example.MyClass.method(MyClass.java:42)";
        assert!(trace_pattern.regex.is_match(java_trace));
    }

    #[test]
    fn test_stack_trace_python() {
        let patterns = get_info_patterns();
        let trace_pattern = patterns.iter().find(|p| p.name == "Stack Trace").unwrap();

        let python_trace = "Traceback (most recent call last)";
        assert!(trace_pattern.regex.is_match(python_trace));
    }

    #[test]
    fn test_stack_trace_php() {
        let patterns = get_info_patterns();
        let trace_pattern = patterns.iter().find(|p| p.name == "Stack Trace").unwrap();

        let php_trace = "Fatal error: Uncaught Exception in /var/www/html/index.php:10";
        assert!(trace_pattern.regex.is_match(php_trace));
    }

    // ==================== Database Connection String Tests ====================

    #[test]
    fn test_db_connection_mongodb() {
        let patterns = get_info_patterns();
        let db_pattern = patterns.iter().find(|p| p.name == "Database Connection String").unwrap();

        assert!(db_pattern.regex.is_match("mongodb://user:pass@localhost:27017/db"));
    }

    #[test]
    fn test_db_connection_mysql() {
        let patterns = get_info_patterns();
        let db_pattern = patterns.iter().find(|p| p.name == "Database Connection String").unwrap();

        assert!(db_pattern.regex.is_match("mysql://root:password@localhost/mydb"));
    }

    #[test]
    fn test_db_connection_postgresql() {
        let patterns = get_info_patterns();
        let db_pattern = patterns.iter().find(|p| p.name == "Database Connection String").unwrap();

        assert!(db_pattern.regex.is_match("postgresql://user:pass@host:5432/db"));
    }

    #[test]
    fn test_db_connection_mssql() {
        let patterns = get_info_patterns();
        let db_pattern = patterns.iter().find(|p| p.name == "Database Connection String").unwrap();

        assert!(db_pattern.regex.is_match("Server=localhost;Database=mydb;User Id=sa;Password=pass;"));
        assert!(db_pattern.regex.is_match("Data Source=.\\SQLEXPRESS;Initial Catalog=TestDB;"));
    }

    // ==================== API Key Detection Tests ====================

    #[test]
    fn test_api_key_pattern_various_formats() {
        let patterns = get_info_patterns();
        let api_pattern = patterns.iter().find(|p| p.name == "Potential API Key").unwrap();

        assert!(api_pattern.regex.is_match("api_key: 'abc123def456ghi789jkl012mno'"));
        assert!(api_pattern.regex.is_match("apikey=\"abcdefghijklmnopqrstuvwxyz\""));
        assert!(api_pattern.regex.is_match("access_token = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4'"));
        assert!(api_pattern.regex.is_match("auth-token: abc123456789012345678901"));
    }

    #[test]
    fn test_aws_access_key_pattern() {
        let patterns = get_info_patterns();
        let aws_pattern = patterns.iter().find(|p| p.name == "AWS Access Key").unwrap();

        // AWS access keys start with AKIA and are 20 characters
        assert!(aws_pattern.regex.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(aws_pattern.regex.is_match("config: AKIAI44QH8DHBEXAMPLE"));
    }

    #[test]
    fn test_aws_access_key_no_false_positives() {
        let patterns = get_info_patterns();
        let aws_pattern = patterns.iter().find(|p| p.name == "AWS Access Key").unwrap();

        // Should not match non-AWS keys
        assert!(!aws_pattern.regex.is_match("ABCDEFGHIJKLMNOPQRST"));
        assert!(!aws_pattern.regex.is_match("regular_text_here"));
    }

    // ==================== Private Key Detection Tests ====================

    #[test]
    fn test_private_key_rsa() {
        let patterns = get_info_patterns();
        let pk_pattern = patterns.iter().find(|p| p.name == "Private Key").unwrap();

        assert!(pk_pattern.regex.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(pk_pattern.regex.is_match("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_private_key_dsa() {
        let patterns = get_info_patterns();
        let pk_pattern = patterns.iter().find(|p| p.name == "Private Key").unwrap();

        assert!(pk_pattern.regex.is_match("-----BEGIN DSA PRIVATE KEY-----"));
    }

    #[test]
    fn test_private_key_ec() {
        let patterns = get_info_patterns();
        let pk_pattern = patterns.iter().find(|p| p.name == "Private Key").unwrap();

        assert!(pk_pattern.regex.is_match("-----BEGIN EC PRIVATE KEY-----"));
    }

    // ==================== Hardcoded Password Tests ====================

    #[test]
    fn test_hardcoded_password_patterns() {
        let patterns = get_info_patterns();
        let pwd_pattern = patterns.iter().find(|p| p.name == "Hardcoded Password").unwrap();

        assert!(pwd_pattern.regex.is_match("password = 'secret123'"));
        assert!(pwd_pattern.regex.is_match("passwd: \"mypassword\""));
        assert!(pwd_pattern.regex.is_match("pwd='admin1234'"));
    }

    // ==================== JWT Token Detection Tests ====================

    #[test]
    fn test_jwt_token_pattern() {
        let patterns = get_info_patterns();
        let jwt_pattern = patterns.iter().find(|p| p.name == "JWT Token").unwrap();

        // Valid JWT format
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(jwt_pattern.regex.is_match(jwt));
    }

    #[test]
    fn test_jwt_token_no_false_positives() {
        let patterns = get_info_patterns();
        let jwt_pattern = patterns.iter().find(|p| p.name == "JWT Token").unwrap();

        // Random strings should not match
        assert!(!jwt_pattern.regex.is_match("random_string_here"));
        assert!(!jwt_pattern.regex.is_match("base64encoded.but.not.jwt"));
    }

    // ==================== Sensitive File Path Tests ====================

    #[test]
    fn test_sensitive_file_paths() {
        let patterns = get_info_patterns();
        let path_pattern = patterns.iter().find(|p| p.name == "Sensitive File Path").unwrap();

        assert!(path_pattern.regex.is_match("/etc/passwd"));
        assert!(path_pattern.regex.is_match("/etc/shadow"));
        assert!(path_pattern.regex.is_match("web.config"));
        assert!(path_pattern.regex.is_match(".env"));
        assert!(path_pattern.regex.is_match(".git/config"));
        assert!(path_pattern.regex.is_match("id_rsa"));
    }

    // ==================== check_directory_listing Tests ====================

    #[test]
    fn test_directory_listing_apache() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/files/").unwrap();
        let response = r#"
            <html>
            <head><title>Index of /files</title></head>
            <body>
            <h1>Index of /files</h1>
            <a href="/files/secret.txt">secret.txt</a>
            </body>
            </html>
        "#;

        check_directory_listing(&mut findings, &url, response);

        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].finding_type, FindingType::DirectoryListing));
    }

    #[test]
    fn test_directory_listing_nginx() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/uploads/").unwrap();
        let response = r#"
            <html>
            <head><title>Directory listing for /uploads</title></head>
            <body>
            <h1>Directory listing for /uploads</h1>
            </body>
            </html>
        "#;

        check_directory_listing(&mut findings, &url, response);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_directory_listing_parent_directory() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/data/").unwrap();
        let response = r#"
            <html>
            <body>
            <a href="..">Parent Directory</a>
            <a href="file1.txt">file1.txt</a>
            </body>
            </html>
        "#;

        check_directory_listing(&mut findings, &url, response);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_directory_listing_no_match() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/page").unwrap();
        let response = r#"
            <html>
            <head><title>Welcome</title></head>
            <body>
            <h1>Welcome to our site</h1>
            </body>
            </html>
        "#;

        check_directory_listing(&mut findings, &url, response);

        assert!(findings.is_empty());
    }

    // ==================== check_debug_info Tests ====================

    #[test]
    fn test_debug_info_django() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/error").unwrap();
        let response = "Settings: DEBUG = True\nSome error occurred";

        check_debug_info(&mut findings, &url, response);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("DEBUG = True"));
    }

    #[test]
    fn test_debug_info_development_mode() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/").unwrap();
        let response = "Application running in development mode";

        check_debug_info(&mut findings, &url, response);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_debug_info_php_warning() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/").unwrap();
        let response = "Warning: mysqli_connect(): Access denied for user";

        check_debug_info(&mut findings, &url, response);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_debug_info_php_notice() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/").unwrap();
        let response = "Notice: Undefined variable: name in /var/www/html/index.php";

        check_debug_info(&mut findings, &url, response);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_debug_info_php_deprecated() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/").unwrap();
        let response = "Deprecated: Function mysql_connect() is deprecated";

        check_debug_info(&mut findings, &url, response);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_debug_info_sqlstate() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/").unwrap();
        let response = "SQLSTATE[HY000] [2002] Connection refused";

        check_debug_info(&mut findings, &url, response);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_debug_info_no_match() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/").unwrap();
        let response = "Welcome to our production website";

        check_debug_info(&mut findings, &url, response);

        assert!(findings.is_empty());
    }

    // ==================== check_html_comments Tests ====================

    #[test]
    fn test_html_comments_password() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/").unwrap();
        let response = r#"
            <html>
            <!-- TODO: remove password from here: admin123 -->
            <body>Content</body>
            </html>
        "#;

        check_html_comments(&mut findings, &url, response);

        assert!(!findings.is_empty());
        assert!(findings[0].evidence.contains("password"));
    }

    #[test]
    fn test_html_comments_todo() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/").unwrap();
        let response = r#"
            <html>
            <!-- TODO: implement authentication -->
            <body>Content</body>
            </html>
        "#;

        check_html_comments(&mut findings, &url, response);

        assert!(!findings.is_empty());
    }

    #[test]
    fn test_html_comments_fixme() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/").unwrap();
        let response = r#"
            <html>
            <!-- FIXME: security vulnerability here -->
            <body>Content</body>
            </html>
        "#;

        check_html_comments(&mut findings, &url, response);

        assert!(!findings.is_empty());
    }

    #[test]
    fn test_html_comments_api_key() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/").unwrap();
        let response = r#"
            <html>
            <!-- api key for testing: abc123 -->
            <body>Content</body>
            </html>
        "#;

        check_html_comments(&mut findings, &url, response);

        assert!(!findings.is_empty());
    }

    #[test]
    fn test_html_comments_admin() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/").unwrap();
        let response = r#"
            <html>
            <!-- admin panel at /secret-admin -->
            <body>Content</body>
            </html>
        "#;

        check_html_comments(&mut findings, &url, response);

        assert!(!findings.is_empty());
    }

    #[test]
    fn test_html_comments_safe() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/").unwrap();
        let response = r#"
            <html>
            <!-- This is a simple comment -->
            <!-- Navigation menu -->
            <body>Content</body>
            </html>
        "#;

        check_html_comments(&mut findings, &url, response);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_html_comments_truncates_long_evidence() {
        let mut findings = Vec::new();
        let url = Url::parse("https://example.com/").unwrap();
        let long_comment = format!("<!-- password: {} -->", "a".repeat(200));
        let response = format!("<html>{}</html>", long_comment);

        check_html_comments(&mut findings, &url, &response);

        assert!(!findings.is_empty());
        assert!(findings[0].evidence.len() < 200);
        assert!(findings[0].evidence.contains("..."));
    }

    // ==================== get_remediation Tests ====================

    #[test]
    fn test_remediation_email() {
        let remediation = get_remediation("Email Address");
        assert!(remediation.contains("obfuscation") || remediation.contains("contact forms"));
    }

    #[test]
    fn test_remediation_private_ip() {
        let remediation = get_remediation("Private IP Address");
        assert!(remediation.contains("internal") || remediation.contains("topology"));
    }

    #[test]
    fn test_remediation_stack_trace() {
        let remediation = get_remediation("Stack Trace");
        assert!(remediation.contains("production") || remediation.contains("generic error"));
    }

    #[test]
    fn test_remediation_db_connection() {
        let remediation = get_remediation("Database Connection String");
        assert!(remediation.contains("CRITICAL"));
        assert!(remediation.contains("environment variable"));
    }

    #[test]
    fn test_remediation_api_key() {
        let remediation = get_remediation("Potential API Key");
        assert!(remediation.contains("CRITICAL"));
        assert!(remediation.contains("Revoke"));
    }

    #[test]
    fn test_remediation_aws_key() {
        let remediation = get_remediation("AWS Access Key");
        assert!(remediation.contains("CRITICAL"));
    }

    #[test]
    fn test_remediation_private_key() {
        let remediation = get_remediation("Private Key");
        assert!(remediation.contains("CRITICAL"));
        assert!(remediation.contains("Revoke"));
    }

    #[test]
    fn test_remediation_hardcoded_password() {
        let remediation = get_remediation("Hardcoded Password");
        assert!(remediation.contains("Remove"));
    }

    #[test]
    fn test_remediation_jwt() {
        let remediation = get_remediation("JWT Token");
        assert!(remediation.contains("expiration") || remediation.contains("logged"));
    }

    #[test]
    fn test_remediation_sensitive_file() {
        let remediation = get_remediation("Sensitive File Path");
        assert!(remediation.contains("access") || remediation.contains("permission"));
    }

    #[test]
    fn test_remediation_unknown() {
        let remediation = get_remediation("Unknown Pattern");
        assert!(remediation.contains("Remove") || remediation.contains("obfuscate"));
    }
}
