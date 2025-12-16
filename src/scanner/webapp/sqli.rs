// Allow unused code for internal helper functions
#![allow(dead_code)]

use anyhow::Result;
use log::debug;
use reqwest::Client;
use url::Url;

use crate::types::{WebAppFinding, FindingType, Severity};
use super::forms::FormData;

// Common SQL injection payloads for error-based detection
const SQLI_PAYLOADS: &[&str] = &[
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' UNION SELECT NULL--",
    "1' AND '1'='2",
    "admin'--",
    "' OR 'a'='a",
    "') OR ('1'='1",
    "1' ORDER BY 1--",
];

// Common SQL error messages
const SQL_ERROR_PATTERNS: &[&str] = &[
    "SQL syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "ORA-",
    "PostgreSQL",
    "SQLite",
    "Microsoft SQL",
    "ODBC SQL Server",
    "Unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "mysql_",
    "Warning: mysql",
    "valid MySQL result",
    "MySqlClient",
    "com.mysql.jdbc.exceptions",
];

/// Test for SQL injection vulnerabilities
pub async fn test_sql_injection(
    client: &Client,
    urls: &[Url],
    forms: &[FormData],
) -> Result<Vec<WebAppFinding>> {
    let mut findings = Vec::new();

    // Test URL parameters
    for url in urls {
        if url.query().is_some() {
            debug!("Testing SQL injection in URL parameters: {}", url);
            if let Some(sqli_findings) = test_url_params(client, url).await? {
                findings.extend(sqli_findings);
            }
        }
    }

    // Test form inputs
    for form in forms {
        debug!("Testing SQL injection in form: {}", form.url);
        if let Some(sqli_findings) = test_form_inputs(client, form).await? {
            findings.extend(sqli_findings);
        }
    }

    Ok(findings)
}

/// Test URL parameters for SQL injection
async fn test_url_params(client: &Client, url: &Url) -> Result<Option<Vec<WebAppFinding>>> {
    let mut findings = Vec::new();

    // Get baseline response
    let baseline = match client.get(url.as_str()).send().await {
        Ok(resp) => resp.text().await.unwrap_or_default(),
        Err(_) => return Ok(None),
    };

    // Parse query parameters
    let params: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    for (param_name, _original_value) in &params {
        for payload in SQLI_PAYLOADS {
            let mut modified_url = url.clone();

            // Replace the parameter value with the payload
            let new_query = params
                .iter()
                .map(|(k, v)| {
                    if k == param_name {
                        format!("{}={}", k, urlencoding::encode(payload))
                    } else {
                        format!("{}={}", k, urlencoding::encode(v))
                    }
                })
                .collect::<Vec<_>>()
                .join("&");

            modified_url.set_query(Some(&new_query));

            // Send request with payload
            match client.get(modified_url.as_str()).send().await {
                Ok(response) => {
                    let response_text = response.text().await.unwrap_or_default();

                    // Check for SQL errors in response
                    if contains_sql_error(&response_text) {
                        findings.push(WebAppFinding {
                            finding_type: FindingType::SqlInjection,
                            url: url.to_string(),
                            parameter: Some(param_name.clone()),
                            evidence: format!(
                                "SQL error detected when parameter '{}' was set to payload: {}",
                                param_name, payload
                            ),
                            severity: Severity::Critical,
                            remediation: "Use parameterized queries (prepared statements) to prevent SQL injection. Never concatenate user input directly into SQL queries. Implement input validation and sanitization.".to_string(),
                        });
                        break; // One finding per parameter is enough
                    }

                    // Check for behavior changes that might indicate blind SQL injection
                    if response_text.len() != baseline.len() {
                        let diff_ratio = (response_text.len() as f32 - baseline.len() as f32).abs()
                            / baseline.len() as f32;

                        if diff_ratio > 0.1 {
                            // Significant difference
                            debug!(
                                "Potential blind SQLi: parameter '{}' with payload '{}' caused {}% change in response size",
                                param_name, payload, diff_ratio * 100.0
                            );
                        }
                    }
                }
                Err(_) => {
                    // Request failed - might indicate SQL error causing server error
                    debug!("Request failed with payload '{}' in parameter '{}'", payload, param_name);
                }
            }

            // Small delay to avoid overwhelming the server
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        Ok(Some(findings))
    }
}

/// Test form inputs for SQL injection
async fn test_form_inputs(client: &Client, form: &FormData) -> Result<Option<Vec<WebAppFinding>>> {
    let mut findings = Vec::new();

    // Only test POST forms to avoid side effects
    if form.method != "POST" {
        return Ok(None);
    }

    // Get baseline by submitting form with normal values
    let baseline_params: Vec<(String, String)> = form
        .inputs
        .iter()
        .map(|input| {
            let value = input.value.clone().unwrap_or_else(|| "test".to_string());
            (input.name.clone(), value)
        })
        .collect();

    let _baseline = match client
        .post(&form.action)
        .form(&baseline_params)
        .send()
        .await
    {
        Ok(resp) => resp.text().await.unwrap_or_default(),
        Err(_) => return Ok(None),
    };

    // Test each input field
    for input in &form.inputs {
        // Skip hidden fields and CSRF tokens
        if input.input_type == "hidden" || input.name.to_lowercase().contains("csrf") {
            continue;
        }

        for payload in SQLI_PAYLOADS {
            let mut test_params = baseline_params.clone();

            // Replace the input value with the payload
            if let Some(param) = test_params.iter_mut().find(|(k, _)| k == &input.name) {
                param.1 = payload.to_string();
            }

            // Submit form with payload
            match client
                .post(&form.action)
                .form(&test_params)
                .send()
                .await
            {
                Ok(response) => {
                    let response_text = response.text().await.unwrap_or_default();

                    // Check for SQL errors
                    if contains_sql_error(&response_text) {
                        findings.push(WebAppFinding {
                            finding_type: FindingType::SqlInjection,
                            url: form.url.clone(),
                            parameter: Some(input.name.clone()),
                            evidence: format!(
                                "SQL error detected in form input '{}' with payload: {}",
                                input.name, payload
                            ),
                            severity: Severity::Critical,
                            remediation: "Use parameterized queries (prepared statements) for all database operations. Never concatenate user input into SQL queries. Implement input validation and use an ORM or query builder.".to_string(),
                        });
                        break;
                    }
                }
                Err(_) => {
                    debug!("Form submission failed with payload '{}' in field '{}'", payload, input.name);
                }
            }

            // Rate limiting
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    if findings.is_empty() {
        Ok(None)
    } else {
        Ok(Some(findings))
    }
}

/// Check if response contains SQL error messages
fn contains_sql_error(text: &str) -> bool {
    let text_lower = text.to_lowercase();
    SQL_ERROR_PATTERNS.iter().any(|pattern| {
        text_lower.contains(&pattern.to_lowercase())
    })
}

/// Get all SQL injection payloads
fn get_sqli_payloads() -> &'static [&'static str] {
    SQLI_PAYLOADS
}

/// Get all SQL error patterns
fn get_sql_error_patterns() -> &'static [&'static str] {
    SQL_ERROR_PATTERNS
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== contains_sql_error Tests ====================

    #[test]
    fn test_contains_sql_error_mysql_syntax() {
        let response = "Error: You have an error in your SQL syntax; check the manual";
        assert!(contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_mysql_fetch() {
        let response = "Warning: mysql_fetch_array() expects parameter 1 to be resource";
        assert!(contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_mysql_num_rows() {
        let response = "Warning: mysql_num_rows() expects parameter 1 to be resource";
        assert!(contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_oracle() {
        let response = "ORA-01756: quoted string not properly terminated";
        assert!(contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_postgresql() {
        let response = "ERROR: PostgreSQL query failed: syntax error at or near";
        assert!(contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_sqlite() {
        let response = "SQLite error: near \"'\": syntax error";
        assert!(contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_mssql() {
        let response = "Microsoft SQL Server error: Incorrect syntax near";
        assert!(contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_odbc() {
        let response = "[ODBC SQL Server Driver] Error in SQL syntax";
        assert!(contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_unclosed_quote() {
        let response = "Unclosed quotation mark after the character string";
        assert!(contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_java_mysql() {
        let response = "com.mysql.jdbc.exceptions.jdbc4.MySQLSyntaxErrorException";
        assert!(contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_case_insensitive() {
        let response = "sql SYNTAX error in query";
        assert!(contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_warning_mysql() {
        let response = "<br>Warning: mysql_connect(): Access denied for user";
        assert!(contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_valid_mysql_result() {
        let response = "supplied argument is not a valid MySQL result resource";
        assert!(contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_no_error() {
        let response = "Welcome to our website! Please login to continue.";
        assert!(!contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_empty_response() {
        let response = "";
        assert!(!contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_html_page() {
        let response = r#"
            <!DOCTYPE html>
            <html>
            <head><title>Product Page</title></head>
            <body>
                <h1>Product Details</h1>
                <p>Price: $29.99</p>
            </body>
            </html>
        "#;
        assert!(!contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_generic_error_page() {
        // Make sure we don't match generic errors
        let response = "An error occurred. Please try again later.";
        assert!(!contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_debug_mode() {
        let response = "DEBUG = True";
        // This shouldn't match SQL errors
        assert!(!contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_syntax_in_context() {
        // Match "syntax error" in the context of SQL
        let response = "Query error: syntax error at or near unexpected token";
        assert!(contains_sql_error(response));
    }

    #[test]
    fn test_contains_sql_error_mysqlclient() {
        let response = "MySqlClient.MySqlException: You have an error in your SQL syntax";
        assert!(contains_sql_error(response));
    }

    // ==================== Payload Tests ====================

    #[test]
    fn test_sqli_payloads_not_empty() {
        let payloads = get_sqli_payloads();
        assert!(!payloads.is_empty());
    }

    #[test]
    fn test_sqli_payloads_contains_basic_quotes() {
        let payloads = get_sqli_payloads();
        assert!(payloads.contains(&"'"));
        assert!(payloads.contains(&"\""));
    }

    #[test]
    fn test_sqli_payloads_contains_or_injection() {
        let payloads = get_sqli_payloads();
        assert!(payloads.iter().any(|p| p.contains("OR")));
    }

    #[test]
    fn test_sqli_payloads_contains_union() {
        let payloads = get_sqli_payloads();
        assert!(payloads.iter().any(|p| p.contains("UNION")));
    }

    #[test]
    fn test_sqli_payloads_contains_comment_terminator() {
        let payloads = get_sqli_payloads();
        assert!(payloads.iter().any(|p| p.contains("--")));
    }

    #[test]
    fn test_sqli_payloads_contains_order_by() {
        let payloads = get_sqli_payloads();
        assert!(payloads.iter().any(|p| p.contains("ORDER BY")));
    }

    // ==================== Error Pattern Tests ====================

    #[test]
    fn test_sql_error_patterns_not_empty() {
        let patterns = get_sql_error_patterns();
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_sql_error_patterns_covers_major_databases() {
        let patterns = get_sql_error_patterns();

        // MySQL
        assert!(patterns.iter().any(|p| p.to_lowercase().contains("mysql")));

        // Oracle
        assert!(patterns.iter().any(|p| p.contains("ORA-")));

        // PostgreSQL
        assert!(patterns.iter().any(|p| p.contains("PostgreSQL")));

        // SQLite
        assert!(patterns.iter().any(|p| p.contains("SQLite")));

        // Microsoft SQL Server
        assert!(patterns.iter().any(|p| p.contains("Microsoft SQL") || p.contains("ODBC SQL Server")));
    }

    #[test]
    fn test_sql_error_patterns_contains_syntax_error() {
        let patterns = get_sql_error_patterns();
        assert!(patterns.iter().any(|p| p.to_lowercase().contains("syntax")));
    }

    // ==================== Integration-like Tests (without network) ====================

    #[test]
    fn test_error_detection_mysql_detailed() {
        let mysql_errors = vec![
            "Warning: mysql_connect(): Access denied for user 'root'@'localhost'",
            "Fatal error: Call to undefined function mysql_connect()",
            "mysql_fetch_row() expects parameter 1 to be resource, boolean given",
            "You have an error in your SQL syntax near '' at line 1",
        ];

        for error in mysql_errors {
            assert!(contains_sql_error(error), "Should detect: {}", error);
        }
    }

    #[test]
    fn test_error_detection_postgresql_detailed() {
        let pg_errors = vec![
            "ERROR: syntax error at or near \"'\"",
            "PostgreSQL query failed: ERROR: column \"id\" does not exist",
            "PostgreSQL query failed: ERROR: invalid input syntax for integer",
        ];

        for error in pg_errors {
            assert!(contains_sql_error(error), "Should detect: {}", error);
        }
    }

    #[test]
    fn test_error_detection_oracle_detailed() {
        let oracle_errors = vec![
            "ORA-00933: SQL command not properly ended",
            "ORA-01756: quoted string not properly terminated",
            "ORA-00942: table or view does not exist",
        ];

        for error in oracle_errors {
            assert!(contains_sql_error(error), "Should detect: {}", error);
        }
    }

    #[test]
    fn test_error_detection_mssql_detailed() {
        let mssql_errors = vec![
            "Microsoft SQL Server error: Incorrect syntax near the keyword 'SELECT'",
            "Unclosed quotation mark after the character string ''",
            "[ODBC SQL Server Driver][SQL Server]Line 1: Incorrect syntax",
        ];

        for error in mssql_errors {
            assert!(contains_sql_error(error), "Should detect: {}", error);
        }
    }

    #[test]
    fn test_false_positives_avoided() {
        let safe_responses = vec![
            "Your search for 'test' returned 0 results",
            "Invalid username or password",
            "Page not found",
            "Internal server error",
            "Connection timeout",
            "Welcome back, user!",
            "Your order has been placed successfully",
            "Email sent to test@example.com",
        ];

        for response in safe_responses {
            assert!(!contains_sql_error(response), "Should NOT detect: {}", response);
        }
    }

    #[test]
    fn test_payload_effectiveness_single_quote() {
        // Single quote should break string concatenation
        let payload = "'";
        assert_eq!(payload, SQLI_PAYLOADS[0]);

        // Simulating what would happen if this payload causes an error
        let simulated_error = format!("SQL syntax error near '{}'", payload);
        assert!(contains_sql_error(&simulated_error));
    }

    #[test]
    fn test_payload_effectiveness_or_true() {
        // OR 1=1 payloads for authentication bypass
        let payloads: Vec<&&str> = SQLI_PAYLOADS.iter()
            .filter(|p| p.contains("1=1") || p.contains("'1'='1"))
            .collect();

        assert!(!payloads.is_empty(), "Should have OR 1=1 type payloads");
    }

    #[test]
    fn test_payload_effectiveness_union_select() {
        // UNION SELECT for data extraction
        let union_payloads: Vec<&&str> = SQLI_PAYLOADS.iter()
            .filter(|p| p.contains("UNION"))
            .collect();

        assert!(!union_payloads.is_empty(), "Should have UNION type payloads");
    }
}
