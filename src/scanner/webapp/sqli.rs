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
