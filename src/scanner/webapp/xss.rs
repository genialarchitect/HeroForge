use anyhow::Result;
use log::debug;
use reqwest::Client;
use url::Url;
use rand::Rng;

use crate::types::{WebAppFinding, FindingType, Severity};
use super::forms::FormData;

/// Generate XSS test payloads with unique markers
fn generate_xss_payloads() -> Vec<String> {
    let marker: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();

    vec![
        format!("<script>alert('{}')</script>", marker),
        format!("<img src=x onerror=alert('{}')>", marker),
        format!("<svg/onload=alert('{}')>", marker),
        format!("'\"><script>alert('{}')</script>", marker),
        format!("javascript:alert('{}')", marker),
        format!("<iframe src=javascript:alert('{}')>", marker),
        format!("<body onload=alert('{}')>", marker),
        format!("<input onfocus=alert('{}') autofocus>", marker),
        // Encoded variants
        format!("%3Cscript%3Ealert('{}')%3C/script%3E", marker),
        format!("<scr<script>ipt>alert('{}')</scr</script>ipt>", marker),
    ]
}

/// Test for reflected XSS vulnerabilities
pub async fn test_xss(
    client: &Client,
    urls: &[Url],
    forms: &[FormData],
) -> Result<Vec<WebAppFinding>> {
    let mut findings = Vec::new();

    // Generate payloads
    let payloads = generate_xss_payloads();

    // Test URL parameters
    for url in urls {
        if url.query().is_some() {
            debug!("Testing XSS in URL parameters: {}", url);
            if let Some(xss_findings) = test_url_params(client, url, &payloads).await? {
                findings.extend(xss_findings);
            }
        }
    }

    // Test form inputs
    for form in forms {
        debug!("Testing XSS in form: {}", form.url);
        if let Some(xss_findings) = test_form_inputs(client, form, &payloads).await? {
            findings.extend(xss_findings);
        }
    }

    Ok(findings)
}

/// Test URL parameters for XSS
async fn test_url_params(
    client: &Client,
    url: &Url,
    payloads: &[String],
) -> Result<Option<Vec<WebAppFinding>>> {
    let mut findings = Vec::new();

    // Parse query parameters
    let params: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    for (param_name, _original_value) in &params {
        for payload in payloads {
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

                    // Check if payload is reflected in response
                    if is_payload_reflected(&response_text, payload) {
                        findings.push(WebAppFinding {
                            finding_type: FindingType::CrossSiteScripting,
                            url: url.to_string(),
                            parameter: Some(param_name.clone()),
                            evidence: format!(
                                "XSS payload reflected in response for parameter '{}': {}",
                                param_name, payload
                            ),
                            severity: Severity::High,
                            remediation: "Implement proper output encoding/escaping for all user input displayed in HTML. Use context-aware encoding (HTML, JavaScript, URL, CSS). Implement Content-Security-Policy header. Consider using a templating engine with auto-escaping.".to_string(),
                        });
                        break; // One finding per parameter
                    }
                }
                Err(e) => {
                    debug!("Request failed with XSS payload in parameter '{}': {}", param_name, e);
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

/// Test form inputs for XSS
async fn test_form_inputs(
    client: &Client,
    form: &FormData,
    payloads: &[String],
) -> Result<Option<Vec<WebAppFinding>>> {
    let mut findings = Vec::new();

    // Prepare baseline params
    let baseline_params: Vec<(String, String)> = form
        .inputs
        .iter()
        .map(|input| {
            let value = input.value.clone().unwrap_or_else(|| "test".to_string());
            (input.name.clone(), value)
        })
        .collect();

    // Test each input field
    for input in &form.inputs {
        // Skip hidden fields and CSRF tokens
        if input.input_type == "hidden" || input.name.to_lowercase().contains("csrf") {
            continue;
        }

        for payload in payloads {
            let mut test_params = baseline_params.clone();

            // Replace the input value with the payload
            if let Some(param) = test_params.iter_mut().find(|(k, _)| k == &input.name) {
                param.1 = payload.clone();
            }

            // Submit form based on method
            let response_result = if form.method == "POST" {
                client.post(&form.action).form(&test_params).send().await
            } else {
                // GET method - construct URL with query params
                let query_string = test_params
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
                    .collect::<Vec<_>>()
                    .join("&");

                let url_with_params = if form.action.contains('?') {
                    format!("{}&{}", form.action, query_string)
                } else {
                    format!("{}?{}", form.action, query_string)
                };

                client.get(&url_with_params).send().await
            };

            match response_result {
                Ok(response) => {
                    let response_text = response.text().await.unwrap_or_default();

                    // Check if payload is reflected
                    if is_payload_reflected(&response_text, payload) {
                        findings.push(WebAppFinding {
                            finding_type: FindingType::CrossSiteScripting,
                            url: form.url.clone(),
                            parameter: Some(input.name.clone()),
                            evidence: format!(
                                "XSS payload reflected in form response for input '{}': {}",
                                input.name, payload
                            ),
                            severity: Severity::High,
                            remediation: "Implement proper output encoding for all user input. Use context-aware escaping (HTML entities, JavaScript escaping, URL encoding). Set Content-Security-Policy header. Use HTTPOnly and Secure flags on cookies.".to_string(),
                        });
                        break;
                    }
                }
                Err(e) => {
                    debug!("Form submission failed with XSS payload in field '{}': {}", input.name, e);
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

/// Check if XSS payload is reflected in the response
fn is_payload_reflected(response: &str, payload: &str) -> bool {
    // Check for exact match
    if response.contains(payload) {
        return true;
    }

    // Check for common encoded variants
    let html_encoded = html_escape::encode_text(payload);
    if response.contains(&*html_encoded) {
        return false; // Properly encoded, not vulnerable
    }

    // Check for partial matches (tags might be stripped but content remains)
    // Extract the unique marker from payload
    if let Some(start) = payload.find("alert('") {
        if let Some(end) = payload[start + 7..].find('\'') {
            let marker = &payload[start + 7..start + 7 + end];
            if response.contains(marker) && response.contains("<script>") {
                return true;
            }
        }
    }

    false
}
