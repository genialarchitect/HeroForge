use anyhow::Result;
use log::debug;
use reqwest::Client;
use scraper::{Html, Selector};
use url::Url;

use crate::types::{WebAppFinding, FindingType, Severity};

#[derive(Debug, Clone)]
pub struct FormData {
    pub url: String,
    pub action: String,
    pub method: String,
    pub inputs: Vec<InputField>,
    pub is_login_form: bool,
}

#[derive(Debug, Clone)]
pub struct InputField {
    pub name: String,
    pub input_type: String,
    pub value: Option<String>,
}

/// Detect and analyze forms on discovered pages
pub async fn detect_forms(
    client: &Client,
    urls: &[Url],
) -> Result<(Vec<WebAppFinding>, Vec<FormData>)> {
    let mut findings = Vec::new();
    let mut forms = Vec::new();

    for url in urls {
        debug!("Analyzing forms on: {}", url);

        match client.get(url.as_str()).send().await {
            Ok(response) => {
                if let Ok(html) = response.text().await {
                    let document = Html::parse_document(&html);

                    // Parse forms
                    if let Ok(form_selector) = Selector::parse("form") {
                        for form_element in document.select(&form_selector) {
                            let form_data = parse_form(url, &form_element);

                            // Check for insecure forms (HTTP forms submitting to HTTP)
                            if url.scheme() == "http" && !form_data.action.starts_with("https://") {
                                findings.push(WebAppFinding {
                                    finding_type: FindingType::InsecureForm,
                                    url: url.to_string(),
                                    parameter: None,
                                    evidence: format!("Form submits over insecure HTTP: {}", form_data.action),
                                    severity: if form_data.is_login_form {
                                        Severity::High
                                    } else {
                                        Severity::Medium
                                    },
                                    remediation: "Use HTTPS for all forms, especially login forms. Sensitive data should never be transmitted over HTTP.".to_string(),
                                });
                            }

                            // Check for forms without CSRF protection
                            if !has_csrf_token(&form_data) && form_data.method.to_uppercase() == "POST" {
                                findings.push(WebAppFinding {
                                    finding_type: FindingType::InsecureForm,
                                    url: url.to_string(),
                                    parameter: None,
                                    evidence: "Form appears to lack CSRF protection token".to_string(),
                                    severity: Severity::Medium,
                                    remediation: "Implement CSRF tokens for all state-changing forms (POST, PUT, DELETE). Use anti-CSRF tokens with each form submission.".to_string(),
                                });
                            }

                            // Check for autocomplete on password fields
                            for input in &form_data.inputs {
                                if input.input_type == "password" {
                                    // This is a simplified check; real implementation would need to parse autocomplete attribute
                                    findings.push(WebAppFinding {
                                        finding_type: FindingType::InsecureForm,
                                        url: url.to_string(),
                                        parameter: Some(input.name.clone()),
                                        evidence: "Password field may allow autocomplete".to_string(),
                                        severity: Severity::Low,
                                        remediation: "Set autocomplete='off' or autocomplete='new-password' on password fields to prevent browsers from caching credentials.".to_string(),
                                    });
                                    break; // Only report once per form
                                }
                            }

                            forms.push(form_data);
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Failed to fetch {}: {}", url, e);
            }
        }
    }

    debug!("Found {} forms", forms.len());
    Ok((findings, forms))
}

/// Parse form element and extract data
fn parse_form(base_url: &Url, form_element: &scraper::ElementRef) -> FormData {
    let action = form_element
        .value()
        .attr("action")
        .unwrap_or("")
        .to_string();

    // Resolve relative URLs
    let action = if action.is_empty() {
        base_url.to_string()
    } else {
        base_url.join(&action)
            .map(|u| u.to_string())
            .unwrap_or(action)
    };

    let method = form_element
        .value()
        .attr("method")
        .unwrap_or("GET")
        .to_uppercase();

    // Parse input fields
    let mut inputs = Vec::new();
    if let Ok(input_selector) = Selector::parse("input, textarea, select") {
        for input in form_element.select(&input_selector) {
            if let Some(name) = input.value().attr("name") {
                let input_type = input.value().attr("type").unwrap_or("text").to_string();
                let value = input.value().attr("value").map(|v| v.to_string());

                inputs.push(InputField {
                    name: name.to_string(),
                    input_type,
                    value,
                });
            }
        }
    }

    // Heuristic to detect login forms
    let is_login_form = inputs.iter().any(|i| {
        let name_lower = i.name.to_lowercase();
        (name_lower.contains("user") || name_lower.contains("email") || name_lower.contains("login"))
            && inputs.iter().any(|j| j.input_type == "password")
    });

    FormData {
        url: base_url.to_string(),
        action,
        method,
        inputs,
        is_login_form,
    }
}

/// Check if form has a CSRF token
fn has_csrf_token(form: &FormData) -> bool {
    form.inputs.iter().any(|input| {
        let name_lower = input.name.to_lowercase();
        name_lower.contains("csrf")
            || name_lower.contains("token")
            || name_lower.contains("_token")
            || name_lower == "authenticity_token"
    })
}
