// Allow unused code for internal helper functions
#![allow(dead_code)]

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
    pub autocomplete: Option<String>,
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
                                    // Check autocomplete attribute for security
                                    let autocomplete_finding = check_password_autocomplete(input);
                                    if let Some((evidence, severity)) = autocomplete_finding {
                                        findings.push(WebAppFinding {
                                            finding_type: FindingType::InsecureForm,
                                            url: url.to_string(),
                                            parameter: Some(input.name.clone()),
                                            evidence,
                                            severity,
                                            remediation: "Set autocomplete='off' or autocomplete='new-password' on password fields to prevent browsers from caching credentials.".to_string(),
                                        });
                                    }
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

    // Get form-level autocomplete attribute (applies to all inputs unless overridden)
    let form_autocomplete = form_element.value().attr("autocomplete").map(|v| v.to_lowercase());

    // Parse input fields
    let mut inputs = Vec::new();
    if let Ok(input_selector) = Selector::parse("input, textarea, select") {
        for input in form_element.select(&input_selector) {
            if let Some(name) = input.value().attr("name") {
                let input_type = input.value().attr("type").unwrap_or("text").to_string();
                let value = input.value().attr("value").map(|v| v.to_string());
                // Get input-level autocomplete, fall back to form-level if not specified
                let autocomplete = input
                    .value()
                    .attr("autocomplete")
                    .map(|v| v.to_lowercase())
                    .or_else(|| form_autocomplete.clone());

                inputs.push(InputField {
                    name: name.to_string(),
                    input_type,
                    value,
                    autocomplete,
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

/// Check password field autocomplete attribute for security issues
/// Returns Some((evidence, severity)) if insecure, None if secure
fn check_password_autocomplete(input: &InputField) -> Option<(String, Severity)> {
    match &input.autocomplete {
        Some(value) => {
            let value = value.trim().to_lowercase();
            match value.as_str() {
                // Secure values - autocomplete explicitly disabled
                "off" => None,
                // Secure values - browser password manager integration (acceptable for login forms)
                "current-password" | "new-password" => None,
                // Explicitly enabled - insecure for password fields
                "on" => Some((
                    format!(
                        "Password field '{}' has autocomplete explicitly enabled (autocomplete=\"on\")",
                        input.name
                    ),
                    Severity::Medium,
                )),
                // Other values (e.g., "username", custom values) - potentially insecure
                other => Some((
                    format!(
                        "Password field '{}' has non-standard autocomplete value (autocomplete=\"{}\")",
                        input.name, other
                    ),
                    Severity::Low,
                )),
            }
        }
        // No autocomplete attribute - browser default behavior (typically enabled)
        None => Some((
            format!(
                "Password field '{}' has no autocomplete attribute (browser default allows autocomplete)",
                input.name
            ),
            Severity::Low,
        )),
    }
}

/// Check if a form is likely a login form based on heuristics
fn is_login_form_heuristic(inputs: &[InputField]) -> bool {
    inputs.iter().any(|i| {
        let name_lower = i.name.to_lowercase();
        (name_lower.contains("user") || name_lower.contains("email") || name_lower.contains("login"))
            && inputs.iter().any(|j| j.input_type == "password")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use scraper::Html;

    // Helper to create InputField for tests
    fn input(name: &str, input_type: &str, value: Option<&str>) -> InputField {
        InputField {
            name: name.to_string(),
            input_type: input_type.to_string(),
            value: value.map(|v| v.to_string()),
            autocomplete: None,
        }
    }

    // Helper to create InputField with autocomplete for tests
    fn input_with_autocomplete(name: &str, input_type: &str, value: Option<&str>, autocomplete: Option<&str>) -> InputField {
        InputField {
            name: name.to_string(),
            input_type: input_type.to_string(),
            value: value.map(|v| v.to_string()),
            autocomplete: autocomplete.map(|v| v.to_string()),
        }
    }

    // Helper to create FormData for tests
    fn form(inputs: Vec<InputField>, method: &str) -> FormData {
        FormData {
            url: "https://example.com/form".to_string(),
            action: "https://example.com/submit".to_string(),
            method: method.to_string(),
            inputs,
            is_login_form: false,
        }
    }

    // ==================== has_csrf_token Tests ====================

    #[test]
    fn test_has_csrf_token_with_csrf() {
        let form_data = form(vec![
            input("username", "text", None),
            input("csrf_token", "hidden", Some("abc123")),
        ], "POST");
        assert!(has_csrf_token(&form_data));
    }

    #[test]
    fn test_has_csrf_token_with_token() {
        let form_data = form(vec![
            input("email", "email", None),
            input("_token", "hidden", Some("xyz789")),
        ], "POST");
        assert!(has_csrf_token(&form_data));
    }

    #[test]
    fn test_has_csrf_token_rails_authenticity() {
        let form_data = form(vec![
            input("name", "text", None),
            input("authenticity_token", "hidden", Some("rails_token")),
        ], "POST");
        assert!(has_csrf_token(&form_data));
    }

    #[test]
    fn test_has_csrf_token_case_insensitive() {
        let form_data = form(vec![
            input("data", "text", None),
            input("CSRF_TOKEN", "hidden", Some("token")),
        ], "POST");
        assert!(has_csrf_token(&form_data));
    }

    #[test]
    fn test_has_csrf_token_partial_match() {
        let form_data = form(vec![
            input("my_custom_token_field", "hidden", Some("value")),
        ], "POST");
        assert!(has_csrf_token(&form_data));
    }

    #[test]
    fn test_has_csrf_token_missing() {
        let form_data = form(vec![
            input("username", "text", None),
            input("password", "password", None),
        ], "POST");
        assert!(!has_csrf_token(&form_data));
    }

    #[test]
    fn test_has_csrf_token_empty_inputs() {
        let form_data = form(vec![], "POST");
        assert!(!has_csrf_token(&form_data));
    }

    // ==================== is_login_form_heuristic Tests ====================

    #[test]
    fn test_is_login_form_with_username_password() {
        let inputs = vec![
            input("username", "text", None),
            input("password", "password", None),
        ];
        assert!(is_login_form_heuristic(&inputs));
    }

    #[test]
    fn test_is_login_form_with_email_password() {
        let inputs = vec![
            input("email", "email", None),
            input("password", "password", None),
        ];
        assert!(is_login_form_heuristic(&inputs));
    }

    #[test]
    fn test_is_login_form_with_login_field() {
        let inputs = vec![
            input("login_name", "text", None),
            input("pass", "password", None),
        ];
        assert!(is_login_form_heuristic(&inputs));
    }

    #[test]
    fn test_is_login_form_with_user_field() {
        let inputs = vec![
            input("user_id", "text", None),
            input("pwd", "password", None),
        ];
        assert!(is_login_form_heuristic(&inputs));
    }

    #[test]
    fn test_is_login_form_no_password() {
        let inputs = vec![
            input("username", "text", None),
            input("submit", "submit", None),
        ];
        assert!(!is_login_form_heuristic(&inputs));
    }

    #[test]
    fn test_is_login_form_password_only() {
        let inputs = vec![
            input("password", "password", None),
        ];
        // Has password but no username/email/login field
        assert!(!is_login_form_heuristic(&inputs));
    }

    #[test]
    fn test_is_login_form_search_form() {
        let inputs = vec![
            input("q", "text", None),
            input("search", "submit", None),
        ];
        assert!(!is_login_form_heuristic(&inputs));
    }

    #[test]
    fn test_is_login_form_empty_inputs() {
        let inputs: Vec<InputField> = vec![];
        assert!(!is_login_form_heuristic(&inputs));
    }

    // ==================== parse_form Tests ====================

    #[test]
    fn test_parse_form_basic() {
        let html = r#"
            <form action="/submit" method="POST">
                <input type="text" name="username">
                <input type="password" name="password">
                <input type="submit" name="login" value="Login">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/login").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        assert_eq!(form_data.method, "POST");
        assert_eq!(form_data.action, "https://example.com/submit");
        assert_eq!(form_data.inputs.len(), 3);
        assert!(form_data.is_login_form);
    }

    #[test]
    fn test_parse_form_get_method_default() {
        let html = r#"
            <form action="/search">
                <input type="text" name="q">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        assert_eq!(form_data.method, "GET");
    }

    #[test]
    fn test_parse_form_relative_action() {
        let html = r#"
            <form action="../api/submit" method="POST">
                <input type="text" name="data">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/app/forms/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        assert_eq!(form_data.action, "https://example.com/app/api/submit");
    }

    #[test]
    fn test_parse_form_empty_action() {
        let html = r#"
            <form method="POST">
                <input type="text" name="data">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/current").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        // Empty action should default to current URL
        assert_eq!(form_data.action, "https://example.com/current");
    }

    #[test]
    fn test_parse_form_extracts_input_values() {
        let html = r#"
            <form action="/submit" method="POST">
                <input type="hidden" name="token" value="abc123">
                <input type="text" name="name" value="default">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        assert_eq!(form_data.inputs.len(), 2);

        let token_input = form_data.inputs.iter().find(|i| i.name == "token").unwrap();
        assert_eq!(token_input.value, Some("abc123".to_string()));
        assert_eq!(token_input.input_type, "hidden");

        let name_input = form_data.inputs.iter().find(|i| i.name == "name").unwrap();
        assert_eq!(name_input.value, Some("default".to_string()));
    }

    #[test]
    fn test_parse_form_textarea() {
        let html = r#"
            <form action="/submit" method="POST">
                <textarea name="message"></textarea>
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        assert_eq!(form_data.inputs.len(), 1);
        assert_eq!(form_data.inputs[0].name, "message");
    }

    #[test]
    fn test_parse_form_select() {
        let html = r#"
            <form action="/submit" method="POST">
                <select name="country">
                    <option value="us">United States</option>
                    <option value="uk">United Kingdom</option>
                </select>
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        assert_eq!(form_data.inputs.len(), 1);
        assert_eq!(form_data.inputs[0].name, "country");
    }

    #[test]
    fn test_parse_form_inputs_without_name_ignored() {
        let html = r#"
            <form action="/submit" method="POST">
                <input type="text" name="valid">
                <input type="text">
                <input type="submit">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        // Only input with name should be included
        assert_eq!(form_data.inputs.len(), 1);
        assert_eq!(form_data.inputs[0].name, "valid");
    }

    #[test]
    fn test_parse_form_method_case_insensitive() {
        let html = r#"
            <form action="/submit" method="post">
                <input type="text" name="data">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        assert_eq!(form_data.method, "POST");
    }

    #[test]
    fn test_parse_form_not_login_form() {
        let html = r#"
            <form action="/search" method="GET">
                <input type="text" name="q">
                <input type="submit" name="submit" value="Search">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        assert!(!form_data.is_login_form);
    }

    #[test]
    fn test_parse_form_absolute_action_url() {
        let html = r#"
            <form action="https://other.com/api/submit" method="POST">
                <input type="text" name="data">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        assert_eq!(form_data.action, "https://other.com/api/submit");
    }

    // ==================== check_password_autocomplete Tests ====================

    #[test]
    fn test_autocomplete_off_is_secure() {
        let input = input_with_autocomplete("password", "password", None, Some("off"));
        assert!(check_password_autocomplete(&input).is_none());
    }

    #[test]
    fn test_autocomplete_off_case_insensitive() {
        let input = input_with_autocomplete("password", "password", None, Some("OFF"));
        assert!(check_password_autocomplete(&input).is_none());
    }

    #[test]
    fn test_autocomplete_current_password_is_secure() {
        let input = input_with_autocomplete("password", "password", None, Some("current-password"));
        assert!(check_password_autocomplete(&input).is_none());
    }

    #[test]
    fn test_autocomplete_new_password_is_secure() {
        let input = input_with_autocomplete("password", "password", None, Some("new-password"));
        assert!(check_password_autocomplete(&input).is_none());
    }

    #[test]
    fn test_autocomplete_on_is_insecure() {
        let input = input_with_autocomplete("password", "password", None, Some("on"));
        let result = check_password_autocomplete(&input);
        assert!(result.is_some());
        let (evidence, severity) = result.unwrap();
        assert!(evidence.contains("autocomplete explicitly enabled"));
        assert_eq!(severity, Severity::Medium);
    }

    #[test]
    fn test_autocomplete_missing_is_insecure() {
        let input = input_with_autocomplete("password", "password", None, None);
        let result = check_password_autocomplete(&input);
        assert!(result.is_some());
        let (evidence, severity) = result.unwrap();
        assert!(evidence.contains("no autocomplete attribute"));
        assert_eq!(severity, Severity::Low);
    }

    #[test]
    fn test_autocomplete_nonstandard_value() {
        let input = input_with_autocomplete("password", "password", None, Some("username"));
        let result = check_password_autocomplete(&input);
        assert!(result.is_some());
        let (evidence, severity) = result.unwrap();
        assert!(evidence.contains("non-standard autocomplete value"));
        assert_eq!(severity, Severity::Low);
    }

    #[test]
    fn test_autocomplete_with_whitespace() {
        let input = input_with_autocomplete("password", "password", None, Some("  off  "));
        assert!(check_password_autocomplete(&input).is_none());
    }

    // ==================== parse_form autocomplete extraction Tests ====================

    #[test]
    fn test_parse_form_extracts_autocomplete() {
        let html = r#"
            <form action="/submit" method="POST">
                <input type="text" name="username" autocomplete="username">
                <input type="password" name="password" autocomplete="off">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        let username_input = form_data.inputs.iter().find(|i| i.name == "username").unwrap();
        assert_eq!(username_input.autocomplete, Some("username".to_string()));

        let password_input = form_data.inputs.iter().find(|i| i.name == "password").unwrap();
        assert_eq!(password_input.autocomplete, Some("off".to_string()));
    }

    #[test]
    fn test_parse_form_inherits_form_autocomplete() {
        let html = r#"
            <form action="/submit" method="POST" autocomplete="off">
                <input type="text" name="username">
                <input type="password" name="password">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        // Both inputs should inherit form-level autocomplete="off"
        for input in &form_data.inputs {
            assert_eq!(input.autocomplete, Some("off".to_string()));
        }
    }

    #[test]
    fn test_parse_form_input_autocomplete_overrides_form() {
        let html = r#"
            <form action="/submit" method="POST" autocomplete="off">
                <input type="text" name="username" autocomplete="username">
                <input type="password" name="password">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        let username_input = form_data.inputs.iter().find(|i| i.name == "username").unwrap();
        // Input-level autocomplete overrides form-level
        assert_eq!(username_input.autocomplete, Some("username".to_string()));

        let password_input = form_data.inputs.iter().find(|i| i.name == "password").unwrap();
        // Password inherits form-level autocomplete
        assert_eq!(password_input.autocomplete, Some("off".to_string()));
    }

    #[test]
    fn test_parse_form_no_autocomplete_attribute() {
        let html = r#"
            <form action="/submit" method="POST">
                <input type="password" name="password">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        let password_input = form_data.inputs.iter().find(|i| i.name == "password").unwrap();
        assert_eq!(password_input.autocomplete, None);
    }

    #[test]
    fn test_parse_form_autocomplete_current_password() {
        let html = r#"
            <form action="/login" method="POST">
                <input type="text" name="username" autocomplete="username">
                <input type="password" name="password" autocomplete="current-password">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        let password_input = form_data.inputs.iter().find(|i| i.name == "password").unwrap();
        assert_eq!(password_input.autocomplete, Some("current-password".to_string()));
    }

    #[test]
    fn test_parse_form_autocomplete_new_password() {
        let html = r#"
            <form action="/register" method="POST">
                <input type="password" name="password" autocomplete="new-password">
                <input type="password" name="confirm_password" autocomplete="new-password">
            </form>
        "#;
        let document = Html::parse_document(html);
        let selector = scraper::Selector::parse("form").unwrap();
        let form_element = document.select(&selector).next().unwrap();
        let base_url = Url::parse("https://example.com/").unwrap();

        let form_data = parse_form(&base_url, &form_element);

        for input in &form_data.inputs {
            assert_eq!(input.autocomplete, Some("new-password".to_string()));
        }
    }
}
