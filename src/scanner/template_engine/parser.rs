//! Template Parser
//!
//! Parses YAML templates in Nuclei-compatible format.

use super::types::*;
use log::{debug, warn};
use std::path::Path;
use walkdir::WalkDir;

/// Parse a single template from YAML string
pub fn parse_template(yaml: &str) -> Result<Template, TemplateError> {
    let template: Template = serde_yaml::from_str(yaml)?;
    validate_template(&template)?;
    Ok(template)
}

/// Parse a template from a file
pub fn parse_template_file(path: &Path) -> Result<Template, TemplateError> {
    let content = std::fs::read_to_string(path)?;
    let mut template = parse_template(&content)?;
    template.source_path = Some(path.display().to_string());
    Ok(template)
}

/// Load all templates from a directory
pub fn load_templates_from_dir(dir: &Path) -> Vec<Template> {
    let mut templates = Vec::new();

    for entry in WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        if path.is_file() {
            let ext = path.extension().and_then(|e| e.to_str());
            if ext == Some("yaml") || ext == Some("yml") {
                match parse_template_file(path) {
                    Ok(template) => {
                        debug!("Loaded template: {} from {:?}", template.id, path);
                        templates.push(template);
                    }
                    Err(e) => {
                        warn!("Failed to parse template {:?}: {}", path, e);
                    }
                }
            }
        }
    }

    templates
}

/// Validate a parsed template
fn validate_template(template: &Template) -> Result<(), TemplateError> {
    if template.id.is_empty() {
        return Err(TemplateError::Validation("Template ID is required".to_string()));
    }

    if template.info.name.is_empty() {
        return Err(TemplateError::Validation(
            "Template name is required".to_string(),
        ));
    }

    if !template.has_requests() {
        return Err(TemplateError::Validation(
            "Template must have at least one request".to_string(),
        ));
    }

    // Validate HTTP requests
    for (i, req) in template.http_requests.iter().enumerate() {
        if req.path.is_empty() && req.raw.is_empty() {
            return Err(TemplateError::Validation(format!(
                "HTTP request {} must have either path or raw request",
                i
            )));
        }

        // Validate matchers
        for matcher in &req.matchers {
            validate_matcher(matcher)?;
        }
    }

    // Validate TCP requests
    for (i, req) in template.tcp_requests.iter().enumerate() {
        if req.host.is_empty() && req.inputs.is_empty() {
            return Err(TemplateError::Validation(format!(
                "TCP request {} must have host or inputs",
                i
            )));
        }
    }

    // Validate DNS requests
    for (i, req) in template.dns_requests.iter().enumerate() {
        if req.name.is_empty() {
            return Err(TemplateError::Validation(format!(
                "DNS request {} must have a name",
                i
            )));
        }
    }

    Ok(())
}

/// Validate a matcher
fn validate_matcher(matcher: &Matcher) -> Result<(), TemplateError> {
    match matcher.matcher_type {
        MatcherType::Word => {
            if matcher.words.is_empty() {
                return Err(TemplateError::Validation(
                    "Word matcher must have words".to_string(),
                ));
            }
        }
        MatcherType::Regex => {
            if matcher.regex.is_empty() {
                return Err(TemplateError::Validation(
                    "Regex matcher must have regex patterns".to_string(),
                ));
            }
            // Validate regex patterns compile
            for pattern in &matcher.regex {
                if let Err(e) = regex::Regex::new(pattern) {
                    return Err(TemplateError::Validation(format!(
                        "Invalid regex pattern '{}': {}",
                        pattern, e
                    )));
                }
            }
        }
        MatcherType::Binary => {
            if matcher.binary.is_empty() {
                return Err(TemplateError::Validation(
                    "Binary matcher must have binary patterns".to_string(),
                ));
            }
        }
        MatcherType::Status => {
            if matcher.status.is_empty() {
                return Err(TemplateError::Validation(
                    "Status matcher must have status codes".to_string(),
                ));
            }
        }
        MatcherType::Size => {
            if matcher.size.is_empty() {
                return Err(TemplateError::Validation(
                    "Size matcher must have sizes".to_string(),
                ));
            }
        }
        MatcherType::Dsl => {
            if matcher.dsl.is_empty() {
                return Err(TemplateError::Validation(
                    "DSL matcher must have DSL expressions".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Filter templates by severity
pub fn filter_by_severity<'a>(templates: &'a [Template], severities: &[Severity]) -> Vec<&'a Template> {
    templates
        .iter()
        .filter(|t| severities.contains(&t.info.severity))
        .collect()
}

/// Filter templates by tags
pub fn filter_by_tags<'a>(templates: &'a [Template], tags: &[String]) -> Vec<&'a Template> {
    templates
        .iter()
        .filter(|t| tags.iter().any(|tag| t.has_tag(tag)))
        .collect()
}

/// Filter templates by ID pattern
pub fn filter_by_id<'a>(templates: &'a [Template], pattern: &str) -> Vec<&'a Template> {
    let pattern = pattern.to_lowercase();
    templates
        .iter()
        .filter(|t| t.id.to_lowercase().contains(&pattern))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_template() {
        let yaml = r#"
id: test-template
info:
  name: Test Template
  author: test
  severity: high
  description: A test template
  tags:
    - test
    - example

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: word
        words:
          - "admin panel"
          - "login"
        condition: or
"#;

        let template = parse_template(yaml).unwrap();
        assert_eq!(template.id, "test-template");
        assert_eq!(template.info.name, "Test Template");
        assert_eq!(template.info.severity, Severity::High);
        assert_eq!(template.http_requests.len(), 1);
        assert!(template.has_tag("test"));
    }

    #[test]
    fn test_parse_template_with_matchers() {
        let yaml = r#"
id: multi-matcher-test
info:
  name: Multi Matcher Test
  severity: medium

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "success"
      - type: regex
        regex:
          - "version[:\\s]+([0-9.]+)"
"#;

        let template = parse_template(yaml).unwrap();
        assert_eq!(template.http_requests[0].matchers.len(), 3);
        assert_eq!(
            template.http_requests[0].matchers_condition,
            MatcherCondition::And
        );
    }

    #[test]
    fn test_invalid_template_no_id() {
        let yaml = r#"
info:
  name: No ID Template
  severity: low

http:
  - method: GET
    path:
      - "/"
    matchers:
      - type: status
        status:
          - 200
"#;

        let result = parse_template(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_tcp_template() {
        let yaml = r#"
id: tcp-test
info:
  name: TCP Test
  severity: info

tcp:
  - inputs:
      - data: "HELLO\r\n"
    host:
      - "{{Hostname}}"
    matchers:
      - type: word
        words:
          - "OK"
"#;

        let template = parse_template(yaml).unwrap();
        assert_eq!(template.tcp_requests.len(), 1);
        assert_eq!(template.tcp_requests[0].inputs.len(), 1);
    }

    #[test]
    fn test_filter_by_severity() {
        let yaml1 = r#"
id: high-sev
info:
  name: High Severity
  severity: high
http:
  - path: ["/"]
    matchers:
      - type: status
        status: [200]
"#;

        let yaml2 = r#"
id: low-sev
info:
  name: Low Severity
  severity: low
http:
  - path: ["/"]
    matchers:
      - type: status
        status: [200]
"#;

        let t1 = parse_template(yaml1).unwrap();
        let t2 = parse_template(yaml2).unwrap();
        let templates = vec![t1, t2];

        let filtered = filter_by_severity(&templates, &[Severity::High]);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "high-sev");
    }
}
