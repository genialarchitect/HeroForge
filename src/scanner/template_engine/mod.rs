//! Native Vulnerability Template Engine
//!
//! A Nuclei-compatible template engine for vulnerability scanning.
//! Supports HTTP, TCP, and DNS protocols with powerful matching capabilities.
//!
//! ## Features
//!
//! - **YAML Templates**: Nuclei-compatible template format
//! - **Multiple Protocols**: HTTP, TCP, DNS request support
//! - **Powerful Matching**: Word, regex, binary, status, size, DSL matchers
//! - **Variable Substitution**: Dynamic payloads with template variables
//! - **Parallel Execution**: Concurrent scanning with configurable limits
//! - **Extractors**: Capture data from responses for chained requests
//!
//! ## Example
//!
//! ```rust,ignore
//! use heroforge::scanner::template_engine::{TemplateExecutor, ExecutionOptions, quick_scan};
//!
//! // Quick scan with inline template
//! let yaml = r#"
//! id: example-check
//! info:
//!   name: Example Check
//!   severity: info
//! http:
//!   - path: ["/"]
//!     matchers:
//!       - type: status
//!         status: [200]
//! "#;
//!
//! let results = quick_scan(yaml, "https://example.com").await?;
//!
//! // Or use the executor for multiple templates
//! let mut executor = TemplateExecutor::new(ExecutionOptions::default());
//! executor.load_templates(Path::new("./templates"));
//! let results = executor.execute_targets(&["https://target1.com".to_string()]).await;
//! ```

pub mod types;
pub mod parser;
pub mod matcher;
pub mod protocols;
pub mod executor;

pub use types::*;
pub use parser::parse_template;
pub use executor::{TemplateExecutor, quick_scan};

use crate::types::HostInfo;
use log::{info, warn};
use std::path::Path;

/// Scan a host using templates from a directory
pub async fn scan_host_with_templates(
    host: &HostInfo,
    template_dir: &Path,
    options: Option<ExecutionOptions>,
) -> Vec<TemplateResult> {
    let options = options.unwrap_or_default();

    // Build target URL from host info
    let target = build_target_url(host);

    info!("Scanning {} with templates from {:?}", target, template_dir);

    let mut executor = TemplateExecutor::new(options);
    let loaded = executor.load_templates(template_dir);

    if loaded == 0 {
        warn!("No templates loaded from {:?}", template_dir);
        return Vec::new();
    }

    executor.execute_target(&target).await
}

/// Scan multiple hosts with templates
pub async fn scan_hosts_with_templates(
    hosts: &[HostInfo],
    template_dir: &Path,
    options: Option<ExecutionOptions>,
) -> Vec<TemplateResult> {
    let options = options.unwrap_or_default();

    let targets: Vec<String> = hosts.iter().map(build_target_url).collect();

    info!("Scanning {} hosts with templates from {:?}", targets.len(), template_dir);

    let mut executor = TemplateExecutor::new(options);
    let loaded = executor.load_templates(template_dir);

    if loaded == 0 {
        warn!("No templates loaded from {:?}", template_dir);
        return Vec::new();
    }

    executor.execute_targets(&targets).await
}

/// Run a single template against a target
pub async fn run_template(
    template_yaml: &str,
    target: &str,
) -> Result<Vec<TemplateResult>, TemplateError> {
    quick_scan(template_yaml, target).await
}

/// Run a single template against multiple targets
pub async fn run_template_against_targets(
    template_yaml: &str,
    targets: &[String],
    options: Option<ExecutionOptions>,
) -> Result<Vec<TemplateResult>, TemplateError> {
    let options = options.unwrap_or_default();
    let mut executor = TemplateExecutor::new(options);
    executor.add_from_yaml(template_yaml)?;
    Ok(executor.execute_targets(targets).await)
}

/// Build target URL from host info
fn build_target_url(host: &HostInfo) -> String {
    // Try to find HTTP/HTTPS ports
    let http_port = host.ports.iter().find(|p| {
        p.service.as_ref().map(|s| s.name.contains("http")).unwrap_or(false)
            || p.port == 80
            || p.port == 443
            || p.port == 8080
            || p.port == 8443
    });

    if let Some(port) = http_port {
        let scheme = if port.port == 443 || port.port == 8443 {
            "https"
        } else {
            "http"
        };

        if (scheme == "http" && port.port == 80) || (scheme == "https" && port.port == 443) {
            format!("{}://{}", scheme, host.target.ip)
        } else {
            format!("{}://{}:{}", scheme, host.target.ip, port.port)
        }
    } else {
        // Default to HTTP on standard port
        format!("http://{}", host.target.ip)
    }
}

/// Vulnerability findings from template results
#[derive(Debug, Clone)]
pub struct TemplateFinding {
    pub template_id: String,
    pub template_name: String,
    pub severity: Severity,
    pub target: String,
    pub matched_at: String,
    pub matcher_name: Option<String>,
    pub extracted_data: std::collections::HashMap<String, Vec<String>>,
    pub curl_command: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl From<TemplateResult> for TemplateFinding {
    fn from(result: TemplateResult) -> Self {
        Self {
            template_id: result.template_id,
            template_name: result.template_name,
            severity: result.severity,
            target: result.request_url.unwrap_or_else(|| result.matched_at.clone()),
            matched_at: result.matched_at,
            matcher_name: result.matcher_name,
            extracted_data: result.extracted,
            curl_command: result.curl_command,
            timestamp: result.timestamp,
        }
    }
}

/// Convert template results to findings (only matched results)
pub fn results_to_findings(results: Vec<TemplateResult>) -> Vec<TemplateFinding> {
    results
        .into_iter()
        .filter(|r| r.matched)
        .map(TemplateFinding::from)
        .collect()
}

/// Group findings by severity
pub fn group_by_severity(findings: &[TemplateFinding]) -> std::collections::HashMap<Severity, Vec<&TemplateFinding>> {
    let mut grouped = std::collections::HashMap::new();

    for finding in findings {
        grouped
            .entry(finding.severity)
            .or_insert_with(Vec::new)
            .push(finding);
    }

    grouped
}

/// Template validation result
#[derive(Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Validate a template YAML
pub fn validate_template(yaml: &str) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    match parse_template(yaml) {
        Ok(template) => {
            // Check for required fields
            if template.id.is_empty() {
                errors.push("Template ID is required".to_string());
            }

            if template.info.name.is_empty() {
                errors.push("Template name is required".to_string());
            }

            // Check for at least one request type
            if template.http_requests.is_empty()
                && template.tcp_requests.is_empty()
                && template.dns_requests.is_empty()
            {
                errors.push("Template must have at least one request (http, tcp, or dns)".to_string());
            }

            // Check HTTP requests have matchers
            for (i, req) in template.http_requests.iter().enumerate() {
                if req.matchers.is_empty() {
                    warnings.push(format!("HTTP request {} has no matchers", i + 1));
                }

                if req.path.is_empty() && req.raw.is_empty() {
                    errors.push(format!("HTTP request {} has no path or raw request", i + 1));
                }
            }

            // Check TCP requests
            for (i, req) in template.tcp_requests.iter().enumerate() {
                if req.matchers.is_empty() {
                    warnings.push(format!("TCP request {} has no matchers", i + 1));
                }
            }

            // Check DNS requests
            for (i, req) in template.dns_requests.iter().enumerate() {
                if req.name.is_empty() {
                    errors.push(format!("DNS request {} has no name", i + 1));
                }
            }

            ValidationResult {
                valid: errors.is_empty(),
                errors,
                warnings,
            }
        }
        Err(e) => {
            errors.push(format!("Parse error: {}", e));
            ValidationResult {
                valid: false,
                errors,
                warnings,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_template_valid() {
        let yaml = r#"
id: test-template
info:
  name: Test Template
  severity: info
http:
  - path: ["/"]
    matchers:
      - type: status
        status: [200]
"#;

        let result = validate_template(yaml);
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validate_template_missing_id() {
        let yaml = r#"
info:
  name: Test Template
  severity: info
http:
  - path: ["/"]
    matchers:
      - type: status
        status: [200]
"#;

        let result = validate_template(yaml);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("ID")));
    }

    #[test]
    fn test_validate_template_no_requests() {
        let yaml = r#"
id: test-template
info:
  name: Test Template
  severity: info
"#;

        let result = validate_template(yaml);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("at least one request")));
    }

    #[test]
    fn test_build_target_url() {
        use crate::types::{PortInfo, ScanTarget, Protocol, PortState, ServiceInfo};

        let host = HostInfo {
            target: ScanTarget {
                ip: "192.168.1.1".parse().unwrap(),
                hostname: None,
            },
            is_alive: true,
            os_guess: None,
            ports: vec![
                PortInfo {
                    port: 80,
                    protocol: Protocol::TCP,
                    state: PortState::Open,
                    service: Some(ServiceInfo {
                        name: "http".to_string(),
                        version: None,
                        banner: None,
                        cpe: None,
                        enumeration: None,
                        ssl_info: None,
                    }),
                }
            ],
            vulnerabilities: Vec::new(),
            scan_duration: std::time::Duration::from_secs(0),
        };

        assert_eq!(build_target_url(&host), "http://192.168.1.1");
    }

    #[test]
    fn test_build_target_url_https() {
        use crate::types::{PortInfo, ScanTarget, Protocol, PortState, ServiceInfo};

        let host = HostInfo {
            target: ScanTarget {
                ip: "192.168.1.1".parse().unwrap(),
                hostname: None,
            },
            is_alive: true,
            os_guess: None,
            ports: vec![
                PortInfo {
                    port: 443,
                    protocol: Protocol::TCP,
                    state: PortState::Open,
                    service: Some(ServiceInfo {
                        name: "https".to_string(),
                        version: None,
                        banner: None,
                        cpe: None,
                        enumeration: None,
                        ssl_info: None,
                    }),
                }
            ],
            vulnerabilities: Vec::new(),
            scan_duration: std::time::Duration::from_secs(0),
        };

        assert_eq!(build_target_url(&host), "https://192.168.1.1");
    }
}
