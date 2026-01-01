//! Template Executor
//!
//! Executes templates against targets with parallel processing.

use super::protocols::{DnsHandler, HttpHandler, TcpHandler};
use super::types::*;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Template executor
pub struct TemplateExecutor {
    templates: Vec<Template>,
    options: ExecutionOptions,
}

impl TemplateExecutor {
    /// Create a new executor with options
    pub fn new(options: ExecutionOptions) -> Self {
        Self {
            templates: Vec::new(),
            options,
        }
    }

    /// Load templates from a directory
    pub fn load_templates(&mut self, dir: &Path) -> usize {
        let templates = super::parser::load_templates_from_dir(dir);
        let count = templates.len();
        self.templates.extend(templates);
        info!("Loaded {} templates from {:?}", count, dir);
        count
    }

    /// Add a single template
    pub fn add_template(&mut self, template: Template) {
        self.templates.push(template);
    }

    /// Add templates from YAML string
    pub fn add_from_yaml(&mut self, yaml: &str) -> Result<(), TemplateError> {
        let template = super::parser::parse_template(yaml)?;
        self.templates.push(template);
        Ok(())
    }

    /// Get loaded template count
    pub fn template_count(&self) -> usize {
        self.templates.len()
    }

    /// Filter templates by severity
    pub fn filter_by_severity(&mut self, severities: &[Severity]) {
        self.templates.retain(|t| severities.contains(&t.info.severity));
    }

    /// Filter templates by tags
    pub fn filter_by_tags(&mut self, tags: &[String]) {
        self.templates.retain(|t| tags.iter().any(|tag| t.has_tag(tag)));
    }

    /// Filter templates by IDs
    pub fn filter_by_ids(&mut self, patterns: &[String]) {
        self.templates.retain(|t| {
            patterns.iter().any(|p| {
                t.id.to_lowercase().contains(&p.to_lowercase())
            })
        });
    }

    /// Execute all templates against a single target
    pub async fn execute_target(&self, target: &str) -> Vec<TemplateResult> {
        let mut results = Vec::new();

        let http_handler = match HttpHandler::new(self.options.clone()) {
            Ok(h) => Some(h),
            Err(e) => {
                warn!("Failed to create HTTP handler: {}", e);
                None
            }
        };

        let tcp_handler = TcpHandler::new(self.options.clone());
        let dns_handler = DnsHandler::new(self.options.clone());

        for template in &self.templates {
            let template_results = self
                .execute_template(
                    template,
                    target,
                    http_handler.as_ref(),
                    &tcp_handler,
                    &dns_handler,
                )
                .await;

            results.extend(template_results);

            // Stop at first match if configured
            if template.stop_at_first_match
                && results.last().map(|r| r.matched).unwrap_or(false)
            {
                break;
            }
        }

        results
    }

    /// Execute all templates against multiple targets
    pub async fn execute_targets(&self, targets: &[String]) -> Vec<TemplateResult> {
        let semaphore = Arc::new(Semaphore::new(self.options.concurrency as usize));
        let mut handles = Vec::new();

        for target in targets {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let target = target.clone();
            let templates = self.templates.clone();
            let options = self.options.clone();

            let handle = tokio::spawn(async move {
                let executor = TemplateExecutor {
                    templates,
                    options,
                };
                let results = executor.execute_target(&target).await;
                drop(permit);
                results
            });

            handles.push(handle);
        }

        let mut all_results = Vec::new();
        for handle in handles {
            if let Ok(results) = handle.await {
                all_results.extend(results);
            }
        }

        all_results
    }

    /// Execute a single template against a target
    async fn execute_template(
        &self,
        template: &Template,
        target: &str,
        http_handler: Option<&HttpHandler>,
        tcp_handler: &TcpHandler,
        dns_handler: &DnsHandler,
    ) -> Vec<TemplateResult> {
        let mut results = Vec::new();
        let variables = self.build_variables(template, target);

        debug!("Executing template {} against {}", template.id, target);

        // Execute HTTP requests
        if let Some(handler) = http_handler {
            for request in &template.http_requests {
                match handler.execute(request, target, &variables).await {
                    Ok(req_results) => {
                        for mut result in req_results {
                            result.template_id = template.id.clone();
                            result.template_name = template.info.name.clone();
                            result.severity = template.info.severity;
                            results.push(result);
                        }
                    }
                    Err(e) => {
                        debug!("HTTP request failed for {}: {}", template.id, e);
                    }
                }
            }
        }

        // Execute TCP requests
        for request in &template.tcp_requests {
            match tcp_handler.execute(request, target, &variables).await {
                Ok(req_results) => {
                    for mut result in req_results {
                        result.template_id = template.id.clone();
                        result.template_name = template.info.name.clone();
                        result.severity = template.info.severity;
                        results.push(result);
                    }
                }
                Err(e) => {
                    debug!("TCP request failed for {}: {}", template.id, e);
                }
            }
        }

        // Execute DNS requests
        for request in &template.dns_requests {
            let dns_target = self.extract_hostname(target);
            match dns_handler.execute(request, &dns_target, &variables).await {
                Ok(req_results) => {
                    for mut result in req_results {
                        result.template_id = template.id.clone();
                        result.template_name = template.info.name.clone();
                        result.severity = template.info.severity;
                        results.push(result);
                    }
                }
                Err(e) => {
                    debug!("DNS request failed for {}: {}", template.id, e);
                }
            }
        }

        results
    }

    /// Build variables for template execution
    fn build_variables(&self, template: &Template, target: &str) -> HashMap<String, String> {
        let mut variables = HashMap::new();

        // Add template-defined variables
        for (key, value) in &template.variables {
            variables.insert(key.clone(), value.clone());
        }

        // Add target variables
        variables.insert("BaseURL".to_string(), target.to_string());
        variables.insert("Target".to_string(), target.to_string());

        // Parse target URL
        if let Ok(url) = url::Url::parse(target) {
            variables.insert(
                "Hostname".to_string(),
                url.host_str().unwrap_or("").to_string(),
            );
            variables.insert(
                "Host".to_string(),
                url.host_str().unwrap_or("").to_string(),
            );
            variables.insert(
                "Port".to_string(),
                url.port_or_known_default()
                    .map(|p| p.to_string())
                    .unwrap_or_default(),
            );
            variables.insert("Scheme".to_string(), url.scheme().to_string());
            variables.insert("Path".to_string(), url.path().to_string());

            let root = format!(
                "{}://{}",
                url.scheme(),
                url.host_str().unwrap_or("")
            );
            variables.insert("RootURL".to_string(), root);
        }

        // Add options variables
        for (key, value) in &self.options.variables {
            variables.insert(key.clone(), value.clone());
        }

        variables
    }

    /// Extract hostname from target
    fn extract_hostname(&self, target: &str) -> String {
        if let Ok(url) = url::Url::parse(target) {
            url.host_str().unwrap_or(target).to_string()
        } else {
            target.split(':').next().unwrap_or(target).to_string()
        }
    }
}

/// Scan result summary
#[derive(Debug, Clone)]
pub struct ScanSummary {
    pub total_requests: usize,
    pub matched: usize,
    pub by_severity: HashMap<Severity, usize>,
    pub duration: std::time::Duration,
}

impl ScanSummary {
    pub fn from_results(results: &[TemplateResult], duration: std::time::Duration) -> Self {
        let mut by_severity = HashMap::new();
        let matched = results.iter().filter(|r| r.matched).count();

        for result in results.iter().filter(|r| r.matched) {
            *by_severity.entry(result.severity).or_insert(0) += 1;
        }

        Self {
            total_requests: results.len(),
            matched,
            by_severity,
            duration,
        }
    }
}

/// Execute templates from a directory against targets
pub async fn scan(
    template_dir: &Path,
    targets: &[String],
    options: ExecutionOptions,
) -> (Vec<TemplateResult>, ScanSummary) {
    let start = std::time::Instant::now();

    let mut executor = TemplateExecutor::new(options);
    executor.load_templates(template_dir);

    let results = executor.execute_targets(targets).await;
    let summary = ScanSummary::from_results(&results, start.elapsed());

    (results, summary)
}

/// Quick scan with a single template YAML
pub async fn quick_scan(
    template_yaml: &str,
    target: &str,
) -> Result<Vec<TemplateResult>, TemplateError> {
    let mut executor = TemplateExecutor::new(ExecutionOptions::default());
    executor.add_from_yaml(template_yaml)?;
    Ok(executor.execute_target(target).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_creation() {
        let executor = TemplateExecutor::new(ExecutionOptions::default());
        assert_eq!(executor.template_count(), 0);
    }

    #[test]
    fn test_add_template_from_yaml() {
        let yaml = r#"
id: test
info:
  name: Test
  severity: info
http:
  - path: ["/"]
    matchers:
      - type: status
        status: [200]
"#;

        let mut executor = TemplateExecutor::new(ExecutionOptions::default());
        executor.add_from_yaml(yaml).unwrap();
        assert_eq!(executor.template_count(), 1);
    }

    #[test]
    fn test_build_variables() {
        let executor = TemplateExecutor::new(ExecutionOptions::default());
        let template = Template {
            id: "test".to_string(),
            ..Default::default()
        };

        let vars = executor.build_variables(&template, "https://example.com:8080/path");

        assert_eq!(vars.get("Hostname"), Some(&"example.com".to_string()));
        assert_eq!(vars.get("Port"), Some(&"8080".to_string()));
        assert_eq!(vars.get("Scheme"), Some(&"https".to_string()));
    }
}
