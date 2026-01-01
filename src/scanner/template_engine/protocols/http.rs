//! HTTP Protocol Handler
//!
//! Executes HTTP-based template requests.

use crate::scanner::template_engine::matcher::{execute_matchers, ResponseData};
use crate::scanner::template_engine::types::*;
use log::{debug, trace};
use reqwest::{Client, Method, Proxy, Response};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// HTTP protocol handler
pub struct HttpHandler {
    client: Client,
    options: ExecutionOptions,
}

impl HttpHandler {
    /// Create a new HTTP handler
    pub fn new(options: ExecutionOptions) -> Result<Self, TemplateError> {
        let mut builder = Client::builder()
            .timeout(options.timeout)
            .danger_accept_invalid_certs(true)
            .redirect(if options.follow_redirects {
                reqwest::redirect::Policy::limited(options.max_redirects as usize)
            } else {
                reqwest::redirect::Policy::none()
            });

        if let Some(ref proxy_url) = options.proxy {
            let proxy = Proxy::all(proxy_url)
                .map_err(|e| TemplateError::Network(format!("Invalid proxy: {}", e)))?;
            builder = builder.proxy(proxy);
        }

        let client = builder
            .build()
            .map_err(|e| TemplateError::Network(e.to_string()))?;

        Ok(Self { client, options })
    }

    /// Execute an HTTP request from template
    pub async fn execute(
        &self,
        request: &HttpRequest,
        base_url: &str,
        variables: &HashMap<String, String>,
    ) -> Result<Vec<TemplateResult>, TemplateError> {
        let mut results = Vec::new();

        // Handle raw requests
        if !request.raw.is_empty() {
            for raw in &request.raw {
                let result = self.execute_raw(raw, base_url, request, variables).await?;
                results.push(result);

                if request.stop_at_first_match && results.last().map(|r| r.matched).unwrap_or(false)
                {
                    break;
                }
            }
            return Ok(results);
        }

        // Handle path-based requests
        for path in &request.path {
            let url = self.build_url(base_url, path, variables);
            let result = self
                .execute_request(&url, request, variables)
                .await?;
            results.push(result);

            if request.stop_at_first_match && results.last().map(|r| r.matched).unwrap_or(false) {
                break;
            }
        }

        Ok(results)
    }

    /// Execute a single HTTP request
    async fn execute_request(
        &self,
        url: &str,
        request: &HttpRequest,
        variables: &HashMap<String, String>,
    ) -> Result<TemplateResult, TemplateError> {
        let start = Instant::now();

        let method = self.to_reqwest_method(request.method);
        let mut req_builder = self.client.request(method.clone(), url);

        // Add headers
        for (key, value) in &request.headers {
            let value = self.substitute_variables(value, variables);
            req_builder = req_builder.header(key, value);
        }

        // Add default headers from options
        for (key, value) in &self.options.headers {
            req_builder = req_builder.header(key, value);
        }

        // Add body if present
        if let Some(ref body) = request.body {
            let body = self.substitute_variables(body, variables);
            req_builder = req_builder.body(body);
        }

        debug!("Executing {} {}", method, url);

        let response = req_builder
            .send()
            .await
            .map_err(|e| TemplateError::Http(e.to_string()))?;

        let elapsed = start.elapsed();
        let status = response.status().as_u16();

        // Collect response data
        let response_data = self.collect_response(response).await?;

        // Execute matchers
        let match_result = execute_matchers(
            &request.matchers,
            request.matchers_condition,
            &response_data,
        );

        // Build result
        let mut result = TemplateResult {
            template_id: String::new(), // Will be filled by executor
            template_name: String::new(),
            severity: Severity::Unknown,
            matched: match_result.matched,
            extracted: HashMap::new(),
            matched_at: url.to_string(),
            matcher_name: match_result.matcher_name,
            request_url: Some(url.to_string()),
            request_method: Some(method.to_string()),
            response_status: Some(status),
            response_time: elapsed,
            curl_command: Some(self.generate_curl(url, request, variables)),
            timestamp: chrono::Utc::now(),
        };

        // Execute extractors
        for extractor in &request.extractors {
            if let Some(name) = &extractor.name {
                let values = self.extract(&extractor, &response_data);
                if !values.is_empty() {
                    result.extracted.insert(name.clone(), values);
                }
            }
        }

        Ok(result)
    }

    /// Execute a raw HTTP request
    async fn execute_raw(
        &self,
        raw: &str,
        base_url: &str,
        request: &HttpRequest,
        variables: &HashMap<String, String>,
    ) -> Result<TemplateResult, TemplateError> {
        let raw = self.substitute_variables(raw, variables);

        // Parse raw HTTP request
        let lines: Vec<&str> = raw.lines().collect();
        if lines.is_empty() {
            return Err(TemplateError::Validation("Empty raw request".to_string()));
        }

        // Parse request line
        let first_line: Vec<&str> = lines[0].split_whitespace().collect();
        if first_line.len() < 2 {
            return Err(TemplateError::Validation(
                "Invalid raw request line".to_string(),
            ));
        }

        let method = first_line[0];
        let path = first_line[1];

        // Build URL
        let url = if path.starts_with("http") {
            path.to_string()
        } else {
            self.build_url(base_url, path, variables)
        };

        // Parse headers
        let mut headers = HashMap::new();
        let mut body_start = None;

        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.is_empty() {
                body_start = Some(i + 1);
                break;
            }

            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        // Extract body
        let body = body_start.map(|start| lines[start..].join("\n"));

        let start = Instant::now();

        let method = Method::from_bytes(method.as_bytes())
            .map_err(|e| TemplateError::Validation(format!("Invalid method: {}", e)))?;

        let mut req_builder = self.client.request(method.clone(), &url);

        for (key, value) in &headers {
            req_builder = req_builder.header(key, value);
        }

        if let Some(body) = body {
            req_builder = req_builder.body(body);
        }

        debug!("Executing raw {} {}", method, url);

        let response = req_builder
            .send()
            .await
            .map_err(|e| TemplateError::Http(e.to_string()))?;

        let elapsed = start.elapsed();
        let status = response.status().as_u16();

        let response_data = self.collect_response(response).await?;

        let match_result = execute_matchers(
            &request.matchers,
            request.matchers_condition,
            &response_data,
        );

        Ok(TemplateResult {
            template_id: String::new(),
            template_name: String::new(),
            severity: Severity::Unknown,
            matched: match_result.matched,
            extracted: HashMap::new(),
            matched_at: url.to_string(),
            matcher_name: match_result.matcher_name,
            request_url: Some(url),
            request_method: Some(method.to_string()),
            response_status: Some(status),
            response_time: elapsed,
            curl_command: None,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Collect response data
    async fn collect_response(&self, response: Response) -> Result<ResponseData, TemplateError> {
        let status = response.status().as_u16();

        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = response
            .text()
            .await
            .map_err(|e| TemplateError::Http(e.to_string()))?;

        Ok(ResponseData::new(status, headers, body))
    }

    /// Extract values using extractor
    fn extract(&self, extractor: &Extractor, response: &ResponseData) -> Vec<String> {
        let content = response.get_part(&extractor.part);
        let mut values = Vec::new();

        match extractor.extractor_type {
            ExtractorType::Regex => {
                for pattern in &extractor.regex {
                    let regex = if extractor.case_insensitive {
                        regex::Regex::new(&format!("(?i){}", pattern))
                    } else {
                        regex::Regex::new(pattern)
                    };

                    if let Ok(re) = regex {
                        for caps in re.captures_iter(content) {
                            let group = extractor.group.unwrap_or(0);
                            if let Some(m) = caps.get(group) {
                                values.push(m.as_str().to_string());
                            }
                        }
                    }
                }
            }
            ExtractorType::Kval => {
                for key in &extractor.kval {
                    if let Some(value) = response.headers.get(key) {
                        values.push(value.clone());
                    }
                }
            }
            ExtractorType::Json => {
                for path in &extractor.json {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
                        if let Some(value) = json.pointer(path) {
                            values.push(value.to_string().trim_matches('"').to_string());
                        }
                    }
                }
            }
            _ => {}
        }

        values
    }

    /// Build URL from base and path
    fn build_url(
        &self,
        base_url: &str,
        path: &str,
        variables: &HashMap<String, String>,
    ) -> String {
        let path = self.substitute_variables(path, variables);

        // Handle {{BaseURL}} placeholder
        if path.contains("{{BaseURL}}") {
            return path.replace("{{BaseURL}}", base_url);
        }

        // Handle {{RootURL}} placeholder
        if path.contains("{{RootURL}}") {
            if let Ok(url) = url::Url::parse(base_url) {
                let root = format!("{}://{}", url.scheme(), url.host_str().unwrap_or(""));
                return path.replace("{{RootURL}}", &root);
            }
        }

        // Handle {{Hostname}} placeholder
        if path.contains("{{Hostname}}") {
            if let Ok(url) = url::Url::parse(base_url) {
                let hostname = url.host_str().unwrap_or("");
                return path.replace("{{Hostname}}", hostname);
            }
        }

        // Append path to base URL
        if path.starts_with('/') {
            format!("{}{}", base_url.trim_end_matches('/'), path)
        } else {
            format!("{}/{}", base_url.trim_end_matches('/'), path)
        }
    }

    /// Substitute variables in a string
    fn substitute_variables(&self, input: &str, variables: &HashMap<String, String>) -> String {
        let mut result = input.to_string();

        // Substitute template variables
        for (key, value) in variables {
            result = result.replace(&format!("{{{{{}}}}}", key), value);
        }

        // Substitute options variables
        for (key, value) in &self.options.variables {
            result = result.replace(&format!("{{{{{}}}}}", key), value);
        }

        result
    }

    /// Convert to reqwest Method
    fn to_reqwest_method(&self, method: HttpMethod) -> Method {
        match method {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
            HttpMethod::Put => Method::PUT,
            HttpMethod::Delete => Method::DELETE,
            HttpMethod::Patch => Method::PATCH,
            HttpMethod::Head => Method::HEAD,
            HttpMethod::Options => Method::OPTIONS,
            HttpMethod::Connect => Method::CONNECT,
            HttpMethod::Trace => Method::TRACE,
        }
    }

    /// Generate curl command for debugging
    fn generate_curl(
        &self,
        url: &str,
        request: &HttpRequest,
        variables: &HashMap<String, String>,
    ) -> String {
        let mut parts = vec!["curl".to_string()];

        // Method
        match request.method {
            HttpMethod::Get => {}
            _ => {
                parts.push("-X".to_string());
                parts.push(request.method.to_string());
            }
        }

        // Headers
        for (key, value) in &request.headers {
            let value = self.substitute_variables(value, variables);
            parts.push("-H".to_string());
            parts.push(format!("'{}: {}'", key, value));
        }

        // Body
        if let Some(ref body) = request.body {
            let body = self.substitute_variables(body, variables);
            parts.push("-d".to_string());
            parts.push(format!("'{}'", body));
        }

        // URL
        parts.push(format!("'{}'", url));

        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_url_with_base_url() {
        let handler = HttpHandler::new(ExecutionOptions::default()).unwrap();
        let variables = HashMap::new();

        let url = handler.build_url("https://example.com", "{{BaseURL}}/admin", &variables);
        assert_eq!(url, "https://example.com/admin");
    }

    #[test]
    fn test_build_url_with_path() {
        let handler = HttpHandler::new(ExecutionOptions::default()).unwrap();
        let variables = HashMap::new();

        let url = handler.build_url("https://example.com", "/api/v1/users", &variables);
        assert_eq!(url, "https://example.com/api/v1/users");
    }

    #[test]
    fn test_substitute_variables() {
        let handler = HttpHandler::new(ExecutionOptions::default()).unwrap();
        let mut variables = HashMap::new();
        variables.insert("user".to_string(), "admin".to_string());
        variables.insert("pass".to_string(), "secret".to_string());

        let result = handler.substitute_variables(
            "username={{user}}&password={{pass}}",
            &variables,
        );
        assert_eq!(result, "username=admin&password=secret");
    }
}
