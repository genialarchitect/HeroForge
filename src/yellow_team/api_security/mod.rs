//! API Security Scanner
//!
//! Analyzes OpenAPI/Swagger and GraphQL specifications for security issues
//! including authentication, authorization, injection vulnerabilities, and
//! API design best practices.

pub mod openapi_parser;
pub mod auth_analyzer;
pub mod rate_limit_checker;
pub mod injection_detector;

use crate::yellow_team::types::*;
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use uuid::Uuid;

/// API Security Scanner
pub struct ApiSecurityScanner {
    /// Scan configuration
    pub config: ApiScanConfig,
    /// Findings from the scan
    pub findings: Vec<ApiSecurityFinding>,
}

/// API Scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiScanConfig {
    /// Check for authentication issues
    pub check_auth: bool,
    /// Check for rate limiting
    pub check_rate_limits: bool,
    /// Check for injection vulnerabilities
    pub check_injections: bool,
    /// Check for sensitive data exposure
    pub check_sensitive_data: bool,
    /// Check for security headers
    pub check_security_headers: bool,
    /// Custom security rules
    pub custom_rules: Vec<ApiSecurityRule>,
}

impl Default for ApiScanConfig {
    fn default() -> Self {
        Self {
            check_auth: true,
            check_rate_limits: true,
            check_injections: true,
            check_sensitive_data: true,
            check_security_headers: true,
            custom_rules: Vec::new(),
        }
    }
}

/// Custom API security rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSecurityRule {
    /// Rule ID
    pub id: String,
    /// Rule name
    pub name: String,
    /// Pattern to match (endpoint, parameter, etc.)
    pub pattern: String,
    /// What to check (endpoint, parameter, header, response)
    pub check_type: ApiCheckType,
    /// Severity if matched
    pub severity: Severity,
    /// Description/message
    pub message: String,
}

/// What to check in the API
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiCheckType {
    Endpoint,
    Parameter,
    Header,
    RequestBody,
    Response,
    Schema,
}

impl ApiSecurityScanner {
    /// Create a new scanner with default config
    pub fn new() -> Self {
        Self {
            config: ApiScanConfig::default(),
            findings: Vec::new(),
        }
    }

    /// Create a new scanner with custom config
    pub fn with_config(config: ApiScanConfig) -> Self {
        Self {
            config,
            findings: Vec::new(),
        }
    }

    /// Scan an OpenAPI specification
    pub fn scan_openapi(&mut self, spec: &str, spec_format: ApiSpecFormat) -> Result<Vec<ApiSecurityFinding>, Box<dyn std::error::Error + Send + Sync>> {
        let parsed: serde_json::Value = match spec_format {
            ApiSpecFormat::OpenApi3 | ApiSpecFormat::OpenApi2 | ApiSpecFormat::Swagger2 => {
                // Try JSON first, then YAML
                serde_json::from_str(spec)
                    .or_else(|_| serde_yaml::from_str::<serde_json::Value>(spec).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>))?
            }
            ApiSpecFormat::GraphQL => {
                // GraphQL schema - different analysis
                return self.scan_graphql(spec);
            }
            ApiSpecFormat::AsyncApi | ApiSpecFormat::Raml | ApiSpecFormat::Wadl => {
                serde_json::from_str(spec)
                    .or_else(|_| serde_yaml::from_str::<serde_json::Value>(spec).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>))?
            }
            ApiSpecFormat::Unknown => {
                // Try to parse as JSON/YAML
                serde_json::from_str(spec)
                    .or_else(|_| serde_yaml::from_str::<serde_json::Value>(spec).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>))?
            }
        };

        // Check security schemes
        if self.config.check_auth {
            self.check_security_schemes(&parsed);
        }

        // Check paths/endpoints
        if let Some(paths) = parsed.get("paths").and_then(|p| p.as_object()) {
            for (path, path_item) in paths {
                self.analyze_path(path, path_item);
            }
        }

        // Check for global security requirements
        if self.config.check_auth {
            self.check_global_security(&parsed);
        }

        // Check components/definitions for sensitive data
        if self.config.check_sensitive_data {
            self.check_schemas(&parsed);
        }

        // Check servers for HTTPS
        self.check_servers(&parsed);

        Ok(self.findings.clone())
    }

    /// Scan a GraphQL schema
    fn scan_graphql(&mut self, schema: &str) -> Result<Vec<ApiSecurityFinding>, Box<dyn std::error::Error + Send + Sync>> {
        // Check for introspection queries
        if !schema.contains("introspection: false") && !schema.contains("introspectionDisabled") {
            self.add_finding(
                "/graphql",
                "GET",
                ApiSecurityFindingType::SecurityMisconfiguration,
                Severity::Medium,
                "GraphQL introspection appears to be enabled",
                "Disable introspection in production to prevent schema disclosure",
            );
        }

        // Check for query depth limiting
        if !schema.contains("maxDepth") && !schema.contains("depthLimit") {
            self.add_finding(
                "/graphql",
                "POST",
                ApiSecurityFindingType::MissingRateLimit,
                Severity::Medium,
                "No query depth limiting detected",
                "Implement query depth limiting to prevent denial of service attacks",
            );
        }

        // Check for query complexity limiting
        if !schema.contains("maxComplexity") && !schema.contains("complexityLimit") {
            self.add_finding(
                "/graphql",
                "POST",
                ApiSecurityFindingType::MissingRateLimit,
                Severity::Medium,
                "No query complexity limiting detected",
                "Implement query complexity analysis to prevent resource exhaustion",
            );
        }

        // Check for sensitive types
        let sensitive_patterns = [
            (r"type\s+Password", "Password type exposed in schema"),
            (r"type\s+Secret", "Secret type exposed in schema"),
            (r"type\s+ApiKey", "API Key type exposed in schema"),
            (r"field\s+password\s*:", "Password field in query type"),
            (r"field\s+token\s*:", "Token field in query type"),
        ];

        for (pattern, message) in sensitive_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(schema) {
                    self.add_finding(
                        "/graphql",
                        "POST",
                        ApiSecurityFindingType::SensitiveDataExposure,
                        Severity::High,
                        message,
                        "Review schema and remove or protect sensitive data types",
                    );
                }
            }
        }

        // Check for mutation validation
        if schema.contains("Mutation") {
            if !schema.contains("@auth") && !schema.contains("@authenticated") {
                self.add_finding(
                    "/graphql",
                    "POST",
                    ApiSecurityFindingType::MissingAuthentication,
                    Severity::Medium,
                    "Mutations do not appear to have authentication directives",
                    "Add authentication requirements to mutation resolvers",
                );
            }
        }

        Ok(self.findings.clone())
    }

    /// Check security schemes defined in the spec
    fn check_security_schemes(&mut self, spec: &serde_json::Value) {
        let security_schemes = spec
            .get("components")
            .and_then(|c| c.get("securitySchemes"))
            .or_else(|| spec.get("securityDefinitions"));

        match security_schemes {
            None => {
                self.add_finding(
                    "/",
                    "*",
                    ApiSecurityFindingType::MissingAuthentication,
                    Severity::High,
                    "No security schemes defined in API specification",
                    "Define authentication mechanisms (OAuth2, API Key, JWT, etc.)",
                );
            }
            Some(schemes) => {
                if let Some(obj) = schemes.as_object() {
                    for (name, scheme) in obj {
                        self.analyze_security_scheme(name, scheme);
                    }
                }
            }
        }
    }

    /// Analyze a security scheme
    fn analyze_security_scheme(&mut self, name: &str, scheme: &serde_json::Value) {
        let scheme_type = scheme.get("type").and_then(|t| t.as_str()).unwrap_or("");

        match scheme_type {
            "http" => {
                let scheme_name = scheme.get("scheme").and_then(|s| s.as_str()).unwrap_or("");
                if scheme_name == "basic" {
                    self.add_finding(
                        "/",
                        "*",
                        ApiSecurityFindingType::WeakAuthentication,
                        Severity::Medium,
                        &format!("Security scheme '{}' uses Basic authentication", name),
                        "Consider using more secure authentication methods like OAuth2 or JWT",
                    );
                }
            }
            "apiKey" => {
                let in_location = scheme.get("in").and_then(|i| i.as_str()).unwrap_or("");
                if in_location == "query" {
                    self.add_finding(
                        "/",
                        "*",
                        ApiSecurityFindingType::SensitiveDataExposure,
                        Severity::Medium,
                        &format!("API key '{}' is passed in query string", name),
                        "Pass API keys in headers instead of query strings to avoid logging exposure",
                    );
                }
            }
            "oauth2" => {
                // Check for proper scopes
                if let Some(flows) = scheme.get("flows").and_then(|f| f.as_object()) {
                    for (flow_name, flow) in flows {
                        if flow.get("scopes").and_then(|s| s.as_object()).map(|s| s.is_empty()).unwrap_or(true) {
                            self.add_finding(
                                "/",
                                "*",
                                ApiSecurityFindingType::WeakAuthentication,
                                Severity::Low,
                                &format!("OAuth2 flow '{}' has no scopes defined", flow_name),
                                "Define granular scopes for proper authorization control",
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Check global security requirements
    fn check_global_security(&mut self, spec: &serde_json::Value) {
        let global_security = spec.get("security");
        
        match global_security {
            None => {
                self.add_finding(
                    "/",
                    "*",
                    ApiSecurityFindingType::MissingAuthentication,
                    Severity::Medium,
                    "No global security requirements defined",
                    "Add global security requirements or ensure each endpoint has security defined",
                );
            }
            Some(sec) if sec.as_array().map(|a| a.is_empty()).unwrap_or(true) => {
                self.add_finding(
                    "/",
                    "*",
                    ApiSecurityFindingType::MissingAuthentication,
                    Severity::Medium,
                    "Global security requirements are empty",
                    "Define security requirements for API access",
                );
            }
            _ => {}
        }
    }

    /// Analyze an API path
    fn analyze_path(&mut self, path: &str, path_item: &serde_json::Value) {
        let methods = ["get", "post", "put", "patch", "delete", "options", "head"];
        
        for method in methods {
            if let Some(operation) = path_item.get(method) {
                self.analyze_operation(path, method, operation);
            }
        }
    }

    /// Analyze an API operation
    fn analyze_operation(&mut self, path: &str, method: &str, operation: &serde_json::Value) {
        // Check for security requirements
        if self.config.check_auth {
            let has_security = operation.get("security").is_some();
            
            // Check if it's a public endpoint pattern
            let is_public_pattern = path.contains("/public/") 
                || path.contains("/health") 
                || path.contains("/version")
                || path.contains("/docs");
            
            if !has_security && !is_public_pattern {
                // Check for sensitive operations
                if method == "post" || method == "put" || method == "patch" || method == "delete" {
                    self.add_finding(
                        path,
                        method,
                        ApiSecurityFindingType::MissingAuthentication,
                        Severity::High,
                        &format!("{} {} has no security requirements", method.to_uppercase(), path),
                        "Add authentication requirements for state-changing operations",
                    );
                }
            }
        }

        // Check parameters
        if let Some(params) = operation.get("parameters").and_then(|p| p.as_array()) {
            for param in params {
                self.analyze_parameter(path, method, param);
            }
        }

        // Check request body
        if let Some(body) = operation.get("requestBody") {
            self.analyze_request_body(path, method, body);
        }

        // Check responses
        if let Some(responses) = operation.get("responses").and_then(|r| r.as_object()) {
            for (status, response) in responses {
                self.analyze_response(path, method, status, response);
            }
        }
    }

    /// Analyze a parameter
    fn analyze_parameter(&mut self, path: &str, method: &str, param: &serde_json::Value) {
        let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let in_location = param.get("in").and_then(|i| i.as_str()).unwrap_or("");
        
        // Check for sensitive parameters in query string
        if in_location == "query" && self.config.check_sensitive_data {
            let sensitive_names = ["password", "token", "secret", "key", "apikey", "api_key", "credential", "auth"];
            let lower_name = name.to_lowercase();
            
            for sensitive in sensitive_names {
                if lower_name.contains(sensitive) {
                    self.add_finding(
                        path,
                        method,
                        ApiSecurityFindingType::SensitiveDataExposure,
                        Severity::High,
                        &format!("Sensitive parameter '{}' passed in query string", name),
                        "Move sensitive parameters to headers or request body",
                    );
                }
            }
        }

        // Check for injection patterns
        if self.config.check_injections {
            let param_schema = param.get("schema");
            let param_type = param_schema
                .and_then(|s| s.get("type"))
                .and_then(|t| t.as_str())
                .unwrap_or("");
            
            // Check for SQL injection risk (numeric IDs without pattern)
            if param_type == "string" && (name.ends_with("_id") || name.ends_with("Id")) {
                if param_schema.and_then(|s| s.get("pattern")).is_none() {
                    self.add_finding(
                        path,
                        method,
                        ApiSecurityFindingType::InjectionRisk,
                        Severity::Low,
                        &format!("ID parameter '{}' lacks input validation pattern", name),
                        "Add a regex pattern to validate ID format",
                    );
                }
            }
        }
    }

    /// Analyze request body
    fn analyze_request_body(&mut self, path: &str, method: &str, body: &serde_json::Value) {
        if let Some(content) = body.get("content").and_then(|c| c.as_object()) {
            for (media_type, schema) in content {
                // Check for XML which can be vulnerable to XXE
                if media_type.contains("xml") {
                    self.add_finding(
                        path,
                        method,
                        ApiSecurityFindingType::InjectionRisk,
                        Severity::Medium,
                        "Endpoint accepts XML content which may be vulnerable to XXE",
                        "Ensure XML parser is configured to prevent XXE attacks",
                    );
                }
            }
        }
    }

    /// Analyze response
    fn analyze_response(&mut self, path: &str, method: &str, status: &str, response: &serde_json::Value) {
        // Check for sensitive data in responses
        if let Some(content) = response.get("content").and_then(|c| c.as_object()) {
            for (_, media_schema) in content {
                if let Some(schema) = media_schema.get("schema") {
                    self.check_schema_for_sensitive_data(path, method, schema);
                }
            }
        }

        // Check for verbose error responses
        if status.starts_with('4') || status.starts_with('5') {
            if let Some(desc) = response.get("description").and_then(|d| d.as_str()) {
                if desc.contains("stack") || desc.contains("trace") || desc.contains("debug") {
                    self.add_finding(
                        path,
                        method,
                        ApiSecurityFindingType::ExcessiveDataExposure,
                        Severity::Medium,
                        &format!("Error response {} may expose sensitive debugging information", status),
                        "Ensure error responses don't leak implementation details",
                    );
                }
            }
        }
    }

    /// Check schema for sensitive data exposure
    fn check_schema_for_sensitive_data(&mut self, path: &str, method: &str, schema: &serde_json::Value) {
        if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
            let sensitive_fields = ["password", "secret", "token", "key", "ssn", "creditCard", "credit_card"];
            
            for (prop_name, _) in properties {
                let lower_name = prop_name.to_lowercase();
                for sensitive in sensitive_fields {
                    if lower_name.contains(sensitive) {
                        self.add_finding(
                            path,
                            method,
                            ApiSecurityFindingType::SensitiveDataExposure,
                            Severity::High,
                            &format!("Response may expose sensitive field: {}", prop_name),
                            "Ensure sensitive fields are excluded from API responses or properly masked",
                        );
                    }
                }
            }
        }
    }

    /// Check for schemas/definitions with sensitive data
    fn check_schemas(&mut self, spec: &serde_json::Value) {
        let schemas = spec
            .get("components")
            .and_then(|c| c.get("schemas"))
            .or_else(|| spec.get("definitions"));

        if let Some(schemas_obj) = schemas.and_then(|s| s.as_object()) {
            for (schema_name, schema) in schemas_obj {
                if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
                    // Check for passwords in user schemas
                    if schema_name.to_lowercase().contains("user") {
                        if properties.contains_key("password") || properties.contains_key("passwordHash") {
                            self.add_finding(
                                &format!("#/components/schemas/{}", schema_name),
                                "SCHEMA",
                                ApiSecurityFindingType::SensitiveDataExposure,
                                Severity::High,
                                &format!("Schema '{}' contains password field", schema_name),
                                "Ensure password fields are write-only and never returned in responses",
                            );
                        }
                    }
                }
            }
        }
    }

    /// Check servers configuration
    fn check_servers(&mut self, spec: &serde_json::Value) {
        if let Some(servers) = spec.get("servers").and_then(|s| s.as_array()) {
            for server in servers {
                if let Some(url) = server.get("url").and_then(|u| u.as_str()) {
                    if url.starts_with("http://") && !url.contains("localhost") && !url.contains("127.0.0.1") {
                        self.add_finding(
                            url,
                            "SERVER",
                            ApiSecurityFindingType::InsecureTransport,
                            Severity::High,
                            &format!("Server URL uses HTTP instead of HTTPS: {}", url),
                            "Use HTTPS for all API endpoints to ensure encrypted communication",
                        );
                    }
                }
            }
        }
    }

    /// Add a finding
    fn add_finding(
        &mut self,
        endpoint: &str,
        method: &str,
        finding_type: ApiSecurityFindingType,
        severity: Severity,
        description: &str,
        remediation: &str,
    ) {
        self.findings.push(ApiSecurityFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            endpoint: endpoint.to_string(),
            method: HttpMethod::from_str(method).ok(),
            finding_type,
            category: ApiSecurityCategory::Authentication, // Default category
            severity,
            title: description.to_string(),
            description: description.to_string(),
            recommendation: Some(remediation.to_string()),
            cwe_id: None,
            owasp_api_id: None,
            evidence: None,
            affected_parameters: Vec::new(),
            remediation_effort: RemediationEffort::Medium,
            remediation: Some(remediation.to_string()),
            created_at: Utc::now(),
        });
    }
}

impl Default for ApiSecurityScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_new() {
        let scanner = ApiSecurityScanner::new();
        assert!(scanner.findings.is_empty());
        assert!(scanner.config.check_auth);
    }

    #[test]
    fn test_scan_openapi_no_security() {
        let spec = r#"
        {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/users": {
                    "get": {
                        "summary": "Get users"
                    },
                    "post": {
                        "summary": "Create user"
                    }
                }
            }
        }
        "#;

        let mut scanner = ApiSecurityScanner::new();
        let findings = scanner.scan_openapi(spec, ApiSpecFormat::OpenApi3).unwrap();
        
        // Should find missing security
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| matches!(f.finding_type, ApiSecurityFindingType::MissingAuthentication)));
    }

    #[test]
    fn test_scan_http_server() {
        let spec = r#"
        {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "servers": [{"url": "http://api.example.com"}],
            "paths": {}
        }
        "#;

        let mut scanner = ApiSecurityScanner::new();
        let findings = scanner.scan_openapi(spec, ApiSpecFormat::OpenApi3).unwrap();
        
        // Should find insecure transport
        assert!(findings.iter().any(|f| matches!(f.finding_type, ApiSecurityFindingType::InsecureTransport)));
    }
}
