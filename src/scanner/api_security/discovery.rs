//! API Endpoint Discovery Module
//!
//! Discovers API endpoints from:
//! - OpenAPI 3.x specifications
//! - Swagger 2.0 specifications
//! - Postman collections
//! - Common endpoint patterns
//! - Crawling the target

use anyhow::Result;
use log::{debug, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use super::{ApiSecurityConfig, ApiSpecType};

/// Represents an API endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    pub path: String,
    pub method: String,
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub parameters: Vec<ApiParameter>,
    pub request_body_schema: Option<Value>,
    pub response_schema: Option<Value>,
    pub auth_required: bool,
    pub tags: Vec<String>,
}

/// Represents an API parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiParameter {
    pub name: String,
    pub location: ParameterLocation,
    pub required: bool,
    pub param_type: String,
    pub description: Option<String>,
    pub example: Option<Value>,
}

/// Location of a parameter
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ParameterLocation {
    Path,
    Query,
    Header,
    Cookie,
    Body,
}

/// Parsed API specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSpec {
    pub title: Option<String>,
    pub version: Option<String>,
    pub base_url: Option<String>,
    pub endpoints: Vec<ApiEndpoint>,
    pub security_schemes: HashMap<String, SecurityScheme>,
}

/// Security scheme definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScheme {
    pub scheme_type: String,
    pub name: Option<String>,
    pub location: Option<String>,
    pub scheme: Option<String>,
}

/// Result of endpoint discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResult {
    pub endpoints: Vec<ApiEndpoint>,
    pub spec_detected: bool,
    pub spec_type: Option<ApiSpecType>,
    pub base_url: String,
}

/// Common paths where API specs are typically found
const COMMON_SPEC_PATHS: &[&str] = &[
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api-docs.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs/openapi.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/.well-known/openapi.json",
];

/// Common API endpoint patterns to probe
const COMMON_ENDPOINTS: &[(&str, &str)] = &[
    ("GET", "/api"),
    ("GET", "/api/v1"),
    ("GET", "/api/v2"),
    ("GET", "/v1"),
    ("GET", "/v2"),
    ("GET", "/users"),
    ("GET", "/api/users"),
    ("GET", "/api/v1/users"),
    ("GET", "/accounts"),
    ("GET", "/api/accounts"),
    ("GET", "/products"),
    ("GET", "/api/products"),
    ("GET", "/orders"),
    ("GET", "/api/orders"),
    ("GET", "/items"),
    ("GET", "/api/items"),
    ("GET", "/health"),
    ("GET", "/api/health"),
    ("GET", "/status"),
    ("GET", "/api/status"),
    ("GET", "/version"),
    ("GET", "/api/version"),
    ("GET", "/info"),
    ("GET", "/api/info"),
    ("POST", "/auth/login"),
    ("POST", "/api/auth/login"),
    ("POST", "/login"),
    ("POST", "/api/login"),
    ("POST", "/register"),
    ("POST", "/api/register"),
    ("GET", "/me"),
    ("GET", "/api/me"),
    ("GET", "/profile"),
    ("GET", "/api/profile"),
    ("GET", "/graphql"),
    ("POST", "/graphql"),
];

/// Discover API endpoints from a target URL
pub async fn discover_endpoints(client: &Client, config: &ApiSecurityConfig) -> Result<DiscoveryResult> {
    let base_url = &config.target_url;
    info!("Discovering API endpoints from {}", base_url);

    let mut endpoints = Vec::new();
    let mut spec_detected = false;
    let mut spec_type = None;

    // Try to find and parse API specification
    for spec_path in COMMON_SPEC_PATHS {
        let spec_url = format!("{}{}", base_url.trim_end_matches('/'), spec_path);
        debug!("Checking for API spec at: {}", spec_url);

        match client.get(&spec_url).send().await {
            Ok(response) if response.status().is_success() => {
                if let Ok(text) = response.text().await {
                    // Try to parse as OpenAPI/Swagger
                    if let Ok(spec) = parse_openapi_json(&text) {
                        info!("Found OpenAPI 3.x spec at {}", spec_url);
                        endpoints.extend(spec.endpoints);
                        spec_detected = true;
                        spec_type = Some(ApiSpecType::OpenApi3);
                        break;
                    } else if let Ok(spec) = parse_swagger_json(&text) {
                        info!("Found Swagger 2.x spec at {}", spec_url);
                        endpoints.extend(spec.endpoints);
                        spec_detected = true;
                        spec_type = Some(ApiSpecType::Swagger2);
                        break;
                    }
                }
            }
            _ => continue,
        }
    }

    // If no spec found, probe common endpoints
    if !spec_detected {
        info!("No API spec found, probing common endpoints");
        endpoints = probe_common_endpoints(client, base_url).await?;
    }

    Ok(DiscoveryResult {
        endpoints,
        spec_detected,
        spec_type,
        base_url: base_url.clone(),
    })
}

/// Parse an API specification based on type
pub fn parse_api_spec(spec_type: &ApiSpecType, content: &str) -> Result<ApiSpec> {
    match spec_type {
        ApiSpecType::OpenApi3 => parse_openapi_json(content),
        ApiSpecType::Swagger2 => parse_swagger_json(content),
        ApiSpecType::Postman => parse_postman_collection(content),
        ApiSpecType::None => Ok(ApiSpec {
            title: None,
            version: None,
            base_url: None,
            endpoints: Vec::new(),
            security_schemes: HashMap::new(),
        }),
    }
}

/// Parse OpenAPI 3.x JSON specification
fn parse_openapi_json(content: &str) -> Result<ApiSpec> {
    let json: Value = serde_json::from_str(content)?;

    // Verify it's OpenAPI 3.x
    let openapi_version = json.get("openapi").and_then(|v| v.as_str()).unwrap_or("");
    if !openapi_version.starts_with("3.") {
        return Err(anyhow::anyhow!("Not a valid OpenAPI 3.x document"));
    }

    let title = json
        .get("info")
        .and_then(|i| i.get("title"))
        .and_then(|t| t.as_str())
        .map(String::from);

    let version = json
        .get("info")
        .and_then(|i| i.get("version"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // Get base URL from servers
    let base_url = json
        .get("servers")
        .and_then(|s| s.as_array())
        .and_then(|arr| arr.first())
        .and_then(|s| s.get("url"))
        .and_then(|u| u.as_str())
        .map(String::from);

    // Parse security schemes
    let mut security_schemes = HashMap::new();
    if let Some(components) = json.get("components") {
        if let Some(schemes) = components.get("securitySchemes") {
            if let Some(obj) = schemes.as_object() {
                for (name, scheme) in obj {
                    security_schemes.insert(
                        name.clone(),
                        SecurityScheme {
                            scheme_type: scheme
                                .get("type")
                                .and_then(|t| t.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            name: scheme.get("name").and_then(|n| n.as_str()).map(String::from),
                            location: scheme.get("in").and_then(|l| l.as_str()).map(String::from),
                            scheme: scheme.get("scheme").and_then(|s| s.as_str()).map(String::from),
                        },
                    );
                }
            }
        }
    }

    // Check if global security is defined
    let has_global_security = json
        .get("security")
        .map(|s| !s.as_array().map(|a| a.is_empty()).unwrap_or(true))
        .unwrap_or(false);

    // Parse paths
    let mut endpoints = Vec::new();
    if let Some(paths) = json.get("paths") {
        if let Some(paths_obj) = paths.as_object() {
            for (path, methods) in paths_obj {
                if let Some(methods_obj) = methods.as_object() {
                    for (method, operation) in methods_obj {
                        // Skip non-HTTP method keys
                        if !["get", "post", "put", "patch", "delete", "head", "options"]
                            .contains(&method.as_str())
                        {
                            continue;
                        }

                        let endpoint = parse_openapi_operation(
                            path,
                            method,
                            operation,
                            has_global_security,
                        );
                        endpoints.push(endpoint);
                    }
                }
            }
        }
    }

    Ok(ApiSpec {
        title,
        version,
        base_url,
        endpoints,
        security_schemes,
    })
}

/// Parse a single OpenAPI operation
fn parse_openapi_operation(
    path: &str,
    method: &str,
    operation: &Value,
    has_global_security: bool,
) -> ApiEndpoint {
    let operation_id = operation
        .get("operationId")
        .and_then(|o| o.as_str())
        .map(String::from);

    let summary = operation
        .get("summary")
        .and_then(|s| s.as_str())
        .map(String::from);

    let tags = operation
        .get("tags")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Parse parameters
    let mut parameters = Vec::new();
    if let Some(params) = operation.get("parameters") {
        if let Some(params_arr) = params.as_array() {
            for param in params_arr {
                let location = match param.get("in").and_then(|i| i.as_str()) {
                    Some("path") => ParameterLocation::Path,
                    Some("query") => ParameterLocation::Query,
                    Some("header") => ParameterLocation::Header,
                    Some("cookie") => ParameterLocation::Cookie,
                    _ => continue,
                };

                parameters.push(ApiParameter {
                    name: param
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    location,
                    required: param.get("required").and_then(|r| r.as_bool()).unwrap_or(false),
                    param_type: param
                        .get("schema")
                        .and_then(|s| s.get("type"))
                        .and_then(|t| t.as_str())
                        .unwrap_or("string")
                        .to_string(),
                    description: param
                        .get("description")
                        .and_then(|d| d.as_str())
                        .map(String::from),
                    example: param.get("example").cloned(),
                });
            }
        }
    }

    // Parse request body
    let request_body_schema = operation
        .get("requestBody")
        .and_then(|rb| rb.get("content"))
        .and_then(|c| c.get("application/json"))
        .and_then(|j| j.get("schema"))
        .cloned();

    // Parse response schema (from 200 response)
    let response_schema = operation
        .get("responses")
        .and_then(|r| r.get("200").or_else(|| r.get("201")))
        .and_then(|r| r.get("content"))
        .and_then(|c| c.get("application/json"))
        .and_then(|j| j.get("schema"))
        .cloned();

    // Check if endpoint requires authentication
    let has_operation_security = operation
        .get("security")
        .map(|s| !s.as_array().map(|a| a.is_empty()).unwrap_or(true))
        .unwrap_or(false);

    let auth_required = has_operation_security || has_global_security;

    ApiEndpoint {
        path: path.to_string(),
        method: method.to_uppercase(),
        operation_id,
        summary,
        parameters,
        request_body_schema,
        response_schema,
        auth_required,
        tags,
    }
}

/// Parse Swagger 2.0 JSON specification
fn parse_swagger_json(content: &str) -> Result<ApiSpec> {
    let json: Value = serde_json::from_str(content)?;

    // Verify it's Swagger 2.0
    let swagger_version = json.get("swagger").and_then(|v| v.as_str()).unwrap_or("");
    if swagger_version != "2.0" {
        return Err(anyhow::anyhow!("Not a valid Swagger 2.0 document"));
    }

    let title = json
        .get("info")
        .and_then(|i| i.get("title"))
        .and_then(|t| t.as_str())
        .map(String::from);

    let version = json
        .get("info")
        .and_then(|i| i.get("version"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // Construct base URL
    let host = json.get("host").and_then(|h| h.as_str()).unwrap_or("");
    let base_path = json.get("basePath").and_then(|b| b.as_str()).unwrap_or("");
    let scheme = json
        .get("schemes")
        .and_then(|s| s.as_array())
        .and_then(|arr| arr.first())
        .and_then(|s| s.as_str())
        .unwrap_or("https");

    let base_url = if !host.is_empty() {
        Some(format!("{}://{}{}", scheme, host, base_path))
    } else {
        None
    };

    // Parse security definitions
    let mut security_schemes = HashMap::new();
    if let Some(definitions) = json.get("securityDefinitions") {
        if let Some(obj) = definitions.as_object() {
            for (name, def) in obj {
                security_schemes.insert(
                    name.clone(),
                    SecurityScheme {
                        scheme_type: def
                            .get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        name: def.get("name").and_then(|n| n.as_str()).map(String::from),
                        location: def.get("in").and_then(|l| l.as_str()).map(String::from),
                        scheme: None,
                    },
                );
            }
        }
    }

    let has_global_security = json
        .get("security")
        .map(|s| !s.as_array().map(|a| a.is_empty()).unwrap_or(true))
        .unwrap_or(false);

    // Parse paths
    let mut endpoints = Vec::new();
    if let Some(paths) = json.get("paths") {
        if let Some(paths_obj) = paths.as_object() {
            for (path, methods) in paths_obj {
                if let Some(methods_obj) = methods.as_object() {
                    for (method, operation) in methods_obj {
                        if !["get", "post", "put", "patch", "delete", "head", "options"]
                            .contains(&method.as_str())
                        {
                            continue;
                        }

                        let endpoint =
                            parse_swagger_operation(path, method, operation, has_global_security);
                        endpoints.push(endpoint);
                    }
                }
            }
        }
    }

    Ok(ApiSpec {
        title,
        version,
        base_url,
        endpoints,
        security_schemes,
    })
}

/// Parse a single Swagger 2.0 operation
fn parse_swagger_operation(
    path: &str,
    method: &str,
    operation: &Value,
    has_global_security: bool,
) -> ApiEndpoint {
    let operation_id = operation
        .get("operationId")
        .and_then(|o| o.as_str())
        .map(String::from);

    let summary = operation
        .get("summary")
        .and_then(|s| s.as_str())
        .map(String::from);

    let tags = operation
        .get("tags")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Parse parameters
    let mut parameters = Vec::new();
    if let Some(params) = operation.get("parameters") {
        if let Some(params_arr) = params.as_array() {
            for param in params_arr {
                let location = match param.get("in").and_then(|i| i.as_str()) {
                    Some("path") => ParameterLocation::Path,
                    Some("query") => ParameterLocation::Query,
                    Some("header") => ParameterLocation::Header,
                    Some("body") => ParameterLocation::Body,
                    Some("formData") => ParameterLocation::Body,
                    _ => continue,
                };

                parameters.push(ApiParameter {
                    name: param
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    location,
                    required: param.get("required").and_then(|r| r.as_bool()).unwrap_or(false),
                    param_type: param
                        .get("type")
                        .and_then(|t| t.as_str())
                        .unwrap_or("string")
                        .to_string(),
                    description: param
                        .get("description")
                        .and_then(|d| d.as_str())
                        .map(String::from),
                    example: None,
                });
            }
        }
    }

    let has_operation_security = operation
        .get("security")
        .map(|s| !s.as_array().map(|a| a.is_empty()).unwrap_or(true))
        .unwrap_or(false);

    ApiEndpoint {
        path: path.to_string(),
        method: method.to_uppercase(),
        operation_id,
        summary,
        parameters,
        request_body_schema: None,
        response_schema: None,
        auth_required: has_operation_security || has_global_security,
        tags,
    }
}

/// Parse Postman collection
fn parse_postman_collection(content: &str) -> Result<ApiSpec> {
    let json: Value = serde_json::from_str(content)?;

    // Verify it's a Postman collection
    let info = json.get("info").ok_or_else(|| anyhow::anyhow!("Not a valid Postman collection"))?;

    let title = info.get("name").and_then(|n| n.as_str()).map(String::from);
    let version = info
        .get("version")
        .and_then(|v| v.as_str())
        .map(String::from);

    let mut endpoints = Vec::new();

    // Parse items recursively
    fn parse_items(items: &Value, endpoints: &mut Vec<ApiEndpoint>) {
        if let Some(arr) = items.as_array() {
            for item in arr {
                // Check if it's a request or a folder
                if let Some(request) = item.get("request") {
                    let method = request
                        .get("method")
                        .and_then(|m| m.as_str())
                        .unwrap_or("GET")
                        .to_uppercase();

                    let url = request.get("url");
                    let path = if let Some(url_obj) = url {
                        if let Some(path_arr) = url_obj.get("path").and_then(|p| p.as_array()) {
                            format!(
                                "/{}",
                                path_arr
                                    .iter()
                                    .filter_map(|p| p.as_str())
                                    .collect::<Vec<_>>()
                                    .join("/")
                            )
                        } else if let Some(raw) = url_obj.get("raw").and_then(|r| r.as_str()) {
                            // Try to extract path from raw URL
                            if let Ok(parsed) = url::Url::parse(raw) {
                                parsed.path().to_string()
                            } else {
                                raw.to_string()
                            }
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };

                    if !path.is_empty() {
                        endpoints.push(ApiEndpoint {
                            path,
                            method,
                            operation_id: item.get("name").and_then(|n| n.as_str()).map(String::from),
                            summary: item
                                .get("name")
                                .and_then(|n| n.as_str())
                                .map(String::from),
                            parameters: Vec::new(),
                            request_body_schema: None,
                            response_schema: None,
                            auth_required: request.get("auth").is_some(),
                            tags: Vec::new(),
                        });
                    }
                }

                // Recurse into folders
                if let Some(sub_items) = item.get("item") {
                    parse_items(sub_items, endpoints);
                }
            }
        }
    }

    if let Some(items) = json.get("item") {
        parse_items(items, &mut endpoints);
    }

    Ok(ApiSpec {
        title,
        version,
        base_url: None,
        endpoints,
        security_schemes: HashMap::new(),
    })
}

/// Probe common API endpoints to discover available paths
async fn probe_common_endpoints(client: &Client, base_url: &str) -> Result<Vec<ApiEndpoint>> {
    let mut endpoints = Vec::new();

    for (method, path) in COMMON_ENDPOINTS {
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);

        let response = match *method {
            "GET" => client.get(&url).send().await,
            "POST" => client.post(&url).send().await,
            _ => continue,
        };

        match response {
            Ok(resp) => {
                let status = resp.status();
                // Consider it found if we get a response that's not 404
                if status.as_u16() != 404 {
                    debug!("Found endpoint: {} {} (status: {})", method, path, status);

                    // Try to detect if auth is required (401/403)
                    let auth_required =
                        status.as_u16() == 401 || status.as_u16() == 403;

                    endpoints.push(ApiEndpoint {
                        path: path.to_string(),
                        method: method.to_string(),
                        operation_id: None,
                        summary: None,
                        parameters: Vec::new(),
                        request_body_schema: None,
                        response_schema: None,
                        auth_required,
                        tags: Vec::new(),
                    });
                }
            }
            Err(e) => {
                warn!("Failed to probe {}: {}", url, e);
            }
        }

        // Small delay between probes
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    Ok(endpoints)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_openapi3() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test API", "version": "1.0" },
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "getUsers",
                        "summary": "Get all users",
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "required": false,
                                "schema": { "type": "integer" }
                            }
                        ]
                    }
                }
            }
        }"#;

        let result = parse_openapi_json(spec).unwrap();
        assert_eq!(result.title, Some("Test API".to_string()));
        assert_eq!(result.endpoints.len(), 1);
        assert_eq!(result.endpoints[0].path, "/users");
        assert_eq!(result.endpoints[0].method, "GET");
    }

    #[test]
    fn test_parse_swagger2() {
        let spec = r#"{
            "swagger": "2.0",
            "info": { "title": "Test API", "version": "1.0" },
            "host": "api.example.com",
            "basePath": "/v1",
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "getUsers"
                    }
                }
            }
        }"#;

        let result = parse_swagger_json(spec).unwrap();
        assert_eq!(result.title, Some("Test API".to_string()));
        assert_eq!(result.base_url, Some("https://api.example.com/v1".to_string()));
    }
}
