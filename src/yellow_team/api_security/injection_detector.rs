//! API injection vulnerability detector

use crate::yellow_team::types::*;
use serde::{Deserialize, Serialize};

/// Injection analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionAnalysis {
    /// Potential injection points found
    pub injection_points: Vec<InjectionPoint>,
    /// Overall risk level
    pub risk_level: Severity,
}

/// Potential injection point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionPoint {
    /// Endpoint
    pub endpoint: String,
    /// HTTP method
    pub method: String,
    /// Parameter name
    pub parameter: String,
    /// Parameter location (query, body, path, header)
    pub location: String,
    /// Injection type risk
    pub injection_type: InjectionType,
    /// Severity
    pub severity: Severity,
    /// Description
    pub description: String,
    /// Remediation
    pub remediation: String,
}

/// Type of injection vulnerability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionType {
    Sql,
    NoSql,
    Command,
    Ldap,
    Xpath,
    HeaderInjection,
    EmailInjection,
    TemplateInjection,
}

/// Analyze API for injection vulnerabilities
pub fn analyze_injections(spec: &serde_json::Value) -> InjectionAnalysis {
    let mut analysis = InjectionAnalysis {
        injection_points: Vec::new(),
        risk_level: Severity::Low,
    };

    if let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) {
        for (path, path_item) in paths {
            analyze_path_injections(&mut analysis, path, path_item);
        }
    }

    // Set overall risk level
    if !analysis.injection_points.is_empty() {
        let max_severity = analysis.injection_points.iter()
            .map(|p| &p.severity)
            .max_by_key(|s| severity_order(s))
            .cloned()
            .unwrap_or(Severity::Low);
        analysis.risk_level = max_severity;
    }

    analysis
}

fn severity_order(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

fn analyze_path_injections(analysis: &mut InjectionAnalysis, path: &str, path_item: &serde_json::Value) {
    let methods = ["get", "post", "put", "patch", "delete"];
    
    for method in methods {
        if let Some(operation) = path_item.get(method) {
            // Check parameters
            if let Some(params) = operation.get("parameters").and_then(|p| p.as_array()) {
                for param in params {
                    check_parameter_injection(analysis, path, method, param);
                }
            }
            
            // Check request body
            if let Some(body) = operation.get("requestBody") {
                check_body_injection(analysis, path, method, body);
            }
        }
    }
}

fn check_parameter_injection(
    analysis: &mut InjectionAnalysis,
    path: &str,
    method: &str,
    param: &serde_json::Value,
) {
    let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let location = param.get("in").and_then(|i| i.as_str()).unwrap_or("");
    let schema = param.get("schema");
    
    let param_type = schema
        .and_then(|s| s.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("");
    
    let has_pattern = schema.and_then(|s| s.get("pattern")).is_some();
    let has_enum = schema.and_then(|s| s.get("enum")).is_some();
    
    // Check for SQL injection risk
    let sql_keywords = ["id", "query", "filter", "search", "order", "sort", "where", "select"];
    let lower_name = name.to_lowercase();
    
    for keyword in sql_keywords {
        if lower_name.contains(keyword) && param_type == "string" && !has_pattern && !has_enum {
            analysis.injection_points.push(InjectionPoint {
                endpoint: path.to_string(),
                method: method.to_uppercase(),
                parameter: name.to_string(),
                location: location.to_string(),
                injection_type: InjectionType::Sql,
                severity: Severity::Medium,
                description: format!("Parameter '{}' may be vulnerable to SQL injection", name),
                remediation: "Add input validation pattern or use parameterized queries".to_string(),
            });
            break;
        }
    }

    // Check for command injection risk
    let cmd_keywords = ["cmd", "command", "exec", "run", "shell", "script", "file", "path"];
    for keyword in cmd_keywords {
        if lower_name.contains(keyword) && param_type == "string" && !has_pattern {
            analysis.injection_points.push(InjectionPoint {
                endpoint: path.to_string(),
                method: method.to_uppercase(),
                parameter: name.to_string(),
                location: location.to_string(),
                injection_type: InjectionType::Command,
                severity: Severity::High,
                description: format!("Parameter '{}' may be vulnerable to command injection", name),
                remediation: "Avoid passing user input to system commands, use allowlists".to_string(),
            });
            break;
        }
    }

    // Check for LDAP injection risk
    if (lower_name.contains("user") || lower_name.contains("dn") || lower_name.contains("ldap")) 
        && param_type == "string" && !has_pattern {
        analysis.injection_points.push(InjectionPoint {
            endpoint: path.to_string(),
            method: method.to_uppercase(),
            parameter: name.to_string(),
            location: location.to_string(),
            injection_type: InjectionType::Ldap,
            severity: Severity::Medium,
            description: format!("Parameter '{}' may be vulnerable to LDAP injection", name),
            remediation: "Escape special LDAP characters and validate input".to_string(),
        });
    }
}

fn check_body_injection(
    analysis: &mut InjectionAnalysis,
    path: &str,
    method: &str,
    body: &serde_json::Value,
) {
    if let Some(content) = body.get("content").and_then(|c| c.as_object()) {
        for (media_type, media_content) in content {
            // XML content - XXE risk
            if media_type.contains("xml") {
                analysis.injection_points.push(InjectionPoint {
                    endpoint: path.to_string(),
                    method: method.to_uppercase(),
                    parameter: "body".to_string(),
                    location: "body".to_string(),
                    injection_type: InjectionType::TemplateInjection, // Using for XXE
                    severity: Severity::High,
                    description: "XML body may be vulnerable to XXE attacks".to_string(),
                    remediation: "Disable DTD processing and external entity resolution".to_string(),
                });
            }
            
            // Check schema for injection-prone fields
            if let Some(schema) = media_content.get("schema") {
                if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
                    for (prop_name, _) in props {
                        let lower = prop_name.to_lowercase();
                        if lower.contains("template") || lower.contains("code") || lower.contains("expression") {
                            analysis.injection_points.push(InjectionPoint {
                                endpoint: path.to_string(),
                                method: method.to_uppercase(),
                                parameter: prop_name.to_string(),
                                location: "body".to_string(),
                                injection_type: InjectionType::TemplateInjection,
                                severity: Severity::High,
                                description: format!("Field '{}' may be vulnerable to template injection", prop_name),
                                remediation: "Sanitize template expressions and use sandboxed execution".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_sql_injection_risk() {
        let spec = serde_json::json!({
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [{
                            "name": "user_id",
                            "in": "query",
                            "schema": {
                                "type": "string"
                            }
                        }]
                    }
                }
            }
        });
        
        let result = analyze_injections(&spec);
        assert!(!result.injection_points.is_empty());
        assert!(result.injection_points.iter().any(|p| matches!(p.injection_type, InjectionType::Sql)));
    }
}
