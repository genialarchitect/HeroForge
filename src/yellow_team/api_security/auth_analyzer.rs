//! Authentication flow analyzer

use crate::yellow_team::types::*;
use serde::{Deserialize, Serialize};

/// Authentication analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAnalysisResult {
    /// Authentication methods found
    pub auth_methods: Vec<AuthMethod>,
    /// Issues found
    pub issues: Vec<AuthIssue>,
    /// Overall security score (0-100)
    pub security_score: u32,
}

/// Authentication method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMethod {
    /// Method name
    pub name: String,
    /// Method type
    pub method_type: AuthMethodType,
    /// Where auth is located (header, query, cookie)
    pub location: String,
    /// Security level
    pub security_level: SecurityLevel,
}

/// Type of authentication method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethodType {
    ApiKey,
    BasicAuth,
    BearerToken,
    OAuth2,
    OpenIdConnect,
    Custom,
}

/// Security level of auth method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLevel {
    High,
    Medium,
    Low,
    None,
}

/// Authentication issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthIssue {
    /// Issue type
    pub issue_type: AuthIssueType,
    /// Severity
    pub severity: Severity,
    /// Affected component
    pub affected: String,
    /// Description
    pub description: String,
    /// Remediation
    pub remediation: String,
}

/// Types of authentication issues
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthIssueType {
    NoAuthentication,
    WeakAuthentication,
    InsecureTransmission,
    MissingMfa,
    LongLivedTokens,
    NoTokenExpiration,
    BroadScopes,
    NoRateLimiting,
}

/// Analyze authentication from OpenAPI spec
pub fn analyze_auth(spec: &serde_json::Value) -> AuthAnalysisResult {
    let mut result = AuthAnalysisResult {
        auth_methods: Vec::new(),
        issues: Vec::new(),
        security_score: 100,
    };

    // Check security schemes
    let security_schemes = spec
        .get("components")
        .and_then(|c| c.get("securitySchemes"))
        .or_else(|| spec.get("securityDefinitions"));

    if security_schemes.is_none() {
        result.issues.push(AuthIssue {
            issue_type: AuthIssueType::NoAuthentication,
            severity: Severity::High,
            affected: "API".to_string(),
            description: "No security schemes defined".to_string(),
            remediation: "Define authentication mechanisms for your API".to_string(),
        });
        result.security_score = 0;
        return result;
    }

    if let Some(schemes) = security_schemes.and_then(|s| s.as_object()) {
        for (name, scheme) in schemes {
            let scheme_type = scheme.get("type").and_then(|t| t.as_str()).unwrap_or("");
            
            let (method_type, security_level) = match scheme_type {
                "apiKey" => {
                    let location = scheme.get("in").and_then(|i| i.as_str()).unwrap_or("");
                    if location == "query" {
                        result.issues.push(AuthIssue {
                            issue_type: AuthIssueType::InsecureTransmission,
                            severity: Severity::Medium,
                            affected: name.clone(),
                            description: "API key in query string may be logged".to_string(),
                            remediation: "Move API key to header".to_string(),
                        });
                        result.security_score -= 10;
                    }
                    (AuthMethodType::ApiKey, SecurityLevel::Medium)
                }
                "http" => {
                    let scheme_name = scheme.get("scheme").and_then(|s| s.as_str()).unwrap_or("");
                    if scheme_name == "basic" {
                        result.issues.push(AuthIssue {
                            issue_type: AuthIssueType::WeakAuthentication,
                            severity: Severity::Medium,
                            affected: name.clone(),
                            description: "Basic auth transmits credentials with each request".to_string(),
                            remediation: "Consider token-based authentication".to_string(),
                        });
                        result.security_score -= 15;
                        (AuthMethodType::BasicAuth, SecurityLevel::Low)
                    } else {
                        (AuthMethodType::BearerToken, SecurityLevel::High)
                    }
                }
                "oauth2" => (AuthMethodType::OAuth2, SecurityLevel::High),
                "openIdConnect" => (AuthMethodType::OpenIdConnect, SecurityLevel::High),
                _ => (AuthMethodType::Custom, SecurityLevel::Medium),
            };

            result.auth_methods.push(AuthMethod {
                name: name.clone(),
                method_type,
                location: scheme.get("in").and_then(|i| i.as_str()).unwrap_or("").to_string(),
                security_level,
            });
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_no_auth() {
        let spec = serde_json::json!({
            "openapi": "3.0.0",
            "paths": {}
        });
        
        let result = analyze_auth(&spec);
        assert!(result.issues.iter().any(|i| matches!(i.issue_type, AuthIssueType::NoAuthentication)));
        assert_eq!(result.security_score, 0);
    }

    #[test]
    fn test_analyze_bearer_auth() {
        let spec = serde_json::json!({
            "openapi": "3.0.0",
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer"
                    }
                }
            }
        });
        
        let result = analyze_auth(&spec);
        assert!(!result.auth_methods.is_empty());
        assert_eq!(result.auth_methods[0].method_type, AuthMethodType::BearerToken);
    }
}
