//! Rate limiting configuration checker

use serde::{Deserialize, Serialize};

/// Rate limit analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitAnalysis {
    /// Whether rate limiting is documented
    pub documented: bool,
    /// Rate limit configurations found
    pub limits: Vec<RateLimitConfig>,
    /// Endpoints without rate limiting
    pub unprotected_endpoints: Vec<String>,
    /// Issues found
    pub issues: Vec<RateLimitIssue>,
}

/// Rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Endpoint or scope
    pub scope: String,
    /// Requests allowed
    pub limit: u32,
    /// Time window in seconds
    pub window_seconds: u32,
    /// Key for rate limiting (IP, user, API key)
    pub key: String,
}

/// Rate limit issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitIssue {
    /// Issue type
    pub issue_type: RateLimitIssueType,
    /// Affected endpoint
    pub endpoint: String,
    /// Description
    pub description: String,
    /// Recommendation
    pub recommendation: String,
}

/// Types of rate limit issues
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitIssueType {
    /// No rate limiting
    None,
    /// Rate limit too high
    TooHigh,
    /// Rate limit not per-user
    NotPerUser,
    /// Sensitive endpoint unprotected
    SensitiveEndpointUnprotected,
    /// Write operations unprotected
    WriteOperationsUnprotected,
}

/// Check rate limiting from OpenAPI spec
pub fn check_rate_limits(spec: &serde_json::Value) -> RateLimitAnalysis {
    let mut analysis = RateLimitAnalysis {
        documented: false,
        limits: Vec::new(),
        unprotected_endpoints: Vec::new(),
        issues: Vec::new(),
    };

    // Check for x-rate-limit extension
    if let Some(rate_limit) = spec.get("x-rate-limit") {
        analysis.documented = true;
        parse_rate_limit_extension(&mut analysis, rate_limit);
    }

    // Check paths for rate limiting
    if let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) {
        for (path, path_item) in paths {
            check_path_rate_limits(&mut analysis, path, path_item);
        }
    }

    // If no rate limiting documented, flag it
    if !analysis.documented && analysis.limits.is_empty() {
        analysis.issues.push(RateLimitIssue {
            issue_type: RateLimitIssueType::None,
            endpoint: "*".to_string(),
            description: "No rate limiting configuration found in API specification".to_string(),
            recommendation: "Add rate limiting to protect against abuse and DoS attacks".to_string(),
        });
    }

    analysis
}

fn parse_rate_limit_extension(analysis: &mut RateLimitAnalysis, rate_limit: &serde_json::Value) {
    if let Some(limit) = rate_limit.get("limit").and_then(|l| l.as_u64()) {
        if let Some(window) = rate_limit.get("window").and_then(|w| w.as_u64()) {
            analysis.limits.push(RateLimitConfig {
                scope: "global".to_string(),
                limit: limit as u32,
                window_seconds: window as u32,
                key: rate_limit.get("key").and_then(|k| k.as_str()).unwrap_or("ip").to_string(),
            });
        }
    }
}

fn check_path_rate_limits(analysis: &mut RateLimitAnalysis, path: &str, path_item: &serde_json::Value) {
    let methods = ["get", "post", "put", "patch", "delete"];
    
    for method in methods {
        if let Some(operation) = path_item.get(method) {
            let has_rate_limit = operation.get("x-rate-limit").is_some();
            
            if !has_rate_limit && !analysis.documented {
                // Check if it's a sensitive operation
                let is_write = matches!(method, "post" | "put" | "patch" | "delete");
                let is_auth = path.contains("auth") || path.contains("login") || path.contains("password");
                
                if is_write {
                    analysis.issues.push(RateLimitIssue {
                        issue_type: RateLimitIssueType::WriteOperationsUnprotected,
                        endpoint: format!("{} {}", method.to_uppercase(), path),
                        description: "Write operation has no documented rate limiting".to_string(),
                        recommendation: "Add rate limiting to prevent abuse".to_string(),
                    });
                }
                
                if is_auth {
                    analysis.issues.push(RateLimitIssue {
                        issue_type: RateLimitIssueType::SensitiveEndpointUnprotected,
                        endpoint: format!("{} {}", method.to_uppercase(), path),
                        description: "Authentication endpoint has no documented rate limiting".to_string(),
                        recommendation: "Add strict rate limiting to authentication endpoints".to_string(),
                    });
                }
                
                analysis.unprotected_endpoints.push(format!("{} {}", method.to_uppercase(), path));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_rate_limits() {
        let spec = serde_json::json!({
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {}
                }
            }
        });
        
        let result = check_rate_limits(&spec);
        assert!(!result.documented);
        assert!(result.issues.iter().any(|i| matches!(i.issue_type, RateLimitIssueType::None)));
    }
}
