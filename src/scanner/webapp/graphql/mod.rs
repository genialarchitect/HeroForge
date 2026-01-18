//! GraphQL Security Scanner
//!
//! Comprehensive security testing for GraphQL endpoints including:
//! - Introspection exposure detection
//! - Injection vulnerability testing (SQLI, NoSQL, IDOR)
//! - Denial of Service vectors (query depth, batch attacks, circular fragments)
//! - Authorization bypass testing
//! - Field suggestion abuse
//! - Alias-based attacks

pub mod types;
pub mod introspection;
pub mod injection;
pub mod dos;
pub mod authorization;

use anyhow::Result;
use log::{info, warn, debug};
use reqwest::Client;
use url::Url;

use crate::types::{WebAppFinding, Severity};
use types::{GraphQLEndpoint, GraphQLScanConfig, GraphQLScanResult, GraphQLFinding};

/// Detect GraphQL endpoints at common paths
pub async fn detect_graphql_endpoints(
    client: &Client,
    base_url: &Url,
) -> Result<Vec<GraphQLEndpoint>> {
    let common_paths = [
        "/graphql",
        "/graphql/",
        "/api/graphql",
        "/api/v1/graphql",
        "/api/v2/graphql",
        "/v1/graphql",
        "/v2/graphql",
        "/gql",
        "/query",
        "/api/query",
        "/graphiql",
        "/playground",
        "/altair",
        "/console",
        "/api",
    ];

    let mut endpoints = Vec::new();

    for path in common_paths {
        let url = match base_url.join(path) {
            Ok(u) => u,
            Err(_) => continue,
        };

        match check_graphql_endpoint(client, &url).await {
            Ok(Some(endpoint)) => {
                info!("Discovered GraphQL endpoint: {}", url);
                endpoints.push(endpoint);
            }
            Ok(None) => {
                debug!("No GraphQL endpoint at: {}", url);
            }
            Err(e) => {
                debug!("Error checking {}: {}", url, e);
            }
        }
    }

    Ok(endpoints)
}

/// Check if a URL is a GraphQL endpoint
async fn check_graphql_endpoint(
    client: &Client,
    url: &Url,
) -> Result<Option<GraphQLEndpoint>> {
    // Send a simple introspection query to detect GraphQL
    let introspection_query = r#"{"query": "{ __typename }"}"#;

    let response = client
        .post(url.as_str())
        .header("Content-Type", "application/json")
        .body(introspection_query)
        .send()
        .await;

    match response {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            // Check for GraphQL indicators in response
            if body.contains("__typename") ||
               body.contains("\"data\"") ||
               body.contains("\"errors\"") ||
               body.contains("Query") ||
               body.contains("Mutation") {
                return Ok(Some(GraphQLEndpoint {
                    url: url.to_string(),
                    introspection_enabled: body.contains("__typename"),
                    supports_batching: None,
                    has_mutations: None,
                    has_subscriptions: None,
                    framework: detect_framework(&body),
                }));
            }

            // Also check GET method for some endpoints
            let get_url = format!("{}?query={{__typename}}", url);
            let get_response = client.get(&get_url).send().await;

            if let Ok(get_resp) = get_response {
                let get_body = get_resp.text().await.unwrap_or_default();
                if get_body.contains("__typename") ||
                   get_body.contains("\"data\"") {
                    return Ok(Some(GraphQLEndpoint {
                        url: url.to_string(),
                        introspection_enabled: get_body.contains("__typename"),
                        supports_batching: None,
                        has_mutations: None,
                        has_subscriptions: None,
                        framework: detect_framework(&get_body),
                    }));
                }
            }

            Ok(None)
        }
        Err(_) => Ok(None),
    }
}

/// Detect GraphQL framework from response
fn detect_framework(body: &str) -> Option<String> {
    if body.contains("apollo") || body.contains("Apollo") {
        Some("Apollo Server".to_string())
    } else if body.contains("graphene") {
        Some("Graphene (Python)".to_string())
    } else if body.contains("graphql-yoga") {
        Some("GraphQL Yoga".to_string())
    } else if body.contains("graphql-java") {
        Some("GraphQL Java".to_string())
    } else if body.contains("Hasura") || body.contains("hasura") {
        Some("Hasura".to_string())
    } else if body.contains("PostGraphile") || body.contains("postgraphile") {
        Some("PostGraphile".to_string())
    } else if body.contains("Prisma") || body.contains("prisma") {
        Some("Prisma".to_string())
    } else {
        None
    }
}

/// Run a comprehensive GraphQL security scan
pub async fn scan_graphql(
    client: &Client,
    endpoint: &GraphQLEndpoint,
    config: &GraphQLScanConfig,
) -> Result<GraphQLScanResult> {
    info!("Starting GraphQL security scan for: {}", endpoint.url);

    let mut findings: Vec<GraphQLFinding> = Vec::new();
    let url = Url::parse(&endpoint.url)?;

    // Phase 1: Introspection Analysis
    if config.check_introspection {
        info!("Phase 1: Checking introspection exposure");
        let intro_findings = introspection::check_introspection(client, &url).await?;
        findings.extend(intro_findings);
    }

    // Phase 2: Injection Testing
    if config.check_injection {
        info!("Phase 2: Testing for injection vulnerabilities");
        let injection_findings = injection::test_injections(client, &url, config).await?;
        findings.extend(injection_findings);
    }

    // Phase 3: DoS Attack Vectors
    if config.check_dos {
        info!("Phase 3: Testing DoS attack vectors");
        let dos_findings = dos::test_dos_vectors(client, &url, config).await?;
        findings.extend(dos_findings);
    }

    // Phase 4: Authorization Testing
    if config.check_authorization {
        info!("Phase 4: Testing authorization controls");
        let auth_findings = authorization::test_authorization(client, &url, config).await?;
        findings.extend(auth_findings);
    }

    let severity_breakdown = calculate_severity_breakdown(&findings);

    info!(
        "GraphQL scan completed. Found {} findings (Critical: {}, High: {}, Medium: {}, Low: {})",
        findings.len(),
        severity_breakdown.0,
        severity_breakdown.1,
        severity_breakdown.2,
        severity_breakdown.3
    );

    Ok(GraphQLScanResult {
        endpoint: endpoint.clone(),
        findings,
        schema_discovered: config.check_introspection,
        scan_duration_ms: 0, // Would be set by caller
    })
}

/// Convert GraphQL findings to WebAppFindings for unified reporting
pub fn to_webapp_findings(graphql_result: &GraphQLScanResult) -> Vec<WebAppFinding> {
    graphql_result.findings.iter().map(|f| {
        WebAppFinding {
            finding_type: crate::types::FindingType::Other,
            url: graphql_result.endpoint.url.clone(),
            parameter: f.field.clone(),
            evidence: f.evidence.clone(),
            severity: f.severity.clone(),
            remediation: f.remediation.clone(),
        }
    }).collect()
}

fn calculate_severity_breakdown(findings: &[GraphQLFinding]) -> (usize, usize, usize, usize) {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    for f in findings {
        match f.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
        }
    }

    (critical, high, medium, low)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_framework_apollo() {
        let body = r#"{"extensions":{"apollo":true}}"#;
        assert_eq!(detect_framework(body), Some("Apollo Server".to_string()));
    }

    #[test]
    fn test_detect_framework_hasura() {
        let body = r#"{"extensions":{"Hasura":true}}"#;
        assert_eq!(detect_framework(body), Some("Hasura".to_string()));
    }

    #[test]
    fn test_detect_framework_unknown() {
        let body = r#"{"data":{"user":null}}"#;
        assert_eq!(detect_framework(body), None);
    }

    #[test]
    fn test_severity_breakdown() {
        let findings = vec![
            GraphQLFinding {
                finding_type: types::GraphQLFindingType::IntrospectionEnabled,
                severity: Severity::Medium,
                title: "Test".to_string(),
                description: "Test".to_string(),
                evidence: "Test".to_string(),
                remediation: "Test".to_string(),
                field: None,
                cwe_id: None,
            },
            GraphQLFinding {
                finding_type: types::GraphQLFindingType::SqlInjection,
                severity: Severity::Critical,
                title: "Test".to_string(),
                description: "Test".to_string(),
                evidence: "Test".to_string(),
                remediation: "Test".to_string(),
                field: None,
                cwe_id: None,
            },
        ];

        let (crit, high, med, low) = calculate_severity_breakdown(&findings);
        assert_eq!(crit, 1);
        assert_eq!(high, 0);
        assert_eq!(med, 1);
        assert_eq!(low, 0);
    }
}
