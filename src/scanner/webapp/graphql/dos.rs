//! GraphQL DoS Attack Vector Testing
//!
//! Tests for denial of service vulnerabilities:
//! - Query depth attacks
//! - Batch query abuse
//! - Circular fragment attacks
//! - Alias overloading
//! - Field duplication
//! - Resource exhaustion

use anyhow::Result;
use log::{debug, info, warn};
use reqwest::Client;
use serde_json::{json, Value};
use url::Url;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::types::Severity;
use super::types::{GraphQLFinding, GraphQLFindingType, GraphQLScanConfig};

/// Test for DoS attack vectors
pub async fn test_dos_vectors(
    client: &Client,
    url: &Url,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    // Test 1: Query depth attack
    info!("Testing query depth limits");
    let depth_findings = test_query_depth(client, url, config).await?;
    findings.extend(depth_findings);

    sleep(Duration::from_millis(config.rate_limit_ms)).await;

    // Test 2: Batch query abuse
    info!("Testing batch query limits");
    let batch_findings = test_batch_queries(client, url, config).await?;
    findings.extend(batch_findings);

    sleep(Duration::from_millis(config.rate_limit_ms)).await;

    // Test 3: Alias overloading
    info!("Testing alias overloading");
    let alias_findings = test_alias_overloading(client, url, config).await?;
    findings.extend(alias_findings);

    sleep(Duration::from_millis(config.rate_limit_ms)).await;

    // Test 4: Field duplication
    info!("Testing field duplication");
    let dup_findings = test_field_duplication(client, url, config).await?;
    findings.extend(dup_findings);

    sleep(Duration::from_millis(config.rate_limit_ms)).await;

    // Test 5: Circular fragments
    info!("Testing circular fragments");
    let fragment_findings = test_circular_fragments(client, url, config).await?;
    findings.extend(fragment_findings);

    Ok(findings)
}

/// Test for query depth limits
async fn test_query_depth(
    client: &Client,
    url: &Url,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    // Test progressively deeper queries
    let depths = [5, 10, 15, 20, 50, 100];
    let mut max_allowed_depth = 0;

    for depth in depths {
        if depth > config.max_query_depth * 2 {
            break;
        }

        let query = build_deep_query(depth);
        let start = Instant::now();
        let response = send_graphql_query(client, url, &query).await?;
        let elapsed = start.elapsed();

        if let Some(body) = response {
            // Check if query was processed (no depth error)
            if body.contains("\"data\"") && !body.to_lowercase().contains("depth") {
                max_allowed_depth = depth;
                debug!("Depth {} query accepted ({}ms)", depth, elapsed.as_millis());
            } else if body.to_lowercase().contains("depth") ||
                      body.to_lowercase().contains("limit") ||
                      body.to_lowercase().contains("too complex") {
                debug!("Depth {} query rejected", depth);
                break;
            }

            // Check for slow response (potential DoS indicator)
            if elapsed > Duration::from_secs(5) {
                findings.push(
                    GraphQLFinding::new(
                        GraphQLFindingType::ResourceExhaustion,
                        Severity::Medium,
                        "Slow Query Processing Detected",
                        format!(
                            "A deeply nested query (depth {}) took {}ms to process. This could indicate vulnerability to DoS attacks via complex queries.",
                            depth, elapsed.as_millis()
                        ),
                        format!("Query depth: {} | Response time: {:?}", depth, elapsed),
                        "Implement query depth limiting and query complexity analysis. Set appropriate timeouts for query processing.",
                    )
                );
            }
        }

        sleep(Duration::from_millis(config.rate_limit_ms)).await;
    }

    // Report if high depth queries are allowed
    if max_allowed_depth >= 10 {
        findings.push(GraphQLFinding::new(
            GraphQLFindingType::QueryDepthExceeded,
            if max_allowed_depth >= 20 { Severity::High } else { Severity::Medium },
            "Insufficient Query Depth Limit",
            format!(
                "The GraphQL endpoint accepts queries with depth of at least {}. Deep queries can be used to exhaust server resources.",
                max_allowed_depth
            ),
            format!("Maximum tested depth accepted: {}", max_allowed_depth),
            "Implement query depth limiting (recommended max: 5-7 for most applications). Use libraries like graphql-depth-limit for Node.js or similar for other frameworks.",
        ));
    }

    Ok(findings)
}

/// Build a deeply nested query
fn build_deep_query(depth: usize) -> String {
    let mut query = String::from("{ ");
    let mut closing = String::new();

    for i in 0..depth {
        if i == 0 {
            query.push_str("__type(name: \"Query\") { ");
        } else {
            query.push_str("ofType { ");
        }
        closing.push_str(" }");
    }

    query.push_str("name");
    query.push_str(&closing);
    query.push_str(" }");

    query
}

/// Test for batch query abuse
async fn test_batch_queries(
    client: &Client,
    url: &Url,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    // Test batch sizes
    let batch_sizes = [5, 10, 20, 50, 100];
    let mut max_accepted_batch = 0;

    for size in batch_sizes {
        if size > config.max_batch_size * 2 {
            break;
        }

        let queries: Vec<Value> = (0..size)
            .map(|i| json!({
                "query": format!("query q{} {{ __typename }}", i)
            }))
            .collect();

        let start = Instant::now();
        let response = send_batch_query(client, url, queries).await?;
        let elapsed = start.elapsed();

        if let Some(body) = response {
            // Check if batch was processed
            if body.starts_with('[') || (body.contains("\"data\"") && !body.contains("batch")) {
                max_accepted_batch = size;
                debug!("Batch of {} queries accepted ({}ms)", size, elapsed.as_millis());
            } else {
                debug!("Batch of {} queries rejected", size);
                break;
            }

            // Check for slow response
            if elapsed > Duration::from_secs(5) {
                findings.push(
                    GraphQLFinding::new(
                        GraphQLFindingType::ResourceExhaustion,
                        Severity::Medium,
                        "Slow Batch Query Processing",
                        format!(
                            "A batch of {} queries took {}ms to process. Large batch queries can be used for DoS attacks.",
                            size, elapsed.as_millis()
                        ),
                        format!("Batch size: {} | Response time: {:?}", size, elapsed),
                        "Implement batch query limits. Limit the number of operations that can be sent in a single request.",
                    )
                );
            }
        }

        sleep(Duration::from_millis(config.rate_limit_ms)).await;
    }

    if max_accepted_batch >= 20 {
        findings.push(GraphQLFinding::new(
            GraphQLFindingType::BatchQueryAbuse,
            if max_accepted_batch >= 50 { Severity::High } else { Severity::Medium },
            "Large Batch Queries Allowed",
            format!(
                "The GraphQL endpoint accepts batch queries with at least {} operations. Large batch queries can be used to amplify attacks or exhaust resources.",
                max_accepted_batch
            ),
            format!("Maximum tested batch size accepted: {}", max_accepted_batch),
            "Limit batch query sizes (recommended: 10-20 operations max). Implement per-request operation limits. Consider disabling batching if not needed.",
        ));
    }

    Ok(findings)
}

/// Test for alias overloading
async fn test_alias_overloading(
    client: &Client,
    url: &Url,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    // Test with many aliases for the same field
    let alias_counts = [10, 50, 100, 500, 1000];
    let mut max_accepted_aliases = 0;

    for count in alias_counts {
        let query = build_alias_query(count);

        let start = Instant::now();
        let response = send_graphql_query(client, url, &query).await?;
        let elapsed = start.elapsed();

        if let Some(body) = response {
            // Check if query was processed
            if body.contains("\"data\"") && !body.to_lowercase().contains("alias") {
                max_accepted_aliases = count;
                debug!("{} aliases accepted ({}ms)", count, elapsed.as_millis());
            } else {
                debug!("{} aliases rejected", count);
                break;
            }

            // Check for slow response
            if elapsed > Duration::from_secs(3) {
                findings.push(
                    GraphQLFinding::new(
                        GraphQLFindingType::AliasOverloading,
                        Severity::Medium,
                        "Alias Overloading Attack Vector",
                        format!(
                            "A query with {} aliases took {}ms to process. Alias overloading can be used to amplify resource consumption.",
                            count, elapsed.as_millis()
                        ),
                        format!("Alias count: {} | Response time: {:?}", count, elapsed),
                        "Limit the number of aliases per field and per query. Implement query complexity analysis that accounts for aliases.",
                    )
                );
            }
        }

        sleep(Duration::from_millis(config.rate_limit_ms)).await;
    }

    if max_accepted_aliases >= 100 {
        findings.push(GraphQLFinding::new(
            GraphQLFindingType::AliasOverloading,
            if max_accepted_aliases >= 500 { Severity::High } else { Severity::Medium },
            "No Alias Limit Detected",
            format!(
                "The GraphQL endpoint accepts queries with at least {} aliases. Alias overloading can multiply query complexity and resource consumption.",
                max_accepted_aliases
            ),
            format!("Maximum tested alias count accepted: {}", max_accepted_aliases),
            "Implement alias limits per query. Consider limiting total number of selections in a query. Use query complexity analysis.",
        ));
    }

    Ok(findings)
}

/// Build a query with many aliases
fn build_alias_query(count: usize) -> String {
    let mut query = String::from("{ ");

    for i in 0..count {
        query.push_str(&format!("a{}: __typename ", i));
    }

    query.push('}');
    query
}

/// Test for field duplication
async fn test_field_duplication(
    client: &Client,
    url: &Url,
    _config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    // Build query with many duplicate fields
    let dup_counts = [10, 100, 500];

    for count in dup_counts {
        let query = build_duplicate_field_query(count);

        let start = Instant::now();
        let response = send_graphql_query(client, url, &query).await?;
        let elapsed = start.elapsed();

        if let Some(body) = response {
            if body.contains("\"data\"") && elapsed > Duration::from_secs(2) {
                findings.push(
                    GraphQLFinding::new(
                        GraphQLFindingType::FieldDuplication,
                        Severity::Medium,
                        "Field Duplication Attack Vector",
                        format!(
                            "A query with {} duplicate fields took {}ms to process. Field duplication can be used to exhaust server resources.",
                            count, elapsed.as_millis()
                        ),
                        format!("Duplicate field count: {} | Response time: {:?}", count, elapsed),
                        "Implement query complexity analysis that detects duplicate fields. Consider deduplicating identical selections before execution.",
                    )
                );
                break;
            }
        }
    }

    Ok(findings)
}

/// Build a query with duplicate fields
fn build_duplicate_field_query(count: usize) -> String {
    let mut query = String::from("{ ");

    for _ in 0..count {
        query.push_str("__typename ");
    }

    query.push('}');
    query
}

/// Test for circular fragment attacks
async fn test_circular_fragments(
    client: &Client,
    url: &Url,
    _config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    // Test circular fragment (should be rejected by spec-compliant servers)
    let circular_queries = [
        // Direct circular reference
        r#"
        fragment A on Query {
            ...B
        }
        fragment B on Query {
            ...A
        }
        { ...A }
        "#,
        // Indirect circular reference
        r#"
        fragment A on Query {
            ...B
        }
        fragment B on Query {
            ...C
        }
        fragment C on Query {
            ...A
        }
        { ...A }
        "#,
        // Self-referencing fragment spread
        r#"
        fragment User on Query {
            __typename
            ...User
        }
        { ...User }
        "#,
    ];

    for query in circular_queries {
        let response = send_graphql_query(client, url, query).await?;

        if let Some(body) = response {
            // Circular fragments should always be rejected
            if body.contains("\"data\"") && !body.contains("\"errors\"") {
                findings.push(
                    GraphQLFinding::new(
                        GraphQLFindingType::CircularFragmentAttack,
                        Severity::High,
                        "Circular Fragment Attack Possible",
                        "The GraphQL endpoint appears to accept circular fragment references. This violates the GraphQL specification and could lead to infinite loops and server crashes.",
                        "Circular fragment query was accepted",
                        "Update your GraphQL library to a version that properly validates fragment cycles. Ensure validation rules are enabled.",
                    )
                );
                break;
            }
        }
    }

    Ok(findings)
}

/// Send a GraphQL query
async fn send_graphql_query(
    client: &Client,
    url: &Url,
    query: &str,
) -> Result<Option<String>> {
    let query_body = json!({ "query": query });

    let response = client
        .post(url.as_str())
        .header("Content-Type", "application/json")
        .json(&query_body)
        .timeout(Duration::from_secs(30))
        .send()
        .await;

    match response {
        Ok(resp) => {
            let body = resp.text().await?;
            Ok(Some(body))
        }
        Err(e) => {
            if e.is_timeout() {
                debug!("Query timed out - this might indicate DoS vulnerability");
            }
            Ok(None)
        }
    }
}

/// Send a batch GraphQL query
async fn send_batch_query(
    client: &Client,
    url: &Url,
    queries: Vec<Value>,
) -> Result<Option<String>> {
    let response = client
        .post(url.as_str())
        .header("Content-Type", "application/json")
        .json(&queries)
        .timeout(Duration::from_secs(30))
        .send()
        .await;

    match response {
        Ok(resp) => {
            let body = resp.text().await?;
            Ok(Some(body))
        }
        Err(e) => {
            if e.is_timeout() {
                debug!("Batch query timed out");
            }
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_deep_query() {
        let query = build_deep_query(3);
        assert!(query.contains("__type"));
        assert!(query.contains("ofType"));
        assert!(query.contains("name"));
        // Count the closing braces
        assert_eq!(query.matches('}').count(), 4);
    }

    #[test]
    fn test_build_alias_query() {
        let query = build_alias_query(5);
        assert!(query.contains("a0: __typename"));
        assert!(query.contains("a4: __typename"));
        assert_eq!(query.matches("__typename").count(), 5);
    }

    #[test]
    fn test_build_duplicate_field_query() {
        let query = build_duplicate_field_query(3);
        assert_eq!(query.matches("__typename").count(), 3);
    }
}
