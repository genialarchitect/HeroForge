//! GraphQL Authorization Testing
//!
//! Tests for authorization vulnerabilities:
//! - Broken authentication detection
//! - IDOR (Insecure Direct Object Reference)
//! - Missing authorization checks
//! - Privilege escalation
//! - Authorization bypass techniques

use anyhow::Result;
use log::{debug, info, warn};
use reqwest::Client;
use serde_json::{json, Value};
use url::Url;
use std::time::Duration;
use tokio::time::sleep;

use crate::types::Severity;
use super::types::{GraphQLFinding, GraphQLFindingType, GraphQLScanConfig};

/// Test for authorization vulnerabilities
pub async fn test_authorization(
    client: &Client,
    url: &Url,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    // Test 1: Unauthenticated access to sensitive queries
    info!("Testing unauthenticated access");
    let unauth_findings = test_unauthenticated_access(client, url, config).await?;
    findings.extend(unauth_findings);

    sleep(Duration::from_millis(config.rate_limit_ms)).await;

    // Test 2: IDOR vulnerabilities
    info!("Testing for IDOR vulnerabilities");
    let idor_findings = test_idor(client, url, config).await?;
    findings.extend(idor_findings);

    sleep(Duration::from_millis(config.rate_limit_ms)).await;

    // Test 3: Privilege escalation via mutations
    info!("Testing for privilege escalation");
    let privesc_findings = test_privilege_escalation(client, url, config).await?;
    findings.extend(privesc_findings);

    sleep(Duration::from_millis(config.rate_limit_ms)).await;

    // Test 4: Authorization bypass techniques
    info!("Testing authorization bypass");
    let bypass_findings = test_authorization_bypass(client, url, config).await?;
    findings.extend(bypass_findings);

    Ok(findings)
}

/// Test for unauthenticated access to sensitive operations
async fn test_unauthenticated_access(
    client: &Client,
    url: &Url,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    // Sensitive queries that should require authentication
    let sensitive_queries = [
        // User data queries
        (r#"{ users { id email name } }"#, "users", "list all users"),
        (r#"{ user(id: "1") { id email password } }"#, "user", "access user details"),
        (r#"{ me { id email role } }"#, "me", "access current user"),
        (r#"{ currentUser { id email permissions } }"#, "currentUser", "access current user"),

        // Admin queries
        (r#"{ adminUsers { id email } }"#, "adminUsers", "list admin users"),
        (r#"{ allUsers { id email role } }"#, "allUsers", "list all users"),
        (r#"{ systemSettings { key value } }"#, "systemSettings", "access system settings"),
        (r#"{ config { database apiKeys } }"#, "config", "access configuration"),

        // Financial data
        (r#"{ orders { id amount customerEmail } }"#, "orders", "list orders"),
        (r#"{ transactions { id amount status } }"#, "transactions", "list transactions"),
        (r#"{ payments { id cardLast4 amount } }"#, "payments", "list payments"),

        // Sensitive operations
        (r#"{ logs { timestamp action user } }"#, "logs", "access logs"),
        (r#"{ auditTrail { action user timestamp } }"#, "auditTrail", "access audit trail"),
        (r#"{ secrets { key value } }"#, "secrets", "access secrets"),
    ];

    // Build a client without authentication
    let unauth_client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    for (query, query_name, description) in sensitive_queries {
        let response = send_graphql_query(&unauth_client, url, query).await?;

        if let Some(body) = response {
            // Check if query returned data without authentication
            if body.contains("\"data\"") && !body.contains("\"errors\"") {
                // Parse to verify it's not just null data
                if let Ok(json) = serde_json::from_str::<Value>(&body) {
                    let data = json.get("data").and_then(|d| d.get(query_name));

                    if let Some(result) = data {
                        if !result.is_null() && result != &Value::Array(vec![]) {
                            findings.push(
                                GraphQLFinding::new(
                                    GraphQLFindingType::BrokenAuthentication,
                                    Severity::High,
                                    format!("Unauthenticated Access: {}", query_name),
                                    format!(
                                        "The '{}' query ({}) is accessible without authentication. This could expose sensitive data to unauthorized users.",
                                        query_name, description
                                    ),
                                    format!("Query '{}' returned data without authentication", query_name),
                                    "Implement authentication checks at the resolver level. Use middleware or directives to enforce authentication for sensitive queries.",
                                ).with_field(query_name.to_string())
                            );
                        }
                    }
                }
            }
        }

        sleep(Duration::from_millis(config.rate_limit_ms)).await;
    }

    // Test sensitive mutations without auth
    let sensitive_mutations = [
        (r#"mutation { updateUser(id: "1", role: "admin") { id } }"#, "updateUser"),
        (r#"mutation { deleteUser(id: "1") { success } }"#, "deleteUser"),
        (r#"mutation { createAdmin(email: "test@test.com") { id } }"#, "createAdmin"),
        (r#"mutation { updateSettings(key: "debug", value: "true") { key } }"#, "updateSettings"),
    ];

    for (mutation, mutation_name) in sensitive_mutations {
        let response = send_graphql_query(&unauth_client, url, mutation).await?;

        if let Some(body) = response {
            if body.contains("\"data\"") && !body.contains("\"errors\"") {
                if let Ok(json) = serde_json::from_str::<Value>(&body) {
                    let data = json.get("data").and_then(|d| d.get(mutation_name));

                    if let Some(result) = data {
                        if !result.is_null() {
                            findings.push(
                                GraphQLFinding::new(
                                    GraphQLFindingType::BrokenAuthentication,
                                    Severity::Critical,
                                    format!("Unauthenticated Mutation: {}", mutation_name),
                                    format!(
                                        "The '{}' mutation is accessible without authentication. This could allow unauthorized data modification.",
                                        mutation_name
                                    ),
                                    format!("Mutation '{}' succeeded without authentication", mutation_name),
                                    "Require authentication for all mutations. Use middleware or directives to enforce authentication.",
                                ).with_field(mutation_name.to_string())
                            );
                        }
                    }
                }
            }
        }

        sleep(Duration::from_millis(config.rate_limit_ms)).await;
    }

    Ok(findings)
}

/// Test for IDOR vulnerabilities
async fn test_idor(
    client: &Client,
    url: &Url,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    // Test sequential ID access
    let idor_queries = [
        // User data with different IDs
        (r#"{ user(id: "1") { id email name } }"#, "user"),
        (r#"{ user(id: "2") { id email name } }"#, "user"),
        (r#"{ user(id: "100") { id email name } }"#, "user"),
        // Document/file access
        (r#"{ document(id: "1") { id content owner } }"#, "document"),
        (r#"{ file(id: "1") { id path owner } }"#, "file"),
        // Order/transaction access
        (r#"{ order(id: "1") { id amount customerEmail } }"#, "order"),
        (r#"{ order(id: "ORD-001") { id amount } }"#, "order"),
        // Message/conversation access
        (r#"{ message(id: "1") { id content sender recipient } }"#, "message"),
        (r#"{ conversation(id: "1") { messages { content } } }"#, "conversation"),
    ];

    let mut successful_queries = Vec::new();

    for (query, query_name) in idor_queries {
        let response = send_graphql_query(client, url, query).await?;

        if let Some(body) = response {
            if body.contains("\"data\"") && !body.contains("\"errors\"") {
                if let Ok(json) = serde_json::from_str::<Value>(&body) {
                    let data = json.get("data").and_then(|d| d.get(query_name));

                    if let Some(result) = data {
                        if !result.is_null() {
                            successful_queries.push(query_name.to_string());
                        }
                    }
                }
            }
        }

        sleep(Duration::from_millis(config.rate_limit_ms)).await;
    }

    // Report IDOR if multiple IDs for same resource type succeeded
    let mut seen_types = std::collections::HashSet::new();
    for query_name in &successful_queries {
        if !seen_types.insert(query_name.clone()) {
            findings.push(
                GraphQLFinding::new(
                    GraphQLFindingType::Idor,
                    Severity::High,
                    format!("Potential IDOR in {} Query", query_name),
                    format!(
                        "The '{}' query accepts different IDs and returns data for multiple resources. This could indicate an IDOR vulnerability where users can access other users' data by manipulating IDs.",
                        query_name
                    ),
                    format!("Multiple ID values returned data for '{}'", query_name),
                    "Implement authorization checks that verify the requesting user has permission to access the requested resource. Use the current user context to validate access.",
                ).with_field(query_name.clone())
            );
            break; // One finding per type
        }
    }

    // Test UUID enumeration
    let uuid_queries = [
        r#"{ user(id: "00000000-0000-0000-0000-000000000001") { id } }"#,
        r#"{ user(id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa") { id } }"#,
    ];

    for query in uuid_queries {
        let response = send_graphql_query(client, url, query).await?;

        if let Some(body) = response {
            if body.contains("\"data\"") && !body.contains("null") && !body.contains("\"errors\"") {
                findings.push(
                    GraphQLFinding::new(
                        GraphQLFindingType::Idor,
                        Severity::Medium,
                        "Predictable UUID Pattern",
                        "The GraphQL API accepts predictable UUID patterns. While UUIDs are harder to guess than sequential IDs, using predictable patterns like all-zeros could still allow enumeration.",
                        "Query with predictable UUID returned data",
                        "Verify user authorization regardless of ID format. Do not rely on ID unpredictability for security.",
                    )
                );
                break;
            }
        }

        sleep(Duration::from_millis(config.rate_limit_ms)).await;
    }

    Ok(findings)
}

/// Test for privilege escalation
async fn test_privilege_escalation(
    client: &Client,
    url: &Url,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    // Mutations that could escalate privileges
    let privesc_mutations = [
        // Role modifications
        (
            r#"mutation { updateUser(id: "1", role: "admin") { id role } }"#,
            "updateUser",
            "change user role to admin"
        ),
        (
            r#"mutation { setUserRole(userId: "1", role: "ADMIN") { success } }"#,
            "setUserRole",
            "set admin role"
        ),
        (
            r#"mutation { promoteToAdmin(userId: "1") { success } }"#,
            "promoteToAdmin",
            "promote to admin"
        ),

        // Permission modifications
        (
            r#"mutation { updatePermissions(userId: "1", permissions: ["*"]) { success } }"#,
            "updatePermissions",
            "grant all permissions"
        ),
        (
            r#"mutation { grantPermission(userId: "1", permission: "admin:*") { success } }"#,
            "grantPermission",
            "grant admin permission"
        ),

        // Direct database access
        (
            r#"mutation { executeSQL(query: "UPDATE users SET role='admin'") { affected } }"#,
            "executeSQL",
            "execute arbitrary SQL"
        ),
        (
            r#"mutation { rawQuery(query: "{$set: {isAdmin: true}}") { result } }"#,
            "rawQuery",
            "execute raw database query"
        ),

        // Feature flag/config modifications
        (
            r#"mutation { setFeatureFlag(name: "admin_access", enabled: true) { success } }"#,
            "setFeatureFlag",
            "enable admin feature flag"
        ),
        (
            r#"mutation { updateConfig(key: "debug_mode", value: "true") { success } }"#,
            "updateConfig",
            "enable debug mode"
        ),
    ];

    for (mutation, mutation_name, description) in privesc_mutations {
        let response = send_graphql_query(client, url, mutation).await?;

        if let Some(body) = response {
            if body.contains("\"data\"") && !body.contains("\"errors\"") {
                if let Ok(json) = serde_json::from_str::<Value>(&body) {
                    let data = json.get("data").and_then(|d| d.get(mutation_name));

                    if let Some(result) = data {
                        if !result.is_null() {
                            findings.push(
                                GraphQLFinding::new(
                                    GraphQLFindingType::PrivilegeEscalation,
                                    Severity::Critical,
                                    format!("Privilege Escalation: {}", mutation_name),
                                    format!(
                                        "The '{}' mutation ({}) appears to be accessible. This could allow attackers to escalate privileges or gain unauthorized access.",
                                        mutation_name, description
                                    ),
                                    format!("Mutation '{}' did not return an error", mutation_name),
                                    "Implement strict role-based access control (RBAC) for administrative mutations. Only allow authorized admins to perform privilege-modifying operations.",
                                ).with_field(mutation_name.to_string())
                            );
                        }
                    }
                }
            }
        }

        sleep(Duration::from_millis(config.rate_limit_ms)).await;
    }

    Ok(findings)
}

/// Test for authorization bypass techniques
async fn test_authorization_bypass(
    client: &Client,
    url: &Url,
    config: &GraphQLScanConfig,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    // Test bypass techniques
    let bypass_tests = [
        // Case manipulation
        (
            r#"{ USERS { id email } }"#,
            "USERS",
            "uppercase field name"
        ),
        (
            r#"{ Users { id email } }"#,
            "Users",
            "mixed case field name"
        ),

        // Alias bypass
        (
            r#"{ publicUsers: users { id email } }"#,
            "publicUsers",
            "alias for protected field"
        ),

        // Nested access
        (
            r#"{
                organization(id: "1") {
                    users { id email password }
                }
            }"#,
            "organization.users",
            "nested access to protected fields"
        ),

        // Indirect access via relationships
        (
            r#"{
                post(id: "1") {
                    author {
                        email
                        password
                        creditCard
                    }
                }
            }"#,
            "post.author",
            "access sensitive fields via relationship"
        ),

        // Mutation return value exploitation
        (
            r#"mutation {
                updateProfile(name: "test") {
                    id
                    email
                    password
                    role
                }
            }"#,
            "updateProfile",
            "access sensitive fields via mutation return"
        ),

        // Subscription bypass
        (
            r#"subscription {
                onUserUpdate { id email password }
            }"#,
            "onUserUpdate",
            "access sensitive fields via subscription"
        ),
    ];

    for (query, bypass_type, description) in bypass_tests {
        let response = send_graphql_query(client, url, query).await?;

        if let Some(body) = response {
            // Check for sensitive data in response
            let body_lower = body.to_lowercase();
            let contains_sensitive = body_lower.contains("password") ||
                                    body_lower.contains("creditcard") ||
                                    body_lower.contains("ssn") ||
                                    body_lower.contains("secret") ||
                                    body_lower.contains("token");

            if body.contains("\"data\"") && !body.contains("\"errors\"") && contains_sensitive {
                findings.push(
                    GraphQLFinding::new(
                        GraphQLFindingType::MissingAuthCheck,
                        Severity::High,
                        format!("Authorization Bypass via {}", bypass_type),
                        format!(
                            "Sensitive data was returned using {}. This could indicate that authorization checks can be bypassed.",
                            description
                        ),
                        format!("Bypass type: {} | Sensitive data returned", description),
                        "Implement field-level authorization. Ensure authorization checks are applied consistently regardless of how the field is accessed.",
                    ).with_field(bypass_type.to_string())
                );
            }
        }

        sleep(Duration::from_millis(config.rate_limit_ms)).await;
    }

    // Test directive bypass
    let directive_bypass = r#"
        query @skip(if: false) {
            users @deprecated(reason: "bypass") {
                id email password
            }
        }
    "#;

    let response = send_graphql_query(client, url, directive_bypass).await?;

    if let Some(body) = response {
        if body.contains("password") && !body.contains("\"errors\"") {
            findings.push(
                GraphQLFinding::new(
                    GraphQLFindingType::MissingAuthCheck,
                    Severity::Medium,
                    "Directive-Based Authorization Bypass",
                    "Authorization might be bypassable using GraphQL directives. The query with directives returned sensitive data.",
                    "Directive bypass query returned password field",
                    "Ensure directives don't interfere with authorization checks. Authorization should be enforced at the resolver level, not through directives.",
                )
            );
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
        .send()
        .await;

    match response {
        Ok(resp) => {
            let body = resp.text().await?;
            Ok(Some(body))
        }
        Err(e) => {
            debug!("Request failed: {}", e);
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_send_graphql_query() {
        // This test would require a mock server
        // Just verify the module compiles correctly
    }
}
