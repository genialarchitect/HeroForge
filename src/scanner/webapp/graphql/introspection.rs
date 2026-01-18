//! GraphQL Introspection Analysis
//!
//! Checks for introspection exposure and analyzes the schema for security issues.

use anyhow::Result;
use log::{info, debug, warn};
use reqwest::Client;
use serde_json::{json, Value};
use url::Url;

use crate::types::Severity;
use super::types::{
    GraphQLFinding, GraphQLFindingType, GraphQLSchema, GraphQLType,
    GraphQLTypeKind, GraphQLField, GraphQLArgument,
    SENSITIVE_FIELD_PATTERNS, INTERNAL_TYPE_PREFIXES,
};

/// Full introspection query to retrieve the complete schema
const FULL_INTROSPECTION_QUERY: &str = r#"
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}
"#;

/// Simple introspection query for detection
const SIMPLE_INTROSPECTION_QUERY: &str = r#"
{
  __schema {
    queryType { name }
    types { name kind }
  }
}
"#;

/// Check for introspection exposure and analyze schema
pub async fn check_introspection(
    client: &Client,
    url: &Url,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    // First check if introspection is enabled
    let introspection_result = send_introspection_query(client, url).await?;

    match introspection_result {
        Some(schema_data) => {
            // Introspection is enabled - this is a finding
            findings.push(GraphQLFinding::new(
                GraphQLFindingType::IntrospectionEnabled,
                Severity::Medium,
                "GraphQL Introspection Enabled",
                "The GraphQL endpoint allows introspection queries, which exposes the entire API schema including all types, fields, and relationships. This can aid attackers in understanding the API surface.",
                "Introspection query returned full schema",
                "Disable introspection in production environments. In Apollo Server, set `introspection: false`. In other frameworks, configure accordingly.",
            ));

            // Parse and analyze the schema
            if let Some(schema) = parse_schema(&schema_data) {
                // Check for sensitive fields
                let sensitive_findings = check_sensitive_fields(&schema);
                findings.extend(sensitive_findings);

                // Check for internal types
                let internal_findings = check_internal_types(&schema);
                findings.extend(internal_findings);

                // Check for deprecated fields in use
                let deprecated_findings = check_deprecated_fields(&schema);
                findings.extend(deprecated_findings);

                // Check for dangerous mutations
                let mutation_findings = check_dangerous_mutations(&schema);
                findings.extend(mutation_findings);
            }

            // Check for field suggestions
            let suggestion_finding = check_field_suggestions(client, url).await?;
            findings.extend(suggestion_finding);
        }
        None => {
            debug!("Introspection is disabled on this endpoint");

            // Still check for field suggestions which can leak info
            let suggestion_finding = check_field_suggestions(client, url).await?;
            findings.extend(suggestion_finding);
        }
    }

    Ok(findings)
}

/// Send introspection query and return schema data if successful
async fn send_introspection_query(
    client: &Client,
    url: &Url,
) -> Result<Option<Value>> {
    let query_body = json!({
        "query": FULL_INTROSPECTION_QUERY
    });

    let response = client
        .post(url.as_str())
        .header("Content-Type", "application/json")
        .json(&query_body)
        .send()
        .await?;

    let body: Value = response.json().await?;

    // Check if introspection was successful
    if body.get("data").and_then(|d| d.get("__schema")).is_some() {
        Ok(Some(body))
    } else if body.get("errors").is_some() {
        // Introspection might be disabled
        debug!("Introspection query returned errors: {:?}", body.get("errors"));
        Ok(None)
    } else {
        Ok(None)
    }
}

/// Parse introspection response into a GraphQLSchema
fn parse_schema(data: &Value) -> Option<GraphQLSchema> {
    let schema_data = data.get("data")?.get("__schema")?;

    let mut schema = GraphQLSchema::default();

    // Parse types
    if let Some(types) = schema_data.get("types").and_then(|t| t.as_array()) {
        for type_data in types {
            if let Some(parsed_type) = parse_type(type_data) {
                // Separate queries, mutations, subscriptions
                let query_type_name = schema_data
                    .get("queryType")
                    .and_then(|q| q.get("name"))
                    .and_then(|n| n.as_str());

                let mutation_type_name = schema_data
                    .get("mutationType")
                    .and_then(|m| m.get("name"))
                    .and_then(|n| n.as_str());

                let subscription_type_name = schema_data
                    .get("subscriptionType")
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str());

                if Some(parsed_type.name.as_str()) == query_type_name {
                    schema.queries = parsed_type.fields.clone();
                } else if Some(parsed_type.name.as_str()) == mutation_type_name {
                    schema.mutations = parsed_type.fields.clone();
                } else if Some(parsed_type.name.as_str()) == subscription_type_name {
                    schema.subscriptions = parsed_type.fields.clone();
                }

                schema.types.push(parsed_type);
            }
        }
    }

    // Parse directives
    if let Some(directives) = schema_data.get("directives").and_then(|d| d.as_array()) {
        for directive in directives {
            if let Some(name) = directive.get("name").and_then(|n| n.as_str()) {
                schema.directives.push(name.to_string());
            }
        }
    }

    Some(schema)
}

/// Parse a single GraphQL type
fn parse_type(data: &Value) -> Option<GraphQLType> {
    let name = data.get("name")?.as_str()?.to_string();
    let kind_str = data.get("kind")?.as_str()?;

    let kind = match kind_str {
        "OBJECT" => GraphQLTypeKind::Object,
        "INTERFACE" => GraphQLTypeKind::Interface,
        "UNION" => GraphQLTypeKind::Union,
        "ENUM" => GraphQLTypeKind::Enum,
        "INPUT_OBJECT" => GraphQLTypeKind::InputObject,
        "SCALAR" => GraphQLTypeKind::Scalar,
        _ => return None,
    };

    let mut fields = Vec::new();
    if let Some(fields_data) = data.get("fields").and_then(|f| f.as_array()) {
        for field_data in fields_data {
            if let Some(field) = parse_field(field_data) {
                fields.push(field);
            }
        }
    }

    let is_internal = name.starts_with("__");

    Some(GraphQLType {
        name,
        kind,
        fields,
        is_internal,
    })
}

/// Parse a single GraphQL field
fn parse_field(data: &Value) -> Option<GraphQLField> {
    let name = data.get("name")?.as_str()?.to_string();

    let return_type = extract_type_name(data.get("type")?);

    let mut arguments = Vec::new();
    if let Some(args) = data.get("args").and_then(|a| a.as_array()) {
        for arg_data in args {
            if let Some(arg) = parse_argument(arg_data) {
                arguments.push(arg);
            }
        }
    }

    let is_deprecated = data
        .get("isDeprecated")
        .and_then(|d| d.as_bool())
        .unwrap_or(false);

    let deprecation_reason = data
        .get("deprecationReason")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string());

    let description = data
        .get("description")
        .and_then(|d| d.as_str())
        .map(|s| s.to_string());

    Some(GraphQLField {
        name,
        return_type,
        arguments,
        is_deprecated,
        deprecation_reason,
        description,
    })
}

/// Parse a GraphQL argument
fn parse_argument(data: &Value) -> Option<GraphQLArgument> {
    let name = data.get("name")?.as_str()?.to_string();
    let argument_type = extract_type_name(data.get("type")?);

    let is_required = data
        .get("type")
        .and_then(|t| t.get("kind"))
        .and_then(|k| k.as_str())
        .map(|k| k == "NON_NULL")
        .unwrap_or(false);

    let default_value = data
        .get("defaultValue")
        .and_then(|d| d.as_str())
        .map(|s| s.to_string());

    Some(GraphQLArgument {
        name,
        argument_type,
        is_required,
        default_value,
    })
}

/// Extract type name from nested type reference
fn extract_type_name(type_data: &Value) -> String {
    if let Some(name) = type_data.get("name").and_then(|n| n.as_str()) {
        return name.to_string();
    }

    if let Some(of_type) = type_data.get("ofType") {
        return extract_type_name(of_type);
    }

    "Unknown".to_string()
}

/// Check for sensitive field exposure
fn check_sensitive_fields(schema: &GraphQLSchema) -> Vec<GraphQLFinding> {
    let mut findings = Vec::new();

    for gql_type in &schema.types {
        if gql_type.is_internal {
            continue;
        }

        for field in &gql_type.fields {
            let field_lower = field.name.to_lowercase();

            for pattern in SENSITIVE_FIELD_PATTERNS {
                if field_lower.contains(pattern) {
                    findings.push(
                        GraphQLFinding::new(
                            GraphQLFindingType::SensitiveFieldExposed,
                            Severity::High,
                            format!("Sensitive Field Exposed: {}.{}", gql_type.name, field.name),
                            format!(
                                "The field '{}' in type '{}' appears to contain sensitive data based on its name. This field is exposed in the GraphQL schema and could leak sensitive information.",
                                field.name, gql_type.name
                            ),
                            format!("Field '{}' matches sensitive pattern '{}'", field.name, pattern),
                            "Review this field and consider: 1) Removing it from the schema if not needed, 2) Implementing field-level authorization, 3) Renaming if the name is misleading, 4) Ensuring the field never returns actual sensitive data.",
                        ).with_field(format!("{}.{}", gql_type.name, field.name))
                    );
                    break;
                }
            }
        }
    }

    findings
}

/// Check for internal type exposure
fn check_internal_types(schema: &GraphQLSchema) -> Vec<GraphQLFinding> {
    let mut findings = Vec::new();

    for gql_type in &schema.types {
        if gql_type.is_internal || gql_type.name.starts_with("__") {
            continue;
        }

        for prefix in INTERNAL_TYPE_PREFIXES {
            if gql_type.name.starts_with(prefix) && *prefix != "_" && *prefix != "__" {
                findings.push(
                    GraphQLFinding::new(
                        GraphQLFindingType::InternalTypeExposed,
                        Severity::Low,
                        format!("Potentially Internal Type Exposed: {}", gql_type.name),
                        format!(
                            "The type '{}' appears to be an internal type based on its naming convention (starts with '{}'). Internal types should not be exposed in the public schema.",
                            gql_type.name, prefix
                        ),
                        format!("Type '{}' matches internal prefix '{}'", gql_type.name, prefix),
                        "Review whether this type should be public. If it's for internal use only, ensure it's not accessible through the GraphQL API.",
                    )
                );
                break;
            }
        }
    }

    findings
}

/// Check for deprecated fields still in use
fn check_deprecated_fields(schema: &GraphQLSchema) -> Vec<GraphQLFinding> {
    let mut findings = Vec::new();
    let mut deprecated_count = 0;

    for gql_type in &schema.types {
        if gql_type.is_internal {
            continue;
        }

        for field in &gql_type.fields {
            if field.is_deprecated {
                deprecated_count += 1;
            }
        }
    }

    if deprecated_count > 0 {
        findings.push(GraphQLFinding::new(
            GraphQLFindingType::DeprecatedFieldUsed,
            Severity::Low,
            format!("{} Deprecated Fields Found", deprecated_count),
            format!(
                "The schema contains {} deprecated field(s). While not a direct security issue, deprecated fields may have known vulnerabilities or may not receive security updates.",
                deprecated_count
            ),
            format!("{} fields marked as deprecated", deprecated_count),
            "Review deprecated fields and migrate clients to use newer alternatives. Consider removing deprecated fields after a transition period.",
        ));
    }

    findings
}

/// Check for dangerous mutations
fn check_dangerous_mutations(schema: &GraphQLSchema) -> Vec<GraphQLFinding> {
    let mut findings = Vec::new();

    let dangerous_patterns = [
        ("delete", "Deletion operations should have proper authorization"),
        ("remove", "Removal operations should have proper authorization"),
        ("drop", "Drop operations could be destructive"),
        ("admin", "Admin mutations require strict access control"),
        ("reset", "Reset operations could affect data integrity"),
        ("update_all", "Bulk update operations are risky"),
        ("truncate", "Truncate operations are destructive"),
        ("execute", "Execute operations could allow code execution"),
        ("raw", "Raw operations might bypass security controls"),
        ("debug", "Debug mutations should not be in production"),
    ];

    for mutation in &schema.mutations {
        let mutation_lower = mutation.name.to_lowercase();

        for (pattern, warning) in dangerous_patterns {
            if mutation_lower.contains(pattern) {
                findings.push(
                    GraphQLFinding::new(
                        GraphQLFindingType::MissingAuthCheck,
                        Severity::Medium,
                        format!("Potentially Dangerous Mutation: {}", mutation.name),
                        format!(
                            "The mutation '{}' appears to be a potentially dangerous operation. {}",
                            mutation.name, warning
                        ),
                        format!("Mutation '{}' matches pattern '{}'", mutation.name, pattern),
                        "Ensure this mutation has proper authorization checks. Implement role-based access control and audit logging for sensitive operations.",
                    ).with_field(mutation.name.clone())
                );
                break;
            }
        }
    }

    findings
}

/// Check if field suggestions are enabled (information disclosure)
async fn check_field_suggestions(
    client: &Client,
    url: &Url,
) -> Result<Vec<GraphQLFinding>> {
    let mut findings = Vec::new();

    // Send a query with a typo to check for suggestions
    let typo_query = json!({
        "query": "{ user { naame } }"  // Intentional typo
    });

    let response = client
        .post(url.as_str())
        .header("Content-Type", "application/json")
        .json(&typo_query)
        .send()
        .await?;

    let body: Value = response.json().await?;

    if let Some(errors) = body.get("errors").and_then(|e| e.as_array()) {
        for error in errors {
            if let Some(message) = error.get("message").and_then(|m| m.as_str()) {
                // Check for suggestion patterns
                if message.contains("Did you mean") ||
                   message.contains("did you mean") ||
                   message.contains("Unknown field") ||
                   message.contains("Cannot query field") {
                    findings.push(GraphQLFinding::new(
                        GraphQLFindingType::FieldSuggestionsEnabled,
                        Severity::Low,
                        "Field Suggestions Enabled",
                        "The GraphQL server provides field name suggestions in error messages. This can help attackers enumerate the schema even when introspection is disabled.",
                        format!("Error message: {}", message),
                        "Disable field suggestions in error messages for production environments. In Apollo Server, use a custom formatError function to sanitize error messages.",
                    ));
                    break;
                }
            }
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_type_name_simple() {
        let data = json!({"name": "String", "kind": "SCALAR"});
        assert_eq!(extract_type_name(&data), "String");
    }

    #[test]
    fn test_extract_type_name_nested() {
        let data = json!({
            "kind": "NON_NULL",
            "ofType": {
                "kind": "LIST",
                "ofType": {
                    "name": "User",
                    "kind": "OBJECT"
                }
            }
        });
        assert_eq!(extract_type_name(&data), "User");
    }

    #[test]
    fn test_check_sensitive_fields() {
        let schema = GraphQLSchema {
            types: vec![
                GraphQLType {
                    name: "User".to_string(),
                    kind: GraphQLTypeKind::Object,
                    fields: vec![
                        GraphQLField {
                            name: "password".to_string(),
                            return_type: "String".to_string(),
                            arguments: vec![],
                            is_deprecated: false,
                            deprecation_reason: None,
                            description: None,
                        },
                        GraphQLField {
                            name: "email".to_string(),
                            return_type: "String".to_string(),
                            arguments: vec![],
                            is_deprecated: false,
                            deprecation_reason: None,
                            description: None,
                        },
                    ],
                    is_internal: false,
                }
            ],
            queries: vec![],
            mutations: vec![],
            subscriptions: vec![],
            directives: vec![],
        };

        let findings = check_sensitive_fields(&schema);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("password"));
    }

    #[test]
    fn test_check_deprecated_fields() {
        let schema = GraphQLSchema {
            types: vec![
                GraphQLType {
                    name: "User".to_string(),
                    kind: GraphQLTypeKind::Object,
                    fields: vec![
                        GraphQLField {
                            name: "oldField".to_string(),
                            return_type: "String".to_string(),
                            arguments: vec![],
                            is_deprecated: true,
                            deprecation_reason: Some("Use newField instead".to_string()),
                            description: None,
                        },
                    ],
                    is_internal: false,
                }
            ],
            queries: vec![],
            mutations: vec![],
            subscriptions: vec![],
            directives: vec![],
        };

        let findings = check_deprecated_fields(&schema);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Deprecated"));
    }

    #[test]
    fn test_check_dangerous_mutations() {
        let schema = GraphQLSchema {
            types: vec![],
            queries: vec![],
            mutations: vec![
                GraphQLField {
                    name: "deleteAllUsers".to_string(),
                    return_type: "Boolean".to_string(),
                    arguments: vec![],
                    is_deprecated: false,
                    deprecation_reason: None,
                    description: None,
                },
                GraphQLField {
                    name: "createUser".to_string(),
                    return_type: "User".to_string(),
                    arguments: vec![],
                    is_deprecated: false,
                    deprecation_reason: None,
                    description: None,
                },
            ],
            subscriptions: vec![],
            directives: vec![],
        };

        let findings = check_dangerous_mutations(&schema);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("deleteAllUsers"));
    }
}
