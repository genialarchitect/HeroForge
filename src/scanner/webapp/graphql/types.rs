//! GraphQL Security Scanner Types

use serde::{Deserialize, Serialize};
use crate::types::Severity;

/// GraphQL endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLEndpoint {
    pub url: String,
    pub introspection_enabled: bool,
    pub supports_batching: Option<bool>,
    pub has_mutations: Option<bool>,
    pub has_subscriptions: Option<bool>,
    pub framework: Option<String>,
}

/// GraphQL scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLScanConfig {
    /// Check for introspection exposure
    pub check_introspection: bool,
    /// Test for injection vulnerabilities
    pub check_injection: bool,
    /// Test DoS attack vectors
    pub check_dos: bool,
    /// Test authorization controls
    pub check_authorization: bool,
    /// Maximum query depth to test
    pub max_query_depth: usize,
    /// Maximum batch size to test
    pub max_batch_size: usize,
    /// Custom headers to include
    pub custom_headers: Vec<(String, String)>,
    /// JWT token for authenticated testing
    pub auth_token: Option<String>,
    /// Rate limit delay between requests (ms)
    pub rate_limit_ms: u64,
}

impl Default for GraphQLScanConfig {
    fn default() -> Self {
        Self {
            check_introspection: true,
            check_injection: true,
            check_dos: true,
            check_authorization: true,
            max_query_depth: 10,
            max_batch_size: 20,
            custom_headers: Vec::new(),
            auth_token: None,
            rate_limit_ms: 100,
        }
    }
}

/// GraphQL scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLScanResult {
    pub endpoint: GraphQLEndpoint,
    pub findings: Vec<GraphQLFinding>,
    pub schema_discovered: bool,
    pub scan_duration_ms: u64,
}

/// Types of GraphQL security findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GraphQLFindingType {
    // Introspection
    IntrospectionEnabled,
    SensitiveFieldExposed,
    DeprecatedFieldUsed,
    InternalTypeExposed,
    FieldSuggestionsEnabled,

    // Injection
    SqlInjection,
    NoSqlInjection,
    CommandInjection,
    ServerSideRequestForgery,
    PathTraversal,
    LdapInjection,

    // DoS
    QueryDepthExceeded,
    BatchQueryAbuse,
    CircularFragmentAttack,
    ResourceExhaustion,
    AliasOverloading,
    FieldDuplication,

    // Authorization
    BrokenAuthentication,
    Idor,
    MissingAuthCheck,
    PrivilegeEscalation,

    // Other
    InformationDisclosure,
    InsecureDirective,
    RateLimitBypass,
    CorsConfiguration,
}

impl GraphQLFindingType {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::IntrospectionEnabled => "Introspection Enabled",
            Self::SensitiveFieldExposed => "Sensitive Field Exposed",
            Self::DeprecatedFieldUsed => "Deprecated Field in Use",
            Self::InternalTypeExposed => "Internal Type Exposed",
            Self::FieldSuggestionsEnabled => "Field Suggestions Enabled",
            Self::SqlInjection => "SQL Injection",
            Self::NoSqlInjection => "NoSQL Injection",
            Self::CommandInjection => "Command Injection",
            Self::ServerSideRequestForgery => "Server-Side Request Forgery (SSRF)",
            Self::PathTraversal => "Path Traversal",
            Self::LdapInjection => "LDAP Injection",
            Self::QueryDepthExceeded => "Query Depth Limit Missing",
            Self::BatchQueryAbuse => "Batch Query Abuse",
            Self::CircularFragmentAttack => "Circular Fragment Attack",
            Self::ResourceExhaustion => "Resource Exhaustion",
            Self::AliasOverloading => "Alias Overloading Attack",
            Self::FieldDuplication => "Field Duplication Attack",
            Self::BrokenAuthentication => "Broken Authentication",
            Self::Idor => "Insecure Direct Object Reference (IDOR)",
            Self::MissingAuthCheck => "Missing Authorization Check",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::InformationDisclosure => "Information Disclosure",
            Self::InsecureDirective => "Insecure Directive",
            Self::RateLimitBypass => "Rate Limit Bypass",
            Self::CorsConfiguration => "CORS Misconfiguration",
        }
    }

    pub fn cwe_id(&self) -> Option<u32> {
        match self {
            Self::IntrospectionEnabled => Some(200),  // Information Exposure
            Self::SensitiveFieldExposed => Some(200),
            Self::SqlInjection => Some(89),           // SQL Injection
            Self::NoSqlInjection => Some(943),        // NoSQL Injection
            Self::CommandInjection => Some(78),       // OS Command Injection
            Self::ServerSideRequestForgery => Some(918), // SSRF
            Self::PathTraversal => Some(22),          // Path Traversal
            Self::LdapInjection => Some(90),          // LDAP Injection
            Self::QueryDepthExceeded => Some(400),    // Resource Exhaustion
            Self::BatchQueryAbuse => Some(400),
            Self::CircularFragmentAttack => Some(400),
            Self::ResourceExhaustion => Some(400),
            Self::AliasOverloading => Some(400),
            Self::FieldDuplication => Some(400),
            Self::BrokenAuthentication => Some(287),  // Improper Authentication
            Self::Idor => Some(639),                  // Authorization Bypass
            Self::MissingAuthCheck => Some(862),      // Missing Authorization
            Self::PrivilegeEscalation => Some(269),   // Improper Privilege Management
            Self::InformationDisclosure => Some(200),
            Self::FieldSuggestionsEnabled => Some(200),
            Self::DeprecatedFieldUsed => None,
            Self::InternalTypeExposed => Some(200),
            Self::InsecureDirective => Some(16),      // Configuration
            Self::RateLimitBypass => Some(770),       // Allocation without Limits
            Self::CorsConfiguration => Some(346),     // Origin Validation Error
        }
    }
}

/// A GraphQL security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLFinding {
    pub finding_type: GraphQLFindingType,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
    pub field: Option<String>,
    pub cwe_id: Option<u32>,
}

impl GraphQLFinding {
    pub fn new(
        finding_type: GraphQLFindingType,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
        evidence: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        let cwe_id = finding_type.cwe_id();
        Self {
            finding_type,
            severity,
            title: title.into(),
            description: description.into(),
            evidence: evidence.into(),
            remediation: remediation.into(),
            field: None,
            cwe_id,
        }
    }

    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }
}

/// Parsed GraphQL schema information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphQLSchema {
    pub types: Vec<GraphQLType>,
    pub queries: Vec<GraphQLField>,
    pub mutations: Vec<GraphQLField>,
    pub subscriptions: Vec<GraphQLField>,
    pub directives: Vec<String>,
}

/// A GraphQL type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLType {
    pub name: String,
    pub kind: GraphQLTypeKind,
    pub fields: Vec<GraphQLField>,
    pub is_internal: bool,
}

/// Kind of GraphQL type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GraphQLTypeKind {
    Object,
    Interface,
    Union,
    Enum,
    InputObject,
    Scalar,
}

/// A GraphQL field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLField {
    pub name: String,
    pub return_type: String,
    pub arguments: Vec<GraphQLArgument>,
    pub is_deprecated: bool,
    pub deprecation_reason: Option<String>,
    pub description: Option<String>,
}

/// A GraphQL argument
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLArgument {
    pub name: String,
    pub argument_type: String,
    pub is_required: bool,
    pub default_value: Option<String>,
}

/// Sensitive field patterns to detect
pub const SENSITIVE_FIELD_PATTERNS: &[&str] = &[
    "password",
    "secret",
    "token",
    "apikey",
    "api_key",
    "apiKey",
    "private",
    "credential",
    "ssn",
    "social_security",
    "credit_card",
    "creditCard",
    "cvv",
    "pin",
    "auth",
    "session",
    "cookie",
    "jwt",
    "bearer",
    "oauth",
    "refresh_token",
    "access_token",
    "admin",
    "root",
    "sudo",
    "internal",
    "debug",
    "test",
    "staging",
    "dev",
    "development",
];

/// Internal type prefixes to detect
pub const INTERNAL_TYPE_PREFIXES: &[&str] = &[
    "_",
    "__",
    "Internal",
    "Private",
    "Admin",
    "Debug",
    "Test",
    "Dev",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graphql_scan_config_default() {
        let config = GraphQLScanConfig::default();
        assert!(config.check_introspection);
        assert!(config.check_injection);
        assert!(config.check_dos);
        assert!(config.check_authorization);
        assert_eq!(config.max_query_depth, 10);
        assert_eq!(config.max_batch_size, 20);
    }

    #[test]
    fn test_finding_type_cwe() {
        assert_eq!(GraphQLFindingType::SqlInjection.cwe_id(), Some(89));
        assert_eq!(GraphQLFindingType::Idor.cwe_id(), Some(639));
        assert_eq!(GraphQLFindingType::DeprecatedFieldUsed.cwe_id(), None);
    }

    #[test]
    fn test_finding_type_display() {
        assert_eq!(
            GraphQLFindingType::IntrospectionEnabled.display_name(),
            "Introspection Enabled"
        );
        assert_eq!(
            GraphQLFindingType::SqlInjection.display_name(),
            "SQL Injection"
        );
    }

    #[test]
    fn test_graphql_finding_new() {
        let finding = GraphQLFinding::new(
            GraphQLFindingType::SqlInjection,
            Severity::Critical,
            "SQL Injection in user query",
            "SQL injection vulnerability detected",
            "' OR 1=1 --",
            "Use parameterized queries",
        );

        assert_eq!(finding.cwe_id, Some(89));
        assert!(finding.field.is_none());
    }

    #[test]
    fn test_graphql_finding_with_field() {
        let finding = GraphQLFinding::new(
            GraphQLFindingType::SensitiveFieldExposed,
            Severity::High,
            "Password field exposed",
            "Password field visible in schema",
            "user { password }",
            "Remove or protect sensitive fields",
        ).with_field("password");

        assert_eq!(finding.field, Some("password".to_string()));
    }

    #[test]
    fn test_sensitive_patterns() {
        assert!(SENSITIVE_FIELD_PATTERNS.contains(&"password"));
        assert!(SENSITIVE_FIELD_PATTERNS.contains(&"apiKey"));
        assert!(!SENSITIVE_FIELD_PATTERNS.contains(&"username"));
    }
}
