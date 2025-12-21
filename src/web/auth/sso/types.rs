#![allow(dead_code)]
//! SSO Types - Shared types for SAML and OIDC authentication
//!
//! This module defines the core types used across SSO authentication methods.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// SSO Provider Type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SsoProviderType {
    /// SAML 2.0 Identity Provider
    Saml,
    /// OpenID Connect Provider
    Oidc,
}

impl std::fmt::Display for SsoProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsoProviderType::Saml => write!(f, "saml"),
            SsoProviderType::Oidc => write!(f, "oidc"),
        }
    }
}

impl std::str::FromStr for SsoProviderType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "saml" => Ok(SsoProviderType::Saml),
            "oidc" | "openid" | "openidconnect" => Ok(SsoProviderType::Oidc),
            _ => Err(format!("Unknown SSO provider type: {}", s)),
        }
    }
}

/// SSO Provider Status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SsoProviderStatus {
    /// Provider is active and can be used for authentication
    Active,
    /// Provider is disabled (cannot be used)
    Disabled,
    /// Provider configuration is incomplete
    Incomplete,
    /// Provider has configuration errors
    Error,
}

impl std::fmt::Display for SsoProviderStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsoProviderStatus::Active => write!(f, "active"),
            SsoProviderStatus::Disabled => write!(f, "disabled"),
            SsoProviderStatus::Incomplete => write!(f, "incomplete"),
            SsoProviderStatus::Error => write!(f, "error"),
        }
    }
}

/// SSO Provider - Configured identity provider
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SsoProvider {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub provider_type: String,
    pub status: String,
    /// Icon URL or CSS class for UI display
    pub icon: Option<String>,
    /// Provider-specific configuration (JSON)
    pub config: String,
    /// Attribute mappings (JSON) - maps IdP attributes to user fields
    pub attribute_mappings: Option<String>,
    /// Group to role mappings (JSON)
    pub group_mappings: Option<String>,
    /// Enable Just-in-Time user provisioning
    pub jit_provisioning: bool,
    /// Default role for JIT-provisioned users
    pub default_role: String,
    /// Allow updating existing users on login
    pub update_on_login: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// SSO Session - Tracks SSO sessions for single logout
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SsoSession {
    pub id: String,
    pub user_id: String,
    pub provider_id: String,
    /// SSO session index (SAML SessionIndex or OIDC session ID)
    pub session_index: Option<String>,
    /// IdP-provided name ID or subject
    pub name_id: Option<String>,
    /// Name ID format (SAML)
    pub name_id_format: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub logged_out_at: Option<DateTime<Utc>>,
}

/// Attribute mapping configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeMapping {
    /// IdP attribute name/OID
    pub source: String,
    /// HeroForge user field
    pub target: String,
    /// Whether this mapping is required
    pub required: bool,
    /// Default value if attribute is missing
    pub default_value: Option<String>,
}

/// Group to role mapping configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMapping {
    /// IdP group name or ID
    pub group: String,
    /// HeroForge role ID
    pub role: String,
    /// Priority (higher wins for conflicts)
    pub priority: i32,
}

/// SSO User info extracted from authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoUserInfo {
    /// Unique identifier from IdP
    pub subject: String,
    /// Email address
    pub email: Option<String>,
    /// Username
    pub username: Option<String>,
    /// Display name
    pub display_name: Option<String>,
    /// First name
    pub first_name: Option<String>,
    /// Last name
    pub last_name: Option<String>,
    /// Group memberships
    pub groups: Vec<String>,
    /// Raw attributes from IdP
    pub raw_attributes: serde_json::Value,
}

impl SsoUserInfo {
    /// Get the preferred username
    pub fn get_username(&self) -> String {
        self.username
            .clone()
            .or_else(|| self.email.clone())
            .unwrap_or_else(|| self.subject.clone())
    }

    /// Get the display name or construct from first/last name
    pub fn get_display_name(&self) -> Option<String> {
        self.display_name.clone().or_else(|| {
            match (&self.first_name, &self.last_name) {
                (Some(first), Some(last)) => Some(format!("{} {}", first, last)),
                (Some(first), None) => Some(first.clone()),
                (None, Some(last)) => Some(last.clone()),
                (None, None) => None,
            }
        })
    }
}

/// SAML-specific provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    /// IdP Entity ID
    pub idp_entity_id: String,
    /// IdP SSO URL
    pub idp_sso_url: String,
    /// IdP SLO URL (optional)
    pub idp_slo_url: Option<String>,
    /// IdP certificate (PEM format)
    pub idp_certificate: String,
    /// SP Entity ID (generated or custom)
    pub sp_entity_id: Option<String>,
    /// Request signing enabled
    pub sign_requests: bool,
    /// Response signing required
    pub require_signed_response: bool,
    /// Assertion signing required
    pub require_signed_assertion: bool,
    /// Encryption enabled
    pub encrypt_assertions: bool,
    /// NameID format
    pub name_id_format: Option<String>,
    /// Assertion consumer service binding (POST or Artifact)
    pub acs_binding: Option<String>,
    /// Force authentication
    pub force_authn: bool,
    /// Requested authentication context
    pub authn_context: Option<Vec<String>>,
    /// Allow clock skew in seconds
    pub allowed_clock_skew: i64,
}

impl Default for SamlConfig {
    fn default() -> Self {
        Self {
            idp_entity_id: String::new(),
            idp_sso_url: String::new(),
            idp_slo_url: None,
            idp_certificate: String::new(),
            sp_entity_id: None,
            sign_requests: true,
            require_signed_response: true,
            require_signed_assertion: true,
            encrypt_assertions: false,
            name_id_format: Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string()),
            acs_binding: Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string()),
            force_authn: false,
            authn_context: None,
            allowed_clock_skew: 60,
        }
    }
}

/// OIDC-specific provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Issuer URL (used for discovery)
    pub issuer_url: String,
    /// Client ID
    pub client_id: String,
    /// Client secret
    #[serde(skip_serializing)]
    pub client_secret: String,
    /// Scopes to request
    pub scopes: Vec<String>,
    /// Additional claims to request
    pub claims: Option<Vec<String>>,
    /// Use PKCE
    pub use_pkce: bool,
    /// Response type (code, id_token, etc.)
    pub response_type: String,
    /// Response mode (query, fragment, form_post)
    pub response_mode: Option<String>,
    /// Token endpoint authentication method
    pub token_endpoint_auth_method: Option<String>,
    /// Custom authorization endpoint (overrides discovery)
    pub authorization_endpoint: Option<String>,
    /// Custom token endpoint (overrides discovery)
    pub token_endpoint: Option<String>,
    /// Custom userinfo endpoint (overrides discovery)
    pub userinfo_endpoint: Option<String>,
    /// Custom JWKS URI (overrides discovery)
    pub jwks_uri: Option<String>,
    /// Custom end session endpoint (overrides discovery)
    pub end_session_endpoint: Option<String>,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
            claims: None,
            use_pkce: true,
            response_type: "code".to_string(),
            response_mode: None,
            token_endpoint_auth_method: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            end_session_endpoint: None,
        }
    }
}

/// Combined provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProviderConfig {
    #[serde(rename = "saml")]
    Saml(SamlConfig),
    #[serde(rename = "oidc")]
    Oidc(OidcConfig),
}

/// Request to create a new SSO provider
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSsoProviderRequest {
    pub name: String,
    pub display_name: String,
    pub provider_type: SsoProviderType,
    pub icon: Option<String>,
    pub config: ProviderConfig,
    pub attribute_mappings: Option<Vec<AttributeMapping>>,
    pub group_mappings: Option<Vec<GroupMapping>>,
    pub jit_provisioning: Option<bool>,
    pub default_role: Option<String>,
    pub update_on_login: Option<bool>,
}

/// Request to update an SSO provider
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateSsoProviderRequest {
    pub display_name: Option<String>,
    pub icon: Option<String>,
    pub status: Option<SsoProviderStatus>,
    pub config: Option<ProviderConfig>,
    pub attribute_mappings: Option<Vec<AttributeMapping>>,
    pub group_mappings: Option<Vec<GroupMapping>>,
    pub jit_provisioning: Option<bool>,
    pub default_role: Option<String>,
    pub update_on_login: Option<bool>,
}

/// SSO provider response for API
#[derive(Debug, Serialize, Deserialize)]
pub struct SsoProviderResponse {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub provider_type: SsoProviderType,
    pub status: SsoProviderStatus,
    pub icon: Option<String>,
    pub jit_provisioning: bool,
    pub default_role: String,
    pub update_on_login: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    /// Only included for admins
    pub config: Option<ProviderConfig>,
    pub attribute_mappings: Option<Vec<AttributeMapping>>,
    pub group_mappings: Option<Vec<GroupMapping>>,
}

/// SSO provider for login page (minimal info)
#[derive(Debug, Serialize, Deserialize)]
pub struct SsoProviderForLogin {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub provider_type: SsoProviderType,
    pub icon: Option<String>,
}

/// SAML Assertion Consumer Service (ACS) response
#[derive(Debug, Deserialize)]
pub struct SamlAcsRequest {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// OIDC callback parameters
#[derive(Debug, Deserialize)]
pub struct OidcCallbackParams {
    pub code: Option<String>,
    pub state: String,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// SSO login initiation response
#[derive(Debug, Serialize)]
pub struct SsoLoginResponse {
    /// Redirect URL for the identity provider
    pub redirect_url: String,
    /// State parameter for verification (OIDC)
    pub state: Option<String>,
    /// SAML request ID for verification
    pub request_id: Option<String>,
}

/// SSO authentication result
#[derive(Debug, Serialize)]
pub struct SsoAuthResult {
    pub token: String,
    pub refresh_token: String,
    pub user: crate::db::models::UserInfo,
    /// Whether a new user was created via JIT provisioning
    pub user_created: bool,
}

/// SSO Single Logout request
#[derive(Debug, Deserialize)]
pub struct SsoLogoutRequest {
    /// Optional: specific session to logout
    pub session_id: Option<String>,
    /// Whether to logout from IdP as well
    pub logout_from_idp: Option<bool>,
}

/// SSO metadata response
#[derive(Debug, Serialize)]
pub struct SsoMetadataResponse {
    /// SP Entity ID
    pub entity_id: String,
    /// SAML metadata XML (for SAML providers)
    pub metadata_xml: Option<String>,
    /// Assertion Consumer Service URL
    pub acs_url: Option<String>,
    /// Single Logout URL
    pub slo_url: Option<String>,
    /// OIDC Redirect URI (for OIDC providers)
    pub redirect_uri: Option<String>,
}

/// Test connection result
#[derive(Debug, Serialize)]
pub struct SsoTestResult {
    pub success: bool,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

/// SSO attribute mapping update request
#[derive(Debug, Deserialize)]
pub struct UpdateMappingsRequest {
    pub attribute_mappings: Option<Vec<AttributeMapping>>,
    pub group_mappings: Option<Vec<GroupMapping>>,
}

/// SSO state for CSRF protection (stored in session/cache)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoState {
    pub provider_id: String,
    pub nonce: Option<String>,
    pub pkce_verifier: Option<String>,
    pub redirect_uri: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// OIDC token response
#[derive(Debug, Clone, Deserialize)]
pub struct OidcTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<i64>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
}

/// OIDC ID token claims (basic set)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: serde_json::Value,
    pub exp: i64,
    pub iat: i64,
    pub nonce: Option<String>,
    pub at_hash: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub groups: Option<Vec<String>>,
}

/// Preset provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderPreset {
    pub id: String,
    pub name: String,
    pub description: String,
    pub provider_type: SsoProviderType,
    pub icon: String,
    /// Default configuration template
    pub default_config: serde_json::Value,
    /// Default attribute mappings
    pub default_attribute_mappings: Vec<AttributeMapping>,
    /// Configuration instructions/documentation
    pub setup_instructions: String,
}
