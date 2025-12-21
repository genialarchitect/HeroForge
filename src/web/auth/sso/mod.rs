//! SSO (Single Sign-On) Authentication Module
//!
//! This module provides enterprise identity provider support including:
//! - SAML 2.0 (Service Provider)
//! - OpenID Connect (Authorization Code + PKCE)
//!
//! Supported Identity Providers:
//! - Okta
//! - Microsoft Entra ID (Azure AD)
//! - Google Workspace
//! - OneLogin
//! - Ping Identity
//! - Auth0
//! - Keycloak
//! - JumpCloud
//! - Generic SAML 2.0 and OIDC providers

pub mod oidc;
pub mod providers;
pub mod saml;
pub mod types;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::db::models::UserInfo;
use crate::web::auth::{create_jwt, create_refresh_token};

pub use oidc::OidcClient;
pub use providers::{get_provider_preset, get_provider_presets};
pub use saml::SamlServiceProvider;
pub use types::*;

/// Cache for SSO states (for CSRF protection)
/// In production, this should be backed by Redis or similar
lazy_static::lazy_static! {
    static ref SSO_STATE_CACHE: Arc<RwLock<HashMap<String, SsoState>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

/// SSO Manager - Coordinates SSO authentication
pub struct SsoManager {
    pool: SqlitePool,
    base_url: String,
}

impl SsoManager {
    /// Create a new SSO manager
    pub fn new(pool: SqlitePool, base_url: String) -> Self {
        Self { pool, base_url }
    }

    /// Get the ACS URL for SAML providers
    pub fn get_acs_url(&self) -> String {
        format!("{}/api/sso/callback/saml", self.base_url)
    }

    /// Get the redirect URI for OIDC providers
    pub fn get_oidc_redirect_uri(&self) -> String {
        format!("{}/api/sso/callback/oidc", self.base_url)
    }

    /// Get SP metadata URL for a provider
    pub fn get_metadata_url(&self, provider_id: &str) -> String {
        format!("{}/api/sso/providers/{}/metadata", self.base_url, provider_id)
    }

    /// Get SP entity ID for a provider
    pub fn get_sp_entity_id(&self, provider_id: &str) -> String {
        format!("{}/api/sso/metadata/{}", self.base_url, provider_id)
    }

    /// Initiate SSO login
    pub async fn initiate_login(&self, provider_id: &str) -> Result<SsoLoginResponse> {
        let provider = get_sso_provider(&self.pool, provider_id).await?;

        if provider.status != "active" {
            return Err(anyhow!("SSO provider is not active"));
        }

        let config: ProviderConfig = serde_json::from_str(&provider.config)
            .context("Failed to parse provider configuration")?;

        match config {
            ProviderConfig::Saml(saml_config) => {
                let sp = SamlServiceProvider::new(
                    self.get_sp_entity_id(provider_id),
                    self.get_acs_url(),
                    Some(format!("{}/api/sso/logout", self.base_url)),
                    None, // SP private key (optional)
                    None, // SP certificate (optional)
                );

                // Generate relay state for CSRF protection
                let relay_state = uuid::Uuid::new_v4().to_string();

                // Store state for verification
                let sso_state = SsoState {
                    provider_id: provider_id.to_string(),
                    nonce: None,
                    pkce_verifier: None,
                    redirect_uri: None,
                    created_at: Utc::now(),
                };
                store_sso_state(&relay_state, sso_state).await;

                let (redirect_url, request_id) = sp.create_authn_request(&saml_config, Some(&relay_state))?;

                Ok(SsoLoginResponse {
                    redirect_url,
                    state: Some(relay_state),
                    request_id: Some(request_id),
                })
            }
            ProviderConfig::Oidc(oidc_config) => {
                let mut client = OidcClient::new(oidc_config, self.get_oidc_redirect_uri());

                // Try to discover endpoints
                if let Err(e) = client.discover().await {
                    log::warn!("OIDC discovery failed: {}, using configured endpoints", e);
                }

                let (redirect_url, sso_state) = client.create_authorization_url(provider_id)?;

                // Store state for verification
                store_sso_state(&sso_state.nonce.clone().unwrap_or_default(), sso_state.clone()).await;

                Ok(SsoLoginResponse {
                    redirect_url,
                    state: sso_state.nonce.clone(),
                    request_id: None,
                })
            }
        }
    }

    /// Process SAML callback
    pub async fn process_saml_callback(
        &self,
        saml_response: &str,
        relay_state: Option<&str>,
    ) -> Result<SsoAuthResult> {
        // Validate relay state
        let state = if let Some(rs) = relay_state {
            get_sso_state(rs)
                .await
                .ok_or_else(|| anyhow!("Invalid or expired relay state"))?
        } else {
            return Err(anyhow!("Missing relay state"));
        };

        // Get provider
        let provider = get_sso_provider(&self.pool, &state.provider_id).await?;
        let config: ProviderConfig = serde_json::from_str(&provider.config)?;

        let saml_config = match config {
            ProviderConfig::Saml(c) => c,
            _ => return Err(anyhow!("Provider is not SAML")),
        };

        // Create SP and process response
        let sp = SamlServiceProvider::new(
            self.get_sp_entity_id(&state.provider_id),
            self.get_acs_url(),
            None,
            None,
            None,
        );

        let user_info = sp.process_response(saml_response, &saml_config, None)?;

        // Clean up state
        remove_sso_state(relay_state.unwrap()).await;

        // Update last used timestamp
        update_provider_last_used(&self.pool, &state.provider_id).await?;

        // Process user info and create/update user
        self.process_user_info(&provider, user_info).await
    }

    /// Process OIDC callback
    pub async fn process_oidc_callback(
        &self,
        params: &OidcCallbackParams,
    ) -> Result<SsoAuthResult> {
        // Get and validate state
        let stored_state = get_sso_state(&params.state)
            .await
            .ok_or_else(|| anyhow!("Invalid or expired state"))?;

        oidc::validate_sso_state(&stored_state, 10)?;

        // Get provider
        let provider = get_sso_provider(&self.pool, &stored_state.provider_id).await?;
        let config: ProviderConfig = serde_json::from_str(&provider.config)?;

        let oidc_config = match config {
            ProviderConfig::Oidc(c) => c,
            _ => return Err(anyhow!("Provider is not OIDC")),
        };

        // Create client and process callback
        let mut client = OidcClient::new(oidc_config, self.get_oidc_redirect_uri());

        // Try to discover endpoints
        if let Err(e) = client.discover().await {
            log::warn!("OIDC discovery failed: {}", e);
        }

        let user_info = client.process_callback(params, &stored_state).await?;

        // Clean up state
        remove_sso_state(&params.state).await;

        // Update last used timestamp
        update_provider_last_used(&self.pool, &stored_state.provider_id).await?;

        // Process user info and create/update user
        self.process_user_info(&provider, user_info).await
    }

    /// Process user info from SSO and create/update user
    async fn process_user_info(
        &self,
        provider: &SsoProvider,
        user_info: SsoUserInfo,
    ) -> Result<SsoAuthResult> {
        // Apply attribute mappings
        let attribute_mappings: Vec<AttributeMapping> = provider
            .attribute_mappings
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();

        let mapped_info = apply_attribute_mappings(&user_info, &attribute_mappings);

        // Get email (required)
        let email = mapped_info
            .email
            .clone()
            .ok_or_else(|| anyhow!("Email is required for SSO authentication"))?;

        // Check if user exists
        let existing_user = crate::db::get_user_by_email(&self.pool, &email).await?;

        let (user, user_created) = match existing_user {
            Some(user) => {
                // User exists
                if provider.update_on_login {
                    // Update user info if configured
                    // TODO: Implement user profile update
                }
                (user, false)
            }
            None => {
                // User doesn't exist
                if !provider.jit_provisioning {
                    return Err(anyhow!(
                        "User does not exist and JIT provisioning is disabled"
                    ));
                }

                // Create new user with JIT provisioning
                let username = mapped_info.get_username();

                let new_user = crate::db::models::CreateUser {
                    username: username.clone(),
                    email: email.clone(),
                    password: uuid::Uuid::new_v4().to_string(), // Random password (user authenticates via SSO)
                    accept_terms: true, // SSO implies acceptance
                };

                let user = crate::db::create_user(&self.pool, &new_user).await?;

                // Assign role based on group mappings or default role
                let role_to_assign = self
                    .determine_role(provider, &mapped_info.groups)
                    .await
                    .unwrap_or_else(|| provider.default_role.clone());

                if let Err(e) = crate::db::assign_role_to_user(&self.pool, &user.id, &role_to_assign, &user.id).await {
                    log::error!("Failed to assign role to SSO user: {}", e);
                }

                log::info!(
                    "JIT provisioned user {} ({}) via SSO provider {}",
                    username,
                    email,
                    provider.name
                );

                (user, true)
            }
        };

        // Create SSO session
        let session = SsoSession {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            provider_id: provider.id.clone(),
            session_index: None,
            name_id: Some(user_info.subject),
            name_id_format: None,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(8),
            logged_out_at: None,
        };

        create_sso_session(&self.pool, &session).await?;

        // Get user roles for JWT
        let roles = crate::db::get_user_roles(&self.pool, &user.id)
            .await
            .unwrap_or_default();
        let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

        // Create JWT tokens
        let token = create_jwt(&user.id, &user.username, role_names)
            .map_err(|e| anyhow::anyhow!("JWT creation failed: {}", e))?;
        let refresh_token = create_refresh_token(&user.id)
            .map_err(|e| anyhow::anyhow!("Refresh token creation failed: {}", e))?;

        // Store refresh token
        let expires_at = Utc::now() + chrono::Duration::days(7);
        crate::db::store_refresh_token(&self.pool, &user.id, &refresh_token, expires_at).await?;

        Ok(SsoAuthResult {
            token,
            refresh_token,
            user: UserInfo::from(user),
            user_created,
        })
    }

    /// Determine user role based on group mappings
    async fn determine_role(&self, provider: &SsoProvider, groups: &[String]) -> Option<String> {
        let group_mappings: Vec<GroupMapping> = provider
            .group_mappings
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();

        if group_mappings.is_empty() {
            return None;
        }

        // Find highest priority matching group
        let mut best_match: Option<(&GroupMapping, i32)> = None;

        for group in groups {
            for mapping in &group_mappings {
                if &mapping.group == group {
                    match &best_match {
                        None => best_match = Some((mapping, mapping.priority)),
                        Some((_, priority)) if mapping.priority > *priority => {
                            best_match = Some((mapping, mapping.priority))
                        }
                        _ => {}
                    }
                }
            }
        }

        best_match.map(|(m, _)| m.role.clone())
    }

    /// Generate SP metadata for a provider
    pub fn generate_sp_metadata(&self, provider_id: &str) -> String {
        let sp = SamlServiceProvider::new(
            self.get_sp_entity_id(provider_id),
            self.get_acs_url(),
            Some(format!("{}/api/sso/logout", self.base_url)),
            None,
            None,
        );

        sp.generate_metadata()
    }

    /// Process single logout
    pub async fn process_logout(&self, user_id: &str, logout_from_idp: bool) -> Result<Option<String>> {
        // Get active SSO sessions for user
        let sessions = get_sso_sessions(&self.pool, user_id).await?;

        if sessions.is_empty() {
            return Ok(None);
        }

        // Mark sessions as logged out
        for session in &sessions {
            mark_session_logged_out(&self.pool, &session.id).await?;
        }

        // If logout from IdP is requested and we have a session with SLO support
        if logout_from_idp {
            if let Some(session) = sessions.first() {
                let provider = get_sso_provider(&self.pool, &session.provider_id).await?;
                let config: ProviderConfig = serde_json::from_str(&provider.config)?;

                return match config {
                    ProviderConfig::Saml(saml_config) => {
                        if let Some(slo_url) = saml_config.idp_slo_url {
                            let logout_request = saml::create_logout_request(
                                &self.get_sp_entity_id(&provider.id),
                                &slo_url,
                                session.name_id.as_deref().unwrap_or(""),
                                session.session_index.as_deref(),
                            );

                            // For redirect binding, we'd need to deflate and encode
                            // For now, return the SLO URL
                            Ok(Some(slo_url))
                        } else {
                            Ok(None)
                        }
                    }
                    ProviderConfig::Oidc(oidc_config) => {
                        let client = OidcClient::new(oidc_config, self.get_oidc_redirect_uri());
                        Ok(client.get_end_session_endpoint())
                    }
                };
            }
        }

        Ok(None)
    }
}

/// Apply attribute mappings to user info
fn apply_attribute_mappings(
    user_info: &SsoUserInfo,
    mappings: &[AttributeMapping],
) -> SsoUserInfo {
    let mut result = user_info.clone();

    for mapping in mappings {
        let value = get_attribute_value(&user_info.raw_attributes, &mapping.source);

        let value = match value {
            Some(v) => Some(v),
            None if mapping.required => mapping.default_value.clone(),
            None => None,
        };

        match mapping.target.as_str() {
            "email" => result.email = value.or(result.email.clone()),
            "username" => result.username = value.or(result.username.clone()),
            "display_name" => result.display_name = value.or(result.display_name.clone()),
            "first_name" => result.first_name = value.or(result.first_name.clone()),
            "last_name" => result.last_name = value.or(result.last_name.clone()),
            _ => {}
        }
    }

    result
}

/// Get attribute value from raw attributes
fn get_attribute_value(attrs: &serde_json::Value, key: &str) -> Option<String> {
    attrs
        .get(key)
        .and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Array(arr) => arr.first().and_then(|v| v.as_str()).map(String::from),
            _ => v.as_str().map(String::from),
        })
}

// ============================================================================
// SSO State Management (in-memory cache)
// ============================================================================

async fn store_sso_state(key: &str, state: SsoState) {
    let mut cache = SSO_STATE_CACHE.write().await;
    cache.insert(key.to_string(), state);
}

async fn get_sso_state(key: &str) -> Option<SsoState> {
    let cache = SSO_STATE_CACHE.read().await;
    cache.get(key).cloned()
}

async fn remove_sso_state(key: &str) {
    let mut cache = SSO_STATE_CACHE.write().await;
    cache.remove(key);
}

// ============================================================================
// Database Functions
// ============================================================================

/// Get SSO provider by ID
pub async fn get_sso_provider(pool: &SqlitePool, id: &str) -> Result<SsoProvider> {
    sqlx::query_as::<_, SsoProvider>(
        "SELECT * FROM sso_providers WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow!("SSO provider not found"))
}

/// Get all active SSO providers
pub async fn get_active_sso_providers(pool: &SqlitePool) -> Result<Vec<SsoProvider>> {
    let providers = sqlx::query_as::<_, SsoProvider>(
        "SELECT * FROM sso_providers WHERE status = 'active' ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    Ok(providers)
}

/// Get all SSO providers (for admin)
pub async fn get_all_sso_providers(pool: &SqlitePool) -> Result<Vec<SsoProvider>> {
    let providers = sqlx::query_as::<_, SsoProvider>(
        "SELECT * FROM sso_providers ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    Ok(providers)
}

/// Create SSO provider
pub async fn create_sso_provider(pool: &SqlitePool, provider: &SsoProvider) -> Result<SsoProvider> {
    sqlx::query(
        r#"
        INSERT INTO sso_providers (
            id, name, display_name, provider_type, status, icon,
            config, attribute_mappings, group_mappings,
            jit_provisioning, default_role, update_on_login,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&provider.id)
    .bind(&provider.name)
    .bind(&provider.display_name)
    .bind(&provider.provider_type)
    .bind(&provider.status)
    .bind(&provider.icon)
    .bind(&provider.config)
    .bind(&provider.attribute_mappings)
    .bind(&provider.group_mappings)
    .bind(provider.jit_provisioning)
    .bind(&provider.default_role)
    .bind(provider.update_on_login)
    .bind(provider.created_at)
    .bind(provider.updated_at)
    .execute(pool)
    .await?;

    Ok(provider.clone())
}

/// Update SSO provider
pub async fn update_sso_provider(pool: &SqlitePool, id: &str, updates: &UpdateSsoProviderRequest) -> Result<SsoProvider> {
    let existing = get_sso_provider(pool, id).await?;

    let display_name = updates.display_name.as_ref().unwrap_or(&existing.display_name);
    let icon = updates.icon.as_ref().or(existing.icon.as_ref());
    let status = updates.status.map(|s| s.to_string()).unwrap_or(existing.status);
    let config = updates.config.as_ref()
        .map(|c| serde_json::to_string(c).unwrap())
        .unwrap_or(existing.config);
    let attribute_mappings = updates.attribute_mappings.as_ref()
        .map(|m| serde_json::to_string(m).ok())
        .unwrap_or(existing.attribute_mappings);
    let group_mappings = updates.group_mappings.as_ref()
        .map(|m| serde_json::to_string(m).ok())
        .unwrap_or(existing.group_mappings);
    let jit_provisioning = updates.jit_provisioning.unwrap_or(existing.jit_provisioning);
    let default_role = updates.default_role.as_ref().unwrap_or(&existing.default_role);
    let update_on_login = updates.update_on_login.unwrap_or(existing.update_on_login);

    sqlx::query(
        r#"
        UPDATE sso_providers SET
            display_name = ?,
            icon = ?,
            status = ?,
            config = ?,
            attribute_mappings = ?,
            group_mappings = ?,
            jit_provisioning = ?,
            default_role = ?,
            update_on_login = ?,
            updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(display_name)
    .bind(icon)
    .bind(&status)
    .bind(&config)
    .bind(&attribute_mappings)
    .bind(&group_mappings)
    .bind(jit_provisioning)
    .bind(default_role)
    .bind(update_on_login)
    .bind(Utc::now())
    .bind(id)
    .execute(pool)
    .await?;

    get_sso_provider(pool, id).await
}

/// Delete SSO provider
pub async fn delete_sso_provider(pool: &SqlitePool, id: &str) -> Result<()> {
    // Delete associated sessions first
    sqlx::query("DELETE FROM sso_sessions WHERE provider_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM sso_providers WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Update provider last used timestamp
async fn update_provider_last_used(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("UPDATE sso_providers SET last_used_at = ? WHERE id = ?")
        .bind(Utc::now())
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Create SSO session
async fn create_sso_session(pool: &SqlitePool, session: &SsoSession) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO sso_sessions (
            id, user_id, provider_id, session_index, name_id, name_id_format,
            created_at, expires_at, logged_out_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&session.id)
    .bind(&session.user_id)
    .bind(&session.provider_id)
    .bind(&session.session_index)
    .bind(&session.name_id)
    .bind(&session.name_id_format)
    .bind(session.created_at)
    .bind(session.expires_at)
    .bind(session.logged_out_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get SSO sessions for user
async fn get_sso_sessions(pool: &SqlitePool, user_id: &str) -> Result<Vec<SsoSession>> {
    let sessions = sqlx::query_as::<_, SsoSession>(
        "SELECT * FROM sso_sessions WHERE user_id = ? AND logged_out_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(sessions)
}

/// Mark SSO session as logged out
async fn mark_session_logged_out(pool: &SqlitePool, session_id: &str) -> Result<()> {
    sqlx::query("UPDATE sso_sessions SET logged_out_at = ? WHERE id = ?")
        .bind(Utc::now())
        .bind(session_id)
        .execute(pool)
        .await?;

    Ok(())
}
