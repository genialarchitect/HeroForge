#![allow(dead_code)]
//! OpenID Connect Authentication Implementation
//!
//! This module implements OIDC authentication using the Authorization Code flow with PKCE.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL, Engine};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::types::{IdTokenClaims, OidcCallbackParams, OidcConfig, OidcTokenResponse, SsoState, SsoUserInfo};

/// OIDC Provider Discovery Document
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub response_modes_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub subject_types_supported: Vec<String>,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    pub claims_supported: Vec<String>,
}

/// OIDC Client for handling authentication
pub struct OidcClient {
    config: OidcConfig,
    discovery: Option<OidcDiscoveryDocument>,
    redirect_uri: String,
    http_client: reqwest::Client,
}

impl OidcClient {
    /// Create a new OIDC client
    pub fn new(config: OidcConfig, redirect_uri: String) -> Self {
        Self {
            config,
            discovery: None,
            redirect_uri,
            http_client: reqwest::Client::new(),
        }
    }

    /// Discover OIDC endpoints from the issuer
    pub async fn discover(&mut self) -> Result<()> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer_url.trim_end_matches('/')
        );

        log::debug!("Fetching OIDC discovery document from {}", discovery_url);

        let response = self
            .http_client
            .get(&discovery_url)
            .send()
            .await
            .context("Failed to fetch OIDC discovery document")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "OIDC discovery failed with status: {}",
                response.status()
            ));
        }

        let discovery: OidcDiscoveryDocument = response
            .json()
            .await
            .context("Failed to parse OIDC discovery document")?;

        self.discovery = Some(discovery);
        Ok(())
    }

    /// Get the authorization endpoint
    fn get_authorization_endpoint(&self) -> Result<String> {
        if let Some(endpoint) = &self.config.authorization_endpoint {
            return Ok(endpoint.clone());
        }
        self.discovery
            .as_ref()
            .map(|d| d.authorization_endpoint.clone())
            .ok_or_else(|| anyhow!("Authorization endpoint not configured and discovery not performed"))
    }

    /// Get the token endpoint
    fn get_token_endpoint(&self) -> Result<String> {
        if let Some(endpoint) = &self.config.token_endpoint {
            return Ok(endpoint.clone());
        }
        self.discovery
            .as_ref()
            .map(|d| d.token_endpoint.clone())
            .ok_or_else(|| anyhow!("Token endpoint not configured and discovery not performed"))
    }

    /// Get the userinfo endpoint
    fn get_userinfo_endpoint(&self) -> Option<String> {
        self.config.userinfo_endpoint.clone().or_else(|| {
            self.discovery
                .as_ref()
                .and_then(|d| d.userinfo_endpoint.clone())
        })
    }

    /// Get the end session endpoint
    pub fn get_end_session_endpoint(&self) -> Option<String> {
        self.config.end_session_endpoint.clone().or_else(|| {
            self.discovery
                .as_ref()
                .and_then(|d| d.end_session_endpoint.clone())
        })
    }

    /// Generate authorization URL for login
    pub fn create_authorization_url(&self, provider_id: &str) -> Result<(String, SsoState)> {
        let auth_endpoint = self.get_authorization_endpoint()?;

        // Generate state for CSRF protection
        let state = Uuid::new_v4().to_string();

        // Generate nonce for replay protection
        let nonce = Uuid::new_v4().to_string();

        // Generate PKCE challenge if enabled
        let (pkce_verifier, pkce_challenge) = if self.config.use_pkce {
            let verifier = generate_pkce_verifier();
            let challenge = generate_pkce_challenge(&verifier);
            (Some(verifier), Some(challenge))
        } else {
            (None, None)
        };

        // Build authorization URL
        let mut params = vec![
            ("client_id", self.config.client_id.clone()),
            ("redirect_uri", self.redirect_uri.clone()),
            ("response_type", self.config.response_type.clone()),
            ("scope", self.config.scopes.join(" ")),
            ("state", state.clone()),
            ("nonce", nonce.clone()),
        ];

        if let Some(ref challenge) = pkce_challenge {
            params.push(("code_challenge", challenge.clone()));
            params.push(("code_challenge_method", "S256".to_string()));
        }

        if let Some(ref mode) = self.config.response_mode {
            params.push(("response_mode", mode.clone()));
        }

        let query_string: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let auth_url = format!("{}?{}", auth_endpoint, query_string);

        let sso_state = SsoState {
            provider_id: provider_id.to_string(),
            nonce: Some(nonce),
            pkce_verifier,
            redirect_uri: Some(self.redirect_uri.clone()),
            created_at: Utc::now(),
        };

        Ok((auth_url, sso_state))
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code(
        &self,
        code: &str,
        stored_state: &SsoState,
    ) -> Result<OidcTokenResponse> {
        let token_endpoint = self.get_token_endpoint()?;

        let mut params = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", self.redirect_uri.clone()),
            ("client_id", self.config.client_id.clone()),
        ];

        // Add PKCE verifier if we used PKCE
        if let Some(ref verifier) = stored_state.pkce_verifier {
            params.push(("code_verifier", verifier.clone()));
        }

        // Determine authentication method
        let auth_method = self
            .config
            .token_endpoint_auth_method
            .as_deref()
            .unwrap_or("client_secret_post");

        let request = match auth_method {
            "client_secret_basic" => {
                let auth = BASE64_URL.encode(format!(
                    "{}:{}",
                    self.config.client_id, self.config.client_secret
                ));
                self.http_client
                    .post(&token_endpoint)
                    .header("Authorization", format!("Basic {}", auth))
                    .form(&params)
            }
            _ => {
                // client_secret_post (default)
                params.push(("client_secret", self.config.client_secret.clone()));
                self.http_client.post(&token_endpoint).form(&params)
            }
        };

        log::debug!("Exchanging authorization code for tokens");

        let response = request
            .send()
            .await
            .context("Failed to exchange authorization code")?;

        if !response.status().is_success() {
            let error_body = response.text().await.unwrap_or_default();
            log::error!("Token exchange failed: {}", error_body);
            return Err(anyhow!("Token exchange failed: {}", error_body));
        }

        let tokens: OidcTokenResponse = response
            .json()
            .await
            .context("Failed to parse token response")?;

        Ok(tokens)
    }

    /// Validate ID token and extract claims
    pub fn validate_id_token(
        &self,
        id_token: &str,
        stored_state: &SsoState,
    ) -> Result<IdTokenClaims> {
        // Split the JWT
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow!("Invalid ID token format"));
        }

        // Decode the payload (middle part)
        let payload = BASE64_URL
            .decode(parts[1])
            .context("Failed to decode ID token payload")?;

        let claims: IdTokenClaims = serde_json::from_slice(&payload)
            .context("Failed to parse ID token claims")?;

        // Validate issuer
        let expected_issuer = self.config.issuer_url.trim_end_matches('/');
        if claims.iss.trim_end_matches('/') != expected_issuer {
            return Err(anyhow!(
                "ID token issuer mismatch: expected {}, got {}",
                expected_issuer,
                claims.iss
            ));
        }

        // Validate audience
        let valid_aud = match &claims.aud {
            serde_json::Value::String(s) => s == &self.config.client_id,
            serde_json::Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_str())
                .any(|s| s == self.config.client_id),
            _ => false,
        };

        if !valid_aud {
            return Err(anyhow!("ID token audience mismatch"));
        }

        // Validate expiration
        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Err(anyhow!("ID token has expired"));
        }

        // Validate issued at (allow 5 minute clock skew)
        if claims.iat > now + 300 {
            return Err(anyhow!("ID token issued in the future"));
        }

        // Validate nonce if we sent one
        if let Some(ref expected_nonce) = stored_state.nonce {
            match &claims.nonce {
                Some(nonce) if nonce == expected_nonce => {}
                Some(_) => return Err(anyhow!("ID token nonce mismatch")),
                None => return Err(anyhow!("ID token missing nonce")),
            }
        }

        // TODO: Validate signature using JWKS
        // This would require:
        // 1. Fetching JWKS from jwks_uri
        // 2. Finding the key matching the token's kid header
        // 3. Verifying the signature using the appropriate algorithm

        log::debug!(
            "ID token validated for subject: {}",
            claims.sub
        );

        Ok(claims)
    }

    /// Fetch user info from the userinfo endpoint
    pub async fn fetch_userinfo(&self, access_token: &str) -> Result<serde_json::Value> {
        let userinfo_endpoint = self
            .get_userinfo_endpoint()
            .ok_or_else(|| anyhow!("UserInfo endpoint not available"))?;

        log::debug!("Fetching user info from {}", userinfo_endpoint);

        let response = self
            .http_client
            .get(&userinfo_endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .context("Failed to fetch user info")?;

        if !response.status().is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(anyhow!("UserInfo request failed: {}", error_body));
        }

        let userinfo: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse user info response")?;

        Ok(userinfo)
    }

    /// Process OIDC callback and return user info
    pub async fn process_callback(
        &self,
        params: &OidcCallbackParams,
        stored_state: &SsoState,
    ) -> Result<SsoUserInfo> {
        // Check for errors
        if let Some(ref error) = params.error {
            let description = params
                .error_description
                .as_deref()
                .unwrap_or("Unknown error");
            return Err(anyhow!("OIDC authentication failed: {} - {}", error, description));
        }

        // Get the authorization code
        let code = params
            .code
            .as_ref()
            .ok_or_else(|| anyhow!("Missing authorization code"))?;

        // Exchange code for tokens
        let tokens = self.exchange_code(code, stored_state).await?;

        // Validate ID token if present
        let id_claims = if let Some(ref id_token) = tokens.id_token {
            Some(self.validate_id_token(id_token, stored_state)?)
        } else {
            None
        };

        // Fetch additional user info if available
        let userinfo = self.fetch_userinfo(&tokens.access_token).await.ok();

        // Build user info from ID token claims and userinfo
        let user_info = build_user_info(id_claims, userinfo)?;

        Ok(user_info)
    }

    /// Refresh access token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<OidcTokenResponse> {
        let token_endpoint = self.get_token_endpoint()?;

        let mut params = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.to_string()),
            ("client_id", self.config.client_id.clone()),
        ];

        let auth_method = self
            .config
            .token_endpoint_auth_method
            .as_deref()
            .unwrap_or("client_secret_post");

        let request = match auth_method {
            "client_secret_basic" => {
                let auth = BASE64_URL.encode(format!(
                    "{}:{}",
                    self.config.client_id, self.config.client_secret
                ));
                self.http_client
                    .post(&token_endpoint)
                    .header("Authorization", format!("Basic {}", auth))
                    .form(&params)
            }
            _ => {
                params.push(("client_secret", self.config.client_secret.clone()));
                self.http_client.post(&token_endpoint).form(&params)
            }
        };

        let response = request.send().await?;

        if !response.status().is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Token refresh failed: {}", error_body));
        }

        let tokens: OidcTokenResponse = response.json().await?;
        Ok(tokens)
    }

    /// Build logout URL for RP-initiated logout
    pub fn build_logout_url(&self, id_token_hint: Option<&str>, post_logout_redirect_uri: Option<&str>) -> Option<String> {
        let end_session_endpoint = self.get_end_session_endpoint()?;

        let mut params = Vec::new();

        if let Some(token) = id_token_hint {
            params.push(format!("id_token_hint={}", urlencoding::encode(token)));
        }

        if let Some(uri) = post_logout_redirect_uri {
            params.push(format!(
                "post_logout_redirect_uri={}",
                urlencoding::encode(uri)
            ));
        }

        if params.is_empty() {
            Some(end_session_endpoint)
        } else {
            Some(format!("{}?{}", end_session_endpoint, params.join("&")))
        }
    }
}

/// Build SsoUserInfo from ID token claims and userinfo response
fn build_user_info(
    id_claims: Option<IdTokenClaims>,
    userinfo: Option<serde_json::Value>,
) -> Result<SsoUserInfo> {
    // We need at least one source of user info
    let (claims, info) = match (id_claims, userinfo) {
        (Some(c), Some(i)) => (Some(c), Some(i)),
        (Some(c), None) => (Some(c), None),
        (None, Some(i)) => (None, Some(i)),
        (None, None) => return Err(anyhow!("No user info available")),
    };

    let subject = claims
        .as_ref()
        .map(|c| c.sub.clone())
        .or_else(|| {
            info.as_ref()
                .and_then(|i| i.get("sub"))
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .ok_or_else(|| anyhow!("Missing subject claim"))?;

    let email = claims
        .as_ref()
        .and_then(|c| c.email.clone())
        .or_else(|| {
            info.as_ref()
                .and_then(|i| i.get("email"))
                .and_then(|v| v.as_str())
                .map(String::from)
        });

    let username = claims
        .as_ref()
        .and_then(|c| c.preferred_username.clone())
        .or_else(|| {
            info.as_ref()
                .and_then(|i| i.get("preferred_username"))
                .and_then(|v| v.as_str())
                .map(String::from)
        });

    let display_name = claims
        .as_ref()
        .and_then(|c| c.name.clone())
        .or_else(|| {
            info.as_ref()
                .and_then(|i| i.get("name"))
                .and_then(|v| v.as_str())
                .map(String::from)
        });

    let first_name = claims
        .as_ref()
        .and_then(|c| c.given_name.clone())
        .or_else(|| {
            info.as_ref()
                .and_then(|i| i.get("given_name"))
                .and_then(|v| v.as_str())
                .map(String::from)
        });

    let last_name = claims
        .as_ref()
        .and_then(|c| c.family_name.clone())
        .or_else(|| {
            info.as_ref()
                .and_then(|i| i.get("family_name"))
                .and_then(|v| v.as_str())
                .map(String::from)
        });

    let groups = claims
        .as_ref()
        .and_then(|c| c.groups.clone())
        .or_else(|| {
            info.as_ref()
                .and_then(|i| i.get("groups"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(String::from)
                        .collect()
                })
        })
        .unwrap_or_default();

    let raw_attributes = if let Some(ref i) = info {
        i.clone()
    } else if let Some(ref c) = claims {
        serde_json::to_value(c)?
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };

    Ok(SsoUserInfo {
        subject,
        email,
        username,
        display_name,
        first_name,
        last_name,
        groups,
        raw_attributes,
    })
}

/// Generate a PKCE code verifier (43-128 characters)
pub fn generate_pkce_verifier() -> String {
    let bytes: [u8; 32] = rand::random();
    BASE64_URL.encode(bytes)
}

/// Generate PKCE code challenge from verifier
pub fn generate_pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    BASE64_URL.encode(hasher.finalize())
}

/// Validate an SSO state (check expiration)
pub fn validate_sso_state(state: &SsoState, max_age_minutes: i64) -> Result<()> {
    let now = Utc::now();
    let expiry = state.created_at + Duration::minutes(max_age_minutes);

    if now > expiry {
        return Err(anyhow!("SSO state has expired"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_generation() {
        let verifier = generate_pkce_verifier();
        assert!(verifier.len() >= 43);

        let challenge = generate_pkce_challenge(&verifier);
        assert!(!challenge.is_empty());

        // Different verifiers should produce different challenges
        let verifier2 = generate_pkce_verifier();
        let challenge2 = generate_pkce_challenge(&verifier2);
        assert_ne!(challenge, challenge2);
    }

    #[test]
    fn test_sso_state_validation() {
        let valid_state = SsoState {
            provider_id: "test".to_string(),
            nonce: Some("nonce".to_string()),
            pkce_verifier: None,
            redirect_uri: None,
            created_at: Utc::now(),
        };

        // Should be valid
        assert!(validate_sso_state(&valid_state, 10).is_ok());

        // Expired state
        let expired_state = SsoState {
            provider_id: "test".to_string(),
            nonce: None,
            pkce_verifier: None,
            redirect_uri: None,
            created_at: Utc::now() - Duration::minutes(15),
        };

        assert!(validate_sso_state(&expired_state, 10).is_err());
    }
}
