//! OAuth 2.0 / OIDC integration (Sprint 10)
//!
//! Complete OAuth 2.0 and OpenID Connect implementation for SSO authentication.
//! Supports authorization code flow, token refresh, and OIDC discovery.

use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// OAuth 2.0 provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub provider_name: String,
    pub client_id: String,
    pub client_secret: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub revocation_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub issuer: Option<String>,
    pub scopes: Vec<String>,
    pub use_pkce: bool,
}

impl OAuthConfig {
    /// Create configuration from OIDC discovery document
    pub async fn from_discovery(discovery_url: &str, client_id: &str, client_secret: &str) -> Result<Self> {
        let client = reqwest::Client::new();
        let discovery: OIDCDiscovery = client
            .get(discovery_url)
            .send()
            .await?
            .json()
            .await?;

        Ok(Self {
            provider_name: discovery.issuer.clone(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            authorization_endpoint: discovery.authorization_endpoint,
            token_endpoint: discovery.token_endpoint,
            userinfo_endpoint: discovery.userinfo_endpoint.unwrap_or_default(),
            revocation_endpoint: discovery.revocation_endpoint,
            jwks_uri: discovery.jwks_uri,
            issuer: Some(discovery.issuer),
            scopes: discovery.scopes_supported.unwrap_or_else(|| vec!["openid".to_string(), "profile".to_string(), "email".to_string()]),
            use_pkce: true,
        })
    }

    /// Create Google OAuth configuration
    pub fn google(client_id: &str, client_secret: &str) -> Self {
        Self {
            provider_name: "Google".to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_endpoint: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo".to_string(),
            revocation_endpoint: Some("https://oauth2.googleapis.com/revoke".to_string()),
            jwks_uri: Some("https://www.googleapis.com/oauth2/v3/certs".to_string()),
            issuer: Some("https://accounts.google.com".to_string()),
            scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
            use_pkce: true,
        }
    }

    /// Create Microsoft/Azure AD OAuth configuration
    pub fn microsoft(client_id: &str, client_secret: &str, tenant_id: &str) -> Self {
        let base_url = format!("https://login.microsoftonline.com/{}", tenant_id);
        Self {
            provider_name: "Microsoft".to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            authorization_endpoint: format!("{}/oauth2/v2.0/authorize", base_url),
            token_endpoint: format!("{}/oauth2/v2.0/token", base_url),
            userinfo_endpoint: "https://graph.microsoft.com/oidc/userinfo".to_string(),
            revocation_endpoint: None,
            jwks_uri: Some(format!("{}/discovery/v2.0/keys", base_url)),
            issuer: Some(format!("{}/v2.0", base_url)),
            scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
            use_pkce: true,
        }
    }

    /// Create GitHub OAuth configuration
    pub fn github(client_id: &str, client_secret: &str) -> Self {
        Self {
            provider_name: "GitHub".to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            authorization_endpoint: "https://github.com/login/oauth/authorize".to_string(),
            token_endpoint: "https://github.com/login/oauth/access_token".to_string(),
            userinfo_endpoint: "https://api.github.com/user".to_string(),
            revocation_endpoint: None,
            jwks_uri: None,
            issuer: None,
            scopes: vec!["read:user".to_string(), "user:email".to_string()],
            use_pkce: false,
        }
    }

    /// Create Okta OAuth configuration
    pub fn okta(client_id: &str, client_secret: &str, domain: &str) -> Self {
        let base_url = format!("https://{}", domain);
        Self {
            provider_name: "Okta".to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            authorization_endpoint: format!("{}/oauth2/default/v1/authorize", base_url),
            token_endpoint: format!("{}/oauth2/default/v1/token", base_url),
            userinfo_endpoint: format!("{}/oauth2/default/v1/userinfo", base_url),
            revocation_endpoint: Some(format!("{}/oauth2/default/v1/revoke", base_url)),
            jwks_uri: Some(format!("{}/oauth2/default/v1/keys", base_url)),
            issuer: Some(format!("{}/oauth2/default", base_url)),
            scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
            use_pkce: true,
        }
    }
}

/// OIDC discovery document
#[derive(Debug, Deserialize)]
pub struct OIDCDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Option<Vec<String>>,
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
}

/// OAuth 2.0 token response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
    #[serde(skip)]
    pub expires_at: Option<DateTime<Utc>>,
}

impl OAuthToken {
    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() >= expires_at
        } else {
            false
        }
    }

    /// Check if token needs refresh (within 5 minutes of expiry)
    pub fn needs_refresh(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() >= expires_at - Duration::minutes(5)
        } else {
            false
        }
    }
}

/// PKCE challenge and verifier
#[derive(Debug, Clone)]
pub struct PKCEChallenge {
    pub code_verifier: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

impl PKCEChallenge {
    /// Generate new PKCE challenge
    pub fn new() -> Self {
        // Generate 32 random bytes for code verifier
        let mut verifier_bytes = [0u8; 32];
        getrandom::getrandom(&mut verifier_bytes).expect("Failed to generate random bytes");
        let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

        // Generate S256 challenge
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let challenge_hash = hasher.finalize();
        let code_challenge = URL_SAFE_NO_PAD.encode(challenge_hash);

        Self {
            code_verifier,
            code_challenge,
            code_challenge_method: "S256".to_string(),
        }
    }
}

impl Default for PKCEChallenge {
    fn default() -> Self {
        Self::new()
    }
}

/// Authorization request state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationState {
    pub state: String,
    pub nonce: String,
    pub redirect_uri: String,
    pub pkce_verifier: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl AuthorizationState {
    /// Generate new authorization state
    pub fn new(redirect_uri: &str, pkce: Option<&PKCEChallenge>) -> Self {
        let mut state_bytes = [0u8; 16];
        let mut nonce_bytes = [0u8; 16];
        getrandom::getrandom(&mut state_bytes).expect("Failed to generate random bytes");
        getrandom::getrandom(&mut nonce_bytes).expect("Failed to generate random bytes");

        Self {
            state: URL_SAFE_NO_PAD.encode(state_bytes),
            nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
            redirect_uri: redirect_uri.to_string(),
            pkce_verifier: pkce.map(|p| p.code_verifier.clone()),
            created_at: Utc::now(),
        }
    }

    /// Check if state is expired (15 minutes)
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.created_at + Duration::minutes(15)
    }
}

/// User info from OAuth provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub locale: Option<String>,
    #[serde(flatten)]
    pub additional_claims: HashMap<String, serde_json::Value>,
}

/// OAuth client for handling authentication flows
pub struct OAuthClient {
    config: OAuthConfig,
    http_client: reqwest::Client,
}

impl OAuthClient {
    /// Create new OAuth client
    pub fn new(config: OAuthConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }

    /// Generate authorization URL with PKCE
    pub fn generate_authorization_url(&self, redirect_uri: &str) -> (String, AuthorizationState) {
        let pkce = if self.config.use_pkce {
            Some(PKCEChallenge::new())
        } else {
            None
        };

        let state = AuthorizationState::new(redirect_uri, pkce.as_ref());

        let mut url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&nonce={}",
            self.config.authorization_endpoint,
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(&self.config.scopes.join(" ")),
            urlencoding::encode(&state.state),
            urlencoding::encode(&state.nonce)
        );

        // Add PKCE challenge if enabled
        if let Some(ref pkce) = pkce {
            url.push_str(&format!(
                "&code_challenge={}&code_challenge_method={}",
                urlencoding::encode(&pkce.code_challenge),
                pkce.code_challenge_method
            ));
        }

        (url, state)
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code(&self, code: &str, state: &AuthorizationState) -> Result<OAuthToken> {
        if state.is_expired() {
            return Err(anyhow!("Authorization state has expired"));
        }

        let mut params = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", state.redirect_uri.clone()),
            ("client_id", self.config.client_id.clone()),
            ("client_secret", self.config.client_secret.clone()),
        ];

        // Add PKCE verifier if present
        if let Some(ref verifier) = state.pkce_verifier {
            params.push(("code_verifier", verifier.clone()));
        }

        let response = self.http_client
            .post(&self.config.token_endpoint)
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Token exchange failed: {}", error_text));
        }

        let mut token: OAuthToken = response.json().await?;
        token.expires_at = Some(Utc::now() + Duration::seconds(token.expires_in as i64));

        Ok(token)
    }

    /// Refresh access token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<OAuthToken> {
        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ];

        let response = self.http_client
            .post(&self.config.token_endpoint)
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Token refresh failed: {}", error_text));
        }

        let mut token: OAuthToken = response.json().await?;
        token.expires_at = Some(Utc::now() + Duration::seconds(token.expires_in as i64));

        Ok(token)
    }

    /// Get user info from OAuth provider
    pub async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo> {
        let response = self.http_client
            .get(&self.config.userinfo_endpoint)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to get user info: {}", error_text));
        }

        let user_info: OAuthUserInfo = response.json().await?;
        Ok(user_info)
    }

    /// Revoke token
    pub async fn revoke_token(&self, token: &str, token_type_hint: Option<&str>) -> Result<()> {
        let revocation_endpoint = self.config.revocation_endpoint.as_ref()
            .ok_or_else(|| anyhow!("Provider does not support token revocation"))?;

        let mut params = vec![
            ("token", token.to_string()),
            ("client_id", self.config.client_id.clone()),
            ("client_secret", self.config.client_secret.clone()),
        ];

        if let Some(hint) = token_type_hint {
            params.push(("token_type_hint", hint.to_string()));
        }

        let response = self.http_client
            .post(revocation_endpoint)
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Token revocation failed: {}", error_text));
        }

        Ok(())
    }

    /// Validate ID token (basic validation)
    pub fn validate_id_token(&self, id_token: &str, nonce: &str) -> Result<IDTokenClaims> {
        // Decode JWT without verification (verification would require JWKS)
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow!("Invalid ID token format"));
        }

        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])
            .map_err(|_| anyhow!("Failed to decode ID token payload"))?;
        let claims: IDTokenClaims = serde_json::from_slice(&payload_bytes)?;

        // Validate issuer
        if let Some(ref issuer) = self.config.issuer {
            if &claims.iss != issuer {
                return Err(anyhow!("Invalid issuer: expected {}, got {}", issuer, claims.iss));
            }
        }

        // Validate audience
        if claims.aud != self.config.client_id {
            return Err(anyhow!("Invalid audience"));
        }

        // Validate nonce
        if let Some(ref token_nonce) = claims.nonce {
            if token_nonce != nonce {
                return Err(anyhow!("Nonce mismatch"));
            }
        }

        // Validate expiration
        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Err(anyhow!("ID token has expired"));
        }

        // Validate not before
        if let Some(nbf) = claims.nbf {
            if nbf > now {
                return Err(anyhow!("ID token is not yet valid"));
            }
        }

        Ok(claims)
    }
}

/// ID token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: Option<i64>,
    pub nonce: Option<String>,
    pub auth_time: Option<i64>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    #[serde(flatten)]
    pub additional_claims: HashMap<String, serde_json::Value>,
}

// Legacy function wrappers for backwards compatibility

pub async fn generate_authorization_url(config: &OAuthConfig, redirect_uri: &str) -> String {
    let client = OAuthClient::new(config.clone());
    let (url, _state) = client.generate_authorization_url(redirect_uri);
    url
}

pub async fn exchange_code_for_token(config: &OAuthConfig, code: &str, redirect_uri: &str) -> Result<OAuthToken> {
    let client = OAuthClient::new(config.clone());

    // Create a minimal state for backwards compatibility
    let state = AuthorizationState {
        state: String::new(),
        nonce: String::new(),
        redirect_uri: redirect_uri.to_string(),
        pkce_verifier: None,
        created_at: Utc::now(),
    };

    client.exchange_code(code, &state).await
}

pub async fn get_user_info(config: &OAuthConfig, access_token: &str) -> Result<serde_json::Value> {
    let client = OAuthClient::new(config.clone());
    let user_info = client.get_user_info(access_token).await?;
    Ok(serde_json::to_value(user_info)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_challenge_generation() {
        let pkce = PKCEChallenge::new();
        assert!(!pkce.code_verifier.is_empty());
        assert!(!pkce.code_challenge.is_empty());
        assert_eq!(pkce.code_challenge_method, "S256");
    }

    #[test]
    fn test_authorization_state() {
        let pkce = PKCEChallenge::new();
        let state = AuthorizationState::new("https://example.com/callback", Some(&pkce));

        assert!(!state.state.is_empty());
        assert!(!state.nonce.is_empty());
        assert!(!state.is_expired());
        assert!(state.pkce_verifier.is_some());
    }

    #[test]
    fn test_google_config() {
        let config = OAuthConfig::google("client_id", "client_secret");
        assert_eq!(config.provider_name, "Google");
        assert!(config.use_pkce);
        assert!(config.scopes.contains(&"openid".to_string()));
    }

    #[test]
    fn test_microsoft_config() {
        let config = OAuthConfig::microsoft("client_id", "client_secret", "tenant_id");
        assert_eq!(config.provider_name, "Microsoft");
        assert!(config.authorization_endpoint.contains("tenant_id"));
    }

    #[test]
    fn test_github_config() {
        let config = OAuthConfig::github("client_id", "client_secret");
        assert_eq!(config.provider_name, "GitHub");
        assert!(!config.use_pkce); // GitHub doesn't support PKCE
    }

    #[test]
    fn test_token_expiration() {
        let mut token = OAuthToken {
            access_token: "test".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: None,
            id_token: None,
            scope: None,
            expires_at: Some(Utc::now() + Duration::hours(1)),
        };

        assert!(!token.is_expired());
        assert!(!token.needs_refresh());

        // Test expired token
        token.expires_at = Some(Utc::now() - Duration::minutes(1));
        assert!(token.is_expired());
        assert!(token.needs_refresh());
    }

    #[test]
    fn test_authorization_url_generation() {
        let config = OAuthConfig::google("test_client", "test_secret");
        let client = OAuthClient::new(config);
        let (url, state) = client.generate_authorization_url("https://app.example.com/callback");

        assert!(url.contains("accounts.google.com"));
        assert!(url.contains("client_id=test_client"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge="));
        assert!(!state.state.is_empty());
    }
}
