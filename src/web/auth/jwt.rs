use actix_web::{dev::Payload, Error as ActixError, FromRequest, HttpMessage, HttpRequest};
use chrono::{Duration, Utc};
use futures_util::future::{ready, Ready};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::error::Error;

// NIST 800-63B recommends short-lived access tokens
const JWT_EXPIRATION_HOURS: i64 = 1;
const REFRESH_TOKEN_EXPIRATION_DAYS: i64 = 7;

static JWT_SECRET: Lazy<String> = Lazy::new(|| {
    std::env::var("JWT_SECRET").expect(
        "JWT_SECRET environment variable must be set for security. \
         Generate a strong secret with: openssl rand -base64 32"
    )
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,                        // user id
    pub username: String,
    pub roles: Vec<String>,                 // user roles (e.g., ["admin", "user"])
    pub exp: usize,                         // expiration time
    #[serde(default)]
    pub iat: usize,                         // issued at time
    #[serde(default)]
    pub org_id: Option<String>,             // current organization id
    #[serde(default)]
    pub org_role: Option<String>,           // role in organization (owner/admin/member)
    #[serde(default)]
    pub teams: Vec<String>,                 // team IDs user belongs to
    #[serde(default)]
    pub permissions: Vec<String>,           // effective permissions (top common ones)
}

/// Extended claims for organization context when creating JWTs
pub struct ExtendedClaimsData {
    pub org_id: Option<String>,
    pub org_role: Option<String>,
    pub teams: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshClaims {
    pub sub: String,        // user id
    pub exp: usize,         // expiration time
    pub token_type: String, // "refresh"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaClaims {
    pub sub: String,        // user id
    pub exp: usize,         // expiration time (5 minutes for MFA step)
    pub token_type: String, // "mfa"
}

pub fn create_jwt(user_id: &str, username: &str, roles: Vec<String>) -> Result<String, Box<dyn Error>> {
    create_jwt_extended(user_id, username, roles, None)
}

/// Create a JWT with extended organization context
pub fn create_jwt_extended(
    user_id: &str,
    username: &str,
    roles: Vec<String>,
    extended: Option<ExtendedClaimsData>,
) -> Result<String, Box<dyn Error>> {
    let now = Utc::now();
    let expiration = now
        .checked_add_signed(Duration::hours(JWT_EXPIRATION_HOURS))
        .expect("valid timestamp")
        .timestamp() as usize;

    let (org_id, org_role, teams, permissions) = match extended {
        Some(ext) => (ext.org_id, ext.org_role, ext.teams, ext.permissions),
        None => (None, None, Vec::new(), Vec::new()),
    };

    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        roles,
        exp: expiration,
        iat: now.timestamp() as usize,
        org_id,
        org_role,
        teams,
        permissions,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )?;

    Ok(token)
}

pub fn create_refresh_token(user_id: &str) -> Result<String, Box<dyn Error>> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::days(REFRESH_TOKEN_EXPIRATION_DAYS))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = RefreshClaims {
        sub: user_id.to_string(),
        exp: expiration,
        token_type: "refresh".to_string(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )?;

    Ok(token)
}

pub fn verify_jwt(token: &str) -> Result<Claims, Box<dyn Error>> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )?;

    Ok(token_data.claims)
}

pub fn verify_refresh_token(token: &str) -> Result<RefreshClaims, Box<dyn Error>> {
    let token_data = decode::<RefreshClaims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )?;

    // Verify it's actually a refresh token
    if token_data.claims.token_type != "refresh" {
        return Err("Invalid token type".into());
    }

    Ok(token_data.claims)
}

pub fn create_mfa_token(user_id: &str) -> Result<String, Box<dyn Error>> {
    // MFA token expires in 5 minutes
    let expiration = Utc::now()
        .checked_add_signed(Duration::minutes(5))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = MfaClaims {
        sub: user_id.to_string(),
        exp: expiration,
        token_type: "mfa".to_string(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )?;

    Ok(token)
}

pub fn verify_mfa_token(token: &str) -> Result<MfaClaims, Box<dyn Error>> {
    let token_data = decode::<MfaClaims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )?;

    // Verify it's actually an MFA token
    if token_data.claims.token_type != "mfa" {
        return Err("Invalid token type".into());
    }

    Ok(token_data.claims)
}

// Implement FromRequest for Claims to allow direct extraction from route handlers
impl FromRequest for Claims {
    type Error = ActixError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Extract Claims from request extensions (placed there by JwtMiddleware)
        if let Some(claims) = req.extensions().get::<Claims>() {
            ready(Ok(claims.clone()))
        } else {
            ready(Err(actix_web::error::ErrorUnauthorized(
                "Authentication required",
            )))
        }
    }
}
