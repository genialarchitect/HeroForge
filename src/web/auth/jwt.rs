use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::error::Error;

const JWT_SECRET: &str = "your-secret-key-change-this-in-production";
const JWT_EXPIRATION_HOURS: i64 = 24;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // user id
    pub username: String,
    pub roles: Vec<String>, // user roles (e.g., ["admin", "user"])
    pub exp: usize,         // expiration time
}

pub fn create_jwt(user_id: &str, username: &str, roles: Vec<String>) -> Result<String, Box<dyn Error>> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(JWT_EXPIRATION_HOURS))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        roles,
        exp: expiration,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_ref()),
    )?;

    Ok(token)
}

pub fn verify_jwt(token: &str) -> Result<Claims, Box<dyn Error>> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &Validation::default(),
    )?;

    Ok(token_data.claims)
}
