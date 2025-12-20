//! Portal Authentication
//!
//! Separate authentication system for customer portal users.
//! Uses different JWT claims to distinguish portal users from main app users.

use actix_web::{web, HttpRequest, HttpResponse, HttpMessage, Result, dev::ServiceRequest};
use actix_web::dev::{Service, ServiceResponse, Transform};
use futures_util::future::{ok, Ready, LocalBoxFuture};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::task::{Context, Poll};
use std::rc::Rc;
use chrono::{Utc, Duration};
use sha2::{Sha256, Digest};
use rand::Rng;

use crate::db::crm::{
    get_portal_user_by_email, update_portal_user_last_login,
    get_portal_user_by_id, PortalUser,
    create_password_reset_token, get_valid_reset_token,
    mark_reset_token_used, update_portal_user_password,
};
use crate::notifications::email::{send_portal_password_reset_email, EmailConfig};

/// Portal-specific JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalClaims {
    /// Portal user ID
    pub sub: String,
    /// Customer ID (for data scoping)
    pub customer_id: String,
    /// User email
    pub email: String,
    /// User role (admin, member, viewer)
    pub role: String,
    /// Indicates this is a portal token (not main app)
    pub portal: bool,
    /// Expiration timestamp
    pub exp: usize,
    /// Issued at timestamp
    pub iat: usize,
}

/// Login request
#[derive(Debug, Deserialize)]
pub struct PortalLoginRequest {
    pub email: String,
    pub password: String,
}

/// Login response
#[derive(Debug, Serialize)]
pub struct PortalLoginResponse {
    pub token: String,
    pub user: PortalUserInfo,
}

/// User info returned to client
#[derive(Debug, Serialize)]
pub struct PortalUserInfo {
    pub id: String,
    pub email: String,
    pub customer_id: String,
    pub customer_name: Option<String>,
    pub role: String,
}

/// Forgot password request (initiate reset)
#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

/// Reset password request (complete reset with token)
#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

/// Change password request (for authenticated users)
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Profile response with full user details
#[derive(Debug, Serialize)]
pub struct PortalProfileResponse {
    pub id: String,
    pub email: String,
    pub customer_id: String,
    pub customer_name: Option<String>,
    pub role: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub title: Option<String>,
    pub last_login: Option<String>,
    pub created_at: String,
}

/// Update profile request
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub title: Option<String>,
}

/// Generate a secure random token and return both raw and hashed versions
fn generate_reset_token() -> (String, String) {
    let mut rng = rand::thread_rng();
    let token_bytes: [u8; 32] = rng.gen();
    let raw_token = hex::encode(token_bytes);

    let mut hasher = Sha256::new();
    hasher.update(raw_token.as_bytes());
    let token_hash = hex::encode(hasher.finalize());

    (raw_token, token_hash)
}

/// Hash a token for comparison
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Get the portal base URL from environment or default
fn get_portal_base_url() -> String {
    std::env::var("PORTAL_BASE_URL")
        .or_else(|_| std::env::var("BASE_URL"))
        .unwrap_or_else(|_| "https://heroforge.genialarchitect.io".to_string())
}

fn get_jwt_secret() -> String {
    std::env::var("JWT_SECRET").unwrap_or_else(|_| "portal-secret-key-change-in-production".to_string())
}

/// Generate a portal JWT token
fn generate_portal_token(user: &PortalUser) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let exp = now + Duration::hours(24); // Portal tokens valid for 24 hours

    let claims = PortalClaims {
        sub: user.id.clone(),
        customer_id: user.customer_id.clone(),
        email: user.email.clone(),
        role: user.role.clone(),
        portal: true,
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(get_jwt_secret().as_bytes()),
    )
}

/// Validate a portal JWT token
pub fn validate_portal_token(token: &str) -> Result<PortalClaims, jsonwebtoken::errors::Error> {
    let token_data = decode::<PortalClaims>(
        token,
        &DecodingKey::from_secret(get_jwt_secret().as_bytes()),
        &Validation::default(),
    )?;

    // Ensure this is actually a portal token
    if !token_data.claims.portal {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ));
    }

    Ok(token_data.claims)
}

/// Portal login endpoint
pub async fn login(
    pool: web::Data<SqlitePool>,
    req: web::Json<PortalLoginRequest>,
) -> Result<HttpResponse> {
    // Find user by email
    let user = match get_portal_user_by_email(&pool, &req.email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid email or password"
            })));
        }
        Err(_) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Login failed"
            })));
        }
    };

    // Check if user is active
    if !user.is_active {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Account is disabled"
        })));
    }

    // Verify password
    let password_valid = bcrypt::verify(&req.password, &user.password_hash)
        .unwrap_or(false);

    if !password_valid {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid email or password"
        })));
    }

    // Generate token
    let token = match generate_portal_token(&user) {
        Ok(t) => t,
        Err(_) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to generate token"
            })));
        }
    };

    // Update last login
    let _ = update_portal_user_last_login(&pool, &user.id).await;

    // Get customer name
    let customer_name = sqlx::query_scalar::<_, String>(
        "SELECT name FROM customers WHERE id = ?"
    )
    .bind(&user.customer_id)
    .fetch_optional(pool.get_ref())
    .await
    .ok()
    .flatten();

    Ok(HttpResponse::Ok().json(PortalLoginResponse {
        token,
        user: PortalUserInfo {
            id: user.id.clone(),
            email: user.email,
            customer_id: user.customer_id,
            customer_name,
            role: user.role,
        },
    }))
}

/// Get current portal user info
pub async fn get_current_user(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            })));
        }
    };

    let user = match get_portal_user_by_id(&pool, &claims.sub).await {
        Ok(u) => u,
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            })));
        }
    };

    // Get customer name
    let customer_name = sqlx::query_scalar::<_, String>(
        "SELECT name FROM customers WHERE id = ?"
    )
    .bind(&user.customer_id)
    .fetch_optional(pool.get_ref())
    .await
    .ok()
    .flatten();

    Ok(HttpResponse::Ok().json(PortalUserInfo {
        id: user.id,
        email: user.email,
        customer_id: user.customer_id,
        customer_name,
        role: user.role,
    }))
}

/// Request password reset - sends email with reset link
pub async fn forgot_password(
    pool: web::Data<SqlitePool>,
    req: web::Json<ForgotPasswordRequest>,
) -> Result<HttpResponse> {
    // Always return success to prevent email enumeration
    let success_response = HttpResponse::Ok().json(serde_json::json!({
        "message": "If the email exists, a password reset link has been sent"
    }));

    // Find user by email (silently fail if not found)
    let user = match get_portal_user_by_email(&pool, &req.email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            log::info!("Password reset requested for non-existent email: {}", req.email);
            return Ok(success_response);
        }
        Err(e) => {
            log::error!("Error looking up user for password reset: {}", e);
            return Ok(success_response);
        }
    };

    // Check if user is active
    if !user.is_active {
        log::info!("Password reset requested for inactive user: {}", req.email);
        return Ok(success_response);
    }

    // Check if email is configured
    if !EmailConfig::is_configured() {
        log::warn!("Password reset requested but email is not configured");
        return Ok(HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "Email service is not configured. Please contact your administrator."
        })));
    }

    // Generate token (raw for URL, hash for storage)
    let (raw_token, token_hash) = generate_reset_token();

    // Token expires in 1 hour
    let expires_at = (Utc::now() + Duration::hours(1)).to_rfc3339();

    // Store hashed token in database
    if let Err(e) = create_password_reset_token(&pool, &user.id, &token_hash, &expires_at).await {
        log::error!("Failed to create password reset token: {}", e);
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to process password reset request"
        })));
    }

    // Build reset URL
    let base_url = get_portal_base_url();
    let reset_url = format!("{}/portal/reset-password?token={}", base_url, raw_token);

    // Send email asynchronously (don't block response)
    let email = user.email.clone();
    tokio::spawn(async move {
        if let Err(e) = send_portal_password_reset_email(&email, &reset_url, 60).await {
            log::error!("Failed to send password reset email to {}: {}", email, e);
        }
    });

    Ok(success_response)
}

/// Complete password reset with token
pub async fn reset_password(
    pool: web::Data<SqlitePool>,
    req: web::Json<ResetPasswordRequest>,
) -> Result<HttpResponse> {
    // Validate new password
    if req.new_password.len() < 8 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password must be at least 8 characters"
        })));
    }

    // Hash the provided token
    let token_hash = hash_token(&req.token);

    // Find valid token
    let token = match get_valid_reset_token(&pool, &token_hash).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid or expired reset token"
            })));
        }
        Err(e) => {
            log::error!("Error validating reset token: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to validate reset token"
            })));
        }
    };

    // Hash new password
    let new_hash = match bcrypt::hash(&req.new_password, 12) {
        Ok(h) => h,
        Err(e) => {
            log::error!("Failed to hash new password: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to reset password"
            })));
        }
    };

    // Update user's password
    if let Err(e) = update_portal_user_password(&pool, &token.portal_user_id, &new_hash).await {
        log::error!("Failed to update portal user password: {}", e);
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to reset password"
        })));
    }

    // Mark token as used
    if let Err(e) = mark_reset_token_used(&pool, &token.id).await {
        log::error!("Failed to mark reset token as used: {}", e);
        // Don't fail the request, password was already updated
    }

    log::info!("Password reset completed for portal user: {}", token.portal_user_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Password has been reset successfully. You can now log in with your new password."
    })))
}

/// Change password for authenticated portal user
pub async fn change_password(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    body: web::Json<ChangePasswordRequest>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            })));
        }
    };

    // Get current user
    let user = match get_portal_user_by_id(&pool, &claims.sub).await {
        Ok(u) => u,
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            })));
        }
    };

    // Verify current password
    let password_valid = bcrypt::verify(&body.current_password, &user.password_hash)
        .unwrap_or(false);

    if !password_valid {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Current password is incorrect"
        })));
    }

    // Validate new password
    if body.new_password.len() < 8 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password must be at least 8 characters"
        })));
    }

    // Hash new password
    let new_hash = match bcrypt::hash(&body.new_password, 12) {
        Ok(h) => h,
        Err(_) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update password"
            })));
        }
    };

    // Update password in database
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        "UPDATE portal_users SET password_hash = ?, updated_at = ? WHERE id = ?"
    )
    .bind(&new_hash)
    .bind(&now)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Password updated successfully"
        }))),
        Err(_) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to update password"
        }))),
    }
}

/// Get current portal user's full profile
pub async fn get_profile(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            })));
        }
    };

    // Get portal user with joined contact and customer info
    let profile = sqlx::query_as::<_, (
        String,  // id
        String,  // email
        String,  // customer_id
        Option<String>,  // contact_id
        Option<String>,  // last_login
        String,  // role
        String,  // created_at
        Option<String>,  // customer_name
        Option<String>,  // first_name
        Option<String>,  // last_name
        Option<String>,  // phone
        Option<String>,  // title
    )>(
        r#"
        SELECT
            pu.id,
            pu.email,
            pu.customer_id,
            pu.contact_id,
            pu.last_login,
            pu.role,
            pu.created_at,
            c.name as customer_name,
            ct.first_name,
            ct.last_name,
            ct.phone,
            ct.title
        FROM portal_users pu
        LEFT JOIN customers c ON c.id = pu.customer_id
        LEFT JOIN contacts ct ON ct.id = pu.contact_id
        WHERE pu.id = ?
        "#
    )
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await;

    match profile {
        Ok(Some((id, email, customer_id, _contact_id, last_login, role, created_at, customer_name, first_name, last_name, phone, title))) => {
            Ok(HttpResponse::Ok().json(PortalProfileResponse {
                id,
                email,
                customer_id,
                customer_name,
                role,
                first_name,
                last_name,
                phone,
                title,
                last_login,
                created_at,
            }))
        }
        Ok(None) => {
            Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            })))
        }
        Err(e) => {
            log::error!("Failed to get portal user profile: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get profile"
            })))
        }
    }
}

/// Update current portal user's profile
pub async fn update_profile(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    body: web::Json<UpdateProfileRequest>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            })));
        }
    };

    // Get current user to check if they have a linked contact
    let user = match get_portal_user_by_id(&pool, &claims.sub).await {
        Ok(u) => u,
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            })));
        }
    };

    let now = Utc::now().to_rfc3339();

    // If user has a linked contact, update it
    if let Some(contact_id) = &user.contact_id {
        // Build dynamic update query for contact
        let mut updates = Vec::new();
        let mut values: Vec<String> = Vec::new();

        if let Some(ref first_name) = body.first_name {
            updates.push("first_name = ?");
            values.push(first_name.clone());
        }
        if let Some(ref last_name) = body.last_name {
            updates.push("last_name = ?");
            values.push(last_name.clone());
        }
        if let Some(ref phone) = body.phone {
            updates.push("phone = ?");
            values.push(phone.clone());
        }
        if let Some(ref title) = body.title {
            updates.push("title = ?");
            values.push(title.clone());
        }

        if !updates.is_empty() {
            updates.push("updated_at = ?");
            values.push(now.clone());

            let query = format!(
                "UPDATE contacts SET {} WHERE id = ?",
                updates.join(", ")
            );

            let mut q = sqlx::query(&query);
            for value in &values {
                q = q.bind(value);
            }
            q = q.bind(contact_id);

            if let Err(e) = q.execute(pool.get_ref()).await {
                log::error!("Failed to update contact: {}", e);
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to update profile"
                })));
            }
        }
    } else {
        // No linked contact - create one
        if body.first_name.is_some() || body.last_name.is_some() || body.phone.is_some() || body.title.is_some() {
            let contact_id = uuid::Uuid::new_v4().to_string();
            let first_name = body.first_name.clone().unwrap_or_default();
            let last_name = body.last_name.clone().unwrap_or_default();

            // Create new contact
            let result = sqlx::query(
                r#"
                INSERT INTO contacts (id, customer_id, first_name, last_name, email, phone, title, is_primary, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                "#
            )
            .bind(&contact_id)
            .bind(&user.customer_id)
            .bind(&first_name)
            .bind(&last_name)
            .bind(&user.email)
            .bind(&body.phone)
            .bind(&body.title)
            .bind(&now)
            .bind(&now)
            .execute(pool.get_ref())
            .await;

            if let Err(e) = result {
                log::error!("Failed to create contact for portal user: {}", e);
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to update profile"
                })));
            }

            // Link contact to portal user
            let result = sqlx::query(
                "UPDATE portal_users SET contact_id = ?, updated_at = ? WHERE id = ?"
            )
            .bind(&contact_id)
            .bind(&now)
            .bind(&claims.sub)
            .execute(pool.get_ref())
            .await;

            if let Err(e) = result {
                log::error!("Failed to link contact to portal user: {}", e);
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to update profile"
                })));
            }
        }
    }

    // Return updated profile
    get_profile(pool, req).await
}

// ============================================================================
// Portal Authentication Middleware
// ============================================================================

pub struct PortalAuthMiddleware;

impl<S, B> Transform<S, ServiceRequest> for PortalAuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = PortalAuthMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(PortalAuthMiddlewareService {
            service: Rc::new(service),
        })
    }
}

pub struct PortalAuthMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for PortalAuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        Box::pin(async move {
            // Extract token from Authorization header
            let token = req
                .headers()
                .get("Authorization")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(|s| s.to_string());

            let token = match token {
                Some(t) => t,
                None => {
                    return Err(actix_web::error::ErrorUnauthorized("Missing authorization token"));
                }
            };

            // Validate token
            let claims = match validate_portal_token(&token) {
                Ok(c) => c,
                Err(_) => {
                    return Err(actix_web::error::ErrorUnauthorized("Invalid or expired token"));
                }
            };

            // Store claims in request extensions
            req.extensions_mut().insert(claims);

            // Call the next service
            service.call(req).await
        })
    }
}
