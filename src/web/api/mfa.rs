use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;
use totp_rs::{Algorithm, TOTP, Secret};
use rand::Rng;

use crate::db::{self, models};
use crate::web::auth;
use crate::web::auth::jwt::{verify_mfa_token, create_jwt_extended, ExtendedClaimsData};

/// Helper function to build extended JWT claims with organization context
async fn build_extended_claims(pool: &SqlitePool, user_id: &str) -> Option<ExtendedClaimsData> {
    // Get user's first/default organization
    let orgs = crate::db::permissions::organizations::list_user_organizations(pool, user_id)
        .await
        .ok()?;

    if orgs.is_empty() {
        return None;
    }

    let org = &orgs[0];

    let org_role = crate::db::permissions::organizations::get_user_org_role(pool, user_id, &org.id)
        .await
        .ok()
        .flatten()
        .map(|r| r.as_str().to_string());

    let teams = crate::db::permissions::organizations::get_user_teams(pool, user_id)
        .await
        .ok()
        .unwrap_or_default()
        .into_iter()
        .map(|(team_id, _role)| team_id)
        .collect();

    let permissions: Vec<String> = crate::db::permissions::evaluation::get_effective_permissions(pool, user_id, &org.id)
        .await
        .ok()
        .map(|p| p.granted.into_iter().take(20).collect())
        .unwrap_or_default();

    Some(ExtendedClaimsData {
        org_id: Some(org.id.clone()),
        org_role,
        teams,
        permissions,
    })
}

/// Setup MFA for the authenticated user
/// Returns TOTP secret, QR code URL, and recovery codes
#[utoipa::path(
    post,
    path = "/api/auth/mfa/setup",
    tag = "MFA",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "MFA setup initiated successfully"),
        (status = 400, description = "MFA already enabled", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "User not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn setup_mfa(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Check if MFA is already enabled
    match db::is_mfa_enabled(&pool, user_id).await {
        Ok(true) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "MFA is already enabled. Disable it first to re-setup."
            })));
        }
        Ok(false) => {},
        Err(e) => {
            log::error!("Error checking MFA status: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to check MFA status"
            })));
        }
    }

    // Get user for email/username
    let user = match db::get_user_by_id(&pool, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            })));
        }
        Err(e) => {
            log::error!("Error fetching user: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch user"
            })));
        }
    };

    // Generate TOTP secret
    let secret = Secret::generate_secret();
    let secret_str = secret.to_encoded().to_string();

    // Create TOTP instance for QR code generation
    let secret_bytes = secret.to_bytes().map_err(|e| {
        log::error!("Failed to convert TOTP secret to bytes: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to generate TOTP secret")
    })?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6, // 6 digit code
        1, // 1 step skew
        30, // 30 second period
        secret_bytes,
        Some("HeroForge".to_string()),
        user.email.clone(),
    ).map_err(|e| {
        log::error!("Failed to create TOTP instance: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create TOTP instance")
    })?;

    // Generate otpauth:// URL for QR code
    let qr_code_url = totp.get_url();

    // Generate 10 recovery codes (8 characters each, alphanumeric)
    let recovery_codes = generate_recovery_codes(10);

    // Store the TOTP secret in database (MFA is NOT enabled yet - totp_enabled remains false)
    // The user must call /api/auth/mfa/verify-setup with a valid TOTP code to complete setup
    // This ensures the user has successfully added the secret to their authenticator app
    if let Err(e) = db::store_totp_secret(&pool, user_id, &secret_str).await {
        log::error!("Failed to store TOTP secret: {}", e);
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to store TOTP secret"
        })));
    }

    // Store recovery codes (hashed)
    if let Err(e) = db::store_recovery_codes(&pool, user_id, &recovery_codes).await {
        log::error!("Failed to store recovery codes: {}", e);
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to store recovery codes"
        })));
    }

    Ok(HttpResponse::Ok().json(models::MfaSetupResponse {
        secret: secret_str,
        qr_code_url,
        recovery_codes,
    }))
}

/// Verify TOTP code to complete MFA setup
#[utoipa::path(
    post,
    path = "/api/auth/mfa/verify-setup",
    tag = "MFA",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = inline(crate::db::models::MfaVerifySetupRequest),
        description = "TOTP code to verify setup. Body should contain: {\"totp_code\": \"123456\"}"
    ),
    responses(
        (status = 200, description = "MFA enabled successfully", body = crate::web::openapi::SuccessResponse),
        (status = 400, description = "MFA not initialized", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Invalid TOTP code", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn verify_setup(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<models::MfaVerifySetupRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Get stored TOTP secret
    let secret_str = match db::get_totp_secret(&pool, user_id).await {
        Ok(Some(secret)) => secret,
        Ok(None) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "MFA not initialized. Call /api/auth/mfa/setup first."
            })));
        }
        Err(e) => {
            log::error!("Error fetching TOTP secret: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch TOTP secret"
            })));
        }
    };

    // Create TOTP instance from stored secret
    let secret = Secret::Encoded(secret_str.clone()).to_bytes()
        .map_err(|e| {
            log::error!("Failed to decode TOTP secret: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to decode TOTP secret")
        })?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some("HeroForge".to_string()),
        "user".to_string(),
    ).map_err(|e| {
        log::error!("Failed to create TOTP instance: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create TOTP instance")
    })?;

    // Verify the TOTP code
    if !totp.check_current(&request.totp_code).map_err(|e| {
        log::error!("Failed to verify TOTP code: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to verify TOTP code")
    })? {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid TOTP code"
        })));
    }

    // Enable MFA for the user
    if let Err(e) = db::enable_mfa(&pool, user_id).await {
        log::error!("Failed to enable MFA: {}", e);
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to enable MFA"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "MFA enabled successfully"
    })))
}

/// Disable MFA for the authenticated user
#[utoipa::path(
    delete,
    path = "/api/auth/mfa",
    tag = "MFA",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = inline(crate::db::models::MfaDisableRequest),
        description = "Password and TOTP/recovery code. Body: {\"password\": \"...\", \"totp_code\": \"123456\"} or {\"password\": \"...\", \"recovery_code\": \"...\"}"
    ),
    responses(
        (status = 200, description = "MFA disabled successfully", body = crate::web::openapi::SuccessResponse),
        (status = 401, description = "Invalid password or code", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "User not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn disable_mfa(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<models::MfaDisableRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Get user to verify password
    let user = match db::get_user_by_id(&pool, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            })));
        }
        Err(e) => {
            log::error!("Error fetching user: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch user"
            })));
        }
    };

    // Verify password
    let password_valid = bcrypt::verify(&request.password, &user.password_hash)
        .unwrap_or(false);

    if !password_valid {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid password"
        })));
    }

    // Verify TOTP code or recovery code
    let mut code_valid = false;

    if let Some(ref totp_code) = request.totp_code {
        // Verify TOTP code
        if let Ok(Some(secret_str)) = db::get_totp_secret(&pool, user_id).await {
            if let Ok(secret) = Secret::Encoded(secret_str.clone()).to_bytes() {
                if let Ok(totp) = TOTP::new(
                    Algorithm::SHA1,
                    6,
                    1,
                    30,
                    secret,
                    Some("HeroForge".to_string()),
                    "user".to_string(),
                ) {
                    code_valid = totp.check_current(totp_code).unwrap_or(false);
                }
            }
        }
    } else if let Some(ref recovery_code) = request.recovery_code {
        // Verify recovery code
        code_valid = db::verify_and_consume_recovery_code(&pool, user_id, recovery_code)
            .await
            .unwrap_or(false);
    }

    if !code_valid {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid TOTP code or recovery code"
        })));
    }

    // Disable MFA
    if let Err(e) = db::disable_mfa(&pool, user_id).await {
        log::error!("Failed to disable MFA: {}", e);
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to disable MFA"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "MFA disabled successfully"
    })))
}

/// Verify MFA code during login
#[utoipa::path(
    post,
    path = "/api/auth/mfa/verify",
    tag = "MFA",
    request_body(
        content = crate::web::openapi::MfaVerifyRequestSchema,
        description = "MFA token and TOTP/recovery code"
    ),
    responses(
        (status = 200, description = "MFA verified, login complete", body = crate::web::openapi::LoginResponseSchema),
        (status = 400, description = "Missing code", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Invalid token or code", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "User not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn verify_mfa(
    pool: web::Data<SqlitePool>,
    request: web::Json<models::MfaVerifyRequest>,
) -> Result<HttpResponse> {
    // Verify the MFA token (short-lived token from login step)
    let mfa_claims = match verify_mfa_token(&request.mfa_token) {
        Ok(claims) => claims,
        Err(_) => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid or expired MFA token"
            })));
        }
    };

    let user_id = &mfa_claims.sub;

    // Verify TOTP code or recovery code
    let mut code_valid = false;

    if let Some(ref totp_code) = request.totp_code {
        // Verify TOTP code
        if let Ok(Some(secret_str)) = db::get_totp_secret(&pool, user_id).await {
            if let Ok(secret) = Secret::Encoded(secret_str.clone()).to_bytes() {
                if let Ok(totp) = TOTP::new(
                    Algorithm::SHA1,
                    6,
                    1,
                    30,
                    secret,
                    Some("HeroForge".to_string()),
                    "user".to_string(),
                ) {
                    code_valid = totp.check_current(totp_code).unwrap_or(false);
                }
            }
        }
    } else if let Some(ref recovery_code) = request.recovery_code {
        // Verify recovery code
        code_valid = db::verify_and_consume_recovery_code(&pool, user_id, recovery_code)
            .await
            .unwrap_or(false);
    } else {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Either totp_code or recovery_code must be provided"
        })));
    }

    if !code_valid {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid TOTP code or recovery code"
        })));
    }

    // MFA verification successful - generate actual JWT and refresh token
    let user = match db::get_user_by_id(&pool, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            })));
        }
        Err(e) => {
            log::error!("Error fetching user: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch user"
            })));
        }
    };

    let roles = db::get_user_roles(&pool, user_id).await.unwrap_or_default();
    let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

    // Get organization context for extended JWT claims
    let extended_claims = build_extended_claims(pool.get_ref(), user_id).await;

    let token = create_jwt_extended(user_id, &user.username, role_names, extended_claims)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create token"))?;

    let refresh_token = auth::create_refresh_token(user_id)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create refresh token"))?;

    // Store refresh token
    let token_hash = refresh_token.clone();
    let expires_at = chrono::Utc::now() + chrono::Duration::days(7);
    if let Err(e) = db::store_refresh_token(&pool, user_id, &token_hash, expires_at).await {
        log::error!("Failed to store refresh token: {}", e);
    }

    Ok(HttpResponse::Ok().json(models::LoginResponse {
        token,
        refresh_token,
        user: user.into(),
    }))
}

/// Regenerate recovery codes (requires password + current TOTP code)
pub async fn regenerate_recovery_codes(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<models::MfaRegenerateRecoveryCodesRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Get user to verify password
    let user = match db::get_user_by_id(&pool, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            })));
        }
        Err(e) => {
            log::error!("Error fetching user: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch user"
            })));
        }
    };

    // Verify password
    let password_valid = bcrypt::verify(&request.password, &user.password_hash)
        .unwrap_or(false);

    if !password_valid {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid password"
        })));
    }

    // Verify TOTP code
    let secret_str = match db::get_totp_secret(&pool, user_id).await {
        Ok(Some(secret)) => secret,
        Ok(None) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "MFA not enabled"
            })));
        }
        Err(e) => {
            log::error!("Error fetching TOTP secret: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch TOTP secret"
            })));
        }
    };

    let secret = Secret::Encoded(secret_str.clone()).to_bytes()
        .map_err(|e| {
            log::error!("Failed to decode TOTP secret: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to decode TOTP secret")
        })?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some("HeroForge".to_string()),
        "user".to_string(),
    ).map_err(|e| {
        log::error!("Failed to create TOTP instance: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create TOTP instance")
    })?;

    if !totp.check_current(&request.totp_code).map_err(|e| {
        log::error!("Failed to verify TOTP code: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to verify TOTP code")
    })? {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid TOTP code"
        })));
    }

    // Generate new recovery codes
    let new_recovery_codes = generate_recovery_codes(10);

    // Store new recovery codes (hashed)
    if let Err(e) = db::store_recovery_codes(&pool, user_id, &new_recovery_codes).await {
        log::error!("Failed to store recovery codes: {}", e);
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to store recovery codes"
        })));
    }

    Ok(HttpResponse::Ok().json(models::MfaRegenerateRecoveryCodesResponse {
        recovery_codes: new_recovery_codes,
    }))
}

/// Generate recovery codes (alphanumeric, 8 characters each)
fn generate_recovery_codes(count: usize) -> Vec<String> {
    let mut rng = rand::thread_rng();
    let charset: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();

    (0..count)
        .map(|_| {
            (0..8)
                .map(|_| charset[rng.gen_range(0..charset.len())])
                .collect()
        })
        .collect()
}
