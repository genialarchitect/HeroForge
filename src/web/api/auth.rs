use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;

use crate::db::{self, models};
use crate::web::auth;
use crate::web::auth::jwt::create_mfa_token;

/// Register a new user account
#[utoipa::path(
    post,
    path = "/api/auth/register",
    tag = "Authentication",
    request_body(
        content = crate::web::openapi::CreateUserSchema,
        description = "User registration data"
    ),
    responses(
        (status = 200, description = "User registered successfully", body = crate::web::openapi::LoginResponseSchema),
        (status = 400, description = "Username already exists or invalid input", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn register(
    pool: web::Data<SqlitePool>,
    user_data: web::Json<models::CreateUser>,
) -> Result<HttpResponse> {
    // Check if user already exists
    if let Ok(Some(_)) = db::get_user_by_username(&pool, &user_data.username).await {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Username already exists"
        })));
    }

    // Create user (email and password validation happens in db::create_user)
    match db::create_user(&pool, &user_data).await {
        Ok(user) => {
            // Check if this is the admin user (based on ADMIN_USERNAME environment variable)
            let admin_username = std::env::var("ADMIN_USERNAME").ok();
            let role_id = if let Some(admin_user) = admin_username {
                if user_data.username == admin_user {
                    "admin"
                } else {
                    "user"
                }
            } else {
                "user"
            };

            // Assign default role
            if let Err(e) = db::assign_role_to_user(&pool, &user.id, role_id, &user.id).await {
                eprintln!("Failed to assign role to user: {}", e);
            }

            // Fetch user roles for JWT
            let roles = db::get_user_roles(&pool, &user.id).await.unwrap_or_default();
            let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

            let token = auth::create_jwt(&user.id, &user.username, role_names)
                .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create token"))?;

            let refresh_token = auth::create_refresh_token(&user.id)
                .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create refresh token"))?;

            Ok(HttpResponse::Ok().json(models::LoginResponse {
                token,
                refresh_token,
                user: user.into(),
            }))
        }
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create user: {}", e)
        }))),
    }
}

/// Authenticate user and obtain JWT tokens
#[utoipa::path(
    post,
    path = "/api/auth/login",
    tag = "Authentication",
    request_body(
        content = crate::web::openapi::LoginRequestSchema,
        description = "Login credentials"
    ),
    responses(
        (status = 200, description = "Login successful", body = crate::web::openapi::LoginResponseSchema),
        (status = 200, description = "MFA verification required", body = crate::web::openapi::MfaLoginResponseSchema),
        (status = 401, description = "Invalid credentials", body = crate::web::openapi::ErrorResponse),
        (status = 403, description = "Account disabled", body = crate::web::openapi::ErrorResponse),
        (status = 429, description = "Account locked due to too many failed attempts", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn login(
    pool: web::Data<SqlitePool>,
    credentials: web::Json<models::LoginRequest>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    // Extract client IP address and user agent for audit logging (NIST 800-53 AC-7)
    let ip_address = req.peer_addr().map(|addr| addr.ip().to_string());
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // STEP 1: Check if account is locked BEFORE attempting authentication
    // This prevents username enumeration via timing attacks
    match db::check_account_locked(&pool, &credentials.username).await {
        Ok((is_locked, locked_until, _attempt_count)) => {
            if is_locked {
                if let Some(until) = locked_until {
                    let duration = until.signed_duration_since(chrono::Utc::now());
                    let minutes = duration.num_minutes();

                    // Log the failed login attempt (account locked)
                    let _ = db::record_login_attempt(
                        &pool,
                        &credentials.username,
                        false,
                        ip_address.as_deref(),
                        user_agent.as_deref(),
                    ).await;

                    return Ok(HttpResponse::TooManyRequests().json(serde_json::json!({
                        "error": "Account temporarily locked due to too many failed login attempts",
                        "locked_until": until.to_rfc3339(),
                        "minutes_remaining": minutes.max(0),
                        "message": "Please try again later or contact support"
                    })));
                }
            }
        }
        Err(e) => {
            eprintln!("Error checking account lockout status: {}", e);
            // Continue with authentication attempt even if lockout check fails
        }
    }

    // STEP 2: Get user by username
    let user = match db::get_user_by_username(&pool, &credentials.username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            // User doesn't exist - record as failed attempt but don't reveal this information
            let _ = db::record_login_attempt(
                &pool,
                &credentials.username,
                false,
                ip_address.as_deref(),
                user_agent.as_deref(),
            ).await;

            // Increment failed attempts counter (will track even non-existent usernames)
            let _ = db::increment_failed_attempts(&pool, &credentials.username).await;

            // Generic error message (don't reveal if username exists)
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid credentials"
            })));
        }
        Err(e) => {
            eprintln!("Database error during login: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Authentication service temporarily unavailable"
            })));
        }
    };

    // STEP 3: Verify password
    let password_valid = bcrypt::verify(&credentials.password, &user.password_hash)
        .unwrap_or(false);

    if !password_valid {
        // Record failed login attempt
        let _ = db::record_login_attempt(
            &pool,
            &credentials.username,
            false,
            ip_address.as_deref(),
            user_agent.as_deref(),
        ).await;

        // Increment failed attempts and check if account should be locked
        match db::increment_failed_attempts(&pool, &credentials.username).await {
            Ok((is_now_locked, locked_until, attempt_count)) => {
                if is_now_locked {
                    if let Some(until) = locked_until {
                        let duration = until.signed_duration_since(chrono::Utc::now());
                        let minutes = duration.num_minutes();

                        return Ok(HttpResponse::TooManyRequests().json(serde_json::json!({
                            "error": "Account locked due to too many failed login attempts",
                            "locked_until": until.to_rfc3339(),
                            "minutes_remaining": minutes.max(0),
                            "attempt_count": attempt_count,
                            "message": "Your account has been temporarily locked for security. Please try again later."
                        })));
                    }
                } else {
                    // Not locked yet, but show warning
                    let remaining = 5 - attempt_count;
                    return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                        "error": "Invalid credentials",
                        "warning": format!("{} attempts remaining before account lockout", remaining.max(0))
                    })));
                }
            }
            Err(e) => {
                eprintln!("Error incrementing failed attempts: {}", e);
            }
        }

        // Generic error response
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid credentials"
        })));
    }

    // STEP 4: Check if user account is active
    if !user.is_active {
        let _ = db::record_login_attempt(
            &pool,
            &credentials.username,
            false,
            ip_address.as_deref(),
            user_agent.as_deref(),
        ).await;

        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Account is disabled. Please contact administrator."
        })));
    }

    // STEP 5: Authentication successful - reset failed attempts counter
    if let Err(e) = db::reset_failed_attempts(&pool, &credentials.username).await {
        eprintln!("Error resetting failed attempts: {}", e);
        // Continue even if reset fails
    }

    // Record successful login attempt
    let _ = db::record_login_attempt(
        &pool,
        &credentials.username,
        true,
        ip_address.as_deref(),
        user_agent.as_deref(),
    ).await;

    // STEP 6: Check if MFA is enabled for this user
    match db::is_mfa_enabled(&pool, &user.id).await {
        Ok(true) => {
            // MFA is enabled - return MFA token instead of actual JWT
            let mfa_token = create_mfa_token(&user.id)
                .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create MFA token"))?;

            return Ok(HttpResponse::Ok().json(models::MfaLoginResponse {
                mfa_required: true,
                mfa_token: Some(mfa_token),
            }));
        }
        Ok(false) => {
            // MFA not enabled, proceed with normal login
        }
        Err(e) => {
            log::error!("Error checking MFA status: {}", e);
            // Continue with normal login on error (fail open for availability)
        }
    }

    // STEP 7: MFA not enabled - complete normal login
    // Fetch user roles for JWT
    let roles = db::get_user_roles(&pool, &user.id).await.unwrap_or_default();
    let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

    // Create JWT token
    let token = auth::create_jwt(&user.id, &user.username, role_names)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create token"))?;

    let refresh_token = auth::create_refresh_token(&user.id)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create refresh token"))?;

    // Store refresh token in database (will be hashed with SHA-256 internally)
    let expires_at = chrono::Utc::now() + chrono::Duration::days(7);
    if let Err(e) = db::store_refresh_token(&pool, &user.id, &refresh_token, expires_at).await {
        log::error!("Failed to store refresh token: {}", e);
    }

    Ok(HttpResponse::Ok().json(models::LoginResponse {
        token,
        refresh_token,
        user: user.into(),
    }))
}

/// Get current authenticated user's information
#[utoipa::path(
    get,
    path = "/api/auth/me",
    tag = "Authentication",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "User information retrieved successfully", body = crate::web::openapi::UserInfoSchema),
        (status = 401, description = "Unauthorized - invalid or missing token", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "User not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn me(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    // Fetch full user details including email
    match db::get_user_by_id(&pool, &claims.sub).await {
        Ok(Some(user)) => {
            let roles = db::get_user_roles(&pool, &user.id).await.unwrap_or_default();
            let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

            // Check MFA status
            let mfa_enabled = db::is_mfa_enabled(&pool, &user.id).await.unwrap_or(false);

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "is_active": user.is_active,
                "created_at": user.created_at,
                "roles": role_names,
                "mfa_enabled": mfa_enabled
            })))
        }
        Ok(None) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "User not found"
        }))),
        Err(e) => {
            log::error!("Database error in me endpoint: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "An internal error occurred. Please try again later."
            })))
        },
    }
}

/// Update current user's profile
#[utoipa::path(
    put,
    path = "/api/auth/profile",
    tag = "Authentication",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = inline(crate::db::models::UpdateProfileRequest),
        description = "Profile update data"
    ),
    responses(
        (status = 200, description = "Profile updated successfully", body = crate::web::openapi::UserInfoSchema),
        (status = 400, description = "Invalid input", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn update_profile(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    updates: web::Json<models::UpdateProfileRequest>,
) -> Result<HttpResponse> {
    // Update user's own profile
    match db::update_user_profile(&pool, &claims.sub, &updates).await {
        Ok(user) => {
            let roles = db::get_user_roles(&pool, &user.id).await.unwrap_or_default();
            let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "is_active": user.is_active,
                "created_at": user.created_at,
                "roles": role_names
            })))
        }
        Err(e) => Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Failed to update profile: {}", e)
        }))),
    }
}

/// Change current user's password
#[utoipa::path(
    put,
    path = "/api/auth/password",
    tag = "Authentication",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = inline(crate::db::models::ChangePasswordRequest),
        description = "Current and new password"
    ),
    responses(
        (status = 200, description = "Password changed successfully", body = crate::web::openapi::SuccessResponse),
        (status = 400, description = "Invalid password or policy violation", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Current password incorrect", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "User not found", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn change_password(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    data: web::Json<models::ChangePasswordRequest>,
) -> Result<HttpResponse> {
    // Get current user
    let user = match db::get_user_by_id(&pool, &claims.sub).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            })));
        }
        Err(e) => {
            log::error!("Database error in change_password: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "An internal error occurred. Please try again later."
            })));
        }
    };

    // Verify current password
    let password_valid = bcrypt::verify(&data.current_password, &user.password_hash)
        .unwrap_or(false);

    if !password_valid {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Current password is incorrect"
        })));
    }

    // Validate new password against NIST 800-63B guidelines
    if let Err(e) = crate::password_validation::validate_password(&data.new_password) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": e
        })));
    }

    // Check password history to prevent reuse (NIST 800-63B)
    match db::check_password_history(&pool, &claims.sub, &data.new_password).await {
        Ok(true) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Password was recently used. Please choose a different password. Your last 5 passwords cannot be reused."
            })));
        }
        Ok(false) => {
            // Password is not in history, proceed
        }
        Err(e) => {
            log::error!("Error checking password history: {}", e);
            // Continue even if history check fails (fail open for availability)
        }
    }

    // Hash new password
    let new_hash = bcrypt::hash(&data.new_password, *crate::db::BCRYPT_COST)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to hash password"))?;

    // Update password
    match db::update_user_password(&pool, &claims.sub, &new_hash).await {
        Ok(_) => {
            // Add new password to history
            if let Err(e) = db::add_password_to_history(&pool, &claims.sub, &new_hash).await {
                log::error!("Failed to add password to history: {}", e);
                // Continue even if history update fails
            }

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "Password changed successfully"
            })))
        }
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to change password: {}", e)
        }))),
    }
}

/// Refresh JWT access token using refresh token
#[utoipa::path(
    post,
    path = "/api/auth/refresh",
    tag = "Authentication",
    request_body(
        content = crate::web::openapi::RefreshTokenRequestSchema,
        description = "Refresh token"
    ),
    responses(
        (status = 200, description = "Token refreshed successfully", body = crate::web::openapi::RefreshTokenResponseSchema),
        (status = 401, description = "Invalid or expired refresh token", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "User not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn refresh(
    pool: web::Data<SqlitePool>,
    request: web::Json<models::RefreshTokenRequest>,
) -> Result<HttpResponse> {
    let claims = match auth::verify_refresh_token(&request.refresh_token) {
        Ok(claims) => claims,
        Err(_) => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid refresh token"
            })));
        }
    };

    // get_refresh_token will hash the token internally with SHA-256
    let stored_token = match db::get_refresh_token(&pool, &request.refresh_token).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Refresh token not found or revoked"
            })));
        }
        Err(_) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            })));
        }
    };

    if stored_token.expires_at < chrono::Utc::now() {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Refresh token expired"
        })));
    }

    let user = match db::get_user_by_id(&pool, &claims.sub).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            })));
        }
        Err(_) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            })));
        }
    };

    let roles = db::get_user_roles(&pool, &user.id).await.unwrap_or_default();
    let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

    let access_token = auth::create_jwt(&user.id, &user.username, role_names)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create token"))?;

    Ok(HttpResponse::Ok().json(models::RefreshTokenResponse {
        access_token,
    }))
}

/// Logout and revoke refresh token
#[utoipa::path(
    post,
    path = "/api/auth/logout",
    tag = "Authentication",
    request_body(
        content = crate::web::openapi::RefreshTokenRequestSchema,
        description = "Refresh token to revoke"
    ),
    responses(
        (status = 200, description = "Logged out successfully", body = crate::web::openapi::SuccessResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn logout(
    pool: web::Data<SqlitePool>,
    request: web::Json<models::RefreshTokenRequest>,
) -> Result<HttpResponse> {
    // revoke_refresh_token will hash the token internally with SHA-256
    if let Err(e) = db::revoke_refresh_token(&pool, &request.refresh_token).await {
        log::error!("Failed to revoke refresh token: {}", e);
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to logout"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Successfully logged out"
    })))
}

// ============================================================================
// GDPR Compliance Endpoints
// ============================================================================

/// Get terms acceptance status for current user
pub async fn get_terms_status(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    match db::get_user_by_id(&pool, &claims.sub).await {
        Ok(Some(user)) => {
            let current_version = "1.0";
            let accepted = user.accepted_terms_at.is_some();
            let needs_update = if let Some(ref version) = user.terms_version {
                version != current_version
            } else {
                true
            };

            Ok(HttpResponse::Ok().json(models::TermsStatusResponse {
                accepted,
                accepted_at: user.accepted_terms_at,
                current_version: current_version.to_string(),
                user_version: user.terms_version,
                needs_update,
            }))
        }
        Ok(None) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "User not found"
        }))),
        Err(e) => {
            log::error!("Database error in get_terms_status: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "An internal error occurred. Please try again later."
            })))
        }
    }
}

/// Accept terms and conditions for current user
pub async fn accept_terms(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    match db::accept_terms(&pool, &claims.sub).await {
        Ok(user) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Terms accepted successfully",
            "accepted_at": user.accepted_terms_at,
            "terms_version": user.terms_version
        }))),
        Err(e) => {
            log::error!("Failed to accept terms: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to accept terms. Please try again later."
            })))
        }
    }
}

/// Export all user data (GDPR data portability right)
pub async fn export_user_data(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    match db::export_user_data(&pool, &claims.sub).await {
        Ok(data) => {
            // Return as JSON with content-disposition header for download
            Ok(HttpResponse::Ok()
                .insert_header((
                    actix_web::http::header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"user_data_{}.json\"", claims.sub),
                ))
                .insert_header((
                    actix_web::http::header::CONTENT_TYPE,
                    "application/json",
                ))
                .json(data))
        }
        Err(e) => {
            log::error!("Failed to export user data: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to export data. Please try again later."
            })))
        }
    }
}

/// Delete user account and all associated data (GDPR right to be forgotten)
pub async fn delete_account(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<models::DeleteAccountRequest>,
) -> Result<HttpResponse> {
    // Get user to verify password
    let user = match db::get_user_by_id(&pool, &claims.sub).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            })));
        }
        Err(e) => {
            log::error!("Database error in delete_account: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "An internal error occurred. Please try again later."
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

    // Log the deletion in audit logs
    let audit_log = models::AuditLog {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: claims.sub.clone(),
        action: "account_deletion".to_string(),
        target_type: Some("user".to_string()),
        target_id: Some(claims.sub.clone()),
        details: Some(format!("User {} ({}) deleted their account", user.username, user.email)),
        ip_address: None,
        user_agent: None,
        created_at: chrono::Utc::now(),
    };

    if let Err(e) = db::create_audit_log(&pool, &audit_log).await {
        log::error!("Failed to create audit log for account deletion: {}", e);
    }

    // Delete the account and all associated data
    match db::delete_user_account(&pool, &claims.sub).await {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Account and all associated data have been permanently deleted"
        }))),
        Err(e) => {
            log::error!("Failed to delete user account: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete account. Please contact support."
            })))
        }
    }
}
