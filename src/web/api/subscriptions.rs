//! Subscription and registration API endpoints
//!
//! Handles:
//! - Tiered registration flow (init, verify, complete)
//! - Stripe checkout integration
//! - Enterprise inquiry submission
//! - Subscription management

use actix_web::{web, HttpResponse, Result as ActixResult};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;

use crate::db;
use crate::email::{EmailConfig, EmailService, EnterpriseInquiry};
use crate::subscriptions::{
    stripe::StripeClient,
    tiers::{self, get_role_for_tier},
    verification::{self, VerificationService},
};
use crate::web::auth::jwt::create_jwt;
use crate::web::error::ApiError;

/// Configure subscription routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/subscriptions")
            .route("/tiers", web::get().to(get_tiers))
            .route("/checkout", web::post().to(create_checkout)),
    )
    .service(
        web::scope("/registration")
            .route("/init", web::post().to(init_registration))
            .route("/verify", web::post().to(verify_email))
            .route("/complete", web::post().to(complete_registration))
            .route("/check-email", web::post().to(check_email)),
    )
    .service(web::resource("/enterprise/inquiry").route(web::post().to(submit_enterprise_inquiry)))
    .service(web::resource("/webhooks/stripe").route(web::post().to(handle_stripe_webhook)));
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct InitRegistrationRequest {
    pub email: String,
    pub tier: String,
    #[serde(default = "default_billing_cycle")]
    pub billing_cycle: String,
}

fn default_billing_cycle() -> String {
    "monthly".to_string()
}

#[derive(Debug, Serialize)]
pub struct InitRegistrationResponse {
    pub verification_id: String,
    pub checkout_url: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_verified: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyEmailResponse {
    pub verified: bool,
    pub email: String,
    pub tier: String,
    pub payment_required: bool,
    pub payment_verified: bool,
}

#[derive(Debug, Deserialize)]
pub struct CompleteRegistrationRequest {
    pub token: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub accept_terms: bool,
}

#[derive(Debug, Serialize)]
pub struct CompleteRegistrationResponse {
    pub success: bool,
    pub user_id: String,
    pub token: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct CheckEmailRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct CheckEmailResponse {
    pub available: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateCheckoutRequest {
    pub tier: String,
    pub billing_cycle: String,
    pub email: String,
    pub success_url: String,
    pub cancel_url: String,
}

#[derive(Debug, Serialize)]
pub struct CreateCheckoutResponse {
    pub checkout_url: String,
    pub session_id: String,
}

#[derive(Debug, Deserialize)]
pub struct EnterpriseInquiryRequest {
    pub email: String,
    pub company_name: String,
    pub contact_name: String,
    pub phone: Option<String>,
    pub job_title: Option<String>,
    pub company_size: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EnterpriseInquiryResponse {
    pub success: bool,
    pub inquiry_id: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct TierResponse {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub monthly_price: Option<f64>,
    pub yearly_price: Option<f64>,
    pub max_users: i32,
    pub max_scans_per_day: i32,
    pub max_assets: i32,
    pub features: serde_json::Value,
}

// ============================================================================
// Endpoint Handlers
// ============================================================================

/// Get all available subscription tiers
pub async fn get_tiers(pool: web::Data<SqlitePool>) -> ActixResult<HttpResponse, ApiError> {
    let tiers = tiers::get_all_tiers(pool.get_ref()).await?;

    let response: Vec<TierResponse> = tiers
        .into_iter()
        .map(|t| TierResponse {
            id: t.id,
            name: t.name,
            display_name: t.display_name,
            description: t.description,
            monthly_price: t.monthly_price_cents.map(|c| c as f64 / 100.0),
            yearly_price: t.yearly_price_cents.map(|c| c as f64 / 100.0),
            max_users: t.max_users,
            max_scans_per_day: t.max_scans_per_day,
            max_assets: t.max_assets,
            features: serde_json::to_value(&t.feature_flags).unwrap_or_default(),
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Initialize registration - checks email, creates verification, redirects to Stripe
pub async fn init_registration(
    pool: web::Data<SqlitePool>,
    req: web::Json<InitRegistrationRequest>,
) -> ActixResult<HttpResponse, ApiError> {
    // Validate email format
    if !req.email.contains('@') {
        return Err(ApiError::bad_request("Invalid email format".to_string()));
    }

    // Check if email is already registered
    if VerificationService::is_email_registered(pool.get_ref(), &req.email).await? {
        return Err(ApiError::bad_request(
            "An account with this email already exists".to_string(),
        ));
    }

    // Get tier info
    let tier_id = format!("tier_{}", req.tier);
    let tier = tiers::get_tier_by_id(pool.get_ref(), &tier_id)
        .await?
        .ok_or_else(|| ApiError::bad_request(format!("Invalid tier: {}", req.tier)))?;

    // Enterprise tier goes to contact sales
    if tier.name == "enterprise" {
        return Err(ApiError::bad_request(
            "Enterprise tier requires contacting sales".to_string(),
        ));
    }

    // Create email verification record
    let verification = VerificationService::create_verification(
        pool.get_ref(),
        &req.email,
        &tier_id,
        &req.billing_cycle,
    )
    .await?;

    // Create Stripe checkout session if Stripe is configured
    let checkout_url = if StripeClient::is_configured() {
        let stripe = StripeClient::from_env()?;

        // Get the appropriate price ID
        let price_id = if req.billing_cycle == "yearly" {
            tier.stripe_yearly_price_id.as_ref()
        } else {
            tier.stripe_monthly_price_id.as_ref()
        };

        if let Some(price_id) = price_id {
            let base_url =
                std::env::var("APP_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

            let success_url = format!(
                "{}/register/verify?token={}&session_id={{CHECKOUT_SESSION_ID}}",
                base_url, verification.token
            );
            let cancel_url = format!("{}/register?canceled=true", base_url);

            let mut metadata = HashMap::new();
            metadata.insert("verification_id".to_string(), verification.id.clone());
            metadata.insert("tier".to_string(), tier.name.clone());

            let session = stripe
                .create_checkout_session(
                    price_id,
                    &req.email,
                    &success_url,
                    &cancel_url,
                    Some(metadata),
                )
                .await?;

            // Update verification with Stripe session ID
            VerificationService::update_stripe_session(
                pool.get_ref(),
                &verification.id,
                &session.id,
            )
            .await?;

            session.url
        } else {
            None
        }
    } else {
        // Stripe not configured - will handle email/auto-verify below
        None
    };

    // If no checkout URL, either send verification email or auto-verify
    let (message, token, auto_verified) = if checkout_url.is_some() {
        ("Please complete payment to continue registration".to_string(), None, None)
    } else if !EmailService::is_configured() {
        // SMTP not configured - auto-verify the email for immediate registration
        log::info!("SMTP not configured - auto-verifying email for {}", req.email);
        VerificationService::mark_email_verified(pool.get_ref(), &verification.id).await?;

        // For free tier, also mark payment as verified (no payment needed)
        if tier.monthly_price_cents.is_none() {
            VerificationService::mark_payment_verified(pool.get_ref(), &verification.id, "").await?;
        }

        (
            "Email auto-verified. Please complete your account setup.".to_string(),
            Some(verification.token.clone()),
            Some(true),
        )
    } else {
        // SMTP configured - send verification email
        send_verification_email(&req.email, &verification.token).await?;
        ("Please check your email to verify your account".to_string(), None, None)
    };

    Ok(HttpResponse::Ok().json(InitRegistrationResponse {
        verification_id: verification.id,
        checkout_url,
        message,
        token,
        auto_verified,
    }))
}

/// Verify email token and check payment status
pub async fn verify_email(
    pool: web::Data<SqlitePool>,
    req: web::Json<VerifyEmailRequest>,
) -> ActixResult<HttpResponse, ApiError> {
    let verification = VerificationService::get_by_token(pool.get_ref(), &req.token)
        .await?
        .ok_or_else(|| ApiError::bad_request("Invalid or expired verification token".to_string()))?;

    // Check if token is expired
    if !VerificationService::is_valid(&verification) {
        return Err(ApiError::bad_request(
            "Verification token has expired".to_string(),
        ));
    }

    // Mark email as verified
    VerificationService::mark_email_verified(pool.get_ref(), &verification.id).await?;

    // Get tier info
    let tier = tiers::get_tier_by_id(pool.get_ref(), &verification.tier_id)
        .await?
        .ok_or_else(|| ApiError::internal("Tier not found".to_string()))?;

    // Check if payment is required and verified
    let payment_required = tier.monthly_price_cents.is_some();
    let payment_verified = verification.payment_verified_at.is_some();

    Ok(HttpResponse::Ok().json(VerifyEmailResponse {
        verified: true,
        email: verification.email,
        tier: tier.name,
        payment_required,
        payment_verified,
    }))
}

/// Complete registration after verification and payment
pub async fn complete_registration(
    pool: web::Data<SqlitePool>,
    req: web::Json<CompleteRegistrationRequest>,
) -> ActixResult<HttpResponse, ApiError> {
    // Validate terms acceptance
    if !req.accept_terms {
        return Err(ApiError::bad_request(
            "You must accept the terms of service".to_string(),
        ));
    }

    // Validate password strength
    if req.password.len() < 8 {
        return Err(ApiError::bad_request(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    // Get verification record
    let verification = VerificationService::get_by_token(pool.get_ref(), &req.token)
        .await?
        .ok_or_else(|| ApiError::bad_request("Invalid or expired verification token".to_string()))?;

    // Ensure email is verified
    if verification.verified_at.is_none() {
        return Err(ApiError::bad_request("Email not verified".to_string()));
    }

    // Get tier info
    let tier = tiers::get_tier_by_id(pool.get_ref(), &verification.tier_id)
        .await?
        .ok_or_else(|| ApiError::internal("Tier not found".to_string()))?;

    // Check payment if required
    if tier.monthly_price_cents.is_some() && verification.payment_verified_at.is_none() {
        return Err(ApiError::bad_request("Payment not verified".to_string()));
    }

    // Check if username is available
    if let Ok(Some(_)) = db::get_user_by_username(pool.get_ref(), &req.username).await {
        return Err(ApiError::bad_request("Username already taken".to_string()));
    }

    // Hash password
    let password_hash = bcrypt::hash(&req.password, bcrypt::DEFAULT_COST)
        .map_err(|e| ApiError::internal(format!("Password hash failed: {}", e)))?;

    // Create the user
    let user_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, email_verified_at, subscription_tier_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&user_id)
    .bind(&req.username)
    .bind(&verification.email)
    .bind(&password_hash)
    .bind(&now)
    .bind(&verification.tier_id)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create user: {}", e)))?;

    // Assign tier-specific role
    let role_name = get_role_for_tier(&tier.name);
    let role_id: Option<String> = sqlx::query_scalar(
        "SELECT id FROM roles WHERE name = ?"
    )
    .bind(role_name)
    .fetch_optional(pool.get_ref())
    .await
    .ok()
    .flatten();

    if let Some(role_id) = role_id {
        let _ = db::assign_role_to_user(pool.get_ref(), &user_id, &role_id, "system").await;
    }

    // Create user subscription record
    if let Some(customer_id) = &verification.stripe_customer_id {
        let subscription_id = uuid::Uuid::new_v4().to_string();
        let _ = sqlx::query(
            r#"
            INSERT INTO user_subscriptions (
                id, user_id, tier_id, stripe_customer_id, status, billing_cycle, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
            "#,
        )
        .bind(&subscription_id)
        .bind(&user_id)
        .bind(&verification.tier_id)
        .bind(customer_id)
        .bind(&verification.billing_cycle)
        .bind(&now)
        .bind(&now)
        .execute(pool.get_ref())
        .await;
    }

    // Create organization with tier quotas
    create_organization_for_user(pool.get_ref(), &user_id, &tier).await?;

    // Clean up verification record
    VerificationService::delete_verification(pool.get_ref(), &verification.id).await?;

    // Generate JWT token
    let token = create_jwt(&user_id, &req.username, vec![role_name.to_string()])
        .map_err(|e| ApiError::internal(format!("Failed to create token: {}", e)))?;

    Ok(HttpResponse::Ok().json(CompleteRegistrationResponse {
        success: true,
        user_id,
        token,
        message: "Registration complete! Welcome to HeroForge.".to_string(),
    }))
}

/// Check if an email is available
pub async fn check_email(
    pool: web::Data<SqlitePool>,
    req: web::Json<CheckEmailRequest>,
) -> ActixResult<HttpResponse, ApiError> {
    let is_registered = VerificationService::is_email_registered(pool.get_ref(), &req.email).await?;

    Ok(HttpResponse::Ok().json(CheckEmailResponse {
        available: !is_registered,
        message: if is_registered {
            "This email is already registered".to_string()
        } else {
            "Email is available".to_string()
        },
    }))
}

/// Create a Stripe checkout session directly
pub async fn create_checkout(
    pool: web::Data<SqlitePool>,
    req: web::Json<CreateCheckoutRequest>,
) -> ActixResult<HttpResponse, ApiError> {
    if !StripeClient::is_configured() {
        return Err(ApiError::internal(
            "Stripe is not configured".to_string(),
        ));
    }

    let tier_id = format!("tier_{}", req.tier);
    let tier = tiers::get_tier_by_id(pool.get_ref(), &tier_id)
        .await?
        .ok_or_else(|| ApiError::bad_request(format!("Invalid tier: {}", req.tier)))?;

    let price_id = if req.billing_cycle == "yearly" {
        tier.stripe_yearly_price_id
    } else {
        tier.stripe_monthly_price_id
    };

    let price_id = price_id.ok_or_else(|| {
        ApiError::internal("Stripe price ID not configured for this tier".to_string())
    })?;

    let stripe = StripeClient::from_env()?;
    let session = stripe
        .create_checkout_session(&price_id, &req.email, &req.success_url, &req.cancel_url, None)
        .await?;

    let checkout_url = session
        .url
        .ok_or_else(|| ApiError::internal("No checkout URL in response".to_string()))?;

    Ok(HttpResponse::Ok().json(CreateCheckoutResponse {
        checkout_url,
        session_id: session.id,
    }))
}

/// Submit enterprise inquiry
pub async fn submit_enterprise_inquiry(
    pool: web::Data<SqlitePool>,
    req: web::Json<EnterpriseInquiryRequest>,
) -> ActixResult<HttpResponse, ApiError> {
    // Validate required fields
    if req.email.is_empty() || req.company_name.is_empty() || req.contact_name.is_empty() {
        return Err(ApiError::bad_request(
            "Email, company name, and contact name are required".to_string(),
        ));
    }

    let inquiry = verification::create_enterprise_inquiry(
        pool.get_ref(),
        &req.email,
        &req.company_name,
        &req.contact_name,
        req.phone.as_deref(),
        req.job_title.as_deref(),
        req.company_size.as_deref(),
        req.message.as_deref(),
    )
    .await?;

    // Send notification email to sales team (non-blocking, log errors but don't fail request)
    if EmailService::is_configured() {
        if let Ok(config) = EmailConfig::from_env() {
            let email_service = EmailService::new(config);
            let email_inquiry = EnterpriseInquiry {
                inquiry_id: inquiry.id.clone(),
                email: req.email.clone(),
                company_name: req.company_name.clone(),
                contact_name: req.contact_name.clone(),
                phone: req.phone.clone(),
                job_title: req.job_title.clone(),
                company_size: req.company_size.clone(),
                message: req.message.clone(),
            };

            // Spawn async task to send email without blocking the response
            tokio::spawn(async move {
                if let Err(e) = email_service
                    .send_enterprise_inquiry_notification(&email_inquiry)
                    .await
                {
                    log::error!("Failed to send sales team notification email: {}", e);
                } else {
                    log::info!(
                        "Sales team notification sent for inquiry {}",
                        email_inquiry.inquiry_id
                    );
                }
            });
        }
    } else {
        log::warn!("Email not configured - sales team notification not sent for inquiry {}", inquiry.id);
    }

    Ok(HttpResponse::Ok().json(EnterpriseInquiryResponse {
        success: true,
        inquiry_id: inquiry.id,
        message: "Thank you for your interest! Our sales team will contact you shortly."
            .to_string(),
    }))
}

/// Handle Stripe webhook events
pub async fn handle_stripe_webhook(
    pool: web::Data<SqlitePool>,
    body: web::Bytes,
    req: actix_web::HttpRequest,
) -> ActixResult<HttpResponse, ApiError> {
    if !StripeClient::is_configured() {
        return Err(ApiError::internal(
            "Stripe is not configured".to_string(),
        ));
    }

    let stripe = StripeClient::from_env()?;

    // Get signature from header
    let signature = req
        .headers()
        .get("Stripe-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::bad_request("Missing Stripe signature".to_string()))?;

    // Parse and verify webhook
    let payload = std::str::from_utf8(&body)
        .map_err(|_| ApiError::bad_request("Invalid payload".to_string()))?;

    let event = stripe
        .verify_webhook(payload, signature)
        .map_err(|e| ApiError::bad_request(format!("Invalid webhook: {}", e)))?;

    // Handle specific event types
    match event.event_type.as_str() {
        "checkout.session.completed" => {
            handle_checkout_completed(pool.get_ref(), &event.data.object).await?;
        }
        "customer.subscription.updated" => {
            // Handle subscription updates (upgrade/downgrade)
            log::info!("Subscription updated: {:?}", event.data.object);
        }
        "customer.subscription.deleted" => {
            // Handle subscription cancellation
            log::info!("Subscription deleted: {:?}", event.data.object);
        }
        _ => {
            log::debug!("Unhandled webhook event type: {}", event.event_type);
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"received": true})))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Send verification email
async fn send_verification_email(email: &str, token: &str) -> Result<(), ApiError> {
    let base_url =
        std::env::var("APP_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    let verify_url = format!("{}/register/verify?token={}", base_url, token);

    // Try to send email if SMTP is configured
    match EmailConfig::from_env() {
        Ok(config) => {
            let subject = "Verify your HeroForge account";
            let body = format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #4F46E5; color: white; padding: 20px; text-align: center; }}
        .content {{ background-color: #f9fafb; padding: 20px; }}
        .button {{ display: inline-block; background-color: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 20px 0; }}
        .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to HeroForge!</h1>
        </div>
        <div class="content">
            <p>Please click the button below to verify your email address:</p>
            <p style="text-align: center;">
                <a href="{}" class="button">Verify Email</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #4F46E5;">{}</p>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't create an account, you can safely ignore this email.</p>
        </div>
        <div class="footer">
            <p>&copy; HeroForge Security Platform</p>
        </div>
    </div>
</body>
</html>"#,
                verify_url, verify_url
            );

            // Use lettre to send the email directly
            use lettre::{Message, SmtpTransport, Transport};
            use lettre::transport::smtp::authentication::Credentials;
            use lettre::message::header::ContentType;

            let from_address = format!("{} <{}>", config.from_name, config.from_address);
            let email_msg = Message::builder()
                .from(from_address.parse().map_err(|e| {
                    ApiError::internal(format!("Invalid from address: {}", e))
                })?)
                .to(email.parse().map_err(|e| {
                    ApiError::internal(format!("Invalid email address: {}", e))
                })?)
                .subject(subject)
                .header(ContentType::TEXT_HTML)
                .body(body)
                .map_err(|e| ApiError::internal(format!("Failed to build email: {}", e)))?;

            let creds = Credentials::new(
                config.smtp_user.clone(),
                config.smtp_password.clone(),
            );

            let mailer = SmtpTransport::relay(&config.smtp_host)
                .map_err(|e| ApiError::internal(format!("SMTP relay error: {}", e)))?
                .port(config.smtp_port)
                .credentials(creds)
                .build();

            mailer.send(&email_msg)
                .map_err(|e| ApiError::internal(format!("Failed to send email: {}", e)))?;

            log::info!("Verification email sent to {}", email);
        }
        Err(_) => {
            // SMTP not configured - log the verification URL instead
            log::warn!(
                "SMTP not configured. Verification URL for {}: {}",
                email,
                verify_url
            );
        }
    }

    Ok(())
}

/// Handle checkout.session.completed webhook
async fn handle_checkout_completed(
    pool: &SqlitePool,
    session_data: &serde_json::Value,
) -> Result<(), ApiError> {
    let session_id = session_data
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::internal("Missing session ID".to_string()))?;

    let customer_id = session_data
        .get("customer")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Find verification by Stripe session ID
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM email_verifications WHERE stripe_session_id = ?",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if let Some((verification_id,)) = row {
        // Mark payment as verified
        VerificationService::mark_payment_verified(pool, &verification_id, customer_id).await?;
        log::info!(
            "Payment verified for verification ID: {}",
            verification_id
        );
    }

    Ok(())
}

/// Create an organization for the new user with tier-based quotas
async fn create_organization_for_user(
    pool: &SqlitePool,
    user_id: &str,
    tier: &tiers::SubscriptionTier,
) -> Result<(), ApiError> {
    let org_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    // Generate a unique slug from the org_id
    let slug = format!("org-{}", &org_id[..8]);

    // Create organization
    sqlx::query(
        r#"
        INSERT INTO organizations (id, name, slug, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(&org_id)
    .bind(format!("{}'s Organization", user_id))
    .bind(&slug)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create organization: {}", e)))?;

    // Associate user with organization
    sqlx::query("UPDATE users SET organization_id = ? WHERE id = ?")
        .bind(&org_id)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to update user: {}", e)))?;

    // Create organization quotas based on tier
    let quota_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO organization_quotas (
            id, organization_id, max_users, max_scans_per_day, max_concurrent_scans,
            max_assets, max_reports_per_month, max_storage_mb, max_api_requests_per_hour,
            max_scheduled_scans, max_teams, max_departments, max_custom_roles,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&quota_id)
    .bind(&org_id)
    .bind(tier.max_users)
    .bind(tier.max_scans_per_day)
    .bind(if tier.max_users > 1 { 3 } else { 1 }) // concurrent scans
    .bind(tier.max_assets)
    .bind(tier.max_reports_per_month)
    .bind(1024 * tier.max_users) // storage based on users
    .bind(100 * tier.max_users)  // API requests based on users
    .bind(tier.max_scans_per_day / 2) // scheduled scans
    .bind(if tier.feature_flags.team_management { 5 } else { 1 })
    .bind(if tier.feature_flags.team_management { 3 } else { 1 })
    .bind(if tier.feature_flags.team_management { 5 } else { 0 })
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create quotas: {}", e)))?;

    Ok(())
}
