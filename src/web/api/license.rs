//! License management API endpoints.
//!
//! Provides endpoints for viewing license status and feature availability.

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};

use crate::license::{self, LicenseTier};
use crate::web::auth;

/// License status response (safe to expose)
#[derive(Debug, Serialize)]
pub struct LicenseStatusResponse {
    /// Current license tier
    pub tier: String,
    /// Whether a valid license is active
    pub is_licensed: bool,
    /// Days until license expiration (None if never expires)
    pub days_until_expiry: Option<i64>,
    /// Maximum assets allowed (None = unlimited)
    pub max_assets: Option<u32>,
    /// Maximum users allowed (None = unlimited)
    pub max_users: Option<u32>,
    /// Features available with current license
    pub features: LicenseFeatures,
}

/// Feature availability based on license
#[derive(Debug, Serialize)]
pub struct LicenseFeatures {
    pub ai_features: bool,
    pub cloud_scanning: bool,
    pub sso: bool,
    pub api_access: bool,
    pub advanced_reporting: bool,
    pub compliance_frameworks: bool,
    pub multi_tenancy: bool,
    pub priority_support: bool,
}

impl LicenseFeatures {
    fn from_tier(tier: LicenseTier) -> Self {
        Self {
            ai_features: tier.has_ai_features(),
            cloud_scanning: tier.has_cloud_scanning(),
            sso: tier.has_sso(),
            api_access: tier.has_api_access(),
            advanced_reporting: matches!(tier, LicenseTier::Pro | LicenseTier::Enterprise | LicenseTier::Trial),
            compliance_frameworks: matches!(tier, LicenseTier::Pro | LicenseTier::Enterprise | LicenseTier::Trial),
            multi_tenancy: matches!(tier, LicenseTier::Enterprise),
            priority_support: matches!(tier, LicenseTier::Enterprise),
        }
    }
}

/// Get current license status
///
/// Returns the current license tier and feature availability.
/// This endpoint is protected but returns sanitized information.
pub async fn get_license_status(
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let tier = license::get_current_tier();
    let license = license::get_current_license();

    let response = LicenseStatusResponse {
        tier: tier.to_string(),
        is_licensed: license.is_some(),
        days_until_expiry: license.as_ref().and_then(|l| l.days_until_expiry()),
        max_assets: tier.max_assets(),
        max_users: tier.max_users(),
        features: LicenseFeatures::from_tier(tier),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Check if a specific feature is available
#[derive(Debug, Deserialize)]
pub struct FeatureCheckRequest {
    pub feature: String,
}

#[derive(Debug, Serialize)]
pub struct FeatureCheckResponse {
    pub feature: String,
    pub available: bool,
    pub tier_required: String,
}

/// Check feature availability
///
/// Checks if a specific feature is available with the current license.
pub async fn check_feature(
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<FeatureCheckRequest>,
) -> Result<HttpResponse> {
    let available = license::has_feature(&query.feature);

    // Determine minimum tier required for this feature
    let tier_required = match query.feature.as_str() {
        "ai" | "ai_features" | "zeus" => "Professional",
        "cloud" | "cloud_scanning" => "Professional",
        "sso" | "saml" | "oauth" => "Enterprise",
        "api" | "api_access" => "Professional",
        "multi_tenancy" => "Enterprise",
        _ => "Free",
    };

    let response = FeatureCheckResponse {
        feature: query.feature.clone(),
        available,
        tier_required: tier_required.to_string(),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// License validation request (admin only)
#[derive(Debug, Deserialize)]
pub struct ValidateLicenseRequest {
    pub license_key: String,
}

/// License validation response
#[derive(Debug, Serialize)]
pub struct ValidateLicenseResponse {
    pub valid: bool,
    pub tier: Option<String>,
    pub expires_at: Option<String>,
    pub days_until_expiry: Option<i64>,
    pub error: Option<String>,
}

/// Validate a license key (admin only)
///
/// Validates a license key and returns its details without activating it.
/// Requires admin role.
pub async fn validate_license(
    claims: web::ReqData<auth::Claims>,
    request: web::Json<ValidateLicenseRequest>,
) -> Result<HttpResponse> {
    // Check admin role
    if !claims.roles.contains(&"admin".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin access required"
        })));
    }

    match license::validate_license(&request.license_key) {
        Ok(lic) => {
            let response = ValidateLicenseResponse {
                valid: lic.is_valid(),
                tier: Some(lic.tier.to_string()),
                expires_at: lic.expires_at.map(|dt| dt.to_rfc3339()),
                days_until_expiry: lic.days_until_expiry(),
                error: if lic.is_expired() {
                    Some("License has expired".to_string())
                } else {
                    None
                },
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            let response = ValidateLicenseResponse {
                valid: false,
                tier: None,
                expires_at: None,
                days_until_expiry: None,
                error: Some(e.to_string()),
            };
            Ok(HttpResponse::Ok().json(response))
        }
    }
}

/// License tier comparison for upgrade prompts
#[derive(Debug, Serialize)]
pub struct TierComparisonResponse {
    pub tiers: Vec<TierInfo>,
}

#[derive(Debug, Serialize)]
pub struct TierInfo {
    pub name: String,
    pub display_name: String,
    pub max_assets: Option<u32>,
    pub max_users: Option<u32>,
    pub features: Vec<String>,
    pub is_current: bool,
}

/// Get tier comparison information
///
/// Returns information about all license tiers for upgrade prompts.
pub async fn get_tier_comparison(
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let current_tier = license::get_current_tier();

    let tiers = vec![
        TierInfo {
            name: "free".to_string(),
            display_name: "Free".to_string(),
            max_assets: Some(25),
            max_users: Some(2),
            features: vec![
                "Basic network scanning".to_string(),
                "Port and service detection".to_string(),
                "Basic reporting".to_string(),
                "Community support".to_string(),
            ],
            is_current: matches!(current_tier, LicenseTier::Free),
        },
        TierInfo {
            name: "pro".to_string(),
            display_name: "Professional".to_string(),
            max_assets: Some(500),
            max_users: Some(25),
            features: vec![
                "Everything in Free".to_string(),
                "AI-powered analysis (Zeus)".to_string(),
                "Cloud security scanning".to_string(),
                "API access".to_string(),
                "Advanced compliance frameworks".to_string(),
                "Scheduled scans".to_string(),
                "Email support".to_string(),
            ],
            is_current: matches!(current_tier, LicenseTier::Pro),
        },
        TierInfo {
            name: "enterprise".to_string(),
            display_name: "Enterprise".to_string(),
            max_assets: None,
            max_users: None,
            features: vec![
                "Everything in Professional".to_string(),
                "Unlimited assets and users".to_string(),
                "SSO integration (SAML, OIDC)".to_string(),
                "Multi-tenancy support".to_string(),
                "Custom integrations".to_string(),
                "Priority support with SLA".to_string(),
                "On-premise deployment support".to_string(),
            ],
            is_current: matches!(current_tier, LicenseTier::Enterprise),
        },
    ];

    Ok(HttpResponse::Ok().json(TierComparisonResponse { tiers }))
}

/// Configure license routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/license")
            .route("", web::get().to(get_license_status))
            .route("/status", web::get().to(get_license_status))
            .route("/feature", web::get().to(check_feature))
            .route("/validate", web::post().to(validate_license))
            .route("/tiers", web::get().to(get_tier_comparison))
    );
}
