//! License management for HeroForge self-hosted installations.
//!
//! License key format: HF-XXXX-XXXX-XXXX-XXXX
//! - Prefix: HF (HeroForge)
//! - Encoded data: tier, expiry, customer ID
//! - HMAC signature for validation

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, NaiveDate, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

/// Secret key for signing licenses (should be kept secure)
/// In production, this would be stored securely and not in code
const LICENSE_SIGNING_KEY: &[u8] = b"heroforge-license-signing-key-2026-v1";

/// License tiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    /// Free tier - limited features
    Free,
    /// Professional tier - full features, limited assets
    Pro,
    /// Enterprise tier - unlimited everything
    Enterprise,
    /// Trial tier - full features, time limited
    Trial,
}

impl fmt::Display for LicenseTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LicenseTier::Free => write!(f, "Free"),
            LicenseTier::Pro => write!(f, "Professional"),
            LicenseTier::Enterprise => write!(f, "Enterprise"),
            LicenseTier::Trial => write!(f, "Trial"),
        }
    }
}

impl LicenseTier {
    fn to_code(&self) -> u8 {
        match self {
            LicenseTier::Free => 0,
            LicenseTier::Trial => 1,
            LicenseTier::Pro => 2,
            LicenseTier::Enterprise => 3,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(LicenseTier::Free),
            1 => Some(LicenseTier::Trial),
            2 => Some(LicenseTier::Pro),
            3 => Some(LicenseTier::Enterprise),
            _ => None,
        }
    }

    /// Maximum number of assets allowed for this tier
    pub fn max_assets(&self) -> Option<u32> {
        match self {
            LicenseTier::Free => Some(25),
            LicenseTier::Trial => Some(100),
            LicenseTier::Pro => Some(500),
            LicenseTier::Enterprise => None, // Unlimited
        }
    }

    /// Maximum number of users allowed for this tier
    pub fn max_users(&self) -> Option<u32> {
        match self {
            LicenseTier::Free => Some(2),
            LicenseTier::Trial => Some(5),
            LicenseTier::Pro => Some(25),
            LicenseTier::Enterprise => None, // Unlimited
        }
    }

    /// Whether this tier includes AI features
    pub fn has_ai_features(&self) -> bool {
        matches!(self, LicenseTier::Pro | LicenseTier::Enterprise | LicenseTier::Trial)
    }

    /// Whether this tier includes cloud scanning
    pub fn has_cloud_scanning(&self) -> bool {
        matches!(self, LicenseTier::Pro | LicenseTier::Enterprise | LicenseTier::Trial)
    }

    /// Whether this tier includes SSO
    pub fn has_sso(&self) -> bool {
        matches!(self, LicenseTier::Enterprise)
    }

    /// Whether this tier includes API access
    pub fn has_api_access(&self) -> bool {
        matches!(self, LicenseTier::Pro | LicenseTier::Enterprise | LicenseTier::Trial)
    }
}

/// License information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    /// License key (HF-XXXX-XXXX-XXXX-XXXX format)
    pub key: String,
    /// License tier
    pub tier: LicenseTier,
    /// Customer ID (for tracking)
    pub customer_id: u32,
    /// Expiration date (None = never expires)
    pub expires_at: Option<DateTime<Utc>>,
    /// Customer email (for display)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_email: Option<String>,
    /// Customer name/organization
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_name: Option<String>,
}

impl License {
    /// Check if the license is valid (not expired)
    pub fn is_valid(&self) -> bool {
        match self.expires_at {
            Some(expires) => Utc::now() < expires,
            None => true, // No expiration
        }
    }

    /// Check if the license is expired
    pub fn is_expired(&self) -> bool {
        !self.is_valid()
    }

    /// Days until expiration (None if never expires)
    pub fn days_until_expiry(&self) -> Option<i64> {
        self.expires_at.map(|expires| {
            (expires - Utc::now()).num_days()
        })
    }
}

/// License generation request
#[derive(Debug, Deserialize)]
pub struct CreateLicenseRequest {
    pub tier: LicenseTier,
    pub customer_id: u32,
    /// Number of days until expiration (None = never expires)
    pub validity_days: Option<u32>,
    pub customer_email: Option<String>,
    pub customer_name: Option<String>,
}

/// License generation response
#[derive(Debug, Serialize)]
pub struct CreateLicenseResponse {
    pub license_key: String,
    pub tier: LicenseTier,
    pub expires_at: Option<DateTime<Utc>>,
    pub customer_id: u32,
}

/// Generate a new license key
pub fn generate_license(request: &CreateLicenseRequest) -> Result<CreateLicenseResponse> {
    let expires_at = request.validity_days.map(|days| {
        Utc::now() + chrono::Duration::days(days as i64)
    });

    // Encode license data
    // Format: tier(1) + customer_id(4) + expiry_days_from_epoch(2) + random(2)
    let mut data = Vec::with_capacity(9);

    // Tier (1 byte)
    data.push(request.tier.to_code());

    // Customer ID (4 bytes, big endian)
    data.extend_from_slice(&request.customer_id.to_be_bytes());

    // Expiry (2 bytes - days since 2024-01-01, or 0xFFFF for never)
    let expiry_days: u16 = match expires_at {
        Some(dt) => {
            let epoch = NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
            let days = (dt.date_naive() - epoch).num_days();
            if days > 0 && days < 65535 {
                days as u16
            } else {
                65535 // Cap at max
            }
        }
        None => 0xFFFF, // Never expires
    };
    data.extend_from_slice(&expiry_days.to_be_bytes());

    // Random bytes for uniqueness (2 bytes)
    let random_bytes: [u8; 2] = rand::random();
    data.extend_from_slice(&random_bytes);

    // Calculate HMAC signature
    let mut mac = HmacSha256::new_from_slice(LICENSE_SIGNING_KEY)
        .map_err(|e| anyhow!("HMAC error: {}", e))?;
    mac.update(&data);
    let signature = mac.finalize().into_bytes();

    // Append first 3 bytes of signature (9 + 3 = 12 bytes = 16 base64 chars)
    data.extend_from_slice(&signature[..3]);

    // Encode as base64 and format as license key
    let encoded = URL_SAFE_NO_PAD.encode(&data);

    // Format: HF-XXXX-XXXX-XXXX-XXXX (16 chars of encoded data)
    let license_key = format!(
        "HF-{}-{}-{}-{}",
        &encoded[0..4],
        &encoded[4..8],
        &encoded[8..12],
        &encoded[12..16]
    );

    Ok(CreateLicenseResponse {
        license_key,
        tier: request.tier,
        expires_at,
        customer_id: request.customer_id,
    })
}

/// Validate a license key and return license information
pub fn validate_license(license_key: &str) -> Result<License> {
    // Check format
    if !license_key.starts_with("HF-") {
        return Err(anyhow!("Invalid license key format: must start with HF-"));
    }

    // Remove prefix and dashes
    let encoded: String = license_key
        .strip_prefix("HF-")
        .ok_or_else(|| anyhow!("Invalid license key format"))?
        .replace('-', "");

    if encoded.len() < 16 {
        return Err(anyhow!("Invalid license key: too short"));
    }

    // Decode base64
    let data = URL_SAFE_NO_PAD
        .decode(&encoded)
        .map_err(|_| anyhow!("Invalid license key: decode error"))?;

    if data.len() < 12 {
        return Err(anyhow!("Invalid license key: invalid data length"));
    }

    // Extract components
    let tier_code = data[0];
    let customer_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    let expiry_days = u16::from_be_bytes([data[5], data[6]]);
    // Random bytes at [7], [8]
    let provided_signature = &data[9..12];

    // Verify HMAC signature
    let payload = &data[..9];
    let mut mac = HmacSha256::new_from_slice(LICENSE_SIGNING_KEY)
        .map_err(|e| anyhow!("HMAC error: {}", e))?;
    mac.update(payload);
    let expected_signature = mac.finalize().into_bytes();

    if provided_signature != &expected_signature[..3] {
        return Err(anyhow!("Invalid license key: signature verification failed"));
    }

    // Parse tier
    let tier = LicenseTier::from_code(tier_code)
        .ok_or_else(|| anyhow!("Invalid license key: unknown tier"))?;

    // Parse expiry
    let expires_at = if expiry_days == 0xFFFF {
        None // Never expires
    } else {
        let epoch = NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
        let expiry_date = epoch + chrono::Duration::days(expiry_days as i64);
        Some(DateTime::from_naive_utc_and_offset(
            expiry_date.and_hms_opt(23, 59, 59).unwrap(),
            Utc,
        ))
    };

    Ok(License {
        key: license_key.to_string(),
        tier,
        customer_id,
        expires_at,
        customer_email: None,
        customer_name: None,
    })
}

/// Check if a license key is valid (convenience function)
pub fn is_valid_license(license_key: &str) -> bool {
    validate_license(license_key)
        .map(|license| license.is_valid())
        .unwrap_or(false)
}

/// Global license state for the application
use once_cell::sync::OnceCell;
use std::sync::RwLock;

static CURRENT_LICENSE: OnceCell<RwLock<Option<License>>> = OnceCell::new();

/// Initialize the license system with a license key
pub fn init_license(license_key: Option<&str>) -> Result<Option<License>> {
    let license = match license_key {
        Some(key) if !key.is_empty() => {
            let license = validate_license(key)?;
            if license.is_expired() {
                return Err(anyhow!("License has expired"));
            }
            Some(license)
        }
        _ => None, // No license = free tier
    };

    let cell = CURRENT_LICENSE.get_or_init(|| RwLock::new(None));
    let mut guard = cell.write().unwrap();
    *guard = license.clone();

    Ok(license)
}

/// Get the current license
pub fn get_current_license() -> Option<License> {
    CURRENT_LICENSE
        .get()
        .and_then(|cell| cell.read().ok())
        .and_then(|guard| guard.clone())
}

/// Get the current license tier (defaults to Free if no license)
pub fn get_current_tier() -> LicenseTier {
    get_current_license()
        .map(|l| l.tier)
        .unwrap_or(LicenseTier::Free)
}

/// Check if a feature is available with the current license
pub fn has_feature(feature: &str) -> bool {
    let tier = get_current_tier();
    match feature {
        "ai" | "ai_features" | "zeus" => tier.has_ai_features(),
        "cloud" | "cloud_scanning" => tier.has_cloud_scanning(),
        "sso" | "saml" | "oauth" => tier.has_sso(),
        "api" | "api_access" => tier.has_api_access(),
        _ => true, // Unknown features are allowed by default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_validate_license() {
        let request = CreateLicenseRequest {
            tier: LicenseTier::Pro,
            customer_id: 12345,
            validity_days: Some(365),
            customer_email: Some("test@example.com".to_string()),
            customer_name: Some("Test Corp".to_string()),
        };

        let response = generate_license(&request).unwrap();
        assert!(response.license_key.starts_with("HF-"));

        let license = validate_license(&response.license_key).unwrap();
        assert_eq!(license.tier, LicenseTier::Pro);
        assert_eq!(license.customer_id, 12345);
        assert!(license.is_valid());
    }

    #[test]
    fn test_enterprise_never_expires() {
        let request = CreateLicenseRequest {
            tier: LicenseTier::Enterprise,
            customer_id: 99999,
            validity_days: None, // Never expires
            customer_email: None,
            customer_name: None,
        };

        let response = generate_license(&request).unwrap();
        let license = validate_license(&response.license_key).unwrap();

        assert_eq!(license.tier, LicenseTier::Enterprise);
        assert!(license.expires_at.is_none());
        assert!(license.is_valid());
    }

    #[test]
    fn test_invalid_license_key() {
        assert!(validate_license("invalid").is_err());
        assert!(validate_license("HF-XXXX-XXXX-XXXX-XXXX").is_err());
        assert!(validate_license("").is_err());
    }

    #[test]
    fn test_tier_limits() {
        assert_eq!(LicenseTier::Free.max_assets(), Some(25));
        assert_eq!(LicenseTier::Pro.max_assets(), Some(500));
        assert_eq!(LicenseTier::Enterprise.max_assets(), None);

        assert!(!LicenseTier::Free.has_ai_features());
        assert!(LicenseTier::Pro.has_ai_features());
        assert!(LicenseTier::Enterprise.has_ai_features());
    }
}
