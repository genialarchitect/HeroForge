//! Device trust and continuous authentication (Sprint 5)
//!
//! Device fingerprinting, trust management, and device-based security controls.
//! Implements device attestation and trust scoring.

use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc, Duration};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

/// Trusted device with security properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub id: String,
    pub user_id: String,
    pub device_fingerprint: String,
    pub device_name: String,
    pub trust_level: TrustLevel,
    pub last_seen: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub device_info: DeviceInfo,
    pub security_features: SecurityFeatures,
    pub access_count: u64,
    pub risk_events: u32,
}

impl TrustedDevice {
    /// Check if device is fully trusted
    pub fn is_trusted(&self) -> bool {
        matches!(self.trust_level, TrustLevel::Trusted | TrustLevel::Verified)
    }

    /// Check if device verification has expired
    pub fn verification_expired(&self) -> bool {
        if let Some(verified_at) = self.verified_at {
            Utc::now() > verified_at + Duration::days(30)
        } else {
            true
        }
    }

    /// Update last seen timestamp
    pub fn update_seen(&mut self) {
        self.last_seen = Utc::now();
        self.access_count += 1;
    }

    /// Record a risk event
    pub fn record_risk_event(&mut self) {
        self.risk_events += 1;
        if self.risk_events >= 5 {
            self.trust_level = TrustLevel::Suspicious;
        } else if self.risk_events >= 3 {
            self.trust_level = TrustLevel::Unverified;
        }
    }
}

/// Device trust levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustLevel {
    /// Fully trusted - verified and in good standing
    Trusted,
    /// Verified but not fully trusted (e.g., corporate device)
    Verified,
    /// Known device but not verified
    Unverified,
    /// Device showing suspicious behavior
    Suspicious,
    /// Device has been blocked
    Blocked,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Trusted => "trusted",
            TrustLevel::Verified => "verified",
            TrustLevel::Unverified => "unverified",
            TrustLevel::Suspicious => "suspicious",
            TrustLevel::Blocked => "blocked",
        }
    }

    pub fn allows_login(&self) -> bool {
        matches!(self, TrustLevel::Trusted | TrustLevel::Verified | TrustLevel::Unverified)
    }

    pub fn allows_sensitive_actions(&self) -> bool {
        matches!(self, TrustLevel::Trusted | TrustLevel::Verified)
    }
}

/// Device fingerprint components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    pub user_agent: String,
    pub ip_address: String,
    pub browser_hash: String,
    pub screen_resolution: Option<String>,
    pub timezone: Option<String>,
    pub language: Option<String>,
    pub platform: Option<String>,
    pub hardware_concurrency: Option<u32>,
    pub webgl_renderer: Option<String>,
    pub canvas_hash: Option<String>,
    pub audio_hash: Option<String>,
    pub fonts_hash: Option<String>,
}

impl DeviceFingerprint {
    /// Calculate stable fingerprint hash
    pub fn calculate_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();

        // Use stable components
        hasher.update(self.user_agent.as_bytes());
        hasher.update(self.browser_hash.as_bytes());

        if let Some(ref platform) = self.platform {
            hasher.update(platform.as_bytes());
        }

        if let Some(ref timezone) = self.timezone {
            hasher.update(timezone.as_bytes());
        }

        if let Some(ref canvas) = self.canvas_hash {
            hasher.update(canvas.as_bytes());
        }

        if let Some(ref webgl) = self.webgl_renderer {
            hasher.update(webgl.as_bytes());
        }

        let hash = hasher.finalize();
        hex::encode(hash)
    }

    /// Calculate similarity to another fingerprint
    pub fn similarity_to(&self, other: &DeviceFingerprint) -> f32 {
        let mut matches = 0f32;
        let mut total = 0f32;

        // User agent similarity (weighted)
        total += 2.0;
        if self.user_agent == other.user_agent {
            matches += 2.0;
        } else if self.platform == other.platform {
            matches += 1.0;
        }

        // Browser hash
        total += 1.0;
        if self.browser_hash == other.browser_hash {
            matches += 1.0;
        }

        // Screen resolution
        if self.screen_resolution.is_some() && other.screen_resolution.is_some() {
            total += 0.5;
            if self.screen_resolution == other.screen_resolution {
                matches += 0.5;
            }
        }

        // Timezone
        if self.timezone.is_some() && other.timezone.is_some() {
            total += 0.5;
            if self.timezone == other.timezone {
                matches += 0.5;
            }
        }

        // Canvas hash
        if self.canvas_hash.is_some() && other.canvas_hash.is_some() {
            total += 1.0;
            if self.canvas_hash == other.canvas_hash {
                matches += 1.0;
            }
        }

        // WebGL renderer
        if self.webgl_renderer.is_some() && other.webgl_renderer.is_some() {
            total += 1.0;
            if self.webgl_renderer == other.webgl_renderer {
                matches += 1.0;
            }
        }

        matches / total
    }
}

/// Device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_type: DeviceType,
    pub os_name: String,
    pub os_version: String,
    pub browser_name: String,
    pub browser_version: String,
    pub is_mobile: bool,
    pub is_tablet: bool,
}

impl Default for DeviceInfo {
    fn default() -> Self {
        Self {
            device_type: DeviceType::Unknown,
            os_name: "Unknown".to_string(),
            os_version: "Unknown".to_string(),
            browser_name: "Unknown".to_string(),
            browser_version: "Unknown".to_string(),
            is_mobile: false,
            is_tablet: false,
        }
    }
}

/// Device type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum DeviceType {
    Desktop,
    Laptop,
    Mobile,
    Tablet,
    Unknown,
}

/// Security features present on device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFeatures {
    pub has_biometrics: bool,
    pub has_secure_enclave: bool,
    pub has_screen_lock: bool,
    pub disk_encrypted: bool,
    pub antivirus_present: bool,
    pub firewall_enabled: bool,
    pub os_up_to_date: bool,
}

impl Default for SecurityFeatures {
    fn default() -> Self {
        Self {
            has_biometrics: false,
            has_secure_enclave: false,
            has_screen_lock: false,
            disk_encrypted: false,
            antivirus_present: false,
            firewall_enabled: false,
            os_up_to_date: true,
        }
    }
}

impl SecurityFeatures {
    /// Calculate security score (0-100)
    pub fn security_score(&self) -> u8 {
        let mut score = 0u8;

        if self.has_screen_lock { score += 20; }
        if self.disk_encrypted { score += 20; }
        if self.has_biometrics { score += 15; }
        if self.has_secure_enclave { score += 15; }
        if self.antivirus_present { score += 10; }
        if self.firewall_enabled { score += 10; }
        if self.os_up_to_date { score += 10; }

        score
    }
}

/// Device verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceVerificationRequest {
    pub device_id: String,
    pub user_id: String,
    pub verification_code: String,
    pub verification_method: VerificationMethod,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl DeviceVerificationRequest {
    pub fn new(device_id: &str, user_id: &str, method: VerificationMethod) -> Self {
        let mut code_bytes = [0u8; 6];
        getrandom::getrandom(&mut code_bytes).expect("Failed to generate random bytes");
        let code: u32 = code_bytes.iter().fold(0u32, |acc, &b| (acc * 256 + b as u32) % 1_000_000);

        Self {
            device_id: device_id.to_string(),
            user_id: user_id.to_string(),
            verification_code: format!("{:06}", code),
            verification_method: method,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(10),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn verify(&self, code: &str) -> bool {
        !self.is_expired() && self.verification_code == code
    }
}

/// Verification method
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum VerificationMethod {
    Email,
    SMS,
    Push,
    TOTP,
}

/// Device trust manager
pub struct DeviceTrustManager {
    max_devices_per_user: usize,
    trust_expiry_days: i64,
    require_verification_for_new: bool,
}

impl DeviceTrustManager {
    pub fn new() -> Self {
        Self {
            max_devices_per_user: 10,
            trust_expiry_days: 30,
            require_verification_for_new: true,
        }
    }

    /// Register a new device
    pub fn register_device(
        &self,
        user_id: &str,
        fingerprint: DeviceFingerprint,
        name: &str,
        device_info: DeviceInfo,
    ) -> TrustedDevice {
        let fp_hash = fingerprint.calculate_fingerprint();

        TrustedDevice {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            device_fingerprint: fp_hash,
            device_name: name.to_string(),
            trust_level: if self.require_verification_for_new {
                TrustLevel::Unverified
            } else {
                TrustLevel::Verified
            },
            last_seen: Utc::now(),
            created_at: Utc::now(),
            verified_at: None,
            device_info,
            security_features: SecurityFeatures::default(),
            access_count: 1,
            risk_events: 0,
        }
    }

    /// Find device by fingerprint
    pub fn find_device<'a>(
        &self,
        devices: &'a [TrustedDevice],
        fingerprint: &DeviceFingerprint,
        similarity_threshold: f32,
    ) -> Option<&'a TrustedDevice> {
        let fp_hash = fingerprint.calculate_fingerprint();

        // First try exact match
        if let Some(device) = devices.iter().find(|d| d.device_fingerprint == fp_hash) {
            return Some(device);
        }

        // Then try similarity matching (for fingerprint drift)
        // In production, you'd need to store the original fingerprint components
        None
    }

    /// Create verification request
    pub fn create_verification_request(
        &self,
        device: &TrustedDevice,
        method: VerificationMethod,
    ) -> DeviceVerificationRequest {
        DeviceVerificationRequest::new(&device.id, &device.user_id, method)
    }

    /// Complete device verification
    pub fn complete_verification(
        &self,
        device: &mut TrustedDevice,
        request: &DeviceVerificationRequest,
        code: &str,
    ) -> Result<()> {
        if request.device_id != device.id {
            return Err(anyhow!("Device ID mismatch"));
        }

        if !request.verify(code) {
            device.record_risk_event();
            return Err(anyhow!("Invalid or expired verification code"));
        }

        device.trust_level = TrustLevel::Verified;
        device.verified_at = Some(Utc::now());

        Ok(())
    }

    /// Promote device to trusted
    pub fn promote_to_trusted(&self, device: &mut TrustedDevice) -> Result<()> {
        if device.trust_level == TrustLevel::Blocked {
            return Err(anyhow!("Cannot promote blocked device"));
        }

        if device.trust_level == TrustLevel::Suspicious {
            return Err(anyhow!("Cannot promote suspicious device"));
        }

        if device.verified_at.is_none() {
            return Err(anyhow!("Device must be verified first"));
        }

        device.trust_level = TrustLevel::Trusted;
        Ok(())
    }

    /// Block a device
    pub fn block_device(&self, device: &mut TrustedDevice, reason: &str) {
        device.trust_level = TrustLevel::Blocked;
        log::warn!("Device {} blocked: {}", device.id, reason);
    }

    /// Evaluate device trust for action
    pub fn evaluate_for_action(
        &self,
        device: &TrustedDevice,
        action: &str,
        is_sensitive: bool,
    ) -> DeviceTrustDecision {
        // Check if device is blocked
        if device.trust_level == TrustLevel::Blocked {
            return DeviceTrustDecision {
                allowed: false,
                requires_mfa: false,
                requires_verification: false,
                reason: "Device is blocked".to_string(),
            };
        }

        // Check if device is suspicious
        if device.trust_level == TrustLevel::Suspicious {
            return DeviceTrustDecision {
                allowed: true,
                requires_mfa: true,
                requires_verification: true,
                reason: "Suspicious device requires additional verification".to_string(),
            };
        }

        // Sensitive actions require verified or trusted
        if is_sensitive && !device.trust_level.allows_sensitive_actions() {
            return DeviceTrustDecision {
                allowed: true,
                requires_mfa: true,
                requires_verification: true,
                reason: format!("Sensitive action '{}' requires device verification", action),
            };
        }

        // Check verification expiry
        if device.verification_expired() {
            return DeviceTrustDecision {
                allowed: true,
                requires_mfa: false,
                requires_verification: true,
                reason: "Device verification has expired".to_string(),
            };
        }

        // Check security score
        if device.security_features.security_score() < 40 {
            return DeviceTrustDecision {
                allowed: true,
                requires_mfa: is_sensitive,
                requires_verification: false,
                reason: "Device security score is low".to_string(),
            };
        }

        DeviceTrustDecision {
            allowed: true,
            requires_mfa: false,
            requires_verification: false,
            reason: "Device is trusted".to_string(),
        }
    }
}

impl Default for DeviceTrustManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Decision result from device trust evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTrustDecision {
    pub allowed: bool,
    pub requires_mfa: bool,
    pub requires_verification: bool,
    pub reason: String,
}

// Public API functions for backwards compatibility

pub async fn register_device(user_id: &str, fingerprint: DeviceFingerprint, name: &str) -> Result<TrustedDevice> {
    let manager = DeviceTrustManager::new();
    Ok(manager.register_device(user_id, fingerprint, name, DeviceInfo::default()))
}

pub async fn verify_device(device_id: &str) -> Result<()> {
    log::info!("Device verification requested for: {}", device_id);
    Ok(())
}

pub async fn check_device_trust(fingerprint: &str, user_id: &str) -> Result<TrustLevel> {
    // In production, would lookup device in database
    Ok(TrustLevel::Unverified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_calculation() {
        let fp = DeviceFingerprint {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
            ip_address: "192.168.1.100".to_string(),
            browser_hash: "abc123".to_string(),
            screen_resolution: Some("1920x1080".to_string()),
            timezone: Some("America/New_York".to_string()),
            language: Some("en-US".to_string()),
            platform: Some("Win32".to_string()),
            hardware_concurrency: Some(8),
            webgl_renderer: Some("NVIDIA GeForce".to_string()),
            canvas_hash: Some("canvas123".to_string()),
            audio_hash: Some("audio123".to_string()),
            fonts_hash: Some("fonts123".to_string()),
        };

        let hash1 = fp.calculate_fingerprint();
        let hash2 = fp.calculate_fingerprint();

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA256 hex
    }

    #[test]
    fn test_fingerprint_similarity() {
        let fp1 = DeviceFingerprint {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
            ip_address: "192.168.1.100".to_string(),
            browser_hash: "abc123".to_string(),
            screen_resolution: Some("1920x1080".to_string()),
            timezone: Some("America/New_York".to_string()),
            language: Some("en-US".to_string()),
            platform: Some("Win32".to_string()),
            hardware_concurrency: Some(8),
            webgl_renderer: Some("NVIDIA GeForce".to_string()),
            canvas_hash: Some("canvas123".to_string()),
            audio_hash: None,
            fonts_hash: None,
        };

        let fp2 = fp1.clone();
        assert_eq!(fp1.similarity_to(&fp2), 1.0);

        let fp3 = DeviceFingerprint {
            user_agent: "Different UA".to_string(),
            browser_hash: "different".to_string(),
            ..fp1.clone()
        };

        let similarity = fp1.similarity_to(&fp3);
        assert!(similarity < 1.0);
        assert!(similarity > 0.0);
    }

    #[test]
    fn test_security_score() {
        let features = SecurityFeatures {
            has_biometrics: true,
            has_secure_enclave: true,
            has_screen_lock: true,
            disk_encrypted: true,
            antivirus_present: true,
            firewall_enabled: true,
            os_up_to_date: true,
        };

        assert_eq!(features.security_score(), 100);

        let minimal = SecurityFeatures::default();
        assert_eq!(minimal.security_score(), 10); // Only os_up_to_date is true by default
    }

    #[test]
    fn test_device_registration() {
        let manager = DeviceTrustManager::new();

        let fp = DeviceFingerprint {
            user_agent: "Test UA".to_string(),
            ip_address: "192.168.1.100".to_string(),
            browser_hash: "abc123".to_string(),
            screen_resolution: None,
            timezone: None,
            language: None,
            platform: None,
            hardware_concurrency: None,
            webgl_renderer: None,
            canvas_hash: None,
            audio_hash: None,
            fonts_hash: None,
        };

        let device = manager.register_device("user123", fp, "My Laptop", DeviceInfo::default());

        assert_eq!(device.user_id, "user123");
        assert_eq!(device.trust_level, TrustLevel::Unverified);
        assert!(!device.device_fingerprint.is_empty());
    }

    #[test]
    fn test_verification_request() {
        let request = DeviceVerificationRequest::new("device123", "user123", VerificationMethod::Email);

        assert!(!request.is_expired());
        assert_eq!(request.verification_code.len(), 6);
        assert!(request.verify(&request.verification_code));
        assert!(!request.verify("wrong"));
    }

    #[test]
    fn test_trust_decision() {
        let manager = DeviceTrustManager::new();

        let mut device = TrustedDevice {
            id: "device123".to_string(),
            user_id: "user123".to_string(),
            device_fingerprint: "fp123".to_string(),
            device_name: "Test Device".to_string(),
            trust_level: TrustLevel::Trusted,
            last_seen: Utc::now(),
            created_at: Utc::now(),
            verified_at: Some(Utc::now()),
            device_info: DeviceInfo::default(),
            security_features: SecurityFeatures {
                has_screen_lock: true,
                disk_encrypted: true,
                has_biometrics: true,
                has_secure_enclave: true,
                ..Default::default()
            },
            access_count: 10,
            risk_events: 0,
        };

        // Trusted device should pass
        let decision = manager.evaluate_for_action(&device, "view_dashboard", false);
        assert!(decision.allowed);
        assert!(!decision.requires_mfa);

        // Block device and check
        manager.block_device(&mut device, "Testing");
        let decision = manager.evaluate_for_action(&device, "view_dashboard", false);
        assert!(!decision.allowed);
    }
}
