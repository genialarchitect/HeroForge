//! Device trust and continuous authentication (Sprint 5)

use serde::{Serialize, Deserialize};
use anyhow::Result;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub id: String,
    pub user_id: String,
    pub device_fingerprint: String,
    pub device_name: String,
    pub trust_level: TrustLevel,
    pub last_seen: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TrustLevel {
    Trusted,
    Verified,
    Unverified,
    Suspicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    pub user_agent: String,
    pub ip_address: String,
    pub browser_hash: String,
}

impl DeviceFingerprint {
    pub fn calculate_fingerprint(&self) -> String {
        use sha2::{Sha256, Digest};
        let combined = format!("{}{}{}", self.user_agent, self.ip_address, self.browser_hash);
        let hash = Sha256::digest(combined.as_bytes());
        hex::encode(hash)
    }
}

pub async fn register_device(user_id: &str, fingerprint: DeviceFingerprint, name: &str) -> Result<TrustedDevice> {
    Ok(TrustedDevice {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        device_fingerprint: fingerprint.calculate_fingerprint(),
        device_name: name.to_string(),
        trust_level: TrustLevel::Unverified,
        last_seen: Utc::now(),
        created_at: Utc::now(),
    })
}

pub async fn verify_device(device_id: &str) -> Result<()> {
    // TODO: Implement device verification (e.g., email/SMS confirmation)
    Ok(())
}

pub async fn check_device_trust(fingerprint: &str, user_id: &str) -> Result<TrustLevel> {
    // TODO: Check if device is trusted
    Ok(TrustLevel::Unverified)
}
