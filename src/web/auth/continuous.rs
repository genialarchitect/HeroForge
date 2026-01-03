//! Continuous authentication monitoring (Sprint 5)
//!
//! Real-time session monitoring and risk-based authentication.
//! Implements behavioral analysis to detect anomalous activity.

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::net::IpAddr;
use sha2::{Sha256, Digest};

/// Active authentication session with monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub id: String,
    pub user_id: String,
    pub risk_score: f32,
    pub last_verification: DateTime<Utc>,
    pub anomalies_detected: u32,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub device_fingerprint: String,
    pub mfa_verified: bool,
    pub status: SessionStatus,
}

/// Session status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SessionStatus {
    Active,
    RequiresVerification,
    Suspicious,
    Locked,
    Expired,
}

/// User behavior pattern for baseline comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorPattern {
    pub user_id: String,
    pub typical_ip_ranges: Vec<String>,
    pub typical_hours: Vec<u8>,
    pub typical_actions: Vec<String>,
    pub typical_locations: Vec<String>,
    pub average_session_duration: i64,
    pub typical_request_rate: f32,
    pub known_devices: Vec<String>,
    pub last_updated: DateTime<Utc>,
}

impl BehaviorPattern {
    /// Create new behavior pattern for user
    pub fn new(user_id: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            typical_ip_ranges: Vec::new(),
            typical_hours: Vec::new(),
            typical_actions: Vec::new(),
            typical_locations: Vec::new(),
            average_session_duration: 3600, // 1 hour default
            typical_request_rate: 1.0,
            known_devices: Vec::new(),
            last_updated: Utc::now(),
        }
    }

    /// Update pattern with new activity
    pub fn update_from_activity(&mut self, activity: &UserActivity) {
        // Add IP range if not known
        if let Ok(ip) = activity.ip_address.parse::<IpAddr>() {
            let range = ip_to_range(&ip);
            if !self.typical_ip_ranges.contains(&range) && self.typical_ip_ranges.len() < 20 {
                self.typical_ip_ranges.push(range);
            }
        }

        // Add hour if not known
        let hour = activity.timestamp.hour() as u8;
        if !self.typical_hours.contains(&hour) {
            self.typical_hours.push(hour);
        }

        // Add action if not known
        if !self.typical_actions.contains(&activity.action) && self.typical_actions.len() < 50 {
            self.typical_actions.push(activity.action.clone());
        }

        // Add device if not known
        if !self.known_devices.contains(&activity.device_fingerprint) && self.known_devices.len() < 10 {
            self.known_devices.push(activity.device_fingerprint.clone());
        }

        self.last_updated = Utc::now();
    }
}

/// User activity record for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserActivity {
    pub session_id: String,
    pub user_id: String,
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub ip_address: String,
    pub user_agent: String,
    pub device_fingerprint: String,
    pub resource: Option<String>,
    pub success: bool,
    pub response_time_ms: Option<u64>,
}

/// Risk factors detected in session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_type: RiskFactorType,
    pub severity: f32,
    pub description: String,
    pub detected_at: DateTime<Utc>,
}

/// Types of risk factors
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum RiskFactorType {
    NewIpAddress,
    UnusualTime,
    UnusualLocation,
    NewDevice,
    RapidLocationChange,
    HighRequestRate,
    SensitiveActionAttempt,
    FailedAuthentications,
    SessionHijackingIndicator,
    BruteForceIndicator,
    PrivilegeEscalation,
}

impl RiskFactorType {
    pub fn base_severity(&self) -> f32 {
        match self {
            RiskFactorType::NewIpAddress => 0.2,
            RiskFactorType::UnusualTime => 0.15,
            RiskFactorType::UnusualLocation => 0.25,
            RiskFactorType::NewDevice => 0.3,
            RiskFactorType::RapidLocationChange => 0.6,
            RiskFactorType::HighRequestRate => 0.4,
            RiskFactorType::SensitiveActionAttempt => 0.35,
            RiskFactorType::FailedAuthentications => 0.5,
            RiskFactorType::SessionHijackingIndicator => 0.8,
            RiskFactorType::BruteForceIndicator => 0.7,
            RiskFactorType::PrivilegeEscalation => 0.9,
        }
    }
}

/// Session verification requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequirement {
    pub required: bool,
    pub reason: String,
    pub verification_type: VerificationType,
    pub expires_at: DateTime<Utc>,
}

/// Type of verification required
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum VerificationType {
    Password,
    MFA,
    Email,
    SMS,
    Biometric,
    SecurityQuestion,
}

/// Continuous authentication monitor
pub struct ContinuousAuthMonitor {
    risk_threshold_warning: f32,
    risk_threshold_lockout: f32,
    session_timeout_minutes: i64,
    max_anomalies_before_lock: u32,
}

impl ContinuousAuthMonitor {
    pub fn new() -> Self {
        Self {
            risk_threshold_warning: 0.5,
            risk_threshold_lockout: 0.8,
            session_timeout_minutes: 30,
            max_anomalies_before_lock: 5,
        }
    }

    pub fn with_thresholds(warning: f32, lockout: f32) -> Self {
        Self {
            risk_threshold_warning: warning,
            risk_threshold_lockout: lockout,
            session_timeout_minutes: 30,
            max_anomalies_before_lock: 5,
        }
    }

    /// Monitor session for suspicious activity
    pub fn monitor_session(&self, session: &mut AuthSession, activity: &UserActivity, pattern: &BehaviorPattern) -> Vec<RiskFactor> {
        let mut risk_factors = Vec::new();

        // Check for new IP address
        if let Ok(ip) = activity.ip_address.parse::<IpAddr>() {
            let range = ip_to_range(&ip);
            if !pattern.typical_ip_ranges.contains(&range) {
                risk_factors.push(RiskFactor {
                    factor_type: RiskFactorType::NewIpAddress,
                    severity: RiskFactorType::NewIpAddress.base_severity(),
                    description: format!("Access from new IP range: {}", range),
                    detected_at: Utc::now(),
                });
            }
        }

        // Check for unusual time
        let hour = activity.timestamp.hour() as u8;
        if !pattern.typical_hours.is_empty() && !pattern.typical_hours.contains(&hour) {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::UnusualTime,
                severity: RiskFactorType::UnusualTime.base_severity(),
                description: format!("Activity at unusual hour: {}", hour),
                detected_at: Utc::now(),
            });
        }

        // Check for new device
        if !pattern.known_devices.contains(&activity.device_fingerprint) {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::NewDevice,
                severity: RiskFactorType::NewDevice.base_severity(),
                description: "Access from unrecognized device".to_string(),
                detected_at: Utc::now(),
            });
        }

        // Check for IP change during session (potential session hijacking)
        if session.ip_address != activity.ip_address {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::SessionHijackingIndicator,
                severity: RiskFactorType::SessionHijackingIndicator.base_severity(),
                description: format!("IP address changed from {} to {}", session.ip_address, activity.ip_address),
                detected_at: Utc::now(),
            });
        }

        // Check for user agent change during session
        if session.user_agent != activity.user_agent {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::SessionHijackingIndicator,
                severity: 0.6,
                description: "User agent changed during session".to_string(),
                detected_at: Utc::now(),
            });
        }

        // Update session state
        session.anomalies_detected += risk_factors.len() as u32;
        session.last_activity = Utc::now();

        // Calculate new risk score
        let total_severity: f32 = risk_factors.iter().map(|r| r.severity).sum();
        session.risk_score = (session.risk_score + total_severity).min(1.0);

        // Update session status based on risk
        if session.risk_score >= self.risk_threshold_lockout || session.anomalies_detected >= self.max_anomalies_before_lock {
            session.status = SessionStatus::Locked;
        } else if session.risk_score >= self.risk_threshold_warning {
            session.status = SessionStatus::Suspicious;
        }

        risk_factors
    }

    /// Check if reauthentication is required
    pub fn check_reauthentication(&self, session: &AuthSession) -> Option<VerificationRequirement> {
        // Check session timeout
        let idle_duration = Utc::now() - session.last_activity;
        if idle_duration > Duration::minutes(self.session_timeout_minutes) {
            return Some(VerificationRequirement {
                required: true,
                reason: "Session timeout due to inactivity".to_string(),
                verification_type: VerificationType::Password,
                expires_at: Utc::now() + Duration::minutes(5),
            });
        }

        // Check risk score
        if session.risk_score >= self.risk_threshold_warning {
            let verification_type = if session.risk_score >= self.risk_threshold_lockout {
                VerificationType::MFA
            } else {
                VerificationType::Password
            };

            return Some(VerificationRequirement {
                required: true,
                reason: format!("Elevated risk score: {:.2}", session.risk_score),
                verification_type,
                expires_at: Utc::now() + Duration::minutes(5),
            });
        }

        // Check if MFA was never verified for this session
        if !session.mfa_verified {
            let since_last_verification = Utc::now() - session.last_verification;
            if since_last_verification > Duration::hours(4) {
                return Some(VerificationRequirement {
                    required: true,
                    reason: "Periodic MFA verification required".to_string(),
                    verification_type: VerificationType::MFA,
                    expires_at: Utc::now() + Duration::minutes(10),
                });
            }
        }

        None
    }

    /// Process reauthentication result
    pub fn process_reauthentication(&self, session: &mut AuthSession, success: bool, verification_type: VerificationType) {
        if success {
            session.last_verification = Utc::now();
            session.risk_score = (session.risk_score * 0.5).max(0.0); // Reduce risk score

            if verification_type == VerificationType::MFA {
                session.mfa_verified = true;
            }

            if session.status == SessionStatus::RequiresVerification || session.status == SessionStatus::Suspicious {
                session.status = SessionStatus::Active;
            }
        } else {
            session.risk_score = (session.risk_score + 0.3).min(1.0);
            session.anomalies_detected += 1;

            if session.anomalies_detected >= self.max_anomalies_before_lock {
                session.status = SessionStatus::Locked;
            }
        }
    }
}

impl Default for ContinuousAuthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate risk score for user activity
pub fn calculate_risk_score(activity: &UserActivity, pattern: &BehaviorPattern) -> f32 {
    let mut risk_score: f32 = 0.0;

    // Check IP address
    if let Ok(ip) = activity.ip_address.parse::<IpAddr>() {
        let range = ip_to_range(&ip);
        if !pattern.typical_ip_ranges.contains(&range) {
            risk_score += 0.2;
        }
    }

    // Check time of day
    let hour = activity.timestamp.hour() as u8;
    if !pattern.typical_hours.is_empty() && !pattern.typical_hours.contains(&hour) {
        risk_score += 0.15;
    }

    // Check device
    if !pattern.known_devices.contains(&activity.device_fingerprint) {
        risk_score += 0.3;
    }

    // Check action
    if !pattern.typical_actions.contains(&activity.action) {
        risk_score += 0.1;
    }

    risk_score.min(1.0)
}

// Helper functions

fn ip_to_range(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
        }
    }
}

// Public API functions for backwards compatibility

pub async fn monitor_session(session_id: &str) -> Result<AuthSession> {
    Ok(AuthSession {
        id: session_id.to_string(),
        user_id: String::new(),
        risk_score: 0.0,
        last_verification: Utc::now(),
        anomalies_detected: 0,
        created_at: Utc::now(),
        last_activity: Utc::now(),
        ip_address: "0.0.0.0".to_string(),
        user_agent: String::new(),
        device_fingerprint: String::new(),
        mfa_verified: false,
        status: SessionStatus::Active,
    })
}

pub async fn calculate_risk_score_legacy(user_id: &str, current_activity: &str) -> f32 {
    // Legacy wrapper - returns default low risk
    0.0
}

pub async fn require_reauthentication(session_id: &str) -> Result<()> {
    // In production, this would update the session in the database
    log::info!("Reauthentication required for session: {}", session_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_behavior_pattern() {
        let mut pattern = BehaviorPattern::new("user123");

        let activity = UserActivity {
            session_id: "session1".to_string(),
            user_id: "user123".to_string(),
            timestamp: Utc::now(),
            action: "login".to_string(),
            ip_address: "192.168.1.100".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            device_fingerprint: "device123".to_string(),
            resource: None,
            success: true,
            response_time_ms: Some(100),
        };

        pattern.update_from_activity(&activity);

        assert!(pattern.typical_ip_ranges.contains(&"192.168.1.0/24".to_string()));
        assert!(pattern.known_devices.contains(&"device123".to_string()));
    }

    #[test]
    fn test_risk_calculation() {
        let pattern = BehaviorPattern {
            user_id: "user123".to_string(),
            typical_ip_ranges: vec!["192.168.1.0/24".to_string()],
            typical_hours: vec![9, 10, 11, 12, 13, 14, 15, 16, 17],
            typical_actions: vec!["login".to_string(), "view_dashboard".to_string()],
            typical_locations: Vec::new(),
            average_session_duration: 3600,
            typical_request_rate: 1.0,
            known_devices: vec!["known_device".to_string()],
            last_updated: Utc::now(),
        };

        // Normal activity
        let normal_activity = UserActivity {
            session_id: "session1".to_string(),
            user_id: "user123".to_string(),
            timestamp: Utc::now(),
            action: "login".to_string(),
            ip_address: "192.168.1.50".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            device_fingerprint: "known_device".to_string(),
            resource: None,
            success: true,
            response_time_ms: Some(100),
        };

        let risk = calculate_risk_score(&normal_activity, &pattern);
        assert!(risk < 0.3);

        // Suspicious activity (new device, new IP)
        let suspicious_activity = UserActivity {
            session_id: "session1".to_string(),
            user_id: "user123".to_string(),
            timestamp: Utc::now(),
            action: "admin_action".to_string(),
            ip_address: "10.0.0.50".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            device_fingerprint: "unknown_device".to_string(),
            resource: None,
            success: true,
            response_time_ms: Some(100),
        };

        let risk = calculate_risk_score(&suspicious_activity, &pattern);
        assert!(risk > 0.4);
    }

    #[test]
    fn test_session_monitoring() {
        let monitor = ContinuousAuthMonitor::new();

        let mut session = AuthSession {
            id: "session123".to_string(),
            user_id: "user123".to_string(),
            risk_score: 0.0,
            last_verification: Utc::now(),
            anomalies_detected: 0,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            ip_address: "192.168.1.100".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            device_fingerprint: "device123".to_string(),
            mfa_verified: false,
            status: SessionStatus::Active,
        };

        let pattern = BehaviorPattern::new("user123");

        // Activity from different IP (potential session hijacking)
        let activity = UserActivity {
            session_id: "session123".to_string(),
            user_id: "user123".to_string(),
            timestamp: Utc::now(),
            action: "view_settings".to_string(),
            ip_address: "10.0.0.50".to_string(), // Different IP
            user_agent: "Mozilla/5.0".to_string(),
            device_fingerprint: "device123".to_string(),
            resource: None,
            success: true,
            response_time_ms: Some(100),
        };

        let risks = monitor.monitor_session(&mut session, &activity, &pattern);

        assert!(!risks.is_empty());
        assert!(session.risk_score > 0.0);
    }

    #[test]
    fn test_reauthentication_check() {
        let monitor = ContinuousAuthMonitor::new();

        // Session with high risk
        let high_risk_session = AuthSession {
            id: "session123".to_string(),
            user_id: "user123".to_string(),
            risk_score: 0.7,
            last_verification: Utc::now(),
            anomalies_detected: 3,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            ip_address: "192.168.1.100".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            device_fingerprint: "device123".to_string(),
            mfa_verified: false,
            status: SessionStatus::Suspicious,
        };

        let requirement = monitor.check_reauthentication(&high_risk_session);
        assert!(requirement.is_some());
        assert!(requirement.unwrap().required);
    }
}
