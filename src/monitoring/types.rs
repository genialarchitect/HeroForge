//! Types for the Continuous Monitoring Engine

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use chrono::{DateTime, Utc};

/// Simplified port info for monitoring (different from scanner's PortInfo)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringPortInfo {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

/// Configuration for the monitoring engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Target hosts to monitor
    pub targets: Vec<String>,
    /// Interval between lightweight scans (seconds)
    pub light_scan_interval_secs: u64,
    /// Interval between full scans (seconds)
    pub full_scan_interval_secs: u64,
    /// Number of top ports for lightweight scans
    pub light_scan_port_count: usize,
    /// Whether to send alerts
    pub alerting_enabled: bool,
    /// Alert destinations (email, webhook, etc.)
    pub alert_destinations: Vec<AlertDestination>,
    /// Which changes to alert on
    pub alert_on: AlertTriggers,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            light_scan_interval_secs: 5,
            full_scan_interval_secs: 4 * 60 * 60,
            light_scan_port_count: 100,
            alerting_enabled: true,
            alert_destinations: Vec::new(),
            alert_on: AlertTriggers::default(),
        }
    }
}

/// What changes should trigger alerts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertTriggers {
    pub new_port: bool,
    pub closed_port: bool,
    pub service_change: bool,
    pub new_vulnerability: bool,
    pub host_up: bool,
    pub host_down: bool,
    pub version_change: bool,
}

impl Default for AlertTriggers {
    fn default() -> Self {
        Self {
            new_port: true,
            closed_port: true,
            service_change: true,
            new_vulnerability: true,
            host_up: true,
            host_down: true,
            version_change: false,
        }
    }
}

/// Alert destination types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AlertDestination {
    Email { address: String },
    Webhook { url: String, secret: Option<String> },
    Slack { webhook_url: String, channel: Option<String> },
    Teams { webhook_url: String },
    Syslog { host: String, port: u16 },
}

/// Current state of monitoring for a target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetState {
    pub target: String,
    pub ip: Option<IpAddr>,
    pub is_up: bool,
    pub last_seen: Option<DateTime<Utc>>,
    pub open_ports: HashMap<u16, PortState>,
    pub last_full_scan: Option<DateTime<Utc>>,
    pub last_light_scan: Option<DateTime<Utc>>,
}

impl TargetState {
    pub fn new(target: String) -> Self {
        Self {
            target,
            ip: None,
            is_up: false,
            last_seen: None,
            open_ports: HashMap::new(),
            last_full_scan: None,
            last_light_scan: None,
        }
    }
}

/// State of a single port
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PortState {
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// A baseline snapshot for comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub targets: Vec<TargetState>,
    pub description: Option<String>,
}

/// Types of changes detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeType {
    NewPort,
    ClosedPort,
    ServiceChanged,
    VersionChanged,
    BannerChanged,
    HostUp,
    HostDown,
    NewVulnerability,
}

impl ChangeType {
    pub fn severity(&self) -> ChangeSeverity {
        match self {
            Self::NewPort => ChangeSeverity::High,
            Self::ClosedPort => ChangeSeverity::Medium,
            Self::ServiceChanged => ChangeSeverity::High,
            Self::VersionChanged => ChangeSeverity::Low,
            Self::BannerChanged => ChangeSeverity::Low,
            Self::HostUp => ChangeSeverity::Medium,
            Self::HostDown => ChangeSeverity::High,
            Self::NewVulnerability => ChangeSeverity::Critical,
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::NewPort => "New Port Opened",
            Self::ClosedPort => "Port Closed",
            Self::ServiceChanged => "Service Changed",
            Self::VersionChanged => "Version Changed",
            Self::BannerChanged => "Banner Changed",
            Self::HostUp => "Host Came Online",
            Self::HostDown => "Host Went Offline",
            Self::NewVulnerability => "New Vulnerability Detected",
        }
    }
}

/// Severity of a change
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// A detected change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedChange {
    pub id: String,
    pub change_type: ChangeType,
    pub severity: ChangeSeverity,
    pub target: String,
    pub port: Option<u16>,
    pub description: String,
    pub previous_value: Option<String>,
    pub current_value: Option<String>,
    pub detected_at: DateTime<Utc>,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
}

impl DetectedChange {
    pub fn new(
        change_type: ChangeType,
        target: String,
        description: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            severity: change_type.severity(),
            change_type,
            target,
            port: None,
            description,
            previous_value: None,
            current_value: None,
            detected_at: Utc::now(),
            acknowledged: false,
            acknowledged_by: None,
            acknowledged_at: None,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_values(mut self, previous: Option<String>, current: Option<String>) -> Self {
        self.previous_value = previous;
        self.current_value = current;
        self
    }
}

/// An alert to be sent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringAlert {
    pub id: String,
    pub changes: Vec<DetectedChange>,
    pub target_summary: String,
    pub created_at: DateTime<Utc>,
    pub sent: bool,
    pub sent_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

impl MonitoringAlert {
    pub fn new(changes: Vec<DetectedChange>) -> Self {
        let target_summary = if changes.len() == 1 {
            format!("1 change on {}", changes[0].target)
        } else {
            let targets: std::collections::HashSet<_> = changes.iter().map(|c| &c.target).collect();
            format!("{} changes across {} target(s)", changes.len(), targets.len())
        };

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            changes,
            target_summary,
            created_at: Utc::now(),
            sent: false,
            sent_at: None,
            error: None,
        }
    }

    pub fn highest_severity(&self) -> ChangeSeverity {
        self.changes
            .iter()
            .map(|c| c.severity)
            .max()
            .unwrap_or(ChangeSeverity::Low)
    }
}

/// Status of the monitoring engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringStatus {
    pub is_running: bool,
    pub targets_count: usize,
    pub last_light_scan: Option<DateTime<Utc>>,
    pub last_full_scan: Option<DateTime<Utc>>,
    pub changes_detected_today: usize,
    pub alerts_sent_today: usize,
    pub uptime_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitoring_config_default() {
        let config = MonitoringConfig::default();
        assert_eq!(config.light_scan_interval_secs, 5);
        assert_eq!(config.full_scan_interval_secs, 4 * 60 * 60);
        assert!(config.alerting_enabled);
    }

    #[test]
    fn test_change_type_severity() {
        assert_eq!(ChangeType::NewPort.severity(), ChangeSeverity::High);
        assert_eq!(ChangeType::NewVulnerability.severity(), ChangeSeverity::Critical);
        assert_eq!(ChangeType::VersionChanged.severity(), ChangeSeverity::Low);
    }

    #[test]
    fn test_detected_change_new() {
        let change = DetectedChange::new(
            ChangeType::NewPort,
            "192.168.1.1".to_string(),
            "Port 22 opened".to_string(),
        ).with_port(22);

        assert_eq!(change.port, Some(22));
        assert_eq!(change.severity, ChangeSeverity::High);
        assert!(!change.acknowledged);
    }

    #[test]
    fn test_monitoring_alert() {
        let changes = vec![
            DetectedChange::new(
                ChangeType::NewPort,
                "192.168.1.1".to_string(),
                "Port 22 opened".to_string(),
            ),
            DetectedChange::new(
                ChangeType::NewVulnerability,
                "192.168.1.1".to_string(),
                "CVE-2024-1234 detected".to_string(),
            ),
        ];

        let alert = MonitoringAlert::new(changes);
        assert_eq!(alert.highest_severity(), ChangeSeverity::Critical);
        assert!(!alert.sent);
    }
}
