pub mod email;
pub mod slack;
pub mod teams;
pub mod sender;

pub use email::{EmailConfig, EmailNotifier};
pub use slack::SlackNotifier;
pub use teams::TeamsNotifier;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Notification event type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationEvent {
    ScanCompleted {
        scan_name: String,
        hosts_discovered: usize,
        open_ports: usize,
        vulnerabilities_found: usize,
        critical_vulns: usize,
        high_vulns: usize,
        medium_vulns: usize,
        low_vulns: usize,
    },
    CriticalVulnerability {
        scan_name: String,
        host: String,
        port: String,
        service: String,
        severity: String,
        title: String,
        description: String,
    },
    ScheduledScanStarted {
        scan_name: String,
        targets: String,
    },
    ScheduledScanCompleted {
        scan_name: String,
        status: String,
        duration_secs: u64,
    },
}

/// Trait for notification providers
pub trait Notifier {
    async fn send_notification(&self, event: &NotificationEvent) -> Result<()>;
    async fn send_test_message(&self) -> Result<()>;
}
