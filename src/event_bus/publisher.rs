//! Event Publisher
//!
//! Publishes security events to the event bus for cross-team communication.

use super::types::SecurityEvent;
use sqlx::SqlitePool;
use anyhow::Result;
use tokio::sync::broadcast;
use std::sync::Arc;

/// Event publisher for cross-team communication
#[derive(Clone)]
pub struct EventPublisher {
    pool: Arc<SqlitePool>,
    broadcast_tx: broadcast::Sender<SecurityEvent>,
}

impl EventPublisher {
    /// Create a new event publisher
    pub fn new(pool: Arc<SqlitePool>, broadcast_tx: broadcast::Sender<SecurityEvent>) -> Self {
        Self {
            pool,
            broadcast_tx,
        }
    }

    /// Publish an event to the event bus
    pub async fn publish(&self, event: SecurityEvent) -> Result<()> {
        // Log event to database
        let event_type = event.event_type();
        let source_team = event.source_team();
        let payload = serde_json::to_value(&event)?;

        // Determine target teams based on event type
        let target_teams = self.get_target_teams(&event);

        crate::db::cross_team::log_event(
            &self.pool,
            event_type,
            source_team,
            &target_teams.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            payload,
        )
        .await?;

        // Broadcast event to WebSocket subscribers (ignore errors if no subscribers)
        let _ = self.broadcast_tx.send(event);

        Ok(())
    }

    /// Determine which teams should receive this event
    fn get_target_teams(&self, event: &SecurityEvent) -> Vec<String> {
        match event {
            // Vulnerability discovered: notify all teams
            SecurityEvent::VulnerabilityDiscovered(_) => {
                vec!["blue".to_string(), "purple".to_string(), "white".to_string(), "green".to_string()]
            }
            // Scan completed: notify blue team for detection, white team for compliance
            SecurityEvent::ScanCompleted(_) => {
                vec!["blue".to_string(), "white".to_string()]
            }
            // Exploit successful: notify blue team and green team (SOC)
            SecurityEvent::ExploitSuccessful(_) => {
                vec!["blue".to_string(), "green".to_string()]
            }
            // Asset discovered: notify all teams
            SecurityEvent::AssetDiscovered(_) => {
                vec!["blue".to_string(), "white".to_string(), "green".to_string()]
            }
            // Detection rule created: notify purple team for validation
            SecurityEvent::DetectionRuleCreated(_) => {
                vec!["purple".to_string(), "green".to_string()]
            }
            // Alert triggered: notify green team (SOC), white team for compliance
            SecurityEvent::AlertTriggered(_) => {
                vec!["green".to_string(), "white".to_string()]
            }
            // Threat detected: notify all teams
            SecurityEvent::ThreatDetected(_) => {
                vec!["red".to_string(), "purple".to_string(), "green".to_string(), "white".to_string()]
            }
            // Exercise completed: notify blue team with findings
            SecurityEvent::ExerciseCompleted(_) => {
                vec!["blue".to_string(), "green".to_string(), "white".to_string()]
            }
            // Gap identified: notify blue team to create detection rules
            SecurityEvent::GapIdentified(_) => {
                vec!["blue".to_string(), "green".to_string()]
            }
            // Detection validated: notify blue team
            SecurityEvent::DetectionValidated(_) => {
                vec!["blue".to_string(), "green".to_string()]
            }
            // Attack simulated: notify blue team and green team
            SecurityEvent::AttackSimulated(_) => {
                vec!["blue".to_string(), "green".to_string()]
            }
            // Code vulnerability found: notify orange team for training, white team for policy
            SecurityEvent::CodeVulnerabilityFound(_) => {
                vec!["orange".to_string(), "white".to_string()]
            }
            // Dependency risk detected: notify white team for risk assessment
            SecurityEvent::DependencyRiskDetected(_) => {
                vec!["white".to_string(), "green".to_string()]
            }
            // Secure code scanned: notify white team
            SecurityEvent::SecureCodeScanned(_) => {
                vec!["white".to_string()]
            }
            // Build failed: notify yellow team developers
            SecurityEvent::BuildFailed(_) => {
                vec!["yellow".to_string()]
            }
            // Phishing clicked: notify green team (insider threat), white team (policy)
            SecurityEvent::PhishingClicked(_) => {
                vec!["green".to_string(), "white".to_string()]
            }
            // Training completed: notify white team for compliance tracking
            SecurityEvent::TrainingCompleted(_) => {
                vec!["white".to_string()]
            }
            // User risk changed: notify green team (UEBA), white team (risk management)
            SecurityEvent::UserRiskChanged(_) => {
                vec!["green".to_string(), "white".to_string()]
            }
            // Security awareness test: notify white team
            SecurityEvent::SecurityAwarenessTest(_) => {
                vec!["white".to_string()]
            }
            // Compliance violation: notify green team and affected teams
            SecurityEvent::ComplianceViolation(_) => {
                vec!["green".to_string(), "red".to_string(), "yellow".to_string(), "orange".to_string()]
            }
            // Policy updated: notify all teams
            SecurityEvent::PolicyUpdated(_) => {
                vec!["red".to_string(), "blue".to_string(), "purple".to_string(), "yellow".to_string(), "orange".to_string(), "green".to_string()]
            }
            // Risk assessed: notify all teams
            SecurityEvent::RiskAssessed(_) => {
                vec!["red".to_string(), "green".to_string()]
            }
            // Audit completed: notify all teams
            SecurityEvent::AuditCompleted(_) => {
                vec!["red".to_string(), "blue".to_string(), "purple".to_string(), "yellow".to_string(), "orange".to_string(), "green".to_string()]
            }
            // Incident created: notify all teams
            SecurityEvent::IncidentCreated(_) => {
                vec!["red".to_string(), "blue".to_string(), "purple".to_string(), "yellow".to_string(), "orange".to_string(), "white".to_string()]
            }
            // Incident resolved: notify all teams
            SecurityEvent::IncidentResolved(_) => {
                vec!["red".to_string(), "blue".to_string(), "purple".to_string(), "white".to_string()]
            }
            // Playbook executed: notify white team
            SecurityEvent::PlaybookExecuted(_) => {
                vec!["white".to_string(), "blue".to_string()]
            }
            // SOAR automated: notify white team
            SecurityEvent::SoarAutomated(_) => {
                vec!["white".to_string(), "blue".to_string()]
            }
        }
    }
}
