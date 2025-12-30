//! Event Handler
//!
//! Central event routing and handling for cross-team events.

use super::types::SecurityEvent;
use super::subscriber::EventSubscriber;
use tokio::sync::broadcast;
use std::sync::Arc;

/// Event handler for routing events to subscribers
pub struct EventHandler {
    subscribers: Vec<Arc<dyn EventSubscriber>>,
    broadcast_tx: broadcast::Sender<SecurityEvent>,
}

impl EventHandler {
    /// Create a new event handler with broadcast channel capacity
    pub fn new(capacity: usize) -> (Self, broadcast::Sender<SecurityEvent>) {
        let (tx, _) = broadcast::channel(capacity);
        let handler = Self {
            subscribers: Vec::new(),
            broadcast_tx: tx.clone(),
        };
        (handler, tx)
    }

    /// Add a subscriber to the event handler
    pub fn add_subscriber(&mut self, subscriber: Arc<dyn EventSubscriber>) {
        self.subscribers.push(subscriber);
    }

    /// Start the event handling loop (spawns a background task)
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut rx = self.broadcast_tx.subscribe();

            loop {
                match rx.recv().await {
                    Ok(event) => {
                        // Route event to all subscribers for the target team
                        for subscriber in &self.subscribers {
                            // Check if this subscriber's team is in the target teams
                            let target_teams = get_target_teams(&event);
                            if target_teams.contains(&subscriber.team().to_string()) {
                                if let Err(e) = subscriber.on_event(event.clone()) {
                                    log::error!(
                                        "Error handling event {} for team {}: {}",
                                        event.event_type(),
                                        subscriber.team(),
                                        e
                                    );
                                }
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        log::warn!("Event handler lagged, skipped {} events", skipped);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        log::info!("Event handler channel closed, exiting");
                        break;
                    }
                }
            }
        })
    }
}

/// Get target teams for an event (matches publisher logic)
fn get_target_teams(event: &SecurityEvent) -> Vec<String> {
    match event {
        SecurityEvent::VulnerabilityDiscovered(_) => {
            vec!["blue".to_string(), "purple".to_string(), "white".to_string(), "green".to_string()]
        }
        SecurityEvent::ScanCompleted(_) => {
            vec!["blue".to_string(), "white".to_string()]
        }
        SecurityEvent::ExploitSuccessful(_) => {
            vec!["blue".to_string(), "green".to_string()]
        }
        SecurityEvent::AssetDiscovered(_) => {
            vec!["blue".to_string(), "white".to_string(), "green".to_string()]
        }
        SecurityEvent::DetectionRuleCreated(_) => {
            vec!["purple".to_string(), "green".to_string()]
        }
        SecurityEvent::AlertTriggered(_) => {
            vec!["green".to_string(), "white".to_string()]
        }
        SecurityEvent::ThreatDetected(_) => {
            vec!["red".to_string(), "purple".to_string(), "green".to_string(), "white".to_string()]
        }
        SecurityEvent::ExerciseCompleted(_) => {
            vec!["blue".to_string(), "green".to_string(), "white".to_string()]
        }
        SecurityEvent::GapIdentified(_) => {
            vec!["blue".to_string(), "green".to_string()]
        }
        SecurityEvent::DetectionValidated(_) => {
            vec!["blue".to_string(), "green".to_string()]
        }
        SecurityEvent::AttackSimulated(_) => {
            vec!["blue".to_string(), "green".to_string()]
        }
        SecurityEvent::CodeVulnerabilityFound(_) => {
            vec!["orange".to_string(), "white".to_string()]
        }
        SecurityEvent::DependencyRiskDetected(_) => {
            vec!["white".to_string(), "green".to_string()]
        }
        SecurityEvent::SecureCodeScanned(_) => {
            vec!["white".to_string()]
        }
        SecurityEvent::BuildFailed(_) => {
            vec!["yellow".to_string()]
        }
        SecurityEvent::PhishingClicked(_) => {
            vec!["green".to_string(), "white".to_string()]
        }
        SecurityEvent::TrainingCompleted(_) => {
            vec!["white".to_string()]
        }
        SecurityEvent::UserRiskChanged(_) => {
            vec!["green".to_string(), "white".to_string()]
        }
        SecurityEvent::SecurityAwarenessTest(_) => {
            vec!["white".to_string()]
        }
        SecurityEvent::ComplianceViolation(_) => {
            vec!["green".to_string(), "red".to_string(), "yellow".to_string(), "orange".to_string()]
        }
        SecurityEvent::PolicyUpdated(_) => {
            vec!["red".to_string(), "blue".to_string(), "purple".to_string(), "yellow".to_string(), "orange".to_string(), "green".to_string()]
        }
        SecurityEvent::RiskAssessed(_) => {
            vec!["red".to_string(), "green".to_string()]
        }
        SecurityEvent::AuditCompleted(_) => {
            vec!["red".to_string(), "blue".to_string(), "purple".to_string(), "yellow".to_string(), "orange".to_string(), "green".to_string()]
        }
        SecurityEvent::IncidentCreated(_) => {
            vec!["red".to_string(), "blue".to_string(), "purple".to_string(), "yellow".to_string(), "orange".to_string(), "white".to_string()]
        }
        SecurityEvent::IncidentResolved(_) => {
            vec!["red".to_string(), "blue".to_string(), "purple".to_string(), "white".to_string()]
        }
        SecurityEvent::PlaybookExecuted(_) => {
            vec!["white".to_string(), "blue".to_string()]
        }
        SecurityEvent::SoarAutomated(_) => {
            vec!["white".to_string(), "blue".to_string()]
        }
    }
}
