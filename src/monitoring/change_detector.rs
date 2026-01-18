//! Change Detection for Continuous Monitoring
//!
//! Compares current scan results against baselines or previous states
//! to detect and report changes in the attack surface.

use std::collections::HashMap;
use chrono::Utc;
use log::{debug, info, warn};

use super::types::{
    ChangeType, ChangeSeverity, DetectedChange, PortState, TargetState, Baseline,
    AlertTriggers, MonitoringPortInfo,
};

/// Detects changes between scan results
pub struct ChangeDetector {
    /// What triggers to check for
    triggers: AlertTriggers,
    /// Minimum severity to report
    min_severity: ChangeSeverity,
}

impl ChangeDetector {
    pub fn new(triggers: AlertTriggers) -> Self {
        Self {
            triggers,
            min_severity: ChangeSeverity::Low,
        }
    }

    pub fn with_min_severity(mut self, severity: ChangeSeverity) -> Self {
        self.min_severity = severity;
        self
    }

    /// Compare current state against previous state and detect changes
    pub fn detect_changes(
        &self,
        previous: &TargetState,
        current: &TargetState,
    ) -> Vec<DetectedChange> {
        let mut changes = Vec::new();

        // Check host status changes
        if self.triggers.host_up && !previous.is_up && current.is_up {
            changes.push(DetectedChange::new(
                ChangeType::HostUp,
                current.target.clone(),
                format!("Host {} came online", current.target),
            ));
        }

        if self.triggers.host_down && previous.is_up && !current.is_up {
            changes.push(DetectedChange::new(
                ChangeType::HostDown,
                current.target.clone(),
                format!("Host {} went offline", current.target),
            ));
        }

        // Only check ports if host is up
        if current.is_up {
            // Check for new ports
            if self.triggers.new_port {
                for (port, state) in &current.open_ports {
                    if !previous.open_ports.contains_key(port) {
                        let service_info = state.service.as_deref().unwrap_or("unknown");
                        changes.push(
                            DetectedChange::new(
                                ChangeType::NewPort,
                                current.target.clone(),
                                format!("New port {} ({}) opened on {}", port, service_info, current.target),
                            )
                            .with_port(*port)
                            .with_values(None, Some(service_info.to_string()))
                        );
                    }
                }
            }

            // Check for closed ports
            if self.triggers.closed_port {
                for (port, state) in &previous.open_ports {
                    if !current.open_ports.contains_key(port) {
                        let service_info = state.service.as_deref().unwrap_or("unknown");
                        changes.push(
                            DetectedChange::new(
                                ChangeType::ClosedPort,
                                current.target.clone(),
                                format!("Port {} ({}) closed on {}", port, service_info, current.target),
                            )
                            .with_port(*port)
                            .with_values(Some(service_info.to_string()), None)
                        );
                    }
                }
            }

            // Check for service changes on existing ports
            if self.triggers.service_change {
                for (port, current_state) in &current.open_ports {
                    if let Some(previous_state) = previous.open_ports.get(port) {
                        if previous_state.service != current_state.service {
                            changes.push(
                                DetectedChange::new(
                                    ChangeType::ServiceChanged,
                                    current.target.clone(),
                                    format!(
                                        "Service on port {} changed from {:?} to {:?}",
                                        port,
                                        previous_state.service,
                                        current_state.service
                                    ),
                                )
                                .with_port(*port)
                                .with_values(
                                    previous_state.service.clone(),
                                    current_state.service.clone(),
                                )
                            );
                        }
                    }
                }
            }

            // Check for version changes
            if self.triggers.version_change {
                for (port, current_state) in &current.open_ports {
                    if let Some(previous_state) = previous.open_ports.get(port) {
                        if previous_state.version != current_state.version &&
                           previous_state.version.is_some() &&
                           current_state.version.is_some() {
                            changes.push(
                                DetectedChange::new(
                                    ChangeType::VersionChanged,
                                    current.target.clone(),
                                    format!(
                                        "Version on port {} changed from {:?} to {:?}",
                                        port,
                                        previous_state.version,
                                        current_state.version
                                    ),
                                )
                                .with_port(*port)
                                .with_values(
                                    previous_state.version.clone(),
                                    current_state.version.clone(),
                                )
                            );
                        }
                    }
                }
            }
        }

        // Filter by minimum severity
        changes.into_iter()
            .filter(|c| c.severity >= self.min_severity)
            .collect()
    }

    /// Compare current state against a baseline
    pub fn compare_to_baseline(
        &self,
        baseline: &Baseline,
        current_states: &[TargetState],
    ) -> Vec<DetectedChange> {
        let mut all_changes = Vec::new();

        // Build lookup map for baseline targets
        let baseline_map: HashMap<&str, &TargetState> = baseline.targets
            .iter()
            .map(|t| (t.target.as_str(), t))
            .collect();

        // Check each current target
        for current in current_states {
            if let Some(baseline_state) = baseline_map.get(current.target.as_str()) {
                let changes = self.detect_changes(baseline_state, current);
                all_changes.extend(changes);
            } else {
                // New target not in baseline
                if current.is_up {
                    all_changes.push(DetectedChange::new(
                        ChangeType::HostUp,
                        current.target.clone(),
                        format!("New host {} detected (not in baseline)", current.target),
                    ));

                    // Also report all its open ports as new
                    if self.triggers.new_port {
                        for (port, state) in &current.open_ports {
                            let service_info = state.service.as_deref().unwrap_or("unknown");
                            all_changes.push(
                                DetectedChange::new(
                                    ChangeType::NewPort,
                                    current.target.clone(),
                                    format!("Port {} ({}) on new host {}", port, service_info, current.target),
                                )
                                .with_port(*port)
                            );
                        }
                    }
                }
            }
        }

        // Check for hosts that are in baseline but not in current (missing hosts)
        let current_map: HashMap<&str, &TargetState> = current_states
            .iter()
            .map(|t| (t.target.as_str(), t))
            .collect();

        for baseline_target in &baseline.targets {
            if !current_map.contains_key(baseline_target.target.as_str()) && baseline_target.is_up {
                all_changes.push(DetectedChange::new(
                    ChangeType::HostDown,
                    baseline_target.target.clone(),
                    format!("Host {} from baseline is no longer detected", baseline_target.target),
                ));
            }
        }

        all_changes
    }

    /// Convert port scan results to PortState
    pub fn port_info_to_state(port_info: &MonitoringPortInfo) -> PortState {
        PortState {
            port: port_info.port,
            protocol: port_info.protocol.clone(),
            service: port_info.service.clone(),
            version: port_info.version.clone(),
            banner: port_info.banner.clone(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    /// Update target state with new scan results
    pub fn update_target_state(
        state: &mut TargetState,
        ports: &[MonitoringPortInfo],
        is_up: bool,
    ) {
        let now = Utc::now();
        state.is_up = is_up;

        if is_up {
            state.last_seen = Some(now);
        }

        // Update ports
        let current_ports: std::collections::HashSet<u16> = ports.iter().map(|p| p.port).collect();

        // Update existing ports and add new ones
        for port_info in ports {
            if let Some(existing) = state.open_ports.get_mut(&port_info.port) {
                // Update existing port
                existing.last_seen = now;
                if port_info.service.is_some() {
                    existing.service = port_info.service.clone();
                }
                if port_info.version.is_some() {
                    existing.version = port_info.version.clone();
                }
                if port_info.banner.is_some() {
                    existing.banner = port_info.banner.clone();
                }
            } else {
                // New port
                state.open_ports.insert(
                    port_info.port,
                    Self::port_info_to_state(port_info),
                );
            }
        }

        // Note: We don't remove closed ports from state here
        // The change detector will catch them when comparing
    }
}

/// Calculate a summary of changes
pub fn summarize_changes(changes: &[DetectedChange]) -> ChangesSummary {
    let mut summary = ChangesSummary::default();

    for change in changes {
        match change.change_type {
            ChangeType::NewPort => summary.new_ports += 1,
            ChangeType::ClosedPort => summary.closed_ports += 1,
            ChangeType::ServiceChanged => summary.service_changes += 1,
            ChangeType::VersionChanged => summary.version_changes += 1,
            ChangeType::BannerChanged => summary.banner_changes += 1,
            ChangeType::HostUp => summary.hosts_up += 1,
            ChangeType::HostDown => summary.hosts_down += 1,
            ChangeType::NewVulnerability => summary.new_vulnerabilities += 1,
        }

        match change.severity {
            ChangeSeverity::Critical => summary.critical += 1,
            ChangeSeverity::High => summary.high += 1,
            ChangeSeverity::Medium => summary.medium += 1,
            ChangeSeverity::Low => summary.low += 1,
        }
    }

    summary.total = changes.len();
    summary
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ChangesSummary {
    pub total: usize,
    pub new_ports: usize,
    pub closed_ports: usize,
    pub service_changes: usize,
    pub version_changes: usize,
    pub banner_changes: usize,
    pub hosts_up: usize,
    pub hosts_down: usize,
    pub new_vulnerabilities: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_port_state(port: u16, service: &str) -> PortState {
        PortState {
            port,
            protocol: "tcp".to_string(),
            service: Some(service.to_string()),
            version: None,
            banner: None,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn test_detect_new_port() {
        let triggers = AlertTriggers::default();
        let detector = ChangeDetector::new(triggers);

        let previous = TargetState {
            target: "192.168.1.1".to_string(),
            ip: None,
            is_up: true,
            last_seen: Some(Utc::now()),
            open_ports: HashMap::new(),
            last_full_scan: None,
            last_light_scan: None,
        };

        let mut current = previous.clone();
        current.open_ports.insert(22, create_test_port_state(22, "ssh"));

        let changes = detector.detect_changes(&previous, &current);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::NewPort);
        assert_eq!(changes[0].port, Some(22));
    }

    #[test]
    fn test_detect_closed_port() {
        let triggers = AlertTriggers::default();
        let detector = ChangeDetector::new(triggers);

        let mut previous = TargetState::new("192.168.1.1".to_string());
        previous.is_up = true;
        previous.open_ports.insert(22, create_test_port_state(22, "ssh"));

        let mut current = previous.clone();
        current.open_ports.clear();

        let changes = detector.detect_changes(&previous, &current);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::ClosedPort);
    }

    #[test]
    fn test_detect_host_down() {
        let triggers = AlertTriggers::default();
        let detector = ChangeDetector::new(triggers);

        let mut previous = TargetState::new("192.168.1.1".to_string());
        previous.is_up = true;

        let mut current = previous.clone();
        current.is_up = false;

        let changes = detector.detect_changes(&previous, &current);

        assert!(changes.iter().any(|c| c.change_type == ChangeType::HostDown));
    }

    #[test]
    fn test_detect_service_change() {
        let triggers = AlertTriggers::default();
        let detector = ChangeDetector::new(triggers);

        let mut previous = TargetState::new("192.168.1.1".to_string());
        previous.is_up = true;
        previous.open_ports.insert(80, create_test_port_state(80, "http"));

        let mut current = previous.clone();
        current.open_ports.get_mut(&80).unwrap().service = Some("https".to_string());

        let changes = detector.detect_changes(&previous, &current);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::ServiceChanged);
    }

    #[test]
    fn test_summarize_changes() {
        let changes = vec![
            DetectedChange::new(ChangeType::NewPort, "test".to_string(), "test".to_string()),
            DetectedChange::new(ChangeType::NewPort, "test".to_string(), "test".to_string()),
            DetectedChange::new(ChangeType::ClosedPort, "test".to_string(), "test".to_string()),
            DetectedChange::new(ChangeType::NewVulnerability, "test".to_string(), "test".to_string()),
        ];

        let summary = summarize_changes(&changes);

        assert_eq!(summary.total, 4);
        assert_eq!(summary.new_ports, 2);
        assert_eq!(summary.closed_ports, 1);
        assert_eq!(summary.new_vulnerabilities, 1);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 2);
        assert_eq!(summary.medium, 1);
    }
}
