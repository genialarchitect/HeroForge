#![allow(dead_code)]
//! Detection Validation Logic
//!
//! This module provides detection validation capabilities for BAS testing.
//! It checks whether security controls detected simulated attacks.

use super::payloads::PayloadResult;
use super::techniques::TechniqueLibrary;
use super::types::{DetectionGap, MitreTactic, TechniqueExecution, TechniqueExecutionStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;
use uuid::Uuid;

/// Result of detection validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Whether detection was observed
    pub detected: bool,
    /// Detection source (e.g., "EDR", "SIEM", "IDS")
    pub source: Option<String>,
    /// Time when detection was observed
    pub detection_time: Option<DateTime<Utc>>,
    /// Time from execution to detection (if available)
    pub detection_latency_ms: Option<u64>,
    /// Alert/event ID from detection system
    pub alert_id: Option<String>,
    /// Alert severity
    pub alert_severity: Option<String>,
    /// Alert details
    pub details: Option<String>,
    /// Validation method used
    pub validation_method: ValidationMethod,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
}

impl DetectionResult {
    pub fn detected(source: impl Into<String>) -> Self {
        Self {
            detected: true,
            source: Some(source.into()),
            detection_time: Some(Utc::now()),
            detection_latency_ms: None,
            alert_id: None,
            alert_severity: None,
            details: None,
            validation_method: ValidationMethod::Manual,
            confidence: 1.0,
        }
    }

    pub fn not_detected() -> Self {
        Self {
            detected: false,
            source: None,
            detection_time: None,
            detection_latency_ms: None,
            alert_id: None,
            alert_severity: None,
            details: None,
            validation_method: ValidationMethod::Timeout,
            confidence: 1.0,
        }
    }

    pub fn with_latency(mut self, latency_ms: u64) -> Self {
        self.detection_latency_ms = Some(latency_ms);
        self
    }

    pub fn with_alert(mut self, id: impl Into<String>, severity: impl Into<String>) -> Self {
        self.alert_id = Some(id.into());
        self.alert_severity = Some(severity.into());
        self
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
}

/// Method used for detection validation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationMethod {
    /// Manual confirmation by operator
    Manual,
    /// Automated API check
    ApiCheck,
    /// Log analysis
    LogAnalysis,
    /// SIEM integration
    SiemQuery,
    /// EDR integration
    EdrQuery,
    /// Network detection
    NetworkAnalysis,
    /// Timeout (no detection within window)
    Timeout,
}

impl ValidationMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            ValidationMethod::Manual => "manual",
            ValidationMethod::ApiCheck => "api_check",
            ValidationMethod::LogAnalysis => "log_analysis",
            ValidationMethod::SiemQuery => "siem_query",
            ValidationMethod::EdrQuery => "edr_query",
            ValidationMethod::NetworkAnalysis => "network_analysis",
            ValidationMethod::Timeout => "timeout",
        }
    }
}

/// Detection validator for BAS simulations
pub struct DetectionValidator {
    /// Timeout for detection validation
    timeout: Duration,
    /// Technique library for context
    library: TechniqueLibrary,
    /// Detection sources to check
    sources: Vec<DetectionSource>,
    /// Results cache (uses RwLock for interior mutability)
    results: RwLock<HashMap<String, DetectionResult>>,
}

/// Configuration for a detection source
#[derive(Debug, Clone)]
pub struct DetectionSource {
    /// Source name
    pub name: String,
    /// Source type
    pub source_type: DetectionSourceType,
    /// Configuration for the source
    pub config: HashMap<String, String>,
    /// Whether this source is enabled
    pub enabled: bool,
}

/// Types of detection sources
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectionSourceType {
    /// SIEM system
    Siem,
    /// EDR/XDR platform
    Edr,
    /// Network IDS/IPS
    Nids,
    /// Host-based IDS
    Hids,
    /// Log aggregation
    Logs,
    /// Cloud security platform
    Cloud,
    /// Manual verification
    Manual,
}

impl DetectionValidator {
    /// Create a new detection validator
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            library: TechniqueLibrary::new(),
            sources: vec![
                DetectionSource {
                    name: "Manual".to_string(),
                    source_type: DetectionSourceType::Manual,
                    config: HashMap::new(),
                    enabled: true,
                },
            ],
            results: RwLock::new(HashMap::new()),
        }
    }

    /// Set detection timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Add a detection source
    pub fn add_source(&mut self, source: DetectionSource) {
        self.sources.push(source);
    }

    /// Validate detection for a technique execution
    pub async fn validate_execution(
        &self,
        execution: &TechniqueExecution,
        payload_result: Option<&PayloadResult>,
    ) -> DetectionResult {
        let execution_id = execution.id.clone();

        // Check if we already have a cached result
        if let Some(result) = self.results.read().unwrap().get(&execution_id) {
            return result.clone();
        }

        // Get expected detection sources for this technique
        let technique = self.library.get(&execution.technique_id);
        let expected_sources: Vec<String> = technique
            .map(|t| t.detection_sources.clone())
            .unwrap_or_default();

        // Determine validation method based on execution status
        let result = match execution.status {
            TechniqueExecutionStatus::Blocked => {
                // If blocked, detection was successful
                DetectionResult::detected("Security Control")
                    .with_details("Execution was blocked by security controls")
                    .with_confidence(1.0)
            }
            TechniqueExecutionStatus::Detected => {
                // Already marked as detected
                DetectionResult::detected("Unspecified")
                    .with_details(
                        execution
                            .detection_details
                            .clone()
                            .unwrap_or_else(|| "Detection reported".to_string()),
                    )
                    .with_confidence(0.9)
            }
            TechniqueExecutionStatus::Success => {
                // Execution succeeded - check if indicators were detected
                if let Some(payload) = payload_result {
                    self.check_payload_detection(payload, &expected_sources).await
                } else {
                    // No payload result - simulate detection check
                    self.simulate_detection_check(&execution.technique_id).await
                }
            }
            _ => {
                // For other statuses, assume no detection
                DetectionResult::not_detected()
            }
        };

        // Cache the result
        self.results.write().unwrap().insert(execution_id, result.clone());

        result
    }

    /// Check if payload indicators were detected
    async fn check_payload_detection(
        &self,
        payload: &PayloadResult,
        expected_sources: &[String],
    ) -> DetectionResult {
        // In a real implementation, this would query actual detection systems
        // For now, we simulate based on indicators

        if payload.indicators.is_empty() {
            return DetectionResult::not_detected();
        }

        // Simulate detection probability based on indicator types
        let detection_probability = self.calculate_detection_probability(&payload.indicators);

        // Simulate detection with probability
        let detected = rand_simple(detection_probability);

        if detected {
            let source = expected_sources.first().cloned().unwrap_or_else(|| "EDR".to_string());
            DetectionResult::detected(source)
                .with_details(format!(
                    "Detected {} indicator(s): {}",
                    payload.indicators.len(),
                    payload.indicators.join(", ")
                ))
                .with_confidence(detection_probability)
        } else {
            DetectionResult::not_detected()
                .with_confidence(1.0 - detection_probability)
        }
    }

    /// Simulate detection check for a technique
    async fn simulate_detection_check(&self, technique_id: &str) -> DetectionResult {
        // Wait a bit to simulate detection latency
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Get technique risk level
        let technique = self.library.get(technique_id);
        let risk_level = technique.map(|t| t.risk_level).unwrap_or(5);

        // Higher risk techniques have lower detection probability in simulation
        // (representing gaps in security coverage)
        let base_probability = match risk_level {
            1..=2 => 0.3,  // Low risk, often detected
            3..=4 => 0.5,  // Medium risk
            5..=6 => 0.6,  // Higher risk
            7..=8 => 0.7,  // High risk, harder to detect
            _ => 0.8,      // Critical risk, very hard to detect
        };

        let detected = rand_simple(base_probability);

        if detected {
            let source = technique
                .and_then(|t| t.detection_sources.first().cloned())
                .unwrap_or_else(|| "Security Monitoring".to_string());

            DetectionResult::detected(source)
                .with_details("Simulated detection based on technique profile")
                .with_confidence(base_probability)
        } else {
            DetectionResult::not_detected()
                .with_confidence(1.0 - base_probability)
        }
    }

    /// Calculate detection probability based on indicators
    fn calculate_detection_probability(&self, indicators: &[String]) -> f64 {
        if indicators.is_empty() {
            return 0.3;
        }

        let mut probability: f64 = 0.3; // Base probability

        for indicator in indicators {
            // Different indicator types have different detection probabilities
            if indicator.starts_with("process:") {
                probability += 0.2;
            } else if indicator.starts_with("file:") {
                probability += 0.15;
            } else if indicator.starts_with("network:") {
                probability += 0.1;
            } else if indicator.starts_with("registry:") {
                probability += 0.2;
            } else if indicator.starts_with("dns:") {
                probability += 0.15;
            } else if indicator.starts_with("http:") {
                probability += 0.1;
            } else if indicator.starts_with("log:") {
                probability += 0.25;
            } else if indicator.starts_with("memory:") {
                probability += 0.05;
            }
        }

        probability.min(0.95) // Cap at 95%
    }

    /// Identify detection gaps from execution results
    pub fn identify_gaps(
        &self,
        executions: &[TechniqueExecution],
        simulation_id: &str,
    ) -> Vec<DetectionGap> {
        let mut gaps = Vec::new();

        for execution in executions {
            // Only consider successful executions that weren't detected
            if execution.status == TechniqueExecutionStatus::Success && !execution.detection_observed
            {
                if let Some(technique) = self.library.get(&execution.technique_id) {
                    let gap = DetectionGap::new(
                        Uuid::new_v4().to_string(),
                        simulation_id,
                        execution.technique_id.clone(),
                        technique.name.clone(),
                        technique.tactics.clone(),
                    )
                    .with_reason(format!(
                        "Technique '{}' executed successfully without detection",
                        technique.name
                    ))
                    .with_sources(technique.detection_sources.clone())
                    .with_recommendations(self.generate_recommendations(technique))
                    .with_severity(self.calculate_gap_severity(technique));

                    gaps.push(gap);
                }
            }
        }

        // Sort gaps by severity
        gaps.sort_by(|a, b| b.severity.cmp(&a.severity));

        gaps
    }

    /// Generate recommendations for closing a detection gap
    fn generate_recommendations(&self, technique: &super::types::AttackTechnique) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Based on technique tactics
        for tactic in &technique.tactics {
            match tactic {
                MitreTactic::Execution => {
                    recommendations.push(
                        "Enable process command-line logging and monitoring".to_string(),
                    );
                    recommendations.push(
                        "Deploy application whitelisting controls".to_string(),
                    );
                }
                MitreTactic::Persistence => {
                    recommendations.push(
                        "Monitor startup folders and registry run keys".to_string(),
                    );
                    recommendations.push(
                        "Enable file integrity monitoring on critical paths".to_string(),
                    );
                }
                MitreTactic::CredentialAccess => {
                    recommendations.push(
                        "Deploy credential theft detection (LSASS access monitoring)".to_string(),
                    );
                    recommendations.push(
                        "Enable honeypot accounts and credentials".to_string(),
                    );
                }
                MitreTactic::LateralMovement => {
                    recommendations.push(
                        "Monitor unusual authentication patterns".to_string(),
                    );
                    recommendations.push(
                        "Deploy network segmentation and monitor cross-segment traffic".to_string(),
                    );
                }
                MitreTactic::CommandAndControl => {
                    recommendations.push(
                        "Deploy DNS monitoring and anomaly detection".to_string(),
                    );
                    recommendations.push(
                        "Monitor for beaconing patterns in network traffic".to_string(),
                    );
                }
                MitreTactic::Exfiltration => {
                    recommendations.push(
                        "Deploy DLP and monitor large data transfers".to_string(),
                    );
                    recommendations.push(
                        "Monitor connections to cloud storage services".to_string(),
                    );
                }
                MitreTactic::Impact => {
                    recommendations.push(
                        "Enable ransomware detection and file entropy monitoring".to_string(),
                    );
                    recommendations.push(
                        "Deploy backup integrity monitoring".to_string(),
                    );
                }
                _ => {}
            }
        }

        // Based on detection sources
        for source in &technique.detection_sources {
            let source_lower = source.to_lowercase();
            if source_lower.contains("log") {
                recommendations.push(format!(
                    "Ensure '{}' logging is enabled and forwarded to SIEM",
                    source
                ));
            }
            if source_lower.contains("network") {
                recommendations.push(format!(
                    "Deploy network monitoring for '{}' events",
                    source
                ));
            }
        }

        // Remove duplicates
        recommendations.sort();
        recommendations.dedup();

        recommendations
    }

    /// Calculate severity for a detection gap
    fn calculate_gap_severity(&self, technique: &super::types::AttackTechnique) -> u8 {
        let mut severity: u8 = technique.risk_level / 2; // Base on risk level

        // Increase severity for critical tactics
        for tactic in &technique.tactics {
            match tactic {
                MitreTactic::CredentialAccess => severity = severity.saturating_add(1),
                MitreTactic::LateralMovement => severity = severity.saturating_add(1),
                MitreTactic::Impact => severity = severity.saturating_add(2),
                MitreTactic::Exfiltration => severity = severity.saturating_add(1),
                _ => {}
            }
        }

        severity.min(5) // Cap at 5
    }

    /// Get detection coverage statistics
    pub fn get_coverage_stats(&self, executions: &[TechniqueExecution]) -> DetectionCoverageStats {
        let total = executions.len();
        let detected = executions
            .iter()
            .filter(|e| {
                e.status == TechniqueExecutionStatus::Detected
                    || e.status == TechniqueExecutionStatus::Blocked
                    || e.detection_observed
            })
            .count();
        let blocked = executions
            .iter()
            .filter(|e| e.status == TechniqueExecutionStatus::Blocked)
            .count();
        let successful = executions
            .iter()
            .filter(|e| e.status == TechniqueExecutionStatus::Success && !e.detection_observed)
            .count();

        let mut tactic_coverage: HashMap<MitreTactic, (usize, usize)> = HashMap::new();

        for execution in executions {
            if let Some(technique) = self.library.get(&execution.technique_id) {
                for tactic in &technique.tactics {
                    let entry = tactic_coverage.entry(*tactic).or_insert((0, 0));
                    entry.0 += 1; // Total
                    if execution.detection_observed
                        || execution.status == TechniqueExecutionStatus::Detected
                        || execution.status == TechniqueExecutionStatus::Blocked
                    {
                        entry.1 += 1; // Detected
                    }
                }
            }
        }

        DetectionCoverageStats {
            total_techniques: total,
            detected,
            blocked,
            successful_undetected: successful,
            detection_rate: if total > 0 {
                detected as f64 / total as f64
            } else {
                0.0
            },
            block_rate: if total > 0 {
                blocked as f64 / total as f64
            } else {
                0.0
            },
            tactic_coverage: tactic_coverage
                .into_iter()
                .map(|(t, (total, detected))| {
                    (
                        t,
                        if total > 0 {
                            detected as f64 / total as f64
                        } else {
                            0.0
                        },
                    )
                })
                .collect(),
        }
    }

    /// Clear cached results
    pub fn clear_cache(&self) {
        self.results.write().unwrap().clear();
    }
}

impl Default for DetectionValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Detection coverage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionCoverageStats {
    pub total_techniques: usize,
    pub detected: usize,
    pub blocked: usize,
    pub successful_undetected: usize,
    pub detection_rate: f64,
    pub block_rate: f64,
    pub tactic_coverage: HashMap<MitreTactic, f64>,
}

/// Simple random function for simulation purposes
fn rand_simple(probability: f64) -> bool {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as f64
        / 1_000_000_000.0;
    seed < probability
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_result() {
        let result = DetectionResult::detected("EDR")
            .with_alert("ALERT-123", "High")
            .with_latency(150);

        assert!(result.detected);
        assert_eq!(result.source, Some("EDR".to_string()));
        assert_eq!(result.alert_id, Some("ALERT-123".to_string()));
        assert_eq!(result.detection_latency_ms, Some(150));
    }

    #[test]
    fn test_detection_validator_creation() {
        let validator = DetectionValidator::new();
        assert!(!validator.sources.is_empty());
    }

    #[test]
    fn test_coverage_stats() {
        let validator = DetectionValidator::new();
        let executions = vec![
            {
                let mut e = TechniqueExecution::new("1", "sim1", "T1059.001");
                e.status = TechniqueExecutionStatus::Detected;
                e.detection_observed = true;
                e
            },
            {
                let mut e = TechniqueExecution::new("2", "sim1", "T1082");
                e.status = TechniqueExecutionStatus::Success;
                e.detection_observed = false;
                e
            },
            {
                let mut e = TechniqueExecution::new("3", "sim1", "T1055");
                e.status = TechniqueExecutionStatus::Blocked;
                e
            },
        ];

        let stats = validator.get_coverage_stats(&executions);
        assert_eq!(stats.total_techniques, 3);
        assert_eq!(stats.detected, 2); // Detected + Blocked
        assert_eq!(stats.blocked, 1);
        assert_eq!(stats.successful_undetected, 1);
    }

    #[test]
    fn test_identify_gaps() {
        let validator = DetectionValidator::new();
        let executions = vec![
            {
                let mut e = TechniqueExecution::new("1", "sim1", "T1059.001");
                e.status = TechniqueExecutionStatus::Success;
                e.detection_observed = false;
                e
            },
        ];

        let gaps = validator.identify_gaps(&executions, "sim1");
        assert!(!gaps.is_empty());
        assert_eq!(gaps[0].technique_id, "T1059.001");
    }
}
