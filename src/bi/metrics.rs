//! Business intelligence metrics

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Core security operations metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Mean Time To Detect (hours) - Average time from threat occurrence to detection
    pub mttd: f64,
    /// Mean Time To Respond (hours) - Average time from detection to response initiation
    pub mttr: f64,
    /// Mean Time To Contain (hours) - Average time from detection to threat containment
    pub mttc: f64,
    /// Mean Time To Remediate (hours) - Average time from detection to full remediation
    pub mttr_remediate: f64,
    /// Average time vulnerabilities remain unpatched (days)
    pub vulnerability_dwell_time: f64,
    /// Percentage of systems with up-to-date patches (0.0 - 100.0)
    pub patch_compliance_rate: f64,
    /// Overall security posture score (0.0 - 100.0)
    pub security_score: f64,
    /// Number of active threats/incidents
    pub active_threats: u32,
    /// Number of vulnerabilities by severity
    pub vulnerability_counts: VulnerabilityCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnerabilityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub informational: u32,
}

/// Detection event with occurrence and detection timestamps
#[derive(Debug, Clone)]
pub struct DetectionEvent {
    /// When the threat actually occurred (if known)
    pub occurrence_time: DateTime<Utc>,
    /// When the threat was detected
    pub detection_time: DateTime<Utc>,
}

/// Incident with timestamps for various response phases
#[derive(Debug, Clone)]
pub struct IncidentTimeline {
    /// When the incident was detected
    pub detected_at: DateTime<Utc>,
    /// When response was initiated (first responder acknowledged)
    pub responded_at: Option<DateTime<Utc>>,
    /// When the threat was contained
    pub contained_at: Option<DateTime<Utc>>,
    /// When remediation was completed
    pub remediated_at: Option<DateTime<Utc>>,
}

/// Vulnerability with discovery and remediation timestamps
#[derive(Debug, Clone)]
pub struct VulnerabilityLifecycle {
    /// When the vulnerability was discovered
    pub discovered_at: DateTime<Utc>,
    /// When the vulnerability was remediated (None if still open)
    pub remediated_at: Option<DateTime<Utc>>,
    /// Severity level
    pub severity: VulnerabilitySeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// Patch compliance data for a system
#[derive(Debug, Clone)]
pub struct SystemPatchStatus {
    /// System identifier
    pub system_id: String,
    /// Total patches applicable
    pub total_patches: u32,
    /// Patches applied
    pub applied_patches: u32,
    /// Whether the system is considered compliant
    pub is_compliant: bool,
}

pub struct MetricsCalculator {}

impl MetricsCalculator {
    pub fn new() -> Self {
        Self {}
    }

    /// Calculate Mean Time to Detect (MTTD) in hours
    ///
    /// MTTD measures the average time between when a threat occurs and when it is detected.
    /// Lower values indicate better detection capabilities.
    pub fn calculate_mttd(&self, detections: &[(DateTime<Utc>, DateTime<Utc>)]) -> f64 {
        if detections.is_empty() {
            return 0.0;
        }

        let total_hours: f64 = detections
            .iter()
            .map(|(occurrence, detection)| {
                let duration = *detection - *occurrence;
                duration.num_seconds() as f64 / 3600.0
            })
            .filter(|&hours| hours >= 0.0) // Filter out invalid negative durations
            .sum();

        let valid_count = detections
            .iter()
            .filter(|(occurrence, detection)| detection >= occurrence)
            .count();

        if valid_count == 0 {
            return 0.0;
        }

        total_hours / valid_count as f64
    }

    /// Calculate Mean Time to Detect from DetectionEvent structs
    pub fn calculate_mttd_from_events(&self, events: &[DetectionEvent]) -> f64 {
        let pairs: Vec<(DateTime<Utc>, DateTime<Utc>)> = events
            .iter()
            .map(|e| (e.occurrence_time, e.detection_time))
            .collect();
        self.calculate_mttd(&pairs)
    }

    /// Calculate Mean Time to Respond (MTTR) in hours
    ///
    /// MTTR measures the average time between detection and response initiation.
    /// Lower values indicate faster incident response.
    pub fn calculate_mttr(&self, incidents: &[(DateTime<Utc>, DateTime<Utc>)]) -> f64 {
        if incidents.is_empty() {
            return 0.0;
        }

        let total_hours: f64 = incidents
            .iter()
            .map(|(detection, response)| {
                let duration = *response - *detection;
                duration.num_seconds() as f64 / 3600.0
            })
            .filter(|&hours| hours >= 0.0)
            .sum();

        let valid_count = incidents
            .iter()
            .filter(|(detection, response)| response >= detection)
            .count();

        if valid_count == 0 {
            return 0.0;
        }

        total_hours / valid_count as f64
    }

    /// Calculate Mean Time to Contain (MTTC) in hours
    ///
    /// MTTC measures the average time from detection to threat containment.
    pub fn calculate_mttc(&self, incidents: &[IncidentTimeline]) -> f64 {
        let contained_incidents: Vec<_> = incidents
            .iter()
            .filter_map(|inc| inc.contained_at.map(|c| (inc.detected_at, c)))
            .collect();

        if contained_incidents.is_empty() {
            return 0.0;
        }

        let total_hours: f64 = contained_incidents
            .iter()
            .map(|(detected, contained)| {
                let duration = *contained - *detected;
                duration.num_seconds() as f64 / 3600.0
            })
            .filter(|&hours| hours >= 0.0)
            .sum();

        total_hours / contained_incidents.len() as f64
    }

    /// Calculate Mean Time to Remediate in hours
    pub fn calculate_mttr_remediate(&self, incidents: &[IncidentTimeline]) -> f64 {
        let remediated_incidents: Vec<_> = incidents
            .iter()
            .filter_map(|inc| inc.remediated_at.map(|r| (inc.detected_at, r)))
            .collect();

        if remediated_incidents.is_empty() {
            return 0.0;
        }

        let total_hours: f64 = remediated_incidents
            .iter()
            .map(|(detected, remediated)| {
                let duration = *remediated - *detected;
                duration.num_seconds() as f64 / 3600.0
            })
            .filter(|&hours| hours >= 0.0)
            .sum();

        total_hours / remediated_incidents.len() as f64
    }

    /// Calculate vulnerability dwell time in days
    ///
    /// Measures how long vulnerabilities remain unpatched on average.
    /// For open vulnerabilities, calculates time from discovery to now.
    pub fn calculate_vulnerability_dwell_time(&self, vulnerabilities: &[VulnerabilityLifecycle]) -> f64 {
        if vulnerabilities.is_empty() {
            return 0.0;
        }

        let now = Utc::now();
        let total_days: f64 = vulnerabilities
            .iter()
            .map(|vuln| {
                let end_time = vuln.remediated_at.unwrap_or(now);
                let duration = end_time - vuln.discovered_at;
                duration.num_seconds() as f64 / 86400.0 // Convert to days
            })
            .filter(|&days| days >= 0.0)
            .sum();

        total_days / vulnerabilities.len() as f64
    }

    /// Calculate weighted vulnerability dwell time based on severity
    ///
    /// Critical vulnerabilities are weighted more heavily than lower severity ones.
    pub fn calculate_weighted_dwell_time(&self, vulnerabilities: &[VulnerabilityLifecycle]) -> f64 {
        if vulnerabilities.is_empty() {
            return 0.0;
        }

        let now = Utc::now();
        let (weighted_sum, weight_total): (f64, f64) = vulnerabilities
            .iter()
            .map(|vuln| {
                let end_time = vuln.remediated_at.unwrap_or(now);
                let duration = end_time - vuln.discovered_at;
                let days = duration.num_seconds() as f64 / 86400.0;
                let weight = match vuln.severity {
                    VulnerabilitySeverity::Critical => 5.0,
                    VulnerabilitySeverity::High => 4.0,
                    VulnerabilitySeverity::Medium => 3.0,
                    VulnerabilitySeverity::Low => 2.0,
                    VulnerabilitySeverity::Informational => 1.0,
                };
                (days.max(0.0) * weight, weight)
            })
            .fold((0.0, 0.0), |acc, (weighted_days, weight)| {
                (acc.0 + weighted_days, acc.1 + weight)
            });

        if weight_total == 0.0 {
            return 0.0;
        }

        weighted_sum / weight_total
    }

    /// Calculate patch compliance rate as a percentage (0.0 - 100.0)
    pub fn calculate_patch_compliance_rate(&self, systems: &[SystemPatchStatus]) -> f64 {
        if systems.is_empty() {
            return 100.0; // No systems = fully compliant
        }

        let compliant_count = systems.iter().filter(|s| s.is_compliant).count();
        (compliant_count as f64 / systems.len() as f64) * 100.0
    }

    /// Calculate detailed patch compliance rate based on individual patches
    pub fn calculate_patch_rate_detailed(&self, systems: &[SystemPatchStatus]) -> f64 {
        if systems.is_empty() {
            return 100.0;
        }

        let total_patches: u32 = systems.iter().map(|s| s.total_patches).sum();
        let applied_patches: u32 = systems.iter().map(|s| s.applied_patches).sum();

        if total_patches == 0 {
            return 100.0;
        }

        (applied_patches as f64 / total_patches as f64) * 100.0
    }

    /// Count vulnerabilities by severity
    pub fn count_vulnerabilities(&self, vulnerabilities: &[VulnerabilityLifecycle]) -> VulnerabilityCounts {
        let mut counts = VulnerabilityCounts::default();

        for vuln in vulnerabilities {
            // Only count open vulnerabilities
            if vuln.remediated_at.is_none() {
                match vuln.severity {
                    VulnerabilitySeverity::Critical => counts.critical += 1,
                    VulnerabilitySeverity::High => counts.high += 1,
                    VulnerabilitySeverity::Medium => counts.medium += 1,
                    VulnerabilitySeverity::Low => counts.low += 1,
                    VulnerabilitySeverity::Informational => counts.informational += 1,
                }
            }
        }

        counts
    }

    /// Calculate overall security score (0.0 - 100.0)
    ///
    /// Composite score based on multiple factors:
    /// - Patch compliance (weight: 25%)
    /// - Vulnerability severity distribution (weight: 35%)
    /// - MTTD/MTTR performance (weight: 20%)
    /// - Active threat count (weight: 20%)
    pub fn calculate_security_score(
        &self,
        patch_compliance: f64,
        vulnerability_counts: &VulnerabilityCounts,
        mttd_hours: f64,
        mttr_hours: f64,
        active_threats: u32,
    ) -> f64 {
        // Patch compliance score (0-100)
        let patch_score = patch_compliance.min(100.0).max(0.0);

        // Vulnerability score - penalize based on open vulnerabilities
        // Using weighted scoring: critical=10, high=5, medium=2, low=0.5, info=0.1
        let vuln_penalty = (vulnerability_counts.critical as f64 * 10.0)
            + (vulnerability_counts.high as f64 * 5.0)
            + (vulnerability_counts.medium as f64 * 2.0)
            + (vulnerability_counts.low as f64 * 0.5)
            + (vulnerability_counts.informational as f64 * 0.1);
        // Convert to 0-100 scale (assuming max reasonable penalty of 200)
        let vuln_score = (100.0 - (vuln_penalty / 2.0).min(100.0)).max(0.0);

        // Response metrics score
        // Target MTTD: < 1 hour = 100, > 24 hours = 0
        let mttd_score = if mttd_hours <= 0.0 {
            100.0
        } else {
            (100.0 - (mttd_hours / 24.0 * 100.0)).max(0.0)
        };
        // Target MTTR: < 4 hours = 100, > 48 hours = 0
        let mttr_score = if mttr_hours <= 0.0 {
            100.0
        } else {
            (100.0 - (mttr_hours / 48.0 * 100.0)).max(0.0)
        };
        let response_score = (mttd_score + mttr_score) / 2.0;

        // Active threats penalty
        // 0 threats = 100, 10+ threats = 0
        let threat_score = (100.0 - (active_threats as f64 * 10.0)).max(0.0);

        // Weighted average
        (patch_score * 0.25)
            + (vuln_score * 0.35)
            + (response_score * 0.20)
            + (threat_score * 0.20)
    }

    /// Calculate comprehensive security metrics from all available data
    pub fn calculate_all_metrics(
        &self,
        detection_events: &[DetectionEvent],
        incidents: &[IncidentTimeline],
        vulnerabilities: &[VulnerabilityLifecycle],
        patch_status: &[SystemPatchStatus],
        active_threats: u32,
    ) -> SecurityMetrics {
        let mttd = self.calculate_mttd_from_events(detection_events);

        let response_pairs: Vec<_> = incidents
            .iter()
            .filter_map(|inc| inc.responded_at.map(|r| (inc.detected_at, r)))
            .collect();
        let mttr = self.calculate_mttr(&response_pairs);

        let mttc = self.calculate_mttc(incidents);
        let mttr_remediate = self.calculate_mttr_remediate(incidents);
        let vulnerability_dwell_time = self.calculate_vulnerability_dwell_time(vulnerabilities);
        let patch_compliance_rate = self.calculate_patch_compliance_rate(patch_status);
        let vulnerability_counts = self.count_vulnerabilities(vulnerabilities);

        let security_score = self.calculate_security_score(
            patch_compliance_rate,
            &vulnerability_counts,
            mttd,
            mttr,
            active_threats,
        );

        SecurityMetrics {
            mttd,
            mttr,
            mttc,
            mttr_remediate,
            vulnerability_dwell_time,
            patch_compliance_rate,
            security_score,
            active_threats,
            vulnerability_counts,
        }
    }
}

impl Default for MetricsCalculator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_calculate_mttd() {
        let calculator = MetricsCalculator::new();
        let now = Utc::now();

        // 2-hour detection time
        let detections = vec![
            (now - Duration::hours(10), now - Duration::hours(8)), // 2 hours
            (now - Duration::hours(6), now - Duration::hours(4)),  // 2 hours
            (now - Duration::hours(4), now - Duration::hours(2)),  // 2 hours
        ];

        let mttd = calculator.calculate_mttd(&detections);
        assert!((mttd - 2.0).abs() < 0.01, "Expected MTTD of ~2 hours, got {}", mttd);
    }

    #[test]
    fn test_calculate_mttd_empty() {
        let calculator = MetricsCalculator::new();
        let mttd = calculator.calculate_mttd(&[]);
        assert_eq!(mttd, 0.0);
    }

    #[test]
    fn test_calculate_mttr() {
        let calculator = MetricsCalculator::new();
        let now = Utc::now();

        let incidents = vec![
            (now - Duration::hours(5), now - Duration::hours(4)), // 1 hour
            (now - Duration::hours(4), now - Duration::hours(2)), // 2 hours
            (now - Duration::hours(3), now - Duration::hours(0)), // 3 hours
        ];

        let mttr = calculator.calculate_mttr(&incidents);
        assert!((mttr - 2.0).abs() < 0.01, "Expected MTTR of ~2 hours, got {}", mttr);
    }

    #[test]
    fn test_calculate_patch_compliance() {
        let calculator = MetricsCalculator::new();

        let systems = vec![
            SystemPatchStatus {
                system_id: "sys1".to_string(),
                total_patches: 10,
                applied_patches: 10,
                is_compliant: true,
            },
            SystemPatchStatus {
                system_id: "sys2".to_string(),
                total_patches: 10,
                applied_patches: 8,
                is_compliant: false,
            },
            SystemPatchStatus {
                system_id: "sys3".to_string(),
                total_patches: 10,
                applied_patches: 10,
                is_compliant: true,
            },
        ];

        let rate = calculator.calculate_patch_compliance_rate(&systems);
        assert!((rate - 66.67).abs() < 0.1, "Expected ~66.67%, got {}", rate);
    }

    #[test]
    fn test_calculate_security_score() {
        let calculator = MetricsCalculator::new();

        let vuln_counts = VulnerabilityCounts {
            critical: 0,
            high: 2,
            medium: 5,
            low: 10,
            informational: 20,
        };

        let score = calculator.calculate_security_score(
            95.0,  // 95% patch compliance
            &vuln_counts,
            0.5,   // 30-minute MTTD
            2.0,   // 2-hour MTTR
            1,     // 1 active threat
        );

        // Score should be reasonably high with these metrics
        assert!(score > 70.0, "Expected score > 70, got {}", score);
        assert!(score < 100.0, "Expected score < 100, got {}", score);
    }

    #[test]
    fn test_vulnerability_counts() {
        let calculator = MetricsCalculator::new();
        let now = Utc::now();

        let vulnerabilities = vec![
            VulnerabilityLifecycle {
                discovered_at: now - Duration::days(5),
                remediated_at: None,
                severity: VulnerabilitySeverity::Critical,
            },
            VulnerabilityLifecycle {
                discovered_at: now - Duration::days(10),
                remediated_at: Some(now - Duration::days(2)),
                severity: VulnerabilitySeverity::High,
            },
            VulnerabilityLifecycle {
                discovered_at: now - Duration::days(3),
                remediated_at: None,
                severity: VulnerabilitySeverity::Medium,
            },
        ];

        let counts = calculator.count_vulnerabilities(&vulnerabilities);
        assert_eq!(counts.critical, 1);
        assert_eq!(counts.high, 0); // Remediated, so not counted
        assert_eq!(counts.medium, 1);
    }
}
