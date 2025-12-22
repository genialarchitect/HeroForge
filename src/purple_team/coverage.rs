//! Detection coverage calculation

use std::collections::HashMap;
use chrono::Utc;
use uuid::Uuid;

use super::types::*;
use super::mitre_attack::MitreMapper;

/// Calculates detection coverage from exercise results
pub struct CoverageCalculator {
    mapper: MitreMapper,
}

impl CoverageCalculator {
    pub fn new() -> Self {
        Self {
            mapper: MitreMapper::new(),
        }
    }

    /// Calculate detection coverage for an exercise
    pub fn calculate_coverage(
        &self,
        exercise_id: &str,
        results: &[PurpleAttackResult],
    ) -> DetectionCoverage {
        let by_tactic = self.calculate_tactic_coverage(results);
        let by_technique = self.calculate_technique_coverage(results);
        let overall_score = self.calculate_overall_score(results);

        DetectionCoverage {
            id: Uuid::new_v4().to_string(),
            exercise_id: exercise_id.to_string(),
            by_tactic,
            by_technique,
            overall_score,
            calculated_at: Utc::now(),
        }
    }

    /// Calculate coverage by tactic
    fn calculate_tactic_coverage(
        &self,
        results: &[PurpleAttackResult],
    ) -> HashMap<String, TacticCoverage> {
        let mut coverage_map: HashMap<String, TacticCoverage> = HashMap::new();

        // Group results by tactic
        for result in results {
            let tactic_id = result.tactic.id().to_string();
            let tactic_name = result.tactic.name().to_string();

            let entry = coverage_map.entry(tactic_id.clone()).or_insert_with(|| {
                TacticCoverage {
                    tactic_id: tactic_id.clone(),
                    tactic_name,
                    total_techniques: 0,
                    detected: 0,
                    partially_detected: 0,
                    not_detected: 0,
                    coverage_percent: 0.0,
                }
            });

            entry.total_techniques += 1;

            match result.detection_status {
                DetectionStatus::Detected => entry.detected += 1,
                DetectionStatus::PartiallyDetected => entry.partially_detected += 1,
                DetectionStatus::NotDetected => entry.not_detected += 1,
                DetectionStatus::Pending => {}
            }
        }

        // Calculate percentages
        for coverage in coverage_map.values_mut() {
            if coverage.total_techniques > 0 {
                let detected_weight = coverage.detected as f32;
                let partial_weight = coverage.partially_detected as f32 * 0.5;
                coverage.coverage_percent =
                    (detected_weight + partial_weight) / coverage.total_techniques as f32 * 100.0;
            }
        }

        coverage_map
    }

    /// Calculate coverage by technique
    fn calculate_technique_coverage(
        &self,
        results: &[PurpleAttackResult],
    ) -> HashMap<String, TechniqueCoverage> {
        let mut coverage_map: HashMap<String, TechniqueCoverage> = HashMap::new();

        // Group results by technique
        for result in results {
            let entry = coverage_map.entry(result.technique_id.clone()).or_insert_with(|| {
                TechniqueCoverage {
                    technique_id: result.technique_id.clone(),
                    technique_name: result.technique_name.clone(),
                    tactic: result.tactic.name().to_string(),
                    tests_run: 0,
                    detected: 0,
                    partially_detected: 0,
                    not_detected: 0,
                    coverage_percent: 0.0,
                    avg_time_to_detect_ms: None,
                }
            });

            entry.tests_run += 1;

            match result.detection_status {
                DetectionStatus::Detected => entry.detected += 1,
                DetectionStatus::PartiallyDetected => entry.partially_detected += 1,
                DetectionStatus::NotDetected => entry.not_detected += 1,
                DetectionStatus::Pending => {}
            }
        }

        // Calculate percentages and average detection time
        for coverage in coverage_map.values_mut() {
            if coverage.tests_run > 0 {
                let detected_weight = coverage.detected as f32;
                let partial_weight = coverage.partially_detected as f32 * 0.5;
                coverage.coverage_percent =
                    (detected_weight + partial_weight) / coverage.tests_run as f32 * 100.0;
            }

            // Calculate average time to detect
            let detection_times: Vec<i64> = results.iter()
                .filter(|r| r.technique_id == coverage.technique_id && r.time_to_detect_ms.is_some())
                .filter_map(|r| r.time_to_detect_ms)
                .collect();

            if !detection_times.is_empty() {
                coverage.avg_time_to_detect_ms = Some(
                    detection_times.iter().sum::<i64>() / detection_times.len() as i64
                );
            }
        }

        coverage_map
    }

    /// Calculate overall detection score
    fn calculate_overall_score(&self, results: &[PurpleAttackResult]) -> f32 {
        if results.is_empty() {
            return 0.0;
        }

        let mut total_score = 0.0;

        for result in results {
            total_score += match result.detection_status {
                DetectionStatus::Detected => 1.0,
                DetectionStatus::PartiallyDetected => 0.5,
                DetectionStatus::NotDetected => 0.0,
                DetectionStatus::Pending => 0.0,
            };
        }

        (total_score / results.len() as f32) * 100.0
    }

    /// Build ATT&CK matrix visualization data
    pub fn build_attack_matrix(
        &self,
        results: &[PurpleAttackResult],
    ) -> AttackMatrix {
        let all_techniques = self.mapper.all_techniques();
        let total_techniques = all_techniques.len();
        let technique_coverage = self.calculate_technique_coverage(results);

        let mut cells: HashMap<String, Vec<MatrixCell>> = HashMap::new();
        let mut tested_count = 0;

        // Initialize cells for each tactic
        for tactic in MitreTactic::all() {
            cells.insert(tactic.name().to_string(), Vec::new());
        }

        // Populate cells
        for technique in &all_techniques {
            let coverage = technique_coverage.get(&technique.id);
            let tested = coverage.is_some();

            if tested {
                tested_count += 1;
            }

            let cell = MatrixCell {
                technique_id: technique.id.clone(),
                technique_name: technique.name.clone(),
                tactic: technique.tactic.name().to_string(),
                tested,
                detection_status: if tested {
                    let c = coverage.unwrap();
                    if c.detected > 0 {
                        Some(DetectionStatus::Detected)
                    } else if c.partially_detected > 0 {
                        Some(DetectionStatus::PartiallyDetected)
                    } else {
                        Some(DetectionStatus::NotDetected)
                    }
                } else {
                    None
                },
                coverage_percent: coverage.map(|c| c.coverage_percent).unwrap_or(0.0),
                gap_severity: if let Some(c) = coverage {
                    if c.not_detected > 0 {
                        Some(self.severity_from_coverage(c.coverage_percent))
                    } else {
                        None
                    }
                } else {
                    None
                },
            };

            if let Some(tactic_cells) = cells.get_mut(technique.tactic.name()) {
                tactic_cells.push(cell);
            }
        }

        let overall_coverage = self.calculate_overall_score(results);

        AttackMatrix {
            tactics: MitreTactic::all().iter().map(|t| t.name().to_string()).collect(),
            cells,
            overall_coverage,
            tested_techniques: tested_count,
            total_techniques,
        }
    }

    fn severity_from_coverage(&self, coverage_percent: f32) -> GapSeverity {
        if coverage_percent < 25.0 {
            GapSeverity::Critical
        } else if coverage_percent < 50.0 {
            GapSeverity::High
        } else if coverage_percent < 75.0 {
            GapSeverity::Medium
        } else {
            GapSeverity::Low
        }
    }
}

impl Default for CoverageCalculator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(technique_id: &str, detection: DetectionStatus) -> PurpleAttackResult {
        PurpleAttackResult {
            id: Uuid::new_v4().to_string(),
            exercise_id: "test".to_string(),
            technique_id: technique_id.to_string(),
            technique_name: "Test Technique".to_string(),
            tactic: MitreTactic::CredentialAccess,
            attack_type: "test".to_string(),
            target: "10.0.0.1".to_string(),
            attack_status: AttackStatus::Executed,
            detection_status: detection,
            detection_details: None,
            time_to_detect_ms: Some(1000),
            executed_at: Utc::now(),
            error_message: None,
        }
    }

    #[test]
    fn test_coverage_calculation() {
        let calc = CoverageCalculator::new();
        let results = vec![
            make_result("T1558.003", DetectionStatus::Detected),
            make_result("T1558.004", DetectionStatus::NotDetected),
            make_result("T1110.003", DetectionStatus::PartiallyDetected),
        ];

        let coverage = calc.calculate_coverage("test", &results);

        // Overall score: 1 detected + 0.5 partial + 0 not detected = 1.5 / 3 = 50%
        assert!(coverage.overall_score >= 49.0 && coverage.overall_score <= 51.0);
    }
}
