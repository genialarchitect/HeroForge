//! Compliance Analyzer (Option C - Hybrid Mode)
//!
//! Post-scan compliance analysis that maps discovered vulnerabilities
//! to compliance controls and runs supplemental compliance-specific checks.

use crate::compliance::controls::mapping::VulnerabilityMapper;
use crate::compliance::controls::{run_compliance_checks, check_results_to_findings};
use crate::compliance::frameworks;
use crate::compliance::scoring::calculate_compliance_score;
use crate::compliance::types::{
    ComplianceFinding, ComplianceFramework, ComplianceSummary, ControlStatus,
    FrameworkSummary, CategorySummary,
};
use crate::types::HostInfo;
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use log::info;

/// Compliance Analyzer for post-scan analysis
pub struct ComplianceAnalyzer {
    /// Frameworks to analyze against
    frameworks: Vec<ComplianceFramework>,
    /// Vulnerability mapper
    mapper: VulnerabilityMapper,
}

impl ComplianceAnalyzer {
    /// Create a new analyzer for the specified frameworks
    pub fn new(frameworks: Vec<ComplianceFramework>) -> Self {
        let mapper = VulnerabilityMapper::new(frameworks.clone());
        Self { frameworks, mapper }
    }

    /// Analyze scan results for compliance
    pub async fn analyze(&self, hosts: &[HostInfo], scan_id: &str) -> Result<ComplianceSummary> {
        info!(
            "Starting compliance analysis for scan {} against {} frameworks",
            scan_id,
            self.frameworks.len()
        );

        let mut all_findings = Vec::new();

        // Phase 1: Map vulnerabilities to compliance controls
        info!("Phase 1: Mapping vulnerabilities to compliance controls");
        let vuln_findings = self.mapper.map_vulnerabilities(hosts, scan_id);
        all_findings.extend(vuln_findings);

        // Phase 2: Run direct compliance checks on each host
        info!("Phase 2: Running direct compliance checks");
        for host in hosts {
            let check_results = run_compliance_checks(host, &self.frameworks);
            let check_findings = check_results_to_findings(check_results, scan_id, &host.target.ip.to_string());
            all_findings.extend(check_findings);
        }

        // Deduplicate findings by control
        let deduplicated = self.deduplicate_findings(all_findings);

        // Generate summary
        let summary = self.generate_summary(scan_id, &deduplicated);

        info!(
            "Compliance analysis complete: {} findings, overall score: {:.1}%",
            summary.total_findings,
            summary.overall_score
        );

        Ok(summary)
    }

    /// Deduplicate findings, keeping the worst status for each control
    fn deduplicate_findings(&self, findings: Vec<ComplianceFinding>) -> Vec<ComplianceFinding> {
        let mut by_control: HashMap<(ComplianceFramework, String), ComplianceFinding> = HashMap::new();

        for finding in findings {
            let key = (finding.framework, finding.control_id.clone());

            if let Some(existing) = by_control.get_mut(&key) {
                // Merge findings: combine affected hosts, ports, and evidence
                for host in &finding.affected_hosts {
                    if !existing.affected_hosts.contains(host) {
                        existing.affected_hosts.push(host.clone());
                    }
                }
                for port in &finding.affected_ports {
                    if !existing.affected_ports.contains(port) {
                        existing.affected_ports.push(*port);
                    }
                }
                for evidence in &finding.evidence {
                    if !existing.evidence.contains(evidence) {
                        existing.evidence.push(evidence.clone());
                    }
                }
                // Keep higher severity
                if finding.severity > existing.severity {
                    existing.severity = finding.severity;
                }
                existing.updated_at = Utc::now();
            } else {
                by_control.insert(key, finding);
            }
        }

        by_control.into_values().collect()
    }

    /// Generate compliance summary from findings
    fn generate_summary(&self, scan_id: &str, findings: &[ComplianceFinding]) -> ComplianceSummary {
        let mut framework_summaries = Vec::new();

        for framework in &self.frameworks {
            let framework_findings: Vec<_> = findings
                .iter()
                .filter(|f| &f.framework == framework)
                .collect();

            let framework_summary = self.summarize_framework(*framework, &framework_findings);
            framework_summaries.push(framework_summary);
        }

        // Calculate overall score
        let overall_score = if framework_summaries.is_empty() {
            100.0
        } else {
            let total_weighted: f32 = framework_summaries
                .iter()
                .map(|s| s.compliance_score * s.total_controls as f32)
                .sum();
            let total_controls: usize = framework_summaries.iter().map(|s| s.total_controls).sum();
            if total_controls > 0 {
                total_weighted / total_controls as f32
            } else {
                100.0
            }
        };

        // Count findings by severity
        let critical_findings = findings
            .iter()
            .filter(|f| f.severity == crate::types::Severity::Critical && f.status == ControlStatus::NonCompliant)
            .count();
        let high_findings = findings
            .iter()
            .filter(|f| f.severity == crate::types::Severity::High && f.status == ControlStatus::NonCompliant)
            .count();
        let medium_findings = findings
            .iter()
            .filter(|f| f.severity == crate::types::Severity::Medium && f.status == ControlStatus::NonCompliant)
            .count();
        let low_findings = findings
            .iter()
            .filter(|f| f.severity == crate::types::Severity::Low && f.status == ControlStatus::NonCompliant)
            .count();

        ComplianceSummary {
            scan_id: scan_id.to_string(),
            frameworks: framework_summaries,
            overall_score,
            total_findings: findings.len(),
            critical_findings,
            high_findings,
            medium_findings,
            low_findings,
            generated_at: Utc::now(),
        }
    }

    /// Summarize compliance status for a single framework
    fn summarize_framework(
        &self,
        framework: ComplianceFramework,
        findings: &[&ComplianceFinding],
    ) -> FrameworkSummary {
        let all_controls = frameworks::get_controls(framework);
        let total_controls = all_controls.len();

        // Build map of control statuses from findings
        let mut control_statuses: HashMap<String, ControlStatus> = HashMap::new();
        for finding in findings {
            let current = control_statuses.get(&finding.control_id).cloned();
            let new_status = match current {
                Some(ControlStatus::NonCompliant) => ControlStatus::NonCompliant,
                Some(ControlStatus::PartiallyCompliant) if finding.status == ControlStatus::NonCompliant => {
                    ControlStatus::NonCompliant
                }
                _ => finding.status,
            };
            control_statuses.insert(finding.control_id.clone(), new_status);
        }

        // Count statuses
        let mut compliant = 0;
        let mut non_compliant = 0;
        let mut partially_compliant = 0;
        let mut not_applicable = 0;
        let mut not_assessed = 0;
        let mut manual_overrides = 0;

        for control in &all_controls {
            match control_statuses.get(&control.control_id) {
                Some(ControlStatus::Compliant) => compliant += 1,
                Some(ControlStatus::NonCompliant) => non_compliant += 1,
                Some(ControlStatus::PartiallyCompliant) => partially_compliant += 1,
                Some(ControlStatus::NotApplicable) => not_applicable += 1,
                Some(ControlStatus::ManualOverride) => manual_overrides += 1,
                Some(ControlStatus::NotAssessed) | None => {
                    // Control not assessed by scan
                    if control.automated_check {
                        // Automated control not flagged = likely compliant
                        compliant += 1;
                    } else {
                        // Manual control = not assessed
                        not_assessed += 1;
                    }
                }
            }
        }

        // Calculate score excluding not assessed and not applicable
        let assessable = total_controls - not_assessed - not_applicable;
        let compliance_score = if assessable > 0 {
            ((compliant as f32 + (partially_compliant as f32 * 0.5)) / assessable as f32) * 100.0
        } else {
            100.0
        };

        // Generate category breakdown
        let categories = frameworks::get_categories(framework);
        let by_category: Vec<CategorySummary> = categories
            .iter()
            .map(|cat| {
                let cat_controls: Vec<_> = all_controls
                    .iter()
                    .filter(|c| &c.category == cat)
                    .collect();
                let cat_total = cat_controls.len();
                let cat_compliant = cat_controls
                    .iter()
                    .filter(|c| {
                        control_statuses.get(&c.control_id) != Some(&ControlStatus::NonCompliant)
                            && control_statuses.get(&c.control_id) != Some(&ControlStatus::PartiallyCompliant)
                    })
                    .count();
                let cat_non_compliant = cat_controls
                    .iter()
                    .filter(|c| {
                        control_statuses.get(&c.control_id) == Some(&ControlStatus::NonCompliant)
                    })
                    .count();

                CategorySummary {
                    category: cat.clone(),
                    total: cat_total,
                    compliant: cat_compliant,
                    non_compliant: cat_non_compliant,
                    percentage: if cat_total > 0 {
                        (cat_compliant as f32 / cat_total as f32) * 100.0
                    } else {
                        100.0
                    },
                }
            })
            .collect();

        FrameworkSummary {
            framework,
            total_controls,
            compliant,
            non_compliant,
            partially_compliant,
            not_applicable,
            not_assessed,
            manual_overrides,
            compliance_score,
            by_category,
        }
    }

    /// Get findings for a specific framework
    pub fn get_framework_findings<'a>(
        findings: &'a [ComplianceFinding],
        framework: ComplianceFramework,
    ) -> Vec<&'a ComplianceFinding> {
        findings
            .iter()
            .filter(|f| f.framework == framework)
            .collect()
    }

    /// Get findings by status
    pub fn get_findings_by_status<'a>(
        findings: &'a [ComplianceFinding],
        status: ControlStatus,
    ) -> Vec<&'a ComplianceFinding> {
        findings
            .iter()
            .filter(|f| f.status == status)
            .collect()
    }

    /// Get findings for a specific host
    pub fn get_host_findings<'a>(
        findings: &'a [ComplianceFinding],
        host_ip: &str,
    ) -> Vec<&'a ComplianceFinding> {
        findings
            .iter()
            .filter(|f| f.affected_hosts.contains(&host_ip.to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = ComplianceAnalyzer::new(vec![
            ComplianceFramework::PciDss4,
            ComplianceFramework::CisBenchmarks,
        ]);
        assert_eq!(analyzer.frameworks.len(), 2);
    }

    #[tokio::test]
    async fn test_analyze_empty_hosts() {
        let analyzer = ComplianceAnalyzer::new(vec![ComplianceFramework::PciDss4]);
        let result = analyzer.analyze(&[], "test-scan").await;
        assert!(result.is_ok());
        let summary = result.unwrap();
        assert_eq!(summary.total_findings, 0);
    }
}
