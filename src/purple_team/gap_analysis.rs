//! Detection gap analysis and prioritization

use std::collections::HashMap;
use chrono::Utc;
use uuid::Uuid;

use super::types::*;
use super::mitre_attack::MitreMapper;
use super::coverage::CoverageCalculator;

/// Analyzes detection gaps from exercise results
pub struct GapAnalyzer {
    mapper: MitreMapper,
    coverage_calc: CoverageCalculator,
}

impl GapAnalyzer {
    pub fn new() -> Self {
        Self {
            mapper: MitreMapper::new(),
            coverage_calc: CoverageCalculator::new(),
        }
    }

    /// Identify all detection gaps from exercise results
    pub fn identify_gaps(
        &self,
        exercise_id: &str,
        results: &[PurpleAttackResult],
    ) -> Vec<DetectionGap> {
        let mut gaps = Vec::new();

        // Group results by technique
        let mut by_technique: HashMap<String, Vec<&PurpleAttackResult>> = HashMap::new();
        for result in results {
            by_technique.entry(result.technique_id.clone())
                .or_default()
                .push(result);
        }

        // Analyze each technique for gaps
        for (technique_id, technique_results) in by_technique {
            if let Some(gap) = self.analyze_technique_gap(exercise_id, &technique_id, &technique_results) {
                gaps.push(gap);
            }
        }

        // Sort by severity (critical first)
        gaps.sort_by(|a, b| {
            let a_priority = severity_priority(&a.severity);
            let b_priority = severity_priority(&b.severity);
            a_priority.cmp(&b_priority)
        });

        gaps
    }

    /// Analyze a specific technique for detection gaps
    fn analyze_technique_gap(
        &self,
        exercise_id: &str,
        technique_id: &str,
        results: &[&PurpleAttackResult],
    ) -> Option<DetectionGap> {
        // Calculate detection rate for this technique
        let total = results.len();
        let detected = results.iter()
            .filter(|r| r.detection_status == DetectionStatus::Detected)
            .count();
        let partially_detected = results.iter()
            .filter(|r| r.detection_status == DetectionStatus::PartiallyDetected)
            .count();
        let not_detected = results.iter()
            .filter(|r| r.detection_status == DetectionStatus::NotDetected)
            .count();

        // If fully detected, no gap
        if detected == total {
            return None;
        }

        // Determine severity based on detection rate and technique criticality
        let detection_rate = (detected as f32 + partially_detected as f32 * 0.5) / total as f32;
        let technique_criticality = self.get_technique_criticality(technique_id);
        let severity = self.calculate_gap_severity(detection_rate, technique_criticality);

        // Get technique info
        let first_result = results.first()?;
        let technique = self.mapper.get_technique(technique_id);

        // Generate recommendations
        let recommendations = self.generate_gap_recommendations(
            technique_id,
            &first_result.attack_type,
            detection_rate,
            technique,
        );

        Some(DetectionGap {
            id: Uuid::new_v4().to_string(),
            exercise_id: exercise_id.to_string(),
            technique_id: technique_id.to_string(),
            technique_name: first_result.technique_name.clone(),
            tactic: first_result.tactic,
            severity,
            recommendations,
            status: GapStatus::Open,
            created_at: Utc::now(),
            remediated_at: None,
        })
    }

    /// Get criticality score for a technique (1-5, 5 being most critical)
    fn get_technique_criticality(&self, technique_id: &str) -> u8 {
        // High criticality techniques - commonly exploited
        let critical_techniques = [
            "T1003",     // OS Credential Dumping
            "T1558",     // Steal or Forge Kerberos Tickets
            "T1110",     // Brute Force
            "T1557",     // Adversary-in-the-Middle
            "T1021",     // Remote Services
            "T1550",     // Use Alternate Authentication Material
            "T1548",     // Abuse Elevation Control Mechanism
            "T1068",     // Exploitation for Privilege Escalation
        ];

        let high_techniques = [
            "T1059",     // Command and Scripting Interpreter
            "T1053",     // Scheduled Task/Job
            "T1547",     // Boot or Logon Autostart Execution
            "T1136",     // Create Account
            "T1098",     // Account Manipulation
            "T1078",     // Valid Accounts
            "T1134",     // Access Token Manipulation
        ];

        // Check if technique or parent matches
        let base_id = if technique_id.contains('.') {
            technique_id.split('.').next().unwrap_or(technique_id)
        } else {
            technique_id
        };

        if critical_techniques.iter().any(|t| base_id.starts_with(t)) {
            5
        } else if high_techniques.iter().any(|t| base_id.starts_with(t)) {
            4
        } else {
            3 // Default medium criticality
        }
    }

    /// Calculate gap severity based on detection rate and criticality
    fn calculate_gap_severity(&self, detection_rate: f32, criticality: u8) -> GapSeverity {
        let score = (1.0 - detection_rate) * (criticality as f32 / 5.0);

        if score >= 0.8 {
            GapSeverity::Critical
        } else if score >= 0.6 {
            GapSeverity::High
        } else if score >= 0.4 {
            GapSeverity::Medium
        } else {
            GapSeverity::Low
        }
    }

    /// Generate recommendations for closing a gap
    fn generate_gap_recommendations(
        &self,
        technique_id: &str,
        attack_type: &str,
        detection_rate: f32,
        technique: Option<&MitreTechnique>,
    ) -> Vec<DetectionRecommendation> {
        let mut recommendations = Vec::new();

        // Determine what kind of recommendation based on detection rate
        if detection_rate < 0.3 {
            // Very low detection - need new rules
            recommendations.push(self.create_new_rule_recommendation(technique_id, attack_type, technique));
        } else if detection_rate < 0.7 {
            // Partial detection - tune existing rules
            recommendations.push(self.create_tune_rule_recommendation(technique_id, attack_type));
        }

        // Always recommend data sources if technique has them
        if let Some(tech) = technique {
            if !tech.data_sources.is_empty() {
                recommendations.push(self.create_data_source_recommendation(technique_id, &tech.data_sources));
            }
        }

        // Add log enhancement recommendation for low detection
        if detection_rate < 0.5 {
            recommendations.push(self.create_log_enhancement_recommendation(technique_id, attack_type));
        }

        // Sort by priority
        recommendations.sort_by(|a, b| a.priority.cmp(&b.priority));

        recommendations
    }

    fn create_new_rule_recommendation(
        &self,
        technique_id: &str,
        attack_type: &str,
        technique: Option<&MitreTechnique>,
    ) -> DetectionRecommendation {
        let technique_name = technique.map(|t| t.name.as_str()).unwrap_or("Unknown Technique");

        // Generate detection rule templates
        let sigma_rule = Some(self.generate_sigma_template(technique_id, technique_name, attack_type));
        let splunk_query = Some(self.generate_splunk_template(technique_id, attack_type));
        let elastic_query = Some(self.generate_elastic_template(technique_id, attack_type));

        DetectionRecommendation {
            recommendation_type: RecommendationType::NewRule,
            title: format!("Create detection rule for {}", technique_name),
            description: format!(
                "No effective detection exists for {} ({}). \
                Implement a new detection rule using the provided templates.",
                technique_name, technique_id
            ),
            sigma_rule,
            splunk_query,
            elastic_query,
            data_sources_required: self.get_required_data_sources(attack_type),
            priority: 1,
        }
    }

    fn create_tune_rule_recommendation(
        &self,
        technique_id: &str,
        attack_type: &str,
    ) -> DetectionRecommendation {
        DetectionRecommendation {
            recommendation_type: RecommendationType::RuleTuning,
            title: format!("Tune existing detection rules for {}", technique_id),
            description: format!(
                "Partial detection was observed for {}. Review and tune existing rules \
                to improve detection fidelity. Consider adjusting thresholds, \
                adding additional indicators, or reducing false positive exclusions.",
                technique_id
            ),
            sigma_rule: None,
            splunk_query: Some(self.generate_tuning_query(attack_type)),
            elastic_query: None,
            data_sources_required: vec![],
            priority: 2,
        }
    }

    fn create_data_source_recommendation(
        &self,
        technique_id: &str,
        data_sources: &[String],
    ) -> DetectionRecommendation {
        DetectionRecommendation {
            recommendation_type: RecommendationType::DataSource,
            title: format!("Enable required data sources for {}", technique_id),
            description: format!(
                "Ensure the following data sources are being collected and forwarded \
                to the SIEM: {}",
                data_sources.join(", ")
            ),
            sigma_rule: None,
            splunk_query: None,
            elastic_query: None,
            data_sources_required: data_sources.to_vec(),
            priority: 3,
        }
    }

    fn create_log_enhancement_recommendation(
        &self,
        technique_id: &str,
        attack_type: &str,
    ) -> DetectionRecommendation {
        let enhancements = match attack_type {
            "kerberoast" | "asrep_roast" => vec![
                "Enable Kerberos Service Ticket Operations audit logging",
                "Enable Security event ID 4769 collection",
                "Configure Kerberos logging on Domain Controllers",
            ],
            "password_spray" | "brute_force" => vec![
                "Enable failed logon auditing (Event ID 4625)",
                "Enable account lockout auditing (Event ID 4740)",
                "Consider implementing honeypot accounts",
            ],
            "dcsync" => vec![
                "Enable Directory Service Changes auditing",
                "Enable Event ID 4662 collection",
                "Monitor DS-Replication-Get-Changes permissions",
            ],
            "credential_dump" => vec![
                "Enable process creation auditing with command line logging",
                "Enable LSASS protection (Credential Guard)",
                "Monitor for LSASS access events",
            ],
            _ => vec![
                "Review current logging configuration",
                "Enable verbose logging for relevant services",
                "Ensure logs are being forwarded to SIEM",
            ],
        };

        DetectionRecommendation {
            recommendation_type: RecommendationType::LogEnhancement,
            title: format!("Enhance logging for {} detection", technique_id),
            description: format!(
                "Improve logging coverage to enable better detection:\n{}",
                enhancements.iter().map(|e| format!("  - {}", e)).collect::<Vec<_>>().join("\n")
            ),
            sigma_rule: None,
            splunk_query: None,
            elastic_query: None,
            data_sources_required: vec![],
            priority: 4,
        }
    }

    fn generate_sigma_template(&self, technique_id: &str, technique_name: &str, attack_type: &str) -> String {
        let (logsource, detection) = match attack_type {
            "kerberoast" => (
                "category: security\n    product: windows",
                "selection:\n        EventID: 4769\n        TicketEncryptionType: '0x17'\n    filter:\n        ServiceName|endswith: '$'\n    condition: selection and not filter"
            ),
            "asrep_roast" => (
                "category: security\n    product: windows",
                "selection:\n        EventID: 4768\n        PreAuthType: '0'\n    condition: selection"
            ),
            "password_spray" => (
                "category: security\n    product: windows",
                "selection:\n        EventID: 4625\n    timeframe: 5m\n    condition: selection | count(TargetUserName) by IpAddress > 10"
            ),
            "dcsync" => (
                "category: security\n    product: windows",
                "selection:\n        EventID: 4662\n        AccessMask: '0x100'\n        Properties|contains:\n            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'\n            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'\n    condition: selection"
            ),
            _ => (
                "category: process_creation\n    product: windows",
                "selection:\n        # Add detection logic\n    condition: selection"
            ),
        };

        format!(
            r#"title: Detection for {}
id: {}
status: experimental
description: Detects {} ({})
references:
    - https://attack.mitre.org/techniques/{}/
author: HeroForge Purple Team
date: {}
tags:
    - attack.{}
logsource:
    {}
detection:
    {}
falsepositives:
    - Legitimate administrative activity
level: medium
"#,
            technique_name,
            Uuid::new_v4(),
            technique_name,
            technique_id,
            technique_id,
            Utc::now().format("%Y/%m/%d"),
            technique_id.to_lowercase(),
            logsource,
            detection
        )
    }

    fn generate_splunk_template(&self, technique_id: &str, attack_type: &str) -> String {
        match attack_type {
            "kerberoast" => format!(
                r#"index=windows sourcetype=WinEventLog:Security EventCode=4769
TicketEncryptionType=0x17 ServiceName!="krbtgt" ServiceName!="*$"
| stats count by Account_Name, ServiceName, Client_Address
| where count > 1
| eval mitre_attack_id="{}"
| table _time, Account_Name, ServiceName, Client_Address, count, mitre_attack_id"#,
                technique_id
            ),
            "password_spray" => format!(
                r#"index=windows sourcetype=WinEventLog:Security EventCode=4625
| bucket _time span=5m
| stats dc(TargetUserName) as unique_users, count by _time, IpAddress
| where unique_users > 10
| eval mitre_attack_id="{}"
| table _time, IpAddress, unique_users, count, mitre_attack_id"#,
                technique_id
            ),
            _ => format!(
                r#"index=windows sourcetype=WinEventLog:Security
| search mitre_attack_id="{}" OR technique_id="{}"
| table _time, EventCode, Account_Name, ComputerName, Message"#,
                technique_id, technique_id
            ),
        }
    }

    fn generate_elastic_template(&self, technique_id: &str, attack_type: &str) -> String {
        let query = match attack_type {
            "kerberoast" => serde_json::json!({
                "query": {
                    "bool": {
                        "must": [
                            { "match": { "event.code": "4769" } },
                            { "match": { "winlog.event_data.TicketEncryptionType": "0x17" } }
                        ],
                        "must_not": [
                            { "wildcard": { "winlog.event_data.ServiceName": "*$" } },
                            { "match": { "winlog.event_data.ServiceName": "krbtgt" } }
                        ]
                    }
                }
            }),
            "password_spray" => serde_json::json!({
                "query": {
                    "bool": {
                        "must": [
                            { "match": { "event.code": "4625" } },
                            { "range": { "@timestamp": { "gte": "now-5m" } } }
                        ]
                    }
                },
                "aggs": {
                    "by_source_ip": {
                        "terms": { "field": "source.ip" },
                        "aggs": {
                            "unique_users": {
                                "cardinality": { "field": "winlog.event_data.TargetUserName.keyword" }
                            }
                        }
                    }
                }
            }),
            _ => serde_json::json!({
                "query": {
                    "bool": {
                        "should": [
                            { "match": { "threat.technique.id": technique_id } },
                            { "match": { "mitre.technique.id": technique_id } }
                        ]
                    }
                }
            }),
        };

        serde_json::to_string_pretty(&query).unwrap_or_default()
    }

    fn generate_tuning_query(&self, attack_type: &str) -> String {
        match attack_type {
            "kerberoast" => r#"| Review current threshold for TGS requests
| Consider adding ServiceName exclusions for known legitimate services
| Review TicketEncryptionType variations"#.to_string(),
            "password_spray" => r#"| Review failed login threshold (currently 10)
| Consider time window adjustments (currently 5m)
| Add source IP exclusions for known scanners"#.to_string(),
            _ => "| Review current detection rule for false positives\n| Adjust thresholds as needed".to_string(),
        }
    }

    fn get_required_data_sources(&self, attack_type: &str) -> Vec<String> {
        match attack_type {
            "kerberoast" | "asrep_roast" => vec![
                "Windows Security Event Logs".to_string(),
                "Domain Controller Logs".to_string(),
                "Kerberos Authentication Logs".to_string(),
            ],
            "password_spray" | "brute_force" => vec![
                "Windows Security Event Logs".to_string(),
                "Authentication Logs".to_string(),
                "Failed Login Events".to_string(),
            ],
            "dcsync" => vec![
                "Windows Security Event Logs".to_string(),
                "Domain Controller Logs".to_string(),
                "Active Directory Logs".to_string(),
            ],
            "credential_dump" => vec![
                "Process Creation Logs".to_string(),
                "Sysmon Logs".to_string(),
                "Windows Security Event Logs".to_string(),
            ],
            _ => vec![
                "Windows Security Event Logs".to_string(),
                "Sysmon Logs".to_string(),
            ],
        }
    }

    /// Get gap statistics for dashboard
    pub fn get_gap_statistics(&self, gaps: &[DetectionGap]) -> GapStatistics {
        let total = gaps.len();
        let critical = gaps.iter().filter(|g| g.severity == GapSeverity::Critical).count();
        let high = gaps.iter().filter(|g| g.severity == GapSeverity::High).count();
        let medium = gaps.iter().filter(|g| g.severity == GapSeverity::Medium).count();
        let low = gaps.iter().filter(|g| g.severity == GapSeverity::Low).count();

        let open = gaps.iter().filter(|g| g.status == GapStatus::Open).count();
        let in_progress = gaps.iter().filter(|g| g.status == GapStatus::InProgress).count();
        let remediated = gaps.iter().filter(|g| g.status == GapStatus::Remediated).count();

        // Group by tactic
        let mut by_tactic: HashMap<String, usize> = HashMap::new();
        for gap in gaps {
            *by_tactic.entry(gap.tactic.name().to_string()).or_default() += 1;
        }

        GapStatistics {
            total,
            critical,
            high,
            medium,
            low,
            open,
            in_progress,
            remediated,
            by_tactic,
        }
    }
}

impl Default for GapAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about detection gaps
#[derive(Debug, Clone)]
pub struct GapStatistics {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub open: usize,
    pub in_progress: usize,
    pub remediated: usize,
    pub by_tactic: HashMap<String, usize>,
}

/// Get priority value for severity (lower is higher priority)
fn severity_priority(severity: &GapSeverity) -> u8 {
    match severity {
        GapSeverity::Critical => 1,
        GapSeverity::High => 2,
        GapSeverity::Medium => 3,
        GapSeverity::Low => 4,
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
            attack_type: "kerberoast".to_string(),
            target: "10.0.0.1".to_string(),
            attack_status: AttackStatus::Executed,
            detection_status: detection,
            detection_details: None,
            time_to_detect_ms: None,
            executed_at: Utc::now(),
            error_message: None,
        }
    }

    #[test]
    fn test_gap_identification() {
        let analyzer = GapAnalyzer::new();
        let results = vec![
            make_result("T1558.003", DetectionStatus::NotDetected),
            make_result("T1558.003", DetectionStatus::PartiallyDetected),
            make_result("T1110.003", DetectionStatus::Detected),
        ];

        let gaps = analyzer.identify_gaps("test", &results);

        // Should have 1 gap for T1558.003 (not fully detected)
        // T1110.003 should not have a gap (fully detected)
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].technique_id, "T1558.003");
    }

    #[test]
    fn test_gap_severity() {
        let analyzer = GapAnalyzer::new();

        // Critical technique with 0% detection should be Critical
        let severity = analyzer.calculate_gap_severity(0.0, 5);
        assert_eq!(severity, GapSeverity::Critical);

        // Medium criticality with partial detection
        let severity = analyzer.calculate_gap_severity(0.5, 3);
        assert_eq!(severity, GapSeverity::Medium);
    }
}
