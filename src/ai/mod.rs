#![allow(dead_code)]
//! AI-Based Vulnerability Prioritization Module
//!
//! This module provides ML-based risk scoring for vulnerability prioritization.
//! It analyzes multiple factors to calculate an "Effective Risk Score" (0-100)
//! and generates a prioritized remediation order.
//!
//! ## Key Features
//! - Weighted scoring model with configurable factor weights
//! - Considers CVSS, exploit availability, asset criticality, network exposure
//! - Integrates with threat intelligence and attack path analysis
//! - Provides remediation effort estimates
//! - Supports feedback learning for score adjustment
//! - AI Chat assistant with multi-provider LLM support (Claude, Ollama, OpenAI)
//!
//! ## LLM Provider Abstraction
//!
//! The `providers` submodule provides a unified interface for LLM backends:
//! - Anthropic Claude (cloud-based)
//! - Ollama (self-hosted)
//! - OpenAI (cloud-based, planned)
//!
//! See `providers::get_provider()` for usage.

pub mod chat;
pub mod context;
pub mod context_builder;
pub mod features;
pub mod llm_orchestrator;
pub mod ml_pipeline;
pub mod models;
pub mod prioritization;
pub mod prompts;
pub mod providers;
pub mod red_team_advisor;
pub mod remediation_planner;
pub mod attack_path_interpreter;

pub use remediation_planner::{
    RemediationPlanner, RemediationRoadmap, RemediationPhase, RemediationTask,
    RoadmapSummary, RiskProjection, CriticalPathItem, ResourceSuggestion,
    GenerateRoadmapRequest,
};

pub use attack_path_interpreter::{
    AttackPathInterpreter, AttackPathInterpretation, AttackNarrative,
    MitreMapping, BusinessImpact, BlockingPoint, RiskAssessment,
};

pub use context_builder::{
    ContextBuilder, ChatContext, ContextType, TrendData, TrendDirection,
    RelatedEntity,
};

use anyhow::Result;
use chrono::Utc;
use log::{debug, info, warn};
use sqlx::SqlitePool;
use std::sync::Arc;

pub use features::*;
pub use models::*;

/// AI Prioritization Manager
///
/// Coordinates vulnerability prioritization using multiple data sources
/// and configurable scoring weights.
pub struct AIPrioritizationManager {
    pool: Arc<SqlitePool>,
    config: AIModelConfig,
}

impl AIPrioritizationManager {
    /// Create a new AI prioritization manager
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self {
            pool,
            config: AIModelConfig::default(),
        }
    }

    /// Create manager with custom configuration
    pub fn with_config(pool: Arc<SqlitePool>, config: AIModelConfig) -> Self {
        Self { pool, config }
    }

    /// Load configuration from database or use defaults
    pub async fn from_database(pool: Arc<SqlitePool>) -> Result<Self> {
        let config = match crate::db::ai::get_model_config(&pool).await {
            Ok(Some(config)) => config,
            Ok(None) => AIModelConfig::default(),
            Err(e) => {
                warn!("Failed to load AI config from database: {}, using defaults", e);
                AIModelConfig::default()
            }
        };

        Ok(Self { pool, config })
    }

    /// Calculate AI prioritization scores for all vulnerabilities in a scan
    pub async fn prioritize_scan(&self, scan_id: &str) -> Result<AIPrioritizationResult> {
        info!("Starting AI prioritization for scan: {}", scan_id);

        // Get scan results
        let scan = crate::db::get_scan_by_id(&self.pool, scan_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Scan not found: {}", scan_id))?;

        let hosts: Vec<crate::types::HostInfo> = scan
            .results
            .as_ref()
            .and_then(|r| serde_json::from_str(r).ok())
            .unwrap_or_default();

        if hosts.is_empty() {
            return Ok(AIPrioritizationResult {
                scan_id: scan_id.to_string(),
                scores: Vec::new(),
                summary: PrioritizationSummary::default(),
                calculated_at: Utc::now(),
            });
        }

        // Get vulnerability tracking records for this scan
        let vulns = crate::db::vulnerabilities::get_vulnerability_tracking_by_scan(&self.pool, scan_id, None, None).await?;

        // Extract features and calculate scores
        let mut scores = Vec::new();
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;

        for vuln in vulns {
            // Extract features for this vulnerability
            let features = self.extract_features(&vuln, &hosts).await?;

            // Calculate effective risk score
            let score = self.calculate_score(&features);

            // Determine risk category
            let category = RiskCategory::from_score(score.effective_risk_score);
            match category {
                RiskCategory::Critical => critical_count += 1,
                RiskCategory::High => high_count += 1,
                RiskCategory::Medium => medium_count += 1,
                RiskCategory::Low => low_count += 1,
            }

            scores.push(score);
        }

        // Sort by effective risk score descending
        scores.sort_by(|a, b| b.effective_risk_score.partial_cmp(&a.effective_risk_score).unwrap());

        // Generate remediation order
        for (i, score) in scores.iter_mut().enumerate() {
            score.remediation_priority = (i + 1) as u32;
        }

        let summary = PrioritizationSummary {
            total_vulnerabilities: scores.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            average_risk_score: if scores.is_empty() {
                0.0
            } else {
                scores.iter().map(|s| s.effective_risk_score).sum::<f64>() / scores.len() as f64
            },
            highest_risk_score: scores.first().map(|s| s.effective_risk_score).unwrap_or(0.0),
        };

        // Store scores in database
        for score in &scores {
            if let Err(e) = crate::db::ai::store_ai_score(&self.pool, scan_id, score).await {
                warn!("Failed to store AI score for {}: {}", score.vulnerability_id, e);
            }
        }

        let result = AIPrioritizationResult {
            scan_id: scan_id.to_string(),
            scores,
            summary,
            calculated_at: Utc::now(),
        };

        // Store result summary
        if let Err(e) = crate::db::ai::store_prioritization_result(&self.pool, &result).await {
            warn!("Failed to store prioritization result: {}", e);
        }

        info!(
            "AI prioritization complete for scan {}: {} vulnerabilities scored",
            scan_id, result.summary.total_vulnerabilities
        );

        Ok(result)
    }

    /// Extract features for a vulnerability
    async fn extract_features(
        &self,
        vuln: &crate::db::models::VulnerabilityTracking,
        hosts: &[crate::types::HostInfo],
    ) -> Result<VulnerabilityFeatures> {
        // Find the host for this vulnerability
        let host = hosts.iter().find(|h| h.target.ip.to_string() == vuln.host_ip);

        // Extract base CVSS score from severity
        let base_cvss = severity_to_cvss(&vuln.severity);

        // Check for exploit availability via threat intel
        let exploit_available = self.check_exploit_availability(&vuln.vulnerability_id).await;

        // Determine asset criticality
        let asset_criticality = self.get_asset_criticality(&vuln.host_ip).await;

        // Determine network exposure
        let network_exposure = self.determine_network_exposure(host);

        // Check if part of attack path
        let attack_path_score = self.get_attack_path_score(&vuln.vulnerability_id).await;

        // Get historical remediation time for similar vulnerabilities
        let historical_remediation_days = self.get_historical_remediation_time(&vuln.severity).await;

        // Get compliance impact score
        let compliance_impact = self.get_compliance_impact(&vuln.vulnerability_id).await;

        // Calculate business context score
        let business_context_score = self.calculate_business_context(asset_criticality, network_exposure);

        // Calculate age in days
        let age_days = (Utc::now() - vuln.created_at).num_days() as u32;

        Ok(VulnerabilityFeatures {
            vulnerability_id: vuln.id.clone(),
            base_cvss,
            temporal_cvss: None,
            environmental_cvss: None,
            exploit_available,
            exploit_maturity: if exploit_available {
                ExploitMaturity::Functional
            } else {
                ExploitMaturity::Unproven
            },
            asset_criticality,
            network_exposure,
            attack_path_score,
            historical_remediation_days,
            compliance_impact,
            business_context_score,
            age_days,
            has_dependencies: false,
            is_actively_exploited: false,
        })
    }

    /// Calculate the effective risk score using weighted factors
    fn calculate_score(&self, features: &VulnerabilityFeatures) -> AIVulnerabilityScore {
        let weights = &self.config.weights;

        // Normalize each factor to 0-100 scale
        let cvss_score = (features.base_cvss / 10.0) * 100.0;
        let exploit_score = if features.exploit_available { 100.0 } else { 0.0 };
        let asset_score = features.asset_criticality.score();
        let exposure_score = features.network_exposure.score();
        let attack_path_normalized = features.attack_path_score.min(100.0);
        let compliance_normalized = features.compliance_impact.min(100.0);
        let business_score = features.business_context_score.min(100.0);

        // Historical remediation factor (inverse - faster remediation = lower priority)
        let _remediation_factor = if features.historical_remediation_days > 0 {
            ((features.historical_remediation_days as f64) / 30.0 * 100.0).min(100.0)
        } else {
            50.0 // Default medium priority
        };

        // Calculate weighted score
        let effective_risk_score = (cvss_score * weights.cvss_weight
            + exploit_score * weights.exploit_weight
            + asset_score * weights.asset_criticality_weight
            + exposure_score * weights.network_exposure_weight
            + attack_path_normalized * weights.attack_path_weight
            + compliance_normalized * weights.compliance_weight
            + business_score * weights.business_context_weight)
            / (weights.cvss_weight
                + weights.exploit_weight
                + weights.asset_criticality_weight
                + weights.network_exposure_weight
                + weights.attack_path_weight
                + weights.compliance_weight
                + weights.business_context_weight);

        // Create factor breakdown
        let factor_scores = vec![
            FactorScore {
                factor_name: "CVSS Score".to_string(),
                raw_value: features.base_cvss,
                normalized_value: cvss_score,
                weight: weights.cvss_weight,
                contribution: cvss_score * weights.cvss_weight,
            },
            FactorScore {
                factor_name: "Exploit Availability".to_string(),
                raw_value: if features.exploit_available { 1.0 } else { 0.0 },
                normalized_value: exploit_score,
                weight: weights.exploit_weight,
                contribution: exploit_score * weights.exploit_weight,
            },
            FactorScore {
                factor_name: "Asset Criticality".to_string(),
                raw_value: asset_score,
                normalized_value: asset_score,
                weight: weights.asset_criticality_weight,
                contribution: asset_score * weights.asset_criticality_weight,
            },
            FactorScore {
                factor_name: "Network Exposure".to_string(),
                raw_value: exposure_score,
                normalized_value: exposure_score,
                weight: weights.network_exposure_weight,
                contribution: exposure_score * weights.network_exposure_weight,
            },
            FactorScore {
                factor_name: "Attack Path Risk".to_string(),
                raw_value: features.attack_path_score,
                normalized_value: attack_path_normalized,
                weight: weights.attack_path_weight,
                contribution: attack_path_normalized * weights.attack_path_weight,
            },
            FactorScore {
                factor_name: "Compliance Impact".to_string(),
                raw_value: features.compliance_impact,
                normalized_value: compliance_normalized,
                weight: weights.compliance_weight,
                contribution: compliance_normalized * weights.compliance_weight,
            },
            FactorScore {
                factor_name: "Business Context".to_string(),
                raw_value: business_score,
                normalized_value: business_score,
                weight: weights.business_context_weight,
                contribution: business_score * weights.business_context_weight,
            },
        ];

        // Estimate remediation effort
        let estimated_effort = self.estimate_effort(features);

        AIVulnerabilityScore {
            vulnerability_id: features.vulnerability_id.clone(),
            effective_risk_score,
            risk_category: RiskCategory::from_score(effective_risk_score),
            factor_scores,
            remediation_priority: 0, // Set later
            estimated_effort,
            confidence: self.calculate_confidence(features),
            calculated_at: Utc::now(),
            explanation: None,
            key_factors: None,
            epss_score: None,
            epss_percentile: None,
        }
    }

    /// Estimate remediation effort
    fn estimate_effort(&self, features: &VulnerabilityFeatures) -> RemediationEffort {
        // Base effort on CVSS complexity
        let base_hours = match features.base_cvss as u32 {
            0..=3 => 1,
            4..=5 => 2,
            6..=7 => 4,
            8..=9 => 8,
            _ => 16,
        };

        // Adjust for dependencies
        let adjusted_hours = if features.has_dependencies {
            base_hours * 2
        } else {
            base_hours
        };

        let effort_level = match adjusted_hours {
            0..=2 => EffortLevel::Low,
            3..=4 => EffortLevel::Medium,
            5..=8 => EffortLevel::High,
            _ => EffortLevel::VeryHigh,
        };

        let impact_level = match features.base_cvss as u32 {
            0..=3 => ImpactLevel::Low,
            4..=6 => ImpactLevel::Medium,
            7..=8 => ImpactLevel::High,
            _ => ImpactLevel::Critical,
        };

        RemediationEffort {
            estimated_hours: adjusted_hours,
            effort_level,
            impact_level,
            requires_downtime: features.base_cvss >= 9.0,
            requires_testing: features.base_cvss >= 7.0,
        }
    }

    /// Calculate confidence in the score
    fn calculate_confidence(&self, features: &VulnerabilityFeatures) -> f64 {
        let mut confidence: f64 = 100.0;

        // Reduce confidence if missing temporal CVSS
        if features.temporal_cvss.is_none() {
            confidence -= 10.0;
        }

        // Reduce confidence if missing environmental CVSS
        if features.environmental_cvss.is_none() {
            confidence -= 10.0;
        }

        // Reduce confidence for unknown exploit status
        if !features.exploit_available && features.exploit_maturity == ExploitMaturity::Unproven {
            confidence -= 5.0;
        }

        // Reduce confidence for new vulnerabilities (less historical data)
        if features.age_days < 7 {
            confidence -= 10.0;
        }

        confidence.max(0.0)
    }

    /// Check if exploit is available for a vulnerability
    async fn check_exploit_availability(&self, vuln_id: &str) -> bool {
        // Check if this looks like a CVE ID (CVE-YYYY-NNNNN format)
        if !vuln_id.to_uppercase().starts_with("CVE-") {
            return false;
        }

        // Try to find exploits using ExploitDB client
        let exploit_db = crate::threat_intel::ExploitDbClient::from_env();
        match exploit_db.search_by_cve(vuln_id).await {
            Ok(exploits) => {
                if !exploits.is_empty() {
                    debug!("Found {} exploit(s) for {}", exploits.len(), vuln_id);
                    return true;
                }
            }
            Err(e) => {
                debug!("ExploitDB lookup failed for {}: {}", vuln_id, e);
            }
        }

        // Check the threat intel feed cache for known exploited vulnerabilities
        let result: Result<Option<String>, _> = sqlx::query_scalar(
            "SELECT references FROM threat_intel_cves WHERE cve_id = ?"
        )
        .bind(vuln_id)
        .fetch_optional(&*self.pool)
        .await;

        if let Ok(Some(refs_json)) = result {
            if let Ok(refs) = serde_json::from_str::<serde_json::Value>(&refs_json) {
                if let Some(refs_array) = refs.as_array() {
                    for r in refs_array {
                        if let Some(url) = r.get("url").and_then(|u| u.as_str()) {
                            let url_lower = url.to_lowercase();
                            if url_lower.contains("exploit-db")
                                || url_lower.contains("packetstorm")
                                || url_lower.contains("metasploit")
                                || (url_lower.contains("github.com") && url_lower.contains("poc"))
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Get asset criticality from asset inventory
    async fn get_asset_criticality(&self, host_ip: &str) -> AssetCriticality {
        // Try to find the asset in our inventory
        if let Ok(Some(asset)) = crate::db::assets::get_asset_by_ip(&self.pool, host_ip).await {
            // Check for criticality tags
            let tags: Vec<String> = serde_json::from_str(&asset.tags).unwrap_or_default();
            for tag in tags {
                let tag_lower = tag.to_lowercase();
                if tag_lower.contains("critical") || tag_lower.contains("production") {
                    return AssetCriticality::Critical;
                }
                if tag_lower.contains("high") || tag_lower.contains("important") {
                    return AssetCriticality::High;
                }
                if tag_lower.contains("development") || tag_lower.contains("test") {
                    return AssetCriticality::Low;
                }
            }
        }
        AssetCriticality::Medium
    }

    /// Determine network exposure level
    fn determine_network_exposure(&self, host: Option<&crate::types::HostInfo>) -> NetworkExposure {
        if let Some(host) = host {
            // Check for common internet-facing services
            let internet_facing_ports = [80, 443, 8080, 8443, 22, 21, 25, 53];
            let has_internet_facing = host
                .ports
                .iter()
                .any(|p| internet_facing_ports.contains(&p.port));

            if has_internet_facing {
                return NetworkExposure::InternetFacing;
            }

            // Check for DMZ indicators
            if host.ports.len() > 10 {
                return NetworkExposure::Dmz;
            }
        }

        NetworkExposure::Internal
    }

    /// Get attack path score for a vulnerability
    /// Returns a score 0-100 based on attack path involvement
    async fn get_attack_path_score(&self, vuln_id: &str) -> f64 {
        // Query attack paths that involve this vulnerability
        let result: Result<Vec<(String, String, Option<f64>)>, _> = sqlx::query_as(
            r#"
            SELECT ap.id, ap.risk_level, ap.probability
            FROM attack_paths ap
            JOIN attack_nodes an ON an.path_id = ap.id
            WHERE an.vulnerability_ids LIKE ?
            "#
        )
        .bind(format!("%{}%", vuln_id))
        .fetch_all(&*self.pool)
        .await;

        match result {
            Ok(paths) if !paths.is_empty() => {
                // Calculate score based on highest risk path involvement
                let mut max_score: f64 = 0.0;
                for (_id, risk_level, probability) in paths {
                    let risk_base = match risk_level.to_lowercase().as_str() {
                        "critical" => 100.0,
                        "high" => 80.0,
                        "medium" => 50.0,
                        "low" => 25.0,
                        _ => 30.0,
                    };
                    // Weight by probability if available
                    let score = risk_base * probability.unwrap_or(0.7);
                    if score > max_score {
                        max_score = score;
                    }
                }
                debug!("Attack path score for {}: {}", vuln_id, max_score);
                max_score
            }
            Ok(_) => {
                // No attack paths involve this vulnerability - low score
                25.0
            }
            Err(e) => {
                debug!("Attack path query failed for {}: {}", vuln_id, e);
                // Default to medium if query fails
                50.0
            }
        }
    }

    /// Get historical remediation time for similar vulnerabilities
    async fn get_historical_remediation_time(&self, severity: &str) -> u32 {
        // Query historical data
        match crate::db::ai::get_avg_remediation_time(&self.pool, severity).await {
            Ok(Some(days)) => days as u32,
            _ => match severity.to_lowercase().as_str() {
                "critical" => 7,
                "high" => 14,
                "medium" => 30,
                _ => 60,
            },
        }
    }

    /// Get compliance impact score
    /// Returns a score 0-100 based on compliance framework impact
    async fn get_compliance_impact(&self, vuln_id: &str) -> f64 {
        // Query compliance findings that reference this vulnerability
        let result: Result<Vec<(String, String)>, _> = sqlx::query_as(
            r#"
            SELECT framework, severity
            FROM compliance_findings
            WHERE evidence LIKE ?
            "#
        )
        .bind(format!("%{}%", vuln_id))
        .fetch_all(&*self.pool)
        .await;

        match result {
            Ok(findings) if !findings.is_empty() => {
                // Score based on number of frameworks impacted and severity
                let framework_count = findings.iter()
                    .map(|(f, _)| f.clone())
                    .collect::<std::collections::HashSet<_>>()
                    .len();

                // Get highest severity impact
                let max_severity_score: f64 = findings.iter()
                    .map(|(_, severity)| match severity.to_lowercase().as_str() {
                        "critical" => 100.0,
                        "high" => 80.0,
                        "medium" => 50.0,
                        "low" => 25.0,
                        _ => 30.0,
                    })
                    .fold(0.0_f64, |a, b| a.max(b));

                // Weight by number of frameworks (more frameworks = higher impact)
                let framework_weight = match framework_count {
                    0 => 0.5,
                    1 => 0.7,
                    2 => 0.85,
                    _ => 1.0, // 3+ frameworks
                };

                let score = max_severity_score * framework_weight;
                debug!("Compliance impact for {}: {} ({} frameworks)", vuln_id, score, framework_count);
                score
            }
            Ok(_) => {
                // No compliance findings reference this vulnerability
                // Return low score - doesn't mean no compliance impact, just no recorded impact
                30.0
            }
            Err(e) => {
                debug!("Compliance query failed for {}: {}", vuln_id, e);
                // Default to medium if query fails
                50.0
            }
        }
    }

    /// Calculate business context score
    fn calculate_business_context(&self, criticality: AssetCriticality, exposure: NetworkExposure) -> f64 {
        let criticality_score = criticality.score();
        let exposure_score = exposure.score();
        (criticality_score + exposure_score) / 2.0
    }

    /// Get prioritization scores for a scan
    pub async fn get_scores(&self, scan_id: &str) -> Result<AIPrioritizationResult> {
        crate::db::ai::get_prioritization_result(&self.pool, scan_id).await
    }

    /// Get score breakdown for a specific vulnerability
    pub async fn get_score_breakdown(&self, vuln_id: &str) -> Result<Option<AIVulnerabilityScore>> {
        crate::db::ai::get_vulnerability_score(&self.pool, vuln_id).await
    }

    /// Update model configuration
    pub async fn update_config(&self, config: AIModelConfig) -> Result<AIModelConfig> {
        crate::db::ai::save_model_config(&self.pool, &config).await?;
        Ok(config)
    }

    /// Get current model configuration
    pub fn get_config(&self) -> &AIModelConfig {
        &self.config
    }

    /// Record feedback for learning
    pub async fn record_feedback(&self, feedback: AIFeedback) -> Result<()> {
        crate::db::ai::store_feedback(&self.pool, &feedback).await
    }
}

/// Convert severity string to approximate CVSS score
fn severity_to_cvss(severity: &str) -> f64 {
    match severity.to_lowercase().as_str() {
        "critical" => 9.5,
        "high" => 7.5,
        "medium" => 5.5,
        "low" => 2.5,
        _ => 5.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_to_cvss() {
        assert_eq!(severity_to_cvss("critical"), 9.5);
        assert_eq!(severity_to_cvss("HIGH"), 7.5);
        assert_eq!(severity_to_cvss("Medium"), 5.5);
        assert_eq!(severity_to_cvss("low"), 2.5);
        assert_eq!(severity_to_cvss("unknown"), 5.0);
    }

    #[test]
    fn test_risk_category_from_score() {
        assert_eq!(RiskCategory::from_score(90.0), RiskCategory::Critical);
        assert_eq!(RiskCategory::from_score(75.0), RiskCategory::High);
        assert_eq!(RiskCategory::from_score(50.0), RiskCategory::Medium);
        assert_eq!(RiskCategory::from_score(25.0), RiskCategory::Low);
    }
}
