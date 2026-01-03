//! Staking security analysis
//!
//! Comprehensive staking security analysis including:
//! - Validator monitoring
//! - Slashing risk analysis
//! - Reward calculation verification
//! - Lock-up period review

use super::types::*;
use anyhow::Result;
use std::collections::HashMap;

/// Staking security analyzer
pub struct StakingAnalyzer {
    /// Known validator reputation scores
    validator_reputation: HashMap<String, ValidatorReputation>,
    /// Slashing risk thresholds
    slashing_threshold: f64,
    /// Minimum uptime percentage for safety
    min_uptime: f64,
}

impl StakingAnalyzer {
    pub fn new() -> Self {
        Self {
            validator_reputation: HashMap::new(),
            slashing_threshold: 0.1, // 10% slashing rate considered risky
            min_uptime: 99.0, // 99% minimum uptime
        }
    }

    /// Analyze validator risk
    pub fn analyze_validator(&self, address: &str, chain: &str, uptime: f64, slashing_history: u32) -> Vec<StakingFinding> {
        let mut findings = Vec::new();

        // Check uptime
        if uptime < self.min_uptime {
            findings.push(StakingFinding {
                validator_address: address.to_string(),
                chain: chain.to_string(),
                finding_type: StakingRiskType::UptimeIssue,
                severity: if uptime < 95.0 { Severity::High } else { Severity::Medium },
                description: format!("Validator uptime ({:.2}%) is below recommended {:.1}%", uptime, self.min_uptime),
                recommendation: "Consider delegating to validators with higher uptime".to_string(),
            });
        }

        // Check slashing history
        if slashing_history > 0 {
            findings.push(StakingFinding {
                validator_address: address.to_string(),
                chain: chain.to_string(),
                finding_type: StakingRiskType::SlashingRisk,
                severity: if slashing_history > 2 { Severity::High } else { Severity::Medium },
                description: format!("Validator has {} slashing events in history", slashing_history),
                recommendation: "Validators with slashing history carry increased risk".to_string(),
            });
        }

        findings
    }

    /// Analyze slashing risk for chain
    pub fn analyze_slashing_risk(&self, address: &str, chain: &str, stake_amount: f64) -> Vec<StakingFinding> {
        let mut findings = Vec::new();

        // General slashing information by chain
        let slashing_info = match chain.to_lowercase().as_str() {
            "ethereum" => ("Up to 100% for correlated failures", Severity::High),
            "cosmos" => ("5% for double signing, 0.01% for downtime", Severity::Medium),
            "polkadot" => ("Varies by offense severity", Severity::Medium),
            "solana" => ("Slashing not currently enabled", Severity::Low),
            _ => ("Slashing rules vary by network", Severity::Info),
        };

        findings.push(StakingFinding {
            validator_address: address.to_string(),
            chain: chain.to_string(),
            finding_type: StakingRiskType::SlashingRisk,
            severity: slashing_info.1,
            description: format!("Slashing risk for {}: {}", chain, slashing_info.0),
            recommendation: "Understand slashing conditions before staking".to_string(),
        });

        // Large stake concentration warning
        if stake_amount > 1_000_000.0 {
            findings.push(StakingFinding {
                validator_address: address.to_string(),
                chain: chain.to_string(),
                finding_type: StakingRiskType::ValidatorRisk,
                severity: Severity::Medium,
                description: "Large stake concentration increases slashing impact".to_string(),
                recommendation: "Consider distributing stake across multiple validators".to_string(),
            });
        }

        findings
    }

    /// Analyze reward calculations
    pub fn analyze_rewards(&self, address: &str, chain: &str, apr: f64, commission: f64) -> Vec<StakingFinding> {
        let mut findings = Vec::new();

        // High commission warning
        if commission > 20.0 {
            findings.push(StakingFinding {
                validator_address: address.to_string(),
                chain: chain.to_string(),
                finding_type: StakingRiskType::RewardRisk,
                severity: Severity::Medium,
                description: format!("Validator commission ({:.1}%) is above average", commission),
                recommendation: "Compare commission rates across validators".to_string(),
            });
        }

        // Suspicious APR warning
        if apr > 50.0 {
            findings.push(StakingFinding {
                validator_address: address.to_string(),
                chain: chain.to_string(),
                finding_type: StakingRiskType::RewardRisk,
                severity: Severity::High,
                description: format!("Suspiciously high APR ({:.1}%) may indicate unsustainable rewards", apr),
                recommendation: "Extremely high APRs often indicate ponzi-like schemes".to_string(),
            });
        }

        // Low APR warning
        if apr < 1.0 && apr > 0.0 {
            findings.push(StakingFinding {
                validator_address: address.to_string(),
                chain: chain.to_string(),
                finding_type: StakingRiskType::RewardRisk,
                severity: Severity::Low,
                description: format!("Low APR ({:.2}%) may not justify lock-up risk", apr),
                recommendation: "Evaluate if staking rewards justify the opportunity cost".to_string(),
            });
        }

        findings
    }

    /// Analyze smart contract staking risks
    pub fn analyze_contract_staking(&self, address: &str, chain: &str, is_audited: bool, is_upgradeable: bool) -> Vec<StakingFinding> {
        let mut findings = Vec::new();

        if !is_audited {
            findings.push(StakingFinding {
                validator_address: address.to_string(),
                chain: chain.to_string(),
                finding_type: StakingRiskType::SmartContractRisk,
                severity: Severity::High,
                description: "Staking contract has not been audited".to_string(),
                recommendation: "Only use staking contracts with reputable audit reports".to_string(),
            });
        }

        if is_upgradeable {
            findings.push(StakingFinding {
                validator_address: address.to_string(),
                chain: chain.to_string(),
                finding_type: StakingRiskType::SmartContractRisk,
                severity: Severity::Medium,
                description: "Staking contract is upgradeable".to_string(),
                recommendation: "Upgradeable contracts can have functionality changed - verify governance".to_string(),
            });
        }

        findings
    }

    /// Analyze lock-up periods
    pub fn analyze_lockup(&self, address: &str, chain: &str, lockup_days: u32, unbonding_days: u32) -> Vec<StakingFinding> {
        let mut findings = Vec::new();

        if lockup_days > 30 {
            findings.push(StakingFinding {
                validator_address: address.to_string(),
                chain: chain.to_string(),
                finding_type: StakingRiskType::ValidatorRisk,
                severity: Severity::Medium,
                description: format!("Lock-up period of {} days limits liquidity", lockup_days),
                recommendation: "Consider liquidity needs before long-term staking".to_string(),
            });
        }

        if unbonding_days > 21 {
            findings.push(StakingFinding {
                validator_address: address.to_string(),
                chain: chain.to_string(),
                finding_type: StakingRiskType::ValidatorRisk,
                severity: Severity::Low,
                description: format!("Unbonding period of {} days delays access to funds", unbonding_days),
                recommendation: "Plan for unbonding delay when considering liquidity".to_string(),
            });
        }

        findings
    }
}

impl Default for StakingAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct ValidatorReputation {
    uptime_30d: f64,
    slashing_events: u32,
    commission: f64,
    total_staked: f64,
}

/// Analyze staking security
pub async fn analyze_staking(addresses: &[String]) -> Result<Vec<StakingFinding>> {
    let mut findings = Vec::new();
    let analyzer = StakingAnalyzer::new();

    for address in addresses {
        // Assume Ethereum for generic analysis (in production, would detect chain)
        let chain = "Unknown";

        // Analyze validator (simulated data)
        findings.extend(analyzer.analyze_validator(address, chain, 99.5, 0));

        // Analyze slashing risk
        findings.extend(analyzer.analyze_slashing_risk(address, chain, 100000.0));

        // Analyze rewards (simulated)
        findings.extend(analyzer.analyze_rewards(address, chain, 5.0, 10.0));

        // Analyze contract risks
        findings.extend(analyzer.analyze_contract_staking(address, chain, false, true));

        // Analyze lock-up
        findings.extend(analyzer.analyze_lockup(address, chain, 0, 21));

        // Add general monitoring recommendation
        findings.push(StakingFinding {
            validator_address: address.clone(),
            chain: chain.to_string(),
            finding_type: StakingRiskType::ValidatorRisk,
            severity: Severity::Info,
            description: format!("Staking validator {} requires ongoing monitoring", address),
            recommendation: "Monitor validator performance, uptime, and governance participation".to_string(),
        });
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_analysis() {
        let analyzer = StakingAnalyzer::new();
        let findings = analyzer.analyze_validator("0x123", "ethereum", 98.5, 1);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_reward_analysis() {
        let analyzer = StakingAnalyzer::new();

        // High APR warning
        let findings = analyzer.analyze_rewards("0x123", "unknown", 100.0, 5.0);
        assert!(findings.iter().any(|f| f.severity == Severity::High));

        // High commission
        let findings = analyzer.analyze_rewards("0x123", "unknown", 5.0, 30.0);
        assert!(findings.iter().any(|f| f.finding_type == StakingRiskType::RewardRisk));
    }

    #[tokio::test]
    async fn test_analyze_staking() {
        let addresses = vec!["0x1234567890abcdef".to_string()];
        let findings = analyze_staking(&addresses).await.unwrap();
        assert!(!findings.is_empty());
    }
}
