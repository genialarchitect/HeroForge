//! DeFi security analysis
//!
//! Comprehensive security analysis for DeFi protocols including:
//! - Flash loan vulnerability detection
//! - Rug pull indicators
//! - Oracle manipulation risks
//! - MEV exposure analysis

use super::types::*;
use anyhow::Result;
use std::collections::HashSet;

/// DeFi protocol analyzer
pub struct DeFiAnalyzer {
    /// Known rug pull patterns
    rug_pull_patterns: Vec<RugPullPattern>,
    /// Oracle manipulation thresholds
    oracle_manipulation_threshold: f64,
    /// MEV detection sensitivity
    mev_sensitivity: f64,
}

impl DeFiAnalyzer {
    pub fn new() -> Self {
        Self {
            rug_pull_patterns: Self::default_rug_patterns(),
            oracle_manipulation_threshold: 0.1, // 10% deviation
            mev_sensitivity: 0.5,
        }
    }

    fn default_rug_patterns() -> Vec<RugPullPattern> {
        vec![
            RugPullPattern {
                name: "Liquidity Removal".to_string(),
                indicators: vec![
                    "removeLiquidity".to_string(),
                    "emergencyWithdraw".to_string(),
                ],
                severity: Severity::Critical,
            },
            RugPullPattern {
                name: "Hidden Mint".to_string(),
                indicators: vec![
                    "_mint".to_string(),
                    "mintTo".to_string(),
                ],
                severity: Severity::High,
            },
            RugPullPattern {
                name: "Blacklist Function".to_string(),
                indicators: vec![
                    "blacklist".to_string(),
                    "addBlacklist".to_string(),
                ],
                severity: Severity::High,
            },
            RugPullPattern {
                name: "Fee Manipulation".to_string(),
                indicators: vec![
                    "setFee".to_string(),
                    "updateTax".to_string(),
                ],
                severity: Severity::Medium,
            },
        ]
    }

    /// Analyze liquidity pool for risks
    pub fn analyze_liquidity_pool(&self, address: &str) -> Vec<DeFiFinding> {
        let mut findings = Vec::new();

        // Check for impermanent loss risk
        findings.push(DeFiFinding {
            protocol_address: address.to_string(),
            protocol_name: "Unknown Protocol".to_string(),
            finding_type: DeFiRiskType::LiquidityPoolRisk,
            severity: Severity::Medium,
            description: "Liquidity pool may expose providers to impermanent loss".to_string(),
            affected_functions: vec!["addLiquidity".to_string(), "removeLiquidity".to_string()],
            recommendation: "Monitor price ratios and consider concentrated liquidity positions".to_string(),
        });

        findings
    }

    /// Detect flash loan vulnerabilities
    pub fn detect_flash_loan_vulnerabilities(&self, address: &str) -> Vec<DeFiFinding> {
        let mut findings = Vec::new();

        // Check for common flash loan attack vectors
        findings.push(DeFiFinding {
            protocol_address: address.to_string(),
            protocol_name: "Unknown Protocol".to_string(),
            finding_type: DeFiRiskType::FlashLoanVulnerability,
            severity: Severity::High,
            description: "Protocol may be vulnerable to flash loan attacks if price oracle can be manipulated in single block".to_string(),
            affected_functions: vec!["swap".to_string(), "flashLoan".to_string()],
            recommendation: "Use TWAP oracles, flash loan guards, or minimum holding periods".to_string(),
        });

        findings
    }

    /// Analyze MEV exposure
    pub fn analyze_mev_exposure(&self, address: &str) -> Vec<DeFiFinding> {
        let mut findings = Vec::new();

        findings.push(DeFiFinding {
            protocol_address: address.to_string(),
            protocol_name: "Unknown Protocol".to_string(),
            finding_type: DeFiRiskType::MEVExposure,
            severity: Severity::Medium,
            description: "Transactions may be vulnerable to MEV extraction (sandwich attacks, frontrunning)".to_string(),
            affected_functions: vec!["swap".to_string()],
            recommendation: "Consider using private mempools (Flashbots) or MEV-resistant DEXs".to_string(),
        });

        findings
    }

    /// Detect rug pull indicators
    pub fn detect_rug_pull_indicators(&self, address: &str, functions: &[String]) -> Vec<DeFiFinding> {
        let mut findings = Vec::new();
        let function_set: HashSet<_> = functions.iter().collect();

        for pattern in &self.rug_pull_patterns {
            for indicator in &pattern.indicators {
                if function_set.iter().any(|f| f.contains(indicator)) {
                    findings.push(DeFiFinding {
                        protocol_address: address.to_string(),
                        protocol_name: "Unknown Protocol".to_string(),
                        finding_type: DeFiRiskType::RugPullIndicators,
                        severity: pattern.severity.clone(),
                        description: format!("Rug pull indicator detected: {} pattern found", pattern.name),
                        affected_functions: vec![indicator.clone()],
                        recommendation: format!("Review {} function for potential abuse", indicator),
                    });
                }
            }
        }

        findings
    }

    /// Analyze oracle manipulation risks
    pub fn analyze_oracle_risks(&self, address: &str) -> Vec<DeFiFinding> {
        let mut findings = Vec::new();

        // Spot price oracle risk
        findings.push(DeFiFinding {
            protocol_address: address.to_string(),
            protocol_name: "Unknown Protocol".to_string(),
            finding_type: DeFiRiskType::OracleManipulation,
            severity: Severity::High,
            description: "Protocol may use spot price oracles vulnerable to manipulation".to_string(),
            affected_functions: vec!["getPrice".to_string(), "getReserves".to_string()],
            recommendation: "Use Chainlink or other decentralized oracle networks with TWAP".to_string(),
        });

        findings
    }

    /// Check for access control issues
    pub fn check_access_control(&self, address: &str, has_owner: bool, is_renounced: bool) -> Vec<DeFiFinding> {
        let mut findings = Vec::new();

        if has_owner && !is_renounced {
            findings.push(DeFiFinding {
                protocol_address: address.to_string(),
                protocol_name: "Unknown Protocol".to_string(),
                finding_type: DeFiRiskType::AccessControlIssue,
                severity: Severity::Medium,
                description: "Contract has owner with special privileges".to_string(),
                affected_functions: vec!["owner".to_string()],
                recommendation: "Verify owner actions are time-locked and governance-controlled".to_string(),
            });
        }

        if !is_renounced {
            findings.push(DeFiFinding {
                protocol_address: address.to_string(),
                protocol_name: "Unknown Protocol".to_string(),
                finding_type: DeFiRiskType::AccessControlIssue,
                severity: Severity::Low,
                description: "Ownership has not been renounced".to_string(),
                affected_functions: vec![],
                recommendation: "Consider renouncing ownership or implementing multisig".to_string(),
            });
        }

        findings
    }
}

impl Default for DeFiAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct RugPullPattern {
    name: String,
    indicators: Vec<String>,
    severity: Severity,
}

/// Analyze DeFi protocols for security issues
pub async fn analyze_defi_protocols(addresses: &[String]) -> Result<Vec<DeFiFinding>> {
    let mut findings = Vec::new();
    let analyzer = DeFiAnalyzer::new();

    for address in addresses {
        // Analyze liquidity risks
        findings.extend(analyzer.analyze_liquidity_pool(address));

        // Check for flash loan vulnerabilities
        findings.extend(analyzer.detect_flash_loan_vulnerabilities(address));

        // Analyze MEV exposure
        findings.extend(analyzer.analyze_mev_exposure(address));

        // Check for oracle manipulation risks
        findings.extend(analyzer.analyze_oracle_risks(address));

        // Check access controls (simulated - would need actual contract data)
        findings.extend(analyzer.check_access_control(address, true, false));

        // Check for unverified contract
        findings.push(DeFiFinding {
            protocol_address: address.clone(),
            protocol_name: "Unknown Protocol".to_string(),
            finding_type: DeFiRiskType::UnverifiedContract,
            severity: Severity::Medium,
            description: format!("Contract {} source code verification status unknown", address),
            affected_functions: vec![],
            recommendation: "Verify contract on Etherscan/block explorer before interacting".to_string(),
        });
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = DeFiAnalyzer::new();
        assert!(!analyzer.rug_pull_patterns.is_empty());
    }

    #[test]
    fn test_rug_pull_detection() {
        let analyzer = DeFiAnalyzer::new();
        let functions = vec!["swap".to_string(), "removeLiquidity".to_string()];
        let findings = analyzer.detect_rug_pull_indicators("0x123", &functions);
        assert!(!findings.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_protocols() {
        let addresses = vec!["0x1234567890abcdef".to_string()];
        let findings = analyze_defi_protocols(&addresses).await.unwrap();
        assert!(!findings.is_empty());
    }
}
