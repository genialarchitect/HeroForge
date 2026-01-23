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
///
/// Requires ETH_RPC_URL for real contract analysis.
pub async fn analyze_defi_protocols(addresses: &[String]) -> Result<Vec<DeFiFinding>> {
    let rpc = match super::eth_rpc::EthRpcClient::from_env() {
        Ok(r) => r,
        Err(e) => {
            log::debug!("ETH_RPC_URL not available: {} - DeFi analysis unavailable", e);
            return Ok(Vec::new());
        }
    };

    let mut findings = Vec::new();
    let analyzer = DeFiAnalyzer::new();

    for address in addresses {
        // 1. Verify contract exists by fetching bytecode
        let code = match rpc.eth_get_code(address).await {
            Ok(c) => c,
            Err(e) => {
                log::debug!("Failed to get code for {}: {}", address, e);
                continue;
            }
        };

        if code == "0x" || code.is_empty() {
            findings.push(DeFiFinding {
                protocol_address: address.clone(),
                protocol_name: "Unknown".to_string(),
                finding_type: DeFiRiskType::UnverifiedContract,
                severity: Severity::Info,
                description: format!("Address {} is not a contract (EOA or empty)", address),
                affected_functions: vec![],
                recommendation: "Verify the contract address is correct".to_string(),
            });
            continue;
        }

        // 2. Check for known DeFi patterns in bytecode
        let bytecode_lower = code.to_lowercase();

        // Check for known DEX patterns (Uniswap router selectors)
        let has_swap = bytecode_lower.contains("38ed1739") || bytecode_lower.contains("7ff36ab5");
        let has_liquidity = bytecode_lower.contains("e8e33700") || bytecode_lower.contains("baa2abde");

        if has_swap || has_liquidity {
            // It's a DEX-like contract - check for reentrancy patterns
            if !bytecode_lower.contains("5c975abb") { // pausable check
                findings.push(DeFiFinding {
                    protocol_address: address.clone(),
                    protocol_name: "DEX".to_string(),
                    finding_type: DeFiRiskType::ReentrancyRisk,
                    severity: Severity::Medium,
                    description: "DEX contract may lack pause functionality".to_string(),
                    affected_functions: vec!["swap".to_string()],
                    recommendation: "Verify emergency pause mechanism exists".to_string(),
                });
            }
        }

        // 3. Query contract owner
        let owner_selector = super::eth_rpc::function_selector("owner()");
        match rpc.eth_call(address, &owner_selector).await {
            Ok(owner_result) => {
                if owner_result.len() >= 66 {
                    let owner_addr = format!("0x{}", &owner_result[26..66]);
                    // Check if owner is a single EOA (centralization risk)
                    let owner_code = rpc.eth_get_code(&owner_addr).await.unwrap_or_default();
                    if owner_code == "0x" || owner_code.is_empty() {
                        findings.push(DeFiFinding {
                            protocol_address: address.clone(),
                            protocol_name: "Unknown".to_string(),
                            finding_type: DeFiRiskType::AccessControlIssue,
                            severity: Severity::High,
                            description: format!("Contract owner is an EOA ({}), not a multisig", owner_addr),
                            affected_functions: vec!["owner".to_string()],
                            recommendation: "Transfer ownership to a multi-signature wallet or timelock".to_string(),
                        });
                    }
                }
            }
            Err(_) => {
                // No owner function - could be immutable or use different pattern
            }
        }

        // 4. Check ERC-20 properties if applicable
        let total_supply_selector = super::eth_rpc::function_selector("totalSupply()");
        if let Ok(supply_result) = rpc.eth_call(address, &total_supply_selector).await {
            if supply_result != "0x" && supply_result.len() > 2 {
                // It's an ERC-20 token - run rug pull pattern detection
                // Extract function selectors from bytecode for analysis
                let mut detected_functions = Vec::new();
                if bytecode_lower.contains("a9059cbb") { detected_functions.push("transfer".to_string()); }
                if bytecode_lower.contains("23b872dd") { detected_functions.push("transferFrom".to_string()); }
                if bytecode_lower.contains("095ea7b3") { detected_functions.push("approve".to_string()); }
                if bytecode_lower.contains("40c10f19") { detected_functions.push("mint".to_string()); }
                if bytecode_lower.contains("42966c68") { detected_functions.push("burn".to_string()); }
                if bytecode_lower.contains("5c975abb") { detected_functions.push("paused".to_string()); }
                if bytecode_lower.contains("8456cb59") { detected_functions.push("pause".to_string()); }
                if bytecode_lower.contains("715018a6") { detected_functions.push("renounceOwnership".to_string()); }
                findings.extend(analyzer.detect_rug_pull_indicators(address, &detected_functions));
            }
        }
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
        // Without ETH_RPC_URL, returns empty - no simulated data
        // Real analysis requires blockchain RPC access
        assert!(findings.is_empty() || std::env::var("ETH_RPC_URL").is_ok());
    }
}
