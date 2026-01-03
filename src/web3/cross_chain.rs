//! Cross-chain bridge security analysis
//!
//! Security analysis for cross-chain bridges including:
//! - Bridge contract security
//! - Wrapped asset verification
//! - Oracle reliability assessment
//! - Validator set analysis

use super::types::*;
use anyhow::Result;
use std::collections::HashMap;

/// Cross-chain bridge analyzer
pub struct BridgeAnalyzer {
    /// Known bridge protocols with security ratings
    known_bridges: HashMap<String, BridgeRating>,
    /// Historical bridge exploits
    exploit_history: Vec<BridgeExploit>,
    /// Minimum TVL for consideration
    min_tvl: f64,
}

impl BridgeAnalyzer {
    pub fn new() -> Self {
        let mut known_bridges = HashMap::new();

        // Add known bridges with ratings
        known_bridges.insert("wormhole".to_string(), BridgeRating {
            security_score: 70,
            audited: true,
            has_bug_bounty: true,
            tvl_usd: 1_000_000_000.0,
            exploit_count: 1,
        });
        known_bridges.insert("multichain".to_string(), BridgeRating {
            security_score: 40,
            audited: true,
            has_bug_bounty: true,
            tvl_usd: 500_000_000.0,
            exploit_count: 2,
        });
        known_bridges.insert("layerzero".to_string(), BridgeRating {
            security_score: 80,
            audited: true,
            has_bug_bounty: true,
            tvl_usd: 2_000_000_000.0,
            exploit_count: 0,
        });
        known_bridges.insert("stargate".to_string(), BridgeRating {
            security_score: 75,
            audited: true,
            has_bug_bounty: true,
            tvl_usd: 500_000_000.0,
            exploit_count: 0,
        });

        let exploit_history = vec![
            BridgeExploit {
                bridge_name: "Ronin".to_string(),
                date: "2022-03-23".to_string(),
                amount_usd: 625_000_000.0,
                attack_type: "Validator Key Compromise".to_string(),
            },
            BridgeExploit {
                bridge_name: "Wormhole".to_string(),
                date: "2022-02-02".to_string(),
                amount_usd: 320_000_000.0,
                attack_type: "Signature Verification Bypass".to_string(),
            },
            BridgeExploit {
                bridge_name: "Nomad".to_string(),
                date: "2022-08-01".to_string(),
                amount_usd: 190_000_000.0,
                attack_type: "Message Verification Bug".to_string(),
            },
            BridgeExploit {
                bridge_name: "Harmony".to_string(),
                date: "2022-06-24".to_string(),
                amount_usd: 100_000_000.0,
                attack_type: "Multisig Compromise".to_string(),
            },
        ];

        Self {
            known_bridges,
            exploit_history,
            min_tvl: 10_000_000.0,
        }
    }

    /// Analyze bridge security
    pub fn analyze_bridge(&self, address: &str, bridge_name: &str) -> Vec<CrossChainFinding> {
        let mut findings = Vec::new();

        if let Some(rating) = self.known_bridges.get(&bridge_name.to_lowercase()) {
            // Check security score
            if rating.security_score < 60 {
                findings.push(CrossChainFinding {
                    bridge_address: address.to_string(),
                    bridge_name: bridge_name.to_string(),
                    chains: vec![],
                    finding_type: CrossChainRiskType::BridgeSecurity,
                    severity: Severity::High,
                    description: format!("Bridge security score ({}/100) is below recommended threshold", rating.security_score),
                    recommendation: "Consider using higher-rated bridges for cross-chain transfers".to_string(),
                });
            }

            // Check exploit history
            if rating.exploit_count > 0 {
                findings.push(CrossChainFinding {
                    bridge_address: address.to_string(),
                    bridge_name: bridge_name.to_string(),
                    chains: vec![],
                    finding_type: CrossChainRiskType::BridgeSecurity,
                    severity: if rating.exploit_count > 1 { Severity::High } else { Severity::Medium },
                    description: format!("Bridge has {} historical exploit(s)", rating.exploit_count),
                    recommendation: "Review exploit post-mortems and remediation measures".to_string(),
                });
            }

            // Check audit status
            if !rating.audited {
                findings.push(CrossChainFinding {
                    bridge_address: address.to_string(),
                    bridge_name: bridge_name.to_string(),
                    chains: vec![],
                    finding_type: CrossChainRiskType::BridgeSecurity,
                    severity: Severity::Critical,
                    description: "Bridge contracts have not been audited".to_string(),
                    recommendation: "Only use audited bridges for cross-chain transfers".to_string(),
                });
            }

            // Check bug bounty
            if !rating.has_bug_bounty {
                findings.push(CrossChainFinding {
                    bridge_address: address.to_string(),
                    bridge_name: bridge_name.to_string(),
                    chains: vec![],
                    finding_type: CrossChainRiskType::BridgeSecurity,
                    severity: Severity::Low,
                    description: "Bridge does not have an active bug bounty program".to_string(),
                    recommendation: "Bug bounties incentivize responsible vulnerability disclosure".to_string(),
                });
            }
        } else {
            findings.push(CrossChainFinding {
                bridge_address: address.to_string(),
                bridge_name: bridge_name.to_string(),
                chains: vec![],
                finding_type: CrossChainRiskType::BridgeSecurity,
                severity: Severity::High,
                description: "Bridge is not in known bridges database".to_string(),
                recommendation: "Research bridge security, audits, and team before use".to_string(),
            });
        }

        findings
    }

    /// Analyze wrapped asset risks
    pub fn analyze_wrapped_assets(&self, address: &str, bridge_name: &str, asset_name: &str) -> Vec<CrossChainFinding> {
        let mut findings = Vec::new();

        // Wrapped asset risks
        findings.push(CrossChainFinding {
            bridge_address: address.to_string(),
            bridge_name: bridge_name.to_string(),
            chains: vec![],
            finding_type: CrossChainRiskType::WrappedAssetRisk,
            severity: Severity::Medium,
            description: format!("Wrapped {} is backed by bridge reserves - if bridge is compromised, wrapped asset loses value", asset_name),
            recommendation: "Verify bridge reserves and consider wrapped asset risks".to_string(),
        });

        // Depegging risk
        findings.push(CrossChainFinding {
            bridge_address: address.to_string(),
            bridge_name: bridge_name.to_string(),
            chains: vec![],
            finding_type: CrossChainRiskType::WrappedAssetRisk,
            severity: Severity::Low,
            description: "Wrapped assets may trade at discount during bridge issues".to_string(),
            recommendation: "Monitor wrapped asset prices relative to underlying".to_string(),
        });

        findings
    }

    /// Analyze oracle reliability
    pub fn analyze_oracles(&self, address: &str, bridge_name: &str, oracle_type: &str) -> Vec<CrossChainFinding> {
        let mut findings = Vec::new();

        match oracle_type.to_lowercase().as_str() {
            "centralized" => {
                findings.push(CrossChainFinding {
                    bridge_address: address.to_string(),
                    bridge_name: bridge_name.to_string(),
                    chains: vec![],
                    finding_type: CrossChainRiskType::OracleFailure,
                    severity: Severity::High,
                    description: "Bridge uses centralized oracle for message verification".to_string(),
                    recommendation: "Centralized oracles are single points of failure".to_string(),
                });
            }
            "multisig" => {
                findings.push(CrossChainFinding {
                    bridge_address: address.to_string(),
                    bridge_name: bridge_name.to_string(),
                    chains: vec![],
                    finding_type: CrossChainRiskType::OracleFailure,
                    severity: Severity::Medium,
                    description: "Bridge uses multisig oracle - check threshold and key management".to_string(),
                    recommendation: "Verify multisig threshold is sufficient (e.g., 3/5 or higher)".to_string(),
                });
            }
            "decentralized" => {
                findings.push(CrossChainFinding {
                    bridge_address: address.to_string(),
                    bridge_name: bridge_name.to_string(),
                    chains: vec![],
                    finding_type: CrossChainRiskType::OracleFailure,
                    severity: Severity::Low,
                    description: "Bridge uses decentralized oracle network".to_string(),
                    recommendation: "Verify validator set diversity and stake distribution".to_string(),
                });
            }
            _ => {
                findings.push(CrossChainFinding {
                    bridge_address: address.to_string(),
                    bridge_name: bridge_name.to_string(),
                    chains: vec![],
                    finding_type: CrossChainRiskType::OracleFailure,
                    severity: Severity::High,
                    description: "Unknown oracle type - cannot assess reliability".to_string(),
                    recommendation: "Research oracle mechanism before using bridge".to_string(),
                });
            }
        }

        findings
    }

    /// Analyze validator set
    pub fn analyze_validators(&self, address: &str, bridge_name: &str, validator_count: u32, threshold: u32) -> Vec<CrossChainFinding> {
        let mut findings = Vec::new();

        if validator_count < 5 {
            findings.push(CrossChainFinding {
                bridge_address: address.to_string(),
                bridge_name: bridge_name.to_string(),
                chains: vec![],
                finding_type: CrossChainRiskType::ValidatorRisk,
                severity: Severity::High,
                description: format!("Bridge has only {} validators - high centralization risk", validator_count),
                recommendation: "Use bridges with larger, more decentralized validator sets".to_string(),
            });
        }

        if threshold < validator_count / 2 + 1 {
            findings.push(CrossChainFinding {
                bridge_address: address.to_string(),
                bridge_name: bridge_name.to_string(),
                chains: vec![],
                finding_type: CrossChainRiskType::ValidatorRisk,
                severity: Severity::Medium,
                description: format!("Threshold ({}/{}) is below majority", threshold, validator_count),
                recommendation: "Threshold should be at least majority (n/2 + 1)".to_string(),
            });
        }

        findings
    }

    /// Analyze message passing security
    pub fn analyze_message_passing(&self, address: &str, bridge_name: &str) -> Vec<CrossChainFinding> {
        let mut findings = Vec::new();

        // General message passing risks
        findings.push(CrossChainFinding {
            bridge_address: address.to_string(),
            bridge_name: bridge_name.to_string(),
            chains: vec![],
            finding_type: CrossChainRiskType::MessagePassingVulnerability,
            severity: Severity::Info,
            description: "Cross-chain message passing introduces latency and finality risks".to_string(),
            recommendation: "Wait for sufficient confirmations before considering transfers final".to_string(),
        });

        // Replay attack risks
        findings.push(CrossChainFinding {
            bridge_address: address.to_string(),
            bridge_name: bridge_name.to_string(),
            chains: vec![],
            finding_type: CrossChainRiskType::MessagePassingVulnerability,
            severity: Severity::Low,
            description: "Verify bridge implements replay protection".to_string(),
            recommendation: "Check nonce handling in bridge message verification".to_string(),
        });

        findings
    }
}

impl Default for BridgeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct BridgeRating {
    security_score: u8,
    audited: bool,
    has_bug_bounty: bool,
    tvl_usd: f64,
    exploit_count: u32,
}

#[derive(Debug, Clone)]
struct BridgeExploit {
    bridge_name: String,
    date: String,
    amount_usd: f64,
    attack_type: String,
}

/// Analyze cross-chain bridges for security issues
pub async fn analyze_bridges(addresses: &[String]) -> Result<Vec<CrossChainFinding>> {
    let mut findings = Vec::new();
    let analyzer = BridgeAnalyzer::new();

    for address in addresses {
        let bridge_name = "Unknown Bridge";

        // Analyze bridge security
        findings.extend(analyzer.analyze_bridge(address, bridge_name));

        // Analyze wrapped assets
        findings.extend(analyzer.analyze_wrapped_assets(address, bridge_name, "ETH"));

        // Analyze oracles
        findings.extend(analyzer.analyze_oracles(address, bridge_name, "unknown"));

        // Analyze validators
        findings.extend(analyzer.analyze_validators(address, bridge_name, 5, 3));

        // Analyze message passing
        findings.extend(analyzer.analyze_message_passing(address, bridge_name));

        // General bridge review
        findings.push(CrossChainFinding {
            bridge_address: address.clone(),
            bridge_name: bridge_name.to_string(),
            chains: vec![],
            finding_type: CrossChainRiskType::BridgeSecurity,
            severity: Severity::Info,
            description: format!("Bridge {} requires comprehensive security review", address),
            recommendation: "Review bridge architecture, audits, and validator set before use".to_string(),
        });
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_bridge_analysis() {
        let analyzer = BridgeAnalyzer::new();
        let findings = analyzer.analyze_bridge("0x123", "wormhole");
        // Should have exploit history finding
        assert!(findings.iter().any(|f| f.description.contains("exploit")));
    }

    #[test]
    fn test_unknown_bridge() {
        let analyzer = BridgeAnalyzer::new();
        let findings = analyzer.analyze_bridge("0x123", "unknown_bridge");
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn test_validator_analysis() {
        let analyzer = BridgeAnalyzer::new();

        // Low validator count
        let findings = analyzer.analyze_validators("0x123", "test", 3, 2);
        assert!(findings.iter().any(|f| f.finding_type == CrossChainRiskType::ValidatorRisk));
    }

    #[tokio::test]
    async fn test_analyze_bridges() {
        let addresses = vec!["0x1234567890abcdef".to_string()];
        let findings = analyze_bridges(&addresses).await.unwrap();
        assert!(!findings.is_empty());
    }
}
