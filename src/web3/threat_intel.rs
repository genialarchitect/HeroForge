//! Web3 threat intelligence
//!
//! Threat intelligence for Web3 ecosystems including:
//! - Scam token databases
//! - Phishing site databases
//! - Known exploit databases
//! - Threat actor tracking

use super::types::*;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc};

/// Web3 threat intelligence provider
pub struct Web3ThreatIntelProvider {
    /// Known scam tokens by address
    scam_tokens: HashMap<String, ScamToken>,
    /// Known phishing domains
    phishing_domains: HashSet<String>,
    /// Known exploits database
    known_exploits: Vec<KnownExploit>,
    /// Tracked threat actors
    threat_actors: Vec<ThreatActor>,
    /// Last update timestamp
    last_updated: DateTime<Utc>,
}

impl Web3ThreatIntelProvider {
    pub fn new() -> Self {
        let mut scam_tokens = HashMap::new();

        // Add known scam token patterns
        scam_tokens.insert(
            "0x0000000000000000000000000000000000000001".to_string(),
            ScamToken {
                address: "0x0000000000000000000000000000000000000001".to_string(),
                name: "Example Scam Token".to_string(),
                symbol: "SCAM".to_string(),
                scam_type: ScamType::RugPull,
                confidence: 0.99,
                description: "Known rug pull - liquidity removed".to_string(),
            },
        );

        let mut phishing_domains = HashSet::new();
        // Common phishing domain patterns
        phishing_domains.insert("uniswap-claim.io".to_string());
        phishing_domains.insert("opensea-airdrop.com".to_string());
        phishing_domains.insert("metamask-verify.com".to_string());
        phishing_domains.insert("pancakeswap-airdrop.io".to_string());
        phishing_domains.insert("eth-airdrop.org".to_string());

        let known_exploits = vec![
            KnownExploit {
                exploit_id: "REKT-2022-001".to_string(),
                name: "Ronin Bridge Hack".to_string(),
                affected_protocols: vec!["Ronin Network".to_string()],
                cve_id: None,
                date: "2022-03-23".to_string(),
                description: "Validator key compromise leading to $625M theft".to_string(),
            },
            KnownExploit {
                exploit_id: "REKT-2022-002".to_string(),
                name: "Wormhole Bridge Exploit".to_string(),
                affected_protocols: vec!["Wormhole".to_string()],
                cve_id: None,
                date: "2022-02-02".to_string(),
                description: "Signature verification bypass allowing unauthorized minting".to_string(),
            },
            KnownExploit {
                exploit_id: "REKT-2023-001".to_string(),
                name: "Euler Finance Exploit".to_string(),
                affected_protocols: vec!["Euler Finance".to_string()],
                cve_id: None,
                date: "2023-03-13".to_string(),
                description: "Flash loan attack exploiting collateral calculation bug".to_string(),
            },
            KnownExploit {
                exploit_id: "REKT-2024-001".to_string(),
                name: "Orbit Bridge Exploit".to_string(),
                affected_protocols: vec!["Orbit Bridge".to_string()],
                cve_id: None,
                date: "2024-01-01".to_string(),
                description: "Validator key compromise".to_string(),
            },
        ];

        let threat_actors = vec![
            ThreatActor {
                actor_id: "LAZARUS-GROUP".to_string(),
                known_addresses: vec![
                    "0x098B716B8Aaf21512996dC57EB0615e2383E2f96".to_string(),
                ],
                techniques: vec![
                    "Spear phishing".to_string(),
                    "Bridge exploits".to_string(),
                    "Social engineering".to_string(),
                ],
                last_activity: "2024-01-01".to_string(),
            },
            ThreatActor {
                actor_id: "RUG-PULL-GROUP-1".to_string(),
                known_addresses: vec![],
                techniques: vec![
                    "Liquidity removal".to_string(),
                    "Honeypot tokens".to_string(),
                    "Social media manipulation".to_string(),
                ],
                last_activity: "2024-12-01".to_string(),
            },
        ];

        Self {
            scam_tokens,
            phishing_domains,
            known_exploits,
            threat_actors,
            last_updated: Utc::now(),
        }
    }

    /// Check if token is a known scam
    pub fn check_scam_token(&self, address: &str) -> Option<&ScamToken> {
        self.scam_tokens.get(&address.to_lowercase())
    }

    /// Check if domain is known phishing
    pub fn check_phishing_domain(&self, url: &str) -> Option<PhishingSite> {
        let domain = extract_domain(url);

        for phishing_domain in &self.phishing_domains {
            if domain.contains(phishing_domain) || phishing_domain.contains(&domain) {
                return Some(PhishingSite {
                    url: url.to_string(),
                    target: identify_target(url),
                    first_seen: "Unknown".to_string(),
                    is_active: true,
                });
            }
        }

        // Pattern-based detection
        if is_suspicious_domain(&domain) {
            return Some(PhishingSite {
                url: url.to_string(),
                target: identify_target(url),
                first_seen: Utc::now().format("%Y-%m-%d").to_string(),
                is_active: true,
            });
        }

        None
    }

    /// Get exploit information for a protocol
    pub fn get_protocol_exploits(&self, protocol_name: &str) -> Vec<&KnownExploit> {
        self.known_exploits
            .iter()
            .filter(|e| e.affected_protocols.iter().any(|p| p.to_lowercase().contains(&protocol_name.to_lowercase())))
            .collect()
    }

    /// Check if address is associated with threat actor
    pub fn check_threat_actor(&self, address: &str) -> Option<&ThreatActor> {
        self.threat_actors
            .iter()
            .find(|actor| actor.known_addresses.contains(&address.to_string()))
    }

    /// Analyze contract for scam patterns
    pub fn analyze_scam_patterns(&self, address: &str, function_signatures: &[String]) -> Vec<ScamIndicator> {
        let mut indicators = Vec::new();

        // Honeypot indicators
        let honeypot_sigs = ["blacklist", "addBlacklist", "setBlacklist", "_isBlacklisted"];
        for sig in &honeypot_sigs {
            if function_signatures.iter().any(|f| f.to_lowercase().contains(*sig)) {
                indicators.push(ScamIndicator {
                    indicator_type: "Honeypot".to_string(),
                    description: format!("Contract has {} function which could block sells", sig),
                    severity: Severity::High,
                    confidence: 0.7,
                });
            }
        }

        // Fee manipulation
        let fee_sigs = ["setFee", "updateFee", "setTax", "updateTax"];
        for sig in &fee_sigs {
            if function_signatures.iter().any(|f| f.to_lowercase().contains(*sig)) {
                indicators.push(ScamIndicator {
                    indicator_type: "Fee Manipulation".to_string(),
                    description: format!("Contract has {} function allowing dynamic fees", sig),
                    severity: Severity::Medium,
                    confidence: 0.6,
                });
            }
        }

        // Unlimited minting
        if function_signatures.iter().any(|f| f.to_lowercase().contains("mint") && !f.contains("onlyOwner")) {
            indicators.push(ScamIndicator {
                indicator_type: "Unlimited Minting".to_string(),
                description: "Contract may allow unrestricted minting".to_string(),
                severity: Severity::High,
                confidence: 0.5,
            });
        }

        indicators
    }

    /// Get recent threats
    pub fn get_recent_threats(&self, days: u32) -> Vec<&KnownExploit> {
        // In production, would filter by date
        self.known_exploits.iter().take(5).collect()
    }

    /// Enrich address with threat data
    pub fn enrich_address(&self, address: &str) -> AddressEnrichment {
        let mut labels = Vec::new();
        let mut risk_score: f64 = 0.0;

        // Check scam token
        if self.check_scam_token(address).is_some() {
            labels.push("Known Scam".to_string());
            risk_score += 0.9;
        }

        // Check threat actor
        if self.check_threat_actor(address).is_some() {
            labels.push("Threat Actor".to_string());
            risk_score += 0.95;
        }

        AddressEnrichment {
            address: address.to_string(),
            labels,
            risk_score: risk_score.min(1.0),
            threat_intel_sources: vec!["Internal Database".to_string()],
        }
    }
}

impl Default for Web3ThreatIntelProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Scam indicator from pattern analysis
#[derive(Debug, Clone)]
pub struct ScamIndicator {
    pub indicator_type: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: f64,
}

/// Address enrichment result
#[derive(Debug, Clone)]
pub struct AddressEnrichment {
    pub address: String,
    pub labels: Vec<String>,
    pub risk_score: f64,
    pub threat_intel_sources: Vec<String>,
}

// Helper functions

fn extract_domain(url: &str) -> String {
    url.replace("https://", "")
        .replace("http://", "")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

fn identify_target(url: &str) -> String {
    let domain = url.to_lowercase();
    if domain.contains("uniswap") { return "Uniswap".to_string(); }
    if domain.contains("opensea") { return "OpenSea".to_string(); }
    if domain.contains("metamask") { return "MetaMask".to_string(); }
    if domain.contains("pancakeswap") { return "PancakeSwap".to_string(); }
    if domain.contains("aave") { return "Aave".to_string(); }
    "Unknown".to_string()
}

fn is_suspicious_domain(domain: &str) -> bool {
    let suspicious_patterns = [
        "claim", "airdrop", "verify", "validate", "sync",
        "connect-wallet", "update-wallet", "secure-wallet",
    ];

    let domain_lower = domain.to_lowercase();
    suspicious_patterns.iter().any(|p| domain_lower.contains(p))
}

/// Check for Web3 threat intelligence
pub async fn check_web3_threats(config: &Web3AssessmentConfig) -> Result<Web3ThreatIntel> {
    let provider = Web3ThreatIntelProvider::new();

    // Check for scam tokens
    let mut scam_tokens = Vec::new();
    for address in &config.contract_addresses {
        if let Some(scam) = provider.check_scam_token(address) {
            scam_tokens.push(scam.clone());
        }
    }

    // Check for phishing sites
    let mut phishing_sites = Vec::new();
    for url in &config.dapp_urls {
        if let Some(phishing) = provider.check_phishing_domain(url) {
            phishing_sites.push(phishing);
        }
    }

    // Get relevant exploits
    let known_exploits = provider.get_recent_threats(30)
        .into_iter()
        .cloned()
        .collect();

    // Get threat actors
    let threat_actors = provider.threat_actors.clone();

    Ok(Web3ThreatIntel {
        scam_tokens,
        phishing_sites,
        known_exploits,
        threat_actors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phishing_detection() {
        let provider = Web3ThreatIntelProvider::new();

        // Known phishing
        let result = provider.check_phishing_domain("https://uniswap-claim.io/");
        assert!(result.is_some());

        // Legitimate site
        let result = provider.check_phishing_domain("https://app.uniswap.org/");
        assert!(result.is_none());
    }

    #[test]
    fn test_suspicious_domain() {
        assert!(is_suspicious_domain("claim-your-eth.io"));
        assert!(is_suspicious_domain("metamask-verify.com"));
        assert!(!is_suspicious_domain("example.com"));
    }

    #[test]
    fn test_scam_patterns() {
        let provider = Web3ThreatIntelProvider::new();
        let functions = vec![
            "transfer".to_string(),
            "approve".to_string(),
            "setBlacklist".to_string(),
        ];

        let indicators = provider.analyze_scam_patterns("0x123", &functions);
        assert!(!indicators.is_empty());
        assert!(indicators.iter().any(|i| i.indicator_type == "Honeypot"));
    }

    #[test]
    fn test_exploit_lookup() {
        let provider = Web3ThreatIntelProvider::new();
        let exploits = provider.get_protocol_exploits("wormhole");
        assert!(!exploits.is_empty());
    }

    #[tokio::test]
    async fn test_check_threats() {
        let config = Web3AssessmentConfig {
            chain: BlockchainNetwork::Ethereum,
            contract_addresses: vec![],
            protocol_addresses: vec![],
            nft_addresses: vec![],
            addresses: vec![],
            bridge_addresses: vec![],
            dapp_urls: vec!["https://uniswap-claim.io".to_string()],
            wallet_addresses: vec![],
            exchange_endpoints: vec![],
            staking_addresses: vec![],
            scan_smart_contracts: false,
            scan_defi: false,
            scan_nfts: false,
            on_chain_analysis: false,
            cross_chain_analysis: false,
            scan_dapps: true,
            scan_wallets: false,
            scan_exchanges: false,
            scan_staking: false,
        };

        let result = check_web3_threats(&config).await.unwrap();
        assert!(!result.phishing_sites.is_empty());
    }
}
