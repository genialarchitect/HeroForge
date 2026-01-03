//! Exchange security monitoring
//!
//! Security analysis for centralized and decentralized exchanges including:
//! - CEX/DEX security analysis
//! - Wash trading detection
//! - API security testing
//! - Reserve verification

use super::types::*;
use anyhow::Result;
use std::collections::HashMap;

/// Exchange security analyzer
pub struct ExchangeAnalyzer {
    /// Known exchange security ratings
    exchange_ratings: HashMap<String, ExchangeRating>,
    /// Wash trading detection thresholds
    wash_trade_threshold: f64,
    /// Minimum liquidity depth for safety
    min_liquidity_depth: f64,
}

impl ExchangeAnalyzer {
    pub fn new() -> Self {
        let mut exchange_ratings = HashMap::new();
        // Add some known exchanges with security ratings
        exchange_ratings.insert("binance".to_string(), ExchangeRating { tier: 1, has_proof_of_reserves: true });
        exchange_ratings.insert("coinbase".to_string(), ExchangeRating { tier: 1, has_proof_of_reserves: true });
        exchange_ratings.insert("kraken".to_string(), ExchangeRating { tier: 1, has_proof_of_reserves: true });
        exchange_ratings.insert("uniswap".to_string(), ExchangeRating { tier: 1, has_proof_of_reserves: false }); // DEX

        Self {
            exchange_ratings,
            wash_trade_threshold: 0.3, // 30% of volume
            min_liquidity_depth: 100000.0, // $100k
        }
    }

    /// Analyze CEX security
    pub fn analyze_cex_security(&self, exchange_name: &str, endpoint: &str) -> Vec<ExchangeFinding> {
        let mut findings = Vec::new();

        if let Some(rating) = self.exchange_ratings.get(&exchange_name.to_lowercase()) {
            if !rating.has_proof_of_reserves {
                findings.push(ExchangeFinding {
                    exchange_name: exchange_name.to_string(),
                    endpoint: endpoint.to_string(),
                    finding_type: ExchangeRiskType::CEXSecurity,
                    severity: Severity::Medium,
                    description: "Exchange does not provide proof of reserves".to_string(),
                    recommendation: "Consider using exchanges with verifiable proof of reserves".to_string(),
                });
            }

            if rating.tier > 2 {
                findings.push(ExchangeFinding {
                    exchange_name: exchange_name.to_string(),
                    endpoint: endpoint.to_string(),
                    finding_type: ExchangeRiskType::CEXSecurity,
                    severity: Severity::High,
                    description: format!("Exchange has lower tier security rating (Tier {})", rating.tier),
                    recommendation: "Use well-established exchanges with strong security track records".to_string(),
                });
            }
        } else {
            findings.push(ExchangeFinding {
                exchange_name: exchange_name.to_string(),
                endpoint: endpoint.to_string(),
                finding_type: ExchangeRiskType::CEXSecurity,
                severity: Severity::High,
                description: "Exchange is not in known exchange database".to_string(),
                recommendation: "Research exchange reputation and regulatory compliance before use".to_string(),
            });
        }

        findings
    }

    /// Analyze DEX security
    pub fn analyze_dex_security(&self, exchange_name: &str, endpoint: &str, contract_verified: bool) -> Vec<ExchangeFinding> {
        let mut findings = Vec::new();

        if !contract_verified {
            findings.push(ExchangeFinding {
                exchange_name: exchange_name.to_string(),
                endpoint: endpoint.to_string(),
                finding_type: ExchangeRiskType::DEXSecurity,
                severity: Severity::High,
                description: "DEX smart contract source is not verified".to_string(),
                recommendation: "Only use DEXs with verified and audited smart contracts".to_string(),
            });
        }

        // General DEX risks
        findings.push(ExchangeFinding {
            exchange_name: exchange_name.to_string(),
            endpoint: endpoint.to_string(),
            finding_type: ExchangeRiskType::DEXSecurity,
            severity: Severity::Info,
            description: "DEX transactions are subject to MEV and frontrunning".to_string(),
            recommendation: "Consider using private mempools or MEV-protected DEXs".to_string(),
        });

        findings
    }

    /// Detect potential wash trading
    pub fn detect_wash_trading(&self, exchange_name: &str, endpoint: &str, volume_24h: f64, unique_traders: u64) -> Vec<ExchangeFinding> {
        let mut findings = Vec::new();

        // Simple heuristic: if volume per trader is abnormally high
        if unique_traders > 0 {
            let avg_volume_per_trader = volume_24h / unique_traders as f64;
            if avg_volume_per_trader > 1_000_000.0 {
                findings.push(ExchangeFinding {
                    exchange_name: exchange_name.to_string(),
                    endpoint: endpoint.to_string(),
                    finding_type: ExchangeRiskType::WashTradingDetection,
                    severity: Severity::Medium,
                    description: format!(
                        "Potential wash trading indicator: avg ${:.0} volume per trader",
                        avg_volume_per_trader
                    ),
                    recommendation: "Volume may be artificially inflated - verify with multiple sources".to_string(),
                });
            }
        }

        findings
    }

    /// Analyze liquidity depth
    pub fn analyze_liquidity(&self, exchange_name: &str, endpoint: &str, liquidity_usd: f64) -> Vec<ExchangeFinding> {
        let mut findings = Vec::new();

        if liquidity_usd < self.min_liquidity_depth {
            findings.push(ExchangeFinding {
                exchange_name: exchange_name.to_string(),
                endpoint: endpoint.to_string(),
                finding_type: ExchangeRiskType::LiquidityRisk,
                severity: Severity::High,
                description: format!(
                    "Low liquidity (${:.0}) increases slippage and manipulation risk",
                    liquidity_usd
                ),
                recommendation: "Use higher liquidity pools for large trades".to_string(),
            });
        }

        findings
    }

    /// Test API security
    pub fn analyze_api_security(&self, exchange_name: &str, endpoint: &str, uses_https: bool, has_rate_limiting: bool) -> Vec<ExchangeFinding> {
        let mut findings = Vec::new();

        if !uses_https {
            findings.push(ExchangeFinding {
                exchange_name: exchange_name.to_string(),
                endpoint: endpoint.to_string(),
                finding_type: ExchangeRiskType::APIVulnerability,
                severity: Severity::Critical,
                description: "Exchange API does not use HTTPS".to_string(),
                recommendation: "Never use exchange APIs without TLS encryption".to_string(),
            });
        }

        if !has_rate_limiting {
            findings.push(ExchangeFinding {
                exchange_name: exchange_name.to_string(),
                endpoint: endpoint.to_string(),
                finding_type: ExchangeRiskType::APIVulnerability,
                severity: Severity::Low,
                description: "API rate limiting not detected".to_string(),
                recommendation: "Implement client-side rate limiting to avoid account restrictions".to_string(),
            });
        }

        findings
    }

    /// Analyze withdrawal security
    pub fn analyze_withdrawal_security(&self, exchange_name: &str, endpoint: &str, has_2fa: bool, has_whitelist: bool) -> Vec<ExchangeFinding> {
        let mut findings = Vec::new();

        if !has_2fa {
            findings.push(ExchangeFinding {
                exchange_name: exchange_name.to_string(),
                endpoint: endpoint.to_string(),
                finding_type: ExchangeRiskType::WithdrawalRisk,
                severity: Severity::Critical,
                description: "Two-factor authentication not enabled for withdrawals".to_string(),
                recommendation: "Always enable 2FA for all exchange accounts".to_string(),
            });
        }

        if !has_whitelist {
            findings.push(ExchangeFinding {
                exchange_name: exchange_name.to_string(),
                endpoint: endpoint.to_string(),
                finding_type: ExchangeRiskType::WithdrawalRisk,
                severity: Severity::Medium,
                description: "Address whitelist not enabled for withdrawals".to_string(),
                recommendation: "Enable address whitelisting to prevent unauthorized withdrawals".to_string(),
            });
        }

        findings
    }
}

impl Default for ExchangeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct ExchangeRating {
    tier: u8,
    has_proof_of_reserves: bool,
}

/// Analyze exchange security
pub async fn analyze_exchanges(endpoints: &[String]) -> Result<Vec<ExchangeFinding>> {
    let mut findings = Vec::new();
    let analyzer = ExchangeAnalyzer::new();

    for endpoint in endpoints {
        let exchange_name = extract_exchange_name(endpoint);

        // Analyze CEX security
        findings.extend(analyzer.analyze_cex_security(&exchange_name, endpoint));

        // Analyze API security
        findings.extend(analyzer.analyze_api_security(
            &exchange_name,
            endpoint,
            endpoint.starts_with("https://"),
            true,
        ));

        // Analyze liquidity (simulated)
        findings.extend(analyzer.analyze_liquidity(&exchange_name, endpoint, 500000.0));

        // Analyze withdrawal security (simulated)
        findings.extend(analyzer.analyze_withdrawal_security(&exchange_name, endpoint, true, false));

        // Add general assessment finding
        findings.push(ExchangeFinding {
            exchange_name: exchange_name.clone(),
            endpoint: endpoint.clone(),
            finding_type: ExchangeRiskType::APIVulnerability,
            severity: Severity::Info,
            description: format!("Exchange {} requires comprehensive security assessment", exchange_name),
            recommendation: "Verify exchange regulatory status, insurance, and security practices".to_string(),
        });
    }

    Ok(findings)
}

fn extract_exchange_name(endpoint: &str) -> String {
    // Simple extraction - in production would use proper URL parsing
    endpoint
        .replace("https://", "")
        .replace("http://", "")
        .split('.')
        .next()
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cex_security() {
        let analyzer = ExchangeAnalyzer::new();
        let findings = analyzer.analyze_cex_security("binance", "https://api.binance.com");
        // Binance has proof of reserves, so should have minimal findings
        assert!(findings.is_empty() || findings.iter().all(|f| f.severity != Severity::High));
    }

    #[test]
    fn test_unknown_exchange() {
        let analyzer = ExchangeAnalyzer::new();
        let findings = analyzer.analyze_cex_security("unknown_exchange", "https://unknown.com");
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[tokio::test]
    async fn test_analyze_exchanges() {
        let endpoints = vec!["https://api.binance.com".to_string()];
        let findings = analyze_exchanges(&endpoints).await.unwrap();
        assert!(!findings.is_empty());
    }
}
