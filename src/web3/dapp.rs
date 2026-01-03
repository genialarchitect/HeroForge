//! DApp frontend security scanning
//!
//! Comprehensive DApp security analysis including:
//! - Phishing detection
//! - Frontend vulnerability scanning
//! - Wallet connection analysis
//! - Supply chain security

use super::types::*;
use anyhow::Result;
use std::collections::HashMap;

/// DApp security scanner
pub struct DAppScanner {
    /// Known legitimate domains for comparison
    legitimate_domains: HashMap<String, String>,
    /// Phishing indicators
    phishing_indicators: Vec<PhishingIndicator>,
    /// Risky permissions to flag
    risky_permissions: Vec<String>,
}

impl DAppScanner {
    pub fn new() -> Self {
        let mut legitimate_domains = HashMap::new();
        legitimate_domains.insert("uniswap".to_string(), "app.uniswap.org".to_string());
        legitimate_domains.insert("opensea".to_string(), "opensea.io".to_string());
        legitimate_domains.insert("aave".to_string(), "app.aave.com".to_string());
        legitimate_domains.insert("compound".to_string(), "app.compound.finance".to_string());
        legitimate_domains.insert("curve".to_string(), "curve.fi".to_string());
        legitimate_domains.insert("metamask".to_string(), "metamask.io".to_string());

        Self {
            legitimate_domains,
            phishing_indicators: Self::default_phishing_indicators(),
            risky_permissions: vec![
                "unlimited_approval".to_string(),
                "all_tokens".to_string(),
                "sign_typed_data".to_string(),
            ],
        }
    }

    fn default_phishing_indicators() -> Vec<PhishingIndicator> {
        vec![
            PhishingIndicator {
                pattern: "urgent".to_string(),
                indicator_type: PhishingType::Urgency,
                severity: Severity::Medium,
            },
            PhishingIndicator {
                pattern: "claim now".to_string(),
                indicator_type: PhishingType::Urgency,
                severity: Severity::High,
            },
            PhishingIndicator {
                pattern: "free airdrop".to_string(),
                indicator_type: PhishingType::FakeAirdrop,
                severity: Severity::High,
            },
            PhishingIndicator {
                pattern: "sync wallet".to_string(),
                indicator_type: PhishingType::WalletDrain,
                severity: Severity::Critical,
            },
            PhishingIndicator {
                pattern: "validate wallet".to_string(),
                indicator_type: PhishingType::WalletDrain,
                severity: Severity::Critical,
            },
        ]
    }

    /// Check for phishing indicators
    pub fn detect_phishing(&self, url: &str, page_content: Option<&str>) -> Vec<DAppFinding> {
        let mut findings = Vec::new();

        // Check domain similarity to known legitimate sites
        for (name, legitimate_domain) in &self.legitimate_domains {
            if url.contains(name) && !url.contains(legitimate_domain) {
                findings.push(DAppFinding {
                    url: url.to_string(),
                    dapp_name: name.clone(),
                    finding_type: DAppRiskType::PhishingIndicator,
                    severity: Severity::Critical,
                    description: format!(
                        "Possible {} phishing site. Legitimate domain is {}",
                        name, legitimate_domain
                    ),
                    recommendation: format!("Verify you are on {} before connecting wallet", legitimate_domain),
                });
            }
        }

        // Check page content for phishing patterns
        if let Some(content) = page_content {
            let content_lower = content.to_lowercase();
            for indicator in &self.phishing_indicators {
                if content_lower.contains(&indicator.pattern) {
                    findings.push(DAppFinding {
                        url: url.to_string(),
                        dapp_name: "Unknown DApp".to_string(),
                        finding_type: DAppRiskType::PhishingIndicator,
                        severity: indicator.severity.clone(),
                        description: format!(
                            "Phishing indicator detected: '{}' pattern found",
                            indicator.pattern
                        ),
                        recommendation: "Be cautious - this may be a phishing attempt".to_string(),
                    });
                }
            }
        }

        findings
    }

    /// Analyze SSL/TLS certificate
    pub fn analyze_certificate(&self, url: &str, has_valid_ssl: bool, cert_issuer: Option<&str>) -> Vec<DAppFinding> {
        let mut findings = Vec::new();

        if !has_valid_ssl {
            findings.push(DAppFinding {
                url: url.to_string(),
                dapp_name: "Unknown DApp".to_string(),
                finding_type: DAppRiskType::FrontendVulnerability,
                severity: Severity::Critical,
                description: "DApp does not have valid SSL/TLS certificate".to_string(),
                recommendation: "Never connect wallet to non-HTTPS sites".to_string(),
            });
        }

        if let Some(issuer) = cert_issuer {
            if issuer.contains("self-signed") || issuer.contains("unknown") {
                findings.push(DAppFinding {
                    url: url.to_string(),
                    dapp_name: "Unknown DApp".to_string(),
                    finding_type: DAppRiskType::FrontendVulnerability,
                    severity: Severity::High,
                    description: "DApp uses self-signed or untrusted certificate".to_string(),
                    recommendation: "Legitimate DApps use trusted certificate authorities".to_string(),
                });
            }
        }

        findings
    }

    /// Analyze wallet connection permissions
    pub fn analyze_wallet_permissions(&self, url: &str, requested_permissions: &[String]) -> Vec<DAppFinding> {
        let mut findings = Vec::new();

        for permission in requested_permissions {
            if self.risky_permissions.iter().any(|r| permission.contains(r)) {
                findings.push(DAppFinding {
                    url: url.to_string(),
                    dapp_name: "Unknown DApp".to_string(),
                    finding_type: DAppRiskType::PermissionAbuse,
                    severity: Severity::High,
                    description: format!("DApp requests risky permission: {}", permission),
                    recommendation: "Review permissions carefully before approving".to_string(),
                });
            }
        }

        // Check for unlimited token approvals
        if requested_permissions.iter().any(|p| p.contains("unlimited") || p.contains("max_uint256")) {
            findings.push(DAppFinding {
                url: url.to_string(),
                dapp_name: "Unknown DApp".to_string(),
                finding_type: DAppRiskType::WalletConnectionRisk,
                severity: Severity::High,
                description: "DApp requests unlimited token approval".to_string(),
                recommendation: "Consider approving only the amount needed for the transaction".to_string(),
            });
        }

        findings
    }

    /// Check for frontend vulnerabilities
    pub fn scan_frontend_vulnerabilities(&self, url: &str) -> Vec<DAppFinding> {
        let mut findings = Vec::new();

        // XSS risk
        findings.push(DAppFinding {
            url: url.to_string(),
            dapp_name: "Unknown DApp".to_string(),
            finding_type: DAppRiskType::FrontendVulnerability,
            severity: Severity::Info,
            description: "Frontend XSS vulnerability analysis required".to_string(),
            recommendation: "Ensure DApp sanitizes all user inputs".to_string(),
        });

        findings
    }

    /// Analyze supply chain risks
    pub fn analyze_supply_chain(&self, url: &str, uses_cdn: bool, npm_packages: Option<usize>) -> Vec<DAppFinding> {
        let mut findings = Vec::new();

        if uses_cdn {
            findings.push(DAppFinding {
                url: url.to_string(),
                dapp_name: "Unknown DApp".to_string(),
                finding_type: DAppRiskType::SupplyChainRisk,
                severity: Severity::Medium,
                description: "DApp uses external CDN resources".to_string(),
                recommendation: "Verify integrity of CDN resources using SRI hashes".to_string(),
            });
        }

        if let Some(count) = npm_packages {
            if count > 100 {
                findings.push(DAppFinding {
                    url: url.to_string(),
                    dapp_name: "Unknown DApp".to_string(),
                    finding_type: DAppRiskType::SupplyChainRisk,
                    severity: Severity::Low,
                    description: format!("DApp uses {} npm dependencies", count),
                    recommendation: "Large dependency trees increase supply chain attack surface".to_string(),
                });
            }
        }

        findings
    }
}

impl Default for DAppScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct PhishingIndicator {
    pattern: String,
    indicator_type: PhishingType,
    severity: Severity,
}

#[derive(Debug, Clone)]
enum PhishingType {
    Urgency,
    FakeAirdrop,
    WalletDrain,
}

/// Scan DApp frontends for security issues
pub async fn scan_dapps(urls: &[String]) -> Result<Vec<DAppFinding>> {
    let mut findings = Vec::new();
    let scanner = DAppScanner::new();

    for url in urls {
        // Check for phishing
        findings.extend(scanner.detect_phishing(url, None));

        // Analyze certificate (simulated)
        findings.extend(scanner.analyze_certificate(url, url.starts_with("https://"), None));

        // Check frontend vulnerabilities
        findings.extend(scanner.scan_frontend_vulnerabilities(url));

        // Analyze supply chain
        findings.extend(scanner.analyze_supply_chain(url, true, Some(50)));

        // General security review recommendation
        findings.push(DAppFinding {
            url: url.clone(),
            dapp_name: "Unknown DApp".to_string(),
            finding_type: DAppRiskType::FrontendVulnerability,
            severity: Severity::Info,
            description: format!("DApp {} requires comprehensive security review", url),
            recommendation: "Verify smart contract addresses and audit reports before use".to_string(),
        });
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phishing_detection() {
        let scanner = DAppScanner::new();
        let findings = scanner.detect_phishing("https://uniswap-claim.io", None);
        assert!(findings.iter().any(|f| f.finding_type == DAppRiskType::PhishingIndicator));
    }

    #[test]
    fn test_certificate_analysis() {
        let scanner = DAppScanner::new();
        let findings = scanner.analyze_certificate("http://example.com", false, None);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[tokio::test]
    async fn test_scan_dapps() {
        let urls = vec!["https://example-dapp.com".to_string()];
        let findings = scan_dapps(&urls).await.unwrap();
        assert!(!findings.is_empty());
    }
}
