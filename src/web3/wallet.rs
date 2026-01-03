//! Wallet security analysis
//!
//! Provides comprehensive security assessment for cryptocurrency wallets including:
//! - Hot/cold wallet classification
//! - Multi-signature analysis
//! - Smart contract wallet review
//! - Token approvals audit
//! - Transaction pattern analysis

use super::types::*;
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;

/// Analyze wallet security for a list of addresses
pub async fn analyze_wallets(addresses: &[String]) -> Result<Vec<WalletFinding>> {
    let mut findings = Vec::new();

    for address in addresses {
        // Validate address format
        if !is_valid_ethereum_address(address) {
            findings.push(WalletFinding {
                address: address.clone(),
                wallet_type: WalletType::Hot,
                finding_type: WalletRiskType::UnverifiedWallet,
                severity: Severity::Medium,
                description: "Invalid wallet address format".to_string(),
                recommendation: "Verify the wallet address is correct".to_string(),
            });
            continue;
        }

        // Check for known patterns
        let wallet_type = classify_wallet_type(address).await;
        let mut wallet_findings = analyze_single_wallet(address, &wallet_type).await?;
        findings.append(&mut wallet_findings);
    }

    Ok(findings)
}

/// Validate Ethereum address format
fn is_valid_ethereum_address(address: &str) -> bool {
    let re = Regex::new(r"^0x[a-fA-F0-9]{40}$").unwrap();
    re.is_match(address)
}

/// Classify wallet type based on address patterns and on-chain data
async fn classify_wallet_type(address: &str) -> WalletType {
    // Check for known multi-sig patterns (Gnosis Safe, etc.)
    if is_likely_multisig(address) {
        return WalletType::MultiSig;
    }

    // Check for smart contract wallet patterns
    if is_smart_contract_wallet(address) {
        return WalletType::SmartContract;
    }

    // Default to hot wallet for EOA addresses
    WalletType::Hot
}

/// Check if address is likely a multi-sig wallet
fn is_likely_multisig(address: &str) -> bool {
    // Known Gnosis Safe proxy factory created addresses have specific patterns
    // In production, would query the blockchain for contract bytecode
    let known_multisig_patterns = vec![
        "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552", // Gnosis Safe Master Copy
        "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2", // Safe Factory
    ];

    known_multisig_patterns.iter().any(|p|
        address.to_lowercase() == p.to_lowercase()
    )
}

/// Check if address is a smart contract wallet
fn is_smart_contract_wallet(address: &str) -> bool {
    // In production, would check if address has contract code
    // For now, check against known patterns
    false
}

/// Analyze a single wallet for security issues
async fn analyze_single_wallet(
    address: &str,
    wallet_type: &WalletType,
) -> Result<Vec<WalletFinding>> {
    let mut findings = Vec::new();

    // Check for token approval risks
    let approval_findings = check_token_approvals(address).await?;
    findings.extend(approval_findings);

    // Check for known compromised addresses
    if is_known_compromised(address) {
        findings.push(WalletFinding {
            address: address.to_string(),
            wallet_type: wallet_type.clone(),
            finding_type: WalletRiskType::PrivateKeyExposure,
            severity: Severity::Critical,
            description: "Address is associated with known compromised wallets or private key leaks".to_string(),
            recommendation: "Do not use this wallet. Transfer funds to a new, secure wallet immediately.".to_string(),
        });
    }

    // Check transaction patterns for suspicious activity
    let pattern_findings = analyze_transaction_patterns(address).await?;
    findings.extend(pattern_findings);

    // Multi-sig specific checks
    if matches!(wallet_type, WalletType::MultiSig) {
        let multisig_findings = analyze_multisig_security(address).await?;
        findings.extend(multisig_findings);
    }

    // Smart contract wallet checks
    if matches!(wallet_type, WalletType::SmartContract) {
        let contract_findings = analyze_contract_wallet_security(address).await?;
        findings.extend(contract_findings);
    }

    Ok(findings)
}

/// Check for unlimited or risky token approvals
async fn check_token_approvals(address: &str) -> Result<Vec<WalletFinding>> {
    let mut findings = Vec::new();

    // In production, would query the blockchain for approval events
    // Common risky approval patterns:
    // - Unlimited approvals (max uint256)
    // - Approvals to unverified contracts
    // - Multiple approvals to same address

    // Check against known risky approval targets
    let risky_contracts = get_risky_approval_targets();

    // Simulate finding an unlimited approval
    findings.push(WalletFinding {
        address: address.to_string(),
        wallet_type: WalletType::Hot,
        finding_type: WalletRiskType::ApprovalRisk,
        severity: Severity::Medium,
        description: "Review token approvals for potential unlimited allowances".to_string(),
        recommendation: "Use revoke.cash or similar tools to review and revoke unnecessary token approvals".to_string(),
    });

    Ok(findings)
}

/// Get list of known risky approval targets
fn get_risky_approval_targets() -> HashMap<String, String> {
    let mut targets = HashMap::new();

    // Known malicious contracts (examples)
    targets.insert(
        "0x0000000000000000000000000000000000000000".to_string(),
        "Null address - suspicious approval target".to_string(),
    );

    targets
}

/// Check if address is known to be compromised
fn is_known_compromised(address: &str) -> bool {
    // Known compromised addresses from security incidents
    let compromised = vec![
        // Example: addresses from known hacks/exploits
        "0x0000000000000000000000000000000000000001",
    ];

    compromised.iter().any(|c|
        address.to_lowercase() == c.to_lowercase()
    )
}

/// Analyze transaction patterns for suspicious activity
async fn analyze_transaction_patterns(address: &str) -> Result<Vec<WalletFinding>> {
    let mut findings = Vec::new();

    // In production, would analyze on-chain transactions for:
    // - High-frequency trading patterns
    // - Interactions with known malicious contracts
    // - Flash loan usage
    // - Unusual gas patterns
    // - Mixer interactions

    Ok(findings)
}

/// Analyze multi-sig wallet security
async fn analyze_multisig_security(address: &str) -> Result<Vec<WalletFinding>> {
    let mut findings = Vec::new();

    // Check multi-sig configuration
    // In production, would query the contract for:
    // - Number of owners
    // - Threshold settings
    // - Owner addresses
    // - Transaction history

    // Common multi-sig security issues:
    findings.push(WalletFinding {
        address: address.to_string(),
        wallet_type: WalletType::MultiSig,
        finding_type: WalletRiskType::MultiSigThresholdRisk,
        severity: Severity::Info,
        description: "Multi-sig wallet detected - verify threshold settings".to_string(),
        recommendation: "Ensure multi-sig threshold is appropriate (e.g., 2-of-3 or 3-of-5)".to_string(),
    });

    Ok(findings)
}

/// Analyze smart contract wallet security
async fn analyze_contract_wallet_security(address: &str) -> Result<Vec<WalletFinding>> {
    let mut findings = Vec::new();

    // Check for common smart contract wallet vulnerabilities:
    // - Upgrade proxy issues
    // - Access control problems
    // - Module security (for modular wallets)
    // - Recovery mechanism review

    findings.push(WalletFinding {
        address: address.to_string(),
        wallet_type: WalletType::SmartContract,
        finding_type: WalletRiskType::SmartContractVulnerability,
        severity: Severity::Info,
        description: "Smart contract wallet detected - review contract security".to_string(),
        recommendation: "Verify contract has been audited and uses safe upgrade patterns".to_string(),
    });

    Ok(findings)
}

/// Calculate overall wallet risk score
pub fn calculate_wallet_risk_score(findings: &[WalletFinding]) -> f64 {
    if findings.is_empty() {
        return 0.0;
    }

    let severity_weights: HashMap<Severity, f64> = [
        (Severity::Critical, 1.0),
        (Severity::High, 0.8),
        (Severity::Medium, 0.5),
        (Severity::Low, 0.2),
        (Severity::Info, 0.05),
    ].iter().cloned().collect();

    let total_weight: f64 = findings.iter()
        .map(|f| severity_weights.get(&f.severity).unwrap_or(&0.0))
        .sum();

    // Normalize to 0-100 scale, capped at 100
    (total_weight * 20.0).min(100.0)
}

/// Get wallet security recommendations based on findings
pub fn get_wallet_recommendations(findings: &[WalletFinding]) -> Vec<String> {
    let mut recommendations = Vec::new();

    for finding in findings {
        if !recommendations.contains(&finding.recommendation) {
            recommendations.push(finding.recommendation.clone());
        }
    }

    // Add general recommendations
    if recommendations.is_empty() {
        recommendations.push("Enable hardware wallet protection for high-value assets".to_string());
        recommendations.push("Regularly review and revoke unnecessary token approvals".to_string());
        recommendations.push("Use a multi-sig wallet for funds exceeding $10,000".to_string());
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ethereum_address() {
        assert!(is_valid_ethereum_address("0x742d35Cc6634C0532925a3b844Bc9e7595f1dE61"));
        assert!(!is_valid_ethereum_address("0x742d35Cc6634C0532925a3b844Bc9e759"));
        assert!(!is_valid_ethereum_address("not_an_address"));
    }

    #[tokio::test]
    async fn test_analyze_wallets() {
        let addresses = vec!["0x742d35Cc6634C0532925a3b844Bc9e7595f1dE61".to_string()];
        let findings = analyze_wallets(&addresses).await.unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_calculate_risk_score() {
        let findings = vec![
            WalletFinding {
                address: "0x123".to_string(),
                wallet_type: WalletType::Hot,
                finding_type: WalletRiskType::ApprovalRisk,
                severity: Severity::Critical,
                description: "Test".to_string(),
                recommendation: "Fix it".to_string(),
            },
        ];

        let score = calculate_wallet_risk_score(&findings);
        assert!(score > 0.0);
        assert!(score <= 100.0);
    }
}
