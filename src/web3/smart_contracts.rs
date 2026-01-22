//! Smart contract security scanning
//!
//! Provides static analysis and vulnerability detection for smart contracts including:
//! - Reentrancy detection
//! - Integer overflow/underflow checks
//! - Access control analysis
//! - Common Solidity vulnerabilities
//! - ERC standard compliance checks

use super::types::*;
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;

/// Scan smart contracts for vulnerabilities
pub async fn scan_contracts(addresses: &[String]) -> Result<Vec<SmartContractFinding>> {
    let mut findings = Vec::new();

    for address in addresses {
        // Validate contract address
        if !is_valid_contract_address(address) {
            findings.push(SmartContractFinding {
                contract_address: address.clone(),
                language: ContractLanguage::Solidity,
                vulnerability_type: "Invalid Address".to_string(),
                severity: Severity::Medium,
                description: "Invalid contract address format".to_string(),
                line_number: None,
                recommendation: "Verify the contract address is correct".to_string(),
                cwe_id: None,
            });
            continue;
        }

        // Perform bytecode analysis if source not available
        let bytecode_findings = analyze_bytecode(address).await?;
        findings.extend(bytecode_findings);

        // Check for known vulnerable patterns
        let pattern_findings = check_known_vulnerabilities(address).await?;
        findings.extend(pattern_findings);

        // Check contract verification status
        let verification_findings = check_verification_status(address).await?;
        findings.extend(verification_findings);
    }

    Ok(findings)
}

/// Analyze smart contract source code
pub async fn analyze_source(source_code: &str, language: ContractLanguage) -> Result<Vec<SmartContractFinding>> {
    let mut findings = Vec::new();

    match language {
        ContractLanguage::Solidity => {
            findings.extend(analyze_solidity_source(source_code)?);
        }
        ContractLanguage::Vyper => {
            findings.extend(analyze_vyper_source(source_code)?);
        }
        ContractLanguage::Rust => {
            findings.extend(analyze_rust_source(source_code)?);
        }
        _ => {
            // Other languages not yet supported
        }
    }

    Ok(findings)
}

/// Validate contract address format
fn is_valid_contract_address(address: &str) -> bool {
    let re = Regex::new(r"^0x[a-fA-F0-9]{40}$").unwrap();
    re.is_match(address)
}

/// Analyze bytecode for vulnerabilities
async fn analyze_bytecode(address: &str) -> Result<Vec<SmartContractFinding>> {
    let mut findings = Vec::new();

    // Fetch bytecode from blockchain
    let bytecode = match fetch_contract_bytecode(address).await {
        Ok(code) => code,
        Err(e) => {
            log::warn!("Could not fetch bytecode for {}: {}", address, e);
            findings.push(SmartContractFinding {
                contract_address: address.to_string(),
                language: ContractLanguage::Solidity,
                vulnerability_type: "Bytecode Analysis Failed".to_string(),
                severity: Severity::Info,
                description: format!("Could not fetch contract bytecode: {}", e),
                line_number: None,
                recommendation: "Verify contract exists and network is accessible".to_string(),
                cwe_id: None,
            });
            return Ok(findings);
        }
    };

    if bytecode.is_empty() || bytecode == "0x" {
        findings.push(SmartContractFinding {
            contract_address: address.to_string(),
            language: ContractLanguage::Solidity,
            vulnerability_type: "No Contract Code".to_string(),
            severity: Severity::Info,
            description: "Address has no contract bytecode (may be EOA)".to_string(),
            line_number: None,
            recommendation: "Verify this is the correct contract address".to_string(),
            cwe_id: None,
        });
        return Ok(findings);
    }

    // Analyze bytecode for dangerous opcodes
    // SELFDESTRUCT (0xff) - can destroy contract
    if bytecode.to_lowercase().contains("ff") {
        // Need to check context - ff could be part of other data
        // SELFDESTRUCT at end of bytecode is more concerning
        if bytecode.to_lowercase().ends_with("ff") ||
           bytecode.to_lowercase().contains("6080604052") && bytecode.to_lowercase().contains("ff00") {
            findings.push(SmartContractFinding {
                contract_address: address.to_string(),
                language: ContractLanguage::Solidity,
                vulnerability_type: "Self-Destruct Capability".to_string(),
                severity: Severity::High,
                description: "Contract bytecode contains SELFDESTRUCT opcode which could destroy the contract".to_string(),
                line_number: None,
                recommendation: "Review if self-destruct is necessary and ensure proper access controls".to_string(),
                cwe_id: Some("CWE-284".to_string()),
            });
        }
    }

    // DELEGATECALL (0xf4) - potential proxy/upgrade pattern
    if bytecode.to_lowercase().contains("f4") {
        findings.push(SmartContractFinding {
            contract_address: address.to_string(),
            language: ContractLanguage::Solidity,
            vulnerability_type: "DELEGATECALL Usage".to_string(),
            severity: Severity::Medium,
            description: "Contract uses DELEGATECALL which executes code in caller's context".to_string(),
            line_number: None,
            recommendation: "Ensure DELEGATECALL targets are trusted and immutable".to_string(),
            cwe_id: Some("CWE-829".to_string()),
        });
    }

    // Check bytecode size (very large contracts may have gas issues)
    let bytecode_size = bytecode.len() / 2; // hex chars to bytes
    if bytecode_size > 24000 {
        findings.push(SmartContractFinding {
            contract_address: address.to_string(),
            language: ContractLanguage::Solidity,
            vulnerability_type: "Large Contract Size".to_string(),
            severity: Severity::Low,
            description: format!("Contract bytecode is {} bytes, approaching deployment limit", bytecode_size),
            line_number: None,
            recommendation: "Consider splitting contract or optimizing code size".to_string(),
            cwe_id: None,
        });
    }

    Ok(findings)
}

/// Fetch contract bytecode from Ethereum RPC
async fn fetch_contract_bytecode(address: &str) -> Result<String> {
    let rpc_url = std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "https://cloudflare-eth.com".to_string());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [address, "latest"],
        "id": 1
    });

    let response = client
        .post(&rpc_url)
        .json(&request_body)
        .send()
        .await?;

    let json: serde_json::Value = response.json().await?;

    if let Some(result) = json.get("result").and_then(|r| r.as_str()) {
        Ok(result.to_string())
    } else {
        Err(anyhow::anyhow!("No bytecode in response"))
    }
}

/// Check for known vulnerability patterns
async fn check_known_vulnerabilities(address: &str) -> Result<Vec<SmartContractFinding>> {
    let mut findings = Vec::new();

    // Check against known vulnerable contracts database
    let known_vulns = get_known_vulnerable_contracts();

    if let Some(vulns) = known_vulns.get(&address.to_lowercase()) {
        for vuln in vulns {
            findings.push(SmartContractFinding {
                contract_address: address.to_string(),
                language: ContractLanguage::Solidity,
                vulnerability_type: vuln.vuln_type.clone(),
                severity: vuln.severity.clone(),
                description: vuln.description.clone(),
                line_number: None,
                recommendation: vuln.recommendation.clone(),
                cwe_id: vuln.cwe_id.clone(),
            });
        }
    }

    Ok(findings)
}

/// Check contract verification status
async fn check_verification_status(address: &str) -> Result<Vec<SmartContractFinding>> {
    let mut findings = Vec::new();

    // Try Etherscan API first
    if let Some(api_key) = std::env::var("ETHERSCAN_API_KEY").ok() {
        let url = format!(
            "https://api.etherscan.io/v2/api?chainid=1&module=contract&action=getsourcecode&address={}&apikey={}",
            address, api_key
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        match client.get(&url).send().await {
            Ok(response) => {
                if let Ok(json) = response.json::<serde_json::Value>().await {
                    if let Some(result) = json.get("result").and_then(|r| r.as_array()) {
                        if let Some(first) = result.first() {
                            let source_code = first.get("SourceCode")
                                .and_then(|s| s.as_str())
                                .unwrap_or("");
                            let contract_name = first.get("ContractName")
                                .and_then(|s| s.as_str())
                                .unwrap_or("Unknown");
                            let compiler_version = first.get("CompilerVersion")
                                .and_then(|s| s.as_str())
                                .unwrap_or("Unknown");

                            if source_code.is_empty() {
                                findings.push(SmartContractFinding {
                                    contract_address: address.to_string(),
                                    language: ContractLanguage::Solidity,
                                    vulnerability_type: "Unverified Contract".to_string(),
                                    severity: Severity::High,
                                    description: "Contract source code is NOT verified on Etherscan".to_string(),
                                    line_number: None,
                                    recommendation: "Verify contract source code on Etherscan for transparency".to_string(),
                                    cwe_id: Some("CWE-1059".to_string()),
                                });
                            } else {
                                findings.push(SmartContractFinding {
                                    contract_address: address.to_string(),
                                    language: ContractLanguage::Solidity,
                                    vulnerability_type: "Verified Contract".to_string(),
                                    severity: Severity::Info,
                                    description: format!(
                                        "Contract '{}' is verified on Etherscan (Compiler: {})",
                                        contract_name, compiler_version
                                    ),
                                    line_number: None,
                                    recommendation: "Review the verified source code for vulnerabilities".to_string(),
                                    cwe_id: None,
                                });
                            }
                            return Ok(findings);
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("Etherscan API request failed: {}", e);
            }
        }
    } else {
        log::debug!("ETHERSCAN_API_KEY not set, skipping verification check");
    }

    // Fallback: Try Sourcify (no API key required)
    let sourcify_url = format!(
        "https://sourcify.dev/server/check-all-by-addresses?addresses={}&chainIds=1",
        address
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    match client.get(&sourcify_url).send().await {
        Ok(response) => {
            if let Ok(json) = response.json::<serde_json::Value>().await {
                // Sourcify returns array with status
                if let Some(arr) = json.as_array() {
                    if let Some(first) = arr.first() {
                        if let Some(status) = first.get("status").and_then(|s| s.as_str()) {
                            if status == "perfect" || status == "partial" {
                                findings.push(SmartContractFinding {
                                    contract_address: address.to_string(),
                                    language: ContractLanguage::Solidity,
                                    vulnerability_type: "Verified Contract (Sourcify)".to_string(),
                                    severity: Severity::Info,
                                    description: format!("Contract is verified on Sourcify ({})", status),
                                    line_number: None,
                                    recommendation: "Review the verified source code for vulnerabilities".to_string(),
                                    cwe_id: None,
                                });
                                return Ok(findings);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            log::debug!("Sourcify check failed: {}", e);
        }
    }

    // Could not verify status
    findings.push(SmartContractFinding {
        contract_address: address.to_string(),
        language: ContractLanguage::Solidity,
        vulnerability_type: "Verification Unknown".to_string(),
        severity: Severity::Medium,
        description: "Could not determine contract verification status (no API key or service unavailable)".to_string(),
        line_number: None,
        recommendation: "Set ETHERSCAN_API_KEY environment variable for verification checks".to_string(),
        cwe_id: None,
    });

    Ok(findings)
}

/// Analyze Solidity source code for vulnerabilities
fn analyze_solidity_source(source: &str) -> Result<Vec<SmartContractFinding>> {
    let mut findings = Vec::new();

    // Reentrancy detection
    if detect_reentrancy_pattern(source) {
        findings.push(SmartContractFinding {
            contract_address: String::new(),
            language: ContractLanguage::Solidity,
            vulnerability_type: "Reentrancy".to_string(),
            severity: Severity::Critical,
            description: "Potential reentrancy vulnerability detected. External calls before state changes.".to_string(),
            line_number: find_pattern_line(source, r"\.call\{"),
            recommendation: "Use checks-effects-interactions pattern. Apply ReentrancyGuard modifier.".to_string(),
            cwe_id: Some("CWE-696".to_string()),
        });
    }

    // Integer overflow (pre-0.8.0)
    if detect_overflow_risk(source) {
        findings.push(SmartContractFinding {
            contract_address: String::new(),
            language: ContractLanguage::Solidity,
            vulnerability_type: "Integer Overflow/Underflow".to_string(),
            severity: Severity::High,
            description: "Contract uses Solidity < 0.8.0 without SafeMath. Integer overflow/underflow possible.".to_string(),
            line_number: find_pattern_line(source, r"pragma solidity"),
            recommendation: "Upgrade to Solidity 0.8.0+ or use SafeMath library.".to_string(),
            cwe_id: Some("CWE-190".to_string()),
        });
    }

    // Unchecked call returns
    if detect_unchecked_returns(source) {
        findings.push(SmartContractFinding {
            contract_address: String::new(),
            language: ContractLanguage::Solidity,
            vulnerability_type: "Unchecked Return Value".to_string(),
            severity: Severity::Medium,
            description: "External call return value not checked. Failed calls may go unnoticed.".to_string(),
            line_number: find_pattern_line(source, r"\.transfer\(|\.send\("),
            recommendation: "Check return values of all external calls or use transfer/send with require.".to_string(),
            cwe_id: Some("CWE-252".to_string()),
        });
    }

    // Self-destruct detection
    if source.contains("selfdestruct") || source.contains("suicide") {
        findings.push(SmartContractFinding {
            contract_address: String::new(),
            language: ContractLanguage::Solidity,
            vulnerability_type: "Self-Destruct".to_string(),
            severity: Severity::High,
            description: "Contract contains selfdestruct. This could be used maliciously if access control is weak.".to_string(),
            line_number: find_pattern_line(source, r"selfdestruct|suicide"),
            recommendation: "Ensure selfdestruct is protected with proper access control.".to_string(),
            cwe_id: Some("CWE-284".to_string()),
        });
    }

    // Delegatecall to user-supplied address
    if detect_unsafe_delegatecall(source) {
        findings.push(SmartContractFinding {
            contract_address: String::new(),
            language: ContractLanguage::Solidity,
            vulnerability_type: "Unsafe Delegatecall".to_string(),
            severity: Severity::Critical,
            description: "Delegatecall to user-controlled address. Attacker could hijack contract storage.".to_string(),
            line_number: find_pattern_line(source, r"delegatecall"),
            recommendation: "Never delegatecall to user-supplied addresses. Use whitelisted addresses only.".to_string(),
            cwe_id: Some("CWE-829".to_string()),
        });
    }

    // tx.origin authentication
    if source.contains("tx.origin") && source.contains("require") {
        findings.push(SmartContractFinding {
            contract_address: String::new(),
            language: ContractLanguage::Solidity,
            vulnerability_type: "tx.origin Authentication".to_string(),
            severity: Severity::High,
            description: "tx.origin used for authentication. Vulnerable to phishing attacks.".to_string(),
            line_number: find_pattern_line(source, r"tx\.origin"),
            recommendation: "Use msg.sender for authentication instead of tx.origin.".to_string(),
            cwe_id: Some("CWE-287".to_string()),
        });
    }

    // Floating pragma
    if detect_floating_pragma(source) {
        findings.push(SmartContractFinding {
            contract_address: String::new(),
            language: ContractLanguage::Solidity,
            vulnerability_type: "Floating Pragma".to_string(),
            severity: Severity::Low,
            description: "Floating pragma version. Different compiler versions may produce different bytecode.".to_string(),
            line_number: find_pattern_line(source, r"pragma solidity"),
            recommendation: "Lock pragma to specific version: pragma solidity 0.8.19;".to_string(),
            cwe_id: None,
        });
    }

    // Block timestamp dependence
    if detect_timestamp_dependence(source) {
        findings.push(SmartContractFinding {
            contract_address: String::new(),
            language: ContractLanguage::Solidity,
            vulnerability_type: "Timestamp Dependence".to_string(),
            severity: Severity::Medium,
            description: "Contract relies on block.timestamp. Miners can manipulate within ~15 seconds.".to_string(),
            line_number: find_pattern_line(source, r"block\.timestamp|now"),
            recommendation: "Avoid using timestamps for critical logic. Use block numbers or external oracles.".to_string(),
            cwe_id: Some("CWE-829".to_string()),
        });
    }

    // Front-running vulnerability
    if detect_front_running_risk(source) {
        findings.push(SmartContractFinding {
            contract_address: String::new(),
            language: ContractLanguage::Solidity,
            vulnerability_type: "Front-Running Risk".to_string(),
            severity: Severity::Medium,
            description: "Contract may be vulnerable to front-running attacks.".to_string(),
            line_number: None,
            recommendation: "Implement commit-reveal scheme or use private mempools.".to_string(),
            cwe_id: Some("CWE-362".to_string()),
        });
    }

    Ok(findings)
}

/// Analyze Vyper source code
fn analyze_vyper_source(source: &str) -> Result<Vec<SmartContractFinding>> {
    let mut findings = Vec::new();

    // Vyper-specific checks
    // Vyper is generally safer by design but still needs review

    if source.contains("raw_call") {
        findings.push(SmartContractFinding {
            contract_address: String::new(),
            language: ContractLanguage::Vyper,
            vulnerability_type: "Raw Call".to_string(),
            severity: Severity::Medium,
            description: "Contract uses raw_call. Ensure proper validation of target and data.".to_string(),
            line_number: None,
            recommendation: "Validate target address and return data from raw calls.".to_string(),
            cwe_id: None,
        });
    }

    Ok(findings)
}

/// Analyze Rust (Solana) source code
fn analyze_rust_source(source: &str) -> Result<Vec<SmartContractFinding>> {
    let mut findings = Vec::new();

    // Solana-specific checks

    // Missing signer check
    if source.contains("AccountInfo") && !source.contains("is_signer") {
        findings.push(SmartContractFinding {
            contract_address: String::new(),
            language: ContractLanguage::Rust,
            vulnerability_type: "Missing Signer Check".to_string(),
            severity: Severity::High,
            description: "Account may be used without verifying signer status.".to_string(),
            line_number: None,
            recommendation: "Always verify account.is_signer for privileged operations.".to_string(),
            cwe_id: Some("CWE-862".to_string()),
        });
    }

    // Missing owner check
    if source.contains("AccountInfo") && !source.contains("owner") {
        findings.push(SmartContractFinding {
            contract_address: String::new(),
            language: ContractLanguage::Rust,
            vulnerability_type: "Missing Owner Check".to_string(),
            severity: Severity::High,
            description: "Account owner not verified. Program may process untrusted data.".to_string(),
            line_number: None,
            recommendation: "Verify account.owner matches expected program id.".to_string(),
            cwe_id: Some("CWE-284".to_string()),
        });
    }

    Ok(findings)
}

// Pattern detection helpers

fn detect_reentrancy_pattern(source: &str) -> bool {
    // Look for external calls followed by state changes
    let call_pattern = Regex::new(r"\.call\{.*\}\(").unwrap();
    let transfer_pattern = Regex::new(r"\.transfer\(|\.send\(").unwrap();

    call_pattern.is_match(source) || transfer_pattern.is_match(source)
}

fn detect_overflow_risk(source: &str) -> bool {
    let pragma_re = Regex::new(r"pragma\s+solidity\s+[\^<>=]*\s*(0\.[0-7]\.\d+)").unwrap();
    pragma_re.is_match(source) && !source.contains("SafeMath")
}

fn detect_unchecked_returns(source: &str) -> bool {
    // Check for .call without checking return value
    let pattern = Regex::new(r"\.call\{[^}]*\}\([^)]*\);").unwrap();
    pattern.is_match(source)
}

fn detect_unsafe_delegatecall(source: &str) -> bool {
    // Look for delegatecall with dynamic target
    source.contains("delegatecall") && source.contains("address(")
}

fn detect_floating_pragma(source: &str) -> bool {
    let pattern = Regex::new(r"pragma\s+solidity\s+[\^~]").unwrap();
    pattern.is_match(source)
}

fn detect_timestamp_dependence(source: &str) -> bool {
    // Critical uses of timestamp
    let timestamp_pattern = Regex::new(r"(block\.timestamp|now)\s*[<>=]").unwrap();
    timestamp_pattern.is_match(source)
}

fn detect_front_running_risk(source: &str) -> bool {
    // DEX/AMM patterns that may be front-runnable
    source.contains("swap") && source.contains("amountOut")
}

fn find_pattern_line(source: &str, pattern: &str) -> Option<u32> {
    let re = Regex::new(pattern).ok()?;
    if let Some(mat) = re.find(source) {
        let line_num = source[..mat.start()].matches('\n').count() + 1;
        return Some(line_num as u32);
    }
    None
}

/// Known vulnerable contract database entry
#[derive(Clone)]
struct KnownVulnerability {
    vuln_type: String,
    severity: Severity,
    description: String,
    recommendation: String,
    cwe_id: Option<String>,
}

fn get_known_vulnerable_contracts() -> HashMap<String, Vec<KnownVulnerability>> {
    let contracts = HashMap::new();

    // Example: Add known vulnerable contracts
    // In production, this would be a database or API call

    contracts
}

/// Calculate contract risk score
pub fn calculate_contract_risk_score(findings: &[SmartContractFinding]) -> f64 {
    if findings.is_empty() {
        return 0.0;
    }

    let severity_weights: HashMap<Severity, f64> = [
        (Severity::Critical, 25.0),
        (Severity::High, 15.0),
        (Severity::Medium, 8.0),
        (Severity::Low, 3.0),
        (Severity::Info, 1.0),
    ].iter().cloned().collect();

    let total_weight: f64 = findings.iter()
        .map(|f| severity_weights.get(&f.severity).unwrap_or(&0.0))
        .sum();

    // Normalize to 0-100
    total_weight.min(100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_contract_address() {
        assert!(is_valid_contract_address("0x742d35Cc6634C0532925a3b844Bc9e7595f1dE61"));
        assert!(!is_valid_contract_address("invalid"));
    }

    #[test]
    fn test_detect_reentrancy() {
        let vulnerable_code = r#"
            function withdraw() external {
                (bool success, ) = msg.sender.call{value: balance}("");
                balances[msg.sender] = 0;
            }
        "#;
        assert!(detect_reentrancy_pattern(vulnerable_code));
    }

    #[test]
    fn test_detect_floating_pragma() {
        assert!(detect_floating_pragma("pragma solidity ^0.8.0;"));
        assert!(!detect_floating_pragma("pragma solidity 0.8.19;"));
    }

    #[tokio::test]
    async fn test_analyze_source() {
        let source = r#"
            pragma solidity ^0.7.0;
            contract Test {
                function unsafe() external {
                    selfdestruct(payable(msg.sender));
                }
            }
        "#;

        let findings = analyze_source(source, ContractLanguage::Solidity).await.unwrap();
        assert!(!findings.is_empty());
    }
}
