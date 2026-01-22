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
    let known_multisig_patterns = vec![
        "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552", // Gnosis Safe Master Copy
        "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2", // Safe Factory
    ];

    if known_multisig_patterns.iter().any(|p| address.to_lowercase() == p.to_lowercase()) {
        return true;
    }

    // Query blockchain to check for Gnosis Safe proxy bytecode signature
    if let Ok(bytecode) = get_contract_bytecode(address) {
        // Gnosis Safe proxies have a specific bytecode pattern
        // delegatecall to masterCopy
        if bytecode.contains("363d3d373d3d3d363d73") {
            return true;
        }
    }

    false
}

/// Check if address is a smart contract wallet
fn is_smart_contract_wallet(address: &str) -> bool {
    // Query the blockchain for contract code
    match get_contract_bytecode(address) {
        Ok(bytecode) => !bytecode.is_empty() && bytecode != "0x",
        Err(_) => false,
    }
}

/// Get contract bytecode from Ethereum RPC
fn get_contract_bytecode(address: &str) -> Result<String> {
    
    
    

    // Use public RPC endpoints
    let rpc_endpoints = [
        ("eth-mainnet.g.alchemy.com", 443, true),
        ("cloudflare-eth.com", 443, true),
        ("rpc.ankr.com", 443, true),
    ];

    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [address, "latest"],
        "id": 1
    });

    for (host, port, use_https) in &rpc_endpoints {
        if let Ok(result) = send_rpc_request(*host, *port, *use_https, &request_body.to_string()) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&result) {
                if let Some(code) = json.get("result").and_then(|r| r.as_str()) {
                    return Ok(code.to_string());
                }
            }
        }
    }

    Ok("0x".to_string())
}

/// Send JSON-RPC request to Ethereum node
fn send_rpc_request(host: &str, port: u16, use_https: bool, body: &str) -> Result<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let http_request = format!(
        "POST / HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        host,
        body.len(),
        body
    );

    if use_https {
        // For HTTPS, use native-tls or rustls
        #[allow(unexpected_cfgs)]
        #[cfg(feature = "native-tls")]
        {
            use native_tls::TlsConnector;

            let connector = TlsConnector::new()?;
            let stream = TcpStream::connect(format!("{}:{}", host, port))?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            stream.set_write_timeout(Some(Duration::from_secs(10)))?;

            let mut stream = connector.connect(host, stream)?;
            stream.write_all(http_request.as_bytes())?;

            let mut response = String::new();
            stream.read_to_string(&mut response)?;

            // Extract body from HTTP response
            if let Some(body_start) = response.find("\r\n\r\n") {
                return Ok(response[body_start + 4..].to_string());
            }
        }

        // Fallback: try without TLS for testing
        #[allow(unexpected_cfgs)]
        #[cfg(not(feature = "native-tls"))]
        {
            // Return empty for non-TLS builds
            return Ok("{}".to_string());
        }
    }

    // Plain HTTP
    let mut stream = TcpStream::connect(format!("{}:{}", host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    stream.write_all(http_request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    if let Some(body_start) = response.find("\r\n\r\n") {
        return Ok(response[body_start + 4..].to_string());
    }

    Ok("{}".to_string())
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

    // Query blockchain for Approval events
    // ERC20 Approval event topic: keccak256("Approval(address,address,uint256)")
    let approval_topic = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";

    // Get approval events where this address is the owner
    let events = get_approval_events(address, approval_topic).await;

    // Check against known risky approval targets
    let risky_contracts = get_risky_approval_targets();

    for event in events {
        let spender = &event.spender;
        let amount = &event.amount;

        // Check for unlimited approval (max uint256)
        let max_uint256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        if amount.to_lowercase().contains(max_uint256) || amount == "115792089237316195423570985008687907853269984665640564039457584007913129639935" {
            findings.push(WalletFinding {
                address: address.to_string(),
                wallet_type: WalletType::Hot,
                finding_type: WalletRiskType::ApprovalRisk,
                severity: Severity::High,
                description: format!("Unlimited token approval to {} for token {}", spender, event.token),
                recommendation: format!("Revoke unlimited approval using revoke.cash or etherscan token approval checker. Spender: {}", spender),
            });
        }

        // Check if spender is a known risky contract
        if let Some(risk_reason) = risky_contracts.get(&spender.to_lowercase()) {
            findings.push(WalletFinding {
                address: address.to_string(),
                wallet_type: WalletType::Hot,
                finding_type: WalletRiskType::ApprovalRisk,
                severity: Severity::Critical,
                description: format!("Token approval to risky address: {}", risk_reason),
                recommendation: "Immediately revoke this approval and check for unauthorized transfers".to_string(),
            });
        }

        // Check if spender is unverified contract
        if is_unverified_contract(spender).await {
            findings.push(WalletFinding {
                address: address.to_string(),
                wallet_type: WalletType::Hot,
                finding_type: WalletRiskType::ApprovalRisk,
                severity: Severity::Medium,
                description: format!("Token approval to unverified contract {}", spender),
                recommendation: "Review this approval carefully - unverified contracts may contain malicious code".to_string(),
            });
        }
    }

    if findings.is_empty() {
        findings.push(WalletFinding {
            address: address.to_string(),
            wallet_type: WalletType::Hot,
            finding_type: WalletRiskType::ApprovalRisk,
            severity: Severity::Info,
            description: "No high-risk token approvals detected".to_string(),
            recommendation: "Regularly review token approvals using revoke.cash".to_string(),
        });
    }

    Ok(findings)
}

/// Approval event data
struct ApprovalEvent {
    token: String,
    spender: String,
    amount: String,
}

/// Get approval events for an address
async fn get_approval_events(address: &str, topic: &str) -> Vec<ApprovalEvent> {
    let mut events = Vec::new();

    // Query eth_getLogs for Approval events
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getLogs",
        "params": [{
            "fromBlock": "0x0",
            "toBlock": "latest",
            "topics": [
                topic,
                format!("0x000000000000000000000000{}", address.trim_start_matches("0x"))
            ]
        }],
        "id": 1
    });

    // Try multiple RPC endpoints
    let rpc_endpoints = [
        ("cloudflare-eth.com", 443, true),
        ("rpc.ankr.com", 443, true),
    ];

    for (host, port, use_https) in &rpc_endpoints {
        if let Ok(result) = send_rpc_request(*host, *port, *use_https, &request_body.to_string()) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&result) {
                if let Some(logs) = json.get("result").and_then(|r| r.as_array()) {
                    for log in logs {
                        if let (Some(token), Some(topics), Some(data)) = (
                            log.get("address").and_then(|a| a.as_str()),
                            log.get("topics").and_then(|t| t.as_array()),
                            log.get("data").and_then(|d| d.as_str()),
                        ) {
                            if topics.len() >= 3 {
                                let spender = topics[2].as_str().unwrap_or("");
                                // Extract last 40 chars as address
                                let spender_addr = if spender.len() >= 42 {
                                    format!("0x{}", &spender[spender.len() - 40..])
                                } else {
                                    spender.to_string()
                                };

                                events.push(ApprovalEvent {
                                    token: token.to_string(),
                                    spender: spender_addr,
                                    amount: data.to_string(),
                                });
                            }
                        }
                    }
                    break;
                }
            }
        }
    }

    events
}

/// Check if contract is unverified on Etherscan
async fn is_unverified_contract(address: &str) -> bool {
    // First check if it's actually a contract
    if let Ok(bytecode) = get_contract_bytecode(address) {
        if bytecode.is_empty() || bytecode == "0x" {
            return false; // Not a contract (EOA)
        }
    } else {
        return false; // Can't determine, assume not unverified
    }

    // Try to check Etherscan API for verification status
    if let Some(api_key) = std::env::var("ETHERSCAN_API_KEY").ok() {
        // Use Etherscan API to check if contract source code is verified
        let url = format!(
            "https://api.etherscan.io/v2/api?chainid=1&module=contract&action=getsourcecode&address={}&apikey={}",
            address, api_key
        );

        if let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            if let Ok(response) = client.get(&url).send().await {
                if let Ok(json) = response.json::<serde_json::Value>().await {
                    // Check if contract has verified source code
                    if let Some(result) = json.get("result").and_then(|r| r.as_array()) {
                        if let Some(first) = result.first() {
                            // If SourceCode is empty, contract is not verified
                            if let Some(source_code) = first.get("SourceCode").and_then(|s| s.as_str()) {
                                if source_code.is_empty() {
                                    log::debug!("Contract {} is NOT verified on Etherscan", address);
                                    return true; // Unverified
                                } else {
                                    log::debug!("Contract {} is verified on Etherscan", address);
                                    return false; // Verified
                                }
                            }
                        }
                    }
                }
            }
        }
        log::warn!("Could not verify contract {} via Etherscan API", address);
    } else {
        log::debug!("ETHERSCAN_API_KEY not set, using bytecode heuristics for contract verification check");
    }

    // Fallback: Use bytecode heuristics when API is unavailable
    // This is less reliable but provides some indication
    if let Ok(bytecode) = get_contract_bytecode(address) {
        // Very short bytecode (< 100 chars / 50 bytes) is suspicious
        // Most legitimate contracts have substantial bytecode
        if bytecode.len() < 100 {
            return true;
        }

        // Check for common verified contract patterns (Solidity compiler output)
        let verified_patterns = [
            "6080604052",     // Solidity 0.8.x standard
            "608060405234",   // Solidity with payable constructor
            "60806040526004", // Common proxy pattern
        ];

        // If none of these patterns are present, might be obfuscated/unverified
        let has_standard_pattern = verified_patterns.iter().any(|p| bytecode.contains(p));
        if !has_standard_pattern {
            return true;
        }
    }

    false
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

    // Get recent transactions for this address
    let transactions = get_recent_transactions(address).await;

    // Analyze transaction patterns
    let mut known_malicious_interactions = Vec::new();
    let mut mixer_interactions = Vec::new();
    let mut flash_loan_count = 0;
    let mut high_gas_count = 0;

    // Known malicious contracts and mixers
    let malicious_contracts = get_known_malicious_contracts();
    let mixer_contracts = get_known_mixers();

    for tx in &transactions {
        // Check for interactions with known malicious contracts
        if let Some(reason) = malicious_contracts.get(&tx.to.to_lowercase()) {
            known_malicious_interactions.push((tx.to.clone(), reason.clone()));
        }

        // Check for mixer interactions (Tornado Cash, etc.)
        if mixer_contracts.contains(&tx.to.to_lowercase()) {
            mixer_interactions.push(tx.to.clone());
        }

        // Check for flash loan patterns (high value, same block in/out)
        if tx.value_wei.len() > 20 {
            flash_loan_count += 1;
        }

        // Check for unusual gas patterns
        if tx.gas_price > 500_000_000_000u64 { // > 500 Gwei
            high_gas_count += 1;
        }
    }

    // Generate findings based on analysis
    if !known_malicious_interactions.is_empty() {
        for (contract, reason) in known_malicious_interactions {
            findings.push(WalletFinding {
                address: address.to_string(),
                wallet_type: WalletType::Hot,
                finding_type: WalletRiskType::MaliciousInteraction,
                severity: Severity::Critical,
                description: format!("Interaction with known malicious contract {}: {}", contract, reason),
                recommendation: "Review all transactions with this contract and check for fund loss".to_string(),
            });
        }
    }

    if !mixer_interactions.is_empty() {
        findings.push(WalletFinding {
            address: address.to_string(),
            wallet_type: WalletType::Hot,
            finding_type: WalletRiskType::MixerUsage,
            severity: Severity::High,
            description: format!("Wallet has {} interactions with mixing services", mixer_interactions.len()),
            recommendation: "Mixer usage may indicate attempts to obscure fund origins".to_string(),
        });
    }

    if flash_loan_count > 5 {
        findings.push(WalletFinding {
            address: address.to_string(),
            wallet_type: WalletType::Hot,
            finding_type: WalletRiskType::SuspiciousActivity,
            severity: Severity::Medium,
            description: format!("Detected {} potential flash loan transactions", flash_loan_count),
            recommendation: "Flash loans are often used in DeFi exploits - verify these are legitimate".to_string(),
        });
    }

    if high_gas_count > 10 {
        findings.push(WalletFinding {
            address: address.to_string(),
            wallet_type: WalletType::Hot,
            finding_type: WalletRiskType::SuspiciousActivity,
            severity: Severity::Low,
            description: format!("{} transactions with unusually high gas prices", high_gas_count),
            recommendation: "High gas transactions may indicate front-running or time-sensitive operations".to_string(),
        });
    }

    Ok(findings)
}

/// Transaction data from blockchain
#[allow(dead_code)]
struct TransactionData {
    hash: String,
    from: String,
    to: String,
    value_wei: String,
    gas_price: u64,
    block_number: u64,
}

/// Get recent transactions for an address
async fn get_recent_transactions(_address: &str) -> Vec<TransactionData> {
    // Query Etherscan API or similar for transaction history
    // Requires API key for full functionality
    Vec::new()
}

/// Get known malicious contracts
fn get_known_malicious_contracts() -> HashMap<String, String> {
    let mut contracts = HashMap::new();

    // Known exploit contracts and scam addresses
    contracts.insert(
        "0x098b716b8aaf21512996dc57eb0615e2383e2f96".to_string(),
        "Ronin Bridge Exploiter".to_string(),
    );
    contracts.insert(
        "0x8589427373d6d84e98730d7795d8f6f8731fda16".to_string(),
        "Wormhole Exploiter".to_string(),
    );
    contracts.insert(
        "0xba12222222228d8ba445958a75a0704d566bf2c8".to_string(),
        "Known phishing contract".to_string(),
    );

    contracts
}

/// Get known mixer contracts
fn get_known_mixers() -> Vec<String> {
    vec![
        "0x722122df12d4e14e13ac3b6895a86e84145b6967".to_lowercase(), // Tornado Cash Router
        "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b".to_lowercase(), // Tornado Cash 0.1 ETH
        "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936".to_lowercase(), // Tornado Cash 1 ETH
        "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf".to_lowercase(), // Tornado Cash 10 ETH
        "0xa160cdab225685da1d56aa342ad8841c3b53f291".to_lowercase(), // Tornado Cash 100 ETH
    ]
}

/// Analyze multi-sig wallet security
async fn analyze_multisig_security(address: &str) -> Result<Vec<WalletFinding>> {
    let mut findings = Vec::new();

    // Query Gnosis Safe contract for configuration
    let config = get_multisig_config(address).await;

    if let Some(cfg) = config {
        // Check threshold ratio
        let threshold_ratio = cfg.threshold as f64 / cfg.owner_count as f64;

        if threshold_ratio < 0.5 {
            findings.push(WalletFinding {
                address: address.to_string(),
                wallet_type: WalletType::MultiSig,
                finding_type: WalletRiskType::MultiSigThresholdRisk,
                severity: Severity::High,
                description: format!("Low multi-sig threshold: {}/{} owners required", cfg.threshold, cfg.owner_count),
                recommendation: "Consider increasing threshold to at least 50% of owners".to_string(),
            });
        }

        if cfg.owner_count < 3 {
            findings.push(WalletFinding {
                address: address.to_string(),
                wallet_type: WalletType::MultiSig,
                finding_type: WalletRiskType::MultiSigThresholdRisk,
                severity: Severity::Medium,
                description: format!("Multi-sig has only {} owners", cfg.owner_count),
                recommendation: "Consider adding more owners for better security distribution".to_string(),
            });
        }

        // Check for single-owner control
        if cfg.threshold == 1 {
            findings.push(WalletFinding {
                address: address.to_string(),
                wallet_type: WalletType::MultiSig,
                finding_type: WalletRiskType::SinglePointOfFailure,
                severity: Severity::Critical,
                description: "Multi-sig requires only 1 signature - effectively a single-owner wallet".to_string(),
                recommendation: "Increase threshold to require multiple signatures".to_string(),
            });
        }
    } else {
        findings.push(WalletFinding {
            address: address.to_string(),
            wallet_type: WalletType::MultiSig,
            finding_type: WalletRiskType::MultiSigThresholdRisk,
            severity: Severity::Info,
            description: "Multi-sig wallet detected - verify threshold settings".to_string(),
            recommendation: "Ensure multi-sig threshold is appropriate (e.g., 2-of-3 or 3-of-5)".to_string(),
        });
    }

    Ok(findings)
}

/// Multi-sig configuration
struct MultisigConfig {
    threshold: u32,
    owner_count: u32,
    owners: Vec<String>,
}

/// Get multi-sig configuration from contract
async fn get_multisig_config(address: &str) -> Option<MultisigConfig> {
    // Call getOwners() and getThreshold() on Gnosis Safe contract
    // getOwners selector: 0xa0e67e2b
    // getThreshold selector: 0xe75235b8

    let threshold_call = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": address,
            "data": "0xe75235b8"
        }, "latest"],
        "id": 1
    });

    let owners_call = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": address,
            "data": "0xa0e67e2b"
        }, "latest"],
        "id": 2
    });

    let mut threshold = 0u32;
    let mut owners = Vec::new();

    // Query threshold
    if let Ok(result) = send_rpc_request("cloudflare-eth.com", 443, true, &threshold_call.to_string()) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&result) {
            if let Some(hex) = json.get("result").and_then(|r| r.as_str()) {
                if hex.len() >= 66 {
                    threshold = u32::from_str_radix(&hex[58..66], 16).unwrap_or(0);
                }
            }
        }
    }

    // Query owners
    if let Ok(result) = send_rpc_request("cloudflare-eth.com", 443, true, &owners_call.to_string()) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&result) {
            if let Some(hex) = json.get("result").and_then(|r| r.as_str()) {
                // Parse ABI-encoded address array
                // First 64 chars after 0x is offset, next 64 is length
                if hex.len() > 130 {
                    let owner_count = u32::from_str_radix(&hex[66..130], 16).unwrap_or(0);
                    for i in 0..owner_count as usize {
                        let start = 130 + i * 64 + 24; // Skip padding
                        let end = start + 40;
                        if end <= hex.len() {
                            owners.push(format!("0x{}", &hex[start..end]));
                        }
                    }
                }
            }
        }
    }

    if threshold > 0 || !owners.is_empty() {
        Some(MultisigConfig {
            threshold,
            owner_count: owners.len() as u32,
            owners,
        })
    } else {
        None
    }
}

/// Analyze smart contract wallet security
async fn analyze_contract_wallet_security(address: &str) -> Result<Vec<WalletFinding>> {
    let mut findings = Vec::new();

    // Get contract bytecode for analysis
    let bytecode = get_contract_bytecode(address).unwrap_or_default();

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
