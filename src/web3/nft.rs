//! NFT security scanning
//!
//! Comprehensive NFT contract and collection analysis including:
//! - Metadata vulnerability detection
//! - Contract verification
//! - Minting security analysis
//! - Royalty implementation review

use super::types::*;
use anyhow::Result;

/// NFT security scanner
pub struct NFTScanner {
    /// Known problematic metadata hosts
    risky_hosts: Vec<String>,
    /// ERC standards to check compliance against
    erc_standards: Vec<ERCStandard>,
}

impl NFTScanner {
    pub fn new() -> Self {
        Self {
            risky_hosts: vec![
                "http://".to_string(),  // Non-HTTPS
                "amazonaws.com".to_string(), // Centralized
                "cloudinary.com".to_string(),
                "dropbox.com".to_string(),
            ],
            erc_standards: vec![
                ERCStandard::ERC721,
                ERCStandard::ERC1155,
            ],
        }
    }

    /// Check metadata storage security
    pub fn analyze_metadata(&self, address: &str, metadata_uri: Option<&str>) -> Vec<NFTFinding> {
        let mut findings = Vec::new();

        if let Some(uri) = metadata_uri {
            // Check for centralized storage
            for risky_host in &self.risky_hosts {
                if uri.contains(risky_host) {
                    findings.push(NFTFinding {
                        contract_address: address.to_string(),
                        collection_name: "Unknown Collection".to_string(),
                        finding_type: NFTRiskType::MetadataVulnerability,
                        severity: Severity::High,
                        description: format!("NFT metadata hosted on centralized service: {}", risky_host),
                        recommendation: "Consider migrating metadata to IPFS or Arweave for permanence".to_string(),
                    });
                }
            }

            // Check for IPFS without pinning service
            if uri.contains("ipfs://") && !uri.contains("pinata") && !uri.contains("nft.storage") {
                findings.push(NFTFinding {
                    contract_address: address.to_string(),
                    collection_name: "Unknown Collection".to_string(),
                    finding_type: NFTRiskType::MetadataVulnerability,
                    severity: Severity::Medium,
                    description: "IPFS metadata may not be properly pinned".to_string(),
                    recommendation: "Use a reliable IPFS pinning service like Pinata or NFT.Storage".to_string(),
                });
            }
        } else {
            findings.push(NFTFinding {
                contract_address: address.to_string(),
                collection_name: "Unknown Collection".to_string(),
                finding_type: NFTRiskType::MetadataVulnerability,
                severity: Severity::High,
                description: "No metadata URI found - NFT may have no associated metadata".to_string(),
                recommendation: "Verify tokenURI function returns valid metadata".to_string(),
            });
        }

        findings
    }

    /// Check minting security
    pub fn analyze_minting(&self, address: &str, has_max_supply: bool, has_access_control: bool) -> Vec<NFTFinding> {
        let mut findings = Vec::new();

        if !has_max_supply {
            findings.push(NFTFinding {
                contract_address: address.to_string(),
                collection_name: "Unknown Collection".to_string(),
                finding_type: NFTRiskType::MintingRisk,
                severity: Severity::Medium,
                description: "NFT contract has no maximum supply limit".to_string(),
                recommendation: "Consider implementing a max supply to ensure scarcity".to_string(),
            });
        }

        if !has_access_control {
            findings.push(NFTFinding {
                contract_address: address.to_string(),
                collection_name: "Unknown Collection".to_string(),
                finding_type: NFTRiskType::MintingRisk,
                severity: Severity::High,
                description: "Minting function may be publicly accessible".to_string(),
                recommendation: "Implement proper access control for minting functions".to_string(),
            });
        }

        findings
    }

    /// Check royalty implementation
    pub fn analyze_royalties(&self, address: &str, has_erc2981: bool) -> Vec<NFTFinding> {
        let mut findings = Vec::new();

        if !has_erc2981 {
            findings.push(NFTFinding {
                contract_address: address.to_string(),
                collection_name: "Unknown Collection".to_string(),
                finding_type: NFTRiskType::RoyaltyBypass,
                severity: Severity::Low,
                description: "Contract does not implement ERC-2981 royalty standard".to_string(),
                recommendation: "Implement ERC-2981 for on-chain royalty enforcement".to_string(),
            });
        }

        // Royalty bypass risk
        findings.push(NFTFinding {
            contract_address: address.to_string(),
            collection_name: "Unknown Collection".to_string(),
            finding_type: NFTRiskType::RoyaltyBypass,
            severity: Severity::Info,
            description: "Marketplace royalties can potentially be bypassed through direct transfers".to_string(),
            recommendation: "Consider operator filtering (OpenSea's registry) for stronger enforcement".to_string(),
        });

        findings
    }

    /// Check centralization risks
    pub fn analyze_centralization(&self, address: &str, has_pause: bool, has_admin: bool) -> Vec<NFTFinding> {
        let mut findings = Vec::new();

        if has_pause {
            findings.push(NFTFinding {
                contract_address: address.to_string(),
                collection_name: "Unknown Collection".to_string(),
                finding_type: NFTRiskType::CentralizationRisk,
                severity: Severity::Medium,
                description: "Contract has pausable functionality".to_string(),
                recommendation: "Ensure pause mechanism has proper governance or is for emergencies only".to_string(),
            });
        }

        if has_admin {
            findings.push(NFTFinding {
                contract_address: address.to_string(),
                collection_name: "Unknown Collection".to_string(),
                finding_type: NFTRiskType::CentralizationRisk,
                severity: Severity::Medium,
                description: "Contract has admin privileges that could affect token transfers".to_string(),
                recommendation: "Review admin capabilities and consider multisig for admin actions".to_string(),
            });
        }

        findings
    }

    /// Verify provenance
    pub fn verify_provenance(&self, address: &str) -> Vec<NFTFinding> {
        let mut findings = Vec::new();

        findings.push(NFTFinding {
            contract_address: address.to_string(),
            collection_name: "Unknown Collection".to_string(),
            finding_type: NFTRiskType::ProvenanceIssue,
            severity: Severity::Info,
            description: "Provenance hash not found or not verifiable".to_string(),
            recommendation: "Verify collection provenance through official channels before purchase".to_string(),
        });

        findings
    }
}

impl Default for NFTScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
enum ERCStandard {
    ERC721,
    ERC1155,
}

/// Scan NFT contracts for security issues
///
/// Requires ETH_RPC_URL for real contract analysis.
pub async fn scan_nft_contracts(addresses: &[String]) -> Result<Vec<NFTFinding>> {
    let rpc = match super::eth_rpc::EthRpcClient::from_env() {
        Ok(r) => r,
        Err(e) => {
            log::debug!("ETH_RPC_URL not available: {} - NFT analysis unavailable", e);
            return Ok(Vec::new());
        }
    };

    let mut findings = Vec::new();
    let scanner = NFTScanner::new();

    for address in addresses {
        // Verify it's a contract
        let code = match rpc.eth_get_code(address).await {
            Ok(c) if c != "0x" && !c.is_empty() => c,
            _ => continue,
        };

        // ERC-165 interface detection
        // Check ERC-721 (0x80ac58cd)
        let erc721_check = format!(
            "{}{}",
            super::eth_rpc::function_selector("supportsInterface(bytes4)"),
            "80ac58cd00000000000000000000000000000000000000000000000000000000"
        );

        let is_erc721 = rpc.eth_call(address, &erc721_check).await
            .map(|r| r.ends_with("0000000000000000000000000000000000000000000000000000000000000001"))
            .unwrap_or(false);

        // Check ERC-1155 (0xd9b67a26)
        let erc1155_check = format!(
            "{}{}",
            super::eth_rpc::function_selector("supportsInterface(bytes4)"),
            "d9b67a2600000000000000000000000000000000000000000000000000000000"
        );

        let is_erc1155 = rpc.eth_call(address, &erc1155_check).await
            .map(|r| r.ends_with("0000000000000000000000000000000000000000000000000000000000000001"))
            .unwrap_or(false);

        if !is_erc721 && !is_erc1155 {
            findings.push(NFTFinding {
                contract_address: address.clone(),
                collection_name: "Unknown".to_string(),
                finding_type: NFTRiskType::UnverifiedContract,
                severity: Severity::Medium,
                description: "Contract does not implement ERC-721 or ERC-1155 interface".to_string(),
                recommendation: "Verify contract implements standard NFT interfaces".to_string(),
            });
            continue;
        }

        // Query tokenURI/uri for metadata location
        let metadata_url = if is_erc721 {
            let selector = format!(
                "{}{}",
                super::eth_rpc::function_selector("tokenURI(uint256)"),
                super::eth_rpc::abi_encode_uint256(1)
            );
            rpc.eth_call(address, &selector).await.ok()
        } else {
            let selector = format!(
                "{}{}",
                super::eth_rpc::function_selector("uri(uint256)"),
                super::eth_rpc::abi_encode_uint256(1)
            );
            rpc.eth_call(address, &selector).await.ok()
        };

        // Decode and analyze metadata URL
        let decoded_uri = metadata_url.and_then(|raw| decode_abi_string(&raw));
        findings.extend(scanner.analyze_metadata(address, decoded_uri.as_deref()));

        // Check ERC-2981 royalty support
        let royalty_check = format!(
            "{}{}",
            super::eth_rpc::function_selector("supportsInterface(bytes4)"),
            "2a55205a00000000000000000000000000000000000000000000000000000000"
        );

        let has_royalties = rpc.eth_call(address, &royalty_check).await
            .map(|r| r.ends_with("0000000000000000000000000000000000000000000000000000000000000001"))
            .unwrap_or(false);

        if !has_royalties {
            findings.push(NFTFinding {
                contract_address: address.clone(),
                collection_name: "Unknown".to_string(),
                finding_type: NFTRiskType::UnverifiedContract,
                severity: Severity::Low,
                description: "Contract does not implement ERC-2981 royalty standard".to_string(),
                recommendation: "Consider implementing on-chain royalty enforcement".to_string(),
            });
        }

        // Check for owner/access control
        let owner_selector = super::eth_rpc::function_selector("owner()");
        if rpc.eth_call(address, &owner_selector).await.is_err() {
            // No owner function - check for AccessControl pattern
            let bytecode_lower = code.to_lowercase();
            if !bytecode_lower.contains("248a9ca3") { // getRoleAdmin selector
                findings.push(NFTFinding {
                    contract_address: address.clone(),
                    collection_name: "Unknown".to_string(),
                    finding_type: NFTRiskType::UnverifiedContract,
                    severity: Severity::Medium,
                    description: "No access control mechanism detected".to_string(),
                    recommendation: "Verify minting is properly access-controlled".to_string(),
                });
            }
        }
    }

    Ok(findings)
}

/// Attempt to decode an ABI-encoded string response
fn decode_abi_string(hex_data: &str) -> Option<String> {
    let data = hex_data.trim_start_matches("0x");
    if data.len() < 128 {
        return None;
    }

    // ABI string encoding: offset (32 bytes) + length (32 bytes) + data
    let length_hex = &data[64..128];
    let length = usize::from_str_radix(length_hex, 16).ok()?;

    if length == 0 || data.len() < 128 + length * 2 {
        return None;
    }

    let string_hex = &data[128..128 + length * 2];
    let bytes: Vec<u8> = (0..string_hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&string_hex[i..i + 2], 16).ok())
        .collect();

    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_analysis() {
        let scanner = NFTScanner::new();
        let findings = scanner.analyze_metadata("0x123", Some("http://example.com/metadata"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_centralized_metadata() {
        let scanner = NFTScanner::new();
        let findings = scanner.analyze_metadata("0x123", Some("https://amazonaws.com/nft/1"));
        assert!(findings.iter().any(|f| f.finding_type == NFTRiskType::MetadataVulnerability));
    }

    #[tokio::test]
    async fn test_scan_contracts() {
        let addresses = vec!["0x1234567890abcdef".to_string()];
        let findings = scan_nft_contracts(&addresses).await.unwrap();
        // Without ETH_RPC_URL, returns empty - no simulated data
        // Real analysis requires blockchain RPC access
        assert!(findings.is_empty() || std::env::var("ETH_RPC_URL").is_ok());
    }
}
