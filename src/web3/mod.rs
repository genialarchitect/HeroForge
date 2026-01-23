//! Web3 & Blockchain Security Module (Phase 4 Sprint 11)
//!
//! Comprehensive Web3, cryptocurrency, and blockchain security scanning.

pub mod smart_contracts;
pub mod defi;
pub mod nft;
pub mod on_chain;
pub mod cross_chain;
pub mod dapp;
pub mod wallet;
pub mod exchange;
pub mod staking;
pub mod threat_intel;
pub mod types;
pub mod eth_rpc;

pub use types::*;
use anyhow::Result;

/// Run a comprehensive Web3 security assessment
pub async fn run_web3_assessment(config: &Web3AssessmentConfig) -> Result<Web3Assessment> {
    let mut assessment = Web3Assessment::default();

    // Smart contract security
    if config.scan_smart_contracts {
        assessment.smart_contract_findings = smart_contracts::scan_contracts(&config.contract_addresses).await?;
    }

    // DeFi security
    if config.scan_defi {
        assessment.defi_findings = defi::analyze_defi_protocols(&config.protocol_addresses).await?;
    }

    // NFT security
    if config.scan_nfts {
        assessment.nft_findings = nft::scan_nft_contracts(&config.nft_addresses).await?;
    }

    // On-chain analytics
    if config.on_chain_analysis {
        assessment.on_chain_analytics = on_chain::analyze_blockchain(&config.chain, &config.addresses).await?;
    }

    // Cross-chain analysis
    if config.cross_chain_analysis {
        assessment.cross_chain_findings = cross_chain::analyze_bridges(&config.bridge_addresses).await?;
    }

    // DApp security
    if config.scan_dapps {
        assessment.dapp_findings = dapp::scan_dapps(&config.dapp_urls).await?;
    }

    // Wallet security
    if config.scan_wallets {
        assessment.wallet_findings = wallet::analyze_wallets(&config.wallet_addresses).await?;
    }

    // Exchange security
    if config.scan_exchanges {
        assessment.exchange_findings = exchange::analyze_exchanges(&config.exchange_endpoints).await?;
    }

    // Staking security
    if config.scan_staking {
        assessment.staking_findings = staking::analyze_staking(&config.staking_addresses).await?;
    }

    // Web3 threat intelligence
    assessment.threat_intel = threat_intel::check_web3_threats(&config).await?;

    Ok(assessment)
}
