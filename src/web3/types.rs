//! Web3 security types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web3AssessmentConfig {
    pub chain: BlockchainNetwork,
    pub contract_addresses: Vec<String>,
    pub protocol_addresses: Vec<String>,
    pub nft_addresses: Vec<String>,
    pub addresses: Vec<String>,
    pub bridge_addresses: Vec<String>,
    pub dapp_urls: Vec<String>,
    pub wallet_addresses: Vec<String>,
    pub exchange_endpoints: Vec<String>,
    pub staking_addresses: Vec<String>,

    // Scan toggles
    pub scan_smart_contracts: bool,
    pub scan_defi: bool,
    pub scan_nfts: bool,
    pub on_chain_analysis: bool,
    pub cross_chain_analysis: bool,
    pub scan_dapps: bool,
    pub scan_wallets: bool,
    pub scan_exchanges: bool,
    pub scan_staking: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockchainNetwork {
    Ethereum,
    BinanceSmartChain,
    Polygon,
    Arbitrum,
    Optimism,
    Avalanche,
    Solana,
    Cardano,
    Polkadot,
    Cosmos,
    Bitcoin,
    Custom(String),
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Web3Assessment {
    pub smart_contract_findings: Vec<SmartContractFinding>,
    pub defi_findings: Vec<DeFiFinding>,
    pub nft_findings: Vec<NFTFinding>,
    pub on_chain_analytics: OnChainAnalytics,
    pub cross_chain_findings: Vec<CrossChainFinding>,
    pub dapp_findings: Vec<DAppFinding>,
    pub wallet_findings: Vec<WalletFinding>,
    pub exchange_findings: Vec<ExchangeFinding>,
    pub staking_findings: Vec<StakingFinding>,
    pub threat_intel: Web3ThreatIntel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartContractFinding {
    pub contract_address: String,
    pub language: ContractLanguage,
    pub vulnerability_type: String,
    pub severity: Severity,
    pub description: String,
    pub line_number: Option<u32>,
    pub recommendation: String,
    pub cwe_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContractLanguage {
    Solidity,
    Vyper,
    Rust,     // Solana
    Move,     // Aptos/Sui
    Plutus,   // Cardano
    Ink,      // Polkadot
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeFiFinding {
    pub protocol_address: String,
    pub protocol_name: String,
    pub finding_type: DeFiRiskType,
    pub severity: Severity,
    pub description: String,
    pub affected_functions: Vec<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeFiRiskType {
    LiquidityPoolRisk,
    FlashLoanVulnerability,
    MEVExposure,
    RugPullIndicators,
    PriceManipulation,
    ReentrancyRisk,
    OracleManipulation,
    AccessControlIssue,
    UnverifiedContract,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NFTFinding {
    pub contract_address: String,
    pub collection_name: String,
    pub finding_type: NFTRiskType,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NFTRiskType {
    MetadataVulnerability,
    UnverifiedContract,
    MintingRisk,
    RoyaltyBypass,
    ProvenanceIssue,
    CentralizationRisk,
    LicensingIssue,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OnChainAnalytics {
    pub transaction_analysis: Vec<TransactionAnalysis>,
    pub wallet_tracking: Vec<WalletTrackingResult>,
    pub mixer_detection: Vec<MixerDetection>,
    pub ofac_compliance: OFACComplianceResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionAnalysis {
    pub tx_hash: String,
    pub from_address: String,
    pub to_address: String,
    pub value: String,
    pub gas_price: String,
    pub risk_score: f64,
    pub risk_factors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTrackingResult {
    pub address: String,
    pub balance: String,
    pub transaction_count: u64,
    pub first_seen: String,
    pub last_seen: String,
    pub labels: Vec<String>,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixerDetection {
    pub address: String,
    pub mixer_type: MixerType,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MixerType {
    TornadoCash,
    ChipMixer,
    Wasabi,
    Samourai,
    Other(String),
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OFACComplianceResult {
    pub sanctioned_addresses: Vec<String>,
    pub total_checked: usize,
    pub last_updated: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainFinding {
    pub bridge_address: String,
    pub bridge_name: String,
    pub chains: Vec<String>,
    pub finding_type: CrossChainRiskType,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrossChainRiskType {
    BridgeSecurity,
    WrappedAssetRisk,
    OracleFailure,
    ValidatorRisk,
    MessagePassingVulnerability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAppFinding {
    pub url: String,
    pub dapp_name: String,
    pub finding_type: DAppRiskType,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DAppRiskType {
    PhishingIndicator,
    FrontendVulnerability,
    WalletConnectionRisk,
    PermissionAbuse,
    SupplyChainRisk,
    MetaMaskPhishing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletFinding {
    pub address: String,
    pub wallet_type: WalletType,
    pub finding_type: WalletRiskType,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletType {
    Hot,
    Cold,
    Hardware,
    MultiSig,
    SmartContract,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletRiskType {
    PrivateKeyExposure,
    MultiSigThresholdRisk,
    SmartContractVulnerability,
    UnverifiedWallet,
    ApprovalRisk,
    MaliciousInteraction,
    MixerUsage,
    SuspiciousActivity,
    SinglePointOfFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeFinding {
    pub exchange_name: String,
    pub endpoint: String,
    pub finding_type: ExchangeRiskType,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExchangeRiskType {
    CEXSecurity,
    DEXSecurity,
    WashTradingDetection,
    LiquidityRisk,
    APIVulnerability,
    WithdrawalRisk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingFinding {
    pub validator_address: String,
    pub chain: String,
    pub finding_type: StakingRiskType,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StakingRiskType {
    ValidatorRisk,
    SlashingRisk,
    RewardRisk,
    UptimeIssue,
    SmartContractRisk,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Web3ThreatIntel {
    pub scam_tokens: Vec<ScamToken>,
    pub phishing_sites: Vec<PhishingSite>,
    pub known_exploits: Vec<KnownExploit>,
    pub threat_actors: Vec<ThreatActor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScamToken {
    pub address: String,
    pub name: String,
    pub symbol: String,
    pub scam_type: ScamType,
    pub confidence: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScamType {
    RugPull,
    HoneypotToken,
    FakeToken,
    PumpAndDump,
    Phishing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingSite {
    pub url: String,
    pub target: String,
    pub first_seen: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownExploit {
    pub exploit_id: String,
    pub name: String,
    pub affected_protocols: Vec<String>,
    pub cve_id: Option<String>,
    pub date: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub actor_id: String,
    pub known_addresses: Vec<String>,
    pub techniques: Vec<String>,
    pub last_activity: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}
