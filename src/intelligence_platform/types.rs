//! Intelligence platform types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
    pub hub_config: HubConfig,
    pub api_config: APIConfig,
    pub sharing_config: SharingConfig,
    pub marketplace_enabled: bool,
    pub marketplace_config: MarketplaceConfig,
    pub ioc_config: IOCConfig,
    pub automation_config: AutomationConfig,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IntelligencePlatform {
    pub hub: IntelligenceHub,
    pub api_endpoints: Vec<String>,
    pub sharing_networks: Vec<SharingNetwork>,
    pub marketplace: Option<Marketplace>,
    pub operations_center: OperationsCenter,
    pub automation: AutomationConfig,
}

// ============================================================================
// Unified Intelligence Hub
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HubConfig {
    pub sources: Vec<IntelligenceSource>,
    pub deduplication: bool,
    pub unified_timeline: bool,
    pub correlation_enabled: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IntelligenceHub {
    pub total_indicators: usize,
    pub sources: Vec<IntelligenceSource>,
    pub unified_view: UnifiedView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceSource {
    pub source_id: String,
    pub source_type: SourceType,
    pub enabled: bool,
    pub last_updated: chrono::DateTime<chrono::Utc>,
    pub indicator_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SourceType {
    ThreatFeed,
    OSINT,
    CommercialIntel,
    ISACSharing,
    Internal,
    Custom(String),
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UnifiedView {
    pub timeline: Vec<TimelineEvent>,
    pub dashboard: Dashboard,
    pub deduplicated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub event_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub source: String,
    pub indicators: Vec<String>,
    pub severity: Severity,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    pub widgets: Vec<DashboardWidget>,
    pub layout: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardWidget {
    pub widget_id: String,
    pub widget_type: WidgetType,
    pub data_source: String,
    pub refresh_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WidgetType {
    MetricCard,
    Chart,
    Table,
    Map,
    Timeline,
}

// ============================================================================
// Intelligence API
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct APIConfig {
    pub enable_rest: bool,
    pub enable_graphql: bool,
    pub enable_webhooks: bool,
    pub enable_streaming: bool,
    pub rate_limit_rps: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceAPIRequest {
    pub request_type: APIRequestType,
    pub parameters: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum APIRequestType {
    QueryIndicators,
    EnrichIOC,
    SubmitIntel,
    GetThreatActors,
    GetCampaigns,
}

// ============================================================================
// Intelligence Sharing Networks
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SharingConfig {
    pub networks: Vec<NetworkConfig>,
    pub auto_sharing: bool,
    pub trusted_peers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub network_id: String,
    pub network_type: NetworkType,
    pub sharing_level: SharingLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkType {
    ISACIntegration,
    IndustryVertical(String),
    SupplyChain,
    PeerToPeer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SharingLevel {
    TLP_WHITE,    // Unlimited disclosure
    TLP_GREEN,    // Community disclosure
    TLP_AMBER,    // Limited disclosure
    TLP_RED,      // Personal use only
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingNetwork {
    pub network_id: String,
    pub members: Vec<String>,
    pub shared_indicators: usize,
    pub last_sync: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// Intelligence Marketplace
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MarketplaceConfig {
    pub endpoint: String,
    pub api_key: String,
    pub auto_purchase: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Marketplace {
    pub available_feeds: Vec<FeedListing>,
    pub subscriptions: Vec<Subscription>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedListing {
    pub feed_id: String,
    pub name: String,
    pub provider: String,
    pub description: String,
    pub category: String,
    pub pricing: PricingModel,
    pub rating: f64,
    pub reviews: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PricingModel {
    Free,
    Monthly(f64),
    PerIndicator(f64),
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub subscription_id: String,
    pub feed_id: String,
    pub status: SubscriptionStatus,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubscriptionStatus {
    Active,
    Suspended,
    Expired,
    Cancelled,
}

// ============================================================================
// Intelligence Operations Center (IOC)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IOCConfig {
    pub enable_247_monitoring: bool,
    pub analyst_workflows: bool,
    pub reporting_enabled: bool,
    pub metrics_tracking: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OperationsCenter {
    pub active_analysts: usize,
    pub workflows: Vec<AnalystWorkflow>,
    pub reports: Vec<IntelligenceReport>,
    pub metrics: IOCMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystWorkflow {
    pub workflow_id: String,
    pub name: String,
    pub steps: Vec<WorkflowStep>,
    pub assigned_to: Option<String>,
    pub status: WorkflowStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub step_id: String,
    pub name: String,
    pub completed: bool,
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowStatus {
    Pending,
    InProgress,
    Review,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceReport {
    pub report_id: String,
    pub title: String,
    pub report_type: ReportType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub author: String,
    pub distribution: SharingLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportType {
    ThreatBrief,
    TacticalAnalysis,
    StrategicAssessment,
    IncidentReport,
    TrendAnalysis,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IOCMetrics {
    pub indicators_processed_24h: usize,
    pub reports_generated_week: usize,
    pub mean_time_to_analysis: f64,
    pub analyst_productivity: HashMap<String, f64>,
}

// ============================================================================
// Intelligence Automation
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AutomationConfig {
    pub auto_collection: bool,
    pub auto_enrichment: bool,
    pub auto_analysis: bool,
    pub auto_dissemination: bool,
    pub feedback_loops: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationPipeline {
    pub pipeline_id: String,
    pub stages: Vec<AutomationStage>,
    pub schedule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationStage {
    pub stage_name: String,
    pub action: AutomationAction,
    pub condition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutomationAction {
    CollectFromSource(String),
    EnrichIndicator,
    AnalyzePattern,
    DistributeIntel,
    UpdateModels,
    GenerateReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}
