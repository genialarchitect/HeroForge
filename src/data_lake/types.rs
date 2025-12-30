use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Data source type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DataSourceType {
    Cloud,
    Network,
    Endpoint,
    Application,
    ThreatIntel,
}

impl std::fmt::Display for DataSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataSourceType::Cloud => write!(f, "cloud"),
            DataSourceType::Network => write!(f, "network"),
            DataSourceType::Endpoint => write!(f, "endpoint"),
            DataSourceType::Application => write!(f, "application"),
            DataSourceType::ThreatIntel => write!(f, "threat_intel"),
        }
    }
}

impl std::str::FromStr for DataSourceType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cloud" => Ok(DataSourceType::Cloud),
            "network" => Ok(DataSourceType::Network),
            "endpoint" => Ok(DataSourceType::Endpoint),
            "application" => Ok(DataSourceType::Application),
            "threat_intel" => Ok(DataSourceType::ThreatIntel),
            _ => Err(anyhow::anyhow!("Invalid data source type: {}", s)),
        }
    }
}

/// Data source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSource {
    pub id: String,
    pub name: String,
    pub source_type: DataSourceType,
    pub config: serde_json::Value,
    pub enabled: bool,
    pub last_sync: Option<DateTime<Utc>>,
    pub records_ingested: i64,
}

/// Request to create a data source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDataSourceRequest {
    pub name: String,
    pub source_type: DataSourceType,
    pub config: serde_json::Value,
}

/// Data record in the data lake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRecord {
    pub id: String,
    pub source_id: String,
    pub timestamp: DateTime<Utc>,
    pub data: serde_json::Value,
    pub metadata: serde_json::Value,
}

/// Storage tier for data retention
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StorageTier {
    Hot,
    Warm,
    Cold,
    Archive,
}

impl std::fmt::Display for StorageTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageTier::Hot => write!(f, "hot"),
            StorageTier::Warm => write!(f, "warm"),
            StorageTier::Cold => write!(f, "cold"),
            StorageTier::Archive => write!(f, "archive"),
        }
    }
}

/// Data retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub id: String,
    pub source_id: String,
    pub hot_retention_days: i64,
    pub warm_retention_days: i64,
    pub cold_retention_days: i64,
    pub archive_retention_days: Option<i64>,
}

/// Data lake statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLakeStats {
    pub total_sources: i64,
    pub enabled_sources: i64,
    pub total_records: i64,
    pub hot_tier_records: i64,
    pub warm_tier_records: i64,
    pub cold_tier_records: i64,
    pub archive_tier_records: i64,
    pub storage_size_bytes: i64,
    pub ingestion_rate_per_second: f64,
}

/// Query request for data lake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLakeQueryRequest {
    pub source_ids: Option<Vec<String>>,
    pub time_range: TimeRange,
    pub filters: Vec<Filter>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Time range for queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Filter for data lake queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filter {
    pub field: String,
    pub operator: FilterOperator,
    pub value: serde_json::Value,
}

/// Filter operators
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FilterOperator {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    Contains,
    StartsWith,
    EndsWith,
    In,
    NotIn,
}

/// Data lake query response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLakeQueryResponse {
    pub records: Vec<DataRecord>,
    pub total_count: i64,
    pub execution_time_ms: i64,
}

/// Data enrichment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentConfig {
    pub enabled: bool,
    pub geo_ip: bool,
    pub threat_intel: bool,
    pub asset_correlation: bool,
    pub user_enrichment: bool,
}

/// Data quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataQualityMetrics {
    pub source_id: String,
    pub completeness_score: f64,
    pub accuracy_score: f64,
    pub timeliness_score: f64,
    pub consistency_score: f64,
    pub overall_score: f64,
    pub issues: Vec<DataQualityIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataQualityIssue {
    pub issue_type: String,
    pub description: String,
    pub severity: String,
    pub count: i64,
}
