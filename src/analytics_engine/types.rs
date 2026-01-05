//! Advanced analytics types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsQuery {
    pub query_id: String,
    pub query_type: QueryType,
    pub parameters: QueryParameters,
    pub time_range: Option<TimeRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryType {
    RealTimeStream,
    BatchProcessing,
    EventCorrelation,
    NaturalLanguage,
    VisualBuilder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryParameters {
    pub filters: Vec<Filter>,
    pub aggregations: Vec<Aggregation>,
    pub grouping: Vec<String>,
    pub sorting: Vec<SortField>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filter {
    pub field: String,
    pub operator: FilterOperator,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterOperator {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    Contains,
    StartsWith,
    EndsWith,
    In,
    NotIn,
    Between,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aggregation {
    pub field: String,
    pub function: AggregationFunction,
    pub alias: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregationFunction {
    Count,
    Sum,
    Average,
    Min,
    Max,
    Percentile(f64),
    StdDev,
    Variance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortField {
    pub field: String,
    pub direction: SortDirection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortDirection {
    Ascending,
    Descending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsResult {
    pub query_id: String,
    pub execution_time_ms: f64,
    pub rows: Vec<HashMap<String, serde_json::Value>>,
    pub total_count: usize,
    pub metadata: ResultMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultMetadata {
    pub columns: Vec<ColumnInfo>,
    pub scanned_bytes: usize,
    pub cached: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnInfo {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
}

// ============================================================================
// Stream Processing
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    pub source: StreamSource,
    pub window_config: WindowConfig,
    pub processing: StreamProcessing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamSource {
    Kafka { brokers: Vec<String>, topic: String, group_id: Option<String>, security: Option<KafkaSecurity> },
    Pulsar { service_url: String, topic: String, subscription: Option<String>, auth: Option<PulsarAuth> },
    Flink { job_id: String },
    Kinesis { stream_name: String, region: Option<String> },
    RedPanda { brokers: Vec<String>, topic: String },
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaSecurity {
    pub protocol: KafkaSecurityProtocol,
    pub sasl_mechanism: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KafkaSecurityProtocol {
    Plaintext,
    Ssl,
    SaslPlaintext,
    SaslSsl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulsarAuth {
    pub auth_type: PulsarAuthType,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PulsarAuthType {
    None,
    Token,
    OAuth2,
    Tls,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowConfig {
    pub window_type: WindowType,
    pub size_seconds: u64,
    pub slide_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WindowType {
    Tumbling,
    Sliding,
    Session,
    Global,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamProcessing {
    Aggregation(Aggregation),
    Filtering(Filter),
    Transformation(String),
    CEP(ComplexEventProcessing),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexEventProcessing {
    pub pattern: String,
    pub within_seconds: u64,
    pub select_strategy: SelectStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SelectStrategy {
    First,
    Last,
    All,
}

// ============================================================================
// Event Correlation
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub rule_id: String,
    pub name: String,
    pub correlation_type: CorrelationType,
    pub events: Vec<EventPattern>,
    pub time_window_seconds: u64,
    pub correlation_key: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorrelationType {
    MultiEvent,        // Multiple events of different types
    CrossSource,       // Events from different sources
    Temporal,          // Time-based correlation
    Spatial,           // Location-based correlation
    Causal,            // Cause-and-effect relationships
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventPattern {
    pub event_type: String,
    pub conditions: Vec<Filter>,
    pub occurrence: OccurrenceConstraint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OccurrenceConstraint {
    Exactly(usize),
    AtLeast(usize),
    AtMost(usize),
    Between { min: usize, max: usize },
}

// ============================================================================
// Data Warehouse Integration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarehouseConfig {
    pub warehouse_type: WarehouseType,
    pub connection_string: String,
    pub schema: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WarehouseType {
    Snowflake,
    BigQuery,
    Redshift,
    Synapse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OLAPCube {
    pub cube_id: String,
    pub dimensions: Vec<Dimension>,
    pub measures: Vec<Measure>,
    pub aggregations: Vec<Aggregation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dimension {
    pub name: String,
    pub hierarchy: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Measure {
    pub name: String,
    pub aggregation: AggregationFunction,
    pub format: String,
}
