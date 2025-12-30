//! Performance optimization types

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub optimize_edge: bool,
    pub optimize_database: bool,
    pub optimize_api: bool,
    pub optimize_frontend: bool,
    pub optimize_scaling: bool,
    pub optimize_partitioning: bool,

    pub edge_config: EdgeConfig,
    pub db_config: DatabaseConfig,
    pub api_config: APIConfig,
    pub frontend_config: FrontendConfig,
    pub scaling_config: ScalingConfig,
    pub partition_config: PartitioningConfig,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PerformanceReport {
    pub edge_metrics: EdgeMetrics,
    pub database_metrics: DatabaseMetrics,
    pub api_metrics: APIMetrics,
    pub frontend_metrics: FrontendMetrics,
    pub scaling_metrics: ScalingMetrics,
    pub partitioning_metrics: PartitioningMetrics,
}

// ============================================================================
// Edge Computing
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EdgeConfig {
    pub target_locations: usize,  // Target 100+ edge locations
    pub platforms: Vec<EdgePlatform>,
    pub edge_intelligence: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgePlatform {
    CloudflareWorkers,
    AWSLambdaEdge,
    AzureFunctions,
    FastlyCompute,
    Custom(String),
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EdgeMetrics {
    pub locations_deployed: usize,
    pub average_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub cache_hit_rate: f64,
}

// ============================================================================
// Database Optimization
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DatabaseConfig {
    pub enable_query_optimization: bool,
    pub enable_partitioning: bool,
    pub enable_read_replicas: bool,
    pub enable_caching: bool,
    pub connection_pool_size: usize,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DatabaseMetrics {
    pub query_latency_ms: f64,
    pub query_optimization_applied: usize,
    pub cache_hit_rate: f64,
    pub read_replica_count: usize,
}

// ============================================================================
// API Optimization
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct APIConfig {
    pub enable_graphql: bool,
    pub enable_compression: bool,
    pub enable_batching: bool,
    pub enable_caching: bool,
    pub rate_limiting: RateLimitConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RateLimitConfig {
    pub requests_per_second: usize,
    pub burst_size: usize,
    pub per_user_limits: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct APIMetrics {
    pub average_response_time_ms: f64,
    pub p95_response_time_ms: f64,
    pub throughput_rps: f64,
    pub compression_ratio: f64,
}

// ============================================================================
// Frontend Optimization
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FrontendConfig {
    pub enable_pwa: bool,
    pub enable_service_worker: bool,
    pub enable_code_splitting: bool,
    pub enable_image_optimization: bool,
    pub enable_lazy_loading: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FrontendMetrics {
    pub first_contentful_paint_ms: f64,
    pub time_to_interactive_ms: f64,
    pub largest_contentful_paint_ms: f64,
    pub bundle_size_kb: f64,
    pub lighthouse_score: f64,
}

// ============================================================================
// Horizontal Scaling
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScalingConfig {
    pub auto_scaling: bool,
    pub load_balancing: LoadBalancingStrategy,
    pub distributed_caching: bool,
    pub queue_based_processing: bool,
    pub min_instances: usize,
    pub max_instances: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum LoadBalancingStrategy {
    #[default]
    RoundRobin,
    LeastConnections,
    IPHash,
    WeightedRoundRobin,
    LatencyBased,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ScalingMetrics {
    pub current_instances: usize,
    pub cpu_utilization: f64,
    pub memory_utilization: f64,
    pub request_queue_size: usize,
}

// ============================================================================
// Data Partitioning
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PartitioningConfig {
    pub tenant_sharding: bool,
    pub geographic_sharding: bool,
    pub time_based_partitioning: bool,
    pub partition_key: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PartitioningMetrics {
    pub partition_count: usize,
    pub average_partition_size_mb: f64,
    pub rebalancing_required: bool,
}
