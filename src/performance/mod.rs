//! Global Performance Optimization (Phase 4 Sprint 16)
//!
//! Achieve sub-100ms latency globally, support massive scale

pub mod edge;
pub mod database;
pub mod api;
pub mod frontend;
pub mod scaling;
pub mod partitioning;
pub mod types;

pub use types::*;
use anyhow::Result;

/// Run comprehensive performance optimization
pub async fn optimize_performance(config: &PerformanceConfig) -> Result<PerformanceReport> {
    let mut report = PerformanceReport::default();

    // Edge computing optimization
    if config.optimize_edge {
        report.edge_metrics = edge::optimize_edge_deployment(&config.edge_config).await?;
    }

    // Database optimization
    if config.optimize_database {
        report.database_metrics = database::optimize_database(&config.db_config).await?;
    }

    // API optimization
    if config.optimize_api {
        report.api_metrics = api::optimize_api(&config.api_config).await?;
    }

    // Frontend optimization
    if config.optimize_frontend {
        report.frontend_metrics = frontend::optimize_frontend(&config.frontend_config).await?;
    }

    // Horizontal scaling
    if config.optimize_scaling {
        report.scaling_metrics = scaling::optimize_scaling(&config.scaling_config).await?;
    }

    // Data partitioning
    if config.optimize_partitioning {
        report.partitioning_metrics = partitioning::optimize_partitioning(&config.partition_config).await?;
    }

    Ok(report)
}
