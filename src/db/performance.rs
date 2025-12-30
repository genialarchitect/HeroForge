//! Performance optimization database operations

use sqlx::SqlitePool;
use anyhow::Result;

/// Run performance optimization migrations
pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    // Performance optimization reports
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS performance_reports (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            report_name TEXT NOT NULL,
            optimization_types TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Edge deployment metrics
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS performance_edge_metrics (
            id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL,
            locations_deployed INTEGER NOT NULL,
            average_latency_ms REAL NOT NULL,
            p95_latency_ms REAL NOT NULL,
            p99_latency_ms REAL NOT NULL,
            cache_hit_rate REAL NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (report_id) REFERENCES performance_reports(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Database optimization metrics
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS performance_database_metrics (
            id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL,
            query_latency_ms REAL NOT NULL,
            query_optimization_applied INTEGER NOT NULL,
            cache_hit_rate REAL NOT NULL,
            read_replica_count INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (report_id) REFERENCES performance_reports(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // API performance metrics
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS performance_api_metrics (
            id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL,
            average_response_time_ms REAL NOT NULL,
            p95_response_time_ms REAL NOT NULL,
            throughput_rps REAL NOT NULL,
            compression_ratio REAL NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (report_id) REFERENCES performance_reports(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Scaling metrics
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS performance_scaling_metrics (
            id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL,
            current_instances INTEGER NOT NULL,
            cpu_utilization REAL NOT NULL,
            memory_utilization REAL NOT NULL,
            request_queue_size INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (report_id) REFERENCES performance_reports(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_perf_reports_user ON performance_reports(user_id)")
        .execute(pool)
        .await?;

    Ok(())
}
