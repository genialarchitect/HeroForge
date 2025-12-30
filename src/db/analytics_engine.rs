//! Analytics engine database operations

use sqlx::SqlitePool;
use anyhow::Result;

/// Run analytics engine migrations
pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    // Analytics queries
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS analytics_queries (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            query_name TEXT NOT NULL,
            query_type TEXT NOT NULL,
            query_definition TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_executed TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Saved queries
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS analytics_saved_queries (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            query_definition TEXT NOT NULL,
            is_shared BOOLEAN DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Stream processing jobs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS analytics_stream_jobs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            job_name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_config TEXT NOT NULL,
            window_config TEXT NOT NULL,
            processing_config TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Event correlation rules
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS analytics_correlation_rules (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            correlation_type TEXT NOT NULL,
            event_patterns TEXT NOT NULL,
            time_window_seconds INTEGER NOT NULL,
            correlation_key TEXT NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Data warehouse connections
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS analytics_warehouse_connections (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            connection_name TEXT NOT NULL,
            warehouse_type TEXT NOT NULL,
            connection_string TEXT NOT NULL,
            schema_name TEXT NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // OLAP cubes
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS analytics_olap_cubes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            cube_name TEXT NOT NULL,
            dimensions TEXT NOT NULL,
            measures TEXT NOT NULL,
            aggregations TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_analytics_queries_user ON analytics_queries(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_saved_queries_user ON analytics_saved_queries(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_stream_jobs_user ON analytics_stream_jobs(user_id)")
        .execute(pool)
        .await?;

    Ok(())
}
