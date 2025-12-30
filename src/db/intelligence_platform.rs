//! Intelligence platform database operations

use sqlx::SqlitePool;
use anyhow::Result;

/// Run intelligence platform migrations
pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    // Intelligence sources
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS intel_sources (
            id TEXT PRIMARY KEY,
            source_type TEXT NOT NULL,
            name TEXT NOT NULL,
            endpoint TEXT,
            is_enabled BOOLEAN DEFAULT 1,
            last_updated TEXT NOT NULL,
            indicator_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Intelligence timeline events
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS intel_timeline_events (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_id TEXT NOT NULL,
            indicators TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (source_id) REFERENCES intel_sources(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Sharing networks
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS intel_sharing_networks (
            id TEXT PRIMARY KEY,
            network_type TEXT NOT NULL,
            name TEXT NOT NULL,
            sharing_level TEXT NOT NULL,
            members TEXT NOT NULL,
            shared_indicators_count INTEGER DEFAULT 0,
            last_sync TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Marketplace feed listings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS intel_marketplace_feeds (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            provider TEXT NOT NULL,
            description TEXT,
            category TEXT NOT NULL,
            pricing_model TEXT NOT NULL,
            pricing_value REAL,
            rating REAL DEFAULT 0.0,
            review_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // User subscriptions
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS intel_marketplace_subscriptions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            feed_id TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (feed_id) REFERENCES intel_marketplace_feeds(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Analyst workflows
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS intel_analyst_workflows (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            workflow_name TEXT NOT NULL,
            steps TEXT NOT NULL,
            assigned_to TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Intelligence reports
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS intel_reports (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            title TEXT NOT NULL,
            report_type TEXT NOT NULL,
            content TEXT NOT NULL,
            distribution_level TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // IOC metrics
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS intel_ioc_metrics (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            indicators_processed_24h INTEGER NOT NULL,
            reports_generated_week INTEGER NOT NULL,
            mean_time_to_analysis REAL NOT NULL,
            active_analysts INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Automation pipelines
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS intel_automation_pipelines (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            pipeline_name TEXT NOT NULL,
            stages TEXT NOT NULL,
            schedule TEXT,
            is_active BOOLEAN DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_intel_timeline_timestamp ON intel_timeline_events(timestamp)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_intel_subscriptions_user ON intel_marketplace_subscriptions(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_intel_workflows_user ON intel_analyst_workflows(user_id)")
        .execute(pool)
        .await?;

    Ok(())
}
