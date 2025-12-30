use anyhow::Result;
use sqlx::SqlitePool;

pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    // Intelligence sources tracking
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_intel_sources (
            id TEXT PRIMARY KEY,
            source_name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            url TEXT,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            last_sync TEXT,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Intelligence correlations
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_intel_correlations (
            id TEXT PRIMARY KEY,
            ioc_ids TEXT NOT NULL,
            campaign_id TEXT,
            actor_id TEXT,
            confidence REAL NOT NULL,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Threat briefings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_briefings (
            id TEXT PRIMARY KEY,
            briefing_type TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            date TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Priority Intelligence Requirements (PIR)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS priority_intel_requirements (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
