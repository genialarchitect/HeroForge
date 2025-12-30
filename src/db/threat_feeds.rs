//! Database operations for threat intelligence feeds

use anyhow::Result;
use sqlx::SqlitePool;

/// Initialize threat feeds tables
pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS threat_indicators (
            id TEXT PRIMARY KEY,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL,
            confidence REAL NOT NULL,
            source TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            threat_types TEXT
        )"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS ioc_enrichment (
            ioc TEXT PRIMARY KEY,
            reputation_score REAL,
            threat_types TEXT,
            enriched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"
    )
    .execute(pool)
    .await?;

    Ok(())
}
