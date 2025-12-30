//! Database operations for compliance automation

use anyhow::Result;
use sqlx::SqlitePool;

/// Initialize compliance automation tables
pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS compliance_assessments (
            id TEXT PRIMARY KEY,
            framework TEXT NOT NULL,
            assessment_date TIMESTAMP NOT NULL,
            overall_score REAL NOT NULL,
            controls_passed INTEGER NOT NULL,
            controls_failed INTEGER NOT NULL,
            controls_manual INTEGER NOT NULL,
            evidence_items INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS compliance_evidence (
            id TEXT PRIMARY KEY,
            control_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            description TEXT,
            collected_at TIMESTAMP NOT NULL,
            collected_by TEXT NOT NULL,
            data TEXT,
            version INTEGER DEFAULT 1
        )"
    )
    .execute(pool)
    .await?;

    Ok(())
}
