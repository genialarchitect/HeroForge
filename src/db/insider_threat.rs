//! Database schema for insider threat detection (Sprint 8)

use sqlx::SqlitePool;
use anyhow::Result;

pub async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_activities (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            activity_type TEXT NOT NULL,
            resource TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            risk_score REAL NOT NULL,
            metadata TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS insider_threat_alerts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity REAL NOT NULL,
            description TEXT NOT NULL,
            indicators TEXT NOT NULL,
            created_at TEXT NOT NULL,
            resolved_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_user_activities_user_timestamp ON user_activities(user_id, timestamp DESC)"
    )
    .execute(pool)
    .await?;

    Ok(())
}
