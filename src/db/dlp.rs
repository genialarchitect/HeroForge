//! Database schema for DLP (Sprint 8)

use sqlx::SqlitePool;
use anyhow::Result;

pub async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dlp_policies (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            patterns TEXT NOT NULL,
            action TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dlp_violations (
            id TEXT PRIMARY KEY,
            policy_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            pattern_matched TEXT NOT NULL,
            action_taken TEXT NOT NULL,
            content_snippet TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (policy_id) REFERENCES dlp_policies(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_dlp_violations_timestamp ON dlp_violations(timestamp DESC)"
    )
    .execute(pool)
    .await?;

    Ok(())
}
