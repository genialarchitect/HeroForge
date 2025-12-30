use anyhow::Result;
use sqlx::SqlitePool;

pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    // Orchestration jobs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS orchestration_jobs (
            id TEXT PRIMARY KEY,
            job_type TEXT NOT NULL,
            target_platform TEXT NOT NULL,
            config TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            result TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Edge nodes
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS edge_nodes (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            location TEXT NOT NULL,
            node_type TEXT NOT NULL,
            status TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            config TEXT,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Multi-cloud configurations
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS multi_cloud_configs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            config_name TEXT NOT NULL,
            aws_config TEXT,
            azure_config TEXT,
            gcp_config TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
