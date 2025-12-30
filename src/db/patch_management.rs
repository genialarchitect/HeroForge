use anyhow::Result;
use sqlx::SqlitePool;

pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    // Patches
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS patches (
            id TEXT PRIMARY KEY,
            patch_id TEXT NOT NULL UNIQUE,
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            version TEXT NOT NULL,
            cve_ids TEXT,
            cvss_score REAL,
            epss_score REAL,
            priority_score REAL NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Patch deployments
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS patch_deployments (
            id TEXT PRIMARY KEY,
            patch_id TEXT NOT NULL,
            strategy TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            success_rate REAL,
            rollback_triggered BOOLEAN NOT NULL DEFAULT 0,
            FOREIGN KEY (patch_id) REFERENCES patches(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Patch testing results
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS patch_test_results (
            id TEXT PRIMARY KEY,
            patch_id TEXT NOT NULL,
            test_type TEXT NOT NULL,
            passed BOOLEAN NOT NULL,
            errors TEXT,
            warnings TEXT,
            tested_at TEXT NOT NULL,
            FOREIGN KEY (patch_id) REFERENCES patches(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Virtual patches
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS virtual_patches (
            id TEXT PRIMARY KEY,
            cve_id TEXT NOT NULL,
            patch_type TEXT NOT NULL,
            rule_content TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            deployed_at TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
