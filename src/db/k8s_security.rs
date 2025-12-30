//! Database operations for Kubernetes security

use anyhow::Result;
use sqlx::SqlitePool;

/// Initialize K8s security tables
pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS k8s_clusters (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT,
            api_server TEXT,
            last_scanned TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS k8s_findings (
            id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_name TEXT NOT NULL,
            namespace TEXT,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            remediation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (cluster_id) REFERENCES k8s_clusters(id)
        )"
    )
    .execute(pool)
    .await?;

    Ok(())
}
