//! Database operations for supply chain security

use anyhow::Result;
use sqlx::SqlitePool;

/// Initialize supply chain security tables
pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sboms (
            id TEXT PRIMARY KEY,
            project_name TEXT NOT NULL,
            format TEXT NOT NULL,
            content TEXT NOT NULL,
            signature TEXT,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS provenance_attestations (
            id TEXT PRIMARY KEY,
            artifact TEXT NOT NULL,
            build_type TEXT,
            builder TEXT,
            slsa_level TEXT,
            attestation TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"
    )
    .execute(pool)
    .await?;

    Ok(())
}
