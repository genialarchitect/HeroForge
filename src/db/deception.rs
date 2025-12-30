//! Database schema for deception technology (Sprint 7)

use sqlx::SqlitePool;
use anyhow::Result;

pub async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    // Honeypots table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS honeypots (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            honeypot_type TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            port INTEGER NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Honeypot interactions table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS honeypot_interactions (
            id TEXT PRIMARY KEY,
            honeypot_id TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            interaction_type TEXT NOT NULL,
            details TEXT,
            FOREIGN KEY (honeypot_id) REFERENCES honeypots(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Honeytokens table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS honeytokens (
            id TEXT PRIMARY KEY,
            token_type TEXT NOT NULL,
            value TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at TEXT NOT NULL,
            accessed_count INTEGER NOT NULL DEFAULT 0
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Honeytoken access logs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS honeytoken_access (
            id TEXT PRIMARY KEY,
            honeytoken_id TEXT NOT NULL,
            accessor_ip TEXT NOT NULL,
            accessor_user TEXT,
            timestamp TEXT NOT NULL,
            access_method TEXT NOT NULL,
            FOREIGN KEY (honeytoken_id) REFERENCES honeytokens(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_honeypot_interactions_timestamp ON honeypot_interactions(timestamp DESC)"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_honeytoken_access_timestamp ON honeytoken_access(timestamp DESC)"
    )
    .execute(pool)
    .await?;

    Ok(())
}
