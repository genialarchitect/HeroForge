//! Database operations for plugin marketplace

use anyhow::Result;
use sqlx::SqlitePool;

/// Initialize plugin marketplace tables
pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS plugins (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            author TEXT NOT NULL,
            description TEXT,
            rating REAL DEFAULT 0.0,
            downloads INTEGER DEFAULT 0,
            certified BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS plugin_reviews (
            id TEXT PRIMARY KEY,
            plugin_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            rating INTEGER NOT NULL,
            review TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (plugin_id) REFERENCES plugins(id)
        )"
    )
    .execute(pool)
    .await?;

    Ok(())
}
