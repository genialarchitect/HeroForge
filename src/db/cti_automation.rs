use anyhow::Result;
use sqlx::SqlitePool;

pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    // IOC enrichment cache
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cti_ioc_enrichments (
            id TEXT PRIMARY KEY,
            ioc TEXT NOT NULL UNIQUE,
            ioc_type TEXT NOT NULL,
            passive_dns TEXT,
            whois_data TEXT,
            reputation_score REAL,
            sandbox_results TEXT,
            ssl_cert_info TEXT,
            geolocation TEXT,
            asn TEXT,
            enriched_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Automated responses
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cti_automated_responses (
            id TEXT PRIMARY KEY,
            ioc TEXT NOT NULL,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            confidence REAL NOT NULL,
            result TEXT,
            created_at TEXT NOT NULL,
            executed_at TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Intelligence sharing logs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cti_sharing_logs (
            id TEXT PRIMARY KEY,
            ioc TEXT NOT NULL,
            shared_with TEXT NOT NULL,
            tlp_level TEXT NOT NULL,
            status TEXT NOT NULL,
            shared_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
