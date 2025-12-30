use anyhow::Result;
use sqlx::SqlitePool;

/// Initialize data lake metadata tables
pub async fn init_data_lake_tables(pool: &SqlitePool) -> Result<()> {
    // Data lake sources table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS data_lake_sources (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            config TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            last_sync TEXT,
            records_ingested INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"
    )
    .execute(pool)
    .await?;

    // Data lake records metadata (for tracking, actual data stored in backend)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS data_lake_records_metadata (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            record_count INTEGER NOT NULL,
            storage_tier TEXT NOT NULL,
            ingestion_timestamp TEXT NOT NULL,
            time_range_start TEXT NOT NULL,
            time_range_end TEXT NOT NULL,
            storage_path TEXT,
            size_bytes INTEGER,
            FOREIGN KEY(source_id) REFERENCES data_lake_sources(id) ON DELETE CASCADE
        )"
    )
    .execute(pool)
    .await?;

    // Retention policies table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS data_lake_retention_policies (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            hot_retention_days INTEGER NOT NULL DEFAULT 7,
            warm_retention_days INTEGER NOT NULL DEFAULT 30,
            cold_retention_days INTEGER NOT NULL DEFAULT 90,
            archive_retention_days INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(source_id) REFERENCES data_lake_sources(id) ON DELETE CASCADE
        )"
    )
    .execute(pool)
    .await?;

    // Data quality metrics table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS data_lake_quality_metrics (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            completeness_score REAL NOT NULL,
            accuracy_score REAL NOT NULL,
            timeliness_score REAL NOT NULL,
            consistency_score REAL NOT NULL,
            overall_score REAL NOT NULL,
            issues TEXT,
            measured_at TEXT NOT NULL,
            FOREIGN KEY(source_id) REFERENCES data_lake_sources(id) ON DELETE CASCADE
        )"
    )
    .execute(pool)
    .await?;

    // Data enrichment configurations table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS data_lake_enrichment_configs (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            geo_ip BOOLEAN NOT NULL DEFAULT 0,
            threat_intel BOOLEAN NOT NULL DEFAULT 0,
            asset_correlation BOOLEAN NOT NULL DEFAULT 0,
            user_enrichment BOOLEAN NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(source_id) REFERENCES data_lake_sources(id) ON DELETE CASCADE
        )"
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_data_lake_sources_type ON data_lake_sources(type)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_data_lake_sources_enabled ON data_lake_sources(enabled)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_data_lake_records_source ON data_lake_records_metadata(source_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_data_lake_records_tier ON data_lake_records_metadata(storage_tier)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_data_lake_records_timestamp ON data_lake_records_metadata(ingestion_timestamp)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_data_lake_quality_source ON data_lake_quality_metrics(source_id)")
        .execute(pool)
        .await?;

    log::info!("Data lake tables initialized");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn test_init_data_lake_tables() {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();

        let result = init_data_lake_tables(&pool).await;
        assert!(result.is_ok());

        // Verify tables were created
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'data_lake_%'"
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        assert!(tables.contains(&"data_lake_sources".to_string()));
        assert!(tables.contains(&"data_lake_records_metadata".to_string()));
        assert!(tables.contains(&"data_lake_retention_policies".to_string()));
        assert!(tables.contains(&"data_lake_quality_metrics".to_string()));
        assert!(tables.contains(&"data_lake_enrichment_configs".to_string()));
    }
}
