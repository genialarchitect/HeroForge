use anyhow::Result;
use sqlx::SqlitePool;

pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    // Attack predictions
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS attack_predictions (
            id TEXT PRIMARY KEY,
            attack_type TEXT NOT NULL,
            predicted_target TEXT,
            likelihood REAL NOT NULL,
            predicted_time TEXT NOT NULL,
            confidence REAL NOT NULL,
            indicators TEXT,
            created_at TEXT NOT NULL,
            validated BOOLEAN,
            validation_notes TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Breach predictions
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS breach_predictions (
            id TEXT PRIMARY KEY,
            asset_id TEXT NOT NULL,
            breach_likelihood REAL NOT NULL,
            estimated_impact REAL NOT NULL,
            time_to_breach INTEGER,
            breach_path TEXT,
            created_at TEXT NOT NULL,
            validated BOOLEAN,
            validation_notes TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Proactive actions
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS proactive_actions (
            id TEXT PRIMARY KEY,
            action_type TEXT NOT NULL,
            target TEXT NOT NULL,
            rationale TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            executed_at TEXT,
            result TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Forecasts
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS security_forecasts (
            id TEXT PRIMARY KEY,
            forecast_type TEXT NOT NULL,
            horizon_days INTEGER NOT NULL,
            forecast_data TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
