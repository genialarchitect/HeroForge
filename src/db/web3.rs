//! Web3 security database operations

use sqlx::SqlitePool;
use anyhow::Result;

/// Run Web3 security migrations
pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    // Web3 assessments table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS web3_assessments (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            assessment_name TEXT NOT NULL,
            blockchain_network TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Smart contract findings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS web3_smart_contract_findings (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL,
            contract_address TEXT NOT NULL,
            language TEXT NOT NULL,
            vulnerability_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            line_number INTEGER,
            recommendation TEXT NOT NULL,
            cwe_id TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (assessment_id) REFERENCES web3_assessments(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // DeFi findings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS web3_defi_findings (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL,
            protocol_address TEXT NOT NULL,
            protocol_name TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            affected_functions TEXT,
            recommendation TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (assessment_id) REFERENCES web3_assessments(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // NFT findings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS web3_nft_findings (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL,
            contract_address TEXT NOT NULL,
            collection_name TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (assessment_id) REFERENCES web3_assessments(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // On-chain transactions
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS web3_transactions (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL,
            tx_hash TEXT NOT NULL,
            from_address TEXT NOT NULL,
            to_address TEXT NOT NULL,
            value TEXT NOT NULL,
            gas_price TEXT NOT NULL,
            risk_score REAL NOT NULL,
            risk_factors TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (assessment_id) REFERENCES web3_assessments(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Wallet tracking
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS web3_wallets (
            id TEXT PRIMARY KEY,
            address TEXT NOT NULL UNIQUE,
            balance TEXT,
            transaction_count INTEGER DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            labels TEXT,
            risk_score REAL DEFAULT 0.0,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_web3_assessments_user ON web3_assessments(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_web3_findings_assessment ON web3_smart_contract_findings(assessment_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_web3_wallets_address ON web3_wallets(address)")
        .execute(pool)
        .await?;

    Ok(())
}
