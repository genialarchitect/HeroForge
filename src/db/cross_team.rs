//! Cross-Team Data Correlation Database Module
//!
//! Provides unified security context across all colored teams with event bus logging,
//! enabling real-time cross-team collaboration and data sharing.

use sqlx::SqlitePool;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

// ============================================================================
// Types
// ============================================================================

/// Unified user security context from all teams
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserSecurityContext {
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub department: Option<String>,
    pub role: Option<String>,

    // Orange Team Data
    pub training_completion_rate: f64,
    pub phishing_click_rate: f64,
    pub security_awareness_score: f64,
    pub last_training: Option<DateTime<Utc>>,

    // Green Team Data
    pub incident_count: i64,
    pub insider_threat_score: f64,
    pub suspicious_activity_count: i64,

    // Yellow Team Data (for developers)
    pub secure_coding_score: Option<f64>,
    pub code_review_compliance: Option<f64>,

    // White Team Data
    pub compliance_violations: i64,
    pub policy_violations: i64,

    // Aggregated Risk
    pub overall_risk_score: f64,
    pub risk_level: String, // low, medium, high, critical

    pub updated_at: DateTime<Utc>,
}

/// Unified asset security context from all teams
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AssetSecurityContext {
    pub asset_id: String,
    pub asset_type: String,
    pub hostname: String,
    pub ip_addresses: String, // JSON array
    pub owner: Option<String>,

    // Red Team Data
    pub vulnerability_count: i64,
    pub critical_vuln_count: i64,
    pub high_vuln_count: i64,
    pub last_scan: Option<DateTime<Utc>>,
    pub exploitability_score: f64,

    // Blue Team Data
    pub detection_coverage: f64,
    pub monitored: bool,
    pub detection_rule_count: i64,

    // Green Team Data
    pub incident_count: i64,
    pub alert_count: i64,

    // Purple Team Data
    pub attack_simulation_count: i64,
    pub detection_gap_count: i64,

    // White Team Data
    pub compliance_scopes: String, // JSON array
    pub risk_rating: String,

    // Aggregated Risk
    pub overall_risk_score: f64,
    pub risk_level: String, // low, medium, high, critical

    pub updated_at: DateTime<Utc>,
}

/// Cross-team event log entry
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CrossTeamEvent {
    pub event_id: String,
    pub event_type: String,
    pub source_team: String,
    pub target_teams: String, // JSON array
    pub payload: String, // JSON
    pub timestamp: DateTime<Utc>,
}

/// Team integration configuration
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TeamIntegration {
    pub integration_id: String,
    pub source_team: String,
    pub target_team: String,
    pub data_type: String,
    pub sync_frequency: String,
    pub last_sync: Option<DateTime<Utc>>,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================================================
// Database Migrations
// ============================================================================

pub async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    // User security context table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_security_context (
            user_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            department TEXT,
            role TEXT,
            training_completion_rate REAL NOT NULL DEFAULT 0.0,
            phishing_click_rate REAL NOT NULL DEFAULT 0.0,
            security_awareness_score REAL NOT NULL DEFAULT 0.0,
            last_training TEXT,
            incident_count INTEGER NOT NULL DEFAULT 0,
            insider_threat_score REAL NOT NULL DEFAULT 0.0,
            suspicious_activity_count INTEGER NOT NULL DEFAULT 0,
            secure_coding_score REAL,
            code_review_compliance REAL,
            compliance_violations INTEGER NOT NULL DEFAULT 0,
            policy_violations INTEGER NOT NULL DEFAULT 0,
            overall_risk_score REAL NOT NULL DEFAULT 0.0,
            risk_level TEXT NOT NULL DEFAULT 'low',
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#
    ).execute(pool).await?;

    // Asset security context table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asset_security_context (
            asset_id TEXT PRIMARY KEY,
            asset_type TEXT NOT NULL,
            hostname TEXT NOT NULL,
            ip_addresses TEXT NOT NULL,
            owner TEXT,
            vulnerability_count INTEGER NOT NULL DEFAULT 0,
            critical_vuln_count INTEGER NOT NULL DEFAULT 0,
            high_vuln_count INTEGER NOT NULL DEFAULT 0,
            last_scan TEXT,
            exploitability_score REAL NOT NULL DEFAULT 0.0,
            detection_coverage REAL NOT NULL DEFAULT 0.0,
            monitored INTEGER NOT NULL DEFAULT 0,
            detection_rule_count INTEGER NOT NULL DEFAULT 0,
            incident_count INTEGER NOT NULL DEFAULT 0,
            alert_count INTEGER NOT NULL DEFAULT 0,
            attack_simulation_count INTEGER NOT NULL DEFAULT 0,
            detection_gap_count INTEGER NOT NULL DEFAULT 0,
            compliance_scopes TEXT NOT NULL DEFAULT '[]',
            risk_rating TEXT NOT NULL DEFAULT 'low',
            overall_risk_score REAL NOT NULL DEFAULT 0.0,
            risk_level TEXT NOT NULL DEFAULT 'low',
            updated_at TEXT NOT NULL
        )
        "#
    ).execute(pool).await?;

    // Cross-team events table (event bus logging)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cross_team_events (
            event_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            source_team TEXT NOT NULL,
            target_teams TEXT NOT NULL,
            payload TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
        "#
    ).execute(pool).await?;

    // Team integrations table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS team_integrations (
            integration_id TEXT PRIMARY KEY,
            source_team TEXT NOT NULL,
            target_team TEXT NOT NULL,
            data_type TEXT NOT NULL,
            sync_frequency TEXT NOT NULL,
            last_sync TEXT,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#
    ).execute(pool).await?;

    // Create indexes for performance
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_context_risk ON user_security_context(overall_risk_score DESC)")
        .execute(pool).await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_context_updated ON user_security_context(updated_at DESC)")
        .execute(pool).await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_context_risk ON asset_security_context(overall_risk_score DESC)")
        .execute(pool).await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_context_updated ON asset_security_context(updated_at DESC)")
        .execute(pool).await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_type ON cross_team_events(event_type)")
        .execute(pool).await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_source ON cross_team_events(source_team)")
        .execute(pool).await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON cross_team_events(timestamp DESC)")
        .execute(pool).await?;

    log::info!("Cross-team correlation tables initialized");
    Ok(())
}

// ============================================================================
// User Security Context Functions
// ============================================================================

/// Get or create user security context
pub async fn get_user_context(pool: &SqlitePool, user_id: &str) -> Result<UserSecurityContext> {
    match sqlx::query_as::<_, UserSecurityContext>(
        r#"
        SELECT * FROM user_security_context WHERE user_id = ?
        "#
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    {
        Some(context) => Ok(context),
        None => {
            // Create default context if not exists
            let user = sqlx::query_as::<_, (String, String)>(
                r#"SELECT username, email FROM users WHERE id = ?"#
            )
            .bind(user_id)
            .fetch_one(pool)
            .await?;

            let now = Utc::now();
            let context = UserSecurityContext {
                user_id: user_id.to_string(),
                username: user.0,
                email: user.1,
                department: None,
                role: None,
                training_completion_rate: 0.0,
                phishing_click_rate: 0.0,
                security_awareness_score: 0.0,
                last_training: None,
                incident_count: 0,
                insider_threat_score: 0.0,
                suspicious_activity_count: 0,
                secure_coding_score: None,
                code_review_compliance: None,
                compliance_violations: 0,
                policy_violations: 0,
                overall_risk_score: 0.0,
                risk_level: "low".to_string(),
                updated_at: now,
            };

            sqlx::query(
                r#"
                INSERT INTO user_security_context (
                    user_id, username, email, updated_at
                ) VALUES (?, ?, ?, ?)
                "#
            )
            .bind(user_id)
            .bind(&context.username)
            .bind(&context.email)
            .bind(&context.updated_at)
            .execute(pool)
            .await?;

            Ok(context)
        }
    }
}

/// Update user security context
pub async fn update_user_context(
    pool: &SqlitePool,
    user_id: &str,
    updates: UserContextUpdate,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE user_security_context
        SET training_completion_rate = COALESCE(?, training_completion_rate),
            phishing_click_rate = COALESCE(?, phishing_click_rate),
            security_awareness_score = COALESCE(?, security_awareness_score),
            last_training = COALESCE(?, last_training),
            incident_count = COALESCE(?, incident_count),
            insider_threat_score = COALESCE(?, insider_threat_score),
            suspicious_activity_count = COALESCE(?, suspicious_activity_count),
            secure_coding_score = COALESCE(?, secure_coding_score),
            code_review_compliance = COALESCE(?, code_review_compliance),
            compliance_violations = COALESCE(?, compliance_violations),
            policy_violations = COALESCE(?, policy_violations),
            overall_risk_score = COALESCE(?, overall_risk_score),
            risk_level = COALESCE(?, risk_level),
            updated_at = ?
        WHERE user_id = ?
        "#
    )
    .bind(updates.training_completion_rate)
    .bind(updates.phishing_click_rate)
    .bind(updates.security_awareness_score)
    .bind(updates.last_training.map(|t| t.to_rfc3339()))
    .bind(updates.incident_count)
    .bind(updates.insider_threat_score)
    .bind(updates.suspicious_activity_count)
    .bind(updates.secure_coding_score)
    .bind(updates.code_review_compliance)
    .bind(updates.compliance_violations)
    .bind(updates.policy_violations)
    .bind(updates.overall_risk_score)
    .bind(updates.risk_level)
    .bind(now.to_rfc3339())
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

#[derive(Debug, Default)]
pub struct UserContextUpdate {
    pub training_completion_rate: Option<f64>,
    pub phishing_click_rate: Option<f64>,
    pub security_awareness_score: Option<f64>,
    pub last_training: Option<DateTime<Utc>>,
    pub incident_count: Option<i64>,
    pub insider_threat_score: Option<f64>,
    pub suspicious_activity_count: Option<i64>,
    pub secure_coding_score: Option<f64>,
    pub code_review_compliance: Option<f64>,
    pub compliance_violations: Option<i64>,
    pub policy_violations: Option<i64>,
    pub overall_risk_score: Option<f64>,
    pub risk_level: Option<String>,
}

/// Get high-risk users (top N by risk score)
pub async fn get_high_risk_users(pool: &SqlitePool, limit: i64) -> Result<Vec<UserSecurityContext>> {
    let users = sqlx::query_as::<_, UserSecurityContext>(
        r#"
        SELECT * FROM user_security_context
        ORDER BY overall_risk_score DESC
        LIMIT ?
        "#
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(users)
}

// ============================================================================
// Asset Security Context Functions
// ============================================================================

/// Get or create asset security context
pub async fn get_asset_context(pool: &SqlitePool, asset_id: &str) -> Result<AssetSecurityContext> {
    match sqlx::query_as::<_, AssetSecurityContext>(
        r#"
        SELECT * FROM asset_security_context WHERE asset_id = ?
        "#
    )
    .bind(asset_id)
    .fetch_optional(pool)
    .await?
    {
        Some(context) => Ok(context),
        None => {
            // Return error if asset doesn't exist - assets should be created first
            anyhow::bail!("Asset context not found for asset_id: {}", asset_id)
        }
    }
}

/// Create or update asset security context
pub async fn upsert_asset_context(
    pool: &SqlitePool,
    asset_id: &str,
    asset_type: &str,
    hostname: &str,
    ip_addresses: &str,
    owner: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO asset_security_context (
            asset_id, asset_type, hostname, ip_addresses, owner, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(asset_id) DO UPDATE SET
            asset_type = excluded.asset_type,
            hostname = excluded.hostname,
            ip_addresses = excluded.ip_addresses,
            owner = excluded.owner,
            updated_at = excluded.updated_at
        "#
    )
    .bind(asset_id)
    .bind(asset_type)
    .bind(hostname)
    .bind(ip_addresses)
    .bind(owner)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(())
}

/// Update asset security context
pub async fn update_asset_context(
    pool: &SqlitePool,
    asset_id: &str,
    updates: AssetContextUpdate,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE asset_security_context
        SET vulnerability_count = COALESCE(?, vulnerability_count),
            critical_vuln_count = COALESCE(?, critical_vuln_count),
            high_vuln_count = COALESCE(?, high_vuln_count),
            last_scan = COALESCE(?, last_scan),
            exploitability_score = COALESCE(?, exploitability_score),
            detection_coverage = COALESCE(?, detection_coverage),
            monitored = COALESCE(?, monitored),
            detection_rule_count = COALESCE(?, detection_rule_count),
            incident_count = COALESCE(?, incident_count),
            alert_count = COALESCE(?, alert_count),
            attack_simulation_count = COALESCE(?, attack_simulation_count),
            detection_gap_count = COALESCE(?, detection_gap_count),
            compliance_scopes = COALESCE(?, compliance_scopes),
            risk_rating = COALESCE(?, risk_rating),
            overall_risk_score = COALESCE(?, overall_risk_score),
            risk_level = COALESCE(?, risk_level),
            updated_at = ?
        WHERE asset_id = ?
        "#
    )
    .bind(updates.vulnerability_count)
    .bind(updates.critical_vuln_count)
    .bind(updates.high_vuln_count)
    .bind(updates.last_scan.map(|t| t.to_rfc3339()))
    .bind(updates.exploitability_score)
    .bind(updates.detection_coverage)
    .bind(updates.monitored.map(|b| if b { 1 } else { 0 }))
    .bind(updates.detection_rule_count)
    .bind(updates.incident_count)
    .bind(updates.alert_count)
    .bind(updates.attack_simulation_count)
    .bind(updates.detection_gap_count)
    .bind(updates.compliance_scopes)
    .bind(updates.risk_rating)
    .bind(updates.overall_risk_score)
    .bind(updates.risk_level)
    .bind(now.to_rfc3339())
    .bind(asset_id)
    .execute(pool)
    .await?;

    Ok(())
}

#[derive(Debug, Default)]
pub struct AssetContextUpdate {
    pub vulnerability_count: Option<i64>,
    pub critical_vuln_count: Option<i64>,
    pub high_vuln_count: Option<i64>,
    pub last_scan: Option<DateTime<Utc>>,
    pub exploitability_score: Option<f64>,
    pub detection_coverage: Option<f64>,
    pub monitored: Option<bool>,
    pub detection_rule_count: Option<i64>,
    pub incident_count: Option<i64>,
    pub alert_count: Option<i64>,
    pub attack_simulation_count: Option<i64>,
    pub detection_gap_count: Option<i64>,
    pub compliance_scopes: Option<String>,
    pub risk_rating: Option<String>,
    pub overall_risk_score: Option<f64>,
    pub risk_level: Option<String>,
}

/// Get high-risk assets (top N by risk score)
pub async fn get_high_risk_assets(pool: &SqlitePool, limit: i64) -> Result<Vec<AssetSecurityContext>> {
    let assets = sqlx::query_as::<_, AssetSecurityContext>(
        r#"
        SELECT * FROM asset_security_context
        ORDER BY overall_risk_score DESC
        LIMIT ?
        "#
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(assets)
}

// ============================================================================
// Cross-Team Event Functions
// ============================================================================

/// Log a cross-team event
pub async fn log_event(
    pool: &SqlitePool,
    event_type: &str,
    source_team: &str,
    target_teams: &[&str],
    payload: serde_json::Value,
) -> Result<String> {
    let event_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO cross_team_events (
            event_id, event_type, source_team, target_teams, payload, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&event_id)
    .bind(event_type)
    .bind(source_team)
    .bind(serde_json::to_string(&target_teams)?)
    .bind(serde_json::to_string(&payload)?)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(event_id)
}

/// Get recent events (last N events)
pub async fn get_recent_events(pool: &SqlitePool, limit: i64) -> Result<Vec<CrossTeamEvent>> {
    let events = sqlx::query_as::<_, CrossTeamEvent>(
        r#"
        SELECT * FROM cross_team_events
        ORDER BY timestamp DESC
        LIMIT ?
        "#
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(events)
}

/// Get events by type
pub async fn get_events_by_type(pool: &SqlitePool, event_type: &str, limit: i64) -> Result<Vec<CrossTeamEvent>> {
    let events = sqlx::query_as::<_, CrossTeamEvent>(
        r#"
        SELECT * FROM cross_team_events
        WHERE event_type = ?
        ORDER BY timestamp DESC
        LIMIT ?
        "#
    )
    .bind(event_type)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(events)
}

/// Get events by source team
pub async fn get_events_by_source(pool: &SqlitePool, source_team: &str, limit: i64) -> Result<Vec<CrossTeamEvent>> {
    let events = sqlx::query_as::<_, CrossTeamEvent>(
        r#"
        SELECT * FROM cross_team_events
        WHERE source_team = ?
        ORDER BY timestamp DESC
        LIMIT ?
        "#
    )
    .bind(source_team)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(events)
}

// ============================================================================
// Team Integration Functions
// ============================================================================

/// Create team integration
pub async fn create_integration(
    pool: &SqlitePool,
    source_team: &str,
    target_team: &str,
    data_type: &str,
    sync_frequency: &str,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO team_integrations (
            integration_id, source_team, target_team, data_type,
            sync_frequency, is_enabled, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        "#
    )
    .bind(&id)
    .bind(source_team)
    .bind(target_team)
    .bind(data_type)
    .bind(sync_frequency)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get all team integrations
pub async fn list_integrations(pool: &SqlitePool) -> Result<Vec<TeamIntegration>> {
    let integrations = sqlx::query_as::<_, TeamIntegration>(
        r#"
        SELECT * FROM team_integrations
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(integrations)
}

/// Update integration last sync time
pub async fn update_integration_sync(pool: &SqlitePool, integration_id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE team_integrations
        SET last_sync = ?, updated_at = ?
        WHERE integration_id = ?
        "#
    )
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(integration_id)
    .execute(pool)
    .await?;

    Ok(())
}
