//! Database operations for Attack Surface Management

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqlitePool;
use sqlx::FromRow;

use crate::asm::{
    AsmMonitor, AsmBaseline, AsmChange, AuthorizedAsset, AssetRiskScore,
    AssetDiscoveryConfig, AlertConfig, AlertSeverity, BaselineSummary,
    ChangeType, ChangeDetails, RiskFactor, BaselineAsset,
    CreateMonitorRequest, UpdateMonitorRequest,
};

// ============================================================================
// Row Types for query_as
// ============================================================================

#[derive(Debug, FromRow)]
struct MonitorRow {
    id: String,
    user_id: String,
    name: String,
    description: Option<String>,
    domains: String,
    discovery_config: String,
    schedule: String,
    alert_config: String,
    enabled: i32,
    last_run_at: Option<String>,
    next_run_at: Option<String>,
    created_at: String,
    updated_at: String,
}

impl From<MonitorRow> for AsmMonitor {
    fn from(row: MonitorRow) -> Self {
        AsmMonitor {
            id: row.id,
            user_id: row.user_id,
            name: row.name,
            description: row.description,
            domains: serde_json::from_str(&row.domains).unwrap_or_default(),
            discovery_config: serde_json::from_str(&row.discovery_config).unwrap_or_default(),
            schedule: row.schedule,
            alert_config: serde_json::from_str(&row.alert_config).unwrap_or_default(),
            enabled: row.enabled != 0,
            last_run_at: row.last_run_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            next_run_at: row.next_run_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            created_at: DateTime::parse_from_rfc3339(&row.created_at).map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at).map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(Debug, FromRow)]
struct BaselineRow {
    id: String,
    monitor_id: String,
    assets: String,
    summary: String,
    is_active: i32,
    created_at: String,
}

impl From<BaselineRow> for AsmBaseline {
    fn from(row: BaselineRow) -> Self {
        AsmBaseline {
            id: row.id,
            monitor_id: row.monitor_id,
            assets: serde_json::from_str(&row.assets).unwrap_or_default(),
            summary: serde_json::from_str(&row.summary).unwrap_or_else(|_| BaselineSummary {
                total_assets: 0,
                total_ports: 0,
                total_services: 0,
                assets_with_ssl: 0,
                unique_technologies: 0,
            }),
            is_active: row.is_active != 0,
            created_at: DateTime::parse_from_rfc3339(&row.created_at).map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(Debug, FromRow)]
struct ChangeRow {
    id: String,
    monitor_id: String,
    baseline_id: String,
    change_type: String,
    severity: String,
    hostname: String,
    details: String,
    detected_at: String,
    acknowledged: i32,
    acknowledged_by: Option<String>,
    acknowledged_at: Option<String>,
}

impl From<ChangeRow> for AsmChange {
    fn from(row: ChangeRow) -> Self {
        let severity = match row.severity.as_str() {
            "critical" => AlertSeverity::Critical,
            "high" => AlertSeverity::High,
            "medium" => AlertSeverity::Medium,
            "low" => AlertSeverity::Low,
            _ => AlertSeverity::Info,
        };

        let change_type = match row.change_type.as_str() {
            "new_subdomain" => ChangeType::NewSubdomain,
            "new_port" => ChangeType::NewPort,
            "port_closed" => ChangeType::PortClosed,
            "certificate_change" => ChangeType::CertificateChange,
            "certificate_expiring" => ChangeType::CertificateExpiring,
            "technology_change" => ChangeType::TechnologyChange,
            "ip_address_change" => ChangeType::IpAddressChange,
            "asset_removed" => ChangeType::AssetRemoved,
            "service_change" => ChangeType::ServiceChange,
            "shadow_it_detected" => ChangeType::ShadowItDetected,
            _ => ChangeType::NewSubdomain,
        };

        AsmChange {
            id: row.id,
            monitor_id: row.monitor_id,
            baseline_id: row.baseline_id,
            change_type,
            severity,
            hostname: row.hostname,
            details: serde_json::from_str(&row.details).unwrap_or_else(|_| ChangeDetails {
                description: String::new(),
                old_value: None,
                new_value: None,
                affected_ports: vec![],
                metadata: std::collections::HashMap::new(),
            }),
            detected_at: DateTime::parse_from_rfc3339(&row.detected_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            acknowledged: row.acknowledged != 0,
            acknowledged_by: row.acknowledged_by,
            acknowledged_at: row.acknowledged_at.and_then(|s|
                DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))
            ),
        }
    }
}

#[derive(Debug, FromRow)]
struct AuthorizedAssetRow {
    id: String,
    user_id: String,
    hostname_pattern: String,
    ip_ranges: Option<String>,
    description: Option<String>,
    created_at: String,
}

impl From<AuthorizedAssetRow> for AuthorizedAsset {
    fn from(row: AuthorizedAssetRow) -> Self {
        AuthorizedAsset {
            id: row.id,
            user_id: row.user_id,
            hostname_pattern: row.hostname_pattern,
            ip_ranges: row.ip_ranges.map(|s| serde_json::from_str(&s).unwrap_or_default()).unwrap_or_default(),
            description: row.description,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(Debug, FromRow)]
struct RiskScoreRow {
    id: String,
    asset_id: Option<String>,
    hostname: String,
    overall_score: i32,
    factors: String,
    calculated_at: String,
}

impl From<RiskScoreRow> for AssetRiskScore {
    fn from(row: RiskScoreRow) -> Self {
        AssetRiskScore {
            id: row.id,
            asset_id: row.asset_id,
            hostname: row.hostname,
            overall_score: row.overall_score as u32,
            factors: serde_json::from_str(&row.factors).unwrap_or_default(),
            calculated_at: DateTime::parse_from_rfc3339(&row.calculated_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

// ============================================================================
// Monitor Operations
// ============================================================================

/// Get a monitor by ID
pub async fn get_monitor(pool: &SqlitePool, id: &str) -> Result<AsmMonitor> {
    let row = sqlx::query_as::<_, MonitorRow>(
        r#"
        SELECT id, user_id, name, description, domains, discovery_config,
               schedule, alert_config, enabled, last_run_at, next_run_at,
               created_at, updated_at
        FROM asm_monitors
        WHERE id = ?1
        "#
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(row.into())
}

/// Get all monitors for a user
pub async fn get_user_monitors(pool: &SqlitePool, user_id: &str) -> Result<Vec<AsmMonitor>> {
    let rows = sqlx::query_as::<_, MonitorRow>(
        r#"
        SELECT id, user_id, name, description, domains, discovery_config,
               schedule, alert_config, enabled, last_run_at, next_run_at,
               created_at, updated_at
        FROM asm_monitors
        WHERE user_id = ?1
        ORDER BY created_at DESC
        "#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Create a new monitor
pub async fn create_monitor(
    pool: &SqlitePool,
    user_id: &str,
    req: &CreateMonitorRequest,
) -> Result<AsmMonitor> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let domains = serde_json::to_string(&req.domains)?;
    let discovery_config = serde_json::to_string(&req.discovery_config.clone().unwrap_or_default())?;
    let alert_config = serde_json::to_string(&req.alert_config.clone().unwrap_or_default())?;

    sqlx::query(
        r#"
        INSERT INTO asm_monitors (
            id, user_id, name, description, domains, discovery_config,
            schedule, alert_config, enabled, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10)
        "#
    )
    .bind(&id)
    .bind(user_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&domains)
    .bind(&discovery_config)
    .bind(&req.schedule)
    .bind(&alert_config)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_monitor(pool, &id).await
}

/// Update a monitor
pub async fn update_monitor(
    pool: &SqlitePool,
    id: &str,
    req: &UpdateMonitorRequest,
) -> Result<AsmMonitor> {
    let now = Utc::now().to_rfc3339();

    if let Some(name) = &req.name {
        sqlx::query("UPDATE asm_monitors SET name = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(name).bind(&now).bind(id)
            .execute(pool).await?;
    }
    if let Some(desc) = &req.description {
        sqlx::query("UPDATE asm_monitors SET description = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(desc).bind(&now).bind(id)
            .execute(pool).await?;
    }
    if let Some(domains) = &req.domains {
        let domains_json = serde_json::to_string(domains)?;
        sqlx::query("UPDATE asm_monitors SET domains = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(&domains_json).bind(&now).bind(id)
            .execute(pool).await?;
    }
    if let Some(config) = &req.discovery_config {
        let config_json = serde_json::to_string(config)?;
        sqlx::query("UPDATE asm_monitors SET discovery_config = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(&config_json).bind(&now).bind(id)
            .execute(pool).await?;
    }
    if let Some(schedule) = &req.schedule {
        sqlx::query("UPDATE asm_monitors SET schedule = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(schedule).bind(&now).bind(id)
            .execute(pool).await?;
    }
    if let Some(alert) = &req.alert_config {
        let alert_json = serde_json::to_string(alert)?;
        sqlx::query("UPDATE asm_monitors SET alert_config = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(&alert_json).bind(&now).bind(id)
            .execute(pool).await?;
    }
    if let Some(enabled) = req.enabled {
        let enabled_int = if enabled { 1i32 } else { 0i32 };
        sqlx::query("UPDATE asm_monitors SET enabled = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(enabled_int).bind(&now).bind(id)
            .execute(pool).await?;
    }

    get_monitor(pool, id).await
}

/// Delete a monitor
pub async fn delete_monitor(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM asm_monitors WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update monitor run time
pub async fn update_monitor_run_time(
    pool: &SqlitePool,
    id: &str,
    run_time: DateTime<Utc>,
) -> Result<()> {
    let run_time_str = run_time.to_rfc3339();
    sqlx::query("UPDATE asm_monitors SET last_run_at = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&run_time_str)
        .bind(&run_time_str)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ============================================================================
// Baseline Operations
// ============================================================================

/// Get active baseline for a monitor
pub async fn get_active_baseline(pool: &SqlitePool, monitor_id: &str) -> Result<AsmBaseline> {
    let row = sqlx::query_as::<_, BaselineRow>(
        r#"
        SELECT id, monitor_id, assets, summary, is_active, created_at
        FROM asm_baselines
        WHERE monitor_id = ?1 AND is_active = 1
        ORDER BY created_at DESC
        LIMIT 1
        "#
    )
    .bind(monitor_id)
    .fetch_one(pool)
    .await?;

    Ok(row.into())
}

/// Create a new baseline
pub async fn create_baseline(pool: &SqlitePool, baseline: &AsmBaseline) -> Result<()> {
    // Deactivate existing baselines
    sqlx::query("UPDATE asm_baselines SET is_active = 0 WHERE monitor_id = ?1")
        .bind(&baseline.monitor_id)
        .execute(pool)
        .await?;

    let assets = serde_json::to_string(&baseline.assets)?;
    let summary = serde_json::to_string(&baseline.summary)?;
    let is_active = if baseline.is_active { 1i32 } else { 0i32 };
    let created_at = baseline.created_at.to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO asm_baselines (id, monitor_id, assets, summary, is_active, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#
    )
    .bind(&baseline.id)
    .bind(&baseline.monitor_id)
    .bind(&assets)
    .bind(&summary)
    .bind(is_active)
    .bind(&created_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update a baseline
pub async fn update_baseline(pool: &SqlitePool, baseline: &AsmBaseline) -> Result<()> {
    let assets = serde_json::to_string(&baseline.assets)?;
    let summary = serde_json::to_string(&baseline.summary)?;

    sqlx::query("UPDATE asm_baselines SET assets = ?1, summary = ?2 WHERE id = ?3")
        .bind(&assets)
        .bind(&summary)
        .bind(&baseline.id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Change Operations
// ============================================================================

/// Create a change record
pub async fn create_change(pool: &SqlitePool, change: &AsmChange) -> Result<()> {
    let severity = change.severity.to_string();
    let change_type = change.change_type.to_string();
    let details = serde_json::to_string(&change.details)?;
    let detected_at = change.detected_at.to_rfc3339();
    let acknowledged = if change.acknowledged { 1i32 } else { 0i32 };
    let acknowledged_at = change.acknowledged_at.map(|t| t.to_rfc3339());

    sqlx::query(
        r#"
        INSERT INTO asm_changes (
            id, monitor_id, baseline_id, change_type, severity, hostname,
            details, detected_at, acknowledged, acknowledged_by, acknowledged_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#
    )
    .bind(&change.id)
    .bind(&change.monitor_id)
    .bind(&change.baseline_id)
    .bind(&change_type)
    .bind(&severity)
    .bind(&change.hostname)
    .bind(&details)
    .bind(&detected_at)
    .bind(acknowledged)
    .bind(&change.acknowledged_by)
    .bind(&acknowledged_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get changes for a monitor
pub async fn get_monitor_changes(
    pool: &SqlitePool,
    monitor_id: &str,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<AsmChange>> {
    let limit = limit.unwrap_or(50);
    let offset = offset.unwrap_or(0);

    let rows = sqlx::query_as::<_, ChangeRow>(
        r#"
        SELECT id, monitor_id, baseline_id, change_type, severity, hostname,
               details, detected_at, acknowledged, acknowledged_by, acknowledged_at
        FROM asm_changes
        WHERE monitor_id = ?1
        ORDER BY detected_at DESC
        LIMIT ?2 OFFSET ?3
        "#
    )
    .bind(monitor_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Acknowledge a change
pub async fn acknowledge_change(
    pool: &SqlitePool,
    change_id: &str,
    user_id: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE asm_changes SET acknowledged = 1, acknowledged_by = ?1, acknowledged_at = ?2 WHERE id = ?3"
    )
    .bind(user_id)
    .bind(&now)
    .bind(change_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ============================================================================
// Authorized Assets
// ============================================================================

/// Get authorized assets for a user
pub async fn get_authorized_assets(pool: &SqlitePool, user_id: &str) -> Result<Vec<AuthorizedAsset>> {
    let rows = sqlx::query_as::<_, AuthorizedAssetRow>(
        r#"
        SELECT id, user_id, hostname_pattern, ip_ranges, description, created_at
        FROM asm_authorized_assets
        WHERE user_id = ?1
        ORDER BY created_at DESC
        "#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Create authorized asset
pub async fn create_authorized_asset(
    pool: &SqlitePool,
    user_id: &str,
    hostname_pattern: &str,
    ip_ranges: &[String],
    description: Option<&str>,
) -> Result<AuthorizedAsset> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let ip_ranges_json = serde_json::to_string(ip_ranges)?;

    sqlx::query(
        r#"
        INSERT INTO asm_authorized_assets (id, user_id, hostname_pattern, ip_ranges, description, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#
    )
    .bind(&id)
    .bind(user_id)
    .bind(hostname_pattern)
    .bind(&ip_ranges_json)
    .bind(description)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(AuthorizedAsset {
        id,
        user_id: user_id.to_string(),
        hostname_pattern: hostname_pattern.to_string(),
        ip_ranges: ip_ranges.to_vec(),
        description: description.map(|s| s.to_string()),
        created_at: Utc::now(),
    })
}

/// Delete authorized asset
pub async fn delete_authorized_asset(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM asm_authorized_assets WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ============================================================================
// Risk Scores
// ============================================================================

/// Save risk score
pub async fn save_risk_score(pool: &SqlitePool, score: &AssetRiskScore) -> Result<()> {
    let factors = serde_json::to_string(&score.factors)?;
    let calculated_at = score.calculated_at.to_rfc3339();

    sqlx::query(
        r#"
        INSERT OR REPLACE INTO asm_risk_scores (id, asset_id, hostname, overall_score, factors, calculated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#
    )
    .bind(&score.id)
    .bind(&score.asset_id)
    .bind(&score.hostname)
    .bind(score.overall_score as i32)
    .bind(&factors)
    .bind(&calculated_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get risk scores for a user (via their monitors)
pub async fn get_risk_scores(pool: &SqlitePool, user_id: &str) -> Result<Vec<AssetRiskScore>> {
    // Get all monitors for the user first
    let monitors = get_user_monitors(pool, user_id).await?;
    if monitors.is_empty() {
        return Ok(vec![]);
    }

    // Build hostname patterns from monitor domains
    let mut all_scores = Vec::new();
    for monitor in &monitors {
        for domain in &monitor.domains {
            let rows = sqlx::query_as::<_, RiskScoreRow>(
                r#"
                SELECT id, asset_id, hostname, overall_score, factors, calculated_at
                FROM asm_risk_scores
                WHERE hostname LIKE '%' || ?1 || '%'
                ORDER BY overall_score DESC
                "#
            )
            .bind(domain)
            .fetch_all(pool)
            .await?;

            all_scores.extend(rows.into_iter().map(|r| r.into()));
        }
    }

    Ok(all_scores)
}

// ============================================================================
// Statistics
// ============================================================================

#[derive(Debug, FromRow)]
struct CountRow {
    count: i32,
}

/// Count changes since a timestamp
pub async fn count_changes_since(
    pool: &SqlitePool,
    user_id: &str,
    since: DateTime<Utc>,
) -> Result<i64> {
    let since_str = since.to_rfc3339();

    let row = sqlx::query_as::<_, CountRow>(
        r#"
        SELECT COUNT(*) as count
        FROM asm_changes c
        INNER JOIN asm_monitors m ON c.monitor_id = m.id
        WHERE m.user_id = ?1 AND c.detected_at >= ?2
        "#
    )
    .bind(user_id)
    .bind(&since_str)
    .fetch_one(pool)
    .await?;

    Ok(row.count as i64)
}

/// Count changes by severity
pub async fn count_changes_by_severity(
    pool: &SqlitePool,
    user_id: &str,
    severity: AlertSeverity,
) -> Result<i64> {
    let severity_str = severity.to_string();

    let row = sqlx::query_as::<_, CountRow>(
        r#"
        SELECT COUNT(*) as count
        FROM asm_changes c
        INNER JOIN asm_monitors m ON c.monitor_id = m.id
        WHERE m.user_id = ?1 AND c.severity = ?2
        "#
    )
    .bind(user_id)
    .bind(&severity_str)
    .fetch_one(pool)
    .await?;

    Ok(row.count as i64)
}

/// Count unacknowledged changes
pub async fn count_unacknowledged_changes(pool: &SqlitePool, user_id: &str) -> Result<i64> {
    let row = sqlx::query_as::<_, CountRow>(
        r#"
        SELECT COUNT(*) as count
        FROM asm_changes c
        INNER JOIN asm_monitors m ON c.monitor_id = m.id
        WHERE m.user_id = ?1 AND c.acknowledged = 0
        "#
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(row.count as i64)
}

/// Count shadow IT detections
pub async fn count_shadow_it(pool: &SqlitePool, user_id: &str) -> Result<i64> {
    let row = sqlx::query_as::<_, CountRow>(
        r#"
        SELECT COUNT(*) as count
        FROM asm_changes c
        INNER JOIN asm_monitors m ON c.monitor_id = m.id
        WHERE m.user_id = ?1 AND c.change_type = 'shadow_it_detected' AND c.acknowledged = 0
        "#
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(row.count as i64)
}

/// Get due monitors for scheduled execution
pub async fn get_due_monitors(pool: &SqlitePool) -> Result<Vec<AsmMonitor>> {
    let now = Utc::now().to_rfc3339();

    let rows = sqlx::query_as::<_, MonitorRow>(
        r#"
        SELECT id, user_id, name, description, domains, discovery_config,
               schedule, alert_config, enabled, last_run_at, next_run_at,
               created_at, updated_at
        FROM asm_monitors
        WHERE enabled = 1 AND (next_run_at IS NULL OR next_run_at <= ?1)
        "#
    )
    .bind(&now)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

// ============================================================================
// Additional API Support Functions
// ============================================================================

/// Set monitor enabled status
pub async fn set_monitor_enabled(pool: &SqlitePool, id: &str, enabled: bool) -> Result<()> {
    let enabled_int = if enabled { 1i32 } else { 0i32 };
    let now = Utc::now().to_rfc3339();

    sqlx::query("UPDATE asm_monitors SET enabled = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(enabled_int)
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get all baselines for a monitor
pub async fn get_monitor_baselines(pool: &SqlitePool, monitor_id: &str) -> Result<Vec<AsmBaseline>> {
    let rows = sqlx::query_as::<_, BaselineRow>(
        r#"
        SELECT id, monitor_id, assets, summary, is_active, created_at
        FROM asm_baselines
        WHERE monitor_id = ?1
        ORDER BY created_at DESC
        "#
    )
    .bind(monitor_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Activate a specific baseline (deactivates others)
pub async fn activate_baseline(pool: &SqlitePool, baseline_id: &str) -> Result<()> {
    // Get the monitor_id for this baseline
    let row = sqlx::query_as::<_, BaselineRow>(
        "SELECT id, monitor_id, assets, summary, is_active, created_at FROM asm_baselines WHERE id = ?1"
    )
    .bind(baseline_id)
    .fetch_one(pool)
    .await?;

    let monitor_id = row.monitor_id;

    // Deactivate all baselines for this monitor
    sqlx::query("UPDATE asm_baselines SET is_active = 0 WHERE monitor_id = ?1")
        .bind(&monitor_id)
        .execute(pool)
        .await?;

    // Activate the specified baseline
    sqlx::query("UPDATE asm_baselines SET is_active = 1 WHERE id = ?1")
        .bind(baseline_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get a single change by ID
pub async fn get_change(pool: &SqlitePool, id: &str) -> Result<AsmChange> {
    let row = sqlx::query_as::<_, ChangeRow>(
        r#"
        SELECT id, monitor_id, baseline_id, change_type, severity, hostname,
               details, detected_at, acknowledged, acknowledged_by, acknowledged_at
        FROM asm_changes
        WHERE id = ?1
        "#
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(row.into())
}

/// Get changes for user with filters
pub async fn get_user_changes(
    pool: &SqlitePool,
    user_id: &str,
    severity: Option<&str>,
    change_type: Option<&str>,
    acknowledged: Option<bool>,
    limit: i64,
    offset: i64,
) -> Result<Vec<AsmChange>> {
    // Build query dynamically based on filters
    let mut query = String::from(
        r#"
        SELECT c.id, c.monitor_id, c.baseline_id, c.change_type, c.severity, c.hostname,
               c.details, c.detected_at, c.acknowledged, c.acknowledged_by, c.acknowledged_at
        FROM asm_changes c
        INNER JOIN asm_monitors m ON c.monitor_id = m.id
        WHERE m.user_id = ?
        "#
    );

    let mut conditions = Vec::new();
    if severity.is_some() {
        conditions.push("c.severity = ?");
    }
    if change_type.is_some() {
        conditions.push("c.change_type = ?");
    }
    if acknowledged.is_some() {
        conditions.push("c.acknowledged = ?");
    }

    for condition in &conditions {
        query.push_str(" AND ");
        query.push_str(condition);
    }

    query.push_str(" ORDER BY c.detected_at DESC LIMIT ? OFFSET ?");

    // Build and execute the query
    let mut q = sqlx::query_as::<_, ChangeRow>(&query).bind(user_id);

    if let Some(sev) = severity {
        q = q.bind(sev);
    }
    if let Some(ct) = change_type {
        q = q.bind(ct);
    }
    if let Some(ack) = acknowledged {
        q = q.bind(if ack { 1i32 } else { 0i32 });
    }

    q = q.bind(limit).bind(offset);

    let rows = q.fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Get monitor changes with filters
pub async fn get_monitor_changes_filtered(
    pool: &SqlitePool,
    monitor_id: &str,
    severity: Option<&str>,
    change_type: Option<&str>,
    acknowledged: Option<bool>,
    limit: i64,
    offset: i64,
) -> Result<Vec<AsmChange>> {
    let mut query = String::from(
        r#"
        SELECT id, monitor_id, baseline_id, change_type, severity, hostname,
               details, detected_at, acknowledged, acknowledged_by, acknowledged_at
        FROM asm_changes
        WHERE monitor_id = ?
        "#
    );

    let mut conditions = Vec::new();
    if severity.is_some() {
        conditions.push("severity = ?");
    }
    if change_type.is_some() {
        conditions.push("change_type = ?");
    }
    if acknowledged.is_some() {
        conditions.push("acknowledged = ?");
    }

    for condition in &conditions {
        query.push_str(" AND ");
        query.push_str(condition);
    }

    query.push_str(" ORDER BY detected_at DESC LIMIT ? OFFSET ?");

    let mut q = sqlx::query_as::<_, ChangeRow>(&query).bind(monitor_id);

    if let Some(sev) = severity {
        q = q.bind(sev);
    }
    if let Some(ct) = change_type {
        q = q.bind(ct);
    }
    if let Some(ack) = acknowledged {
        q = q.bind(if ack { 1i32 } else { 0i32 });
    }

    q = q.bind(limit).bind(offset);

    let rows = q.fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Get a single authorized asset by ID
pub async fn get_authorized_asset(pool: &SqlitePool, id: &str) -> Result<AuthorizedAsset> {
    let row = sqlx::query_as::<_, AuthorizedAssetRow>(
        r#"
        SELECT id, user_id, hostname_pattern, ip_ranges, description, created_at
        FROM asm_authorized_assets
        WHERE id = ?1
        "#
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(row.into())
}
