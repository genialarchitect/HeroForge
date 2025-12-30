//! OT/ICS Database Operations
//!
//! Database operations for OT/ICS asset management and scanning.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::ot_ics::types::*;

// ============================================================================
// Database Row Structs
// ============================================================================

#[derive(Debug, sqlx::FromRow)]
struct OtAssetRow {
    id: String,
    user_id: String,
    name: String,
    asset_type: String,
    vendor: Option<String>,
    model: Option<String>,
    firmware_version: Option<String>,
    ip_address: Option<String>,
    mac_address: Option<String>,
    protocols: String,
    purdue_level: Option<i32>,
    zone: Option<String>,
    criticality: String,
    last_seen: Option<String>,
    first_seen: Option<String>,
    scan_id: Option<String>,
    vulnerabilities: String,
    risk_score: i32,
    notes: Option<String>,
    customer_id: Option<String>,
    engagement_id: Option<String>,
    created_at: String,
    updated_at: String,
}

impl OtAssetRow {
    fn into_ot_asset(self) -> OtAsset {
        let protocols: Vec<OtProtocolType> = serde_json::from_str(&self.protocols)
            .unwrap_or_default();
        let vulnerabilities: Vec<OtVulnerability> = serde_json::from_str(&self.vulnerabilities)
            .unwrap_or_default();

        OtAsset {
            id: self.id,
            user_id: self.user_id,
            name: self.name,
            asset_type: self.asset_type.parse().unwrap_or(OtAssetType::Unknown),
            vendor: self.vendor,
            model: self.model,
            firmware_version: self.firmware_version,
            ip_address: self.ip_address,
            mac_address: self.mac_address,
            protocols,
            purdue_level: self.purdue_level,
            zone: self.zone,
            criticality: self.criticality.parse().unwrap_or(Criticality::Medium),
            last_seen: self.last_seen.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            first_seen: self.first_seen.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            scan_id: self.scan_id,
            vulnerabilities,
            risk_score: self.risk_score,
            notes: self.notes,
            customer_id: self.customer_id,
            engagement_id: self.engagement_id,
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&self.updated_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct OtScanRow {
    id: String,
    user_id: String,
    name: String,
    scan_type: String,
    target_range: String,
    protocols_enabled: String,
    status: String,
    assets_discovered: i32,
    vulnerabilities_found: i32,
    started_at: Option<String>,
    completed_at: Option<String>,
    customer_id: Option<String>,
    engagement_id: Option<String>,
    created_at: String,
}

impl OtScanRow {
    fn into_ot_scan(self) -> OtScan {
        let protocols_enabled: Vec<OtProtocolType> = serde_json::from_str(&self.protocols_enabled)
            .unwrap_or_default();

        OtScan {
            id: self.id,
            user_id: self.user_id,
            name: self.name,
            scan_type: self.scan_type.parse().unwrap_or(OtScanType::Discovery),
            target_range: self.target_range,
            protocols_enabled,
            status: self.status.parse().unwrap_or(ScanStatus::Pending),
            assets_discovered: self.assets_discovered,
            vulnerabilities_found: self.vulnerabilities_found,
            started_at: self.started_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            completed_at: self.completed_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            customer_id: self.customer_id,
            engagement_id: self.engagement_id,
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

// ============================================================================
// Request Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateOtAssetRequest {
    pub name: String,
    pub asset_type: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
    pub protocols: Option<Vec<String>>,
    pub purdue_level: Option<i32>,
    pub zone: Option<String>,
    pub criticality: Option<String>,
    pub notes: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOtAssetRequest {
    pub name: Option<String>,
    pub asset_type: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
    pub protocols: Option<Vec<String>>,
    pub purdue_level: Option<i32>,
    pub zone: Option<String>,
    pub criticality: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateOtScanRequest {
    pub name: String,
    pub scan_type: String,
    pub target_range: String,
    pub protocols_enabled: Option<Vec<String>>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListOtAssetsQuery {
    pub asset_type: Option<String>,
    pub purdue_level: Option<i32>,
    pub criticality: Option<String>,
    pub customer_id: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct ListOtScansQuery {
    pub status: Option<String>,
    pub scan_type: Option<String>,
    pub customer_id: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

// ============================================================================
// Asset Operations
// ============================================================================

/// Create a new OT asset
pub async fn create_ot_asset(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateOtAssetRequest,
) -> Result<OtAsset> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let protocols = request.protocols.as_ref()
        .map(|p| serde_json::to_string(p).unwrap_or_default())
        .unwrap_or_else(|| "[]".to_string());

    let criticality = request.criticality.clone().unwrap_or_else(|| "medium".to_string());

    sqlx::query(
        r#"
        INSERT INTO ot_assets (
            id, user_id, name, asset_type, vendor, model, firmware_version,
            ip_address, mac_address, protocols, purdue_level, zone, criticality,
            first_seen, vulnerabilities, risk_score, notes, customer_id, engagement_id,
            created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', 0, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.asset_type)
    .bind(&request.vendor)
    .bind(&request.model)
    .bind(&request.firmware_version)
    .bind(&request.ip_address)
    .bind(&request.mac_address)
    .bind(&protocols)
    .bind(request.purdue_level)
    .bind(&request.zone)
    .bind(&criticality)
    .bind(&now)
    .bind(&request.notes)
    .bind(&request.customer_id)
    .bind(&request.engagement_id)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_ot_asset_by_id(pool, &id, user_id).await
}

/// Get OT asset by ID
pub async fn get_ot_asset_by_id(pool: &SqlitePool, id: &str, user_id: &str) -> Result<OtAsset> {
    let row: OtAssetRow = sqlx::query_as(
        "SELECT * FROM ot_assets WHERE id = ? AND user_id = ?"
    )
    .bind(id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(row.into_ot_asset())
}

/// List OT assets for a user
pub async fn list_ot_assets(
    pool: &SqlitePool,
    user_id: &str,
    query: &ListOtAssetsQuery,
) -> Result<Vec<OtAsset>> {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from("SELECT * FROM ot_assets WHERE user_id = ?");
    let mut bindings: Vec<String> = vec![user_id.to_string()];

    if let Some(asset_type) = &query.asset_type {
        sql.push_str(" AND asset_type = ?");
        bindings.push(asset_type.clone());
    }

    if let Some(level) = query.purdue_level {
        sql.push_str(" AND purdue_level = ?");
        bindings.push(level.to_string());
    }

    if let Some(criticality) = &query.criticality {
        sql.push_str(" AND criticality = ?");
        bindings.push(criticality.clone());
    }

    if let Some(customer_id) = &query.customer_id {
        sql.push_str(" AND customer_id = ?");
        bindings.push(customer_id.clone());
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

    // Build query dynamically
    let mut query_builder = sqlx::query_as::<_, OtAssetRow>(&sql);
    for binding in &bindings {
        query_builder = query_builder.bind(binding);
    }
    query_builder = query_builder.bind(limit).bind(offset);

    let rows: Vec<OtAssetRow> = query_builder.fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.into_ot_asset()).collect())
}

/// Update OT asset
pub async fn update_ot_asset(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    request: &UpdateOtAssetRequest,
) -> Result<OtAsset> {
    let now = Utc::now().to_rfc3339();

    // Get existing asset
    let existing = get_ot_asset_by_id(pool, id, user_id).await?;

    let name = request.name.clone().unwrap_or(existing.name);
    let asset_type = request.asset_type.clone().unwrap_or(existing.asset_type.to_string());
    let vendor = request.vendor.clone().or(existing.vendor);
    let model = request.model.clone().or(existing.model);
    let firmware_version = request.firmware_version.clone().or(existing.firmware_version);
    let ip_address = request.ip_address.clone().or(existing.ip_address);
    let mac_address = request.mac_address.clone().or(existing.mac_address);
    let protocols = request.protocols.as_ref()
        .map(|p| serde_json::to_string(p).unwrap_or_default())
        .unwrap_or_else(|| serde_json::to_string(&existing.protocols).unwrap_or_default());
    let purdue_level = request.purdue_level.or(existing.purdue_level);
    let zone = request.zone.clone().or(existing.zone);
    let criticality = request.criticality.clone().unwrap_or(existing.criticality.to_string());
    let notes = request.notes.clone().or(existing.notes);

    sqlx::query(
        r#"
        UPDATE ot_assets SET
            name = ?, asset_type = ?, vendor = ?, model = ?, firmware_version = ?,
            ip_address = ?, mac_address = ?, protocols = ?, purdue_level = ?,
            zone = ?, criticality = ?, notes = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&name)
    .bind(&asset_type)
    .bind(&vendor)
    .bind(&model)
    .bind(&firmware_version)
    .bind(&ip_address)
    .bind(&mac_address)
    .bind(&protocols)
    .bind(purdue_level)
    .bind(&zone)
    .bind(&criticality)
    .bind(&notes)
    .bind(&now)
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;

    get_ot_asset_by_id(pool, id, user_id).await
}

/// Delete OT asset
pub async fn delete_ot_asset(pool: &SqlitePool, id: &str, user_id: &str) -> Result<()> {
    // First delete related protocols
    sqlx::query("DELETE FROM ot_protocols WHERE asset_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM ot_assets WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Scan Operations
// ============================================================================

/// Create a new OT scan
pub async fn create_ot_scan(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateOtScanRequest,
) -> Result<OtScan> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let protocols_enabled = request.protocols_enabled.as_ref()
        .map(|p| serde_json::to_string(p).unwrap_or_default())
        .unwrap_or_else(|| "[]".to_string());

    sqlx::query(
        r#"
        INSERT INTO ot_scans (
            id, user_id, name, scan_type, target_range, protocols_enabled,
            status, assets_discovered, vulnerabilities_found,
            customer_id, engagement_id, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, 0, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.scan_type)
    .bind(&request.target_range)
    .bind(&protocols_enabled)
    .bind(&request.customer_id)
    .bind(&request.engagement_id)
    .bind(&now)
    .execute(pool)
    .await?;

    get_ot_scan_by_id(pool, &id, user_id).await
}

/// Get OT scan by ID
pub async fn get_ot_scan_by_id(pool: &SqlitePool, id: &str, user_id: &str) -> Result<OtScan> {
    let row: OtScanRow = sqlx::query_as(
        "SELECT * FROM ot_scans WHERE id = ? AND user_id = ?"
    )
    .bind(id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(row.into_ot_scan())
}

/// List OT scans for a user
pub async fn list_ot_scans(
    pool: &SqlitePool,
    user_id: &str,
    query: &ListOtScansQuery,
) -> Result<Vec<OtScan>> {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from("SELECT * FROM ot_scans WHERE user_id = ?");
    let mut bindings: Vec<String> = vec![user_id.to_string()];

    if let Some(status) = &query.status {
        sql.push_str(" AND status = ?");
        bindings.push(status.clone());
    }

    if let Some(scan_type) = &query.scan_type {
        sql.push_str(" AND scan_type = ?");
        bindings.push(scan_type.clone());
    }

    if let Some(customer_id) = &query.customer_id {
        sql.push_str(" AND customer_id = ?");
        bindings.push(customer_id.clone());
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

    let mut query_builder = sqlx::query_as::<_, OtScanRow>(&sql);
    for binding in &bindings {
        query_builder = query_builder.bind(binding);
    }
    query_builder = query_builder.bind(limit).bind(offset);

    let rows: Vec<OtScanRow> = query_builder.fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.into_ot_scan()).collect())
}

/// Update OT scan status
pub async fn update_ot_scan_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    error_message: Option<&str>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    match status {
        "running" => {
            sqlx::query("UPDATE ot_scans SET status = ?, started_at = ? WHERE id = ?")
                .bind(status)
                .bind(&now)
                .bind(id)
                .execute(pool)
                .await?;
        }
        "completed" | "failed" | "cancelled" => {
            sqlx::query("UPDATE ot_scans SET status = ?, completed_at = ? WHERE id = ?")
                .bind(status)
                .bind(&now)
                .bind(id)
                .execute(pool)
                .await?;
        }
        _ => {
            sqlx::query("UPDATE ot_scans SET status = ? WHERE id = ?")
                .bind(status)
                .bind(id)
                .execute(pool)
                .await?;
        }
    }

    Ok(())
}

/// Update OT scan results
pub async fn update_ot_scan_results(
    pool: &SqlitePool,
    id: &str,
    assets_discovered: i32,
    vulnerabilities_found: i32,
) -> Result<()> {
    sqlx::query(
        "UPDATE ot_scans SET assets_discovered = ?, vulnerabilities_found = ? WHERE id = ?"
    )
    .bind(assets_discovered)
    .bind(vulnerabilities_found)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Dashboard Operations
// ============================================================================

/// Get OT dashboard statistics
pub async fn get_ot_dashboard_stats(pool: &SqlitePool, user_id: &str) -> Result<OtDashboardStats> {
    // Total assets
    let total: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ot_assets WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Assets by type
    let assets_by_type: Vec<(String, i64)> = sqlx::query_as(
        "SELECT asset_type, COUNT(*) FROM ot_assets WHERE user_id = ? GROUP BY asset_type"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    // Assets by criticality
    let assets_by_criticality: Vec<(String, i64)> = sqlx::query_as(
        "SELECT criticality, COUNT(*) FROM ot_assets WHERE user_id = ? GROUP BY criticality"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    // Assets by Purdue level
    let assets_by_purdue: Vec<(Option<i32>, i64)> = sqlx::query_as(
        "SELECT purdue_level, COUNT(*) FROM ot_assets WHERE user_id = ? GROUP BY purdue_level"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    // Recent scans
    let recent_scans = list_ot_scans(pool, user_id, &ListOtScansQuery {
        status: None,
        scan_type: None,
        customer_id: None,
        limit: Some(5),
        offset: Some(0),
    }).await?;

    Ok(OtDashboardStats {
        total_assets: total.0 as i32,
        assets_by_type: assets_by_type.into_iter()
            .map(|(t, c)| TypeCount { asset_type: t, count: c as i32 })
            .collect(),
        assets_by_criticality: assets_by_criticality.into_iter()
            .map(|(c, count)| CriticalityCount { criticality: c, count: count as i32 })
            .collect(),
        assets_by_purdue_level: assets_by_purdue.into_iter()
            .map(|(level, count)| {
                let l = level.unwrap_or(-1);
                let name = match l {
                    0 => "Process".to_string(),
                    1 => "Basic Control".to_string(),
                    2 => "Area Control".to_string(),
                    3 => "Site Operations".to_string(),
                    4 => "Business".to_string(),
                    5 => "Enterprise".to_string(),
                    _ => "Unclassified".to_string(),
                };
                PurdueCount { level: l, name, count: count as i32 }
            })
            .collect(),
        total_vulnerabilities: 0, // TODO: Calculate from assets
        vulnerabilities_by_severity: Vec::new(),
        recent_scans,
        protocols_detected: Vec::new(), // TODO: Calculate from assets
    })
}
