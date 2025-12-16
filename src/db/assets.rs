use sqlx::SqlitePool;
use anyhow::Result;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::db::models;

// ============================================================================
// Asset Inventory Management Functions
// ============================================================================

/// Create or update an asset from scan results (upsert)
pub async fn upsert_asset(
    pool: &SqlitePool,
    user_id: &str,
    ip_address: &str,
    hostname: Option<&str>,
    mac_address: Option<&str>,
    os_family: Option<&str>,
    os_version: Option<&str>,
    scan_id: &str,
) -> Result<models::Asset> {
    let now = Utc::now();

    // Try to get existing asset
    let existing: Option<models::Asset> = sqlx::query_as(
        "SELECT * FROM assets WHERE user_id = ?1 AND ip_address = ?2",
    )
    .bind(user_id)
    .bind(ip_address)
    .fetch_optional(pool)
    .await?;

    if let Some(mut asset) = existing {
        // Track changes for history
        let mut changes = serde_json::Map::new();

        if let Some(h) = hostname {
            if asset.hostname.as_deref() != Some(h) {
                changes.insert("hostname".to_string(), serde_json::json!({
                    "from": asset.hostname,
                    "to": h
                }));
                asset.hostname = Some(h.to_string());
            }
        }

        if let Some(m) = mac_address {
            if asset.mac_address.as_deref() != Some(m) {
                changes.insert("mac_address".to_string(), serde_json::json!({
                    "from": asset.mac_address,
                    "to": m
                }));
                asset.mac_address = Some(m.to_string());
            }
        }

        if let Some(os_f) = os_family {
            if asset.os_family.as_deref() != Some(os_f) {
                changes.insert("os_family".to_string(), serde_json::json!({
                    "from": asset.os_family,
                    "to": os_f
                }));
                asset.os_family = Some(os_f.to_string());
            }
        }

        if let Some(os_v) = os_version {
            if asset.os_version.as_deref() != Some(os_v) {
                changes.insert("os_version".to_string(), serde_json::json!({
                    "from": asset.os_version,
                    "to": os_v
                }));
                asset.os_version = Some(os_v.to_string());
            }
        }

        // Update asset
        asset.last_seen = now;
        asset.scan_count += 1;

        sqlx::query(
            r#"
            UPDATE assets
            SET hostname = ?1, mac_address = ?2, last_seen = ?3, scan_count = ?4,
                os_family = ?5, os_version = ?6
            WHERE id = ?7
            "#,
        )
        .bind(&asset.hostname)
        .bind(&asset.mac_address)
        .bind(now)
        .bind(asset.scan_count)
        .bind(&asset.os_family)
        .bind(&asset.os_version)
        .bind(&asset.id)
        .execute(pool)
        .await?;

        // Record changes if any
        if !changes.is_empty() {
            record_asset_history(pool, &asset.id, scan_id, &changes).await?;
        }

        Ok(asset)
    } else {
        // Create new asset
        let id = Uuid::new_v4().to_string();
        let tags_json = "[]";

        let asset = sqlx::query_as::<_, models::Asset>(
            r#"
            INSERT INTO assets (id, user_id, ip_address, hostname, mac_address, first_seen, last_seen, scan_count, os_family, os_version, status, tags)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(ip_address)
        .bind(hostname)
        .bind(mac_address)
        .bind(now)
        .bind(now)
        .bind(1)
        .bind(os_family)
        .bind(os_version)
        .bind("active")
        .bind(tags_json)
        .fetch_one(pool)
        .await?;

        // Record creation in history
        let mut changes = serde_json::Map::new();
        changes.insert("created".to_string(), serde_json::json!(true));
        record_asset_history(pool, &asset.id, scan_id, &changes).await?;

        Ok(asset)
    }
}

/// Upsert an asset port
pub async fn upsert_asset_port(
    pool: &SqlitePool,
    asset_id: &str,
    port: i32,
    protocol: &str,
    service_name: Option<&str>,
    service_version: Option<&str>,
    state: &str,
) -> Result<models::AssetPort> {
    let now = Utc::now();

    // Try to get existing port
    let existing: Option<models::AssetPort> = sqlx::query_as(
        "SELECT * FROM asset_ports WHERE asset_id = ?1 AND port = ?2 AND protocol = ?3",
    )
    .bind(asset_id)
    .bind(port)
    .bind(protocol)
    .fetch_optional(pool)
    .await?;

    if let Some(mut asset_port) = existing {
        // Update port
        asset_port.service_name = service_name.map(|s| s.to_string());
        asset_port.service_version = service_version.map(|s| s.to_string());
        asset_port.last_seen = now;
        asset_port.current_state = state.to_string();

        sqlx::query(
            r#"
            UPDATE asset_ports
            SET service_name = ?1, service_version = ?2, last_seen = ?3, current_state = ?4
            WHERE id = ?5
            "#,
        )
        .bind(&asset_port.service_name)
        .bind(&asset_port.service_version)
        .bind(now)
        .bind(state)
        .bind(&asset_port.id)
        .execute(pool)
        .await?;

        Ok(asset_port)
    } else {
        // Create new port
        let id = Uuid::new_v4().to_string();

        let asset_port = sqlx::query_as::<_, models::AssetPort>(
            r#"
            INSERT INTO asset_ports (id, asset_id, port, protocol, service_name, service_version, first_seen, last_seen, current_state)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(asset_id)
        .bind(port)
        .bind(protocol)
        .bind(service_name)
        .bind(service_version)
        .bind(now)
        .bind(now)
        .bind(state)
        .fetch_one(pool)
        .await?;

        Ok(asset_port)
    }
}

/// Record asset change history
async fn record_asset_history(
    pool: &SqlitePool,
    asset_id: &str,
    scan_id: &str,
    changes: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let changes_json = serde_json::to_string(changes)?;

    sqlx::query(
        r#"
        INSERT INTO asset_history (id, asset_id, scan_id, changes, recorded_at)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
    )
    .bind(&id)
    .bind(asset_id)
    .bind(scan_id)
    .bind(&changes_json)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get all assets for a user with optional filtering
pub async fn get_user_assets(
    pool: &SqlitePool,
    user_id: &str,
    status: Option<&str>,
    tags: Option<&[String]>,
    days_inactive: Option<i64>,
) -> Result<Vec<models::Asset>> {
    let mut query = String::from("SELECT * FROM assets WHERE user_id = ?1");
    let mut params: Vec<String> = vec![user_id.to_string()];

    if let Some(s) = status {
        query.push_str(" AND status = ?");
        params.push(s.to_string());
    }

    if let Some(tag_list) = tags {
        for tag in tag_list {
            query.push_str(" AND tags LIKE ?");
            params.push(format!("%\"{}%", tag));
        }
    }

    if let Some(days) = days_inactive {
        let cutoff_date = Utc::now() - chrono::Duration::days(days);
        query.push_str(" AND last_seen < ?");
        params.push(cutoff_date.to_rfc3339());
    }

    query.push_str(" ORDER BY last_seen DESC");

    let mut q = sqlx::query_as::<_, models::Asset>(&query);
    for param in &params {
        q = q.bind(param);
    }

    let assets = q.fetch_all(pool).await?;
    Ok(assets)
}

/// Get asset by ID
pub async fn get_asset_by_id(
    pool: &SqlitePool,
    asset_id: &str,
    user_id: &str,
) -> Result<Option<models::Asset>> {
    let asset = sqlx::query_as::<_, models::Asset>(
        "SELECT * FROM assets WHERE id = ?1 AND user_id = ?2",
    )
    .bind(asset_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(asset)
}

/// Get asset detail with ports and history
pub async fn get_asset_detail(
    pool: &SqlitePool,
    asset_id: &str,
    user_id: &str,
) -> Result<Option<models::AssetDetail>> {
    let asset = get_asset_by_id(pool, asset_id, user_id).await?;

    if let Some(asset) = asset {
        // Get ports
        let ports = sqlx::query_as::<_, models::AssetPort>(
            "SELECT * FROM asset_ports WHERE asset_id = ?1 ORDER BY port ASC",
        )
        .bind(asset_id)
        .fetch_all(pool)
        .await?;

        // Get history with scan names
        let history_raw: Vec<(String, String, String, String, DateTime<Utc>)> = sqlx::query_as(
            r#"
            SELECT
                ah.id,
                ah.scan_id,
                sr.name as scan_name,
                ah.changes,
                ah.recorded_at
            FROM asset_history ah
            JOIN scan_results sr ON ah.scan_id = sr.id
            WHERE ah.asset_id = ?1
            ORDER BY ah.recorded_at DESC
            LIMIT 50
            "#,
        )
        .bind(asset_id)
        .fetch_all(pool)
        .await?;

        let history: Vec<models::AssetHistoryWithScan> = history_raw
            .into_iter()
            .map(|(id, scan_id, scan_name, changes_str, recorded_at)| {
                let changes = serde_json::from_str::<serde_json::Value>(&changes_str)
                    .unwrap_or(serde_json::json!({}));
                models::AssetHistoryWithScan {
                    id,
                    scan_id,
                    scan_name,
                    changes,
                    recorded_at,
                }
            })
            .collect();

        Ok(Some(models::AssetDetail {
            asset,
            ports,
            history,
        }))
    } else {
        Ok(None)
    }
}

/// Update asset metadata (status, tags, notes)
pub async fn update_asset(
    pool: &SqlitePool,
    asset_id: &str,
    user_id: &str,
    request: &models::UpdateAssetRequest,
) -> Result<models::Asset> {
    if let Some(status) = &request.status {
        sqlx::query("UPDATE assets SET status = ?1 WHERE id = ?2 AND user_id = ?3")
            .bind(status)
            .bind(asset_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    if let Some(tags) = &request.tags {
        let tags_json = serde_json::to_string(tags)?;
        sqlx::query("UPDATE assets SET tags = ?1 WHERE id = ?2 AND user_id = ?3")
            .bind(&tags_json)
            .bind(asset_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    if let Some(notes) = &request.notes {
        sqlx::query("UPDATE assets SET notes = ?1 WHERE id = ?2 AND user_id = ?3")
            .bind(notes)
            .bind(asset_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    let asset = sqlx::query_as::<_, models::Asset>(
        "SELECT * FROM assets WHERE id = ?1 AND user_id = ?2",
    )
    .bind(asset_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(asset)
}

/// Delete an asset
pub async fn delete_asset(
    pool: &SqlitePool,
    asset_id: &str,
    user_id: &str,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM assets WHERE id = ?1 AND user_id = ?2")
        .bind(asset_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Get asset history for a specific asset
pub async fn get_asset_history(
    pool: &SqlitePool,
    asset_id: &str,
    user_id: &str,
) -> Result<Vec<models::AssetHistoryWithScan>> {
    // First verify user owns this asset
    let asset = get_asset_by_id(pool, asset_id, user_id).await?;
    if asset.is_none() {
        return Ok(vec![]);
    }

    let history_raw: Vec<(String, String, String, String, DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT
            ah.id,
            ah.scan_id,
            sr.name as scan_name,
            ah.changes,
            ah.recorded_at
        FROM asset_history ah
        JOIN scan_results sr ON ah.scan_id = sr.id
        WHERE ah.asset_id = ?1
        ORDER BY ah.recorded_at DESC
        "#,
    )
    .bind(asset_id)
    .fetch_all(pool)
    .await?;

    let history: Vec<models::AssetHistoryWithScan> = history_raw
        .into_iter()
        .map(|(id, scan_id, scan_name, changes_str, recorded_at)| {
            let changes = serde_json::from_str::<serde_json::Value>(&changes_str)
                .unwrap_or(serde_json::json!({}));
            models::AssetHistoryWithScan {
                id,
                scan_id,
                scan_name,
                changes,
                recorded_at,
            }
        })
        .collect();

    Ok(history)
}
