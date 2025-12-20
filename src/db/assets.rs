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

// ============================================================================
// Asset Tags Functions
// ============================================================================

/// Create a new asset tag
pub async fn create_asset_tag(
    pool: &SqlitePool,
    user_id: &str,
    request: &models::CreateAssetTagRequest,
) -> Result<models::AssetTag> {
    let now = Utc::now();
    let id = Uuid::new_v4().to_string();

    let tag = sqlx::query_as::<_, models::AssetTag>(
        r#"
        INSERT INTO asset_tags (id, user_id, name, color, category, description, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.color)
    .bind(&request.category)
    .bind(&request.description)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(tag)
}

/// Get all asset tags for a user
pub async fn get_user_asset_tags(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<models::AssetTag>> {
    let tags = sqlx::query_as::<_, models::AssetTag>(
        "SELECT * FROM asset_tags WHERE user_id = ?1 ORDER BY category, name",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(tags)
}

/// Get all asset tags with usage counts
pub async fn get_user_asset_tags_with_counts(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<models::AssetTagWithCount>> {
    let tags_raw: Vec<(String, String, String, String, String, Option<String>, DateTime<Utc>, DateTime<Utc>, i64)> = sqlx::query_as(
        r#"
        SELECT
            at.id,
            at.user_id,
            at.name,
            at.color,
            at.category,
            at.description,
            at.created_at,
            at.updated_at,
            COUNT(atm.asset_id) as asset_count
        FROM asset_tags at
        LEFT JOIN asset_tag_mappings atm ON at.id = atm.tag_id
        WHERE at.user_id = ?1
        GROUP BY at.id
        ORDER BY at.category, at.name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let tags_with_counts = tags_raw
        .into_iter()
        .map(|(id, user_id, name, color, category, description, created_at, updated_at, asset_count)| {
            models::AssetTagWithCount {
                tag: models::AssetTag {
                    id,
                    user_id,
                    name,
                    color,
                    category,
                    description,
                    created_at,
                    updated_at,
                },
                asset_count,
            }
        })
        .collect();

    Ok(tags_with_counts)
}

/// Get asset tag by ID
pub async fn get_asset_tag_by_id(
    pool: &SqlitePool,
    tag_id: &str,
    user_id: &str,
) -> Result<Option<models::AssetTag>> {
    let tag = sqlx::query_as::<_, models::AssetTag>(
        "SELECT * FROM asset_tags WHERE id = ?1 AND user_id = ?2",
    )
    .bind(tag_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(tag)
}

/// Update an asset tag
pub async fn update_asset_tag(
    pool: &SqlitePool,
    tag_id: &str,
    user_id: &str,
    request: &models::UpdateAssetTagRequest,
) -> Result<models::AssetTag> {
    let now = Utc::now();

    if let Some(name) = &request.name {
        sqlx::query("UPDATE asset_tags SET name = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(name)
            .bind(now)
            .bind(tag_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    if let Some(color) = &request.color {
        sqlx::query("UPDATE asset_tags SET color = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(color)
            .bind(now)
            .bind(tag_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    if let Some(category) = &request.category {
        sqlx::query("UPDATE asset_tags SET category = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(category)
            .bind(now)
            .bind(tag_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    if let Some(description) = &request.description {
        sqlx::query("UPDATE asset_tags SET description = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(description)
            .bind(now)
            .bind(tag_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    let tag = sqlx::query_as::<_, models::AssetTag>(
        "SELECT * FROM asset_tags WHERE id = ?1 AND user_id = ?2",
    )
    .bind(tag_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(tag)
}

/// Delete an asset tag
pub async fn delete_asset_tag(
    pool: &SqlitePool,
    tag_id: &str,
    user_id: &str,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM asset_tags WHERE id = ?1 AND user_id = ?2")
        .bind(tag_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Add tags to an asset
pub async fn add_tags_to_asset(
    pool: &SqlitePool,
    asset_id: &str,
    tag_ids: &[String],
    user_id: &str,
) -> Result<()> {
    let now = Utc::now();

    // First verify the asset belongs to the user
    let asset = get_asset_by_id(pool, asset_id, user_id).await?;
    if asset.is_none() {
        return Err(anyhow::anyhow!("Asset not found"));
    }

    for tag_id in tag_ids {
        // Verify tag belongs to user
        let tag = get_asset_tag_by_id(pool, tag_id, user_id).await?;
        if tag.is_none() {
            continue; // Skip tags that don't exist or don't belong to user
        }

        // Insert mapping (ignore if already exists)
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO asset_tag_mappings (asset_id, tag_id, created_at)
            VALUES (?1, ?2, ?3)
            "#,
        )
        .bind(asset_id)
        .bind(tag_id)
        .bind(now)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Remove a tag from an asset
pub async fn remove_tag_from_asset(
    pool: &SqlitePool,
    asset_id: &str,
    tag_id: &str,
    user_id: &str,
) -> Result<bool> {
    // First verify the asset belongs to the user
    let asset = get_asset_by_id(pool, asset_id, user_id).await?;
    if asset.is_none() {
        return Ok(false);
    }

    let result = sqlx::query("DELETE FROM asset_tag_mappings WHERE asset_id = ?1 AND tag_id = ?2")
        .bind(asset_id)
        .bind(tag_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Get all tags for an asset
pub async fn get_asset_tags(
    pool: &SqlitePool,
    asset_id: &str,
) -> Result<Vec<models::AssetTag>> {
    let tags = sqlx::query_as::<_, models::AssetTag>(
        r#"
        SELECT at.*
        FROM asset_tags at
        INNER JOIN asset_tag_mappings atm ON at.id = atm.tag_id
        WHERE atm.asset_id = ?1
        ORDER BY at.category, at.name
        "#,
    )
    .bind(asset_id)
    .fetch_all(pool)
    .await?;

    Ok(tags)
}

/// Get asset detail with tags
pub async fn get_asset_detail_with_tags(
    pool: &SqlitePool,
    asset_id: &str,
    user_id: &str,
) -> Result<Option<models::AssetDetailWithTags>> {
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

        // Get tags
        let asset_tags = get_asset_tags(pool, asset_id).await?;

        Ok(Some(models::AssetDetailWithTags {
            asset,
            ports,
            history,
            asset_tags,
        }))
    } else {
        Ok(None)
    }
}

/// Get assets filtered by tag IDs
pub async fn get_assets_by_tags(
    pool: &SqlitePool,
    user_id: &str,
    tag_ids: &[String],
    status: Option<&str>,
) -> Result<Vec<models::Asset>> {
    if tag_ids.is_empty() {
        return get_user_assets(pool, user_id, status, None, None).await;
    }

    // Build query with tag filtering
    let placeholders: Vec<String> = (0..tag_ids.len()).map(|i| format!("?{}", i + 3)).collect();
    let placeholders_str = placeholders.join(", ");

    let mut query = format!(
        r#"
        SELECT DISTINCT a.*
        FROM assets a
        INNER JOIN asset_tag_mappings atm ON a.id = atm.asset_id
        WHERE a.user_id = ?1 AND atm.tag_id IN ({})
        "#,
        placeholders_str
    );

    if status.is_some() {
        query.push_str(" AND a.status = ?2");
    }

    query.push_str(" ORDER BY a.last_seen DESC");

    let mut q = sqlx::query_as::<_, models::Asset>(&query);
    q = q.bind(user_id);

    if let Some(s) = status {
        q = q.bind(s);
    }

    for tag_id in tag_ids {
        q = q.bind(tag_id);
    }

    let assets = q.fetch_all(pool).await?;
    Ok(assets)
}

// ============================================================================
// Asset Groups Functions
// ============================================================================

/// Create a new asset group
pub async fn create_asset_group(
    pool: &SqlitePool,
    user_id: &str,
    request: &models::CreateAssetGroupRequest,
) -> Result<models::AssetGroup> {
    let now = Utc::now();
    let id = Uuid::new_v4().to_string();

    let group = sqlx::query_as::<_, models::AssetGroup>(
        r#"
        INSERT INTO asset_groups (id, user_id, name, description, color, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&request.color)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(group)
}

/// Get all asset groups for a user
pub async fn get_user_asset_groups(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<models::AssetGroup>> {
    let groups = sqlx::query_as::<_, models::AssetGroup>(
        "SELECT * FROM asset_groups WHERE user_id = ?1 ORDER BY name",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(groups)
}

/// Get all asset groups with member counts
pub async fn get_user_asset_groups_with_counts(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<models::AssetGroupWithCount>> {
    let groups_raw: Vec<(String, String, String, Option<String>, String, DateTime<Utc>, DateTime<Utc>, i64)> = sqlx::query_as(
        r#"
        SELECT
            ag.id,
            ag.user_id,
            ag.name,
            ag.description,
            ag.color,
            ag.created_at,
            ag.updated_at,
            COUNT(agm.asset_id) as asset_count
        FROM asset_groups ag
        LEFT JOIN asset_group_members agm ON ag.id = agm.asset_group_id
        WHERE ag.user_id = ?1
        GROUP BY ag.id
        ORDER BY ag.name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let groups_with_counts = groups_raw
        .into_iter()
        .map(|(id, user_id, name, description, color, created_at, updated_at, asset_count)| {
            models::AssetGroupWithCount {
                group: models::AssetGroup {
                    id,
                    user_id,
                    name,
                    description,
                    color,
                    created_at,
                    updated_at,
                },
                asset_count,
            }
        })
        .collect();

    Ok(groups_with_counts)
}

/// Get asset group by ID
pub async fn get_asset_group_by_id(
    pool: &SqlitePool,
    group_id: &str,
    user_id: &str,
) -> Result<Option<models::AssetGroup>> {
    let group = sqlx::query_as::<_, models::AssetGroup>(
        "SELECT * FROM asset_groups WHERE id = ?1 AND user_id = ?2",
    )
    .bind(group_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(group)
}

/// Update an asset group
pub async fn update_asset_group(
    pool: &SqlitePool,
    group_id: &str,
    user_id: &str,
    request: &models::UpdateAssetGroupRequest,
) -> Result<models::AssetGroup> {
    let now = Utc::now();

    if let Some(name) = &request.name {
        sqlx::query("UPDATE asset_groups SET name = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(name)
            .bind(now)
            .bind(group_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    if let Some(description) = &request.description {
        sqlx::query("UPDATE asset_groups SET description = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(description)
            .bind(now)
            .bind(group_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    if let Some(color) = &request.color {
        sqlx::query("UPDATE asset_groups SET color = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(color)
            .bind(now)
            .bind(group_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    let group = sqlx::query_as::<_, models::AssetGroup>(
        "SELECT * FROM asset_groups WHERE id = ?1 AND user_id = ?2",
    )
    .bind(group_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(group)
}

/// Delete an asset group
pub async fn delete_asset_group(
    pool: &SqlitePool,
    group_id: &str,
    user_id: &str,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM asset_groups WHERE id = ?1 AND user_id = ?2")
        .bind(group_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Add assets to a group
pub async fn add_assets_to_group(
    pool: &SqlitePool,
    group_id: &str,
    asset_ids: &[String],
    user_id: &str,
) -> Result<()> {
    let now = Utc::now();

    // First verify the group belongs to the user
    let group = get_asset_group_by_id(pool, group_id, user_id).await?;
    if group.is_none() {
        return Err(anyhow::anyhow!("Asset group not found"));
    }

    for asset_id in asset_ids {
        // Verify asset belongs to user
        let asset = get_asset_by_id(pool, asset_id, user_id).await?;
        if asset.is_none() {
            continue; // Skip assets that don't exist or don't belong to user
        }

        // Insert mapping (ignore if already exists)
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO asset_group_members (asset_group_id, asset_id, added_at)
            VALUES (?1, ?2, ?3)
            "#,
        )
        .bind(group_id)
        .bind(asset_id)
        .bind(now)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Remove an asset from a group
pub async fn remove_asset_from_group(
    pool: &SqlitePool,
    group_id: &str,
    asset_id: &str,
    user_id: &str,
) -> Result<bool> {
    // First verify the group belongs to the user
    let group = get_asset_group_by_id(pool, group_id, user_id).await?;
    if group.is_none() {
        return Ok(false);
    }

    let result = sqlx::query("DELETE FROM asset_group_members WHERE asset_group_id = ?1 AND asset_id = ?2")
        .bind(group_id)
        .bind(asset_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Get all assets in a group
pub async fn get_group_assets(
    pool: &SqlitePool,
    group_id: &str,
    user_id: &str,
) -> Result<Vec<models::Asset>> {
    // First verify the group belongs to the user
    let group = get_asset_group_by_id(pool, group_id, user_id).await?;
    if group.is_none() {
        return Ok(vec![]);
    }

    let assets = sqlx::query_as::<_, models::Asset>(
        r#"
        SELECT a.*
        FROM assets a
        INNER JOIN asset_group_members agm ON a.id = agm.asset_id
        WHERE agm.asset_group_id = ?1
        ORDER BY a.ip_address
        "#,
    )
    .bind(group_id)
    .fetch_all(pool)
    .await?;

    Ok(assets)
}

/// Get group with its member assets
pub async fn get_asset_group_with_members(
    pool: &SqlitePool,
    group_id: &str,
    user_id: &str,
) -> Result<Option<models::AssetGroupWithMembers>> {
    let group = get_asset_group_by_id(pool, group_id, user_id).await?;

    if let Some(group) = group {
        let assets = get_group_assets(pool, group_id, user_id).await?;

        Ok(Some(models::AssetGroupWithMembers {
            group,
            assets,
        }))
    } else {
        Ok(None)
    }
}

/// Get all groups for an asset
pub async fn get_asset_groups(
    pool: &SqlitePool,
    asset_id: &str,
) -> Result<Vec<models::AssetGroup>> {
    let groups = sqlx::query_as::<_, models::AssetGroup>(
        r#"
        SELECT ag.*
        FROM asset_groups ag
        INNER JOIN asset_group_members agm ON ag.id = agm.asset_group_id
        WHERE agm.asset_id = ?1
        ORDER BY ag.name
        "#,
    )
    .bind(asset_id)
    .fetch_all(pool)
    .await?;

    Ok(groups)
}

/// Get asset detail with tags and groups
pub async fn get_asset_detail_full(
    pool: &SqlitePool,
    asset_id: &str,
    user_id: &str,
) -> Result<Option<models::AssetDetailFull>> {
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

        // Get tags
        let asset_tags = get_asset_tags(pool, asset_id).await?;

        // Get groups
        let asset_groups = get_asset_groups(pool, asset_id).await?;

        Ok(Some(models::AssetDetailFull {
            asset,
            ports,
            history,
            asset_tags,
            asset_groups,
        }))
    } else {
        Ok(None)
    }
}

/// Get assets filtered by group ID
pub async fn get_assets_by_group(
    pool: &SqlitePool,
    user_id: &str,
    group_id: &str,
    status: Option<&str>,
) -> Result<Vec<models::Asset>> {
    let mut query = String::from(
        r#"
        SELECT DISTINCT a.*
        FROM assets a
        INNER JOIN asset_group_members agm ON a.id = agm.asset_id
        WHERE a.user_id = ?1 AND agm.asset_group_id = ?2
        "#,
    );

    if status.is_some() {
        query.push_str(" AND a.status = ?3");
    }

    query.push_str(" ORDER BY a.last_seen DESC");

    let mut q = sqlx::query_as::<_, models::Asset>(&query);
    q = q.bind(user_id);
    q = q.bind(group_id);

    if let Some(s) = status {
        q = q.bind(s);
    }

    let assets = q.fetch_all(pool).await?;
    Ok(assets)
}

// ============================================================================
// Assets with Tags Functions
// ============================================================================

/// Get all assets for a user with their tags (for list view with badges)
pub async fn get_user_assets_with_tags(
    pool: &SqlitePool,
    user_id: &str,
    status: Option<&str>,
    tag_ids: Option<&[String]>,
    group_id: Option<&str>,
) -> Result<Vec<models::AssetWithTags>> {
    // First, get the assets based on filters
    let assets = if let Some(gid) = group_id {
        get_assets_by_group(pool, user_id, gid, status).await?
    } else if let Some(tids) = tag_ids {
        if tids.is_empty() {
            get_user_assets(pool, user_id, status, None, None).await?
        } else {
            get_assets_by_tags(pool, user_id, tids, status).await?
        }
    } else {
        get_user_assets(pool, user_id, status, None, None).await?
    };

    // Now fetch tags for each asset
    let mut assets_with_tags = Vec::with_capacity(assets.len());
    for asset in assets {
        let tags = get_asset_tags(pool, &asset.id).await?;
        assets_with_tags.push(models::AssetWithTags {
            asset,
            asset_tags: tags,
        });
    }

    Ok(assets_with_tags)
}

/// Bulk add assets to a group
pub async fn bulk_add_assets_to_group(
    pool: &SqlitePool,
    group_id: &str,
    asset_ids: &[String],
    user_id: &str,
) -> Result<usize> {
    let now = Utc::now();

    // First verify the group belongs to the user
    let group = get_asset_group_by_id(pool, group_id, user_id).await?;
    if group.is_none() {
        return Err(anyhow::anyhow!("Asset group not found"));
    }

    let mut added_count = 0;

    for asset_id in asset_ids {
        // Verify asset belongs to user
        let asset = get_asset_by_id(pool, asset_id, user_id).await?;
        if asset.is_none() {
            continue; // Skip assets that don't exist or don't belong to user
        }

        // Insert mapping (ignore if already exists)
        let result = sqlx::query(
            r#"
            INSERT OR IGNORE INTO asset_group_members (asset_group_id, asset_id, added_at)
            VALUES (?1, ?2, ?3)
            "#,
        )
        .bind(group_id)
        .bind(asset_id)
        .bind(now)
        .execute(pool)
        .await?;

        if result.rows_affected() > 0 {
            added_count += 1;
        }
    }

    Ok(added_count)
}
