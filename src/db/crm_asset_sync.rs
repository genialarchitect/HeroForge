//! CRM Asset Sync Module
//!
//! Provides automatic synchronization of discovered assets from recon scans
//! to CRM customer records. When scans are associated with a customer/engagement,
//! discovered assets (domains, IPs, subdomains, services) are automatically
//! linked to that customer's asset inventory.

use sqlx::SqlitePool;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Types of assets that can be discovered and linked to CRM
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssetType {
    Domain,
    Subdomain,
    IpAddress,
    Service,
    Port,
    Certificate,
    EmailAddress,
    Repository,
    DnsRecord,
    Technology,
    Endpoint,
    ApiEndpoint,
    Credential,
    Secret,
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetType::Domain => write!(f, "domain"),
            AssetType::Subdomain => write!(f, "subdomain"),
            AssetType::IpAddress => write!(f, "ip_address"),
            AssetType::Service => write!(f, "service"),
            AssetType::Port => write!(f, "port"),
            AssetType::Certificate => write!(f, "certificate"),
            AssetType::EmailAddress => write!(f, "email_address"),
            AssetType::Repository => write!(f, "repository"),
            AssetType::DnsRecord => write!(f, "dns_record"),
            AssetType::Technology => write!(f, "technology"),
            AssetType::Endpoint => write!(f, "endpoint"),
            AssetType::ApiEndpoint => write!(f, "api_endpoint"),
            AssetType::Credential => write!(f, "credential"),
            AssetType::Secret => write!(f, "secret"),
        }
    }
}

impl AssetType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "domain" => Some(AssetType::Domain),
            "subdomain" => Some(AssetType::Subdomain),
            "ip_address" => Some(AssetType::IpAddress),
            "service" => Some(AssetType::Service),
            "port" => Some(AssetType::Port),
            "certificate" => Some(AssetType::Certificate),
            "email_address" => Some(AssetType::EmailAddress),
            "repository" => Some(AssetType::Repository),
            "dns_record" => Some(AssetType::DnsRecord),
            "technology" => Some(AssetType::Technology),
            "endpoint" => Some(AssetType::Endpoint),
            "api_endpoint" => Some(AssetType::ApiEndpoint),
            "credential" => Some(AssetType::Credential),
            "secret" => Some(AssetType::Secret),
            _ => None,
        }
    }
}

/// A discovered asset from a recon scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAsset {
    pub asset_type: AssetType,
    pub value: String,
    pub source: String,
    pub source_scan_id: Option<String>,
    pub source_scan_type: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// A CRM discovered asset record from the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrmDiscoveredAsset {
    pub id: String,
    pub customer_id: String,
    pub engagement_id: Option<String>,
    pub asset_type: String,
    pub value: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub source: String,
    pub source_scan_id: Option<String>,
    pub source_scan_type: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub is_in_scope: bool,
    pub is_verified: bool,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Result of syncing discovered assets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub total_assets: usize,
    pub new_assets: usize,
    pub updated_assets: usize,
    pub failed_assets: usize,
    pub errors: Vec<String>,
}

/// Request to manually add a discovered asset
#[derive(Debug, Clone, Deserialize)]
pub struct CreateDiscoveredAssetRequest {
    pub asset_type: String,
    pub value: String,
    pub engagement_id: Option<String>,
    pub source: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub is_in_scope: Option<bool>,
    pub notes: Option<String>,
}

/// Request to update a discovered asset
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateDiscoveredAssetRequest {
    pub is_in_scope: Option<bool>,
    pub is_verified: Option<bool>,
    pub notes: Option<String>,
    pub engagement_id: Option<String>,
}

/// Sync discovered assets from a scan to a customer's CRM record
///
/// This function is called when a scan with a customer_id completes.
/// It creates or updates discovered asset records for the customer.
pub async fn sync_discovered_assets(
    pool: &SqlitePool,
    customer_id: &str,
    engagement_id: Option<&str>,
    assets: Vec<DiscoveredAsset>,
) -> Result<SyncResult> {
    let mut result = SyncResult {
        total_assets: assets.len(),
        new_assets: 0,
        updated_assets: 0,
        failed_assets: 0,
        errors: Vec::new(),
    };

    let now = Utc::now().to_rfc3339();

    for asset in assets {
        let asset_type_str = asset.asset_type.to_string();

        // Check if asset already exists for this customer
        let existing: Option<(String, String)> = sqlx::query_as(
            r#"
            SELECT id, last_seen_at FROM crm_discovered_assets
            WHERE customer_id = ? AND asset_type = ? AND value = ?
            "#
        )
        .bind(customer_id)
        .bind(&asset_type_str)
        .bind(&asset.value)
        .fetch_optional(pool)
        .await?;

        match existing {
            Some((id, _)) => {
                // Update last_seen_at and optionally metadata/source
                let update_result = sqlx::query(
                    r#"
                    UPDATE crm_discovered_assets
                    SET last_seen_at = ?,
                        source = COALESCE(?, source),
                        source_scan_id = COALESCE(?, source_scan_id),
                        source_scan_type = COALESCE(?, source_scan_type),
                        metadata = COALESCE(?, metadata),
                        engagement_id = COALESCE(?, engagement_id),
                        updated_at = ?
                    WHERE id = ?
                    "#
                )
                .bind(&now)
                .bind(&asset.source)
                .bind(&asset.source_scan_id)
                .bind(&asset.source_scan_type)
                .bind(asset.metadata.as_ref().map(|m| serde_json::to_string(m).ok()).flatten())
                .bind(engagement_id)
                .bind(&now)
                .bind(&id)
                .execute(pool)
                .await;

                match update_result {
                    Ok(_) => result.updated_assets += 1,
                    Err(e) => {
                        result.failed_assets += 1;
                        result.errors.push(format!("Failed to update asset {}: {}", asset.value, e));
                    }
                }
            }
            None => {
                // Insert new asset
                let id = Uuid::new_v4().to_string();
                let insert_result = sqlx::query(
                    r#"
                    INSERT INTO crm_discovered_assets (
                        id, customer_id, engagement_id, asset_type, value,
                        first_seen_at, last_seen_at, source, source_scan_id,
                        source_scan_type, metadata, is_in_scope, is_verified,
                        notes, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE, FALSE, NULL, ?, ?)
                    "#
                )
                .bind(&id)
                .bind(customer_id)
                .bind(engagement_id)
                .bind(&asset_type_str)
                .bind(&asset.value)
                .bind(&now)
                .bind(&now)
                .bind(&asset.source)
                .bind(&asset.source_scan_id)
                .bind(&asset.source_scan_type)
                .bind(asset.metadata.as_ref().map(|m| serde_json::to_string(m).ok()).flatten())
                .bind(&now)
                .bind(&now)
                .execute(pool)
                .await;

                match insert_result {
                    Ok(_) => result.new_assets += 1,
                    Err(e) => {
                        result.failed_assets += 1;
                        result.errors.push(format!("Failed to insert asset {}: {}", asset.value, e));
                    }
                }
            }
        }
    }

    log::info!(
        "Synced {} assets for customer {}: {} new, {} updated, {} failed",
        result.total_assets, customer_id, result.new_assets, result.updated_assets, result.failed_assets
    );

    Ok(result)
}

/// Get all discovered assets for a customer
pub async fn get_customer_discovered_assets(
    pool: &SqlitePool,
    customer_id: &str,
    asset_type: Option<&str>,
    is_in_scope: Option<bool>,
    limit: Option<u32>,
    offset: Option<u32>,
) -> Result<Vec<CrmDiscoveredAsset>> {
    let limit = limit.unwrap_or(100);
    let offset = offset.unwrap_or(0);

    let mut query = String::from(
        r#"
        SELECT id, customer_id, engagement_id, asset_type, value,
               first_seen_at, last_seen_at, source, source_scan_id,
               source_scan_type, metadata, is_in_scope, is_verified,
               notes, created_at, updated_at
        FROM crm_discovered_assets
        WHERE customer_id = ?
        "#
    );

    if asset_type.is_some() {
        query.push_str(" AND asset_type = ?");
    }

    if is_in_scope.is_some() {
        query.push_str(" AND is_in_scope = ?");
    }

    query.push_str(" ORDER BY last_seen_at DESC LIMIT ? OFFSET ?");

    let rows: Vec<(
        String, String, Option<String>, String, String,
        String, String, String, Option<String>,
        Option<String>, Option<String>, bool, bool,
        Option<String>, String, String
    )> = if let Some(at) = asset_type {
        if let Some(scope) = is_in_scope {
            sqlx::query_as(&query)
                .bind(customer_id)
                .bind(at)
                .bind(scope)
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(pool)
                .await?
        } else {
            sqlx::query_as(&query)
                .bind(customer_id)
                .bind(at)
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(pool)
                .await?
        }
    } else if let Some(scope) = is_in_scope {
        sqlx::query_as(&query)
            .bind(customer_id)
            .bind(scope)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(pool)
            .await?
    } else {
        sqlx::query_as(&query)
            .bind(customer_id)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(pool)
            .await?
    };

    let assets: Vec<CrmDiscoveredAsset> = rows.into_iter().map(|row| {
        CrmDiscoveredAsset {
            id: row.0,
            customer_id: row.1,
            engagement_id: row.2,
            asset_type: row.3,
            value: row.4,
            first_seen_at: chrono::DateTime::parse_from_rfc3339(&row.5)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_seen_at: chrono::DateTime::parse_from_rfc3339(&row.6)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            source: row.7,
            source_scan_id: row.8,
            source_scan_type: row.9,
            metadata: row.10.and_then(|s| serde_json::from_str(&s).ok()),
            is_in_scope: row.11,
            is_verified: row.12,
            notes: row.13,
            created_at: chrono::DateTime::parse_from_rfc3339(&row.14)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.15)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }).collect();

    Ok(assets)
}

/// Get a discovered asset by ID
pub async fn get_discovered_asset_by_id(
    pool: &SqlitePool,
    asset_id: &str,
) -> Result<Option<CrmDiscoveredAsset>> {
    let row: Option<(
        String, String, Option<String>, String, String,
        String, String, String, Option<String>,
        Option<String>, Option<String>, bool, bool,
        Option<String>, String, String
    )> = sqlx::query_as(
        r#"
        SELECT id, customer_id, engagement_id, asset_type, value,
               first_seen_at, last_seen_at, source, source_scan_id,
               source_scan_type, metadata, is_in_scope, is_verified,
               notes, created_at, updated_at
        FROM crm_discovered_assets
        WHERE id = ?
        "#
    )
    .bind(asset_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| {
        CrmDiscoveredAsset {
            id: row.0,
            customer_id: row.1,
            engagement_id: row.2,
            asset_type: row.3,
            value: row.4,
            first_seen_at: chrono::DateTime::parse_from_rfc3339(&row.5)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_seen_at: chrono::DateTime::parse_from_rfc3339(&row.6)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            source: row.7,
            source_scan_id: row.8,
            source_scan_type: row.9,
            metadata: row.10.and_then(|s| serde_json::from_str(&s).ok()),
            is_in_scope: row.11,
            is_verified: row.12,
            notes: row.13,
            created_at: chrono::DateTime::parse_from_rfc3339(&row.14)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.15)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }))
}

/// Manually create a discovered asset
pub async fn create_discovered_asset(
    pool: &SqlitePool,
    customer_id: &str,
    request: CreateDiscoveredAssetRequest,
) -> Result<CrmDiscoveredAsset> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let source = request.source.unwrap_or_else(|| "manual".to_string());
    let is_in_scope = request.is_in_scope.unwrap_or(false);

    sqlx::query(
        r#"
        INSERT INTO crm_discovered_assets (
            id, customer_id, engagement_id, asset_type, value,
            first_seen_at, last_seen_at, source, source_scan_id,
            source_scan_type, metadata, is_in_scope, is_verified,
            notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, FALSE, ?, ?, ?)
        "#
    )
    .bind(&id)
    .bind(customer_id)
    .bind(&request.engagement_id)
    .bind(&request.asset_type)
    .bind(&request.value)
    .bind(&now)
    .bind(&now)
    .bind(&source)
    .bind(request.metadata.as_ref().map(|m| serde_json::to_string(m).ok()).flatten())
    .bind(is_in_scope)
    .bind(&request.notes)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    // Fetch and return the created asset
    get_discovered_asset_by_id(pool, &id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to retrieve created asset"))
}

/// Update a discovered asset
pub async fn update_discovered_asset(
    pool: &SqlitePool,
    asset_id: &str,
    request: UpdateDiscoveredAssetRequest,
) -> Result<CrmDiscoveredAsset> {
    let now = Utc::now().to_rfc3339();

    // Build dynamic update query
    let mut updates = vec!["updated_at = ?"];
    let mut has_scope = false;
    let mut has_verified = false;
    let mut has_notes = false;
    let mut has_engagement = false;

    if request.is_in_scope.is_some() {
        updates.push("is_in_scope = ?");
        has_scope = true;
    }
    if request.is_verified.is_some() {
        updates.push("is_verified = ?");
        has_verified = true;
    }
    if request.notes.is_some() {
        updates.push("notes = ?");
        has_notes = true;
    }
    if request.engagement_id.is_some() {
        updates.push("engagement_id = ?");
        has_engagement = true;
    }

    let query = format!(
        "UPDATE crm_discovered_assets SET {} WHERE id = ?",
        updates.join(", ")
    );

    // Build query with binds
    let mut q = sqlx::query(&query).bind(&now);

    if has_scope {
        q = q.bind(request.is_in_scope.unwrap());
    }
    if has_verified {
        q = q.bind(request.is_verified.unwrap());
    }
    if has_notes {
        q = q.bind(request.notes.as_ref());
    }
    if has_engagement {
        q = q.bind(request.engagement_id.as_ref());
    }

    q.bind(asset_id).execute(pool).await?;

    // Fetch and return the updated asset
    get_discovered_asset_by_id(pool, asset_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Asset not found"))
}

/// Delete a discovered asset
pub async fn delete_discovered_asset(
    pool: &SqlitePool,
    asset_id: &str,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM crm_discovered_assets WHERE id = ?")
        .bind(asset_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Get asset type distribution for a customer
pub async fn get_asset_type_distribution(
    pool: &SqlitePool,
    customer_id: &str,
) -> Result<Vec<(String, i64)>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT asset_type, COUNT(*) as count
        FROM crm_discovered_assets
        WHERE customer_id = ?
        GROUP BY asset_type
        ORDER BY count DESC
        "#
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Get asset source distribution for a customer
pub async fn get_asset_source_distribution(
    pool: &SqlitePool,
    customer_id: &str,
) -> Result<Vec<(String, i64)>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT source, COUNT(*) as count
        FROM crm_discovered_assets
        WHERE customer_id = ?
        GROUP BY source
        ORDER BY count DESC
        "#
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Get total asset count for a customer
pub async fn get_customer_asset_count(
    pool: &SqlitePool,
    customer_id: &str,
) -> Result<i64> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM crm_discovered_assets WHERE customer_id = ?"
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    Ok(count.0)
}

/// Get in-scope asset count for a customer
pub async fn get_customer_in_scope_asset_count(
    pool: &SqlitePool,
    customer_id: &str,
) -> Result<i64> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM crm_discovered_assets WHERE customer_id = ? AND is_in_scope = TRUE"
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    Ok(count.0)
}

/// Customer discovered assets summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAssetsSummary {
    pub total_assets: i64,
    pub in_scope_assets: i64,
    pub verified_assets: i64,
    pub assets_by_type: Vec<(String, i64)>,
    pub assets_by_source: Vec<(String, i64)>,
    pub recent_discoveries: Vec<CrmDiscoveredAsset>,
}

/// Get a summary of discovered assets for a customer
pub async fn get_discovered_assets_summary(
    pool: &SqlitePool,
    customer_id: &str,
) -> Result<DiscoveredAssetsSummary> {
    let total: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM crm_discovered_assets WHERE customer_id = ?"
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    let in_scope: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM crm_discovered_assets WHERE customer_id = ? AND is_in_scope = TRUE"
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    let verified: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM crm_discovered_assets WHERE customer_id = ? AND is_verified = TRUE"
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    let assets_by_type = get_asset_type_distribution(pool, customer_id).await?;
    let assets_by_source = get_asset_source_distribution(pool, customer_id).await?;
    let recent_discoveries = get_customer_discovered_assets(pool, customer_id, None, None, Some(10), Some(0)).await?;

    Ok(DiscoveredAssetsSummary {
        total_assets: total.0,
        in_scope_assets: in_scope.0,
        verified_assets: verified.0,
        assets_by_type,
        assets_by_source,
        recent_discoveries,
    })
}

/// Bulk update assets' in_scope status
pub async fn bulk_update_in_scope(
    pool: &SqlitePool,
    asset_ids: &[String],
    is_in_scope: bool,
) -> Result<u64> {
    if asset_ids.is_empty() {
        return Ok(0);
    }

    let now = Utc::now().to_rfc3339();
    let placeholders: Vec<&str> = asset_ids.iter().map(|_| "?").collect();
    let query = format!(
        "UPDATE crm_discovered_assets SET is_in_scope = ?, updated_at = ? WHERE id IN ({})",
        placeholders.join(", ")
    );

    let mut q = sqlx::query(&query).bind(is_in_scope).bind(&now);
    for id in asset_ids {
        q = q.bind(id);
    }

    let result = q.execute(pool).await?;
    Ok(result.rows_affected())
}

/// Sync assets from scan completion - convenience function
/// Called by recon scan completion handlers
pub async fn sync_from_scan_completion(
    pool: &SqlitePool,
    customer_id: &str,
    engagement_id: Option<&str>,
    scan_id: &str,
    scan_type: &str,
    assets: Vec<DiscoveredAsset>,
) -> Result<SyncResult> {
    // Enrich assets with scan info if not already set
    let enriched_assets: Vec<DiscoveredAsset> = assets.into_iter().map(|mut a| {
        if a.source_scan_id.is_none() {
            a.source_scan_id = Some(scan_id.to_string());
        }
        if a.source_scan_type.is_none() {
            a.source_scan_type = Some(scan_type.to_string());
        }
        a
    }).collect();

    sync_discovered_assets(pool, customer_id, engagement_id, enriched_assets).await
}
