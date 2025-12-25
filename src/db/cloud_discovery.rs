//! Database operations for cloud asset discovery
//!
//! This module provides CRUD operations for cloud discovery scans and their results.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;

use crate::scanner::cloud::cloud_discovery::{
    AccessibilityStatus, CloudAsset, CloudAssetType, CloudDiscoveryConfig, CloudDiscoveryResult,
    CloudDiscoveryStatus, CloudProviderType, DiscoveryMethod, DiscoveryStatistics,
};

// ============================================================================
// Database Models
// ============================================================================

/// Database row for cloud discovery scans
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CloudDiscoveryRow {
    pub id: String,
    pub user_id: String,
    pub domain: String,
    pub config: String,  // JSON
    pub status: String,
    pub statistics: Option<String>,  // JSON
    pub errors: Option<String>,  // JSON array
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl CloudDiscoveryRow {
    /// Convert to domain model
    pub fn to_discovery_result(&self, assets: Vec<CloudAsset>) -> CloudDiscoveryResult {
        let config: CloudDiscoveryConfig = self
            .config
            .parse::<serde_json::Value>()
            .ok()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();

        let statistics: DiscoveryStatistics = self
            .statistics
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();

        let errors: Vec<String> = self
            .errors
            .as_ref()
            .and_then(|e| serde_json::from_str(e).ok())
            .unwrap_or_default();

        let status = self.status.parse().unwrap_or(CloudDiscoveryStatus::Pending);

        CloudDiscoveryResult {
            id: self.id.clone(),
            user_id: self.user_id.clone(),
            domain: self.domain.clone(),
            config,
            status,
            assets,
            statistics,
            errors,
            started_at: self.started_at,
            completed_at: self.completed_at,
        }
    }
}

/// Database row for discovered cloud assets
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CloudAssetRow {
    pub id: String,
    pub discovery_id: String,
    pub provider: String,
    pub asset_type: String,
    pub name: String,
    pub url: Option<String>,
    pub region: Option<String>,
    pub accessibility: String,
    pub discovery_method: String,
    pub cname_chain: Option<String>,  // JSON array
    pub metadata: Option<String>,  // JSON object
    pub risk_level: String,
    pub notes: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

impl CloudAssetRow {
    /// Convert to domain model
    pub fn to_cloud_asset(&self) -> CloudAsset {
        let provider = self.provider.parse().unwrap_or(CloudProviderType::Unknown);

        let asset_type = match self.asset_type.as_str() {
            "storage_bucket" => CloudAssetType::StorageBucket,
            "cdn_endpoint" => CloudAssetType::CdnEndpoint,
            "web_application" => CloudAssetType::WebApplication,
            "serverless_function" => CloudAssetType::ServerlessFunction,
            "database_endpoint" => CloudAssetType::DatabaseEndpoint,
            "container_service" => CloudAssetType::ContainerService,
            "compute_instance" => CloudAssetType::ComputeInstance,
            "load_balancer" => CloudAssetType::LoadBalancer,
            "dns_service" => CloudAssetType::DnsService,
            "api_gateway" => CloudAssetType::ApiGateway,
            other => CloudAssetType::Other(other.to_string()),
        };

        let discovery_method = match self.discovery_method.as_str() {
            "dns_cname" => DiscoveryMethod::DnsCname,
            "bucket_enumeration" => DiscoveryMethod::BucketEnumeration,
            "certificate_transparency" => DiscoveryMethod::CertificateTransparency,
            "ip_range_matching" => DiscoveryMethod::IpRangeMatching,
            "http_headers" => DiscoveryMethod::HttpHeaders,
            "subdomain_enumeration" => DiscoveryMethod::SubdomainEnumeration,
            _ => DiscoveryMethod::Manual,
        };

        let accessibility = self.accessibility.parse().unwrap_or(AccessibilityStatus::Unknown);

        let cname_chain: Vec<String> = self
            .cname_chain
            .as_ref()
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or_default();

        let metadata = self
            .metadata
            .as_ref()
            .and_then(|m| serde_json::from_str(m).ok())
            .unwrap_or_default();

        CloudAsset {
            id: self.id.clone(),
            provider,
            asset_type,
            name: self.name.clone(),
            url: self.url.clone(),
            region: self.region.clone(),
            accessibility,
            discovery_method,
            cname_chain,
            metadata,
            discovered_at: self.discovered_at,
            risk_level: self.risk_level.clone(),
            notes: self.notes.clone(),
        }
    }
}

// ============================================================================
// Request/Response DTOs
// ============================================================================

/// Request to create a cloud discovery scan
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCloudDiscoveryRequest {
    pub domain: String,
    #[serde(default = "default_true")]
    pub enable_dns_discovery: bool,
    #[serde(default = "default_true")]
    pub enable_bucket_enumeration: bool,
    #[serde(default = "default_true")]
    pub enable_ct_logs: bool,
    #[serde(default)]
    pub custom_bucket_patterns: Vec<String>,
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default)]
    pub check_accessibility: bool,
}

fn default_true() -> bool {
    true
}

/// Request to check specific bucket names
#[derive(Debug, Serialize, Deserialize)]
pub struct BucketCheckRequest {
    pub bucket_names: Vec<String>,
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default)]
    pub check_accessibility: bool,
}

/// Query parameters for listing discoveries
#[derive(Debug, Deserialize)]
pub struct ListCloudDiscoveriesQuery {
    pub domain: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ============================================================================
// Database Operations - Discoveries
// ============================================================================

/// Create a new cloud discovery scan record
pub async fn create_cloud_discovery(
    pool: &SqlitePool,
    user_id: &str,
    domain: &str,
    config: &CloudDiscoveryConfig,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let config_json = serde_json::to_string(config)?;

    sqlx::query(
        r#"
        INSERT INTO cloud_discovery_results (
            id, user_id, domain, config, status, started_at, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(domain)
    .bind(&config_json)
    .bind("pending")
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get a cloud discovery scan by ID
pub async fn get_cloud_discovery(
    pool: &SqlitePool,
    discovery_id: &str,
    user_id: &str,
) -> Result<Option<CloudDiscoveryResult>> {
    let row = sqlx::query_as::<_, CloudDiscoveryRow>(
        "SELECT * FROM cloud_discovery_results WHERE id = ?1 AND user_id = ?2",
    )
    .bind(discovery_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => {
            let assets = get_cloud_discovery_assets(pool, discovery_id).await?;
            Ok(Some(r.to_discovery_result(assets)))
        }
        None => Ok(None),
    }
}

/// List cloud discovery scans for a user
pub async fn list_cloud_discoveries(
    pool: &SqlitePool,
    user_id: &str,
    query: &ListCloudDiscoveriesQuery,
) -> Result<Vec<CloudDiscoveryRow>> {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from("SELECT * FROM cloud_discovery_results WHERE user_id = ?1");
    let mut param_count = 2;

    if query.domain.is_some() {
        sql.push_str(&format!(" AND domain LIKE ?{}", param_count));
        param_count += 1;
    }

    if query.status.is_some() {
        sql.push_str(&format!(" AND status = ?{}", param_count));
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

    let mut q = sqlx::query_as::<_, CloudDiscoveryRow>(&sql).bind(user_id);

    if let Some(domain) = &query.domain {
        q = q.bind(format!("%{}%", domain));
    }

    if let Some(status) = &query.status {
        q = q.bind(status);
    }

    q = q.bind(limit).bind(offset);

    let rows = q.fetch_all(pool).await?;
    Ok(rows)
}

/// Update cloud discovery scan status
pub async fn update_cloud_discovery_status(
    pool: &SqlitePool,
    discovery_id: &str,
    status: CloudDiscoveryStatus,
    error_message: Option<&str>,
) -> Result<()> {
    let status_str = status.to_string();
    let now = Utc::now();

    match status {
        CloudDiscoveryStatus::Running => {
            sqlx::query("UPDATE cloud_discovery_results SET status = ?1, started_at = ?2 WHERE id = ?3")
                .bind(&status_str)
                .bind(now)
                .bind(discovery_id)
                .execute(pool)
                .await?;
        }
        CloudDiscoveryStatus::Completed | CloudDiscoveryStatus::Failed => {
            let errors = error_message.map(|e| serde_json::to_string(&vec![e]).unwrap_or_default());
            sqlx::query(
                "UPDATE cloud_discovery_results SET status = ?1, completed_at = ?2, errors = COALESCE(?3, errors) WHERE id = ?4",
            )
            .bind(&status_str)
            .bind(now)
            .bind(&errors)
            .bind(discovery_id)
            .execute(pool)
            .await?;
        }
        _ => {
            sqlx::query("UPDATE cloud_discovery_results SET status = ?1 WHERE id = ?2")
                .bind(&status_str)
                .bind(discovery_id)
                .execute(pool)
                .await?;
        }
    }

    Ok(())
}

/// Update cloud discovery statistics
pub async fn update_cloud_discovery_statistics(
    pool: &SqlitePool,
    discovery_id: &str,
    statistics: &DiscoveryStatistics,
) -> Result<()> {
    let stats_json = serde_json::to_string(statistics)?;

    sqlx::query("UPDATE cloud_discovery_results SET statistics = ?1 WHERE id = ?2")
        .bind(&stats_json)
        .bind(discovery_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Delete a cloud discovery scan and its assets
pub async fn delete_cloud_discovery(
    pool: &SqlitePool,
    discovery_id: &str,
    user_id: &str,
) -> Result<bool> {
    // Verify ownership first
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM cloud_discovery_results WHERE id = ?1 AND user_id = ?2",
    )
    .bind(discovery_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    if exists.is_none() {
        return Ok(false);
    }

    // Delete assets first (no cascade in SQLite by default)
    sqlx::query("DELETE FROM cloud_discovery_assets WHERE discovery_id = ?1")
        .bind(discovery_id)
        .execute(pool)
        .await?;

    // Delete the discovery record
    let result = sqlx::query("DELETE FROM cloud_discovery_results WHERE id = ?1 AND user_id = ?2")
        .bind(discovery_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Database Operations - Assets
// ============================================================================

/// Store discovered cloud assets
pub async fn store_cloud_assets(
    pool: &SqlitePool,
    discovery_id: &str,
    assets: &[CloudAsset],
) -> Result<()> {
    for asset in assets {
        let cname_json = serde_json::to_string(&asset.cname_chain)?;
        let metadata_json = serde_json::to_string(&asset.metadata)?;

        sqlx::query(
            r#"
            INSERT INTO cloud_discovery_assets (
                id, discovery_id, provider, asset_type, name, url, region,
                accessibility, discovery_method, cname_chain, metadata,
                risk_level, notes, discovered_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            "#,
        )
        .bind(&asset.id)
        .bind(discovery_id)
        .bind(asset.provider.to_string())
        .bind(asset.asset_type.to_string())
        .bind(&asset.name)
        .bind(&asset.url)
        .bind(&asset.region)
        .bind(asset.accessibility.to_string())
        .bind(asset.discovery_method.to_string())
        .bind(&cname_json)
        .bind(&metadata_json)
        .bind(&asset.risk_level)
        .bind(&asset.notes)
        .bind(asset.discovered_at)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Get assets for a cloud discovery scan
pub async fn get_cloud_discovery_assets(
    pool: &SqlitePool,
    discovery_id: &str,
) -> Result<Vec<CloudAsset>> {
    let rows = sqlx::query_as::<_, CloudAssetRow>(
        "SELECT * FROM cloud_discovery_assets WHERE discovery_id = ?1 ORDER BY provider, asset_type, name",
    )
    .bind(discovery_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.to_cloud_asset()).collect())
}

/// Get a single cloud asset by ID
pub async fn get_cloud_asset(
    pool: &SqlitePool,
    asset_id: &str,
) -> Result<Option<CloudAsset>> {
    let row = sqlx::query_as::<_, CloudAssetRow>(
        "SELECT * FROM cloud_discovery_assets WHERE id = ?1",
    )
    .bind(asset_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.to_cloud_asset()))
}

/// Get assets filtered by provider or type
pub async fn get_cloud_assets_filtered(
    pool: &SqlitePool,
    discovery_id: &str,
    provider: Option<&str>,
    asset_type: Option<&str>,
    accessibility: Option<&str>,
) -> Result<Vec<CloudAsset>> {
    let mut sql = String::from("SELECT * FROM cloud_discovery_assets WHERE discovery_id = ?1");

    if provider.is_some() {
        sql.push_str(" AND provider = ?2");
    }
    if asset_type.is_some() {
        sql.push_str(&format!(" AND asset_type = ?{}", if provider.is_some() { 3 } else { 2 }));
    }
    if accessibility.is_some() {
        let param_num = 2 + provider.is_some() as usize + asset_type.is_some() as usize;
        sql.push_str(&format!(" AND accessibility = ?{}", param_num));
    }

    sql.push_str(" ORDER BY provider, asset_type, name");

    let mut q = sqlx::query_as::<_, CloudAssetRow>(&sql).bind(discovery_id);

    if let Some(p) = provider {
        q = q.bind(p);
    }
    if let Some(t) = asset_type {
        q = q.bind(t);
    }
    if let Some(a) = accessibility {
        q = q.bind(a);
    }

    let rows = q.fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.to_cloud_asset()).collect())
}

// ============================================================================
// Database Migration
// ============================================================================

/// Create the cloud discovery tables
pub async fn create_cloud_discovery_tables(pool: &SqlitePool) -> Result<()> {
    // Create cloud_discovery_results table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cloud_discovery_results (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            config TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            statistics TEXT,
            errors TEXT,
            started_at DATETIME NOT NULL,
            completed_at DATETIME,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on user_id and domain
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_cloud_discovery_user ON cloud_discovery_results(user_id)",
    )
    .execute(pool)
    .await;

    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_cloud_discovery_domain ON cloud_discovery_results(domain)",
    )
    .execute(pool)
    .await;

    // Create cloud_discovery_assets table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cloud_discovery_assets (
            id TEXT PRIMARY KEY,
            discovery_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            name TEXT NOT NULL,
            url TEXT,
            region TEXT,
            accessibility TEXT NOT NULL DEFAULT 'unknown',
            discovery_method TEXT NOT NULL,
            cname_chain TEXT,
            metadata TEXT,
            risk_level TEXT NOT NULL DEFAULT 'info',
            notes TEXT,
            discovered_at DATETIME NOT NULL,
            FOREIGN KEY (discovery_id) REFERENCES cloud_discovery_results(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indices for assets
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_cloud_assets_discovery ON cloud_discovery_assets(discovery_id)",
    )
    .execute(pool)
    .await;

    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_cloud_assets_provider ON cloud_discovery_assets(provider)",
    )
    .execute(pool)
    .await;

    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_cloud_assets_type ON cloud_discovery_assets(asset_type)",
    )
    .execute(pool)
    .await;

    Ok(())
}
