use anyhow::Result;
use sqlx::{FromRow, SqlitePool};
use chrono::{DateTime, Utc};

use crate::scanner::asset_discovery::{
    AssetDiscoveryConfig, AssetDiscoveryResult, AssetDiscoveryStatus,
    DiscoveredAsset, DiscoverySource, DiscoveryStatistics, WhoisInfo,
};

/// Database model for asset discovery scans
#[derive(Debug, FromRow)]
pub struct AssetDiscoveryScanRow {
    pub id: String,
    pub user_id: String,
    pub domain: String,
    pub config: String,           // JSON serialized
    pub status: String,
    pub whois_data: Option<String>, // JSON serialized
    pub statistics: String,       // JSON serialized
    pub errors: String,           // JSON serialized array
    pub started_at: String,
    pub completed_at: Option<String>,
    pub created_at: String,
}

/// Database model for discovered assets
#[derive(Debug, FromRow)]
pub struct DiscoveredAssetRow {
    pub id: String,
    pub scan_id: String,
    pub hostname: String,
    pub ip_addresses: String,     // JSON serialized array
    pub sources: String,          // JSON serialized array
    pub ports: String,            // JSON serialized array
    pub technologies: String,     // JSON serialized array
    pub certificates: String,     // JSON serialized array
    pub dns_records: String,      // JSON serialized HashMap
    pub asn: Option<String>,
    pub asn_org: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub tags: String,             // JSON serialized array
    pub first_seen: String,
    pub last_seen: String,
    pub created_at: String,
}

/// Create a new asset discovery scan
pub async fn create_asset_discovery_scan(
    pool: &SqlitePool,
    user_id: &str,
    config: &AssetDiscoveryConfig,
    customer_id: Option<&str>,
    engagement_id: Option<&str>,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let config_json = serde_json::to_string(config)?;
    let stats_json = serde_json::to_string(&DiscoveryStatistics::default())?;
    let errors_json = "[]".to_string();

    sqlx::query(
        r#"
        INSERT INTO asset_discovery_scans (
            id, user_id, domain, config, status, statistics, errors, started_at, created_at, customer_id, engagement_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&config.domain)
    .bind(&config_json)
    .bind("pending")
    .bind(&stats_json)
    .bind(&errors_json)
    .bind(&now)
    .bind(&now)
    .bind(customer_id)
    .bind(engagement_id)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Update asset discovery scan status
pub async fn update_scan_status(
    pool: &SqlitePool,
    scan_id: &str,
    status: AssetDiscoveryStatus,
) -> Result<()> {
    let status_str = match status {
        AssetDiscoveryStatus::Pending => "pending",
        AssetDiscoveryStatus::Running => "running",
        AssetDiscoveryStatus::Completed => "completed",
        AssetDiscoveryStatus::Failed => "failed",
        AssetDiscoveryStatus::Cancelled => "cancelled",
    };

    sqlx::query("UPDATE asset_discovery_scans SET status = ? WHERE id = ?")
        .bind(status_str)
        .bind(scan_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Save asset discovery results
pub async fn save_discovery_results(
    pool: &SqlitePool,
    result: &AssetDiscoveryResult,
) -> Result<()> {
    let _now = Utc::now().to_rfc3339();
    let completed_at = result.completed_at.map(|dt| dt.to_rfc3339());
    let whois_json = result.whois.as_ref().map(|w| serde_json::to_string(w)).transpose()?;
    let stats_json = serde_json::to_string(&result.statistics)?;
    let errors_json = serde_json::to_string(&result.errors)?;

    let status_str = match result.status {
        AssetDiscoveryStatus::Pending => "pending",
        AssetDiscoveryStatus::Running => "running",
        AssetDiscoveryStatus::Completed => "completed",
        AssetDiscoveryStatus::Failed => "failed",
        AssetDiscoveryStatus::Cancelled => "cancelled",
    };

    // Update scan record
    sqlx::query(
        r#"
        UPDATE asset_discovery_scans
        SET status = ?, whois_data = ?, statistics = ?, errors = ?, completed_at = ?
        WHERE id = ?
        "#,
    )
    .bind(status_str)
    .bind(&whois_json)
    .bind(&stats_json)
    .bind(&errors_json)
    .bind(&completed_at)
    .bind(&result.id)
    .execute(pool)
    .await?;

    // Save discovered assets
    for asset in &result.assets {
        save_discovered_asset(pool, &result.id, asset).await?;
    }

    Ok(())
}

/// Save a single discovered asset
pub async fn save_discovered_asset(
    pool: &SqlitePool,
    scan_id: &str,
    asset: &DiscoveredAsset,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let ips_json = serde_json::to_string(&asset.ip_addresses)?;
    let sources_json = serde_json::to_string(&asset.sources)?;
    let ports_json = serde_json::to_string(&asset.ports)?;
    let techs_json = serde_json::to_string(&asset.technologies)?;
    let certs_json = serde_json::to_string(&asset.certificates)?;
    let dns_json = serde_json::to_string(&asset.dns_records)?;
    let tags_json = serde_json::to_string(&asset.tags)?;

    sqlx::query(
        r#"
        INSERT INTO discovered_assets (
            id, scan_id, hostname, ip_addresses, sources, ports, technologies,
            certificates, dns_records, asn, asn_org, country, city, tags,
            first_seen, last_seen, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            ip_addresses = excluded.ip_addresses,
            sources = excluded.sources,
            ports = excluded.ports,
            technologies = excluded.technologies,
            certificates = excluded.certificates,
            dns_records = excluded.dns_records,
            last_seen = excluded.last_seen
        "#,
    )
    .bind(&asset.id)
    .bind(scan_id)
    .bind(&asset.hostname)
    .bind(&ips_json)
    .bind(&sources_json)
    .bind(&ports_json)
    .bind(&techs_json)
    .bind(&certs_json)
    .bind(&dns_json)
    .bind(&asset.asn)
    .bind(&asset.asn_org)
    .bind(&asset.country)
    .bind(&asset.city)
    .bind(&tags_json)
    .bind(asset.first_seen.to_rfc3339())
    .bind(asset.last_seen.to_rfc3339())
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get an asset discovery scan by ID
pub async fn get_scan_by_id(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Option<AssetDiscoveryScanRow>> {
    let row = sqlx::query_as::<_, AssetDiscoveryScanRow>(
        "SELECT * FROM asset_discovery_scans WHERE id = ?"
    )
    .bind(scan_id)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

/// Get all scans for a user
pub async fn get_user_scans(
    pool: &SqlitePool,
    user_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<AssetDiscoveryScanRow>> {
    let rows = sqlx::query_as::<_, AssetDiscoveryScanRow>(
        "SELECT * FROM asset_discovery_scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?"
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Get discovered assets for a scan
pub async fn get_scan_assets(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Vec<DiscoveredAssetRow>> {
    let rows = sqlx::query_as::<_, DiscoveredAssetRow>(
        "SELECT * FROM discovered_assets WHERE scan_id = ? ORDER BY hostname"
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Get a specific discovered asset
pub async fn get_asset_by_id(
    pool: &SqlitePool,
    asset_id: &str,
) -> Result<Option<DiscoveredAssetRow>> {
    let row = sqlx::query_as::<_, DiscoveredAssetRow>(
        "SELECT * FROM discovered_assets WHERE id = ?"
    )
    .bind(asset_id)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

/// Search assets by hostname
pub async fn search_assets(
    pool: &SqlitePool,
    user_id: &str,
    query: &str,
    limit: i64,
) -> Result<Vec<DiscoveredAssetRow>> {
    let pattern = format!("%{}%", query);
    let rows = sqlx::query_as::<_, DiscoveredAssetRow>(
        r#"
        SELECT da.* FROM discovered_assets da
        JOIN asset_discovery_scans ads ON da.scan_id = ads.id
        WHERE ads.user_id = ? AND da.hostname LIKE ?
        ORDER BY da.last_seen DESC
        LIMIT ?
        "#
    )
    .bind(user_id)
    .bind(&pattern)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Delete an asset discovery scan and its assets
pub async fn delete_scan(pool: &SqlitePool, scan_id: &str) -> Result<()> {
    // Delete assets first (due to foreign key)
    sqlx::query("DELETE FROM discovered_assets WHERE scan_id = ?")
        .bind(scan_id)
        .execute(pool)
        .await?;

    // Delete scan
    sqlx::query("DELETE FROM asset_discovery_scans WHERE id = ?")
        .bind(scan_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Convert database row to result object
pub fn row_to_result(row: AssetDiscoveryScanRow, assets: Vec<DiscoveredAssetRow>) -> Result<AssetDiscoveryResult> {
    let config: AssetDiscoveryConfig = serde_json::from_str(&row.config)?;
    let statistics: DiscoveryStatistics = serde_json::from_str(&row.statistics)?;
    let errors: Vec<String> = serde_json::from_str(&row.errors)?;
    let whois: Option<WhoisInfo> = row.whois_data
        .map(|w| serde_json::from_str(&w))
        .transpose()?;

    let status = match row.status.as_str() {
        "pending" => AssetDiscoveryStatus::Pending,
        "running" => AssetDiscoveryStatus::Running,
        "completed" => AssetDiscoveryStatus::Completed,
        "failed" => AssetDiscoveryStatus::Failed,
        "cancelled" => AssetDiscoveryStatus::Cancelled,
        _ => AssetDiscoveryStatus::Pending,
    };

    let started_at = DateTime::parse_from_rfc3339(&row.started_at)?
        .with_timezone(&Utc);
    let completed_at = row.completed_at
        .map(|dt| DateTime::parse_from_rfc3339(&dt))
        .transpose()?
        .map(|dt| dt.with_timezone(&Utc));

    // Convert asset rows
    let discovered_assets: Vec<DiscoveredAsset> = assets
        .into_iter()
        .map(row_to_asset)
        .collect::<Result<Vec<_>>>()?;

    Ok(AssetDiscoveryResult {
        id: row.id,
        domain: row.domain,
        config,
        status,
        assets: discovered_assets,
        whois,
        statistics,
        errors,
        started_at,
        completed_at,
    })
}

/// Convert database row to discovered asset
pub fn row_to_asset(row: DiscoveredAssetRow) -> Result<DiscoveredAsset> {
    use std::net::IpAddr;

    let ip_addresses: Vec<IpAddr> = serde_json::from_str(&row.ip_addresses)?;
    let sources: Vec<DiscoverySource> = serde_json::from_str(&row.sources)?;
    let ports = serde_json::from_str(&row.ports)?;
    let technologies = serde_json::from_str(&row.technologies)?;
    let certificates = serde_json::from_str(&row.certificates)?;
    let dns_records = serde_json::from_str(&row.dns_records)?;
    let tags: Vec<String> = serde_json::from_str(&row.tags)?;

    let first_seen = DateTime::parse_from_rfc3339(&row.first_seen)?
        .with_timezone(&Utc);
    let last_seen = DateTime::parse_from_rfc3339(&row.last_seen)?
        .with_timezone(&Utc);

    Ok(DiscoveredAsset {
        id: row.id,
        hostname: row.hostname,
        ip_addresses,
        sources,
        ports,
        technologies,
        certificates,
        dns_records,
        first_seen,
        last_seen,
        asn: row.asn,
        asn_org: row.asn_org,
        country: row.country,
        city: row.city,
        tags,
    })
}
