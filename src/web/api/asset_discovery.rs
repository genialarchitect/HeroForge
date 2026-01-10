use actix_web::{web, HttpResponse};
use log::{error, info};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashSet;
use tokio::sync::RwLock;

use crate::db::asset_discovery;
use crate::db::crm_asset_sync::{self, AssetType, DiscoveredAsset as CrmDiscoveredAsset};
use crate::scanner::asset_discovery::{
    run_asset_discovery, AssetDiscoveryConfig, AssetDiscoveryStatus,
};
use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;

/// State for tracking running discovery scans
pub struct DiscoveryState {
    pub running_scans: RwLock<HashSet<String>>,
}

impl Default for DiscoveryState {
    fn default() -> Self {
        Self {
            running_scans: RwLock::new(HashSet::new()),
        }
    }
}

/// Request to start a new asset discovery scan
#[derive(Debug, Deserialize)]
pub struct StartDiscoveryRequest {
    pub domain: String,
    #[serde(default = "default_true")]
    pub include_ct_logs: bool,
    #[serde(default = "default_true")]
    pub include_dns: bool,
    #[serde(default)]
    pub include_shodan: bool,
    #[serde(default)]
    pub include_censys: bool,
    #[serde(default = "default_true")]
    pub include_whois: bool,
    #[serde(default)]
    pub active_enum: bool,
    pub wordlist: Option<Vec<String>>,
    pub shodan_api_key: Option<String>,
    pub censys_api_id: Option<String>,
    pub censys_api_secret: Option<String>,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Optional CRM customer ID
    pub customer_id: Option<String>,
    /// Optional CRM engagement ID
    pub engagement_id: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_concurrency() -> usize {
    10
}

fn default_timeout() -> u64 {
    30
}

/// Response for scan creation
#[derive(Serialize)]
pub struct StartDiscoveryResponse {
    pub id: String,
    pub domain: String,
    pub status: String,
    pub message: String,
}

/// Response for scan list
#[derive(Serialize)]
pub struct ScanListResponse {
    pub scans: Vec<ScanSummary>,
    pub total: i64,
}

#[derive(Serialize)]
pub struct ScanSummary {
    pub id: String,
    pub domain: String,
    pub status: String,
    pub assets_count: usize,
    pub created_at: String,
    pub completed_at: Option<String>,
}

/// Start a new asset discovery scan
pub async fn start_discovery(
    pool: web::Data<SqlitePool>,
    state: web::Data<DiscoveryState>,
    claims: Claims,
    req: web::Json<StartDiscoveryRequest>,
) -> Result<HttpResponse, ApiError> {
    info!(
        "User {} starting asset discovery for domain: {}",
        claims.sub, req.domain
    );

    // Validate domain
    if req.domain.is_empty() {
        return Err(ApiError::bad_request("Domain is required"));
    }

    // Build config
    let config = AssetDiscoveryConfig {
        domain: req.domain.clone(),
        include_ct_logs: req.include_ct_logs,
        include_dns: req.include_dns,
        include_shodan: req.include_shodan,
        include_censys: req.include_censys,
        include_whois: req.include_whois,
        active_enum: req.active_enum,
        wordlist: req.wordlist.clone(),
        shodan_api_key: req.shodan_api_key.clone(),
        censys_api_id: req.censys_api_id.clone(),
        censys_api_secret: req.censys_api_secret.clone(),
        concurrency: req.concurrency,
        timeout_secs: req.timeout_secs,
    };

    // Create scan record in database
    let scan_id = asset_discovery::create_asset_discovery_scan(
        pool.get_ref(),
        &claims.sub,
        &config,
        req.customer_id.as_deref(),
        req.engagement_id.as_deref(),
    ).await?;

    // Track running scan
    {
        let mut running = state.running_scans.write().await;
        running.insert(scan_id.clone());
    }

    // Spawn background task for discovery
    let pool_clone = pool.get_ref().clone();
    let scan_id_clone = scan_id.clone();
    let state_clone = state.clone();
    let customer_id_clone = req.customer_id.clone();
    let engagement_id_clone = req.engagement_id.clone();
    let domain_clone = req.domain.clone();

    tokio::spawn(async move {
        // Update status to running
        let _ = asset_discovery::update_scan_status(
            &pool_clone,
            &scan_id_clone,
            AssetDiscoveryStatus::Running,
        )
        .await;

        // Run discovery
        let result = run_asset_discovery(config).await;

        match result {
            Ok(mut discovery_result) => {
                discovery_result.id = scan_id_clone.clone();
                discovery_result.status = AssetDiscoveryStatus::Completed;

                // Save results
                if let Err(e) =
                    asset_discovery::save_discovery_results(&pool_clone, &discovery_result).await
                {
                    error!("Failed to save discovery results: {}", e);
                }

                // Sync discovered assets to CRM if customer_id is set
                if let Some(ref customer_id) = customer_id_clone {
                    let crm_assets = convert_to_crm_assets(
                        &discovery_result.assets,
                        &domain_clone,
                        &scan_id_clone,
                    );

                    if !crm_assets.is_empty() {
                        match crm_asset_sync::sync_from_scan_completion(
                            &pool_clone,
                            customer_id,
                            engagement_id_clone.as_deref(),
                            &scan_id_clone,
                            "asset_discovery",
                            crm_assets,
                        ).await {
                            Ok(sync_result) => {
                                info!(
                                    "Synced {} assets to CRM for customer {}: {} new, {} updated",
                                    sync_result.total_assets,
                                    customer_id,
                                    sync_result.new_assets,
                                    sync_result.updated_assets
                                );
                            }
                            Err(e) => {
                                error!("Failed to sync assets to CRM: {}", e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Asset discovery failed: {}", e);
                let _ = asset_discovery::update_scan_status(
                    &pool_clone,
                    &scan_id_clone,
                    AssetDiscoveryStatus::Failed,
                )
                .await;
            }
        }

        // Remove from running scans
        let mut running = state_clone.running_scans.write().await;
        running.remove(&scan_id_clone);
    });

    Ok(HttpResponse::Ok().json(StartDiscoveryResponse {
        id: scan_id,
        domain: req.domain.clone(),
        status: "running".to_string(),
        message: "Asset discovery scan started".to_string(),
    }))
}

/// Get all discovery scans for the current user
pub async fn list_scans(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<PaginationQuery>,
) -> Result<HttpResponse, ApiError> {
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let scans =
        asset_discovery::get_user_scans(pool.get_ref(), &claims.sub, limit as i64, offset as i64)
            .await?;

    let summaries: Vec<ScanSummary> = scans
        .into_iter()
        .map(|s| {
            let stats: crate::scanner::asset_discovery::DiscoveryStatistics =
                serde_json::from_str(&s.statistics).unwrap_or_default();
            ScanSummary {
                id: s.id,
                domain: s.domain,
                status: s.status,
                assets_count: stats.total_assets,
                created_at: s.created_at,
                completed_at: s.completed_at,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(ScanListResponse {
        total: summaries.len() as i64,
        scans: summaries,
    }))
}

#[derive(Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Get a specific discovery scan with its assets
pub async fn get_scan(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();

    let scan = asset_discovery::get_scan_by_id(pool.get_ref(), &scan_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Scan not found"))?;

    // Verify ownership
    if scan.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let assets = asset_discovery::get_scan_assets(pool.get_ref(), &scan_id).await?;

    let result = asset_discovery::row_to_result(scan, assets)?;

    Ok(HttpResponse::Ok().json(result))
}

/// Get assets for a specific scan
pub async fn get_scan_assets(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();

    // Verify scan exists and user has access
    let scan = asset_discovery::get_scan_by_id(pool.get_ref(), &scan_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Scan not found"))?;

    if scan.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let assets = asset_discovery::get_scan_assets(pool.get_ref(), &scan_id).await?;

    let converted: Vec<crate::scanner::asset_discovery::DiscoveredAsset> = assets
        .into_iter()
        .filter_map(|a| asset_discovery::row_to_asset(a).ok())
        .collect();

    Ok(HttpResponse::Ok().json(converted))
}

/// Cancel a running discovery scan
pub async fn cancel_scan(
    pool: web::Data<SqlitePool>,
    state: web::Data<DiscoveryState>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();

    // Verify scan exists and user has access
    let scan = asset_discovery::get_scan_by_id(pool.get_ref(), &scan_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Scan not found"))?;

    if scan.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    // Remove from running scans
    {
        let mut running = state.running_scans.write().await;
        running.remove(&scan_id);
    }

    // Update status
    asset_discovery::update_scan_status(pool.get_ref(), &scan_id, AssetDiscoveryStatus::Cancelled)
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Scan cancelled",
        "id": scan_id
    })))
}

/// Delete a discovery scan and its assets
pub async fn delete_scan(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();

    // Verify scan exists and user has access
    let scan = asset_discovery::get_scan_by_id(pool.get_ref(), &scan_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Scan not found"))?;

    if scan.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    asset_discovery::delete_scan(pool.get_ref(), &scan_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Scan deleted",
        "id": scan_id
    })))
}

/// Search assets across all scans
pub async fn search_assets(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<SearchQuery>,
) -> Result<HttpResponse, ApiError> {
    let search_query = query.q.clone().unwrap_or_default();
    let limit = query.limit.unwrap_or(50).min(200);

    let assets =
        asset_discovery::search_assets(pool.get_ref(), &claims.sub, &search_query, limit as i64)
            .await?;

    let converted: Vec<crate::scanner::asset_discovery::DiscoveredAsset> = assets
        .into_iter()
        .filter_map(|a| asset_discovery::row_to_asset(a).ok())
        .collect();

    Ok(HttpResponse::Ok().json(converted))
}

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
    pub limit: Option<usize>,
}

/// Configure routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/discovery")
            .route("", web::post().to(start_discovery))
            .route("/scans", web::get().to(list_scans))
            .route("/scans/{id}", web::get().to(get_scan))
            .route("/scans/{id}/assets", web::get().to(get_scan_assets))
            .route("/scans/{id}/cancel", web::post().to(cancel_scan))
            .route("/scans/{id}", web::delete().to(delete_scan))
            .route("/assets/search", web::get().to(search_assets)),
    );
}

/// Convert scanner discovered assets to CRM discovered assets
fn convert_to_crm_assets(
    assets: &[crate::scanner::asset_discovery::DiscoveredAsset],
    domain: &str,
    scan_id: &str,
) -> Vec<CrmDiscoveredAsset> {
    let mut crm_assets = Vec::new();

    // Add the main domain
    crm_assets.push(CrmDiscoveredAsset {
        asset_type: AssetType::Domain,
        value: domain.to_string(),
        source: "asset_discovery".to_string(),
        source_scan_id: Some(scan_id.to_string()),
        source_scan_type: Some("asset_discovery".to_string()),
        metadata: None,
    });

    for asset in assets {
        // Add subdomain
        if asset.hostname != domain && !asset.hostname.is_empty() {
            crm_assets.push(CrmDiscoveredAsset {
                asset_type: AssetType::Subdomain,
                value: asset.hostname.clone(),
                source: "asset_discovery".to_string(),
                source_scan_id: Some(scan_id.to_string()),
                source_scan_type: Some("asset_discovery".to_string()),
                metadata: Some(serde_json::json!({
                    "sources": asset.sources.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                    "tags": asset.tags,
                })),
            });
        }

        // Add IP addresses
        for ip in &asset.ip_addresses {
            crm_assets.push(CrmDiscoveredAsset {
                asset_type: AssetType::IpAddress,
                value: ip.to_string(),
                source: "asset_discovery".to_string(),
                source_scan_id: Some(scan_id.to_string()),
                source_scan_type: Some("asset_discovery".to_string()),
                metadata: Some(serde_json::json!({
                    "hostname": asset.hostname,
                    "asn": asset.asn,
                    "asn_org": asset.asn_org,
                    "country": asset.country,
                    "city": asset.city,
                })),
            });
        }

        // Add services (ports)
        for port in &asset.ports {
            crm_assets.push(CrmDiscoveredAsset {
                asset_type: AssetType::Service,
                value: format!("{}:{}/{}", asset.hostname, port.port, port.protocol),
                source: "asset_discovery".to_string(),
                source_scan_id: Some(scan_id.to_string()),
                source_scan_type: Some("asset_discovery".to_string()),
                metadata: Some(serde_json::json!({
                    "hostname": asset.hostname,
                    "port": port.port,
                    "protocol": port.protocol,
                    "service": port.service,
                    "version": port.version,
                    "banner": port.banner,
                })),
            });
        }

        // Add technologies
        for tech in &asset.technologies {
            crm_assets.push(CrmDiscoveredAsset {
                asset_type: AssetType::Technology,
                value: format!("{}:{}", asset.hostname, tech.name),
                source: "asset_discovery".to_string(),
                source_scan_id: Some(scan_id.to_string()),
                source_scan_type: Some("asset_discovery".to_string()),
                metadata: Some(serde_json::json!({
                    "hostname": asset.hostname,
                    "technology": tech.name,
                    "version": tech.version,
                    "category": tech.category,
                    "confidence": tech.confidence,
                })),
            });
        }

        // Add certificates
        for cert in &asset.certificates {
            crm_assets.push(CrmDiscoveredAsset {
                asset_type: AssetType::Certificate,
                value: cert.fingerprint_sha256.clone(),
                source: "asset_discovery".to_string(),
                source_scan_id: Some(scan_id.to_string()),
                source_scan_type: Some("asset_discovery".to_string()),
                metadata: Some(serde_json::json!({
                    "hostname": asset.hostname,
                    "subject": cert.subject,
                    "issuer": cert.issuer,
                    "valid_from": cert.valid_from,
                    "valid_to": cert.valid_to,
                    "sans": cert.sans,
                })),
            });
        }

        // Add DNS records
        for (record_type, values) in &asset.dns_records {
            for value in values {
                crm_assets.push(CrmDiscoveredAsset {
                    asset_type: AssetType::DnsRecord,
                    value: format!("{}:{}:{}", asset.hostname, record_type, value),
                    source: "asset_discovery".to_string(),
                    source_scan_id: Some(scan_id.to_string()),
                    source_scan_type: Some("asset_discovery".to_string()),
                    metadata: Some(serde_json::json!({
                        "hostname": asset.hostname,
                        "record_type": record_type,
                        "value": value,
                    })),
                });
            }
        }
    }

    crm_assets
}
