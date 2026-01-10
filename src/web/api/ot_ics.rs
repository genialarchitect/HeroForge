//! OT/ICS (Operational Technology / Industrial Control Systems) API endpoints
//!
//! Provides endpoints for:
//! - OT asset management (PLC, HMI, SCADA, RTU, etc.)
//! - Protocol scanning (Modbus, DNP3, OPC UA, BACnet, EtherNet/IP, S7)
//! - Purdue Model network segmentation analysis
//! - OT-specific vulnerability assessment

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::ot_ics::{
    self, CreateOtAssetRequest, CreateOtScanRequest, ListOtAssetsQuery, ListOtScansQuery,
    UpdateOtAssetRequest,
};
use crate::ot_ics::purdue::{analyze_purdue_compliance, build_purdue_view, classify_asset, PurdueLevel};
use crate::web::auth;

// ============================================================================
// Asset Endpoints
// ============================================================================

/// Get all OT assets
pub async fn get_assets(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ListOtAssetsQuery>,
) -> Result<HttpResponse> {
    let assets = ot_ics::list_ot_assets(&pool, &claims.sub, &query)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch OT assets: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch assets")
        })?;

    Ok(HttpResponse::Ok().json(assets))
}

/// Get a specific OT asset
pub async fn get_asset(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    asset_id: web::Path<String>,
) -> Result<HttpResponse> {
    match ot_ics::get_ot_asset_by_id(&pool, &asset_id, &claims.sub).await {
        Ok(asset) => Ok(HttpResponse::Ok().json(asset)),
        Err(e) => {
            log::error!("Failed to fetch OT asset: {}", e);
            Err(actix_web::error::ErrorNotFound("Asset not found"))
        }
    }
}

/// Create a new OT asset
pub async fn create_asset(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateOtAssetRequest>,
) -> Result<HttpResponse> {
    let asset = ot_ics::create_ot_asset(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to create OT asset: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create asset")
        })?;

    Ok(HttpResponse::Created().json(asset))
}

/// Update an OT asset
pub async fn update_asset(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    asset_id: web::Path<String>,
    request: web::Json<UpdateOtAssetRequest>,
) -> Result<HttpResponse> {
    let asset = ot_ics::update_ot_asset(&pool, &asset_id, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to update OT asset: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to update asset")
        })?;

    Ok(HttpResponse::Ok().json(asset))
}

/// Delete an OT asset
pub async fn delete_asset(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    asset_id: web::Path<String>,
) -> Result<HttpResponse> {
    ot_ics::delete_ot_asset(&pool, &asset_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete OT asset: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete asset")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Asset deleted" })))
}

// ============================================================================
// Scan Endpoints
// ============================================================================

/// Start an OT scan
pub async fn start_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateOtScanRequest>,
) -> Result<HttpResponse> {
    let scan = ot_ics::create_ot_scan(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to create OT scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create scan")
        })?;

    // Spawn async scan task
    let scan_id = scan.id.clone();
    let target_range = request.target_range.clone();
    let protocols: Vec<crate::ot_ics::types::OtProtocolType> = request.protocols_enabled
        .as_ref()
        .map(|p| p.iter().filter_map(|s| s.parse().ok()).collect())
        .unwrap_or_default();
    let pool_clone = pool.get_ref().clone();

    tokio::spawn(async move {
        log::info!("Starting OT scan {} for network {}", scan_id, target_range);

        // Update status to running
        if let Err(e) = ot_ics::update_ot_scan_status(&pool_clone, &scan_id, "running", None).await {
            log::error!("Failed to update scan status to running: {}", e);
            return;
        }

        // Parse target network into IPs
        let targets: Vec<std::net::IpAddr> = match parse_target_network(&target_range) {
            Ok(ips) => ips,
            Err(e) => {
                log::error!("Failed to parse target network: {}", e);
                let _ = ot_ics::update_ot_scan_status(&pool_clone, &scan_id, "failed", Some(&e.to_string())).await;
                return;
            }
        };

        // Run discovery
        let engine = crate::ot_ics::OtDiscoveryEngine::default();
        match engine.discover(&targets, &protocols).await {
            Ok(discovered) => {
                let asset_count = discovered.len() as i32;
                let vuln_count = discovered.iter()
                    .flat_map(|a| &a.scan_results)
                    .map(|r| r.security_issues.len())
                    .sum::<usize>() as i32;

                // Update scan results
                if let Err(e) = ot_ics::update_ot_scan_results(&pool_clone, &scan_id, asset_count, vuln_count).await {
                    log::error!("Failed to update scan results: {}", e);
                }

                // Mark as completed
                if let Err(e) = ot_ics::update_ot_scan_status(&pool_clone, &scan_id, "completed", None).await {
                    log::error!("Failed to update scan status to completed: {}", e);
                }

                log::info!("OT scan {} completed: {} assets discovered, {} vulnerabilities", scan_id, asset_count, vuln_count);
            }
            Err(e) => {
                log::error!("OT scan {} failed: {}", scan_id, e);
                let _ = ot_ics::update_ot_scan_status(&pool_clone, &scan_id, "failed", Some(&e.to_string())).await;
            }
        }
    });

    Ok(HttpResponse::Accepted().json(scan))
}

/// Parse target network string into IP addresses
fn parse_target_network(network: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
    let mut ips = Vec::new();

    // Try parsing as CIDR
    if let Ok(network) = network.parse::<ipnetwork::IpNetwork>() {
        for ip in network.iter().take(256) {  // Limit to 256 for safety
            ips.push(ip);
        }
    } else if let Ok(ip) = network.parse::<std::net::IpAddr>() {
        // Single IP
        ips.push(ip);
    } else {
        // Try parsing as IP range (e.g., "192.168.1.1-192.168.1.10")
        if let Some((start, end)) = network.split_once('-') {
            let start_ip: std::net::Ipv4Addr = start.trim().parse()?;
            let end_ip: std::net::Ipv4Addr = end.trim().parse()?;

            let start_u32 = u32::from(start_ip);
            let end_u32 = u32::from(end_ip);

            for ip_u32 in start_u32..=end_u32.min(start_u32 + 255) {
                ips.push(std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip_u32)));
            }
        } else {
            anyhow::bail!("Invalid network format: {}", network);
        }
    }

    Ok(ips)
}

/// Get all OT scans
pub async fn get_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ListOtScansQuery>,
) -> Result<HttpResponse> {
    let scans = ot_ics::list_ot_scans(&pool, &claims.sub, &query)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch OT scans: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch scans")
        })?;

    Ok(HttpResponse::Ok().json(scans))
}

/// Get a specific OT scan
pub async fn get_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    match ot_ics::get_ot_scan_by_id(&pool, &scan_id, &claims.sub).await {
        Ok(scan) => Ok(HttpResponse::Ok().json(scan)),
        Err(e) => {
            log::error!("Failed to fetch OT scan: {}", e);
            Err(actix_web::error::ErrorNotFound("Scan not found"))
        }
    }
}

// ============================================================================
// Purdue Model Endpoints
// ============================================================================

/// Purdue level info for API response
#[derive(Debug, Serialize)]
pub struct PurdueLevelInfo {
    pub level: i32,
    pub name: String,
    pub description: String,
    pub typical_systems: Vec<String>,
}

/// Get all Purdue Model levels
pub async fn get_purdue_levels(
    _pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let levels: Vec<PurdueLevelInfo> = PurdueLevel::all_levels()
        .into_iter()
        .map(|l| PurdueLevelInfo {
            level: l.level,
            name: l.name,
            description: l.description,
            typical_systems: l.typical_systems,
        })
        .collect();

    // Add DMZ
    let dmz = PurdueLevel::get_dmz();
    let mut all_levels = levels;
    all_levels.push(PurdueLevelInfo {
        level: dmz.level,
        name: dmz.name,
        description: dmz.description,
        typical_systems: dmz.typical_systems,
    });

    Ok(HttpResponse::Ok().json(all_levels))
}

/// Get Purdue Model view with asset classification
pub async fn get_purdue_view(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ListOtAssetsQuery>,
) -> Result<HttpResponse> {
    // Get all assets for analysis
    let assets = ot_ics::list_ot_assets(
        &pool,
        &claims.sub,
        &ListOtAssetsQuery {
            asset_type: None,
            purdue_level: None,
            criticality: None,
            customer_id: query.customer_id.clone(),
            limit: Some(1000),
            offset: Some(0),
        },
    )
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assets for Purdue view: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch assets")
    })?;

    let view = build_purdue_view(&assets);
    Ok(HttpResponse::Ok().json(view))
}

/// Get Purdue Model compliance analysis
pub async fn get_purdue_compliance(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ListOtAssetsQuery>,
) -> Result<HttpResponse> {
    // Get all assets for analysis
    let assets = ot_ics::list_ot_assets(
        &pool,
        &claims.sub,
        &ListOtAssetsQuery {
            asset_type: None,
            purdue_level: None,
            criticality: None,
            customer_id: query.customer_id.clone(),
            limit: Some(1000),
            offset: Some(0),
        },
    )
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assets for compliance: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch assets")
    })?;

    let recommendations = analyze_purdue_compliance(&assets);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "total_assets": assets.len(),
        "recommendations": recommendations,
    })))
}

/// Asset classification request
#[derive(Debug, Deserialize)]
pub struct ClassifyAssetRequest {
    pub asset_type: String,
    pub protocols: Vec<String>,
}

/// Classify an asset into a Purdue level
pub async fn classify_purdue_level(
    _pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    request: web::Json<ClassifyAssetRequest>,
) -> Result<HttpResponse> {
    use crate::ot_ics::types::{OtAssetType, OtProtocolType};

    let asset_type: OtAssetType = request.asset_type.parse().unwrap_or(OtAssetType::Unknown);
    let protocols: Vec<OtProtocolType> = request
        .protocols
        .iter()
        .filter_map(|p| p.parse().ok())
        .collect();

    let level = classify_asset(&asset_type, &protocols);
    let level_info = PurdueLevel::get_level(level);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "level": level,
        "level_info": level_info,
    })))
}

// ============================================================================
// Dashboard Endpoint
// ============================================================================

/// Get OT dashboard statistics
pub async fn get_dashboard(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let stats = ot_ics::get_ot_dashboard_stats(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch OT dashboard stats: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch dashboard stats")
        })?;

    Ok(HttpResponse::Ok().json(stats))
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/ot")
            // Asset endpoints
            .route("/assets", web::get().to(get_assets))
            .route("/assets", web::post().to(create_asset))
            .route("/assets/{id}", web::get().to(get_asset))
            .route("/assets/{id}", web::put().to(update_asset))
            .route("/assets/{id}", web::delete().to(delete_asset))
            // Scan endpoints
            .route("/scan", web::post().to(start_scan))
            .route("/scans", web::get().to(get_scans))
            .route("/scans/{id}", web::get().to(get_scan))
            // Purdue Model endpoints
            .route("/purdue/levels", web::get().to(get_purdue_levels))
            .route("/purdue/view", web::get().to(get_purdue_view))
            .route("/purdue/compliance", web::get().to(get_purdue_compliance))
            .route("/purdue/classify", web::post().to(classify_purdue_level))
            // Dashboard
            .route("/dashboard", web::get().to(get_dashboard)),
    );
}
