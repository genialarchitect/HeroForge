//! IoT (Internet of Things) Security API endpoints
//!
//! Provides endpoints for:
//! - IoT device management (cameras, thermostats, routers, etc.)
//! - Device discovery (mDNS, SSDP, MQTT broker scanning)
//! - Default credential checking
//! - IoT-specific vulnerability assessment

use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;

use crate::db::iot::{
    self, CreateIotDeviceRequest, CreateIotScanRequest, ListIotDevicesQuery, ListIotScansQuery,
    SearchCredentialsQuery, UpdateIotDeviceRequest,
};
use crate::web::auth;

// ============================================================================
// Device Endpoints
// ============================================================================

/// Get all IoT devices
pub async fn get_devices(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ListIotDevicesQuery>,
) -> Result<HttpResponse> {
    let devices = iot::list_iot_devices(&pool, &claims.sub, &query)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch IoT devices: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch devices")
        })?;

    Ok(HttpResponse::Ok().json(devices))
}

/// Get a specific IoT device
pub async fn get_device(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    device_id: web::Path<String>,
) -> Result<HttpResponse> {
    match iot::get_iot_device_by_id(&pool, &device_id, &claims.sub).await {
        Ok(device) => Ok(HttpResponse::Ok().json(device)),
        Err(e) => {
            log::error!("Failed to fetch IoT device: {}", e);
            Err(actix_web::error::ErrorNotFound("Device not found"))
        }
    }
}

/// Create a new IoT device
pub async fn create_device(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateIotDeviceRequest>,
) -> Result<HttpResponse> {
    let device = iot::create_iot_device(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to create IoT device: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create device")
        })?;

    Ok(HttpResponse::Created().json(device))
}

/// Update an IoT device
pub async fn update_device(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    device_id: web::Path<String>,
    request: web::Json<UpdateIotDeviceRequest>,
) -> Result<HttpResponse> {
    let device = iot::update_iot_device(&pool, &device_id, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to update IoT device: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to update device")
        })?;

    Ok(HttpResponse::Ok().json(device))
}

/// Delete an IoT device
pub async fn delete_device(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    device_id: web::Path<String>,
) -> Result<HttpResponse> {
    iot::delete_iot_device(&pool, &device_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete IoT device: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete device")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Device deleted" })))
}

// ============================================================================
// Scan Endpoints
// ============================================================================

/// Start an IoT scan
pub async fn start_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateIotScanRequest>,
) -> Result<HttpResponse> {
    let scan = iot::create_iot_scan(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to create IoT scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create scan")
        })?;

    // TODO: Spawn async scan task here
    // For now, just return the scan record

    Ok(HttpResponse::Accepted().json(scan))
}

/// Get all IoT scans
pub async fn get_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ListIotScansQuery>,
) -> Result<HttpResponse> {
    let scans = iot::list_iot_scans(&pool, &claims.sub, &query)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch IoT scans: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch scans")
        })?;

    Ok(HttpResponse::Ok().json(scans))
}

/// Get a specific IoT scan
pub async fn get_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    match iot::get_iot_scan_by_id(&pool, &scan_id, &claims.sub).await {
        Ok(scan) => Ok(HttpResponse::Ok().json(scan)),
        Err(e) => {
            log::error!("Failed to fetch IoT scan: {}", e);
            Err(actix_web::error::ErrorNotFound("Scan not found"))
        }
    }
}

// ============================================================================
// Credential Endpoints
// ============================================================================

/// Search default credentials database
pub async fn search_credentials(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<SearchCredentialsQuery>,
) -> Result<HttpResponse> {
    let credentials = iot::search_iot_credentials(&pool, &query)
        .await
        .map_err(|e| {
            log::error!("Failed to search credentials: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to search credentials")
        })?;

    Ok(HttpResponse::Ok().json(credentials))
}

// ============================================================================
// Dashboard Endpoint
// ============================================================================

/// Get IoT dashboard statistics
pub async fn get_dashboard(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let stats = iot::get_iot_dashboard_stats(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch IoT dashboard stats: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch dashboard stats")
        })?;

    Ok(HttpResponse::Ok().json(stats))
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/iot")
            // Device endpoints
            .route("/devices", web::get().to(get_devices))
            .route("/devices", web::post().to(create_device))
            .route("/devices/{id}", web::get().to(get_device))
            .route("/devices/{id}", web::put().to(update_device))
            .route("/devices/{id}", web::delete().to(delete_device))
            // Scan endpoints
            .route("/scan", web::post().to(start_scan))
            .route("/scans", web::get().to(get_scans))
            .route("/scans/{id}", web::get().to(get_scan))
            // Credential endpoints
            .route("/credentials/search", web::get().to(search_credentials))
            // Dashboard
            .route("/dashboard", web::get().to(get_dashboard)),
    );
}
