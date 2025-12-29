//! Wireless Security API Endpoints
//!
//! REST API for wireless security assessment including network discovery,
//! handshake capture, and password cracking.

#![allow(dead_code)]

use actix_web::{web, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::scanner::wireless::{
    WirelessManager, WirelessScanner, HandshakeCapturer,
    DeauthAttack, AircrackCracker, WpsAttack,
    WirelessScanConfig, CaptureConfig, DeauthConfig, StartScanRequest,
    DeauthRequest, CaptureRequest, CrackRequest, WpsAttackRequest,
};
use crate::web::auth;
use crate::web::error::ApiError;

/// Wireless state for active operations
pub struct WirelessState {
    pub active_scans: Arc<Mutex<std::collections::HashMap<String, tokio::task::JoinHandle<()>>>>,
}

impl Default for WirelessState {
    fn default() -> Self {
        Self {
            active_scans: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
}

/// Configure wireless routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/wireless")
            // Dashboard
            .route("/dashboard", web::get().to(get_dashboard))
            // Interfaces
            .route("/interfaces", web::get().to(list_interfaces))
            .route("/interfaces/{name}/monitor", web::post().to(enable_monitor_mode))
            .route("/interfaces/{name}/managed", web::post().to(disable_monitor_mode))
            // Scans
            .route("/scans", web::post().to(start_scan))
            .route("/scans", web::get().to(list_scans))
            .route("/scans/{id}", web::get().to(get_scan))
            .route("/scans/{id}", web::delete().to(stop_scan))
            // Networks
            .route("/networks", web::get().to(list_networks))
            .route("/networks/{bssid}", web::get().to(get_network))
            // Attacks
            .route("/deauth", web::post().to(send_deauth))
            .route("/capture/handshake", web::post().to(capture_handshake))
            .route("/capture/pmkid", web::post().to(capture_pmkid))
            .route("/wps/pixie-dust", web::post().to(wps_pixie_dust))
            // Captures
            .route("/handshakes", web::get().to(list_handshakes))
            .route("/handshakes/{id}/crack", web::post().to(crack_handshake))
            .route("/pmkids", web::get().to(list_pmkids))
            // Wordlists
            .route("/wordlists", web::get().to(list_wordlists)),
    );
}

#[derive(Deserialize)]
struct ListQuery {
    limit: Option<i32>,
    offset: Option<i32>,
}

// ============================================================================
// Dashboard
// ============================================================================

async fn get_dashboard(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let manager = WirelessManager::new(pool.get_ref().clone());
    let stats = manager.get_dashboard_stats(&claims.sub).await?;
    Ok(HttpResponse::Ok().json(stats))
}

// ============================================================================
// Interfaces
// ============================================================================

async fn list_interfaces(
    _claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let interfaces = WirelessScanner::list_interfaces().await
        .map_err(|e| ApiError::internal(format!("Failed to list interfaces: {}", e)))?;
    Ok(HttpResponse::Ok().json(interfaces))
}

async fn enable_monitor_mode(
    path: web::Path<String>,
    _claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let interface = path.into_inner();
    let monitor_interface = WirelessScanner::enable_monitor_mode(&interface).await
        .map_err(|e| ApiError::bad_request(format!("Failed to enable monitor mode: {}", e)))?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "interface": monitor_interface,
        "message": "Monitor mode enabled"
    })))
}

async fn disable_monitor_mode(
    path: web::Path<String>,
    _claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let interface = path.into_inner();
    WirelessScanner::disable_monitor_mode(&interface).await
        .map_err(|e| ApiError::bad_request(format!("Failed to disable monitor mode: {}", e)))?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Monitor mode disabled"
    })))
}

// ============================================================================
// Scans
// ============================================================================

async fn start_scan(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<StartScanRequest>,
) -> Result<HttpResponse, ApiError> {
    let manager = WirelessManager::new(pool.get_ref().clone());

    let config = WirelessScanConfig {
        interface: body.interface.clone(),
        channels: body.channels.clone(),
        duration_secs: body.duration_secs.unwrap_or(60),
        ..Default::default()
    };

    let scan = manager.create_scan(
        &claims.sub,
        config.clone(),
        body.customer_id.as_deref(),
        body.engagement_id.as_deref(),
    ).await?;

    // Start scan in background
    let scan_id = scan.id.clone();
    let user_id = claims.sub.clone();
    let pool_clone = pool.get_ref().clone();
    let interface = config.interface.clone();
    let duration = config.duration_secs;

    tokio::spawn(async move {
        let scanner = WirelessScanner::new(&interface);

        // Update scan status to running
        let _ = sqlx::query("UPDATE wireless_scans SET status = 'running' WHERE id = ?")
            .bind(&scan_id)
            .execute(&pool_clone)
            .await;

        // Perform scan
        match scanner.scan_networks(duration).await {
            Ok(networks) => {
                let manager = WirelessManager::new(pool_clone.clone());

                // Save discovered networks
                for network in &networks {
                    let _ = manager.save_network(&user_id, network).await;
                }

                // Update scan with results
                let _ = sqlx::query(
                    "UPDATE wireless_scans SET status = 'success', networks_found = ?, completed_at = ? WHERE id = ?"
                )
                .bind(networks.len() as i32)
                .bind(chrono::Utc::now().to_rfc3339())
                .bind(&scan_id)
                .execute(&pool_clone)
                .await;
            }
            Err(e) => {
                log::error!("Wireless scan failed: {}", e);
                let _ = sqlx::query(
                    "UPDATE wireless_scans SET status = 'failed', completed_at = ? WHERE id = ?"
                )
                .bind(chrono::Utc::now().to_rfc3339())
                .bind(&scan_id)
                .execute(&pool_clone)
                .await;
            }
        }
    });

    Ok(HttpResponse::Created().json(scan))
}

async fn list_scans(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    _query: web::Query<ListQuery>,
) -> Result<HttpResponse, ApiError> {
    let manager = WirelessManager::new(pool.get_ref().clone());
    let scans = manager.list_scans(&claims.sub).await?;
    Ok(HttpResponse::Ok().json(scans))
}

async fn get_scan(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();
    let scans = sqlx::query_as::<_, (String, String)>(
        "SELECT id, user_id FROM wireless_scans WHERE id = ? AND user_id = ?"
    )
    .bind(&scan_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await?;

    match scans {
        Some(_) => {
            let manager = WirelessManager::new(pool.get_ref().clone());
            let all_scans = manager.list_scans(&claims.sub).await?;
            let scan = all_scans.into_iter().find(|s| s.id == scan_id);
            match scan {
                Some(s) => Ok(HttpResponse::Ok().json(s)),
                None => Err(ApiError::not_found("Scan not found")),
            }
        }
        None => Err(ApiError::not_found("Scan not found")),
    }
}

async fn stop_scan(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();

    sqlx::query(
        "UPDATE wireless_scans SET status = 'cancelled', completed_at = ? WHERE id = ? AND user_id = ?"
    )
    .bind(chrono::Utc::now().to_rfc3339())
    .bind(&scan_id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Scan stopped"
    })))
}

// ============================================================================
// Networks
// ============================================================================

async fn list_networks(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    _query: web::Query<ListQuery>,
) -> Result<HttpResponse, ApiError> {
    let manager = WirelessManager::new(pool.get_ref().clone());
    let networks = manager.list_networks(&claims.sub).await?;
    Ok(HttpResponse::Ok().json(networks))
}

async fn get_network(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let bssid = path.into_inner();
    let manager = WirelessManager::new(pool.get_ref().clone());
    let networks = manager.list_networks(&claims.sub).await?;
    let network = networks.into_iter().find(|n| n.bssid == bssid);

    match network {
        Some(n) => Ok(HttpResponse::Ok().json(n)),
        None => Err(ApiError::not_found("Network not found")),
    }
}

// ============================================================================
// Attacks
// ============================================================================

async fn send_deauth(
    _claims: auth::Claims,
    body: web::Json<DeauthRequest>,
) -> Result<HttpResponse, ApiError> {
    let config = DeauthConfig {
        interface: body.interface.clone(),
        bssid: body.bssid.clone(),
        client: body.client.clone(),
        count: body.count.unwrap_or(5),
        reason_code: 7, // Class 3 frame received from nonassociated STA
    };

    let attack = DeauthAttack::new(&config.interface);
    let result = attack.execute(&config).await
        .map_err(|e| ApiError::internal(format!("Deauth attack failed: {}", e)))?;

    Ok(HttpResponse::Ok().json(result))
}

async fn capture_handshake(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CaptureRequest>,
) -> Result<HttpResponse, ApiError> {
    let config = CaptureConfig {
        interface: body.interface.clone(),
        bssid: body.bssid.clone(),
        channel: body.channel,
        timeout_secs: body.timeout_secs.unwrap_or(120),
        deauth_enabled: body.use_deauth.unwrap_or(true),
        deauth_count: 5,
    };

    let capturer = HandshakeCapturer::new(&config.interface);
    let handshake = capturer.capture_handshake(&config, None).await
        .map_err(|e| ApiError::internal(format!("Handshake capture failed: {}", e)))?;

    // Save to database
    let manager = WirelessManager::new(pool.get_ref().clone());
    manager.save_handshake(&claims.sub, &handshake).await?;

    Ok(HttpResponse::Ok().json(handshake))
}

async fn capture_pmkid(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CaptureRequest>,
) -> Result<HttpResponse, ApiError> {
    let capturer = HandshakeCapturer::new(&body.interface);
    let pmkid = capturer
        .capture_pmkid(&body.bssid, body.channel, body.timeout_secs.unwrap_or(60))
        .await
        .map_err(|e| ApiError::internal(format!("PMKID capture failed: {}", e)))?;

    match pmkid {
        Some(p) => {
            let manager = WirelessManager::new(pool.get_ref().clone());
            manager.save_pmkid(&claims.sub, &p).await?;
            Ok(HttpResponse::Ok().json(p))
        }
        None => Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "message": "No PMKID captured"
        }))),
    }
}

async fn wps_pixie_dust(
    _claims: auth::Claims,
    body: web::Json<WpsAttackRequest>,
) -> Result<HttpResponse, ApiError> {
    let attack = WpsAttack::new(&body.interface);
    let result = attack.pixie_dust(&body.bssid, 300).await
        .map_err(|e| ApiError::internal(format!("WPS attack failed: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": result.success,
        "pin": result.pin,
        "psk": result.psk,
        "error": result.error
    })))
}

// ============================================================================
// Captures
// ============================================================================

async fn list_handshakes(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    _query: web::Query<ListQuery>,
) -> Result<HttpResponse, ApiError> {
    let manager = WirelessManager::new(pool.get_ref().clone());
    let handshakes = manager.list_handshakes(&claims.sub).await?;
    Ok(HttpResponse::Ok().json(handshakes))
}

async fn crack_handshake(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: auth::Claims,
    body: web::Json<CrackRequest>,
) -> Result<HttpResponse, ApiError> {
    let handshake_id = path.into_inner();

    // Get handshake details
    let handshake: Option<(String, String)> = sqlx::query_as(
        "SELECT id, capture_file FROM wireless_handshakes WHERE id = ? AND user_id = ?"
    )
    .bind(&handshake_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await?;

    let (_, capture_file) = handshake
        .ok_or_else(|| ApiError::not_found("Handshake not found"))?;

    // Start cracking
    let cracker = if let Some(ref wl) = body.wordlist {
        AircrackCracker::with_wordlist(wl)
    } else {
        AircrackCracker::new()
    };

    let result = cracker.crack_handshake(&capture_file, None, None).await
        .map_err(|e| ApiError::internal(format!("Cracking failed: {}", e)))?;

    // Update database if cracked
    if let Some(ref password) = result.password {
        let manager = WirelessManager::new(pool.get_ref().clone());
        manager.update_handshake_cracked(&handshake_id, password).await?;
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": format!("{:?}", result.status),
        "password": result.password,
        "keys_tested": result.keys_tested,
        "keys_per_second": result.keys_per_second
    })))
}

async fn list_pmkids(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    _query: web::Query<ListQuery>,
) -> Result<HttpResponse, ApiError> {
    let rows: Vec<(String, String, String, String, String, bool, Option<String>, String)> = sqlx::query_as(
        "SELECT id, bssid, ssid, pmkid, capture_file, cracked, password, captured_at
         FROM wireless_pmkids WHERE user_id = ? ORDER BY captured_at DESC"
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await?;

    let pmkids: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(id, bssid, ssid, pmkid, capture_file, cracked, password, captured_at)| {
            serde_json::json!({
                "id": id,
                "bssid": bssid,
                "ssid": ssid,
                "pmkid": pmkid,
                "capture_file": capture_file,
                "cracked": cracked,
                "password": password,
                "captured_at": captured_at
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(pmkids))
}

// ============================================================================
// Wordlists
// ============================================================================

async fn list_wordlists(
    _claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let wordlists = AircrackCracker::list_wordlists().await;
    Ok(HttpResponse::Ok().json(wordlists))
}
