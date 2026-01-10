use actix_web::{web, HttpResponse};
use log::{error, info};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashSet;
use tokio::sync::RwLock;

use crate::db::privesc;
use crate::scanner::privesc::{
    run_privesc_scan, OsType, PrivescConfig, PrivescStatus,
};
use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;

/// State for tracking running privesc scans
pub struct PrivescState {
    pub running_scans: RwLock<HashSet<String>>,
}

impl Default for PrivescState {
    fn default() -> Self {
        Self {
            running_scans: RwLock::new(HashSet::new()),
        }
    }
}

/// Request to start a new privesc scan
#[derive(Debug, Deserialize)]
pub struct StartPrivescRequest {
    pub target: String,
    pub os_type: String, // "linux" or "windows"
    pub ssh_username: Option<String>,
    pub ssh_password: Option<String>,
    pub ssh_key_path: Option<String>,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    pub winrm_username: Option<String>,
    pub winrm_password: Option<String>,
    #[serde(default = "default_winrm_port")]
    pub winrm_port: u16,
    #[serde(default)]
    pub winrm_https: bool,
    #[serde(default = "default_true")]
    pub run_peas: bool,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

fn default_ssh_port() -> u16 {
    22
}

fn default_winrm_port() -> u16 {
    5985
}

fn default_true() -> bool {
    true
}

fn default_timeout() -> u64 {
    300
}

/// Response for scan creation
#[derive(Serialize)]
pub struct StartPrivescResponse {
    pub id: String,
    pub target: String,
    pub os_type: String,
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
    pub target: String,
    pub os_type: String,
    pub status: String,
    pub findings_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub created_at: String,
    pub completed_at: Option<String>,
}

/// Start a new privilege escalation scan
pub async fn start_scan(
    pool: web::Data<SqlitePool>,
    state: web::Data<PrivescState>,
    claims: Claims,
    req: web::Json<StartPrivescRequest>,
) -> Result<HttpResponse, ApiError> {
    info!(
        "User {} starting privesc scan for target: {}",
        claims.sub, req.target
    );

    // Validate target
    if req.target.is_empty() {
        return Err(ApiError::bad_request("Target is required"));
    }

    // Parse OS type
    let os_type = match req.os_type.to_lowercase().as_str() {
        "linux" => OsType::Linux,
        "windows" => OsType::Windows,
        _ => return Err(ApiError::bad_request("Invalid OS type. Use 'linux' or 'windows'")),
    };

    // Build config
    let config = PrivescConfig {
        target: req.target.clone(),
        os_type,
        ssh_username: req.ssh_username.clone(),
        ssh_password: req.ssh_password.clone(),
        ssh_key_path: req.ssh_key_path.clone(),
        ssh_port: req.ssh_port,
        winrm_username: req.winrm_username.clone(),
        winrm_password: req.winrm_password.clone(),
        winrm_port: req.winrm_port,
        winrm_https: req.winrm_https,
        run_peas: req.run_peas,
        custom_checks: Vec::new(),
        timeout_secs: req.timeout_secs,
    };

    // Create scan record in database
    let scan_id = privesc::create_privesc_scan(
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

    // Spawn background task for scan
    let pool_clone = pool.get_ref().clone();
    let scan_id_clone = scan_id.clone();
    let state_clone = state.clone();

    tokio::spawn(async move {
        // Update status to running
        let _ = privesc::update_scan_status(&pool_clone, &scan_id_clone, PrivescStatus::Running).await;

        // Run scan
        let result = run_privesc_scan(config).await;

        match result {
            Ok(mut privesc_result) => {
                privesc_result.id = scan_id_clone.clone();
                privesc_result.status = PrivescStatus::Completed;

                // Save results
                if let Err(e) = privesc::save_scan_results(&pool_clone, &privesc_result).await {
                    error!("Failed to save privesc results: {}", e);
                }
            }
            Err(e) => {
                error!("Privesc scan failed: {}", e);
                let _ = privesc::update_scan_status(
                    &pool_clone,
                    &scan_id_clone,
                    PrivescStatus::Failed,
                )
                .await;
            }
        }

        // Remove from running scans
        let mut running = state_clone.running_scans.write().await;
        running.remove(&scan_id_clone);
    });

    let os_type_str = match os_type {
        OsType::Linux => "linux",
        OsType::Windows => "windows",
    };

    Ok(HttpResponse::Ok().json(StartPrivescResponse {
        id: scan_id,
        target: req.target.clone(),
        os_type: os_type_str.to_string(),
        status: "running".to_string(),
        message: "Privilege escalation scan started".to_string(),
    }))
}

/// Pagination query parameters
#[derive(Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Get all privesc scans for the current user
pub async fn list_scans(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<PaginationQuery>,
) -> Result<HttpResponse, ApiError> {
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let scans = privesc::get_user_scans(pool.get_ref(), &claims.sub, limit as i64, offset as i64)
        .await?;

    let summaries: Vec<ScanSummary> = scans
        .into_iter()
        .map(|s| {
            let stats: crate::scanner::privesc::PrivescStatistics =
                serde_json::from_str(&s.statistics).unwrap_or_default();
            ScanSummary {
                id: s.id,
                target: s.target,
                os_type: s.os_type,
                status: s.status,
                findings_count: stats.total_findings,
                critical_count: stats.critical_findings,
                high_count: stats.high_findings,
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

/// Get a specific privesc scan with its findings
pub async fn get_scan(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();

    let scan = privesc::get_scan_by_id(pool.get_ref(), &scan_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Scan not found"))?;

    // Verify ownership
    if scan.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let findings = privesc::get_scan_findings(pool.get_ref(), &scan_id).await?;
    let result = privesc::row_to_result(scan, findings)?;

    Ok(HttpResponse::Ok().json(result))
}

/// Get findings for a specific scan
pub async fn get_scan_findings(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();

    // Verify scan exists and user has access
    let scan = privesc::get_scan_by_id(pool.get_ref(), &scan_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Scan not found"))?;

    if scan.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let findings = privesc::get_scan_findings(pool.get_ref(), &scan_id).await?;
    let converted: Vec<crate::scanner::privesc::PrivescFinding> = findings
        .into_iter()
        .filter_map(|f| privesc::row_to_finding(f).ok())
        .collect();

    Ok(HttpResponse::Ok().json(converted))
}

/// Cancel a running privesc scan
pub async fn cancel_scan(
    pool: web::Data<SqlitePool>,
    state: web::Data<PrivescState>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();

    // Verify scan exists and user has access
    let scan = privesc::get_scan_by_id(pool.get_ref(), &scan_id)
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
    privesc::update_scan_status(pool.get_ref(), &scan_id, PrivescStatus::Cancelled).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Scan cancelled",
        "id": scan_id
    })))
}

/// Delete a privesc scan and its findings
pub async fn delete_scan(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();

    // Verify scan exists and user has access
    let scan = privesc::get_scan_by_id(pool.get_ref(), &scan_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Scan not found"))?;

    if scan.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    privesc::delete_scan(pool.get_ref(), &scan_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Scan deleted",
        "id": scan_id
    })))
}

/// Get GTFOBins information for a binary
pub async fn get_gtfobins(
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let binary = path.into_inner();

    if let Some(entry) = crate::scanner::privesc::lookup_gtfobins(&binary) {
        Ok(HttpResponse::Ok().json(entry))
    } else {
        Err(ApiError::not_found("Binary not found in GTFOBins"))
    }
}

/// Get LOLBAS information for a binary
pub async fn get_lolbas(
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let binary = path.into_inner();

    if let Some(entry) = crate::scanner::privesc::lookup_lolbas(&binary) {
        Ok(HttpResponse::Ok().json(entry))
    } else {
        Err(ApiError::not_found("Binary not found in LOLBAS"))
    }
}

/// Configure routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/privesc")
            .route("", web::post().to(start_scan))
            .route("/scans", web::get().to(list_scans))
            .route("/scans/{id}", web::get().to(get_scan))
            .route("/scans/{id}/findings", web::get().to(get_scan_findings))
            .route("/scans/{id}/cancel", web::post().to(cancel_scan))
            .route("/scans/{id}", web::delete().to(delete_scan))
            .route("/gtfobins/{binary}", web::get().to(get_gtfobins))
            .route("/lolbas/{binary}", web::get().to(get_lolbas)),
    );
}
