//! Health check endpoints

use actix_web::{web, HttpResponse, Result};
use serde::{Serialize, Deserialize};
use sqlx::SqlitePool;
use chrono::Utc;
use std::sync::OnceLock;
use std::time::Instant;

/// Application start time for uptime tracking
static APP_START_TIME: OnceLock<Instant> = OnceLock::new();

/// Initialize the application start time (call once at startup)
pub fn init_start_time() {
    APP_START_TIME.get_or_init(Instant::now);
}

/// Get the current uptime in seconds
fn get_uptime_seconds() -> u64 {
    APP_START_TIME
        .get()
        .map(|start| start.elapsed().as_secs())
        .unwrap_or(0)
}

/// Check disk space availability
fn check_disk_space() -> CheckStatus {
    // Try to get disk space info for the current working directory
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::mem::MaybeUninit;

        let path = CString::new(".").unwrap_or_default();
        let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();

        let result = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };

        if result == 0 {
            let stat = unsafe { stat.assume_init() };
            let block_size = stat.f_frsize as u64;
            let total_blocks = stat.f_blocks as u64;
            let available_blocks = stat.f_bavail as u64;

            let total_bytes = total_blocks * block_size;
            let available_bytes = available_blocks * block_size;

            let available_gb = available_bytes / (1024 * 1024 * 1024);
            let total_gb = total_bytes / (1024 * 1024 * 1024);
            let used_percent = if total_bytes > 0 {
                ((total_bytes - available_bytes) as f64 / total_bytes as f64 * 100.0) as u32
            } else {
                0
            };

            // Consider unhealthy if less than 1GB available or more than 95% used
            let status = if available_gb < 1 || used_percent > 95 {
                "unhealthy"
            } else if available_gb < 5 || used_percent > 90 {
                "warning"
            } else {
                "healthy"
            };

            CheckStatus {
                status: status.to_string(),
                message: Some(format!(
                    "{}GB available of {}GB total ({}% used)",
                    available_gb, total_gb, used_percent
                )),
                latency_ms: None,
            }
        } else {
            CheckStatus {
                status: "unknown".to_string(),
                message: Some("Failed to check disk space".to_string()),
                latency_ms: None,
            }
        }
    }

    #[cfg(not(unix))]
    {
        CheckStatus {
            status: "unknown".to_string(),
            message: Some("Disk space check not available on this platform".to_string()),
            latency_ms: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub checks: HealthChecks,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthChecks {
    pub database: CheckStatus,
    pub redis: CheckStatus,
    pub disk_space: CheckStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckStatus {
    pub status: String,
    pub message: Option<String>,
    pub latency_ms: Option<u64>,
}

/// Liveness probe - returns 200 if service is running
pub async fn liveness() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "alive",
        "timestamp": Utc::now().to_rfc3339()
    })))
}

/// Readiness probe - checks if service is ready to accept traffic
pub async fn readiness(pool: web::Data<SqlitePool>) -> Result<HttpResponse> {
    let start = std::time::Instant::now();

    // Check database connectivity
    let db_check = match sqlx::query("SELECT 1").fetch_one(pool.get_ref()).await {
        Ok(_) => CheckStatus {
            status: "healthy".to_string(),
            message: None,
            latency_ms: Some(start.elapsed().as_millis() as u64),
        },
        Err(e) => CheckStatus {
            status: "unhealthy".to_string(),
            message: Some(e.to_string()),
            latency_ms: None,
        },
    };

    // Check disk space on the system
    let disk_check = check_disk_space();

    let all_healthy = db_check.status == "healthy" && disk_check.status != "unhealthy";

    let response = HealthResponse {
        status: if all_healthy { "ready".to_string() } else { "not_ready".to_string() },
        timestamp: Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: get_uptime_seconds(),
        checks: HealthChecks {
            database: db_check,
            redis: CheckStatus {
                status: "disabled".to_string(),
                message: Some("Redis not configured for this deployment".to_string()),
                latency_ms: None,
            },
            disk_space: disk_check,
        },
    };

    if all_healthy {
        Ok(HttpResponse::Ok().json(response))
    } else {
        Ok(HttpResponse::ServiceUnavailable().json(response))
    }
}

/// Detailed health check with metrics
pub async fn health_detailed(
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let response = readiness(pool).await?;
    Ok(response)
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/health")
            .route("/live", web::get().to(liveness))
            .route("/ready", web::get().to(readiness))
            .route("", web::get().to(health_detailed))
    );
}
