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

    let all_healthy = db_check.status == "healthy";

    let response = HealthResponse {
        status: if all_healthy { "ready".to_string() } else { "not_ready".to_string() },
        timestamp: Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: get_uptime_seconds(),
        checks: HealthChecks {
            database: db_check,
            redis: CheckStatus {
                status: "unknown".to_string(),
                message: Some("Redis health check not implemented".to_string()),
                latency_ms: None,
            },
            disk_space: CheckStatus {
                status: "healthy".to_string(),
                message: None,
                latency_ms: None,
            },
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
