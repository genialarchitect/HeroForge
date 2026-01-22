use actix_web::{web, HttpResponse};
use crate::web::auth::Claims;
use crate::orchestration;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CloudOrchestrationRequest {
    pub platform: String, // aws, azure, gcp
    pub function_name: String,
    pub payload: serde_json::Value,
}

/// Execute cloud orchestration
pub async fn execute_cloud_orchestration(
    _claims: Claims,
    req: web::Json<CloudOrchestrationRequest>,
) -> actix_web::Result<HttpResponse> {
    let result = match req.platform.as_str() {
        "aws" => orchestration::multi_cloud::orchestrate_aws_lambda(&req.function_name, req.payload.clone()).await,
        "azure" => orchestration::multi_cloud::orchestrate_azure_logic_app(&req.function_name, req.payload.clone()).await,
        "gcp" => orchestration::multi_cloud::orchestrate_gcp_function(&req.function_name, req.payload.clone()).await,
        _ => Err(anyhow::anyhow!("Unsupported platform")),
    }
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Deserialize)]
pub struct EdgeActionRequest {
    pub node_id: String,
    pub action: String,
}

/// Execute edge orchestration
pub async fn execute_edge_orchestration(
    _claims: Claims,
    req: web::Json<EdgeActionRequest>,
) -> actix_web::Result<HttpResponse> {
    orchestration::edge::orchestrate_edge_device(&req.node_id, &req.action)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "executed"})))
}

/// Get scaling recommendation
pub async fn get_scaling_recommendation(
    _claims: Claims,
) -> actix_web::Result<HttpResponse> {
    let current_load = get_current_system_load().await;
    let required_instances = orchestration::scale::horizontal_scaling(current_load)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "current_load": current_load,
        "required_instances": required_instances,
        "metrics": get_system_metrics().await
    })))
}

/// Calculate current system load from actual metrics
async fn get_current_system_load() -> f64 {
    let metrics = get_system_metrics().await;

    // Weighted average of different load factors
    let cpu_weight = 0.4;
    let memory_weight = 0.3;
    let scan_weight = 0.3;

    let cpu_load = metrics.cpu_usage / 100.0;
    let memory_load = metrics.memory_usage / 100.0;
    let scan_load = (metrics.active_scans as f64 / 10.0).min(1.0); // Assume 10 concurrent scans = full load

    let combined = cpu_load * cpu_weight + memory_load * memory_weight + scan_load * scan_weight;

    // Clamp to 0.0-1.0 range
    combined.max(0.0).min(1.0)
}

#[derive(serde::Serialize)]
struct SystemMetrics {
    cpu_usage: f64,
    memory_usage: f64,
    active_scans: i32,
    disk_usage: f64,
    load_average_1m: f64,
}

/// Get actual system metrics
async fn get_system_metrics() -> SystemMetrics {
    // Get CPU load average
    let load_avg = get_load_average();

    // Get memory usage
    let memory = get_memory_usage();

    // Get disk usage
    let disk = get_disk_usage();

    // Active scan count would come from database, but we don't have pool here
    // Use a simple estimate based on system load
    let estimated_scans = (load_avg * 5.0) as i32;

    SystemMetrics {
        cpu_usage: (load_avg / num_cpus::get() as f64 * 100.0).min(100.0),
        memory_usage: memory,
        active_scans: estimated_scans,
        disk_usage: disk,
        load_average_1m: load_avg,
    }
}

fn get_load_average() -> f64 {
    #[cfg(unix)]
    {
        use std::fs;
        if let Ok(content) = fs::read_to_string("/proc/loadavg") {
            if let Some(load_str) = content.split_whitespace().next() {
                if let Ok(load) = load_str.parse::<f64>() {
                    return load;
                }
            }
        }
    }
    0.5 // Default fallback
}

fn get_memory_usage() -> f64 {
    #[cfg(unix)]
    {
        use std::fs;
        if let Ok(content) = fs::read_to_string("/proc/meminfo") {
            let mut total: u64 = 0;
            let mut available: u64 = 0;

            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    total = parse_meminfo_value(line);
                } else if line.starts_with("MemAvailable:") {
                    available = parse_meminfo_value(line);
                }
            }

            if total > 0 {
                return ((total - available) as f64 / total as f64) * 100.0;
            }
        }
    }
    50.0 // Default fallback
}

#[cfg(unix)]
fn parse_meminfo_value(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn get_disk_usage() -> f64 {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::mem::MaybeUninit;

        let path = CString::new("/").unwrap();
        let mut stat = MaybeUninit::<libc::statvfs>::uninit();

        unsafe {
            if libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) == 0 {
                let stat = stat.assume_init();
                let total = stat.f_blocks * stat.f_frsize as u64;
                let available = stat.f_bavail * stat.f_frsize as u64;

                if total > 0 {
                    return ((total - available) as f64 / total as f64) * 100.0;
                }
            }
        }
    }
    50.0 // Default fallback
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/orchestration")
            .route("/cloud", web::post().to(execute_cloud_orchestration))
            .route("/edge", web::post().to(execute_edge_orchestration))
            .route("/scaling", web::get().to(get_scaling_recommendation))
    );
}
