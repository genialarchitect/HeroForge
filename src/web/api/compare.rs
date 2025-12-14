use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::db;
use crate::scanner::comparison;
use crate::types::HostInfo;
use crate::web::auth;

#[derive(Debug, Deserialize)]
pub struct CompareScanRequest {
    pub scan_id_1: String,
    pub scan_id_2: String,
}

/// Compare two scans and return the differences
pub async fn compare_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CompareScanRequest>,
) -> Result<HttpResponse> {
    // Fetch both scans
    let scan1 = db::get_scan_by_id(&pool, &request.scan_id_1)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch scan 1"))?;

    let scan2 = db::get_scan_by_id(&pool, &request.scan_id_2)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch scan 2"))?;

    // Verify both scans exist
    let scan1 = match scan1 {
        Some(scan) => scan,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan 1 not found"
            })))
        }
    };

    let scan2 = match scan2 {
        Some(scan) => scan,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan 2 not found"
            })))
        }
    };

    // Verify ownership of both scans
    if scan1.user_id != claims.sub || scan2.user_id != claims.sub {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })));
    }

    // Verify both scans are completed
    if scan1.status != "completed" {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Scan 1 is not completed (status: {})", scan1.status)
        })));
    }

    if scan2.status != "completed" {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Scan 2 is not completed (status: {})", scan2.status)
        })));
    }

    // Parse scan results
    let results1 = scan1.results.ok_or_else(|| {
        actix_web::error::ErrorInternalServerError("Scan 1 has no results")
    })?;

    let results2 = scan2.results.ok_or_else(|| {
        actix_web::error::ErrorInternalServerError("Scan 2 has no results")
    })?;

    let hosts1: Vec<HostInfo> = serde_json::from_str(&results1)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to parse scan 1 results"))?;

    let hosts2: Vec<HostInfo> = serde_json::from_str(&results2)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to parse scan 2 results"))?;

    // Compare scans
    let diff = comparison::compare_scans(hosts1, hosts2);

    // Return comparison results
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "scan1": {
            "id": scan1.id,
            "name": scan1.name,
            "created_at": scan1.created_at,
        },
        "scan2": {
            "id": scan2.id,
            "name": scan2.name,
            "created_at": scan2.created_at,
        },
        "diff": diff,
    })))
}
