//! Portal Reports
//!
//! Provides read-only access to reports for portal users.

use actix_web::{web, HttpRequest, HttpResponse, HttpMessage, Result};
use serde::Serialize;
use sqlx::SqlitePool;

use super::auth::PortalClaims;

/// Report summary for portal
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PortalReport {
    pub id: String,
    pub name: String,
    pub report_type: String,
    pub format: String,
    pub status: String,
    pub created_at: String,
    pub engagement_id: Option<String>,
    pub engagement_name: Option<String>,
}

/// List reports for the customer
pub async fn list_reports(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            })));
        }
    };

    // Get reports linked to customer's engagements
    // Use COALESCE to fall back to template_id if report_type is NULL (for legacy reports)
    let reports: Vec<PortalReport> = sqlx::query_as::<_, (String, String, String, String, String, String, Option<String>)>(
        r#"
        SELECT r.id, r.name, COALESCE(r.report_type, r.template_id) as report_type, r.format, r.status, r.created_at, r.engagement_id
        FROM reports r
        JOIN engagements e ON r.engagement_id = e.id
        WHERE e.customer_id = ? AND r.status = 'completed'
        ORDER BY r.created_at DESC
        "#
    )
    .bind(&claims.customer_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, report_type, format, status, created_at, engagement_id)| {
        PortalReport {
            id,
            name,
            report_type,
            format,
            status,
            created_at,
            engagement_id,
            engagement_name: None, // Will be populated below if needed
        }
    })
    .collect();

    Ok(HttpResponse::Ok().json(reports))
}

/// Get a specific report
pub async fn get_report(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            })));
        }
    };

    let report_id = path.into_inner();

    // Get report (ensuring it belongs to customer's engagement)
    let report: Option<(String, String, String, String, String, String, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT r.id, r.name, COALESCE(r.report_type, r.template_id) as report_type, r.format, r.status, r.created_at, r.engagement_id, e.name
        FROM reports r
        JOIN engagements e ON r.engagement_id = e.id
        WHERE r.id = ? AND e.customer_id = ? AND r.status = 'completed'
        "#
    )
    .bind(&report_id)
    .bind(&claims.customer_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch report: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch report")
    })?;

    match report {
        Some((id, name, report_type, format, status, created_at, engagement_id, engagement_name)) => {
            Ok(HttpResponse::Ok().json(PortalReport {
                id,
                name,
                report_type,
                format,
                status,
                created_at,
                engagement_id,
                engagement_name,
            }))
        }
        None => {
            Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Report not found"
            })))
        }
    }
}

/// Download a report file
pub async fn download_report(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            })));
        }
    };

    let report_id = path.into_inner();

    // Get report file path (ensuring it belongs to customer's engagement)
    let report: Option<(String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT r.name, r.format, r.file_path
        FROM reports r
        JOIN engagements e ON r.engagement_id = e.id
        WHERE r.id = ? AND e.customer_id = ? AND r.status = 'completed'
        "#
    )
    .bind(&report_id)
    .bind(&claims.customer_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch report for download: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch report")
    })?;

    let (name, format, file_path) = match report {
        Some(r) => r,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Report not found"
            })));
        }
    };

    let file_path = match file_path {
        Some(p) => p,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Report file not available"
            })));
        }
    };

    // Read the file
    let file_content = match tokio::fs::read(&file_path).await {
        Ok(content) => content,
        Err(e) => {
            log::error!("Failed to read report file {}: {}", file_path, e);
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Report file not found"
            })));
        }
    };

    // Determine content type based on format
    let content_type = match format.as_str() {
        "pdf" => "application/pdf",
        "html" => "text/html",
        "json" => "application/json",
        "csv" => "text/csv",
        _ => "application/octet-stream",
    };

    // Generate filename
    let filename = format!("{}.{}", name.replace(' ', "_"), format);

    Ok(HttpResponse::Ok()
        .content_type(content_type)
        .append_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
        .body(file_content))
}
