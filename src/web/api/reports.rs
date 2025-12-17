use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use log::{error, info};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db;
use crate::db::models::CreateReportRequest;
use crate::reports::storage;
use crate::reports::types::{ReportFormat, ReportTemplate};
use crate::reports::ReportGenerator;
use crate::web::auth::Claims;

/// Default directory for generated reports
const REPORTS_DIR: &str = "./reports";

/// Create a new report
pub async fn create_report(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateReportRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    // Validate format
    let format: ReportFormat = match body.format.parse() {
        Ok(f) => f,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid format. Must be 'pdf', 'html', or 'json'"
        })),
    };

    // Validate template
    if ReportTemplate::by_id(&body.template_id).is_none() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid template_id. Must be 'executive', 'technical', or 'compliance'"
        }));
    }

    // Check if scan exists and belongs to user
    let scan = match db::get_scan_by_id(&pool, &body.scan_id).await {
        Ok(Some(scan)) => scan,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "Scan not found"})),
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Database error"}));
        }
    };

    // Verify ownership (unless admin)
    if scan.user_id != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
    }

    // Create report record
    let metadata_json = serde_json::to_string(&body.options).ok();
    let report = match db::create_report(
        &pool,
        &claims.sub,
        &body.scan_id,
        &body.name,
        body.description.as_deref(),
        &body.format,
        &body.template_id,
        &body.sections,
        metadata_json.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to create report: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to create report"}));
        }
    };

    // Spawn async task to generate the report
    let report_id = report.id.clone();
    let scan_id = body.scan_id.clone();
    let name = body.name.clone();
    let description = body.description.clone();
    let template_id = body.template_id.clone();
    let sections = body.sections.clone();
    let options = body.options.clone();
    let pool_clone = pool.get_ref().clone();

    tokio::spawn(async move {
        let pool_for_error = pool_clone.clone();
        let generator = ReportGenerator::new(pool_clone, REPORTS_DIR.to_string());

        if let Err(e) = generator
            .generate(
                &report_id,
                &scan_id,
                &name,
                description.as_deref(),
                format,
                &template_id,
                sections,
                options,
            )
            .await
        {
            error!("Report generation failed: {}", e);
            let _ = db::update_report_status(
                &pool_for_error,
                &report_id,
                "failed",
                None,
                None,
                Some(&e.to_string()),
            )
            .await;
        }
    });

    info!("Report creation started: {}", report.id);
    HttpResponse::Created().json(report)
}

/// Get all reports for current user
pub async fn get_reports(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    query: web::Query<ReportQueryParams>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let reports = if let Some(ref scan_id) = query.scan_id {
        // Get reports for specific scan
        match db::get_scan_reports(&pool, scan_id).await {
            Ok(r) => r,
            Err(e) => {
                error!("Database error: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Database error"}));
            }
        }
    } else {
        // Get all user's reports
        match db::get_user_reports(&pool, &claims.sub).await {
            Ok(r) => r,
            Err(e) => {
                error!("Database error: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Database error"}));
            }
        }
    };

    // Filter to user's reports only
    let user_reports: Vec<_> = reports
        .into_iter()
        .filter(|r| r.user_id == claims.sub)
        .collect();

    HttpResponse::Ok().json(user_reports)
}

/// Get a specific report
pub async fn get_report(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let report_id = path.into_inner();

    let report = match db::get_report_by_id(&pool, &report_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "Report not found"})),
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Database error"}));
        }
    };

    // Verify ownership
    if report.user_id != claims.sub {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
    }

    HttpResponse::Ok().json(report)
}

/// Download a report file
pub async fn download_report(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let report_id = path.into_inner();

    let report = match db::get_report_by_id(&pool, &report_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "Report not found"})),
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Database error"}));
        }
    };

    // Verify ownership
    if report.user_id != claims.sub {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
    }

    // Check if report is completed
    if report.status != "completed" {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Report not ready",
            "status": report.status
        }));
    }

    let file_path = match report.file_path {
        Some(ref p) => p,
        None => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Report file not found"})),
    };

    // Read file
    let content = match storage::read_report(file_path).await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to read report file: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to read report file"}));
        }
    };

    // Determine content type
    let format: ReportFormat = report.format.parse().unwrap_or(ReportFormat::Html);
    let content_type = format.content_type();

    // Generate filename
    let extension = format.extension();
    let filename = format!(
        "{}-{}.{}",
        report.name.replace(' ', "_"),
        report.id.chars().take(8).collect::<String>(),
        extension
    );

    HttpResponse::Ok()
        .content_type(content_type)
        .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
        .body(content)
}

/// Delete a report
pub async fn delete_report(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let report_id = path.into_inner();

    let report = match db::get_report_by_id(&pool, &report_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "Report not found"})),
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Database error"}));
        }
    };

    // Verify ownership
    if report.user_id != claims.sub {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
    }

    // Delete file if exists
    if let Some(ref file_path) = report.file_path {
        let _ = storage::delete_report_file(file_path).await;
    }

    // Delete database record
    if let Err(e) = db::delete_report(&pool, &report_id).await {
        error!("Failed to delete report: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to delete report"}));
    }

    info!("Report deleted: {}", report_id);
    HttpResponse::NoContent().finish()
}

/// Get available report templates
pub async fn get_templates() -> HttpResponse {
    let templates = ReportGenerator::get_templates();

    // Convert to serializable format
    let template_list: Vec<TemplateResponse> = templates
        .into_iter()
        .map(|t| TemplateResponse {
            id: t.id,
            name: t.name,
            description: t.description,
            default_sections: t.default_sections.iter().map(|s| s.title().to_string()).collect(),
            supports_formats: t.supports_formats.iter().map(|f| f.extension().to_string()).collect(),
        })
        .collect();

    HttpResponse::Ok().json(template_list)
}

#[derive(Debug, Deserialize)]
pub struct ReportQueryParams {
    pub scan_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct TemplateResponse {
    id: String,
    name: String,
    description: String,
    default_sections: Vec<String>,
    supports_formats: Vec<String>,
}
