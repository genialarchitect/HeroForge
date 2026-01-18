use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db;
use crate::db::models::{CreateReportRequest, UpdateReportNotesRequest, UpdateFindingNoteRequest};
use crate::db::quotas::{self, QuotaType};
use crate::reports::storage;
use crate::reports::types::{ReportFormat, ReportTemplate};
use crate::reports::ReportGenerator;
use crate::web::auth::Claims;
use crate::web::auth::org_context::OrganizationContext;

/// Default directory for generated reports
const REPORTS_DIR: &str = "./reports";

/// Create a new report
pub async fn create_report(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    org_context: OrganizationContext,
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

    // Check organization quota for reports per month
    if let Some(org_id) = org_context.org_id() {
        match quotas::check_quota(&pool, org_id, QuotaType::ReportsPerMonth).await {
            Ok(quota_check) => {
                if !quota_check.allowed {
                    return HttpResponse::TooManyRequests().json(serde_json::json!({
                        "error": "Monthly report limit reached for your organization",
                        "quota_type": "reports_per_month",
                        "current": quota_check.current,
                        "limit": quota_check.limit
                    }));
                }
            }
            Err(e) => {
                warn!("Failed to check report quota for org {}: {}", org_id, e);
                // Continue anyway - don't block reports on quota check failures
            }
        }
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

    // Increment organization quota usage for reports
    if let Some(org_id) = org_context.org_id() {
        if let Err(e) = quotas::increment_quota_usage(&pool, org_id, QuotaType::ReportsPerMonth, 1).await {
            warn!("Failed to increment report quota for org {}: {}", org_id, e);
            // Don't fail the report if quota tracking fails
        }
    }

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

// ============================================================================
// Operator Notes Endpoints
// ============================================================================

/// Get all operator notes for a report (report-level + finding-level)
pub async fn get_report_notes(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let report_id = path.into_inner();

    // Verify report exists and user owns it
    let report = match db::get_report_by_id(&pool, &report_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "Report not found"})),
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Database error"}));
        }
    };

    // Verify ownership (unless admin)
    if report.user_id != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
    }

    match db::get_report_notes(&pool, &report_id).await {
        Ok(notes) => HttpResponse::Ok().json(notes),
        Err(e) => {
            error!("Failed to get report notes: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to get notes"}))
        }
    }
}

/// Update report-level operator notes
pub async fn update_report_notes(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateReportNotesRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let report_id = path.into_inner();

    // Verify report exists and user owns it
    let report = match db::get_report_by_id(&pool, &report_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "Report not found"})),
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Database error"}));
        }
    };

    // Verify ownership (unless admin)
    if report.user_id != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
    }

    if let Err(e) = db::update_report_notes(&pool, &report_id, &body.operator_notes).await {
        error!("Failed to update report notes: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to update notes"}));
    }

    info!("Updated operator notes for report: {}", report_id);
    HttpResponse::Ok().json(serde_json::json!({"status": "ok", "message": "Notes updated"}))
}

/// Update or create a finding-level note
pub async fn update_finding_note(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
    body: web::Json<UpdateFindingNoteRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let (report_id, finding_id) = path.into_inner();

    // Verify report exists and user owns it
    let report = match db::get_report_by_id(&pool, &report_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "Report not found"})),
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Database error"}));
        }
    };

    // Verify ownership (unless admin)
    if report.user_id != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
    }

    match db::upsert_finding_note(&pool, &report_id, &finding_id, &body.notes).await {
        Ok(note) => {
            info!("Updated finding note for report {}, finding {}", report_id, finding_id);
            HttpResponse::Ok().json(note)
        }
        Err(e) => {
            error!("Failed to update finding note: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to update note"}))
        }
    }
}

/// Delete a finding-level note
pub async fn delete_finding_note(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let (report_id, finding_id) = path.into_inner();

    // Verify report exists and user owns it
    let report = match db::get_report_by_id(&pool, &report_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "Report not found"})),
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Database error"}));
        }
    };

    // Verify ownership (unless admin)
    if report.user_id != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
    }

    if let Err(e) = db::delete_finding_note(&pool, &report_id, &finding_id).await {
        error!("Failed to delete finding note: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to delete note"}));
    }

    info!("Deleted finding note for report {}, finding {}", report_id, finding_id);
    HttpResponse::NoContent().finish()
}

/// Get a preview of a report
/// Returns a lightweight HTML preview suitable for embedding
pub async fn preview_report(
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

    // Verify ownership (unless admin)
    if report.user_id != claims.sub && !claims.roles.contains(&"admin".to_string()) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
    }

    // Check if report is completed
    if report.status != "completed" {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Report not ready",
            "status": report.status
        }));
    }

    // Get scan data for the preview
    let scan = match db::get_scan_by_id(&pool, &report.scan_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Scan not found"})),
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Database error"}));
        }
    };

    // Parse hosts from scan results for summary stats
    let hosts: Vec<crate::types::HostInfo> = if let Some(ref results_json) = scan.results {
        serde_json::from_str(results_json).unwrap_or_default()
    } else {
        Vec::new()
    };

    // Calculate summary statistics
    let total_hosts = hosts.len();
    let total_ports: usize = hosts.iter().map(|h| h.ports.len()).sum();
    let total_vulns: usize = hosts.iter().map(|h| h.vulnerabilities.len()).sum();
    let critical_vulns = hosts.iter()
        .flat_map(|h| h.vulnerabilities.iter())
        .filter(|v| matches!(v.severity, crate::types::Severity::Critical))
        .count();
    let high_vulns = hosts.iter()
        .flat_map(|h| h.vulnerabilities.iter())
        .filter(|v| matches!(v.severity, crate::types::Severity::High))
        .count();
    let medium_vulns = hosts.iter()
        .flat_map(|h| h.vulnerabilities.iter())
        .filter(|v| matches!(v.severity, crate::types::Severity::Medium))
        .count();
    let low_vulns = hosts.iter()
        .flat_map(|h| h.vulnerabilities.iter())
        .filter(|v| matches!(v.severity, crate::types::Severity::Low))
        .count();

    // Generate preview HTML
    let preview_html = format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report Preview: {}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
        .header {{ margin-bottom: 2rem; }}
        .title {{ font-size: 1.5rem; font-weight: 600; color: #fff; margin-bottom: 0.5rem; }}
        .meta {{ color: #94a3b8; font-size: 0.875rem; }}
        .card {{ background: #1e293b; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1rem; }}
        .card-title {{ font-size: 1rem; font-weight: 500; color: #fff; margin-bottom: 1rem; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; }}
        .stat {{ text-align: center; }}
        .stat-value {{ font-size: 1.5rem; font-weight: 600; color: #22d3ee; }}
        .stat-label {{ font-size: 0.75rem; color: #94a3b8; margin-top: 0.25rem; }}
        .vuln-bar {{ display: flex; gap: 0.5rem; margin-top: 1rem; }}
        .vuln-item {{ flex: 1; text-align: center; padding: 0.75rem; border-radius: 0.375rem; }}
        .critical {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; }}
        .high {{ background: rgba(249, 115, 22, 0.2); color: #fdba74; }}
        .medium {{ background: rgba(234, 179, 8, 0.2); color: #fcd34d; }}
        .low {{ background: rgba(34, 197, 94, 0.2); color: #86efac; }}
        .badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 500; }}
        .badge-format {{ background: rgba(34, 211, 238, 0.2); color: #22d3ee; }}
        .badge-template {{ background: rgba(168, 85, 247, 0.2); color: #c4b5fd; }}
        .hosts-list {{ margin-top: 1rem; }}
        .host-item {{ background: #334155; border-radius: 0.375rem; padding: 0.75rem; margin-bottom: 0.5rem; }}
        .host-ip {{ font-weight: 500; color: #fff; }}
        .host-details {{ font-size: 0.75rem; color: #94a3b8; margin-top: 0.25rem; }}
    </style>
</head>
<body>
    <div class="header">
        <h1 class="title">{}</h1>
        <p class="meta">
            <span class="badge badge-format">{}</span>
            <span class="badge badge-template">{}</span>
            &nbsp;&bull;&nbsp; Generated: {}
        </p>
    </div>

    <div class="card">
        <h2 class="card-title">Summary</h2>
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Hosts</div>
            </div>
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
        </div>
    </div>

    <div class="card">
        <h2 class="card-title">Vulnerability Breakdown</h2>
        <div class="vuln-bar">
            <div class="vuln-item critical">
                <div style="font-size: 1.25rem; font-weight: 600;">{}</div>
                <div style="font-size: 0.75rem;">Critical</div>
            </div>
            <div class="vuln-item high">
                <div style="font-size: 1.25rem; font-weight: 600;">{}</div>
                <div style="font-size: 0.75rem;">High</div>
            </div>
            <div class="vuln-item medium">
                <div style="font-size: 1.25rem; font-weight: 600;">{}</div>
                <div style="font-size: 0.75rem;">Medium</div>
            </div>
            <div class="vuln-item low">
                <div style="font-size: 1.25rem; font-weight: 600;">{}</div>
                <div style="font-size: 0.75rem;">Low</div>
            </div>
        </div>
    </div>

    <div class="card">
        <h2 class="card-title">Hosts ({} discovered)</h2>
        <div class="hosts-list">
            {}
        </div>
    </div>

    <p style="margin-top: 2rem; text-align: center; color: #64748b; font-size: 0.875rem;">
        This is a preview. Download the full report for complete details.
    </p>
</body>
</html>
"#,
        report.name,
        report.name,
        report.format.to_uppercase(),
        report.template_id,
        report.created_at,
        total_hosts,
        total_ports,
        total_vulns,
        critical_vulns,
        high_vulns,
        medium_vulns,
        low_vulns,
        total_hosts,
        hosts.iter().take(10).map(|h| {
            let ports_count = h.ports.len();
            let vulns_count = h.vulnerabilities.len();
            format!(
                r#"<div class="host-item"><span class="host-ip">{}</span><div class="host-details">{} ports &bull; {} vulns</div></div>"#,
                h.target.ip,
                ports_count,
                vulns_count
            )
        }).collect::<Vec<_>>().join("")
    );

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(preview_html)
}
