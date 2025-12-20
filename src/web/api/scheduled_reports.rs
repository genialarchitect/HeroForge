//! Scheduled Reports API endpoints
//!
//! Provides REST endpoints for managing scheduled report configurations.

use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;

use crate::db::{self, models};
use crate::web::auth;

/// Create a new scheduled report
///
/// POST /api/scheduled-reports
pub async fn create_scheduled_report(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<models::CreateScheduledReportRequest>,
) -> Result<HttpResponse> {
    // Validate cron expression
    if let Err(e) = validate_cron_expression(&request.schedule) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid cron expression: {}", e)
        })));
    }

    // Validate recipients
    if request.recipients.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one recipient email is required"
        })));
    }

    for email in &request.recipients {
        if !is_valid_email(email) {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid email address: {}", email)
            })));
        }
    }

    // Validate report type
    let valid_types = ["vulnerability", "compliance", "executive", "scan_summary"];
    if !valid_types.contains(&request.report_type.as_str()) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid report type. Must be one of: {:?}", valid_types)
        })));
    }

    // Validate format
    let valid_formats = ["pdf", "html", "csv"];
    if !valid_formats.contains(&request.format.as_str()) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid format. Must be one of: {:?}", valid_formats)
        })));
    }

    let report = db::create_scheduled_report(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to create scheduled report: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create scheduled report")
        })?;

    Ok(HttpResponse::Created().json(report))
}

/// Get all scheduled reports for the current user
///
/// GET /api/scheduled-reports
pub async fn get_scheduled_reports(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let reports = db::get_user_scheduled_reports(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch scheduled reports: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch scheduled reports")
        })?;

    Ok(HttpResponse::Ok().json(reports))
}

/// Get a specific scheduled report by ID
///
/// GET /api/scheduled-reports/{id}
pub async fn get_scheduled_report(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    report_id: web::Path<String>,
) -> Result<HttpResponse> {
    let report = db::get_scheduled_report_by_id(&pool, &report_id)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch scheduled report: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch scheduled report")
        })?;

    match report {
        Some(r) => {
            // Verify the report belongs to the user
            if r.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
            Ok(HttpResponse::Ok().json(r))
        }
        None => Err(actix_web::error::ErrorNotFound("Scheduled report not found")),
    }
}

/// Update a scheduled report
///
/// PUT /api/scheduled-reports/{id}
pub async fn update_scheduled_report(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    report_id: web::Path<String>,
    request: web::Json<models::UpdateScheduledReportRequest>,
) -> Result<HttpResponse> {
    // First check if report exists and belongs to user
    let existing = db::get_scheduled_report_by_id(&pool, &report_id)
        .await
        .map_err(|e| {
            log::error!("Database error: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    match existing {
        Some(r) => {
            if r.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
        }
        None => return Err(actix_web::error::ErrorNotFound("Scheduled report not found")),
    }

    // Validate cron expression if provided
    if let Some(ref schedule) = request.schedule {
        if let Err(e) = validate_cron_expression(schedule) {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid cron expression: {}", e)
            })));
        }
    }

    // Validate recipients if provided
    if let Some(ref recipients) = request.recipients {
        if recipients.is_empty() {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "At least one recipient email is required"
            })));
        }
        for email in recipients {
            if !is_valid_email(email) {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("Invalid email address: {}", email)
                })));
            }
        }
    }

    // Validate report type if provided
    if let Some(ref report_type) = request.report_type {
        let valid_types = ["vulnerability", "compliance", "executive", "scan_summary"];
        if !valid_types.contains(&report_type.as_str()) {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid report type. Must be one of: {:?}", valid_types)
            })));
        }
    }

    // Validate format if provided
    if let Some(ref format) = request.format {
        let valid_formats = ["pdf", "html", "csv"];
        if !valid_formats.contains(&format.as_str()) {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid format. Must be one of: {:?}", valid_formats)
            })));
        }
    }

    let updated = db::update_scheduled_report(&pool, &report_id, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to update scheduled report: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to update scheduled report")
        })?;

    Ok(HttpResponse::Ok().json(updated))
}

/// Delete a scheduled report
///
/// DELETE /api/scheduled-reports/{id}
pub async fn delete_scheduled_report(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    report_id: web::Path<String>,
) -> Result<HttpResponse> {
    // First check if report exists and belongs to user
    let existing = db::get_scheduled_report_by_id(&pool, &report_id)
        .await
        .map_err(|e| {
            log::error!("Database error: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    match existing {
        Some(r) => {
            if r.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
        }
        None => return Err(actix_web::error::ErrorNotFound("Scheduled report not found")),
    }

    db::delete_scheduled_report(&pool, &report_id)
        .await
        .map_err(|e| {
            log::error!("Failed to delete scheduled report: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete scheduled report")
        })?;

    Ok(HttpResponse::NoContent().finish())
}

/// Trigger immediate execution of a scheduled report
///
/// POST /api/scheduled-reports/{id}/run-now
pub async fn run_scheduled_report_now(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    report_id: web::Path<String>,
) -> Result<HttpResponse> {
    // First check if report exists and belongs to user
    let existing = db::get_scheduled_report_by_id(&pool, &report_id)
        .await
        .map_err(|e| {
            log::error!("Database error: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    let report = match existing {
        Some(r) => {
            if r.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
            r
        }
        None => return Err(actix_web::error::ErrorNotFound("Scheduled report not found")),
    };

    // Spawn the report generation task
    let pool_clone = pool.get_ref().clone();
    let report_id_clone = report_id.clone();

    tokio::spawn(async move {
        if let Err(e) = crate::web::scheduler::execute_scheduled_report(&pool_clone, &report).await {
            log::error!("Failed to execute scheduled report {}: {}", report_id_clone, e);
        }
    });

    Ok(HttpResponse::Accepted().json(serde_json::json!({
        "message": "Report generation started",
        "report_id": report_id.as_str()
    })))
}

/// Get available cron presets
///
/// GET /api/scheduled-reports/presets
pub async fn get_schedule_presets() -> Result<HttpResponse> {
    let presets = vec![
        serde_json::json!({
            "id": "daily_8am",
            "label": "Daily at 8:00 AM",
            "cron": "0 8 * * *",
            "description": "Run every day at 8:00 AM"
        }),
        serde_json::json!({
            "id": "weekly_monday_8am",
            "label": "Weekly on Monday at 8:00 AM",
            "cron": "0 8 * * 1",
            "description": "Run every Monday at 8:00 AM"
        }),
        serde_json::json!({
            "id": "monthly_1st_8am",
            "label": "Monthly on the 1st at 8:00 AM",
            "cron": "0 8 1 * *",
            "description": "Run on the 1st of each month at 8:00 AM"
        }),
        serde_json::json!({
            "id": "weekly_friday_5pm",
            "label": "Weekly on Friday at 5:00 PM",
            "cron": "0 17 * * 5",
            "description": "Run every Friday at 5:00 PM"
        }),
        serde_json::json!({
            "id": "biweekly_monday_8am",
            "label": "Bi-weekly on Monday at 8:00 AM",
            "cron": "0 8 1,15 * *",
            "description": "Run on the 1st and 15th of each month at 8:00 AM"
        }),
        serde_json::json!({
            "id": "quarterly",
            "label": "Quarterly on the 1st at 8:00 AM",
            "cron": "0 8 1 1,4,7,10 *",
            "description": "Run on the 1st of January, April, July, and October at 8:00 AM"
        }),
    ];

    Ok(HttpResponse::Ok().json(presets))
}

/// Validate a cron expression
fn validate_cron_expression(cron_expr: &str) -> std::result::Result<(), String> {
    use cron::Schedule;
    use std::str::FromStr;

    // Handle preset schedules
    let effective_cron = match cron_expr {
        "daily_8am" => "0 8 * * *",
        "weekly_monday_8am" => "0 8 * * 1",
        "monthly_1st_8am" => "0 8 1 * *",
        _ => cron_expr,
    };

    // cron crate expects 6-field cron (with seconds) or 7-field (with years)
    // Convert 5-field to 6-field by prepending "0" for seconds
    let cron_6field = if effective_cron.split_whitespace().count() == 5 {
        format!("0 {}", effective_cron)
    } else {
        effective_cron.to_string()
    };

    Schedule::from_str(&cron_6field).map_err(|e| e.to_string())?;
    Ok(())
}

/// Simple email validation
fn is_valid_email(email: &str) -> bool {
    // Basic validation: contains @ with local part before and domain after
    if let Some(at_pos) = email.find('@') {
        let local = &email[..at_pos];
        let domain = &email[at_pos + 1..];
        !local.is_empty()
            && !domain.is_empty()
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_cron_daily() {
        assert!(validate_cron_expression("0 8 * * *").is_ok());
    }

    #[test]
    fn test_validate_cron_weekly() {
        assert!(validate_cron_expression("0 8 * * 1").is_ok());
    }

    #[test]
    fn test_validate_cron_monthly() {
        assert!(validate_cron_expression("0 8 1 * *").is_ok());
    }

    #[test]
    fn test_validate_cron_invalid() {
        assert!(validate_cron_expression("invalid").is_err());
    }

    #[test]
    fn test_validate_cron_preset() {
        assert!(validate_cron_expression("daily_8am").is_ok());
    }

    #[test]
    fn test_is_valid_email() {
        assert!(is_valid_email("test@example.com"));
        assert!(is_valid_email("user.name@domain.org"));
        assert!(!is_valid_email("invalid"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("test@"));
    }
}
