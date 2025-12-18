//! Combined Compliance Report API handlers
//!
//! Provides REST API endpoint for getting combined automated and manual
//! compliance results for a scan.

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use sqlx::SqlitePool;

use crate::compliance::manual_assessment::ManualAssessment;
use crate::compliance::types::ComplianceFramework;
use crate::web::auth;

use super::types::{AssessmentRow, CombinedComplianceResponse};

/// GET /api/scans/{id}/compliance/combined
/// Get combined automated and manual compliance results for a scan
#[utoipa::path(
    get,
    path = "/api/scans/{id}/compliance/combined",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    responses(
        (status = 200, description = "Combined compliance results"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Scan not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_combined_compliance(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let scan_id = scan_id.into_inner();

    // Verify scan ownership
    let scan = crate::db::get_scan_by_id(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch scan")
        })?;

    let scan = match scan {
        Some(s) if s.user_id == *user_id => s,
        Some(_) => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to view this scan"
            })));
        }
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            })));
        }
    };

    // Get automated compliance summary if scan is completed
    let automated_summary = if scan.status == "completed" {
        let hosts: Vec<crate::types::HostInfo> = match &scan.results {
            Some(results_json) => serde_json::from_str(results_json).unwrap_or_default(),
            None => Vec::new(),
        };

        let frameworks = vec![
            ComplianceFramework::PciDss4,
            ComplianceFramework::Nist80053,
            ComplianceFramework::CisBenchmarks,
            ComplianceFramework::OwaspTop10,
        ];

        let analyzer = crate::compliance::analyzer::ComplianceAnalyzer::new(frameworks);
        match analyzer.analyze(&hosts, &scan_id).await {
            Ok(summary) => Some(serde_json::to_value(summary).unwrap_or_default()),
            Err(e) => {
                log::warn!("Failed to generate automated compliance: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Get manual assessments for this user
    let manual_assessments = sqlx::query_as::<_, AssessmentRow>(
        r#"
        SELECT id, user_id, rubric_id, framework_id, control_id,
               assessment_period_start, assessment_period_end,
               overall_rating, rating_score, criteria_responses,
               evidence_summary, findings, recommendations,
               review_status, created_at, updated_at
        FROM manual_assessments
        WHERE user_id = ?1 AND review_status = 'approved'
        ORDER BY framework_id, control_id
        "#,
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch manual assessments: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch assessments")
    })?;

    let manual_assessments: Vec<ManualAssessment> =
        manual_assessments.into_iter().map(|a| a.into()).collect();

    // Calculate combined score
    let automated_score = automated_summary
        .as_ref()
        .and_then(|s| s.get("overall_score"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0) as f32;

    let manual_score = if !manual_assessments.is_empty() {
        manual_assessments.iter().map(|a| a.rating_score).sum::<f32>()
            / manual_assessments.len() as f32
    } else {
        0.0
    };

    // Weight: 60% automated, 40% manual (if both available)
    let combined_score = if automated_summary.is_some() && !manual_assessments.is_empty() {
        automated_score * 0.6 + manual_score * 0.4
    } else if automated_summary.is_some() {
        automated_score
    } else {
        manual_score
    };

    Ok(HttpResponse::Ok().json(CombinedComplianceResponse {
        scan_id,
        automated_summary,
        manual_assessments,
        combined_score,
        generated_at: Utc::now(),
    }))
}
