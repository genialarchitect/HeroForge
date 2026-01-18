// ============================================================================
// Findings API Endpoints
// ============================================================================
//
// REST API for the finding deduplication engine. Provides endpoints for
// querying deduplicated findings, registering new occurrences, and
// retrieving deduplication statistics.

use actix_web::{web, HttpResponse};
use log::error;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::findings::{
    DeduplicatedFinding, DeduplicationEngine, DeduplicationStats,
    RegisterFindingRequest, RegisterFindingResult,
};
use crate::web::auth;

/// Query parameters for listing findings
#[derive(Debug, Deserialize)]
pub struct ListFindingsQuery {
    pub severity: Option<String>,
    pub status: Option<String>,
    pub host: Option<String>,
    pub min_occurrences: Option<i32>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Request to update finding status
#[derive(Debug, Deserialize)]
pub struct UpdateFindingStatusRequest {
    pub status: String,
}

/// Request to merge findings
#[derive(Debug, Deserialize)]
pub struct MergeFindingsRequest {
    pub source_finding_id: String,
    pub target_finding_id: String,
    pub reason: Option<String>,
}

/// Response for finding operations
#[derive(Debug, Serialize)]
pub struct FindingResponse {
    pub finding: DeduplicatedFinding,
}

/// Response for listing findings
#[derive(Debug, Serialize)]
pub struct ListFindingsResponse {
    pub findings: Vec<DeduplicatedFinding>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Response for statistics
#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub stats: DeduplicationStats,
}

/// List deduplicated findings with optional filters
pub async fn list_findings(
    pool: web::Data<SqlitePool>,
    query: web::Query<ListFindingsQuery>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let engine = DeduplicationEngine::new();

    let limit = query.limit.unwrap_or(50).min(500);
    let offset = query.offset.unwrap_or(0);

    match engine.list_findings(
        pool.get_ref(),
        query.severity.as_deref(),
        query.status.as_deref(),
        query.host.as_deref(),
        query.min_occurrences,
        limit,
        offset,
    ).await {
        Ok(findings) => {
            // Get total count for pagination
            let total = match get_total_count(
                pool.get_ref(),
                query.severity.as_deref(),
                query.status.as_deref(),
                query.host.as_deref(),
                query.min_occurrences,
            ).await {
                Ok(count) => count,
                Err(_) => findings.len() as i64,
            };

            HttpResponse::Ok().json(ListFindingsResponse {
                findings,
                total,
                limit,
                offset,
            })
        }
        Err(e) => {
            error!("Failed to list findings: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list findings"
            }))
        }
    }
}

/// Get total count for pagination
async fn get_total_count(
    pool: &SqlitePool,
    severity: Option<&str>,
    status: Option<&str>,
    host: Option<&str>,
    min_occurrences: Option<i32>,
) -> anyhow::Result<i64> {
    let mut query = String::from("SELECT COUNT(*) FROM deduplicated_findings WHERE 1=1");

    if severity.is_some() {
        query.push_str(" AND LOWER(severity) = LOWER(?)");
    }
    if status.is_some() {
        query.push_str(" AND LOWER(status) = LOWER(?)");
    }
    if host.is_some() {
        query.push_str(" AND host LIKE ?");
    }
    if min_occurrences.is_some() {
        query.push_str(" AND occurrence_count >= ?");
    }

    let mut q = sqlx::query_as::<_, (i64,)>(&query);

    if let Some(sev) = severity {
        q = q.bind(sev);
    }
    if let Some(stat) = status {
        q = q.bind(stat);
    }
    if let Some(h) = host {
        q = q.bind(format!("%{}%", h));
    }
    if let Some(min) = min_occurrences {
        q = q.bind(min);
    }

    let (count,) = q.fetch_one(pool).await?;
    Ok(count)
}

/// Get a specific finding by ID
pub async fn get_finding(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let finding_id = path.into_inner();
    let engine = DeduplicationEngine::new();

    match engine.get_finding(pool.get_ref(), &finding_id).await {
        Ok(Some(finding)) => HttpResponse::Ok().json(FindingResponse { finding }),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Finding not found"
        })),
        Err(e) => {
            error!("Failed to get finding: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get finding"
            }))
        }
    }
}

/// Get findings for a specific scan
pub async fn get_findings_for_scan(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let scan_id = path.into_inner();
    let engine = DeduplicationEngine::new();

    match engine.get_findings_for_scan(pool.get_ref(), &scan_id).await {
        Ok(findings) => HttpResponse::Ok().json(serde_json::json!({
            "findings": findings,
            "scan_id": scan_id,
            "count": findings.len()
        })),
        Err(e) => {
            error!("Failed to get findings for scan: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get findings for scan"
            }))
        }
    }
}

/// Register a new finding occurrence
pub async fn register_finding(
    pool: web::Data<SqlitePool>,
    body: web::Json<RegisterFindingRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let engine = DeduplicationEngine::new();

    match engine.register_finding(pool.get_ref(), &body.into_inner()).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => {
            error!("Failed to register finding: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to register finding"
            }))
        }
    }
}

/// Update finding status
pub async fn update_finding_status(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateFindingStatusRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let finding_id = path.into_inner();
    let engine = DeduplicationEngine::new();

    // Validate status
    let valid_statuses = ["open", "resolved", "false_positive", "accepted_risk", "in_progress"];
    if !valid_statuses.contains(&body.status.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid status",
            "valid_statuses": valid_statuses
        }));
    }

    match engine.update_status(pool.get_ref(), &finding_id, &body.status).await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Status updated successfully",
            "finding_id": finding_id,
            "status": body.status
        })),
        Err(e) => {
            error!("Failed to update finding status: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update status"
            }))
        }
    }
}

/// Get deduplication statistics
pub async fn get_stats(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let engine = DeduplicationEngine::new();

    match engine.get_stats(pool.get_ref()).await {
        Ok(stats) => HttpResponse::Ok().json(StatsResponse { stats }),
        Err(e) => {
            error!("Failed to get deduplication stats: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get statistics"
            }))
        }
    }
}

/// Merge two findings
pub async fn merge_findings(
    pool: web::Data<SqlitePool>,
    body: web::Json<MergeFindingsRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let engine = DeduplicationEngine::new();

    // Verify source and target exist
    let source = match engine.get_finding(pool.get_ref(), &body.source_finding_id).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Source finding not found"
            }));
        }
        Err(e) => {
            error!("Failed to verify source finding: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to verify source finding"
            }));
        }
    };

    let _target = match engine.get_finding(pool.get_ref(), &body.target_finding_id).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Target finding not found"
            }));
        }
        Err(e) => {
            error!("Failed to verify target finding: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to verify target finding"
            }));
        }
    };

    // Record merge history
    let merge_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO finding_merge_history (id, source_finding_id, target_finding_id, merged_at, merged_by, reason)
        VALUES (?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&merge_id)
    .bind(&body.source_finding_id)
    .bind(&body.target_finding_id)
    .bind(&now)
    .bind(&claims.sub)
    .bind(&body.reason)
    .execute(pool.get_ref())
    .await {
        error!("Failed to record merge history: {}", e);
    }

    // Perform merge
    match engine.merge_findings(pool.get_ref(), &body.source_finding_id, &body.target_finding_id).await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Findings merged successfully",
            "source_id": body.source_finding_id,
            "target_id": body.target_finding_id,
            "merged_occurrence_count": source.occurrence_count
        })),
        Err(e) => {
            error!("Failed to merge findings: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to merge findings"
            }))
        }
    }
}

/// Find finding by fingerprint hash
pub async fn find_by_fingerprint(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let fingerprint_hash = path.into_inner();
    let engine = DeduplicationEngine::new();

    match engine.find_by_fingerprint(pool.get_ref(), &fingerprint_hash).await {
        Ok(Some(finding)) => HttpResponse::Ok().json(FindingResponse { finding }),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Finding not found for fingerprint"
        })),
        Err(e) => {
            error!("Failed to find by fingerprint: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to find by fingerprint"
            }))
        }
    }
}
