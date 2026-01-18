//! SCAP 1.3 API Endpoints
//!
//! Provides API endpoints for SCAP content management, XCCDF benchmark operations,
//! OVAL definition queries, and SCAP assessment execution.

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::web::auth::Claims;

// ============================================================================
// Types
// ============================================================================

/// SCAP content bundle list response
#[derive(Debug, Serialize)]
pub struct ScapContentBundleList {
    pub bundles: Vec<ScapContentBundle>,
    pub total: i64,
}

/// SCAP content bundle
#[derive(Debug, Serialize, Deserialize)]
pub struct ScapContentBundle {
    pub id: String,
    pub name: String,
    pub version: String,
    pub schema_version: String,
    pub source: Option<String>,
    pub benchmark_count: i32,
    pub profile_count: i32,
    pub rule_count: i32,
    pub oval_definition_count: i32,
    pub status: String,
    pub created_at: String,
}

/// Import SCAP content request
#[derive(Debug, Deserialize)]
pub struct ImportScapContentRequest {
    pub name: String,
    pub source: Option<String>,
    pub content: String, // Base64 encoded SCAP content
}

/// XCCDF benchmark response
#[derive(Debug, Serialize)]
pub struct XccdfBenchmark {
    pub id: String,
    pub bundle_id: String,
    pub benchmark_id: String,
    pub title: String,
    pub description: Option<String>,
    pub version: String,
    pub status: String,
    pub profile_count: i32,
    pub rule_count: i32,
}

/// XCCDF profile response
#[derive(Debug, Serialize)]
pub struct XccdfProfile {
    pub id: String,
    pub benchmark_id: String,
    pub profile_id: String,
    pub title: String,
    pub description: Option<String>,
    pub selected_rules: i32,
}

/// XCCDF rule response
#[derive(Debug, Serialize)]
pub struct XccdfRule {
    pub id: String,
    pub benchmark_id: String,
    pub rule_id: String,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub check_type: String,
    pub oval_definition_id: Option<String>,
}

/// Query params for listing rules
#[derive(Debug, Deserialize)]
pub struct RuleQueryParams {
    pub profile_id: Option<String>,
    pub severity: Option<String>,
    pub limit: Option<i32>,
}

/// Start SCAP assessment request
#[derive(Debug, Deserialize)]
pub struct StartScapAssessmentRequest {
    pub benchmark_id: String,
    pub profile_id: String,
    pub target_host: String,
    pub target_ip: Option<String>,
    pub credential_id: Option<String>,
    pub engagement_id: Option<String>,
    pub customer_id: Option<String>,
}

/// SCAP assessment response
#[derive(Debug, Serialize)]
pub struct ScapAssessment {
    pub id: String,
    pub bundle_id: String,
    pub benchmark_id: String,
    pub profile_id: String,
    pub target_host: String,
    pub target_ip: Option<String>,
    pub status: String,
    pub total_rules: i32,
    pub passed: i32,
    pub failed: i32,
    pub error: i32,
    pub not_applicable: i32,
    pub score_percent: Option<f64>,
    pub started_at: String,
    pub completed_at: Option<String>,
}

// ============================================================================
// Handlers
// ============================================================================

/// List SCAP content bundles
pub async fn list_scap_content(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let bundles = sqlx::query_as::<_, (String, String, String, String, Option<String>, i32, i32, i32, i32, String, String)>(
        r#"
        SELECT id, name, version, schema_version, source, benchmark_count, profile_count,
               rule_count, oval_definition_count, status, created_at
        FROM scap_content_bundles
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(pool.get_ref())
    .await;

    match bundles {
        Ok(rows) => {
            let bundles: Vec<ScapContentBundle> = rows
                .into_iter()
                .map(|r| ScapContentBundle {
                    id: r.0,
                    name: r.1,
                    version: r.2,
                    schema_version: r.3,
                    source: r.4,
                    benchmark_count: r.5,
                    profile_count: r.6,
                    rule_count: r.7,
                    oval_definition_count: r.8,
                    status: r.9,
                    created_at: r.10,
                })
                .collect();
            let total = bundles.len() as i64;
            HttpResponse::Ok().json(ScapContentBundleList { bundles, total })
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Get SCAP content bundle by ID
pub async fn get_scap_content(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let bundle_id = path.into_inner();

    let bundle = sqlx::query_as::<_, (String, String, String, String, Option<String>, i32, i32, i32, i32, String, String)>(
        r#"
        SELECT id, name, version, schema_version, source, benchmark_count, profile_count,
               rule_count, oval_definition_count, status, created_at
        FROM scap_content_bundles WHERE id = ?
        "#
    )
    .bind(&bundle_id)
    .fetch_optional(pool.get_ref())
    .await;

    match bundle {
        Ok(Some(r)) => HttpResponse::Ok().json(ScapContentBundle {
            id: r.0,
            name: r.1,
            version: r.2,
            schema_version: r.3,
            source: r.4,
            benchmark_count: r.5,
            profile_count: r.6,
            rule_count: r.7,
            oval_definition_count: r.8,
            status: r.9,
            created_at: r.10,
        }),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Bundle not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Import SCAP content bundle
pub async fn import_scap_content(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<ImportScapContentRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    // Generate a unique ID for the bundle
    let bundle_id = uuid::Uuid::new_v4().to_string();

    // Decode base64 content
    use base64::Engine;
    let _content_bytes = match base64::engine::general_purpose::STANDARD.decode(&body.content) {
        Ok(bytes) => bytes,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid base64 content: {}", e)
        })),
    };

    // TODO: Parse SCAP content and extract benchmarks, profiles, rules, OVAL definitions
    // For now, create a placeholder bundle

    let result = sqlx::query(
        r#"
        INSERT INTO scap_content_bundles (id, name, version, schema_version, source, benchmark_count,
                                          profile_count, rule_count, oval_definition_count, status,
                                          created_by, created_at)
        VALUES (?, ?, '1.0', '1.3', ?, 0, 0, 0, 0, 'processing', ?, datetime('now'))
        "#
    )
    .bind(&bundle_id)
    .bind(&body.name)
    .bind(&body.source)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": bundle_id,
            "status": "processing",
            "message": "SCAP content import started"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Delete SCAP content bundle
pub async fn delete_scap_content(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let bundle_id = path.into_inner();

    let result = sqlx::query("DELETE FROM scap_content_bundles WHERE id = ?")
        .bind(&bundle_id)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => HttpResponse::Ok().json(serde_json::json!({
            "message": "Bundle deleted successfully"
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "Bundle not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// List benchmarks in a bundle
pub async fn list_benchmarks(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let bundle_id = path.into_inner();

    let benchmarks = sqlx::query_as::<_, (String, String, String, String, Option<String>, String, String, i32, i32)>(
        r#"
        SELECT id, bundle_id, benchmark_id, title, description, version, status, profile_count, rule_count
        FROM scap_xccdf_benchmarks WHERE bundle_id = ?
        ORDER BY title
        "#
    )
    .bind(&bundle_id)
    .fetch_all(pool.get_ref())
    .await;

    match benchmarks {
        Ok(rows) => {
            let benchmarks: Vec<XccdfBenchmark> = rows
                .into_iter()
                .map(|r| XccdfBenchmark {
                    id: r.0,
                    bundle_id: r.1,
                    benchmark_id: r.2,
                    title: r.3,
                    description: r.4,
                    version: r.5,
                    status: r.6,
                    profile_count: r.7,
                    rule_count: r.8,
                })
                .collect();
            HttpResponse::Ok().json(benchmarks)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// List profiles in a benchmark
pub async fn list_profiles(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let benchmark_id = path.into_inner();

    let profiles = sqlx::query_as::<_, (String, String, String, String, Option<String>, i32)>(
        r#"
        SELECT id, benchmark_id, profile_id, title, description, selected_rules
        FROM scap_xccdf_profiles WHERE benchmark_id = ?
        ORDER BY title
        "#
    )
    .bind(&benchmark_id)
    .fetch_all(pool.get_ref())
    .await;

    match profiles {
        Ok(rows) => {
            let profiles: Vec<XccdfProfile> = rows
                .into_iter()
                .map(|r| XccdfProfile {
                    id: r.0,
                    benchmark_id: r.1,
                    profile_id: r.2,
                    title: r.3,
                    description: r.4,
                    selected_rules: r.5,
                })
                .collect();
            HttpResponse::Ok().json(profiles)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// List rules in a benchmark
pub async fn list_rules(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    query: web::Query<RuleQueryParams>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let benchmark_id = path.into_inner();
    let limit = query.limit.unwrap_or(100);

    let rules = sqlx::query_as::<_, (String, String, String, String, Option<String>, String, String, Option<String>)>(
        r#"
        SELECT id, benchmark_id, rule_id, title, description, severity, check_type, oval_definition_id
        FROM scap_xccdf_rules WHERE benchmark_id = ?
        ORDER BY severity DESC, title
        LIMIT ?
        "#
    )
    .bind(&benchmark_id)
    .bind(limit)
    .fetch_all(pool.get_ref())
    .await;

    match rules {
        Ok(rows) => {
            let rules: Vec<XccdfRule> = rows
                .into_iter()
                .map(|r| XccdfRule {
                    id: r.0,
                    benchmark_id: r.1,
                    rule_id: r.2,
                    title: r.3,
                    description: r.4,
                    severity: r.5,
                    check_type: r.6,
                    oval_definition_id: r.7,
                })
                .collect();
            HttpResponse::Ok().json(rules)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Start SCAP assessment
pub async fn start_assessment(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<StartScapAssessmentRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let assessment_id = uuid::Uuid::new_v4().to_string();

    let result = sqlx::query(
        r#"
        INSERT INTO scap_scan_executions (id, benchmark_id, profile_id, target_host, target_ip,
                                          status, created_by, started_at)
        VALUES (?, ?, ?, ?, ?, 'pending', ?, datetime('now'))
        "#
    )
    .bind(&assessment_id)
    .bind(&body.benchmark_id)
    .bind(&body.profile_id)
    .bind(&body.target_host)
    .bind(&body.target_ip)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => {
            // TODO: Spawn async task to run the SCAP assessment
            HttpResponse::Created().json(serde_json::json!({
                "id": assessment_id,
                "status": "pending",
                "message": "SCAP assessment started"
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// List SCAP assessments
pub async fn list_assessments(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let assessments = sqlx::query_as::<_, (String, String, String, String, String, Option<String>, String, i32, i32, i32, i32, i32, Option<f64>, String, Option<String>)>(
        r#"
        SELECT id, bundle_id, benchmark_id, profile_id, target_host, target_ip, status,
               total_rules, passed, failed, error, not_applicable, score_percent, started_at, completed_at
        FROM scap_scan_executions
        ORDER BY started_at DESC
        LIMIT 100
        "#
    )
    .fetch_all(pool.get_ref())
    .await;

    match assessments {
        Ok(rows) => {
            let assessments: Vec<ScapAssessment> = rows
                .into_iter()
                .map(|r| ScapAssessment {
                    id: r.0,
                    bundle_id: r.1,
                    benchmark_id: r.2,
                    profile_id: r.3,
                    target_host: r.4,
                    target_ip: r.5,
                    status: r.6,
                    total_rules: r.7,
                    passed: r.8,
                    failed: r.9,
                    error: r.10,
                    not_applicable: r.11,
                    score_percent: r.12,
                    started_at: r.13,
                    completed_at: r.14,
                })
                .collect();
            HttpResponse::Ok().json(assessments)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Get assessment by ID
pub async fn get_assessment(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let assessment_id = path.into_inner();

    let assessment = sqlx::query_as::<_, (String, String, String, String, String, Option<String>, String, i32, i32, i32, i32, i32, Option<f64>, String, Option<String>)>(
        r#"
        SELECT id, bundle_id, benchmark_id, profile_id, target_host, target_ip, status,
               total_rules, passed, failed, error, not_applicable, score_percent, started_at, completed_at
        FROM scap_scan_executions WHERE id = ?
        "#
    )
    .bind(&assessment_id)
    .fetch_optional(pool.get_ref())
    .await;

    match assessment {
        Ok(Some(r)) => HttpResponse::Ok().json(ScapAssessment {
            id: r.0,
            bundle_id: r.1,
            benchmark_id: r.2,
            profile_id: r.3,
            target_host: r.4,
            target_ip: r.5,
            status: r.6,
            total_rules: r.7,
            passed: r.8,
            failed: r.9,
            error: r.10,
            not_applicable: r.11,
            score_percent: r.12,
            started_at: r.13,
            completed_at: r.14,
        }),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Assessment not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Get ARF report for an assessment
pub async fn get_arf_report(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let assessment_id = path.into_inner();

    // Get ARF report from database
    let arf = sqlx::query_as::<_, (String, String, String)>(
        r#"
        SELECT id, arf_xml, created_at
        FROM scap_arf_reports WHERE execution_id = ?
        "#
    )
    .bind(&assessment_id)
    .fetch_optional(pool.get_ref())
    .await;

    match arf {
        Ok(Some(r)) => HttpResponse::Ok()
            .content_type("application/xml")
            .body(r.1),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "ARF report not found for this assessment"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Get CKL (STIG Viewer Checklist) report for an assessment
pub async fn get_ckl_report(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let assessment_id = path.into_inner();

    // Generate CKL report using the CKL generator
    use crate::scap::ckl::CklGenerator;

    let generator = CklGenerator::new(pool.get_ref());

    match generator.generate(&assessment_id).await {
        Ok(ckl_xml) => HttpResponse::Ok()
            .content_type("application/xml")
            .insert_header(("Content-Disposition", format!("attachment; filename=\"{}.ckl\"", assessment_id)))
            .body(ckl_xml),
        Err(e) => {
            // Check if the error is "not found"
            let error_msg = e.to_string();
            if error_msg.contains("not found") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Assessment not found"
                }))
            } else {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to generate CKL report: {}", e)
                }))
            }
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configure SCAP API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/scap")
            // Content management
            .route("/content", web::get().to(list_scap_content))
            .route("/content", web::post().to(import_scap_content))
            .route("/content/{id}", web::get().to(get_scap_content))
            .route("/content/{id}", web::delete().to(delete_scap_content))
            // Benchmarks and profiles
            .route("/content/{id}/benchmarks", web::get().to(list_benchmarks))
            .route("/benchmarks/{id}/profiles", web::get().to(list_profiles))
            .route("/benchmarks/{id}/rules", web::get().to(list_rules))
            // Assessments
            .route("/assessments", web::get().to(list_assessments))
            .route("/assessments", web::post().to(start_assessment))
            .route("/assessments/{id}", web::get().to(get_assessment))
            .route("/assessments/{id}/arf", web::get().to(get_arf_report))
            .route("/assessments/{id}/ckl", web::get().to(get_ckl_report))
            // STIG Repository Sync
            .route("/stigs/sync/status", web::get().to(get_stig_sync_status))
            .route("/stigs/sync/check", web::post().to(trigger_stig_sync))
            .route("/stigs/available", web::get().to(list_available_stigs))
            .route("/stigs/search", web::get().to(search_available_stigs))
            .route("/stigs/tracked", web::get().to(list_tracked_stigs))
            .route("/stigs/tracked", web::post().to(add_tracked_stig))
            .route("/stigs/tracked/{id}", web::get().to(get_tracked_stig))
            .route("/stigs/tracked/{id}", web::delete().to(delete_tracked_stig))
            .route("/stigs/tracked/{id}/auto-update", web::put().to(update_tracked_stig_auto_update))
            .route("/stigs/tracked/{id}/download", web::post().to(download_stig))
            .route("/stigs/sync/history", web::get().to(get_sync_history))
            // STIG Diff Reports
            .route("/stigs/diff", web::post().to(compare_stigs))
            .route("/stigs/diff/{old_id}/{new_id}", web::get().to(get_stig_diff))
            // STIG Notifications
            .route("/stigs/notifications/test", web::post().to(test_stig_notification))
    );
}

// ============================================================================
// STIG Repository Sync Types
// ============================================================================

/// STIG sync status response
#[derive(Debug, Serialize)]
pub struct StigSyncStatusResponse {
    pub in_progress: bool,
    pub current_operation: Option<String>,
    pub last_sync_at: Option<String>,
    pub last_sync_result: Option<String>,
    pub next_sync_at: Option<String>,
    pub total_tracked: usize,
    pub updates_available: usize,
    pub last_errors: Vec<String>,
}

/// Available STIG entry response
#[derive(Debug, Serialize)]
pub struct AvailableStigResponse {
    pub stig_id: String,
    pub name: String,
    pub short_name: String,
    pub version: i32,
    pub release: i32,
    pub release_date: Option<String>,
    pub target_product: String,
    pub category: String,
    pub download_url: String,
    pub is_benchmark: bool,
}

/// Tracked STIG response
#[derive(Debug, Serialize)]
pub struct TrackedStigResponse {
    pub id: String,
    pub stig_id: String,
    pub stig_name: String,
    pub current_version: i32,
    pub current_release: i32,
    pub available_version: Option<i32>,
    pub available_release: Option<i32>,
    pub release_date: Option<String>,
    pub bundle_id: Option<String>,
    pub local_path: Option<String>,
    pub last_checked_at: Option<String>,
    pub last_updated_at: Option<String>,
    pub auto_update: bool,
    pub has_update: bool,
    pub created_at: String,
}

/// Add tracked STIG request
#[derive(Debug, Deserialize)]
pub struct AddTrackedStigRequest {
    pub stig_id: String,
    pub auto_update: Option<bool>,
}

/// Update auto-update request
#[derive(Debug, Deserialize)]
pub struct UpdateAutoUpdateRequest {
    pub auto_update: bool,
}

/// Search STIGs query params
#[derive(Debug, Deserialize)]
pub struct SearchStigsQuery {
    pub q: String,
}

/// Sync history query params
#[derive(Debug, Deserialize)]
pub struct SyncHistoryQuery {
    pub stig_id: Option<String>,
    pub limit: Option<i32>,
}

// ============================================================================
// STIG Repository Sync Handlers
// ============================================================================

use crate::scap::stig_sync::{StigDownloader, StigSyncConfig};
use crate::db::scap as db_scap;

/// Get STIG sync status
pub async fn get_stig_sync_status(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    // Get tracked STIGs count
    let tracked = match db_scap::list_tracked_stigs(pool.get_ref()).await {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to list tracked STIGs: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Database error: {}", e)
            }));
        }
    };

    // Count updates available
    let updates_available = tracked.iter()
        .filter(|t| {
            t.available_version.map_or(false, |av| {
                av > t.current_version ||
                (av == t.current_version && t.available_release.unwrap_or(0) > t.current_release)
            })
        })
        .count();

    HttpResponse::Ok().json(StigSyncStatusResponse {
        in_progress: false, // Would need scheduler state for real-time status
        current_operation: None,
        last_sync_at: tracked.iter()
            .filter_map(|t| t.last_checked_at)
            .max()
            .map(|dt| dt.to_rfc3339()),
        last_sync_result: Some("success".to_string()),
        next_sync_at: None,
        total_tracked: tracked.len(),
        updates_available,
        last_errors: vec![],
    })
}

/// Trigger a manual STIG sync check
pub async fn trigger_stig_sync(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    // For now, just check for updates for all tracked STIGs
    let tracked = match db_scap::list_tracked_stigs(pool.get_ref()).await {
        Ok(t) => t,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Database error: {}", e)
            }));
        }
    };

    let config = StigSyncConfig::default();
    let downloader = match StigDownloader::new(config) {
        Ok(d) => d,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create downloader: {}", e)
            }));
        }
    };

    let mut updates_found = 0;
    let mut errors = Vec::new();

    for stig in &tracked {
        match downloader.check_for_update(stig).await {
            Ok(Some(update)) => {
                updates_found += 1;
                if let Err(e) = db_scap::update_tracked_stig_available_version(
                    pool.get_ref(),
                    &stig.id,
                    update.version,
                    update.release,
                ).await {
                    errors.push(format!("Failed to update {}: {}", stig.stig_name, e));
                }
            }
            Ok(None) => {}
            Err(e) => {
                errors.push(format!("Failed to check {}: {}", stig.stig_name, e));
            }
        }

        // Update last_checked_at
        let _ = db_scap::update_tracked_stig_last_checked(pool.get_ref(), &stig.id).await;
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Sync check completed",
        "tracked_count": tracked.len(),
        "updates_found": updates_found,
        "errors": errors
    }))
}

/// List available STIGs from DISA
pub async fn list_available_stigs(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let config = StigSyncConfig::default();
    let downloader = match StigDownloader::new(config) {
        Ok(d) => d,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create downloader: {}", e)
            }));
        }
    };

    match downloader.fetch_available_stigs().await {
        Ok(stigs) => {
            let response: Vec<AvailableStigResponse> = stigs.into_iter()
                .map(|s| AvailableStigResponse {
                    stig_id: s.stig_id,
                    name: s.name,
                    short_name: s.short_name,
                    version: s.version,
                    release: s.release,
                    release_date: s.release_date.map(|d| d.to_string()),
                    target_product: s.target_product,
                    category: s.category.to_string(),
                    download_url: s.download_url,
                    is_benchmark: s.is_benchmark,
                })
                .collect();

            HttpResponse::Ok().json(serde_json::json!({
                "stigs": response,
                "total": response.len()
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to fetch available STIGs: {}", e)
        })),
    }
}

/// Search available STIGs
pub async fn search_available_stigs(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    query: web::Query<SearchStigsQuery>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let config = StigSyncConfig::default();
    let downloader = match StigDownloader::new(config) {
        Ok(d) => d,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create downloader: {}", e)
            }));
        }
    };

    match downloader.search_stigs(&query.q).await {
        Ok(stigs) => {
            let response: Vec<AvailableStigResponse> = stigs.into_iter()
                .map(|s| AvailableStigResponse {
                    stig_id: s.stig_id,
                    name: s.name,
                    short_name: s.short_name,
                    version: s.version,
                    release: s.release,
                    release_date: s.release_date.map(|d| d.to_string()),
                    target_product: s.target_product,
                    category: s.category.to_string(),
                    download_url: s.download_url,
                    is_benchmark: s.is_benchmark,
                })
                .collect();

            HttpResponse::Ok().json(serde_json::json!({
                "stigs": response,
                "total": response.len()
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to search STIGs: {}", e)
        })),
    }
}

/// List tracked STIGs
pub async fn list_tracked_stigs(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    match db_scap::list_tracked_stigs(pool.get_ref()).await {
        Ok(stigs) => {
            let response: Vec<TrackedStigResponse> = stigs.into_iter()
                .map(|s| {
                    let has_update = s.available_version.map_or(false, |av| {
                        av > s.current_version ||
                        (av == s.current_version && s.available_release.unwrap_or(0) > s.current_release)
                    });
                    TrackedStigResponse {
                        id: s.id,
                        stig_id: s.stig_id,
                        stig_name: s.stig_name,
                        current_version: s.current_version,
                        current_release: s.current_release,
                        available_version: s.available_version,
                        available_release: s.available_release,
                        release_date: s.release_date.map(|d| d.to_string()),
                        bundle_id: s.bundle_id,
                        local_path: s.local_path,
                        last_checked_at: s.last_checked_at.map(|dt| dt.to_rfc3339()),
                        last_updated_at: s.last_updated_at.map(|dt| dt.to_rfc3339()),
                        auto_update: s.auto_update,
                        has_update,
                        created_at: s.created_at.to_rfc3339(),
                    }
                })
                .collect();

            HttpResponse::Ok().json(serde_json::json!({
                "stigs": response,
                "total": response.len()
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Add a STIG to track
pub async fn add_tracked_stig(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<AddTrackedStigRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    // First, fetch the STIG info from DISA
    let config = StigSyncConfig::default();
    let downloader = match StigDownloader::new(config.clone()) {
        Ok(d) => d,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create downloader: {}", e)
            }));
        }
    };

    let available = match downloader.fetch_available_stigs().await {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to fetch available STIGs: {}", e)
            }));
        }
    };

    let stig = match available.iter().find(|s| s.stig_id == body.stig_id) {
        Some(s) => s,
        None => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("STIG {} not found", body.stig_id)
            }));
        }
    };

    // Check if already tracked
    if let Ok(Some(_)) = db_scap::get_tracked_stig_by_stig_id(pool.get_ref(), &body.stig_id).await {
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "STIG is already being tracked"
        }));
    }

    use crate::scap::stig_sync::types::TrackedStig;
    use chrono::Utc;

    let tracked = TrackedStig {
        id: String::new(),
        stig_id: stig.stig_id.clone(),
        stig_name: stig.name.clone(),
        current_version: stig.version,
        current_release: stig.release,
        available_version: None,
        available_release: None,
        release_date: stig.release_date,
        bundle_id: None,
        local_path: None,
        download_url: Some(stig.download_url.clone()),
        last_checked_at: Some(Utc::now()),
        last_updated_at: None,
        auto_update: body.auto_update.unwrap_or(true),
        created_at: Utc::now(),
    };

    match db_scap::create_tracked_stig(pool.get_ref(), &tracked).await {
        Ok(id) => HttpResponse::Created().json(serde_json::json!({
            "id": id,
            "message": "STIG added to tracking",
            "stig_id": body.stig_id
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to add tracked STIG: {}", e)
        })),
    }
}

/// Get a tracked STIG by ID
pub async fn get_tracked_stig(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let id = path.into_inner();

    match db_scap::get_tracked_stig(pool.get_ref(), &id).await {
        Ok(Some(s)) => {
            let has_update = s.available_version.map_or(false, |av| {
                av > s.current_version ||
                (av == s.current_version && s.available_release.unwrap_or(0) > s.current_release)
            });
            HttpResponse::Ok().json(TrackedStigResponse {
                id: s.id,
                stig_id: s.stig_id,
                stig_name: s.stig_name,
                current_version: s.current_version,
                current_release: s.current_release,
                available_version: s.available_version,
                available_release: s.available_release,
                release_date: s.release_date.map(|d| d.to_string()),
                bundle_id: s.bundle_id,
                local_path: s.local_path,
                last_checked_at: s.last_checked_at.map(|dt| dt.to_rfc3339()),
                last_updated_at: s.last_updated_at.map(|dt| dt.to_rfc3339()),
                auto_update: s.auto_update,
                has_update,
                created_at: s.created_at.to_rfc3339(),
            })
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Tracked STIG not found"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Delete a tracked STIG
pub async fn delete_tracked_stig(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let id = path.into_inner();

    match db_scap::delete_tracked_stig(pool.get_ref(), &id).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Tracked STIG deleted successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to delete tracked STIG: {}", e)
        })),
    }
}

/// Update auto-update setting for a tracked STIG
pub async fn update_tracked_stig_auto_update(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateAutoUpdateRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let id = path.into_inner();

    match db_scap::update_tracked_stig_auto_update(pool.get_ref(), &id, body.auto_update).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Auto-update setting updated",
            "auto_update": body.auto_update
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to update auto-update setting: {}", e)
        })),
    }
}

/// Download and import a STIG
pub async fn download_stig(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let id = path.into_inner();

    // Get the tracked STIG
    let tracked = match db_scap::get_tracked_stig(pool.get_ref(), &id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Tracked STIG not found"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Database error: {}", e)
            }));
        }
    };

    let config = StigSyncConfig::default();
    let downloader = match StigDownloader::new(config.clone()) {
        Ok(d) => d,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create downloader: {}", e)
            }));
        }
    };

    // Fetch available STIGs to get download info
    let available = match downloader.fetch_available_stigs().await {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to fetch available STIGs: {}", e)
            }));
        }
    };

    let stig_entry = match available.iter().find(|s| s.stig_id == tracked.stig_id) {
        Some(s) => s,
        None => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("STIG {} not found in available list", tracked.stig_id)
            }));
        }
    };

    // Download the STIG
    match downloader.download_stig(stig_entry, &config.download_dir).await {
        Ok(path) => {
            // Update the tracked STIG with the new path
            if let Err(e) = db_scap::update_tracked_stig_version(
                pool.get_ref(),
                &id,
                stig_entry.version,
                stig_entry.release,
                None,
                Some(&path),
            ).await {
                log::error!("Failed to update tracked STIG after download: {}", e);
            }

            HttpResponse::Ok().json(serde_json::json!({
                "message": "STIG downloaded successfully",
                "path": path,
                "version": stig_entry.version,
                "release": stig_entry.release
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to download STIG: {}", e)
        })),
    }
}

/// Get sync history
pub async fn get_sync_history(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    query: web::Query<SyncHistoryQuery>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let limit = query.limit.unwrap_or(50);

    let history = if let Some(stig_id) = &query.stig_id {
        db_scap::get_stig_sync_history(pool.get_ref(), stig_id, limit).await
    } else {
        db_scap::get_recent_sync_history(pool.get_ref(), limit).await
    };

    match history {
        Ok(entries) => HttpResponse::Ok().json(serde_json::json!({
            "history": entries,
            "total": entries.len()
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

// ============================================================================
// STIG Diff Types and Handlers
// ============================================================================

/// Request to compare two STIGs
#[derive(Debug, Deserialize)]
pub struct CompareStigsRequest {
    /// Path or bundle ID for the old STIG
    pub old_stig: String,
    /// Path or bundle ID for the new STIG
    pub new_stig: String,
    /// Output format: json, html, or markdown
    #[serde(default = "default_diff_format")]
    pub format: String,
}

fn default_diff_format() -> String {
    "json".to_string()
}

/// STIG diff summary response
#[derive(Debug, Serialize)]
pub struct StigDiffSummaryResponse {
    pub old_benchmark: BenchmarkInfoResponse,
    pub new_benchmark: BenchmarkInfoResponse,
    pub summary: DiffSummaryResponse,
    pub generated_at: String,
}

#[derive(Debug, Serialize)]
pub struct BenchmarkInfoResponse {
    pub id: String,
    pub title: String,
    pub version: String,
    pub rule_count: usize,
    pub profile_count: usize,
}

#[derive(Debug, Serialize)]
pub struct DiffSummaryResponse {
    pub total_changes: usize,
    pub rules_added: usize,
    pub rules_removed: usize,
    pub rules_modified: usize,
    pub severity_upgrades: usize,
    pub severity_downgrades: usize,
    pub profiles_added: usize,
    pub profiles_removed: usize,
    pub values_added: usize,
    pub values_removed: usize,
}

/// Compare two STIGs and generate a diff report
pub async fn compare_stigs(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<CompareStigsRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    use crate::scap::stig_sync::diff::compare_stig_bundles;

    // Perform the comparison
    let diff = match compare_stig_bundles(&body.old_stig, &body.new_stig).await {
        Ok(d) => d,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Failed to compare STIGs: {}", e)
            }));
        }
    };

    // Return in requested format
    match body.format.to_lowercase().as_str() {
        "html" => {
            HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(diff.to_html())
        }
        "markdown" | "md" => {
            HttpResponse::Ok()
                .content_type("text/markdown; charset=utf-8")
                .body(diff.to_markdown())
        }
        _ => {
            // Default to JSON
            match diff.to_json() {
                Ok(json) => HttpResponse::Ok()
                    .content_type("application/json")
                    .body(json),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to serialize diff: {}", e)
                })),
            }
        }
    }
}

/// Get diff between two tracked STIGs by their IDs
pub async fn get_stig_diff(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
    query: web::Query<DiffQueryParams>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let (old_id, new_id) = path.into_inner();

    // Get the tracked STIGs
    let old_tracked = match db_scap::get_tracked_stig(pool.get_ref(), &old_id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("Old STIG {} not found", old_id)
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Database error: {}", e)
            }));
        }
    };

    let new_tracked = match db_scap::get_tracked_stig(pool.get_ref(), &new_id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("New STIG {} not found", new_id)
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Database error: {}", e)
            }));
        }
    };

    // Ensure both have local paths
    let old_path = match &old_tracked.local_path {
        Some(p) => p.clone(),
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Old STIG has not been downloaded"
            }));
        }
    };

    let new_path = match &new_tracked.local_path {
        Some(p) => p.clone(),
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "New STIG has not been downloaded"
            }));
        }
    };

    use crate::scap::stig_sync::diff::compare_stig_bundles;

    let diff = match compare_stig_bundles(&old_path, &new_path).await {
        Ok(d) => d,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to compare STIGs: {}", e)
            }));
        }
    };

    // Return in requested format
    let format = query.format.as_deref().unwrap_or("json");
    match format.to_lowercase().as_str() {
        "html" => {
            HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .insert_header(("Content-Disposition", format!(
                    "attachment; filename=\"stig_diff_{}_{}.html\"",
                    old_tracked.stig_id, new_tracked.stig_id
                )))
                .body(diff.to_html())
        }
        "markdown" | "md" => {
            HttpResponse::Ok()
                .content_type("text/markdown; charset=utf-8")
                .insert_header(("Content-Disposition", format!(
                    "attachment; filename=\"stig_diff_{}_{}.md\"",
                    old_tracked.stig_id, new_tracked.stig_id
                )))
                .body(diff.to_markdown())
        }
        _ => {
            match diff.to_json() {
                Ok(json) => HttpResponse::Ok()
                    .content_type("application/json")
                    .body(json),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to serialize diff: {}", e)
                })),
            }
        }
    }
}

/// Query params for diff endpoint
#[derive(Debug, Deserialize)]
pub struct DiffQueryParams {
    /// Output format: json, html, or markdown
    pub format: Option<String>,
}

// ============================================================================
// STIG Notification Handlers
// ============================================================================

/// Send a test STIG notification to verify webhook configuration
pub async fn test_stig_notification(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    use crate::scap::stig_sync::notifications::StigNotifier;

    let notifier = StigNotifier::new(pool.get_ref().clone());

    match notifier.send_test_notification(&claims.sub).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Test notification sent successfully",
            "note": "Check your configured webhooks for the test payload"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to send test notification: {}", e)
        })),
    }
}
