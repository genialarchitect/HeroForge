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
    );
}
