//! Evidence API handlers
//!
//! Provides REST API endpoints for assessment evidence management including:
//! - Add evidence (link or content)
//! - Upload evidence files
//! - List evidence for an assessment
//! - Delete evidence
//! - Download evidence files

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::compliance::manual_assessment::{AssessmentEvidence, EvidenceType};
use crate::web::auth;

use super::types::{
    AddEvidenceRequest, EvidenceListResponse, EvidenceRow, UploadEvidenceFileRequest,
    get_content_type_from_extension,
};

/// POST /api/compliance/assessments/{id}/evidence
/// Upload evidence file or add link to an assessment
#[utoipa::path(
    post,
    path = "/api/compliance/assessments/{id}/evidence",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Assessment ID")
    ),
    request_body = AddEvidenceRequest,
    responses(
        (status = 201, description = "Evidence added"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Assessment not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn add_evidence(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    assessment_id: web::Path<String>,
    request: web::Json<AddEvidenceRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let assessment_id = assessment_id.into_inner();

    // Verify ownership
    let existing =
        sqlx::query_as::<_, (String,)>("SELECT user_id FROM manual_assessments WHERE id = ?1")
            .bind(&assessment_id)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| {
                log::error!("Failed to fetch assessment: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to fetch assessment")
            })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Assessment not found"
            })));
        }
        Some((owner_id,)) if owner_id != *user_id => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to add evidence to this assessment"
            })));
        }
        _ => {}
    }

    let now = Utc::now();
    let evidence_id = Uuid::new_v4().to_string();

    let evidence_type_str = serde_json::to_string(&request.evidence_type)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid evidence type: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO assessment_evidence (
            id, assessment_id, user_id, evidence_type, title, description,
            file_path, external_url, content, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
    )
    .bind(&evidence_id)
    .bind(&assessment_id)
    .bind(user_id)
    .bind(&evidence_type_str)
    .bind(&request.title)
    .bind(&request.description)
    .bind::<Option<String>>(None) // file_path - set later for file uploads
    .bind(&request.external_url)
    .bind(&request.content)
    .bind(now)
    .bind(now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to add evidence: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to add evidence")
    })?;

    let evidence = AssessmentEvidence {
        id: evidence_id,
        assessment_id,
        evidence_type: request.evidence_type.clone(),
        title: request.title.clone(),
        description: request.description.clone(),
        file_path: None,
        external_url: request.external_url.clone(),
        content: request.content.clone(),
        created_at: now,
        updated_at: now,
    };

    Ok(HttpResponse::Created().json(evidence))
}

/// POST /api/compliance/assessments/{id}/evidence/upload
/// Upload an evidence file (base64 encoded in JSON)
#[utoipa::path(
    post,
    path = "/api/compliance/assessments/{id}/evidence/upload",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Assessment ID")
    ),
    request_body = UploadEvidenceFileRequest,
    responses(
        (status = 201, description = "Evidence file uploaded"),
        (status = 400, description = "Invalid file"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Assessment not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn upload_evidence_file(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    assessment_id: web::Path<String>,
    request: web::Json<UploadEvidenceFileRequest>,
) -> Result<HttpResponse> {
    use base64::Engine;

    let user_id = &claims.sub;
    let assessment_id = assessment_id.into_inner();

    // Verify ownership
    let existing =
        sqlx::query_as::<_, (String,)>("SELECT user_id FROM manual_assessments WHERE id = ?1")
            .bind(&assessment_id)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| {
                log::error!("Failed to fetch assessment: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to fetch assessment")
            })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Assessment not found"
            })));
        }
        Some((owner_id,)) if owner_id != *user_id => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to upload evidence to this assessment"
            })));
        }
        _ => {}
    }

    // Decode base64 file data
    let file_bytes = base64::engine::general_purpose::STANDARD
        .decode(&request.file_data)
        .map_err(|e| {
            log::error!("Failed to decode base64: {}", e);
            actix_web::error::ErrorBadRequest("Invalid base64-encoded file data")
        })?;

    // Create evidence directory if it doesn't exist
    let evidence_dir = std::env::var("EVIDENCE_DIR").unwrap_or_else(|_| "./evidence".to_string());
    tokio::fs::create_dir_all(&evidence_dir).await.map_err(|e| {
        log::error!("Failed to create evidence directory: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to process upload")
    })?;

    let now = Utc::now();
    let evidence_id = Uuid::new_v4().to_string();

    // Sanitize filename - keep only alphanumeric, dots, dashes, and underscores
    let sanitized_filename: String = request
        .filename
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let filename = if sanitized_filename.is_empty() {
        format!("{}.bin", evidence_id)
    } else {
        sanitized_filename
    };

    let filepath = format!("{}/{}_{}", evidence_dir, evidence_id, filename);

    // Write file
    tokio::fs::write(&filepath, &file_bytes).await.map_err(|e| {
        log::error!("Failed to write file: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to save file")
    })?;

    let evidence_type_str = serde_json::to_string(&EvidenceType::File)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid evidence type: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO assessment_evidence (
            id, assessment_id, user_id, evidence_type, title, description,
            file_path, external_url, content, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
    )
    .bind(&evidence_id)
    .bind(&assessment_id)
    .bind(user_id)
    .bind(&evidence_type_str)
    .bind(&request.title)
    .bind(&request.description)
    .bind(&filepath)
    .bind::<Option<String>>(None)
    .bind::<Option<String>>(None)
    .bind(now)
    .bind(now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to add evidence: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to add evidence")
    })?;

    let evidence = AssessmentEvidence {
        id: evidence_id,
        assessment_id,
        evidence_type: EvidenceType::File,
        title: request.title.clone(),
        description: request.description.clone(),
        file_path: Some(filepath),
        external_url: None,
        content: None,
        created_at: now,
        updated_at: now,
    };

    Ok(HttpResponse::Created().json(evidence))
}

/// GET /api/compliance/assessments/{id}/evidence
/// List all evidence for an assessment
#[utoipa::path(
    get,
    path = "/api/compliance/assessments/{id}/evidence",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Assessment ID")
    ),
    responses(
        (status = 200, description = "List of evidence"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Assessment not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn list_evidence(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    assessment_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let is_admin = claims.roles.contains(&"admin".to_string());
    let is_reviewer = claims.roles.contains(&"reviewer".to_string());
    let assessment_id = assessment_id.into_inner();

    // Verify access
    let existing =
        sqlx::query_as::<_, (String,)>("SELECT user_id FROM manual_assessments WHERE id = ?1")
            .bind(&assessment_id)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| {
                log::error!("Failed to fetch assessment: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to fetch assessment")
            })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Assessment not found"
            })));
        }
        Some((owner_id,)) if owner_id != *user_id && !is_admin && !is_reviewer => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to view evidence for this assessment"
            })));
        }
        _ => {}
    }

    let evidence = sqlx::query_as::<_, EvidenceRow>(
        r#"
        SELECT id, assessment_id, evidence_type, title, description,
               file_path, external_url, content, created_at, updated_at
        FROM assessment_evidence
        WHERE assessment_id = ?1
        ORDER BY created_at DESC
        "#,
    )
    .bind(&assessment_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch evidence: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch evidence")
    })?;

    let evidence: Vec<AssessmentEvidence> = evidence.into_iter().map(|e| e.into()).collect();
    let total = evidence.len();

    Ok(HttpResponse::Ok().json(EvidenceListResponse { evidence, total }))
}

/// DELETE /api/compliance/evidence/{id}
/// Delete an evidence item
#[utoipa::path(
    delete,
    path = "/api/compliance/evidence/{id}",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Evidence ID")
    ),
    responses(
        (status = 200, description = "Evidence deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Evidence not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn delete_evidence(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    evidence_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let is_admin = claims.roles.contains(&"admin".to_string());
    let evidence_id = evidence_id.into_inner();

    // Get evidence with assessment info
    let existing = sqlx::query_as::<_, (String, Option<String>)>(
        r#"
        SELECT ma.user_id, ae.file_path
        FROM assessment_evidence ae
        JOIN manual_assessments ma ON ae.assessment_id = ma.id
        WHERE ae.id = ?1
        "#,
    )
    .bind(&evidence_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch evidence: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch evidence")
    })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Evidence not found"
            })));
        }
        Some((owner_id, _)) if owner_id != *user_id && !is_admin => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to delete this evidence"
            })));
        }
        Some((_, Some(file_path))) => {
            // Delete file from disk
            if let Err(e) = tokio::fs::remove_file(&file_path).await {
                log::warn!("Failed to delete evidence file {}: {}", file_path, e);
            }
        }
        _ => {}
    }

    sqlx::query("DELETE FROM assessment_evidence WHERE id = ?1")
        .bind(&evidence_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete evidence: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete evidence")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Evidence deleted successfully"
    })))
}

/// GET /api/compliance/evidence/{id}/download
/// Download an evidence file
#[utoipa::path(
    get,
    path = "/api/compliance/evidence/{id}/download",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Evidence ID")
    ),
    responses(
        (status = 200, description = "Evidence file downloaded"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Evidence not found or not a file"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn download_evidence(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    evidence_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let is_admin = claims.roles.contains(&"admin".to_string());
    let is_reviewer = claims.roles.contains(&"reviewer".to_string());
    let evidence_id = evidence_id.into_inner();

    // Get evidence with assessment info
    let existing = sqlx::query_as::<_, (String, Option<String>, String)>(
        r#"
        SELECT ma.user_id, ae.file_path, ae.title
        FROM assessment_evidence ae
        JOIN manual_assessments ma ON ae.assessment_id = ma.id
        WHERE ae.id = ?1
        "#,
    )
    .bind(&evidence_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch evidence: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch evidence")
    })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Evidence not found"
            })));
        }
        Some((owner_id, _, _)) if owner_id != *user_id && !is_admin && !is_reviewer => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to download this evidence"
            })));
        }
        Some((_, None, _)) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Evidence is not a file"
            })));
        }
        Some((_, Some(file_path), title)) => {
            let content = tokio::fs::read(&file_path).await.map_err(|e| {
                log::error!("Failed to read evidence file: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to read file")
            })?;

            // Determine content type from file extension
            let content_type = get_content_type_from_extension(&file_path);

            // Extract filename from path
            let filename = std::path::Path::new(&file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&title);

            return Ok(HttpResponse::Ok()
                .content_type(content_type)
                .insert_header((
                    "Content-Disposition",
                    format!("attachment; filename=\"{}\"", filename),
                ))
                .body(content));
        }
    }
}
