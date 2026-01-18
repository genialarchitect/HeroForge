//! Portal Collaboration API
//!
//! Enables collaboration features for the customer portal including:
//! - Threaded discussions on findings
//! - Severity dispute workflow
//! - Bulk vulnerability acknowledgment
//! - File attachments and evidence sharing

use actix_web::{web, HttpRequest, HttpResponse, HttpMessage, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use super::auth::PortalClaims;

// ============================================================================
// Types
// ============================================================================

/// Discussion comment on a vulnerability
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct VulnerabilityComment {
    pub id: String,
    pub vulnerability_id: String,
    pub author_id: String,
    pub author_name: String,
    pub author_type: String, // "customer" or "consultant"
    pub content: String,
    pub parent_id: Option<String>,
    pub created_at: String,
    pub updated_at: Option<String>,
    pub is_internal: bool,
}

/// Create comment request
#[derive(Debug, Deserialize)]
pub struct CreateCommentRequest {
    pub content: String,
    pub parent_id: Option<String>,
}

/// Severity dispute
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct SeverityDispute {
    pub id: String,
    pub vulnerability_id: String,
    pub original_severity: String,
    pub proposed_severity: String,
    pub justification: String,
    pub status: String, // "pending", "approved", "rejected", "under_review"
    pub submitted_by: String,
    pub submitted_at: String,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<String>,
    pub review_notes: Option<String>,
}

/// Create severity dispute request
#[derive(Debug, Deserialize)]
pub struct CreateDisputeRequest {
    pub proposed_severity: String,
    pub justification: String,
}

/// Vulnerability acknowledgment
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct VulnerabilityAcknowledgment {
    pub id: String,
    pub vulnerability_id: String,
    pub acknowledged_by: String,
    pub acknowledged_at: String,
    pub notes: Option<String>,
    pub risk_accepted: bool,
    pub expected_remediation_date: Option<String>,
}

/// Bulk acknowledgment request
#[derive(Debug, Deserialize)]
pub struct BulkAcknowledgmentRequest {
    pub vulnerability_ids: Vec<String>,
    pub notes: Option<String>,
    pub risk_accepted: bool,
    pub expected_remediation_date: Option<String>,
}

/// Single acknowledgment request
#[derive(Debug, Deserialize)]
pub struct AcknowledgmentRequest {
    pub notes: Option<String>,
    pub risk_accepted: bool,
    pub expected_remediation_date: Option<String>,
}

/// File attachment metadata
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct VulnerabilityAttachment {
    pub id: String,
    pub vulnerability_id: String,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub uploaded_by: String,
    pub uploaded_at: String,
    pub description: Option<String>,
}

/// Upload attachment request
#[derive(Debug, Deserialize)]
pub struct UploadAttachmentRequest {
    pub filename: String,
    pub content_type: String,
    pub description: Option<String>,
    pub data_base64: String,
}

/// Discussion thread summary
#[derive(Debug, Serialize)]
pub struct DiscussionThread {
    pub root_comment: VulnerabilityComment,
    pub replies: Vec<VulnerabilityComment>,
    pub reply_count: i64,
}

/// Collaboration summary for a vulnerability
#[derive(Debug, Serialize)]
pub struct VulnerabilityCollaboration {
    pub vulnerability_id: String,
    pub comment_count: i64,
    pub has_dispute: bool,
    pub dispute_status: Option<String>,
    pub is_acknowledged: bool,
    pub attachment_count: i64,
    pub last_activity: Option<String>,
}

// ============================================================================
// Discussion Endpoints
// ============================================================================

/// GET /api/portal/vulnerabilities/{id}/comments - List comments for a vulnerability
pub async fn list_comments(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => return Ok(HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"}))),
    };

    let vulnerability_id = path.into_inner();

    // Verify the vulnerability belongs to this customer
    let vuln_check = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM vulnerability_tracking vt
           JOIN scan_results sr ON vt.scan_id = sr.id
           WHERE vt.id = ? AND sr.customer_id = ?"#
    )
    .bind(&vulnerability_id)
    .bind(&claims.customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    if vuln_check == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Vulnerability not found"})));
    }

    // Get all comments (excluding internal consultant notes for portal users)
    let comments = sqlx::query_as::<_, VulnerabilityComment>(
        r#"SELECT id, vulnerability_id, author_id, author_name, author_type,
                  content, parent_id, created_at, updated_at, is_internal
           FROM portal_vulnerability_comments
           WHERE vulnerability_id = ? AND is_internal = 0
           ORDER BY created_at ASC"#
    )
    .bind(&vulnerability_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // Organize into threads
    let threads = organize_into_threads(comments);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "vulnerability_id": vulnerability_id,
        "threads": threads
    })))
}

/// POST /api/portal/vulnerabilities/{id}/comments - Add a comment
pub async fn create_comment(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<CreateCommentRequest>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => return Ok(HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"}))),
    };

    let vulnerability_id = path.into_inner();

    // Verify access
    let vuln_check = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM vulnerability_tracking vt
           JOIN scan_results sr ON vt.scan_id = sr.id
           WHERE vt.id = ? AND sr.customer_id = ?"#
    )
    .bind(&vulnerability_id)
    .bind(&claims.customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    if vuln_check == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Vulnerability not found"})));
    }

    // Validate content
    if body.content.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "Comment content cannot be empty"})));
    }

    if body.content.len() > 10000 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "Comment too long (max 10000 chars)"})));
    }

    // If replying, verify parent exists
    if let Some(parent_id) = &body.parent_id {
        let parent_exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM portal_vulnerability_comments WHERE id = ? AND vulnerability_id = ?"
        )
        .bind(parent_id)
        .bind(&vulnerability_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or(0);

        if parent_exists == 0 {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "Parent comment not found"})));
        }
    }

    let comment_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"INSERT INTO portal_vulnerability_comments
           (id, vulnerability_id, author_id, author_name, author_type, content, parent_id, created_at, is_internal)
           VALUES (?, ?, ?, ?, 'customer', ?, ?, ?, 0)"#
    )
    .bind(&comment_id)
    .bind(&vulnerability_id)
    .bind(&claims.sub)
    .bind(&claims.email)
    .bind(&body.content)
    .bind(&body.parent_id)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": comment_id,
        "vulnerability_id": vulnerability_id,
        "content": body.content,
        "created_at": now,
        "message": "Comment created successfully"
    })))
}

// ============================================================================
// Severity Dispute Endpoints
// ============================================================================

/// GET /api/portal/vulnerabilities/{id}/dispute - Get dispute status
pub async fn get_dispute(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => return Ok(HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"}))),
    };

    let vulnerability_id = path.into_inner();

    // Verify access
    let vuln_check = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM vulnerability_tracking vt
           JOIN scan_results sr ON vt.scan_id = sr.id
           WHERE vt.id = ? AND sr.customer_id = ?"#
    )
    .bind(&vulnerability_id)
    .bind(&claims.customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    if vuln_check == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Vulnerability not found"})));
    }

    let dispute = sqlx::query_as::<_, SeverityDispute>(
        r#"SELECT id, vulnerability_id, original_severity, proposed_severity, justification,
                  status, submitted_by, submitted_at, reviewed_by, reviewed_at, review_notes
           FROM severity_disputes
           WHERE vulnerability_id = ?
           ORDER BY submitted_at DESC LIMIT 1"#
    )
    .bind(&vulnerability_id)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "vulnerability_id": vulnerability_id,
        "dispute": dispute
    })))
}

/// POST /api/portal/vulnerabilities/{id}/dispute - Submit severity dispute
pub async fn create_dispute(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<CreateDisputeRequest>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => return Ok(HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"}))),
    };

    let vulnerability_id = path.into_inner();

    // Verify access and get current severity
    let vuln = sqlx::query_as::<_, (String,)>(
        r#"SELECT vt.severity FROM vulnerability_tracking vt
           JOIN scan_results sr ON vt.scan_id = sr.id
           WHERE vt.id = ? AND sr.customer_id = ?"#
    )
    .bind(&vulnerability_id)
    .bind(&claims.customer_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let original_severity = match vuln {
        Some((s,)) => s,
        None => return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Vulnerability not found"}))),
    };

    // Validate proposed severity
    let valid_severities = ["critical", "high", "medium", "low", "info"];
    let proposed = body.proposed_severity.to_lowercase();
    if !valid_severities.contains(&proposed.as_str()) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid severity level",
            "valid_values": valid_severities
        })));
    }

    if proposed == original_severity.to_lowercase() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Proposed severity is the same as current severity"
        })));
    }

    // Check for existing pending dispute
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM severity_disputes WHERE vulnerability_id = ? AND status = 'pending'"
    )
    .bind(&vulnerability_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    if existing > 0 {
        return Ok(HttpResponse::Conflict().json(serde_json::json!({
            "error": "A pending dispute already exists for this vulnerability"
        })));
    }

    // Validate justification
    if body.justification.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Justification is required"
        })));
    }

    let dispute_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"INSERT INTO severity_disputes
           (id, vulnerability_id, original_severity, proposed_severity, justification, status, submitted_by, submitted_at)
           VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)"#
    )
    .bind(&dispute_id)
    .bind(&vulnerability_id)
    .bind(&original_severity)
    .bind(&proposed)
    .bind(&body.justification)
    .bind(&claims.email)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": dispute_id,
        "vulnerability_id": vulnerability_id,
        "original_severity": original_severity,
        "proposed_severity": proposed,
        "status": "pending",
        "message": "Severity dispute submitted for review"
    })))
}

// ============================================================================
// Acknowledgment Endpoints
// ============================================================================

/// POST /api/portal/vulnerabilities/{id}/acknowledge - Acknowledge a vulnerability
pub async fn acknowledge_vulnerability(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<AcknowledgmentRequest>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => return Ok(HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"}))),
    };

    let vulnerability_id = path.into_inner();

    // Verify access
    let vuln_check = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM vulnerability_tracking vt
           JOIN scan_results sr ON vt.scan_id = sr.id
           WHERE vt.id = ? AND sr.customer_id = ?"#
    )
    .bind(&vulnerability_id)
    .bind(&claims.customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    if vuln_check == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Vulnerability not found"})));
    }

    let ack_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Upsert acknowledgment
    sqlx::query(
        r#"INSERT INTO vulnerability_acknowledgments
           (id, vulnerability_id, acknowledged_by, acknowledged_at, notes, risk_accepted, expected_remediation_date)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(vulnerability_id) DO UPDATE SET
           acknowledged_by = excluded.acknowledged_by,
           acknowledged_at = excluded.acknowledged_at,
           notes = excluded.notes,
           risk_accepted = excluded.risk_accepted,
           expected_remediation_date = excluded.expected_remediation_date"#
    )
    .bind(&ack_id)
    .bind(&vulnerability_id)
    .bind(&claims.email)
    .bind(&now)
    .bind(&body.notes)
    .bind(body.risk_accepted)
    .bind(&body.expected_remediation_date)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "vulnerability_id": vulnerability_id,
        "acknowledged": true,
        "risk_accepted": body.risk_accepted,
        "message": "Vulnerability acknowledged"
    })))
}

/// POST /api/portal/vulnerabilities/bulk-acknowledge - Bulk acknowledge vulnerabilities
pub async fn bulk_acknowledge(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    body: web::Json<BulkAcknowledgmentRequest>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => return Ok(HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"}))),
    };

    if body.vulnerability_ids.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No vulnerability IDs provided"
        })));
    }

    if body.vulnerability_ids.len() > 100 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Maximum 100 vulnerabilities per batch"
        })));
    }

    let now = Utc::now().to_rfc3339();
    let mut acknowledged = Vec::new();
    let mut failed = Vec::new();

    for vuln_id in &body.vulnerability_ids {
        // Verify access for each
        let vuln_check = sqlx::query_scalar::<_, i64>(
            r#"SELECT COUNT(*) FROM vulnerability_tracking vt
               JOIN scan_results sr ON vt.scan_id = sr.id
               WHERE vt.id = ? AND sr.customer_id = ?"#
        )
        .bind(vuln_id)
        .bind(&claims.customer_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or(0);

        if vuln_check == 0 {
            failed.push(vuln_id.clone());
            continue;
        }

        let ack_id = Uuid::new_v4().to_string();

        let result = sqlx::query(
            r#"INSERT INTO vulnerability_acknowledgments
               (id, vulnerability_id, acknowledged_by, acknowledged_at, notes, risk_accepted, expected_remediation_date)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(vulnerability_id) DO UPDATE SET
               acknowledged_by = excluded.acknowledged_by,
               acknowledged_at = excluded.acknowledged_at,
               notes = excluded.notes,
               risk_accepted = excluded.risk_accepted,
               expected_remediation_date = excluded.expected_remediation_date"#
        )
        .bind(&ack_id)
        .bind(vuln_id)
        .bind(&claims.email)
        .bind(&now)
        .bind(&body.notes)
        .bind(body.risk_accepted)
        .bind(&body.expected_remediation_date)
        .execute(pool.get_ref())
        .await;

        match result {
            Ok(_) => acknowledged.push(vuln_id.clone()),
            Err(_) => failed.push(vuln_id.clone()),
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "acknowledged": acknowledged,
        "failed": failed,
        "total_acknowledged": acknowledged.len(),
        "total_failed": failed.len()
    })))
}

/// GET /api/portal/vulnerabilities/{id}/acknowledgment - Get acknowledgment status
pub async fn get_acknowledgment(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => return Ok(HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"}))),
    };

    let vulnerability_id = path.into_inner();

    // Verify access
    let vuln_check = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM vulnerability_tracking vt
           JOIN scan_results sr ON vt.scan_id = sr.id
           WHERE vt.id = ? AND sr.customer_id = ?"#
    )
    .bind(&vulnerability_id)
    .bind(&claims.customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    if vuln_check == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Vulnerability not found"})));
    }

    let ack = sqlx::query_as::<_, VulnerabilityAcknowledgment>(
        r#"SELECT id, vulnerability_id, acknowledged_by, acknowledged_at, notes,
                  risk_accepted, expected_remediation_date
           FROM vulnerability_acknowledgments
           WHERE vulnerability_id = ?"#
    )
    .bind(&vulnerability_id)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "vulnerability_id": vulnerability_id,
        "acknowledgment": ack
    })))
}

// ============================================================================
// Attachment Endpoints
// ============================================================================

/// GET /api/portal/vulnerabilities/{id}/attachments - List attachments
pub async fn list_attachments(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => return Ok(HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"}))),
    };

    let vulnerability_id = path.into_inner();

    // Verify access
    let vuln_check = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM vulnerability_tracking vt
           JOIN scan_results sr ON vt.scan_id = sr.id
           WHERE vt.id = ? AND sr.customer_id = ?"#
    )
    .bind(&vulnerability_id)
    .bind(&claims.customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    if vuln_check == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Vulnerability not found"})));
    }

    let attachments = sqlx::query_as::<_, VulnerabilityAttachment>(
        r#"SELECT id, vulnerability_id, filename, content_type, size_bytes,
                  uploaded_by, uploaded_at, description
           FROM vulnerability_attachments
           WHERE vulnerability_id = ?
           ORDER BY uploaded_at DESC"#
    )
    .bind(&vulnerability_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "vulnerability_id": vulnerability_id,
        "attachments": attachments
    })))
}

/// POST /api/portal/vulnerabilities/{id}/attachments - Upload attachment
pub async fn upload_attachment(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<UploadAttachmentRequest>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => return Ok(HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"}))),
    };

    let vulnerability_id = path.into_inner();

    // Verify access
    let vuln_check = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM vulnerability_tracking vt
           JOIN scan_results sr ON vt.scan_id = sr.id
           WHERE vt.id = ? AND sr.customer_id = ?"#
    )
    .bind(&vulnerability_id)
    .bind(&claims.customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    if vuln_check == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Vulnerability not found"})));
    }

    // Validate file
    let allowed_types = [
        "image/png", "image/jpeg", "image/gif",
        "application/pdf",
        "text/plain", "text/csv",
        "application/zip",
        "application/json",
    ];

    if !allowed_types.contains(&body.content_type.as_str()) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "File type not allowed",
            "allowed_types": allowed_types
        })));
    }

    // Decode and check size
    let data = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body.data_base64) {
        Ok(d) => d,
        Err(_) => return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid base64 data"}))),
    };

    const MAX_SIZE: usize = 10 * 1024 * 1024; // 10 MB
    if data.len() > MAX_SIZE {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "File too large",
            "max_size_bytes": MAX_SIZE
        })));
    }

    // Sanitize filename
    let filename = sanitize_filename(&body.filename);
    if filename.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid filename"})));
    }

    let attachment_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Store attachment metadata and data
    sqlx::query(
        r#"INSERT INTO vulnerability_attachments
           (id, vulnerability_id, filename, content_type, size_bytes, uploaded_by, uploaded_at, description, data)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#
    )
    .bind(&attachment_id)
    .bind(&vulnerability_id)
    .bind(&filename)
    .bind(&body.content_type)
    .bind(data.len() as i64)
    .bind(&claims.email)
    .bind(&now)
    .bind(&body.description)
    .bind(&data)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": attachment_id,
        "vulnerability_id": vulnerability_id,
        "filename": filename,
        "size_bytes": data.len(),
        "message": "Attachment uploaded successfully"
    })))
}

/// GET /api/portal/vulnerabilities/{id}/attachments/{attachment_id} - Download attachment
pub async fn download_attachment(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => return Ok(HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"}))),
    };

    let (vulnerability_id, attachment_id) = path.into_inner();

    // Verify access
    let vuln_check = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM vulnerability_tracking vt
           JOIN scan_results sr ON vt.scan_id = sr.id
           WHERE vt.id = ? AND sr.customer_id = ?"#
    )
    .bind(&vulnerability_id)
    .bind(&claims.customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    if vuln_check == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Vulnerability not found"})));
    }

    // Get attachment
    let attachment = sqlx::query_as::<_, (String, String, Vec<u8>)>(
        r#"SELECT filename, content_type, data
           FROM vulnerability_attachments
           WHERE id = ? AND vulnerability_id = ?"#
    )
    .bind(&attachment_id)
    .bind(&vulnerability_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    match attachment {
        Some((filename, content_type, data)) => {
            Ok(HttpResponse::Ok()
                .content_type(content_type)
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .body(data))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Attachment not found"}))),
    }
}

// ============================================================================
// Collaboration Summary
// ============================================================================

/// GET /api/portal/vulnerabilities/{id}/collaboration - Get collaboration summary
pub async fn get_collaboration_summary(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => return Ok(HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"}))),
    };

    let vulnerability_id = path.into_inner();

    // Verify access
    let vuln_check = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM vulnerability_tracking vt
           JOIN scan_results sr ON vt.scan_id = sr.id
           WHERE vt.id = ? AND sr.customer_id = ?"#
    )
    .bind(&vulnerability_id)
    .bind(&claims.customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    if vuln_check == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Vulnerability not found"})));
    }

    // Get counts
    let comment_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM portal_vulnerability_comments WHERE vulnerability_id = ? AND is_internal = 0"
    )
    .bind(&vulnerability_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    let dispute = sqlx::query_as::<_, (String,)>(
        "SELECT status FROM severity_disputes WHERE vulnerability_id = ? ORDER BY submitted_at DESC LIMIT 1"
    )
    .bind(&vulnerability_id)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None);

    let is_acknowledged = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM vulnerability_acknowledgments WHERE vulnerability_id = ?"
    )
    .bind(&vulnerability_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0) > 0;

    let attachment_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM vulnerability_attachments WHERE vulnerability_id = ?"
    )
    .bind(&vulnerability_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    // Get last activity
    let last_activity = sqlx::query_scalar::<_, String>(
        r#"SELECT MAX(activity_time) FROM (
            SELECT created_at as activity_time FROM portal_vulnerability_comments WHERE vulnerability_id = ?
            UNION ALL
            SELECT submitted_at FROM severity_disputes WHERE vulnerability_id = ?
            UNION ALL
            SELECT acknowledged_at FROM vulnerability_acknowledgments WHERE vulnerability_id = ?
            UNION ALL
            SELECT uploaded_at FROM vulnerability_attachments WHERE vulnerability_id = ?
        )"#
    )
    .bind(&vulnerability_id)
    .bind(&vulnerability_id)
    .bind(&vulnerability_id)
    .bind(&vulnerability_id)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None);

    Ok(HttpResponse::Ok().json(VulnerabilityCollaboration {
        vulnerability_id,
        comment_count,
        has_dispute: dispute.is_some(),
        dispute_status: dispute.map(|(s,)| s),
        is_acknowledged,
        attachment_count,
        last_activity,
    }))
}

// ============================================================================
// Helper Functions
// ============================================================================

fn organize_into_threads(comments: Vec<VulnerabilityComment>) -> Vec<DiscussionThread> {
    let mut threads = Vec::new();
    let mut reply_map: std::collections::HashMap<String, Vec<VulnerabilityComment>> = std::collections::HashMap::new();

    // Separate root comments from replies
    for comment in comments {
        if comment.parent_id.is_some() {
            reply_map
                .entry(comment.parent_id.clone().unwrap())
                .or_default()
                .push(comment);
        } else {
            threads.push(DiscussionThread {
                reply_count: 0,
                root_comment: comment,
                replies: Vec::new(),
            });
        }
    }

    // Attach replies to their parent threads
    for thread in &mut threads {
        if let Some(replies) = reply_map.remove(&thread.root_comment.id) {
            thread.reply_count = replies.len() as i64;
            thread.replies = replies;
        }
    }

    threads
}

fn sanitize_filename(filename: &str) -> String {
    let name: String = filename
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect();

    // Ensure it has a reasonable length
    if name.len() > 255 {
        name[..255].to_string()
    } else {
        name
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/vulnerabilities")
            // Comments/Discussion
            .route("/{id}/comments", web::get().to(list_comments))
            .route("/{id}/comments", web::post().to(create_comment))
            // Severity Disputes
            .route("/{id}/dispute", web::get().to(get_dispute))
            .route("/{id}/dispute", web::post().to(create_dispute))
            // Acknowledgments
            .route("/{id}/acknowledge", web::post().to(acknowledge_vulnerability))
            .route("/{id}/acknowledgment", web::get().to(get_acknowledgment))
            .route("/bulk-acknowledge", web::post().to(bulk_acknowledge))
            // Attachments
            .route("/{id}/attachments", web::get().to(list_attachments))
            .route("/{id}/attachments", web::post().to(upload_attachment))
            .route("/{id}/attachments/{attachment_id}", web::get().to(download_attachment))
            // Collaboration Summary
            .route("/{id}/collaboration", web::get().to(get_collaboration_summary))
    );
}
