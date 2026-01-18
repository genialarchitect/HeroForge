//! Legal Documents API Endpoints
//!
//! REST API endpoints for managing legal documents, templates, and signatures.

use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::{crm, legal_documents as db};
use crate::legal_documents::{
    placeholders::PlaceholderEngine,
    pdf,
    types::*,
};
use crate::notifications::email::{EmailConfig, EmailNotifier};
use crate::web::auth;

// ============================================================================
// Template Endpoints
// ============================================================================

/// GET /api/legal/templates - List all templates
pub async fn list_templates(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let templates = db::list_templates(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to list legal templates: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to list templates")
        })?;

    Ok(HttpResponse::Ok().json(templates))
}

/// GET /api/legal/templates/{id} - Get a specific template
pub async fn get_template(
    pool: web::Data<SqlitePool>,
    template_id: web::Path<String>,
) -> Result<HttpResponse> {
    let template = db::get_template_by_id(&pool, &template_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get template: {}", e);
            actix_web::error::ErrorNotFound("Template not found")
        })?;

    Ok(HttpResponse::Ok().json(template))
}

/// POST /api/legal/templates - Create a new template
pub async fn create_template(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    req: web::Json<CreateTemplateRequest>,
) -> Result<HttpResponse> {
    // Validate document type
    if DocumentType::from_str(&req.document_type).is_none() {
        return Err(actix_web::error::ErrorBadRequest("Invalid document type"));
    }

    let template = db::create_template(&pool, &claims.sub, &req)
        .await
        .map_err(|e| {
            log::error!("Failed to create template: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create template")
        })?;

    Ok(HttpResponse::Created().json(template))
}

/// PUT /api/legal/templates/{id} - Update a template
pub async fn update_template(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    template_id: web::Path<String>,
    req: web::Json<UpdateTemplateRequest>,
) -> Result<HttpResponse> {
    let template = db::update_template(&pool, &template_id, &claims.sub, &req)
        .await
        .map_err(|e| {
            log::error!("Failed to update template: {}", e);
            if e.to_string().contains("system") || e.to_string().contains("authorized") {
                actix_web::error::ErrorForbidden(e.to_string())
            } else {
                actix_web::error::ErrorInternalServerError("Failed to update template")
            }
        })?;

    Ok(HttpResponse::Ok().json(template))
}

/// DELETE /api/legal/templates/{id} - Delete a template
pub async fn delete_template(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    template_id: web::Path<String>,
) -> Result<HttpResponse> {
    db::delete_template(&pool, &template_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete template: {}", e);
            if e.to_string().contains("system") || e.to_string().contains("authorized") {
                actix_web::error::ErrorForbidden(e.to_string())
            } else {
                actix_web::error::ErrorInternalServerError("Failed to delete template")
            }
        })?;

    Ok(HttpResponse::NoContent().finish())
}

/// GET /api/legal/placeholders - Get available placeholders
pub async fn get_placeholders() -> Result<HttpResponse> {
    let placeholders = PlaceholderEngine::get_available_placeholders();
    Ok(HttpResponse::Ok().json(placeholders))
}

// ============================================================================
// Document Endpoints
// ============================================================================

/// GET /api/legal/documents - List all documents
pub async fn list_documents(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ListDocumentsQuery>,
) -> Result<HttpResponse> {
    let documents = db::get_documents_with_details(
        &pool,
        &claims.sub,
        query.status.as_deref(),
    )
    .await
    .map_err(|e| {
        log::error!("Failed to list documents: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to list documents")
    })?;

    Ok(HttpResponse::Ok().json(documents))
}

#[derive(Debug, Deserialize)]
pub struct ListDocumentsQuery {
    pub status: Option<String>,
}

/// GET /api/legal/documents/stats - Get document statistics
pub async fn get_document_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let stats = db::get_document_stats(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to get document stats: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get statistics")
        })?;

    Ok(HttpResponse::Ok().json(stats))
}

/// GET /api/legal/documents/{id} - Get a specific document
pub async fn get_document(
    pool: web::Data<SqlitePool>,
    document_id: web::Path<String>,
) -> Result<HttpResponse> {
    let document = db::get_document_by_id(&pool, &document_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get document: {}", e);
            actix_web::error::ErrorNotFound("Document not found")
        })?;

    let signatures = db::get_document_signatures(&pool, &document_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get signatures: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get signatures")
        })?;

    let history = db::get_document_history(&pool, &document_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get history: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get history")
        })?;

    Ok(HttpResponse::Ok().json(DocumentDetail {
        document,
        signatures,
        history,
    }))
}

#[derive(Debug, Serialize)]
pub struct DocumentDetail {
    pub document: LegalDocument,
    pub signatures: Vec<LegalDocumentSignature>,
    pub history: Vec<LegalDocumentHistory>,
}

/// POST /api/legal/documents - Create a new document
pub async fn create_document(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    req: web::Json<CreateDocumentRequest>,
) -> Result<HttpResponse> {
    // Validate document type
    if DocumentType::from_str(&req.document_type).is_none() {
        return Err(actix_web::error::ErrorBadRequest("Invalid document type"));
    }

    // Get engagement and customer data for placeholder substitution
    let engagement = crm::get_engagement_by_id(&pool, &req.engagement_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get engagement: {}", e);
            actix_web::error::ErrorBadRequest("Invalid engagement_id")
        })?;

    let customer = crm::get_customer_by_id(&pool, &req.customer_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get customer: {}", e);
            actix_web::error::ErrorBadRequest("Invalid customer_id")
        })?;

    // Get primary contact if available
    let contacts = crm::get_customer_contacts(&pool, &req.customer_id).await.ok();
    let primary_contact = contacts.as_ref().and_then(|c| c.iter().find(|c| c.is_primary));

    // Get content (from template or request)
    let content = if let Some(ref content) = req.content_html {
        content.clone()
    } else if let Some(ref template_id) = req.template_id {
        let template = db::get_template_by_id(&pool, template_id)
            .await
            .map_err(|_| actix_web::error::ErrorBadRequest("Invalid template_id"))?;
        template.content_html
    } else {
        return Err(actix_web::error::ErrorBadRequest("Either content_html or template_id required"));
    };

    // Substitute placeholders
    let company_name = std::env::var("COMPANY_NAME").unwrap_or_else(|_| "Genial Architect Security".to_string());
    let company_address = std::env::var("COMPANY_ADDRESS").unwrap_or_else(|_| "[Company Address]".to_string());

    let engine = PlaceholderEngine::new();
    let values = PlaceholderEngine::build_values_map(
        &customer,
        &engagement,
        primary_contact,
        &company_name,
        &company_address,
    );
    let rendered_content = engine.replace_placeholders(&content, &values);

    // Create the document with rendered content
    let mut create_req = req.into_inner();
    create_req.content_html = Some(rendered_content);

    let document = db::create_document(&pool, &claims.sub, &create_req)
        .await
        .map_err(|e| {
            log::error!("Failed to create document: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create document")
        })?;

    Ok(HttpResponse::Created().json(document))
}

/// PUT /api/legal/documents/{id} - Update a document
pub async fn update_document(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    document_id: web::Path<String>,
    req: web::Json<UpdateDocumentRequest>,
) -> Result<HttpResponse> {
    let document = db::update_document(&pool, &document_id, &claims.sub, &req)
        .await
        .map_err(|e| {
            log::error!("Failed to update document: {}", e);
            if e.to_string().contains("draft") {
                actix_web::error::ErrorBadRequest(e.to_string())
            } else {
                actix_web::error::ErrorInternalServerError("Failed to update document")
            }
        })?;

    Ok(HttpResponse::Ok().json(document))
}

/// DELETE /api/legal/documents/{id} - Delete a document
pub async fn delete_document(
    pool: web::Data<SqlitePool>,
    document_id: web::Path<String>,
) -> Result<HttpResponse> {
    db::delete_document(&pool, &document_id)
        .await
        .map_err(|e| {
            log::error!("Failed to delete document: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete document")
        })?;

    Ok(HttpResponse::NoContent().finish())
}

/// POST /api/legal/documents/{id}/void - Void a document
pub async fn void_document(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    document_id: web::Path<String>,
    req: web::Json<VoidDocumentRequest>,
) -> Result<HttpResponse> {
    db::void_document(&pool, &document_id, &claims.sub, &req.reason)
        .await
        .map_err(|e| {
            log::error!("Failed to void document: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to void document")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "voided"})))
}

#[derive(Debug, Deserialize)]
pub struct VoidDocumentRequest {
    pub reason: String,
}

// ============================================================================
// Signature Management Endpoints
// ============================================================================

/// POST /api/legal/documents/{id}/signatures - Add a signature requirement
pub async fn add_signature(
    pool: web::Data<SqlitePool>,
    document_id: web::Path<String>,
    req: web::Json<AddSignatureRequest>,
) -> Result<HttpResponse> {
    // Validate signer type
    if SignerType::from_str(&req.signer_type).is_none() {
        return Err(actix_web::error::ErrorBadRequest("Invalid signer_type"));
    }

    // Validate email format (basic check)
    if !req.signer_email.contains('@') {
        return Err(actix_web::error::ErrorBadRequest("Invalid email address"));
    }

    let signature = db::add_signature(&pool, &document_id, &req)
        .await
        .map_err(|e| {
            log::error!("Failed to add signature: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to add signature requirement")
        })?;

    Ok(HttpResponse::Created().json(signature))
}

/// DELETE /api/legal/documents/{id}/signatures/{sig_id} - Remove a signature requirement
pub async fn delete_signature(
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse> {
    let (document_id, sig_id) = path.into_inner();

    // Verify the signature belongs to this document
    let signature = db::get_signature_by_id(&pool, &sig_id)
        .await
        .map_err(|_| actix_web::error::ErrorNotFound("Signature not found"))?;

    if signature.document_id != document_id {
        return Err(actix_web::error::ErrorNotFound("Signature not found"));
    }

    if signature.status == "signed" {
        return Err(actix_web::error::ErrorBadRequest("Cannot delete completed signature"));
    }

    db::delete_signature(&pool, &sig_id)
        .await
        .map_err(|e| {
            log::error!("Failed to delete signature: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete signature")
        })?;

    Ok(HttpResponse::NoContent().finish())
}

/// POST /api/legal/documents/{id}/send - Send document for signature
pub async fn send_for_signature(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    document_id: web::Path<String>,
    req: web::Json<SendForSignatureRequest>,
) -> Result<HttpResponse> {
    let document = db::get_document_by_id(&pool, &document_id)
        .await
        .map_err(|_| actix_web::error::ErrorNotFound("Document not found"))?;

    // Check document is in draft status
    if document.status != "draft" {
        return Err(actix_web::error::ErrorBadRequest("Document must be in draft status to send"));
    }

    // Check there are signatures to collect
    let signatures = db::get_document_signatures(&pool, &document_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get signatures: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get signatures")
        })?;

    if signatures.is_empty() {
        return Err(actix_web::error::ErrorBadRequest("No signatures configured"));
    }

    // Generate signature token (valid for 30 days)
    let token = db::generate_signature_token(&pool, &document_id, 30)
        .await
        .map_err(|e| {
            log::error!("Failed to generate token: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to generate signature token")
        })?;

    // Update status to pending_signature
    db::update_document_status(&pool, &document_id, "pending_signature")
        .await
        .map_err(|e| {
            log::error!("Failed to update document status: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to update document status")
        })?;

    // Add history entry
    db::add_document_history(
        &pool,
        &document_id,
        "sent_for_signature",
        Some(&claims.sub),
        None,
        Some("Document sent for signature"),
    )
    .await
    .map_err(|e| {
        log::error!("Failed to add document history: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to add document history")
    })?;

    // Try to send email notifications
    let signing_url = format!(
        "{}/sign/{}",
        std::env::var("APP_URL").unwrap_or_else(|_| "https://heroforge.genialarchitect.io".to_string()),
        token
    );

    if EmailConfig::is_configured() {
        for sig in &signatures {
            if sig.status == "pending" {
                if let Err(e) = send_signature_request_email(
                    &sig.signer_email,
                    &document.name,
                    &sig.signer_role,
                    &signing_url,
                    req.message.as_deref(),
                ).await {
                    log::warn!("Failed to send signature request email to {}: {}", sig.signer_email, e);
                }
            }
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "sent",
        "signing_url": signing_url,
        "token": token,
    })))
}

/// POST /api/legal/documents/{id}/remind - Send reminder emails
pub async fn send_reminder(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    document_id: web::Path<String>,
) -> Result<HttpResponse> {
    let document = db::get_document_by_id(&pool, &document_id)
        .await
        .map_err(|_| actix_web::error::ErrorNotFound("Document not found"))?;

    if document.status != "pending_signature" && document.status != "partially_signed" {
        return Err(actix_web::error::ErrorBadRequest("Document not awaiting signatures"));
    }

    let token = document.signature_token.as_ref()
        .ok_or_else(|| actix_web::error::ErrorBadRequest("No signature token"))?;

    let signing_url = format!(
        "{}/sign/{}",
        std::env::var("APP_URL").unwrap_or_else(|_| "https://heroforge.genialarchitect.io".to_string()),
        token
    );

    let signatures = db::get_document_signatures(&pool, &document_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get document signatures: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get document signatures")
        })?;
    let mut sent_count = 0;

    if EmailConfig::is_configured() {
        for sig in &signatures {
            if sig.status == "pending" {
                if let Err(e) = send_reminder_email(
                    &sig.signer_email,
                    &document.name,
                    &sig.signer_role,
                    &signing_url,
                ).await {
                    log::warn!("Failed to send reminder email to {}: {}", sig.signer_email, e);
                } else {
                    sent_count += 1;
                }
            }
        }
    }

    db::add_document_history(
        &pool,
        &document_id,
        "reminder_sent",
        Some(&claims.sub),
        None,
        Some(&format!("Reminder sent to {} pending signers", sent_count)),
    )
    .await
    .map_err(|e| {
        log::error!("Failed to add document history: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to add document history")
    })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "reminders_sent": sent_count,
    })))
}

/// GET /api/legal/documents/{id}/pdf - Download document PDF
pub async fn download_pdf(
    pool: web::Data<SqlitePool>,
    document_id: web::Path<String>,
) -> Result<HttpResponse> {
    let document = db::get_document_by_id(&pool, &document_id)
        .await
        .map_err(|_| actix_web::error::ErrorNotFound("Document not found"))?;

    let signatures = db::get_document_signatures(&pool, &document_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get document signatures: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get document signatures")
        })?;

    // Generate PDF
    let reports_dir = std::env::var("REPORTS_DIR").unwrap_or_else(|_| "./reports".to_string());
    let legal_dir = format!("{}/legal", reports_dir);

    let pdf_path = pdf::generate_document_pdf(&document, &signatures, &legal_dir)
        .await
        .map_err(|e| {
            log::error!("Failed to generate PDF: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to generate PDF")
        })?;

    // Read and return the PDF
    let pdf_content = tokio::fs::read(&pdf_path)
        .await
        .map_err(|e| {
            log::error!("Failed to read PDF: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to read PDF")
        })?;

    Ok(HttpResponse::Ok()
        .content_type("application/pdf")
        .append_header((
            "Content-Disposition",
            format!("attachment; filename=\"{}.pdf\"", sanitize_filename(&document.name)),
        ))
        .body(pdf_content))
}

// ============================================================================
// Public Signing Endpoints (No Auth Required)
// ============================================================================

/// GET /api/legal/sign/{token} - Get document for signing (public)
pub async fn get_signing_document(
    pool: web::Data<SqlitePool>,
    token: web::Path<String>,
    query: web::Query<SigningQuery>,
) -> Result<HttpResponse> {
    let document = db::get_document_by_token(&pool, &token)
        .await
        .map_err(|e| {
            log::error!("Failed to get document: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get document")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Invalid or expired signing link"))?;

    // Find the signature for this email
    let signer_email = query.email.as_deref()
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Email parameter required"))?;

    let signature = db::get_signature_by_email(&pool, &document.id, signer_email)
        .await
        .map_err(|e| {
            log::error!("Failed to get signature: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get signature")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Signer not found for this document"))?;

    // Get customer and engagement names for context
    let engagement = crm::get_engagement_by_id(&pool, &document.engagement_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get engagement: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get engagement")
        })?;
    let customer = crm::get_customer_by_id(&pool, &document.customer_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get customer: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get customer")
        })?;

    // Get all signatures for display
    let all_signatures: Vec<SignatureInfo> = db::get_document_signatures(&pool, &document.id)
        .await
        .map_err(|e| {
            log::error!("Failed to get signatures: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get signatures")
        })?
        .into_iter()
        .map(|s| SignatureInfo {
            signer_type: s.signer_type,
            signer_role: s.signer_role,
            signer_name: s.signer_name,
            signer_email: s.signer_email,
            status: s.status,
            signed_at: s.signed_at,
        })
        .collect();

    Ok(HttpResponse::Ok().json(SigningData {
        document_id: document.id,
        document_name: document.name,
        document_type: document.document_type,
        content_html: document.content_html,
        signer_email: signature.signer_email,
        signer_role: signature.signer_role,
        signer_type: signature.signer_type,
        customer_name: customer.name,
        engagement_name: engagement.name,
        all_signatures,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SigningQuery {
    pub email: Option<String>,
}

/// POST /api/legal/sign/{token} - Submit signature (public)
pub async fn submit_signature(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    token: web::Path<String>,
    body: web::Json<SubmitSignatureWithEmail>,
) -> Result<HttpResponse> {
    let document = db::get_document_by_token(&pool, &token)
        .await
        .map_err(|e| {
            log::error!("Failed to get document: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get document")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Invalid or expired signing link"))?;

    // Find the signature for this email
    let signature = db::get_signature_by_email(&pool, &document.id, &body.signer_email)
        .await
        .map_err(|e| {
            log::error!("Failed to get signature: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get signature")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Signer not found"))?;

    if signature.status != "pending" {
        return Err(actix_web::error::ErrorBadRequest("Signature already recorded or declined"));
    }

    // Validate acknowledgment
    if !body.acknowledgment {
        return Err(actix_web::error::ErrorBadRequest("Acknowledgment required"));
    }

    // Validate signature image
    pdf::validate_signature_image(&body.signature_image)
        .map_err(|e| actix_web::error::ErrorBadRequest(e.to_string()))?;

    // Get client IP
    let ip_address = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    // Record the signature
    let updated_signature = db::record_signature(
        &pool,
        &signature.id,
        &body.signer_name,
        &body.signature_image,
        &ip_address,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to record signature: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to record signature")
    })?;

    // Check if all signatures are now complete
    let document = db::get_document_by_id(&pool, &document.id)
        .await
        .map_err(|e| {
            log::error!("Failed to get document: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get document")
        })?;

    // If fully signed, generate final PDF
    if document.status == "fully_signed" {
        let signatures = db::get_document_signatures(&pool, &document.id)
            .await
            .map_err(|e| {
                log::error!("Failed to get signatures: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to get signatures")
            })?;
        let reports_dir = std::env::var("REPORTS_DIR").unwrap_or_else(|_| "./reports".to_string());
        let legal_dir = format!("{}/legal", reports_dir);

        if let Ok(pdf_path) = pdf::generate_document_pdf(&document, &signatures, &legal_dir).await {
            let _ = db::update_document_pdf_path(&pool, &document.id, &pdf_path).await;

            // Send completion notification
            if EmailConfig::is_configured() {
                // Notify document creator
                let _ = send_completion_email(&document.created_by, &document.name).await;
            }
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "signed",
        "document_status": document.status,
        "signature": updated_signature,
    })))
}

#[derive(Debug, Deserialize)]
pub struct SubmitSignatureWithEmail {
    pub signer_email: String,
    pub signer_name: String,
    pub signature_image: String,
    pub acknowledgment: bool,
}

/// POST /api/legal/sign/{token}/decline - Decline to sign (public)
pub async fn decline_signature(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    token: web::Path<String>,
    body: web::Json<DeclineSignatureRequest>,
) -> Result<HttpResponse> {
    let document = db::get_document_by_token(&pool, &token)
        .await
        .map_err(|e| {
            log::error!("Failed to get document: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get document")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Invalid or expired signing link"))?;

    let signature = db::get_signature_by_email(&pool, &document.id, &body.signer_email)
        .await
        .map_err(|e| {
            log::error!("Failed to get signature: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get signature")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Signer not found"))?;

    if signature.status != "pending" {
        return Err(actix_web::error::ErrorBadRequest("Signature already recorded or declined"));
    }

    let ip_address = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    db::decline_signature(&pool, &signature.id, &body.reason, &ip_address)
        .await
        .map_err(|e| {
            log::error!("Failed to decline signature: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to decline signature")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "declined",
    })))
}

#[derive(Debug, Deserialize)]
pub struct DeclineSignatureRequest {
    pub signer_email: String,
    pub reason: String,
}

// ============================================================================
// Email Helpers
// ============================================================================

async fn send_signature_request_email(
    to_email: &str,
    document_name: &str,
    signer_role: &str,
    signing_url: &str,
    custom_message: Option<&str>,
) -> anyhow::Result<()> {
    let notifier = EmailNotifier::from_env(to_email.to_string())?;

    let subject = format!("Signature Requested: {}", document_name);

    let custom_msg = custom_message
        .map(|m| format!("<p><strong>Message:</strong> {}</p>", m))
        .unwrap_or_default();

    let html_body = format!(
        r#"<!DOCTYPE html>
<html>
<head><style>
body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
.container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
.btn {{ display: inline-block; padding: 12px 24px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 6px; }}
</style></head>
<body>
<div class="container">
<h2>Signature Requested</h2>
<p>You have been requested to sign the following document as <strong>{}</strong>:</p>
<p><strong>{}</strong></p>
{}
<p>Please click the button below to review and sign the document:</p>
<p><a href="{}?email={}" class="btn">Review &amp; Sign Document</a></p>
<p>This link will expire in 30 days.</p>
<hr>
<p style="font-size: 12px; color: #666;">
If you believe you received this email in error, please ignore it.
</p>
</div>
</body>
</html>"#,
        signer_role, document_name, custom_msg, signing_url, urlencoding::encode(to_email)
    );

    let text_body = format!(
        "Signature Requested\n\nYou have been requested to sign \"{}\" as {}.\n\nVisit: {}?email={}\n\nThis link expires in 30 days.",
        document_name, signer_role, signing_url, to_email
    );

    notifier.send_email(&subject, &text_body, &html_body).await
}

async fn send_reminder_email(
    to_email: &str,
    document_name: &str,
    signer_role: &str,
    signing_url: &str,
) -> anyhow::Result<()> {
    let notifier = EmailNotifier::from_env(to_email.to_string())?;

    let subject = format!("Reminder: Signature Requested for {}", document_name);

    let html_body = format!(
        r#"<!DOCTYPE html>
<html>
<head><style>
body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
.container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
.btn {{ display: inline-block; padding: 12px 24px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 6px; }}
</style></head>
<body>
<div class="container">
<h2>Reminder: Signature Still Required</h2>
<p>This is a reminder that your signature is still required on:</p>
<p><strong>{}</strong></p>
<p>You are signing as: <strong>{}</strong></p>
<p><a href="{}?email={}" class="btn">Review &amp; Sign Document</a></p>
</div>
</body>
</html>"#,
        document_name, signer_role, signing_url, urlencoding::encode(to_email)
    );

    let text_body = format!(
        "Reminder: Your signature is still required on \"{}\"\n\nVisit: {}?email={}",
        document_name, signing_url, to_email
    );

    notifier.send_email(&subject, &text_body, &html_body).await
}

async fn send_completion_email(
    to_email: &str,
    document_name: &str,
) -> anyhow::Result<()> {
    let notifier = EmailNotifier::from_env(to_email.to_string())?;

    let subject = format!("Document Fully Signed: {}", document_name);

    let html_body = format!(
        r#"<!DOCTYPE html>
<html>
<head><style>
body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
.container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
.success {{ color: #27ae60; }}
</style></head>
<body>
<div class="container">
<h2 class="success">Document Fully Signed</h2>
<p>All required signatures have been collected for:</p>
<p><strong>{}</strong></p>
<p>You can now download the final signed PDF from the HeroForge dashboard.</p>
</div>
</body>
</html>"#,
        document_name
    );

    let text_body = format!(
        "Document Fully Signed\n\nAll signatures collected for: {}\n\nDownload the final PDF from the HeroForge dashboard.",
        document_name
    );

    notifier.send_email(&subject, &text_body, &html_body).await
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' { c } else { '_' })
        .collect::<String>()
        .replace(' ', "_")
}
