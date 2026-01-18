//! Legal Documents Database Operations
//!
//! This module provides database operations for the legal documents system including:
//! - Document templates
//! - Generated documents
//! - Signatures
//! - Document history/audit trail

use anyhow::Result;
use chrono::{Duration, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::legal_documents::types::*;
use crate::legal_documents::templates::get_all_default_templates;

// ============================================================================
// Database Initialization
// ============================================================================

/// Initialize legal documents tables
pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    // Legal document templates table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS legal_document_templates (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            document_type TEXT NOT NULL,
            description TEXT,
            content_html TEXT NOT NULL,
            is_system INTEGER DEFAULT 0,
            user_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Legal documents table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS legal_documents (
            id TEXT PRIMARY KEY,
            template_id TEXT,
            engagement_id TEXT NOT NULL,
            customer_id TEXT NOT NULL,
            document_type TEXT NOT NULL,
            name TEXT NOT NULL,
            content_html TEXT NOT NULL,
            status TEXT DEFAULT 'draft',
            signature_token TEXT UNIQUE,
            signature_token_expires_at TEXT,
            final_pdf_path TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (template_id) REFERENCES legal_document_templates(id),
            FOREIGN KEY (engagement_id) REFERENCES engagements(id),
            FOREIGN KEY (customer_id) REFERENCES customers(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Legal document signatures table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS legal_document_signatures (
            id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            signer_type TEXT NOT NULL,
            signer_role TEXT NOT NULL,
            signer_name TEXT,
            signer_email TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            signed_at TEXT,
            signed_ip TEXT,
            signature_image TEXT,
            decline_reason TEXT,
            signature_order INTEGER DEFAULT 1,
            FOREIGN KEY (document_id) REFERENCES legal_documents(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Legal document history table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS legal_document_history (
            id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            action TEXT NOT NULL,
            actor_email TEXT,
            ip_address TEXT,
            details TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (document_id) REFERENCES legal_documents(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_legal_docs_engagement ON legal_documents(engagement_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_legal_docs_customer ON legal_documents(customer_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_legal_docs_status ON legal_documents(status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_legal_docs_token ON legal_documents(signature_token)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_legal_sigs_document ON legal_document_signatures(document_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_legal_history_document ON legal_document_history(document_id)")
        .execute(pool)
        .await?;

    // Seed default templates if none exist
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM legal_document_templates WHERE is_system = 1")
        .fetch_one(pool)
        .await?;

    if count == 0 {
        seed_default_templates(pool).await?;
    }

    Ok(())
}

/// Seed default system templates
async fn seed_default_templates(pool: &SqlitePool) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    for (doc_type, name, description, content) in get_all_default_templates() {
        let id = Uuid::new_v4().to_string();

        sqlx::query(
            r#"
            INSERT INTO legal_document_templates (id, name, document_type, description, content_html, is_system, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(name)
        .bind(doc_type)
        .bind(description)
        .bind(content)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await?;
    }

    log::info!("Seeded {} default legal document templates", get_all_default_templates().len());
    Ok(())
}

// ============================================================================
// Template Operations
// ============================================================================

/// Create a new template
pub async fn create_template(
    pool: &SqlitePool,
    user_id: &str,
    req: &CreateTemplateRequest,
) -> Result<LegalDocumentTemplate> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO legal_document_templates (id, name, document_type, description, content_html, is_system, user_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.document_type)
    .bind(&req.description)
    .bind(&req.content_html)
    .bind(user_id)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_template_by_id(pool, &id).await
}

/// Get a template by ID
pub async fn get_template_by_id(pool: &SqlitePool, id: &str) -> Result<LegalDocumentTemplate> {
    let template = sqlx::query_as::<_, LegalDocumentTemplate>(
        "SELECT * FROM legal_document_templates WHERE id = ?"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(template)
}

/// List all templates (system + user's custom)
pub async fn list_templates(pool: &SqlitePool, user_id: &str) -> Result<Vec<LegalDocumentTemplate>> {
    let templates = sqlx::query_as::<_, LegalDocumentTemplate>(
        r#"
        SELECT * FROM legal_document_templates
        WHERE is_system = 1 OR user_id = ?
        ORDER BY is_system DESC, name ASC
        "#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// List templates by type
pub async fn list_templates_by_type(
    pool: &SqlitePool,
    user_id: &str,
    document_type: &str,
) -> Result<Vec<LegalDocumentTemplate>> {
    let templates = sqlx::query_as::<_, LegalDocumentTemplate>(
        r#"
        SELECT * FROM legal_document_templates
        WHERE document_type = ? AND (is_system = 1 OR user_id = ?)
        ORDER BY is_system DESC, name ASC
        "#
    )
    .bind(document_type)
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Update a template (only custom templates)
pub async fn update_template(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    req: &UpdateTemplateRequest,
) -> Result<LegalDocumentTemplate> {
    let existing = get_template_by_id(pool, id).await?;

    // Can't edit system templates
    if existing.is_system {
        return Err(anyhow::anyhow!("Cannot modify system templates"));
    }

    // Can only edit own templates
    if existing.user_id.as_ref() != Some(&user_id.to_string()) {
        return Err(anyhow::anyhow!("Not authorized to modify this template"));
    }

    let now = Utc::now().to_rfc3339();
    let name = req.name.as_ref().unwrap_or(&existing.name);
    let description = req.description.as_ref().or(existing.description.as_ref());
    let content_html = req.content_html.as_ref().unwrap_or(&existing.content_html);

    sqlx::query(
        "UPDATE legal_document_templates SET name = ?, description = ?, content_html = ?, updated_at = ? WHERE id = ?"
    )
    .bind(name)
    .bind(description)
    .bind(content_html)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    get_template_by_id(pool, id).await
}

/// Delete a template (only custom templates)
pub async fn delete_template(pool: &SqlitePool, id: &str, user_id: &str) -> Result<()> {
    let existing = get_template_by_id(pool, id).await?;

    if existing.is_system {
        return Err(anyhow::anyhow!("Cannot delete system templates"));
    }

    if existing.user_id.as_ref() != Some(&user_id.to_string()) {
        return Err(anyhow::anyhow!("Not authorized to delete this template"));
    }

    sqlx::query("DELETE FROM legal_document_templates WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Document Operations
// ============================================================================

/// Create a new document
pub async fn create_document(
    pool: &SqlitePool,
    user_id: &str,
    req: &CreateDocumentRequest,
) -> Result<LegalDocument> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Get content from template if not provided
    let content_html = if let Some(ref content) = req.content_html {
        content.clone()
    } else if let Some(ref template_id) = req.template_id {
        let template = get_template_by_id(pool, template_id).await?;
        template.content_html
    } else {
        return Err(anyhow::anyhow!("Either content_html or template_id must be provided"));
    };

    sqlx::query(
        r#"
        INSERT INTO legal_documents (id, template_id, engagement_id, customer_id, document_type, name, content_html, status, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&req.template_id)
    .bind(&req.engagement_id)
    .bind(&req.customer_id)
    .bind(&req.document_type)
    .bind(&req.name)
    .bind(&content_html)
    .bind(user_id)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    // Add history entry
    add_document_history(pool, &id, "created", Some(user_id), None, Some("Document created")).await?;

    get_document_by_id(pool, &id).await
}

/// Get a document by ID
pub async fn get_document_by_id(pool: &SqlitePool, id: &str) -> Result<LegalDocument> {
    let document = sqlx::query_as::<_, LegalDocument>(
        "SELECT * FROM legal_documents WHERE id = ?"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(document)
}

/// Get a document by signature token
pub async fn get_document_by_token(pool: &SqlitePool, token: &str) -> Result<Option<LegalDocument>> {
    let document = sqlx::query_as::<_, LegalDocument>(
        "SELECT * FROM legal_documents WHERE signature_token = ? AND signature_token_expires_at > ?"
    )
    .bind(token)
    .bind(Utc::now().to_rfc3339())
    .fetch_optional(pool)
    .await?;

    Ok(document)
}

/// List documents for an engagement
pub async fn list_documents_for_engagement(
    pool: &SqlitePool,
    engagement_id: &str,
) -> Result<Vec<LegalDocument>> {
    let documents = sqlx::query_as::<_, LegalDocument>(
        "SELECT * FROM legal_documents WHERE engagement_id = ? ORDER BY created_at DESC"
    )
    .bind(engagement_id)
    .fetch_all(pool)
    .await?;

    Ok(documents)
}

/// List documents for a customer
pub async fn list_documents_for_customer(
    pool: &SqlitePool,
    customer_id: &str,
) -> Result<Vec<LegalDocument>> {
    let documents = sqlx::query_as::<_, LegalDocument>(
        "SELECT * FROM legal_documents WHERE customer_id = ? ORDER BY created_at DESC"
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await?;

    Ok(documents)
}

/// List all documents (with optional status filter)
pub async fn list_all_documents(
    pool: &SqlitePool,
    user_id: &str,
    status: Option<&str>,
) -> Result<Vec<LegalDocument>> {
    let documents = if let Some(status) = status {
        sqlx::query_as::<_, LegalDocument>(
            r#"
            SELECT d.* FROM legal_documents d
            INNER JOIN engagements e ON d.engagement_id = e.id
            INNER JOIN customers c ON e.customer_id = c.id
            WHERE c.user_id = ? AND d.status = ?
            ORDER BY d.created_at DESC
            "#
        )
        .bind(user_id)
        .bind(status)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, LegalDocument>(
            r#"
            SELECT d.* FROM legal_documents d
            INNER JOIN engagements e ON d.engagement_id = e.id
            INNER JOIN customers c ON e.customer_id = c.id
            WHERE c.user_id = ?
            ORDER BY d.created_at DESC
            "#
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?
    };

    Ok(documents)
}

/// Update a document
pub async fn update_document(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    req: &UpdateDocumentRequest,
) -> Result<LegalDocument> {
    let existing = get_document_by_id(pool, id).await?;

    // Can only edit drafts
    if existing.status != "draft" {
        return Err(anyhow::anyhow!("Can only edit documents in draft status"));
    }

    let now = Utc::now().to_rfc3339();
    let name = req.name.as_ref().unwrap_or(&existing.name);
    let content_html = req.content_html.as_ref().unwrap_or(&existing.content_html);

    sqlx::query(
        "UPDATE legal_documents SET name = ?, content_html = ?, updated_at = ? WHERE id = ?"
    )
    .bind(name)
    .bind(content_html)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    add_document_history(pool, id, "updated", Some(user_id), None, Some("Document content updated")).await?;

    get_document_by_id(pool, id).await
}

/// Update document status
pub async fn update_document_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE legal_documents SET status = ?, updated_at = ? WHERE id = ?"
    )
    .bind(status)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update document PDF path
pub async fn update_document_pdf_path(
    pool: &SqlitePool,
    id: &str,
    pdf_path: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE legal_documents SET final_pdf_path = ?, updated_at = ? WHERE id = ?"
    )
    .bind(pdf_path)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Generate and set signature token for a document
pub async fn generate_signature_token(
    pool: &SqlitePool,
    id: &str,
    expiry_days: i64,
) -> Result<String> {
    let token = Uuid::new_v4().to_string();
    let expires_at = (Utc::now() + Duration::days(expiry_days)).to_rfc3339();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE legal_documents SET signature_token = ?, signature_token_expires_at = ?, updated_at = ? WHERE id = ?"
    )
    .bind(&token)
    .bind(&expires_at)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(token)
}

/// Delete a document
pub async fn delete_document(pool: &SqlitePool, id: &str) -> Result<()> {
    // First delete signatures and history (cascade should handle this, but be explicit)
    sqlx::query("DELETE FROM legal_document_signatures WHERE document_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM legal_document_history WHERE document_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM legal_documents WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Void a document
pub async fn void_document(pool: &SqlitePool, id: &str, user_id: &str, reason: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE legal_documents SET status = 'voided', signature_token = NULL, updated_at = ? WHERE id = ?"
    )
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    add_document_history(pool, id, "voided", Some(user_id), None, Some(reason)).await?;

    Ok(())
}

// ============================================================================
// Signature Operations
// ============================================================================

/// Add a signature requirement to a document
pub async fn add_signature(
    pool: &SqlitePool,
    document_id: &str,
    req: &AddSignatureRequest,
) -> Result<LegalDocumentSignature> {
    let id = Uuid::new_v4().to_string();

    // Get next signature order if not specified
    let order = if let Some(order) = req.signature_order {
        order
    } else {
        let (max_order,): (i32,) = sqlx::query_as(
            "SELECT COALESCE(MAX(signature_order), 0) FROM legal_document_signatures WHERE document_id = ?"
        )
        .bind(document_id)
        .fetch_one(pool)
        .await?;
        max_order + 1
    };

    sqlx::query(
        r#"
        INSERT INTO legal_document_signatures (id, document_id, signer_type, signer_role, signer_email, status, signature_order)
        VALUES (?, ?, ?, ?, ?, 'pending', ?)
        "#,
    )
    .bind(&id)
    .bind(document_id)
    .bind(&req.signer_type)
    .bind(&req.signer_role)
    .bind(&req.signer_email)
    .bind(order)
    .execute(pool)
    .await?;

    get_signature_by_id(pool, &id).await
}

/// Get a signature by ID
pub async fn get_signature_by_id(pool: &SqlitePool, id: &str) -> Result<LegalDocumentSignature> {
    let signature = sqlx::query_as::<_, LegalDocumentSignature>(
        "SELECT * FROM legal_document_signatures WHERE id = ?"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(signature)
}

/// Get signature by document and email
pub async fn get_signature_by_email(
    pool: &SqlitePool,
    document_id: &str,
    email: &str,
) -> Result<Option<LegalDocumentSignature>> {
    let signature = sqlx::query_as::<_, LegalDocumentSignature>(
        "SELECT * FROM legal_document_signatures WHERE document_id = ? AND signer_email = ?"
    )
    .bind(document_id)
    .bind(email)
    .fetch_optional(pool)
    .await?;

    Ok(signature)
}

/// Get all signatures for a document
pub async fn get_document_signatures(
    pool: &SqlitePool,
    document_id: &str,
) -> Result<Vec<LegalDocumentSignature>> {
    let signatures = sqlx::query_as::<_, LegalDocumentSignature>(
        "SELECT * FROM legal_document_signatures WHERE document_id = ? ORDER BY signature_order ASC"
    )
    .bind(document_id)
    .fetch_all(pool)
    .await?;

    Ok(signatures)
}

/// Record a signature
pub async fn record_signature(
    pool: &SqlitePool,
    signature_id: &str,
    signer_name: &str,
    signature_image: &str,
    ip_address: &str,
) -> Result<LegalDocumentSignature> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE legal_document_signatures
        SET signer_name = ?, signature_image = ?, status = 'signed', signed_at = ?, signed_ip = ?
        WHERE id = ?
        "#
    )
    .bind(signer_name)
    .bind(signature_image)
    .bind(&now)
    .bind(ip_address)
    .bind(signature_id)
    .execute(pool)
    .await?;

    let signature = get_signature_by_id(pool, signature_id).await?;

    // Add history entry
    add_document_history(
        pool,
        &signature.document_id,
        "signed",
        Some(&signature.signer_email),
        Some(ip_address),
        Some(&format!("{} signed as {}", signer_name, signature.signer_role)),
    ).await?;

    // Check if all signatures are complete
    update_document_status_if_complete(pool, &signature.document_id).await?;

    Ok(signature)
}

/// Record a declined signature
pub async fn decline_signature(
    pool: &SqlitePool,
    signature_id: &str,
    reason: &str,
    ip_address: &str,
) -> Result<LegalDocumentSignature> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE legal_document_signatures
        SET status = 'declined', decline_reason = ?, signed_at = ?, signed_ip = ?
        WHERE id = ?
        "#
    )
    .bind(reason)
    .bind(&now)
    .bind(ip_address)
    .bind(signature_id)
    .execute(pool)
    .await?;

    let signature = get_signature_by_id(pool, signature_id).await?;

    add_document_history(
        pool,
        &signature.document_id,
        "declined",
        Some(&signature.signer_email),
        Some(ip_address),
        Some(&format!("Signature declined: {}", reason)),
    ).await?;

    Ok(signature)
}

/// Delete a signature
pub async fn delete_signature(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM legal_document_signatures WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Check if all signatures are complete and update document status
async fn update_document_status_if_complete(pool: &SqlitePool, document_id: &str) -> Result<()> {
    let signatures = get_document_signatures(pool, document_id).await?;

    if signatures.is_empty() {
        return Ok(());
    }

    let signed_count = signatures.iter().filter(|s| s.status == "signed").count();
    let total_count = signatures.len();

    let new_status = if signed_count == total_count {
        "fully_signed"
    } else if signed_count > 0 {
        "partially_signed"
    } else {
        return Ok(()); // No change needed
    };

    update_document_status(pool, document_id, new_status).await?;

    if new_status == "fully_signed" {
        add_document_history(pool, document_id, "completed", None, None, Some("All signatures collected")).await?;
    }

    Ok(())
}

// ============================================================================
// History Operations
// ============================================================================

/// Add a history entry
pub async fn add_document_history(
    pool: &SqlitePool,
    document_id: &str,
    action: &str,
    actor_email: Option<&str>,
    ip_address: Option<&str>,
    details: Option<&str>,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO legal_document_history (id, document_id, action, actor_email, ip_address, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(document_id)
    .bind(action)
    .bind(actor_email)
    .bind(ip_address)
    .bind(details)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get document history
pub async fn get_document_history(
    pool: &SqlitePool,
    document_id: &str,
) -> Result<Vec<LegalDocumentHistory>> {
    let history = sqlx::query_as::<_, LegalDocumentHistory>(
        "SELECT * FROM legal_document_history WHERE document_id = ? ORDER BY created_at DESC"
    )
    .bind(document_id)
    .fetch_all(pool)
    .await?;

    Ok(history)
}

// ============================================================================
// Statistics and Helpers
// ============================================================================

/// Get document counts by status
pub async fn get_document_stats(pool: &SqlitePool, user_id: &str) -> Result<DocumentStats> {
    let stats = sqlx::query_as::<_, DocumentStatsRow>(
        r#"
        SELECT
            d.status,
            COUNT(*) as count
        FROM legal_documents d
        INNER JOIN engagements e ON d.engagement_id = e.id
        INNER JOIN customers c ON e.customer_id = c.id
        WHERE c.user_id = ?
        GROUP BY d.status
        "#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut result = DocumentStats::default();
    for row in stats {
        match row.status.as_str() {
            "draft" => result.draft = row.count,
            "pending_signature" => result.pending_signature = row.count,
            "partially_signed" => result.partially_signed = row.count,
            "fully_signed" => result.fully_signed = row.count,
            "voided" => result.voided = row.count,
            _ => {}
        }
    }

    Ok(result)
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct DocumentStatsRow {
    status: String,
    count: i64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DocumentStats {
    pub draft: i64,
    pub pending_signature: i64,
    pub partially_signed: i64,
    pub fully_signed: i64,
    pub voided: i64,
}

/// Get document list with customer and engagement names
pub async fn get_documents_with_details(
    pool: &SqlitePool,
    user_id: &str,
    status: Option<&str>,
) -> Result<Vec<DocumentListItem>> {
    let base_query = r#"
        SELECT
            d.id,
            d.name,
            d.document_type,
            d.status,
            c.name as customer_name,
            e.name as engagement_name,
            d.created_at,
            d.updated_at,
            (SELECT COUNT(*) FROM legal_document_signatures WHERE document_id = d.id) as signature_count,
            (SELECT COUNT(*) FROM legal_document_signatures WHERE document_id = d.id AND status = 'signed') as signed_count
        FROM legal_documents d
        INNER JOIN engagements e ON d.engagement_id = e.id
        INNER JOIN customers c ON e.customer_id = c.id
        WHERE c.user_id = ?
    "#;

    let items = if let Some(status) = status {
        let query = format!("{} AND d.status = ? ORDER BY d.updated_at DESC", base_query);
        sqlx::query_as::<_, DocumentListItemRow>(&query)
            .bind(user_id)
            .bind(status)
            .fetch_all(pool)
            .await?
    } else {
        let query = format!("{} ORDER BY d.updated_at DESC", base_query);
        sqlx::query_as::<_, DocumentListItemRow>(&query)
            .bind(user_id)
            .fetch_all(pool)
            .await?
    };

    Ok(items.into_iter().map(Into::into).collect())
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct DocumentListItemRow {
    id: String,
    name: String,
    document_type: String,
    status: String,
    customer_name: String,
    engagement_name: String,
    created_at: String,
    updated_at: String,
    signature_count: i32,
    signed_count: i32,
}

impl From<DocumentListItemRow> for DocumentListItem {
    fn from(row: DocumentListItemRow) -> Self {
        DocumentListItem {
            id: row.id,
            name: row.name,
            document_type: row.document_type,
            status: row.status,
            customer_name: row.customer_name,
            engagement_name: row.engagement_name,
            created_at: row.created_at,
            updated_at: row.updated_at,
            signature_count: row.signature_count,
            signed_count: row.signed_count,
        }
    }
}
