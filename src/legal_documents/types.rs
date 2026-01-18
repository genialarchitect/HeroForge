//! Legal Documents Types
//!
//! Data structures for legal document management.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Document types for pre-engagement legal documents
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DocumentType {
    Roe,  // Rules of Engagement
    Ato,  // Authorization to Test
    Nda,  // Non-Disclosure Agreement
    Sow,  // Statement of Work
    Msa,  // Master Service Agreement
}

impl DocumentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DocumentType::Roe => "roe",
            DocumentType::Ato => "ato",
            DocumentType::Nda => "nda",
            DocumentType::Sow => "sow",
            DocumentType::Msa => "msa",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "roe" => Some(DocumentType::Roe),
            "ato" => Some(DocumentType::Ato),
            "nda" => Some(DocumentType::Nda),
            "sow" => Some(DocumentType::Sow),
            "msa" => Some(DocumentType::Msa),
            _ => None,
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            DocumentType::Roe => "Rules of Engagement",
            DocumentType::Ato => "Authorization to Test",
            DocumentType::Nda => "Non-Disclosure Agreement",
            DocumentType::Sow => "Statement of Work",
            DocumentType::Msa => "Master Service Agreement",
        }
    }
}

impl std::fmt::Display for DocumentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Document status workflow
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DocumentStatus {
    Draft,
    PendingSignature,
    PartiallySigned,
    FullySigned,
    Voided,
}

impl DocumentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DocumentStatus::Draft => "draft",
            DocumentStatus::PendingSignature => "pending_signature",
            DocumentStatus::PartiallySigned => "partially_signed",
            DocumentStatus::FullySigned => "fully_signed",
            DocumentStatus::Voided => "voided",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "draft" => Some(DocumentStatus::Draft),
            "pending_signature" => Some(DocumentStatus::PendingSignature),
            "partially_signed" => Some(DocumentStatus::PartiallySigned),
            "fully_signed" => Some(DocumentStatus::FullySigned),
            "voided" => Some(DocumentStatus::Voided),
            _ => None,
        }
    }
}

impl std::fmt::Display for DocumentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Signature status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Pending,
    Signed,
    Declined,
}

impl SignatureStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureStatus::Pending => "pending",
            SignatureStatus::Signed => "signed",
            SignatureStatus::Declined => "declined",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pending" => Some(SignatureStatus::Pending),
            "signed" => Some(SignatureStatus::Signed),
            "declined" => Some(SignatureStatus::Declined),
            _ => None,
        }
    }
}

impl std::fmt::Display for SignatureStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Signer type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignerType {
    Client,
    Provider,
}

impl SignerType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignerType::Client => "client",
            SignerType::Provider => "provider",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "client" => Some(SignerType::Client),
            "provider" => Some(SignerType::Provider),
            _ => None,
        }
    }
}

impl std::fmt::Display for SignerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Legal document template
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct LegalDocumentTemplate {
    pub id: String,
    pub name: String,
    pub document_type: String,
    pub description: Option<String>,
    pub content_html: String,
    pub is_system: bool,
    pub user_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Generated legal document
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct LegalDocument {
    pub id: String,
    pub template_id: Option<String>,
    pub engagement_id: String,
    pub customer_id: String,
    pub document_type: String,
    pub name: String,
    pub content_html: String,
    pub status: String,
    pub signature_token: Option<String>,
    pub signature_token_expires_at: Option<String>,
    pub final_pdf_path: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Document signature record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct LegalDocumentSignature {
    pub id: String,
    pub document_id: String,
    pub signer_type: String,
    pub signer_role: String,
    pub signer_name: Option<String>,
    pub signer_email: String,
    pub status: String,
    pub signed_at: Option<String>,
    pub signed_ip: Option<String>,
    pub signature_image: Option<String>,
    pub decline_reason: Option<String>,
    pub signature_order: i32,
}

/// Document history entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct LegalDocumentHistory {
    pub id: String,
    pub document_id: String,
    pub action: String,
    pub actor_email: Option<String>,
    pub ip_address: Option<String>,
    pub details: Option<String>,
    pub created_at: String,
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to create a new template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTemplateRequest {
    pub name: String,
    pub document_type: String,
    pub description: Option<String>,
    pub content_html: String,
}

/// Request to update a template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTemplateRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub content_html: Option<String>,
}

/// Request to create a document from template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDocumentRequest {
    pub template_id: Option<String>,
    pub engagement_id: String,
    pub customer_id: String,
    pub document_type: String,
    pub name: String,
    pub content_html: Option<String>,  // If not provided, will use template
}

/// Request to update a document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDocumentRequest {
    pub name: Option<String>,
    pub content_html: Option<String>,
}

/// Request to add a signature block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddSignatureRequest {
    pub signer_type: String,
    pub signer_role: String,
    pub signer_email: String,
    pub signature_order: Option<i32>,
}

/// Request to send document for signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendForSignatureRequest {
    pub message: Option<String>,  // Optional custom message in email
}

/// Public signing data returned to signer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningData {
    pub document_id: String,
    pub document_name: String,
    pub document_type: String,
    pub content_html: String,
    pub signer_email: String,
    pub signer_role: String,
    pub signer_type: String,
    pub customer_name: String,
    pub engagement_name: String,
    pub all_signatures: Vec<SignatureInfo>,
}

/// Signature info for display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub signer_type: String,
    pub signer_role: String,
    pub signer_name: Option<String>,
    pub signer_email: String,
    pub status: String,
    pub signed_at: Option<String>,
}

/// Request to submit a signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitSignatureRequest {
    pub signer_name: String,
    pub signature_image: String,  // Base64 PNG from signature pad
    pub acknowledgment: bool,     // Must be true
}

/// Document list item with summary info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentListItem {
    pub id: String,
    pub name: String,
    pub document_type: String,
    pub status: String,
    pub customer_name: String,
    pub engagement_name: String,
    pub created_at: String,
    pub updated_at: String,
    pub signature_count: i32,
    pub signed_count: i32,
}

/// Available placeholders for template editing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaceholderInfo {
    pub key: String,
    pub description: String,
    pub source: String,
    pub example: String,
}
