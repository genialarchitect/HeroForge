//! Shared types for manual compliance API endpoints
//!
//! Contains request/response types and database row types used across
//! rubrics, assessments, evidence, and campaigns handlers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::compliance::manual_assessment::{
    AssessmentCampaign, AssessmentCriterion, AssessmentEvidence, CampaignStatus,
    ComplianceRubric, CriterionResponse, EvidenceRequirement, EvidenceType, ManualAssessment,
    OverallRating, RatingScale, ReviewStatus,
};

// ============================================================================
// Rubric Types
// ============================================================================

/// Query parameters for listing rubrics
#[derive(Debug, Deserialize)]
pub struct RubricListQuery {
    /// Filter by framework ID
    pub framework_id: Option<String>,
}

/// Request to create a new rubric
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRubricRequest {
    pub framework_id: String,
    pub control_id: String,
    pub name: String,
    pub description: Option<String>,
    #[schema(value_type = Vec<Object>)]
    pub assessment_criteria: Vec<AssessmentCriterion>,
    #[schema(value_type = Option<Object>)]
    pub rating_scale: Option<RatingScale>,
    #[schema(value_type = Vec<Object>)]
    pub evidence_requirements: Vec<EvidenceRequirement>,
}

/// Request to update a rubric
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRubricRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    #[schema(value_type = Option<Vec<Object>>)]
    pub assessment_criteria: Option<Vec<AssessmentCriterion>>,
    #[schema(value_type = Option<Object>)]
    pub rating_scale: Option<RatingScale>,
    #[schema(value_type = Option<Vec<Object>>)]
    pub evidence_requirements: Option<Vec<EvidenceRequirement>>,
}

/// Response for rubric list
#[derive(Debug, Serialize)]
pub struct RubricListResponse {
    pub rubrics: Vec<ComplianceRubric>,
    pub total: usize,
}

// ============================================================================
// Assessment Types
// ============================================================================

/// Query parameters for listing assessments
#[derive(Debug, Deserialize)]
pub struct AssessmentListQuery {
    /// Filter by framework ID
    pub framework_id: Option<String>,
    /// Filter by review status
    pub status: Option<String>,
}

/// Request to create a new assessment
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAssessmentRequest {
    pub rubric_id: String,
    pub framework_id: String,
    pub control_id: String,
    pub assessment_period_start: DateTime<Utc>,
    pub assessment_period_end: DateTime<Utc>,
    #[schema(value_type = String)]
    pub overall_rating: OverallRating,
    pub rating_score: f32,
    #[schema(value_type = Vec<Object>)]
    pub criteria_responses: Vec<CriterionResponse>,
    pub evidence_summary: Option<String>,
    pub findings: Option<String>,
    pub recommendations: Option<String>,
}

/// Request to update an assessment
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAssessmentRequest {
    #[schema(value_type = Option<String>)]
    pub overall_rating: Option<OverallRating>,
    pub rating_score: Option<f32>,
    #[schema(value_type = Option<Vec<Object>>)]
    pub criteria_responses: Option<Vec<CriterionResponse>>,
    pub evidence_summary: Option<String>,
    pub findings: Option<String>,
    pub recommendations: Option<String>,
}

/// Request to reject an assessment
#[derive(Debug, Deserialize, ToSchema)]
pub struct RejectAssessmentRequest {
    pub notes: String,
}

/// Response for assessment list
#[derive(Debug, Serialize)]
pub struct AssessmentListResponse {
    pub assessments: Vec<ManualAssessment>,
    pub total: usize,
}

// ============================================================================
// Evidence Types
// ============================================================================

/// Request to add evidence to an assessment
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddEvidenceRequest {
    #[schema(value_type = String)]
    pub evidence_type: EvidenceType,
    pub title: String,
    pub description: Option<String>,
    pub external_url: Option<String>,
    pub content: Option<String>,
}

/// Request to upload an evidence file (base64 encoded)
#[derive(Debug, Deserialize, ToSchema)]
pub struct UploadEvidenceFileRequest {
    pub title: String,
    pub description: Option<String>,
    pub filename: String,
    /// Base64-encoded file content
    pub file_data: String,
}

/// Response for evidence list
#[derive(Debug, Serialize)]
pub struct EvidenceListResponse {
    pub evidence: Vec<AssessmentEvidence>,
    pub total: usize,
}

// ============================================================================
// Campaign Types
// ============================================================================

/// Query parameters for listing campaigns
#[derive(Debug, Deserialize)]
pub struct CampaignListQuery {
    /// Filter by status
    pub status: Option<String>,
}

/// Request to create a new campaign
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCampaignRequest {
    pub name: String,
    pub description: Option<String>,
    pub frameworks: Vec<String>,
    pub due_date: Option<DateTime<Utc>>,
}

/// Request to update a campaign
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCampaignRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub frameworks: Option<Vec<String>>,
    pub due_date: Option<DateTime<Utc>>,
    #[schema(value_type = Option<String>)]
    pub status: Option<CampaignStatus>,
}

/// Response for campaign list
#[derive(Debug, Serialize)]
pub struct CampaignListResponse {
    pub campaigns: Vec<AssessmentCampaign>,
    pub total: usize,
}

// ============================================================================
// Combined Compliance Types
// ============================================================================

/// Combined compliance results response
#[derive(Debug, Serialize)]
pub struct CombinedComplianceResponse {
    pub scan_id: String,
    pub automated_summary: Option<serde_json::Value>,
    pub manual_assessments: Vec<ManualAssessment>,
    pub combined_score: f32,
    pub generated_at: DateTime<Utc>,
}

// ============================================================================
// Database Row Types
// ============================================================================

#[derive(Debug, sqlx::FromRow)]
pub struct RubricRow {
    pub id: String,
    pub user_id: Option<String>,
    pub framework_id: String,
    pub control_id: String,
    pub name: String,
    pub description: Option<String>,
    pub assessment_criteria: String,
    pub rating_scale: String,
    pub evidence_requirements: String,
    pub is_system_default: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<RubricRow> for ComplianceRubric {
    fn from(row: RubricRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            framework_id: row.framework_id,
            control_id: row.control_id,
            name: row.name,
            description: row.description,
            assessment_criteria: serde_json::from_str(&row.assessment_criteria).unwrap_or_default(),
            rating_scale: serde_json::from_str(&row.rating_scale).unwrap_or_default(),
            evidence_requirements: serde_json::from_str(&row.evidence_requirements)
                .unwrap_or_default(),
            is_system_default: row.is_system_default,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct AssessmentRow {
    pub id: String,
    pub user_id: String,
    pub rubric_id: String,
    pub framework_id: String,
    pub control_id: String,
    pub assessment_period_start: DateTime<Utc>,
    pub assessment_period_end: DateTime<Utc>,
    pub overall_rating: String,
    pub rating_score: f32,
    pub criteria_responses: String,
    pub evidence_summary: Option<String>,
    pub findings: Option<String>,
    pub recommendations: Option<String>,
    pub review_status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<AssessmentRow> for ManualAssessment {
    fn from(row: AssessmentRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            rubric_id: row.rubric_id,
            framework_id: row.framework_id,
            control_id: row.control_id,
            assessment_period_start: row.assessment_period_start,
            assessment_period_end: row.assessment_period_end,
            overall_rating: serde_json::from_str(&row.overall_rating)
                .unwrap_or(OverallRating::NonCompliant),
            rating_score: row.rating_score,
            criteria_responses: serde_json::from_str(&row.criteria_responses).unwrap_or_default(),
            evidence_summary: row.evidence_summary,
            findings: row.findings,
            recommendations: row.recommendations,
            review_status: match row.review_status.as_str() {
                "draft" => ReviewStatus::Draft,
                "pending_review" => ReviewStatus::PendingReview,
                "approved" => ReviewStatus::Approved,
                "rejected" => ReviewStatus::Rejected,
                _ => ReviewStatus::Draft,
            },
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct EvidenceRow {
    pub id: String,
    pub assessment_id: String,
    pub evidence_type: String,
    pub title: String,
    pub description: Option<String>,
    pub file_path: Option<String>,
    pub external_url: Option<String>,
    pub content: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<EvidenceRow> for AssessmentEvidence {
    fn from(row: EvidenceRow) -> Self {
        Self {
            id: row.id,
            assessment_id: row.assessment_id,
            evidence_type: serde_json::from_str(&row.evidence_type).unwrap_or(EvidenceType::Note),
            title: row.title,
            description: row.description,
            file_path: row.file_path,
            external_url: row.external_url,
            content: row.content,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct CampaignRow {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub frameworks: String,
    pub due_date: Option<DateTime<Utc>>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<CampaignRow> for AssessmentCampaign {
    fn from(row: CampaignRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            name: row.name,
            description: row.description,
            frameworks: serde_json::from_str(&row.frameworks).unwrap_or_default(),
            due_date: row.due_date,
            status: match row.status.as_str() {
                "draft" => CampaignStatus::Draft,
                "active" => CampaignStatus::Active,
                "completed" => CampaignStatus::Completed,
                "archived" => CampaignStatus::Archived,
                _ => CampaignStatus::Draft,
            },
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Helper to fetch assessments with dynamic parameters
pub async fn fetch_assessments_dynamic(
    pool: &sqlx::SqlitePool,
    sql: &str,
    params: &[String],
) -> Result<Vec<ManualAssessment>, sqlx::Error> {
    // Build query dynamically based on number of parameters
    // This is a workaround since sqlx doesn't support dynamic parameter binding
    match params.len() {
        1 => sqlx::query_as::<_, AssessmentRow>(sql)
            .bind(&params[0])
            .fetch_all(pool)
            .await
            .map(|rows| rows.into_iter().map(|r| r.into()).collect()),
        2 => sqlx::query_as::<_, AssessmentRow>(sql)
            .bind(&params[0])
            .bind(&params[1])
            .fetch_all(pool)
            .await
            .map(|rows| rows.into_iter().map(|r| r.into()).collect()),
        3 => sqlx::query_as::<_, AssessmentRow>(sql)
            .bind(&params[0])
            .bind(&params[1])
            .bind(&params[2])
            .fetch_all(pool)
            .await
            .map(|rows| rows.into_iter().map(|r| r.into()).collect()),
        _ => Ok(Vec::new()),
    }
}

/// Determine content type from file extension
pub fn get_content_type_from_extension(path: &str) -> &'static str {
    let extension = std::path::Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_lowercase();

    match extension.as_str() {
        "pdf" => "application/pdf",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "txt" => "text/plain",
        "csv" => "text/csv",
        "json" => "application/json",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        "rar" => "application/vnd.rar",
        "7z" => "application/x-7z-compressed",
        _ => "application/octet-stream",
    }
}
