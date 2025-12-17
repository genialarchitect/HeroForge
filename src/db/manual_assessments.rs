//! Database operations for manual compliance assessment system
//!
//! This module provides functions for managing compliance rubrics, manual assessments,
//! assessment evidence, and assessment campaigns.

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::compliance::manual_assessment::types::{
    AssessmentCampaign, AssessmentEvidence, CampaignProgress, CampaignStatus,
    ComplianceRubric, ManualAssessment, ReviewStatus,
};

// ============================================================================
// Rubric Management Functions
// ============================================================================

/// Create a new compliance rubric
pub async fn create_rubric(pool: &SqlitePool, rubric: &ComplianceRubric) -> Result<String> {
    let id = if rubric.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        rubric.id.clone()
    };
    let now = Utc::now();

    // Serialize complex fields to JSON
    let criteria_json = serde_json::to_string(&rubric.assessment_criteria)?;
    let rating_scale_json = serde_json::to_string(&rubric.rating_scale)?;
    let evidence_requirements_json = serde_json::to_string(&rubric.evidence_requirements)?;

    sqlx::query(
        r#"
        INSERT INTO compliance_rubrics (
            id, user_id, framework_id, control_id, name, description,
            criteria, rating_scale, evidence_requirements, guidance,
            weight, is_template, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        "#,
    )
    .bind(&id)
    .bind(&rubric.user_id)
    .bind(&rubric.framework_id)
    .bind(&rubric.control_id)
    .bind(&rubric.name)
    .bind(&rubric.description)
    .bind(&criteria_json)
    .bind(&rating_scale_json)
    .bind(&evidence_requirements_json)
    .bind::<Option<&str>>(None) // guidance - not in types.rs but in schema
    .bind(1.0_f64) // weight - default
    .bind(rubric.is_system_default)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get a rubric by ID
pub async fn get_rubric(pool: &SqlitePool, id: &str) -> Result<Option<ComplianceRubric>> {
    let row: Option<RubricRow> = sqlx::query_as(
        "SELECT * FROM compliance_rubrics WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(rubric_from_row(r)?)),
        None => Ok(None),
    }
}

/// List rubrics with optional filters
pub async fn list_rubrics(
    pool: &SqlitePool,
    user_id: &str,
    framework_id: Option<&str>,
) -> Result<Vec<ComplianceRubric>> {
    let rows: Vec<RubricRow> = match framework_id {
        Some(fid) => {
            sqlx::query_as(
                r#"
                SELECT * FROM compliance_rubrics
                WHERE (user_id = ?1 OR is_template = 1)
                AND framework_id = ?2
                ORDER BY name
                "#,
            )
            .bind(user_id)
            .bind(fid)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as(
                r#"
                SELECT * FROM compliance_rubrics
                WHERE user_id = ?1 OR is_template = 1
                ORDER BY name
                "#,
            )
            .bind(user_id)
            .fetch_all(pool)
            .await?
        }
    };

    rows.into_iter().map(rubric_from_row).collect()
}

/// Get all rubrics for a specific framework
pub async fn get_rubrics_for_framework(
    pool: &SqlitePool,
    framework_id: &str,
) -> Result<Vec<ComplianceRubric>> {
    let rows: Vec<RubricRow> = sqlx::query_as(
        r#"
        SELECT * FROM compliance_rubrics
        WHERE framework_id = ?1
        ORDER BY control_id, name
        "#,
    )
    .bind(framework_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(rubric_from_row).collect()
}

/// Update an existing rubric
pub async fn update_rubric(pool: &SqlitePool, id: &str, rubric: &ComplianceRubric) -> Result<()> {
    let now = Utc::now();

    let criteria_json = serde_json::to_string(&rubric.assessment_criteria)?;
    let rating_scale_json = serde_json::to_string(&rubric.rating_scale)?;
    let evidence_requirements_json = serde_json::to_string(&rubric.evidence_requirements)?;

    sqlx::query(
        r#"
        UPDATE compliance_rubrics
        SET framework_id = ?1, control_id = ?2, name = ?3, description = ?4,
            criteria = ?5, rating_scale = ?6, evidence_requirements = ?7,
            is_template = ?8, updated_at = ?9
        WHERE id = ?10
        "#,
    )
    .bind(&rubric.framework_id)
    .bind(&rubric.control_id)
    .bind(&rubric.name)
    .bind(&rubric.description)
    .bind(&criteria_json)
    .bind(&rating_scale_json)
    .bind(&evidence_requirements_json)
    .bind(rubric.is_system_default)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a rubric by ID
pub async fn delete_rubric(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM compliance_rubrics WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Assessment Management Functions
// ============================================================================

/// Create a new manual assessment
pub async fn create_assessment(pool: &SqlitePool, assessment: &ManualAssessment) -> Result<String> {
    let id = if assessment.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        assessment.id.clone()
    };
    let now = Utc::now();

    // Serialize complex fields to JSON
    let rating_json = serde_json::to_string(&assessment.overall_rating)?;
    let criteria_responses_json = serde_json::to_string(&assessment.criteria_responses)?;
    let status_str = review_status_to_str(&assessment.review_status);

    sqlx::query(
        r#"
        INSERT INTO manual_assessments (
            id, user_id, rubric_id, framework_id, control_id,
            rating, score, findings, recommendations, compensating_controls,
            status, assessed_by, assessed_at, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
        "#,
    )
    .bind(&id)
    .bind(&assessment.user_id)
    .bind(&assessment.rubric_id)
    .bind(&assessment.framework_id)
    .bind(&assessment.control_id)
    .bind(&rating_json)
    .bind(assessment.rating_score)
    .bind(&assessment.findings)
    .bind(&assessment.recommendations)
    .bind(&criteria_responses_json) // Store criteria_responses in compensating_controls field
    .bind(status_str)
    .bind(&assessment.user_id) // assessed_by
    .bind(now)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get an assessment by ID
pub async fn get_assessment(pool: &SqlitePool, id: &str) -> Result<Option<ManualAssessment>> {
    let row: Option<AssessmentRow> = sqlx::query_as(
        "SELECT * FROM manual_assessments WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(assessment_from_row(r)?)),
        None => Ok(None),
    }
}

/// List assessments with optional filters
pub async fn list_assessments(
    pool: &SqlitePool,
    user_id: &str,
    framework_id: Option<&str>,
    status: Option<&str>,
) -> Result<Vec<ManualAssessment>> {
    let rows: Vec<AssessmentRow> = match (framework_id, status) {
        (Some(fid), Some(st)) => {
            sqlx::query_as(
                r#"
                SELECT * FROM manual_assessments
                WHERE user_id = ?1 AND framework_id = ?2 AND status = ?3
                ORDER BY created_at DESC
                "#,
            )
            .bind(user_id)
            .bind(fid)
            .bind(st)
            .fetch_all(pool)
            .await?
        }
        (Some(fid), None) => {
            sqlx::query_as(
                r#"
                SELECT * FROM manual_assessments
                WHERE user_id = ?1 AND framework_id = ?2
                ORDER BY created_at DESC
                "#,
            )
            .bind(user_id)
            .bind(fid)
            .fetch_all(pool)
            .await?
        }
        (None, Some(st)) => {
            sqlx::query_as(
                r#"
                SELECT * FROM manual_assessments
                WHERE user_id = ?1 AND status = ?2
                ORDER BY created_at DESC
                "#,
            )
            .bind(user_id)
            .bind(st)
            .fetch_all(pool)
            .await?
        }
        (None, None) => {
            sqlx::query_as(
                r#"
                SELECT * FROM manual_assessments
                WHERE user_id = ?1
                ORDER BY created_at DESC
                "#,
            )
            .bind(user_id)
            .fetch_all(pool)
            .await?
        }
    };

    rows.into_iter().map(assessment_from_row).collect()
}

/// Get all assessments for a specific control
pub async fn get_assessments_for_control(
    pool: &SqlitePool,
    framework_id: &str,
    control_id: &str,
) -> Result<Vec<ManualAssessment>> {
    let rows: Vec<AssessmentRow> = sqlx::query_as(
        r#"
        SELECT * FROM manual_assessments
        WHERE framework_id = ?1 AND control_id = ?2
        ORDER BY created_at DESC
        "#,
    )
    .bind(framework_id)
    .bind(control_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(assessment_from_row).collect()
}

/// Update an existing assessment
pub async fn update_assessment(
    pool: &SqlitePool,
    id: &str,
    assessment: &ManualAssessment,
) -> Result<()> {
    let now = Utc::now();

    let rating_json = serde_json::to_string(&assessment.overall_rating)?;
    let criteria_responses_json = serde_json::to_string(&assessment.criteria_responses)?;
    let status_str = review_status_to_str(&assessment.review_status);

    sqlx::query(
        r#"
        UPDATE manual_assessments
        SET rating = ?1, score = ?2, findings = ?3, recommendations = ?4,
            compensating_controls = ?5, status = ?6, updated_at = ?7
        WHERE id = ?8
        "#,
    )
    .bind(&rating_json)
    .bind(assessment.rating_score)
    .bind(&assessment.findings)
    .bind(&assessment.recommendations)
    .bind(&criteria_responses_json)
    .bind(status_str)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete an assessment by ID
pub async fn delete_assessment(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM manual_assessments WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Submit an assessment for review (change status to pending_review)
pub async fn submit_assessment(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE manual_assessments
        SET status = 'pending_review', updated_at = ?1
        WHERE id = ?2
        "#,
    )
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Approve an assessment
pub async fn approve_assessment(pool: &SqlitePool, id: &str, reviewer_id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE manual_assessments
        SET status = 'approved', reviewed_by = ?1, reviewed_at = ?2,
            approved_by = ?1, approved_at = ?2, updated_at = ?2
        WHERE id = ?3
        "#,
    )
    .bind(reviewer_id)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Reject an assessment with notes
pub async fn reject_assessment(
    pool: &SqlitePool,
    id: &str,
    reviewer_id: &str,
    notes: &str,
) -> Result<()> {
    let now = Utc::now();

    // First update the assessment status
    sqlx::query(
        r#"
        UPDATE manual_assessments
        SET status = 'rejected', reviewed_by = ?1, reviewed_at = ?2, updated_at = ?2
        WHERE id = ?3
        "#,
    )
    .bind(reviewer_id)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    // Record rejection in history
    let history_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO assessment_history (
            id, assessment_id, user_id, action, field_name, old_value, new_value, comment, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(&history_id)
    .bind(id)
    .bind(reviewer_id)
    .bind("rejected")
    .bind("status")
    .bind("pending_review")
    .bind("rejected")
    .bind(notes)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Evidence Management Functions
// ============================================================================

/// Add evidence to an assessment
pub async fn add_evidence(
    pool: &SqlitePool,
    evidence: &AssessmentEvidence,
    user_id: &str,
) -> Result<String> {
    let id = if evidence.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        evidence.id.clone()
    };
    let now = Utc::now();

    let evidence_type_str = evidence_type_to_str(&evidence.evidence_type);

    sqlx::query(
        r#"
        INSERT INTO assessment_evidence (
            id, assessment_id, user_id, evidence_type, title, description,
            file_path, url, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(&id)
    .bind(&evidence.assessment_id)
    .bind(user_id)
    .bind(evidence_type_str)
    .bind(&evidence.title)
    .bind(&evidence.description)
    .bind(&evidence.file_path)
    .bind(&evidence.external_url)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get evidence by ID
pub async fn get_evidence(pool: &SqlitePool, id: &str) -> Result<Option<AssessmentEvidence>> {
    let row: Option<EvidenceRow> = sqlx::query_as(
        "SELECT * FROM assessment_evidence WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(evidence_from_row(r)?)),
        None => Ok(None),
    }
}

/// List all evidence for an assessment
pub async fn list_evidence_for_assessment(
    pool: &SqlitePool,
    assessment_id: &str,
) -> Result<Vec<AssessmentEvidence>> {
    let rows: Vec<EvidenceRow> = sqlx::query_as(
        r#"
        SELECT * FROM assessment_evidence
        WHERE assessment_id = ?1
        ORDER BY created_at DESC
        "#,
    )
    .bind(assessment_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(evidence_from_row).collect()
}

/// Delete evidence by ID
pub async fn delete_evidence(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM assessment_evidence WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Campaign Management Functions
// ============================================================================

/// Create a new assessment campaign
pub async fn create_campaign(pool: &SqlitePool, campaign: &AssessmentCampaign) -> Result<String> {
    let id = if campaign.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        campaign.id.clone()
    };
    let now = Utc::now();

    let status_str = campaign_status_to_str(&campaign.status);
    let frameworks_json = serde_json::to_string(&campaign.frameworks)?;

    sqlx::query(
        r#"
        INSERT INTO assessment_campaigns (
            id, user_id, name, description, framework_id, start_date, end_date,
            status, target_completion_date, scope, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
    )
    .bind(&id)
    .bind(&campaign.user_id)
    .bind(&campaign.name)
    .bind(&campaign.description)
    .bind(&frameworks_json) // Store frameworks array in framework_id field
    .bind(now)
    .bind(&campaign.due_date)
    .bind(status_str)
    .bind(&campaign.due_date) // target_completion_date
    .bind::<Option<&str>>(None) // scope
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get a campaign by ID
pub async fn get_campaign(pool: &SqlitePool, id: &str) -> Result<Option<AssessmentCampaign>> {
    let row: Option<CampaignRow> = sqlx::query_as(
        "SELECT * FROM assessment_campaigns WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(campaign_from_row(r)?)),
        None => Ok(None),
    }
}

/// List all campaigns for a user
pub async fn list_campaigns(pool: &SqlitePool, user_id: &str) -> Result<Vec<AssessmentCampaign>> {
    let rows: Vec<CampaignRow> = sqlx::query_as(
        r#"
        SELECT * FROM assessment_campaigns
        WHERE user_id = ?1
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(campaign_from_row).collect()
}

/// Update an existing campaign
pub async fn update_campaign(
    pool: &SqlitePool,
    id: &str,
    campaign: &AssessmentCampaign,
) -> Result<()> {
    let now = Utc::now();

    let status_str = campaign_status_to_str(&campaign.status);
    let frameworks_json = serde_json::to_string(&campaign.frameworks)?;

    sqlx::query(
        r#"
        UPDATE assessment_campaigns
        SET name = ?1, description = ?2, framework_id = ?3, end_date = ?4,
            status = ?5, target_completion_date = ?6, updated_at = ?7
        WHERE id = ?8
        "#,
    )
    .bind(&campaign.name)
    .bind(&campaign.description)
    .bind(&frameworks_json)
    .bind(&campaign.due_date)
    .bind(status_str)
    .bind(&campaign.due_date)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a campaign by ID
pub async fn delete_campaign(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM assessment_campaigns WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Calculate campaign progress
pub async fn get_campaign_progress(pool: &SqlitePool, campaign_id: &str) -> Result<CampaignProgress> {
    // Get all assessments linked to this campaign
    let assessments: Vec<AssessmentRow> = sqlx::query_as(
        r#"
        SELECT ma.* FROM manual_assessments ma
        INNER JOIN campaign_assessments ca ON ma.id = ca.assessment_id
        WHERE ca.campaign_id = ?1
        "#,
    )
    .bind(campaign_id)
    .fetch_all(pool)
    .await?;

    let total_controls = assessments.len();
    let mut assessed = 0;
    let mut pending_review = 0;
    let mut approved = 0;

    for a in assessments {
        let status = a.status.as_str();
        match status {
            "draft" => {} // Not counted as assessed
            "pending_review" => {
                assessed += 1;
                pending_review += 1;
            }
            "approved" => {
                assessed += 1;
                approved += 1;
            }
            "rejected" => {
                assessed += 1; // Was assessed but needs revision
            }
            _ => {}
        }
    }

    Ok(CampaignProgress::new(total_controls, assessed, pending_review, approved))
}

/// Link an assessment to a campaign
pub async fn add_assessment_to_campaign(
    pool: &SqlitePool,
    campaign_id: &str,
    assessment_id: &str,
) -> Result<()> {
    let now = Utc::now();

    // Get user_id from assessment to use as added_by
    let assessment: Option<AssessmentRow> = sqlx::query_as(
        "SELECT * FROM manual_assessments WHERE id = ?1",
    )
    .bind(assessment_id)
    .fetch_optional(pool)
    .await?;

    let added_by = assessment
        .map(|a| a.user_id)
        .unwrap_or_else(|| "system".to_string());

    sqlx::query(
        r#"
        INSERT OR IGNORE INTO campaign_assessments (campaign_id, assessment_id, added_at, added_by)
        VALUES (?1, ?2, ?3, ?4)
        "#,
    )
    .bind(campaign_id)
    .bind(assessment_id)
    .bind(now)
    .bind(&added_by)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Helper Types and Conversion Functions
// ============================================================================

/// Database row structure for compliance_rubrics table
#[derive(Debug, sqlx::FromRow)]
struct RubricRow {
    id: String,
    user_id: String,
    framework_id: String,
    control_id: String,
    name: String,
    description: Option<String>,
    criteria: String,
    rating_scale: String,
    evidence_requirements: String,
    #[allow(dead_code)]
    guidance: Option<String>,
    #[allow(dead_code)]
    weight: f64,
    is_template: bool,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

fn rubric_from_row(row: RubricRow) -> Result<ComplianceRubric> {
    let assessment_criteria = serde_json::from_str(&row.criteria)?;
    let rating_scale = serde_json::from_str(&row.rating_scale)?;
    let evidence_requirements = serde_json::from_str(&row.evidence_requirements)?;

    Ok(ComplianceRubric {
        id: row.id,
        user_id: Some(row.user_id),
        framework_id: row.framework_id,
        control_id: row.control_id,
        name: row.name,
        description: row.description,
        assessment_criteria,
        rating_scale,
        evidence_requirements,
        is_system_default: row.is_template,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// Database row structure for manual_assessments table
#[derive(Debug, sqlx::FromRow)]
struct AssessmentRow {
    id: String,
    user_id: String,
    rubric_id: String,
    framework_id: String,
    control_id: String,
    #[allow(dead_code)]
    scan_id: Option<String>,
    rating: String,
    score: Option<f64>,
    findings: Option<String>,
    recommendations: Option<String>,
    compensating_controls: Option<String>,
    status: String,
    #[allow(dead_code)]
    assessed_by: String,
    assessed_at: chrono::DateTime<Utc>,
    #[allow(dead_code)]
    reviewed_by: Option<String>,
    #[allow(dead_code)]
    reviewed_at: Option<chrono::DateTime<Utc>>,
    #[allow(dead_code)]
    approved_by: Option<String>,
    #[allow(dead_code)]
    approved_at: Option<chrono::DateTime<Utc>>,
    #[allow(dead_code)]
    valid_until: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

fn assessment_from_row(row: AssessmentRow) -> Result<ManualAssessment> {
    let overall_rating = serde_json::from_str(&row.rating)?;
    let criteria_responses = row
        .compensating_controls
        .as_ref()
        .map(|c| serde_json::from_str(c))
        .transpose()?
        .unwrap_or_default();
    let review_status = str_to_review_status(&row.status);

    Ok(ManualAssessment {
        id: row.id,
        user_id: row.user_id,
        rubric_id: row.rubric_id,
        framework_id: row.framework_id,
        control_id: row.control_id,
        assessment_period_start: row.assessed_at,
        assessment_period_end: row.updated_at,
        overall_rating,
        rating_score: row.score.unwrap_or(0.0) as f32,
        criteria_responses,
        evidence_summary: None,
        findings: row.findings,
        recommendations: row.recommendations,
        review_status,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn review_status_to_str(status: &ReviewStatus) -> &'static str {
    match status {
        ReviewStatus::Draft => "draft",
        ReviewStatus::PendingReview => "pending_review",
        ReviewStatus::Approved => "approved",
        ReviewStatus::Rejected => "rejected",
    }
}

fn str_to_review_status(s: &str) -> ReviewStatus {
    match s {
        "draft" => ReviewStatus::Draft,
        "pending_review" => ReviewStatus::PendingReview,
        "approved" => ReviewStatus::Approved,
        "rejected" => ReviewStatus::Rejected,
        _ => ReviewStatus::Draft,
    }
}

/// Database row structure for assessment_evidence table
#[derive(Debug, sqlx::FromRow)]
struct EvidenceRow {
    id: String,
    assessment_id: String,
    #[allow(dead_code)]
    user_id: String,
    evidence_type: String,
    title: String,
    description: Option<String>,
    file_path: Option<String>,
    #[allow(dead_code)]
    file_name: Option<String>,
    #[allow(dead_code)]
    file_size: Option<i64>,
    #[allow(dead_code)]
    file_mime_type: Option<String>,
    url: Option<String>,
    #[allow(dead_code)]
    screenshot_path: Option<String>,
    #[allow(dead_code)]
    metadata: Option<String>,
    created_at: chrono::DateTime<Utc>,
}

fn evidence_from_row(row: EvidenceRow) -> Result<AssessmentEvidence> {
    use crate::compliance::manual_assessment::types::EvidenceType;

    let evidence_type = match row.evidence_type.as_str() {
        "file" => EvidenceType::File,
        "link" => EvidenceType::Link,
        "screenshot" => EvidenceType::Screenshot,
        "note" => EvidenceType::Note,
        _ => EvidenceType::Note,
    };

    Ok(AssessmentEvidence {
        id: row.id,
        assessment_id: row.assessment_id,
        evidence_type,
        title: row.title,
        description: row.description,
        file_path: row.file_path,
        external_url: row.url,
        content: None,
        created_at: row.created_at,
        updated_at: row.created_at, // No updated_at in schema
    })
}

fn evidence_type_to_str(et: &crate::compliance::manual_assessment::types::EvidenceType) -> &'static str {
    use crate::compliance::manual_assessment::types::EvidenceType;
    match et {
        EvidenceType::File => "file",
        EvidenceType::Link => "link",
        EvidenceType::Screenshot => "screenshot",
        EvidenceType::Note => "note",
    }
}

/// Database row structure for assessment_campaigns table
#[derive(Debug, sqlx::FromRow)]
struct CampaignRow {
    id: String,
    user_id: String,
    name: String,
    description: Option<String>,
    framework_id: String,
    start_date: chrono::DateTime<Utc>,
    end_date: Option<chrono::DateTime<Utc>>,
    status: String,
    #[allow(dead_code)]
    target_completion_date: Option<chrono::DateTime<Utc>>,
    #[allow(dead_code)]
    scope: Option<String>,
    #[allow(dead_code)]
    objectives: Option<String>,
    #[allow(dead_code)]
    notes: Option<String>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

fn campaign_from_row(row: CampaignRow) -> Result<AssessmentCampaign> {
    let status = str_to_campaign_status(&row.status);

    // Try to parse framework_id as JSON array, fall back to single framework
    let frameworks: Vec<String> = serde_json::from_str(&row.framework_id)
        .unwrap_or_else(|_| vec![row.framework_id.clone()]);

    Ok(AssessmentCampaign {
        id: row.id,
        user_id: row.user_id,
        name: row.name,
        description: row.description,
        frameworks,
        due_date: row.end_date,
        status,
        created_at: row.start_date,
        updated_at: row.updated_at,
    })
}

fn campaign_status_to_str(status: &CampaignStatus) -> &'static str {
    match status {
        CampaignStatus::Draft => "draft",
        CampaignStatus::Active => "active",
        CampaignStatus::Completed => "completed",
        CampaignStatus::Archived => "archived",
    }
}

fn str_to_campaign_status(s: &str) -> CampaignStatus {
    match s {
        "draft" => CampaignStatus::Draft,
        "active" => CampaignStatus::Active,
        "completed" => CampaignStatus::Completed,
        "archived" => CampaignStatus::Archived,
        _ => CampaignStatus::Draft,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_review_status_conversion() {
        assert_eq!(review_status_to_str(&ReviewStatus::Draft), "draft");
        assert_eq!(review_status_to_str(&ReviewStatus::PendingReview), "pending_review");
        assert_eq!(review_status_to_str(&ReviewStatus::Approved), "approved");
        assert_eq!(review_status_to_str(&ReviewStatus::Rejected), "rejected");

        assert_eq!(str_to_review_status("draft"), ReviewStatus::Draft);
        assert_eq!(str_to_review_status("pending_review"), ReviewStatus::PendingReview);
        assert_eq!(str_to_review_status("approved"), ReviewStatus::Approved);
        assert_eq!(str_to_review_status("rejected"), ReviewStatus::Rejected);
        assert_eq!(str_to_review_status("unknown"), ReviewStatus::Draft);
    }

    #[test]
    fn test_campaign_status_conversion() {
        assert_eq!(campaign_status_to_str(&CampaignStatus::Draft), "draft");
        assert_eq!(campaign_status_to_str(&CampaignStatus::Active), "active");
        assert_eq!(campaign_status_to_str(&CampaignStatus::Completed), "completed");
        assert_eq!(campaign_status_to_str(&CampaignStatus::Archived), "archived");

        assert_eq!(str_to_campaign_status("draft"), CampaignStatus::Draft);
        assert_eq!(str_to_campaign_status("active"), CampaignStatus::Active);
        assert_eq!(str_to_campaign_status("completed"), CampaignStatus::Completed);
        assert_eq!(str_to_campaign_status("archived"), CampaignStatus::Archived);
        assert_eq!(str_to_campaign_status("unknown"), CampaignStatus::Draft);
    }
}
