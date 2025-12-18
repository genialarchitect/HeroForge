//! Types for manual compliance assessment system
//!
//! This module defines the data structures used for manual compliance assessments,
//! including rubrics, assessment criteria, evidence tracking, and assessment campaigns.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::super::types::ControlStatus;

/// Type of rating scale used for assessments
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RatingScaleType {
    /// Five-point scale (1-5 rating)
    FivePoint,
    /// Compliance status scale (compliant, non-compliant, partial, n/a)
    ComplianceStatus,
    /// Maturity level scale (e.g., CMM-style levels)
    Maturity,
}

impl Default for RatingScaleType {
    fn default() -> Self {
        Self::FivePoint
    }
}

/// A single level within a rating scale
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatingLevel {
    /// Numeric value of this level (e.g., 1, 2, 3, 4, 5)
    pub value: i32,
    /// Short label for this level (e.g., "Fully Implemented", "Not Implemented")
    pub label: String,
    /// Detailed description of what this level represents
    pub description: String,
    /// The ControlStatus this rating level maps to for compliance scoring
    pub maps_to_status: ControlStatus,
}

/// A rating scale definition containing the scale type and its levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatingScale {
    /// The type of rating scale
    pub scale_type: RatingScaleType,
    /// The levels in this scale, ordered from lowest to highest
    pub levels: Vec<RatingLevel>,
}

impl Default for RatingScale {
    fn default() -> Self {
        Self {
            scale_type: RatingScaleType::FivePoint,
            levels: vec![
                RatingLevel {
                    value: 1,
                    label: "Not Implemented".to_string(),
                    description: "The control is not implemented or there is no evidence of implementation.".to_string(),
                    maps_to_status: ControlStatus::NonCompliant,
                },
                RatingLevel {
                    value: 2,
                    label: "Partially Implemented".to_string(),
                    description: "The control is partially implemented but significant gaps exist.".to_string(),
                    maps_to_status: ControlStatus::PartiallyCompliant,
                },
                RatingLevel {
                    value: 3,
                    label: "Largely Implemented".to_string(),
                    description: "The control is largely implemented with minor gaps.".to_string(),
                    maps_to_status: ControlStatus::PartiallyCompliant,
                },
                RatingLevel {
                    value: 4,
                    label: "Fully Implemented".to_string(),
                    description: "The control is fully implemented and documented.".to_string(),
                    maps_to_status: ControlStatus::Compliant,
                },
                RatingLevel {
                    value: 5,
                    label: "Optimized".to_string(),
                    description: "The control is fully implemented with continuous improvement processes.".to_string(),
                    maps_to_status: ControlStatus::Compliant,
                },
            ],
        }
    }
}

/// A single assessment criterion (question) within a rubric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentCriterion {
    /// Unique identifier for this criterion
    pub id: String,
    /// The question to be answered during assessment
    pub question: String,
    /// Additional description or context for the criterion
    pub description: Option<String>,
    /// Guidance on how to evaluate this criterion
    pub guidance: Option<String>,
    /// Weight of this criterion in the overall assessment (0.0 to 1.0)
    pub weight: f32,
    /// Hint about what evidence should be collected for this criterion
    pub evidence_hint: Option<String>,
}

/// A response to a single assessment criterion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriterionResponse {
    /// The ID of the criterion being responded to
    pub criterion_id: String,
    /// The rating value selected (must match a level in the rating scale)
    pub rating: i32,
    /// Additional notes or observations for this criterion
    pub notes: Option<String>,
    /// IDs of evidence items supporting this response
    pub evidence_ids: Vec<String>,
}

/// Type of evidence that can be attached to an assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    /// Uploaded file (document, spreadsheet, etc.)
    File,
    /// External URL/link
    Link,
    /// Screenshot or image
    Screenshot,
    /// Text note or description
    Note,
}

/// An evidence requirement definition within a rubric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRequirement {
    /// The type of evidence required
    pub evidence_type: EvidenceType,
    /// Description of what evidence is needed
    pub description: String,
    /// Whether this evidence is required or optional
    pub required: bool,
}

/// A compliance rubric defining how to assess a control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRubric {
    /// Unique identifier for this rubric
    pub id: String,
    /// User who created/owns this rubric (None for system defaults)
    pub user_id: Option<String>,
    /// The compliance framework this rubric belongs to
    pub framework_id: String,
    /// The control ID this rubric is for
    pub control_id: String,
    /// Human-readable name for this rubric
    pub name: String,
    /// Description of what this rubric assesses
    pub description: Option<String>,
    /// The assessment criteria (questions) in this rubric
    pub assessment_criteria: Vec<AssessmentCriterion>,
    /// The rating scale to use for this rubric
    pub rating_scale: RatingScale,
    /// Evidence requirements for this rubric
    pub evidence_requirements: Vec<EvidenceRequirement>,
    /// Whether this is a system-provided default rubric
    pub is_system_default: bool,
    /// When this rubric was created
    pub created_at: DateTime<Utc>,
    /// When this rubric was last updated
    pub updated_at: DateTime<Utc>,
}

/// Overall rating for a manual assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OverallRating {
    /// Control requirements are fully met
    Compliant,
    /// Control requirements are not met
    NonCompliant,
    /// Control requirements are partially met
    Partial,
    /// Control is not applicable to this environment
    NotApplicable,
}

impl From<OverallRating> for ControlStatus {
    fn from(rating: OverallRating) -> Self {
        match rating {
            OverallRating::Compliant => ControlStatus::Compliant,
            OverallRating::NonCompliant => ControlStatus::NonCompliant,
            OverallRating::Partial => ControlStatus::PartiallyCompliant,
            OverallRating::NotApplicable => ControlStatus::NotApplicable,
        }
    }
}

/// Review status for an assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    /// Assessment is in draft state
    Draft,
    /// Assessment is pending review
    PendingReview,
    /// Assessment has been approved
    Approved,
    /// Assessment was rejected and needs revision
    Rejected,
}

impl Default for ReviewStatus {
    fn default() -> Self {
        Self::Draft
    }
}

/// A manual compliance assessment record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualAssessment {
    /// Unique identifier for this assessment
    pub id: String,
    /// User who performed the assessment
    pub user_id: String,
    /// The rubric used for this assessment
    pub rubric_id: String,
    /// The compliance framework being assessed
    pub framework_id: String,
    /// The control being assessed
    pub control_id: String,
    /// Start of the assessment period
    pub assessment_period_start: DateTime<Utc>,
    /// End of the assessment period
    pub assessment_period_end: DateTime<Utc>,
    /// Overall compliance rating
    pub overall_rating: OverallRating,
    /// Numeric score derived from criterion responses (0.0 to 100.0)
    pub rating_score: f32,
    /// Responses to each assessment criterion
    pub criteria_responses: Vec<CriterionResponse>,
    /// Summary of evidence collected
    pub evidence_summary: Option<String>,
    /// Key findings from the assessment
    pub findings: Option<String>,
    /// Recommendations for improvement
    pub recommendations: Option<String>,
    /// Current review status
    pub review_status: ReviewStatus,
    /// When this assessment was created
    pub created_at: DateTime<Utc>,
    /// When this assessment was last updated
    pub updated_at: DateTime<Utc>,
}

/// Evidence attached to a manual assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentEvidence {
    /// Unique identifier for this evidence item
    pub id: String,
    /// The assessment this evidence belongs to
    pub assessment_id: String,
    /// Type of evidence
    pub evidence_type: EvidenceType,
    /// Title/name of the evidence
    pub title: String,
    /// Description of what this evidence demonstrates
    pub description: Option<String>,
    /// Path to uploaded file (for File and Screenshot types)
    pub file_path: Option<String>,
    /// External URL (for Link type)
    pub external_url: Option<String>,
    /// Text content (for Note type)
    pub content: Option<String>,
    /// When this evidence was uploaded/created
    pub created_at: DateTime<Utc>,
    /// When this evidence was last updated
    pub updated_at: DateTime<Utc>,
}

/// Status of an assessment campaign
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    /// Campaign is being set up
    Draft,
    /// Campaign is active and assessments are in progress
    Active,
    /// All assessments have been completed
    Completed,
    /// Campaign has been archived
    Archived,
}

impl Default for CampaignStatus {
    fn default() -> Self {
        Self::Draft
    }
}

/// An assessment campaign for coordinating multiple control assessments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentCampaign {
    /// Unique identifier for this campaign
    pub id: String,
    /// User who created/owns this campaign
    pub user_id: String,
    /// Name of the campaign
    pub name: String,
    /// Description of the campaign's purpose and scope
    pub description: Option<String>,
    /// Compliance frameworks included in this campaign
    pub frameworks: Vec<String>,
    /// Due date for completing all assessments
    pub due_date: Option<DateTime<Utc>>,
    /// Current status of the campaign
    pub status: CampaignStatus,
    /// When this campaign was created
    pub created_at: DateTime<Utc>,
    /// When this campaign was last updated
    pub updated_at: DateTime<Utc>,
}

/// Progress tracking for an assessment campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignProgress {
    /// Total number of controls to assess in the campaign
    pub total_controls: usize,
    /// Number of controls that have been assessed
    pub assessed: usize,
    /// Number of assessments pending review
    pub pending_review: usize,
    /// Number of assessments that have been approved
    pub approved: usize,
    /// Overall completion percentage (0.0 to 100.0)
    pub percentage_complete: f32,
}

impl CampaignProgress {
    /// Create a new CampaignProgress with calculated percentage
    pub fn new(total_controls: usize, assessed: usize, pending_review: usize, approved: usize) -> Self {
        let percentage_complete = if total_controls > 0 {
            (assessed as f32 / total_controls as f32) * 100.0
        } else {
            0.0
        };

        Self {
            total_controls,
            assessed,
            pending_review,
            approved,
            percentage_complete,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rating_scale_default() {
        let scale = RatingScale::default();
        assert_eq!(scale.scale_type, RatingScaleType::FivePoint);
        assert_eq!(scale.levels.len(), 5);
        assert_eq!(scale.levels[0].value, 1);
        assert_eq!(scale.levels[4].value, 5);
    }

    #[test]
    fn test_overall_rating_to_control_status() {
        assert_eq!(ControlStatus::from(OverallRating::Compliant), ControlStatus::Compliant);
        assert_eq!(ControlStatus::from(OverallRating::NonCompliant), ControlStatus::NonCompliant);
        assert_eq!(ControlStatus::from(OverallRating::Partial), ControlStatus::PartiallyCompliant);
        assert_eq!(ControlStatus::from(OverallRating::NotApplicable), ControlStatus::NotApplicable);
    }

    #[test]
    fn test_campaign_progress_calculation() {
        let progress = CampaignProgress::new(100, 50, 10, 30);
        assert_eq!(progress.total_controls, 100);
        assert_eq!(progress.assessed, 50);
        assert_eq!(progress.pending_review, 10);
        assert_eq!(progress.approved, 30);
        assert_eq!(progress.percentage_complete, 50.0);
    }

    #[test]
    fn test_campaign_progress_zero_total() {
        let progress = CampaignProgress::new(0, 0, 0, 0);
        assert_eq!(progress.percentage_complete, 0.0);
    }
}
