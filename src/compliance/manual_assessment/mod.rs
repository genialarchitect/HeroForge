//! Manual Compliance Assessment Module
//!
//! This module provides types and functionality for manual compliance assessments,
//! complementing the automated compliance scanning capabilities.
//!
//! ## Overview
//!
//! Manual assessments allow users to:
//! - Define custom rubrics with assessment criteria for controls
//! - Record manual assessments with structured responses
//! - Attach evidence (files, links, screenshots, notes) to assessments
//! - Organize assessments into campaigns for coordinated review
//! - Track progress and review status across multiple controls
//!
//! ## Key Components
//!
//! - **Rubrics**: Define how a control should be assessed, including criteria,
//!   rating scales, and evidence requirements
//! - **Assessments**: Record of a manual assessment including responses,
//!   evidence, findings, and recommendations
//! - **Evidence**: Supporting documentation attached to assessments
//! - **Campaigns**: Coordinate multiple assessments with deadlines and tracking
//! - **Default Rubrics**: System-provided rubrics for non-automated controls

pub mod default_rubrics;
pub mod types;

// Re-export types that are used by other modules
pub use types::{
    AssessmentCampaign,
    AssessmentCriterion,
    AssessmentEvidence,
    CampaignProgress,
    CampaignStatus,
    ComplianceRubric,
    CriterionResponse,
    EvidenceRequirement,
    EvidenceType,
    ManualAssessment,
    OverallRating,
    RatingScale,
    ReviewStatus,
};
