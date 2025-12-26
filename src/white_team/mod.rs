// White Team - Governance, Risk & Compliance (GRC)
//
// This module provides comprehensive GRC capabilities:
// - Policy Management: Document lifecycle, versioning, approvals, acknowledgments
// - Risk Management: Risk register, assessments, FAIR analysis, treatment plans
// - Control Framework: Control library, framework mapping, testing, crosswalk
// - Audit Management: Audit planning, execution, findings, evidence
// - Vendor Risk Management: Assessments, questionnaires, monitoring

pub mod types;
pub mod policy;
pub mod risk;
pub mod controls;
pub mod audit;
pub mod vendor;

pub use types::*;
