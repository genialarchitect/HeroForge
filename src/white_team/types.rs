// White Team - Governance, Risk & Compliance (GRC) Types

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Policy Management Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Draft,
    PendingReview,
    PendingApproval,
    Approved,
    Retired,
}

impl std::fmt::Display for PolicyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draft => write!(f, "draft"),
            Self::PendingReview => write!(f, "pending_review"),
            Self::PendingApproval => write!(f, "pending_approval"),
            Self::Approved => write!(f, "approved"),
            Self::Retired => write!(f, "retired"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCategory {
    InformationSecurity,
    AcceptableUse,
    DataProtection,
    IncidentResponse,
    AccessControl,
    BusinessContinuity,
    ChangeManagement,
    VendorManagement,
    Compliance,
    Privacy,
    PhysicalSecurity,
    HumanResources,
}

impl std::fmt::Display for PolicyCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InformationSecurity => write!(f, "information_security"),
            Self::AcceptableUse => write!(f, "acceptable_use"),
            Self::DataProtection => write!(f, "data_protection"),
            Self::IncidentResponse => write!(f, "incident_response"),
            Self::AccessControl => write!(f, "access_control"),
            Self::BusinessContinuity => write!(f, "business_continuity"),
            Self::ChangeManagement => write!(f, "change_management"),
            Self::VendorManagement => write!(f, "vendor_management"),
            Self::Compliance => write!(f, "compliance"),
            Self::Privacy => write!(f, "privacy"),
            Self::PhysicalSecurity => write!(f, "physical_security"),
            Self::HumanResources => write!(f, "human_resources"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub policy_number: String,
    pub title: String,
    pub category: PolicyCategory,
    pub status: PolicyStatus,
    pub version: String,
    pub content: String,
    pub summary: Option<String>,
    pub owner_id: String,
    pub effective_date: Option<NaiveDate>,
    pub review_date: Option<NaiveDate>,
    pub expiry_date: Option<NaiveDate>,
    pub parent_policy_id: Option<String>,
    pub requires_acknowledgment: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersion {
    pub id: String,
    pub policy_id: String,
    pub version: String,
    pub content: String,
    pub change_summary: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyApproval {
    pub id: String,
    pub policy_id: String,
    pub version: String,
    pub approver_id: String,
    pub status: ApprovalStatus,
    pub comments: Option<String>,
    pub decided_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Rejected => write!(f, "rejected"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAcknowledgment {
    pub id: String,
    pub policy_id: String,
    pub user_id: String,
    pub version: String,
    pub acknowledged_at: DateTime<Utc>,
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyException {
    pub id: String,
    pub policy_id: String,
    pub title: String,
    pub description: String,
    pub justification: String,
    pub risk_accepted: Option<String>,
    pub compensating_controls: Option<String>,
    pub requestor_id: String,
    pub approver_id: Option<String>,
    pub status: ExceptionStatus,
    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

impl std::fmt::Display for ExceptionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Rejected => write!(f, "rejected"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

// ============================================================================
// Risk Management Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    Operational,
    Strategic,
    Compliance,
    Financial,
    Reputational,
    Cyber,
    Technology,
    ThirdParty,
    Legal,
    Regulatory,
}

impl std::fmt::Display for RiskCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Operational => write!(f, "operational"),
            Self::Strategic => write!(f, "strategic"),
            Self::Compliance => write!(f, "compliance"),
            Self::Financial => write!(f, "financial"),
            Self::Reputational => write!(f, "reputational"),
            Self::Cyber => write!(f, "cyber"),
            Self::Technology => write!(f, "technology"),
            Self::ThirdParty => write!(f, "third_party"),
            Self::Legal => write!(f, "legal"),
            Self::Regulatory => write!(f, "regulatory"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskStatus {
    Open,
    Mitigating,
    Accepted,
    Transferred,
    Closed,
}

impl std::fmt::Display for RiskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Mitigating => write!(f, "mitigating"),
            Self::Accepted => write!(f, "accepted"),
            Self::Transferred => write!(f, "transferred"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TreatmentStrategy {
    Mitigate,
    Accept,
    Transfer,
    Avoid,
}

impl std::fmt::Display for TreatmentStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mitigate => write!(f, "mitigate"),
            Self::Accept => write!(f, "accept"),
            Self::Transfer => write!(f, "transfer"),
            Self::Avoid => write!(f, "avoid"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risk {
    pub id: String,
    pub risk_id: String, // e.g., "RISK-2024-001"
    pub title: String,
    pub description: String,
    pub category: RiskCategory,
    pub status: RiskStatus,
    pub source: Option<String>,
    pub owner_id: String,

    // Inherent Risk (before controls)
    pub inherent_likelihood: u8, // 1-5
    pub inherent_impact: u8,     // 1-5
    pub inherent_risk_score: u8, // calculated: likelihood * impact

    // Residual Risk (after controls)
    pub residual_likelihood: Option<u8>,
    pub residual_impact: Option<u8>,
    pub residual_risk_score: Option<u8>,

    // FAIR Analysis
    pub fair_analysis: Option<FairAnalysis>,
    pub annualized_loss_expectancy: Option<f64>,

    // Treatment
    pub treatment_strategy: Option<TreatmentStrategy>,
    pub treatment_plan: Option<String>,
    pub target_date: Option<NaiveDate>,

    // Relationships
    pub related_controls: Vec<String>,
    pub related_assets: Vec<String>,
    pub tags: Vec<String>,

    pub last_assessed_at: Option<DateTime<Utc>>,
    pub next_review_date: Option<NaiveDate>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskRating {
    pub likelihood: u8, // 1-5
    pub impact: u8,     // 1-5
    pub score: u8,      // likelihood * impact
    pub level: RiskLevel,
}

impl RiskRating {
    pub fn calculate(likelihood: u8, impact: u8) -> Self {
        let score = likelihood * impact;
        let level = match score {
            1..=4 => RiskLevel::Low,
            5..=9 => RiskLevel::Medium,
            10..=16 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };
        Self { likelihood, impact, score, level }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub id: String,
    pub risk_id: String,
    pub assessment_type: AssessmentType,
    pub assessor_id: String,
    pub likelihood: u8,
    pub impact: u8,
    pub risk_score: u8,
    pub likelihood_rationale: Option<String>,
    pub impact_rationale: Option<String>,
    pub threats_identified: Vec<String>,
    pub vulnerabilities_identified: Vec<String>,
    pub recommendations: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentType {
    Initial,
    Periodic,
    TriggerBased,
}

impl std::fmt::Display for AssessmentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initial => write!(f, "initial"),
            Self::Periodic => write!(f, "periodic"),
            Self::TriggerBased => write!(f, "trigger_based"),
        }
    }
}

// FAIR (Factor Analysis of Information Risk) Analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FairAnalysis {
    pub threat_event_frequency: FrequencyRange,
    pub vulnerability: Percentage,
    pub loss_magnitude: MoneyRange,
    pub annualized_loss_expectancy: f64,
    pub confidence_level: Percentage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrequencyRange {
    pub min: f64,
    pub most_likely: f64,
    pub max: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Percentage {
    pub value: f64, // 0.0 - 1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoneyRange {
    pub min: f64,
    pub most_likely: f64,
    pub max: f64,
    pub currency: String,
}

// ============================================================================
// Control Framework Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlCategory {
    Preventive,
    Detective,
    Corrective,
    Compensating,
}

impl std::fmt::Display for ControlCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preventive => write!(f, "preventive"),
            Self::Detective => write!(f, "detective"),
            Self::Corrective => write!(f, "corrective"),
            Self::Compensating => write!(f, "compensating"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlType {
    Administrative,
    Technical,
    Physical,
}

impl std::fmt::Display for ControlType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Administrative => write!(f, "administrative"),
            Self::Technical => write!(f, "technical"),
            Self::Physical => write!(f, "physical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationStatus {
    NotImplemented,
    PartiallyImplemented,
    Implemented,
    NotApplicable,
}

impl std::fmt::Display for ImplementationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotImplemented => write!(f, "not_implemented"),
            Self::PartiallyImplemented => write!(f, "partially_implemented"),
            Self::Implemented => write!(f, "implemented"),
            Self::NotApplicable => write!(f, "not_applicable"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Effectiveness {
    Effective,
    PartiallyEffective,
    Ineffective,
    NotTested,
}

impl std::fmt::Display for Effectiveness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Effective => write!(f, "effective"),
            Self::PartiallyEffective => write!(f, "partially_effective"),
            Self::Ineffective => write!(f, "ineffective"),
            Self::NotTested => write!(f, "not_tested"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub control_id: String, // e.g., "CTRL-AC-001"
    pub title: String,
    pub description: String,
    pub category: ControlCategory,
    pub control_type: ControlType,
    pub domain: String,
    pub owner_id: Option<String>,
    pub implementation_status: ImplementationStatus,
    pub effectiveness: Option<Effectiveness>,
    pub testing_frequency: Option<String>,
    pub last_tested_at: Option<DateTime<Utc>>,
    pub next_test_date: Option<NaiveDate>,
    pub evidence_requirements: Vec<String>,
    pub automation_status: AutomationStatus,
    pub framework_mappings: Vec<FrameworkMapping>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutomationStatus {
    Manual,
    Partial,
    Automated,
}

impl std::fmt::Display for AutomationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Manual => write!(f, "manual"),
            Self::Partial => write!(f, "partial"),
            Self::Automated => write!(f, "automated"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkMapping {
    pub framework: ComplianceFramework,
    pub control_id: String,
    pub control_name: Option<String>,
    pub mapping_notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    Nist80053,
    NistCsf,
    Cis,
    Iso27001,
    PciDss,
    Soc2,
    Hipaa,
    Gdpr,
    Ferpa,
    Ccpa,
    Hitrust,
}

impl std::fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nist80053 => write!(f, "nist_800_53"),
            Self::NistCsf => write!(f, "nist_csf"),
            Self::Cis => write!(f, "cis"),
            Self::Iso27001 => write!(f, "iso_27001"),
            Self::PciDss => write!(f, "pci_dss"),
            Self::Soc2 => write!(f, "soc2"),
            Self::Hipaa => write!(f, "hipaa"),
            Self::Gdpr => write!(f, "gdpr"),
            Self::Ferpa => write!(f, "ferpa"),
            Self::Ccpa => write!(f, "ccpa"),
            Self::Hitrust => write!(f, "hitrust"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlTest {
    pub id: String,
    pub control_id: String,
    pub test_date: NaiveDate,
    pub tester_id: String,
    pub test_type: TestType,
    pub test_procedure: String,
    pub sample_size: Option<u32>,
    pub result: TestResult,
    pub findings: Option<String>,
    pub evidence_refs: Vec<String>,
    pub remediation_required: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestType {
    Design,
    OperatingEffectiveness,
}

impl std::fmt::Display for TestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Design => write!(f, "design"),
            Self::OperatingEffectiveness => write!(f, "operating_effectiveness"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestResult {
    Pass,
    Fail,
    Partial,
    NotApplicable,
}

impl std::fmt::Display for TestResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Fail => write!(f, "fail"),
            Self::Partial => write!(f, "partial"),
            Self::NotApplicable => write!(f, "not_applicable"),
        }
    }
}

// ============================================================================
// Audit Management Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditType {
    Internal,
    External,
    Regulatory,
}

impl std::fmt::Display for AuditType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => write!(f, "internal"),
            Self::External => write!(f, "external"),
            Self::Regulatory => write!(f, "regulatory"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Planning,
    Fieldwork,
    Reporting,
    FollowUp,
    Closed,
}

impl std::fmt::Display for AuditStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Planning => write!(f, "planning"),
            Self::Fieldwork => write!(f, "fieldwork"),
            Self::Reporting => write!(f, "reporting"),
            Self::FollowUp => write!(f, "follow_up"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Audit {
    pub id: String,
    pub audit_number: String,
    pub title: String,
    pub audit_type: AuditType,
    pub scope: String,
    pub objectives: Option<String>,
    pub status: AuditStatus,
    pub lead_auditor_id: String,
    pub auditee_id: Option<String>,
    pub planned_start_date: Option<NaiveDate>,
    pub planned_end_date: Option<NaiveDate>,
    pub actual_start_date: Option<NaiveDate>,
    pub actual_end_date: Option<NaiveDate>,
    pub frameworks: Vec<ComplianceFramework>,
    pub controls_in_scope: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Informational => write!(f, "informational"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    RemediationInProgress,
    PendingValidation,
    Closed,
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::RemediationInProgress => write!(f, "remediation_in_progress"),
            Self::PendingValidation => write!(f, "pending_validation"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub id: String,
    pub audit_id: String,
    pub finding_number: String,
    pub title: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub status: FindingStatus,
    pub control_id: Option<String>,
    pub root_cause: Option<String>,
    pub recommendation: String,
    pub management_response: Option<String>,
    pub remediation_owner_id: Option<String>,
    pub remediation_due_date: Option<NaiveDate>,
    pub remediation_completed_date: Option<NaiveDate>,
    pub evidence_refs: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    Document,
    Screenshot,
    Log,
    Interview,
    Observation,
}

impl std::fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Document => write!(f, "document"),
            Self::Screenshot => write!(f, "screenshot"),
            Self::Log => write!(f, "log"),
            Self::Interview => write!(f, "interview"),
            Self::Observation => write!(f, "observation"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvidence {
    pub id: String,
    pub audit_id: String,
    pub finding_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub evidence_type: EvidenceType,
    pub file_path: Option<String>,
    pub file_hash: Option<String>,
    pub collected_by: String,
    pub collected_at: DateTime<Utc>,
}

// ============================================================================
// Vendor Risk Management Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VendorCategory {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for VendorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VendorTier {
    Tier1, // Critical vendors
    Tier2, // Important vendors
    Tier3, // Standard vendors
}

impl std::fmt::Display for VendorTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tier1 => write!(f, "tier1"),
            Self::Tier2 => write!(f, "tier2"),
            Self::Tier3 => write!(f, "tier3"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VendorStatus {
    Prospective,
    Active,
    OnHold,
    Terminated,
}

impl std::fmt::Display for VendorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prospective => write!(f, "prospective"),
            Self::Active => write!(f, "active"),
            Self::OnHold => write!(f, "on_hold"),
            Self::Terminated => write!(f, "terminated"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataAccessLevel {
    None,
    Limited,
    Confidential,
    Restricted,
}

impl std::fmt::Display for DataAccessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Limited => write!(f, "limited"),
            Self::Confidential => write!(f, "confidential"),
            Self::Restricted => write!(f, "restricted"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vendor {
    pub id: String,
    pub vendor_id: String, // e.g., "VND-001"
    pub name: String,
    pub category: VendorCategory,
    pub tier: VendorTier,
    pub status: VendorStatus,
    pub primary_contact_name: Option<String>,
    pub primary_contact_email: Option<String>,
    pub services_provided: Option<String>,
    pub data_access_level: DataAccessLevel,
    pub data_types_accessed: Vec<String>,
    pub contract_start_date: Option<NaiveDate>,
    pub contract_end_date: Option<NaiveDate>,
    pub contract_value: Option<f64>,
    pub inherent_risk_score: Option<u8>,
    pub residual_risk_score: Option<u8>,
    pub last_assessment_date: Option<NaiveDate>,
    pub next_assessment_date: Option<NaiveDate>,
    pub soc2_report: bool,
    pub iso_27001_certified: bool,
    pub other_certifications: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorAssessment {
    pub id: String,
    pub vendor_id: String,
    pub assessment_type: AssessmentType,
    pub assessment_date: NaiveDate,
    pub assessor_id: String,
    pub questionnaire_id: Option<String>,
    pub questionnaire_score: Option<f64>,
    pub risk_areas: Vec<String>,
    pub findings: Vec<String>,
    pub recommendations: Option<String>,
    pub overall_risk_rating: RiskLevel,
    pub approval_status: VendorApprovalStatus,
    pub approval_notes: Option<String>,
    pub approved_by: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VendorApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Conditional,
}

impl std::fmt::Display for VendorApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Rejected => write!(f, "rejected"),
            Self::Conditional => write!(f, "conditional"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorQuestionnaire {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub version: String,
    pub questions: Vec<QuestionnaireQuestion>,
    pub scoring_method: ScoringMethod,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionnaireQuestion {
    pub id: String,
    pub section: String,
    pub question: String,
    pub question_type: QuestionType,
    pub options: Option<Vec<String>>,
    pub weight: f64,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuestionType {
    YesNo,
    MultipleChoice,
    Text,
    Rating,
    Upload,
}

impl std::fmt::Display for QuestionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::YesNo => write!(f, "yes_no"),
            Self::MultipleChoice => write!(f, "multiple_choice"),
            Self::Text => write!(f, "text"),
            Self::Rating => write!(f, "rating"),
            Self::Upload => write!(f, "upload"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScoringMethod {
    Weighted,
    Average,
    Custom,
}

impl std::fmt::Display for ScoringMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Weighted => write!(f, "weighted"),
            Self::Average => write!(f, "average"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionnaireResponse {
    pub id: String,
    pub vendor_id: String,
    pub questionnaire_id: String,
    pub assessment_id: Option<String>,
    pub responses: HashMap<String, serde_json::Value>,
    pub score: Option<f64>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub reviewed_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Dashboard and Reporting Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrcDashboard {
    pub policy_stats: PolicyStats,
    pub risk_stats: RiskStats,
    pub control_stats: ControlStats,
    pub audit_stats: AuditStats,
    pub vendor_stats: VendorStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStats {
    pub total_policies: u32,
    pub active_policies: u32,
    pub pending_review: u32,
    pub pending_approval: u32,
    pub exceptions_count: u32,
    pub acknowledgment_compliance: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskStats {
    pub total_risks: u32,
    pub open_risks: u32,
    pub critical_risks: u32,
    pub high_risks: u32,
    pub risks_by_category: HashMap<String, u32>,
    pub avg_risk_score: f64,
    pub total_ale: f64, // Annualized Loss Expectancy
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlStats {
    pub total_controls: u32,
    pub implemented_controls: u32,
    pub partially_implemented: u32,
    pub not_implemented: u32,
    pub effective_controls: u32,
    pub controls_due_testing: u32,
    pub framework_coverage: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    pub total_audits: u32,
    pub active_audits: u32,
    pub open_findings: u32,
    pub critical_findings: u32,
    pub high_findings: u32,
    pub overdue_remediations: u32,
    pub avg_remediation_days: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorStats {
    pub total_vendors: u32,
    pub active_vendors: u32,
    pub critical_vendors: u32,
    pub high_risk_vendors: u32,
    pub vendors_due_assessment: u32,
    pub avg_vendor_risk_score: f64,
}
