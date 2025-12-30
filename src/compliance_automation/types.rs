//! Type definitions for compliance automation

use serde::{Deserialize, Serialize};

/// Trust Services Criteria categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustServicesCriteria {
    Security,      // CC6
    Availability,  // A1
    ProcessingIntegrity, // PI1
    Confidentiality,     // C1
    Privacy,       // P1
}

/// ISO 27001 control domain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Iso27001Domain {
    InformationSecurityPolicies,
    OrganizationOfInformationSecurity,
    HumanResourceSecurity,
    AssetManagement,
    AccessControl,
    Cryptography,
    PhysicalAndEnvironmentalSecurity,
    OperationsSecurity,
    CommunicationsSecurity,
    SystemAcquisitionDevelopmentAndMaintenance,
    SupplierRelationships,
    InformationSecurityIncidentManagement,
    InformationSecurityAspectsOfBusinessContinuityManagement,
    Compliance,
}

/// FedRAMP baseline level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FedRampBaseline {
    Low,
    Moderate,
    High,
}

/// Control implementation status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlImplementation {
    pub control_id: String,
    pub control_name: String,
    pub implementation_status: ImplementationStatus,
    pub effectiveness: ControlEffectiveness,
    pub evidence_ids: Vec<String>,
    pub last_tested: Option<chrono::DateTime<chrono::Utc>>,
    pub next_test_date: Option<chrono::DateTime<chrono::Utc>>,
}

/// Implementation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImplementationStatus {
    Implemented,
    PartiallyImplemented,
    PlannedForImplementation,
    AlternativeImplementation,
    NotApplicable,
}

/// Control effectiveness
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlEffectiveness {
    Effective,
    PartiallyEffective,
    Ineffective,
    NotTested,
}
