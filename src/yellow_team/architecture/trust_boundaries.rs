//! Trust Boundary Analysis

use serde::{Deserialize, Serialize};

/// Trust boundary analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBoundaryAnalysis {
    /// Identified boundaries
    pub boundaries: Vec<IdentifiedBoundary>,
    /// Boundary crossings
    pub crossings: Vec<BoundaryCrossing>,
    /// Issues found
    pub issues: Vec<BoundaryIssue>,
}

/// Identified trust boundary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifiedBoundary {
    pub id: String,
    pub name: String,
    pub trust_level_inside: u8,
    pub trust_level_outside: u8,
    pub boundary_type: BoundaryKind,
}

/// Kind of boundary
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryKind {
    NetworkPerimeter,
    ProcessIsolation,
    ContainerBoundary,
    VmBoundary,
    CloudVpc,
    TrustZone,
}

/// Crossing of a trust boundary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundaryCrossing {
    pub boundary_id: String,
    pub flow_id: String,
    pub direction: CrossingDirection,
    pub authenticated: bool,
    pub encrypted: bool,
    pub validated: bool,
}

/// Direction of boundary crossing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossingDirection {
    Inbound,
    Outbound,
    Bidirectional,
}

/// Boundary issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundaryIssue {
    pub boundary_id: String,
    pub crossing_id: Option<String>,
    pub issue_type: BoundaryIssueType,
    pub description: String,
    pub recommendation: String,
}

/// Type of boundary issue
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryIssueType {
    UnauthenticatedCrossing,
    UnencryptedCrossing,
    NoInputValidation,
    ExcessivePermissions,
    MissingBoundary,
}

/// Analyze trust boundaries
pub fn analyze_boundaries(
    boundaries: &[IdentifiedBoundary],
    crossings: &[BoundaryCrossing],
) -> TrustBoundaryAnalysis {
    let mut analysis = TrustBoundaryAnalysis {
        boundaries: boundaries.to_vec(),
        crossings: crossings.to_vec(),
        issues: Vec::new(),
    };

    for crossing in crossings {
        // Check for unauthenticated crossings
        if !crossing.authenticated {
            analysis.issues.push(BoundaryIssue {
                boundary_id: crossing.boundary_id.clone(),
                crossing_id: Some(crossing.flow_id.clone()),
                issue_type: BoundaryIssueType::UnauthenticatedCrossing,
                description: "Data crosses trust boundary without authentication".to_string(),
                recommendation: "Implement authentication at the boundary".to_string(),
            });
        }

        // Check for unencrypted crossings
        if !crossing.encrypted {
            analysis.issues.push(BoundaryIssue {
                boundary_id: crossing.boundary_id.clone(),
                crossing_id: Some(crossing.flow_id.clone()),
                issue_type: BoundaryIssueType::UnencryptedCrossing,
                description: "Data crosses trust boundary without encryption".to_string(),
                recommendation: "Use TLS or application-level encryption".to_string(),
            });
        }

        // Check for missing input validation
        if !crossing.validated && matches!(crossing.direction, CrossingDirection::Inbound) {
            analysis.issues.push(BoundaryIssue {
                boundary_id: crossing.boundary_id.clone(),
                crossing_id: Some(crossing.flow_id.clone()),
                issue_type: BoundaryIssueType::NoInputValidation,
                description: "Inbound data not validated at trust boundary".to_string(),
                recommendation: "Validate all input at trust boundaries".to_string(),
            });
        }
    }

    analysis
}
