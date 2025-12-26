//! Architecture Review Module
//!
//! Provides STRIDE threat modeling, data flow analysis,
//! trust boundary identification, and security recommendations.

pub mod threat_model;
pub mod data_flow;
pub mod trust_boundaries;
pub mod recommendations;

use crate::yellow_team::types::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Architecture review engine
pub struct ArchitectureReviewEngine {
    /// Current review
    pub review: ArchitectureReview,
    /// Identified threats
    pub threats: Vec<ArchitectureThreat>,
    /// Recommendations
    pub recommendations: Vec<SecurityRecommendation>,
}

/// Security recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRecommendation {
    /// Recommendation ID
    pub id: String,
    /// Category
    pub category: RecommendationCategory,
    /// Priority
    pub priority: Severity,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Implementation guidance
    pub implementation: String,
    /// Related threats
    pub related_threats: Vec<String>,
}

/// Recommendation category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationCategory {
    Authentication,
    Authorization,
    Encryption,
    InputValidation,
    Logging,
    ErrorHandling,
    Configuration,
    NetworkSecurity,
    DataProtection,
    AvailabilityResilience,
}

impl ArchitectureReviewEngine {
    /// Create a new review
    pub fn new(project_name: &str, description: Option<&str>) -> Self {
        Self {
            review: ArchitectureReview {
                id: Uuid::new_v4().to_string(),
                user_id: String::new(),
                project_name: project_name.to_string(),
                description: description.map(|s| s.to_string()),
                diagram_data: None,
                status: ReviewStatus::Draft,
                threat_count: 0,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            threats: Vec::new(),
            recommendations: Vec::new(),
        }
    }

    /// Add a component to the architecture
    pub fn add_component(&mut self, component: ArchitectureComponent) {
        if let Some(ref mut diagram) = self.review.diagram_data {
            // diagram is already a serde_json::Value
            if let Some(components) = diagram.get_mut("components").and_then(|c| c.as_array_mut()) {
                components.push(serde_json::to_value(&component).unwrap_or_default());
            }
        } else {
            // Initialize diagram data
            let data = serde_json::json!({
                "components": [component],
                "data_flows": [],
                "trust_boundaries": []
            });
            self.review.diagram_data = Some(data);
        }
    }

    /// Add a data flow between components
    pub fn add_data_flow(&mut self, flow: ArchDataFlow) {
        if let Some(ref mut diagram) = self.review.diagram_data {
            // diagram is already a serde_json::Value
            if let Some(flows) = diagram.get_mut("data_flows").and_then(|f| f.as_array_mut()) {
                flows.push(serde_json::to_value(&flow).unwrap_or_default());
            }
        }
    }

    /// Perform STRIDE threat analysis
    pub fn analyze_threats(&mut self) {
        self.threats.clear();

        if let Some(ref diagram) = self.review.diagram_data {
            // diagram is already a serde_json::Value, use from_value
            if let Ok(data) = serde_json::from_value::<ArchitectureDiagram>(diagram.clone()) {
                // Analyze each component
                for component in &data.components {
                    self.analyze_component_threats(component);
                }

                // Analyze data flows
                for flow in &data.data_flows {
                    self.analyze_flow_threats(flow, &data.components);
                }

                // Analyze trust boundaries
                for boundary in &data.trust_boundaries {
                    self.analyze_boundary_threats(boundary, &data.data_flows);
                }
            }
        }
        
        self.review.threat_count = self.threats.len() as i32;
    }

    /// Analyze threats for a component
    fn analyze_component_threats(&mut self, component: &ArchitectureComponent) {
        // Spoofing threats
        if component.component_type.requires_authentication() {
            if !component.has_authentication {
                self.add_threat(
                    StrideCategory::Spoofing,
                    &component.name,
                    "Identity spoofing risk",
                    "Component lacks authentication, allowing potential identity spoofing",
                    Severity::High,
                );
            }
        }

        // Tampering threats
        if component.stores_data && !component.data_encrypted {
            self.add_threat(
                StrideCategory::Tampering,
                &component.name,
                "Data tampering risk",
                "Unencrypted data storage allows potential tampering",
                Severity::High,
            );
        }

        // Repudiation threats
        if component.is_critical && !component.has_logging {
            self.add_threat(
                StrideCategory::Repudiation,
                &component.name,
                "Repudiation risk",
                "Critical component lacks audit logging",
                Severity::Medium,
            );
        }

        // Information disclosure threats
        if component.handles_sensitive_data && !component.data_encrypted {
            self.add_threat(
                StrideCategory::InformationDisclosure,
                &component.name,
                "Information disclosure risk",
                "Sensitive data not encrypted at rest or in transit",
                Severity::Critical,
            );
        }

        // Denial of service threats
        if component.is_external_facing && !component.has_rate_limiting {
            self.add_threat(
                StrideCategory::DenialOfService,
                &component.name,
                "Denial of service risk",
                "External-facing component lacks rate limiting",
                Severity::High,
            );
        }

        // Elevation of privilege threats
        if component.has_admin_access && !component.has_rbac {
            self.add_threat(
                StrideCategory::ElevationOfPrivilege,
                &component.name,
                "Privilege escalation risk",
                "Administrative access without role-based access control",
                Severity::Critical,
            );
        }
    }

    /// Analyze threats for a data flow
    fn analyze_flow_threats(&mut self, flow: &ArchDataFlow, components: &[ArchitectureComponent]) {
        // Check if flow crosses trust boundary
        let source = components.iter().find(|c| c.id == flow.source_id);
        let target = components.iter().find(|c| c.id == flow.target_id);

        if let (Some(src), Some(tgt)) = (source, target) {
            // Different trust levels - need encryption
            if src.trust_level != tgt.trust_level && !flow.encrypted {
                self.add_threat(
                    StrideCategory::InformationDisclosure,
                    &format!("{} -> {}", src.name, tgt.name),
                    "Unencrypted cross-boundary data flow",
                    "Data flow crosses trust boundary without encryption",
                    Severity::High,
                );
            }

            // Sensitive data flow
            if flow.contains_sensitive_data && !flow.encrypted {
                self.add_threat(
                    StrideCategory::InformationDisclosure,
                    &format!("{} -> {}", src.name, tgt.name),
                    "Unencrypted sensitive data flow",
                    "Sensitive data transmitted without encryption",
                    Severity::Critical,
                );
            }

            // Input validation
            if !flow.input_validated && tgt.component_type.processes_input() {
                self.add_threat(
                    StrideCategory::Tampering,
                    &format!("{} -> {}", src.name, tgt.name),
                    "Input validation missing",
                    "Data flow lacks input validation at target",
                    Severity::High,
                );
            }
        }
    }

    /// Analyze threats at trust boundaries
    fn analyze_boundary_threats(&mut self, boundary: &ArchTrustBoundary, flows: &[ArchDataFlow]) {
        let crossing_flows: Vec<_> = flows.iter()
            .filter(|f| boundary.flows_crossing.contains(&f.id))
            .collect();

        for flow in crossing_flows {
            if !flow.authenticated {
                self.add_threat(
                    StrideCategory::Spoofing,
                    &boundary.name,
                    "Unauthenticated boundary crossing",
                    &format!("Flow crosses '{}' boundary without authentication", boundary.name),
                    Severity::High,
                );
            }
        }
    }

    /// Add a threat
    fn add_threat(
        &mut self,
        category: StrideCategory,
        component: &str,
        title: &str,
        description: &str,
        severity: Severity,
    ) {
        let threat = ArchitectureThreat {
            id: Uuid::new_v4().to_string(),
            review_id: self.review.id.clone(),
            stride_category: category,
            component: component.to_string(),
            threat_description: format!("{}: {}", title, description),
            severity,
            likelihood: RiskLevel::Medium,
            impact: match severity {
                Severity::Critical => RiskLevel::Critical,
                Severity::High => RiskLevel::High,
                Severity::Medium => RiskLevel::Medium,
                _ => RiskLevel::Low,
            },
            mitigations: Vec::new(),
            status: ThreatStatus::Open,
            created_at: Utc::now(),
        };
        
        self.threats.push(threat);
    }

    /// Generate security recommendations based on threats
    pub fn generate_recommendations(&mut self) {
        self.recommendations.clear();
        
        // Group threats by category
        let mut has_auth_threats = false;
        let mut has_encryption_threats = false;
        let mut has_logging_threats = false;
        let mut has_validation_threats = false;
        let mut has_dos_threats = false;
        
        for threat in &self.threats {
            match threat.stride_category {
                StrideCategory::Spoofing => has_auth_threats = true,
                StrideCategory::InformationDisclosure => has_encryption_threats = true,
                StrideCategory::Repudiation => has_logging_threats = true,
                StrideCategory::Tampering => has_validation_threats = true,
                StrideCategory::DenialOfService => has_dos_threats = true,
                _ => {}
            }
        }

        if has_auth_threats {
            self.recommendations.push(SecurityRecommendation {
                id: Uuid::new_v4().to_string(),
                category: RecommendationCategory::Authentication,
                priority: Severity::High,
                title: "Implement Strong Authentication".to_string(),
                description: "Multiple components lack proper authentication mechanisms".to_string(),
                implementation: "Implement OAuth 2.0/OIDC for user authentication, API keys for service-to-service, and consider MFA for sensitive operations".to_string(),
                related_threats: self.threats.iter()
                    .filter(|t| matches!(t.stride_category, StrideCategory::Spoofing))
                    .map(|t| t.id.clone())
                    .collect(),
            });
        }

        if has_encryption_threats {
            self.recommendations.push(SecurityRecommendation {
                id: Uuid::new_v4().to_string(),
                category: RecommendationCategory::Encryption,
                priority: Severity::Critical,
                title: "Enable Encryption for Data at Rest and in Transit".to_string(),
                description: "Sensitive data is not adequately protected by encryption".to_string(),
                implementation: "Use TLS 1.3 for data in transit, AES-256 for data at rest, and implement proper key management".to_string(),
                related_threats: self.threats.iter()
                    .filter(|t| matches!(t.stride_category, StrideCategory::InformationDisclosure))
                    .map(|t| t.id.clone())
                    .collect(),
            });
        }

        if has_logging_threats {
            self.recommendations.push(SecurityRecommendation {
                id: Uuid::new_v4().to_string(),
                category: RecommendationCategory::Logging,
                priority: Severity::Medium,
                title: "Implement Comprehensive Audit Logging".to_string(),
                description: "Critical operations lack proper audit trails".to_string(),
                implementation: "Log all authentication events, administrative actions, and data access. Ensure logs are tamper-evident and stored securely".to_string(),
                related_threats: self.threats.iter()
                    .filter(|t| matches!(t.stride_category, StrideCategory::Repudiation))
                    .map(|t| t.id.clone())
                    .collect(),
            });
        }

        if has_validation_threats {
            self.recommendations.push(SecurityRecommendation {
                id: Uuid::new_v4().to_string(),
                category: RecommendationCategory::InputValidation,
                priority: Severity::High,
                title: "Implement Input Validation".to_string(),
                description: "Data flows lack proper input validation".to_string(),
                implementation: "Validate all input at trust boundaries using allowlists, sanitize output, and use parameterized queries".to_string(),
                related_threats: self.threats.iter()
                    .filter(|t| matches!(t.stride_category, StrideCategory::Tampering))
                    .map(|t| t.id.clone())
                    .collect(),
            });
        }

        if has_dos_threats {
            self.recommendations.push(SecurityRecommendation {
                id: Uuid::new_v4().to_string(),
                category: RecommendationCategory::AvailabilityResilience,
                priority: Severity::High,
                title: "Implement Rate Limiting and DDoS Protection".to_string(),
                description: "External-facing components are vulnerable to denial of service".to_string(),
                implementation: "Implement rate limiting, use CDN with DDoS protection, design for graceful degradation".to_string(),
                related_threats: self.threats.iter()
                    .filter(|t| matches!(t.stride_category, StrideCategory::DenialOfService))
                    .map(|t| t.id.clone())
                    .collect(),
            });
        }
    }

    /// Get review summary
    pub fn get_summary(&self) -> ReviewSummary {
        let mut by_category: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        let mut by_severity: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        
        for threat in &self.threats {
            *by_category.entry(format!("{:?}", threat.stride_category)).or_insert(0) += 1;
            *by_severity.entry(format!("{:?}", threat.severity)).or_insert(0) += 1;
        }
        
        ReviewSummary {
            total_threats: self.threats.len() as u32,
            open_threats: self.threats.iter().filter(|t| matches!(t.status, ThreatStatus::Open)).count() as u32,
            by_category,
            by_severity,
            recommendations_count: self.recommendations.len() as u32,
        }
    }
}

/// Architecture component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchitectureComponent {
    pub id: String,
    pub name: String,
    pub component_type: ArchComponentType,
    pub trust_level: ArchTrustLevel,
    pub stores_data: bool,
    pub handles_sensitive_data: bool,
    pub data_encrypted: bool,
    pub has_authentication: bool,
    pub has_authorization: bool,
    pub has_logging: bool,
    pub has_rate_limiting: bool,
    pub has_rbac: bool,
    pub has_admin_access: bool,
    pub is_external_facing: bool,
    pub is_critical: bool,
}

/// Architecture component type (different from SBOM ComponentType)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchComponentType {
    WebApplication,
    ApiGateway,
    Microservice,
    Database,
    MessageQueue,
    Cache,
    LoadBalancer,
    FileStorage,
    IdentityProvider,
    ExternalService,
    MobileApp,
    IoTDevice,
}

impl ArchComponentType {
    pub fn requires_authentication(&self) -> bool {
        matches!(self,
            ArchComponentType::WebApplication |
            ArchComponentType::ApiGateway |
            ArchComponentType::Microservice |
            ArchComponentType::MobileApp
        )
    }

    pub fn processes_input(&self) -> bool {
        matches!(self,
            ArchComponentType::WebApplication |
            ArchComponentType::ApiGateway |
            ArchComponentType::Microservice |
            ArchComponentType::Database
        )
    }
}

/// Architecture trust level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchTrustLevel {
    External,
    Dmz,
    Internal,
    Trusted,
    HighlyTrusted,
}

/// Architecture data flow between components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchDataFlow {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub data_type: String,
    pub protocol: String,
    pub encrypted: bool,
    pub authenticated: bool,
    pub contains_sensitive_data: bool,
    pub input_validated: bool,
}

/// Architecture trust boundary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchTrustBoundary {
    pub id: String,
    pub name: String,
    pub boundary_type: ArchBoundaryType,
    pub components_inside: Vec<String>,
    pub flows_crossing: Vec<String>,
}

/// Architecture boundary type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchBoundaryType {
    Network,
    Process,
    Machine,
    Container,
    Zone,
}

/// Architecture diagram data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchitectureDiagram {
    pub components: Vec<ArchitectureComponent>,
    pub data_flows: Vec<ArchDataFlow>,
    pub trust_boundaries: Vec<ArchTrustBoundary>,
}

/// Review summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSummary {
    pub total_threats: u32,
    pub open_threats: u32,
    pub by_category: std::collections::HashMap<String, u32>,
    pub by_severity: std::collections::HashMap<String, u32>,
    pub recommendations_count: u32,
}

/// STRIDE analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrideAnalysisResult {
    /// Review ID
    pub review_id: String,
    /// List of identified threats
    pub threats: Vec<ArchitectureThreat>,
    /// Threats grouped by STRIDE category
    pub threats_by_category: std::collections::HashMap<String, u32>,
    /// Threats grouped by risk level (critical, high, medium, low)
    pub threats_by_risk: std::collections::HashMap<String, u32>,
    /// Generated recommendations
    pub recommendations: Vec<SecurityRecommendation>,
    /// Overall risk score (0-100, higher is riskier)
    pub risk_score: f64,
    /// Analysis timestamp
    pub analyzed_at: chrono::DateTime<Utc>,
}

impl StrideAnalysisResult {
    /// Create a new STRIDE analysis result from an engine
    pub fn from_engine(engine: &ArchitectureReviewEngine) -> Self {
        let mut threats_by_category = std::collections::HashMap::new();
        let mut threats_by_risk = std::collections::HashMap::new();

        for threat in &engine.threats {
            let category_key = format!("{:?}", threat.stride_category).to_lowercase();
            *threats_by_category.entry(category_key).or_insert(0) += 1;

            let risk_key = format!("{:?}", threat.severity).to_lowercase();
            *threats_by_risk.entry(risk_key).or_insert(0) += 1;
        }

        Self {
            review_id: engine.review.id.clone(),
            threats: engine.threats.clone(),
            threats_by_category,
            threats_by_risk,
            recommendations: engine.recommendations.clone(),
            risk_score: 0.0, // Will be calculated by caller
            analyzed_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_review() {
        let engine = ArchitectureReviewEngine::new("Test Project", Some("Test description"));
        assert_eq!(engine.review.project_name, "Test Project");
        assert!(engine.threats.is_empty());
    }

    #[test]
    fn test_add_component() {
        let mut engine = ArchitectureReviewEngine::new("Test", None);
        engine.add_component(ArchitectureComponent {
            id: "1".to_string(),
            name: "Web App".to_string(),
            component_type: ArchComponentType::WebApplication,
            trust_level: ArchTrustLevel::External,
            stores_data: false,
            handles_sensitive_data: false,
            data_encrypted: false,
            has_authentication: false,
            has_authorization: false,
            has_logging: false,
            has_rate_limiting: false,
            has_rbac: false,
            has_admin_access: false,
            is_external_facing: true,
            is_critical: true,
        });

        assert!(engine.review.diagram_data.is_some());
    }
}
