//! Security Recommendations Engine

use crate::yellow_team::types::*;
use serde::{Deserialize, Serialize};

/// Generate recommendations based on analysis
pub fn generate_recommendations(
    threats: &[ArchitectureThreat],
    components: &[super::ArchitectureComponent],
) -> Vec<Recommendation> {
    let mut recommendations = Vec::new();

    // Authentication recommendations
    let auth_threats: Vec<_> = threats.iter()
        .filter(|t| matches!(t.stride_category, StrideCategory::Spoofing))
        .collect();
    
    if !auth_threats.is_empty() {
        recommendations.push(Recommendation {
            id: "REC-AUTH-001".to_string(),
            title: "Strengthen Authentication".to_string(),
            priority: Priority::High,
            effort: Effort::Medium,
            category: "Authentication".to_string(),
            description: "Implement multi-factor authentication for all user-facing components".to_string(),
            implementation_steps: vec![
                "Evaluate MFA solutions (TOTP, WebAuthn, SMS)".to_string(),
                "Implement MFA for admin accounts first".to_string(),
                "Roll out to all users".to_string(),
                "Configure fallback/recovery options".to_string(),
            ],
            related_threats: auth_threats.iter().map(|t| t.id.clone()).collect(),
        });
    }

    // Encryption recommendations
    let info_disclosure_threats: Vec<_> = threats.iter()
        .filter(|t| matches!(t.stride_category, StrideCategory::InformationDisclosure))
        .collect();
    
    if !info_disclosure_threats.is_empty() {
        recommendations.push(Recommendation {
            id: "REC-CRYPTO-001".to_string(),
            title: "Implement End-to-End Encryption".to_string(),
            priority: Priority::Critical,
            effort: Effort::High,
            category: "Cryptography".to_string(),
            description: "Encrypt all sensitive data at rest and in transit".to_string(),
            implementation_steps: vec![
                "Inventory all sensitive data flows".to_string(),
                "Implement TLS 1.3 for all communications".to_string(),
                "Enable encryption at rest for databases".to_string(),
                "Implement key management solution".to_string(),
            ],
            related_threats: info_disclosure_threats.iter().map(|t| t.id.clone()).collect(),
        });
    }

    // Rate limiting recommendations
    let dos_threats: Vec<_> = threats.iter()
        .filter(|t| matches!(t.stride_category, StrideCategory::DenialOfService))
        .collect();
    
    if !dos_threats.is_empty() {
        recommendations.push(Recommendation {
            id: "REC-AVAIL-001".to_string(),
            title: "Implement Rate Limiting".to_string(),
            priority: Priority::High,
            effort: Effort::Low,
            category: "Availability".to_string(),
            description: "Add rate limiting to all external-facing endpoints".to_string(),
            implementation_steps: vec![
                "Identify external-facing endpoints".to_string(),
                "Define rate limits per endpoint".to_string(),
                "Implement rate limiting middleware".to_string(),
                "Add monitoring and alerting".to_string(),
            ],
            related_threats: dos_threats.iter().map(|t| t.id.clone()).collect(),
        });
    }

    // RBAC recommendations
    let privesc_threats: Vec<_> = threats.iter()
        .filter(|t| matches!(t.stride_category, StrideCategory::ElevationOfPrivilege))
        .collect();
    
    if !privesc_threats.is_empty() {
        recommendations.push(Recommendation {
            id: "REC-AUTHZ-001".to_string(),
            title: "Implement Role-Based Access Control".to_string(),
            priority: Priority::Critical,
            effort: Effort::High,
            category: "Authorization".to_string(),
            description: "Implement fine-grained RBAC across all components".to_string(),
            implementation_steps: vec![
                "Define roles and permissions matrix".to_string(),
                "Implement centralized authorization service".to_string(),
                "Apply principle of least privilege".to_string(),
                "Regular access reviews".to_string(),
            ],
            related_threats: privesc_threats.iter().map(|t| t.id.clone()).collect(),
        });
    }

    recommendations
}

/// Security recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: String,
    pub title: String,
    pub priority: Priority,
    pub effort: Effort,
    pub category: String,
    pub description: String,
    pub implementation_steps: Vec<String>,
    pub related_threats: Vec<String>,
}

/// Priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

/// Implementation effort
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effort {
    Low,
    Medium,
    High,
}
