//! Data Loss Prevention (DLP) engine (Sprint 8)

use serde::{Serialize, Deserialize};
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DLPPolicy {
    pub id: String,
    pub name: String,
    pub patterns: Vec<DataPattern>,
    pub action: PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPattern {
    pub pattern_type: PatternType,
    pub regex: String,
    pub sensitivity: Sensitivity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    CreditCard,
    SSN,
    Email,
    APIKey,
    Password,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Sensitivity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    Block,
    Warn,
    Log,
    Encrypt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DLPViolation {
    pub id: String,
    pub policy_id: String,
    pub user_id: String,
    pub pattern_matched: String,
    pub action_taken: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub async fn scan_content(content: &str, policies: &[DLPPolicy]) -> Vec<DLPViolation> {
    // TODO: Scan content against DLP policies
    Vec::new()
}

pub fn get_default_patterns() -> Vec<DataPattern> {
    vec![
        DataPattern {
            pattern_type: PatternType::CreditCard,
            regex: r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b".to_string(),
            sensitivity: Sensitivity::Critical,
        },
        DataPattern {
            pattern_type: PatternType::SSN,
            regex: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
            sensitivity: Sensitivity::Critical,
        },
        DataPattern {
            pattern_type: PatternType::Email,
            regex: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b".to_string(),
            sensitivity: Sensitivity::Medium,
        },
    ]
}
