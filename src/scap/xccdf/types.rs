//! XCCDF Types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::scap::{LocalizedText, Reference, Ident, ScapSeverity, cpe::CpePlatform};

/// XCCDF Benchmark - top-level container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XccdfBenchmark {
    pub id: String,
    pub version: String,
    pub status: Vec<BenchmarkStatus>,
    pub title: LocalizedText,
    pub description: Option<LocalizedText>,
    pub platform: Vec<CpePlatform>,
    pub profiles: Vec<XccdfProfile>,
    pub groups: Vec<XccdfGroup>,
    pub rules: Vec<XccdfRule>,
    pub values: Vec<XccdfValue>,
    pub metadata: BenchmarkMetadata,
    pub scoring: ScoringModel,
}

impl Default for XccdfBenchmark {
    fn default() -> Self {
        Self {
            id: String::new(),
            version: "1.0".to_string(),
            status: Vec::new(),
            title: LocalizedText::default(),
            description: None,
            platform: Vec::new(),
            profiles: Vec::new(),
            groups: Vec::new(),
            rules: Vec::new(),
            values: Vec::new(),
            metadata: BenchmarkMetadata::default(),
            scoring: ScoringModel::Default,
        }
    }
}

/// Summary of a benchmark for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XccdfBenchmarkSummary {
    pub id: String,
    pub title: String,
    pub version: String,
    pub profile_count: usize,
    pub rule_count: usize,
    pub platform: Vec<String>,
}

/// Benchmark status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkStatus {
    pub status: StatusType,
    pub date: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatusType {
    Draft,
    Interim,
    Accepted,
    Deprecated,
    Incomplete,
}

/// Benchmark metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchmarkMetadata {
    pub publisher: Option<String>,
    pub creator: Option<String>,
    pub contributor: Vec<String>,
    pub source: Option<String>,
}

/// Scoring model for benchmark
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScoringModel {
    #[default]
    Default,
    Flat,
    FlatUnweighted,
    Absolute,
}

/// XCCDF Profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XccdfProfile {
    pub id: String,
    pub title: LocalizedText,
    pub description: Option<LocalizedText>,
    pub extends: Option<String>,
    pub selects: Vec<ProfileSelect>,
    pub set_values: Vec<ProfileSetValue>,
    pub refine_values: Vec<RefineValue>,
    pub refine_rules: Vec<RefineRule>,
}

/// Profile rule selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSelect {
    pub id_ref: String,
    pub selected: bool,
}

/// Profile value setting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSetValue {
    pub id_ref: String,
    pub value: String,
}

/// Value refinement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefineValue {
    pub id_ref: String,
    pub selector: Option<String>,
    pub operator: Option<String>,
}

/// Rule refinement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefineRule {
    pub id_ref: String,
    pub weight: Option<f64>,
    pub severity: Option<ScapSeverity>,
    pub role: Option<RuleRole>,
}

/// XCCDF Group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XccdfGroup {
    pub id: String,
    pub title: LocalizedText,
    pub description: Option<LocalizedText>,
    pub rules: Vec<String>,
    pub groups: Vec<XccdfGroup>,
}

/// XCCDF Rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XccdfRule {
    pub id: String,
    pub version: String,
    pub severity: ScapSeverity,
    pub weight: f64,
    pub role: RuleRole,
    pub title: LocalizedText,
    pub description: Option<LocalizedText>,
    pub rationale: Option<LocalizedText>,
    pub idents: Vec<Ident>,
    pub fixtext: Option<Fixtext>,
    pub fix: Vec<Fix>,
    pub checks: Vec<XccdfCheck>,
    pub requires: Vec<String>,
    pub conflicts: Vec<String>,
    pub platform: Vec<CpePlatform>,
    pub references: Vec<Reference>,
}

impl Default for XccdfRule {
    fn default() -> Self {
        Self {
            id: String::new(),
            version: "1".to_string(),
            severity: ScapSeverity::Medium,
            weight: 1.0,
            role: RuleRole::Full,
            title: LocalizedText::default(),
            description: None,
            rationale: None,
            idents: Vec::new(),
            fixtext: None,
            fix: Vec::new(),
            checks: Vec::new(),
            requires: Vec::new(),
            conflicts: Vec::new(),
            platform: Vec::new(),
            references: Vec::new(),
        }
    }
}

/// Rule role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleRole {
    #[default]
    Full,
    Unscored,
    Unchecked,
}

/// Fix text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fixtext {
    pub text: String,
    pub fixref: Option<String>,
    pub reboot: bool,
    pub strategy: Option<String>,
    pub disruption: Option<String>,
    pub complexity: Option<String>,
}

/// Fix script
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fix {
    pub id: Option<String>,
    pub content: String,
    pub system: Option<String>,
    pub platform: Option<String>,
    pub reboot: bool,
    pub strategy: Option<String>,
    pub disruption: Option<String>,
    pub complexity: Option<String>,
}

/// XCCDF Check reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XccdfCheck {
    pub system: CheckSystem,
    pub content_ref: Option<String>,
    pub check_content_ref: Option<String>,
    pub check_exports: Vec<CheckExport>,
    pub check_imports: Vec<CheckImport>,
    pub multi_check: bool,
}

/// Check system type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CheckSystem {
    #[default]
    Oval,
    Ocil,
    Sce,
    Custom(String),
}

/// Check export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckExport {
    pub value_id: String,
    pub export_name: String,
}

/// Check import
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckImport {
    pub import_name: String,
    pub import_xpath: Option<String>,
}

/// XCCDF Value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XccdfValue {
    pub id: String,
    pub value_type: ValueType,
    pub title: LocalizedText,
    pub description: Option<LocalizedText>,
    pub value: String,
    pub default_value: Option<String>,
    pub choices: Vec<ValueChoice>,
    pub lower_bound: Option<String>,
    pub upper_bound: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ValueType {
    #[default]
    String,
    Number,
    Boolean,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueChoice {
    pub selector: Option<String>,
    pub value: String,
}

/// Rule evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResult {
    pub rule_id: String,
    pub result: XccdfResultType,
    pub severity: ScapSeverity,
    pub time: DateTime<Utc>,
    pub version: String,
    pub weight: f64,
    pub check_results: Vec<CheckResult>,
    pub idents: Vec<Ident>,
    pub fix: Option<Fix>,
    pub message: Option<String>,
    pub instance: Option<String>,
}

/// Check evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub system: CheckSystem,
    pub definition_id: String,
    pub result: XccdfResultType,
    pub message: Option<String>,
}

/// XCCDF result types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum XccdfResultType {
    #[default]
    Pass,
    Fail,
    Error,
    Unknown,
    NotApplicable,
    NotChecked,
    NotSelected,
    Informational,
    Fixed,
}

impl XccdfResultType {
    pub fn is_pass(&self) -> bool {
        matches!(self, XccdfResultType::Pass | XccdfResultType::Fixed)
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, XccdfResultType::Fail)
    }
}

impl std::fmt::Display for XccdfResultType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XccdfResultType::Pass => write!(f, "pass"),
            XccdfResultType::Fail => write!(f, "fail"),
            XccdfResultType::Error => write!(f, "error"),
            XccdfResultType::Unknown => write!(f, "unknown"),
            XccdfResultType::NotApplicable => write!(f, "notapplicable"),
            XccdfResultType::NotChecked => write!(f, "notchecked"),
            XccdfResultType::NotSelected => write!(f, "notselected"),
            XccdfResultType::Informational => write!(f, "informational"),
            XccdfResultType::Fixed => write!(f, "fixed"),
        }
    }
}
