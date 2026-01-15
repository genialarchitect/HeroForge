//! OVAL Types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::scap::{LocalizedText, TargetPlatform};

/// OVAL Definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvalDefinition {
    pub id: String,
    pub version: u32,
    pub class: DefinitionClass,
    pub status: DefinitionStatus,
    pub metadata: OvalMetadata,
    pub criteria: Option<Criteria>,
    pub deprecated: bool,
}

/// Definition class
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefinitionClass {
    #[default]
    Compliance,
    Inventory,
    Patch,
    Vulnerability,
    Miscellaneous,
}

/// Definition status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefinitionStatus {
    #[default]
    Draft,
    Interim,
    Accepted,
    Deprecated,
}

/// OVAL Metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OvalMetadata {
    pub title: Option<String>,
    pub description: Option<String>,
    pub affected: Vec<AffectedPlatform>,
    pub references: Vec<OvalReference>,
}

/// Affected platform info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedPlatform {
    pub family: String,
    pub platform: Vec<String>,
    pub product: Vec<String>,
}

/// OVAL reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvalReference {
    pub source: String,
    pub ref_id: String,
    pub ref_url: Option<String>,
}

/// Criteria tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Criteria {
    pub operator: LogicalOperator,
    pub negate: bool,
    pub children: Vec<CriteriaNode>,
    pub comment: Option<String>,
}

/// Criteria node (either nested criteria or a criterion)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CriteriaNode {
    Criteria(Box<Criteria>),
    Criterion(Criterion),
    ExtendDefinition(String),
}

/// Single criterion (references a test)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Criterion {
    pub test_ref: String,
    pub negate: bool,
    pub comment: Option<String>,
}

/// Logical operator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogicalOperator {
    #[default]
    And,
    Or,
    One,
    Xor,
}

/// OVAL Test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvalTest {
    pub id: String,
    pub version: u32,
    pub comment: Option<String>,
    pub check_existence: ExistenceCheck,
    pub check: CheckEnumeration,
    pub object_ref: String,
    pub state_ref: Option<String>,
    pub state_operator: Option<LogicalOperator>,
}

/// Existence check type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExistenceCheck {
    #[default]
    AtLeastOneExists,
    AllExist,
    AnyExist,
    NoneExist,
    OnlyOneExists,
}

/// Check enumeration type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CheckEnumeration {
    #[default]
    All,
    AtLeastOne,
    NoneExist,
    NoneSatisfy,
    OnlyOne,
}

/// OVAL Object (generic wrapper)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvalObject {
    pub id: String,
    pub version: u32,
    pub object_type: ObjectType,
    pub comment: Option<String>,
    pub data: HashMap<String, serde_json::Value>,
}

/// Object type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectType {
    // Unix
    UnixFile,
    UnixPassword,
    UnixShadow,
    UnixProcess,
    UnixUname,
    UnixInterface,
    UnixSysctl,

    // Linux
    LinuxDpkgInfo,
    LinuxRpmInfo,
    LinuxPartition,
    LinuxSystemdUnit,

    // Windows
    WinRegistry,
    WinFile,
    WinWmi,
    WinService,
    WinUser,
    WinGroup,
    WinAuditEventPolicy,
    WinLockoutPolicy,
    WinPasswordPolicy,

    // Independent
    IndFamily,
    IndTextFileContent,
    IndVariable,
    IndEnvironmentVariable,
    IndSql,
    IndFileHash,
}

/// OVAL State (generic wrapper)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvalState {
    pub id: String,
    pub version: u32,
    pub state_type: ObjectType,
    pub comment: Option<String>,
    pub data: HashMap<String, StateValue>,
}

/// State value with operator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateValue {
    pub value: serde_json::Value,
    pub operation: Operation,
    pub datatype: DataType,
}

/// Comparison operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    #[default]
    Equals,
    NotEqual,
    CaseInsensitiveEquals,
    CaseInsensitiveNotEqual,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    BitwiseAnd,
    BitwiseOr,
    PatternMatch,
    SubsetOf,
    SupersetOf,
}

/// Data type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DataType {
    #[default]
    String,
    Int,
    Float,
    Boolean,
    Binary,
    EvrsString,
    Version,
    Ipv4Address,
    Ipv6Address,
}

/// OVAL Variable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvalVariable {
    pub id: String,
    pub version: u32,
    pub variable_type: VariableType,
    pub datatype: DataType,
    pub comment: Option<String>,
    pub values: Vec<serde_json::Value>,
}

/// Variable type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum VariableType {
    #[default]
    Constant,
    Local,
    External,
}

/// OVAL result type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OvalResultType {
    #[default]
    True,
    False,
    Unknown,
    Error,
    NotApplicable,
    NotEvaluated,
}

impl OvalResultType {
    pub fn negate(self) -> Self {
        match self {
            OvalResultType::True => OvalResultType::False,
            OvalResultType::False => OvalResultType::True,
            other => other,
        }
    }
}

/// Definition evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionResult {
    pub definition_id: String,
    pub result: OvalResultType,
    pub criteria_results: Option<CriteriaResult>,
    pub message: Option<String>,
    pub evaluated_at: DateTime<Utc>,
}

/// Criteria evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriteriaResult {
    pub operator: LogicalOperator,
    pub negate: bool,
    pub result: OvalResultType,
    pub children: Vec<CriteriaNodeResult>,
}

/// Criteria node result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CriteriaNodeResult {
    Criteria(Box<CriteriaResult>),
    Criterion(CriterionResult),
    ExtendDefinition(DefinitionResult),
}

/// Criterion result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriterionResult {
    pub test_ref: String,
    pub result: OvalResultType,
    pub negate: bool,
}

/// Collected item from object evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvalItem {
    pub id: u64,
    pub status: ItemStatus,
    pub item_type: ObjectType,
    pub data: HashMap<String, OvalValue>,
}

/// Item collection status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    #[default]
    Exists,
    DoesNotExist,
    Error,
    NotCollected,
}

/// OVAL value (for collected items)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OvalValue {
    String(String),
    Int(i64),
    Float(f64),
    Boolean(bool),
    Binary(Vec<u8>),
    List(Vec<OvalValue>),
}
