//! Sigma Rule Support for HeroForge SIEM
//!
//! This module provides parsing, validation, and execution of Sigma rules,
//! the open standard for log detection rules.
//!
//! # Features
//! - Parse Sigma YAML rules (detection logic, logsource, level, tags)
//! - Convert Sigma to internal query format
//! - Rule validation and testing
//! - Built-in Sigma rule library (10+ common rules)
//!
//! # Example
//! ```rust,ignore
//! use heroforge::siem::sigma::{SigmaParser, SigmaRule};
//!
//! let yaml = r#"
//! title: Windows Logon Failure
//! logsource:
//!     product: windows
//!     service: security
//! detection:
//!     selection:
//!         EventID: 4625
//!     condition: selection
//! level: medium
//! "#;
//!
//! let rule = SigmaParser::parse(yaml)?;
//! let matches = rule.evaluate(&log_entry)?;
//! ```

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::types::{LogEntry, SiemSeverity};

// ============================================================================
// Sigma Rule Types
// ============================================================================

/// A parsed Sigma rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    /// Unique identifier
    pub id: String,
    /// Rule title
    pub title: String,
    /// Rule description
    pub description: Option<String>,
    /// Author of the rule
    pub author: Option<String>,
    /// Log source specification
    pub logsource: LogSource,
    /// Detection logic
    pub detection: Detection,
    /// Severity level (informational, low, medium, high, critical)
    pub level: SigmaSeverity,
    /// Rule status (stable, test, experimental)
    pub status: SigmaStatus,
    /// Tags (e.g., attack.t1110)
    pub tags: Vec<String>,
    /// References (URLs, CVE IDs)
    pub references: Vec<String>,
    /// False positive descriptions
    pub falsepositives: Vec<String>,
    /// Creation date
    pub date: Option<String>,
    /// Last modification date
    pub modified: Option<String>,
    /// MITRE ATT&CK relation
    pub related: Vec<RelatedRule>,
    /// Custom fields
    pub custom_fields: HashMap<String, serde_yaml::Value>,
}

/// Log source specification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogSource {
    /// Product (e.g., windows, linux, apache)
    pub product: Option<String>,
    /// Service (e.g., security, sysmon, auth)
    pub service: Option<String>,
    /// Category (e.g., process_creation, network_connection)
    pub category: Option<String>,
    /// Definition (custom log source definition)
    pub definition: Option<String>,
}

/// Detection block with selections and condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Named selections (detection patterns)
    pub selections: HashMap<String, SelectionBlock>,
    /// Condition combining selections (e.g., "selection1 or selection2")
    pub condition: String,
    /// Time-based aggregation
    pub timeframe: Option<String>,
}

/// A selection block containing field matches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SelectionBlock {
    /// Simple field-value pairs
    Simple(HashMap<String, FieldValue>),
    /// List of field-value sets (OR between sets)
    List(Vec<HashMap<String, FieldValue>>),
}

/// Field value in a selection (can be a single value, list, or pattern)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    List(Vec<String>),
    Null,
}

/// Sigma severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigmaSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl SigmaSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "informational" | "info" => Self::Informational,
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" | "crit" => Self::Critical,
            _ => Self::Medium,
        }
    }

    /// Convert to SIEM severity
    pub fn to_siem_severity(&self) -> SiemSeverity {
        match self {
            Self::Informational => SiemSeverity::Info,
            Self::Low => SiemSeverity::Notice,
            Self::Medium => SiemSeverity::Warning,
            Self::High => SiemSeverity::Error,
            Self::Critical => SiemSeverity::Critical,
        }
    }
}

impl Default for SigmaSeverity {
    fn default() -> Self {
        Self::Medium
    }
}

/// Sigma rule status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigmaStatus {
    Stable,
    Test,
    Experimental,
    Deprecated,
    Unsupported,
}

impl SigmaStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Test => "test",
            Self::Experimental => "experimental",
            Self::Deprecated => "deprecated",
            Self::Unsupported => "unsupported",
        }
    }
}

impl Default for SigmaStatus {
    fn default() -> Self {
        Self::Experimental
    }
}

/// Related rule reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedRule {
    pub id: String,
    pub relation_type: String,
}

// ============================================================================
// Sigma Parser
// ============================================================================

/// Parser for Sigma YAML rules
pub struct SigmaParser;

impl SigmaParser {
    /// Parse a Sigma rule from YAML string
    pub fn parse(yaml: &str) -> Result<SigmaRule> {
        let doc: serde_yaml::Value = serde_yaml::from_str(yaml)?;

        let obj = doc.as_mapping()
            .ok_or_else(|| anyhow!("Invalid Sigma rule: root must be a mapping"))?;

        // Parse required fields
        let title = obj.get(&serde_yaml::Value::String("title".into()))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing required field: title"))?
            .to_string();

        // Parse optional fields
        let id = obj.get(&serde_yaml::Value::String("id".into()))
            .and_then(|v| v.as_str())
            .unwrap_or(&uuid::Uuid::new_v4().to_string())
            .to_string();

        let description = obj.get(&serde_yaml::Value::String("description".into()))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let author = obj.get(&serde_yaml::Value::String("author".into()))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Parse logsource
        let logsource = Self::parse_logsource(
            obj.get(&serde_yaml::Value::String("logsource".into()))
        )?;

        // Parse detection
        let detection = Self::parse_detection(
            obj.get(&serde_yaml::Value::String("detection".into()))
        )?;

        // Parse level
        let level = obj.get(&serde_yaml::Value::String("level".into()))
            .and_then(|v| v.as_str())
            .map(SigmaSeverity::from_str)
            .unwrap_or_default();

        // Parse status
        let status = obj.get(&serde_yaml::Value::String("status".into()))
            .and_then(|v| v.as_str())
            .map(|s| match s {
                "stable" => SigmaStatus::Stable,
                "test" => SigmaStatus::Test,
                "deprecated" => SigmaStatus::Deprecated,
                "unsupported" => SigmaStatus::Unsupported,
                _ => SigmaStatus::Experimental,
            })
            .unwrap_or_default();

        // Parse tags
        let tags = Self::parse_string_list(
            obj.get(&serde_yaml::Value::String("tags".into()))
        );

        // Parse references
        let references = Self::parse_string_list(
            obj.get(&serde_yaml::Value::String("references".into()))
        );

        // Parse false positives
        let falsepositives = Self::parse_string_list(
            obj.get(&serde_yaml::Value::String("falsepositives".into()))
        );

        // Parse dates
        let date = obj.get(&serde_yaml::Value::String("date".into()))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let modified = obj.get(&serde_yaml::Value::String("modified".into()))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Parse related rules
        let related = Self::parse_related(
            obj.get(&serde_yaml::Value::String("related".into()))
        );

        Ok(SigmaRule {
            id,
            title,
            description,
            author,
            logsource,
            detection,
            level,
            status,
            tags,
            references,
            falsepositives,
            date,
            modified,
            related,
            custom_fields: HashMap::new(),
        })
    }

    fn parse_logsource(value: Option<&serde_yaml::Value>) -> Result<LogSource> {
        let Some(v) = value else {
            return Ok(LogSource::default());
        };

        let obj = v.as_mapping()
            .ok_or_else(|| anyhow!("Invalid logsource: must be a mapping"))?;

        Ok(LogSource {
            product: obj.get(&serde_yaml::Value::String("product".into()))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            service: obj.get(&serde_yaml::Value::String("service".into()))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            category: obj.get(&serde_yaml::Value::String("category".into()))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            definition: obj.get(&serde_yaml::Value::String("definition".into()))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        })
    }

    fn parse_detection(value: Option<&serde_yaml::Value>) -> Result<Detection> {
        let v = value.ok_or_else(|| anyhow!("Missing required field: detection"))?;
        let obj = v.as_mapping()
            .ok_or_else(|| anyhow!("Invalid detection: must be a mapping"))?;

        let condition = obj.get(&serde_yaml::Value::String("condition".into()))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing required field: detection.condition"))?
            .to_string();

        let timeframe = obj.get(&serde_yaml::Value::String("timeframe".into()))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Parse selections (everything except condition and timeframe)
        let mut selections = HashMap::new();
        for (key, value) in obj {
            let key_str = key.as_str().unwrap_or_default();
            if key_str != "condition" && key_str != "timeframe" {
                let selection = Self::parse_selection_block(value)?;
                selections.insert(key_str.to_string(), selection);
            }
        }

        Ok(Detection {
            selections,
            condition,
            timeframe,
        })
    }

    fn parse_selection_block(value: &serde_yaml::Value) -> Result<SelectionBlock> {
        if let Some(seq) = value.as_sequence() {
            // List of field-value sets
            let mut list = Vec::new();
            for item in seq {
                if let Some(mapping) = item.as_mapping() {
                    let mut fields = HashMap::new();
                    for (k, v) in mapping {
                        if let Some(key) = k.as_str() {
                            fields.insert(key.to_string(), Self::parse_field_value(v));
                        }
                    }
                    list.push(fields);
                }
            }
            Ok(SelectionBlock::List(list))
        } else if let Some(mapping) = value.as_mapping() {
            // Simple field-value pairs
            let mut fields = HashMap::new();
            for (k, v) in mapping {
                if let Some(key) = k.as_str() {
                    fields.insert(key.to_string(), Self::parse_field_value(v));
                }
            }
            Ok(SelectionBlock::Simple(fields))
        } else {
            Err(anyhow!("Invalid selection block"))
        }
    }

    fn parse_field_value(value: &serde_yaml::Value) -> FieldValue {
        match value {
            serde_yaml::Value::String(s) => FieldValue::String(s.clone()),
            serde_yaml::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    FieldValue::Integer(i)
                } else {
                    FieldValue::String(n.to_string())
                }
            }
            serde_yaml::Value::Bool(b) => FieldValue::Boolean(*b),
            serde_yaml::Value::Sequence(seq) => {
                let list: Vec<String> = seq.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                FieldValue::List(list)
            }
            serde_yaml::Value::Null => FieldValue::Null,
            _ => FieldValue::String(format!("{:?}", value)),
        }
    }

    fn parse_string_list(value: Option<&serde_yaml::Value>) -> Vec<String> {
        let Some(v) = value else { return Vec::new() };

        if let Some(seq) = v.as_sequence() {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        } else if let Some(s) = v.as_str() {
            vec![s.to_string()]
        } else {
            Vec::new()
        }
    }

    fn parse_related(value: Option<&serde_yaml::Value>) -> Vec<RelatedRule> {
        let Some(v) = value else { return Vec::new() };
        let Some(seq) = v.as_sequence() else { return Vec::new() };

        seq.iter()
            .filter_map(|item| {
                let mapping = item.as_mapping()?;
                let id = mapping.get(&serde_yaml::Value::String("id".into()))
                    ?.as_str()?.to_string();
                let relation_type = mapping.get(&serde_yaml::Value::String("type".into()))
                    ?.as_str()?.to_string();
                Some(RelatedRule { id, relation_type })
            })
            .collect()
    }
}

// ============================================================================
// Compiled Sigma Rule (for efficient matching)
// ============================================================================

/// A compiled Sigma rule for efficient log matching
#[derive(Debug, Clone)]
pub struct CompiledSigmaRule {
    pub rule: SigmaRule,
    /// Compiled matchers for each selection
    pub matchers: HashMap<String, Vec<FieldMatcher>>,
    /// Parsed condition AST
    pub condition_ast: ConditionNode,
}

/// Field matcher for efficient log evaluation
#[derive(Debug, Clone)]
pub struct FieldMatcher {
    pub field: String,
    pub match_type: MatchType,
    pub modifier: FieldModifier,
}

/// Type of match to perform
#[derive(Debug, Clone)]
pub enum MatchType {
    Exact(String),
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    Regex(Regex),
    Integer(i64),
    Boolean(bool),
    List(Vec<String>),
    All(Vec<String>),
    Null,
}

/// Field modifiers that affect matching
#[derive(Debug, Clone, Default)]
pub struct FieldModifier {
    pub contains: bool,
    pub all: bool,
    pub starts_with: bool,
    pub ends_with: bool,
    pub base64: bool,
    pub re: bool,
    pub cidr: bool,
    pub case_insensitive: bool,
}

/// Condition AST node
#[derive(Debug, Clone)]
pub enum ConditionNode {
    Selection(String),
    Not(Box<ConditionNode>),
    And(Vec<ConditionNode>),
    Or(Vec<ConditionNode>),
    OneOf(String),  // 1 of selection*
    AllOf(String),  // all of selection*
}

impl CompiledSigmaRule {
    /// Compile a parsed Sigma rule
    pub fn compile(rule: SigmaRule) -> Result<Self> {
        let mut matchers = HashMap::new();

        for (name, selection) in &rule.detection.selections {
            let selection_matchers = Self::compile_selection(name, selection)?;
            matchers.insert(name.clone(), selection_matchers);
        }

        let condition_ast = Self::parse_condition(&rule.detection.condition, &matchers)?;

        Ok(Self {
            rule,
            matchers,
            condition_ast,
        })
    }

    fn compile_selection(name: &str, selection: &SelectionBlock) -> Result<Vec<FieldMatcher>> {
        let mut matchers = Vec::new();

        match selection {
            SelectionBlock::Simple(fields) => {
                for (field, value) in fields {
                    let (field_name, modifier) = Self::parse_field_name(field);
                    let match_type = Self::value_to_match_type(value, &modifier)?;
                    matchers.push(FieldMatcher {
                        field: field_name,
                        match_type,
                        modifier,
                    });
                }
            }
            SelectionBlock::List(list) => {
                // For lists, we need to match any of the sets
                for fields in list {
                    for (field, value) in fields {
                        let (field_name, modifier) = Self::parse_field_name(field);
                        let match_type = Self::value_to_match_type(value, &modifier)?;
                        matchers.push(FieldMatcher {
                            field: field_name,
                            match_type,
                            modifier,
                        });
                    }
                }
            }
        }

        if matchers.is_empty() {
            log::warn!("Selection '{}' has no matchers", name);
        }

        Ok(matchers)
    }

    fn parse_field_name(field: &str) -> (String, FieldModifier) {
        let mut modifier = FieldModifier::default();
        let mut name = field.to_string();

        // Check for modifiers (field|modifier)
        if let Some(pos) = field.find('|') {
            name = field[..pos].to_string();
            let mods = &field[pos + 1..];

            for m in mods.split('|') {
                match m {
                    "contains" => modifier.contains = true,
                    "all" => modifier.all = true,
                    "startswith" => modifier.starts_with = true,
                    "endswith" => modifier.ends_with = true,
                    "base64" | "base64offset" => modifier.base64 = true,
                    "re" => modifier.re = true,
                    "cidr" => modifier.cidr = true,
                    "i" | "ignorecase" => modifier.case_insensitive = true,
                    _ => {}
                }
            }
        }

        (name, modifier)
    }

    fn value_to_match_type(value: &FieldValue, modifier: &FieldModifier) -> Result<MatchType> {
        match value {
            FieldValue::String(s) => {
                if modifier.re {
                    let regex = Regex::new(s)?;
                    Ok(MatchType::Regex(regex))
                } else if modifier.contains {
                    Ok(MatchType::Contains(s.clone()))
                } else if modifier.starts_with {
                    Ok(MatchType::StartsWith(s.clone()))
                } else if modifier.ends_with {
                    Ok(MatchType::EndsWith(s.clone()))
                } else if s.contains('*') || s.contains('?') {
                    // Wildcard pattern - convert to regex
                    let pattern = s
                        .replace('.', "\\.")
                        .replace('*', ".*")
                        .replace('?', ".");
                    let regex = Regex::new(&format!("^{}$", pattern))?;
                    Ok(MatchType::Regex(regex))
                } else {
                    Ok(MatchType::Exact(s.clone()))
                }
            }
            FieldValue::Integer(i) => Ok(MatchType::Integer(*i)),
            FieldValue::Boolean(b) => Ok(MatchType::Boolean(*b)),
            FieldValue::List(list) => {
                if modifier.all {
                    Ok(MatchType::All(list.clone()))
                } else {
                    Ok(MatchType::List(list.clone()))
                }
            }
            FieldValue::Null => Ok(MatchType::Null),
        }
    }

    fn parse_condition(condition: &str, _matchers: &HashMap<String, Vec<FieldMatcher>>) -> Result<ConditionNode> {
        // Simple condition parser
        // Supports: selection, not selection, selection and selection, selection or selection
        // Also: 1 of selection*, all of selection*, 1 of them, all of them

        let condition = condition.trim();

        // Handle "1 of selection*" or "all of selection*"
        if condition.starts_with("1 of ") || condition.starts_with("all of ") {
            let is_all = condition.starts_with("all of ");
            let pattern = if is_all {
                condition.strip_prefix("all of ").unwrap()
            } else {
                condition.strip_prefix("1 of ").unwrap()
            };

            if is_all {
                return Ok(ConditionNode::AllOf(pattern.to_string()));
            } else {
                return Ok(ConditionNode::OneOf(pattern.to_string()));
            }
        }

        // Handle 'or' operator
        if condition.contains(" or ") {
            let parts: Vec<&str> = condition.split(" or ").collect();
            let nodes: Result<Vec<ConditionNode>> = parts.iter()
                .map(|p| Self::parse_condition(p.trim(), _matchers))
                .collect();
            return Ok(ConditionNode::Or(nodes?));
        }

        // Handle 'and' operator
        if condition.contains(" and ") {
            let parts: Vec<&str> = condition.split(" and ").collect();
            let nodes: Result<Vec<ConditionNode>> = parts.iter()
                .map(|p| Self::parse_condition(p.trim(), _matchers))
                .collect();
            return Ok(ConditionNode::And(nodes?));
        }

        // Handle 'not' operator
        if condition.starts_with("not ") {
            let inner = condition.strip_prefix("not ").unwrap();
            let node = Self::parse_condition(inner, _matchers)?;
            return Ok(ConditionNode::Not(Box::new(node)));
        }

        // Handle parentheses
        if condition.starts_with('(') && condition.ends_with(')') {
            let inner = &condition[1..condition.len()-1];
            return Self::parse_condition(inner, _matchers);
        }

        // Simple selection reference
        Ok(ConditionNode::Selection(condition.to_string()))
    }

    /// Evaluate the compiled rule against a log entry
    pub fn evaluate(&self, entry: &LogEntry) -> bool {
        // Convert log entry to field map
        let fields = Self::log_to_fields(entry);

        // Evaluate the condition AST
        self.evaluate_condition(&self.condition_ast, &fields)
    }

    fn log_to_fields(entry: &LogEntry) -> HashMap<String, String> {
        let mut fields = HashMap::new();

        fields.insert("message".to_string(), entry.message.clone());
        fields.insert("raw".to_string(), entry.raw.clone());

        if let Some(ref hostname) = entry.hostname {
            fields.insert("hostname".to_string(), hostname.clone());
            fields.insert("ComputerName".to_string(), hostname.clone());
        }
        if let Some(ref app) = entry.application {
            fields.insert("application".to_string(), app.clone());
            fields.insert("process".to_string(), app.clone());
        }
        if let Some(ref user) = entry.user {
            fields.insert("user".to_string(), user.clone());
            fields.insert("TargetUserName".to_string(), user.clone());
            fields.insert("SubjectUserName".to_string(), user.clone());
        }
        if let Some(ref category) = entry.category {
            fields.insert("category".to_string(), category.clone());
        }
        if let Some(ref action) = entry.action {
            fields.insert("action".to_string(), action.clone());
        }
        if let Some(ref outcome) = entry.outcome {
            fields.insert("outcome".to_string(), outcome.clone());
        }
        if let Some(ip) = entry.source_ip {
            fields.insert("source_ip".to_string(), ip.to_string());
            fields.insert("SourceIp".to_string(), ip.to_string());
            fields.insert("IpAddress".to_string(), ip.to_string());
        }
        if let Some(ip) = entry.destination_ip {
            fields.insert("destination_ip".to_string(), ip.to_string());
            fields.insert("DestinationIp".to_string(), ip.to_string());
        }
        if let Some(port) = entry.source_port {
            fields.insert("source_port".to_string(), port.to_string());
            fields.insert("SourcePort".to_string(), port.to_string());
        }
        if let Some(port) = entry.destination_port {
            fields.insert("destination_port".to_string(), port.to_string());
            fields.insert("DestinationPort".to_string(), port.to_string());
        }
        if let Some(ref protocol) = entry.protocol {
            fields.insert("protocol".to_string(), protocol.clone());
        }
        if let Some(pid) = entry.pid {
            fields.insert("pid".to_string(), pid.to_string());
            fields.insert("ProcessId".to_string(), pid.to_string());
        }

        // Add structured data fields
        for (k, v) in &entry.structured_data {
            if let Some(s) = v.as_str() {
                fields.insert(k.clone(), s.to_string());
            } else {
                fields.insert(k.clone(), v.to_string());
            }
        }

        fields
    }

    fn evaluate_condition(&self, node: &ConditionNode, fields: &HashMap<String, String>) -> bool {
        match node {
            ConditionNode::Selection(name) => {
                self.evaluate_selection(name, fields)
            }
            ConditionNode::Not(inner) => {
                !self.evaluate_condition(inner, fields)
            }
            ConditionNode::And(nodes) => {
                nodes.iter().all(|n| self.evaluate_condition(n, fields))
            }
            ConditionNode::Or(nodes) => {
                nodes.iter().any(|n| self.evaluate_condition(n, fields))
            }
            ConditionNode::OneOf(pattern) => {
                // Match any selection that starts with the pattern (minus *)
                let prefix = pattern.trim_end_matches('*');
                self.matchers.keys()
                    .filter(|k| k.starts_with(prefix))
                    .any(|k| self.evaluate_selection(k, fields))
            }
            ConditionNode::AllOf(pattern) => {
                let prefix = pattern.trim_end_matches('*');
                if pattern == "them" {
                    // All selections must match
                    self.matchers.keys()
                        .all(|k| self.evaluate_selection(k, fields))
                } else {
                    self.matchers.keys()
                        .filter(|k| k.starts_with(prefix))
                        .all(|k| self.evaluate_selection(k, fields))
                }
            }
        }
    }

    fn evaluate_selection(&self, name: &str, fields: &HashMap<String, String>) -> bool {
        let Some(matchers) = self.matchers.get(name) else {
            return false;
        };

        // All matchers in a selection must match (AND logic)
        matchers.iter().all(|m| self.evaluate_matcher(m, fields))
    }

    fn evaluate_matcher(&self, matcher: &FieldMatcher, fields: &HashMap<String, String>) -> bool {
        let Some(value) = fields.get(&matcher.field) else {
            // Check if we need to match null
            return matches!(matcher.match_type, MatchType::Null);
        };

        let value_lower = value.to_lowercase();

        match &matcher.match_type {
            MatchType::Exact(pattern) => {
                if matcher.modifier.case_insensitive {
                    value_lower == pattern.to_lowercase()
                } else {
                    value == pattern
                }
            }
            MatchType::Contains(pattern) => {
                if matcher.modifier.case_insensitive {
                    value_lower.contains(&pattern.to_lowercase())
                } else {
                    value.contains(pattern)
                }
            }
            MatchType::StartsWith(pattern) => {
                if matcher.modifier.case_insensitive {
                    value_lower.starts_with(&pattern.to_lowercase())
                } else {
                    value.starts_with(pattern)
                }
            }
            MatchType::EndsWith(pattern) => {
                if matcher.modifier.case_insensitive {
                    value_lower.ends_with(&pattern.to_lowercase())
                } else {
                    value.ends_with(pattern)
                }
            }
            MatchType::Regex(regex) => {
                regex.is_match(value)
            }
            MatchType::Integer(i) => {
                value.parse::<i64>().map(|v| v == *i).unwrap_or(false)
            }
            MatchType::Boolean(b) => {
                matches!(value.to_lowercase().as_str(), "true" | "1" | "yes") == *b
            }
            MatchType::List(patterns) => {
                // OR logic: any pattern matches
                patterns.iter().any(|p| {
                    if matcher.modifier.case_insensitive {
                        value_lower.contains(&p.to_lowercase())
                    } else if matcher.modifier.contains {
                        value.contains(p)
                    } else {
                        value == p
                    }
                })
            }
            MatchType::All(patterns) => {
                // AND logic: all patterns must match
                patterns.iter().all(|p| {
                    if matcher.modifier.case_insensitive {
                        value_lower.contains(&p.to_lowercase())
                    } else {
                        value.contains(p)
                    }
                })
            }
            MatchType::Null => {
                false // Field has value, so null match fails
            }
        }
    }
}

// ============================================================================
// Sigma Rule Validation
// ============================================================================

/// Validation result for a Sigma rule
#[derive(Debug, Clone, Serialize)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Validate a Sigma rule
pub fn validate_sigma_rule(yaml: &str) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Try to parse
    match SigmaParser::parse(yaml) {
        Ok(rule) => {
            // Check required fields
            if rule.title.is_empty() {
                errors.push("Title is required".to_string());
            }

            // Check detection has at least one selection
            if rule.detection.selections.is_empty() {
                errors.push("Detection must have at least one selection".to_string());
            }

            // Validate condition references
            let condition = &rule.detection.condition;
            for (name, _) in &rule.detection.selections {
                if !condition.contains(name) && !condition.contains("them") && !condition.contains('*') {
                    warnings.push(format!("Selection '{}' is defined but not used in condition", name));
                }
            }

            // Check for logsource
            if rule.logsource.product.is_none()
                && rule.logsource.service.is_none()
                && rule.logsource.category.is_none()
            {
                warnings.push("Logsource is not specified".to_string());
            }

            // Check for description
            if rule.description.is_none() {
                warnings.push("Description is recommended".to_string());
            }

            // Try to compile the rule
            if let Err(e) = CompiledSigmaRule::compile(rule) {
                errors.push(format!("Failed to compile rule: {}", e));
            }
        }
        Err(e) => {
            errors.push(format!("Failed to parse YAML: {}", e));
        }
    }

    ValidationResult {
        is_valid: errors.is_empty(),
        errors,
        warnings,
    }
}

// ============================================================================
// Sigma Rule Testing
// ============================================================================

/// Test result for a Sigma rule
#[derive(Debug, Clone, Serialize)]
pub struct TestResult {
    pub rule_id: String,
    pub rule_title: String,
    pub matches: Vec<TestMatch>,
    pub total_logs_tested: usize,
    pub match_count: usize,
}

/// A single match in test results
#[derive(Debug, Clone, Serialize)]
pub struct TestMatch {
    pub log_id: String,
    pub message: String,
    pub matched_selections: Vec<String>,
}

/// Test a Sigma rule against sample logs
pub fn test_sigma_rule(rule: &CompiledSigmaRule, logs: &[LogEntry]) -> TestResult {
    let mut matches = Vec::new();

    for log in logs {
        if rule.evaluate(log) {
            // Find which selections matched
            let fields = CompiledSigmaRule::log_to_fields(log);
            let matched_selections: Vec<String> = rule.matchers.keys()
                .filter(|name| rule.evaluate_selection(name, &fields))
                .cloned()
                .collect();

            matches.push(TestMatch {
                log_id: log.id.clone(),
                message: log.message.clone(),
                matched_selections,
            });
        }
    }

    TestResult {
        rule_id: rule.rule.id.clone(),
        rule_title: rule.rule.title.clone(),
        match_count: matches.len(),
        total_logs_tested: logs.len(),
        matches,
    }
}

// ============================================================================
// Built-in Sigma Rules Library
// ============================================================================

/// Get the built-in Sigma rules library
pub fn get_builtin_rules() -> Vec<&'static str> {
    vec![
        // Windows Security - Failed Logon
        r#"title: Windows Logon Failure
id: 0e95725d-7320-415d-80f7-004da920fc11
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
level: low
tags:
    - attack.credential_access
    - attack.t1110
description: Detects failed Windows logon attempts"#,

        // Windows Security - Multiple Failed Logons
        r#"title: Multiple Failed Windows Logons
id: 3f4a5e29-8f2d-4c1e-9d3b-7a6c8d9e0f1a
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    timeframe: 5m
    condition: selection | count() > 5
level: medium
tags:
    - attack.credential_access
    - attack.t1110.001
description: Detects multiple failed logon attempts indicating potential brute force"#,

        // Windows - Suspicious PowerShell Command
        r#"title: Suspicious PowerShell Command
id: 6d3e8f4a-9b2c-4d1e-8f5a-7c8d9e0a1b2c
status: stable
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-Expression'
            - 'IEX'
            - 'Invoke-Command'
            - 'Invoke-WebRequest'
            - 'downloadstring'
            - '-enc'
            - '-EncodedCommand'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
description: Detects suspicious PowerShell commands that may indicate malicious activity"#,

        // Linux - SSH Brute Force
        r#"title: SSH Brute Force Attempt
id: 7e4f6a5b-8c3d-4e2f-9a1b-0c8d9e7f6a5b
status: stable
logsource:
    product: linux
    service: sshd
detection:
    selection:
        message|contains:
            - 'Failed password'
            - 'Invalid user'
            - 'authentication failure'
    condition: selection
level: low
tags:
    - attack.credential_access
    - attack.t1110
description: Detects failed SSH login attempts"#,

        // Linux - Privilege Escalation via sudo
        r#"title: Sudo Privilege Escalation
id: 8f5a7b6c-9d4e-4f3a-0b2c-1d8e9f7a6b5c
status: stable
logsource:
    product: linux
    service: sudo
detection:
    selection:
        message|contains:
            - 'COMMAND='
            - 'USER=root'
    filter:
        message|contains: 'pam_unix'
    condition: selection and not filter
level: medium
tags:
    - attack.privilege_escalation
    - attack.t1548.003
description: Detects sudo command execution for privilege escalation"#,

        // Web - SQL Injection Attempt
        r#"title: SQL Injection Attempt
id: 9a6b8c7d-0e5f-4a3b-1c2d-8e9f0a7b6c5d
status: stable
logsource:
    category: webserver
detection:
    selection:
        message|contains:
            - "' OR '"
            - "' AND '"
            - 'UNION SELECT'
            - 'UNION ALL SELECT'
            - '; DROP'
            - '-- -'
            - "1'='1"
            - 'or 1=1'
            - '" or ""="'
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1190
description: Detects potential SQL injection attempts in web logs"#,

        // Web - XSS Attempt
        r#"title: Cross-Site Scripting Attempt
id: 0b7c9d8e-1f6a-4b5c-2d3e-9f0a1b8c7d6e
status: stable
logsource:
    category: webserver
detection:
    selection:
        message|contains:
            - '<script>'
            - 'javascript:'
            - 'onerror='
            - 'onload='
            - 'onclick='
            - 'onmouseover='
            - '<iframe'
            - '<img src=x'
    condition: selection
level: medium
tags:
    - attack.initial_access
    - attack.t1189
description: Detects potential cross-site scripting (XSS) attempts"#,

        // Web - Path Traversal
        r#"title: Path Traversal Attempt
id: 1c8d0e9f-2a7b-4c6d-3e5f-0a1b2c9d8e7f
status: stable
logsource:
    category: webserver
detection:
    selection:
        message|contains:
            - '../'
            - '..%2f'
            - '..%252f'
            - '%2e%2e/'
            - '%252e%252e/'
            - '....///'
    condition: selection
level: high
tags:
    - attack.discovery
    - attack.t1083
description: Detects path traversal attempts to access files outside webroot"#,

        // Network - Port Scan Detection
        r#"title: Network Port Scan
id: 2d9e1f0a-3b8c-4d7e-4f6a-1b2c3d0e9f8a
status: stable
logsource:
    category: firewall
detection:
    selection:
        action: blocked
    timeframe: 1m
    condition: selection | count(destination_port) by source_ip > 10
level: medium
tags:
    - attack.reconnaissance
    - attack.t1046
description: Detects port scanning activity based on blocked connections"#,

        // Windows - Suspicious Service Installation
        r#"title: Suspicious Service Installation
id: 3e0f2a1b-4c9d-4e8f-5a7b-2c3d4e1f0a9b
status: stable
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    filter:
        ServiceName|contains:
            - 'Windows'
            - 'Microsoft'
    condition: selection and not filter
level: medium
tags:
    - attack.persistence
    - attack.t1543.003
description: Detects installation of new services that may indicate persistence"#,

        // Windows - Suspicious Process Creation
        r#"title: Suspicious Process from Temp Directory
id: 4f1a3b2c-5d0e-4f9a-6b8c-3d4e5f2a1b0c
status: stable
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|contains:
            - '\\Temp\\'
            - '\\AppData\\Local\\Temp\\'
            - '\\Downloads\\'
    condition: selection
level: medium
tags:
    - attack.execution
    - attack.t1204
description: Detects process execution from temporary directories"#,

        // Linux - Reverse Shell Detection
        r#"title: Potential Reverse Shell
id: 5a2b4c3d-6e1f-4a0b-7c9d-4e5f6a3b2c1d
status: stable
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'bash -i'
            - 'nc -e'
            - 'ncat -e'
            - '/dev/tcp/'
            - 'python -c'
            - 'perl -e'
            - 'ruby -rsocket'
            - 'socat'
    condition: selection
level: critical
tags:
    - attack.execution
    - attack.t1059.004
description: Detects potential reverse shell execution"#,
    ]
}

/// Load all built-in Sigma rules as compiled rules
pub fn load_builtin_rules() -> Result<Vec<CompiledSigmaRule>> {
    let yaml_rules = get_builtin_rules();
    let mut compiled = Vec::new();

    for yaml in yaml_rules {
        match SigmaParser::parse(yaml) {
            Ok(rule) => {
                match CompiledSigmaRule::compile(rule) {
                    Ok(compiled_rule) => compiled.push(compiled_rule),
                    Err(e) => log::warn!("Failed to compile built-in rule: {}", e),
                }
            }
            Err(e) => log::warn!("Failed to parse built-in rule: {}", e),
        }
    }

    Ok(compiled)
}

// ============================================================================
// Database Types for Sigma Rules
// ============================================================================

/// Database record for a stored Sigma rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRuleRecord {
    pub id: String,
    pub name: String,
    pub yaml_content: String,
    pub compiled_query: Option<String>,
    pub enabled: bool,
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
level: medium
"#;

        let rule = SigmaParser::parse(yaml).unwrap();
        assert_eq!(rule.title, "Test Rule");
        assert_eq!(rule.level, SigmaSeverity::Medium);
        assert!(rule.logsource.product.as_deref() == Some("windows"));
    }

    #[test]
    fn test_compile_and_match() {
        let yaml = r#"
title: Failed Login Detection
logsource:
    product: windows
detection:
    selection:
        message|contains: 'failed'
    condition: selection
level: low
"#;

        let rule = SigmaParser::parse(yaml).unwrap();
        let compiled = CompiledSigmaRule::compile(rule).unwrap();

        let mut entry = LogEntry::new(
            "test-source".to_string(),
            "Login failed for user admin".to_string(),
            "Login failed for user admin".to_string(),
        );

        assert!(compiled.evaluate(&entry));

        entry.message = "Login successful".to_string();
        assert!(!compiled.evaluate(&entry));
    }

    #[test]
    fn test_validation() {
        let valid_yaml = r#"
title: Valid Rule
detection:
    selection:
        EventID: 1234
    condition: selection
level: high
"#;

        let result = validate_sigma_rule(valid_yaml);
        assert!(result.is_valid);

        let invalid_yaml = "not valid yaml: [[[";
        let result = validate_sigma_rule(invalid_yaml);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_builtin_rules_load() {
        let rules = load_builtin_rules().unwrap();
        assert!(rules.len() >= 10, "Should have at least 10 built-in rules");
    }
}
