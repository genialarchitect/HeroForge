//! Sigma Rule Backend Converters
//!
//! Converts Sigma detection rules to various SIEM query languages:
//! - Splunk SPL (Search Processing Language)
//! - Elastic EQL (Event Query Language)
//! - Elastic KQL (Kibana Query Language)
//! - QRadar AQL (Ariel Query Language)
//! - Microsoft Sentinel KQL

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};

use super::sigma::{CompiledSigmaRule, ConditionNode, FieldMatcher, MatchType, SigmaRule};

/// Supported backend conversion targets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigmaBackend {
    SplunkSpl,
    ElasticEql,
    ElasticKql,
    QRadarAql,
    MicrosoftSentinel,
    Grep,  // Simple grep-like pattern for testing
}

impl std::fmt::Display for SigmaBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigmaBackend::SplunkSpl => write!(f, "splunk_spl"),
            SigmaBackend::ElasticEql => write!(f, "elastic_eql"),
            SigmaBackend::ElasticKql => write!(f, "elastic_kql"),
            SigmaBackend::QRadarAql => write!(f, "qradar_aql"),
            SigmaBackend::MicrosoftSentinel => write!(f, "microsoft_sentinel"),
            SigmaBackend::Grep => write!(f, "grep"),
        }
    }
}

impl std::str::FromStr for SigmaBackend {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "splunk_spl" | "splunk" | "spl" => Ok(SigmaBackend::SplunkSpl),
            "elastic_eql" | "eql" => Ok(SigmaBackend::ElasticEql),
            "elastic_kql" | "kql" | "kibana" => Ok(SigmaBackend::ElasticKql),
            "qradar_aql" | "qradar" | "aql" => Ok(SigmaBackend::QRadarAql),
            "microsoft_sentinel" | "sentinel" | "azure_sentinel" => Ok(SigmaBackend::MicrosoftSentinel),
            "grep" => Ok(SigmaBackend::Grep),
            _ => Err(anyhow!("Unknown backend: {}", s)),
        }
    }
}

/// Field mapping configuration for different log sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMappings {
    /// Map Sigma field names to backend-specific field names
    pub field_map: HashMap<String, String>,
    /// Log source product to index/data stream mapping
    pub index_map: HashMap<String, String>,
    /// Event ID mappings
    pub event_id_map: HashMap<String, String>,
}

impl Default for FieldMappings {
    fn default() -> Self {
        let mut field_map = HashMap::new();
        // Windows Security Event Log mappings
        field_map.insert("EventID".to_string(), "event_id".to_string());
        field_map.insert("EventType".to_string(), "event_type".to_string());
        field_map.insert("SourceHostname".to_string(), "source_hostname".to_string());
        field_map.insert("TargetHostname".to_string(), "dest_hostname".to_string());
        field_map.insert("TargetUserName".to_string(), "user".to_string());
        field_map.insert("SourceUserName".to_string(), "src_user".to_string());
        field_map.insert("IpAddress".to_string(), "src_ip".to_string());
        field_map.insert("SourceAddress".to_string(), "src_ip".to_string());
        field_map.insert("DestinationAddress".to_string(), "dest_ip".to_string());
        field_map.insert("DestinationPort".to_string(), "dest_port".to_string());
        field_map.insert("SourcePort".to_string(), "src_port".to_string());
        field_map.insert("ProcessName".to_string(), "process_name".to_string());
        field_map.insert("Image".to_string(), "process_path".to_string());
        field_map.insert("CommandLine".to_string(), "cmdline".to_string());
        field_map.insert("ParentImage".to_string(), "parent_process_path".to_string());
        field_map.insert("ParentCommandLine".to_string(), "parent_cmdline".to_string());
        field_map.insert("LogonType".to_string(), "logon_type".to_string());
        field_map.insert("Status".to_string(), "status".to_string());
        field_map.insert("FailureReason".to_string(), "failure_reason".to_string());

        let mut index_map = HashMap::new();
        index_map.insert("windows".to_string(), "wineventlog".to_string());
        index_map.insert("linux".to_string(), "syslog".to_string());
        index_map.insert("apache".to_string(), "apache".to_string());
        index_map.insert("nginx".to_string(), "nginx".to_string());
        index_map.insert("firewall".to_string(), "firewall".to_string());

        Self {
            field_map,
            index_map,
            event_id_map: HashMap::new(),
        }
    }
}

/// Conversion result with query and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionResult {
    pub backend: SigmaBackend,
    pub query: String,
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub field_mappings_used: HashMap<String, String>,
    pub unsupported_features: Vec<String>,
}

/// Sigma to backend converter
pub struct SigmaConverter {
    pub backend: SigmaBackend,
    pub field_mappings: FieldMappings,
}

impl SigmaConverter {
    pub fn new(backend: SigmaBackend) -> Self {
        Self {
            backend,
            field_mappings: FieldMappings::default(),
        }
    }

    pub fn with_field_mappings(mut self, mappings: FieldMappings) -> Self {
        self.field_mappings = mappings;
        self
    }

    /// Convert a Sigma rule to the target backend
    pub fn convert(&self, rule: &SigmaRule, compiled: &CompiledSigmaRule) -> ConversionResult {
        match self.backend {
            SigmaBackend::SplunkSpl => self.convert_to_splunk(rule, compiled),
            SigmaBackend::ElasticEql => self.convert_to_eql(rule, compiled),
            SigmaBackend::ElasticKql => self.convert_to_kql(rule, compiled),
            SigmaBackend::QRadarAql => self.convert_to_qradar(rule, compiled),
            SigmaBackend::MicrosoftSentinel => self.convert_to_sentinel(rule, compiled),
            SigmaBackend::Grep => self.convert_to_grep(rule, compiled),
        }
    }

    /// Convert to Splunk SPL (Search Processing Language)
    fn convert_to_splunk(&self, rule: &SigmaRule, compiled: &CompiledSigmaRule) -> ConversionResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let unsupported = Vec::new();
        let mut fields_used = HashMap::new();

        // Build index/sourcetype from logsource
        let mut query_parts = Vec::new();

        // Add index clause
        if let Some(product) = &rule.logsource.product {
            let index = self.field_mappings.index_map.get(product)
                .map(|s| s.as_str())
                .unwrap_or("*");
            query_parts.push(format!("index={}", index));
        }

        if let Some(service) = &rule.logsource.service {
            query_parts.push(format!("sourcetype=*{}*", service));
        }

        // Convert condition to SPL
        match self.condition_to_splunk(&compiled.condition_ast, &compiled.matchers, &mut fields_used, &mut warnings) {
            Ok(condition) => query_parts.push(condition),
            Err(e) => errors.push(e.to_string()),
        }

        // Add aggregation for timeframe if specified
        if let Some(timeframe) = &rule.detection.timeframe {
            query_parts.push(format!("| bin _time span={}", timeframe));
            query_parts.push("| stats count by _time".to_string());
        }

        let query = query_parts.join(" ");

        ConversionResult {
            backend: SigmaBackend::SplunkSpl,
            query,
            is_valid: errors.is_empty(),
            errors,
            warnings,
            field_mappings_used: fields_used,
            unsupported_features: unsupported,
        }
    }

    fn condition_to_splunk(
        &self,
        node: &ConditionNode,
        matchers: &HashMap<String, Vec<FieldMatcher>>,
        fields_used: &mut HashMap<String, String>,
        warnings: &mut Vec<String>,
    ) -> Result<String> {
        match node {
            ConditionNode::Selection(name) => {
                if let Some(field_matchers) = matchers.get(name) {
                    Ok(format!("({})", self.matchers_to_splunk(field_matchers, fields_used)))
                } else {
                    Err(anyhow!("Selection '{}' not found", name))
                }
            }
            ConditionNode::Not(inner) => {
                let inner_spl = self.condition_to_splunk(inner, matchers, fields_used, warnings)?;
                Ok(format!("NOT ({})", inner_spl))
            }
            ConditionNode::And(nodes) => {
                let parts: Result<Vec<String>> = nodes.iter()
                    .map(|n| self.condition_to_splunk(n, matchers, fields_used, warnings))
                    .collect();
                Ok(format!("({})", parts?.join(" AND ")))
            }
            ConditionNode::Or(nodes) => {
                let parts: Result<Vec<String>> = nodes.iter()
                    .map(|n| self.condition_to_splunk(n, matchers, fields_used, warnings))
                    .collect();
                Ok(format!("({})", parts?.join(" OR ")))
            }
            ConditionNode::OneOf(pattern) => {
                let prefix = pattern.trim_end_matches('*');
                let parts: Vec<String> = matchers.iter()
                    .filter(|(name, _)| prefix == "them" || name.starts_with(prefix))
                    .map(|(_, field_matchers)| format!("({})", self.matchers_to_splunk(field_matchers, fields_used)))
                    .collect();
                if parts.is_empty() {
                    warnings.push(format!("No selections matched pattern: {}", pattern));
                    Ok("*".to_string())
                } else {
                    Ok(format!("({})", parts.join(" OR ")))
                }
            }
            ConditionNode::AllOf(pattern) => {
                let prefix = pattern.trim_end_matches('*');
                let parts: Vec<String> = matchers.iter()
                    .filter(|(name, _)| prefix == "them" || name.starts_with(prefix))
                    .map(|(_, field_matchers)| format!("({})", self.matchers_to_splunk(field_matchers, fields_used)))
                    .collect();
                if parts.is_empty() {
                    warnings.push(format!("No selections matched pattern: {}", pattern));
                    Ok("*".to_string())
                } else {
                    Ok(format!("({})", parts.join(" AND ")))
                }
            }
        }
    }

    fn matchers_to_splunk(&self, matchers: &[FieldMatcher], fields_used: &mut HashMap<String, String>) -> String {
        let parts: Vec<String> = matchers.iter().map(|m| {
            let mapped_field = self.field_mappings.field_map.get(&m.field)
                .cloned()
                .unwrap_or_else(|| m.field.clone());
            fields_used.insert(m.field.clone(), mapped_field.clone());

            match &m.match_type {
                MatchType::Exact(v) => format!("{}=\"{}\"", mapped_field, self.escape_splunk(v)),
                MatchType::Contains(v) => format!("{}=\"*{}*\"", mapped_field, self.escape_splunk(v)),
                MatchType::StartsWith(v) => format!("{}=\"{}*\"", mapped_field, self.escape_splunk(v)),
                MatchType::EndsWith(v) => format!("{}=\"*{}\"", mapped_field, self.escape_splunk(v)),
                MatchType::Regex(re) => format!("{}=\"{}\"", mapped_field, re.as_str()),
                MatchType::Integer(n) => format!("{}={}", mapped_field, n),
                MatchType::Boolean(b) => format!("{}={}", mapped_field, if *b { "true" } else { "false" }),
                MatchType::List(values) => {
                    let list: Vec<String> = values.iter()
                        .map(|v| format!("\"{}\"", self.escape_splunk(v)))
                        .collect();
                    format!("{} IN ({})", mapped_field, list.join(", "))
                }
                MatchType::All(values) => {
                    let parts: Vec<String> = values.iter()
                        .map(|v| format!("{}=\"*{}*\"", mapped_field, self.escape_splunk(v)))
                        .collect();
                    format!("({})", parts.join(" AND "))
                }
                MatchType::Null => format!("NOT {}=*", mapped_field),
            }
        }).collect();

        parts.join(" AND ")
    }

    fn escape_splunk(&self, s: &str) -> String {
        s.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("*", "\\*")
    }

    /// Convert to Elastic EQL (Event Query Language)
    fn convert_to_eql(&self, rule: &SigmaRule, compiled: &CompiledSigmaRule) -> ConversionResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut fields_used = HashMap::new();
        let unsupported = Vec::new();

        // Determine event category from logsource
        let event_category = match rule.logsource.category.as_deref() {
            Some("process_creation") => "process",
            Some("network_connection") => "network",
            Some("file_event") | Some("file_creation") => "file",
            Some("registry_event") => "registry",
            Some("dns_query") => "dns",
            _ => "any",
        };

        let mut query = format!("{} where ", event_category);

        // Convert condition to EQL
        match self.condition_to_eql(&compiled.condition_ast, &compiled.matchers, &mut fields_used, &mut warnings) {
            Ok(condition) => query.push_str(&condition),
            Err(e) => errors.push(e.to_string()),
        }

        ConversionResult {
            backend: SigmaBackend::ElasticEql,
            query,
            is_valid: errors.is_empty(),
            errors,
            warnings,
            field_mappings_used: fields_used,
            unsupported_features: unsupported,
        }
    }

    fn condition_to_eql(
        &self,
        node: &ConditionNode,
        matchers: &HashMap<String, Vec<FieldMatcher>>,
        fields_used: &mut HashMap<String, String>,
        warnings: &mut Vec<String>,
    ) -> Result<String> {
        match node {
            ConditionNode::Selection(name) => {
                if let Some(field_matchers) = matchers.get(name) {
                    Ok(format!("({})", self.matchers_to_eql(field_matchers, fields_used)))
                } else {
                    Err(anyhow!("Selection '{}' not found", name))
                }
            }
            ConditionNode::Not(inner) => {
                let inner_eql = self.condition_to_eql(inner, matchers, fields_used, warnings)?;
                Ok(format!("not ({})", inner_eql))
            }
            ConditionNode::And(nodes) => {
                let parts: Result<Vec<String>> = nodes.iter()
                    .map(|n| self.condition_to_eql(n, matchers, fields_used, warnings))
                    .collect();
                Ok(format!("({})", parts?.join(" and ")))
            }
            ConditionNode::Or(nodes) => {
                let parts: Result<Vec<String>> = nodes.iter()
                    .map(|n| self.condition_to_eql(n, matchers, fields_used, warnings))
                    .collect();
                Ok(format!("({})", parts?.join(" or ")))
            }
            ConditionNode::OneOf(pattern) => {
                let prefix = pattern.trim_end_matches('*');
                let parts: Vec<String> = matchers.iter()
                    .filter(|(name, _)| prefix == "them" || name.starts_with(prefix))
                    .map(|(_, field_matchers)| format!("({})", self.matchers_to_eql(field_matchers, fields_used)))
                    .collect();
                Ok(format!("({})", parts.join(" or ")))
            }
            ConditionNode::AllOf(pattern) => {
                let prefix = pattern.trim_end_matches('*');
                let parts: Vec<String> = matchers.iter()
                    .filter(|(name, _)| prefix == "them" || name.starts_with(prefix))
                    .map(|(_, field_matchers)| format!("({})", self.matchers_to_eql(field_matchers, fields_used)))
                    .collect();
                Ok(format!("({})", parts.join(" and ")))
            }
        }
    }

    fn matchers_to_eql(&self, matchers: &[FieldMatcher], fields_used: &mut HashMap<String, String>) -> String {
        let parts: Vec<String> = matchers.iter().map(|m| {
            let mapped_field = self.map_field_to_ecs(&m.field);
            fields_used.insert(m.field.clone(), mapped_field.clone());

            match &m.match_type {
                MatchType::Exact(v) => format!("{} == \"{}\"", mapped_field, self.escape_eql(v)),
                MatchType::Contains(v) => format!("{} : \"*{}*\"", mapped_field, self.escape_eql(v)),
                MatchType::StartsWith(v) => format!("{} : \"{}*\"", mapped_field, self.escape_eql(v)),
                MatchType::EndsWith(v) => format!("{} : \"*{}\"", mapped_field, self.escape_eql(v)),
                MatchType::Regex(re) => format!("{} regex \"{}\"", mapped_field, re.as_str()),
                MatchType::Integer(n) => format!("{} == {}", mapped_field, n),
                MatchType::Boolean(b) => format!("{} == {}", mapped_field, b),
                MatchType::List(values) => {
                    let list: Vec<String> = values.iter()
                        .map(|v| format!("\"{}\"", self.escape_eql(v)))
                        .collect();
                    format!("{} in ({})", mapped_field, list.join(", "))
                }
                MatchType::All(values) => {
                    let parts: Vec<String> = values.iter()
                        .map(|v| format!("{} : \"*{}*\"", mapped_field, self.escape_eql(v)))
                        .collect();
                    format!("({})", parts.join(" and "))
                }
                MatchType::Null => format!("{} == null", mapped_field),
            }
        }).collect();

        parts.join(" and ")
    }

    fn map_field_to_ecs(&self, field: &str) -> String {
        // Map Sigma fields to Elastic Common Schema (ECS)
        match field.to_lowercase().as_str() {
            "eventid" => "event.code".to_string(),
            "image" | "processname" => "process.executable".to_string(),
            "commandline" => "process.command_line".to_string(),
            "parentimage" => "process.parent.executable".to_string(),
            "parentcommandline" => "process.parent.command_line".to_string(),
            "user" | "targetusername" => "user.name".to_string(),
            "sourceip" | "ipaddress" => "source.ip".to_string(),
            "destinationip" => "destination.ip".to_string(),
            "destinationport" => "destination.port".to_string(),
            "sourceport" => "source.port".to_string(),
            "hostname" | "computername" => "host.name".to_string(),
            _ => self.field_mappings.field_map.get(field)
                .cloned()
                .unwrap_or_else(|| field.to_string()),
        }
    }

    fn escape_eql(&self, s: &str) -> String {
        s.replace("\\", "\\\\")
            .replace("\"", "\\\"")
    }

    /// Convert to Elastic/Kibana KQL (Kibana Query Language)
    fn convert_to_kql(&self, rule: &SigmaRule, compiled: &CompiledSigmaRule) -> ConversionResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut fields_used = HashMap::new();
        let unsupported = Vec::new();

        // Convert condition to KQL
        let query = match self.condition_to_kql(&compiled.condition_ast, &compiled.matchers, &mut fields_used, &mut warnings) {
            Ok(q) => q,
            Err(e) => {
                errors.push(e.to_string());
                String::new()
            }
        };

        ConversionResult {
            backend: SigmaBackend::ElasticKql,
            query,
            is_valid: errors.is_empty(),
            errors,
            warnings,
            field_mappings_used: fields_used,
            unsupported_features: unsupported,
        }
    }

    fn condition_to_kql(
        &self,
        node: &ConditionNode,
        matchers: &HashMap<String, Vec<FieldMatcher>>,
        fields_used: &mut HashMap<String, String>,
        warnings: &mut Vec<String>,
    ) -> Result<String> {
        match node {
            ConditionNode::Selection(name) => {
                if let Some(field_matchers) = matchers.get(name) {
                    Ok(format!("({})", self.matchers_to_kql(field_matchers, fields_used)))
                } else {
                    Err(anyhow!("Selection '{}' not found", name))
                }
            }
            ConditionNode::Not(inner) => {
                let inner_kql = self.condition_to_kql(inner, matchers, fields_used, warnings)?;
                Ok(format!("NOT ({})", inner_kql))
            }
            ConditionNode::And(nodes) => {
                let parts: Result<Vec<String>> = nodes.iter()
                    .map(|n| self.condition_to_kql(n, matchers, fields_used, warnings))
                    .collect();
                Ok(format!("({})", parts?.join(" AND ")))
            }
            ConditionNode::Or(nodes) => {
                let parts: Result<Vec<String>> = nodes.iter()
                    .map(|n| self.condition_to_kql(n, matchers, fields_used, warnings))
                    .collect();
                Ok(format!("({})", parts?.join(" OR ")))
            }
            ConditionNode::OneOf(pattern) => {
                let prefix = pattern.trim_end_matches('*');
                let parts: Vec<String> = matchers.iter()
                    .filter(|(name, _)| prefix == "them" || name.starts_with(prefix))
                    .map(|(_, field_matchers)| format!("({})", self.matchers_to_kql(field_matchers, fields_used)))
                    .collect();
                Ok(format!("({})", parts.join(" OR ")))
            }
            ConditionNode::AllOf(pattern) => {
                let prefix = pattern.trim_end_matches('*');
                let parts: Vec<String> = matchers.iter()
                    .filter(|(name, _)| prefix == "them" || name.starts_with(prefix))
                    .map(|(_, field_matchers)| format!("({})", self.matchers_to_kql(field_matchers, fields_used)))
                    .collect();
                Ok(format!("({})", parts.join(" AND ")))
            }
        }
    }

    fn matchers_to_kql(&self, matchers: &[FieldMatcher], fields_used: &mut HashMap<String, String>) -> String {
        let parts: Vec<String> = matchers.iter().map(|m| {
            let mapped_field = self.map_field_to_ecs(&m.field);
            fields_used.insert(m.field.clone(), mapped_field.clone());

            match &m.match_type {
                MatchType::Exact(v) => format!("{}: \"{}\"", mapped_field, self.escape_kql(v)),
                MatchType::Contains(v) => format!("{}: *{}*", mapped_field, self.escape_kql(v)),
                MatchType::StartsWith(v) => format!("{}: {}*", mapped_field, self.escape_kql(v)),
                MatchType::EndsWith(v) => format!("{}: *{}", mapped_field, self.escape_kql(v)),
                MatchType::Regex(re) => format!("{}: /{}/", mapped_field, re.as_str()),
                MatchType::Integer(n) => format!("{}: {}", mapped_field, n),
                MatchType::Boolean(b) => format!("{}: {}", mapped_field, b),
                MatchType::List(values) => {
                    let list: Vec<String> = values.iter()
                        .map(|v| format!("\"{}\"", self.escape_kql(v)))
                        .collect();
                    format!("{}: ({})", mapped_field, list.join(" OR "))
                }
                MatchType::All(values) => {
                    let parts: Vec<String> = values.iter()
                        .map(|v| format!("{}: *{}*", mapped_field, self.escape_kql(v)))
                        .collect();
                    format!("({})", parts.join(" AND "))
                }
                MatchType::Null => format!("NOT {}: *", mapped_field),
            }
        }).collect();

        parts.join(" AND ")
    }

    fn escape_kql(&self, s: &str) -> String {
        // KQL special characters that need escaping
        s.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace(":", "\\:")
    }

    /// Convert to QRadar AQL (Ariel Query Language)
    fn convert_to_qradar(&self, rule: &SigmaRule, compiled: &CompiledSigmaRule) -> ConversionResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut fields_used = HashMap::new();
        let unsupported = Vec::new();

        // Build base query with log source
        let mut query = String::from("SELECT * FROM events WHERE ");

        // Add log source filter
        if let Some(product) = &rule.logsource.product {
            query.push_str(&format!("LOGSOURCETYPENAME(logsourceid) ILIKE '%{}%' AND ", product));
        }

        // Convert condition to AQL
        match self.condition_to_qradar(&compiled.condition_ast, &compiled.matchers, &mut fields_used, &mut warnings) {
            Ok(condition) => query.push_str(&condition),
            Err(e) => errors.push(e.to_string()),
        }

        // Add time range (last 24 hours by default)
        query.push_str(" LAST 24 HOURS");

        ConversionResult {
            backend: SigmaBackend::QRadarAql,
            query,
            is_valid: errors.is_empty(),
            errors,
            warnings,
            field_mappings_used: fields_used,
            unsupported_features: unsupported,
        }
    }

    fn condition_to_qradar(
        &self,
        node: &ConditionNode,
        matchers: &HashMap<String, Vec<FieldMatcher>>,
        fields_used: &mut HashMap<String, String>,
        warnings: &mut Vec<String>,
    ) -> Result<String> {
        match node {
            ConditionNode::Selection(name) => {
                if let Some(field_matchers) = matchers.get(name) {
                    Ok(format!("({})", self.matchers_to_qradar(field_matchers, fields_used)))
                } else {
                    Err(anyhow!("Selection '{}' not found", name))
                }
            }
            ConditionNode::Not(inner) => {
                let inner_aql = self.condition_to_qradar(inner, matchers, fields_used, warnings)?;
                Ok(format!("NOT ({})", inner_aql))
            }
            ConditionNode::And(nodes) => {
                let parts: Result<Vec<String>> = nodes.iter()
                    .map(|n| self.condition_to_qradar(n, matchers, fields_used, warnings))
                    .collect();
                Ok(format!("({})", parts?.join(" AND ")))
            }
            ConditionNode::Or(nodes) => {
                let parts: Result<Vec<String>> = nodes.iter()
                    .map(|n| self.condition_to_qradar(n, matchers, fields_used, warnings))
                    .collect();
                Ok(format!("({})", parts?.join(" OR ")))
            }
            ConditionNode::OneOf(pattern) => {
                let prefix = pattern.trim_end_matches('*');
                let parts: Vec<String> = matchers.iter()
                    .filter(|(name, _)| prefix == "them" || name.starts_with(prefix))
                    .map(|(_, field_matchers)| format!("({})", self.matchers_to_qradar(field_matchers, fields_used)))
                    .collect();
                Ok(format!("({})", parts.join(" OR ")))
            }
            ConditionNode::AllOf(pattern) => {
                let prefix = pattern.trim_end_matches('*');
                let parts: Vec<String> = matchers.iter()
                    .filter(|(name, _)| prefix == "them" || name.starts_with(prefix))
                    .map(|(_, field_matchers)| format!("({})", self.matchers_to_qradar(field_matchers, fields_used)))
                    .collect();
                Ok(format!("({})", parts.join(" AND ")))
            }
        }
    }

    fn matchers_to_qradar(&self, matchers: &[FieldMatcher], fields_used: &mut HashMap<String, String>) -> String {
        let parts: Vec<String> = matchers.iter().map(|m| {
            let mapped_field = self.map_field_to_qradar(&m.field);
            fields_used.insert(m.field.clone(), mapped_field.clone());

            match &m.match_type {
                MatchType::Exact(v) => format!("\"{}\" = '{}'", mapped_field, self.escape_aql(v)),
                MatchType::Contains(v) => format!("\"{}\" ILIKE '%{}%'", mapped_field, self.escape_aql(v)),
                MatchType::StartsWith(v) => format!("\"{}\" ILIKE '{}%'", mapped_field, self.escape_aql(v)),
                MatchType::EndsWith(v) => format!("\"{}\" ILIKE '%{}'", mapped_field, self.escape_aql(v)),
                MatchType::Regex(re) => format!("\"{}\" MATCHES '{}'", mapped_field, re.as_str()),
                MatchType::Integer(n) => format!("\"{}\" = {}", mapped_field, n),
                MatchType::Boolean(b) => format!("\"{}\" = {}", mapped_field, if *b { "true" } else { "false" }),
                MatchType::List(values) => {
                    let list: Vec<String> = values.iter()
                        .map(|v| format!("'{}'", self.escape_aql(v)))
                        .collect();
                    format!("\"{}\" IN ({})", mapped_field, list.join(", "))
                }
                MatchType::All(values) => {
                    let parts: Vec<String> = values.iter()
                        .map(|v| format!("\"{}\" ILIKE '%{}%'", mapped_field, self.escape_aql(v)))
                        .collect();
                    format!("({})", parts.join(" AND "))
                }
                MatchType::Null => format!("\"{}\" IS NULL", mapped_field),
            }
        }).collect();

        parts.join(" AND ")
    }

    fn map_field_to_qradar(&self, field: &str) -> String {
        // Map Sigma fields to QRadar fields
        match field.to_lowercase().as_str() {
            "eventid" => "EventID".to_string(),
            "image" | "processname" => "Process Name".to_string(),
            "commandline" => "Command".to_string(),
            "user" | "targetusername" => "Username".to_string(),
            "sourceip" | "ipaddress" => "sourceIP".to_string(),
            "destinationip" => "destinationIP".to_string(),
            "destinationport" => "destinationPort".to_string(),
            "sourceport" => "sourcePort".to_string(),
            "hostname" | "computername" => "Hostname".to_string(),
            _ => self.field_mappings.field_map.get(field)
                .cloned()
                .unwrap_or_else(|| field.to_string()),
        }
    }

    fn escape_aql(&self, s: &str) -> String {
        s.replace("'", "''")
    }

    /// Convert to Microsoft Sentinel KQL
    fn convert_to_sentinel(&self, rule: &SigmaRule, compiled: &CompiledSigmaRule) -> ConversionResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut fields_used = HashMap::new();
        let unsupported = Vec::new();

        // Determine the table from logsource
        let table = match (rule.logsource.product.as_deref(), rule.logsource.service.as_deref()) {
            (Some("windows"), Some("security")) => "SecurityEvent",
            (Some("windows"), Some("sysmon")) => "SysmonEvent",
            (Some("windows"), Some("powershell")) => "PowerShellEvent",
            (Some("linux"), Some("syslog")) => "Syslog",
            (Some("azure"), _) => "AzureActivity",
            (Some("office365"), _) => "OfficeActivity",
            _ => "CommonSecurityLog",
        };

        let mut query = format!("{}\n| where ", table);

        // Convert condition to Sentinel KQL
        match self.condition_to_sentinel(&compiled.condition_ast, &compiled.matchers, &mut fields_used, &mut warnings) {
            Ok(condition) => query.push_str(&condition),
            Err(e) => errors.push(e.to_string()),
        }

        ConversionResult {
            backend: SigmaBackend::MicrosoftSentinel,
            query,
            is_valid: errors.is_empty(),
            errors,
            warnings,
            field_mappings_used: fields_used,
            unsupported_features: unsupported,
        }
    }

    fn condition_to_sentinel(
        &self,
        node: &ConditionNode,
        matchers: &HashMap<String, Vec<FieldMatcher>>,
        fields_used: &mut HashMap<String, String>,
        warnings: &mut Vec<String>,
    ) -> Result<String> {
        match node {
            ConditionNode::Selection(name) => {
                if let Some(field_matchers) = matchers.get(name) {
                    Ok(format!("({})", self.matchers_to_sentinel(field_matchers, fields_used)))
                } else {
                    Err(anyhow!("Selection '{}' not found", name))
                }
            }
            ConditionNode::Not(inner) => {
                let inner_kql = self.condition_to_sentinel(inner, matchers, fields_used, warnings)?;
                Ok(format!("not ({})", inner_kql))
            }
            ConditionNode::And(nodes) => {
                let parts: Result<Vec<String>> = nodes.iter()
                    .map(|n| self.condition_to_sentinel(n, matchers, fields_used, warnings))
                    .collect();
                Ok(format!("({})", parts?.join(" and ")))
            }
            ConditionNode::Or(nodes) => {
                let parts: Result<Vec<String>> = nodes.iter()
                    .map(|n| self.condition_to_sentinel(n, matchers, fields_used, warnings))
                    .collect();
                Ok(format!("({})", parts?.join(" or ")))
            }
            ConditionNode::OneOf(pattern) => {
                let prefix = pattern.trim_end_matches('*');
                let parts: Vec<String> = matchers.iter()
                    .filter(|(name, _)| prefix == "them" || name.starts_with(prefix))
                    .map(|(_, field_matchers)| format!("({})", self.matchers_to_sentinel(field_matchers, fields_used)))
                    .collect();
                Ok(format!("({})", parts.join(" or ")))
            }
            ConditionNode::AllOf(pattern) => {
                let prefix = pattern.trim_end_matches('*');
                let parts: Vec<String> = matchers.iter()
                    .filter(|(name, _)| prefix == "them" || name.starts_with(prefix))
                    .map(|(_, field_matchers)| format!("({})", self.matchers_to_sentinel(field_matchers, fields_used)))
                    .collect();
                Ok(format!("({})", parts.join(" and ")))
            }
        }
    }

    fn matchers_to_sentinel(&self, matchers: &[FieldMatcher], fields_used: &mut HashMap<String, String>) -> String {
        let parts: Vec<String> = matchers.iter().map(|m| {
            let mapped_field = self.map_field_to_sentinel(&m.field);
            fields_used.insert(m.field.clone(), mapped_field.clone());

            match &m.match_type {
                MatchType::Exact(v) => format!("{} == \"{}\"", mapped_field, self.escape_sentinel(v)),
                MatchType::Contains(v) => format!("{} contains \"{}\"", mapped_field, self.escape_sentinel(v)),
                MatchType::StartsWith(v) => format!("{} startswith \"{}\"", mapped_field, self.escape_sentinel(v)),
                MatchType::EndsWith(v) => format!("{} endswith \"{}\"", mapped_field, self.escape_sentinel(v)),
                MatchType::Regex(re) => format!("{} matches regex \"{}\"", mapped_field, re.as_str()),
                MatchType::Integer(n) => format!("{} == {}", mapped_field, n),
                MatchType::Boolean(b) => format!("{} == {}", mapped_field, b),
                MatchType::List(values) => {
                    let list: Vec<String> = values.iter()
                        .map(|v| format!("\"{}\"", self.escape_sentinel(v)))
                        .collect();
                    format!("{} in ({})", mapped_field, list.join(", "))
                }
                MatchType::All(values) => {
                    let parts: Vec<String> = values.iter()
                        .map(|v| format!("{} contains \"{}\"", mapped_field, self.escape_sentinel(v)))
                        .collect();
                    format!("({})", parts.join(" and "))
                }
                MatchType::Null => format!("isempty({})", mapped_field),
            }
        }).collect();

        parts.join(" and ")
    }

    fn map_field_to_sentinel(&self, field: &str) -> String {
        // Map Sigma fields to Sentinel/Azure fields
        match field.to_lowercase().as_str() {
            "eventid" => "EventID".to_string(),
            "image" | "processname" => "NewProcessName".to_string(),
            "commandline" => "CommandLine".to_string(),
            "parentimage" => "ParentProcessName".to_string(),
            "user" | "targetusername" => "TargetUserName".to_string(),
            "sourceip" | "ipaddress" => "IpAddress".to_string(),
            "hostname" | "computername" => "Computer".to_string(),
            "logontype" => "LogonType".to_string(),
            _ => self.field_mappings.field_map.get(field)
                .cloned()
                .unwrap_or_else(|| field.to_string()),
        }
    }

    fn escape_sentinel(&self, s: &str) -> String {
        s.replace("\\", "\\\\")
            .replace("\"", "\\\"")
    }

    /// Convert to simple grep pattern for testing
    fn convert_to_grep(&self, _rule: &SigmaRule, compiled: &CompiledSigmaRule) -> ConversionResult {
        let mut patterns = Vec::new();
        let mut fields_used = HashMap::new();

        for matchers in compiled.matchers.values() {
            for m in matchers {
                fields_used.insert(m.field.clone(), m.field.clone());

                match &m.match_type {
                    MatchType::Exact(v) | MatchType::Contains(v) => {
                        patterns.push(v.clone());
                    }
                    MatchType::StartsWith(v) => patterns.push(format!("^{}", v)),
                    MatchType::EndsWith(v) => patterns.push(format!("{}$", v)),
                    MatchType::Regex(re) => patterns.push(re.as_str().to_string()),
                    MatchType::List(values) => {
                        let pattern = format!("({})", values.join("|"));
                        patterns.push(pattern);
                    }
                    _ => {}
                }
            }
        }

        let query = patterns.join(".*");

        ConversionResult {
            backend: SigmaBackend::Grep,
            query,
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            field_mappings_used: fields_used,
            unsupported_features: Vec::new(),
        }
    }
}

/// Convert a Sigma rule to multiple backends at once
pub fn convert_to_all_backends(rule: &SigmaRule, compiled: &CompiledSigmaRule) -> Vec<ConversionResult> {
    let backends = vec![
        SigmaBackend::SplunkSpl,
        SigmaBackend::ElasticEql,
        SigmaBackend::ElasticKql,
        SigmaBackend::QRadarAql,
        SigmaBackend::MicrosoftSentinel,
    ];

    backends.into_iter()
        .map(|backend| SigmaConverter::new(backend).convert(rule, compiled))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blue_team::security_monitoring::SigmaParser;

    fn parse_and_compile(yaml: &str) -> (SigmaRule, CompiledSigmaRule) {
        let rule = SigmaParser::parse(yaml).unwrap();
        let compiled = CompiledSigmaRule::compile(rule.clone()).unwrap();
        (rule, compiled)
    }

    #[test]
    fn test_splunk_conversion() {
        let yaml = r#"
title: Windows Failed Logon
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
level: medium
"#;

        let (rule, compiled) = parse_and_compile(yaml);

        let converter = SigmaConverter::new(SigmaBackend::SplunkSpl);
        let result = converter.convert(&rule, &compiled);

        assert!(result.is_valid);
        assert!(result.query.contains("EventID") || result.query.contains("event_id"));
        assert!(result.query.contains("4625"));
    }

    #[test]
    fn test_eql_conversion() {
        let yaml = r#"
title: Process Creation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
level: low
"#;

        let (rule, compiled) = parse_and_compile(yaml);

        let converter = SigmaConverter::new(SigmaBackend::ElasticEql);
        let result = converter.convert(&rule, &compiled);

        assert!(result.is_valid);
        assert!(result.query.starts_with("process where"));
    }

    #[test]
    fn test_kql_conversion() {
        let yaml = r#"
title: PowerShell Command
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-Expression'
            - 'IEX'
    condition: selection
level: high
"#;

        let (rule, compiled) = parse_and_compile(yaml);

        let converter = SigmaConverter::new(SigmaBackend::ElasticKql);
        let result = converter.convert(&rule, &compiled);

        assert!(result.is_valid);
        assert!(result.query.contains("Invoke-Expression") || result.query.contains("IEX"));
    }

    #[test]
    fn test_qradar_conversion() {
        let yaml = r#"
title: SSH Login
logsource:
    product: linux
    service: sshd
detection:
    selection:
        message|contains: 'Failed password'
    condition: selection
level: low
"#;

        let (rule, compiled) = parse_and_compile(yaml);

        let converter = SigmaConverter::new(SigmaBackend::QRadarAql);
        let result = converter.convert(&rule, &compiled);

        assert!(result.is_valid);
        assert!(result.query.contains("SELECT * FROM events"));
        assert!(result.query.contains("Failed password"));
    }

    #[test]
    fn test_sentinel_conversion() {
        let yaml = r#"
title: Windows Security Event
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
    condition: selection
level: medium
"#;

        let (rule, compiled) = parse_and_compile(yaml);

        let converter = SigmaConverter::new(SigmaBackend::MicrosoftSentinel);
        let result = converter.convert(&rule, &compiled);

        assert!(result.is_valid);
        assert!(result.query.starts_with("SecurityEvent"));
        assert!(result.query.contains("EventID"));
    }

    #[test]
    fn test_backend_parsing() {
        assert_eq!("splunk".parse::<SigmaBackend>().unwrap(), SigmaBackend::SplunkSpl);
        assert_eq!("eql".parse::<SigmaBackend>().unwrap(), SigmaBackend::ElasticEql);
        assert_eq!("qradar".parse::<SigmaBackend>().unwrap(), SigmaBackend::QRadarAql);
        assert_eq!("sentinel".parse::<SigmaBackend>().unwrap(), SigmaBackend::MicrosoftSentinel);
    }

    #[test]
    fn test_convert_all_backends() {
        let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        EventID: 1234
    condition: selection
level: low
"#;

        let (rule, compiled) = parse_and_compile(yaml);
        let results = convert_to_all_backends(&rule, &compiled);

        assert_eq!(results.len(), 5);
        for result in &results {
            assert!(result.is_valid, "Backend {:?} failed: {:?}", result.backend, result.errors);
        }
    }
}
