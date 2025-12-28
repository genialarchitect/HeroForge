//! YARA Scanning Module for Blue Team Threat Detection
//!
//! This module provides YARA rule-based scanning capabilities for malware detection:
//! - File scanning with pattern matching
//! - Directory scanning (recursive)
//! - Byte buffer scanning for in-memory analysis
//! - Memory dump scanning (minidump, ELF core, raw)
//! - Custom rule compilation and validation
//! - Built-in rules for common malware families

#![allow(dead_code)]

pub mod rules;
pub mod memory_scanner;
pub mod file_monitor;
pub mod effectiveness;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::fs;
use walkdir::WalkDir;

// ============================================================================
// Core Types
// ============================================================================

/// Metadata associated with a YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleMetadata {
    pub author: Option<String>,
    pub description: Option<String>,
    pub reference: Option<String>,
    pub date: Option<String>,
    pub version: Option<String>,
    pub malware_family: Option<String>,
    pub severity: Option<String>,
    pub tlp: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

impl Default for YaraRuleMetadata {
    fn default() -> Self {
        Self {
            author: None,
            description: None,
            reference: None,
            date: None,
            version: None,
            malware_family: None,
            severity: None,
            tlp: None,
            extra: HashMap::new(),
        }
    }
}

/// A YARA string pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraString {
    pub identifier: String,
    pub value: StringValue,
    pub modifiers: Vec<StringModifier>,
}

/// Value type for YARA strings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum StringValue {
    Text(String),
    Hex(Vec<u8>),
    Regex(String),
}

/// Modifiers that can be applied to YARA strings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StringModifier {
    Nocase,
    Wide,
    Ascii,
    Fullword,
    Private,
    Xor,
    Base64,
    Base64Wide,
}

/// A YARA rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub name: String,
    pub metadata: YaraRuleMetadata,
    pub tags: Vec<String>,
    pub strings: Vec<YaraString>,
    pub condition: String,
    /// Whether this is a built-in rule
    pub is_builtin: bool,
}

impl YaraRule {
    /// Create a new YARA rule
    pub fn new(name: &str, condition: &str) -> Self {
        Self {
            name: name.to_string(),
            metadata: YaraRuleMetadata::default(),
            tags: Vec::new(),
            strings: Vec::new(),
            condition: condition.to_string(),
            is_builtin: false,
        }
    }

    /// Add a string pattern to the rule
    pub fn add_string(&mut self, identifier: &str, value: StringValue, modifiers: Vec<StringModifier>) {
        self.strings.push(YaraString {
            identifier: identifier.to_string(),
            value,
            modifiers,
        });
    }

    /// Add metadata to the rule
    pub fn with_metadata(mut self, metadata: YaraRuleMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Add tags to the rule
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Generate YARA rule text from the struct
    pub fn to_yara_text(&self) -> String {
        let mut output = String::new();

        // Rule header with tags
        if self.tags.is_empty() {
            output.push_str(&format!("rule {} {{\n", self.name));
        } else {
            output.push_str(&format!("rule {} : {} {{\n", self.name, self.tags.join(" ")));
        }

        // Metadata section
        if self.has_metadata() {
            output.push_str("    meta:\n");
            if let Some(ref author) = self.metadata.author {
                output.push_str(&format!("        author = \"{}\"\n", escape_string(author)));
            }
            if let Some(ref desc) = self.metadata.description {
                output.push_str(&format!("        description = \"{}\"\n", escape_string(desc)));
            }
            if let Some(ref reference) = self.metadata.reference {
                output.push_str(&format!("        reference = \"{}\"\n", escape_string(reference)));
            }
            if let Some(ref date) = self.metadata.date {
                output.push_str(&format!("        date = \"{}\"\n", escape_string(date)));
            }
            if let Some(ref version) = self.metadata.version {
                output.push_str(&format!("        version = \"{}\"\n", escape_string(version)));
            }
            if let Some(ref family) = self.metadata.malware_family {
                output.push_str(&format!("        malware_family = \"{}\"\n", escape_string(family)));
            }
            if let Some(ref severity) = self.metadata.severity {
                output.push_str(&format!("        severity = \"{}\"\n", escape_string(severity)));
            }
            for (key, value) in &self.metadata.extra {
                output.push_str(&format!("        {} = \"{}\"\n", key, escape_string(value)));
            }
        }

        // Strings section
        if !self.strings.is_empty() {
            output.push_str("    strings:\n");
            for s in &self.strings {
                let value_str = match &s.value {
                    StringValue::Text(t) => format!("\"{}\"", escape_string(t)),
                    StringValue::Hex(h) => format!("{{ {} }}", hex::encode(h).to_uppercase()
                        .chars()
                        .collect::<Vec<_>>()
                        .chunks(2)
                        .map(|c| c.iter().collect::<String>())
                        .collect::<Vec<_>>()
                        .join(" ")),
                    StringValue::Regex(r) => format!("/{}/", r),
                };

                let modifiers_str: Vec<&str> = s.modifiers.iter().map(|m| match m {
                    StringModifier::Nocase => "nocase",
                    StringModifier::Wide => "wide",
                    StringModifier::Ascii => "ascii",
                    StringModifier::Fullword => "fullword",
                    StringModifier::Private => "private",
                    StringModifier::Xor => "xor",
                    StringModifier::Base64 => "base64",
                    StringModifier::Base64Wide => "base64wide",
                }).collect();

                if modifiers_str.is_empty() {
                    output.push_str(&format!("        {} = {}\n", s.identifier, value_str));
                } else {
                    output.push_str(&format!("        {} = {} {}\n", s.identifier, value_str, modifiers_str.join(" ")));
                }
            }
        }

        // Condition section
        output.push_str("    condition:\n");
        output.push_str(&format!("        {}\n", self.condition));

        output.push_str("}\n");
        output
    }

    fn has_metadata(&self) -> bool {
        self.metadata.author.is_some()
            || self.metadata.description.is_some()
            || self.metadata.reference.is_some()
            || self.metadata.date.is_some()
            || self.metadata.version.is_some()
            || self.metadata.malware_family.is_some()
            || self.metadata.severity.is_some()
            || !self.metadata.extra.is_empty()
    }
}

/// Escape special characters in a string for YARA
fn escape_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Information about a matched string within a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedString {
    pub identifier: String,
    pub offset: u64,
    pub length: usize,
    pub data: String,
}

/// A YARA rule match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub file_path: Option<String>,
    pub matched_strings: Vec<MatchedString>,
    pub metadata: YaraRuleMetadata,
    pub tags: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

/// Statistics for a YARA scan operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanStats {
    pub files_scanned: u64,
    pub files_matched: u64,
    pub files_skipped: u64,
    pub files_errored: u64,
    pub bytes_scanned: u64,
    pub rules_loaded: usize,
}

impl Default for YaraScanStats {
    fn default() -> Self {
        Self {
            files_scanned: 0,
            files_matched: 0,
            files_skipped: 0,
            files_errored: 0,
            bytes_scanned: 0,
            rules_loaded: 0,
        }
    }
}

/// Result of a YARA scan operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanResult {
    pub matches: Vec<YaraMatch>,
    pub scan_time: Duration,
    pub stats: YaraScanStats,
    pub errors: Vec<String>,
}

// ============================================================================
// Compiled Rules
// ============================================================================

/// Compiled YARA rules ready for matching
#[derive(Debug, Clone)]
pub struct CompiledRules {
    rules: Vec<CompiledRule>,
    compile_time: Duration,
}

/// A single compiled rule with pre-compiled patterns
#[derive(Debug, Clone)]
struct CompiledRule {
    name: String,
    metadata: YaraRuleMetadata,
    tags: Vec<String>,
    patterns: Vec<CompiledPattern>,
    condition: ConditionExpr,
}

/// A compiled pattern for matching
#[derive(Debug, Clone)]
struct CompiledPattern {
    identifier: String,
    matcher: PatternMatcher,
}

/// Pattern matching strategy
#[derive(Debug, Clone)]
enum PatternMatcher {
    Literal(Vec<u8>, bool), // bytes, case_insensitive
    Regex(String),
    Hex(Vec<u8>),
}

/// Parsed condition expression
#[derive(Debug, Clone)]
enum ConditionExpr {
    All,                              // all of them
    Any,                              // any of them
    Count(u32),                       // N of them
    AtLeast(u32),                     // at least N of them
    StringRef(String),                // $string_name
    And(Box<ConditionExpr>, Box<ConditionExpr>),
    Or(Box<ConditionExpr>, Box<ConditionExpr>),
    Not(Box<ConditionExpr>),
    True,
    False,
    FileSize(FileSizeCondition),
}

#[derive(Debug, Clone)]
enum FileSizeCondition {
    LessThan(u64),
    GreaterThan(u64),
    Equals(u64),
}

impl CompiledRules {
    /// Get the number of rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get compilation time
    pub fn compile_time(&self) -> Duration {
        self.compile_time
    }
}

// ============================================================================
// YARA Scanner
// ============================================================================

/// YARA Scanner for file and memory scanning
pub struct YaraScanner {
    rules: Vec<YaraRule>,
    compiled: Option<CompiledRules>,
    max_file_size: u64,
    timeout: Duration,
}

impl Default for YaraScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl YaraScanner {
    /// Create a new YARA scanner
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            compiled: None,
            max_file_size: 100 * 1024 * 1024, // 100 MB default
            timeout: Duration::from_secs(60),
        }
    }

    /// Create a scanner with built-in rules
    pub fn with_builtin_rules() -> Self {
        let mut scanner = Self::new();
        scanner.rules = rules::get_builtin_rules();
        scanner
    }

    /// Set maximum file size to scan
    pub fn set_max_file_size(&mut self, size: u64) {
        self.max_file_size = size;
    }

    /// Set scan timeout
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Add a rule to the scanner
    pub fn add_rule(&mut self, rule: YaraRule) {
        self.rules.push(rule);
        self.compiled = None; // Invalidate compiled rules
    }

    /// Add multiple rules
    pub fn add_rules(&mut self, rules: Vec<YaraRule>) {
        self.rules.extend(rules);
        self.compiled = None;
    }

    /// Get all loaded rules
    pub fn get_rules(&self) -> &[YaraRule] {
        &self.rules
    }

    /// Compile all loaded rules
    pub fn compile(&mut self) -> Result<()> {
        let start = Instant::now();
        let mut compiled_rules = Vec::new();

        for rule in &self.rules {
            let compiled = compile_single_rule(rule)?;
            compiled_rules.push(compiled);
        }

        self.compiled = Some(CompiledRules {
            rules: compiled_rules,
            compile_time: start.elapsed(),
        });

        Ok(())
    }

    /// Scan a file with loaded rules
    pub async fn scan_file(&mut self, path: &str) -> Result<Vec<YaraMatch>> {
        // Compile if needed
        if self.compiled.is_none() {
            self.compile()?;
        }

        let path = Path::new(path);
        if !path.exists() {
            return Err(anyhow!("File not found: {}", path.display()));
        }

        let metadata = fs::metadata(path).await?;
        if metadata.len() > self.max_file_size {
            return Err(anyhow!(
                "File too large: {} bytes (max: {} bytes)",
                metadata.len(),
                self.max_file_size
            ));
        }

        let data = fs::read(path).await?;
        let matches = self.scan_bytes_internal(&data, Some(path.to_string_lossy().to_string()))?;

        Ok(matches)
    }

    /// Scan a directory with loaded rules
    pub async fn scan_directory(
        &mut self,
        path: &str,
        recursive: bool,
    ) -> Result<YaraScanResult> {
        let start = Instant::now();
        let mut stats = YaraScanStats::default();
        let mut all_matches = Vec::new();
        let mut errors = Vec::new();

        // Compile if needed
        if self.compiled.is_none() {
            self.compile()?;
        }

        stats.rules_loaded = self.compiled.as_ref().map(|c| c.rule_count()).unwrap_or(0);

        let walker = if recursive {
            WalkDir::new(path).follow_links(false)
        } else {
            WalkDir::new(path).max_depth(1).follow_links(false)
        };

        for entry in walker {
            match entry {
                Ok(entry) => {
                    if entry.file_type().is_file() {
                        let file_path = entry.path();

                        // Check file size
                        match fs::metadata(file_path).await {
                            Ok(metadata) => {
                                if metadata.len() > self.max_file_size {
                                    stats.files_skipped += 1;
                                    continue;
                                }
                                stats.bytes_scanned += metadata.len();
                            }
                            Err(e) => {
                                errors.push(format!("Failed to read metadata for {}: {}", file_path.display(), e));
                                stats.files_errored += 1;
                                continue;
                            }
                        }

                        // Read and scan file
                        match fs::read(file_path).await {
                            Ok(data) => {
                                stats.files_scanned += 1;
                                match self.scan_bytes_internal(&data, Some(file_path.to_string_lossy().to_string())) {
                                    Ok(matches) => {
                                        if !matches.is_empty() {
                                            stats.files_matched += 1;
                                            all_matches.extend(matches);
                                        }
                                    }
                                    Err(e) => {
                                        errors.push(format!("Failed to scan {}: {}", file_path.display(), e));
                                        stats.files_errored += 1;
                                    }
                                }
                            }
                            Err(e) => {
                                errors.push(format!("Failed to read {}: {}", file_path.display(), e));
                                stats.files_errored += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    errors.push(format!("Directory walk error: {}", e));
                }
            }
        }

        Ok(YaraScanResult {
            matches: all_matches,
            scan_time: start.elapsed(),
            stats,
            errors,
        })
    }

    /// Scan raw bytes with loaded rules
    pub async fn scan_bytes(&mut self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        // Compile if needed
        if self.compiled.is_none() {
            self.compile()?;
        }

        self.scan_bytes_internal(data, None)
    }

    /// Internal byte scanning implementation
    fn scan_bytes_internal(&self, data: &[u8], file_path: Option<String>) -> Result<Vec<YaraMatch>> {
        let compiled = self.compiled.as_ref()
            .ok_or_else(|| anyhow!("Rules not compiled"))?;

        let mut matches = Vec::new();

        for rule in &compiled.rules {
            // Find all pattern matches
            let mut pattern_matches: HashMap<String, Vec<MatchedString>> = HashMap::new();

            for pattern in &rule.patterns {
                let found = find_pattern_matches(data, pattern);
                if !found.is_empty() {
                    pattern_matches.insert(pattern.identifier.clone(), found);
                }
            }

            // Evaluate condition
            if evaluate_condition(&rule.condition, &pattern_matches, data.len() as u64) {
                let all_matched_strings: Vec<MatchedString> = pattern_matches
                    .values()
                    .flatten()
                    .cloned()
                    .collect();

                matches.push(YaraMatch {
                    rule_name: rule.name.clone(),
                    file_path: file_path.clone(),
                    matched_strings: all_matched_strings,
                    metadata: rule.metadata.clone(),
                    tags: rule.tags.clone(),
                    timestamp: Utc::now(),
                });
            }
        }

        Ok(matches)
    }
}

// ============================================================================
// Rule Compilation
// ============================================================================

/// Compile a single YARA rule
fn compile_single_rule(rule: &YaraRule) -> Result<CompiledRule> {
    let mut patterns = Vec::new();

    for s in &rule.strings {
        let matcher = match &s.value {
            StringValue::Text(text) => {
                let case_insensitive = s.modifiers.contains(&StringModifier::Nocase);
                let bytes = if s.modifiers.contains(&StringModifier::Wide) {
                    // Convert to wide string (UTF-16 LE)
                    text.encode_utf16()
                        .flat_map(|c| c.to_le_bytes())
                        .collect()
                } else {
                    text.as_bytes().to_vec()
                };
                PatternMatcher::Literal(bytes, case_insensitive)
            }
            StringValue::Hex(bytes) => {
                PatternMatcher::Hex(bytes.clone())
            }
            StringValue::Regex(pattern) => {
                // Validate regex
                let _ = Regex::new(pattern)?;
                PatternMatcher::Regex(pattern.clone())
            }
        };

        patterns.push(CompiledPattern {
            identifier: s.identifier.clone(),
            matcher,
        });
    }

    let condition = parse_condition(&rule.condition)?;

    Ok(CompiledRule {
        name: rule.name.clone(),
        metadata: rule.metadata.clone(),
        tags: rule.tags.clone(),
        patterns,
        condition,
    })
}

/// Parse a condition expression
fn parse_condition(condition: &str) -> Result<ConditionExpr> {
    let condition = condition.trim();

    // Handle "all of them"
    if condition == "all of them" {
        return Ok(ConditionExpr::All);
    }

    // Handle "any of them"
    if condition == "any of them" {
        return Ok(ConditionExpr::Any);
    }

    // Handle "N of them"
    if let Some(captures) = Regex::new(r"^(\d+)\s+of\s+them$")?.captures(condition) {
        let count: u32 = captures.get(1).unwrap().as_str().parse()?;
        return Ok(ConditionExpr::Count(count));
    }

    // Handle "true" and "false"
    if condition == "true" {
        return Ok(ConditionExpr::True);
    }
    if condition == "false" {
        return Ok(ConditionExpr::False);
    }

    // Handle "$string_name"
    if condition.starts_with('$') {
        return Ok(ConditionExpr::StringRef(condition.to_string()));
    }

    // Handle file size conditions
    if condition.starts_with("filesize") {
        if let Some(captures) = Regex::new(r"filesize\s*(<|>|==)\s*(\d+)(?:KB|MB|GB)?")?.captures(condition) {
            let op = captures.get(1).unwrap().as_str();
            let mut size: u64 = captures.get(2).unwrap().as_str().parse()?;

            // Handle size suffixes
            if condition.contains("KB") {
                size *= 1024;
            } else if condition.contains("MB") {
                size *= 1024 * 1024;
            } else if condition.contains("GB") {
                size *= 1024 * 1024 * 1024;
            }

            return Ok(ConditionExpr::FileSize(match op {
                "<" => FileSizeCondition::LessThan(size),
                ">" => FileSizeCondition::GreaterThan(size),
                "==" => FileSizeCondition::Equals(size),
                _ => return Err(anyhow!("Invalid filesize operator: {}", op)),
            }));
        }
    }

    // Handle "and" expressions
    if let Some(idx) = condition.find(" and ") {
        let left = parse_condition(&condition[..idx])?;
        let right = parse_condition(&condition[idx + 5..])?;
        return Ok(ConditionExpr::And(Box::new(left), Box::new(right)));
    }

    // Handle "or" expressions
    if let Some(idx) = condition.find(" or ") {
        let left = parse_condition(&condition[..idx])?;
        let right = parse_condition(&condition[idx + 4..])?;
        return Ok(ConditionExpr::Or(Box::new(left), Box::new(right)));
    }

    // Handle "not" expressions
    if condition.starts_with("not ") {
        let inner = parse_condition(&condition[4..])?;
        return Ok(ConditionExpr::Not(Box::new(inner)));
    }

    // Default: treat as any of them for simple conditions
    Ok(ConditionExpr::Any)
}

// ============================================================================
// Pattern Matching
// ============================================================================

/// Find all matches of a pattern in the data
fn find_pattern_matches(data: &[u8], pattern: &CompiledPattern) -> Vec<MatchedString> {
    let mut matches = Vec::new();

    match &pattern.matcher {
        PatternMatcher::Literal(bytes, case_insensitive) => {
            if *case_insensitive {
                // Case-insensitive search
                let lower_pattern: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
                let lower_data: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();

                for (offset, _) in lower_data.windows(lower_pattern.len())
                    .enumerate()
                    .filter(|(_, window)| *window == lower_pattern.as_slice())
                {
                    let matched_data = &data[offset..offset + bytes.len()];
                    matches.push(MatchedString {
                        identifier: pattern.identifier.clone(),
                        offset: offset as u64,
                        length: bytes.len(),
                        data: String::from_utf8_lossy(matched_data).to_string(),
                    });
                }
            } else {
                // Exact match
                for (offset, _) in data.windows(bytes.len())
                    .enumerate()
                    .filter(|(_, window)| *window == bytes.as_slice())
                {
                    matches.push(MatchedString {
                        identifier: pattern.identifier.clone(),
                        offset: offset as u64,
                        length: bytes.len(),
                        data: String::from_utf8_lossy(&data[offset..offset + bytes.len()]).to_string(),
                    });
                }
            }
        }
        PatternMatcher::Hex(bytes) => {
            for (offset, _) in data.windows(bytes.len())
                .enumerate()
                .filter(|(_, window)| *window == bytes.as_slice())
            {
                matches.push(MatchedString {
                    identifier: pattern.identifier.clone(),
                    offset: offset as u64,
                    length: bytes.len(),
                    data: hex::encode(&data[offset..offset + bytes.len()]),
                });
            }
        }
        PatternMatcher::Regex(pattern_str) => {
            if let Ok(regex) = Regex::new(pattern_str) {
                // Convert data to string for regex matching
                let text = String::from_utf8_lossy(data);
                for m in regex.find_iter(&text) {
                    matches.push(MatchedString {
                        identifier: pattern.identifier.clone(),
                        offset: m.start() as u64,
                        length: m.len(),
                        data: m.as_str().to_string(),
                    });
                }
            }
        }
    }

    matches
}

/// Evaluate a condition expression against pattern matches
fn evaluate_condition(
    condition: &ConditionExpr,
    pattern_matches: &HashMap<String, Vec<MatchedString>>,
    file_size: u64,
) -> bool {
    match condition {
        ConditionExpr::All => {
            // All patterns must match at least once
            !pattern_matches.is_empty() && pattern_matches.values().all(|m| !m.is_empty())
        }
        ConditionExpr::Any => {
            // At least one pattern must match
            pattern_matches.values().any(|m| !m.is_empty())
        }
        ConditionExpr::Count(n) => {
            // Exactly N patterns must match
            let matched_count = pattern_matches.values().filter(|m| !m.is_empty()).count() as u32;
            matched_count == *n
        }
        ConditionExpr::AtLeast(n) => {
            // At least N patterns must match
            let matched_count = pattern_matches.values().filter(|m| !m.is_empty()).count() as u32;
            matched_count >= *n
        }
        ConditionExpr::StringRef(name) => {
            // Check if the specific string matched
            let name = name.trim_start_matches('$');
            pattern_matches.get(name).map(|m| !m.is_empty()).unwrap_or(false)
        }
        ConditionExpr::And(left, right) => {
            evaluate_condition(left, pattern_matches, file_size)
                && evaluate_condition(right, pattern_matches, file_size)
        }
        ConditionExpr::Or(left, right) => {
            evaluate_condition(left, pattern_matches, file_size)
                || evaluate_condition(right, pattern_matches, file_size)
        }
        ConditionExpr::Not(inner) => {
            !evaluate_condition(inner, pattern_matches, file_size)
        }
        ConditionExpr::True => true,
        ConditionExpr::False => false,
        ConditionExpr::FileSize(cond) => match cond {
            FileSizeCondition::LessThan(size) => file_size < *size,
            FileSizeCondition::GreaterThan(size) => file_size > *size,
            FileSizeCondition::Equals(size) => file_size == *size,
        },
    }
}

// ============================================================================
// Rule Validation
// ============================================================================

/// Validation result for a YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Validate YARA rule syntax
pub fn validate_rule(rule_text: &str) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Check for rule keyword
    if !rule_text.contains("rule ") {
        errors.push("Missing 'rule' keyword".to_string());
    }

    // Check for condition section
    if !rule_text.contains("condition:") {
        errors.push("Missing 'condition:' section".to_string());
    }

    // Check for balanced braces
    let open_braces = rule_text.matches('{').count();
    let close_braces = rule_text.matches('}').count();
    if open_braces != close_braces {
        errors.push(format!(
            "Unbalanced braces: {} opening, {} closing",
            open_braces, close_braces
        ));
    }

    // Try to parse the rule
    if let Err(e) = parse_yara_rule_text(rule_text) {
        errors.push(format!("Parse error: {}", e));
    }

    // Check for common issues
    if rule_text.contains("strings:") && !rule_text.contains('$') {
        warnings.push("Strings section defined but no string identifiers found".to_string());
    }

    ValidationResult {
        valid: errors.is_empty(),
        errors,
        warnings,
    }
}

/// Parse YARA rule text into a YaraRule struct
pub fn parse_yara_rule_text(rule_text: &str) -> Result<YaraRule> {
    // Extract rule name
    let rule_regex = Regex::new(r"rule\s+(\w+)\s*(?::\s*([\w\s]+))?\s*\{")?;
    let captures = rule_regex
        .captures(rule_text)
        .ok_or_else(|| anyhow!("Invalid rule format: could not find rule declaration"))?;

    let name = captures.get(1).unwrap().as_str().to_string();
    let tags: Vec<String> = captures
        .get(2)
        .map(|m| m.as_str().split_whitespace().map(|s| s.to_string()).collect())
        .unwrap_or_default();

    // Extract metadata
    let mut metadata = YaraRuleMetadata::default();
    let meta_regex = Regex::new(r"meta:\s*([\s\S]*?)(?:strings:|condition:)")?;
    if let Some(meta_captures) = meta_regex.captures(rule_text) {
        let meta_section = meta_captures.get(1).unwrap().as_str();
        let meta_line_regex = Regex::new(r#"(\w+)\s*=\s*"([^"]*)""#)?;
        for cap in meta_line_regex.captures_iter(meta_section) {
            let key = cap.get(1).unwrap().as_str();
            let value = cap.get(2).unwrap().as_str().to_string();
            match key {
                "author" => metadata.author = Some(value),
                "description" => metadata.description = Some(value),
                "reference" => metadata.reference = Some(value),
                "date" => metadata.date = Some(value),
                "version" => metadata.version = Some(value),
                "malware_family" => metadata.malware_family = Some(value),
                "severity" => metadata.severity = Some(value),
                "tlp" => metadata.tlp = Some(value),
                _ => { metadata.extra.insert(key.to_string(), value); }
            }
        }
    }

    // Extract strings
    let mut strings = Vec::new();
    let strings_regex = Regex::new(r"strings:\s*([\s\S]*?)condition:")?;
    if let Some(str_captures) = strings_regex.captures(rule_text) {
        let strings_section = str_captures.get(1).unwrap().as_str();

        // Parse text strings
        let text_string_regex = Regex::new(r#"\$(\w+)\s*=\s*"([^"]*)"(\s+(?:nocase|wide|ascii|fullword))*"#)?;
        for cap in text_string_regex.captures_iter(strings_section) {
            let identifier = format!("${}", cap.get(1).unwrap().as_str());
            let value = cap.get(2).unwrap().as_str().to_string();
            let modifiers_str = cap.get(3).map(|m| m.as_str()).unwrap_or("");

            let mut modifiers = Vec::new();
            if modifiers_str.contains("nocase") {
                modifiers.push(StringModifier::Nocase);
            }
            if modifiers_str.contains("wide") {
                modifiers.push(StringModifier::Wide);
            }
            if modifiers_str.contains("ascii") {
                modifiers.push(StringModifier::Ascii);
            }
            if modifiers_str.contains("fullword") {
                modifiers.push(StringModifier::Fullword);
            }

            strings.push(YaraString {
                identifier,
                value: StringValue::Text(value),
                modifiers,
            });
        }

        // Parse hex strings
        let hex_string_regex = Regex::new(r"\$(\w+)\s*=\s*\{\s*([0-9A-Fa-f\s?]+)\s*\}")?;
        for cap in hex_string_regex.captures_iter(strings_section) {
            let identifier = format!("${}", cap.get(1).unwrap().as_str());
            let hex_str: String = cap.get(2).unwrap().as_str()
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect();

            if let Ok(bytes) = hex::decode(&hex_str) {
                strings.push(YaraString {
                    identifier,
                    value: StringValue::Hex(bytes),
                    modifiers: Vec::new(),
                });
            }
        }
    }

    // Extract condition
    let condition_regex = Regex::new(r"condition:\s*([\s\S]*?)\}")?;
    let condition = condition_regex
        .captures(rule_text)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_else(|| "any of them".to_string());

    Ok(YaraRule {
        name,
        metadata,
        tags,
        strings,
        condition,
        is_builtin: false,
    })
}

/// Compile multiple rules from text
pub fn compile_rules(rule_text: &str) -> Result<CompiledRules> {
    let start = Instant::now();
    let mut compiled_rules = Vec::new();

    // Split by "rule " to handle multiple rules
    let rule_regex = Regex::new(r"rule\s+\w+[\s\S]*?\n\}")?;
    for cap in rule_regex.find_iter(rule_text) {
        let rule_str = cap.as_str();
        let rule = parse_yara_rule_text(rule_str)?;
        let compiled = compile_single_rule(&rule)?;
        compiled_rules.push(compiled);
    }

    if compiled_rules.is_empty() {
        return Err(anyhow!("No valid rules found in input"));
    }

    Ok(CompiledRules {
        rules: compiled_rules,
        compile_time: start.elapsed(),
    })
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Scan a file with the provided rules
pub async fn scan_file(path: &str, rules: &[YaraRule]) -> Result<Vec<YaraMatch>> {
    let mut scanner = YaraScanner::new();
    scanner.add_rules(rules.to_vec());
    scanner.scan_file(path).await
}

/// Scan a directory with the provided rules
pub async fn scan_directory(path: &str, rules: &[YaraRule], recursive: bool) -> Result<YaraScanResult> {
    let mut scanner = YaraScanner::new();
    scanner.add_rules(rules.to_vec());
    scanner.scan_directory(path, recursive).await
}

/// Scan bytes with the provided rules
pub async fn scan_bytes(data: &[u8], rules: &[YaraRule]) -> Result<Vec<YaraMatch>> {
    let mut scanner = YaraScanner::new();
    scanner.add_rules(rules.to_vec());
    scanner.scan_bytes(data).await
}

/// Scan a memory dump file with the provided rules
pub async fn scan_memory_dump(path: &str, rules: Vec<YaraRule>) -> Result<memory_scanner::MemoryScanResult> {
    let mut scanner = memory_scanner::MemoryScanner::new();
    scanner.load_rules(rules)?;
    scanner.scan_file(path).await
}

/// Scan memory bytes with the provided rules
pub async fn scan_memory_bytes(data: &[u8], rules: Vec<YaraRule>) -> Result<memory_scanner::MemoryScanResult> {
    let mut scanner = memory_scanner::MemoryScanner::new();
    scanner.load_rules(rules)?;
    scanner.scan_bytes(data).await
}

// Re-export memory scanner types
pub use memory_scanner::{
    MemoryScanner, MemoryScanResult, MemoryScanOptions,
    MemoryRegion, MemoryProtection, MemoryState, MemoryType,
    MemoryDumpFormat, MemoryYaraMatch, MemoryMatchedString,
};

// Re-export file monitor types
pub use file_monitor::{
    FileMonitor, FileMonitorConfig, FileMonitorStats, FileMonitorAlert,
    MonitorManager, MonitorStatus, FileEventType, AlertSeverity,
};

// Re-export effectiveness types
pub use effectiveness::{
    EffectivenessCalculator, EffectivenessTracker, EffectivenessConfig,
    RuleEffectivenessScore, RuleMatchStats, EffectivenessGrade,
    MatchEvent, VerificationStatus, EffectivenessDataPoint, EffectivenessSummary,
};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_to_yara_text() {
        let mut rule = YaraRule::new("TestRule", "any of them");
        rule.add_string(
            "$a",
            StringValue::Text("malware".to_string()),
            vec![StringModifier::Nocase],
        );

        let text = rule.to_yara_text();
        assert!(text.contains("rule TestRule"));
        assert!(text.contains("$a = \"malware\" nocase"));
        assert!(text.contains("any of them"));
    }

    #[test]
    fn test_validate_rule() {
        let valid_rule = r#"
rule TestRule {
    strings:
        $a = "test"
    condition:
        any of them
}
"#;
        let result = validate_rule(valid_rule);
        assert!(result.valid);

        let invalid_rule = "not a valid rule";
        let result = validate_rule(invalid_rule);
        assert!(!result.valid);
    }

    #[test]
    fn test_parse_yara_rule_text() {
        let rule_text = r#"
rule TestRule : malware suspicious {
    meta:
        author = "Test"
        description = "A test rule"
    strings:
        $a = "malware" nocase
        $b = { 4D 5A 90 00 }
    condition:
        any of them
}
"#;
        let rule = parse_yara_rule_text(rule_text).unwrap();
        assert_eq!(rule.name, "TestRule");
        assert_eq!(rule.tags, vec!["malware", "suspicious"]);
        assert_eq!(rule.metadata.author, Some("Test".to_string()));
        assert_eq!(rule.strings.len(), 2);
    }

    #[tokio::test]
    async fn test_scan_bytes() {
        let mut rule = YaraRule::new("FindMalware", "any of them");
        rule.add_string(
            "$a",
            StringValue::Text("MALWARE".to_string()),
            vec![StringModifier::Nocase],
        );

        let mut scanner = YaraScanner::new();
        scanner.add_rule(rule);

        let data = b"This is a test with malware string";
        let matches = scanner.scan_bytes(data).await.unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "FindMalware");
    }
}
