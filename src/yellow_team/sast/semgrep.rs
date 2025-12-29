//! Semgrep Rule Integration
//!
//! Provides parsing and execution of Semgrep rules for SAST scanning.
//! Supports both importing community Semgrep rules and custom rule creation.

use crate::yellow_team::types::*;
use anyhow::{anyhow, Result};
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Semgrep rule as parsed from YAML
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SemgrepRule {
    pub id: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub metadata: Option<SemgrepMetadata>,
    #[serde(flatten)]
    pub pattern_spec: SemgrepPatternSpec,
}

/// Semgrep pattern specification (supports multiple pattern types)
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SemgrepPatternSpec {
    pub pattern: Option<String>,
    pub patterns: Option<Vec<SemgrepPatternItem>>,
    #[serde(rename = "pattern-either")]
    pub pattern_either: Option<Vec<SemgrepPatternItem>>,
    #[serde(rename = "pattern-regex")]
    pub pattern_regex: Option<String>,
}

/// Individual pattern item for complex patterns
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SemgrepPatternItem {
    pub pattern: Option<String>,
    #[serde(rename = "pattern-not")]
    pub pattern_not: Option<String>,
    #[serde(rename = "pattern-inside")]
    pub pattern_inside: Option<String>,
    #[serde(rename = "pattern-not-inside")]
    pub pattern_not_inside: Option<String>,
    #[serde(rename = "pattern-regex")]
    pub pattern_regex: Option<String>,
    #[serde(rename = "pattern-either")]
    pub pattern_either: Option<Vec<SemgrepPatternItem>>,
    #[serde(rename = "metavariable-regex")]
    pub metavariable_regex: Option<MetavariableRegex>,
    #[serde(rename = "metavariable-pattern")]
    pub metavariable_pattern: Option<MetavariablePattern>,
    #[serde(rename = "metavariable-comparison")]
    pub metavariable_comparison: Option<MetavariableComparison>,
    pub focus: Option<String>,
}

/// Metavariable regex constraint
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetavariableRegex {
    pub metavariable: String,
    pub regex: String,
}

/// Metavariable pattern constraint
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetavariablePattern {
    pub metavariable: String,
    pub pattern: Option<String>,
    pub patterns: Option<Vec<SemgrepPatternItem>>,
}

/// Metavariable comparison constraint
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetavariableComparison {
    pub metavariable: String,
    pub comparison: String,
}

/// Semgrep rule metadata
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SemgrepMetadata {
    pub category: Option<String>,
    pub technology: Option<Vec<String>>,
    pub cwe: Option<Vec<String>>,
    pub owasp: Option<Vec<String>>,
    pub confidence: Option<String>,
    pub likelihood: Option<String>,
    pub impact: Option<String>,
    pub subcategory: Option<Vec<String>>,
    pub references: Option<Vec<String>>,
    pub source: Option<String>,
}

/// Semgrep rules file (can contain multiple rules)
#[derive(Debug, Clone, Deserialize)]
pub struct SemgrepRulesFile {
    pub rules: Vec<SemgrepRule>,
}

/// Semgrep rule source for syncing community rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemgrepRuleSource {
    pub id: String,
    pub name: String,
    pub source_type: SemgrepSourceType,
    pub url: String,
    pub branch: Option<String>,
    pub path_filter: Option<String>,
    pub enabled: bool,
    pub last_sync: Option<chrono::DateTime<Utc>>,
    pub rules_count: u32,
}

/// Type of Semgrep rule source
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SemgrepSourceType {
    GitHub,
    GitLab,
    Local,
    Url,
    Registry,
}

/// Result of parsing a Semgrep rule
#[derive(Debug, Clone)]
pub struct ParsedSemgrepRule {
    pub original: SemgrepRule,
    pub converted: SastRule,
    pub effective_pattern: String,
    pub negation_patterns: Vec<String>,
    pub context_patterns: Vec<String>,
}

/// Semgrep rule parser and converter
pub struct SemgrepParser {
    /// Built-in rule sources
    builtin_sources: Vec<SemgrepRuleSource>,
}

impl SemgrepParser {
    pub fn new() -> Self {
        Self {
            builtin_sources: Self::get_builtin_sources(),
        }
    }

    /// Get built-in Semgrep rule sources
    fn get_builtin_sources() -> Vec<SemgrepRuleSource> {
        vec![
            SemgrepRuleSource {
                id: "semgrep-rules".to_string(),
                name: "Official Semgrep Rules".to_string(),
                source_type: SemgrepSourceType::GitHub,
                url: "https://github.com/semgrep/semgrep-rules".to_string(),
                branch: Some("main".to_string()),
                path_filter: None,
                enabled: true,
                last_sync: None,
                rules_count: 0,
            },
            SemgrepRuleSource {
                id: "trailofbits".to_string(),
                name: "Trail of Bits Rules".to_string(),
                source_type: SemgrepSourceType::GitHub,
                url: "https://github.com/trailofbits/semgrep-rules".to_string(),
                branch: Some("main".to_string()),
                path_filter: None,
                enabled: true,
                last_sync: None,
                rules_count: 0,
            },
            SemgrepRuleSource {
                id: "returntocorp".to_string(),
                name: "Return to Corp Rules".to_string(),
                source_type: SemgrepSourceType::GitHub,
                url: "https://github.com/returntocorp/semgrep-rules".to_string(),
                branch: Some("develop".to_string()),
                path_filter: None,
                enabled: false, // Disabled by default (duplicate of official)
                last_sync: None,
                rules_count: 0,
            },
        ]
    }

    /// Parse a Semgrep YAML file
    pub fn parse_yaml(&self, yaml_content: &str) -> Result<Vec<ParsedSemgrepRule>> {
        // Try parsing as a rules file first
        let rules_file: Result<SemgrepRulesFile, _> = serde_yaml::from_str(yaml_content);

        let rules = match rules_file {
            Ok(file) => file.rules,
            Err(_) => {
                // Try parsing as a single rule
                let single_rule: SemgrepRule = serde_yaml::from_str(yaml_content)?;
                vec![single_rule]
            }
        };

        rules.into_iter().map(|r| self.convert_rule(r)).collect()
    }

    /// Convert a Semgrep rule to HeroForge's internal format
    fn convert_rule(&self, rule: SemgrepRule) -> Result<ParsedSemgrepRule> {
        // Extract the effective pattern
        let (effective_pattern, negation_patterns, context_patterns) = self.extract_patterns(&rule.pattern_spec)?;

        // Determine language
        let language = self.map_language(&rule.languages);

        // Determine severity
        let severity = self.map_severity(&rule.severity);

        // Determine category
        let category = self.map_category(&rule.metadata);

        // Extract CWE
        let cwe_id = rule.metadata.as_ref()
            .and_then(|m| m.cwe.as_ref())
            .and_then(|cwes| cwes.first())
            .cloned();

        // Build remediation guidance from references
        let remediation_guidance = rule.metadata.as_ref()
            .and_then(|m| m.references.as_ref())
            .map(|refs| format!("References: {}", refs.join(", ")));

        let converted = SastRule {
            id: format!("SEMGREP-{}", rule.id),
            name: rule.id.clone(),
            description: rule.message.clone(),
            language,
            severity,
            category,
            pattern: effective_pattern.clone(),
            pattern_type: if rule.pattern_spec.pattern_regex.is_some() {
                PatternType::Regex
            } else {
                PatternType::Semantic
            },
            cwe_id,
            remediation_guidance,
            enabled: true,
            custom: false,
            created_by: None,
            created_at: Utc::now(),
        };

        Ok(ParsedSemgrepRule {
            original: rule,
            converted,
            effective_pattern,
            negation_patterns,
            context_patterns,
        })
    }

    /// Extract patterns from a Semgrep pattern specification
    fn extract_patterns(&self, spec: &SemgrepPatternSpec) -> Result<(String, Vec<String>, Vec<String>)> {
        let mut effective_pattern = String::new();
        let mut negation_patterns = Vec::new();
        let mut context_patterns = Vec::new();

        // Simple pattern
        if let Some(ref pattern) = spec.pattern {
            effective_pattern = self.semgrep_to_regex(pattern);
        }

        // Pattern regex (already regex)
        if let Some(ref regex) = spec.pattern_regex {
            effective_pattern = regex.clone();
        }

        // Pattern-either (any of the patterns)
        if let Some(ref either) = spec.pattern_either {
            let patterns: Vec<String> = either.iter()
                .filter_map(|p| p.pattern.as_ref().or(p.pattern_regex.as_ref()))
                .map(|p| self.semgrep_to_regex(p))
                .collect();
            if !patterns.is_empty() {
                effective_pattern = format!("({})", patterns.join("|"));
            }
        }

        // Complex patterns (AND logic)
        if let Some(ref patterns) = spec.patterns {
            for item in patterns {
                if let Some(ref pattern) = item.pattern {
                    if effective_pattern.is_empty() {
                        effective_pattern = self.semgrep_to_regex(pattern);
                    }
                }
                if let Some(ref pattern) = item.pattern_regex {
                    if effective_pattern.is_empty() {
                        effective_pattern = pattern.clone();
                    }
                }
                if let Some(ref pattern) = item.pattern_not {
                    negation_patterns.push(self.semgrep_to_regex(pattern));
                }
                if let Some(ref pattern) = item.pattern_inside {
                    context_patterns.push(self.semgrep_to_regex(pattern));
                }
            }
        }

        if effective_pattern.is_empty() {
            return Err(anyhow!("No pattern found in Semgrep rule"));
        }

        Ok((effective_pattern, negation_patterns, context_patterns))
    }

    /// Convert Semgrep pattern syntax to regex
    fn semgrep_to_regex(&self, pattern: &str) -> String {
        let mut regex = regex::escape(pattern);

        // Convert Semgrep metavariables to regex capture groups
        // $VAR -> captures any identifier
        let metavar_re = Regex::new(r"\\\$([A-Z_][A-Z0-9_]*)").unwrap();
        regex = metavar_re.replace_all(&regex, r"(?P<$1>[a-zA-Z_][a-zA-Z0-9_]*)").to_string();

        // Convert ... to match anything (non-greedy)
        regex = regex.replace(r"\.\.\.", ".*?");

        // Handle $... (ellipsis with metavariable) -> match anything
        let ellipsis_re = Regex::new(r"\\\$\.\.\.[A-Z_][A-Z0-9_]*").unwrap();
        regex = ellipsis_re.replace_all(&regex, ".*?").to_string();

        regex
    }

    /// Map Semgrep languages to SAST language
    fn map_language(&self, languages: &[String]) -> SastLanguage {
        for lang in languages {
            match lang.to_lowercase().as_str() {
                "python" | "py" | "python3" => return SastLanguage::Python,
                "javascript" | "js" => return SastLanguage::JavaScript,
                "typescript" | "ts" => return SastLanguage::TypeScript,
                "rust" | "rs" => return SastLanguage::Rust,
                "go" | "golang" => return SastLanguage::Go,
                "java" => return SastLanguage::Java,
                "c" => return SastLanguage::C,
                "cpp" | "c++" => return SastLanguage::Cpp,
                "csharp" | "c#" => return SastLanguage::CSharp,
                "ruby" | "rb" => return SastLanguage::Ruby,
                "php" => return SastLanguage::Php,
                "swift" => return SastLanguage::Swift,
                "kotlin" | "kt" => return SastLanguage::Kotlin,
                "scala" => return SastLanguage::Scala,
                _ => continue,
            }
        }
        SastLanguage::Unknown
    }

    /// Map Semgrep severity to HeroForge severity
    fn map_severity(&self, severity: &str) -> Severity {
        match severity.to_uppercase().as_str() {
            "ERROR" | "CRITICAL" => Severity::Critical,
            "WARNING" | "HIGH" => Severity::High,
            "INFO" | "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Medium,
        }
    }

    /// Map Semgrep metadata to SAST category
    fn map_category(&self, metadata: &Option<SemgrepMetadata>) -> SastCategory {
        if let Some(ref meta) = metadata {
            if let Some(ref category) = meta.category {
                return match category.to_lowercase().as_str() {
                    "security" => SastCategory::SecurityMisconfiguration,
                    "correctness" => SastCategory::Other,
                    "best-practice" => SastCategory::Other,
                    "performance" => SastCategory::Other,
                    _ => SastCategory::Other,
                };
            }

            // Check OWASP mapping
            if let Some(ref owasp) = meta.owasp {
                for item in owasp {
                    let lower = item.to_lowercase();
                    if lower.contains("injection") {
                        return SastCategory::Injection;
                    }
                    if lower.contains("xss") {
                        return SastCategory::Xss;
                    }
                    if lower.contains("xxe") {
                        return SastCategory::Xxe;
                    }
                    if lower.contains("auth") {
                        return SastCategory::BrokenAuth;
                    }
                    if lower.contains("access") {
                        return SastCategory::BrokenAccessControl;
                    }
                    if lower.contains("misconfig") {
                        return SastCategory::SecurityMisconfiguration;
                    }
                    if lower.contains("deserial") {
                        return SastCategory::InsecureDeserialization;
                    }
                }
            }

            // Check subcategory
            if let Some(ref subcats) = meta.subcategory {
                for subcat in subcats {
                    let lower = subcat.to_lowercase();
                    if lower.contains("sql") {
                        return SastCategory::SqlInjection;
                    }
                    if lower.contains("command") || lower.contains("os") {
                        return SastCategory::CommandInjection;
                    }
                    if lower.contains("path") || lower.contains("traversal") {
                        return SastCategory::PathTraversal;
                    }
                    if lower.contains("xss") || lower.contains("cross-site") {
                        return SastCategory::Xss;
                    }
                    if lower.contains("crypto") {
                        return SastCategory::Cryptography;
                    }
                    if lower.contains("secret") || lower.contains("hardcode") {
                        return SastCategory::HardcodedSecrets;
                    }
                }
            }
        }
        SastCategory::Other
    }

    /// Get available rule sources
    pub fn get_sources(&self) -> &[SemgrepRuleSource] {
        &self.builtin_sources
    }
}

impl Default for SemgrepParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Semgrep rule matcher for executing rules against code
pub struct SemgrepMatcher {
    rules: Vec<ParsedSemgrepRule>,
}

impl SemgrepMatcher {
    pub fn new(rules: Vec<ParsedSemgrepRule>) -> Self {
        Self { rules }
    }

    /// Match rules against source code
    pub fn match_code(&self, code: &str, file_path: &str) -> Vec<SastFinding> {
        let mut findings = Vec::new();

        for rule in &self.rules {
            if let Ok(regex) = Regex::new(&rule.effective_pattern) {
                for mat in regex.find_iter(code) {
                    // Check negation patterns
                    let mut should_skip = false;
                    for neg_pattern in &rule.negation_patterns {
                        if let Ok(neg_re) = Regex::new(neg_pattern) {
                            // Check if negation pattern matches in the same region
                            if neg_re.is_match(&code[mat.start().saturating_sub(50)..mat.end().saturating_add(50).min(code.len())]) {
                                should_skip = true;
                                break;
                            }
                        }
                    }

                    if should_skip {
                        continue;
                    }

                    // Check context patterns (must match somewhere in the file)
                    if !rule.context_patterns.is_empty() {
                        let mut context_found = true;
                        for ctx_pattern in &rule.context_patterns {
                            if let Ok(ctx_re) = Regex::new(ctx_pattern) {
                                if !ctx_re.is_match(code) {
                                    context_found = false;
                                    break;
                                }
                            }
                        }
                        if !context_found {
                            continue;
                        }
                    }

                    let line_start = code[..mat.start()].lines().count() as u32;
                    let snippet = get_code_snippet(code, line_start as usize);

                    findings.push(SastFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        scan_id: String::new(),
                        rule_id: rule.converted.id.clone(),
                        severity: rule.converted.severity,
                        category: rule.converted.category,
                        file_path: file_path.to_string(),
                        location: CodeLocation {
                            line_start,
                            line_end: Some(line_start),
                            column_start: None,
                            column_end: None,
                        },
                        code_snippet: Some(snippet),
                        message: rule.converted.description.clone(),
                        cwe_id: rule.converted.cwe_id.clone(),
                        remediation: rule.converted.remediation_guidance.clone(),
                        false_positive: false,
                        suppressed: false,
                        created_at: Utc::now(),
                    });
                }
            }
        }

        findings
    }
}

/// Get a code snippet around a line
fn get_code_snippet(content: &str, line_num: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = line_num.saturating_sub(2);
    let end = (line_num + 3).min(lines.len());

    lines[start..end]
        .iter()
        .enumerate()
        .map(|(i, line)| format!("{}: {}", start + i + 1, line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Built-in Semgrep-style rules for common vulnerabilities
pub fn get_builtin_semgrep_rules() -> Vec<SemgrepRule> {
    vec![
        SemgrepRule {
            id: "python-sql-injection".to_string(),
            message: "Potential SQL injection via string concatenation or formatting".to_string(),
            severity: "ERROR".to_string(),
            languages: vec!["python".to_string()],
            metadata: Some(SemgrepMetadata {
                category: Some("security".to_string()),
                cwe: Some(vec!["CWE-89".to_string()]),
                owasp: Some(vec!["A03:2021 - Injection".to_string()]),
                confidence: Some("HIGH".to_string()),
                ..Default::default()
            }),
            pattern_spec: SemgrepPatternSpec {
                pattern_either: Some(vec![
                    SemgrepPatternItem {
                        pattern_regex: Some(r#"cursor\.execute\s*\([^)]*%"#.to_string()),
                        ..Default::default()
                    },
                    SemgrepPatternItem {
                        pattern_regex: Some(r#"cursor\.execute\s*\([^)]*\.format\("#.to_string()),
                        ..Default::default()
                    },
                    SemgrepPatternItem {
                        pattern_regex: Some(r#"cursor\.execute\s*\(f["']"#.to_string()),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            },
        },
        SemgrepRule {
            id: "javascript-eval-injection".to_string(),
            message: "Use of eval() with untrusted input can lead to code injection".to_string(),
            severity: "ERROR".to_string(),
            languages: vec!["javascript".to_string(), "typescript".to_string()],
            metadata: Some(SemgrepMetadata {
                category: Some("security".to_string()),
                cwe: Some(vec!["CWE-95".to_string()]),
                owasp: Some(vec!["A03:2021 - Injection".to_string()]),
                confidence: Some("MEDIUM".to_string()),
                ..Default::default()
            }),
            pattern_spec: SemgrepPatternSpec {
                pattern_regex: Some(r#"eval\s*\([^)]*(\$|req\.|request\.|params\.|query\.)"#.to_string()),
                ..Default::default()
            },
        },
        SemgrepRule {
            id: "java-xxe-vulnerability".to_string(),
            message: "XML parser is vulnerable to XXE attacks".to_string(),
            severity: "ERROR".to_string(),
            languages: vec!["java".to_string()],
            metadata: Some(SemgrepMetadata {
                category: Some("security".to_string()),
                cwe: Some(vec!["CWE-611".to_string()]),
                owasp: Some(vec!["A05:2021 - Security Misconfiguration".to_string()]),
                confidence: Some("HIGH".to_string()),
                ..Default::default()
            }),
            pattern_spec: SemgrepPatternSpec {
                pattern: Some("DocumentBuilderFactory.newInstance()".to_string()),
                patterns: Some(vec![
                    SemgrepPatternItem {
                        pattern_not: Some("setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)".to_string()),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            },
        },
        SemgrepRule {
            id: "go-command-injection".to_string(),
            message: "Potential command injection via user-controlled input".to_string(),
            severity: "ERROR".to_string(),
            languages: vec!["go".to_string()],
            metadata: Some(SemgrepMetadata {
                category: Some("security".to_string()),
                cwe: Some(vec!["CWE-78".to_string()]),
                owasp: Some(vec!["A03:2021 - Injection".to_string()]),
                confidence: Some("MEDIUM".to_string()),
                ..Default::default()
            }),
            pattern_spec: SemgrepPatternSpec {
                pattern_regex: Some(r#"exec\.Command\s*\([^)]*(\+|fmt\.Sprintf)"#.to_string()),
                ..Default::default()
            },
        },
        SemgrepRule {
            id: "rust-unsafe-block".to_string(),
            message: "Use of unsafe block requires careful review".to_string(),
            severity: "WARNING".to_string(),
            languages: vec!["rust".to_string()],
            metadata: Some(SemgrepMetadata {
                category: Some("security".to_string()),
                cwe: Some(vec!["CWE-676".to_string()]),
                confidence: Some("HIGH".to_string()),
                ..Default::default()
            }),
            pattern_spec: SemgrepPatternSpec {
                pattern_regex: Some(r#"unsafe\s*\{"#.to_string()),
                ..Default::default()
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let yaml = r#"
rules:
  - id: test-rule
    message: Test message
    severity: ERROR
    languages:
      - python
    pattern: print($X)
"#;

        let parser = SemgrepParser::new();
        let result = parser.parse_yaml(yaml);
        assert!(result.is_ok());
        let rules = result.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].converted.name, "test-rule");
    }

    #[test]
    fn test_map_severity() {
        let parser = SemgrepParser::new();
        assert!(matches!(parser.map_severity("ERROR"), Severity::Critical));
        assert!(matches!(parser.map_severity("WARNING"), Severity::High));
        assert!(matches!(parser.map_severity("INFO"), Severity::Medium));
    }

    #[test]
    fn test_semgrep_to_regex() {
        let parser = SemgrepParser::new();

        // Test metavariable conversion
        let pattern = "print($VAR)";
        let regex = parser.semgrep_to_regex(pattern);
        assert!(regex.contains("?P<VAR>"));

        // Test ellipsis conversion
        let pattern2 = "func(..., $X)";
        let regex2 = parser.semgrep_to_regex(pattern2);
        assert!(regex2.contains(".*?"));
    }
}
