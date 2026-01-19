//! Taint Analysis for Data Flow Tracking
//!
//! Implements taint analysis to track how potentially dangerous data flows
//! from sources (user input, etc.) to sinks (SQL queries, command execution, etc.).

use crate::yellow_team::types::*;
use anyhow::Result;
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Taint source - where untrusted data enters the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    pub id: String,
    pub name: String,
    pub description: String,
    pub language: SastLanguage,
    /// Regex patterns to identify the source
    pub patterns: Vec<String>,
    /// Variable names that capture the tainted value
    pub capture_vars: Vec<String>,
    /// Risk level of this source
    pub risk_level: TaintRiskLevel,
}

/// Taint sink - where data becomes dangerous
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    pub id: String,
    pub name: String,
    pub description: String,
    pub language: SastLanguage,
    /// Regex patterns to identify the sink
    pub patterns: Vec<String>,
    /// Position of the tainted argument (0-indexed, -1 for any)
    pub tainted_arg_position: i32,
    /// Vulnerability type when taint reaches this sink
    pub vuln_type: SastCategory,
    /// CWE ID
    pub cwe_id: Option<String>,
    /// Severity when taint reaches this sink
    pub severity: Severity,
}

/// Sanitizer - removes or neutralizes taint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSanitizer {
    pub id: String,
    pub name: String,
    pub description: String,
    pub language: SastLanguage,
    /// Regex patterns to identify sanitization
    pub patterns: Vec<String>,
    /// Which sinks this sanitizer protects against
    pub protects_against: Vec<String>,
}

/// Risk level for taint sources
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaintRiskLevel {
    High,    // Direct user input (request params, form data)
    Medium,  // Indirect user input (database, file reads)
    Low,     // Semi-trusted sources (configuration, environment)
}

/// A taint flow from source to sink
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    pub id: String,
    pub source: TaintSourceMatch,
    pub sink: TaintSinkMatch,
    pub path: Vec<TaintPathNode>,
    pub sanitizers_passed: Vec<String>,
    pub is_sanitized: bool,
    pub severity: Severity,
    pub category: SastCategory,
    pub cwe_id: Option<String>,
    pub confidence: TaintConfidence,
}

/// Match result for a taint source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSourceMatch {
    pub source_id: String,
    pub source_name: String,
    pub variable_name: String,
    pub file_path: String,
    pub line: u32,
    pub code_snippet: String,
}

/// Match result for a taint sink
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSinkMatch {
    pub sink_id: String,
    pub sink_name: String,
    pub file_path: String,
    pub line: u32,
    pub code_snippet: String,
}

/// Node in the taint propagation path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPathNode {
    pub variable_name: String,
    pub operation: String,
    pub file_path: String,
    pub line: u32,
}

/// Confidence level of taint analysis
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaintConfidence {
    High,    // Direct flow with clear path
    Medium,  // Flow through intermediate variables
    Low,     // Heuristic-based detection
}

/// Taint analysis engine
pub struct TaintAnalyzer {
    sources: Vec<TaintSource>,
    sinks: Vec<TaintSink>,
    sanitizers: Vec<TaintSanitizer>,
}

impl TaintAnalyzer {
    pub fn new() -> Self {
        Self {
            sources: get_builtin_sources(),
            sinks: get_builtin_sinks(),
            sanitizers: get_builtin_sanitizers(),
        }
    }

    pub fn with_config(
        sources: Vec<TaintSource>,
        sinks: Vec<TaintSink>,
        sanitizers: Vec<TaintSanitizer>,
    ) -> Self {
        Self { sources, sinks, sanitizers }
    }

    /// Analyze code for taint flows
    pub fn analyze(&self, code: &str, file_path: &str, language: SastLanguage) -> Vec<TaintFlow> {
        let mut flows = Vec::new();

        // Step 1: Find all source matches
        let source_matches = self.find_sources(code, file_path, language);

        // Step 2: For each source, track taint propagation
        for source_match in &source_matches {
            // Step 3: Find potential sinks that use the tainted variable
            let sink_matches = self.find_sinks(code, file_path, language, &source_match.variable_name);

            // Step 4: Check for sanitizers between source and sink
            for sink_match in sink_matches {
                let (path, sanitizers_passed, is_sanitized) = self.trace_flow(
                    code,
                    file_path,
                    source_match,
                    &sink_match,
                );

                // Look up sink details for severity/category
                let sink = self.sinks.iter().find(|s| s.id == sink_match.sink_id);
                let (severity, category, cwe_id) = sink
                    .map(|s| (s.severity, s.vuln_type, s.cwe_id.clone()))
                    .unwrap_or((Severity::Medium, SastCategory::Injection, None));

                let confidence = if is_sanitized {
                    TaintConfidence::Low
                } else if path.len() <= 3 {
                    TaintConfidence::High
                } else {
                    TaintConfidence::Medium
                };

                flows.push(TaintFlow {
                    id: uuid::Uuid::new_v4().to_string(),
                    source: source_match.clone(),
                    sink: sink_match,
                    path,
                    sanitizers_passed,
                    is_sanitized,
                    severity: if is_sanitized { Severity::Low } else { severity },
                    category,
                    cwe_id,
                    confidence,
                });
            }
        }

        flows
    }

    /// Find source matches in code
    fn find_sources(&self, code: &str, file_path: &str, language: SastLanguage) -> Vec<TaintSourceMatch> {
        let mut matches = Vec::new();

        for source in &self.sources {
            if source.language != language && source.language != SastLanguage::Unknown {
                continue;
            }

            for pattern in &source.patterns {
                if let Ok(regex) = Regex::new(pattern) {
                    for cap in regex.captures_iter(code) {
                        let mat = cap.get(0).unwrap();
                        let line = code[..mat.start()].lines().count() as u32;

                        // Try to extract variable name from capture groups
                        let var_name = cap.get(1)
                            .map(|m| m.as_str().to_string())
                            .unwrap_or_else(|| "tainted".to_string());

                        matches.push(TaintSourceMatch {
                            source_id: source.id.clone(),
                            source_name: source.name.clone(),
                            variable_name: var_name,
                            file_path: file_path.to_string(),
                            line,
                            code_snippet: get_line(code, line as usize),
                        });
                    }
                }
            }
        }

        matches
    }

    /// Find sinks that use a tainted variable
    fn find_sinks(&self, code: &str, file_path: &str, language: SastLanguage, var_name: &str) -> Vec<TaintSinkMatch> {
        let mut matches = Vec::new();

        for sink in &self.sinks {
            if sink.language != language && sink.language != SastLanguage::Unknown {
                continue;
            }

            for pattern in &sink.patterns {
                // Modify pattern to include variable name
                let var_pattern = pattern.replace("$VAR", &regex::escape(var_name))
                    .replace("$ANY", ".*?");

                if let Ok(regex) = Regex::new(&var_pattern) {
                    for mat in regex.find_iter(code) {
                        let line = code[..mat.start()].lines().count() as u32;

                        matches.push(TaintSinkMatch {
                            sink_id: sink.id.clone(),
                            sink_name: sink.name.clone(),
                            file_path: file_path.to_string(),
                            line,
                            code_snippet: get_line(code, line as usize),
                        });
                    }
                }
            }
        }

        matches
    }

    /// Trace the flow between source and sink, checking for sanitizers
    fn trace_flow(
        &self,
        code: &str,
        file_path: &str,
        source: &TaintSourceMatch,
        sink: &TaintSinkMatch,
    ) -> (Vec<TaintPathNode>, Vec<String>, bool) {
        let mut path = Vec::new();
        let mut sanitizers_passed = Vec::new();
        let mut is_sanitized = false;

        // Add source to path
        path.push(TaintPathNode {
            variable_name: source.variable_name.clone(),
            operation: "source".to_string(),
            file_path: file_path.to_string(),
            line: source.line,
        });

        // Track variable assignments between source and sink
        let source_line = source.line as usize;
        let sink_line = sink.line as usize;

        if source_line < sink_line {
            let lines: Vec<&str> = code.lines().collect();

            // Simple tracking: look for assignments involving the variable
            let mut current_var = source.variable_name.clone();
            let assignment_re = Regex::new(&format!(
                r"(\w+)\s*=\s*.*\b{}\b",
                regex::escape(&current_var)
            )).unwrap_or_else(|_| Regex::new(r"^$").unwrap());

            for line_num in source_line..sink_line.min(lines.len()) {
                let line = lines.get(line_num).unwrap_or(&"");

                // Check for sanitizers
                for sanitizer in &self.sanitizers {
                    for pattern in &sanitizer.patterns {
                        if let Ok(re) = Regex::new(pattern) {
                            if re.is_match(line) && line.contains(&current_var) {
                                sanitizers_passed.push(sanitizer.id.clone());
                                if sanitizer.protects_against.contains(&sink.sink_id) {
                                    is_sanitized = true;
                                }
                            }
                        }
                    }
                }

                // Track variable reassignments
                if let Some(cap) = assignment_re.captures(line) {
                    if let Some(new_var) = cap.get(1) {
                        let new_var_name = new_var.as_str().to_string();
                        path.push(TaintPathNode {
                            variable_name: new_var_name.clone(),
                            operation: "assignment".to_string(),
                            file_path: file_path.to_string(),
                            line: (line_num + 1) as u32,
                        });
                        current_var = new_var_name;
                    }
                }
            }
        }

        // Add sink to path
        path.push(TaintPathNode {
            variable_name: "sink".to_string(),
            operation: "sink".to_string(),
            file_path: file_path.to_string(),
            line: sink.line,
        });

        (path, sanitizers_passed, is_sanitized)
    }

    /// Convert taint flows to SAST findings
    pub fn to_findings(&self, flows: Vec<TaintFlow>, scan_id: &str) -> Vec<SastFinding> {
        flows.into_iter()
            .filter(|f| !f.is_sanitized) // Only report unsanitized flows
            .map(|flow| {
                let path_description = flow.path.iter()
                    .map(|n| format!("{}:{} ({})", n.file_path.split('/').last().unwrap_or(""), n.line, n.operation))
                    .collect::<Vec<_>>()
                    .join(" -> ");

                let message = format!(
                    "Taint flow detected: {} flows to {} ({}). Path: {}",
                    flow.source.source_name,
                    flow.sink.sink_name,
                    if flow.confidence == TaintConfidence::High { "high confidence" }
                    else if flow.confidence == TaintConfidence::Medium { "medium confidence" }
                    else { "low confidence" },
                    path_description
                );

                SastFinding {
                    id: flow.id,
                    scan_id: scan_id.to_string(),
                    rule_id: format!("TAINT-{}", flow.sink.sink_id),
                    severity: flow.severity,
                    category: flow.category,
                    file_path: flow.sink.file_path,
                    location: CodeLocation {
                        line_start: flow.sink.line,
                        line_end: Some(flow.sink.line),
                        column_start: None,
                        column_end: None,
                    },
                    code_snippet: Some(flow.sink.code_snippet),
                    message,
                    cwe_id: flow.cwe_id,
                    remediation: Some(format!(
                        "Ensure data from '{}' at line {} is properly validated before use.",
                        flow.source.source_name,
                        flow.source.line
                    )),
                    false_positive: false,
                    suppressed: false,
                    created_at: Utc::now(),
                }
            })
            .collect()
    }

    /// Get all sources
    pub fn get_sources(&self) -> &[TaintSource] {
        &self.sources
    }

    /// Get all sinks
    pub fn get_sinks(&self) -> &[TaintSink] {
        &self.sinks
    }

    /// Get all sanitizers
    pub fn get_sanitizers(&self) -> &[TaintSanitizer] {
        &self.sanitizers
    }
}

impl Default for TaintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Get a specific line from code
fn get_line(code: &str, line_num: usize) -> String {
    code.lines()
        .nth(line_num.saturating_sub(1))
        .unwrap_or("")
        .to_string()
}

/// Built-in taint sources
fn get_builtin_sources() -> Vec<TaintSource> {
    vec![
        // Python sources
        TaintSource {
            id: "py-request-params".to_string(),
            name: "Flask/Django Request Parameters".to_string(),
            description: "User input from request parameters".to_string(),
            language: SastLanguage::Python,
            patterns: vec![
                r#"request\.(args|form|json|data|values|cookies)\[['"]\w+['"]\]"#.to_string(),
                r"request\.get_json\(\)".to_string(),
                r"(\w+)\s*=\s*request\.(args|form|json)\.get\(".to_string(),
            ],
            capture_vars: vec!["$1".to_string()],
            risk_level: TaintRiskLevel::High,
        },
        TaintSource {
            id: "py-input".to_string(),
            name: "Python input()".to_string(),
            description: "User input from stdin".to_string(),
            language: SastLanguage::Python,
            patterns: vec![r"(\w+)\s*=\s*input\(".to_string()],
            capture_vars: vec!["$1".to_string()],
            risk_level: TaintRiskLevel::High,
        },
        TaintSource {
            id: "py-file-read".to_string(),
            name: "File Read".to_string(),
            description: "Data read from file".to_string(),
            language: SastLanguage::Python,
            patterns: vec![
                r"(\w+)\s*=\s*(?:open|Path)\([^)]*\)\.read".to_string(),
                r"(\w+)\s*=\s*\w+\.read\(\)".to_string(),
            ],
            capture_vars: vec!["$1".to_string()],
            risk_level: TaintRiskLevel::Medium,
        },
        // JavaScript sources
        TaintSource {
            id: "js-request-params".to_string(),
            name: "Express Request Parameters".to_string(),
            description: "User input from request parameters".to_string(),
            language: SastLanguage::JavaScript,
            patterns: vec![
                r#"req\.(body|query|params)\[['"]\w+['"]\]"#.to_string(),
                r"req\.(body|query|params)\.(\w+)".to_string(),
            ],
            capture_vars: vec!["$2".to_string()],
            risk_level: TaintRiskLevel::High,
        },
        TaintSource {
            id: "js-location".to_string(),
            name: "Window Location".to_string(),
            description: "User-controlled URL data".to_string(),
            language: SastLanguage::JavaScript,
            patterns: vec![
                r"(\w+)\s*=\s*(?:window\.)?location\.(href|search|hash|pathname)".to_string(),
                r"(\w+)\s*=\s*new URL\(".to_string(),
            ],
            capture_vars: vec!["$1".to_string()],
            risk_level: TaintRiskLevel::High,
        },
        // Java sources
        TaintSource {
            id: "java-request-params".to_string(),
            name: "Servlet Request Parameters".to_string(),
            description: "User input from HTTP request".to_string(),
            language: SastLanguage::Java,
            patterns: vec![
                r"(\w+)\s*=\s*request\.getParameter\(".to_string(),
                r"(\w+)\s*=\s*request\.getHeader\(".to_string(),
                r"(\w+)\s*=\s*request\.getCookies\(\)".to_string(),
            ],
            capture_vars: vec!["$1".to_string()],
            risk_level: TaintRiskLevel::High,
        },
        // Go sources
        TaintSource {
            id: "go-request-params".to_string(),
            name: "HTTP Request Parameters".to_string(),
            description: "User input from HTTP request".to_string(),
            language: SastLanguage::Go,
            patterns: vec![
                r"(\w+)\s*:?=\s*r\.FormValue\(".to_string(),
                r"(\w+)\s*:?=\s*r\.URL\.Query\(\)\.Get\(".to_string(),
                r"(\w+)\s*:?=\s*c\.Query\(".to_string(),
            ],
            capture_vars: vec!["$1".to_string()],
            risk_level: TaintRiskLevel::High,
        },
        // Rust sources
        TaintSource {
            id: "rust-web-params".to_string(),
            name: "Web Framework Parameters".to_string(),
            description: "User input from web request".to_string(),
            language: SastLanguage::Rust,
            patterns: vec![
                r"(\w+)\s*=\s*(?:query|form|json)\.(0|\w+)".to_string(),
                r"(\w+)\s*=\s*req\.match_info\(\)\.get\(".to_string(),
            ],
            capture_vars: vec!["$1".to_string()],
            risk_level: TaintRiskLevel::High,
        },
    ]
}

/// Built-in taint sinks
fn get_builtin_sinks() -> Vec<TaintSink> {
    vec![
        // SQL Injection sinks
        TaintSink {
            id: "sql-execute".to_string(),
            name: "SQL Execute".to_string(),
            description: "SQL query execution with potential injection".to_string(),
            language: SastLanguage::Unknown,
            patterns: vec![
                r"\.execute\s*\([^)]*$VAR".to_string(),
                r"\.query\s*\([^)]*$VAR".to_string(),
                r"\.raw\s*\([^)]*$VAR".to_string(),
            ],
            tainted_arg_position: 0,
            vuln_type: SastCategory::SqlInjection,
            cwe_id: Some("CWE-89".to_string()),
            severity: Severity::Critical,
        },
        // Command Injection sinks
        TaintSink {
            id: "cmd-exec".to_string(),
            name: "Command Execution".to_string(),
            description: "OS command execution with potential injection".to_string(),
            language: SastLanguage::Unknown,
            patterns: vec![
                r"os\.system\s*\([^)]*$VAR".to_string(),
                r"subprocess\.(call|run|Popen)\s*\([^)]*$VAR".to_string(),
                r"exec\.Command\s*\([^)]*$VAR".to_string(),
                r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*$VAR".to_string(),
                r"child_process\.(exec|spawn)\s*\([^)]*$VAR".to_string(),
            ],
            tainted_arg_position: 0,
            vuln_type: SastCategory::CommandInjection,
            cwe_id: Some("CWE-78".to_string()),
            severity: Severity::Critical,
        },
        // XSS sinks
        TaintSink {
            id: "html-output".to_string(),
            name: "HTML Output".to_string(),
            description: "Unsanitized output to HTML".to_string(),
            language: SastLanguage::Unknown,
            patterns: vec![
                r"\.innerHTML\s*=\s*$VAR".to_string(),
                r"document\.write\s*\([^)]*$VAR".to_string(),
                r"Response\.Write\s*\([^)]*$VAR".to_string(),
            ],
            tainted_arg_position: 0,
            vuln_type: SastCategory::Xss,
            cwe_id: Some("CWE-79".to_string()),
            severity: Severity::High,
        },
        // Path Traversal sinks
        TaintSink {
            id: "file-open".to_string(),
            name: "File Open".to_string(),
            description: "File operations with potential path traversal".to_string(),
            language: SastLanguage::Unknown,
            patterns: vec![
                r"open\s*\([^)]*$VAR".to_string(),
                r"readFile\s*\([^)]*$VAR".to_string(),
                r"new File\s*\([^)]*$VAR".to_string(),
                r"os\.Open\s*\([^)]*$VAR".to_string(),
            ],
            tainted_arg_position: 0,
            vuln_type: SastCategory::PathTraversal,
            cwe_id: Some("CWE-22".to_string()),
            severity: Severity::High,
        },
        // SSRF sinks
        TaintSink {
            id: "http-request".to_string(),
            name: "HTTP Request".to_string(),
            description: "HTTP request with potential SSRF".to_string(),
            language: SastLanguage::Unknown,
            patterns: vec![
                r"requests?\.(get|post|put|delete)\s*\([^)]*$VAR".to_string(),
                r"fetch\s*\([^)]*$VAR".to_string(),
                r"axios\.(get|post|put|delete)\s*\([^)]*$VAR".to_string(),
                r"http\.Get\s*\([^)]*$VAR".to_string(),
            ],
            tainted_arg_position: 0,
            vuln_type: SastCategory::Ssrf,
            cwe_id: Some("CWE-918".to_string()),
            severity: Severity::High,
        },
        // Deserialization sinks
        TaintSink {
            id: "deserialize".to_string(),
            name: "Deserialization".to_string(),
            description: "Deserialization of untrusted data".to_string(),
            language: SastLanguage::Unknown,
            patterns: vec![
                r"pickle\.loads?\s*\([^)]*$VAR".to_string(),
                r"yaml\.load\s*\([^)]*$VAR".to_string(),
                r"ObjectInputStream\s*\([^)]*$VAR".to_string(),
                r"JSON\.parse\s*\([^)]*$VAR".to_string(),
            ],
            tainted_arg_position: 0,
            vuln_type: SastCategory::InsecureDeserialization,
            cwe_id: Some("CWE-502".to_string()),
            severity: Severity::High,
        },
        // Code execution sinks
        TaintSink {
            id: "code-eval".to_string(),
            name: "Code Evaluation".to_string(),
            description: "Dynamic code execution".to_string(),
            language: SastLanguage::Unknown,
            patterns: vec![
                r"eval\s*\([^)]*$VAR".to_string(),
                r"exec\s*\([^)]*$VAR".to_string(),
                r"Function\s*\([^)]*$VAR".to_string(),
            ],
            tainted_arg_position: 0,
            vuln_type: SastCategory::Injection,
            cwe_id: Some("CWE-95".to_string()),
            severity: Severity::Critical,
        },
    ]
}

/// Built-in sanitizers
fn get_builtin_sanitizers() -> Vec<TaintSanitizer> {
    vec![
        // SQL parameterization
        TaintSanitizer {
            id: "sql-parameterized".to_string(),
            name: "SQL Parameterized Query".to_string(),
            description: "Use of parameterized queries".to_string(),
            language: SastLanguage::Unknown,
            patterns: vec![
                r"execute\s*\([^)]*\?\s*,".to_string(),
                r"execute\s*\([^)]*%s\s*,".to_string(),
                r"PreparedStatement".to_string(),
            ],
            protects_against: vec!["sql-execute".to_string()],
        },
        // HTML encoding
        TaintSanitizer {
            id: "html-escape".to_string(),
            name: "HTML Escaping".to_string(),
            description: "HTML entity encoding".to_string(),
            language: SastLanguage::Unknown,
            patterns: vec![
                r"(html\.escape|escape|sanitize|encode|htmlspecialchars)".to_string(),
                r"textContent".to_string(),
                r"innerText".to_string(),
            ],
            protects_against: vec!["html-output".to_string()],
        },
        // Path validation
        TaintSanitizer {
            id: "path-validate".to_string(),
            name: "Path Validation".to_string(),
            description: "Path sanitization/validation".to_string(),
            language: SastLanguage::Unknown,
            patterns: vec![
                r"(os\.path\.basename|Path\.name|filepath\.Base|filepath\.Clean)".to_string(),
                r"(realpath|abspath|normpath)".to_string(),
            ],
            protects_against: vec!["file-open".to_string()],
        },
        // Shell escaping
        TaintSanitizer {
            id: "shell-escape".to_string(),
            name: "Shell Escaping".to_string(),
            description: "Shell argument escaping".to_string(),
            language: SastLanguage::Unknown,
            patterns: vec![
                r"(shlex\.quote|escapeshellarg|shellescape)".to_string(),
                r"subprocess\.[a-z]+\s*\(\s*\[".to_string(),  // List form
            ],
            protects_against: vec!["cmd-exec".to_string()],
        },
        // URL validation
        TaintSanitizer {
            id: "url-validate".to_string(),
            name: "URL Validation".to_string(),
            description: "URL validation/whitelist".to_string(),
            language: SastLanguage::Unknown,
            patterns: vec![
                r"(urlparse|URL\.parse|new URL)".to_string(),
                r"(allowlist|whitelist|trusted_hosts)".to_string(),
            ],
            protects_against: vec!["http-request".to_string()],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_analyzer_creation() {
        let analyzer = TaintAnalyzer::new();
        assert!(!analyzer.sources.is_empty());
        assert!(!analyzer.sinks.is_empty());
        assert!(!analyzer.sanitizers.is_empty());
    }

    #[test]
    fn test_python_sql_injection_detection() {
        let analyzer = TaintAnalyzer::new();
        let code = r#"
from flask import request

@app.route('/search')
def search():
    query = request.args.get('q')
    cursor.execute("SELECT * FROM users WHERE name = '" + query + "'")
    return results
"#;

        let flows = analyzer.analyze(code, "test.py", SastLanguage::Python);
        assert!(!flows.is_empty(), "Should detect SQL injection flow");
    }

    #[test]
    fn test_sanitized_flow() {
        let analyzer = TaintAnalyzer::new();
        // Code that uses html_escape on user input (recognized HTML sanitizer)
        let code = r#"
from flask import request

@app.route('/search')
def search():
    query = request.args.get('q')
    safe_query = html_escape(query)
    document.write(safe_query)
    return results
"#;

        let flows = analyzer.analyze(code, "test.py", SastLanguage::Python);
        // html_escape sanitizer should mark XSS flows as sanitized
        // Filter for html-output sinks (XSS vulnerability)
        let xss_unsanitized: Vec<_> = flows.iter()
            .filter(|f| f.sink.sink_id == "html-output" && !f.is_sanitized)
            .collect();
        // With html_escape pattern and html-output sink, flow should be sanitized
        assert!(xss_unsanitized.is_empty(),
            "Expected XSS flows to be sanitized with html_escape, found: {:?}", xss_unsanitized);
    }
}
