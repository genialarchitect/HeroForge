//! Static Application Security Testing (SAST) module
//!
//! Provides code analysis for security vulnerabilities across multiple languages.

pub mod rules;
pub mod analyzers;

use crate::yellow_team::types::*;

// Re-export key types and functions
pub use crate::yellow_team::types::StartSastScanRequest as SastScanRequest;

/// Get all available SAST rules (built-in + custom)
pub fn get_all_rules() -> Vec<SastRule> {
    rules::get_builtin_rules()
}
use anyhow::{anyhow, Result};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tokio::sync::mpsc;
use uuid::Uuid;
use walkdir::WalkDir;

/// SAST Scanner Engine
pub struct SastScanner {
    pub rules: Vec<SastRule>,
}

impl SastScanner {
    pub fn new() -> Self {
        Self {
            rules: rules::get_builtin_rules(),
        }
    }

    pub fn with_rules(rules: Vec<SastRule>) -> Self {
        Self { rules }
    }

    /// Scan a directory or file for security vulnerabilities
    pub async fn scan(
        &self,
        source_path: &str,
        language: Option<SastLanguage>,
        progress_tx: Option<mpsc::Sender<ScanProgress>>,
    ) -> Result<Vec<SastFinding>> {
        let path = Path::new(source_path);
        let mut findings = Vec::new();

        if path.is_file() {
            let lang = language.unwrap_or_else(|| {
                path.extension()
                    .and_then(|e| e.to_str())
                    .map(SastLanguage::from_extension)
                    .unwrap_or(SastLanguage::Unknown)
            });
            let file_findings = self.scan_file(path, lang).await?;
            findings.extend(file_findings);
        } else if path.is_dir() {
            let files: Vec<_> = WalkDir::new(path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .filter(|e| !is_excluded_path(e.path()))
                .collect();

            let total = files.len();
            for (i, entry) in files.into_iter().enumerate() {
                let file_path = entry.path();
                let lang = language.unwrap_or_else(|| {
                    file_path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(SastLanguage::from_extension)
                        .unwrap_or(SastLanguage::Unknown)
                });

                if lang != SastLanguage::Unknown {
                    let file_findings = self.scan_file(file_path, lang).await?;
                    findings.extend(file_findings);
                }

                if let Some(ref tx) = progress_tx {
                    let _ = tx.send(ScanProgress {
                        files_scanned: i + 1,
                        total_files: total,
                        current_file: file_path.to_string_lossy().to_string(),
                        findings_so_far: findings.len(),
                    }).await;
                }
            }
        } else {
            return Err(anyhow!("Source path does not exist: {}", source_path));
        }

        Ok(findings)
    }

    /// Scan a single file
    async fn scan_file(&self, path: &Path, language: SastLanguage) -> Result<Vec<SastFinding>> {
        let content = fs::read_to_string(path)?;
        let mut findings = Vec::new();

        // Get rules applicable to this language
        let applicable_rules: Vec<&SastRule> = self.rules
            .iter()
            .filter(|r| r.enabled && (r.language == language || r.language == SastLanguage::Unknown))
            .collect();

        for rule in applicable_rules {
            match rule.pattern_type {
                PatternType::Regex => {
                    if let Ok(regex) = Regex::new(&rule.pattern) {
                        for mat in regex.find_iter(&content) {
                            let line_start = content[..mat.start()].lines().count() as u32;
                            let snippet = get_code_snippet(&content, line_start as usize);

                            findings.push(SastFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(), // Will be set by caller
                                rule_id: rule.id.clone(),
                                severity: rule.severity,
                                category: rule.category,
                                file_path: path.to_string_lossy().to_string(),
                                location: CodeLocation {
                                    line_start,
                                    line_end: Some(line_start),
                                    column_start: None,
                                    column_end: None,
                                },
                                code_snippet: Some(snippet),
                                message: rule.description.clone(),
                                cwe_id: rule.cwe_id.clone(),
                                remediation: rule.remediation_guidance.clone(),
                                false_positive: false,
                                suppressed: false,
                                created_at: chrono::Utc::now(),
                            });
                        }
                    }
                }
                PatternType::Ast | PatternType::Semantic => {
                    // AST/Semantic analysis would use tree-sitter
                    // For now, fall back to regex-based detection
                    let findings_from_analyzer = match language {
                        SastLanguage::Rust => analyzers::rust::analyze(&content, rule),
                        SastLanguage::Python => analyzers::python::analyze(&content, rule),
                        SastLanguage::JavaScript | SastLanguage::TypeScript => {
                            analyzers::javascript::analyze(&content, rule)
                        }
                        SastLanguage::Go => analyzers::go::analyze(&content, rule),
                        SastLanguage::Java => analyzers::java::analyze(&content, rule),
                        _ => Vec::new(),
                    };
                    
                    for mut finding in findings_from_analyzer {
                        finding.file_path = path.to_string_lossy().to_string();
                        findings.push(finding);
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Export findings as SARIF format
    pub fn to_sarif(&self, findings: &[SastFinding]) -> SarifReport {
        let mut rules_map: HashMap<String, &SastRule> = HashMap::new();
        for rule in &self.rules {
            rules_map.insert(rule.id.clone(), rule);
        }

        let sarif_rules: Vec<SarifRule> = findings
            .iter()
            .filter_map(|f| rules_map.get(&f.rule_id))
            .map(|rule| SarifRule {
                id: rule.id.clone(),
                name: rule.name.clone(),
                short_description: SarifMessage {
                    text: rule.description.clone(),
                },
                full_description: rule.remediation_guidance.as_ref().map(|r| SarifMessage {
                    text: r.clone(),
                }),
                default_configuration: Some(SarifConfiguration {
                    level: match rule.severity {
                        Severity::Critical | Severity::High => "error".to_string(),
                        Severity::Medium => "warning".to_string(),
                        _ => "note".to_string(),
                    },
                }),
            })
            .collect();

        let results: Vec<SarifResult> = findings
            .iter()
            .map(|f| SarifResult {
                rule_id: f.rule_id.clone(),
                level: match f.severity {
                    Severity::Critical | Severity::High => "error".to_string(),
                    Severity::Medium => "warning".to_string(),
                    _ => "note".to_string(),
                },
                message: SarifMessage {
                    text: f.message.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: f.file_path.clone(),
                        },
                        region: Some(SarifRegion {
                            start_line: f.location.line_start,
                            end_line: f.location.line_end,
                            start_column: f.location.column_start,
                            end_column: f.location.column_end,
                        }),
                    },
                }],
            })
            .collect();

        SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "HeroForge SAST".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        rules: sarif_rules,
                    },
                },
                results,
            }],
        }
    }
}

impl Default for SastScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a SAST scan
#[derive(Debug, Clone)]
pub struct SastScanResult {
    pub findings: Vec<SastFinding>,
    pub files_scanned: usize,
    pub rules_applied: usize,
    pub duration_ms: u64,
}

impl SastScanner {
    /// Run a SAST scan based on a scan request
    /// This is a synchronous wrapper around the async scan method
    pub fn run_scan(&self, request: &SastScanRequest) -> SastScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        // If code is provided inline, analyze it directly
        if let Some(ref code) = request.code {
            // Determine language
            let language = request.language.unwrap_or(SastLanguage::Unknown);

            // Get applicable rules
            let applicable_rules: Vec<&SastRule> = self.rules
                .iter()
                .filter(|r| r.enabled && (r.language == language || r.language == SastLanguage::Unknown))
                .filter(|r| {
                    if let Some(ref enabled) = request.enabled_rules {
                        enabled.contains(&r.id)
                    } else {
                        true
                    }
                })
                .filter(|r| {
                    if let Some(ref disabled) = request.disabled_rules {
                        !disabled.contains(&r.id)
                    } else {
                        true
                    }
                })
                .collect();

            for rule in applicable_rules {
                if let PatternType::Regex = rule.pattern_type {
                    if let Ok(regex) = Regex::new(&rule.pattern) {
                        for mat in regex.find_iter(code) {
                            let line_start = code[..mat.start()].lines().count() as u32;
                            let snippet = get_code_snippet(code, line_start as usize);

                            findings.push(SastFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(),
                                rule_id: rule.id.clone(),
                                severity: rule.severity,
                                category: rule.category,
                                file_path: "inline".to_string(),
                                location: CodeLocation {
                                    line_start,
                                    line_end: Some(line_start),
                                    column_start: None,
                                    column_end: None,
                                },
                                code_snippet: Some(snippet),
                                message: rule.description.clone(),
                                cwe_id: rule.cwe_id.clone(),
                                remediation: rule.remediation_guidance.clone(),
                                false_positive: false,
                                suppressed: false,
                                created_at: chrono::Utc::now(),
                            });
                        }
                    }
                }
            }
        }

        SastScanResult {
            findings,
            files_scanned: if request.code.is_some() { 1 } else { 0 },
            rules_applied: self.rules.len(),
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }
}

/// Progress update during scanning
#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub files_scanned: usize,
    pub total_files: usize,
    pub current_file: String,
    pub findings_so_far: usize,
}

/// Check if a path should be excluded from scanning
fn is_excluded_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    let excluded_dirs = [
        "node_modules",
        ".git",
        "target",
        "dist",
        "build",
        "vendor",
        "__pycache__",
        ".venv",
        "venv",
        ".idea",
        ".vscode",
    ];

    for dir in &excluded_dirs {
        if path_str.contains(&format!("/{}/", dir)) || path_str.contains(&format!("\\{}\\", dir)) {
            return true;
        }
    }

    false
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scanner_creation() {
        let scanner = SastScanner::new();
        assert!(!scanner.rules.is_empty());
    }
}
