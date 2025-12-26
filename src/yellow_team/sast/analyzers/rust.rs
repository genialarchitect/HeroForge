//! Rust-specific code analyzer

use crate::yellow_team::types::*;
use chrono::Utc;
use regex::Regex;
use uuid::Uuid;

/// Analyze Rust code for security issues
pub fn analyze(content: &str, rule: &SastRule) -> Vec<SastFinding> {
    let mut findings = Vec::new();

    // Pattern-based analysis
    if let Ok(regex) = Regex::new(&rule.pattern) {
        for mat in regex.find_iter(content) {
            let line_start = content[..mat.start()].lines().count() as u32;
            let snippet = get_context(content, line_start as usize);

            findings.push(SastFinding {
                id: Uuid::new_v4().to_string(),
                scan_id: String::new(),
                rule_id: rule.id.clone(),
                severity: rule.severity,
                category: rule.category,
                file_path: String::new(),
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
                created_at: Utc::now(),
            });
        }
    }

    // Semantic analysis for Rust-specific patterns
    findings.extend(check_unsafe_blocks(content, rule));
    findings.extend(check_panic_handling(content, rule));

    findings
}

/// Check for unsafe blocks that might be problematic
fn check_unsafe_blocks(content: &str, rule: &SastRule) -> Vec<SastFinding> {
    let mut findings = Vec::new();

    if rule.category != SastCategory::SecurityMisconfiguration {
        return findings;
    }

    // Look for unsafe blocks with potentially dangerous operations
    let unsafe_regex = Regex::new(r"unsafe\s*\{[^}]*\}").unwrap();
    let dangerous_patterns = [
        r"as\s+\*mut",
        r"as\s+\*const",
        r"from_raw_parts",
        r"transmute",
        r"forget\(",
    ];

    for mat in unsafe_regex.find_iter(content) {
        let block_content = mat.as_str();
        for pattern in &dangerous_patterns {
            if Regex::new(pattern).unwrap().is_match(block_content) {
                let line_start = content[..mat.start()].lines().count() as u32;
                findings.push(SastFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    rule_id: rule.id.clone(),
                    severity: Severity::High,
                    category: SastCategory::SecurityMisconfiguration,
                    file_path: String::new(),
                    location: CodeLocation {
                        line_start,
                        line_end: None,
                        column_start: None,
                        column_end: None,
                    },
                    code_snippet: Some(block_content.to_string()),
                    message: format!("Dangerous operation in unsafe block: {}", pattern),
                    cwe_id: Some("CWE-676".to_string()),
                    remediation: Some("Review unsafe code carefully for memory safety issues.".to_string()),
                    false_positive: false,
                    suppressed: false,
                    created_at: Utc::now(),
                });
                break;
            }
        }
    }

    findings
}

/// Check for panic-inducing code patterns
fn check_panic_handling(content: &str, _rule: &SastRule) -> Vec<SastFinding> {
    let mut findings = Vec::new();

    // Check for expect/unwrap without proper context
    let patterns: &[(&str, &str)] = &[
        (r#"\.expect\(\s*["']['"]['"]\s*\)"#, "Empty expect message"),
        (r"\.unwrap\(\)", "Unwrap without error handling"),
        (r"panic!\s*\(", "Explicit panic"),
        (r"todo!\s*\(", "TODO macro in code"),
        (r"unimplemented!\s*\(", "Unimplemented macro"),
    ];

    for (pattern, message) in patterns {
        if let Ok(regex) = Regex::new(pattern) {
            for mat in regex.find_iter(content) {
                let line_start = content[..mat.start()].lines().count() as u32;
                findings.push(SastFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    rule_id: "RUST-PANIC".to_string(),
                    severity: Severity::Low,
                    category: SastCategory::Other,
                    file_path: String::new(),
                    location: CodeLocation {
                        line_start,
                        line_end: None,
                        column_start: None,
                        column_end: None,
                    },
                    code_snippet: Some(mat.as_str().to_string()),
                    message: message.to_string(),
                    cwe_id: None,
                    remediation: Some("Handle errors gracefully instead of panicking.".to_string()),
                    false_positive: false,
                    suppressed: false,
                    created_at: Utc::now(),
                });
            }
        }
    }

    findings
}

fn get_context(content: &str, line_num: usize) -> String {
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
