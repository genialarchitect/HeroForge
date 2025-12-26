//! Go-specific code analyzer

use crate::yellow_team::types::*;
use chrono::Utc;
use regex::Regex;
use uuid::Uuid;

/// Analyze Go code for security issues
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

    // Go-specific semantic analysis
    findings.extend(check_error_handling(content));
    findings.extend(check_http_security(content));

    findings
}

/// Check for Go error handling issues
fn check_error_handling(content: &str) -> Vec<SastFinding> {
    let mut findings = Vec::new();

    // Check for ignored errors (using blank identifier)
    let ignore_err_pattern = Regex::new(r"_\s*,\s*err\s*:?=|err\s*=\s*[^;]+;\s*_").unwrap();
    for mat in ignore_err_pattern.find_iter(content) {
        let line_start = content[..mat.start()].lines().count() as u32;
        findings.push(SastFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            rule_id: "GO-ERR-001".to_string(),
            severity: Severity::Medium,
            category: SastCategory::InsufficientLogging,
            file_path: String::new(),
            location: CodeLocation {
                line_start,
                line_end: None,
                column_start: None,
                column_end: None,
            },
            code_snippet: Some(mat.as_str().to_string()),
            message: "Error value ignored".to_string(),
            cwe_id: Some("CWE-391".to_string()),
            remediation: Some("Handle errors properly instead of ignoring them.".to_string()),
            false_positive: false,
            suppressed: false,
            created_at: Utc::now(),
        });
    }

    findings
}

/// Check for HTTP security issues in Go
fn check_http_security(content: &str) -> Vec<SastFinding> {
    let mut findings = Vec::new();

    let patterns = [
        (r"http\.ListenAndServe\s*\(", "HTTP without TLS", Severity::Medium, "GO-HTTP-001"),
        (r"http\.Get\s*\([^)]*\+", "Potential SSRF via HTTP GET", Severity::High, "GO-HTTP-002"),
        (r"http\.NewRequest\s*\([^)]*\+", "Potential SSRF via HTTP request", Severity::High, "GO-HTTP-003"),
        (r"template\.HTML\s*\(", "Unescaped HTML template", Severity::High, "GO-HTTP-004"),
        (r"w\.Write\s*\(\[\]byte\([^)]*\+", "Potential XSS via Write", Severity::High, "GO-HTTP-005"),
    ];

    for (pattern, message, severity, rule_id) in patterns {
        if let Ok(regex) = Regex::new(pattern) {
            for mat in regex.find_iter(content) {
                let line_start = content[..mat.start()].lines().count() as u32;
                findings.push(SastFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    rule_id: rule_id.to_string(),
                    severity,
                    category: SastCategory::SecurityMisconfiguration,
                    file_path: String::new(),
                    location: CodeLocation {
                        line_start,
                        line_end: None,
                        column_start: None,
                        column_end: None,
                    },
                    code_snippet: Some(mat.as_str().to_string()),
                    message: message.to_string(),
                    cwe_id: Some("CWE-918".to_string()),
                    remediation: Some("Review HTTP handling for security issues.".to_string()),
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
