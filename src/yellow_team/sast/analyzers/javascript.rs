//! JavaScript/TypeScript code analyzer

use crate::yellow_team::types::*;
use chrono::Utc;
use regex::Regex;
use uuid::Uuid;

/// Analyze JavaScript/TypeScript code for security issues
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

    // JS/TS-specific analysis
    findings.extend(check_react_security(content));
    findings.extend(check_express_security(content));

    findings
}

/// Check for React security issues
fn check_react_security(content: &str) -> Vec<SastFinding> {
    let mut findings = Vec::new();

    let patterns = [
        (r"dangerouslySetInnerHTML", "Use of dangerouslySetInnerHTML", Severity::High, "JS-REACT-001"),
        (r"<a\s+[^>]*href\s*=\s*\{[^}]*\}", "Dynamic href attribute (potential XSS)", Severity::Medium, "JS-REACT-002"),
        (r"document\.cookie", "Direct cookie access", Severity::Low, "JS-REACT-003"),
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
                    category: SastCategory::Xss,
                    file_path: String::new(),
                    location: CodeLocation {
                        line_start,
                        line_end: None,
                        column_start: None,
                        column_end: None,
                    },
                    code_snippet: Some(mat.as_str().to_string()),
                    message: message.to_string(),
                    cwe_id: Some("CWE-79".to_string()),
                    remediation: Some("Sanitize user input before rendering in React components.".to_string()),
                    false_positive: false,
                    suppressed: false,
                    created_at: Utc::now(),
                });
            }
        }
    }

    findings
}

/// Check for Express.js security issues
fn check_express_security(content: &str) -> Vec<SastFinding> {
    let mut findings = Vec::new();

    let patterns: &[(&str, &str, Severity, &str)] = &[
        (r#"app\.disable\s*\(\s*["']x-powered-by["']\s*\)"#, "Good: x-powered-by disabled", Severity::Info, ""), // This is good, skip
        (r"helmet\s*\(\s*\)", "Good: Helmet middleware used", Severity::Info, ""), // This is good, skip
        (r"res\.send\s*\([^)]*req\.(body|query|params)", "Potential reflected XSS", Severity::High, "JS-EXPRESS-001"),
        (r"res\.redirect\s*\([^)]*req\.(body|query|params)", "Open redirect vulnerability", Severity::High, "JS-EXPRESS-002"),
        (r"cors\s*\(\s*\{[^}]*origin\s*:\s*true", "CORS allowing all origins", Severity::Medium, "JS-EXPRESS-003"),
        (r"cookie\s*\([^)]*httpOnly\s*:\s*false", "Cookie without httpOnly flag", Severity::Medium, "JS-EXPRESS-004"),
    ];

    for (pattern, message, severity, rule_id) in patterns {
        if rule_id.is_empty() {
            continue; // Skip "good" patterns
        }
        if let Ok(regex) = Regex::new(pattern) {
            for mat in regex.find_iter(content) {
                let line_start = content[..mat.start()].lines().count() as u32;
                findings.push(SastFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    rule_id: rule_id.to_string(),
                    severity: *severity,
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
                    cwe_id: Some("CWE-16".to_string()),
                    remediation: Some("Configure Express.js security settings properly.".to_string()),
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
