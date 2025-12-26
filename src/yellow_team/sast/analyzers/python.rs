//! Python-specific code analyzer

use crate::yellow_team::types::*;
use chrono::Utc;
use regex::Regex;
use uuid::Uuid;

/// Analyze Python code for security issues
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

    // Python-specific semantic analysis
    findings.extend(check_flask_security(content));
    findings.extend(check_django_security(content));

    findings
}

/// Check for Flask security misconfigurations
fn check_flask_security(content: &str) -> Vec<SastFinding> {
    let mut findings = Vec::new();

    let patterns: &[(&str, &str, Severity, &str)] = &[
        (r"app\.run\s*\([^)]*debug\s*=\s*True", "Debug mode enabled in production", Severity::High, "PY-FLASK-001"),
        (r#"SECRET_KEY\s*=\s*["'][^"']{0,10}["']"#, "Weak or hardcoded secret key", Severity::Critical, "PY-FLASK-002"),
        (r"@app\.route.*\)\s*\ndef\s+\w+\([^)]*\):", "Missing CSRF protection", Severity::Medium, "PY-FLASK-003"),
    ];

    for (pattern, message, severity, rule_id) in patterns {
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
                    cwe_id: Some("CWE-215".to_string()),
                    remediation: Some("Configure Flask security settings properly for production.".to_string()),
                    false_positive: false,
                    suppressed: false,
                    created_at: Utc::now(),
                });
            }
        }
    }

    findings
}

/// Check for Django security misconfigurations
fn check_django_security(content: &str) -> Vec<SastFinding> {
    let mut findings = Vec::new();

    let patterns: &[(&str, &str, Severity, &str)] = &[
        (r"DEBUG\s*=\s*True", "Debug mode enabled", Severity::High, "PY-DJANGO-001"),
        (r#"ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']\s*\]"#, "Wildcard ALLOWED_HOSTS", Severity::Medium, "PY-DJANGO-002"),
        (r"CSRF_COOKIE_SECURE\s*=\s*False", "CSRF cookie not secure", Severity::Medium, "PY-DJANGO-003"),
        (r"SESSION_COOKIE_SECURE\s*=\s*False", "Session cookie not secure", Severity::Medium, "PY-DJANGO-004"),
        (r"@csrf_exempt", "CSRF protection disabled", Severity::High, "PY-DJANGO-005"),
    ];

    for (pattern, message, severity, rule_id) in patterns {
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
                    remediation: Some("Review Django security settings and enable security features.".to_string()),
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
