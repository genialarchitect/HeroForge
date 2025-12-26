//! Java-specific code analyzer

use crate::yellow_team::types::*;
use chrono::Utc;
use regex::Regex;
use uuid::Uuid;

/// Analyze Java code for security issues
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

    // Java-specific semantic analysis
    findings.extend(check_spring_security(content));
    findings.extend(check_logging_security(content));

    findings
}

/// Check for Spring Security issues
fn check_spring_security(content: &str) -> Vec<SastFinding> {
    let mut findings = Vec::new();

    let patterns = [
        (r#"@CrossOrigin\s*\(\s*origins\s*=\s*"\*""#, "CORS allowing all origins", Severity::Medium, "JAVA-SPRING-001"),
        (r"csrf\(\)\.disable\(\)", "CSRF protection disabled", Severity::High, "JAVA-SPRING-002"),
        (r"@RequestMapping[^)]*method\s*=\s*RequestMethod\.GET[^)]*@RequestParam", "GET request with sensitive params", Severity::Low, "JAVA-SPRING-003"),
        (r"antMatchers\s*\([^)]*\)\.permitAll\(\)", "Review permitAll() usage", Severity::Low, "JAVA-SPRING-004"),
        (r#"\.password\s*\(\s*"[^"]+"\s*\)"#, "Hardcoded password in configuration", Severity::Critical, "JAVA-SPRING-005"),
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
                    cwe_id: Some("CWE-16".to_string()),
                    remediation: Some("Review Spring Security configuration.".to_string()),
                    false_positive: false,
                    suppressed: false,
                    created_at: Utc::now(),
                });
            }
        }
    }

    findings
}

/// Check for logging security issues
fn check_logging_security(content: &str) -> Vec<SastFinding> {
    let mut findings = Vec::new();

    let patterns = [
        (r#"(log|logger)\.(info|debug|warn|error)\s*\([^)]*password"#, "Password potentially logged", Severity::High, "JAVA-LOG-001"),
        (r#"(log|logger)\.(info|debug|warn|error)\s*\([^)]*secret"#, "Secret potentially logged", Severity::High, "JAVA-LOG-002"),
        (r"printStackTrace\s*\(\s*\)", "Stack trace exposed to user", Severity::Medium, "JAVA-LOG-003"),
        (r#"System\.(out|err)\.print"#, "Use proper logging framework", Severity::Low, "JAVA-LOG-004"),
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
                    category: SastCategory::InsufficientLogging,
                    file_path: String::new(),
                    location: CodeLocation {
                        line_start,
                        line_end: None,
                        column_start: None,
                        column_end: None,
                    },
                    code_snippet: Some(mat.as_str().to_string()),
                    message: message.to_string(),
                    cwe_id: Some("CWE-532".to_string()),
                    remediation: Some("Review logging practices to avoid exposing sensitive data.".to_string()),
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
