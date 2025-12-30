//! IDE File Scanner
//!
//! Quick file scanning for IDE integration with reduced rule set for real-time feedback.

use super::types::{IdeFindingResponse, QuickFixOption, ScanResponse};
use std::time::Instant;
use uuid::Uuid;

/// IDE-optimized scanner for real-time file analysis
pub struct IdeScanner {
    /// Maximum file size to scan (in KB)
    max_file_size_kb: i32,
    /// Scan timeout in seconds
    timeout_seconds: i32,
    /// Severity filter
    severity_filter: Vec<String>,
}

impl Default for IdeScanner {
    fn default() -> Self {
        Self {
            max_file_size_kb: 1024,
            timeout_seconds: 30,
            severity_filter: vec!["critical".to_string(), "high".to_string(), "medium".to_string()],
        }
    }
}

impl IdeScanner {
    /// Create a new IDE scanner with custom settings
    pub fn new(max_file_size_kb: i32, timeout_seconds: i32, severity_filter: Vec<String>) -> Self {
        Self {
            max_file_size_kb,
            timeout_seconds,
            severity_filter,
        }
    }

    /// Scan a single file for security issues
    pub fn scan_file(&self, file_path: &str, content: &str, language: Option<&str>) -> ScanResponse {
        let start = Instant::now();
        let mut findings = Vec::new();

        // Check file size
        let size_kb = content.len() as i32 / 1024;
        if size_kb > self.max_file_size_kb {
            return ScanResponse {
                file_path: file_path.to_string(),
                findings: vec![],
                scan_duration_ms: start.elapsed().as_millis() as i64,
            };
        }

        // Detect language if not provided
        let lang = language.unwrap_or_else(|| Self::detect_language(file_path));

        // Run language-specific security checks
        match lang {
            "javascript" | "typescript" | "jsx" | "tsx" => {
                findings.extend(self.scan_javascript(file_path, content));
            }
            "python" => {
                findings.extend(self.scan_python(file_path, content));
            }
            "rust" => {
                findings.extend(self.scan_rust(file_path, content));
            }
            "go" => {
                findings.extend(self.scan_go(file_path, content));
            }
            "java" | "kotlin" => {
                findings.extend(self.scan_java(file_path, content));
            }
            "php" => {
                findings.extend(self.scan_php(file_path, content));
            }
            "ruby" => {
                findings.extend(self.scan_ruby(file_path, content));
            }
            "yaml" | "yml" => {
                findings.extend(self.scan_yaml(file_path, content));
            }
            "json" => {
                findings.extend(self.scan_json(file_path, content));
            }
            _ => {
                // Generic secret scanning for unknown languages
                findings.extend(self.scan_secrets(file_path, content));
            }
        }

        // Also run generic checks
        findings.extend(self.scan_secrets(file_path, content));

        // Filter by severity
        findings.retain(|f| self.severity_filter.contains(&f.severity.to_lowercase()));

        // Deduplicate findings
        findings.dedup_by(|a, b| {
            a.rule_id == b.rule_id && a.line_start == b.line_start && a.line_end == b.line_end
        });

        ScanResponse {
            file_path: file_path.to_string(),
            findings,
            scan_duration_ms: start.elapsed().as_millis() as i64,
        }
    }

    /// Detect language from file extension
    fn detect_language(file_path: &str) -> &'static str {
        let extension = file_path.rsplit('.').next().unwrap_or("");
        match extension.to_lowercase().as_str() {
            "js" | "mjs" | "cjs" => "javascript",
            "ts" | "mts" | "cts" => "typescript",
            "jsx" => "jsx",
            "tsx" => "tsx",
            "py" | "pyw" => "python",
            "rs" => "rust",
            "go" => "go",
            "java" => "java",
            "kt" | "kts" => "kotlin",
            "php" => "php",
            "rb" => "ruby",
            "yaml" | "yml" => "yaml",
            "json" => "json",
            "xml" => "xml",
            "html" | "htm" => "html",
            "css" | "scss" | "less" => "css",
            "sh" | "bash" => "shell",
            "sql" => "sql",
            "c" | "h" => "c",
            "cpp" | "cc" | "cxx" | "hpp" => "cpp",
            "cs" => "csharp",
            _ => "unknown",
        }
    }

    /// Scan JavaScript/TypeScript for security issues
    fn scan_javascript(&self, _file_path: &str, content: &str) -> Vec<IdeFindingResponse> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num as i32 + 1;

            // Check for eval() usage
            if line.contains("eval(") {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "JS001".to_string(),
                    severity: "high".to_string(),
                    category: "Injection".to_string(),
                    title: "Dangerous eval() usage".to_string(),
                    description: "Using eval() can lead to code injection vulnerabilities".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: line.find("eval(").map(|i| i as i32),
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Consider using JSON.parse() or Function() instead".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-94".to_string()),
                    quick_fixes: vec![],
                });
            }

            // Check for innerHTML without sanitization
            if line.contains(".innerHTML") && !line.contains("DOMPurify") {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "JS002".to_string(),
                    severity: "high".to_string(),
                    category: "XSS".to_string(),
                    title: "Potential XSS via innerHTML".to_string(),
                    description: "Setting innerHTML with untrusted data can lead to XSS".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: line.find(".innerHTML").map(|i| i as i32),
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Use textContent or sanitize with DOMPurify".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-79".to_string()),
                    quick_fixes: vec![
                        QuickFixOption {
                            id: Uuid::new_v4().to_string(),
                            title: "Replace with textContent".to_string(),
                            description: "Replace innerHTML with textContent for plain text".to_string(),
                            fix_type: "replace_text".to_string(),
                            preview: Some(line.replace(".innerHTML", ".textContent")),
                        },
                    ],
                });
            }

            // Check for document.write
            if line.contains("document.write") {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "JS003".to_string(),
                    severity: "medium".to_string(),
                    category: "XSS".to_string(),
                    title: "document.write usage".to_string(),
                    description: "document.write can lead to XSS and performance issues".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: line.find("document.write").map(|i| i as i32),
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Use DOM manipulation methods instead".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-79".to_string()),
                    quick_fixes: vec![],
                });
            }
        }

        findings
    }

    /// Scan Python for security issues
    fn scan_python(&self, _file_path: &str, content: &str) -> Vec<IdeFindingResponse> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num as i32 + 1;

            // Check for exec/eval
            if line.contains("exec(") || line.contains("eval(") {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "PY001".to_string(),
                    severity: "high".to_string(),
                    category: "Injection".to_string(),
                    title: "Dangerous exec/eval usage".to_string(),
                    description: "Using exec() or eval() can lead to code injection".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: None,
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Consider using ast.literal_eval() for safe parsing".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-94".to_string()),
                    quick_fixes: vec![],
                });
            }

            // Check for pickle usage (deserialization vulnerability)
            if line.contains("pickle.load") || line.contains("pickle.loads") {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "PY002".to_string(),
                    severity: "high".to_string(),
                    category: "Deserialization".to_string(),
                    title: "Unsafe pickle deserialization".to_string(),
                    description: "Pickle deserialization of untrusted data can lead to RCE".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: None,
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Use JSON or other safe serialization formats".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-502".to_string()),
                    quick_fixes: vec![],
                });
            }

            // Check for shell=True in subprocess
            if line.contains("shell=True") {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "PY003".to_string(),
                    severity: "high".to_string(),
                    category: "Command Injection".to_string(),
                    title: "Shell injection risk".to_string(),
                    description: "Using shell=True can lead to command injection".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: line.find("shell=True").map(|i| i as i32),
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Use shell=False and pass arguments as a list".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-78".to_string()),
                    quick_fixes: vec![
                        QuickFixOption {
                            id: Uuid::new_v4().to_string(),
                            title: "Remove shell=True".to_string(),
                            description: "Remove shell=True and use list arguments".to_string(),
                            fix_type: "replace_text".to_string(),
                            preview: Some(line.replace("shell=True", "shell=False")),
                        },
                    ],
                });
            }
        }

        findings
    }

    /// Scan Rust for security issues
    fn scan_rust(&self, _file_path: &str, content: &str) -> Vec<IdeFindingResponse> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num as i32 + 1;

            // Check for unsafe blocks
            if line.trim().starts_with("unsafe") || line.contains("unsafe {") {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "RS001".to_string(),
                    severity: "medium".to_string(),
                    category: "Memory Safety".to_string(),
                    title: "Unsafe block detected".to_string(),
                    description: "Unsafe blocks bypass Rust's memory safety guarantees".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: line.find("unsafe").map(|i| i as i32),
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Ensure unsafe code is properly reviewed and documented".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-119".to_string()),
                    quick_fixes: vec![],
                });
            }

            // Check for unwrap() which can panic
            if line.contains(".unwrap()") {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "RS002".to_string(),
                    severity: "low".to_string(),
                    category: "Error Handling".to_string(),
                    title: "Potential panic with unwrap()".to_string(),
                    description: "unwrap() will panic if the value is None/Err".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: line.find(".unwrap()").map(|i| i as i32),
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Use ? operator, unwrap_or, or match for proper error handling".to_string()),
                    fix_code: None,
                    cwe_id: None,
                    quick_fixes: vec![
                        QuickFixOption {
                            id: Uuid::new_v4().to_string(),
                            title: "Replace with ?".to_string(),
                            description: "Replace unwrap() with ? for propagating errors".to_string(),
                            fix_type: "replace_text".to_string(),
                            preview: Some(line.replace(".unwrap()", "?")),
                        },
                    ],
                });
            }
        }

        findings
    }

    /// Scan Go for security issues
    fn scan_go(&self, _file_path: &str, content: &str) -> Vec<IdeFindingResponse> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num as i32 + 1;

            // Check for SQL query concatenation
            if (line.contains("db.Query") || line.contains("db.Exec")) && line.contains("+") {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "GO001".to_string(),
                    severity: "high".to_string(),
                    category: "SQL Injection".to_string(),
                    title: "Potential SQL injection".to_string(),
                    description: "String concatenation in SQL queries can lead to injection".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: None,
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Use parameterized queries with ? placeholders".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-89".to_string()),
                    quick_fixes: vec![],
                });
            }

            // Check for ignored errors
            if line.contains("_ = ") && (line.contains("err") || line.ends_with("()")) {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "GO002".to_string(),
                    severity: "medium".to_string(),
                    category: "Error Handling".to_string(),
                    title: "Error ignored".to_string(),
                    description: "Ignoring errors can hide security issues".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: None,
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Handle errors properly or log them".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-391".to_string()),
                    quick_fixes: vec![],
                });
            }
        }

        findings
    }

    /// Scan Java for security issues
    fn scan_java(&self, _file_path: &str, content: &str) -> Vec<IdeFindingResponse> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num as i32 + 1;

            // Check for SQL string concatenation
            if line.contains("executeQuery") && line.contains("+") {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "JAVA001".to_string(),
                    severity: "high".to_string(),
                    category: "SQL Injection".to_string(),
                    title: "Potential SQL injection".to_string(),
                    description: "String concatenation in SQL can lead to injection".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: None,
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Use PreparedStatement with parameterized queries".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-89".to_string()),
                    quick_fixes: vec![],
                });
            }

            // Check for Runtime.exec
            if line.contains("Runtime.getRuntime().exec") {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "JAVA002".to_string(),
                    severity: "high".to_string(),
                    category: "Command Injection".to_string(),
                    title: "Command execution detected".to_string(),
                    description: "Runtime.exec with user input can lead to command injection".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: None,
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Validate and sanitize all command arguments".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-78".to_string()),
                    quick_fixes: vec![],
                });
            }
        }

        findings
    }

    /// Scan PHP for security issues
    fn scan_php(&self, _file_path: &str, content: &str) -> Vec<IdeFindingResponse> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num as i32 + 1;

            // Check for shell_exec, exec, system, passthru
            if line.contains("shell_exec(")
                || line.contains("exec(")
                || line.contains("system(")
                || line.contains("passthru(")
            {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "PHP001".to_string(),
                    severity: "high".to_string(),
                    category: "Command Injection".to_string(),
                    title: "Command execution function".to_string(),
                    description: "Command execution with user input can lead to RCE".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: None,
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Validate and escape all command arguments".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-78".to_string()),
                    quick_fixes: vec![],
                });
            }

            // Check for $_GET/$_POST in SQL
            if (line.contains("$_GET") || line.contains("$_POST")) && line.to_lowercase().contains("query") {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "PHP002".to_string(),
                    severity: "high".to_string(),
                    category: "SQL Injection".to_string(),
                    title: "Unsanitized input in SQL".to_string(),
                    description: "Using $_GET/$_POST directly in SQL can lead to injection".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: None,
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Use prepared statements with PDO or mysqli".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-89".to_string()),
                    quick_fixes: vec![],
                });
            }
        }

        findings
    }

    /// Scan Ruby for security issues
    fn scan_ruby(&self, _file_path: &str, content: &str) -> Vec<IdeFindingResponse> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num as i32 + 1;

            // Check for system/exec calls
            if line.contains("system(") || line.contains("`") || line.contains("%x(") {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "RB001".to_string(),
                    severity: "high".to_string(),
                    category: "Command Injection".to_string(),
                    title: "Command execution detected".to_string(),
                    description: "Command execution with user input can lead to RCE".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: None,
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Use Shellwords.escape or avoid shell commands".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-78".to_string()),
                    quick_fixes: vec![],
                });
            }

            // Check for Marshal.load
            if line.contains("Marshal.load") {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "RB002".to_string(),
                    severity: "high".to_string(),
                    category: "Deserialization".to_string(),
                    title: "Unsafe deserialization".to_string(),
                    description: "Marshal.load of untrusted data can lead to RCE".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: None,
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Use JSON or other safe serialization formats".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-502".to_string()),
                    quick_fixes: vec![],
                });
            }
        }

        findings
    }

    /// Scan YAML files for security issues
    fn scan_yaml(&self, _file_path: &str, content: &str) -> Vec<IdeFindingResponse> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num as i32 + 1;

            // Check for hardcoded secrets
            let lower = line.to_lowercase();
            if (lower.contains("password:") || lower.contains("secret:") || lower.contains("api_key:"))
                && !line.contains("${")
                && !line.contains("{{")
            {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "YAML001".to_string(),
                    severity: "high".to_string(),
                    category: "Secrets".to_string(),
                    title: "Hardcoded secret detected".to_string(),
                    description: "Secrets should not be hardcoded in configuration files".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: None,
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Use environment variables or secret management".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-798".to_string()),
                    quick_fixes: vec![],
                });
            }
        }

        findings
    }

    /// Scan JSON files for security issues
    fn scan_json(&self, _file_path: &str, content: &str) -> Vec<IdeFindingResponse> {
        let mut findings = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num as i32 + 1;

            // Check for potential secrets in JSON
            let lower = line.to_lowercase();
            if (lower.contains("\"password\"") || lower.contains("\"secret\"") || lower.contains("\"api_key\""))
                && line.contains(":")
            {
                findings.push(IdeFindingResponse {
                    id: Uuid::new_v4().to_string(),
                    rule_id: "JSON001".to_string(),
                    severity: "high".to_string(),
                    category: "Secrets".to_string(),
                    title: "Potential secret in JSON".to_string(),
                    description: "Secrets should not be stored in JSON files".to_string(),
                    line_start: line_num,
                    line_end: line_num,
                    column_start: None,
                    column_end: None,
                    code_snippet: Some(line.trim().to_string()),
                    fix_suggestion: Some("Use environment variables or secret management".to_string()),
                    fix_code: None,
                    cwe_id: Some("CWE-798".to_string()),
                    quick_fixes: vec![],
                });
            }
        }

        findings
    }

    /// Scan for secrets in any file type
    fn scan_secrets(&self, _file_path: &str, content: &str) -> Vec<IdeFindingResponse> {
        let mut findings = Vec::new();

        let secret_patterns = vec![
            ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "CWE-798"),
            ("Private Key", r"-----BEGIN.*PRIVATE KEY-----", "CWE-321"),
            ("GitHub Token", r"ghp_[a-zA-Z0-9]{36}", "CWE-798"),
            ("Generic API Key", r#"api[_-]?key['"]?\s*[:=]\s*['"][a-zA-Z0-9]{20,}"#, "CWE-798"),
        ];

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num as i32 + 1;

            for (name, pattern, cwe) in &secret_patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if re.is_match(line) {
                        findings.push(IdeFindingResponse {
                            id: Uuid::new_v4().to_string(),
                            rule_id: "SEC001".to_string(),
                            severity: "critical".to_string(),
                            category: "Secrets".to_string(),
                            title: format!("{} detected", name),
                            description: format!("Potential {} found in code", name),
                            line_start: line_num,
                            line_end: line_num,
                            column_start: None,
                            column_end: None,
                            code_snippet: Some(Self::mask_secret(line)),
                            fix_suggestion: Some("Remove secret and use environment variables".to_string()),
                            fix_code: None,
                            cwe_id: Some(cwe.to_string()),
                            quick_fixes: vec![],
                        });
                        break; // One finding per line for secrets
                    }
                }
            }
        }

        findings
    }

    /// Mask secret values in code snippets
    fn mask_secret(line: &str) -> String {
        // Simple masking - replace potential secret values
        let mut masked = line.to_string();
        let patterns = vec![
            (r#"["'][A-Za-z0-9+/=]{20,}["']"#, r#""***MASKED***""#),
            (r"AKIA[0-9A-Z]{16}", "AKIA***MASKED***"),
            (r"ghp_[a-zA-Z0-9]{36}", "ghp_***MASKED***"),
        ];

        for (pattern, replacement) in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                masked = re.replace_all(&masked, replacement).to_string();
            }
        }

        masked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_language() {
        assert_eq!(IdeScanner::detect_language("test.js"), "javascript");
        assert_eq!(IdeScanner::detect_language("test.py"), "python");
        assert_eq!(IdeScanner::detect_language("test.rs"), "rust");
        assert_eq!(IdeScanner::detect_language("test.go"), "go");
    }

    #[test]
    fn test_scan_javascript_eval() {
        let scanner = IdeScanner::default();
        let content = r#"const result = eval(userInput);"#;
        let response = scanner.scan_file("test.js", content, None);
        assert!(!response.findings.is_empty());
        assert_eq!(response.findings[0].rule_id, "JS001");
    }

    #[test]
    fn test_scan_python_exec() {
        let scanner = IdeScanner::default();
        let content = r#"exec(user_code)"#;
        let response = scanner.scan_file("test.py", content, None);
        assert!(!response.findings.is_empty());
        assert_eq!(response.findings[0].rule_id, "PY001");
    }
}
