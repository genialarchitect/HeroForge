//! Jenkins Pipeline Security Scanner
//!
//! Scans Jenkins pipeline files (Jenkinsfile) for security issues:
//! - Hardcoded credentials
//! - Sandbox escape attempts
//! - Untrusted shared libraries
//! - Shell injection vulnerabilities
//! - Insecure Groovy patterns

use super::types::*;
use regex::Regex;
use std::path::Path;

/// Jenkins Pipeline Security Scanner
pub struct JenkinsScanner {
    rules: Vec<CiCdRule>,
}

impl Default for JenkinsScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl JenkinsScanner {
    /// Create a new Jenkins scanner with default rules
    pub fn new() -> Self {
        Self {
            rules: Self::default_rules(),
        }
    }

    /// Get all rules
    pub fn get_rules(&self) -> Vec<CiCdRule> {
        self.rules.clone()
    }

    /// Get default security rules for Jenkins
    fn default_rules() -> Vec<CiCdRule> {
        vec![
            CiCdRule {
                id: "JENKINS001".to_string(),
                platform: CiCdPlatform::Jenkins,
                category: CiCdCategory::Secrets,
                severity: CiCdSeverity::Critical,
                title: "Hardcoded credentials in pipeline".to_string(),
                description: "Pipeline contains hardcoded credentials that should be stored in Jenkins Credentials.".to_string(),
                remediation: "Use Jenkins Credentials plugin: withCredentials([usernamePassword(...)]) { ... }".to_string(),
                cwe_id: Some("CWE-798".to_string()),
                references: vec![
                    "https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#handling-credentials".to_string(),
                ],
            },
            CiCdRule {
                id: "JENKINS002".to_string(),
                platform: CiCdPlatform::Jenkins,
                category: CiCdCategory::CodeExecution,
                severity: CiCdSeverity::Critical,
                title: "Script security sandbox bypass".to_string(),
                description: "Pipeline attempts to bypass the script security sandbox using @Grab, @NonCPS, or reflection.".to_string(),
                remediation: "Avoid sandbox bypass techniques. Request script approval through proper channels if needed.".to_string(),
                cwe_id: Some("CWE-693".to_string()),
                references: vec![
                    "https://www.jenkins.io/doc/book/managing/script-approval/".to_string(),
                ],
            },
            CiCdRule {
                id: "JENKINS003".to_string(),
                platform: CiCdPlatform::Jenkins,
                category: CiCdCategory::SupplyChain,
                severity: CiCdSeverity::High,
                title: "Untrusted shared library".to_string(),
                description: "Pipeline loads a shared library without version pinning or from an untrusted source.".to_string(),
                remediation: "Pin shared libraries to specific versions: @Library('my-lib@v1.0.0')".to_string(),
                cwe_id: Some("CWE-829".to_string()),
                references: vec![
                    "https://www.jenkins.io/doc/book/pipeline/shared-libraries/".to_string(),
                ],
            },
            CiCdRule {
                id: "JENKINS004".to_string(),
                platform: CiCdPlatform::Jenkins,
                category: CiCdCategory::Injection,
                severity: CiCdSeverity::High,
                title: "Shell command injection".to_string(),
                description: "Pipeline uses unescaped parameters in shell commands, enabling command injection.".to_string(),
                remediation: "Use proper escaping or use the 'sh' step's script parameter with GString interpolation carefully.".to_string(),
                cwe_id: Some("CWE-78".to_string()),
                references: vec![
                    "https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#string-interpolation".to_string(),
                ],
            },
            CiCdRule {
                id: "JENKINS005".to_string(),
                platform: CiCdPlatform::Jenkins,
                category: CiCdCategory::Secrets,
                severity: CiCdSeverity::High,
                title: "Password parameter visible".to_string(),
                description: "Pipeline uses a password parameter that may be visible in build logs or UI.".to_string(),
                remediation: "Use credentials binding instead of password parameters: withCredentials([string(...)]) { ... }".to_string(),
                cwe_id: Some("CWE-200".to_string()),
                references: vec![
                    "https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#handling-credentials".to_string(),
                ],
            },
            CiCdRule {
                id: "JENKINS006".to_string(),
                platform: CiCdPlatform::Jenkins,
                category: CiCdCategory::Configuration,
                severity: CiCdSeverity::Medium,
                title: "Agent set to 'any'".to_string(),
                description: "Pipeline uses 'agent any' which may run on untrusted or insecure agents.".to_string(),
                remediation: "Specify explicit agent labels for controlled execution environments.".to_string(),
                cwe_id: Some("CWE-668".to_string()),
                references: vec![
                    "https://www.jenkins.io/doc/book/pipeline/syntax/#agent".to_string(),
                ],
            },
            CiCdRule {
                id: "JENKINS007".to_string(),
                platform: CiCdPlatform::Jenkins,
                category: CiCdCategory::DataExposure,
                severity: CiCdSeverity::Medium,
                title: "Credentials exposed in logs".to_string(),
                description: "Pipeline may expose credentials in build logs through echo or print statements.".to_string(),
                remediation: "Wrap credential usage in steps that mask output, avoid echoing credential values.".to_string(),
                cwe_id: Some("CWE-532".to_string()),
                references: vec![
                    "https://www.jenkins.io/doc/pipeline/steps/credentials-binding/".to_string(),
                ],
            },
            CiCdRule {
                id: "JENKINS008".to_string(),
                platform: CiCdPlatform::Jenkins,
                category: CiCdCategory::CodeExecution,
                severity: CiCdSeverity::High,
                title: "Evaluate Groovy from external source".to_string(),
                description: "Pipeline evaluates Groovy code from external sources, enabling code injection.".to_string(),
                remediation: "Never evaluate code from untrusted sources. Use approved shared libraries instead.".to_string(),
                cwe_id: Some("CWE-94".to_string()),
                references: vec![
                    "https://www.jenkins.io/doc/book/managing/script-approval/".to_string(),
                ],
            },
            CiCdRule {
                id: "JENKINS009".to_string(),
                platform: CiCdPlatform::Jenkins,
                category: CiCdCategory::Configuration,
                severity: CiCdSeverity::Low,
                title: "Missing build timeout".to_string(),
                description: "Pipeline does not have a timeout, which could lead to resource exhaustion.".to_string(),
                remediation: "Add timeout option: options { timeout(time: 1, unit: 'HOURS') }".to_string(),
                cwe_id: Some("CWE-400".to_string()),
                references: vec![
                    "https://www.jenkins.io/doc/book/pipeline/syntax/#options".to_string(),
                ],
            },
            CiCdRule {
                id: "JENKINS010".to_string(),
                platform: CiCdPlatform::Jenkins,
                category: CiCdCategory::Configuration,
                severity: CiCdSeverity::Low,
                title: "Disabled build discard".to_string(),
                description: "Pipeline does not configure build log rotation, potentially consuming excessive disk space.".to_string(),
                remediation: "Add build discard: options { buildDiscarder(logRotator(numToKeepStr: '10')) }".to_string(),
                cwe_id: Some("CWE-400".to_string()),
                references: vec![
                    "https://www.jenkins.io/doc/book/pipeline/syntax/#options".to_string(),
                ],
            },
        ]
    }

    /// Scan pipeline content for security issues
    pub fn scan_content(&self, content: &str, file_path: &str) -> CiCdScanResult {
        let start = std::time::Instant::now();
        let mut result = CiCdScanResult::new(CiCdPlatform::Jenkins);
        result.files_scanned.push(file_path.to_string());

        // Run all checks
        self.check_hardcoded_credentials(content, file_path, &mut result);
        self.check_sandbox_bypass(content, file_path, &mut result);
        self.check_shared_libraries(content, file_path, &mut result);
        self.check_shell_injection(content, file_path, &mut result);
        self.check_password_parameters(content, file_path, &mut result);
        self.check_agent_configuration(content, file_path, &mut result);
        self.check_credential_exposure(content, file_path, &mut result);
        self.check_external_code_evaluation(content, file_path, &mut result);
        self.check_timeout(content, file_path, &mut result);
        self.check_build_discard(content, file_path, &mut result);

        result.duration_ms = start.elapsed().as_millis() as u64;
        result
    }

    /// Scan a pipeline file
    pub fn scan_file(&self, path: &Path) -> CiCdScanResult {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                let mut result = CiCdScanResult::new(CiCdPlatform::Jenkins);
                result.errors.push(format!("Failed to read file: {}", e));
                return result;
            }
        };

        self.scan_content(&content, &path.to_string_lossy())
    }

    /// Scan a repository for Jenkins pipeline files
    pub fn scan_directory(&self, path: &Path) -> CiCdScanResult {
        let start = std::time::Instant::now();
        let mut result = CiCdScanResult::new(CiCdPlatform::Jenkins);

        // Common Jenkins pipeline file names
        let jenkinsfile_names = [
            "Jenkinsfile",
            "jenkinsfile",
            "Jenkinsfile.groovy",
            "jenkinsfile.groovy",
        ];

        let mut found_any = false;

        for name in jenkinsfile_names {
            let file_path = path.join(name);
            if file_path.exists() {
                found_any = true;
                let file_result = self.scan_file(&file_path);
                result.files_scanned.extend(file_result.files_scanned);
                for finding in file_result.findings {
                    result.add_finding(finding);
                }
                result.errors.extend(file_result.errors);
            }
        }

        // Also check for *.jenkinsfile patterns
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                if let Some(name) = file_path.file_name().and_then(|n| n.to_str()) {
                    if name.ends_with(".jenkinsfile") || name.ends_with(".Jenkinsfile") {
                        found_any = true;
                        let file_result = self.scan_file(&file_path);
                        result.files_scanned.extend(file_result.files_scanned);
                        for finding in file_result.findings {
                            result.add_finding(finding);
                        }
                        result.errors.extend(file_result.errors);
                    }
                }
            }
        }

        if !found_any {
            result.errors.push("No Jenkinsfile found".to_string());
        }

        result.duration_ms = start.elapsed().as_millis() as u64;
        result
    }

    /// Check for hardcoded credentials
    fn check_hardcoded_credentials(&self, content: &str, file_path: &str, result: &mut CiCdScanResult) {
        let secret_patterns = [
            (r#"(?i)password\s*[:=]\s*['"][^'"]{8,}['"]"#, "password"),
            (r#"(?i)apikey\s*[:=]\s*['"][^'"]{16,}['"]"#, "API key"),
            (r#"(?i)secret\s*[:=]\s*['"][^'"]{16,}['"]"#, "secret"),
            (r#"(?i)token\s*[:=]\s*['"][^'"]{16,}['"]"#, "token"),
            (r#"(?i)credentials\s*\(\s*['"][^'"]+['"]\s*,\s*['"][^'"]+['"]"#, "inline credentials"),
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
            (r#"(?i)aws[_-]?secret[_-]?access[_-]?key\s*=\s*["'][^"']{20,}["']"#, "AWS Secret Key"),
            (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "private key"),
        ];

        let rule = self.rules.iter().find(|r| r.id == "JENKINS001").unwrap();

        for (pattern, secret_type) in secret_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(content) {
                    let line_num = content[..mat.start()].matches('\n').count() + 1;
                    let line_content = content.lines().nth(line_num - 1).unwrap_or("");

                    // Skip if using credentials binding properly
                    if line_content.contains("withCredentials") || line_content.contains("credentials(") {
                        continue;
                    }

                    let finding = CiCdFinding::from_rule(
                        rule,
                        file_path,
                        Some(line_num),
                        Some(Self::mask_secret(line_content)),
                    ).with_metadata("secret_type", secret_type);

                    result.add_finding(finding);
                }
            }
        }
    }

    /// Check for sandbox bypass attempts
    fn check_sandbox_bypass(&self, content: &str, file_path: &str, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "JENKINS002").unwrap();

        let bypass_patterns = [
            (r"@Grab\s*\(", "@Grab annotation"),
            (r"@NonCPS", "@NonCPS annotation"),
            (r"\.getClass\(\)\.getClassLoader\(\)", "ClassLoader access"),
            (r"java\.lang\.reflect\.", "Reflection API"),
            (r"java\.lang\.Runtime\.getRuntime\(\)", "Runtime access"),
            (r"ProcessBuilder", "ProcessBuilder"),
            (r"\.newInstance\(\)", "Dynamic instantiation"),
            (r"Eval\.", "Eval class"),
            (r"GroovyShell", "GroovyShell"),
            (r"\.metaClass", "MetaClass manipulation"),
        ];

        for (pattern, bypass_type) in bypass_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(content) {
                    let line_num = content[..mat.start()].matches('\n').count() + 1;
                    let line_content = content.lines().nth(line_num - 1).unwrap_or("");

                    let finding = CiCdFinding::from_rule(
                        rule,
                        file_path,
                        Some(line_num),
                        Some(line_content.trim().to_string()),
                    ).with_metadata("bypass_type", bypass_type);

                    result.add_finding(finding);
                }
            }
        }
    }

    /// Check for shared library usage
    fn check_shared_libraries(&self, content: &str, file_path: &str, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "JENKINS003").unwrap();

        // Pattern for @Library annotation
        let library_pattern = Regex::new(r#"@Library\s*\(\s*['"]([\w\-/]+)(?:@([\w.\-]+))?['"]\s*\)"#).unwrap();

        for cap in library_pattern.captures_iter(content) {
            let library_name = cap.get(1).map_or("", |m| m.as_str());
            let version = cap.get(2).map_or("", |m| m.as_str());

            // Check if version is pinned (not empty, not 'main', 'master', 'latest')
            let unpinned = version.is_empty()
                || version == "main"
                || version == "master"
                || version == "latest";

            if unpinned {
                let line_num = content[..cap.get(0).unwrap().start()].matches('\n').count() + 1;
                let line_content = content.lines().nth(line_num - 1).unwrap_or("");

                let finding = CiCdFinding::from_rule(
                    rule,
                    file_path,
                    Some(line_num),
                    Some(line_content.trim().to_string()),
                )
                .with_metadata("library", library_name)
                .with_metadata("version", if version.is_empty() { "none" } else { version });

                result.add_finding(finding);
            }
        }

        // Also check for library step
        let library_step_pattern = Regex::new(r#"library\s*['"]([^'"@]+)(@([^'"]+))?['"]"#).unwrap();
        for cap in library_step_pattern.captures_iter(content) {
            let library_name = cap.get(1).map_or("", |m| m.as_str());
            let version = cap.get(3).map_or("", |m| m.as_str());

            let unpinned = version.is_empty()
                || version == "main"
                || version == "master";

            if unpinned {
                let line_num = content[..cap.get(0).unwrap().start()].matches('\n').count() + 1;
                let line_content = content.lines().nth(line_num - 1).unwrap_or("");

                let finding = CiCdFinding::from_rule(
                    rule,
                    file_path,
                    Some(line_num),
                    Some(line_content.trim().to_string()),
                )
                .with_metadata("library", library_name);

                result.add_finding(finding);
            }
        }
    }

    /// Check for shell command injection
    fn check_shell_injection(&self, content: &str, file_path: &str, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "JENKINS004").unwrap();

        // Look for sh/bat steps with GString interpolation of parameters
        let sh_patterns = [
            r#"sh\s*['"]\s*.*\$\{?params\.\w+\}?"#,
            r#"sh\s*['"]\s*.*\$\{?env\.\w+\}?"#,
            r#"bat\s*['"]\s*.*\$\{?params\.\w+\}?"#,
            r#"sh\s+script:\s*['"]\s*.*\$\{"#,
            r#"sh\s*"""\s*[^"]*\$\{params\."#,
        ];

        // User-controllable parameters that could contain malicious input
        let dangerous_params = [
            "BRANCH_NAME", "CHANGE_BRANCH", "CHANGE_TITLE", "CHANGE_AUTHOR",
            "GIT_BRANCH", "GIT_COMMIT", "BUILD_TAG",
        ];

        for pattern in sh_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(content) {
                    let line_num = content[..mat.start()].matches('\n').count() + 1;
                    let line_content = content.lines().nth(line_num - 1).unwrap_or("");

                    let finding = CiCdFinding::from_rule(
                        rule,
                        file_path,
                        Some(line_num),
                        Some(line_content.trim().to_string()),
                    );

                    result.add_finding(finding);
                }
            }
        }

        // Also check for dangerous environment variable interpolation
        for param in dangerous_params {
            let env_pattern = format!(r#"sh\s*['"].*\$\{{?env\.{}|{}\}}?"#, param, param);
            if let Ok(re) = Regex::new(&env_pattern) {
                for mat in re.find_iter(content) {
                    let line_num = content[..mat.start()].matches('\n').count() + 1;
                    let line_content = content.lines().nth(line_num - 1).unwrap_or("");

                    let finding = CiCdFinding::from_rule(
                        rule,
                        file_path,
                        Some(line_num),
                        Some(line_content.trim().to_string()),
                    ).with_metadata("parameter", param);

                    result.add_finding(finding);
                }
            }
        }
    }

    /// Check for password parameters
    fn check_password_parameters(&self, content: &str, file_path: &str, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "JENKINS005").unwrap();

        let password_pattern = Regex::new(r#"password\s*\(\s*name:\s*['"]([^'"]+)['"]"#).unwrap();

        for cap in password_pattern.captures_iter(content) {
            let param_name = cap.get(1).map_or("", |m| m.as_str());
            let line_num = content[..cap.get(0).unwrap().start()].matches('\n').count() + 1;
            let line_content = content.lines().nth(line_num - 1).unwrap_or("");

            let finding = CiCdFinding::from_rule(
                rule,
                file_path,
                Some(line_num),
                Some(line_content.trim().to_string()),
            ).with_metadata("parameter", param_name);

            result.add_finding(finding);
        }
    }

    /// Check for agent configuration
    fn check_agent_configuration(&self, content: &str, file_path: &str, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "JENKINS006").unwrap();

        let agent_any_pattern = Regex::new(r"agent\s+any\b").unwrap();

        for mat in agent_any_pattern.find_iter(content) {
            let line_num = content[..mat.start()].matches('\n').count() + 1;
            let line_content = content.lines().nth(line_num - 1).unwrap_or("");

            let finding = CiCdFinding::from_rule(
                rule,
                file_path,
                Some(line_num),
                Some(line_content.trim().to_string()),
            );

            result.add_finding(finding);
        }
    }

    /// Check for credential exposure in logs
    fn check_credential_exposure(&self, content: &str, file_path: &str, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "JENKINS007").unwrap();

        // Look for echo/print of credential-like variables
        let exposure_patterns = [
            r#"echo\s+['"].*\$\{?(\w*(?:password|secret|token|key|credential)\w*)\}?"#,
            r#"println\s+['"].*\$\{?(\w*(?:password|secret|token|key|credential)\w*)\}?"#,
            r#"print\s+['"].*\$\{?(\w*(?:password|secret|token|key|credential)\w*)\}?"#,
        ];

        for pattern in exposure_patterns {
            if let Ok(re) = Regex::new(&format!("(?i){}", pattern)) {
                for mat in re.find_iter(content) {
                    let line_num = content[..mat.start()].matches('\n').count() + 1;
                    let line_content = content.lines().nth(line_num - 1).unwrap_or("");

                    let finding = CiCdFinding::from_rule(
                        rule,
                        file_path,
                        Some(line_num),
                        Some(line_content.trim().to_string()),
                    );

                    result.add_finding(finding);
                }
            }
        }
    }

    /// Check for external code evaluation
    fn check_external_code_evaluation(&self, content: &str, file_path: &str, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "JENKINS008").unwrap();

        let eval_patterns = [
            (r"evaluate\s*\(", "evaluate()"),
            (r#"load\s*\(\s*['"]http"#, "load from URL"),
            (r"readTrusted\s*\(", "readTrusted()"),
            (r"\.execute\(\)", ".execute()"),
        ];

        for (pattern, eval_type) in eval_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(content) {
                    let line_num = content[..mat.start()].matches('\n').count() + 1;
                    let line_content = content.lines().nth(line_num - 1).unwrap_or("");

                    let finding = CiCdFinding::from_rule(
                        rule,
                        file_path,
                        Some(line_num),
                        Some(line_content.trim().to_string()),
                    ).with_metadata("evaluation_type", eval_type);

                    result.add_finding(finding);
                }
            }
        }
    }

    /// Check for timeout configuration
    fn check_timeout(&self, content: &str, file_path: &str, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "JENKINS009").unwrap();

        // Check if pipeline has timeout
        let has_timeout = content.contains("timeout(") || content.contains("timeout {");

        if !has_timeout && (content.contains("pipeline {") || content.contains("pipeline{")) {
            let finding = CiCdFinding::from_rule(
                rule,
                file_path,
                Some(1),
                Some("Pipeline has no timeout configured".to_string()),
            );
            result.add_finding(finding);
        }
    }

    /// Check for build discard configuration
    fn check_build_discard(&self, content: &str, file_path: &str, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "JENKINS010").unwrap();

        // Check if pipeline has build discard
        let has_discard = content.contains("buildDiscarder") || content.contains("logRotator");

        if !has_discard && (content.contains("pipeline {") || content.contains("pipeline{")) {
            let finding = CiCdFinding::from_rule(
                rule,
                file_path,
                Some(1),
                Some("Pipeline has no build discard policy".to_string()),
            );
            result.add_finding(finding);
        }
    }

    /// Mask a secret value for display
    fn mask_secret(line: &str) -> String {
        let re = Regex::new(r#"(['"])[^'"]{8,}(['"])"#).unwrap();
        re.replace_all(line, |caps: &regex::Captures| {
            let quote = caps.get(1).map_or("\"", |m| m.as_str());
            format!("{}****MASKED****{}", quote, quote)
        }).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_hardcoded_password() {
        let scanner = JenkinsScanner::new();
        let pipeline = r#"
pipeline {
    agent any
    environment {
        DB_PASSWORD = "super_secret_password_123"
    }
    stages {
        stage('Build') {
            steps {
                echo "Building"
            }
        }
    }
}
"#;

        let result = scanner.scan_content(pipeline, "Jenkinsfile");
        assert!(result.findings.iter().any(|f| f.rule_id == "JENKINS001"));
    }

    #[test]
    fn test_detect_sandbox_bypass() {
        let scanner = JenkinsScanner::new();
        let pipeline = r#"
@Grab('org.apache.commons:commons-lang3:3.12.0')
import org.apache.commons.lang3.StringUtils

pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo StringUtils.capitalize("hello")
            }
        }
    }
}
"#;

        let result = scanner.scan_content(pipeline, "Jenkinsfile");
        assert!(result.findings.iter().any(|f| f.rule_id == "JENKINS002"));
    }

    #[test]
    fn test_detect_unpinned_library() {
        let scanner = JenkinsScanner::new();
        let pipeline = r#"
@Library('my-shared-lib') _

pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo "Building"
            }
        }
    }
}
"#;

        let result = scanner.scan_content(pipeline, "Jenkinsfile");
        assert!(result.findings.iter().any(|f| f.rule_id == "JENKINS003"));
    }

    #[test]
    fn test_detect_agent_any() {
        let scanner = JenkinsScanner::new();
        let pipeline = r#"
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo "Building"
            }
        }
    }
}
"#;

        let result = scanner.scan_content(pipeline, "Jenkinsfile");
        assert!(result.findings.iter().any(|f| f.rule_id == "JENKINS006"));
    }

    #[test]
    fn test_detect_missing_timeout() {
        let scanner = JenkinsScanner::new();
        let pipeline = r#"
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo "Building"
            }
        }
    }
}
"#;

        let result = scanner.scan_content(pipeline, "Jenkinsfile");
        assert!(result.findings.iter().any(|f| f.rule_id == "JENKINS009"));
    }

    #[test]
    fn test_no_timeout_warning_when_present() {
        let scanner = JenkinsScanner::new();
        let pipeline = r#"
pipeline {
    agent any
    options {
        timeout(time: 1, unit: 'HOURS')
    }
    stages {
        stage('Build') {
            steps {
                echo "Building"
            }
        }
    }
}
"#;

        let result = scanner.scan_content(pipeline, "Jenkinsfile");
        assert!(!result.findings.iter().any(|f| f.rule_id == "JENKINS009"));
    }
}
