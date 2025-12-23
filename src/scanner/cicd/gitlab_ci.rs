//! GitLab CI/CD Security Scanner
//!
//! Scans GitLab CI/CD configuration files (.gitlab-ci.yml) for security issues:
//! - Hardcoded secrets and credentials
//! - Insecure variable configurations
//! - Remote include risks
//! - Missing security scanning jobs
//! - Privileged Docker operations

use super::types::*;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

/// GitLab CI/CD Security Scanner
pub struct GitLabCIScanner {
    rules: Vec<CiCdRule>,
}

impl Default for GitLabCIScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl GitLabCIScanner {
    /// Create a new GitLab CI scanner with default rules
    pub fn new() -> Self {
        Self {
            rules: Self::default_rules(),
        }
    }

    /// Get all rules
    pub fn get_rules(&self) -> Vec<CiCdRule> {
        self.rules.clone()
    }

    /// Get default security rules for GitLab CI/CD
    fn default_rules() -> Vec<CiCdRule> {
        vec![
            CiCdRule {
                id: "GITLAB001".to_string(),
                platform: CiCdPlatform::GitLabCI,
                category: CiCdCategory::Secrets,
                severity: CiCdSeverity::Critical,
                title: "Hardcoded secret in pipeline".to_string(),
                description: "Pipeline contains hardcoded secrets or credentials that should be stored in GitLab CI/CD variables.".to_string(),
                remediation: "Move sensitive values to GitLab CI/CD Variables (Settings > CI/CD > Variables) and reference them using $VARIABLE_NAME.".to_string(),
                cwe_id: Some("CWE-798".to_string()),
                references: vec![
                    "https://docs.gitlab.com/ee/ci/variables/".to_string(),
                ],
            },
            CiCdRule {
                id: "GITLAB002".to_string(),
                platform: CiCdPlatform::GitLabCI,
                category: CiCdCategory::Secrets,
                severity: CiCdSeverity::High,
                title: "Unprotected CI/CD variable usage".to_string(),
                description: "Pipeline uses variables that may not be protected or masked, potentially exposing sensitive data in logs.".to_string(),
                remediation: "Ensure sensitive variables are marked as 'Protected' and 'Masked' in GitLab CI/CD settings.".to_string(),
                cwe_id: Some("CWE-532".to_string()),
                references: vec![
                    "https://docs.gitlab.com/ee/ci/variables/#protect-a-cicd-variable".to_string(),
                ],
            },
            CiCdRule {
                id: "GITLAB003".to_string(),
                platform: CiCdPlatform::GitLabCI,
                category: CiCdCategory::SupplyChain,
                severity: CiCdSeverity::High,
                title: "Remote include without version pinning".to_string(),
                description: "Pipeline includes remote templates without pinning to a specific ref, risking supply chain attacks.".to_string(),
                remediation: "Pin remote includes to a specific commit SHA or tag: include: project: 'group/project' ref: 'v1.0.0'".to_string(),
                cwe_id: Some("CWE-829".to_string()),
                references: vec![
                    "https://docs.gitlab.com/ee/ci/yaml/includes.html".to_string(),
                ],
            },
            CiCdRule {
                id: "GITLAB004".to_string(),
                platform: CiCdPlatform::GitLabCI,
                category: CiCdCategory::SupplyChain,
                severity: CiCdSeverity::Medium,
                title: "External remote include".to_string(),
                description: "Pipeline includes configuration from external URLs, which could be compromised.".to_string(),
                remediation: "Mirror external templates to your own GitLab instance or use trusted GitLab templates.".to_string(),
                cwe_id: Some("CWE-829".to_string()),
                references: vec![
                    "https://docs.gitlab.com/ee/ci/yaml/includes.html#include-remote".to_string(),
                ],
            },
            CiCdRule {
                id: "GITLAB005".to_string(),
                platform: CiCdPlatform::GitLabCI,
                category: CiCdCategory::Configuration,
                severity: CiCdSeverity::Medium,
                title: "Missing security scanning jobs".to_string(),
                description: "Pipeline does not include security scanning jobs (SAST, DAST, dependency scanning, container scanning).".to_string(),
                remediation: "Add GitLab security scanning templates: include: template: Security/SAST.gitlab-ci.yml".to_string(),
                cwe_id: Some("CWE-1035".to_string()),
                references: vec![
                    "https://docs.gitlab.com/ee/user/application_security/".to_string(),
                ],
            },
            CiCdRule {
                id: "GITLAB006".to_string(),
                platform: CiCdPlatform::GitLabCI,
                category: CiCdCategory::CodeExecution,
                severity: CiCdSeverity::High,
                title: "Privileged Docker-in-Docker".to_string(),
                description: "Pipeline uses privileged Docker-in-Docker mode, which provides root access to the host.".to_string(),
                remediation: "Use Kaniko or buildah for building containers without privileged mode. If DinD is necessary, use --userns-remap.".to_string(),
                cwe_id: Some("CWE-250".to_string()),
                references: vec![
                    "https://docs.gitlab.com/ee/ci/docker/using_docker_build.html".to_string(),
                ],
            },
            CiCdRule {
                id: "GITLAB007".to_string(),
                platform: CiCdPlatform::GitLabCI,
                category: CiCdCategory::Injection,
                severity: CiCdSeverity::High,
                title: "Script injection via CI variables".to_string(),
                description: "Pipeline uses CI variables in shell scripts without proper quoting, enabling injection attacks.".to_string(),
                remediation: "Always quote variable expansions in shell commands: \"$CI_COMMIT_MESSAGE\" instead of $CI_COMMIT_MESSAGE.".to_string(),
                cwe_id: Some("CWE-78".to_string()),
                references: vec![
                    "https://docs.gitlab.com/ee/ci/variables/where_variables_can_be_used.html".to_string(),
                ],
            },
            CiCdRule {
                id: "GITLAB008".to_string(),
                platform: CiCdPlatform::GitLabCI,
                category: CiCdCategory::Permissions,
                severity: CiCdSeverity::Medium,
                title: "Overly permissive artifact access".to_string(),
                description: "Pipeline artifacts are accessible to all jobs by default, potentially exposing sensitive build outputs.".to_string(),
                remediation: "Use 'dependencies: []' or specific job names to limit artifact access.".to_string(),
                cwe_id: Some("CWE-200".to_string()),
                references: vec![
                    "https://docs.gitlab.com/ee/ci/yaml/#dependencies".to_string(),
                ],
            },
            CiCdRule {
                id: "GITLAB009".to_string(),
                platform: CiCdPlatform::GitLabCI,
                category: CiCdCategory::DataExposure,
                severity: CiCdSeverity::Medium,
                title: "Debug mode enabled".to_string(),
                description: "Pipeline has debug mode enabled, which may expose sensitive information in logs.".to_string(),
                remediation: "Remove CI_DEBUG_TRACE variable or set it to false for production pipelines.".to_string(),
                cwe_id: Some("CWE-200".to_string()),
                references: vec![
                    "https://docs.gitlab.com/ee/ci/variables/index.html#debug-logging".to_string(),
                ],
            },
            CiCdRule {
                id: "GITLAB010".to_string(),
                platform: CiCdPlatform::GitLabCI,
                category: CiCdCategory::Configuration,
                severity: CiCdSeverity::Low,
                title: "Missing job timeout".to_string(),
                description: "Pipeline jobs do not have explicit timeouts, which could lead to resource exhaustion.".to_string(),
                remediation: "Set explicit job timeouts using 'timeout' keyword.".to_string(),
                cwe_id: Some("CWE-400".to_string()),
                references: vec![
                    "https://docs.gitlab.com/ee/ci/yaml/#timeout".to_string(),
                ],
            },
        ]
    }

    /// Scan pipeline content for security issues
    pub fn scan_content(&self, content: &str, file_path: &str) -> CiCdScanResult {
        let start = std::time::Instant::now();
        let mut result = CiCdScanResult::new(CiCdPlatform::GitLabCI);
        result.files_scanned.push(file_path.to_string());

        // Parse YAML
        let pipeline: serde_yaml::Value = match serde_yaml::from_str(content) {
            Ok(v) => v,
            Err(e) => {
                result.errors.push(format!("Failed to parse YAML: {}", e));
                result.duration_ms = start.elapsed().as_millis() as u64;
                return result;
            }
        };

        // Run all checks
        self.check_hardcoded_secrets(content, file_path, &mut result);
        self.check_variable_exposure(content, file_path, &pipeline, &mut result);
        self.check_remote_includes(content, file_path, &pipeline, &mut result);
        self.check_security_scanning(content, file_path, &pipeline, &mut result);
        self.check_privileged_docker(content, file_path, &pipeline, &mut result);
        self.check_script_injection(content, file_path, &pipeline, &mut result);
        self.check_debug_mode(content, file_path, &pipeline, &mut result);
        self.check_job_timeouts(content, file_path, &pipeline, &mut result);

        result.duration_ms = start.elapsed().as_millis() as u64;
        result
    }

    /// Scan a pipeline file
    pub fn scan_file(&self, path: &Path) -> CiCdScanResult {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                let mut result = CiCdScanResult::new(CiCdPlatform::GitLabCI);
                result.errors.push(format!("Failed to read file: {}", e));
                return result;
            }
        };

        self.scan_content(&content, &path.to_string_lossy())
    }

    /// Scan a repository for GitLab CI files
    pub fn scan_directory(&self, path: &Path) -> CiCdScanResult {
        let start = std::time::Instant::now();
        let mut result = CiCdScanResult::new(CiCdPlatform::GitLabCI);

        // Check for .gitlab-ci.yml
        let gitlab_ci_path = path.join(".gitlab-ci.yml");
        if gitlab_ci_path.exists() {
            let file_result = self.scan_file(&gitlab_ci_path);
            result.files_scanned.extend(file_result.files_scanned);
            for finding in file_result.findings {
                result.add_finding(finding);
            }
            result.errors.extend(file_result.errors);
        } else {
            result.errors.push("No .gitlab-ci.yml found".to_string());
        }

        // Also check for .gitlab directory with additional configs
        let gitlab_dir = path.join(".gitlab");
        if gitlab_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&gitlab_dir) {
                for entry in entries.flatten() {
                    let file_path = entry.path();
                    if let Some(ext) = file_path.extension() {
                        if ext == "yml" || ext == "yaml" {
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
        }

        result.duration_ms = start.elapsed().as_millis() as u64;
        result
    }

    /// Check for hardcoded secrets
    fn check_hardcoded_secrets(&self, content: &str, file_path: &str, result: &mut CiCdScanResult) {
        let secret_patterns = [
            (r#"(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']"#, "password"),
            (r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*["'][^"']{16,}["']"#, "API key"),
            (r#"(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["'][^"']{16,}["']"#, "secret key"),
            (r#"(?i)(access[_-]?token|accesstoken)\s*[:=]\s*["'][^"']{16,}["']"#, "access token"),
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
            (r"glpat-[a-zA-Z0-9_-]{20,}", "GitLab Personal Access Token"),
            (r"glcbt-[a-zA-Z0-9_-]{20,}", "GitLab CI Build Token"),
            (r"GR1348941[a-zA-Z0-9_-]{20,}", "GitLab Runner Token"),
            (r"(?i)private[_-]?key\s*[:=]", "private key"),
        ];

        let rule = self.rules.iter().find(|r| r.id == "GITLAB001").unwrap();

        for (pattern, secret_type) in secret_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(content) {
                    let line_num = content[..mat.start()].matches('\n').count() + 1;
                    let line_content = content.lines().nth(line_num - 1).unwrap_or("");

                    // Skip if it's a variable reference
                    if line_content.contains("$") && !line_content.contains("\"") {
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

    /// Check for unprotected variable exposure
    fn check_variable_exposure(&self, content: &str, file_path: &str, pipeline: &serde_yaml::Value, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "GITLAB002").unwrap();

        // Check for sensitive-looking variables in scripts that might be echoed
        let sensitive_vars = [
            "PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIAL",
            "API_KEY", "APIKEY", "AUTH", "PRIVATE",
        ];

        // Look for echo/print of sensitive variables
        let echo_patterns = [
            r#"echo\s+['"$]*\$?\{?([A-Z_]+)"#,
            r#"printf\s+.*\$\{?([A-Z_]+)"#,
            r#"cat\s+<<.*\$\{?([A-Z_]+)"#,
        ];

        for pattern in echo_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    if let Some(var_match) = cap.get(1) {
                        let var_name = var_match.as_str();
                        if sensitive_vars.iter().any(|s| var_name.contains(s)) {
                            let line_num = content[..cap.get(0).unwrap().start()].matches('\n').count() + 1;
                            let line_content = content.lines().nth(line_num - 1).unwrap_or("");

                            let finding = CiCdFinding::from_rule(
                                rule,
                                file_path,
                                Some(line_num),
                                Some(line_content.trim().to_string()),
                            ).with_metadata("variable", var_name);

                            result.add_finding(finding);
                        }
                    }
                }
            }
        }
    }

    /// Check for remote includes
    fn check_remote_includes(&self, content: &str, file_path: &str, pipeline: &serde_yaml::Value, result: &mut CiCdScanResult) {
        let rule_unversioned = self.rules.iter().find(|r| r.id == "GITLAB003").unwrap();
        let rule_external = self.rules.iter().find(|r| r.id == "GITLAB004").unwrap();

        if let Some(includes) = pipeline.get("include") {
            let includes_list = if includes.is_sequence() {
                includes.as_sequence().unwrap().clone()
            } else {
                vec![includes.clone()]
            };

            for include in includes_list {
                // Check for remote URL includes
                if let Some(remote) = include.get("remote").and_then(|r| r.as_str()) {
                    let line_num = Self::find_line_number(content, remote);
                    let finding = CiCdFinding::from_rule(
                        rule_external,
                        file_path,
                        line_num,
                        Some(format!("remote: {}", remote)),
                    ).with_metadata("remote_url", remote);
                    result.add_finding(finding);
                }

                // Check for project includes without ref
                if let Some(project) = include.get("project").and_then(|p| p.as_str()) {
                    let has_ref = include.get("ref").is_some();
                    if !has_ref {
                        let line_num = Self::find_line_number(content, project);
                        let finding = CiCdFinding::from_rule(
                            rule_unversioned,
                            file_path,
                            line_num,
                            Some(format!("project: {} (no ref specified)", project)),
                        ).with_metadata("project", project);
                        result.add_finding(finding);
                    }
                }
            }
        }
    }

    /// Check for security scanning jobs
    fn check_security_scanning(&self, content: &str, file_path: &str, pipeline: &serde_yaml::Value, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "GITLAB005").unwrap();

        let security_indicators = [
            "SAST", "DAST", "dependency_scanning", "container_scanning",
            "secret_detection", "license_scanning", "Security/",
        ];

        let has_security_scanning = security_indicators.iter()
            .any(|indicator| content.contains(indicator));

        if !has_security_scanning {
            let finding = CiCdFinding::from_rule(
                rule,
                file_path,
                Some(1),
                Some("No security scanning templates included".to_string()),
            );
            result.add_finding(finding);
        }
    }

    /// Check for privileged Docker operations
    fn check_privileged_docker(&self, content: &str, file_path: &str, pipeline: &serde_yaml::Value, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "GITLAB006").unwrap();

        // Check for privileged: true in services or variables
        let privileged_patterns = [
            r"privileged:\s*true",
            r"DOCKER_HOST:\s*tcp://",
            r"docker:.*dind",
        ];

        for pattern in privileged_patterns {
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
    }

    /// Check for script injection vulnerabilities
    fn check_script_injection(&self, content: &str, file_path: &str, pipeline: &serde_yaml::Value, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "GITLAB007").unwrap();

        // User-controlled CI variables that could contain malicious input
        let dangerous_vars = [
            "CI_COMMIT_MESSAGE",
            "CI_COMMIT_TITLE",
            "CI_MERGE_REQUEST_TITLE",
            "CI_MERGE_REQUEST_DESCRIPTION",
            "CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
        ];

        // Look for unquoted variable usage in scripts
        for var in dangerous_vars {
            let unquoted_pattern = format!(r#"\$\{{{}\}}"#, var);
            let unquoted_simple = format!("${}", var);

            for pattern_str in [&unquoted_pattern, &unquoted_simple] {
                if content.contains(pattern_str) {
                    // Check if it's used in a script block without quotes
                    let lines: Vec<&str> = content.lines().collect();
                    for (idx, line) in lines.iter().enumerate() {
                        if line.contains(pattern_str) && !line.contains(&format!("\"${}\"", var)) {
                            let finding = CiCdFinding::from_rule(
                                rule,
                                file_path,
                                Some(idx + 1),
                                Some(line.trim().to_string()),
                            ).with_metadata("variable", var);
                            result.add_finding(finding);
                        }
                    }
                }
            }
        }
    }

    /// Check for debug mode
    fn check_debug_mode(&self, content: &str, file_path: &str, pipeline: &serde_yaml::Value, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "GITLAB009").unwrap();

        let debug_patterns = [
            r#"CI_DEBUG_TRACE:\s*["']?true"#,
            r#"CI_DEBUG_SERVICES:\s*["']?true"#,
            r#"DEBUG:\s*["']?true"#,
            r#"DEBUG:\s*["']?1"#,
        ];

        for pattern in debug_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(mat) = re.find(content) {
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

    /// Check for missing job timeouts
    fn check_job_timeouts(&self, content: &str, file_path: &str, pipeline: &serde_yaml::Value, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "GITLAB010").unwrap();

        // Check if there's a default timeout
        let has_default_timeout = pipeline.get("default")
            .and_then(|d| d.get("timeout"))
            .is_some();

        if has_default_timeout {
            return;
        }

        // Check each job for timeout
        let reserved_keys: HashSet<&str> = [
            "image", "services", "stages", "before_script", "after_script",
            "variables", "cache", "include", "default", "workflow", "pages",
        ].iter().copied().collect();

        if let Some(mapping) = pipeline.as_mapping() {
            for (key, value) in mapping {
                if let Some(job_name) = key.as_str() {
                    if reserved_keys.contains(job_name) {
                        continue;
                    }

                    // Check if this looks like a job (has script or extends)
                    let is_job = value.get("script").is_some() || value.get("extends").is_some();
                    if !is_job {
                        continue;
                    }

                    let has_timeout = value.get("timeout").is_some();
                    if !has_timeout {
                        let line_num = Self::find_line_number(content, job_name);
                        let finding = CiCdFinding::from_rule(
                            rule,
                            file_path,
                            line_num,
                            Some(format!("job '{}' has no timeout", job_name)),
                        ).with_job(job_name);
                        result.add_finding(finding);
                    }
                }
            }
        }
    }

    /// Find line number of a string in content
    fn find_line_number(content: &str, needle: &str) -> Option<usize> {
        content.find(needle).map(|pos| {
            content[..pos].matches('\n').count() + 1
        })
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
    fn test_detect_hardcoded_secret() {
        let scanner = GitLabCIScanner::new();
        let pipeline = r#"
variables:
  API_KEY: "sk-1234567890abcdefghijklmn"

build:
  script:
    - echo "Building"
"#;

        let result = scanner.scan_content(pipeline, ".gitlab-ci.yml");
        assert!(result.findings.iter().any(|f| f.rule_id == "GITLAB001"));
    }

    #[test]
    fn test_detect_remote_include() {
        let scanner = GitLabCIScanner::new();
        let pipeline = r#"
include:
  - remote: 'https://example.com/pipeline.yml'

build:
  script:
    - echo "Building"
"#;

        let result = scanner.scan_content(pipeline, ".gitlab-ci.yml");
        assert!(result.findings.iter().any(|f| f.rule_id == "GITLAB004"));
    }

    #[test]
    fn test_detect_unversioned_include() {
        let scanner = GitLabCIScanner::new();
        let pipeline = r#"
include:
  - project: 'my-group/my-project'
    file: '/templates/ci.yml'

build:
  script:
    - echo "Building"
"#;

        let result = scanner.scan_content(pipeline, ".gitlab-ci.yml");
        assert!(result.findings.iter().any(|f| f.rule_id == "GITLAB003"));
    }

    #[test]
    fn test_detect_privileged_dind() {
        let scanner = GitLabCIScanner::new();
        let pipeline = r#"
services:
  - name: docker:dind
    privileged: true

build:
  script:
    - docker build .
"#;

        let result = scanner.scan_content(pipeline, ".gitlab-ci.yml");
        assert!(result.findings.iter().any(|f| f.rule_id == "GITLAB006"));
    }

    #[test]
    fn test_detect_missing_security_scanning() {
        let scanner = GitLabCIScanner::new();
        let pipeline = r#"
build:
  script:
    - echo "Building"

test:
  script:
    - echo "Testing"
"#;

        let result = scanner.scan_content(pipeline, ".gitlab-ci.yml");
        assert!(result.findings.iter().any(|f| f.rule_id == "GITLAB005"));
    }

    #[test]
    fn test_no_missing_security_when_included() {
        let scanner = GitLabCIScanner::new();
        let pipeline = r#"
include:
  - template: Security/SAST.gitlab-ci.yml

build:
  script:
    - echo "Building"
"#;

        let result = scanner.scan_content(pipeline, ".gitlab-ci.yml");
        assert!(!result.findings.iter().any(|f| f.rule_id == "GITLAB005"));
    }
}
