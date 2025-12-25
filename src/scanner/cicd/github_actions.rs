//! GitHub Actions Security Scanner
//!
//! Scans GitHub Actions workflow files (.github/workflows/*.yml) for security issues:
//! - Hardcoded secrets and credentials
//! - Script injection via untrusted input
//! - Unpinned action versions
//! - Excessive permissions
//! - Supply chain risks
//! - Dangerous workflow triggers

use super::types::*;
use regex::Regex;
use std::path::Path;

/// GitHub Actions Security Scanner
pub struct GitHubActionsScanner {
    rules: Vec<CiCdRule>,
}

impl Default for GitHubActionsScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl GitHubActionsScanner {
    /// Create a new GitHub Actions scanner with default rules
    pub fn new() -> Self {
        Self {
            rules: Self::default_rules(),
        }
    }

    /// Get all rules
    pub fn get_rules(&self) -> Vec<CiCdRule> {
        self.rules.clone()
    }

    /// Get default security rules for GitHub Actions
    fn default_rules() -> Vec<CiCdRule> {
        vec![
            CiCdRule {
                id: "ACTIONS001".to_string(),
                platform: CiCdPlatform::GitHubActions,
                category: CiCdCategory::Secrets,
                severity: CiCdSeverity::Critical,
                title: "Hardcoded secret in workflow".to_string(),
                description: "Workflow contains hardcoded secrets or credentials that should be stored in GitHub Secrets.".to_string(),
                remediation: "Move sensitive values to GitHub Secrets and reference them using ${{ secrets.SECRET_NAME }}.".to_string(),
                cwe_id: Some("CWE-798".to_string()),
                references: vec![
                    "https://docs.github.com/en/actions/security-guides/encrypted-secrets".to_string(),
                ],
            },
            CiCdRule {
                id: "ACTIONS002".to_string(),
                platform: CiCdPlatform::GitHubActions,
                category: CiCdCategory::Injection,
                severity: CiCdSeverity::Critical,
                title: "Script injection via untrusted input".to_string(),
                description: "Workflow uses untrusted input (like github.event.*.body) directly in a run command, enabling script injection attacks.".to_string(),
                remediation: "Use an intermediate environment variable or GitHub Action input instead of direct interpolation in shell commands.".to_string(),
                cwe_id: Some("CWE-78".to_string()),
                references: vec![
                    "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections".to_string(),
                ],
            },
            CiCdRule {
                id: "ACTIONS003".to_string(),
                platform: CiCdPlatform::GitHubActions,
                category: CiCdCategory::SupplyChain,
                severity: CiCdSeverity::High,
                title: "Unpinned action version".to_string(),
                description: "Action reference uses a mutable tag (like @main, @master, @v1) instead of a pinned SHA commit hash.".to_string(),
                remediation: "Pin actions to a full SHA commit hash (e.g., actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675).".to_string(),
                cwe_id: Some("CWE-829".to_string()),
                references: vec![
                    "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions".to_string(),
                ],
            },
            CiCdRule {
                id: "ACTIONS004".to_string(),
                platform: CiCdPlatform::GitHubActions,
                category: CiCdCategory::SupplyChain,
                severity: CiCdSeverity::Medium,
                title: "Third-party action without verification".to_string(),
                description: "Workflow uses a third-party action that is not from a verified creator or well-known organization.".to_string(),
                remediation: "Verify the action source, check its security practices, or fork and audit the action.".to_string(),
                cwe_id: Some("CWE-829".to_string()),
                references: vec![
                    "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions".to_string(),
                ],
            },
            CiCdRule {
                id: "ACTIONS005".to_string(),
                platform: CiCdPlatform::GitHubActions,
                category: CiCdCategory::Permissions,
                severity: CiCdSeverity::High,
                title: "Excessive workflow permissions".to_string(),
                description: "Workflow has write permissions that may not be necessary, increasing attack surface.".to_string(),
                remediation: "Follow the principle of least privilege. Set 'permissions: {}' at workflow level and grant specific permissions per job.".to_string(),
                cwe_id: Some("CWE-250".to_string()),
                references: vec![
                    "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token".to_string(),
                ],
            },
            CiCdRule {
                id: "ACTIONS006".to_string(),
                platform: CiCdPlatform::GitHubActions,
                category: CiCdCategory::CodeExecution,
                severity: CiCdSeverity::Critical,
                title: "Dangerous pull_request_target with checkout".to_string(),
                description: "Workflow uses pull_request_target trigger and checks out PR code, allowing arbitrary code execution from forks.".to_string(),
                remediation: "Never checkout PR head code in pull_request_target workflows. Use pull_request trigger for building PR code.".to_string(),
                cwe_id: Some("CWE-94".to_string()),
                references: vec![
                    "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/".to_string(),
                ],
            },
            CiCdRule {
                id: "ACTIONS007".to_string(),
                platform: CiCdPlatform::GitHubActions,
                category: CiCdCategory::CodeExecution,
                severity: CiCdSeverity::High,
                title: "Workflow triggered by untrusted fork PRs".to_string(),
                description: "Workflow runs on pull_request from forks without restricting the trigger type, potentially executing malicious code.".to_string(),
                remediation: "Limit triggers to specific types (e.g., types: [labeled]) or use pull_request_target with proper isolation.".to_string(),
                cwe_id: Some("CWE-94".to_string()),
                references: vec![
                    "https://docs.github.com/en/actions/managing-workflow-runs/approving-workflow-runs-from-public-forks".to_string(),
                ],
            },
            CiCdRule {
                id: "ACTIONS008".to_string(),
                platform: CiCdPlatform::GitHubActions,
                category: CiCdCategory::Configuration,
                severity: CiCdSeverity::High,
                title: "Self-hosted runner without security controls".to_string(),
                description: "Workflow runs on self-hosted runners which may persist state between jobs and share resources.".to_string(),
                remediation: "Use ephemeral runners, ensure proper isolation, or use GitHub-hosted runners for public repositories.".to_string(),
                cwe_id: Some("CWE-668".to_string()),
                references: vec![
                    "https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners#self-hosted-runner-security".to_string(),
                ],
            },
            CiCdRule {
                id: "ACTIONS009".to_string(),
                platform: CiCdPlatform::GitHubActions,
                category: CiCdCategory::DataExposure,
                severity: CiCdSeverity::Medium,
                title: "Artifacts may contain secrets".to_string(),
                description: "Workflow uploads artifacts that may inadvertently include sensitive data.".to_string(),
                remediation: "Review artifact contents, use .gitignore patterns, and avoid uploading directories that may contain secrets.".to_string(),
                cwe_id: Some("CWE-200".to_string()),
                references: vec![
                    "https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts".to_string(),
                ],
            },
            CiCdRule {
                id: "ACTIONS010".to_string(),
                platform: CiCdPlatform::GitHubActions,
                category: CiCdCategory::DataExposure,
                severity: CiCdSeverity::Medium,
                title: "Caching potentially sensitive data".to_string(),
                description: "Workflow caches directories that may contain sensitive data like credentials or tokens.".to_string(),
                remediation: "Review cached paths and ensure they don't include sensitive files. Use cache keys that don't expose information.".to_string(),
                cwe_id: Some("CWE-200".to_string()),
                references: vec![
                    "https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows".to_string(),
                ],
            },
        ]
    }

    /// Scan workflow content for security issues
    pub fn scan_content(&self, content: &str, file_path: &str) -> CiCdScanResult {
        let start = std::time::Instant::now();
        let mut result = CiCdScanResult::new(CiCdPlatform::GitHubActions);
        result.files_scanned.push(file_path.to_string());

        // Parse YAML
        let workflow: serde_yaml::Value = match serde_yaml::from_str(content) {
            Ok(v) => v,
            Err(e) => {
                result.errors.push(format!("Failed to parse YAML: {}", e));
                result.duration_ms = start.elapsed().as_millis() as u64;
                return result;
            }
        };

        // Run all checks
        self.check_hardcoded_secrets(content, file_path, &mut result);
        self.check_script_injection(content, file_path, &workflow, &mut result);
        self.check_unpinned_actions(content, file_path, &workflow, &mut result);
        self.check_third_party_actions(content, file_path, &workflow, &mut result);
        self.check_permissions(content, file_path, &workflow, &mut result);
        self.check_pull_request_target(content, file_path, &workflow, &mut result);
        self.check_self_hosted_runners(content, file_path, &workflow, &mut result);
        self.check_artifact_uploads(content, file_path, &workflow, &mut result);
        self.check_cache_usage(content, file_path, &workflow, &mut result);

        result.duration_ms = start.elapsed().as_millis() as u64;
        result
    }

    /// Scan a workflow file
    pub fn scan_file(&self, path: &Path) -> CiCdScanResult {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                let mut result = CiCdScanResult::new(CiCdPlatform::GitHubActions);
                result.errors.push(format!("Failed to read file: {}", e));
                return result;
            }
        };

        self.scan_content(&content, &path.to_string_lossy())
    }

    /// Scan all workflow files in a directory
    pub fn scan_directory(&self, path: &Path) -> CiCdScanResult {
        let start = std::time::Instant::now();
        let mut result = CiCdScanResult::new(CiCdPlatform::GitHubActions);

        let workflows_path = path.join(".github").join("workflows");
        if !workflows_path.exists() {
            result.errors.push("No .github/workflows directory found".to_string());
            return result;
        }

        let entries = match std::fs::read_dir(&workflows_path) {
            Ok(e) => e,
            Err(e) => {
                result.errors.push(format!("Failed to read workflows directory: {}", e));
                return result;
            }
        };

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
            (r#"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["'][^"']{20,}["']"#, "AWS Secret Key"),
            (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
            (r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}", "GitHub Fine-grained PAT"),
            (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token"),
            (r"ghu_[a-zA-Z0-9]{36}", "GitHub User-to-Server Token"),
            (r"ghs_[a-zA-Z0-9]{36}", "GitHub Server-to-Server Token"),
            (r"glpat-[a-zA-Z0-9_-]{20,}", "GitLab Personal Access Token"),
            (r"(?i)bearer\s+[a-zA-Z0-9._-]{20,}", "Bearer token"),
        ];

        let rule = self.rules.iter().find(|r| r.id == "ACTIONS001").unwrap();

        for (pattern, secret_type) in secret_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(content) {
                    let line_num = content[..mat.start()].matches('\n').count() + 1;
                    let line_content = content.lines().nth(line_num - 1).unwrap_or("");

                    // Skip if it's a reference to secrets context
                    if line_content.contains("${{ secrets.") {
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

    /// Check for script injection vulnerabilities
    fn check_script_injection(&self, content: &str, file_path: &str, workflow: &serde_yaml::Value, result: &mut CiCdScanResult) {
        // Dangerous GitHub context values that could be attacker-controlled
        let dangerous_contexts = [
            "github.event.issue.title",
            "github.event.issue.body",
            "github.event.pull_request.title",
            "github.event.pull_request.body",
            "github.event.comment.body",
            "github.event.review.body",
            "github.event.review_comment.body",
            "github.event.pages.*.page_name",
            "github.event.commits.*.message",
            "github.event.commits.*.author.email",
            "github.event.commits.*.author.name",
            "github.event.head_commit.message",
            "github.event.head_commit.author.email",
            "github.event.head_commit.author.name",
            "github.head_ref",
            "github.event.workflow_run.head_branch",
            "github.event.workflow_run.head_commit.message",
        ];

        let rule = self.rules.iter().find(|r| r.id == "ACTIONS002").unwrap();

        // Look for direct interpolation in run commands
        if let Some(jobs) = workflow.get("jobs").and_then(|j| j.as_mapping()) {
            for (job_name, job) in jobs {
                if let Some(steps) = job.get("steps").and_then(|s| s.as_sequence()) {
                    for (step_idx, step) in steps.iter().enumerate() {
                        if let Some(run_cmd) = step.get("run").and_then(|r| r.as_str()) {
                            for ctx in dangerous_contexts {
                                let pattern = format!("${{{{ {} }}}}", ctx);
                                if run_cmd.contains(&pattern) || run_cmd.contains(&pattern.replace(" ", "")) {
                                    let line_num = Self::find_line_number(content, run_cmd);
                                    let default_step_name = format!("step {}", step_idx + 1);
                                    let step_name = step.get("name")
                                        .and_then(|n| n.as_str())
                                        .unwrap_or(&default_step_name);

                                    let finding = CiCdFinding::from_rule(
                                        rule,
                                        file_path,
                                        line_num,
                                        Some(run_cmd.lines().next().unwrap_or("").to_string()),
                                    )
                                    .with_job(job_name.as_str().unwrap_or("unknown"))
                                    .with_step(step_name)
                                    .with_metadata("dangerous_context", ctx);

                                    result.add_finding(finding);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check for unpinned action versions
    fn check_unpinned_actions(&self, content: &str, file_path: &str, workflow: &serde_yaml::Value, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "ACTIONS003").unwrap();
        let sha_pattern = Regex::new(r"@[a-f0-9]{40}$").unwrap();
        let mutable_tags = ["@main", "@master", "@latest", "@dev", "@develop"];

        if let Some(jobs) = workflow.get("jobs").and_then(|j| j.as_mapping()) {
            for (job_name, job) in jobs {
                if let Some(steps) = job.get("steps").and_then(|s| s.as_sequence()) {
                    for (step_idx, step) in steps.iter().enumerate() {
                        if let Some(uses) = step.get("uses").and_then(|u| u.as_str()) {
                            // Skip local actions (./path)
                            if uses.starts_with("./") || uses.starts_with("docker://") {
                                continue;
                            }

                            // Check if pinned to SHA
                            let is_pinned = sha_pattern.is_match(uses);
                            let has_mutable_tag = mutable_tags.iter().any(|t| uses.ends_with(t));

                            // Also flag semver tags like @v1, @v2, @v1.2 (these are mutable)
                            let semver_tag = Regex::new(r"@v\d+(\.\d+)?(\.\d+)?$").unwrap();
                            let has_semver = semver_tag.is_match(uses);

                            if !is_pinned && (has_mutable_tag || has_semver) {
                                let line_num = Self::find_line_number(content, uses);
                                let default_step_name = format!("step {}", step_idx + 1);
                                let step_name = step.get("name")
                                    .and_then(|n| n.as_str())
                                    .unwrap_or(&default_step_name);

                                let finding = CiCdFinding::from_rule(
                                    rule,
                                    file_path,
                                    line_num,
                                    Some(format!("uses: {}", uses)),
                                )
                                .with_job(job_name.as_str().unwrap_or("unknown"))
                                .with_step(step_name)
                                .with_metadata("action", uses);

                                result.add_finding(finding);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check for third-party actions
    fn check_third_party_actions(&self, content: &str, file_path: &str, workflow: &serde_yaml::Value, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "ACTIONS004").unwrap();

        // Well-known trusted organizations
        let trusted_orgs = [
            "actions/", "github/", "azure/", "aws-actions/", "google-github-actions/",
            "docker/", "hashicorp/", "microsoft/", "codecov/", "snyk/",
            "sonarqube/", "sonarsource/",
        ];

        if let Some(jobs) = workflow.get("jobs").and_then(|j| j.as_mapping()) {
            for (job_name, job) in jobs {
                if let Some(steps) = job.get("steps").and_then(|s| s.as_sequence()) {
                    for (step_idx, step) in steps.iter().enumerate() {
                        if let Some(uses) = step.get("uses").and_then(|u| u.as_str()) {
                            // Skip local actions
                            if uses.starts_with("./") || uses.starts_with("docker://") {
                                continue;
                            }

                            let is_trusted = trusted_orgs.iter().any(|org| uses.starts_with(org));

                            if !is_trusted {
                                let line_num = Self::find_line_number(content, uses);
                                let default_step_name = format!("step {}", step_idx + 1);
                                let step_name = step.get("name")
                                    .and_then(|n| n.as_str())
                                    .unwrap_or(&default_step_name);

                                let finding = CiCdFinding::from_rule(
                                    rule,
                                    file_path,
                                    line_num,
                                    Some(format!("uses: {}", uses)),
                                )
                                .with_job(job_name.as_str().unwrap_or("unknown"))
                                .with_step(step_name)
                                .with_metadata("action", uses);

                                result.add_finding(finding);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check for excessive permissions
    fn check_permissions(&self, content: &str, file_path: &str, workflow: &serde_yaml::Value, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "ACTIONS005").unwrap();

        let sensitive_permissions = [
            "contents: write",
            "packages: write",
            "actions: write",
            "security-events: write",
            "deployments: write",
            "id-token: write",
        ];

        // Check workflow-level permissions
        if let Some(permissions) = workflow.get("permissions") {
            if permissions.as_str() == Some("write-all") {
                let line_num = Self::find_line_number(content, "permissions: write-all");
                let finding = CiCdFinding::from_rule(
                    rule,
                    file_path,
                    line_num,
                    Some("permissions: write-all".to_string()),
                ).with_metadata("permission_level", "write-all");
                result.add_finding(finding);
            } else if let Some(perms) = permissions.as_mapping() {
                for (perm, value) in perms {
                    if let (Some(perm_name), Some(perm_value)) = (perm.as_str(), value.as_str()) {
                        let perm_str = format!("{}: {}", perm_name, perm_value);
                        if sensitive_permissions.contains(&perm_str.as_str()) {
                            let line_num = Self::find_line_number(content, &perm_str);
                            let finding = CiCdFinding::from_rule(
                                rule,
                                file_path,
                                line_num,
                                Some(perm_str.clone()),
                            ).with_metadata("permission", &perm_str);
                            result.add_finding(finding);
                        }
                    }
                }
            }
        }

        // Check job-level permissions
        if let Some(jobs) = workflow.get("jobs").and_then(|j| j.as_mapping()) {
            for (job_name, job) in jobs {
                if let Some(permissions) = job.get("permissions") {
                    if permissions.as_str() == Some("write-all") {
                        let line_num = Self::find_line_number(content, "permissions: write-all");
                        let finding = CiCdFinding::from_rule(
                            rule,
                            file_path,
                            line_num,
                            Some("permissions: write-all".to_string()),
                        )
                        .with_job(job_name.as_str().unwrap_or("unknown"))
                        .with_metadata("permission_level", "write-all");
                        result.add_finding(finding);
                    }
                }
            }
        }
    }

    /// Check for dangerous pull_request_target usage
    fn check_pull_request_target(&self, content: &str, file_path: &str, workflow: &serde_yaml::Value, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "ACTIONS006").unwrap();

        // Check if workflow uses pull_request_target trigger
        let uses_pr_target = if let Some(on) = workflow.get("on") {
            if on.is_string() && on.as_str() == Some("pull_request_target") {
                true
            } else if let Some(triggers) = on.as_mapping() {
                triggers.contains_key(&serde_yaml::Value::String("pull_request_target".to_string()))
            } else if let Some(triggers) = on.as_sequence() {
                triggers.iter().any(|t| t.as_str() == Some("pull_request_target"))
            } else {
                false
            }
        } else {
            false
        };

        if !uses_pr_target {
            return;
        }

        // Check if any job checks out PR code
        if let Some(jobs) = workflow.get("jobs").and_then(|j| j.as_mapping()) {
            for (job_name, job) in jobs {
                if let Some(steps) = job.get("steps").and_then(|s| s.as_sequence()) {
                    for (step_idx, step) in steps.iter().enumerate() {
                        if let Some(uses) = step.get("uses").and_then(|u| u.as_str()) {
                            if uses.contains("checkout") {
                                // Check if it explicitly checks out PR head
                                let checks_pr_head = step.get("with")
                                    .and_then(|w| w.get("ref"))
                                    .and_then(|r| r.as_str())
                                    .map(|r| r.contains("github.event.pull_request.head"))
                                    .unwrap_or(false);

                                if checks_pr_head {
                                    let line_num = Self::find_line_number(content, uses);
                                    let default_step_name = format!("step {}", step_idx + 1);
                                    let step_name = step.get("name")
                                        .and_then(|n| n.as_str())
                                        .unwrap_or(&default_step_name);

                                    let finding = CiCdFinding::from_rule(
                                        rule,
                                        file_path,
                                        line_num,
                                        Some(format!("uses: {} with PR head checkout", uses)),
                                    )
                                    .with_job(job_name.as_str().unwrap_or("unknown"))
                                    .with_step(step_name);

                                    result.add_finding(finding);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check for self-hosted runners
    fn check_self_hosted_runners(&self, content: &str, file_path: &str, workflow: &serde_yaml::Value, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "ACTIONS008").unwrap();

        if let Some(jobs) = workflow.get("jobs").and_then(|j| j.as_mapping()) {
            for (job_name, job) in jobs {
                if let Some(runs_on) = job.get("runs-on") {
                    let is_self_hosted = if let Some(runner) = runs_on.as_str() {
                        runner.contains("self-hosted")
                    } else if let Some(runners) = runs_on.as_sequence() {
                        runners.iter().any(|r| r.as_str() == Some("self-hosted"))
                    } else {
                        false
                    };

                    if is_self_hosted {
                        let line_num = Self::find_line_number(content, "self-hosted");
                        let finding = CiCdFinding::from_rule(
                            rule,
                            file_path,
                            line_num,
                            Some(format!("runs-on: {:?}", runs_on)),
                        )
                        .with_job(job_name.as_str().unwrap_or("unknown"));

                        result.add_finding(finding);
                    }
                }
            }
        }
    }

    /// Check for artifact uploads that might contain secrets
    fn check_artifact_uploads(&self, content: &str, file_path: &str, workflow: &serde_yaml::Value, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "ACTIONS009").unwrap();

        // Paths that might contain secrets
        let sensitive_paths = [
            ".env", "*.env", ".env.*",
            ".git", ".git/",
            "node_modules/",
            ".aws/", ".ssh/",
            "credentials", "secrets",
            "*.pem", "*.key", "*.p12",
        ];

        if let Some(jobs) = workflow.get("jobs").and_then(|j| j.as_mapping()) {
            for (job_name, job) in jobs {
                if let Some(steps) = job.get("steps").and_then(|s| s.as_sequence()) {
                    for (step_idx, step) in steps.iter().enumerate() {
                        if let Some(uses) = step.get("uses").and_then(|u| u.as_str()) {
                            if uses.contains("upload-artifact") {
                                if let Some(with) = step.get("with") {
                                    let path = with.get("path")
                                        .and_then(|p| p.as_str())
                                        .unwrap_or("");

                                    // Check if uploading potentially sensitive paths
                                    let is_sensitive = sensitive_paths.iter()
                                        .any(|sp| path.contains(sp) || path == "." || path == "./");

                                    if is_sensitive || path == "." || path == "./" {
                                        let line_num = Self::find_line_number(content, path);
                                        let default_step_name = format!("step {}", step_idx + 1);
                                        let step_name = step.get("name")
                                            .and_then(|n| n.as_str())
                                            .unwrap_or(&default_step_name);

                                        let finding = CiCdFinding::from_rule(
                                            rule,
                                            file_path,
                                            line_num,
                                            Some(format!("path: {}", path)),
                                        )
                                        .with_job(job_name.as_str().unwrap_or("unknown"))
                                        .with_step(step_name)
                                        .with_metadata("upload_path", path);

                                        result.add_finding(finding);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check for cache usage with potentially sensitive data
    fn check_cache_usage(&self, content: &str, file_path: &str, workflow: &serde_yaml::Value, result: &mut CiCdScanResult) {
        let rule = self.rules.iter().find(|r| r.id == "ACTIONS010").unwrap();

        // Paths that shouldn't be cached
        let sensitive_cache_paths = [
            ".env", "*.env",
            ".aws", ".ssh", ".gnupg",
            "credentials", "secrets",
        ];

        if let Some(jobs) = workflow.get("jobs").and_then(|j| j.as_mapping()) {
            for (job_name, job) in jobs {
                if let Some(steps) = job.get("steps").and_then(|s| s.as_sequence()) {
                    for (step_idx, step) in steps.iter().enumerate() {
                        if let Some(uses) = step.get("uses").and_then(|u| u.as_str()) {
                            if uses.contains("/cache@") || uses.contains("/cache-") {
                                if let Some(with) = step.get("with") {
                                    let path = with.get("path")
                                        .and_then(|p| p.as_str())
                                        .unwrap_or("");

                                    let is_sensitive = sensitive_cache_paths.iter()
                                        .any(|sp| path.contains(sp));

                                    if is_sensitive {
                                        let line_num = Self::find_line_number(content, path);
                                        let default_step_name = format!("step {}", step_idx + 1);
                                        let step_name = step.get("name")
                                            .and_then(|n| n.as_str())
                                            .unwrap_or(&default_step_name);

                                        let finding = CiCdFinding::from_rule(
                                            rule,
                                            file_path,
                                            line_num,
                                            Some(format!("cache path: {}", path)),
                                        )
                                        .with_job(job_name.as_str().unwrap_or("unknown"))
                                        .with_step(step_name)
                                        .with_metadata("cache_path", path);

                                        result.add_finding(finding);
                                    }
                                }
                            }
                        }
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
        // Simple masking - show first 4 and last 4 chars
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
        let scanner = GitHubActionsScanner::new();
        let workflow = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -H "Authorization: Bearer ghp_1234567890abcdefghijklmnopqrstuvwxyz" https://api.github.com
"#;

        let result = scanner.scan_content(workflow, "test.yml");
        assert!(result.findings.iter().any(|f| f.rule_id == "ACTIONS001"));
    }

    #[test]
    fn test_detect_script_injection() {
        let scanner = GitHubActionsScanner::new();
        let workflow = r#"name: Test
on: issues
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Dangerous step
        run: 'echo "Issue: ${{ github.event.issue.title }}"'
"#;

        let result = scanner.scan_content(workflow, "test.yml");
        assert!(result.findings.iter().any(|f| f.rule_id == "ACTIONS002"),
            "Expected ACTIONS002 finding for script injection. Found: {:?}, Errors: {:?}",
            result.findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>(),
            result.errors);
    }

    #[test]
    fn test_detect_unpinned_action() {
        let scanner = GitHubActionsScanner::new();
        let workflow = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
"#;

        let result = scanner.scan_content(workflow, "test.yml");
        assert!(result.findings.iter().any(|f| f.rule_id == "ACTIONS003"));
    }

    #[test]
    fn test_detect_third_party_action() {
        let scanner = GitHubActionsScanner::new();
        let workflow = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: some-random-org/random-action@v1
"#;

        let result = scanner.scan_content(workflow, "test.yml");
        assert!(result.findings.iter().any(|f| f.rule_id == "ACTIONS004"));
    }

    #[test]
    fn test_detect_self_hosted_runner() {
        let scanner = GitHubActionsScanner::new();
        let workflow = r#"
name: Test
on: push
jobs:
  test:
    runs-on: self-hosted
    steps:
      - run: echo "hello"
"#;

        let result = scanner.scan_content(workflow, "test.yml");
        assert!(result.findings.iter().any(|f| f.rule_id == "ACTIONS008"));
    }
}
