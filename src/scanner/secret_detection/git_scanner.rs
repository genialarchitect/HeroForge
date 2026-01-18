//! Git repository scanner for secret detection
//!
//! Scans git repositories for secrets in:
//! - Current working tree
//! - Commit history
//! - Deleted files in history
//! - Staged changes

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

use super::entropy::{EntropyConfig, find_high_entropy_strings};
use super::types::{SecretFinding, SecretSeverity, SecretSource};
use super::{detect_secrets, SecretDetectionConfig};

/// Configuration for git repository scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitScanConfig {
    /// Number of commits to scan in history (0 = current only)
    pub commit_depth: usize,
    /// Scan deleted files in history
    pub scan_deleted_files: bool,
    /// Scan staged changes
    pub scan_staged: bool,
    /// File patterns to include (glob patterns)
    pub include_patterns: Vec<String>,
    /// File patterns to exclude (glob patterns)
    pub exclude_patterns: Vec<String>,
    /// Enable entropy-based detection
    pub entropy_detection: bool,
    /// Branch to scan (None = current branch)
    pub branch: Option<String>,
    /// Maximum file size to scan (bytes)
    pub max_file_size: usize,
    /// Secret detection config
    #[serde(skip)]
    pub secret_config: SecretDetectionConfig,
    /// Entropy detection config
    #[serde(skip)]
    pub entropy_config: EntropyConfig,
}

impl Default for GitScanConfig {
    fn default() -> Self {
        Self {
            commit_depth: 50,
            scan_deleted_files: true,
            scan_staged: true,
            include_patterns: vec!["*".to_string()],
            exclude_patterns: vec![
                "*.png".to_string(),
                "*.jpg".to_string(),
                "*.jpeg".to_string(),
                "*.gif".to_string(),
                "*.ico".to_string(),
                "*.svg".to_string(),
                "*.woff".to_string(),
                "*.woff2".to_string(),
                "*.ttf".to_string(),
                "*.eot".to_string(),
                "*.pdf".to_string(),
                "*.zip".to_string(),
                "*.tar".to_string(),
                "*.gz".to_string(),
                "*.exe".to_string(),
                "*.dll".to_string(),
                "*.so".to_string(),
                "*.dylib".to_string(),
                "node_modules/*".to_string(),
                "vendor/*".to_string(),
                ".git/*".to_string(),
            ],
            entropy_detection: true,
            branch: None,
            max_file_size: 1024 * 1024, // 1MB
            secret_config: SecretDetectionConfig::default(),
            entropy_config: EntropyConfig::default(),
        }
    }
}

/// A secret finding from git history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitSecretFinding {
    /// The underlying secret finding
    pub finding: SecretFinding,
    /// Git commit SHA where the secret was found
    pub commit_sha: String,
    /// Commit author
    pub commit_author: Option<String>,
    /// Commit date
    pub commit_date: Option<String>,
    /// File path in the repository
    pub file_path: String,
    /// Whether the secret is in the current HEAD
    pub is_current: bool,
    /// Line number in the file
    pub line_number: Option<usize>,
    /// Whether the secret was introduced in this commit
    pub introduced_in_commit: bool,
    /// Whether the secret was removed in a later commit
    pub removed: bool,
}

/// Git commit metadata
#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub sha: String,
    pub author: String,
    pub date: String,
    pub message: String,
}

/// Git repository scanner
pub struct GitSecretScanner {
    config: GitScanConfig,
}

impl GitSecretScanner {
    /// Create a new git secret scanner with the given configuration
    pub fn new(config: GitScanConfig) -> Self {
        Self { config }
    }

    /// Check if a path is a git repository
    pub fn is_git_repo(path: &Path) -> bool {
        path.join(".git").exists() || path.join(".git").is_file()
    }

    /// Get the current HEAD commit SHA
    fn get_head_sha(&self, repo_path: &Path) -> Result<String> {
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(repo_path)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to get HEAD SHA"));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Get commit history
    fn get_commit_history(&self, repo_path: &Path, depth: usize) -> Result<Vec<CommitInfo>> {
        let mut args = vec![
            "log".to_string(),
            format!("-{}", depth),
            "--pretty=format:%H|%an|%aI|%s".to_string(),
        ];

        if let Some(ref branch) = self.config.branch {
            args.push(branch.clone());
        }

        let output = Command::new("git")
            .args(&args)
            .current_dir(repo_path)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to get commit history"));
        }

        let commits = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.splitn(4, '|').collect();
                if parts.len() >= 4 {
                    Some(CommitInfo {
                        sha: parts[0].to_string(),
                        author: parts[1].to_string(),
                        date: parts[2].to_string(),
                        message: parts[3].to_string(),
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(commits)
    }

    /// Get list of files changed in a commit
    fn get_commit_files(&self, repo_path: &Path, sha: &str) -> Result<Vec<String>> {
        let output = Command::new("git")
            .args(["diff-tree", "--no-commit-id", "--name-only", "-r", sha])
            .current_dir(repo_path)
            .output()?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect())
    }

    /// Get file content at a specific commit
    fn get_file_at_commit(&self, repo_path: &Path, sha: &str, file_path: &str) -> Result<String> {
        let output = Command::new("git")
            .args(["show", &format!("{}:{}", sha, file_path)])
            .current_dir(repo_path)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to get file content"));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Get current working tree files
    fn get_working_tree_files(&self, repo_path: &Path) -> Result<Vec<String>> {
        let output = Command::new("git")
            .args(["ls-files"])
            .current_dir(repo_path)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to list working tree files"));
        }

        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect())
    }

    /// Get staged files
    fn get_staged_files(&self, repo_path: &Path) -> Result<Vec<String>> {
        let output = Command::new("git")
            .args(["diff", "--cached", "--name-only"])
            .current_dir(repo_path)
            .output()?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect())
    }

    /// Check if a file should be scanned based on patterns
    fn should_scan_file(&self, file_path: &str) -> bool {
        // Check exclude patterns first
        for pattern in &self.config.exclude_patterns {
            if glob_match(pattern, file_path) {
                return false;
            }
        }

        // Check include patterns
        for pattern in &self.config.include_patterns {
            if glob_match(pattern, file_path) {
                return true;
            }
        }

        // If no include patterns match, include by default if patterns are empty or just "*"
        self.config.include_patterns.is_empty()
            || self.config.include_patterns.iter().any(|p| p == "*")
    }

    /// Scan a single file for secrets
    fn scan_file_content(
        &self,
        content: &str,
        file_path: &str,
        commit_sha: &str,
        commit_info: Option<&CommitInfo>,
        is_current: bool,
    ) -> Vec<GitSecretFinding> {
        let mut findings = Vec::new();

        // Pattern-based detection
        let source = SecretSource::ConfigFile {
            path: file_path.to_string(),
        };
        let pattern_findings = detect_secrets(content, source, &self.config.secret_config);

        for finding in pattern_findings {
            findings.push(GitSecretFinding {
                finding: finding.clone(),
                commit_sha: commit_sha.to_string(),
                commit_author: commit_info.map(|c| c.author.clone()),
                commit_date: commit_info.map(|c| c.date.clone()),
                file_path: file_path.to_string(),
                is_current,
                line_number: finding.line,
                introduced_in_commit: true,
                removed: !is_current,
            });
        }

        // Entropy-based detection
        if self.config.entropy_detection {
            let entropy_findings = find_high_entropy_strings(content, &self.config.entropy_config);

            for result in entropy_findings {
                let finding = SecretFinding {
                    secret_type: super::types::SecretType::GenericSecretKey,
                    severity: if result.confidence > 0.7 {
                        SecretSeverity::High
                    } else if result.confidence > 0.5 {
                        SecretSeverity::Medium
                    } else {
                        SecretSeverity::Low
                    },
                    redacted_value: redact_secret(&result.value),
                    source: SecretSource::ConfigFile {
                        path: file_path.to_string(),
                    },
                    line: None,
                    column: None,
                    context: Some(format!(
                        "High entropy string detected (entropy: {:.2}, confidence: {:.0}%)",
                        result.entropy,
                        result.confidence * 100.0
                    )),
                    remediation: Some(
                        "Review this high-entropy string. If it's a secret, rotate it and remove from history.".to_string()
                    ),
                    verified: false,
                    entropy_score: Some(result.entropy),
                    detection_method: Some("entropy".to_string()),
                };

                findings.push(GitSecretFinding {
                    finding,
                    commit_sha: commit_sha.to_string(),
                    commit_author: commit_info.map(|c| c.author.clone()),
                    commit_date: commit_info.map(|c| c.date.clone()),
                    file_path: file_path.to_string(),
                    is_current,
                    line_number: None,
                    introduced_in_commit: true,
                    removed: !is_current,
                });
            }
        }

        findings
    }

    /// Scan a git repository for secrets
    pub fn scan_repository(&self, repo_path: &Path) -> Result<Vec<GitSecretFinding>> {
        if !Self::is_git_repo(repo_path) {
            return Err(anyhow!("Not a git repository: {:?}", repo_path));
        }

        let mut all_findings = Vec::new();
        let head_sha = self.get_head_sha(repo_path)?;

        // Scan current working tree
        log::info!("Scanning current working tree...");
        let working_files = self.get_working_tree_files(repo_path)?;

        for file_path in &working_files {
            if !self.should_scan_file(file_path) {
                continue;
            }

            let full_path = repo_path.join(file_path);
            if let Ok(metadata) = full_path.metadata() {
                if metadata.len() > self.config.max_file_size as u64 {
                    continue;
                }
            }

            if let Ok(content) = std::fs::read_to_string(&full_path) {
                let findings = self.scan_file_content(&content, file_path, &head_sha, None, true);
                all_findings.extend(findings);
            }
        }

        // Scan staged changes
        if self.config.scan_staged {
            log::info!("Scanning staged changes...");
            let staged_files = self.get_staged_files(repo_path)?;

            for file_path in &staged_files {
                if !self.should_scan_file(file_path) {
                    continue;
                }

                if let Ok(content) = self.get_file_at_commit(repo_path, "HEAD", file_path) {
                    let findings = self.scan_file_content(&content, file_path, "STAGED", None, true);
                    all_findings.extend(findings);
                }
            }
        }

        // Scan commit history
        if self.config.commit_depth > 0 {
            log::info!("Scanning {} commits in history...", self.config.commit_depth);
            let commits = self.get_commit_history(repo_path, self.config.commit_depth)?;

            for commit in &commits {
                let files = self.get_commit_files(repo_path, &commit.sha)?;

                for file_path in files {
                    if !self.should_scan_file(&file_path) {
                        continue;
                    }

                    if let Ok(content) = self.get_file_at_commit(repo_path, &commit.sha, &file_path) {
                        if content.len() > self.config.max_file_size {
                            continue;
                        }

                        let is_current = commit.sha == head_sha;
                        let findings = self.scan_file_content(
                            &content,
                            &file_path,
                            &commit.sha,
                            Some(commit),
                            is_current,
                        );
                        all_findings.extend(findings);
                    }
                }
            }
        }

        // Deduplicate findings (same secret in same file across commits)
        deduplicate_findings(&mut all_findings);

        log::info!("Found {} secret(s) in repository", all_findings.len());
        Ok(all_findings)
    }

    /// Scan a specific commit range
    pub fn scan_commit_range(
        &self,
        repo_path: &Path,
        from_sha: &str,
        to_sha: &str,
    ) -> Result<Vec<GitSecretFinding>> {
        if !Self::is_git_repo(repo_path) {
            return Err(anyhow!("Not a git repository: {:?}", repo_path));
        }

        let mut all_findings = Vec::new();

        // Get commits in range
        let output = Command::new("git")
            .args([
                "log",
                "--pretty=format:%H|%an|%aI|%s",
                &format!("{}..{}", from_sha, to_sha),
            ])
            .current_dir(repo_path)
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to get commit range"));
        }

        let commits: Vec<CommitInfo> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.splitn(4, '|').collect();
                if parts.len() >= 4 {
                    Some(CommitInfo {
                        sha: parts[0].to_string(),
                        author: parts[1].to_string(),
                        date: parts[2].to_string(),
                        message: parts[3].to_string(),
                    })
                } else {
                    None
                }
            })
            .collect();

        for commit in &commits {
            let files = self.get_commit_files(repo_path, &commit.sha)?;

            for file_path in files {
                if !self.should_scan_file(&file_path) {
                    continue;
                }

                if let Ok(content) = self.get_file_at_commit(repo_path, &commit.sha, &file_path) {
                    if content.len() > self.config.max_file_size {
                        continue;
                    }

                    let findings = self.scan_file_content(
                        &content,
                        &file_path,
                        &commit.sha,
                        Some(commit),
                        false,
                    );
                    all_findings.extend(findings);
                }
            }
        }

        deduplicate_findings(&mut all_findings);
        Ok(all_findings)
    }
}

/// Simple glob pattern matching
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.ends_with("/*") {
        let prefix = &pattern[..pattern.len() - 2];
        return text.starts_with(prefix);
    }

    if pattern.starts_with("*.") {
        let ext = &pattern[1..];
        return text.ends_with(ext);
    }

    pattern == text
}

/// Redact a secret value for safe storage/display
fn redact_secret(value: &str) -> String {
    let len = value.len();
    if len <= 8 {
        "*".repeat(len)
    } else {
        format!(
            "{}...{}",
            &value[..4],
            &value[len - 4..]
        )
    }
}

/// Deduplicate findings based on secret value and file
fn deduplicate_findings(findings: &mut Vec<GitSecretFinding>) {
    use std::collections::HashSet;

    let mut seen = HashSet::new();
    findings.retain(|f| {
        let key = format!(
            "{}:{}:{}",
            f.file_path,
            f.finding.redacted_value,
            f.finding.secret_type.to_string()
        );
        seen.insert(key)
    });
}

impl super::types::SecretType {
    /// Convert to debug string representation
    pub fn as_debug_string(&self) -> String {
        format!("{:?}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*.js", "file.js"));
        assert!(!glob_match("*.js", "file.ts"));
        assert!(glob_match("node_modules/*", "node_modules/package/file.js"));
        assert!(!glob_match("node_modules/*", "src/file.js"));
    }

    #[test]
    fn test_redact_secret() {
        assert_eq!(redact_secret("short"), "*****");
        assert_eq!(redact_secret("a_longer_secret_value"), "a_lo...alue");
    }
}
