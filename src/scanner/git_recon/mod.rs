//! Git Repository Reconnaissance Module
//!
//! This module provides capabilities for scanning public GitHub and GitLab repositories
//! for exposed secrets using their APIs, without requiring full repository cloning.
//!
//! # Features
//!
//! - Enumerate repositories for users/organizations
//! - Scan repository contents for secrets via API
//! - Search commit history for accidentally committed secrets
//! - Support for GitHub and GitLab APIs
//!
//! # Security Notes
//!
//! - All detected secrets are redacted before storage
//! - API tokens are stored securely and never logged
//! - Rate limiting is implemented to avoid API throttling

pub mod github;
pub mod gitlab;
pub mod types;

pub use github::GitHubClient;
pub use gitlab::GitLabClient;
pub use types::*;

use anyhow::Result;
use log::{debug, info, warn};

use crate::scanner::secret_detection::{detect_secrets, SecretDetectionConfig};

/// Trait for git hosting platform clients
#[allow(async_fn_in_trait)]
pub trait GitPlatformClient: Send + Sync {
    /// Get the platform name
    fn platform_name(&self) -> &'static str;

    /// Enumerate repositories for a user
    async fn enumerate_user_repos(&self, username: &str) -> Result<Vec<RepoInfo>>;

    /// Enumerate repositories for an organization
    async fn enumerate_org_repos(&self, org_name: &str) -> Result<Vec<RepoInfo>>;

    /// Get repository metadata
    async fn get_repo_info(&self, owner: &str, repo: &str) -> Result<RepoInfo>;

    /// Get file contents from a repository
    async fn get_file_contents(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        ref_name: Option<&str>,
    ) -> Result<String>;

    /// List files in a repository (recursive tree)
    async fn list_repo_files(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        ref_name: Option<&str>,
    ) -> Result<Vec<RepoFile>>;

    /// Get recent commits
    async fn get_commits(
        &self,
        owner: &str,
        repo: &str,
        limit: usize,
    ) -> Result<Vec<CommitInfo>>;

    /// Get files changed in a commit
    async fn get_commit_files(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> Result<Vec<CommitFile>>;

    /// Search code in a repository
    async fn search_code(
        &self,
        owner: &str,
        repo: &str,
        query: &str,
    ) -> Result<Vec<CodeSearchResult>>;
}

/// Git repository scanner for remote repositories
pub struct GitReconScanner {
    config: GitReconConfig,
    secret_config: SecretDetectionConfig,
}

impl GitReconScanner {
    /// Create a new git recon scanner
    pub fn new(config: GitReconConfig) -> Self {
        Self {
            config,
            secret_config: SecretDetectionConfig::default(),
        }
    }

    /// Create a new scanner with custom secret detection config
    pub fn with_secret_config(mut self, config: SecretDetectionConfig) -> Self {
        self.secret_config = config;
        self
    }

    /// Scan a single repository for secrets
    pub async fn scan_repository<C: GitPlatformClient>(
        &self,
        client: &C,
        owner: &str,
        repo: &str,
    ) -> Result<GitRepoScanResult> {
        info!("Starting git recon scan for {}/{}", owner, repo);

        let mut result = GitRepoScanResult {
            owner: owner.to_string(),
            repo: repo.to_string(),
            platform: client.platform_name().to_string(),
            secrets: Vec::new(),
            files_scanned: 0,
            commits_scanned: 0,
            errors: Vec::new(),
        };

        // Get repository info
        let repo_info = match client.get_repo_info(owner, repo).await {
            Ok(info) => info,
            Err(e) => {
                result.errors.push(format!("Failed to get repo info: {}", e));
                return Ok(result);
            }
        };

        // Skip if private and we don't have access
        if repo_info.is_private && !self.config.include_private {
            debug!("Skipping private repository {}/{}", owner, repo);
            return Ok(result);
        }

        // Scan current files
        if self.config.scan_current_files {
            self.scan_repo_files(client, owner, repo, &mut result).await;
        }

        // Scan commit history
        if self.config.scan_commit_history && self.config.commit_depth > 0 {
            self.scan_commit_history(client, owner, repo, &mut result).await;
        }

        info!(
            "Git recon scan complete for {}/{}: {} secrets found, {} files scanned, {} commits scanned",
            owner, repo, result.secrets.len(), result.files_scanned, result.commits_scanned
        );

        Ok(result)
    }

    /// Enumerate and scan all repositories for a user
    pub async fn scan_user_repos<C: GitPlatformClient>(
        &self,
        client: &C,
        username: &str,
    ) -> Result<Vec<GitRepoScanResult>> {
        info!("Enumerating repositories for user: {}", username);

        let repos = client.enumerate_user_repos(username).await?;
        info!("Found {} repositories for user {}", repos.len(), username);

        let mut results = Vec::new();
        for repo_info in repos {
            if self.should_scan_repo(&repo_info) {
                match self.scan_repository(client, username, &repo_info.name).await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        warn!("Failed to scan repo {}/{}: {}", username, repo_info.name, e);
                    }
                }
            }
        }

        Ok(results)
    }

    /// Enumerate and scan all repositories for an organization
    pub async fn scan_org_repos<C: GitPlatformClient>(
        &self,
        client: &C,
        org_name: &str,
    ) -> Result<Vec<GitRepoScanResult>> {
        info!("Enumerating repositories for organization: {}", org_name);

        let repos = client.enumerate_org_repos(org_name).await?;
        info!("Found {} repositories for org {}", repos.len(), org_name);

        let mut results = Vec::new();
        for repo_info in repos {
            if self.should_scan_repo(&repo_info) {
                match self.scan_repository(client, org_name, &repo_info.name).await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        warn!("Failed to scan repo {}/{}: {}", org_name, repo_info.name, e);
                    }
                }
            }
        }

        Ok(results)
    }

    /// Determine if a repository should be scanned based on config
    fn should_scan_repo(&self, repo_info: &RepoInfo) -> bool {
        // Skip forks unless configured to include them
        if repo_info.is_fork && !self.config.include_forks {
            return false;
        }

        // Skip archived unless configured to include them
        if repo_info.is_archived && !self.config.include_archived {
            return false;
        }

        // Skip private unless configured to include them
        if repo_info.is_private && !self.config.include_private {
            return false;
        }

        // Check size limit
        if let Some(size) = repo_info.size_kb {
            if size > self.config.max_repo_size_kb {
                return false;
            }
        }

        true
    }

    /// Scan repository files for secrets
    async fn scan_repo_files<C: GitPlatformClient>(
        &self,
        client: &C,
        owner: &str,
        repo: &str,
        result: &mut GitRepoScanResult,
    ) {
        let files = match client.list_repo_files(owner, repo, "", None).await {
            Ok(f) => f,
            Err(e) => {
                result.errors.push(format!("Failed to list repo files: {}", e));
                return;
            }
        };

        for file in files {
            if !self.should_scan_file(&file) {
                continue;
            }

            match client.get_file_contents(owner, repo, &file.path, None).await {
                Ok(content) => {
                    result.files_scanned += 1;
                    self.scan_content_for_secrets(
                        &content,
                        &file.path,
                        None,
                        result,
                    );
                }
                Err(e) => {
                    debug!("Failed to get file contents for {}: {}", file.path, e);
                }
            }
        }
    }

    /// Scan commit history for secrets
    async fn scan_commit_history<C: GitPlatformClient>(
        &self,
        client: &C,
        owner: &str,
        repo: &str,
        result: &mut GitRepoScanResult,
    ) {
        let commits = match client.get_commits(owner, repo, self.config.commit_depth).await {
            Ok(c) => c,
            Err(e) => {
                result.errors.push(format!("Failed to get commits: {}", e));
                return;
            }
        };

        for commit in commits {
            result.commits_scanned += 1;

            let commit_files = match client.get_commit_files(owner, repo, &commit.sha).await {
                Ok(f) => f,
                Err(e) => {
                    debug!("Failed to get commit files for {}: {}", commit.sha, e);
                    continue;
                }
            };

            for file in commit_files {
                if !self.should_scan_path(&file.path) {
                    continue;
                }

                // Scan the patch content for secrets
                if let Some(patch) = &file.patch {
                    self.scan_content_for_secrets(
                        patch,
                        &file.path,
                        Some(&commit),
                        result,
                    );
                }
            }
        }
    }

    /// Determine if a file should be scanned
    fn should_scan_file(&self, file: &RepoFile) -> bool {
        // Only scan files (not directories)
        if file.file_type != "file" && file.file_type != "blob" {
            return false;
        }

        // Check file size
        if let Some(size) = file.size {
            if size > self.config.max_file_size {
                return false;
            }
        }

        self.should_scan_path(&file.path)
    }

    /// Determine if a path should be scanned based on patterns
    fn should_scan_path(&self, path: &str) -> bool {
        // Check exclude patterns first
        for pattern in &self.config.exclude_patterns {
            if path_matches(pattern, path) {
                return false;
            }
        }

        // If include patterns are specified, check them
        if !self.config.include_patterns.is_empty() {
            for pattern in &self.config.include_patterns {
                if path_matches(pattern, path) {
                    return true;
                }
            }
            return false;
        }

        true
    }

    /// Scan content for secrets and add findings to result
    fn scan_content_for_secrets(
        &self,
        content: &str,
        file_path: &str,
        commit: Option<&CommitInfo>,
        result: &mut GitRepoScanResult,
    ) {
        let source = crate::scanner::secret_detection::SecretSource::ConfigFile {
            path: file_path.to_string(),
        };

        let findings = detect_secrets(content, source, &self.secret_config);

        for finding in findings {
            let secret_finding = GitSecretFinding {
                secret_type: format!("{:?}", finding.secret_type),
                severity: format!("{}", finding.severity),
                redacted_value: finding.redacted_value,
                file_path: file_path.to_string(),
                line_number: finding.line,
                context: finding.context,
                commit_sha: commit.map(|c| c.sha.clone()),
                commit_author: commit.map(|c| c.author.clone()),
                commit_date: commit.map(|c| c.date.clone()),
                is_current: commit.is_none(), // If no commit, it's from current HEAD
                detection_method: finding.detection_method,
                remediation: finding.remediation,
            };

            result.secrets.push(secret_finding);
        }
    }
}

/// Simple glob-like pattern matching
fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.ends_with("/*") {
        let prefix = &pattern[..pattern.len() - 2];
        return path.starts_with(prefix);
    }

    if pattern.starts_with("*.") {
        let ext = &pattern[1..];
        return path.ends_with(ext);
    }

    if pattern.starts_with("**/") {
        let suffix = &pattern[3..];
        return path.ends_with(suffix) || path.contains(&format!("/{}", suffix));
    }

    pattern == path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_matches() {
        assert!(path_matches("*", "anything"));
        assert!(path_matches("*.js", "file.js"));
        assert!(!path_matches("*.js", "file.ts"));
        assert!(path_matches("node_modules/*", "node_modules/package/file.js"));
        assert!(!path_matches("node_modules/*", "src/file.js"));
        assert!(path_matches("**/.env", ".env"));
        assert!(path_matches("**/.env", "config/.env"));
    }
}
