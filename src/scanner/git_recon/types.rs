//! Types for Git Repository Reconnaissance
//!
//! Data structures for GitHub and GitLab API responses and scan results.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Configuration for git recon scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitReconConfig {
    /// Include private repositories (requires authentication)
    pub include_private: bool,
    /// Include forked repositories
    pub include_forks: bool,
    /// Include archived repositories
    pub include_archived: bool,
    /// Scan current files in HEAD
    pub scan_current_files: bool,
    /// Scan commit history for secrets
    pub scan_commit_history: bool,
    /// Number of commits to scan in history
    pub commit_depth: usize,
    /// Maximum repository size to scan (KB)
    pub max_repo_size_kb: u64,
    /// Maximum file size to scan (bytes)
    pub max_file_size: usize,
    /// File patterns to include (glob patterns)
    pub include_patterns: Vec<String>,
    /// File patterns to exclude (glob patterns)
    pub exclude_patterns: Vec<String>,
}

impl Default for GitReconConfig {
    fn default() -> Self {
        Self {
            include_private: false,
            include_forks: false,
            include_archived: false,
            scan_current_files: true,
            scan_commit_history: true,
            commit_depth: 50,
            max_repo_size_kb: 500_000, // 500 MB
            max_file_size: 1024 * 1024, // 1 MB
            include_patterns: vec![],
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
                "package-lock.json".to_string(),
                "yarn.lock".to_string(),
                "Cargo.lock".to_string(),
            ],
        }
    }
}

/// Repository information from GitHub/GitLab API
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RepoInfo {
    /// Repository name
    pub name: String,
    /// Full repository name (owner/repo)
    pub full_name: String,
    /// Repository description
    pub description: Option<String>,
    /// Repository URL
    pub url: String,
    /// Clone URL (HTTPS)
    pub clone_url: String,
    /// Default branch
    pub default_branch: String,
    /// Whether the repository is private
    pub is_private: bool,
    /// Whether the repository is a fork
    pub is_fork: bool,
    /// Whether the repository is archived
    pub is_archived: bool,
    /// Repository size in KB
    pub size_kb: Option<u64>,
    /// Programming language
    pub language: Option<String>,
    /// Star count
    pub stars: Option<u64>,
    /// Fork count
    pub forks: Option<u64>,
    /// Last push date
    pub pushed_at: Option<String>,
    /// Created date
    pub created_at: Option<String>,
    /// Owner/organization name
    pub owner: String,
}

/// File in a repository
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RepoFile {
    /// File path relative to repository root
    pub path: String,
    /// File name
    pub name: String,
    /// File type (file, dir, submodule, symlink)
    pub file_type: String,
    /// File size in bytes (if applicable)
    pub size: Option<usize>,
    /// Git SHA of the file
    pub sha: Option<String>,
    /// Download URL for the file
    pub download_url: Option<String>,
}

/// Commit information
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CommitInfo {
    /// Commit SHA
    pub sha: String,
    /// Commit message
    pub message: String,
    /// Author name
    pub author: String,
    /// Author email
    pub email: Option<String>,
    /// Commit date (ISO 8601)
    pub date: String,
    /// Parent commit SHAs
    pub parents: Vec<String>,
    /// Commit URL
    pub url: Option<String>,
}

/// File changed in a commit
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CommitFile {
    /// File path
    pub path: String,
    /// Change status (added, removed, modified, renamed)
    pub status: String,
    /// Number of additions
    pub additions: Option<u32>,
    /// Number of deletions
    pub deletions: Option<u32>,
    /// Patch content (diff)
    pub patch: Option<String>,
    /// Previous path (if renamed)
    pub previous_path: Option<String>,
}

/// Code search result
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CodeSearchResult {
    /// File path
    pub path: String,
    /// Repository name
    pub repo: String,
    /// Matching lines
    pub text_matches: Vec<TextMatch>,
    /// Git SHA of the file
    pub sha: Option<String>,
}

/// Text match in code search
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TextMatch {
    /// Object type (file_content, file_path)
    pub object_type: String,
    /// Fragment containing the match
    pub fragment: String,
    /// Match indices within fragment
    pub indices: Vec<(usize, usize)>,
}

/// Result of scanning a single repository
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GitRepoScanResult {
    /// Repository owner
    pub owner: String,
    /// Repository name
    pub repo: String,
    /// Platform (github, gitlab)
    pub platform: String,
    /// Secrets found
    pub secrets: Vec<GitSecretFinding>,
    /// Number of files scanned
    pub files_scanned: usize,
    /// Number of commits scanned
    pub commits_scanned: usize,
    /// Errors encountered during scanning
    pub errors: Vec<String>,
}

/// A secret found in a git repository
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GitSecretFinding {
    /// Type of secret detected
    pub secret_type: String,
    /// Severity level
    pub severity: String,
    /// Redacted value (never the full secret)
    pub redacted_value: String,
    /// File path where the secret was found
    pub file_path: String,
    /// Line number (if applicable)
    pub line_number: Option<usize>,
    /// Context around the secret (redacted)
    pub context: Option<String>,
    /// Commit SHA where the secret was found (None = HEAD)
    pub commit_sha: Option<String>,
    /// Commit author
    pub commit_author: Option<String>,
    /// Commit date
    pub commit_date: Option<String>,
    /// Whether the secret is in the current HEAD
    pub is_current: bool,
    /// Detection method (pattern, entropy)
    pub detection_method: Option<String>,
    /// Recommended remediation
    pub remediation: Option<String>,
}

/// Result of enumerating repositories
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RepoEnumerationResult {
    /// Target username or organization
    pub target: String,
    /// Target type (user or org)
    pub target_type: String,
    /// Platform (github, gitlab)
    pub platform: String,
    /// Repositories found
    pub repositories: Vec<RepoInfo>,
    /// Total count (may differ from repos.len() if pagination limited)
    pub total_count: usize,
    /// Whether there are more results
    pub has_more: bool,
}

/// Rate limit information from API
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RateLimitInfo {
    /// Remaining requests
    pub remaining: u32,
    /// Total limit
    pub limit: u32,
    /// Reset time (Unix timestamp)
    pub reset_at: u64,
    /// Resource type (core, search, etc.)
    pub resource: String,
}

/// Authentication method for git platforms
#[derive(Debug, Clone)]
pub enum GitAuthMethod {
    /// No authentication (public API access)
    None,
    /// Personal access token
    Token(String),
    /// OAuth token
    OAuth { token: String },
    /// GitHub App installation
    GitHubApp {
        app_id: String,
        installation_id: String,
        private_key: String,
    },
}

impl Default for GitAuthMethod {
    fn default() -> Self {
        Self::None
    }
}
