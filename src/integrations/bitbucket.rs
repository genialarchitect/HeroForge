//! Bitbucket integration

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Bitbucket Cloud API base URL
const BITBUCKET_API_BASE: &str = "https://api.bitbucket.org/2.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitbucketRepository {
    pub uuid: String,
    pub name: String,
    pub full_name: String,
    pub is_private: bool,
    #[serde(default)]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitbucketMainBranch {
    pub name: String,
    #[serde(rename = "type")]
    pub branch_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitbucketRepoDetails {
    pub uuid: String,
    pub name: String,
    pub full_name: String,
    pub is_private: bool,
    #[serde(default)]
    pub mainbranch: Option<BitbucketMainBranch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitbucketTreeEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    #[serde(default)]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitbucketTreeResponse {
    pub values: Vec<BitbucketTreeEntry>,
    #[serde(default)]
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitbucketCommit {
    pub hash: String,
    pub message: String,
    pub date: String,
    pub author: BitbucketAuthor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitbucketAuthor {
    pub raw: String,
    #[serde(default)]
    pub user: Option<BitbucketUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitbucketUser {
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitbucketCommitsResponse {
    pub values: Vec<BitbucketCommit>,
    #[serde(default)]
    pub next: Option<String>,
}

pub struct BitbucketIntegration {
    token: String,
    base_url: String,
}

impl BitbucketIntegration {
    pub fn new(token: String) -> Self {
        Self {
            token,
            base_url: BITBUCKET_API_BASE.to_string(),
        }
    }

    /// Create integration with custom API base URL (for Bitbucket Server)
    pub fn with_base_url(token: String, base_url: String) -> Self {
        Self { token, base_url }
    }

    /// Scan a Bitbucket repository for security findings
    ///
    /// # Arguments
    /// * `repo` - Repository in format "workspace/repo_slug" (e.g., "myteam/myproject")
    ///
    /// # Returns
    /// A list of security-related findings
    pub async fn scan_repository(&self, repo: &str) -> Result<Vec<String>> {
        let client = reqwest::Client::new();
        let mut findings = Vec::new();

        // Parse workspace and repo_slug from the repo string
        let parts: Vec<&str> = repo.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow!(
                "Invalid repository format. Expected 'workspace/repo_slug', got '{}'",
                repo
            ));
        }
        let workspace = parts[0];
        let repo_slug = parts[1];

        // Get repository details
        let repo_url = format!("{}/repositories/{}/{}", self.base_url, workspace, repo_slug);
        let repo_response = client
            .get(&repo_url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| anyhow!("Failed to connect to Bitbucket API: {}", e))?;

        if !repo_response.status().is_success() {
            let status = repo_response.status();
            let body = repo_response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Bitbucket API error ({}): {}",
                status,
                body
            ));
        }

        let repo_details: BitbucketRepoDetails = repo_response.json().await
            .map_err(|e| anyhow!("Failed to parse repository response: {}", e))?;

        findings.push(format!(
            "Repository: {} (private: {})",
            repo_details.full_name, repo_details.is_private
        ));

        // Get the main branch
        let main_branch = repo_details.mainbranch
            .as_ref()
            .map(|b| b.name.as_str())
            .unwrap_or("main");

        // Check for sensitive files in repository
        let sensitive_paths = [
            ".env", ".env.local", ".env.production",
            "secrets.yml", "secrets.json", "credentials.json",
            "private.key", "id_rsa", "id_ed25519",
            ".aws/credentials", ".docker/config.json",
            "serviceAccountKey.json", "gcloud-service-key.json",
        ];

        // Get repository source tree
        let tree_url = format!(
            "{}/repositories/{}/{}/src/{}/?pagelen=100",
            self.base_url, workspace, repo_slug, main_branch
        );

        let tree_response = client
            .get(&tree_url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/json")
            .send()
            .await;

        if let Ok(response) = tree_response {
            if response.status().is_success() {
                if let Ok(tree) = response.json::<BitbucketTreeResponse>().await {
                    for entry in tree.values {
                        if entry.entry_type == "commit_file" {
                            let file_lower = entry.path.to_lowercase();

                            // Check for sensitive file names
                            for sensitive in &sensitive_paths {
                                if file_lower.ends_with(sensitive) || file_lower.contains(sensitive) {
                                    findings.push(format!(
                                        "SENSITIVE FILE: {} - potentially contains secrets",
                                        entry.path
                                    ));
                                }
                            }

                            // Check for backup files
                            if file_lower.ends_with(".bak") || file_lower.ends_with(".backup")
                                || file_lower.ends_with(".old") || file_lower.ends_with(".orig") {
                                findings.push(format!(
                                    "BACKUP FILE: {} - may contain sensitive data",
                                    entry.path
                                ));
                            }

                            // Check for SQL dumps
                            if file_lower.ends_with(".sql") || file_lower.ends_with(".dump") {
                                findings.push(format!(
                                    "DATABASE DUMP: {} - may contain sensitive data",
                                    entry.path
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Get recent commits to check for security-related changes
        let commits_url = format!(
            "{}/repositories/{}/{}/commits/{}?pagelen=20",
            self.base_url, workspace, repo_slug, main_branch
        );

        let commits_response = client
            .get(&commits_url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/json")
            .send()
            .await;

        if let Ok(response) = commits_response {
            if response.status().is_success() {
                if let Ok(commits) = response.json::<BitbucketCommitsResponse>().await {
                    let security_keywords = [
                        "secret", "password", "credential", "key", "token",
                        "api_key", "apikey", "auth", "private",
                    ];

                    for commit in commits.values {
                        let message_lower = commit.message.to_lowercase();
                        for keyword in &security_keywords {
                            if message_lower.contains(keyword) {
                                let short_hash = &commit.hash[..8.min(commit.hash.len())];
                                let first_line = commit.message.lines().next().unwrap_or("");
                                findings.push(format!(
                                    "SECURITY COMMIT: {} - '{}' by {} ({})",
                                    short_hash, first_line, commit.author.raw, commit.date
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Check repository visibility
        if !repo_details.is_private {
            findings.push(
                "WARNING: Repository is public - ensure no secrets are exposed".to_string()
            );
        }

        Ok(findings)
    }

    /// Get repository details
    pub async fn get_repository(&self, workspace: &str, repo_slug: &str) -> Result<BitbucketRepoDetails> {
        let client = reqwest::Client::new();
        let url = format!("{}/repositories/{}/{}", self.base_url, workspace, repo_slug);

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| anyhow!("Failed to connect to Bitbucket API: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("Bitbucket API error: {}", response.status()));
        }

        response.json().await
            .map_err(|e| anyhow!("Failed to parse repository: {}", e))
    }

    /// List files in a repository path
    pub async fn list_files(
        &self,
        workspace: &str,
        repo_slug: &str,
        path: Option<&str>,
        ref_name: Option<&str>,
    ) -> Result<Vec<BitbucketTreeEntry>> {
        let client = reqwest::Client::new();

        let ref_part = ref_name.unwrap_or("main");
        let mut url = format!(
            "{}/repositories/{}/{}/src/{}",
            self.base_url, workspace, repo_slug, ref_part
        );

        if let Some(p) = path {
            url.push('/');
            url.push_str(p);
        }

        url.push_str("?pagelen=100");

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| anyhow!("Failed to connect to Bitbucket API: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("Bitbucket API error: {}", response.status()));
        }

        let tree: BitbucketTreeResponse = response.json().await
            .map_err(|e| anyhow!("Failed to parse files: {}", e))?;

        Ok(tree.values)
    }

    /// Get file content
    pub async fn get_file_content(
        &self,
        workspace: &str,
        repo_slug: &str,
        file_path: &str,
        ref_name: Option<&str>,
    ) -> Result<String> {
        let client = reqwest::Client::new();
        let ref_part = ref_name.unwrap_or("main");

        let url = format!(
            "{}/repositories/{}/{}/src/{}/{}",
            self.base_url, workspace, repo_slug, ref_part, file_path
        );

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to connect to Bitbucket API: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("Bitbucket API error: {}", response.status()));
        }

        response.text().await
            .map_err(|e| anyhow!("Failed to read file content: {}", e))
    }
}
