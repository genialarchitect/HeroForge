//! GitLab integration

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// GitLab API base URL
const GITLAB_API_BASE: &str = "https://gitlab.com/api/v4";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabProject {
    pub id: u64,
    pub name: String,
    pub path_with_namespace: String,
    pub default_branch: Option<String>,
    pub visibility: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabFile {
    pub file_name: String,
    pub file_path: String,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabCommit {
    pub id: String,
    pub short_id: String,
    pub title: String,
    pub author_name: String,
    pub author_email: String,
    pub created_at: String,
}

pub struct GitLabIntegration {
    token: String,
    base_url: String,
}

impl GitLabIntegration {
    pub fn new(token: String) -> Self {
        Self {
            token,
            base_url: GITLAB_API_BASE.to_string(),
        }
    }

    /// Create integration with custom GitLab instance URL
    pub fn with_base_url(token: String, base_url: String) -> Self {
        Self { token, base_url }
    }

    /// Scan a GitLab project for security findings
    ///
    /// Returns a list of security-related findings including:
    /// - Exposed secrets in files
    /// - Sensitive file paths
    /// - Recent commits with potential security issues
    pub async fn scan_project(&self, project_id: &str) -> Result<Vec<String>> {
        let client = reqwest::Client::new();
        let mut findings = Vec::new();

        // URL-encode the project ID (handles paths like "group/project")
        let encoded_project_id = urlencoding::encode(project_id);

        // Get project details
        let project_url = format!("{}/projects/{}", self.base_url, encoded_project_id);
        let project_response = client
            .get(&project_url)
            .header("PRIVATE-TOKEN", &self.token)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| anyhow!("Failed to connect to GitLab API: {}", e))?;

        if !project_response.status().is_success() {
            let status = project_response.status();
            let body = project_response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "GitLab API error ({}): {}",
                status,
                body
            ));
        }

        let project: GitLabProject = project_response.json().await
            .map_err(|e| anyhow!("Failed to parse project response: {}", e))?;

        findings.push(format!(
            "Project: {} (visibility: {})",
            project.path_with_namespace, project.visibility
        ));

        // Check for sensitive files in repository
        let sensitive_paths = [
            ".env", ".env.local", ".env.production",
            "secrets.yml", "secrets.json", "credentials.json",
            "private.key", "id_rsa", "id_ed25519",
            ".aws/credentials", ".docker/config.json",
            "serviceAccountKey.json", "gcloud-service-key.json",
        ];

        let default_branch = project.default_branch.as_deref().unwrap_or("main");

        // Get repository tree to find files
        let tree_url = format!(
            "{}/projects/{}/repository/tree?ref={}&recursive=true&per_page=100",
            self.base_url, encoded_project_id, default_branch
        );

        let tree_response = client
            .get(&tree_url)
            .header("PRIVATE-TOKEN", &self.token)
            .header("Accept", "application/json")
            .send()
            .await;

        if let Ok(response) = tree_response {
            if response.status().is_success() {
                if let Ok(files) = response.json::<Vec<GitLabFile>>().await {
                    for file in files {
                        let file_lower = file.file_path.to_lowercase();

                        // Check for sensitive file names
                        for sensitive in &sensitive_paths {
                            if file_lower.ends_with(sensitive) || file_lower.contains(sensitive) {
                                findings.push(format!(
                                    "SENSITIVE FILE: {} - potentially contains secrets",
                                    file.file_path
                                ));
                            }
                        }

                        // Check for backup files that might contain sensitive data
                        if file_lower.ends_with(".bak") || file_lower.ends_with(".backup")
                            || file_lower.ends_with(".old") || file_lower.ends_with(".orig") {
                            findings.push(format!(
                                "BACKUP FILE: {} - may contain sensitive data",
                                file.file_path
                            ));
                        }

                        // Check for SQL dumps
                        if file_lower.ends_with(".sql") || file_lower.ends_with(".dump") {
                            findings.push(format!(
                                "DATABASE DUMP: {} - may contain sensitive data",
                                file.file_path
                            ));
                        }
                    }
                }
            }
        }

        // Get recent commits to check for security-related changes
        let commits_url = format!(
            "{}/projects/{}/repository/commits?ref_name={}&per_page=20",
            self.base_url, encoded_project_id, default_branch
        );

        let commits_response = client
            .get(&commits_url)
            .header("PRIVATE-TOKEN", &self.token)
            .header("Accept", "application/json")
            .send()
            .await;

        if let Ok(response) = commits_response {
            if response.status().is_success() {
                if let Ok(commits) = response.json::<Vec<GitLabCommit>>().await {
                    let security_keywords = [
                        "secret", "password", "credential", "key", "token",
                        "api_key", "apikey", "auth", "private",
                    ];

                    for commit in commits {
                        let title_lower = commit.title.to_lowercase();
                        for keyword in &security_keywords {
                            if title_lower.contains(keyword) {
                                findings.push(format!(
                                    "SECURITY COMMIT: {} - '{}' by {} ({})",
                                    commit.short_id, commit.title,
                                    commit.author_name, commit.created_at
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Check project visibility
        if project.visibility == "public" {
            findings.push(
                "WARNING: Project is publicly visible - ensure no secrets are exposed".to_string()
            );
        }

        Ok(findings)
    }

    /// Get project details
    pub async fn get_project(&self, project_id: &str) -> Result<GitLabProject> {
        let client = reqwest::Client::new();
        let encoded_project_id = urlencoding::encode(project_id);
        let url = format!("{}/projects/{}", self.base_url, encoded_project_id);

        let response = client
            .get(&url)
            .header("PRIVATE-TOKEN", &self.token)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| anyhow!("Failed to connect to GitLab API: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("GitLab API error: {}", response.status()));
        }

        response.json().await
            .map_err(|e| anyhow!("Failed to parse project: {}", e))
    }

    /// List files in a repository
    pub async fn list_files(&self, project_id: &str, path: Option<&str>, ref_name: Option<&str>) -> Result<Vec<GitLabFile>> {
        let client = reqwest::Client::new();
        let encoded_project_id = urlencoding::encode(project_id);

        let mut url = format!(
            "{}/projects/{}/repository/tree?per_page=100",
            self.base_url, encoded_project_id
        );

        if let Some(p) = path {
            url.push_str(&format!("&path={}", urlencoding::encode(p)));
        }

        if let Some(r) = ref_name {
            url.push_str(&format!("&ref={}", urlencoding::encode(r)));
        }

        let response = client
            .get(&url)
            .header("PRIVATE-TOKEN", &self.token)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| anyhow!("Failed to connect to GitLab API: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("GitLab API error: {}", response.status()));
        }

        response.json().await
            .map_err(|e| anyhow!("Failed to parse files: {}", e))
    }
}
