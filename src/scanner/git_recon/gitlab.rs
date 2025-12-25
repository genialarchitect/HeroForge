//! GitLab API Client for Git Reconnaissance
//!
//! Implements the GitPlatformClient trait for GitLab's REST API.

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use log::{debug, warn};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::time::Duration;

use super::types::*;
use super::GitPlatformClient;

/// GitLab API client
pub struct GitLabClient {
    client: Client,
    base_url: String,
    auth: GitAuthMethod,
}

impl GitLabClient {
    /// Create a new GitLab client for gitlab.com
    pub fn new() -> Self {
        Self::with_auth(GitAuthMethod::None)
    }

    /// Create a new GitLab client with authentication
    pub fn with_auth(auth: GitAuthMethod) -> Self {
        Self::with_base_url("https://gitlab.com/api/v4", auth)
    }

    /// Create a GitLab client for a self-hosted instance
    pub fn with_base_url(base_url: &str, auth: GitAuthMethod) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("HeroForge-GitRecon/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth,
        }
    }

    /// Build a request with appropriate headers
    fn build_request(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.client.get(url);

        match &self.auth {
            GitAuthMethod::Token(token) => {
                req = req.header("PRIVATE-TOKEN", token);
            }
            GitAuthMethod::OAuth { token } => {
                req = req.header("Authorization", format!("Bearer {}", token));
            }
            GitAuthMethod::None => {}
            _ => {} // Other auth methods not yet implemented
        }

        req
    }

    /// URL-encode a project path (e.g., "group/subgroup/project" -> "group%2Fsubgroup%2Fproject")
    fn encode_project_path(owner: &str, repo: &str) -> String {
        let path = format!("{}/{}", owner, repo);
        urlencoding::encode(&path).to_string()
    }

    /// Make a paginated request
    async fn get_paginated<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        per_page: usize,
        max_pages: usize,
    ) -> Result<Vec<T>> {
        let mut results = Vec::new();
        let mut page = 1;

        loop {
            let paginated_url = if url.contains('?') {
                format!("{}&per_page={}&page={}", url, per_page, page)
            } else {
                format!("{}?per_page={}&page={}", url, per_page, page)
            };

            let response = self.build_request(&paginated_url).send().await?;

            if response.status() == StatusCode::NOT_FOUND {
                break;
            }

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(anyhow!("GitLab API error {}: {}", status, body));
            }

            let items: Vec<T> = response.json().await?;
            let item_count = items.len();
            results.extend(items);

            if item_count < per_page || page >= max_pages {
                break;
            }

            page += 1;
        }

        Ok(results)
    }
}

impl Default for GitLabClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GitPlatformClient for GitLabClient {
    fn platform_name(&self) -> &'static str {
        "gitlab"
    }

    async fn enumerate_user_repos(&self, username: &str) -> Result<Vec<RepoInfo>> {
        let url = format!("{}/users/{}/projects", self.base_url, username);
        let gl_projects: Vec<GitLabProject> = self.get_paginated(&url, 100, 10).await?;
        Ok(gl_projects.into_iter().map(|p| p.into()).collect())
    }

    async fn enumerate_org_repos(&self, org_name: &str) -> Result<Vec<RepoInfo>> {
        // GitLab uses "groups" for organizations
        let encoded_group = urlencoding::encode(org_name);
        let url = format!("{}/groups/{}/projects", self.base_url, encoded_group);
        let gl_projects: Vec<GitLabProject> = self.get_paginated(&url, 100, 10).await?;
        Ok(gl_projects.into_iter().map(|p| p.into()).collect())
    }

    async fn get_repo_info(&self, owner: &str, repo: &str) -> Result<RepoInfo> {
        let project_path = Self::encode_project_path(owner, repo);
        let url = format!("{}/projects/{}", self.base_url, project_path);

        let response = self.build_request(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("GitLab API error {}: {}", status, body));
        }

        let gl_project: GitLabProject = response.json().await?;
        Ok(gl_project.into())
    }

    async fn get_file_contents(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        ref_name: Option<&str>,
    ) -> Result<String> {
        let project_path = Self::encode_project_path(owner, repo);
        let encoded_path = urlencoding::encode(path);
        let ref_param = ref_name.unwrap_or("HEAD");

        let url = format!(
            "{}/projects/{}/repository/files/{}?ref={}",
            self.base_url, project_path, encoded_path, ref_param
        );

        let response = self.build_request(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("GitLab API error {}: {}", status, body));
        }

        let file: GitLabFile = response.json().await?;

        // GitLab returns base64-encoded content
        let cleaned = file.content.replace('\n', "").replace('\r', "");
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &cleaned) {
            Ok(bytes) => String::from_utf8(bytes).map_err(|e| anyhow!("UTF-8 decode error: {}", e)),
            Err(e) => Err(anyhow!("Base64 decode error: {}", e)),
        }
    }

    async fn list_repo_files(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        ref_name: Option<&str>,
    ) -> Result<Vec<RepoFile>> {
        let project_path = Self::encode_project_path(owner, repo);
        let ref_param = ref_name.unwrap_or("HEAD");

        let mut url = format!(
            "{}/projects/{}/repository/tree?ref={}&recursive=true",
            self.base_url, project_path, ref_param
        );

        if !path.is_empty() {
            url.push_str(&format!("&path={}", urlencoding::encode(path)));
        }

        let gl_files: Vec<GitLabTreeItem> = self.get_paginated(&url, 100, 20).await?;

        let files: Vec<RepoFile> = gl_files
            .into_iter()
            .map(|item| RepoFile {
                path: item.path.clone(),
                name: item.name,
                file_type: item.item_type,
                size: None, // GitLab tree API doesn't include size
                sha: Some(item.id),
                download_url: None,
            })
            .collect();

        Ok(files)
    }

    async fn get_commits(
        &self,
        owner: &str,
        repo: &str,
        limit: usize,
    ) -> Result<Vec<CommitInfo>> {
        let project_path = Self::encode_project_path(owner, repo);
        let url = format!(
            "{}/projects/{}/repository/commits?per_page={}",
            self.base_url, project_path, limit.min(100)
        );

        let response = self.build_request(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("GitLab API error {}: {}", status, body));
        }

        let gl_commits: Vec<GitLabCommit> = response.json().await?;

        let commits: Vec<CommitInfo> = gl_commits
            .into_iter()
            .map(|c| CommitInfo {
                sha: c.id,
                message: c.message,
                author: c.author_name,
                email: Some(c.author_email),
                date: c.authored_date,
                parents: c.parent_ids,
                url: Some(c.web_url),
            })
            .collect();

        Ok(commits)
    }

    async fn get_commit_files(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> Result<Vec<CommitFile>> {
        let project_path = Self::encode_project_path(owner, repo);
        let url = format!(
            "{}/projects/{}/repository/commits/{}/diff",
            self.base_url, project_path, sha
        );

        let response = self.build_request(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("GitLab API error {}: {}", status, body));
        }

        let gl_diffs: Vec<GitLabDiff> = response.json().await?;

        let files: Vec<CommitFile> = gl_diffs
            .into_iter()
            .map(|d| {
                let status = if d.new_file {
                    "added"
                } else if d.deleted_file {
                    "removed"
                } else if d.renamed_file {
                    "renamed"
                } else {
                    "modified"
                };

                CommitFile {
                    path: d.new_path.clone(),
                    status: status.to_string(),
                    additions: None, // GitLab diff API doesn't provide line counts
                    deletions: None,
                    patch: Some(d.diff),
                    previous_path: if d.renamed_file {
                        Some(d.old_path)
                    } else {
                        None
                    },
                }
            })
            .collect();

        Ok(files)
    }

    async fn search_code(
        &self,
        owner: &str,
        repo: &str,
        query: &str,
    ) -> Result<Vec<CodeSearchResult>> {
        // GitLab search requires authentication
        let project_path = Self::encode_project_path(owner, repo);
        let encoded_query = urlencoding::encode(query);
        let url = format!(
            "{}/projects/{}/search?scope=blobs&search={}",
            self.base_url, project_path, encoded_query
        );

        let response = self.build_request(&url).send().await?;

        if response.status() == StatusCode::UNAUTHORIZED {
            warn!("GitLab code search requires authentication");
            return Ok(Vec::new());
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            debug!("GitLab search API error {}: {}", status, body);
            return Ok(Vec::new());
        }

        let search_results: Vec<GitLabSearchResult> = response.json().await?;

        let results: Vec<CodeSearchResult> = search_results
            .into_iter()
            .map(|item| CodeSearchResult {
                path: item.filename,
                repo: format!("{}/{}", owner, repo),
                text_matches: vec![TextMatch {
                    object_type: "file_content".to_string(),
                    fragment: item.data,
                    indices: vec![],
                }],
                sha: Some(item.ref_name),
            })
            .collect();

        Ok(results)
    }
}

// GitLab API response types

#[derive(Debug, Deserialize)]
struct GitLabProject {
    id: u64,
    name: String,
    path_with_namespace: String,
    description: Option<String>,
    web_url: String,
    http_url_to_repo: String,
    default_branch: Option<String>,
    visibility: String,
    forked_from_project: Option<serde_json::Value>,
    archived: bool,
    star_count: Option<u64>,
    forks_count: Option<u64>,
    last_activity_at: Option<String>,
    created_at: Option<String>,
    namespace: GitLabNamespace,
}

#[derive(Debug, Deserialize)]
struct GitLabNamespace {
    name: String,
    path: String,
}

impl From<GitLabProject> for RepoInfo {
    fn from(gl: GitLabProject) -> Self {
        Self {
            name: gl.name,
            full_name: gl.path_with_namespace.clone(),
            description: gl.description,
            url: gl.web_url,
            clone_url: gl.http_url_to_repo,
            default_branch: gl.default_branch.unwrap_or_else(|| "main".to_string()),
            is_private: gl.visibility == "private",
            is_fork: gl.forked_from_project.is_some(),
            is_archived: gl.archived,
            size_kb: None, // GitLab doesn't provide size in basic API
            language: None,
            stars: gl.star_count,
            forks: gl.forks_count,
            pushed_at: gl.last_activity_at,
            created_at: gl.created_at,
            owner: gl.namespace.path,
        }
    }
}

#[derive(Debug, Deserialize)]
struct GitLabFile {
    file_name: String,
    file_path: String,
    size: usize,
    encoding: String,
    content: String,
    #[serde(rename = "ref")]
    ref_name: String,
}

#[derive(Debug, Deserialize)]
struct GitLabTreeItem {
    id: String,
    name: String,
    path: String,
    #[serde(rename = "type")]
    item_type: String,
    mode: String,
}

#[derive(Debug, Deserialize)]
struct GitLabCommit {
    id: String,
    short_id: String,
    title: String,
    message: String,
    author_name: String,
    author_email: String,
    authored_date: String,
    parent_ids: Vec<String>,
    web_url: String,
}

#[derive(Debug, Deserialize)]
struct GitLabDiff {
    old_path: String,
    new_path: String,
    diff: String,
    new_file: bool,
    renamed_file: bool,
    deleted_file: bool,
}

#[derive(Debug, Deserialize)]
struct GitLabSearchResult {
    filename: String,
    #[serde(rename = "ref")]
    ref_name: String,
    data: String,
    startline: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gitlab_client_creation() {
        let client = GitLabClient::new();
        assert_eq!(client.base_url, "https://gitlab.com/api/v4");
        assert_eq!(client.platform_name(), "gitlab");
    }

    #[test]
    fn test_gitlab_client_with_token() {
        let client = GitLabClient::with_auth(GitAuthMethod::Token("test_token".to_string()));
        assert!(matches!(client.auth, GitAuthMethod::Token(_)));
    }

    #[test]
    fn test_gitlab_self_hosted() {
        let client = GitLabClient::with_base_url(
            "https://gitlab.example.com/api/v4",
            GitAuthMethod::None,
        );
        assert_eq!(client.base_url, "https://gitlab.example.com/api/v4");
    }

    #[test]
    fn test_encode_project_path() {
        assert_eq!(
            GitLabClient::encode_project_path("group", "project"),
            "group%2Fproject"
        );
        assert_eq!(
            GitLabClient::encode_project_path("group/subgroup", "project"),
            "group%2Fsubgroup%2Fproject"
        );
    }
}
