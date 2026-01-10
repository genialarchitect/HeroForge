//! GitHub API Client for Git Reconnaissance
//!
//! Implements the GitPlatformClient trait for GitHub's REST API.

use anyhow::{anyhow, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use log::{debug, warn};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::types::*;
use super::GitPlatformClient;

/// JWT claims for GitHub App authentication
#[derive(Debug, Serialize)]
struct GitHubAppJwtClaims {
    iat: u64,  // Issued at time
    exp: u64,  // Expiration time (max 10 minutes)
    iss: String,  // GitHub App ID
}

/// Cached installation token
struct CachedToken {
    token: String,
    expires_at: u64,
}

/// GitHub API client
#[allow(dead_code)]
pub struct GitHubClient {
    client: Client,
    base_url: String,
    auth: GitAuthMethod,
    installation_token_cache: Mutex<Option<CachedToken>>,
}

impl GitHubClient {
    /// Create a new GitHub client with default settings
    pub fn new() -> Self {
        Self::with_auth(GitAuthMethod::None)
    }

    /// Create a new GitHub client with authentication
    pub fn with_auth(auth: GitAuthMethod) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("HeroForge-GitRecon/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url: "https://api.github.com".to_string(),
            auth,
            installation_token_cache: Mutex::new(None),
        }
    }

    /// Create a GitHub client for GitHub Enterprise
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
            installation_token_cache: Mutex::new(None),
        }
    }

    /// Generate a JWT for GitHub App authentication
    fn generate_app_jwt(app_id: &str, private_key: &str) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("Time error: {}", e))?
            .as_secs();

        let claims = GitHubAppJwtClaims {
            iat: now - 60, // Allow for clock drift
            exp: now + 600, // JWT valid for 10 minutes
            iss: app_id.to_string(),
        };

        let header = Header::new(Algorithm::RS256);
        let key = EncodingKey::from_rsa_pem(private_key.as_bytes())
            .map_err(|e| anyhow!("Invalid private key: {}", e))?;

        encode(&header, &claims, &key)
            .map_err(|e| anyhow!("JWT encoding error: {}", e))
    }

    /// Get installation access token (cached)
    async fn get_installation_token(&self, app_id: &str, installation_id: &str, private_key: &str) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("Time error: {}", e))?
            .as_secs();

        // Check cache
        {
            let cache = self.installation_token_cache.lock().unwrap();
            if let Some(ref cached) = *cache {
                if cached.expires_at > now + 60 {
                    return Ok(cached.token.clone());
                }
            }
        }

        // Generate JWT
        let jwt = Self::generate_app_jwt(app_id, private_key)?;

        // Request installation token
        let url = format!("{}/app/installations/{}/access_tokens", self.base_url, installation_id);
        let response = self.client
            .post(&url)
            .header("Accept", "application/vnd.github+json")
            .header("Authorization", format!("Bearer {}", jwt))
            .send()
            .await
            .map_err(|e| anyhow!("Request error: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to get installation token: {} - {}", status, body));
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            token: String,
            expires_at: String,
        }

        let token_response: TokenResponse = response.json().await
            .map_err(|e| anyhow!("Failed to parse token response: {}", e))?;

        // Parse expiration and cache
        let expires_at = chrono::DateTime::parse_from_rfc3339(&token_response.expires_at)
            .map(|dt| dt.timestamp() as u64)
            .unwrap_or(now + 3600);

        {
            let mut cache = self.installation_token_cache.lock().unwrap();
            *cache = Some(CachedToken {
                token: token_response.token.clone(),
                expires_at,
            });
        }

        Ok(token_response.token)
    }

    /// Build a request with appropriate headers
    async fn build_request_async(&self, url: &str) -> Result<reqwest::RequestBuilder> {
        let mut req = self.client.get(url).header("Accept", "application/vnd.github+json");

        match &self.auth {
            GitAuthMethod::Token(token) => {
                req = req.header("Authorization", format!("Bearer {}", token));
            }
            GitAuthMethod::OAuth { token } => {
                req = req.header("Authorization", format!("token {}", token));
            }
            GitAuthMethod::GitHubApp { app_id, installation_id, private_key } => {
                let token = self.get_installation_token(app_id, installation_id, private_key).await?;
                req = req.header("Authorization", format!("token {}", token));
            }
            GitAuthMethod::None => {}
        }

        Ok(req)
    }

    /// Build a request with appropriate headers (sync version for simple auth)
    fn build_request(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.client.get(url).header("Accept", "application/vnd.github+json");

        match &self.auth {
            GitAuthMethod::Token(token) => {
                req = req.header("Authorization", format!("Bearer {}", token));
            }
            GitAuthMethod::OAuth { token } => {
                req = req.header("Authorization", format!("token {}", token));
            }
            GitAuthMethod::None => {}
            GitAuthMethod::GitHubApp { .. } => {
                // For App auth, use build_request_async instead
                warn!("GitHubApp auth requires async token fetch, use build_request_async");
            }
        }

        req
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
            let paginated_url = format!("{}?per_page={}&page={}", url, per_page, page);
            let response = self.build_request_async(&paginated_url).await?.send().await?;

            if response.status() == StatusCode::NOT_FOUND {
                break;
            }

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(anyhow!("GitHub API error {}: {}", status, body));
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

impl Default for GitHubClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GitPlatformClient for GitHubClient {
    fn platform_name(&self) -> &'static str {
        "github"
    }

    async fn enumerate_user_repos(&self, username: &str) -> Result<Vec<RepoInfo>> {
        let url = format!("{}/users/{}/repos", self.base_url, username);
        let gh_repos: Vec<GitHubRepo> = self.get_paginated(&url, 100, 10).await?;
        Ok(gh_repos.into_iter().map(|r| r.into()).collect())
    }

    async fn enumerate_org_repos(&self, org_name: &str) -> Result<Vec<RepoInfo>> {
        let url = format!("{}/orgs/{}/repos", self.base_url, org_name);
        let gh_repos: Vec<GitHubRepo> = self.get_paginated(&url, 100, 10).await?;
        Ok(gh_repos.into_iter().map(|r| r.into()).collect())
    }

    async fn get_repo_info(&self, owner: &str, repo: &str) -> Result<RepoInfo> {
        let url = format!("{}/repos/{}/{}", self.base_url, owner, repo);
        let response = self.build_request(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("GitHub API error {}: {}", status, body));
        }

        let gh_repo: GitHubRepo = response.json().await?;
        Ok(gh_repo.into())
    }

    async fn get_file_contents(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        ref_name: Option<&str>,
    ) -> Result<String> {
        let mut url = format!("{}/repos/{}/{}/contents/{}", self.base_url, owner, repo, path);
        if let Some(r) = ref_name {
            url.push_str(&format!("?ref={}", r));
        }

        let response = self.build_request(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("GitHub API error {}: {}", status, body));
        }

        let content: GitHubContent = response.json().await?;

        // GitHub returns base64-encoded content
        if let Some(encoded) = content.content {
            // Remove newlines from base64 content
            let cleaned = encoded.replace('\n', "").replace('\r', "");
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &cleaned) {
                Ok(bytes) => String::from_utf8(bytes).map_err(|e| anyhow!("UTF-8 decode error: {}", e)),
                Err(e) => Err(anyhow!("Base64 decode error: {}", e)),
            }
        } else {
            Err(anyhow!("No content in response"))
        }
    }

    async fn list_repo_files(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        ref_name: Option<&str>,
    ) -> Result<Vec<RepoFile>> {
        // Use the Git Trees API for efficient recursive listing
        let sha = ref_name.unwrap_or("HEAD");
        let url = format!(
            "{}/repos/{}/{}/git/trees/{}?recursive=1",
            self.base_url, owner, repo, sha
        );

        let response = self.build_request(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("GitHub API error {}: {}", status, body));
        }

        let tree: GitHubTree = response.json().await?;

        let files: Vec<RepoFile> = tree
            .tree
            .into_iter()
            .filter(|item| {
                // Filter by path prefix if specified
                if path.is_empty() {
                    true
                } else {
                    item.path.starts_with(path)
                }
            })
            .map(|item| RepoFile {
                path: item.path.clone(),
                name: item.path.rsplit('/').next().unwrap_or(&item.path).to_string(),
                file_type: item.item_type,
                size: item.size,
                sha: Some(item.sha),
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
        let url = format!(
            "{}/repos/{}/{}/commits?per_page={}",
            self.base_url, owner, repo, limit.min(100)
        );

        let response = self.build_request(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("GitHub API error {}: {}", status, body));
        }

        let gh_commits: Vec<GitHubCommit> = response.json().await?;

        let commits: Vec<CommitInfo> = gh_commits
            .into_iter()
            .map(|c| CommitInfo {
                sha: c.sha,
                message: c.commit.message,
                author: c.commit.author.name,
                email: Some(c.commit.author.email),
                date: c.commit.author.date,
                parents: c.parents.into_iter().map(|p| p.sha).collect(),
                url: Some(c.html_url),
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
        let url = format!("{}/repos/{}/{}/commits/{}", self.base_url, owner, repo, sha);

        let response = self.build_request(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("GitHub API error {}: {}", status, body));
        }

        let commit_detail: GitHubCommitDetail = response.json().await?;

        let files: Vec<CommitFile> = commit_detail
            .files
            .unwrap_or_default()
            .into_iter()
            .map(|f| CommitFile {
                path: f.filename,
                status: f.status,
                additions: Some(f.additions),
                deletions: Some(f.deletions),
                patch: f.patch,
                previous_path: f.previous_filename,
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
        // GitHub code search requires authentication
        let url = format!(
            "{}/search/code?q={}+repo:{}/{}",
            self.base_url, query, owner, repo
        );

        let response = self.build_request(&url).send().await?;

        if response.status() == StatusCode::UNAUTHORIZED {
            warn!("GitHub code search requires authentication");
            return Ok(Vec::new());
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            debug!("GitHub search API error {}: {}", status, body);
            return Ok(Vec::new());
        }

        let search_result: GitHubSearchResult = response.json().await?;

        let results: Vec<CodeSearchResult> = search_result
            .items
            .into_iter()
            .map(|item| CodeSearchResult {
                path: item.path,
                repo: item.repository.full_name,
                text_matches: item
                    .text_matches
                    .unwrap_or_default()
                    .into_iter()
                    .map(|m| TextMatch {
                        object_type: m.object_type,
                        fragment: m.fragment,
                        indices: m.matches.into_iter().map(|i| (i.indices[0], i.indices[1])).collect(),
                    })
                    .collect(),
                sha: Some(item.sha),
            })
            .collect();

        Ok(results)
    }
}

// GitHub API response types

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubRepo {
    name: String,
    full_name: String,
    description: Option<String>,
    html_url: String,
    clone_url: String,
    default_branch: String,
    private: bool,
    fork: bool,
    archived: bool,
    size: Option<u64>,
    language: Option<String>,
    stargazers_count: Option<u64>,
    forks_count: Option<u64>,
    pushed_at: Option<String>,
    created_at: Option<String>,
    owner: GitHubOwner,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubOwner {
    login: String,
}

impl From<GitHubRepo> for RepoInfo {
    fn from(gh: GitHubRepo) -> Self {
        Self {
            name: gh.name,
            full_name: gh.full_name,
            description: gh.description,
            url: gh.html_url,
            clone_url: gh.clone_url,
            default_branch: gh.default_branch,
            is_private: gh.private,
            is_fork: gh.fork,
            is_archived: gh.archived,
            size_kb: gh.size,
            language: gh.language,
            stars: gh.stargazers_count,
            forks: gh.forks_count,
            pushed_at: gh.pushed_at,
            created_at: gh.created_at,
            owner: gh.owner.login,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubContent {
    content: Option<String>,
    encoding: Option<String>,
    size: Option<usize>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubTree {
    sha: String,
    tree: Vec<GitHubTreeItem>,
    truncated: bool,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubTreeItem {
    path: String,
    mode: String,
    #[serde(rename = "type")]
    item_type: String,
    sha: String,
    size: Option<usize>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubCommit {
    sha: String,
    commit: GitHubCommitData,
    html_url: String,
    parents: Vec<GitHubParent>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubCommitData {
    message: String,
    author: GitHubAuthor,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubAuthor {
    name: String,
    email: String,
    date: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubParent {
    sha: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubCommitDetail {
    sha: String,
    files: Option<Vec<GitHubCommitFile>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubCommitFile {
    filename: String,
    status: String,
    additions: u32,
    deletions: u32,
    patch: Option<String>,
    previous_filename: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubSearchResult {
    total_count: u32,
    items: Vec<GitHubSearchItem>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubSearchItem {
    name: String,
    path: String,
    sha: String,
    repository: GitHubSearchRepo,
    text_matches: Option<Vec<GitHubTextMatch>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubSearchRepo {
    full_name: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubTextMatch {
    object_type: String,
    fragment: String,
    matches: Vec<GitHubMatchIndex>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GitHubMatchIndex {
    indices: Vec<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_client_creation() {
        let client = GitHubClient::new();
        assert_eq!(client.base_url, "https://api.github.com");
        assert_eq!(client.platform_name(), "github");
    }

    #[test]
    fn test_github_client_with_token() {
        let client = GitHubClient::with_auth(GitAuthMethod::Token("test_token".to_string()));
        assert!(matches!(client.auth, GitAuthMethod::Token(_)));
    }

    #[test]
    fn test_github_enterprise() {
        let client = GitHubClient::with_base_url(
            "https://github.example.com/api/v3",
            GitAuthMethod::None,
        );
        assert_eq!(client.base_url, "https://github.example.com/api/v3");
    }
}
