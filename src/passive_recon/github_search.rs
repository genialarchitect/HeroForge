//! GitHub Code Search for Passive Reconnaissance
//!
//! Searches GitHub for code containing references to a target domain,
//! potentially revealing exposed credentials, API keys, or configuration.

use anyhow::Result;
use log::{debug, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::CodeSearchResult;

/// GitHub API search response
#[derive(Debug, Deserialize)]
struct GitHubSearchResponse {
    total_count: u64,
    incomplete_results: bool,
    items: Vec<GitHubCodeItem>,
}

/// Individual code search result from GitHub
#[derive(Debug, Deserialize)]
struct GitHubCodeItem {
    name: String,
    path: String,
    sha: String,
    url: String,
    html_url: String,
    repository: GitHubRepository,
    text_matches: Option<Vec<TextMatch>>,
}

/// Repository information
#[derive(Debug, Deserialize)]
struct GitHubRepository {
    full_name: String,
    html_url: String,
    description: Option<String>,
    private: bool,
    fork: bool,
}

/// Text match within a file
#[derive(Debug, Deserialize)]
struct TextMatch {
    fragment: String,
    matches: Vec<MatchInfo>,
}

/// Match position info
#[derive(Debug, Deserialize)]
struct MatchInfo {
    text: String,
    indices: Vec<u32>,
}

/// GitHub code search client
pub struct GitHubCodeSearch {
    client: Client,
    api_token: Option<String>,
}

impl GitHubCodeSearch {
    /// Create a new GitHub search client
    pub fn new(api_token: Option<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("HeroForge Security Scanner")
            .build()?;

        Ok(Self { client, api_token })
    }

    /// Search for code containing a domain
    pub async fn search_domain(&self, domain: &str) -> Result<Vec<CodeSearchResult>> {
        self.search(&format!("\"{}\"", domain), None).await
    }

    /// Search for code containing specific patterns related to a domain
    pub async fn search_secrets(&self, domain: &str) -> Result<Vec<SecretFinding>> {
        let patterns = vec![
            (format!("\"{}\" password", domain), "Potential password"),
            (format!("\"{}\" api_key", domain), "Potential API key"),
            (format!("\"{}\" secret", domain), "Potential secret"),
            (format!("\"{}\" token", domain), "Potential token"),
            (format!("\"{}\" AWS_SECRET", domain), "AWS credential"),
            (
                format!("\"{}\" PRIVATE_KEY", domain),
                "Private key reference",
            ),
            (
                format!("\"{}\" connection_string", domain),
                "Database connection",
            ),
            (
                format!("\"{}\" smtp_password", domain),
                "SMTP credentials",
            ),
        ];

        let mut findings: Vec<SecretFinding> = Vec::new();

        for (query, category) in patterns {
            debug!("Searching GitHub for: {}", query);

            match self.search(&query, Some(10)).await {
                Ok(results) => {
                    for result in results {
                        findings.push(SecretFinding {
                            repository: result.repository,
                            file_path: result.file_path,
                            match_line: result.match_line,
                            url: result.url,
                            category: category.to_string(),
                            severity: categorize_severity(category),
                        });
                    }
                }
                Err(e) => {
                    warn!("GitHub search failed for '{}': {}", query, e);
                }
            }

            // Rate limiting - wait between requests
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        info!("Found {} potential secrets for {}", findings.len(), domain);

        Ok(findings)
    }

    /// Search GitHub code
    pub async fn search(
        &self,
        query: &str,
        per_page: Option<u32>,
    ) -> Result<Vec<CodeSearchResult>> {
        let url = "https://api.github.com/search/code";

        let mut request = self
            .client
            .get(url)
            .query(&[
                ("q", query),
                ("per_page", &per_page.unwrap_or(30).to_string()),
            ])
            .header("Accept", "application/vnd.github.text-match+json");

        if let Some(ref token) = self.api_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request.send().await?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            warn!("GitHub API authentication required for code search");
            return Err(anyhow::anyhow!(
                "GitHub API token required for code search"
            ));
        }

        if response.status() == reqwest::StatusCode::FORBIDDEN {
            let remaining = response
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("0");

            if remaining == "0" {
                warn!("GitHub API rate limit exceeded");
                return Err(anyhow::anyhow!("GitHub API rate limit exceeded"));
            }
        }

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "GitHub API error {}: {}",
                status,
                text
            ));
        }

        let search_response: GitHubSearchResponse = response.json().await?;

        let mut results: Vec<CodeSearchResult> = Vec::new();

        for item in search_response.items {
            // Skip forks to avoid duplicates
            if item.repository.fork {
                continue;
            }

            let match_line = item
                .text_matches
                .as_ref()
                .and_then(|m| m.first())
                .map(|m| m.fragment.clone())
                .unwrap_or_default();

            results.push(CodeSearchResult {
                repository: item.repository.full_name,
                file_path: item.path,
                match_line,
                line_number: None,
                url: item.html_url,
            });
        }

        Ok(results)
    }

    /// Search for exposed configuration files
    pub async fn search_configs(&self, domain: &str) -> Result<Vec<CodeSearchResult>> {
        let config_patterns = vec![
            format!("filename:.env \"{}\"", domain),
            format!("filename:config.json \"{}\"", domain),
            format!("filename:settings.json \"{}\"", domain),
            format!("filename:application.yml \"{}\"", domain),
            format!("filename:docker-compose \"{}\"", domain),
            format!("filename:.htaccess \"{}\"", domain),
            format!("filename:wp-config.php \"{}\"", domain),
        ];

        let mut all_results: Vec<CodeSearchResult> = Vec::new();

        for pattern in config_patterns {
            match self.search(&pattern, Some(10)).await {
                Ok(results) => {
                    all_results.extend(results);
                }
                Err(e) => {
                    debug!("Search failed for '{}': {}", pattern, e);
                }
            }

            // Rate limiting
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        Ok(all_results)
    }

    /// Search for internal/development references
    pub async fn search_internal_refs(&self, domain: &str) -> Result<Vec<CodeSearchResult>> {
        let internal_patterns = vec![
            format!("\"internal.{}\"", domain),
            format!("\"dev.{}\"", domain),
            format!("\"staging.{}\"", domain),
            format!("\"test.{}\"", domain),
            format!("\"admin.{}\"", domain),
            format!("\"api.{}\"", domain),
            format!("\"vpn.{}\"", domain),
        ];

        let mut all_results: Vec<CodeSearchResult> = Vec::new();

        for pattern in internal_patterns {
            match self.search(&pattern, Some(10)).await {
                Ok(results) => {
                    all_results.extend(results);
                }
                Err(e) => {
                    debug!("Search failed for '{}': {}", pattern, e);
                }
            }

            // Rate limiting
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        Ok(all_results)
    }
}

impl Default for GitHubCodeSearch {
    fn default() -> Self {
        Self::new(None).expect("Failed to create GitHubCodeSearch")
    }
}

/// Secret finding from GitHub search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub repository: String,
    pub file_path: String,
    pub match_line: String,
    pub url: String,
    pub category: String,
    pub severity: Severity,
}

/// Severity levels for findings
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Categorize severity based on finding type
fn categorize_severity(category: &str) -> Severity {
    match category.to_lowercase().as_str() {
        s if s.contains("aws") => Severity::Critical,
        s if s.contains("private_key") => Severity::Critical,
        s if s.contains("password") => Severity::High,
        s if s.contains("api_key") => Severity::High,
        s if s.contains("secret") => Severity::High,
        s if s.contains("token") => Severity::Medium,
        s if s.contains("connection") => Severity::Medium,
        s if s.contains("smtp") => Severity::Medium,
        _ => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_categorization() {
        assert_eq!(categorize_severity("AWS credential"), Severity::Critical);
        assert_eq!(categorize_severity("Potential password"), Severity::High);
        assert_eq!(categorize_severity("Potential token"), Severity::Medium);
    }
}
