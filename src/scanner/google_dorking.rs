//! Google Dorking Automation Module
//!
//! This module provides automated Google dork queries for reconnaissance.
//!
//! # WARNING: Responsible Use Required
//!
//! Google dorking should ONLY be used for:
//! - Authorized security assessments of your own domains
//! - Penetration tests with explicit written permission
//! - Bug bounty programs where allowed by scope
//!
//! Misuse may violate:
//! - Computer fraud and abuse laws
//! - Google's Terms of Service
//! - Target organization's acceptable use policies
//!
//! Always ensure you have proper authorization before running dorks against any domain.

use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

pub mod templates {
    pub use crate::scanner::dorks::*;
}

/// Categories of Google dorks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DorkCategory {
    /// Sensitive files (passwords, configs, keys)
    SensitiveFiles,
    /// Login and authentication pages
    LoginPages,
    /// Configuration files
    ConfigFiles,
    /// Error messages and stack traces
    ErrorMessages,
    /// Administrative panels and interfaces
    AdminPanels,
    /// Directory listings
    Directories,
    /// Database files and exports
    DatabaseFiles,
    /// Backup files
    BackupFiles,
    /// API endpoints and documentation
    ApiEndpoints,
    /// Cloud storage buckets
    CloudStorage,
    /// Git/SVN repository exposure
    SourceControl,
    /// Log files
    LogFiles,
}

impl DorkCategory {
    /// Get all categories
    pub fn all() -> Vec<DorkCategory> {
        vec![
            DorkCategory::SensitiveFiles,
            DorkCategory::LoginPages,
            DorkCategory::ConfigFiles,
            DorkCategory::ErrorMessages,
            DorkCategory::AdminPanels,
            DorkCategory::Directories,
            DorkCategory::DatabaseFiles,
            DorkCategory::BackupFiles,
            DorkCategory::ApiEndpoints,
            DorkCategory::CloudStorage,
            DorkCategory::SourceControl,
            DorkCategory::LogFiles,
        ]
    }

    /// Get category description
    pub fn description(&self) -> &'static str {
        match self {
            DorkCategory::SensitiveFiles => "Find exposed sensitive files like passwords, keys, and credentials",
            DorkCategory::LoginPages => "Discover login and authentication pages",
            DorkCategory::ConfigFiles => "Find exposed configuration files",
            DorkCategory::ErrorMessages => "Locate error messages and stack traces that may leak information",
            DorkCategory::AdminPanels => "Find administrative panels and management interfaces",
            DorkCategory::Directories => "Discover directory listings and file indices",
            DorkCategory::DatabaseFiles => "Find database files, exports, and SQL dumps",
            DorkCategory::BackupFiles => "Locate backup files and archives",
            DorkCategory::ApiEndpoints => "Find API endpoints and documentation",
            DorkCategory::CloudStorage => "Discover exposed cloud storage buckets",
            DorkCategory::SourceControl => "Find exposed Git/SVN repositories",
            DorkCategory::LogFiles => "Locate exposed log files",
        }
    }

    /// Get category display name
    pub fn display_name(&self) -> &'static str {
        match self {
            DorkCategory::SensitiveFiles => "Sensitive Files",
            DorkCategory::LoginPages => "Login Pages",
            DorkCategory::ConfigFiles => "Configuration Files",
            DorkCategory::ErrorMessages => "Error Messages",
            DorkCategory::AdminPanels => "Admin Panels",
            DorkCategory::Directories => "Directory Listings",
            DorkCategory::DatabaseFiles => "Database Files",
            DorkCategory::BackupFiles => "Backup Files",
            DorkCategory::ApiEndpoints => "API Endpoints",
            DorkCategory::CloudStorage => "Cloud Storage",
            DorkCategory::SourceControl => "Source Control",
            DorkCategory::LogFiles => "Log Files",
        }
    }
}

impl std::fmt::Display for DorkCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// A Google dork template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DorkTemplate {
    /// Unique identifier
    pub id: String,
    /// Category of the dork
    pub category: DorkCategory,
    /// Human-readable name
    pub name: String,
    /// The dork query template with placeholders
    /// Supports: {domain}, {target}, {site}
    pub query_template: String,
    /// Description of what this dork finds
    pub description: String,
    /// Risk level (info, low, medium, high, critical)
    pub risk_level: String,
    /// Whether this is a built-in template
    pub is_builtin: bool,
    /// Tags for filtering
    pub tags: Vec<String>,
}

impl DorkTemplate {
    /// Create a new dork template
    pub fn new(
        id: impl Into<String>,
        category: DorkCategory,
        name: impl Into<String>,
        query_template: impl Into<String>,
        description: impl Into<String>,
        risk_level: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            category,
            name: name.into(),
            query_template: query_template.into(),
            description: description.into(),
            risk_level: risk_level.into(),
            is_builtin: true,
            tags: Vec::new(),
        }
    }

    /// Build the actual query by substituting placeholders
    pub fn build_query(&self, domain: &str) -> String {
        self.query_template
            .replace("{domain}", domain)
            .replace("{target}", domain)
            .replace("{site}", domain)
    }

    /// Get the Google search URL for this dork
    pub fn get_search_url(&self, domain: &str) -> String {
        let query = self.build_query(domain);
        format!(
            "https://www.google.com/search?q={}",
            urlencoding::encode(&query)
        )
    }
}

/// A single search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Page title
    pub title: String,
    /// URL of the result
    pub url: String,
    /// Snippet/description
    pub snippet: String,
    /// Position in search results
    pub position: u32,
}

/// Result from executing a dork query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DorkResult {
    /// The dork template used
    pub template_id: String,
    /// The actual query executed
    pub query: String,
    /// Domain/target scanned
    pub domain: String,
    /// Search results found
    pub results: Vec<SearchResult>,
    /// Number of results
    pub result_count: usize,
    /// When the dork was executed
    pub executed_at: DateTime<Utc>,
    /// Duration of the search in milliseconds
    pub duration_ms: u64,
    /// Status of the search
    pub status: DorkStatus,
    /// Error message if failed
    pub error: Option<String>,
    /// Search provider used
    pub provider: String,
}

/// Status of a dork execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DorkStatus {
    /// Successfully executed
    Success,
    /// Rate limited by search provider
    RateLimited,
    /// Provider error
    ProviderError,
    /// Network error
    NetworkError,
    /// Manual execution required (placeholder mode)
    ManualRequired,
}

/// Configuration for dork execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DorkConfig {
    /// Maximum results per query
    pub max_results: usize,
    /// Delay between queries in milliseconds (for rate limiting)
    pub delay_ms: u64,
    /// Timeout for each query in seconds
    pub timeout_secs: u64,
    /// Search provider to use
    pub provider: SearchProviderType,
    /// SerpAPI key (if using SerpAPI)
    pub serpapi_key: Option<String>,
    /// Whether to include only exact domain matches
    pub exact_domain_only: bool,
}

impl Default for DorkConfig {
    fn default() -> Self {
        Self {
            max_results: 10,
            delay_ms: 2000, // 2 second delay to avoid rate limiting
            timeout_secs: 30,
            provider: SearchProviderType::Placeholder,
            serpapi_key: None,
            exact_domain_only: true,
        }
    }
}

/// Types of search providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchProviderType {
    /// Direct Google search (not recommended, easily blocked)
    DirectGoogle,
    /// SerpAPI service (recommended)
    SerpApi,
    /// Placeholder mode - returns URLs for manual execution
    Placeholder,
}

/// Trait for search providers
#[async_trait::async_trait]
pub trait SearchProvider: Send + Sync {
    /// Execute a search query
    async fn search(&self, query: &str, max_results: usize) -> Result<Vec<SearchResult>>;

    /// Get the provider name
    fn name(&self) -> &str;

    /// Check if the provider is available
    fn is_available(&self) -> bool;
}

/// Placeholder search provider - returns query URLs for manual execution
pub struct PlaceholderProvider;

#[async_trait::async_trait]
impl SearchProvider for PlaceholderProvider {
    async fn search(&self, query: &str, _max_results: usize) -> Result<Vec<SearchResult>> {
        // Return a single result with the search URL for manual execution
        let search_url = format!(
            "https://www.google.com/search?q={}",
            urlencoding::encode(query)
        );

        Ok(vec![SearchResult {
            title: "Manual Search Required".to_string(),
            url: search_url,
            snippet: format!("Open this URL to manually execute the dork: {}", query),
            position: 1,
        }])
    }

    fn name(&self) -> &str {
        "placeholder"
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// SerpAPI search provider
pub struct SerpApiProvider {
    api_key: String,
    client: reqwest::Client,
}

impl SerpApiProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct SerpApiResponse {
    organic_results: Option<Vec<SerpApiResult>>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SerpApiResult {
    title: Option<String>,
    link: Option<String>,
    snippet: Option<String>,
    position: Option<u32>,
}

#[async_trait::async_trait]
impl SearchProvider for SerpApiProvider {
    async fn search(&self, query: &str, max_results: usize) -> Result<Vec<SearchResult>> {
        let url = format!(
            "https://serpapi.com/search.json?q={}&api_key={}&num={}",
            urlencoding::encode(query),
            self.api_key,
            max_results
        );

        debug!("Executing SerpAPI search: {}", query);

        let response = self.client
            .get(&url)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "SerpAPI request failed with status: {}",
                response.status()
            ));
        }

        let data: SerpApiResponse = response.json().await?;

        if let Some(error) = data.error {
            return Err(anyhow::anyhow!("SerpAPI error: {}", error));
        }

        let results = data.organic_results
            .unwrap_or_default()
            .into_iter()
            .map(|r| SearchResult {
                title: r.title.unwrap_or_default(),
                url: r.link.unwrap_or_default(),
                snippet: r.snippet.unwrap_or_default(),
                position: r.position.unwrap_or(0),
            })
            .collect();

        Ok(results)
    }

    fn name(&self) -> &str {
        "serpapi"
    }

    fn is_available(&self) -> bool {
        !self.api_key.is_empty()
    }
}

/// Create a search provider based on configuration
pub fn create_provider(config: &DorkConfig) -> Box<dyn SearchProvider> {
    match config.provider {
        SearchProviderType::SerpApi => {
            if let Some(key) = &config.serpapi_key {
                Box::new(SerpApiProvider::new(key.clone()))
            } else {
                warn!("SerpAPI key not provided, falling back to placeholder mode");
                Box::new(PlaceholderProvider)
            }
        }
        SearchProviderType::DirectGoogle => {
            warn!("Direct Google search is not recommended and may be blocked. Using placeholder mode.");
            Box::new(PlaceholderProvider)
        }
        SearchProviderType::Placeholder => Box::new(PlaceholderProvider),
    }
}

/// Run a single dork against a domain
pub async fn run_dork(
    domain: &str,
    template: &DorkTemplate,
    config: &DorkConfig,
) -> Result<DorkResult> {
    let start = std::time::Instant::now();
    let query = template.build_query(domain);
    let provider = create_provider(config);

    info!(
        "Running dork '{}' against domain: {} (provider: {})",
        template.name,
        domain,
        provider.name()
    );

    let (results, status, error) = match provider.search(&query, config.max_results).await {
        Ok(results) => (results, DorkStatus::Success, None),
        Err(e) => {
            let error_str = e.to_string();
            let status = if error_str.contains("rate") || error_str.contains("429") {
                DorkStatus::RateLimited
            } else if error_str.contains("network") || error_str.contains("connection") {
                DorkStatus::NetworkError
            } else {
                DorkStatus::ProviderError
            };
            (Vec::new(), status, Some(error_str))
        }
    };

    let duration = start.elapsed();
    let result_count = results.len();

    Ok(DorkResult {
        template_id: template.id.clone(),
        query,
        domain: domain.to_string(),
        results,
        result_count,
        executed_at: Utc::now(),
        duration_ms: duration.as_millis() as u64,
        status,
        error,
        provider: provider.name().to_string(),
    })
}

/// Run all dorks in a category against a domain
pub async fn run_category_dorks(
    domain: &str,
    category: DorkCategory,
    config: &DorkConfig,
) -> Result<Vec<DorkResult>> {
    let templates = templates::get_templates_by_category(category);
    let mut results = Vec::new();

    info!(
        "Running {} dorks in category '{}' against domain: {}",
        templates.len(),
        category,
        domain
    );

    for template in templates {
        let result = run_dork(domain, &template, config).await?;
        results.push(result);

        // Rate limiting delay between queries
        if config.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(config.delay_ms)).await;
        }
    }

    Ok(results)
}

/// Run all built-in dorks against a domain
pub async fn run_all_dorks(
    domain: &str,
    config: &DorkConfig,
) -> Result<Vec<DorkResult>> {
    let templates = templates::get_all_templates();
    let mut results = Vec::new();

    info!(
        "Running all {} dorks against domain: {}",
        templates.len(),
        domain
    );

    for template in templates {
        let result = run_dork(domain, &template, config).await?;
        results.push(result);

        // Rate limiting delay between queries
        if config.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(config.delay_ms)).await;
        }
    }

    Ok(results)
}

/// Run selected dorks by template IDs
pub async fn run_selected_dorks(
    domain: &str,
    template_ids: &[String],
    config: &DorkConfig,
) -> Result<Vec<DorkResult>> {
    let all_templates = templates::get_all_templates();
    let selected: Vec<_> = all_templates
        .into_iter()
        .filter(|t| template_ids.contains(&t.id))
        .collect();

    let mut results = Vec::new();

    info!(
        "Running {} selected dorks against domain: {}",
        selected.len(),
        domain
    );

    for template in selected {
        let result = run_dork(domain, &template, config).await?;
        results.push(result);

        // Rate limiting delay between queries
        if config.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(config.delay_ms)).await;
        }
    }

    Ok(results)
}

/// Run a custom dork query (not from template)
pub async fn run_custom_dork(
    domain: &str,
    query: &str,
    config: &DorkConfig,
) -> Result<DorkResult> {
    let start = std::time::Instant::now();

    // Substitute {domain} placeholder if present
    let final_query = query
        .replace("{domain}", domain)
        .replace("{target}", domain)
        .replace("{site}", domain);

    let provider = create_provider(config);

    info!(
        "Running custom dork against domain: {} (provider: {})",
        domain,
        provider.name()
    );

    let (results, status, error) = match provider.search(&final_query, config.max_results).await {
        Ok(results) => (results, DorkStatus::Success, None),
        Err(e) => {
            let error_str = e.to_string();
            let status = if error_str.contains("rate") || error_str.contains("429") {
                DorkStatus::RateLimited
            } else if error_str.contains("network") || error_str.contains("connection") {
                DorkStatus::NetworkError
            } else {
                DorkStatus::ProviderError
            };
            (Vec::new(), status, Some(error_str))
        }
    };

    let duration = start.elapsed();
    let result_count = results.len();

    Ok(DorkResult {
        template_id: "custom".to_string(),
        query: final_query,
        domain: domain.to_string(),
        results,
        result_count,
        executed_at: Utc::now(),
        duration_ms: duration.as_millis() as u64,
        status,
        error,
        provider: provider.name().to_string(),
    })
}

/// Summary of dork scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DorkScanSummary {
    /// Domain scanned
    pub domain: String,
    /// Total number of dorks executed
    pub total_dorks: usize,
    /// Number of successful dorks
    pub successful_dorks: usize,
    /// Number of dorks with results
    pub dorks_with_results: usize,
    /// Total results found
    pub total_results: usize,
    /// Results by category
    pub results_by_category: HashMap<String, usize>,
    /// Results by risk level
    pub results_by_risk: HashMap<String, usize>,
    /// Scan started at
    pub started_at: DateTime<Utc>,
    /// Scan completed at
    pub completed_at: DateTime<Utc>,
    /// Total duration in seconds
    pub duration_secs: f64,
}

/// Generate a summary from dork results
pub fn summarize_results(
    domain: &str,
    results: &[DorkResult],
    started_at: DateTime<Utc>,
) -> DorkScanSummary {
    let templates = templates::get_all_templates();
    let template_map: HashMap<_, _> = templates
        .into_iter()
        .map(|t| (t.id.clone(), t))
        .collect();

    let mut results_by_category: HashMap<String, usize> = HashMap::new();
    let mut results_by_risk: HashMap<String, usize> = HashMap::new();

    let completed_at = Utc::now();
    let duration_secs = (completed_at - started_at).num_milliseconds() as f64 / 1000.0;

    let successful_dorks = results.iter().filter(|r| r.status == DorkStatus::Success).count();
    let dorks_with_results = results.iter().filter(|r| !r.results.is_empty()).count();
    let total_results: usize = results.iter().map(|r| r.result_count).sum();

    for result in results {
        if let Some(template) = template_map.get(&result.template_id) {
            let category = template.category.display_name().to_string();
            *results_by_category.entry(category).or_insert(0) += result.result_count;

            let risk = template.risk_level.clone();
            *results_by_risk.entry(risk).or_insert(0) += result.result_count;
        }
    }

    DorkScanSummary {
        domain: domain.to_string(),
        total_dorks: results.len(),
        successful_dorks,
        dorks_with_results,
        total_results,
        results_by_category,
        results_by_risk,
        started_at,
        completed_at,
        duration_secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dork_category_all() {
        let categories = DorkCategory::all();
        assert!(!categories.is_empty());
        assert!(categories.contains(&DorkCategory::SensitiveFiles));
        assert!(categories.contains(&DorkCategory::LoginPages));
    }

    #[test]
    fn test_dork_template_build_query() {
        let template = DorkTemplate::new(
            "test-1",
            DorkCategory::SensitiveFiles,
            "Test Dork",
            "site:{domain} filetype:sql",
            "Find SQL files",
            "high",
        );

        let query = template.build_query("example.com");
        assert_eq!(query, "site:example.com filetype:sql");
    }

    #[test]
    fn test_dork_template_search_url() {
        let template = DorkTemplate::new(
            "test-1",
            DorkCategory::SensitiveFiles,
            "Test Dork",
            "site:{domain} filetype:sql",
            "Find SQL files",
            "high",
        );

        let url = template.get_search_url("example.com");
        assert!(url.starts_with("https://www.google.com/search?q="));
        assert!(url.contains("example.com"));
    }

    #[test]
    fn test_dork_config_default() {
        let config = DorkConfig::default();
        assert_eq!(config.max_results, 10);
        assert_eq!(config.delay_ms, 2000);
        assert_eq!(config.provider, SearchProviderType::Placeholder);
    }

    #[tokio::test]
    async fn test_placeholder_provider() {
        let provider = PlaceholderProvider;
        let results = provider.search("test query", 10).await.unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].url.contains("google.com/search"));
    }
}
