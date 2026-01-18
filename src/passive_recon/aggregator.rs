//! Passive Reconnaissance Aggregator
//!
//! Combines results from multiple passive recon sources into a unified view.

use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use super::{
    crtsh::CrtshClient,
    github_search::{GitHubCodeSearch, SecretFinding},
    securitytrails::SecurityTrailsClient,
    wayback::{SensitivePath, WaybackClient},
    CodeSearchResult, HistoricalUrl, PassiveDnsRecord, SubdomainResult,
};

/// Recon data source
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconSource {
    CrtSh,
    Wayback,
    GitHub,
    SecurityTrails,
    VirusTotal,
}

impl std::fmt::Display for ReconSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrtSh => write!(f, "crt.sh"),
            Self::Wayback => write!(f, "Wayback Machine"),
            Self::GitHub => write!(f, "GitHub"),
            Self::SecurityTrails => write!(f, "SecurityTrails"),
            Self::VirusTotal => write!(f, "VirusTotal"),
        }
    }
}

/// Aggregated passive recon result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveReconResult {
    pub domain: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub sources_queried: Vec<ReconSource>,
    pub sources_succeeded: Vec<ReconSource>,
    pub sources_failed: HashMap<ReconSource, String>,
    pub subdomains: Vec<AggregatedSubdomain>,
    pub historical_urls: Vec<HistoricalUrl>,
    pub sensitive_paths: Vec<SensitivePath>,
    pub code_exposures: Vec<CodeSearchResult>,
    pub secret_findings: Vec<SecretFinding>,
    pub dns_history: Vec<PassiveDnsRecord>,
    pub statistics: ReconStatistics,
}

/// Aggregated subdomain with sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedSubdomain {
    pub subdomain: String,
    pub sources: Vec<ReconSource>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub additional_info: HashMap<String, serde_json::Value>,
}

/// Recon statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReconStatistics {
    pub total_subdomains: usize,
    pub unique_subdomains: usize,
    pub total_historical_urls: usize,
    pub sensitive_paths_found: usize,
    pub code_exposures: usize,
    pub secret_findings: usize,
    pub dns_records: usize,
    pub sources_by_subdomain_count: HashMap<String, usize>,
}

/// Configuration for passive recon
#[derive(Debug, Clone)]
pub struct PassiveReconConfig {
    pub use_crtsh: bool,
    pub use_wayback: bool,
    pub use_github: bool,
    pub use_securitytrails: bool,
    pub github_token: Option<String>,
    pub securitytrails_key: Option<String>,
    pub wayback_url_limit: Option<usize>,
}

impl Default for PassiveReconConfig {
    fn default() -> Self {
        Self {
            use_crtsh: true,
            use_wayback: true,
            use_github: false, // Requires token
            use_securitytrails: false, // Requires key
            github_token: None,
            securitytrails_key: None,
            wayback_url_limit: Some(10000),
        }
    }
}

/// Passive reconnaissance aggregator
pub struct PassiveReconAggregator {
    config: PassiveReconConfig,
}

impl PassiveReconAggregator {
    /// Create a new aggregator with config
    pub fn new(config: PassiveReconConfig) -> Self {
        Self { config }
    }

    /// Run full passive reconnaissance on a domain
    pub async fn run(&self, domain: &str) -> Result<PassiveReconResult> {
        info!("Starting passive reconnaissance for: {}", domain);
        let started_at = Utc::now();

        let mut sources_queried: Vec<ReconSource> = Vec::new();
        let mut sources_succeeded: Vec<ReconSource> = Vec::new();
        let mut sources_failed: HashMap<ReconSource, String> = HashMap::new();

        let mut all_subdomains: HashMap<String, AggregatedSubdomain> = HashMap::new();
        let mut historical_urls: Vec<HistoricalUrl> = Vec::new();
        let mut sensitive_paths: Vec<SensitivePath> = Vec::new();
        let mut code_exposures: Vec<CodeSearchResult> = Vec::new();
        let mut secret_findings: Vec<SecretFinding> = Vec::new();
        let mut dns_history: Vec<PassiveDnsRecord> = Vec::new();

        // crt.sh
        if self.config.use_crtsh {
            sources_queried.push(ReconSource::CrtSh);
            match self.query_crtsh(domain).await {
                Ok(subs) => {
                    sources_succeeded.push(ReconSource::CrtSh);
                    for sub in subs {
                        merge_subdomain(&mut all_subdomains, sub, ReconSource::CrtSh);
                    }
                }
                Err(e) => {
                    sources_failed.insert(ReconSource::CrtSh, e.to_string());
                }
            }
        }

        // Wayback Machine
        if self.config.use_wayback {
            sources_queried.push(ReconSource::Wayback);
            match self.query_wayback(domain).await {
                Ok((urls, sensitive, subs)) => {
                    sources_succeeded.push(ReconSource::Wayback);
                    historical_urls = urls;
                    sensitive_paths = sensitive;
                    for subdomain in subs {
                        merge_subdomain(
                            &mut all_subdomains,
                            SubdomainResult {
                                subdomain,
                                source: "Wayback".to_string(),
                                first_seen: None,
                                last_seen: None,
                                additional_info: None,
                            },
                            ReconSource::Wayback,
                        );
                    }
                }
                Err(e) => {
                    sources_failed.insert(ReconSource::Wayback, e.to_string());
                }
            }
        }

        // GitHub
        if self.config.use_github {
            sources_queried.push(ReconSource::GitHub);
            match self.query_github(domain).await {
                Ok((code, secrets)) => {
                    sources_succeeded.push(ReconSource::GitHub);
                    code_exposures = code;
                    secret_findings = secrets;
                }
                Err(e) => {
                    sources_failed.insert(ReconSource::GitHub, e.to_string());
                }
            }
        }

        // SecurityTrails
        if self.config.use_securitytrails && self.config.securitytrails_key.is_some() {
            sources_queried.push(ReconSource::SecurityTrails);
            match self.query_securitytrails(domain).await {
                Ok((subs, dns)) => {
                    sources_succeeded.push(ReconSource::SecurityTrails);
                    for sub in subs {
                        merge_subdomain(&mut all_subdomains, sub, ReconSource::SecurityTrails);
                    }
                    dns_history = dns;
                }
                Err(e) => {
                    sources_failed.insert(ReconSource::SecurityTrails, e.to_string());
                }
            }
        }

        let completed_at = Utc::now();

        // Build statistics
        let subdomains: Vec<AggregatedSubdomain> = all_subdomains.into_values().collect();

        let mut sources_by_count: HashMap<String, usize> = HashMap::new();
        for source in &sources_succeeded {
            let count = subdomains
                .iter()
                .filter(|s| s.sources.contains(source))
                .count();
            sources_by_count.insert(source.to_string(), count);
        }

        let statistics = ReconStatistics {
            total_subdomains: subdomains.len(),
            unique_subdomains: subdomains.len(),
            total_historical_urls: historical_urls.len(),
            sensitive_paths_found: sensitive_paths.len(),
            code_exposures: code_exposures.len(),
            secret_findings: secret_findings.len(),
            dns_records: dns_history.len(),
            sources_by_subdomain_count: sources_by_count,
        };

        info!(
            "Passive recon completed for {}: {} subdomains, {} URLs, {} sensitive paths",
            domain,
            statistics.unique_subdomains,
            statistics.total_historical_urls,
            statistics.sensitive_paths_found
        );

        Ok(PassiveReconResult {
            domain: domain.to_string(),
            started_at,
            completed_at,
            sources_queried,
            sources_succeeded,
            sources_failed,
            subdomains,
            historical_urls,
            sensitive_paths,
            code_exposures,
            secret_findings,
            dns_history,
            statistics,
        })
    }

    /// Run subdomain discovery only
    pub async fn discover_subdomains(&self, domain: &str) -> Result<Vec<AggregatedSubdomain>> {
        let mut all_subdomains: HashMap<String, AggregatedSubdomain> = HashMap::new();

        if self.config.use_crtsh {
            if let Ok(subs) = self.query_crtsh(domain).await {
                for sub in subs {
                    merge_subdomain(&mut all_subdomains, sub, ReconSource::CrtSh);
                }
            }
        }

        if self.config.use_wayback {
            if let Ok((_, _, subs)) = self.query_wayback(domain).await {
                for subdomain in subs {
                    merge_subdomain(
                        &mut all_subdomains,
                        SubdomainResult {
                            subdomain,
                            source: "Wayback".to_string(),
                            first_seen: None,
                            last_seen: None,
                            additional_info: None,
                        },
                        ReconSource::Wayback,
                    );
                }
            }
        }

        if self.config.use_securitytrails && self.config.securitytrails_key.is_some() {
            if let Ok((subs, _)) = self.query_securitytrails(domain).await {
                for sub in subs {
                    merge_subdomain(&mut all_subdomains, sub, ReconSource::SecurityTrails);
                }
            }
        }

        Ok(all_subdomains.into_values().collect())
    }

    // Internal query methods

    async fn query_crtsh(&self, domain: &str) -> Result<Vec<SubdomainResult>> {
        let client = CrtshClient::new()?;
        client.find_subdomains(domain).await
    }

    async fn query_wayback(
        &self,
        domain: &str,
    ) -> Result<(Vec<HistoricalUrl>, Vec<SensitivePath>, Vec<String>)> {
        let client = WaybackClient::new()?;

        let urls = client.get_urls(domain, self.config.wayback_url_limit).await?;
        let sensitive = client.find_sensitive_paths(domain).await?;
        let subdomains = client.get_subdomains(domain).await?;

        Ok((urls, sensitive, subdomains))
    }

    async fn query_github(&self, domain: &str) -> Result<(Vec<CodeSearchResult>, Vec<SecretFinding>)> {
        let client = GitHubCodeSearch::new(self.config.github_token.clone())?;

        let code = client.search_domain(domain).await?;
        let secrets = client.search_secrets(domain).await?;

        Ok((code, secrets))
    }

    async fn query_securitytrails(
        &self,
        domain: &str,
    ) -> Result<(Vec<SubdomainResult>, Vec<PassiveDnsRecord>)> {
        let key = self
            .config
            .securitytrails_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SecurityTrails API key required"))?;

        let client = SecurityTrailsClient::new(key.clone())?;

        let subdomains = client.get_subdomains(domain).await?;
        let dns_history = client.get_full_dns_history(domain).await?;

        Ok((subdomains, dns_history))
    }
}

impl Default for PassiveReconAggregator {
    fn default() -> Self {
        Self::new(PassiveReconConfig::default())
    }
}

/// Merge a subdomain result into the aggregated map
fn merge_subdomain(
    map: &mut HashMap<String, AggregatedSubdomain>,
    result: SubdomainResult,
    source: ReconSource,
) {
    let subdomain = result.subdomain.to_lowercase();

    if let Some(existing) = map.get_mut(&subdomain) {
        if !existing.sources.contains(&source) {
            existing.sources.push(source);
        }

        // Update timestamps if newer
        if let Some(first_seen) = result.first_seen {
            if existing.first_seen.is_none() || existing.first_seen > Some(first_seen) {
                existing.first_seen = Some(first_seen);
            }
        }
        if let Some(last_seen) = result.last_seen {
            if existing.last_seen.is_none() || existing.last_seen < Some(last_seen) {
                existing.last_seen = Some(last_seen);
            }
        }

        // Merge additional info
        if let Some(info) = result.additional_info {
            existing
                .additional_info
                .insert(source.to_string(), info);
        }
    } else {
        let mut additional_info = HashMap::new();
        if let Some(info) = result.additional_info {
            additional_info.insert(source.to_string(), info);
        }

        map.insert(
            subdomain.clone(),
            AggregatedSubdomain {
                subdomain,
                sources: vec![source],
                first_seen: result.first_seen,
                last_seen: result.last_seen,
                additional_info,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_subdomain() {
        let mut map: HashMap<String, AggregatedSubdomain> = HashMap::new();

        let result1 = SubdomainResult {
            subdomain: "api.example.com".to_string(),
            source: "crt.sh".to_string(),
            first_seen: Some(Utc::now()),
            last_seen: None,
            additional_info: None,
        };

        merge_subdomain(&mut map, result1, ReconSource::CrtSh);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("api.example.com").unwrap().sources.len(), 1);

        let result2 = SubdomainResult {
            subdomain: "api.example.com".to_string(),
            source: "wayback".to_string(),
            first_seen: None,
            last_seen: None,
            additional_info: None,
        };

        merge_subdomain(&mut map, result2, ReconSource::Wayback);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("api.example.com").unwrap().sources.len(), 2);
    }
}
