//! Threat Intelligence Automation
//!
//! Provides automated threat intelligence capabilities:
//! - IOC feed management and polling
//! - Automatic enrichment of IOCs
//! - IOC correlation across sources
//! - Threat actor tracking

use crate::green_team::types::*;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use uuid::Uuid;

/// Threat Intelligence Automation Engine
pub struct ThreatIntelEngine {
    feeds: HashMap<Uuid, IocFeed>,
    iocs: HashMap<Uuid, Vec<AutomatedIoc>>,
    enrichment_sources: Vec<EnrichmentSource>,
}

impl ThreatIntelEngine {
    /// Create a new threat intel engine
    pub fn new() -> Self {
        Self {
            feeds: HashMap::new(),
            iocs: HashMap::new(),
            enrichment_sources: create_default_enrichment_sources(),
        }
    }

    /// Register a new IOC feed
    pub fn register_feed(&mut self, feed: IocFeed) -> Uuid {
        let id = feed.id;
        self.feeds.insert(id, feed);
        self.iocs.insert(id, Vec::new());
        id
    }

    /// Get a feed by ID
    pub fn get_feed(&self, id: &Uuid) -> Option<&IocFeed> {
        self.feeds.get(id)
    }

    /// List all feeds
    pub fn list_feeds(&self) -> Vec<&IocFeed> {
        self.feeds.values().collect()
    }

    /// List active feeds
    pub fn list_active_feeds(&self) -> Vec<&IocFeed> {
        self.feeds.values().filter(|f| f.is_active).collect()
    }

    /// Update feed status after polling
    pub fn update_feed_status(&mut self, feed_id: &Uuid, status: &str, ioc_count: u32) {
        if let Some(feed) = self.feeds.get_mut(feed_id) {
            feed.last_poll_at = Some(Utc::now());
            feed.last_poll_status = Some(status.to_string());
            feed.ioc_count = ioc_count;
        }
    }

    /// Add an IOC from a feed
    pub fn add_ioc(&mut self, feed_id: &Uuid, ioc: AutomatedIoc) -> Result<(), String> {
        let iocs = self.iocs.get_mut(feed_id).ok_or("Feed not found")?;

        // Check for duplicates
        if !iocs.iter().any(|i| i.ioc_type == ioc.ioc_type && i.value == ioc.value) {
            iocs.push(ioc);
        }

        Ok(())
    }

    /// Get IOCs for a feed
    pub fn get_feed_iocs(&self, feed_id: &Uuid) -> Vec<&AutomatedIoc> {
        self.iocs
            .get(feed_id)
            .map(|iocs| iocs.iter().collect())
            .unwrap_or_default()
    }

    /// Search IOCs across all feeds
    pub fn search_iocs(&self, query: &str, ioc_type: Option<&IocType>) -> Vec<&AutomatedIoc> {
        let query_lower = query.to_lowercase();

        self.iocs
            .values()
            .flatten()
            .filter(|ioc| {
                if let Some(t) = ioc_type {
                    if &ioc.ioc_type != t {
                        return false;
                    }
                }
                ioc.value.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    /// Get IOCs by type
    pub fn get_iocs_by_type(&self, ioc_type: &IocType) -> Vec<&AutomatedIoc> {
        self.iocs
            .values()
            .flatten()
            .filter(|ioc| &ioc.ioc_type == ioc_type)
            .collect()
    }

    /// Get recently added IOCs
    pub fn get_recent_iocs(&self, hours: i64) -> Vec<&AutomatedIoc> {
        let cutoff = Utc::now() - Duration::hours(hours);

        self.iocs
            .values()
            .flatten()
            .filter(|ioc| ioc.created_at > cutoff)
            .collect()
    }

    /// Enrich an IOC
    pub async fn enrich_ioc(&self, ioc: &AutomatedIoc) -> EnrichmentResult {
        let mut results = HashMap::new();

        for source in &self.enrichment_sources {
            if source.supports_type(&ioc.ioc_type) {
                let result = self.query_enrichment_source(source, &ioc.value).await;
                results.insert(source.name.clone(), result);
            }
        }

        EnrichmentResult {
            ioc_value: ioc.value.clone(),
            ioc_type: ioc.ioc_type.clone(),
            sources_queried: results.keys().cloned().collect(),
            enrichment_data: serde_json::to_value(&results).unwrap_or_default(),
            enriched_at: Utc::now(),
        }
    }

    /// Query an enrichment source
    async fn query_enrichment_source(&self, source: &EnrichmentSource, value: &str) -> serde_json::Value {
        // In production, this would make actual API calls
        log::info!("Querying {} for {}", source.name, value);

        serde_json::json!({
            "source": source.name,
            "value": value,
            "reputation": "unknown",
            "last_seen": null,
            "categories": []
        })
    }

    /// Check if an IOC exists in any feed
    pub fn ioc_exists(&self, value: &str, ioc_type: &IocType) -> bool {
        self.iocs.values().flatten().any(|ioc| {
            &ioc.ioc_type == ioc_type && ioc.value.to_lowercase() == value.to_lowercase()
        })
    }

    /// Get feeds that need polling
    pub fn get_feeds_needing_poll(&self) -> Vec<&IocFeed> {
        let now = Utc::now();

        self.feeds
            .values()
            .filter(|feed| {
                if !feed.is_active {
                    return false;
                }

                match feed.last_poll_at {
                    Some(last_poll) => {
                        let interval = Duration::minutes(feed.poll_interval_minutes as i64);
                        now - last_poll > interval
                    }
                    None => true,
                }
            })
            .collect()
    }

    /// Get IOC statistics
    pub fn get_statistics(&self) -> IocStatistics {
        let total_iocs: usize = self.iocs.values().map(|v| v.len()).sum();
        let active_feeds = self.feeds.values().filter(|f| f.is_active).count();

        let mut by_type: HashMap<IocType, usize> = HashMap::new();
        for ioc in self.iocs.values().flatten() {
            *by_type.entry(ioc.ioc_type.clone()).or_insert(0) += 1;
        }

        let recent_24h = self.get_recent_iocs(24).len();

        IocStatistics {
            total_iocs,
            active_feeds,
            total_feeds: self.feeds.len(),
            by_type,
            added_last_24h: recent_24h,
        }
    }
}

impl Default for ThreatIntelEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Enrichment source configuration
#[derive(Debug, Clone)]
pub struct EnrichmentSource {
    pub name: String,
    pub source_type: EnrichmentSourceType,
    pub api_url: String,
    pub api_key: Option<String>,
    pub supported_types: Vec<IocType>,
    pub rate_limit_per_minute: u32,
    pub is_active: bool,
}

impl EnrichmentSource {
    /// Check if this source supports a given IOC type
    pub fn supports_type(&self, ioc_type: &IocType) -> bool {
        self.supported_types.contains(ioc_type)
    }
}

/// Types of enrichment sources
#[derive(Debug, Clone)]
pub enum EnrichmentSourceType {
    VirusTotal,
    Shodan,
    AbuseIPDB,
    AlienVault,
    MalwareBazaar,
    GreyNoise,
    Urlscan,
    Custom,
}

/// Result of IOC enrichment
#[derive(Debug, Clone)]
pub struct EnrichmentResult {
    pub ioc_value: String,
    pub ioc_type: IocType,
    pub sources_queried: Vec<String>,
    pub enrichment_data: serde_json::Value,
    pub enriched_at: DateTime<Utc>,
}

/// IOC statistics
#[derive(Debug, Clone)]
pub struct IocStatistics {
    pub total_iocs: usize,
    pub active_feeds: usize,
    pub total_feeds: usize,
    pub by_type: HashMap<IocType, usize>,
    pub added_last_24h: usize,
}

/// Create default enrichment sources
fn create_default_enrichment_sources() -> Vec<EnrichmentSource> {
    vec![
        EnrichmentSource {
            name: "VirusTotal".to_string(),
            source_type: EnrichmentSourceType::VirusTotal,
            api_url: "https://www.virustotal.com/api/v3".to_string(),
            api_key: None,
            supported_types: vec![
                IocType::Ipv4,
                IocType::Domain,
                IocType::Url,
                IocType::FileHash,
            ],
            rate_limit_per_minute: 4,
            is_active: true,
        },
        EnrichmentSource {
            name: "Shodan".to_string(),
            source_type: EnrichmentSourceType::Shodan,
            api_url: "https://api.shodan.io".to_string(),
            api_key: None,
            supported_types: vec![IocType::Ipv4, IocType::Ipv6],
            rate_limit_per_minute: 1,
            is_active: true,
        },
        EnrichmentSource {
            name: "AbuseIPDB".to_string(),
            source_type: EnrichmentSourceType::AbuseIPDB,
            api_url: "https://api.abuseipdb.com/api/v2".to_string(),
            api_key: None,
            supported_types: vec![IocType::Ipv4, IocType::Ipv6],
            rate_limit_per_minute: 60,
            is_active: true,
        },
        EnrichmentSource {
            name: "URLScan".to_string(),
            source_type: EnrichmentSourceType::Urlscan,
            api_url: "https://urlscan.io/api/v1".to_string(),
            api_key: None,
            supported_types: vec![IocType::Url, IocType::Domain],
            rate_limit_per_minute: 2,
            is_active: true,
        },
    ]
}

/// Create default IOC feeds from public threat intelligence sources
pub fn create_default_ioc_feeds() -> Vec<IocFeed> {
    let now = Utc::now();
    vec![
        // abuse.ch URLhaus feeds
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch URLhaus - CSV (online only)".to_string(),
            description: Some("Malicious URLs currently online from URLhaus".to_string()),
            feed_type: IocFeedType::Csv,
            url: "https://urlhaus.abuse.ch/downloads/csv_online/".to_string(),
            api_key: None,
            poll_interval_minutes: 60,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch URLhaus - CSV (recent only)".to_string(),
            description: Some("Recent malicious URLs from URLhaus".to_string()),
            feed_type: IocFeedType::Csv,
            url: "https://urlhaus.abuse.ch/downloads/csv_recent/".to_string(),
            api_key: None,
            poll_interval_minutes: 30,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch URLhaus - CSV (full; zip)".to_string(),
            description: Some("Complete URLhaus database (zipped CSV)".to_string()),
            feed_type: IocFeedType::Csv,
            url: "https://urlhaus.abuse.ch/downloads/csv/".to_string(),
            api_key: None,
            poll_interval_minutes: 1440, // Daily
            is_active: false, // Disabled by default due to size
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch URLhaus - Plain-text URLs".to_string(),
            description: Some("Plain-text list of malicious URLs".to_string()),
            feed_type: IocFeedType::Text,
            url: "https://urlhaus.abuse.ch/downloads/text/".to_string(),
            api_key: None,
            poll_interval_minutes: 60,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch URLhaus - Plain-text URLs (recent)".to_string(),
            description: Some("Recent malicious URLs (plain text)".to_string()),
            feed_type: IocFeedType::Text,
            url: "https://urlhaus.abuse.ch/downloads/text_recent/".to_string(),
            api_key: None,
            poll_interval_minutes: 30,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch URLhaus - Plain-text URLs (online)".to_string(),
            description: Some("Currently online malicious URLs (plain text)".to_string()),
            feed_type: IocFeedType::Text,
            url: "https://urlhaus.abuse.ch/downloads/text_online/".to_string(),
            api_key: None,
            poll_interval_minutes: 60,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        // abuse.ch Feodo Tracker
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch Feodo Tracker - C2 IPs (CSV)".to_string(),
            description: Some("Feodo/Emotet/Dridex C2 servers".to_string()),
            feed_type: IocFeedType::Csv,
            url: "https://feodotracker.abuse.ch/downloads/ipblocklist.csv".to_string(),
            api_key: None,
            poll_interval_minutes: 60,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch Feodo Tracker - C2 IPs (JSON)".to_string(),
            description: Some("Feodo/Emotet/Dridex C2 servers (JSON format)".to_string()),
            feed_type: IocFeedType::Json,
            url: "https://feodotracker.abuse.ch/downloads/ipblocklist.json".to_string(),
            api_key: None,
            poll_interval_minutes: 60,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch Feodo Tracker - C2 IPs (aggressive CSV)".to_string(),
            description: Some("Aggressive Feodo C2 blocklist".to_string()),
            feed_type: IocFeedType::Csv,
            url: "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv".to_string(),
            api_key: None,
            poll_interval_minutes: 60,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        // abuse.ch MalwareBazaar
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch MalwareBazaar - Hashes (CSV recent)".to_string(),
            description: Some("Recent malware hashes from MalwareBazaar".to_string()),
            feed_type: IocFeedType::Csv,
            url: "https://bazaar.abuse.ch/export/csv/recent/".to_string(),
            api_key: None,
            poll_interval_minutes: 60,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch MalwareBazaar - Hashes (CSV full; zip)".to_string(),
            description: Some("Complete MalwareBazaar database (zipped CSV)".to_string()),
            feed_type: IocFeedType::Csv,
            url: "https://bazaar.abuse.ch/export/csv/full/".to_string(),
            api_key: None,
            poll_interval_minutes: 1440, // Daily
            is_active: false, // Disabled by default due to size
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch MalwareBazaar - SHA256 (recent)".to_string(),
            description: Some("Recent SHA256 hashes (plain text)".to_string()),
            feed_type: IocFeedType::Text,
            url: "https://bazaar.abuse.ch/export/txt/sha256/recent/".to_string(),
            api_key: None,
            poll_interval_minutes: 60,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch MalwareBazaar - MD5 (recent)".to_string(),
            description: Some("Recent MD5 hashes (plain text)".to_string()),
            feed_type: IocFeedType::Text,
            url: "https://bazaar.abuse.ch/export/txt/md5/recent/".to_string(),
            api_key: None,
            poll_interval_minutes: 60,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        // abuse.ch SSLBL
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch SSLBL - SSL cert blacklist (SHA1 CSV)".to_string(),
            description: Some("Malicious SSL certificates".to_string()),
            feed_type: IocFeedType::Csv,
            url: "https://sslbl.abuse.ch/blacklist/sslblacklist.csv".to_string(),
            api_key: None,
            poll_interval_minutes: 240, // Every 4 hours
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch SSLBL - Botnet C2 IP blacklist (CSV; deprecated)".to_string(),
            description: Some("Botnet C2 IPs based on SSL certs (deprecated feed)".to_string()),
            feed_type: IocFeedType::Csv,
            url: "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv".to_string(),
            api_key: None,
            poll_interval_minutes: 240,
            is_active: false, // Deprecated
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        // abuse.ch ThreatFox
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch ThreatFox - IOC export (JSON full; zip)".to_string(),
            description: Some("Complete ThreatFox IOC database (zipped JSON)".to_string()),
            feed_type: IocFeedType::Json,
            url: "https://threatfox.abuse.ch/export/json/full/".to_string(),
            api_key: None,
            poll_interval_minutes: 1440, // Daily
            is_active: false, // Disabled by default due to size
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch ThreatFox - IOC export (JSON recent)".to_string(),
            description: Some("Recent IOCs from ThreatFox".to_string()),
            feed_type: IocFeedType::Json,
            url: "https://threatfox.abuse.ch/export/json/recent/".to_string(),
            api_key: None,
            poll_interval_minutes: 60,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "abuse.ch ThreatFox - Domains hostfile".to_string(),
            description: Some("Malicious domains in hosts file format".to_string()),
            feed_type: IocFeedType::Text,
            url: "https://threatfox.abuse.ch/downloads/hostfile/".to_string(),
            api_key: None,
            poll_interval_minutes: 120,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        // OpenPhish
        IocFeed {
            id: Uuid::new_v4(),
            name: "OpenPhish - Phishing URLs".to_string(),
            description: Some("Active phishing URLs from OpenPhish".to_string()),
            feed_type: IocFeedType::Text,
            url: "https://openphish.com/feed.txt".to_string(),
            api_key: None,
            poll_interval_minutes: 60,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        // Spamhaus
        IocFeed {
            id: Uuid::new_v4(),
            name: "Spamhaus DROP - Do Not Route/Peer IP ranges".to_string(),
            description: Some("Spamhaus Don't Route Or Peer lists".to_string()),
            feed_type: IocFeedType::Text,
            url: "https://www.spamhaus.org/drop/drop.txt".to_string(),
            api_key: None,
            poll_interval_minutes: 1440, // Daily
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "Spamhaus EDROP - extended DROP IP ranges".to_string(),
            description: Some("Extended Spamhaus DROP list".to_string()),
            feed_type: IocFeedType::Text,
            url: "https://www.spamhaus.org/drop/edrop.txt".to_string(),
            api_key: None,
            poll_interval_minutes: 1440, // Daily
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        // SANS ISC/DShield
        IocFeed {
            id: Uuid::new_v4(),
            name: "SANS ISC/DShield - Recommended blocklist".to_string(),
            description: Some("Top 20 attacking class C (/24) subnets".to_string()),
            feed_type: IocFeedType::Text,
            url: "https://isc.sans.edu/block.txt".to_string(),
            api_key: None,
            poll_interval_minutes: 360, // Every 6 hours
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        // FireHOL
        IocFeed {
            id: Uuid::new_v4(),
            name: "FireHOL - aggregated IP blacklist (level2)".to_string(),
            description: Some("FireHOL Level 2 IP blocklist".to_string()),
            feed_type: IocFeedType::Text,
            url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset".to_string(),
            api_key: None,
            poll_interval_minutes: 360,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        // CINS Army
        IocFeed {
            id: Uuid::new_v4(),
            name: "CINS Army - bad guys IP list".to_string(),
            description: Some("CINS Active Threat Intelligence IP list".to_string()),
            feed_type: IocFeedType::Text,
            url: "http://cinsscore.com/list/ci-badguys.txt".to_string(),
            api_key: None,
            poll_interval_minutes: 360,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        // MalSilo
        IocFeed {
            id: Uuid::new_v4(),
            name: "MalSilo - malicious domains".to_string(),
            description: Some("Malicious domains from MalSilo project".to_string()),
            feed_type: IocFeedType::Text,
            url: "https://malsilo.gitlab.io/feeds/dumps/domain_list.txt".to_string(),
            api_key: None,
            poll_interval_minutes: 720, // Every 12 hours
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        // OTX - AlienVault
        IocFeed {
            id: Uuid::new_v4(),
            name: "OTX - TAXII Discovery".to_string(),
            description: Some("AlienVault OTX TAXII feed discovery service".to_string()),
            feed_type: IocFeedType::Taxii,
            url: "https://otx.alienvault.com/taxii/discovery".to_string(),
            api_key: None,
            poll_interval_minutes: 1440, // Daily
            is_active: false, // Requires API key
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        // MISP OSINT Feeds
        IocFeed {
            id: Uuid::new_v4(),
            name: "MISP OSINT Feed - CIRCL".to_string(),
            description: Some("CIRCL MISP OSINT feed".to_string()),
            feed_type: IocFeedType::Misp,
            url: "https://www.circl.lu/doc/misp/feed-osint".to_string(),
            api_key: None,
            poll_interval_minutes: 720,
            is_active: false, // Requires configuration
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        IocFeed {
            id: Uuid::new_v4(),
            name: "MISP OSINT Feed - Botvrij.eu".to_string(),
            description: Some("Botvrij.eu MISP OSINT feed".to_string()),
            feed_type: IocFeedType::Misp,
            url: "https://www.botvrij.eu/data/feed-osint".to_string(),
            api_key: None,
            poll_interval_minutes: 720,
            is_active: false, // Requires configuration
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        // PhishTank
        IocFeed {
            id: Uuid::new_v4(),
            name: "PhishTank - URL lookup API".to_string(),
            description: Some("PhishTank phishing URL verification API".to_string()),
            feed_type: IocFeedType::Custom,
            url: "http://checkurl.phishtank.com/checkurl/".to_string(),
            api_key: None,
            poll_interval_minutes: 0, // On-demand API, not polled
            is_active: false, // API endpoint, not a feed
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
        // Emerging Threats
        IocFeed {
            id: Uuid::new_v4(),
            name: "Emerging Threats OPEN - Suricata ruleset".to_string(),
            description: Some("Emerging Threats Open ruleset for Suricata".to_string()),
            feed_type: IocFeedType::Custom,
            url: "http://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules.tar.gz".to_string(),
            api_key: None,
            poll_interval_minutes: 1440, // Daily
            is_active: false, // Requires special handling (tar.gz)
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        },
    ]
}

/// Feed parser for different feed formats
pub struct FeedParser;

impl FeedParser {
    /// Parse a CSV feed
    pub fn parse_csv(content: &str, ioc_type: IocType, value_column: usize) -> Vec<ParsedIoc> {
        content
            .lines()
            .skip(1) // Skip header
            .filter_map(|line| {
                let columns: Vec<&str> = line.split(',').collect();
                if columns.len() > value_column {
                    Some(ParsedIoc {
                        ioc_type: ioc_type.clone(),
                        value: columns[value_column].trim().to_string(),
                        confidence: None,
                        tags: Vec::new(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Parse a JSON feed
    pub fn parse_json(content: &str, ioc_field: &str, type_field: Option<&str>) -> Vec<ParsedIoc> {
        let value: serde_json::Value = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };

        let items = match value.as_array() {
            Some(arr) => arr,
            None => return Vec::new(),
        };

        items
            .iter()
            .filter_map(|item| {
                let value = item.get(ioc_field)?.as_str()?.to_string();
                let ioc_type = if let Some(tf) = type_field {
                    parse_ioc_type(item.get(tf)?.as_str()?)
                } else {
                    detect_ioc_type(&value)
                };

                Some(ParsedIoc {
                    ioc_type,
                    value,
                    confidence: item.get("confidence").and_then(|c| c.as_f64()),
                    tags: item
                        .get("tags")
                        .and_then(|t| t.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default(),
                })
            })
            .collect()
    }
}

/// Parsed IOC from a feed
#[derive(Debug, Clone)]
pub struct ParsedIoc {
    pub ioc_type: IocType,
    pub value: String,
    pub confidence: Option<f64>,
    pub tags: Vec<String>,
}

/// Parse IOC type from string
fn parse_ioc_type(type_str: &str) -> IocType {
    match type_str.to_lowercase().as_str() {
        "ip" | "ipv4" | "ip-src" | "ip-dst" => IocType::Ipv4,
        "ipv6" => IocType::Ipv6,
        "domain" | "hostname" => IocType::Domain,
        "url" | "uri" => IocType::Url,
        "email" | "email-src" | "email-dst" => IocType::Email,
        "md5" | "sha1" | "sha256" | "hash" | "file-hash" => IocType::FileHash,
        "filename" | "file-name" => IocType::FileName,
        "registry" | "regkey" => IocType::Registry,
        "mutex" => IocType::Mutex,
        "user-agent" => IocType::UserAgent,
        "cidr" => IocType::Cidr,
        "asn" => IocType::Asn,
        "btc" | "bitcoin" => IocType::Bitcoin,
        "cve" => IocType::Cve,
        _ => IocType::Other,
    }
}

/// Detect IOC type from value
fn detect_ioc_type(value: &str) -> IocType {
    // Simple detection heuristics
    if value.contains("://") {
        return IocType::Url;
    }

    // IPv4 pattern
    if value.split('.').count() == 4 {
        if value.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return IocType::Ipv4;
        }
    }

    // Domain pattern
    if value.contains('.') && !value.contains('/') && !value.contains('@') {
        return IocType::Domain;
    }

    // Email pattern
    if value.contains('@') {
        return IocType::Email;
    }

    // Hash patterns
    let len = value.len();
    if value.chars().all(|c| c.is_ascii_hexdigit()) {
        if len == 32 || len == 40 || len == 64 {
            return IocType::FileHash;
        }
    }

    // CVE pattern
    if value.to_uppercase().starts_with("CVE-") {
        return IocType::Cve;
    }

    IocType::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ioc_type() {
        assert_eq!(detect_ioc_type("192.168.1.1"), IocType::Ipv4);
        assert_eq!(detect_ioc_type("https://example.com"), IocType::Url);
        assert_eq!(detect_ioc_type("example.com"), IocType::Domain);
        assert_eq!(detect_ioc_type("user@example.com"), IocType::Email);
        assert_eq!(
            detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e"),
            IocType::FileHash
        );
        assert_eq!(detect_ioc_type("CVE-2024-1234"), IocType::Cve);
    }

    #[test]
    fn test_feed_registration() {
        let mut engine = ThreatIntelEngine::new();
        let now = Utc::now();

        let feed = IocFeed {
            id: Uuid::new_v4(),
            name: "Test Feed".to_string(),
            description: Some("A test feed".to_string()),
            feed_type: IocFeedType::Csv,
            url: "https://example.com/feed.csv".to_string(),
            api_key: None,
            poll_interval_minutes: 60,
            is_active: true,
            last_poll_at: None,
            last_poll_status: None,
            ioc_count: 0,
            created_at: now,
        };

        let id = engine.register_feed(feed);
        assert!(engine.get_feed(&id).is_some());
    }
}
