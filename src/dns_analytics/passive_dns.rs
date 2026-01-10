//! Passive DNS Collection and Storage
//!
//! Collects and stores DNS query/response pairs for analysis.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use super::types::{
    PassiveDnsRecord, DnsRecordType, DnsThreatType, DnsQuery,
    DnsStats, DomainCount, QueryTypeCount, ClientQueryCount,
};

/// Passive DNS store configuration
#[derive(Debug, Clone)]
pub struct PassiveDnsConfig {
    /// Maximum records to keep in memory
    pub max_records: usize,
    /// Maximum source IPs to track per record
    pub max_source_ips: usize,
    /// Record expiry time (hours)
    pub record_ttl_hours: i64,
    /// Enable threat scoring
    pub enable_threat_scoring: bool,
}

impl Default for PassiveDnsConfig {
    fn default() -> Self {
        Self {
            max_records: 100_000,
            max_source_ips: 100,
            record_ttl_hours: 24 * 7, // 1 week
            enable_threat_scoring: true,
        }
    }
}

/// Passive DNS store
pub struct PassiveDnsStore {
    config: PassiveDnsConfig,
    /// Records indexed by (domain, record_type, response_data)
    records: Arc<RwLock<HashMap<String, PassiveDnsRecord>>>,
    /// Query count per client IP
    client_queries: Arc<RwLock<HashMap<IpAddr, ClientStats>>>,
    /// Domain statistics
    domain_stats: Arc<RwLock<HashMap<String, DomainStats>>>,
    /// Query type counts
    query_type_counts: Arc<RwLock<HashMap<DnsRecordType, i64>>>,
    /// Total query count
    total_queries: Arc<RwLock<i64>>,
    /// NXDOMAIN count
    nxdomain_count: Arc<RwLock<i64>>,
}

#[derive(Debug, Clone)]
struct ClientStats {
    query_count: i64,
    unique_domains: std::collections::HashSet<String>,
    nxdomain_count: i64,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct DomainStats {
    query_count: i64,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    is_suspicious: bool,
    threat_type: Option<DnsThreatType>,
}

impl PassiveDnsStore {
    pub fn new() -> Self {
        Self::with_config(PassiveDnsConfig::default())
    }

    pub fn with_config(config: PassiveDnsConfig) -> Self {
        Self {
            config,
            records: Arc::new(RwLock::new(HashMap::new())),
            client_queries: Arc::new(RwLock::new(HashMap::new())),
            domain_stats: Arc::new(RwLock::new(HashMap::new())),
            query_type_counts: Arc::new(RwLock::new(HashMap::new())),
            total_queries: Arc::new(RwLock::new(0)),
            nxdomain_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Process a DNS query and store in passive DNS
    pub async fn process_query(&self, query: &DnsQuery) {
        // Update total queries
        {
            let mut total = self.total_queries.write().await;
            *total += 1;
        }

        // Update NXDOMAIN count
        if matches!(query.response_code, super::types::DnsResponseCode::NXDomain) {
            let mut nx = self.nxdomain_count.write().await;
            *nx += 1;
        }

        // Update query type counts
        {
            let mut counts = self.query_type_counts.write().await;
            *counts.entry(query.query_type).or_insert(0) += 1;
        }

        // Update client stats
        {
            let mut clients = self.client_queries.write().await;
            let stats = clients.entry(query.source_ip).or_insert_with(|| ClientStats {
                query_count: 0,
                unique_domains: std::collections::HashSet::new(),
                nxdomain_count: 0,
                first_seen: query.timestamp,
                last_seen: query.timestamp,
            });
            stats.query_count += 1;
            stats.unique_domains.insert(query.query_name.clone());
            if matches!(query.response_code, super::types::DnsResponseCode::NXDomain) {
                stats.nxdomain_count += 1;
            }
            stats.last_seen = query.timestamp;
        }

        // Update domain stats
        {
            let mut domains = self.domain_stats.write().await;
            let stats = domains.entry(query.query_name.clone()).or_insert_with(|| DomainStats {
                query_count: 0,
                first_seen: query.timestamp,
                last_seen: query.timestamp,
                is_suspicious: false,
                threat_type: None,
            });
            stats.query_count += 1;
            stats.last_seen = query.timestamp;
        }

        // Store passive DNS records for responses
        if !query.response_data.is_empty() {
            let mut records = self.records.write().await;

            for response in &query.response_data {
                let key = format!("{}:{}:{}", query.query_name, query.query_type, response);

                if let Some(record) = records.get_mut(&key) {
                    // Update existing record
                    record.query_count += 1;
                    record.last_seen = query.timestamp;
                    if !record.source_ips.contains(&query.source_ip) &&
                       record.source_ips.len() < self.config.max_source_ips {
                        record.source_ips.push(query.source_ip);
                    }
                } else {
                    // Create new record
                    let record = PassiveDnsRecord {
                        id: uuid::Uuid::new_v4().to_string(),
                        query_name: query.query_name.clone(),
                        query_type: query.query_type,
                        response_data: response.clone(),
                        ttl: query.ttl,
                        first_seen: query.timestamp,
                        last_seen: query.timestamp,
                        query_count: 1,
                        source_ips: vec![query.source_ip],
                        is_suspicious: false,
                        threat_type: None,
                        threat_score: 0,
                        created_at: Utc::now(),
                    };
                    records.insert(key, record);
                }
            }

            // Enforce max records limit
            if records.len() > self.config.max_records {
                self.cleanup_old_records(&mut records);
            }
        }
    }

    /// Mark a domain as suspicious
    pub async fn mark_suspicious(&self, domain: &str, threat_type: DnsThreatType, threat_score: i32) {
        // Update domain stats
        {
            let mut domains = self.domain_stats.write().await;
            if let Some(stats) = domains.get_mut(domain) {
                stats.is_suspicious = true;
                stats.threat_type = Some(threat_type);
            }
        }

        // Update passive DNS records for this domain
        {
            let mut records = self.records.write().await;
            for record in records.values_mut() {
                if record.query_name == domain {
                    record.is_suspicious = true;
                    record.threat_type = Some(threat_type);
                    record.threat_score = threat_score;
                }
            }
        }
    }

    /// Get passive DNS records for a domain
    pub async fn get_domain_records(&self, domain: &str) -> Vec<PassiveDnsRecord> {
        let records = self.records.read().await;
        records.values()
            .filter(|r| r.query_name == domain)
            .cloned()
            .collect()
    }

    /// Get domain history (all unique response IPs/data)
    pub async fn get_domain_history(&self, domain: &str) -> Vec<PassiveDnsRecord> {
        let records = self.records.read().await;
        records.values()
            .filter(|r| r.query_name.ends_with(domain) || r.query_name == domain)
            .cloned()
            .collect()
    }

    /// Search passive DNS by response data (e.g., IP address)
    pub async fn search_by_response(&self, response_data: &str) -> Vec<PassiveDnsRecord> {
        let records = self.records.read().await;
        records.values()
            .filter(|r| r.response_data.contains(response_data))
            .cloned()
            .collect()
    }

    /// Get statistics
    pub async fn get_stats(&self) -> DnsStats {
        let records = self.records.read().await;
        let clients = self.client_queries.read().await;
        let domains = self.domain_stats.read().await;
        let query_types = self.query_type_counts.read().await;
        let total = *self.total_queries.read().await;
        let nxdomain = *self.nxdomain_count.read().await;

        // Calculate top queried domains
        let mut domain_counts: Vec<_> = domains.iter()
            .map(|(d, s)| (d.clone(), s.query_count, s.is_suspicious))
            .collect();
        domain_counts.sort_by(|a, b| b.1.cmp(&a.1));
        let top_queried_domains: Vec<DomainCount> = domain_counts.into_iter()
            .take(20)
            .map(|(domain, count, is_suspicious)| DomainCount { domain, count, is_suspicious })
            .collect();

        // Calculate query type distribution
        let total_type_queries: i64 = query_types.values().sum();
        let top_query_types: Vec<QueryTypeCount> = query_types.iter()
            .map(|(&qt, &count)| QueryTypeCount {
                query_type: qt,
                count,
                percentage: if total_type_queries > 0 {
                    count as f64 / total_type_queries as f64 * 100.0
                } else {
                    0.0
                },
            })
            .collect();

        // Calculate top clients
        let mut client_counts: Vec<_> = clients.iter()
            .map(|(ip, s)| (*ip, s.query_count, s.unique_domains.len() as i64, s.nxdomain_count))
            .collect();
        client_counts.sort_by(|a, b| b.1.cmp(&a.1));
        let top_clients: Vec<ClientQueryCount> = client_counts.into_iter()
            .take(20)
            .map(|(client_ip, query_count, unique_domains, nxdomain_count)| {
                ClientQueryCount { client_ip, query_count, unique_domains, nxdomain_count }
            })
            .collect();

        // Count suspicious domains
        let suspicious_domains = domains.values().filter(|s| s.is_suspicious).count() as i64;

        DnsStats {
            total_queries: total,
            unique_domains: domains.len() as i64,
            unique_clients: clients.len() as i64,
            nxdomain_count: nxdomain,
            nxdomain_rate: if total > 0 { nxdomain as f64 / total as f64 } else { 0.0 },
            dga_detections: 0, // Filled by analyzer
            tunnel_detections: 0,
            fast_flux_detections: 0,
            newly_observed_domains: 0,
            suspicious_domains,
            top_queried_domains,
            top_query_types,
            top_clients,
            queries_per_hour: vec![], // Filled by analyzer with time series data
        }
    }

    /// Cleanup old records when limit exceeded
    fn cleanup_old_records(&self, records: &mut HashMap<String, PassiveDnsRecord>) {
        // Sort by last_seen and remove oldest
        let mut sorted: Vec<_> = records.iter()
            .map(|(k, v)| (k.clone(), v.last_seen))
            .collect();
        sorted.sort_by(|a, b| a.1.cmp(&b.1));

        let to_remove = records.len() - self.config.max_records + (self.config.max_records / 10);
        for (key, _) in sorted.into_iter().take(to_remove) {
            records.remove(&key);
        }
    }

    /// Clear all data
    pub async fn clear(&self) {
        self.records.write().await.clear();
        self.client_queries.write().await.clear();
        self.domain_stats.write().await.clear();
        self.query_type_counts.write().await.clear();
        *self.total_queries.write().await = 0;
        *self.nxdomain_count.write().await = 0;
    }

    /// Get all suspicious domains
    pub async fn get_suspicious_domains(&self) -> Vec<(String, DnsThreatType, i64)> {
        let domains = self.domain_stats.read().await;
        domains.iter()
            .filter_map(|(d, s)| {
                if s.is_suspicious {
                    Some((d.clone(), s.threat_type.unwrap_or(DnsThreatType::Unknown), s.query_count))
                } else {
                    None
                }
            })
            .collect()
    }
}

impl Default for PassiveDnsStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_analytics::types::DnsResponseCode;

    fn create_query(name: &str, qtype: DnsRecordType, response: &str) -> DnsQuery {
        DnsQuery {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            source_ip: "192.168.1.100".parse().unwrap(),
            source_port: 12345,
            query_name: name.to_string(),
            query_type: qtype,
            response_code: DnsResponseCode::NoError,
            response_data: vec![response.to_string()],
            ttl: Some(300),
            latency_ms: Some(10),
            server_ip: None,
            is_recursive: true,
            is_dnssec: false,
        }
    }

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let store = PassiveDnsStore::new();

        store.process_query(&create_query("example.com", DnsRecordType::A, "93.184.216.34")).await;
        store.process_query(&create_query("example.com", DnsRecordType::A, "93.184.216.34")).await;

        let records = store.get_domain_records("example.com").await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].query_count, 2);
    }

    #[tokio::test]
    async fn test_stats() {
        let store = PassiveDnsStore::new();

        store.process_query(&create_query("example.com", DnsRecordType::A, "93.184.216.34")).await;
        store.process_query(&create_query("google.com", DnsRecordType::A, "8.8.8.8")).await;

        let stats = store.get_stats().await;
        assert_eq!(stats.total_queries, 2);
        assert_eq!(stats.unique_domains, 2);
    }

    #[tokio::test]
    async fn test_mark_suspicious() {
        let store = PassiveDnsStore::new();

        store.process_query(&create_query("malware.com", DnsRecordType::A, "1.2.3.4")).await;
        store.mark_suspicious("malware.com", DnsThreatType::Malware, 90).await;

        let records = store.get_domain_records("malware.com").await;
        assert!(records[0].is_suspicious);
        assert_eq!(records[0].threat_score, 90);
    }
}
