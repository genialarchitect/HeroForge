use crate::web::broadcast::{get_all_scans_stats, ScanStats};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;

/// Aggregated statistics across all active scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedScanStats {
    pub total_scans: usize,
    pub running_scans: usize,
    pub completed_scans: usize,
    pub total_messages: u64,
    pub average_elapsed_time: f64,
    pub scans: Vec<ScanStats>,
}

/// Global aggregator state
pub struct ScanAggregator {
    host_counts: Arc<RwLock<HashMap<String, usize>>>,
    port_counts: Arc<RwLock<HashMap<String, usize>>>,
    vuln_counts: Arc<RwLock<HashMap<String, usize>>>,
}

impl ScanAggregator {
    pub fn new() -> Self {
        Self {
            host_counts: Arc::new(RwLock::new(HashMap::new())),
            port_counts: Arc::new(RwLock::new(HashMap::new())),
            vuln_counts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Track a host discovered in a scan
    pub async fn track_host(&self, scan_id: String) {
        let mut counts = self.host_counts.write().await;
        *counts.entry(scan_id).or_insert(0) += 1;
    }

    /// Track a port found in a scan
    pub async fn track_port(&self, scan_id: String) {
        let mut counts = self.port_counts.write().await;
        *counts.entry(scan_id).or_insert(0) += 1;
    }

    /// Track a vulnerability found in a scan
    pub async fn track_vulnerability(&self, scan_id: String) {
        let mut counts = self.vuln_counts.write().await;
        *counts.entry(scan_id).or_insert(0) += 1;
    }

    /// Get aggregated statistics for a specific scan
    pub async fn get_scan_stats(&self, scan_id: &str) -> ScanAggStats {
        let hosts = self.host_counts.read().await;
        let ports = self.port_counts.read().await;
        let vulns = self.vuln_counts.read().await;

        ScanAggStats {
            scan_id: scan_id.to_string(),
            hosts_found: hosts.get(scan_id).copied().unwrap_or(0),
            ports_found: ports.get(scan_id).copied().unwrap_or(0),
            vulnerabilities_found: vulns.get(scan_id).copied().unwrap_or(0),
        }
    }

    /// Get aggregated statistics across all scans
    pub async fn get_all_stats(&self) -> AllScansAggStats {
        let hosts = self.host_counts.read().await;
        let ports = self.port_counts.read().await;
        let vulns = self.vuln_counts.read().await;

        let total_hosts: usize = hosts.values().sum();
        let total_ports: usize = ports.values().sum();
        let total_vulns: usize = vulns.values().sum();

        AllScansAggStats {
            total_hosts_found: total_hosts,
            total_ports_found: total_ports,
            total_vulnerabilities_found: total_vulns,
            active_scan_count: hosts.len(),
        }
    }

    /// Clean up tracking data for a completed scan
    pub async fn cleanup_scan(&self, scan_id: &str) {
        let mut hosts = self.host_counts.write().await;
        let mut ports = self.port_counts.write().await;
        let mut vulns = self.vuln_counts.write().await;

        hosts.remove(scan_id);
        ports.remove(scan_id);
        vulns.remove(scan_id);
    }
}

impl Default for ScanAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for a single scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanAggStats {
    pub scan_id: String,
    pub hosts_found: usize,
    pub ports_found: usize,
    pub vulnerabilities_found: usize,
}

/// Aggregated statistics across all scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllScansAggStats {
    pub total_hosts_found: usize,
    pub total_ports_found: usize,
    pub total_vulnerabilities_found: usize,
    pub active_scan_count: usize,
}

/// Get comprehensive aggregated statistics
pub async fn get_aggregated_stats() -> AggregatedScanStats {
    let scans = get_all_scans_stats().await;

    let total_scans = scans.len();
    let running_scans = scans.iter().filter(|s| !s.is_completed).count();
    let completed_scans = scans.iter().filter(|s| s.is_completed).count();
    let total_messages: u64 = scans.iter().map(|s| s.message_count as u64).sum();
    let average_elapsed_time = if !scans.is_empty() {
        scans.iter().map(|s| s.elapsed_time).sum::<f64>() / scans.len() as f64
    } else {
        0.0
    };

    AggregatedScanStats {
        total_scans,
        running_scans,
        completed_scans,
        total_messages,
        average_elapsed_time,
        scans,
    }
}
