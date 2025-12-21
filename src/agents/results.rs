//! Result aggregation for agent-based scanning
//!
//! This module handles:
//! - Collecting results from agents
//! - Aggregating results from multiple agents
//! - Merging results into scan results

use anyhow::{anyhow, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use super::types::AgentResult;
use crate::db;
use crate::types::HostInfo;

// ============================================================================
// Result Collection
// ============================================================================

/// Collects and aggregates results from agents
pub struct ResultCollector {
    pool: SqlitePool,
}

impl ResultCollector {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Store a result from an agent
    pub async fn store_result(
        &self,
        task_id: &str,
        agent_id: &str,
        result_data: &serde_json::Value,
        hosts_discovered: i32,
        ports_found: i32,
        vulnerabilities_found: i32,
    ) -> Result<AgentResult> {
        let result = db::agents::create_agent_result(
            &self.pool,
            task_id,
            agent_id,
            &serde_json::to_string(result_data)?,
            hosts_discovered,
            ports_found,
            vulnerabilities_found,
        )
        .await?;

        Ok(result)
    }

    /// Get all results for a task
    pub async fn get_task_results(&self, task_id: &str) -> Result<Vec<AgentResult>> {
        let results = db::agents::get_results_for_task(&self.pool, task_id).await?;
        Ok(results)
    }

    /// Get all results for a scan (from all tasks)
    pub async fn get_scan_results(&self, scan_id: &str) -> Result<Vec<AgentResult>> {
        let results = db::agents::get_results_for_scan(&self.pool, scan_id).await?;
        Ok(results)
    }

    /// Aggregate results from multiple agents into a single scan result
    pub async fn aggregate_scan_results(&self, scan_id: &str) -> Result<AggregatedResults> {
        let results = self.get_scan_results(scan_id).await?;

        let mut aggregated = AggregatedResults::default();

        for result in results {
            // Parse result data
            let hosts: Vec<HostInfo> = match serde_json::from_str(&result.result_data) {
                Ok(hosts) => hosts,
                Err(e) => {
                    log::warn!("Failed to parse result data for task {}: {}", result.task_id, e);
                    continue;
                }
            };

            // Merge hosts into aggregated results
            for host in hosts {
                aggregated.merge_host(host);
            }

            aggregated.tasks_completed += 1;
            aggregated.total_hosts_discovered += result.hosts_discovered;
            aggregated.total_ports_found += result.ports_found;
            aggregated.total_vulnerabilities_found += result.vulnerabilities_found;
        }

        Ok(aggregated)
    }

    /// Check if all tasks for a scan are complete and aggregate results
    pub async fn finalize_scan_results(&self, scan_id: &str) -> Result<Option<String>> {
        // Get task status
        let task_status = super::tasks::get_scan_task_status(&self.pool, scan_id).await?;

        if !task_status.is_complete() {
            return Ok(None);
        }

        // Aggregate all results
        let aggregated = self.aggregate_scan_results(scan_id).await?;

        // Convert to JSON for storage
        let results_json = serde_json::to_string(&aggregated.hosts)?;

        // Update scan with aggregated results
        db::update_scan_status(
            &self.pool,
            scan_id,
            if task_status.has_failures() { "completed_with_errors" } else { "completed" },
            Some(&results_json),
            None,
        )
        .await?;

        Ok(Some(results_json))
    }
}

// ============================================================================
// Aggregated Results
// ============================================================================

/// Aggregated results from all agents for a scan
#[derive(Debug, Default)]
pub struct AggregatedResults {
    /// All discovered hosts
    pub hosts: Vec<HostInfo>,
    /// Number of tasks that contributed results
    pub tasks_completed: i32,
    /// Total hosts across all tasks
    pub total_hosts_discovered: i32,
    /// Total ports across all tasks
    pub total_ports_found: i32,
    /// Total vulnerabilities across all tasks
    pub total_vulnerabilities_found: i32,
}

impl AggregatedResults {
    /// Merge a host into the aggregated results
    pub fn merge_host(&mut self, host: HostInfo) {
        // Check if host already exists (by IP)
        let existing = self.hosts.iter_mut().find(|h| h.target.ip == host.target.ip);

        if let Some(existing_host) = existing {
            // Merge ports - add any new ports
            for port in host.ports {
                if !existing_host.ports.iter().any(|p| p.port == port.port && p.protocol == port.protocol) {
                    existing_host.ports.push(port);
                }
            }

            // Merge vulnerabilities - add any new ones
            for vuln in host.vulnerabilities {
                if !existing_host.vulnerabilities.iter().any(|v| v.cve_id == vuln.cve_id && v.title == vuln.title) {
                    existing_host.vulnerabilities.push(vuln);
                }
            }

            // Update OS guess if new one has higher confidence
            if let Some(new_os) = &host.os_guess {
                if let Some(existing_os) = &existing_host.os_guess {
                    if new_os.confidence > existing_os.confidence {
                        existing_host.os_guess = Some(new_os.clone());
                    }
                } else {
                    existing_host.os_guess = Some(new_os.clone());
                }
            }

            // Update hostname if not already set
            if existing_host.target.hostname.is_none() && host.target.hostname.is_some() {
                existing_host.target.hostname = host.target.hostname;
            }
        } else {
            // Add new host
            self.hosts.push(host);
        }
    }

    /// Get summary statistics
    pub fn summary(&self) -> ResultSummary {
        let mut summary = ResultSummary::default();

        summary.total_hosts = self.hosts.len() as i32;
        summary.live_hosts = self.hosts.iter().filter(|h| h.is_alive).count() as i32;

        for host in &self.hosts {
            summary.total_ports += host.ports.len() as i32;
            summary.open_ports += host.ports.iter().filter(|p| p.state == crate::types::PortState::Open).count() as i32;
            summary.total_vulnerabilities += host.vulnerabilities.len() as i32;

            for vuln in &host.vulnerabilities {
                match vuln.severity {
                    crate::types::Severity::Critical => summary.critical_vulnerabilities += 1,
                    crate::types::Severity::High => summary.high_vulnerabilities += 1,
                    crate::types::Severity::Medium => summary.medium_vulnerabilities += 1,
                    crate::types::Severity::Low => summary.low_vulnerabilities += 1,
                }
            }
        }

        summary
    }
}

/// Summary of aggregated results
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ResultSummary {
    pub total_hosts: i32,
    pub live_hosts: i32,
    pub total_ports: i32,
    pub open_ports: i32,
    pub total_vulnerabilities: i32,
    pub critical_vulnerabilities: i32,
    pub high_vulnerabilities: i32,
    pub medium_vulnerabilities: i32,
    pub low_vulnerabilities: i32,
}

// ============================================================================
// Real-time Updates
// ============================================================================

/// Represents a real-time update from an agent
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentUpdate {
    /// Host discovered during scan
    HostDiscovered {
        task_id: String,
        agent_id: String,
        host_ip: String,
        hostname: Option<String>,
    },
    /// Port found during scan
    PortDiscovered {
        task_id: String,
        agent_id: String,
        host_ip: String,
        port: u16,
        protocol: String,
        service: Option<String>,
    },
    /// Vulnerability found
    VulnerabilityFound {
        task_id: String,
        agent_id: String,
        host_ip: String,
        cve_id: Option<String>,
        title: String,
        severity: String,
    },
    /// Task progress update
    Progress {
        task_id: String,
        agent_id: String,
        progress_percent: f32,
        phase: String,
        message: Option<String>,
    },
    /// Task completed
    TaskComplete {
        task_id: String,
        agent_id: String,
        success: bool,
        error_message: Option<String>,
    },
}

impl AgentUpdate {
    /// Get the task ID for this update
    pub fn task_id(&self) -> &str {
        match self {
            Self::HostDiscovered { task_id, .. } => task_id,
            Self::PortDiscovered { task_id, .. } => task_id,
            Self::VulnerabilityFound { task_id, .. } => task_id,
            Self::Progress { task_id, .. } => task_id,
            Self::TaskComplete { task_id, .. } => task_id,
        }
    }

    /// Get the agent ID for this update
    pub fn agent_id(&self) -> &str {
        match self {
            Self::HostDiscovered { agent_id, .. } => agent_id,
            Self::PortDiscovered { agent_id, .. } => agent_id,
            Self::VulnerabilityFound { agent_id, .. } => agent_id,
            Self::Progress { agent_id, .. } => agent_id,
            Self::TaskComplete { agent_id, .. } => agent_id,
        }
    }
}
