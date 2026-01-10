//! Automatic Scan Processing Pipeline
//!
//! This module provides automatic post-scan processing that ensures data flows
//! between all modules and enhances ML analysis with comprehensive scan data.
//!
//! ## Pipeline Steps
//! 1. Extract vulnerabilities from scan results
//! 2. Enrich with CVE data from local cache + NVD API
//! 3. Run threat intel enrichment
//! 4. Execute compliance analysis
//! 5. Feed enhanced features to AI/ML prioritization
//! 6. Publish events to event bus for cross-team workflows

pub mod enrichment;
pub mod extractor;
pub mod ml_feeder;

use anyhow::Result;
use chrono::Utc;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::ai::AIPrioritizationManager;
use crate::compliance::analyzer::ComplianceAnalyzer;
use crate::event_bus::{EventPublisher, SecurityEvent};
use crate::event_bus::types::{ScanEvent, VulnerabilityEvent};
use crate::threat_intel::ThreatIntelManager;
use crate::types::{HostInfo, Severity};

pub use enrichment::*;
pub use extractor::*;

/// Processing result summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingResult {
    pub scan_id: String,
    pub vulns_extracted: usize,
    pub vulns_enriched: usize,
    pub cves_cached: usize,
    pub compliance_findings: usize,
    pub ai_scores_calculated: usize,
    pub events_published: usize,
    pub processing_time_ms: u64,
    pub errors: Vec<String>,
}

/// Scan processing status for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingStatus {
    pub scan_id: String,
    pub extraction_completed: bool,
    pub cve_enrichment_completed: bool,
    pub threat_intel_completed: bool,
    pub compliance_completed: bool,
    pub ai_prioritization_completed: bool,
    pub events_published: bool,
    pub processing_started: Option<String>,
    pub processing_completed: Option<String>,
    pub error_message: Option<String>,
}

/// Scan Processor - orchestrates the post-scan processing pipeline
pub struct ScanProcessor {
    pool: Arc<SqlitePool>,
    threat_intel: Option<Arc<ThreatIntelManager>>,
    ai_manager: Option<Arc<AIPrioritizationManager>>,
    compliance_analyzer: Option<Arc<ComplianceAnalyzer>>,
    event_publisher: Option<Arc<EventPublisher>>,
}

impl ScanProcessor {
    /// Create a new scan processor with all integrations
    pub fn new(
        pool: Arc<SqlitePool>,
        threat_intel: Option<Arc<ThreatIntelManager>>,
        ai_manager: Option<Arc<AIPrioritizationManager>>,
        compliance_analyzer: Option<Arc<ComplianceAnalyzer>>,
        event_publisher: Option<Arc<EventPublisher>>,
    ) -> Self {
        Self {
            pool,
            threat_intel,
            ai_manager,
            compliance_analyzer,
            event_publisher,
        }
    }

    /// Create a minimal processor with just database (for testing)
    pub fn minimal(pool: Arc<SqlitePool>) -> Self {
        Self {
            pool,
            threat_intel: None,
            ai_manager: None,
            compliance_analyzer: None,
            event_publisher: None,
        }
    }

    /// Process a completed scan through the full pipeline
    pub async fn process_completed_scan(&self, scan_id: &str) -> Result<ProcessingResult> {
        let start_time = std::time::Instant::now();
        let mut errors = Vec::new();
        let mut result = ProcessingResult {
            scan_id: scan_id.to_string(),
            vulns_extracted: 0,
            vulns_enriched: 0,
            cves_cached: 0,
            compliance_findings: 0,
            ai_scores_calculated: 0,
            events_published: 0,
            processing_time_ms: 0,
            errors: Vec::new(),
        };

        info!("Starting scan processing pipeline for scan: {}", scan_id);

        // Update processing status
        self.update_status(scan_id, "started", None).await;

        // Step 1: Get scan results
        let scan = match crate::db::get_scan_by_id(&self.pool, scan_id).await {
            Ok(Some(scan)) => scan,
            Ok(None) => {
                let err = format!("Scan not found: {}", scan_id);
                error!("{}", err);
                self.update_status(scan_id, "error", Some(&err)).await;
                return Err(anyhow::anyhow!(err));
            }
            Err(e) => {
                let err = format!("Failed to get scan: {}", e);
                error!("{}", err);
                self.update_status(scan_id, "error", Some(&err)).await;
                return Err(e);
            }
        };

        let hosts: Vec<HostInfo> = scan
            .results
            .as_ref()
            .and_then(|r| serde_json::from_str(r).ok())
            .unwrap_or_default();

        if hosts.is_empty() {
            info!("No hosts found in scan {}, skipping processing", scan_id);
            self.update_status(scan_id, "completed", None).await;
            return Ok(result);
        }

        info!("Processing {} hosts from scan {}", hosts.len(), scan_id);

        // Step 2: Extract vulnerabilities
        match extractor::extract_vulnerabilities(&self.pool, scan_id, &hosts).await {
            Ok(extracted) => {
                result.vulns_extracted = extracted.len();
                info!("Extracted {} vulnerabilities from scan", extracted.len());
                self.mark_step_complete(scan_id, "extraction").await;

                // Step 3: Enrich with CVE data
                match enrichment::enrich_vulnerabilities(&self.pool, &extracted).await {
                    Ok(enriched) => {
                        result.vulns_enriched = enriched.enriched_count;
                        result.cves_cached = enriched.cves_cached;
                        info!(
                            "Enriched {} vulnerabilities, cached {} new CVEs",
                            enriched.enriched_count, enriched.cves_cached
                        );
                        self.mark_step_complete(scan_id, "cve_enrichment").await;
                    }
                    Err(e) => {
                        let err = format!("CVE enrichment failed: {}", e);
                        warn!("{}", err);
                        errors.push(err);
                    }
                }
            }
            Err(e) => {
                let err = format!("Vulnerability extraction failed: {}", e);
                warn!("{}", err);
                errors.push(err);
            }
        }

        // Step 4: Threat intel enrichment
        if let Some(ref threat_intel) = self.threat_intel {
            match self.run_threat_intel_enrichment(threat_intel, scan_id, &hosts).await {
                Ok(count) => {
                    info!("Threat intel enrichment completed with {} indicators", count);
                    self.mark_step_complete(scan_id, "threat_intel").await;
                }
                Err(e) => {
                    let err = format!("Threat intel enrichment failed: {}", e);
                    warn!("{}", err);
                    errors.push(err);
                }
            }
        }

        // Step 5: Compliance analysis
        if let Some(ref compliance) = self.compliance_analyzer {
            match self.run_compliance_analysis(compliance, scan_id, &hosts).await {
                Ok(findings) => {
                    result.compliance_findings = findings;
                    info!("Compliance analysis found {} issues", findings);
                    self.mark_step_complete(scan_id, "compliance").await;
                }
                Err(e) => {
                    let err = format!("Compliance analysis failed: {}", e);
                    warn!("{}", err);
                    errors.push(err);
                }
            }
        }

        // Step 6: AI/ML prioritization with enhanced features
        if let Some(ref ai_manager) = self.ai_manager {
            match ai_manager.prioritize_scan(scan_id).await {
                Ok(ai_result) => {
                    result.ai_scores_calculated = ai_result.scores.len();
                    info!(
                        "AI prioritization calculated {} scores (avg: {:.1})",
                        ai_result.scores.len(),
                        ai_result.summary.average_risk_score
                    );
                    self.mark_step_complete(scan_id, "ai_prioritization").await;
                }
                Err(e) => {
                    let err = format!("AI prioritization failed: {}", e);
                    warn!("{}", err);
                    errors.push(err);
                }
            }
        }

        // Step 7: Publish events to event bus
        if let Some(ref publisher) = self.event_publisher {
            match self.publish_scan_events(publisher, scan_id, &hosts, result.vulns_extracted).await {
                Ok(count) => {
                    result.events_published = count;
                    info!("Published {} events to event bus", count);
                    self.mark_step_complete(scan_id, "events_published").await;
                }
                Err(e) => {
                    let err = format!("Event publishing failed: {}", e);
                    warn!("{}", err);
                    errors.push(err);
                }
            }
        }

        result.errors = errors;
        result.processing_time_ms = start_time.elapsed().as_millis() as u64;

        // Update final status
        if result.errors.is_empty() {
            self.update_status(scan_id, "completed", None).await;
        } else {
            self.update_status(scan_id, "completed_with_errors", Some(&result.errors.join("; "))).await;
        }

        info!(
            "Scan processing complete for {} in {}ms: {} vulns, {} enriched, {} AI scores, {} events",
            scan_id,
            result.processing_time_ms,
            result.vulns_extracted,
            result.vulns_enriched,
            result.ai_scores_calculated,
            result.events_published
        );

        Ok(result)
    }

    /// Run threat intel enrichment for scan hosts
    async fn run_threat_intel_enrichment(
        &self,
        threat_intel: &ThreatIntelManager,
        scan_id: &str,
        hosts: &[HostInfo],
    ) -> Result<usize> {
        let mut indicator_count = 0;

        for host in hosts {
            let ip = host.target.ip.to_string();

            // Look up IP threat intel
            if let Ok(intel) = threat_intel.lookup_ip(&ip).await {
                // Count CVEs and exploits found
                indicator_count += intel.associated_cves.len();
                indicator_count += intel.available_exploits.len();
                if intel.threat_score > 0 {
                    debug!("Found threat intel for IP {}: score={}", ip, intel.threat_score);
                }
            }
        }

        let _ = scan_id; // Silence unused warning
        Ok(indicator_count)
    }

    /// Run compliance analysis against all frameworks
    async fn run_compliance_analysis(
        &self,
        compliance: &ComplianceAnalyzer,
        scan_id: &str,
        hosts: &[HostInfo],
    ) -> Result<usize> {
        // Run automated compliance checks
        let summary = compliance.analyze(hosts, scan_id).await?;
        Ok(summary.total_findings)
    }

    /// Publish scan completion and vulnerability events
    async fn publish_scan_events(
        &self,
        publisher: &EventPublisher,
        scan_id: &str,
        hosts: &[HostInfo],
        vuln_count: usize,
    ) -> Result<usize> {
        let mut event_count = 0;

        // Get user_id from scan
        let user_id = if let Ok(Some(scan)) = crate::db::get_scan_by_id(&self.pool, scan_id).await {
            scan.user_id.clone()
        } else {
            "system".to_string()
        };

        // Collect targets
        let targets: Vec<String> = hosts.iter().map(|h| h.target.ip.to_string()).collect();

        // Publish ScanCompleted event
        let scan_event = SecurityEvent::ScanCompleted(ScanEvent {
            scan_id: scan_id.to_string(),
            user_id: user_id.clone(),
            targets,
            vulnerability_count: vuln_count,
            host_count: hosts.len(),
            timestamp: Utc::now(),
        });

        if let Err(e) = publisher.publish(scan_event).await {
            warn!("Failed to publish ScanCompleted event: {}", e);
        } else {
            event_count += 1;
        }

        // Publish VulnerabilityDiscovered for high/critical vulns
        for host in hosts {
            for vuln in &host.vulnerabilities {
                if vuln.severity >= Severity::High {
                    let vuln_event = SecurityEvent::VulnerabilityDiscovered(VulnerabilityEvent {
                        vulnerability_id: vuln.cve_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                        asset_id: host.target.ip.to_string(),
                        severity: format!("{:?}", vuln.severity),
                        cvss_score: severity_to_cvss(&vuln.severity),
                        cve_id: vuln.cve_id.clone(),
                        description: vuln.title.clone(),
                        timestamp: Utc::now(),
                    });

                    if let Err(e) = publisher.publish(vuln_event).await {
                        debug!("Failed to publish VulnerabilityDiscovered event: {}", e);
                    } else {
                        event_count += 1;
                    }
                }
            }
        }

        Ok(event_count)
    }

    /// Update processing status in database
    async fn update_status(&self, scan_id: &str, status: &str, error: Option<&str>) {
        let now = Utc::now().to_rfc3339();
        let query = match status {
            "started" => {
                sqlx::query(
                    "INSERT OR REPLACE INTO scan_processing_status
                     (scan_id, processing_started, error_message)
                     VALUES (?1, ?2, NULL)"
                )
                .bind(scan_id)
                .bind(&now)
            }
            "completed" => {
                sqlx::query(
                    "UPDATE scan_processing_status
                     SET processing_completed = ?1, error_message = NULL
                     WHERE scan_id = ?2"
                )
                .bind(&now)
                .bind(scan_id)
            }
            "completed_with_errors" | "error" => {
                sqlx::query(
                    "UPDATE scan_processing_status
                     SET processing_completed = ?1, error_message = ?2
                     WHERE scan_id = ?3"
                )
                .bind(&now)
                .bind(error.unwrap_or("Unknown error"))
                .bind(scan_id)
            }
            _ => return,
        };

        if let Err(e) = query.execute(self.pool.as_ref()).await {
            debug!("Failed to update processing status: {}", e);
        }
    }

    /// Mark a processing step as complete
    async fn mark_step_complete(&self, scan_id: &str, step: &str) {
        let column = match step {
            "extraction" => "extraction_completed",
            "cve_enrichment" => "cve_enrichment_completed",
            "threat_intel" => "threat_intel_completed",
            "compliance" => "compliance_completed",
            "ai_prioritization" => "ai_prioritization_completed",
            "events_published" => "events_published",
            _ => return,
        };

        let query = format!(
            "UPDATE scan_processing_status SET {} = 1 WHERE scan_id = ?1",
            column
        );

        if let Err(e) = sqlx::query(&query).bind(scan_id).execute(self.pool.as_ref()).await {
            debug!("Failed to mark step {} complete: {}", step, e);
        }
    }

    /// Get processing status for a scan
    pub async fn get_status(&self, scan_id: &str) -> Result<Option<ProcessingStatus>> {
        let row = sqlx::query_as::<_, (
            String, i32, i32, i32, i32, i32, i32,
            Option<String>, Option<String>, Option<String>
        )>(
            "SELECT scan_id, extraction_completed, cve_enrichment_completed,
                    threat_intel_completed, compliance_completed,
                    ai_prioritization_completed, events_published,
                    processing_started, processing_completed, error_message
             FROM scan_processing_status WHERE scan_id = ?1"
        )
        .bind(scan_id)
        .fetch_optional(self.pool.as_ref())
        .await?;

        Ok(row.map(|r| ProcessingStatus {
            scan_id: r.0,
            extraction_completed: r.1 != 0,
            cve_enrichment_completed: r.2 != 0,
            threat_intel_completed: r.3 != 0,
            compliance_completed: r.4 != 0,
            ai_prioritization_completed: r.5 != 0,
            events_published: r.6 != 0,
            processing_started: r.7,
            processing_completed: r.8,
            error_message: r.9,
        }))
    }
}

/// Convert severity to approximate CVSS score
fn severity_to_cvss(severity: &Severity) -> Option<f64> {
    Some(match severity {
        Severity::Critical => 9.5,
        Severity::High => 7.5,
        Severity::Medium => 5.0,
        Severity::Low => 2.5,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_to_cvss() {
        assert_eq!(severity_to_cvss(&Severity::Critical), Some(9.5));
        assert_eq!(severity_to_cvss(&Severity::High), Some(7.5));
        assert_eq!(severity_to_cvss(&Severity::Medium), Some(5.0));
        assert_eq!(severity_to_cvss(&Severity::Low), Some(2.5));
    }
}
