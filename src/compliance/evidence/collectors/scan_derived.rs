//! Scan-derived evidence collector
//!
//! Collects compliance evidence from scan results, vulnerability findings,
//! and other scan-related data sources.

#![allow(dead_code)]

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::compliance::evidence::storage::EvidenceStorage;
use crate::compliance::evidence::types::{
    CollectionSource, Evidence, EvidenceContent, EvidenceMetadata, EvidenceStatus, EvidenceType,
    RetentionPolicy,
};

/// Scan summary for evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEvidenceSummary {
    /// Scan ID
    pub scan_id: String,
    /// Scan name
    pub scan_name: String,
    /// Scan status
    pub status: String,
    /// Number of hosts discovered
    pub hosts_discovered: i32,
    /// Number of open ports found
    pub open_ports: i32,
    /// Number of vulnerabilities found
    pub vulnerability_count: i32,
    /// Critical vulnerabilities
    pub critical_count: i32,
    /// High vulnerabilities
    pub high_count: i32,
    /// Medium vulnerabilities
    pub medium_count: i32,
    /// Low vulnerabilities
    pub low_count: i32,
    /// Scan targets
    pub targets: Vec<String>,
    /// When the scan started
    pub started_at: Option<String>,
    /// When the scan completed
    pub completed_at: Option<String>,
}

/// Vulnerability summary for evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityEvidenceSummary {
    /// Total vulnerabilities
    pub total: i32,
    /// By severity
    pub by_severity: SeverityCounts,
    /// By status
    pub by_status: StatusCounts,
    /// Top CVEs found
    pub top_cves: Vec<CveSummary>,
    /// Affected hosts
    pub affected_hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SeverityCounts {
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub info: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StatusCounts {
    pub open: i32,
    pub in_progress: i32,
    pub resolved: i32,
    pub accepted: i32,
    pub false_positive: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveSummary {
    pub cve_id: String,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub affected_count: i32,
}

/// Collector for scan-derived evidence
pub struct ScanDerivedCollector {
    storage: Arc<EvidenceStorage>,
}

impl ScanDerivedCollector {
    /// Create a new scan-derived collector
    pub fn new(storage: Arc<EvidenceStorage>) -> Self {
        Self { storage }
    }

    /// Collect evidence from a scan result
    pub async fn collect_from_scan(
        &self,
        pool: &SqlitePool,
        scan_id: &str,
        control_ids: &[String],
        user_id: &str,
    ) -> Result<Evidence> {
        // Fetch scan details from database
        let scan_summary = self.fetch_scan_summary(pool, scan_id).await?;

        let now = Utc::now();
        let evidence_id = uuid::Uuid::new_v4().to_string();

        // Create JSON content from scan summary
        let content_data = serde_json::to_value(&scan_summary)
            .context("Failed to serialize scan summary")?;

        let _content_hash = EvidenceStorage::compute_hash(
            &serde_json::to_vec(&content_data).context("Failed to serialize for hash")?,
        );

        // Store as JSON file
        let stored = self
            .storage
            .store_json(&evidence_id, &content_data)
            .await?;

        let evidence = Evidence {
            id: evidence_id,
            evidence_type: EvidenceType::ScanResult {
                scan_id: scan_id.to_string(),
            },
            control_ids: control_ids.to_vec(),
            framework_ids: Vec::new(), // Will be populated based on control mappings
            title: format!("Scan Result: {}", scan_summary.scan_name),
            description: Some(format!(
                "Security scan showing {} hosts discovered, {} open ports, {} vulnerabilities found",
                scan_summary.hosts_discovered,
                scan_summary.open_ports,
                scan_summary.vulnerability_count
            )),
            content_hash: stored.content_hash,
            content: EvidenceContent::Json { data: content_data },
            collection_source: CollectionSource::AutomatedScan,
            status: EvidenceStatus::Active,
            version: 1,
            previous_version_id: None,
            collected_at: now,
            collected_by: user_id.to_string(),
            expires_at: None,
            retention_policy: RetentionPolicy::FrameworkDefault,
            metadata: EvidenceMetadata {
                tags: std::collections::HashMap::from([
                    ("source".to_string(), "scan".to_string()),
                    ("scan_id".to_string(), scan_id.to_string()),
                ]),
                ..Default::default()
            },
            created_at: now,
            updated_at: now,
        };

        Ok(evidence)
    }

    /// Collect vulnerability-specific evidence
    pub async fn collect_vulnerabilities(
        &self,
        pool: &SqlitePool,
        scan_id: &str,
        control_ids: &[String],
        user_id: &str,
    ) -> Result<Evidence> {
        let vuln_summary = self.fetch_vulnerability_summary(pool, scan_id).await?;

        let now = Utc::now();
        let evidence_id = uuid::Uuid::new_v4().to_string();

        let content_data = serde_json::to_value(&vuln_summary)
            .context("Failed to serialize vulnerability summary")?;

        let _content_hash = EvidenceStorage::compute_hash(
            &serde_json::to_vec(&content_data).context("Failed to serialize for hash")?,
        );

        let stored = self
            .storage
            .store_json(&evidence_id, &content_data)
            .await?;

        let evidence = Evidence {
            id: evidence_id,
            evidence_type: EvidenceType::VulnerabilityScan {
                scan_id: scan_id.to_string(),
                finding_count: Some(vuln_summary.total),
            },
            control_ids: control_ids.to_vec(),
            framework_ids: Vec::new(),
            title: format!("Vulnerability Assessment: {} findings", vuln_summary.total),
            description: Some(format!(
                "Vulnerability assessment showing {} critical, {} high, {} medium, {} low findings",
                vuln_summary.by_severity.critical,
                vuln_summary.by_severity.high,
                vuln_summary.by_severity.medium,
                vuln_summary.by_severity.low
            )),
            content_hash: stored.content_hash,
            content: EvidenceContent::Json { data: content_data },
            collection_source: CollectionSource::AutomatedScan,
            status: EvidenceStatus::Active,
            version: 1,
            previous_version_id: None,
            collected_at: now,
            collected_by: user_id.to_string(),
            expires_at: None,
            retention_policy: RetentionPolicy::FrameworkDefault,
            metadata: EvidenceMetadata {
                tags: std::collections::HashMap::from([
                    ("source".to_string(), "vulnerability_scan".to_string()),
                    ("scan_id".to_string(), scan_id.to_string()),
                ]),
                ..Default::default()
            },
            created_at: now,
            updated_at: now,
        };

        Ok(evidence)
    }

    /// Fetch scan summary from database
    async fn fetch_scan_summary(
        &self,
        pool: &SqlitePool,
        scan_id: &str,
    ) -> Result<ScanEvidenceSummary> {
        // Query scan_results table
        let scan_row: Option<ScanRow> = sqlx::query_as(
            r#"
            SELECT id, name, targets, status, started_at, completed_at, results
            FROM scan_results
            WHERE id = ?1
            "#,
        )
        .bind(scan_id)
        .fetch_optional(pool)
        .await
        .context("Failed to query scan results")?;

        let scan = scan_row.context("Scan not found")?;

        // Parse results JSON to extract host/port counts
        let results: Option<serde_json::Value> = scan
            .results
            .as_ref()
            .and_then(|r| serde_json::from_str(r).ok());

        let (hosts_discovered, open_ports) = if let Some(ref results) = results {
            let hosts = results
                .as_array()
                .map(|arr| arr.len() as i32)
                .unwrap_or(0);
            let ports = results
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|h| h.get("ports"))
                        .filter_map(|p| p.as_array())
                        .map(|arr| arr.len() as i32)
                        .sum()
                })
                .unwrap_or(0);
            (hosts, ports)
        } else {
            (0, 0)
        };

        // Query vulnerability counts
        let vuln_counts: VulnCountRow = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
            FROM vulnerability_tracking
            WHERE scan_id = ?1
            "#,
        )
        .bind(scan_id)
        .fetch_one(pool)
        .await
        .unwrap_or_default();

        let targets: Vec<String> = scan
            .targets
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        Ok(ScanEvidenceSummary {
            scan_id: scan.id,
            scan_name: scan.name,
            status: scan.status,
            hosts_discovered,
            open_ports,
            vulnerability_count: vuln_counts.total,
            critical_count: vuln_counts.critical,
            high_count: vuln_counts.high,
            medium_count: vuln_counts.medium,
            low_count: vuln_counts.low,
            targets,
            started_at: scan.started_at,
            completed_at: scan.completed_at,
        })
    }

    /// Fetch vulnerability summary from database
    async fn fetch_vulnerability_summary(
        &self,
        pool: &SqlitePool,
        scan_id: &str,
    ) -> Result<VulnerabilityEvidenceSummary> {
        // Get vulnerability counts by severity
        let severity_counts: VulnCountRow = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
            FROM vulnerability_tracking
            WHERE scan_id = ?1
            "#,
        )
        .bind(scan_id)
        .fetch_one(pool)
        .await
        .unwrap_or_default();

        // Get status counts
        let status_counts: StatusCountRow = sqlx::query_as(
            r#"
            SELECT
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open,
                SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved,
                SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) as accepted,
                SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END) as false_positive
            FROM vulnerability_tracking
            WHERE scan_id = ?1
            "#,
        )
        .bind(scan_id)
        .fetch_one(pool)
        .await
        .unwrap_or_default();

        // Get top CVEs
        let top_cves: Vec<CveRow> = sqlx::query_as(
            r#"
            SELECT cve_ids, severity, cvss_score, COUNT(*) as count
            FROM vulnerability_tracking
            WHERE scan_id = ?1 AND cve_ids IS NOT NULL AND cve_ids != ''
            GROUP BY cve_ids, severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                count DESC
            LIMIT 10
            "#,
        )
        .bind(scan_id)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        // Get affected hosts
        let affected_hosts: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT host_ip
            FROM vulnerability_tracking
            WHERE scan_id = ?1
            "#,
        )
        .bind(scan_id)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        Ok(VulnerabilityEvidenceSummary {
            total: severity_counts.total,
            by_severity: SeverityCounts {
                critical: severity_counts.critical,
                high: severity_counts.high,
                medium: severity_counts.medium,
                low: severity_counts.low,
                info: 0,
            },
            by_status: StatusCounts {
                open: status_counts.open,
                in_progress: status_counts.in_progress,
                resolved: status_counts.resolved,
                accepted: status_counts.accepted,
                false_positive: status_counts.false_positive,
            },
            top_cves: top_cves
                .into_iter()
                .map(|c| CveSummary {
                    cve_id: c.cve_ids.unwrap_or_default(),
                    severity: c.severity,
                    cvss_score: c.cvss_score,
                    affected_count: c.count,
                })
                .collect(),
            affected_hosts: affected_hosts.into_iter().map(|(h,)| h).collect(),
        })
    }

    /// Collect evidence from container scan
    pub async fn collect_container_scan(
        &self,
        pool: &SqlitePool,
        scan_id: &str,
        control_ids: &[String],
        user_id: &str,
    ) -> Result<Evidence> {
        // Query container scan results
        let scan_row: Option<ContainerScanRow> = sqlx::query_as(
            r#"
            SELECT id, name, status, scan_types, created_at, completed_at
            FROM container_scans
            WHERE id = ?1
            "#,
        )
        .bind(scan_id)
        .fetch_optional(pool)
        .await
        .context("Failed to query container scan")?;

        let scan = scan_row.context("Container scan not found")?;

        // Get image count
        let image_count: (i32,) = sqlx::query_as(
            "SELECT COUNT(*) FROM container_images WHERE scan_id = ?1",
        )
        .bind(scan_id)
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

        // Get finding counts
        let finding_counts: VulnCountRow = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
            FROM container_findings
            WHERE scan_id = ?1
            "#,
        )
        .bind(scan_id)
        .fetch_one(pool)
        .await
        .unwrap_or_default();

        let summary = serde_json::json!({
            "scan_id": scan.id,
            "scan_name": scan.name,
            "status": scan.status,
            "scan_types": scan.scan_types,
            "image_count": image_count.0,
            "findings": {
                "total": finding_counts.total,
                "critical": finding_counts.critical,
                "high": finding_counts.high,
                "medium": finding_counts.medium,
                "low": finding_counts.low
            },
            "created_at": scan.created_at,
            "completed_at": scan.completed_at
        });

        let now = Utc::now();
        let evidence_id = uuid::Uuid::new_v4().to_string();

        let _content_hash = EvidenceStorage::compute_hash(
            &serde_json::to_vec(&summary).context("Failed to serialize for hash")?,
        );

        let stored = self.storage.store_json(&evidence_id, &summary).await?;

        Ok(Evidence {
            id: evidence_id,
            evidence_type: EvidenceType::ContainerScan {
                scan_id: scan_id.to_string(),
                image_count: Some(image_count.0),
            },
            control_ids: control_ids.to_vec(),
            framework_ids: Vec::new(),
            title: format!("Container Scan: {}", scan.name),
            description: Some(format!(
                "Container security scan with {} images analyzed, {} findings",
                image_count.0, finding_counts.total
            )),
            content_hash: stored.content_hash,
            content: EvidenceContent::Json { data: summary },
            collection_source: CollectionSource::AutomatedScan,
            status: EvidenceStatus::Active,
            version: 1,
            previous_version_id: None,
            collected_at: now,
            collected_by: user_id.to_string(),
            expires_at: None,
            retention_policy: RetentionPolicy::FrameworkDefault,
            metadata: EvidenceMetadata {
                tags: std::collections::HashMap::from([
                    ("source".to_string(), "container_scan".to_string()),
                    ("scan_id".to_string(), scan_id.to_string()),
                ]),
                ..Default::default()
            },
            created_at: now,
            updated_at: now,
        })
    }
}

// Database row types
#[derive(Debug, sqlx::FromRow)]
struct ScanRow {
    id: String,
    name: String,
    targets: String,
    status: String,
    started_at: Option<String>,
    completed_at: Option<String>,
    results: Option<String>,
}

#[derive(Debug, sqlx::FromRow, Default)]
struct VulnCountRow {
    total: i32,
    critical: i32,
    high: i32,
    medium: i32,
    low: i32,
}

#[derive(Debug, sqlx::FromRow, Default)]
struct StatusCountRow {
    open: i32,
    in_progress: i32,
    resolved: i32,
    accepted: i32,
    false_positive: i32,
}

#[derive(Debug, sqlx::FromRow)]
struct CveRow {
    cve_ids: Option<String>,
    severity: String,
    cvss_score: Option<f64>,
    count: i32,
}

#[derive(Debug, sqlx::FromRow)]
struct ContainerScanRow {
    id: String,
    name: String,
    status: String,
    scan_types: String,
    created_at: String,
    completed_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_evidence_summary_serialization() {
        let summary = ScanEvidenceSummary {
            scan_id: "test-scan".to_string(),
            scan_name: "Test Scan".to_string(),
            status: "completed".to_string(),
            hosts_discovered: 5,
            open_ports: 25,
            vulnerability_count: 10,
            critical_count: 1,
            high_count: 3,
            medium_count: 4,
            low_count: 2,
            targets: vec!["192.168.1.0/24".to_string()],
            started_at: Some("2024-01-01T00:00:00Z".to_string()),
            completed_at: Some("2024-01-01T01:00:00Z".to_string()),
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("test-scan"));
        assert!(json.contains("192.168.1.0/24"));
    }

    #[test]
    fn test_severity_counts_default() {
        let counts = SeverityCounts::default();
        assert_eq!(counts.critical, 0);
        assert_eq!(counts.high, 0);
        assert_eq!(counts.medium, 0);
        assert_eq!(counts.low, 0);
        assert_eq!(counts.info, 0);
    }
}
