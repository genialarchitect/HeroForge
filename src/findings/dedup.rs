// ============================================================================
// Finding Deduplication Engine
// ============================================================================
//
// Provides deduplication capabilities for vulnerability findings across
// multiple scans. This engine tracks unique findings, their occurrence
// history, and provides APIs for querying deduplicated results.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;

use super::fingerprint::{FindingFingerprint, FingerprintGenerator};

/// A deduplicated finding record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicatedFinding {
    /// Unique ID for this deduplicated finding
    pub id: String,
    /// The fingerprint hash
    pub fingerprint_hash: String,
    /// Original vulnerability ID (CVE, etc.)
    pub vulnerability_id: String,
    /// Title/name of the vulnerability
    pub title: Option<String>,
    /// Severity level
    pub severity: String,
    /// First time this finding was seen
    pub first_seen_at: DateTime<Utc>,
    /// Most recent time this finding was seen
    pub last_seen_at: DateTime<Utc>,
    /// Number of times this finding has been observed
    pub occurrence_count: i32,
    /// IDs of scans where this finding was observed
    pub scan_ids: Vec<String>,
    /// Current status (open, resolved, false_positive, etc.)
    pub status: String,
    /// Host where finding was detected
    pub host: String,
    /// Port (if applicable)
    pub port: Option<i32>,
    /// Protocol (if applicable)
    pub protocol: Option<String>,
    /// Service name (if applicable)
    pub service: Option<String>,
}

/// Statistics about deduplicated findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationStats {
    /// Total unique findings
    pub total_unique: i64,
    /// Total occurrences across all scans
    pub total_occurrences: i64,
    /// Deduplication ratio (1 - unique/occurrences)
    pub dedup_ratio: f64,
    /// Findings by severity
    pub by_severity: HashMap<String, i64>,
    /// Findings by status
    pub by_status: HashMap<String, i64>,
    /// New findings in last 24 hours
    pub new_last_24h: i64,
    /// Recurring findings (seen more than once)
    pub recurring_count: i64,
}

/// Request to register a new finding occurrence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterFindingRequest {
    pub scan_id: String,
    pub vulnerability_id: String,
    pub title: Option<String>,
    pub severity: String,
    pub host: String,
    pub port: Option<i32>,
    pub protocol: Option<String>,
    pub service: Option<String>,
    pub context: Option<String>,
    pub description: Option<String>,
    pub solution: Option<String>,
    pub references: Option<Vec<String>>,
}

/// Result of registering a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterFindingResult {
    /// ID of the deduplicated finding
    pub finding_id: String,
    /// The fingerprint hash
    pub fingerprint_hash: String,
    /// Whether this is a new finding (first occurrence)
    pub is_new: bool,
    /// Total occurrence count after this registration
    pub occurrence_count: i32,
    /// First seen timestamp
    pub first_seen_at: DateTime<Utc>,
}

/// The deduplication engine
pub struct DeduplicationEngine {
    fingerprint_gen: FingerprintGenerator,
}

impl DeduplicationEngine {
    /// Create a new deduplication engine
    pub fn new() -> Self {
        Self {
            fingerprint_gen: FingerprintGenerator::new(),
        }
    }

    /// Register a finding occurrence
    ///
    /// This will either create a new deduplicated finding or update an
    /// existing one's occurrence count and timestamps.
    pub async fn register_finding(
        &self,
        pool: &SqlitePool,
        request: &RegisterFindingRequest,
    ) -> Result<RegisterFindingResult> {
        // Generate fingerprint
        let fingerprint = self.fingerprint_gen.generate(
            &request.vulnerability_id,
            &request.host,
            request.port.map(|p| p as u16),
            request.protocol.as_deref(),
            request.service.as_deref(),
            request.context.as_deref(),
        );

        let now = Utc::now();

        // Check if finding already exists
        let existing = sqlx::query_as::<_, (String, String, i32)>(
            r#"
            SELECT id, first_seen_at, occurrence_count
            FROM deduplicated_findings
            WHERE fingerprint_hash = ?
            "#
        )
        .bind(&fingerprint.hash)
        .fetch_optional(pool)
        .await
        .context("Failed to check for existing finding")?;

        match existing {
            Some((id, first_seen_str, count)) => {
                // Update existing finding
                let new_count = count + 1;

                sqlx::query(
                    r#"
                    UPDATE deduplicated_findings
                    SET last_seen_at = ?,
                        occurrence_count = ?,
                        title = COALESCE(?, title),
                        severity = ?,
                        service = COALESCE(?, service)
                    WHERE id = ?
                    "#
                )
                .bind(now.to_rfc3339())
                .bind(new_count)
                .bind(&request.title)
                .bind(&request.severity)
                .bind(&request.service)
                .bind(&id)
                .execute(pool)
                .await
                .context("Failed to update finding")?;

                // Record the occurrence
                self.record_occurrence(pool, &id, &request.scan_id, &now).await?;

                let first_seen = DateTime::parse_from_rfc3339(&first_seen_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now);

                Ok(RegisterFindingResult {
                    finding_id: id,
                    fingerprint_hash: fingerprint.hash,
                    is_new: false,
                    occurrence_count: new_count,
                    first_seen_at: first_seen,
                })
            }
            None => {
                // Create new finding
                let id = uuid::Uuid::new_v4().to_string();

                sqlx::query(
                    r#"
                    INSERT INTO deduplicated_findings (
                        id, fingerprint_hash, vulnerability_id, title, severity,
                        host, port, protocol, service, description, solution,
                        first_seen_at, last_seen_at, occurrence_count, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'open')
                    "#
                )
                .bind(&id)
                .bind(&fingerprint.hash)
                .bind(&request.vulnerability_id)
                .bind(&request.title)
                .bind(&request.severity)
                .bind(&request.host)
                .bind(request.port)
                .bind(&request.protocol)
                .bind(&request.service)
                .bind(&request.description)
                .bind(&request.solution)
                .bind(now.to_rfc3339())
                .bind(now.to_rfc3339())
                .execute(pool)
                .await
                .context("Failed to insert new finding")?;

                // Record the occurrence
                self.record_occurrence(pool, &id, &request.scan_id, &now).await?;

                // Store references if provided
                if let Some(refs) = &request.references {
                    self.store_references(pool, &id, refs).await?;
                }

                Ok(RegisterFindingResult {
                    finding_id: id,
                    fingerprint_hash: fingerprint.hash,
                    is_new: true,
                    occurrence_count: 1,
                    first_seen_at: now,
                })
            }
        }
    }

    /// Record a finding occurrence in a specific scan
    async fn record_occurrence(
        &self,
        pool: &SqlitePool,
        finding_id: &str,
        scan_id: &str,
        seen_at: &DateTime<Utc>,
    ) -> Result<()> {
        let id = uuid::Uuid::new_v4().to_string();

        sqlx::query(
            r#"
            INSERT OR IGNORE INTO finding_occurrences (id, finding_id, scan_id, seen_at)
            VALUES (?, ?, ?, ?)
            "#
        )
        .bind(&id)
        .bind(finding_id)
        .bind(scan_id)
        .bind(seen_at.to_rfc3339())
        .execute(pool)
        .await
        .context("Failed to record occurrence")?;

        Ok(())
    }

    /// Store vulnerability references
    async fn store_references(
        &self,
        pool: &SqlitePool,
        finding_id: &str,
        references: &[String],
    ) -> Result<()> {
        for reference in references {
            let id = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT OR IGNORE INTO finding_references (id, finding_id, reference_url) VALUES (?, ?, ?)"
            )
            .bind(&id)
            .bind(finding_id)
            .bind(reference)
            .execute(pool)
            .await
            .context("Failed to store reference")?;
        }
        Ok(())
    }

    /// Get a deduplicated finding by ID
    pub async fn get_finding(
        &self,
        pool: &SqlitePool,
        finding_id: &str,
    ) -> Result<Option<DeduplicatedFinding>> {
        let row = sqlx::query_as::<_, (
            String, String, String, Option<String>, String,
            String, String, i32, String,
            String, Option<i32>, Option<String>, Option<String>,
        )>(
            r#"
            SELECT
                id, fingerprint_hash, vulnerability_id, title, severity,
                first_seen_at, last_seen_at, occurrence_count, status,
                host, port, protocol, service
            FROM deduplicated_findings
            WHERE id = ?
            "#
        )
        .bind(finding_id)
        .fetch_optional(pool)
        .await
        .context("Failed to fetch finding")?;

        match row {
            Some((
                id, fingerprint_hash, vulnerability_id, title, severity,
                first_seen_str, last_seen_str, occurrence_count, status,
                host, port, protocol, service,
            )) => {
                // Get scan IDs
                let scan_ids = self.get_scan_ids_for_finding(pool, &id).await?;

                let first_seen_at = DateTime::parse_from_rfc3339(&first_seen_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                let last_seen_at = DateTime::parse_from_rfc3339(&last_seen_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                Ok(Some(DeduplicatedFinding {
                    id,
                    fingerprint_hash,
                    vulnerability_id,
                    title,
                    severity,
                    first_seen_at,
                    last_seen_at,
                    occurrence_count,
                    scan_ids,
                    status,
                    host,
                    port,
                    protocol,
                    service,
                }))
            }
            None => Ok(None),
        }
    }

    /// Get scan IDs where a finding was observed
    async fn get_scan_ids_for_finding(
        &self,
        pool: &SqlitePool,
        finding_id: &str,
    ) -> Result<Vec<String>> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT DISTINCT scan_id FROM finding_occurrences WHERE finding_id = ? ORDER BY seen_at DESC"
        )
        .bind(finding_id)
        .fetch_all(pool)
        .await
        .context("Failed to fetch scan IDs")?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// List deduplicated findings with filters
    pub async fn list_findings(
        &self,
        pool: &SqlitePool,
        severity: Option<&str>,
        status: Option<&str>,
        host: Option<&str>,
        min_occurrences: Option<i32>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DeduplicatedFinding>> {
        let mut query = String::from(
            r#"
            SELECT
                id, fingerprint_hash, vulnerability_id, title, severity,
                first_seen_at, last_seen_at, occurrence_count, status,
                host, port, protocol, service
            FROM deduplicated_findings
            WHERE 1=1
            "#
        );

        if severity.is_some() {
            query.push_str(" AND LOWER(severity) = LOWER(?)");
        }
        if status.is_some() {
            query.push_str(" AND LOWER(status) = LOWER(?)");
        }
        if host.is_some() {
            query.push_str(" AND host LIKE ?");
        }
        if min_occurrences.is_some() {
            query.push_str(" AND occurrence_count >= ?");
        }

        query.push_str(" ORDER BY last_seen_at DESC LIMIT ? OFFSET ?");

        let mut q = sqlx::query_as::<_, (
            String, String, String, Option<String>, String,
            String, String, i32, String,
            String, Option<i32>, Option<String>, Option<String>,
        )>(&query);

        if let Some(sev) = severity {
            q = q.bind(sev);
        }
        if let Some(stat) = status {
            q = q.bind(stat);
        }
        if let Some(h) = host {
            q = q.bind(format!("%{}%", h));
        }
        if let Some(min) = min_occurrences {
            q = q.bind(min);
        }

        q = q.bind(limit).bind(offset);

        let rows = q.fetch_all(pool).await.context("Failed to list findings")?;

        let mut findings = Vec::new();
        for (
            id, fingerprint_hash, vulnerability_id, title, severity,
            first_seen_str, last_seen_str, occurrence_count, status,
            host, port, protocol, service,
        ) in rows {
            let scan_ids = self.get_scan_ids_for_finding(pool, &id).await?;

            let first_seen_at = DateTime::parse_from_rfc3339(&first_seen_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let last_seen_at = DateTime::parse_from_rfc3339(&last_seen_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            findings.push(DeduplicatedFinding {
                id,
                fingerprint_hash,
                vulnerability_id,
                title,
                severity,
                first_seen_at,
                last_seen_at,
                occurrence_count,
                scan_ids,
                status,
                host,
                port,
                protocol,
                service,
            });
        }

        Ok(findings)
    }

    /// Get deduplication statistics
    pub async fn get_stats(&self, pool: &SqlitePool) -> Result<DeduplicationStats> {
        // Total unique findings
        let (total_unique,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM deduplicated_findings"
        )
        .fetch_one(pool)
        .await
        .context("Failed to count findings")?;

        // Total occurrences
        let (total_occurrences,): (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(occurrence_count), 0) FROM deduplicated_findings"
        )
        .fetch_one(pool)
        .await
        .context("Failed to sum occurrences")?;

        // By severity
        let severity_rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT LOWER(severity), COUNT(*) FROM deduplicated_findings GROUP BY LOWER(severity)"
        )
        .fetch_all(pool)
        .await
        .context("Failed to count by severity")?;
        let by_severity: HashMap<String, i64> = severity_rows.into_iter().collect();

        // By status
        let status_rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT LOWER(status), COUNT(*) FROM deduplicated_findings GROUP BY LOWER(status)"
        )
        .fetch_all(pool)
        .await
        .context("Failed to count by status")?;
        let by_status: HashMap<String, i64> = status_rows.into_iter().collect();

        // New in last 24 hours
        let cutoff = (Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
        let (new_last_24h,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM deduplicated_findings WHERE first_seen_at > ?"
        )
        .bind(&cutoff)
        .fetch_one(pool)
        .await
        .context("Failed to count new findings")?;

        // Recurring findings (seen more than once)
        let (recurring_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM deduplicated_findings WHERE occurrence_count > 1"
        )
        .fetch_one(pool)
        .await
        .context("Failed to count recurring findings")?;

        let dedup_ratio = if total_occurrences > 0 {
            1.0 - (total_unique as f64 / total_occurrences as f64)
        } else {
            0.0
        };

        Ok(DeduplicationStats {
            total_unique,
            total_occurrences,
            dedup_ratio,
            by_severity,
            by_status,
            new_last_24h,
            recurring_count,
        })
    }

    /// Update finding status
    pub async fn update_status(
        &self,
        pool: &SqlitePool,
        finding_id: &str,
        status: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE deduplicated_findings SET status = ? WHERE id = ?"
        )
        .bind(status)
        .bind(finding_id)
        .execute(pool)
        .await
        .context("Failed to update status")?;

        Ok(())
    }

    /// Merge duplicate findings (when fingerprinting algorithm changes)
    pub async fn merge_findings(
        &self,
        pool: &SqlitePool,
        source_id: &str,
        target_id: &str,
    ) -> Result<()> {
        // Move occurrences from source to target
        sqlx::query(
            "UPDATE finding_occurrences SET finding_id = ? WHERE finding_id = ?"
        )
        .bind(target_id)
        .bind(source_id)
        .execute(pool)
        .await
        .context("Failed to move occurrences")?;

        // Update target's occurrence count
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM finding_occurrences WHERE finding_id = ?"
        )
        .bind(target_id)
        .fetch_one(pool)
        .await?;

        sqlx::query(
            "UPDATE deduplicated_findings SET occurrence_count = ? WHERE id = ?"
        )
        .bind(count as i32)
        .bind(target_id)
        .execute(pool)
        .await?;

        // Delete source finding
        sqlx::query("DELETE FROM deduplicated_findings WHERE id = ?")
            .bind(source_id)
            .execute(pool)
            .await?;

        Ok(())
    }

    /// Find findings by fingerprint hash
    pub async fn find_by_fingerprint(
        &self,
        pool: &SqlitePool,
        fingerprint_hash: &str,
    ) -> Result<Option<DeduplicatedFinding>> {
        let row = sqlx::query_as::<_, (String,)>(
            "SELECT id FROM deduplicated_findings WHERE fingerprint_hash = ?"
        )
        .bind(fingerprint_hash)
        .fetch_optional(pool)
        .await?;

        match row {
            Some((id,)) => self.get_finding(pool, &id).await,
            None => Ok(None),
        }
    }

    /// Get findings that appeared in a specific scan
    pub async fn get_findings_for_scan(
        &self,
        pool: &SqlitePool,
        scan_id: &str,
    ) -> Result<Vec<DeduplicatedFinding>> {
        let rows = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT DISTINCT f.id
            FROM deduplicated_findings f
            JOIN finding_occurrences o ON f.id = o.finding_id
            WHERE o.scan_id = ?
            ORDER BY f.severity DESC, f.last_seen_at DESC
            "#
        )
        .bind(scan_id)
        .fetch_all(pool)
        .await?;

        let mut findings = Vec::new();
        for (id,) in rows {
            if let Some(finding) = self.get_finding(pool, &id).await? {
                findings.push(finding);
            }
        }

        Ok(findings)
    }
}

impl Default for DeduplicationEngine {
    fn default() -> Self {
        Self::new()
    }
}
