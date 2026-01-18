//! Evidence Capture Module
//!
//! Provides functionality to capture screenshots and evidence during scans,
//! tied to specific findings for inclusion in reports.

use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::path::PathBuf;

use crate::screenshots::{ScreenshotOptions, ScreenshotService};

/// Evidence type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    Screenshot,
    TerminalOutput,
    RequestResponse,
    FileContent,
    NetworkCapture,
}

impl EvidenceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EvidenceType::Screenshot => "screenshot",
            EvidenceType::TerminalOutput => "terminal_output",
            EvidenceType::RequestResponse => "request_response",
            EvidenceType::FileContent => "file_content",
            EvidenceType::NetworkCapture => "network_capture",
        }
    }
}

impl std::str::FromStr for EvidenceType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "screenshot" => Ok(EvidenceType::Screenshot),
            "terminal_output" => Ok(EvidenceType::TerminalOutput),
            "request_response" => Ok(EvidenceType::RequestResponse),
            "file_content" => Ok(EvidenceType::FileContent),
            "network_capture" => Ok(EvidenceType::NetworkCapture),
            _ => Err(format!("Unknown evidence type: {}", s)),
        }
    }
}

/// Scan evidence record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEvidence {
    pub id: String,
    pub scan_id: String,
    pub finding_id: Option<String>,
    pub evidence_type: EvidenceType,
    pub description: Option<String>,
    pub file_path: String,
    pub file_size: Option<i64>,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub step_number: Option<i32>,
    pub selector: Option<String>,
    pub url: Option<String>,
    pub captured_at: DateTime<Utc>,
}

/// Evidence step for multi-step capture sequences
#[derive(Debug, Clone)]
pub struct EvidenceStep {
    pub url: String,
    pub description: String,
    pub selector: Option<String>,
    pub wait_ms: Option<u64>,
}

/// Evidence capture service for a scan
pub struct EvidenceCapture {
    scan_id: String,
    pool: SqlitePool,
    evidence_dir: PathBuf,
    screenshot_service: Option<ScreenshotService>,
}

impl EvidenceCapture {
    /// Create a new evidence capture instance for a scan
    pub fn new(pool: SqlitePool, scan_id: String, evidence_dir: PathBuf) -> Self {
        // Try to initialize screenshot service
        let screenshot_service = match ScreenshotService::new() {
            Ok(s) => Some(s),
            Err(e) => {
                warn!("Failed to initialize screenshot service for evidence capture: {}", e);
                None
            }
        };

        Self {
            scan_id,
            pool,
            evidence_dir,
            screenshot_service,
        }
    }

    /// Capture screenshot for a specific finding
    pub async fn capture_for_finding(
        &self,
        finding_id: &str,
        url: &str,
        selector: Option<&str>,
        description: &str,
        step_number: Option<u32>,
    ) -> Result<ScanEvidence> {
        let screenshot_service = self.screenshot_service.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Screenshot service not available"))?;

        // Create evidence directory if needed
        let scan_evidence_dir = self.evidence_dir.join(&self.scan_id);
        std::fs::create_dir_all(&scan_evidence_dir)?;

        // Generate unique filename
        let id = uuid::Uuid::new_v4().to_string();
        let filename = format!("{}_{}.png", finding_id, step_number.unwrap_or(0));
        let output_path = scan_evidence_dir.join(&filename);

        let options = ScreenshotOptions {
            url: url.to_string(),
            output_path: output_path.clone(),
            full_page: false,
            timeout: 15000,
            wait: 2000,
            ignore_ssl: true,
            selector: selector.map(|s| s.to_string()),
            ..Default::default()
        };

        let result = screenshot_service.capture(&options).await?;

        if !result.success {
            return Err(anyhow::anyhow!(
                "Screenshot capture failed: {}",
                result.error.unwrap_or_else(|| "Unknown error".to_string())
            ));
        }

        let file_size = std::fs::metadata(&output_path).map(|m| m.len() as i64).ok();
        let now = Utc::now();

        let evidence = ScanEvidence {
            id: id.clone(),
            scan_id: self.scan_id.clone(),
            finding_id: Some(finding_id.to_string()),
            evidence_type: EvidenceType::Screenshot,
            description: Some(description.to_string()),
            file_path: output_path.to_string_lossy().to_string(),
            file_size,
            width: result.width.map(|w| w as i32),
            height: result.height.map(|h| h as i32),
            step_number: step_number.map(|s| s as i32),
            selector: selector.map(|s| s.to_string()),
            url: Some(url.to_string()),
            captured_at: now,
        };

        // Save to database
        self.save_evidence(&evidence).await?;

        info!(
            "Captured evidence for finding {}: {}",
            finding_id, output_path.display()
        );

        Ok(evidence)
    }

    /// Capture multi-step exploitation sequence
    pub async fn capture_sequence(
        &self,
        finding_id: &str,
        steps: Vec<EvidenceStep>,
    ) -> Result<Vec<ScanEvidence>> {
        let mut evidence_list = Vec::new();

        for (i, step) in steps.iter().enumerate() {
            match self
                .capture_for_finding(
                    finding_id,
                    &step.url,
                    step.selector.as_deref(),
                    &step.description,
                    Some(i as u32 + 1),
                )
                .await
            {
                Ok(evidence) => {
                    evidence_list.push(evidence);
                    // Wait between steps if specified
                    if let Some(wait_ms) = step.wait_ms {
                        tokio::time::sleep(tokio::time::Duration::from_millis(wait_ms)).await;
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to capture step {} for finding {}: {}",
                        i + 1,
                        finding_id,
                        e
                    );
                }
            }
        }

        Ok(evidence_list)
    }

    /// Save evidence record to database
    async fn save_evidence(&self, evidence: &ScanEvidence) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO scan_evidence (
                id, scan_id, finding_id, evidence_type, description,
                file_path, file_size, width, height, step_number,
                selector, url, captured_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&evidence.id)
        .bind(&evidence.scan_id)
        .bind(&evidence.finding_id)
        .bind(evidence.evidence_type.as_str())
        .bind(&evidence.description)
        .bind(&evidence.file_path)
        .bind(evidence.file_size)
        .bind(evidence.width)
        .bind(evidence.height)
        .bind(evidence.step_number)
        .bind(&evidence.selector)
        .bind(&evidence.url)
        .bind(evidence.captured_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

/// Get all evidence for a scan
pub async fn get_scan_evidence(pool: &SqlitePool, scan_id: &str) -> Result<Vec<ScanEvidence>> {
    let rows = sqlx::query_as::<_, (
        String, String, Option<String>, String, Option<String>,
        String, Option<i64>, Option<i32>, Option<i32>, Option<i32>,
        Option<String>, Option<String>, String,
    )>(
        r#"
        SELECT id, scan_id, finding_id, evidence_type, description,
               file_path, file_size, width, height, step_number,
               selector, url, captured_at
        FROM scan_evidence
        WHERE scan_id = ?
        ORDER BY captured_at ASC, step_number ASC
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| ScanEvidence {
            id: r.0,
            scan_id: r.1,
            finding_id: r.2,
            evidence_type: r.3.parse().unwrap_or(EvidenceType::Screenshot),
            description: r.4,
            file_path: r.5,
            file_size: r.6,
            width: r.7,
            height: r.8,
            step_number: r.9,
            selector: r.10,
            url: r.11,
            captured_at: DateTime::parse_from_rfc3339(&r.12)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
        .collect())
}

/// Get evidence for a specific finding
pub async fn get_finding_evidence(
    pool: &SqlitePool,
    finding_id: &str,
) -> Result<Vec<ScanEvidence>> {
    let rows = sqlx::query_as::<_, (
        String, String, Option<String>, String, Option<String>,
        String, Option<i64>, Option<i32>, Option<i32>, Option<i32>,
        Option<String>, Option<String>, String,
    )>(
        r#"
        SELECT id, scan_id, finding_id, evidence_type, description,
               file_path, file_size, width, height, step_number,
               selector, url, captured_at
        FROM scan_evidence
        WHERE finding_id = ?
        ORDER BY step_number ASC, captured_at ASC
        "#,
    )
    .bind(finding_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| ScanEvidence {
            id: r.0,
            scan_id: r.1,
            finding_id: r.2,
            evidence_type: r.3.parse().unwrap_or(EvidenceType::Screenshot),
            description: r.4,
            file_path: r.5,
            file_size: r.6,
            width: r.7,
            height: r.8,
            step_number: r.9,
            selector: r.10,
            url: r.11,
            captured_at: DateTime::parse_from_rfc3339(&r.12)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
        .collect())
}

/// Delete evidence for a scan
pub async fn delete_scan_evidence(pool: &SqlitePool, scan_id: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM scan_evidence WHERE scan_id = ?")
        .bind(scan_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_type_parsing() {
        assert_eq!(
            "screenshot".parse::<EvidenceType>().unwrap(),
            EvidenceType::Screenshot
        );
        assert_eq!(
            "terminal_output".parse::<EvidenceType>().unwrap(),
            EvidenceType::TerminalOutput
        );
        assert!("invalid".parse::<EvidenceType>().is_err());
    }

    #[test]
    fn test_evidence_type_as_str() {
        assert_eq!(EvidenceType::Screenshot.as_str(), "screenshot");
        assert_eq!(EvidenceType::RequestResponse.as_str(), "request_response");
    }
}
