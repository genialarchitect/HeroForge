//! Main evidence collector module
//!
//! Orchestrates evidence collection from various sources and manages
//! the collection workflow including scheduling, execution, and storage.

#![allow(dead_code)]

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;

use super::collectors::ScanDerivedCollector;
use super::storage::EvidenceStorage;
use super::types::{
    CollectEvidenceRequest, CollectEvidenceResponse, CollectionSource, Evidence,
    EvidenceCollectionSchedule, EvidenceContent, EvidenceMetadata,
    EvidenceStatus, EvidenceType, RetentionPolicy,
};
use super::versioning::EvidenceVersioning;

/// Result of an evidence collection operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionResult {
    /// Whether the collection was successful
    pub success: bool,
    /// Collected evidence (if successful)
    pub evidence: Option<Evidence>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Collection duration in milliseconds
    pub duration_ms: u64,
    /// Source of the collection
    pub source: CollectionSource,
}

/// Statistics for collection operations
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectionStats {
    /// Total collection attempts
    pub total_attempts: i64,
    /// Successful collections
    pub successful: i64,
    /// Failed collections
    pub failed: i64,
    /// Total evidence items collected
    pub total_evidence: i64,
    /// Average collection time in milliseconds
    pub avg_duration_ms: u64,
    /// Last collection time
    pub last_collection: Option<DateTime<Utc>>,
}

/// Main evidence collector that orchestrates collection from various sources
pub struct EvidenceCollector {
    storage: Arc<EvidenceStorage>,
    versioning: Arc<EvidenceVersioning>,
    scan_collector: ScanDerivedCollector,
    stats: CollectionStats,
}

impl EvidenceCollector {
    /// Create a new evidence collector
    pub fn new(storage: EvidenceStorage) -> Self {
        let storage = Arc::new(storage);
        let versioning = Arc::new(EvidenceVersioning::new(
            EvidenceStorage::new(super::storage::StorageConfig::from_env()),
        ));

        Self {
            storage: Arc::clone(&storage),
            versioning,
            scan_collector: ScanDerivedCollector::new(Arc::clone(&storage)),
            stats: CollectionStats::default(),
        }
    }

    /// Initialize the collector (create storage directories, etc.)
    pub async fn init(&self) -> Result<()> {
        self.storage.init().await
    }

    /// Collect evidence based on a request
    pub async fn collect(
        &mut self,
        pool: &SqlitePool,
        request: &CollectEvidenceRequest,
        user_id: &str,
    ) -> Result<CollectEvidenceResponse> {
        let start = std::time::Instant::now();
        self.stats.total_attempts += 1;

        let result = match request.evidence_type.as_str() {
            "scan_result" => {
                self.collect_scan_evidence(pool, request, user_id).await
            }
            "vulnerability_scan" => {
                self.collect_vulnerability_evidence(pool, request, user_id)
                    .await
            }
            "manual_upload" => self.handle_manual_upload(request, user_id).await,
            "configuration_export" => {
                self.collect_config_export(request, user_id).await
            }
            _ => Err(anyhow::anyhow!(
                "Unsupported evidence type: {}",
                request.evidence_type
            )),
        };

        let duration = start.elapsed().as_millis() as u64;
        self.stats.last_collection = Some(Utc::now());

        match result {
            Ok(evidence) => {
                self.stats.successful += 1;
                self.stats.total_evidence += 1;
                self.update_avg_duration(duration);

                Ok(CollectEvidenceResponse {
                    success: true,
                    evidence_id: Some(evidence.id),
                    message: "Evidence collected successfully".to_string(),
                    job_id: None,
                })
            }
            Err(e) => {
                self.stats.failed += 1;

                Ok(CollectEvidenceResponse {
                    success: false,
                    evidence_id: None,
                    message: format!("Collection failed: {}", e),
                    job_id: None,
                })
            }
        }
    }

    /// Collect evidence from a scan result
    async fn collect_scan_evidence(
        &self,
        pool: &SqlitePool,
        request: &CollectEvidenceRequest,
        user_id: &str,
    ) -> Result<Evidence> {
        let scan_id = request
            .params
            .get("scan_id")
            .and_then(|v| v.as_str())
            .context("scan_id is required for scan_result evidence")?;

        self.scan_collector
            .collect_from_scan(pool, scan_id, &request.control_ids, user_id)
            .await
    }

    /// Collect evidence from vulnerability scan
    async fn collect_vulnerability_evidence(
        &self,
        pool: &SqlitePool,
        request: &CollectEvidenceRequest,
        user_id: &str,
    ) -> Result<Evidence> {
        let scan_id = request
            .params
            .get("scan_id")
            .and_then(|v| v.as_str())
            .context("scan_id is required for vulnerability_scan evidence")?;

        self.scan_collector
            .collect_vulnerabilities(pool, scan_id, &request.control_ids, user_id)
            .await
    }

    /// Handle manual file upload
    async fn handle_manual_upload(
        &self,
        request: &CollectEvidenceRequest,
        user_id: &str,
    ) -> Result<Evidence> {
        let file_data = request
            .params
            .get("file_data")
            .and_then(|v| v.as_str())
            .context("file_data is required for manual_upload")?;

        let filename = request
            .params
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or("upload.bin");

        // Decode base64 file data
        let data = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            file_data,
        )
        .context("Invalid base64 file data")?;

        // Store the file
        let evidence_id = uuid::Uuid::new_v4().to_string();
        let stored = self
            .storage
            .store_file(&evidence_id, filename, &data)
            .await?;

        let now = Utc::now();
        let evidence = Evidence {
            id: evidence_id,
            evidence_type: EvidenceType::ManualUpload {
                file_path: stored.path.clone(),
                original_filename: Some(stored.original_filename),
            },
            control_ids: request.control_ids.clone(),
            framework_ids: request.framework_ids.clone(),
            title: request.title.clone(),
            description: request.description.clone(),
            content_hash: stored.content_hash,
            content: EvidenceContent::File {
                file_path: stored.path,
                mime_type: stored.mime_type,
                size_bytes: stored.size_bytes,
            },
            collection_source: CollectionSource::ManualUpload,
            status: EvidenceStatus::Active,
            version: 1,
            previous_version_id: None,
            collected_at: now,
            collected_by: user_id.to_string(),
            expires_at: None,
            retention_policy: RetentionPolicy::FrameworkDefault,
            metadata: EvidenceMetadata::default(),
            created_at: now,
            updated_at: now,
        };

        Ok(evidence)
    }

    /// Collect configuration export evidence
    async fn collect_config_export(
        &self,
        request: &CollectEvidenceRequest,
        user_id: &str,
    ) -> Result<Evidence> {
        let system_name = request
            .params
            .get("system_name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let config_type = request
            .params
            .get("config_type")
            .and_then(|v| v.as_str())
            .unwrap_or("general");

        let config_data = request
            .params
            .get("config_data")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        let evidence_id = uuid::Uuid::new_v4().to_string();

        // Store as JSON
        let stored = self
            .storage
            .store_json(&evidence_id, &config_data)
            .await?;

        let now = Utc::now();
        let evidence = Evidence {
            id: evidence_id,
            evidence_type: EvidenceType::ConfigurationExport {
                system_name: system_name.to_string(),
                config_type: config_type.to_string(),
            },
            control_ids: request.control_ids.clone(),
            framework_ids: request.framework_ids.clone(),
            title: request.title.clone(),
            description: request.description.clone(),
            content_hash: stored.content_hash,
            content: EvidenceContent::Json { data: config_data },
            collection_source: CollectionSource::ApiIntegration,
            status: EvidenceStatus::Active,
            version: 1,
            previous_version_id: None,
            collected_at: now,
            collected_by: user_id.to_string(),
            expires_at: None,
            retention_policy: RetentionPolicy::FrameworkDefault,
            metadata: EvidenceMetadata::default(),
            created_at: now,
            updated_at: now,
        };

        Ok(evidence)
    }

    /// Create a new version of existing evidence
    pub async fn create_new_version(
        &self,
        existing: &Evidence,
        new_content: EvidenceContent,
        change_description: Option<String>,
        user_id: &str,
    ) -> Result<Evidence> {
        self.versioning
            .create_new_version(existing, new_content, change_description, user_id)
    }

    /// Run a scheduled collection job
    pub async fn run_scheduled_collection(
        &mut self,
        pool: &SqlitePool,
        schedule: &EvidenceCollectionSchedule,
    ) -> Result<Vec<CollectionResult>> {
        let mut results = Vec::new();

        // For each control, collect evidence
        for control_id in &schedule.control_ids {
            let request = CollectEvidenceRequest {
                evidence_type: match schedule.collection_source {
                    CollectionSource::AutomatedScan => "scan_result".to_string(),
                    _ => "configuration_export".to_string(),
                },
                control_ids: vec![control_id.clone()],
                framework_ids: schedule.framework_ids.clone(),
                title: format!("Scheduled collection for {}", control_id),
                description: Some(format!(
                    "Automatically collected by schedule: {}",
                    schedule.name
                )),
                params: schedule.config.clone(),
            };

            let start = std::time::Instant::now();
            let result = self
                .collect(pool, &request, &schedule.user_id)
                .await;

            let duration = start.elapsed().as_millis() as u64;

            match result {
                Ok(response) if response.success => {
                    results.push(CollectionResult {
                        success: true,
                        evidence: None, // Would need to fetch from DB
                        error: None,
                        duration_ms: duration,
                        source: CollectionSource::ScheduledCollection,
                    });
                }
                Ok(response) => {
                    results.push(CollectionResult {
                        success: false,
                        evidence: None,
                        error: Some(response.message),
                        duration_ms: duration,
                        source: CollectionSource::ScheduledCollection,
                    });
                }
                Err(e) => {
                    results.push(CollectionResult {
                        success: false,
                        evidence: None,
                        error: Some(e.to_string()),
                        duration_ms: duration,
                        source: CollectionSource::ScheduledCollection,
                    });
                }
            }
        }

        Ok(results)
    }

    /// Get collection statistics
    pub fn get_stats(&self) -> &CollectionStats {
        &self.stats
    }

    /// Update average duration
    fn update_avg_duration(&mut self, new_duration: u64) {
        let total = self.stats.successful + self.stats.failed;
        if total == 0 {
            self.stats.avg_duration_ms = new_duration;
        } else {
            // Running average
            self.stats.avg_duration_ms = (self.stats.avg_duration_ms * (total as u64 - 1)
                + new_duration)
                / total as u64;
        }
    }

    /// Verify integrity of evidence
    pub async fn verify_integrity(
        &self,
        evidence: &Evidence,
    ) -> Result<super::storage::IntegrityCheckResult> {
        self.storage.verify_integrity(evidence).await
    }

    /// Archive old evidence
    pub async fn archive_evidence(&self, evidence: &mut Evidence) -> Result<()> {
        if let EvidenceContent::File { file_path, .. } = &evidence.content {
            let new_path = self.storage.archive_file(file_path).await?;

            // Update content with new path
            evidence.content = EvidenceContent::File {
                file_path: new_path,
                mime_type: "application/octet-stream".to_string(), // Preserve if needed
                size_bytes: evidence.content.size_bytes(),
            };
            evidence.status = EvidenceStatus::Archived;
            evidence.updated_at = Utc::now();
        }

        Ok(())
    }
}

/// Builder for creating evidence with proper defaults
pub struct EvidenceBuilder {
    evidence: Evidence,
}

impl EvidenceBuilder {
    /// Create a new builder
    pub fn new(evidence_type: EvidenceType, title: String, collected_by: String) -> Self {
        Self {
            evidence: Evidence::new(evidence_type, title, collected_by),
        }
    }

    /// Set the description
    pub fn description(mut self, description: String) -> Self {
        self.evidence.description = Some(description);
        self
    }

    /// Add control IDs
    pub fn control_ids(mut self, ids: Vec<String>) -> Self {
        self.evidence.control_ids = ids;
        self
    }

    /// Add framework IDs
    pub fn framework_ids(mut self, ids: Vec<String>) -> Self {
        self.evidence.framework_ids = ids;
        self
    }

    /// Set the content
    pub fn content(mut self, content: EvidenceContent) -> Self {
        self.evidence.content = content;
        self
    }

    /// Set the content hash
    pub fn content_hash(mut self, hash: String) -> Self {
        self.evidence.content_hash = hash;
        self
    }

    /// Set the collection source
    pub fn collection_source(mut self, source: CollectionSource) -> Self {
        self.evidence.collection_source = source;
        self
    }

    /// Set expiration date
    pub fn expires_at(mut self, expires: DateTime<Utc>) -> Self {
        self.evidence.expires_at = Some(expires);
        self
    }

    /// Set retention policy
    pub fn retention_policy(mut self, policy: RetentionPolicy) -> Self {
        self.evidence.retention_policy = policy;
        self
    }

    /// Set metadata
    pub fn metadata(mut self, metadata: EvidenceMetadata) -> Self {
        self.evidence.metadata = metadata;
        self
    }

    /// Build the evidence
    pub fn build(self) -> Evidence {
        self.evidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_builder() {
        let evidence = EvidenceBuilder::new(
            EvidenceType::ManualUpload {
                file_path: "/test/file.pdf".to_string(),
                original_filename: Some("document.pdf".to_string()),
            },
            "Test Evidence".to_string(),
            "user123".to_string(),
        )
        .description("Test description".to_string())
        .control_ids(vec!["AC-1".to_string(), "AC-2".to_string()])
        .framework_ids(vec!["nist_800_53".to_string()])
        .collection_source(CollectionSource::ManualUpload)
        .build();

        assert_eq!(evidence.title, "Test Evidence");
        assert_eq!(evidence.description, Some("Test description".to_string()));
        assert_eq!(evidence.control_ids.len(), 2);
        assert_eq!(evidence.framework_ids.len(), 1);
        assert_eq!(evidence.version, 1);
    }

    #[test]
    fn test_collection_stats_default() {
        let stats = CollectionStats::default();
        assert_eq!(stats.total_attempts, 0);
        assert_eq!(stats.successful, 0);
        assert_eq!(stats.failed, 0);
    }
}
