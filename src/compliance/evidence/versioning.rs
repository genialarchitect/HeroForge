//! Evidence versioning module
//!
//! Provides version control functionality for compliance evidence,
//! including version tracking, history management, and change detection.

#![allow(dead_code)]

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::storage::EvidenceStorage;
use super::types::{Evidence, EvidenceContent, EvidenceStatus};

/// A version entry in the evidence history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceVersion {
    /// Version number (1-based)
    pub version: i32,
    /// Evidence ID for this version
    pub evidence_id: String,
    /// Content hash for this version
    pub content_hash: String,
    /// Content snapshot (may be summarized for large content)
    pub content_summary: Option<String>,
    /// User who created this version
    pub created_by: String,
    /// When this version was created
    pub created_at: DateTime<Utc>,
    /// Change description
    pub change_description: Option<String>,
    /// Size of content in bytes
    pub content_size: i64,
}

/// Change between two versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionChange {
    /// Type of change
    pub change_type: ChangeType,
    /// Field that changed
    pub field: String,
    /// Previous value (may be truncated)
    pub old_value: Option<String>,
    /// New value (may be truncated)
    pub new_value: Option<String>,
}

/// Type of change between versions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    /// Field was added
    Added,
    /// Field was modified
    Modified,
    /// Field was removed
    Removed,
    /// Content was updated
    ContentUpdated,
}

/// Comparison between two evidence versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionComparison {
    /// ID of the base version
    pub base_version_id: String,
    /// ID of the comparison version
    pub compare_version_id: String,
    /// Base version number
    pub base_version: i32,
    /// Compare version number
    pub compare_version: i32,
    /// List of changes
    pub changes: Vec<VersionChange>,
    /// Whether the content hash changed
    pub content_changed: bool,
    /// Summary of changes
    pub summary: String,
}

/// Evidence version control manager
pub struct EvidenceVersioning {
    storage: EvidenceStorage,
}

impl EvidenceVersioning {
    /// Create a new versioning manager
    pub fn new(storage: EvidenceStorage) -> Self {
        Self { storage }
    }

    /// Create a new version of evidence
    pub fn create_new_version(
        &self,
        existing: &Evidence,
        new_content: EvidenceContent,
        change_description: Option<String>,
        user_id: &str,
    ) -> Result<Evidence> {
        let now = Utc::now();

        // Compute hash for new content
        let content_hash = EvidenceStorage::compute_content_hash(&new_content)
            .context("Failed to compute content hash")?;

        // Create new evidence record with incremented version
        let mut new_evidence = Evidence {
            id: uuid::Uuid::new_v4().to_string(),
            evidence_type: existing.evidence_type.clone(),
            control_ids: existing.control_ids.clone(),
            framework_ids: existing.framework_ids.clone(),
            title: existing.title.clone(),
            description: existing.description.clone(),
            content_hash,
            content: new_content,
            collection_source: existing.collection_source.clone(),
            status: EvidenceStatus::Active,
            version: existing.version + 1,
            previous_version_id: Some(existing.id.clone()),
            collected_at: now,
            collected_by: user_id.to_string(),
            expires_at: existing.expires_at,
            retention_policy: existing.retention_policy.clone(),
            metadata: existing.metadata.clone(),
            created_at: now,
            updated_at: now,
        };

        // Add change description to metadata if provided
        if let Some(desc) = change_description {
            new_evidence
                .metadata
                .custom_fields
                .insert("change_description".to_string(), serde_json::json!(desc));
        }

        Ok(new_evidence)
    }

    /// Compare two versions of evidence
    pub fn compare_versions(
        &self,
        base: &Evidence,
        compare: &Evidence,
    ) -> Result<VersionComparison> {
        let mut changes = Vec::new();

        // Check title change
        if base.title != compare.title {
            changes.push(VersionChange {
                change_type: ChangeType::Modified,
                field: "title".to_string(),
                old_value: Some(base.title.clone()),
                new_value: Some(compare.title.clone()),
            });
        }

        // Check description change
        if base.description != compare.description {
            changes.push(VersionChange {
                change_type: if base.description.is_none() {
                    ChangeType::Added
                } else if compare.description.is_none() {
                    ChangeType::Removed
                } else {
                    ChangeType::Modified
                },
                field: "description".to_string(),
                old_value: base.description.clone(),
                new_value: compare.description.clone(),
            });
        }

        // Check control IDs
        let base_controls: std::collections::HashSet<_> = base.control_ids.iter().collect();
        let compare_controls: std::collections::HashSet<_> = compare.control_ids.iter().collect();

        for added in compare_controls.difference(&base_controls) {
            changes.push(VersionChange {
                change_type: ChangeType::Added,
                field: "control_ids".to_string(),
                old_value: None,
                new_value: Some((*added).clone()),
            });
        }

        for removed in base_controls.difference(&compare_controls) {
            changes.push(VersionChange {
                change_type: ChangeType::Removed,
                field: "control_ids".to_string(),
                old_value: Some((*removed).clone()),
                new_value: None,
            });
        }

        // Check content hash
        let content_changed = base.content_hash != compare.content_hash;
        if content_changed {
            changes.push(VersionChange {
                change_type: ChangeType::ContentUpdated,
                field: "content".to_string(),
                old_value: Some(format!("hash: {}", truncate_string(&base.content_hash, 16))),
                new_value: Some(format!("hash: {}", truncate_string(&compare.content_hash, 16))),
            });
        }

        // Check status change
        if base.status != compare.status {
            changes.push(VersionChange {
                change_type: ChangeType::Modified,
                field: "status".to_string(),
                old_value: Some(format!("{:?}", base.status)),
                new_value: Some(format!("{:?}", compare.status)),
            });
        }

        // Generate summary
        let summary = if changes.is_empty() {
            "No changes detected".to_string()
        } else {
            let field_changes: Vec<_> = changes.iter().map(|c| c.field.as_str()).collect();
            format!(
                "{} change(s): {}",
                changes.len(),
                field_changes.join(", ")
            )
        };

        Ok(VersionComparison {
            base_version_id: base.id.clone(),
            compare_version_id: compare.id.clone(),
            base_version: base.version,
            compare_version: compare.version,
            changes,
            content_changed,
            summary,
        })
    }

    /// Create a version entry from evidence
    pub fn create_version_entry(&self, evidence: &Evidence) -> EvidenceVersion {
        let content_summary = match &evidence.content {
            EvidenceContent::Json { data } => {
                serde_json::to_string(data)
                    .ok()
                    .map(|s| truncate_string(&s, 200))
            }
            EvidenceContent::Text { text } => Some(truncate_string(text, 200)),
            EvidenceContent::File { file_path, .. } => Some(format!("File: {}", file_path)),
            EvidenceContent::ExternalUrl { url } => Some(format!("URL: {}", url)),
            EvidenceContent::None => None,
        };

        EvidenceVersion {
            version: evidence.version,
            evidence_id: evidence.id.clone(),
            content_hash: evidence.content_hash.clone(),
            content_summary,
            created_by: evidence.collected_by.clone(),
            created_at: evidence.created_at,
            change_description: evidence
                .metadata
                .custom_fields
                .get("change_description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            content_size: evidence.content.size_bytes(),
        }
    }

    /// Check if content has changed between two pieces of evidence
    pub fn has_content_changed(&self, base: &Evidence, compare: &Evidence) -> bool {
        base.content_hash != compare.content_hash
    }

    /// Generate a rollback to a previous version
    pub fn create_rollback(
        &self,
        current: &Evidence,
        target: &Evidence,
        user_id: &str,
    ) -> Result<Evidence> {
        let now = Utc::now();

        // Create new evidence record based on target, with incremented version
        let mut rollback = Evidence {
            id: uuid::Uuid::new_v4().to_string(),
            evidence_type: target.evidence_type.clone(),
            control_ids: target.control_ids.clone(),
            framework_ids: target.framework_ids.clone(),
            title: target.title.clone(),
            description: target.description.clone(),
            content_hash: target.content_hash.clone(),
            content: target.content.clone(),
            collection_source: target.collection_source.clone(),
            status: EvidenceStatus::Active,
            version: current.version + 1,
            previous_version_id: Some(current.id.clone()),
            collected_at: now,
            collected_by: user_id.to_string(),
            expires_at: target.expires_at,
            retention_policy: target.retention_policy.clone(),
            metadata: target.metadata.clone(),
            created_at: now,
            updated_at: now,
        };

        // Add rollback note to metadata
        rollback.metadata.custom_fields.insert(
            "change_description".to_string(),
            serde_json::json!(format!(
                "Rollback to version {} (evidence {})",
                target.version, target.id
            )),
        );
        rollback.metadata.custom_fields.insert(
            "rollback_from_version".to_string(),
            serde_json::json!(current.version),
        );
        rollback.metadata.custom_fields.insert(
            "rollback_to_version".to_string(),
            serde_json::json!(target.version),
        );

        Ok(rollback)
    }
}

/// Version history for an evidence chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionHistory {
    /// Original evidence ID (first version)
    pub original_id: String,
    /// Current/latest evidence ID
    pub current_id: String,
    /// Total number of versions
    pub total_versions: i32,
    /// List of versions (ordered oldest to newest)
    pub versions: Vec<EvidenceVersion>,
}

impl VersionHistory {
    /// Create a new version history
    pub fn new(original_id: String) -> Self {
        Self {
            original_id: original_id.clone(),
            current_id: original_id,
            total_versions: 0,
            versions: Vec::new(),
        }
    }

    /// Add a version to the history
    pub fn add_version(&mut self, version: EvidenceVersion) {
        self.current_id = version.evidence_id.clone();
        self.versions.push(version);
        self.total_versions = self.versions.len() as i32;
    }

    /// Get the latest version
    pub fn latest(&self) -> Option<&EvidenceVersion> {
        self.versions.last()
    }

    /// Get a specific version by number
    pub fn get_version(&self, version_number: i32) -> Option<&EvidenceVersion> {
        self.versions.iter().find(|v| v.version == version_number)
    }
}

/// Truncate a string with ellipsis
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::evidence::types::CollectionSource;

    fn create_test_evidence(version: i32, content: &str) -> Evidence {
        let now = Utc::now();
        Evidence {
            id: format!("test-{}", version),
            evidence_type: crate::compliance::evidence::types::EvidenceType::ManualUpload {
                file_path: "/test/file.pdf".to_string(),
                original_filename: Some("test.pdf".to_string()),
            },
            control_ids: vec!["AC-1".to_string()],
            framework_ids: vec!["nist_800_53".to_string()],
            title: "Test Evidence".to_string(),
            description: Some(format!("Version {} description", version)),
            content_hash: EvidenceStorage::compute_hash(content.as_bytes()),
            content: EvidenceContent::Text {
                text: content.to_string(),
            },
            collection_source: CollectionSource::ManualUpload,
            status: EvidenceStatus::Active,
            version,
            previous_version_id: if version > 1 {
                Some(format!("test-{}", version - 1))
            } else {
                None
            },
            collected_at: now,
            collected_by: "test-user".to_string(),
            expires_at: None,
            retention_policy: crate::compliance::evidence::types::RetentionPolicy::Indefinite,
            metadata: crate::compliance::evidence::types::EvidenceMetadata::default(),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_compare_versions_no_changes() {
        let storage = EvidenceStorage::new(super::super::storage::StorageConfig::default());
        let versioning = EvidenceVersioning::new(storage);

        let v1 = create_test_evidence(1, "content");
        let v1_copy = v1.clone();

        let comparison = versioning.compare_versions(&v1, &v1_copy).unwrap();
        assert!(!comparison.content_changed);
        assert!(comparison.changes.is_empty());
        assert_eq!(comparison.summary, "No changes detected");
    }

    #[test]
    fn test_compare_versions_content_changed() {
        let storage = EvidenceStorage::new(super::super::storage::StorageConfig::default());
        let versioning = EvidenceVersioning::new(storage);

        let v1 = create_test_evidence(1, "old content");
        let v2 = create_test_evidence(2, "new content");

        let comparison = versioning.compare_versions(&v1, &v2).unwrap();
        assert!(comparison.content_changed);
        assert!(!comparison.changes.is_empty());
    }

    #[test]
    fn test_create_new_version() {
        let storage = EvidenceStorage::new(super::super::storage::StorageConfig::default());
        let versioning = EvidenceVersioning::new(storage);

        let v1 = create_test_evidence(1, "original");
        let new_content = EvidenceContent::Text {
            text: "updated content".to_string(),
        };

        let v2 = versioning
            .create_new_version(&v1, new_content, Some("Updated content".to_string()), "user123")
            .unwrap();

        assert_eq!(v2.version, 2);
        assert_eq!(v2.previous_version_id, Some(v1.id.clone()));
        assert_ne!(v2.content_hash, v1.content_hash);
    }

    #[test]
    fn test_version_history() {
        let mut history = VersionHistory::new("original-id".to_string());
        assert_eq!(history.total_versions, 0);

        let version = EvidenceVersion {
            version: 1,
            evidence_id: "v1".to_string(),
            content_hash: "hash1".to_string(),
            content_summary: Some("Summary 1".to_string()),
            created_by: "user".to_string(),
            created_at: Utc::now(),
            change_description: None,
            content_size: 100,
        };

        history.add_version(version);
        assert_eq!(history.total_versions, 1);
        assert_eq!(history.current_id, "v1");
        assert!(history.latest().is_some());
        assert!(history.get_version(1).is_some());
        assert!(history.get_version(99).is_none());
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("short", 10), "short");
        assert_eq!(truncate_string("this is a long string", 10), "this is...");
        assert_eq!(truncate_string("", 10), "");
    }
}
