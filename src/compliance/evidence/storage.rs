//! Evidence storage module
//!
//! Provides file and database storage operations for compliance evidence.
//! Handles content hashing, file storage, and retrieval.

#![allow(dead_code)]

use anyhow::{Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;

use super::types::{Evidence, EvidenceContent};

/// Configuration for evidence storage
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Base directory for storing evidence files
    pub base_dir: PathBuf,
    /// Maximum file size in bytes (default: 100MB)
    pub max_file_size: u64,
    /// Allowed file extensions
    pub allowed_extensions: Vec<String>,
    /// Whether to compute content hashes
    pub compute_hashes: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            base_dir: PathBuf::from("./evidence"),
            max_file_size: 100 * 1024 * 1024, // 100MB
            allowed_extensions: vec![
                "pdf".to_string(),
                "doc".to_string(),
                "docx".to_string(),
                "xls".to_string(),
                "xlsx".to_string(),
                "csv".to_string(),
                "txt".to_string(),
                "json".to_string(),
                "xml".to_string(),
                "png".to_string(),
                "jpg".to_string(),
                "jpeg".to_string(),
                "gif".to_string(),
                "zip".to_string(),
                "log".to_string(),
            ],
            compute_hashes: true,
        }
    }
}

impl StorageConfig {
    /// Create config from environment variables
    pub fn from_env() -> Self {
        let base_dir = std::env::var("EVIDENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./evidence"));

        let max_file_size = std::env::var("EVIDENCE_MAX_FILE_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100 * 1024 * 1024);

        Self {
            base_dir,
            max_file_size,
            ..Default::default()
        }
    }
}

/// Evidence storage handler
pub struct EvidenceStorage {
    config: StorageConfig,
}

impl EvidenceStorage {
    /// Create a new evidence storage handler
    pub fn new(config: StorageConfig) -> Self {
        Self { config }
    }

    /// Create storage with default configuration from environment
    pub fn from_env() -> Self {
        Self::new(StorageConfig::from_env())
    }

    /// Initialize storage directory
    pub async fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.config.base_dir)
            .await
            .context("Failed to create evidence storage directory")?;

        // Create subdirectories for organization
        for subdir in &["scans", "uploads", "exports", "archived"] {
            fs::create_dir_all(self.config.base_dir.join(subdir))
                .await
                .context(format!("Failed to create {} subdirectory", subdir))?;
        }

        Ok(())
    }

    /// Compute SHA-256 hash of content
    pub fn compute_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Compute hash from file
    pub async fn compute_file_hash(path: &Path) -> Result<String> {
        let data = fs::read(path)
            .await
            .context("Failed to read file for hashing")?;
        Ok(Self::compute_hash(&data))
    }

    /// Compute hash for evidence content
    pub fn compute_content_hash(content: &EvidenceContent) -> Result<String> {
        let data = match content {
            EvidenceContent::Json { data } => {
                serde_json::to_vec(data).context("Failed to serialize JSON")?
            }
            EvidenceContent::Text { text } => text.as_bytes().to_vec(),
            EvidenceContent::File { file_path, .. } => {
                // For file content, we'll use the path as a placeholder
                // Actual hash should be computed from file contents
                file_path.as_bytes().to_vec()
            }
            EvidenceContent::ExternalUrl { url } => url.as_bytes().to_vec(),
            EvidenceContent::None => Vec::new(),
        };
        Ok(Self::compute_hash(&data))
    }

    /// Store binary data as a file
    pub async fn store_file(
        &self,
        evidence_id: &str,
        filename: &str,
        data: &[u8],
    ) -> Result<StoredFile> {
        // Validate file size
        if data.len() as u64 > self.config.max_file_size {
            anyhow::bail!(
                "File size {} exceeds maximum allowed size {}",
                data.len(),
                self.config.max_file_size
            );
        }

        // Validate and sanitize filename
        let sanitized_filename = sanitize_filename(filename);
        let extension = Path::new(&sanitized_filename)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();

        if !self.config.allowed_extensions.is_empty()
            && !self.config.allowed_extensions.contains(&extension)
        {
            anyhow::bail!(
                "File extension '{}' is not allowed. Allowed: {:?}",
                extension,
                self.config.allowed_extensions
            );
        }

        // Compute hash
        let content_hash = if self.config.compute_hashes {
            Self::compute_hash(data)
        } else {
            String::new()
        };

        // Create storage path
        let storage_filename = format!("{}_{}", evidence_id, sanitized_filename);
        let storage_path = self.config.base_dir.join("uploads").join(&storage_filename);

        // Write file
        let mut file = fs::File::create(&storage_path)
            .await
            .context("Failed to create file")?;
        file.write_all(data)
            .await
            .context("Failed to write file data")?;
        file.sync_all().await.context("Failed to sync file")?;

        Ok(StoredFile {
            path: storage_path.to_string_lossy().to_string(),
            original_filename: filename.to_string(),
            size_bytes: data.len() as i64,
            content_hash,
            mime_type: guess_mime_type(&extension),
        })
    }

    /// Store JSON content
    pub async fn store_json(
        &self,
        evidence_id: &str,
        data: &serde_json::Value,
    ) -> Result<StoredFile> {
        let json_bytes =
            serde_json::to_vec_pretty(data).context("Failed to serialize JSON")?;

        let filename = format!("{}.json", evidence_id);
        let content_hash = Self::compute_hash(&json_bytes);

        let storage_path = self.config.base_dir.join("exports").join(&filename);

        fs::write(&storage_path, &json_bytes)
            .await
            .context("Failed to write JSON file")?;

        Ok(StoredFile {
            path: storage_path.to_string_lossy().to_string(),
            original_filename: filename,
            size_bytes: json_bytes.len() as i64,
            content_hash,
            mime_type: "application/json".to_string(),
        })
    }

    /// Read file content
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        // Security: ensure path is within storage directory
        let full_path = PathBuf::from(path);
        let canonical_base = self
            .config
            .base_dir
            .canonicalize()
            .context("Failed to canonicalize base directory")?;

        if let Ok(canonical_path) = full_path.canonicalize() {
            if !canonical_path.starts_with(&canonical_base) {
                anyhow::bail!("Access denied: path is outside storage directory");
            }
        }

        fs::read(&full_path)
            .await
            .context("Failed to read file")
    }

    /// Delete a stored file
    pub async fn delete_file(&self, path: &str) -> Result<()> {
        let full_path = PathBuf::from(path);

        // Security check
        let canonical_base = self
            .config
            .base_dir
            .canonicalize()
            .context("Failed to canonicalize base directory")?;

        if let Ok(canonical_path) = full_path.canonicalize() {
            if !canonical_path.starts_with(&canonical_base) {
                anyhow::bail!("Access denied: path is outside storage directory");
            }
        }

        if full_path.exists() {
            fs::remove_file(&full_path)
                .await
                .context("Failed to delete file")?;
        }

        Ok(())
    }

    /// Move evidence file to archive
    pub async fn archive_file(&self, path: &str) -> Result<String> {
        let full_path = PathBuf::from(path);

        if !full_path.exists() {
            anyhow::bail!("File not found: {}", path);
        }

        let filename = full_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let archive_path = self
            .config
            .base_dir
            .join("archived")
            .join(format!("{}_{}", Utc::now().format("%Y%m%d_%H%M%S"), filename));

        fs::rename(&full_path, &archive_path)
            .await
            .context("Failed to archive file")?;

        Ok(archive_path.to_string_lossy().to_string())
    }

    /// Get storage statistics
    pub async fn get_stats(&self) -> Result<StorageStats> {
        let mut total_files = 0u64;
        let mut total_size = 0u64;

        for subdir in &["scans", "uploads", "exports"] {
            let dir_path = self.config.base_dir.join(subdir);
            if dir_path.exists() {
                let mut entries = fs::read_dir(&dir_path).await?;
                while let Some(entry) = entries.next_entry().await? {
                    if let Ok(metadata) = entry.metadata().await {
                        if metadata.is_file() {
                            total_files += 1;
                            total_size += metadata.len();
                        }
                    }
                }
            }
        }

        Ok(StorageStats {
            total_files,
            total_size_bytes: total_size,
            base_directory: self.config.base_dir.to_string_lossy().to_string(),
            max_file_size: self.config.max_file_size,
        })
    }

    /// Verify integrity of stored evidence
    pub async fn verify_integrity(&self, evidence: &Evidence) -> Result<IntegrityCheckResult> {
        match &evidence.content {
            EvidenceContent::File { file_path, .. } => {
                let path = PathBuf::from(file_path);
                if !path.exists() {
                    return Ok(IntegrityCheckResult {
                        valid: false,
                        message: "File not found".to_string(),
                        computed_hash: None,
                        expected_hash: Some(evidence.content_hash.clone()),
                    });
                }

                let computed_hash = Self::compute_file_hash(&path).await?;
                let valid = computed_hash == evidence.content_hash;

                Ok(IntegrityCheckResult {
                    valid,
                    message: if valid {
                        "Integrity verified".to_string()
                    } else {
                        "Hash mismatch - content may have been modified".to_string()
                    },
                    computed_hash: Some(computed_hash),
                    expected_hash: Some(evidence.content_hash.clone()),
                })
            }
            EvidenceContent::Json { data } => {
                let computed_hash = Self::compute_hash(
                    &serde_json::to_vec(data).context("Failed to serialize JSON")?,
                );
                let valid = computed_hash == evidence.content_hash;

                Ok(IntegrityCheckResult {
                    valid,
                    message: if valid {
                        "Integrity verified".to_string()
                    } else {
                        "Hash mismatch - content may have been modified".to_string()
                    },
                    computed_hash: Some(computed_hash),
                    expected_hash: Some(evidence.content_hash.clone()),
                })
            }
            EvidenceContent::Text { text } => {
                let computed_hash = Self::compute_hash(text.as_bytes());
                let valid = computed_hash == evidence.content_hash;

                Ok(IntegrityCheckResult {
                    valid,
                    message: if valid {
                        "Integrity verified".to_string()
                    } else {
                        "Hash mismatch - content may have been modified".to_string()
                    },
                    computed_hash: Some(computed_hash),
                    expected_hash: Some(evidence.content_hash.clone()),
                })
            }
            _ => Ok(IntegrityCheckResult {
                valid: true,
                message: "No content to verify".to_string(),
                computed_hash: None,
                expected_hash: None,
            }),
        }
    }
}

/// Information about a stored file
#[derive(Debug, Clone)]
pub struct StoredFile {
    /// Path where the file is stored
    pub path: String,
    /// Original filename
    pub original_filename: String,
    /// File size in bytes
    pub size_bytes: i64,
    /// SHA-256 hash of content
    pub content_hash: String,
    /// MIME type
    pub mime_type: String,
}

/// Storage statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageStats {
    /// Total number of stored files
    pub total_files: u64,
    /// Total size in bytes
    pub total_size_bytes: u64,
    /// Base storage directory
    pub base_directory: String,
    /// Maximum allowed file size
    pub max_file_size: u64,
}

/// Result of integrity verification
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegrityCheckResult {
    /// Whether the integrity check passed
    pub valid: bool,
    /// Message describing the result
    pub message: String,
    /// Computed hash (if applicable)
    pub computed_hash: Option<String>,
    /// Expected hash from evidence record
    pub expected_hash: Option<String>,
}

/// Sanitize a filename for safe storage
fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Guess MIME type from file extension
fn guess_mime_type(extension: &str) -> String {
    match extension.to_lowercase().as_str() {
        "pdf" => "application/pdf",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "csv" => "text/csv",
        "txt" => "text/plain",
        "json" => "application/json",
        "xml" => "application/xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "zip" => "application/zip",
        "log" => "text/plain",
        _ => "application/octet-stream",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hash() {
        let hash = EvidenceStorage::compute_hash(b"Hello, World!");
        assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex characters
        assert_eq!(
            hash,
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        );
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("test.pdf"), "test.pdf");
        assert_eq!(sanitize_filename("test file.pdf"), "test_file.pdf");
        assert_eq!(sanitize_filename("../../../etc/passwd"), ".._.._.._etc_passwd");
        assert_eq!(sanitize_filename("test<script>.txt"), "test_script_.txt");
    }

    #[test]
    fn test_guess_mime_type() {
        assert_eq!(guess_mime_type("pdf"), "application/pdf");
        assert_eq!(guess_mime_type("JSON"), "application/json");
        assert_eq!(guess_mime_type("unknown"), "application/octet-stream");
    }

    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();
        assert_eq!(config.max_file_size, 100 * 1024 * 1024);
        assert!(config.compute_hashes);
        assert!(config.allowed_extensions.contains(&"pdf".to_string()));
    }
}
