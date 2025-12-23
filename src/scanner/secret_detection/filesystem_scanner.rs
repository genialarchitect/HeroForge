//! Filesystem scanner for secret detection
//!
//! Scans directories and files for secrets, supporting:
//! - Recursive directory traversal
//! - File pattern filtering
//! - Size limits
//! - Concurrent scanning

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;
use walkdir::WalkDir;

use super::entropy::{EntropyConfig, find_high_entropy_strings};
use super::types::{SecretFinding, SecretSeverity, SecretSource, SecretType};
use super::{detect_secrets, SecretDetectionConfig};

/// Configuration for filesystem scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemScanConfig {
    /// Paths to scan
    pub paths: Vec<PathBuf>,
    /// Scan directories recursively
    pub recursive: bool,
    /// Maximum directory depth (0 = unlimited)
    pub max_depth: usize,
    /// File patterns to include (glob patterns)
    pub include_patterns: Vec<String>,
    /// File patterns to exclude (glob patterns)
    pub exclude_patterns: Vec<String>,
    /// Maximum file size to scan (bytes)
    pub max_file_size: u64,
    /// Enable entropy-based detection
    pub entropy_detection: bool,
    /// Maximum concurrent file scans
    pub max_concurrent: usize,
    /// Follow symbolic links
    pub follow_symlinks: bool,
    /// Secret detection config
    #[serde(skip)]
    pub secret_config: SecretDetectionConfig,
    /// Entropy detection config
    #[serde(skip)]
    pub entropy_config: EntropyConfig,
}

impl Default for FilesystemScanConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            recursive: true,
            max_depth: 0,
            include_patterns: vec!["*".to_string()],
            exclude_patterns: vec![
                // Binary and media files
                "*.png".to_string(),
                "*.jpg".to_string(),
                "*.jpeg".to_string(),
                "*.gif".to_string(),
                "*.ico".to_string(),
                "*.svg".to_string(),
                "*.woff".to_string(),
                "*.woff2".to_string(),
                "*.ttf".to_string(),
                "*.eot".to_string(),
                "*.pdf".to_string(),
                "*.zip".to_string(),
                "*.tar".to_string(),
                "*.gz".to_string(),
                "*.exe".to_string(),
                "*.dll".to_string(),
                "*.so".to_string(),
                "*.dylib".to_string(),
                "*.o".to_string(),
                "*.a".to_string(),
                "*.pyc".to_string(),
                "*.class".to_string(),
                // Common directories to skip
                ".git/*".to_string(),
                ".svn/*".to_string(),
                "node_modules/*".to_string(),
                "vendor/*".to_string(),
                "__pycache__/*".to_string(),
                "target/*".to_string(),
                "dist/*".to_string(),
                "build/*".to_string(),
            ],
            max_file_size: 10 * 1024 * 1024, // 10MB
            entropy_detection: true,
            max_concurrent: 10,
            follow_symlinks: false,
            secret_config: SecretDetectionConfig::default(),
            entropy_config: EntropyConfig::default(),
        }
    }
}

/// A secret finding from filesystem scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemSecretFinding {
    /// The underlying secret finding
    pub finding: SecretFinding,
    /// Absolute path to the file
    pub file_path: PathBuf,
    /// Relative path from scan root
    pub relative_path: String,
    /// File size in bytes
    pub file_size: u64,
    /// File modification time
    pub modified_at: Option<String>,
    /// Owner (Unix only)
    pub owner: Option<String>,
    /// File permissions (Unix only)
    pub permissions: Option<String>,
}

/// Filesystem scanner result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemScanResult {
    /// All findings
    pub findings: Vec<FilesystemSecretFinding>,
    /// Total files scanned
    pub files_scanned: usize,
    /// Total bytes scanned
    pub bytes_scanned: u64,
    /// Files skipped (too large, binary, etc.)
    pub files_skipped: usize,
    /// Directories scanned
    pub directories_scanned: usize,
    /// Scan duration in milliseconds
    pub duration_ms: u64,
    /// Errors encountered
    pub errors: Vec<String>,
}

/// Filesystem secret scanner
pub struct FilesystemScanner {
    config: FilesystemScanConfig,
}

impl FilesystemScanner {
    /// Create a new filesystem scanner
    pub fn new(config: FilesystemScanConfig) -> Self {
        Self { config }
    }

    /// Check if a file should be scanned based on patterns
    fn should_scan_file(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Check exclude patterns first
        for pattern in &self.config.exclude_patterns {
            if glob_match(pattern, &path_str) {
                return false;
            }
        }

        // Check include patterns
        for pattern in &self.config.include_patterns {
            if glob_match(pattern, &path_str) {
                return true;
            }
        }

        // Default to include if no patterns match
        self.config.include_patterns.is_empty()
            || self.config.include_patterns.iter().any(|p| p == "*")
    }

    /// Check if content appears to be binary
    fn is_binary_content(content: &[u8]) -> bool {
        // Check first 8KB for null bytes or high proportion of non-text chars
        let check_len = content.len().min(8192);
        let sample = &content[..check_len];

        let null_count = sample.iter().filter(|&&b| b == 0).count();
        if null_count > 0 {
            return true;
        }

        // Check for high proportion of control characters
        let control_count = sample
            .iter()
            .filter(|&&b| b < 32 && b != 9 && b != 10 && b != 13)
            .count();

        control_count > check_len / 10
    }

    /// Get file metadata as strings
    fn get_file_metadata(path: &Path) -> (Option<String>, Option<String>, Option<String>) {
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return (None, None, None),
        };

        let modified = metadata
            .modified()
            .ok()
            .map(|t| {
                chrono::DateTime::<chrono::Utc>::from(t)
                    .format("%Y-%m-%dT%H:%M:%SZ")
                    .to_string()
            });

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let permissions = Some(format!("{:o}", metadata.mode() & 0o777));
            // Note: Would need 'users' crate for owner lookup
            let owner: Option<String> = None;
            (modified, owner, permissions)
        }

        #[cfg(not(unix))]
        {
            (modified, None, None)
        }
    }

    /// Scan a single file for secrets
    fn scan_file(&self, path: &Path, base_path: &Path) -> Result<Vec<FilesystemSecretFinding>> {
        let metadata = std::fs::metadata(path)?;

        // Skip if too large
        if metadata.len() > self.config.max_file_size {
            return Ok(Vec::new());
        }

        // Read file content
        let content_bytes = std::fs::read(path)?;

        // Skip binary files
        if Self::is_binary_content(&content_bytes) {
            return Ok(Vec::new());
        }

        // Convert to string
        let content = match String::from_utf8(content_bytes) {
            Ok(s) => s,
            Err(_) => return Ok(Vec::new()),
        };

        let mut findings = Vec::new();
        let relative_path = path
            .strip_prefix(base_path)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        let (modified_at, owner, permissions) = Self::get_file_metadata(path);

        // Pattern-based detection
        let source = SecretSource::ConfigFile {
            path: relative_path.clone(),
        };
        let pattern_findings = detect_secrets(&content, source, &self.config.secret_config);

        for finding in pattern_findings {
            findings.push(FilesystemSecretFinding {
                finding,
                file_path: path.to_path_buf(),
                relative_path: relative_path.clone(),
                file_size: metadata.len(),
                modified_at: modified_at.clone(),
                owner: owner.clone(),
                permissions: permissions.clone(),
            });
        }

        // Entropy-based detection
        if self.config.entropy_detection {
            let entropy_findings = find_high_entropy_strings(&content, &self.config.entropy_config);

            for result in entropy_findings {
                let finding = SecretFinding {
                    secret_type: SecretType::GenericSecretKey,
                    severity: if result.confidence > 0.7 {
                        SecretSeverity::High
                    } else if result.confidence > 0.5 {
                        SecretSeverity::Medium
                    } else {
                        SecretSeverity::Low
                    },
                    redacted_value: redact_secret(&result.value),
                    source: SecretSource::ConfigFile {
                        path: relative_path.clone(),
                    },
                    line: None,
                    column: None,
                    context: Some(format!(
                        "High entropy string (entropy: {:.2}, confidence: {:.0}%)",
                        result.entropy,
                        result.confidence * 100.0
                    )),
                    remediation: Some(
                        "Review this high-entropy string and remove if it's a secret.".to_string(),
                    ),
                    verified: false,
                    entropy_score: Some(result.entropy),
                    detection_method: Some("entropy".to_string()),
                };

                findings.push(FilesystemSecretFinding {
                    finding,
                    file_path: path.to_path_buf(),
                    relative_path: relative_path.clone(),
                    file_size: metadata.len(),
                    modified_at: modified_at.clone(),
                    owner: owner.clone(),
                    permissions: permissions.clone(),
                });
            }
        }

        Ok(findings)
    }

    /// Scan the filesystem for secrets
    pub async fn scan(&self) -> Result<FilesystemScanResult> {
        let start_time = std::time::Instant::now();
        let mut all_findings = Vec::new();
        let mut files_scanned = 0;
        let mut bytes_scanned = 0u64;
        let mut files_skipped = 0;
        let mut directories_scanned = 0;
        let mut errors = Vec::new();

        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent));

        for base_path in &self.config.paths {
            if !base_path.exists() {
                errors.push(format!("Path does not exist: {:?}", base_path));
                continue;
            }

            let walker = if self.config.recursive {
                let mut builder = WalkDir::new(base_path);
                if self.config.max_depth > 0 {
                    builder = builder.max_depth(self.config.max_depth);
                }
                if self.config.follow_symlinks {
                    builder = builder.follow_links(true);
                }
                builder
            } else {
                WalkDir::new(base_path).max_depth(1)
            };

            for entry in walker {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        errors.push(format!("Walk error: {}", e));
                        continue;
                    }
                };

                let path = entry.path();

                if path.is_dir() {
                    directories_scanned += 1;
                    continue;
                }

                if !self.should_scan_file(path) {
                    files_skipped += 1;
                    continue;
                }

                // Check file size before acquiring semaphore
                if let Ok(metadata) = std::fs::metadata(path) {
                    if metadata.len() > self.config.max_file_size {
                        files_skipped += 1;
                        continue;
                    }
                    bytes_scanned += metadata.len();
                }

                let _permit = semaphore.clone().acquire_owned().await?;

                match self.scan_file(path, base_path) {
                    Ok(findings) => {
                        files_scanned += 1;
                        all_findings.extend(findings);
                    }
                    Err(e) => {
                        errors.push(format!("Error scanning {:?}: {}", path, e));
                        files_skipped += 1;
                    }
                }
            }
        }

        let duration_ms = start_time.elapsed().as_millis() as u64;

        log::info!(
            "Filesystem scan complete: {} files scanned, {} findings, {} errors",
            files_scanned,
            all_findings.len(),
            errors.len()
        );

        Ok(FilesystemScanResult {
            findings: all_findings,
            files_scanned,
            bytes_scanned,
            files_skipped,
            directories_scanned,
            duration_ms,
            errors,
        })
    }
}

/// Simple glob pattern matching
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.ends_with("/*") {
        let prefix = &pattern[..pattern.len() - 2];
        return text.contains(prefix);
    }

    if pattern.starts_with("*.") {
        let ext = &pattern[1..];
        return text.ends_with(ext);
    }

    text.ends_with(pattern) || text.contains(pattern)
}

/// Redact a secret value for safe storage/display
fn redact_secret(value: &str) -> String {
    let len = value.len();
    if len <= 8 {
        "*".repeat(len)
    } else {
        format!("{}...{}", &value[..4], &value[len - 4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*.js", "file.js"));
        assert!(!glob_match("*.js", "file.ts"));
        assert!(glob_match("node_modules/*", "/path/node_modules/package"));
    }

    #[test]
    fn test_is_binary() {
        assert!(FilesystemScanner::is_binary_content(&[0x00, 0x01, 0x02]));
        assert!(!FilesystemScanner::is_binary_content(b"Hello, World!"));
    }
}
