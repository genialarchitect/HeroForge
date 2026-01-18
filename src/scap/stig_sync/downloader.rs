//! DISA STIG Downloader
//!
//! Fetches STIG bundles from the DISA Cyber website.

use anyhow::{Result, Context, bail};
use chrono::{NaiveDate, Utc};
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use sha2::{Sha256, Digest};
use std::path::Path;
use tokio::io::AsyncWriteExt;

use super::types::{StigEntry, StigCategory, StigSyncConfig};

/// DISA STIG downloader client
pub struct StigDownloader {
    client: Client,
    config: StigSyncConfig,
}

impl StigDownloader {
    /// Create a new STIG downloader
    pub fn new(config: StigSyncConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.http_timeout_seconds))
            .user_agent("HeroForge-STIG-Sync/1.0")
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self { client, config })
    }

    /// Fetch the list of available STIGs from DISA
    pub async fn fetch_available_stigs(&self) -> Result<Vec<StigEntry>> {
        log::info!("Fetching available STIGs from DISA: {}", self.config.disa_base_url);

        let response = self.client
            .get(&self.config.disa_base_url)
            .send()
            .await
            .context("Failed to fetch DISA STIG downloads page")?;

        if !response.status().is_success() {
            bail!("DISA returned status: {}", response.status());
        }

        let html_content = response.text().await
            .context("Failed to read response body")?;

        self.parse_stig_list(&html_content)
    }

    /// Parse the HTML page to extract STIG entries
    fn parse_stig_list(&self, html: &str) -> Result<Vec<StigEntry>> {
        let document = Html::parse_document(html);
        let mut stigs = Vec::new();

        // DISA pages typically use links with .zip extensions
        let link_selector = Selector::parse("a[href*='.zip']").unwrap();
        let version_regex = Regex::new(r"[Vv](\d+)[Rr](\d+)").unwrap();
        let date_regex = Regex::new(r"(\d{1,2})[_-]?(\w{3})[_-]?(\d{4})").unwrap();

        for element in document.select(&link_selector) {
            if let Some(href) = element.value().attr("href") {
                let link_text = element.text().collect::<String>();
                let name = link_text.trim();

                // Skip non-STIG files
                if !name.to_lowercase().contains("stig") &&
                   !href.to_lowercase().contains("stig") {
                    continue;
                }

                // Extract version and release
                let (version, release) = version_regex
                    .captures(name)
                    .or_else(|| version_regex.captures(href))
                    .map(|cap| {
                        (
                            cap.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(1),
                            cap.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(1),
                        )
                    })
                    .unwrap_or((1, 1));

                // Extract date if present
                let release_date = date_regex
                    .captures(name)
                    .or_else(|| date_regex.captures(href))
                    .and_then(|cap| {
                        let day = cap.get(1)?.as_str().parse().ok()?;
                        let month_str = cap.get(2)?.as_str();
                        let year = cap.get(3)?.as_str().parse().ok()?;
                        let month = match month_str.to_lowercase().as_str() {
                            "jan" => 1, "feb" => 2, "mar" => 3, "apr" => 4,
                            "may" => 5, "jun" => 6, "jul" => 7, "aug" => 8,
                            "sep" => 9, "oct" => 10, "nov" => 11, "dec" => 12,
                            _ => return None,
                        };
                        NaiveDate::from_ymd_opt(year, month, day)
                    });

                // Build full URL
                let download_url = if href.starts_with("http") {
                    href.to_string()
                } else if href.starts_with('/') {
                    format!("https://public.cyber.mil{}", href)
                } else {
                    format!("{}{}", self.config.disa_base_url.trim_end_matches('/'), href)
                };

                // Determine category from name
                let category = self.categorize_stig(name);

                // Generate STIG ID from name
                let stig_id = self.generate_stig_id(name);
                let short_name = self.generate_short_name(name);

                stigs.push(StigEntry {
                    stig_id,
                    name: name.to_string(),
                    short_name,
                    version,
                    release,
                    release_date,
                    target_product: self.extract_product(name),
                    category,
                    download_url,
                    file_size: None,
                    file_hash: None,
                    is_benchmark: name.to_lowercase().contains("benchmark"),
                });
            }
        }

        log::info!("Found {} STIG entries", stigs.len());
        Ok(stigs)
    }

    /// Categorize a STIG based on its name
    fn categorize_stig(&self, name: &str) -> StigCategory {
        let name_lower = name.to_lowercase();

        if name_lower.contains("windows") || name_lower.contains("linux") ||
           name_lower.contains("rhel") || name_lower.contains("ubuntu") ||
           name_lower.contains("macos") || name_lower.contains("solaris") {
            StigCategory::OperatingSystem
        } else if name_lower.contains("cisco") || name_lower.contains("juniper") ||
                  name_lower.contains("palo alto") || name_lower.contains("firewall") ||
                  name_lower.contains("router") || name_lower.contains("switch") {
            StigCategory::NetworkDevice
        } else if name_lower.contains("oracle") || name_lower.contains("sql server") ||
                  name_lower.contains("mysql") || name_lower.contains("postgresql") ||
                  name_lower.contains("mongodb") || name_lower.contains("database") {
            StigCategory::Database
        } else if name_lower.contains("apache") || name_lower.contains("iis") ||
                  name_lower.contains("nginx") || name_lower.contains("tomcat") ||
                  name_lower.contains("web server") {
            StigCategory::WebServer
        } else if name_lower.contains("vmware") || name_lower.contains("hyper-v") ||
                  name_lower.contains("esxi") || name_lower.contains("virtual") {
            StigCategory::Virtualization
        } else if name_lower.contains("android") || name_lower.contains("ios") ||
                  name_lower.contains("mobile") {
            StigCategory::MobileDevice
        } else if name_lower.contains("docker") || name_lower.contains("kubernetes") ||
                  name_lower.contains("container") || name_lower.contains("cloud") {
            StigCategory::Container
        } else if name_lower.contains("office") || name_lower.contains("browser") ||
                  name_lower.contains("chrome") || name_lower.contains("edge") ||
                  name_lower.contains("firefox") {
            StigCategory::Application
        } else {
            StigCategory::Other
        }
    }

    /// Generate a unique STIG ID from the name
    fn generate_stig_id(&self, name: &str) -> String {
        let cleaned = name
            .to_lowercase()
            .replace(' ', "_")
            .replace('-', "_")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .collect::<String>();

        // Truncate if too long
        if cleaned.len() > 64 {
            cleaned[..64].to_string()
        } else {
            cleaned
        }
    }

    /// Generate a short name from the STIG name
    fn generate_short_name(&self, name: &str) -> String {
        // Extract key words
        let words: Vec<&str> = name
            .split_whitespace()
            .filter(|w| {
                let lower = w.to_lowercase();
                !["stig", "security", "technical", "implementation", "guide", "the", "a", "an"].contains(&lower.as_str())
            })
            .take(3)
            .collect();

        words.join("_")
    }

    /// Extract the target product from the STIG name
    fn extract_product(&self, name: &str) -> String {
        // Remove common suffixes
        let cleaned = name
            .replace("STIG", "")
            .replace("Security Technical Implementation Guide", "")
            .replace("Benchmark", "")
            .trim()
            .to_string();

        if cleaned.is_empty() {
            name.to_string()
        } else {
            cleaned
        }
    }

    /// Download a STIG bundle to the specified path
    pub async fn download_stig(&self, entry: &StigEntry, dest_dir: &str) -> Result<String> {
        log::info!("Downloading STIG: {} from {}", entry.name, entry.download_url);

        // Create destination directory if needed
        tokio::fs::create_dir_all(dest_dir).await
            .context("Failed to create download directory")?;

        // Generate filename from URL
        let default_filename = format!("{}.zip", entry.stig_id);
        let filename = entry.download_url
            .split('/')
            .last()
            .unwrap_or(&default_filename);

        let dest_path = Path::new(dest_dir).join(filename);

        // Download with retries
        let mut last_error = None;
        for attempt in 1..=self.config.retry_count {
            match self.download_file(&entry.download_url, &dest_path).await {
                Ok(hash) => {
                    log::info!("Downloaded {} successfully (SHA256: {})", filename, hash);
                    return Ok(dest_path.to_string_lossy().to_string());
                }
                Err(e) => {
                    log::warn!("Download attempt {}/{} failed: {}", attempt, self.config.retry_count, e);
                    last_error = Some(e);
                    if attempt < self.config.retry_count {
                        tokio::time::sleep(std::time::Duration::from_secs(2 * attempt as u64)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Download failed")))
    }

    /// Download a file and compute its hash
    async fn download_file(&self, url: &str, dest: &Path) -> Result<String> {
        let response = self.client
            .get(url)
            .send()
            .await
            .context("Failed to initiate download")?;

        if !response.status().is_success() {
            bail!("Download failed with status: {}", response.status());
        }

        let bytes = response.bytes().await
            .context("Failed to read download bytes")?;

        // Compute hash
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = format!("{:x}", hasher.finalize());

        // Write to file
        let mut file = tokio::fs::File::create(dest).await
            .context("Failed to create destination file")?;

        file.write_all(&bytes).await
            .context("Failed to write file")?;

        file.flush().await?;

        Ok(hash)
    }

    /// Check if a STIG update is available
    pub async fn check_for_update(&self, tracked: &super::types::TrackedStig) -> Result<Option<StigEntry>> {
        let available_stigs = self.fetch_available_stigs().await?;

        // Find matching STIG by ID or name similarity
        for entry in available_stigs {
            if entry.stig_id == tracked.stig_id ||
               entry.name.to_lowercase().contains(&tracked.stig_name.to_lowercase()) {
                // Check if newer version/release
                if entry.version > tracked.current_version ||
                   (entry.version == tracked.current_version && entry.release > tracked.current_release) {
                    log::info!(
                        "Update available for {}: V{}R{} -> V{}R{}",
                        tracked.stig_name,
                        tracked.current_version, tracked.current_release,
                        entry.version, entry.release
                    );
                    return Ok(Some(entry));
                }
            }
        }

        Ok(None)
    }

    /// Search for STIGs matching a query
    pub async fn search_stigs(&self, query: &str) -> Result<Vec<StigEntry>> {
        let all_stigs = self.fetch_available_stigs().await?;
        let query_lower = query.to_lowercase();

        Ok(all_stigs
            .into_iter()
            .filter(|s| {
                s.name.to_lowercase().contains(&query_lower) ||
                s.target_product.to_lowercase().contains(&query_lower) ||
                s.stig_id.to_lowercase().contains(&query_lower)
            })
            .collect())
    }

    /// Download multiple STIGs in parallel
    pub async fn download_stigs_bulk(
        &self,
        entries: Vec<StigEntry>,
        dest_dir: &str,
        max_concurrent: usize,
        progress_callback: Option<Box<dyn Fn(BulkDownloadProgress) + Send + Sync>>,
    ) -> Result<BulkDownloadResult> {
        use tokio::sync::Semaphore;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let total = entries.len();
        if total == 0 {
            return Ok(BulkDownloadResult {
                total: 0,
                successful: 0,
                failed: 0,
                results: Vec::new(),
            });
        }

        log::info!("Starting bulk download of {} STIGs with {} concurrent downloads", total, max_concurrent);

        // Create destination directory
        tokio::fs::create_dir_all(dest_dir).await
            .context("Failed to create download directory")?;

        // Semaphore to limit concurrent downloads
        let semaphore = Arc::new(Semaphore::new(max_concurrent));

        // Progress tracking
        let completed = Arc::new(AtomicUsize::new(0));
        let successful = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicUsize::new(0));

        // Clone self for parallel execution
        let client = self.client.clone();
        let config = self.config.clone();
        let dest_dir = dest_dir.to_string();

        // Wrap callback in Arc for sharing across tasks
        let progress_callback: Option<Arc<dyn Fn(BulkDownloadProgress) + Send + Sync>> =
            progress_callback.map(|cb| Arc::from(cb) as Arc<dyn Fn(BulkDownloadProgress) + Send + Sync>);

        // Create download tasks
        let mut handles = Vec::with_capacity(total);

        for entry in entries {
            let semaphore = semaphore.clone();
            let client = client.clone();
            let config = config.clone();
            let dest_dir = dest_dir.clone();
            let completed = completed.clone();
            let successful = successful.clone();
            let failed = failed.clone();
            let progress_callback = progress_callback.clone();

            let handle = tokio::spawn(async move {
                // Acquire semaphore permit
                let _permit = semaphore.acquire().await.unwrap();

                // Generate filename
                let default_filename = format!("{}.zip", entry.stig_id);
                let filename = entry.download_url
                    .split('/')
                    .last()
                    .unwrap_or(&default_filename)
                    .to_string();

                let dest_path = Path::new(&dest_dir).join(&filename);

                // Attempt download with retries
                let mut last_error = None;
                for attempt in 1..=config.retry_count {
                    match download_file_internal(&client, &entry.download_url, &dest_path).await {
                        Ok(hash) => {
                            successful.fetch_add(1, Ordering::SeqCst);
                            let done = completed.fetch_add(1, Ordering::SeqCst) + 1;

                            // Report progress
                            if let Some(ref cb) = progress_callback {
                                cb(BulkDownloadProgress {
                                    total,
                                    completed: done,
                                    successful: successful.load(Ordering::SeqCst),
                                    failed: failed.load(Ordering::SeqCst),
                                    current_stig: entry.name.clone(),
                                    current_status: DownloadStatus::Completed,
                                });
                            }

                            return SingleDownloadResult {
                                stig_id: entry.stig_id,
                                name: entry.name,
                                success: true,
                                path: Some(dest_path.to_string_lossy().to_string()),
                                hash: Some(hash),
                                error: None,
                            };
                        }
                        Err(e) => {
                            log::warn!(
                                "Download attempt {}/{} for {} failed: {}",
                                attempt, config.retry_count, entry.name, e
                            );
                            last_error = Some(e.to_string());
                            if attempt < config.retry_count {
                                tokio::time::sleep(std::time::Duration::from_secs(2 * attempt as u64)).await;
                            }
                        }
                    }
                }

                // Download failed after all retries
                failed.fetch_add(1, Ordering::SeqCst);
                let done = completed.fetch_add(1, Ordering::SeqCst) + 1;

                // Report progress
                if let Some(ref cb) = progress_callback {
                    cb(BulkDownloadProgress {
                        total,
                        completed: done,
                        successful: successful.load(Ordering::SeqCst),
                        failed: failed.load(Ordering::SeqCst),
                        current_stig: entry.name.clone(),
                        current_status: DownloadStatus::Failed,
                    });
                }

                SingleDownloadResult {
                    stig_id: entry.stig_id,
                    name: entry.name,
                    success: false,
                    path: None,
                    hash: None,
                    error: last_error,
                }
            });

            handles.push(handle);
        }

        // Wait for all downloads to complete
        let mut results = Vec::with_capacity(total);
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => {
                    log::error!("Download task panicked: {}", e);
                    results.push(SingleDownloadResult {
                        stig_id: "unknown".to_string(),
                        name: "unknown".to_string(),
                        success: false,
                        path: None,
                        hash: None,
                        error: Some(format!("Task panicked: {}", e)),
                    });
                }
            }
        }

        Ok(BulkDownloadResult {
            total,
            successful: successful.load(Ordering::SeqCst),
            failed: failed.load(Ordering::SeqCst),
            results,
        })
    }

    /// Download all tracked STIGs that have updates available
    pub async fn download_pending_updates(
        &self,
        tracked_stigs: Vec<super::types::TrackedStig>,
        dest_dir: &str,
        max_concurrent: usize,
        progress_callback: Option<Box<dyn Fn(BulkDownloadProgress) + Send + Sync>>,
    ) -> Result<BulkDownloadResult> {
        let mut entries_to_download = Vec::new();

        // Check each tracked STIG for updates
        for tracked in tracked_stigs {
            if let Some(update) = self.check_for_update(&tracked).await? {
                entries_to_download.push(update);
            }
        }

        if entries_to_download.is_empty() {
            log::info!("No updates available for tracked STIGs");
            return Ok(BulkDownloadResult {
                total: 0,
                successful: 0,
                failed: 0,
                results: Vec::new(),
            });
        }

        log::info!("Found {} updates to download", entries_to_download.len());
        self.download_stigs_bulk(entries_to_download, dest_dir, max_concurrent, progress_callback).await
    }

    /// Download STIGs by category
    pub async fn download_by_category(
        &self,
        category: StigCategory,
        dest_dir: &str,
        max_concurrent: usize,
        progress_callback: Option<Box<dyn Fn(BulkDownloadProgress) + Send + Sync>>,
    ) -> Result<BulkDownloadResult> {
        let all_stigs = self.fetch_available_stigs().await?;

        let entries: Vec<StigEntry> = all_stigs
            .into_iter()
            .filter(|s| s.category == category)
            .collect();

        if entries.is_empty() {
            log::info!("No STIGs found for category {:?}", category);
            return Ok(BulkDownloadResult {
                total: 0,
                successful: 0,
                failed: 0,
                results: Vec::new(),
            });
        }

        log::info!("Downloading {} STIGs for category {:?}", entries.len(), category);
        self.download_stigs_bulk(entries, dest_dir, max_concurrent, progress_callback).await
    }
}

/// Internal helper function for downloading files
async fn download_file_internal(client: &Client, url: &str, dest: &Path) -> Result<String> {
    let response = client
        .get(url)
        .send()
        .await
        .context("Failed to initiate download")?;

    if !response.status().is_success() {
        bail!("Download failed with status: {}", response.status());
    }

    let bytes = response.bytes().await
        .context("Failed to read download bytes")?;

    // Compute hash
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = format!("{:x}", hasher.finalize());

    // Write to file
    let mut file = tokio::fs::File::create(dest).await
        .context("Failed to create destination file")?;

    file.write_all(&bytes).await
        .context("Failed to write file")?;

    file.flush().await?;

    Ok(hash)
}

/// Result of a bulk download operation
#[derive(Debug, Clone)]
pub struct BulkDownloadResult {
    /// Total number of STIGs to download
    pub total: usize,
    /// Number of successful downloads
    pub successful: usize,
    /// Number of failed downloads
    pub failed: usize,
    /// Individual results for each STIG
    pub results: Vec<SingleDownloadResult>,
}

/// Result of a single STIG download
#[derive(Debug, Clone)]
pub struct SingleDownloadResult {
    /// STIG ID
    pub stig_id: String,
    /// STIG name
    pub name: String,
    /// Whether the download was successful
    pub success: bool,
    /// Path to the downloaded file (if successful)
    pub path: Option<String>,
    /// SHA256 hash of the downloaded file
    pub hash: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Progress information for bulk downloads
#[derive(Debug, Clone)]
pub struct BulkDownloadProgress {
    /// Total number of STIGs to download
    pub total: usize,
    /// Number of completed downloads (successful + failed)
    pub completed: usize,
    /// Number of successful downloads
    pub successful: usize,
    /// Number of failed downloads
    pub failed: usize,
    /// Name of the current STIG being processed
    pub current_stig: String,
    /// Status of the current download
    pub current_status: DownloadStatus,
}

/// Status of a download
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadStatus {
    /// Download is starting
    Starting,
    /// Download is in progress
    InProgress,
    /// Download completed successfully
    Completed,
    /// Download failed
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_categorize_stig() {
        let config = StigSyncConfig::default();
        let downloader = StigDownloader::new(config).unwrap();

        assert_eq!(
            downloader.categorize_stig("Windows Server 2022 STIG"),
            StigCategory::OperatingSystem
        );
        assert_eq!(
            downloader.categorize_stig("Cisco IOS XE Router STIG"),
            StigCategory::NetworkDevice
        );
        assert_eq!(
            downloader.categorize_stig("Oracle Database 19c STIG"),
            StigCategory::Database
        );
    }

    #[test]
    fn test_generate_stig_id() {
        let config = StigSyncConfig::default();
        let downloader = StigDownloader::new(config).unwrap();

        let id = downloader.generate_stig_id("Windows Server 2022 STIG V1R1");
        assert!(!id.contains(' '));
        assert!(!id.contains('-'));
    }
}
