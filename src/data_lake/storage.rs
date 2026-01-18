use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use chrono::{DateTime, Utc, Duration};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use log::{debug, info, warn};

use super::types::{DataRecord, StorageTier};

/// Storage backend abstraction
#[derive(Debug, Clone)]
pub enum StorageBackend {
    S3(S3Config),
    Local(LocalConfig),
    Azure(AzureConfig),
    GCP(GCPConfig),
}

/// S3 storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub endpoint: Option<String>,
    pub prefix: Option<String>,
}

/// Local filesystem storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalConfig {
    pub base_path: String,
    pub max_size_bytes: Option<u64>,
    pub retention_days: Option<u32>,
}

/// Azure Blob storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureConfig {
    pub account_name: String,
    pub container: String,
    pub access_key: Option<String>,
    pub sas_token: Option<String>,
}

/// GCP Cloud Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCPConfig {
    pub bucket: String,
    pub project_id: String,
    pub credentials_path: Option<String>,
}

/// Storage tier paths
#[derive(Debug, Clone)]
pub struct TierConfig {
    pub hot_path: String,
    pub warm_path: String,
    pub cold_path: String,
    pub frozen_path: String,
}

impl Default for TierConfig {
    fn default() -> Self {
        Self {
            hot_path: "hot".to_string(),
            warm_path: "warm".to_string(),
            cold_path: "cold".to_string(),
            frozen_path: "frozen".to_string(),
        }
    }
}

/// Storage metadata index for quick lookups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordIndex {
    pub record_id: String,
    pub source_id: String,
    pub timestamp: DateTime<Utc>,
    pub tier: String,
    pub path: String,
    pub size_bytes: u64,
}

/// Data lake storage manager
pub struct StorageManager {
    backend: StorageBackend,
    tier_config: TierConfig,
    index: HashMap<String, RecordIndex>,
}

impl StorageManager {
    /// Create a new storage manager with the specified backend
    pub fn new(backend: StorageBackend) -> Self {
        Self {
            backend,
            tier_config: TierConfig::default(),
            index: HashMap::new(),
        }
    }

    /// Create with custom tier configuration
    pub fn with_tier_config(backend: StorageBackend, tier_config: TierConfig) -> Self {
        Self {
            backend,
            tier_config,
            index: HashMap::new(),
        }
    }

    /// Get tier path
    fn get_tier_path(&self, tier: &StorageTier) -> &str {
        match tier {
            StorageTier::Hot => &self.tier_config.hot_path,
            StorageTier::Warm => &self.tier_config.warm_path,
            StorageTier::Cold => &self.tier_config.cold_path,
            StorageTier::Archive => &self.tier_config.frozen_path,
        }
    }

    /// Generate storage path for a record
    fn generate_path(&self, record: &DataRecord, tier: &StorageTier) -> String {
        let tier_path = self.get_tier_path(tier);
        let date = record.timestamp.format("%Y/%m/%d");
        let hour = record.timestamp.format("%H");
        format!("{}/{}/{}/{}.json", tier_path, date, hour, record.id)
    }

    /// Store a record in the data lake
    pub async fn store_record(&self, record: &DataRecord, tier: StorageTier) -> Result<()> {
        match &self.backend {
            StorageBackend::S3(config) => self.store_to_s3(config, record, tier).await,
            StorageBackend::Local(config) => self.store_to_local(config, record, tier).await,
            StorageBackend::Azure(config) => self.store_to_azure(config, record, tier).await,
            StorageBackend::GCP(config) => self.store_to_gcp(config, record, tier).await,
        }
    }

    /// Retrieve records from the data lake
    pub async fn retrieve_records(
        &self,
        source_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<Vec<DataRecord>> {
        match &self.backend {
            StorageBackend::Local(config) => {
                self.retrieve_from_local(config, source_id, start_time, end_time).await
            }
            StorageBackend::S3(config) => {
                self.retrieve_from_s3(config, source_id, start_time, end_time).await
            }
            StorageBackend::Azure(config) => {
                self.retrieve_from_azure(config, source_id, start_time, end_time).await
            }
            StorageBackend::GCP(config) => {
                self.retrieve_from_gcp(config, source_id, start_time, end_time).await
            }
        }
    }

    /// Retrieve from local filesystem
    async fn retrieve_from_local(
        &self,
        config: &LocalConfig,
        source_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<Vec<DataRecord>> {
        let mut records = Vec::new();

        // Iterate through all tiers
        for tier in &[StorageTier::Hot, StorageTier::Warm, StorageTier::Cold, StorageTier::Archive] {
            let tier_path = self.get_tier_path(tier);
            let base_path = PathBuf::from(&config.base_path).join(tier_path);

            if !base_path.exists() {
                continue;
            }

            // Walk through date directories
            let mut current = start_time;
            while current <= end_time {
                let date_path = base_path.join(current.format("%Y/%m/%d").to_string());

                if date_path.exists() {
                    records.extend(
                        self.scan_directory_for_records(&date_path, source_id, start_time, end_time).await?
                    );
                }

                current = current + Duration::days(1);
            }
        }

        // Sort by timestamp
        records.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        info!("Retrieved {} records for source '{}' between {} and {}",
              records.len(), source_id, start_time, end_time);

        Ok(records)
    }

    /// Scan directory for matching records
    async fn scan_directory_for_records(
        &self,
        dir: &PathBuf,
        source_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<Vec<DataRecord>> {
        let mut records = Vec::new();
        let mut entries = fs::read_dir(dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.is_dir() {
                // Recurse into subdirectories (hour directories)
                records.extend(
                    Box::pin(self.scan_directory_for_records(&path, source_id, start_time, end_time)).await?
                );
            } else if path.extension().map(|e| e == "json").unwrap_or(false) {
                // Read and parse JSON file
                if let Ok(mut file) = fs::File::open(&path).await {
                    let mut content = String::new();
                    if file.read_to_string(&mut content).await.is_ok() {
                        if let Ok(record) = serde_json::from_str::<DataRecord>(&content) {
                            // Filter by source_id and time range
                            if record.source_id == source_id
                               && record.timestamp >= start_time
                               && record.timestamp <= end_time {
                                records.push(record);
                            }
                        }
                    }
                }
            }
        }

        Ok(records)
    }

    /// Retrieve from S3
    async fn retrieve_from_s3(
        &self,
        config: &S3Config,
        source_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<Vec<DataRecord>> {
        // Build list of prefixes to search
        let mut prefixes = Vec::new();
        let mut current = start_time;

        while current <= end_time {
            let prefix = format!(
                "{}{}/",
                config.prefix.as_deref().unwrap_or(""),
                current.format("%Y/%m/%d")
            );
            prefixes.push(prefix);
            current = current + Duration::days(1);
        }

        debug!("S3 retrieval would search prefixes: {:?}", prefixes);

        // In production, use aws-sdk-s3 to list and get objects
        // For now, return empty as this requires AWS credentials
        warn!("S3 retrieval not fully implemented - requires aws-sdk-s3");
        let _ = (source_id, config);
        Ok(Vec::new())
    }

    /// Retrieve from Azure Blob
    async fn retrieve_from_azure(
        &self,
        config: &AzureConfig,
        source_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<Vec<DataRecord>> {
        debug!(
            "Azure Blob retrieval for container '{}' from {} to {}",
            config.container, start_time, end_time
        );

        // In production, use azure-storage-blobs crate
        warn!("Azure Blob retrieval not fully implemented - requires azure SDK");
        let _ = (source_id, config);
        Ok(Vec::new())
    }

    /// Retrieve from GCP Cloud Storage
    async fn retrieve_from_gcp(
        &self,
        config: &GCPConfig,
        source_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<Vec<DataRecord>> {
        debug!(
            "GCP Cloud Storage retrieval for bucket '{}' from {} to {}",
            config.bucket, start_time, end_time
        );

        // In production, use google-cloud-storage crate
        warn!("GCP Cloud Storage retrieval not fully implemented - requires GCP SDK");
        let _ = (source_id, config);
        Ok(Vec::new())
    }

    /// Move data between storage tiers
    pub async fn move_to_tier(
        &self,
        record_id: &str,
        target_tier: StorageTier,
    ) -> Result<()> {
        match &self.backend {
            StorageBackend::Local(config) => {
                self.move_local_to_tier(config, record_id, target_tier).await
            }
            StorageBackend::S3(config) => {
                self.move_s3_to_tier(config, record_id, target_tier).await
            }
            StorageBackend::Azure(config) => {
                self.move_azure_to_tier(config, record_id, target_tier).await
            }
            StorageBackend::GCP(config) => {
                self.move_gcp_to_tier(config, record_id, target_tier).await
            }
        }
    }

    /// Move local file to different tier
    async fn move_local_to_tier(
        &self,
        config: &LocalConfig,
        record_id: &str,
        target_tier: StorageTier,
    ) -> Result<()> {
        // Find the record in current tiers
        let base_path = PathBuf::from(&config.base_path);
        let mut source_path: Option<PathBuf> = None;
        let mut current_tier: Option<StorageTier> = None;

        for tier in &[StorageTier::Hot, StorageTier::Warm, StorageTier::Cold, StorageTier::Archive] {
            let tier_path = base_path.join(self.get_tier_path(tier));
            if let Some(path) = self.find_record_in_dir(&tier_path, record_id).await? {
                source_path = Some(path);
                current_tier = Some(tier.clone());
                break;
            }
        }

        let source = source_path.ok_or_else(|| anyhow!("Record not found: {}", record_id))?;
        let current = current_tier.unwrap();

        if current == target_tier {
            debug!("Record {} is already in {:?} tier", record_id, target_tier);
            return Ok(());
        }

        // Read the record
        let content = fs::read_to_string(&source).await?;
        let record: DataRecord = serde_json::from_str(&content)?;

        // Create target path
        let target_tier_path = self.get_tier_path(&target_tier);
        let relative_path = source.strip_prefix(&base_path.join(self.get_tier_path(&current)))
            .map_err(|_| anyhow!("Failed to get relative path"))?;
        let target_path = base_path.join(target_tier_path).join(relative_path);

        // Create target directory
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Copy to target
        let json = serde_json::to_string_pretty(&record)?;
        fs::write(&target_path, json).await?;

        // Remove from source
        fs::remove_file(&source).await?;

        info!("Moved record {} from {:?} to {:?}", record_id, current, target_tier);
        Ok(())
    }

    /// Find record file in directory tree
    async fn find_record_in_dir(&self, dir: &PathBuf, record_id: &str) -> Result<Option<PathBuf>> {
        if !dir.exists() {
            return Ok(None);
        }

        let mut entries = fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.is_dir() {
                if let Some(found) = Box::pin(self.find_record_in_dir(&path, record_id)).await? {
                    return Ok(Some(found));
                }
            } else if path.file_stem().map(|s| s.to_string_lossy() == record_id).unwrap_or(false) {
                return Ok(Some(path));
            }
        }

        Ok(None)
    }

    /// Move S3 object to different tier (storage class)
    async fn move_s3_to_tier(
        &self,
        config: &S3Config,
        record_id: &str,
        target_tier: StorageTier,
    ) -> Result<()> {
        let storage_class = match target_tier {
            StorageTier::Hot => "STANDARD",
            StorageTier::Warm => "STANDARD_IA",
            StorageTier::Cold => "GLACIER",
            StorageTier::Archive => "DEEP_ARCHIVE",
        };

        debug!(
            "S3 tier change for {} in bucket '{}' to {}",
            record_id, config.bucket, storage_class
        );

        // In production, use CopyObject with StorageClass
        warn!("S3 tier migration not fully implemented - requires aws-sdk-s3");
        Ok(())
    }

    /// Move Azure blob to different tier
    async fn move_azure_to_tier(
        &self,
        config: &AzureConfig,
        record_id: &str,
        target_tier: StorageTier,
    ) -> Result<()> {
        let access_tier = match target_tier {
            StorageTier::Hot => "Hot",
            StorageTier::Warm => "Cool",
            StorageTier::Cold => "Cold",
            StorageTier::Archive => "Archive",
        };

        debug!(
            "Azure Blob tier change for {} in container '{}' to {}",
            record_id, config.container, access_tier
        );

        // In production, use Set Blob Tier API
        warn!("Azure Blob tier migration not fully implemented - requires azure SDK");
        Ok(())
    }

    /// Move GCP object to different tier
    async fn move_gcp_to_tier(
        &self,
        config: &GCPConfig,
        record_id: &str,
        target_tier: StorageTier,
    ) -> Result<()> {
        let storage_class = match target_tier {
            StorageTier::Hot => "STANDARD",
            StorageTier::Warm => "NEARLINE",
            StorageTier::Cold => "COLDLINE",
            StorageTier::Archive => "ARCHIVE",
        };

        debug!(
            "GCP Cloud Storage tier change for {} in bucket '{}' to {}",
            record_id, config.bucket, storage_class
        );

        // In production, use rewrite with storageClass
        warn!("GCP Cloud Storage tier migration not fully implemented - requires GCP SDK");
        Ok(())
    }

    async fn store_to_s3(&self, config: &S3Config, record: &DataRecord, tier: StorageTier) -> Result<()> {
        let path = self.generate_path(record, &tier);
        let key = format!("{}{}", config.prefix.as_deref().unwrap_or(""), path);

        let storage_class = match tier {
            StorageTier::Hot => "STANDARD",
            StorageTier::Warm => "STANDARD_IA",
            StorageTier::Cold => "GLACIER_IR",
            StorageTier::Archive => "DEEP_ARCHIVE",
        };

        debug!(
            "Storing record {} to S3 bucket '{}' key '{}' with class {}",
            record.id, config.bucket, key, storage_class
        );

        // In production, use aws-sdk-s3
        // let client = aws_sdk_s3::Client::new(&config);
        // client.put_object()
        //     .bucket(&config.bucket)
        //     .key(&key)
        //     .body(ByteStream::from(json_bytes))
        //     .storage_class(storage_class.into())
        //     .send().await?;

        info!("S3 storage: would store to s3://{}/{}", config.bucket, key);
        Ok(())
    }

    async fn store_to_local(&self, config: &LocalConfig, record: &DataRecord, tier: StorageTier) -> Result<()> {
        let path = self.generate_path(record, &tier);
        let file_path = PathBuf::from(&config.base_path).join(&path);

        // Create directory structure
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Serialize and write
        let json = serde_json::to_string_pretty(record)?;
        let mut file = fs::File::create(&file_path).await?;
        file.write_all(json.as_bytes()).await?;

        debug!("Stored record {} to {}", record.id, file_path.display());
        Ok(())
    }

    async fn store_to_azure(&self, config: &AzureConfig, record: &DataRecord, tier: StorageTier) -> Result<()> {
        let path = self.generate_path(record, &tier);

        let access_tier = match tier {
            StorageTier::Hot => "Hot",
            StorageTier::Warm => "Cool",
            StorageTier::Cold => "Cold",
            StorageTier::Archive => "Archive",
        };

        debug!(
            "Storing record {} to Azure Blob container '{}' path '{}' tier {}",
            record.id, config.container, path, access_tier
        );

        // In production, use azure-storage-blobs
        info!(
            "Azure Blob storage: would store to https://{}.blob.core.windows.net/{}/{}",
            config.account_name, config.container, path
        );
        Ok(())
    }

    async fn store_to_gcp(&self, config: &GCPConfig, record: &DataRecord, tier: StorageTier) -> Result<()> {
        let path = self.generate_path(record, &tier);

        let storage_class = match tier {
            StorageTier::Hot => "STANDARD",
            StorageTier::Warm => "NEARLINE",
            StorageTier::Cold => "COLDLINE",
            StorageTier::Archive => "ARCHIVE",
        };

        debug!(
            "Storing record {} to GCP bucket '{}' path '{}' class {}",
            record.id, config.bucket, path, storage_class
        );

        // In production, use google-cloud-storage
        info!(
            "GCP Cloud Storage: would store to gs://{}/{}",
            config.bucket, path
        );
        Ok(())
    }

    /// List records by source
    pub async fn list_records(&self, source_id: &str, limit: usize) -> Result<Vec<RecordIndex>> {
        let records: Vec<RecordIndex> = self.index
            .values()
            .filter(|r| r.source_id == source_id)
            .take(limit)
            .cloned()
            .collect();

        Ok(records)
    }

    /// Delete old records based on retention policy
    pub async fn apply_retention_policy(&self, max_age_days: u32) -> Result<usize> {
        let cutoff = Utc::now() - Duration::days(max_age_days as i64);
        let mut deleted_count = 0;

        match &self.backend {
            StorageBackend::Local(config) => {
                let base = PathBuf::from(&config.base_path);
                deleted_count = self.delete_old_local_records(&base, cutoff).await?;
            }
            _ => {
                warn!("Retention policy not implemented for non-local backends");
            }
        }

        info!("Applied retention policy: deleted {} records older than {} days",
              deleted_count, max_age_days);
        Ok(deleted_count)
    }

    /// Delete old records from local storage
    async fn delete_old_local_records(&self, base: &PathBuf, cutoff: DateTime<Utc>) -> Result<usize> {
        let mut deleted = 0;

        for tier in &[StorageTier::Hot, StorageTier::Warm, StorageTier::Cold, StorageTier::Archive] {
            let tier_path = base.join(self.get_tier_path(tier));
            if tier_path.exists() {
                deleted += Box::pin(self.delete_old_in_dir(&tier_path, cutoff)).await?;
            }
        }

        Ok(deleted)
    }

    /// Recursively delete old files
    async fn delete_old_in_dir(&self, dir: &PathBuf, cutoff: DateTime<Utc>) -> Result<usize> {
        let mut deleted = 0;
        let mut entries = fs::read_dir(dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.is_dir() {
                deleted += Box::pin(self.delete_old_in_dir(&path, cutoff)).await?;
            } else if path.extension().map(|e| e == "json").unwrap_or(false) {
                // Check file modification time
                if let Ok(metadata) = entry.metadata().await {
                    if let Ok(modified) = metadata.modified() {
                        let modified_utc: DateTime<Utc> = modified.into();
                        if modified_utc < cutoff {
                            fs::remove_file(&path).await?;
                            deleted += 1;
                        }
                    }
                }
            }
        }

        Ok(deleted)
    }

    /// Get storage statistics
    pub async fn get_stats(&self) -> Result<StorageStats> {
        let mut stats = StorageStats::default();

        match &self.backend {
            StorageBackend::Local(config) => {
                let base = PathBuf::from(&config.base_path);

                for tier in &[StorageTier::Hot, StorageTier::Warm, StorageTier::Cold, StorageTier::Archive] {
                    let tier_path = base.join(self.get_tier_path(tier));
                    if tier_path.exists() {
                        let (count, size) = self.count_files_and_size(&tier_path).await?;
                        match tier {
                            StorageTier::Hot => {
                                stats.hot_records = count;
                                stats.hot_size_bytes = size;
                            }
                            StorageTier::Warm => {
                                stats.warm_records = count;
                                stats.warm_size_bytes = size;
                            }
                            StorageTier::Cold => {
                                stats.cold_records = count;
                                stats.cold_size_bytes = size;
                            }
                            StorageTier::Archive => {
                                stats.frozen_records = count;
                                stats.frozen_size_bytes = size;
                            }
                        }
                    }
                }
            }
            _ => {
                warn!("Stats not implemented for non-local backends");
            }
        }

        stats.total_records = stats.hot_records + stats.warm_records
                            + stats.cold_records + stats.frozen_records;
        stats.total_size_bytes = stats.hot_size_bytes + stats.warm_size_bytes
                               + stats.cold_size_bytes + stats.frozen_size_bytes;

        Ok(stats)
    }

    /// Count files and total size in directory
    async fn count_files_and_size(&self, dir: &PathBuf) -> Result<(u64, u64)> {
        let mut count = 0;
        let mut size = 0;

        let mut entries = fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.is_dir() {
                let (sub_count, sub_size) = Box::pin(self.count_files_and_size(&path)).await?;
                count += sub_count;
                size += sub_size;
            } else {
                count += 1;
                if let Ok(metadata) = entry.metadata().await {
                    size += metadata.len();
                }
            }
        }

        Ok((count, size))
    }
}

/// Storage statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_records: u64,
    pub total_size_bytes: u64,
    pub hot_records: u64,
    pub hot_size_bytes: u64,
    pub warm_records: u64,
    pub warm_size_bytes: u64,
    pub cold_records: u64,
    pub cold_size_bytes: u64,
    pub frozen_records: u64,
    pub frozen_size_bytes: u64,
}

/// Time-series data storage optimized for hunt queries
pub struct TimeSeriesStorage {
    manager: StorageManager,
}

impl TimeSeriesStorage {
    pub fn new(manager: StorageManager) -> Self {
        Self { manager }
    }

    /// Store time-series data with optimized indexing
    pub async fn store_time_series(&self, record: &DataRecord) -> Result<()> {
        // Default to hot tier for recent data
        self.manager.store_record(record, StorageTier::Hot).await
    }

    /// Query time-series data efficiently
    pub async fn query_time_series(
        &self,
        source_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Vec<DataRecord>> {
        self.manager.retrieve_records(source_id, start, end).await
    }

    /// Aggregate time-series data by time buckets
    pub async fn aggregate_by_time(
        &self,
        source_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        bucket_minutes: i64,
    ) -> Result<Vec<TimeBucket>> {
        let records = self.manager.retrieve_records(source_id, start, end).await?;

        let mut buckets: HashMap<DateTime<Utc>, Vec<DataRecord>> = HashMap::new();

        for record in records {
            // Round timestamp to bucket boundary
            let bucket_start = round_to_bucket(record.timestamp, bucket_minutes);
            buckets.entry(bucket_start).or_default().push(record);
        }

        let mut result: Vec<TimeBucket> = buckets
            .into_iter()
            .map(|(timestamp, records)| TimeBucket {
                timestamp,
                count: records.len() as u64,
                records,
            })
            .collect();

        result.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(result)
    }
}

/// Round timestamp to bucket boundary
fn round_to_bucket(timestamp: DateTime<Utc>, bucket_minutes: i64) -> DateTime<Utc> {
    let minutes = timestamp.timestamp() / 60;
    let bucket_num = minutes / bucket_minutes;
    DateTime::from_timestamp(bucket_num * bucket_minutes * 60, 0)
        .unwrap_or(timestamp)
}

/// Time bucket for aggregated data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBucket {
    pub timestamp: DateTime<Utc>,
    pub count: u64,
    pub records: Vec<DataRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn test_storage_backend_creation() {
        let local_backend = StorageBackend::Local(LocalConfig {
            base_path: "/tmp/data_lake".to_string(),
            max_size_bytes: None,
            retention_days: None,
        });

        match local_backend {
            StorageBackend::Local(_) => {}
            _ => panic!("Expected Local backend"),
        }
    }

    #[test]
    fn test_s3_config_creation() {
        let config = S3Config {
            bucket: "my-data-lake".to_string(),
            region: "us-east-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            endpoint: None,
            prefix: None,
        };

        assert_eq!(config.bucket, "my-data-lake");
        assert_eq!(config.region, "us-east-1");
    }

    #[test]
    fn test_tier_paths() {
        let backend = StorageBackend::Local(LocalConfig {
            base_path: "/tmp/test".to_string(),
            max_size_bytes: None,
            retention_days: None,
        });
        let manager = StorageManager::new(backend);

        assert_eq!(manager.get_tier_path(&StorageTier::Hot), "hot");
        assert_eq!(manager.get_tier_path(&StorageTier::Cold), "cold");
    }

    #[test]
    fn test_round_to_bucket() {
        let ts = DateTime::parse_from_rfc3339("2024-01-15T10:27:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let rounded = round_to_bucket(ts, 5); // 5-minute buckets
        assert_eq!(rounded.minute(), 25);
    }
}
