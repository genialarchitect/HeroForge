/// Report file storage utilities

use anyhow::Result;
use std::path::{Path, PathBuf};
use tokio::fs;

/// Default reports directory relative to working directory
pub const DEFAULT_REPORTS_DIR: &str = "./reports";

/// Ensure the reports directory exists
pub async fn ensure_reports_dir(reports_dir: &str) -> Result<PathBuf> {
    let path = Path::new(reports_dir);
    fs::create_dir_all(path).await?;
    Ok(path.to_path_buf())
}

/// Get the full path for a report file
pub fn get_report_path(reports_dir: &str, report_id: &str, extension: &str) -> PathBuf {
    Path::new(reports_dir).join(format!("{}.{}", report_id, extension))
}

/// Check if a report file exists
pub async fn report_exists(file_path: &str) -> bool {
    fs::metadata(file_path).await.is_ok()
}

/// Read a report file
pub async fn read_report(file_path: &str) -> Result<Vec<u8>> {
    let content = fs::read(file_path).await?;
    Ok(content)
}

/// Delete a report file
pub async fn delete_report_file(file_path: &str) -> Result<()> {
    if report_exists(file_path).await {
        fs::remove_file(file_path).await?;
    }
    Ok(())
}

/// Get file size
pub async fn get_file_size(file_path: &str) -> Result<i64> {
    let metadata = fs::metadata(file_path).await?;
    Ok(metadata.len() as i64)
}

/// Clean up expired reports (older than specified days)
pub async fn cleanup_expired_reports(reports_dir: &str, max_age_days: u32) -> Result<usize> {
    use std::time::{Duration, SystemTime};

    let max_age = Duration::from_secs(max_age_days as u64 * 24 * 60 * 60);
    let mut deleted = 0;

    let mut entries = fs::read_dir(reports_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        if let Ok(metadata) = entry.metadata().await {
            if let Ok(modified) = metadata.modified() {
                if let Ok(age) = SystemTime::now().duration_since(modified) {
                    if age > max_age {
                        if fs::remove_file(entry.path()).await.is_ok() {
                            deleted += 1;
                        }
                    }
                }
            }
        }
    }

    Ok(deleted)
}

/// List all reports in directory
pub async fn list_report_files(reports_dir: &str) -> Result<Vec<String>> {
    let mut files = Vec::new();

    let mut entries = fs::read_dir(reports_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        if let Ok(file_type) = entry.file_type().await {
            if file_type.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    files.push(name.to_string());
                }
            }
        }
    }

    Ok(files)
}
