use anyhow::Result;
use std::path::Path;
use tokio::fs;

use crate::reports::types::ReportData;

/// Generate a JSON report
pub async fn generate(data: &ReportData, reports_dir: &str) -> Result<(String, i64)> {
    // Ensure reports directory exists
    fs::create_dir_all(reports_dir).await?;

    // Generate filename
    let filename = format!("{}.json", data.id);
    let file_path = Path::new(reports_dir).join(&filename);

    // Serialize to pretty JSON
    let json_content = serde_json::to_string_pretty(data)?;

    // Write to file
    fs::write(&file_path, &json_content).await?;

    let file_size = json_content.len() as i64;
    let path_str = file_path.to_string_lossy().to_string();

    Ok((path_str, file_size))
}
