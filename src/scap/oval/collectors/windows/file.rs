//! Windows File OVAL Collector
//!
//! Collects file information for OVAL evaluation.

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};
use super::{WindowsCollector, CollectionContext, CloneCollector, generate_item_id};

/// Windows file collector
#[derive(Debug, Clone)]
pub struct FileCollector;

impl FileCollector {
    pub fn new() -> Self {
        Self
    }

    /// Build PowerShell script to query file information
    fn build_file_script(&self, path: &str, filename: Option<&str>, recurse: bool) -> String {
        let full_path = if let Some(fname) = filename {
            format!("{}\\{}", path, fname)
        } else {
            path.to_string()
        };

        let recurse_flag = if recurse { "-Recurse" } else { "" };

        format!(
            r#"
$results = @()
try {{
    $items = Get-ChildItem -Path '{}' {} -ErrorAction Stop | Where-Object {{ -not $_.PSIsContainer }}
    foreach ($item in $items) {{
        $acl = Get-Acl -Path $item.FullName -ErrorAction SilentlyContinue
        $hash = Get-FileHash -Path $item.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue

        $results += @{{
            filepath = $item.FullName
            path = $item.DirectoryName
            filename = $item.Name
            type = 'file'
            owner = if ($acl) {{ $acl.Owner }} else {{ 'Unknown' }}
            size = $item.Length
            a_time = $item.LastAccessTime.ToString('o')
            c_time = $item.CreationTime.ToString('o')
            m_time = $item.LastWriteTime.ToString('o')
            attributes = $item.Attributes.ToString()
            sha256 = if ($hash) {{ $hash.Hash }} else {{ '' }}
            exists = $true
        }}
    }}
    $results | ConvertTo-Json -Compress -Depth 2
}} catch {{
    @{{
        path = '{}'
        filename = '{}'
        exists = $false
        error = $_.Exception.Message
    }} | ConvertTo-Json -Compress
}}
"#,
            full_path,
            recurse_flag,
            path,
            filename.unwrap_or("")
        )
    }

    /// Build PowerShell script to check file existence only
    fn build_existence_script(&self, path: &str, filename: Option<&str>) -> String {
        let full_path = if let Some(fname) = filename {
            format!("{}\\{}", path, fname)
        } else {
            path.to_string()
        };

        format!(
            r#"
$exists = Test-Path -Path '{}'
@{{
    path = '{}'
    filename = '{}'
    exists = $exists
}} | ConvertTo-Json -Compress
"#,
            full_path,
            path,
            filename.unwrap_or("")
        )
    }

    /// Build item from JSON result
    fn build_item(&self, json: &serde_json::Value) -> Option<OvalItem> {
        let exists = json.get("exists").and_then(|v| v.as_bool()).unwrap_or(false);

        if !exists {
            let mut data = HashMap::new();
            data.insert("path".to_string(), OvalValue::String(
                json.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string()
            ));
            if let Some(filename) = json.get("filename").and_then(|v| v.as_str()) {
                data.insert("filename".to_string(), OvalValue::String(filename.to_string()));
            }

            return Some(OvalItem {
                id: generate_item_id(),
                status: ItemStatus::DoesNotExist,
                item_type: ObjectType::WinFile,
                data,
            });
        }

        let mut data = HashMap::new();

        // Required fields
        data.insert("filepath".to_string(), OvalValue::String(
            json.get("filepath").and_then(|v| v.as_str()).unwrap_or("").to_string()
        ));
        data.insert("path".to_string(), OvalValue::String(
            json.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string()
        ));
        data.insert("filename".to_string(), OvalValue::String(
            json.get("filename").and_then(|v| v.as_str()).unwrap_or("").to_string()
        ));
        data.insert("type".to_string(), OvalValue::String(
            json.get("type").and_then(|v| v.as_str()).unwrap_or("file").to_string()
        ));
        data.insert("owner".to_string(), OvalValue::String(
            json.get("owner").and_then(|v| v.as_str()).unwrap_or("").to_string()
        ));

        // Size
        if let Some(size) = json.get("size").and_then(|v| v.as_i64()) {
            data.insert("size".to_string(), OvalValue::Int(size));
        }

        // Timestamps
        for field in &["a_time", "c_time", "m_time"] {
            if let Some(val) = json.get(*field).and_then(|v| v.as_str()) {
                data.insert(field.to_string(), OvalValue::String(val.to_string()));
            }
        }

        // Attributes
        if let Some(attrs) = json.get("attributes").and_then(|v| v.as_str()) {
            data.insert("attributes".to_string(), OvalValue::String(attrs.to_string()));
        }

        // Hash
        if let Some(hash) = json.get("sha256").and_then(|v| v.as_str()) {
            if !hash.is_empty() {
                data.insert("sha256".to_string(), OvalValue::String(hash.to_string()));
            }
        }

        Some(OvalItem {
            id: generate_item_id(),
            status: ItemStatus::Exists,
            item_type: ObjectType::WinFile,
            data,
        })
    }
}

impl Default for FileCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WindowsCollector for FileCollector {
    async fn collect(&self, object: &OvalObject, context: &CollectionContext) -> Result<Vec<OvalItem>> {
        // Check if we have credentials configured
        if !context.has_credentials() {
            log::warn!("No WinRM credentials configured, skipping file collection");
            return Ok(vec![]);
        }

        // Extract file object parameters
        let path = object.data.get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let filename = object.data.get("filename")
            .and_then(|v| v.as_str());

        let recurse = object.data.get("behaviors")
            .and_then(|v| v.get("recurse_direction"))
            .and_then(|v| v.as_str())
            .map(|s| s == "down")
            .unwrap_or(false);

        // Build the PowerShell script
        let script = self.build_file_script(path, filename, recurse);

        // Execute via WinRM
        let output = match context.execute_script(&script).await {
            Ok(out) => out,
            Err(e) => {
                log::warn!("Failed to execute file collection script: {}", e);
                return Ok(vec![]);
            }
        };

        // Parse the JSON output
        let json: serde_json::Value = match serde_json::from_str(&output) {
            Ok(j) => j,
            Err(e) => {
                log::warn!("Failed to parse file collection output: {}", e);
                return Ok(vec![]);
            }
        };

        // Handle single result vs array
        let mut items = Vec::new();
        if let Some(arr) = json.as_array() {
            for item in arr {
                if let Some(oval_item) = self.build_item(item) {
                    items.push(oval_item);
                }
            }
        } else if let Some(item) = self.build_item(&json) {
            items.push(item);
        }

        Ok(items)
    }

    fn supported_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::WinFile]
    }
}

impl CloneCollector for FileCollector {
    fn clone_collector(&self) -> Box<dyn CloneCollector> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_file_script() {
        let collector = FileCollector::new();

        // Test with specific filename
        let script = collector.build_file_script(
            r"C:\Windows\System32",
            Some("cmd.exe"),
            false,
        );
        assert!(script.contains("Get-ChildItem"));
        assert!(script.contains("cmd.exe"));
        assert!(!script.contains("-Recurse"));

        // Test with recursion
        let script = collector.build_file_script(
            r"C:\Windows",
            None,
            true,
        );
        assert!(script.contains("-Recurse"));
    }

    #[test]
    fn test_build_existence_script() {
        let collector = FileCollector::new();

        let script = collector.build_existence_script(
            r"C:\Windows\System32",
            Some("notepad.exe"),
        );
        assert!(script.contains("Test-Path"));
        assert!(script.contains("notepad.exe"));
    }
}
