//! Unix File OVAL Collector
//!
//! Collects file information for OVAL evaluation on Unix/Linux systems.

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};
use super::{UnixCollector, UnixCollectionContext, CloneUnixCollector, generate_item_id};

/// Unix file collector
#[derive(Debug, Clone)]
pub struct FileCollector;

impl FileCollector {
    pub fn new() -> Self {
        Self
    }

    /// Build shell command to query file information using stat and ls
    fn build_file_command(&self, path: &str, filename: Option<&str>, recurse: bool) -> String {
        let target_path = if let Some(fname) = filename {
            format!("{}/{}", path.trim_end_matches('/'), fname)
        } else {
            path.to_string()
        };

        let find_opts = if recurse {
            format!("find '{}' -type f", target_path)
        } else {
            format!("find '{}' -maxdepth 1 -type f", target_path)
        };

        // Use stat to get detailed file information in a parseable format
        // %n = filename, %s = size, %U = owner user, %G = owner group
        // %a = access permissions (octal), %Y = mtime epoch, %X = atime epoch, %W = ctime epoch
        // %F = file type
        format!(
            r#"
{} 2>/dev/null | while read filepath; do
    if [ -e "$filepath" ]; then
        stat_out=$(stat --printf='%n\t%s\t%U\t%G\t%a\t%Y\t%X\t%W\t%F\n' "$filepath" 2>/dev/null)
        sha256=$(sha256sum "$filepath" 2>/dev/null | cut -d' ' -f1)
        echo "$stat_out\t$sha256"
    fi
done
"#,
            find_opts
        )
    }

    /// Build command to check file existence
    fn build_existence_command(&self, path: &str, filename: Option<&str>) -> String {
        let target_path = if let Some(fname) = filename {
            format!("{}/{}", path.trim_end_matches('/'), fname)
        } else {
            path.to_string()
        };

        format!("test -e '{}' && echo 'exists' || echo 'not_exists'", target_path)
    }

    /// Parse stat output line into OvalItem
    fn parse_stat_line(&self, line: &str, base_path: &str) -> Option<OvalItem> {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 9 {
            return None;
        }

        let filepath = parts[0];
        let size = parts[1].parse::<i64>().unwrap_or(0);
        let owner = parts[2];
        let group = parts[3];
        let permissions = parts[4];
        let mtime = parts[5];
        let atime = parts[6];
        let ctime = parts[7];
        let file_type = parts[8];
        let sha256 = if parts.len() > 9 { parts[9] } else { "" };

        // Extract filename from filepath
        let filename = std::path::Path::new(filepath)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // Extract directory path
        let dir_path = std::path::Path::new(filepath)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or(base_path);

        let mut data = HashMap::new();
        data.insert("filepath".to_string(), OvalValue::String(filepath.to_string()));
        data.insert("path".to_string(), OvalValue::String(dir_path.to_string()));
        data.insert("filename".to_string(), OvalValue::String(filename.to_string()));
        data.insert("type".to_string(), OvalValue::String(file_type.to_string()));
        data.insert("owner".to_string(), OvalValue::String(owner.to_string()));
        data.insert("group".to_string(), OvalValue::String(group.to_string()));
        data.insert("size".to_string(), OvalValue::Int(size));

        // Convert octal permissions to int
        if let Ok(perm) = i64::from_str_radix(permissions, 8) {
            data.insert("permissions".to_string(), OvalValue::Int(perm));
        }

        // Timestamps (Unix epoch)
        if let Ok(mt) = mtime.parse::<i64>() {
            data.insert("m_time".to_string(), OvalValue::Int(mt));
        }
        if let Ok(at) = atime.parse::<i64>() {
            data.insert("a_time".to_string(), OvalValue::Int(at));
        }
        if let Ok(ct) = ctime.parse::<i64>() {
            data.insert("c_time".to_string(), OvalValue::Int(ct));
        }

        // SHA256 hash if available
        if !sha256.is_empty() && sha256.len() == 64 {
            data.insert("sha256".to_string(), OvalValue::String(sha256.to_string()));
        }

        Some(OvalItem {
            id: generate_item_id(),
            status: ItemStatus::Exists,
            item_type: ObjectType::UnixFile,
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
impl UnixCollector for FileCollector {
    async fn collect(&self, object: &OvalObject, context: &UnixCollectionContext) -> Result<Vec<OvalItem>> {
        if !context.has_credentials() {
            log::warn!("No SSH credentials configured, skipping file collection");
            return Ok(vec![]);
        }

        // Extract file object parameters
        let path = object.data.get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if path.is_empty() {
            log::warn!("No path specified in file object");
            return Ok(vec![]);
        }

        let filename = object.data.get("filename")
            .and_then(|v| v.as_str());

        let recurse = object.data.get("behaviors")
            .and_then(|v| v.get("recurse_direction"))
            .and_then(|v| v.as_str())
            .map(|s| s == "down")
            .unwrap_or(false);

        // First check if path exists
        let existence_cmd = self.build_existence_command(path, filename);
        let existence_result = match context.execute_command(&existence_cmd).await {
            Ok(out) => out.trim().to_string(),
            Err(e) => {
                log::warn!("Failed to check file existence: {}", e);
                return Ok(vec![]);
            }
        };

        if existence_result == "not_exists" {
            let mut data = HashMap::new();
            data.insert("path".to_string(), OvalValue::String(path.to_string()));
            if let Some(fname) = filename {
                data.insert("filename".to_string(), OvalValue::String(fname.to_string()));
            }

            return Ok(vec![OvalItem {
                id: generate_item_id(),
                status: ItemStatus::DoesNotExist,
                item_type: ObjectType::UnixFile,
                data,
            }]);
        }

        // Build and execute the file collection command
        let command = self.build_file_command(path, filename, recurse);
        let output = match context.execute_command(&command).await {
            Ok(out) => out,
            Err(e) => {
                log::warn!("Failed to execute file collection command: {}", e);
                return Ok(vec![]);
            }
        };

        // Parse output
        let mut items = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                if let Some(item) = self.parse_stat_line(trimmed, path) {
                    items.push(item);
                }
            }
        }

        // If no items but path exists, create a single not-collected item
        if items.is_empty() {
            let mut data = HashMap::new();
            data.insert("path".to_string(), OvalValue::String(path.to_string()));
            if let Some(fname) = filename {
                data.insert("filename".to_string(), OvalValue::String(fname.to_string()));
            }

            items.push(OvalItem {
                id: generate_item_id(),
                status: ItemStatus::NotCollected,
                item_type: ObjectType::UnixFile,
                data,
            });
        }

        Ok(items)
    }

    fn supported_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::UnixFile]
    }
}

impl CloneUnixCollector for FileCollector {
    fn clone_collector(&self) -> Box<dyn CloneUnixCollector> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_file_command() {
        let collector = FileCollector::new();

        // Test with specific filename
        let cmd = collector.build_file_command("/etc", Some("passwd"), false);
        assert!(cmd.contains("find"));
        assert!(cmd.contains("/etc/passwd"));
        assert!(cmd.contains("-maxdepth 1"));

        // Test with recursion
        let cmd = collector.build_file_command("/etc", None, true);
        assert!(cmd.contains("find"));
        assert!(!cmd.contains("-maxdepth"));
    }

    #[test]
    fn test_parse_stat_line() {
        let collector = FileCollector::new();

        let line = "/etc/passwd\t2048\troot\troot\t644\t1704067200\t1704067200\t1704067200\tregular file\tabc123...";
        let item = collector.parse_stat_line(line, "/etc");

        assert!(item.is_some());
        let item = item.unwrap();
        assert_eq!(item.item_type, ObjectType::UnixFile);
        assert_eq!(item.status, ItemStatus::Exists);

        if let Some(OvalValue::String(fp)) = item.data.get("filepath") {
            assert_eq!(fp, "/etc/passwd");
        } else {
            panic!("Expected filepath");
        }
    }
}
