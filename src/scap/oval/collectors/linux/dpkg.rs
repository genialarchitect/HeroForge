//! Debian Package (dpkg) OVAL Collector
//!
//! Collects installed Debian/Ubuntu package information for OVAL evaluation.

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};
use super::{LinuxCollector, CloneLinuxCollector, generate_item_id};
use super::super::unix::{UnixCollector, UnixCollectionContext, CloneUnixCollector};

/// Debian package info collector
#[derive(Debug, Clone)]
pub struct DpkgInfoCollector;

impl DpkgInfoCollector {
    pub fn new() -> Self {
        Self
    }

    /// Build command to query dpkg for package information
    fn build_dpkg_query(&self, package_name: Option<&str>) -> String {
        // Query format: name, version, architecture, status
        // Using dpkg-query with custom format
        let format = r#"${Package}\t${Version}\t${Architecture}\t${Status}\n"#;

        if let Some(name) = package_name {
            // Query specific package
            format!(
                "dpkg-query -W -f '{}' '{}' 2>/dev/null || echo 'not_installed'",
                format,
                name.replace('\'', "'\\''")
            )
        } else {
            // Query all packages
            format!("dpkg-query -W -f '{}'", format)
        }
    }

    /// Build command to check if dpkg is available
    fn build_check_command(&self) -> String {
        "command -v dpkg-query >/dev/null 2>&1 && echo 'available' || echo 'unavailable'".to_string()
    }

    /// Parse dpkg-query output line into OvalItem
    fn parse_dpkg_line(&self, line: &str) -> Option<OvalItem> {
        if line == "not_installed" || line.is_empty() {
            return None;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 4 {
            return None;
        }

        let name = parts[0];
        let version = parts[1];
        let arch = parts[2];
        let status = parts[3];

        // Only consider installed packages (status contains "install ok installed")
        let is_installed = status.contains("install ok installed") ||
                           status.contains("install ok config-files");

        if !is_installed && !status.contains("install") {
            return None;
        }

        // Parse version into epoch, version, release (Debian format: [epoch:]version[-revision])
        let (epoch, ver, release) = parse_debian_version(version);

        let mut data = HashMap::new();
        data.insert("name".to_string(), OvalValue::String(name.to_string()));
        data.insert("arch".to_string(), OvalValue::String(arch.to_string()));
        data.insert("epoch".to_string(), OvalValue::Int(epoch as i64));
        data.insert("version".to_string(), OvalValue::String(ver));
        data.insert("release".to_string(), OvalValue::String(release));
        data.insert("evr".to_string(), OvalValue::String(version.to_string()));

        Some(OvalItem {
            id: generate_item_id(),
            status: if is_installed { ItemStatus::Exists } else { ItemStatus::DoesNotExist },
            item_type: ObjectType::LinuxDpkgInfo,
            data,
        })
    }
}

/// Parse Debian version string into (epoch, version, release)
/// Format: [epoch:]upstream_version[-debian_revision]
fn parse_debian_version(version: &str) -> (i32, String, String) {
    let (epoch, rest) = if let Some(idx) = version.find(':') {
        let epoch = version[..idx].parse::<i32>().unwrap_or(0);
        (epoch, &version[idx + 1..])
    } else {
        (0, version)
    };

    let (ver, release) = if let Some(idx) = rest.rfind('-') {
        (rest[..idx].to_string(), rest[idx + 1..].to_string())
    } else {
        (rest.to_string(), String::new())
    };

    (epoch, ver, release)
}

impl Default for DpkgInfoCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UnixCollector for DpkgInfoCollector {
    async fn collect(&self, object: &OvalObject, context: &UnixCollectionContext) -> Result<Vec<OvalItem>> {
        if !context.has_credentials() {
            log::warn!("No SSH credentials configured, skipping dpkg collection");
            return Ok(vec![]);
        }

        // Check if dpkg is available
        let check_cmd = self.build_check_command();
        let check_result = match context.execute_command(&check_cmd).await {
            Ok(out) => out.trim().to_string(),
            Err(e) => {
                log::warn!("Failed to check dpkg availability: {}", e);
                return Ok(vec![]);
            }
        };

        if check_result != "available" {
            log::debug!("dpkg not available on target system");
            return Ok(vec![]);
        }

        // Extract package name from object
        let package_name = object.data.get("name")
            .and_then(|v| v.as_str());

        // Build and execute the dpkg query
        let command = self.build_dpkg_query(package_name);
        let output = match context.execute_command(&command).await {
            Ok(out) => out,
            Err(e) => {
                log::warn!("Failed to execute dpkg query: {}", e);
                return Ok(vec![]);
            }
        };

        // Parse output
        let mut items = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                if let Some(item) = self.parse_dpkg_line(trimmed) {
                    items.push(item);
                }
            }
        }

        // If searching for specific package and not found
        if package_name.is_some() && items.is_empty() {
            let mut data = HashMap::new();
            data.insert("name".to_string(), OvalValue::String(
                package_name.unwrap_or_default().to_string()
            ));

            items.push(OvalItem {
                id: generate_item_id(),
                status: ItemStatus::DoesNotExist,
                item_type: ObjectType::LinuxDpkgInfo,
                data,
            });
        }

        Ok(items)
    }

    fn supported_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::LinuxDpkgInfo]
    }
}

#[async_trait]
impl LinuxCollector for DpkgInfoCollector {
    async fn is_supported(&self, context: &UnixCollectionContext) -> bool {
        let check_cmd = self.build_check_command();
        context.execute_command(&check_cmd).await
            .map(|out| out.trim() == "available")
            .unwrap_or(false)
    }
}

impl CloneUnixCollector for DpkgInfoCollector {
    fn clone_collector(&self) -> Box<dyn CloneUnixCollector> {
        Box::new(self.clone())
    }
}

impl CloneLinuxCollector for DpkgInfoCollector {
    fn clone_collector(&self) -> Box<dyn CloneLinuxCollector> {
        Box::new(self.clone())
    }

    fn as_linux_collector(&self) -> &dyn LinuxCollector {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_debian_version() {
        // Simple version
        let (epoch, ver, rel) = parse_debian_version("1.0.0");
        assert_eq!(epoch, 0);
        assert_eq!(ver, "1.0.0");
        assert_eq!(rel, "");

        // With release
        let (epoch, ver, rel) = parse_debian_version("1.0.0-1ubuntu1");
        assert_eq!(epoch, 0);
        assert_eq!(ver, "1.0.0");
        assert_eq!(rel, "1ubuntu1");

        // With epoch
        let (epoch, ver, rel) = parse_debian_version("2:1.0.0-1");
        assert_eq!(epoch, 2);
        assert_eq!(ver, "1.0.0");
        assert_eq!(rel, "1");
    }

    #[test]
    fn test_parse_dpkg_line() {
        let collector = DpkgInfoCollector::new();

        // Installed package
        let line = "openssl\t3.0.2-0ubuntu1.12\tamd64\tinstall ok installed";
        let item = collector.parse_dpkg_line(line);
        assert!(item.is_some());

        let item = item.unwrap();
        assert_eq!(item.status, ItemStatus::Exists);

        if let Some(OvalValue::String(name)) = item.data.get("name") {
            assert_eq!(name, "openssl");
        } else {
            panic!("Expected name");
        }
    }

    #[test]
    fn test_build_dpkg_query() {
        let collector = DpkgInfoCollector::new();

        // Specific package
        let cmd = collector.build_dpkg_query(Some("openssl"));
        assert!(cmd.contains("dpkg-query"));
        assert!(cmd.contains("openssl"));

        // All packages
        let cmd = collector.build_dpkg_query(None);
        assert!(cmd.contains("dpkg-query"));
        assert!(!cmd.contains("openssl"));
    }
}
