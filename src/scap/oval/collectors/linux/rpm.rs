//! RPM Package OVAL Collector
//!
//! Collects installed RPM package information for OVAL evaluation (RHEL, CentOS, Fedora, etc).

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};
use super::{LinuxCollector, CloneLinuxCollector, generate_item_id};
use super::super::unix::{UnixCollector, UnixCollectionContext, CloneUnixCollector};

/// RPM package info collector
#[derive(Debug, Clone)]
pub struct RpmInfoCollector;

impl RpmInfoCollector {
    pub fn new() -> Self {
        Self
    }

    /// Build command to query rpm for package information
    fn build_rpm_query(&self, package_name: Option<&str>) -> String {
        // Query format: name, epoch, version, release, arch, signature_keyid
        // %{EPOCH} might be "(none)" if not set
        let format = r#"%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SIGPGP:pgpsig}\n"#;

        if let Some(name) = package_name {
            // Query specific package
            format!(
                "rpm -q --qf '{}' '{}' 2>/dev/null || echo 'not_installed'",
                format,
                name.replace('\'', "'\\''")
            )
        } else {
            // Query all packages
            format!("rpm -qa --qf '{}'", format)
        }
    }

    /// Build command to check if rpm is available
    fn build_check_command(&self) -> String {
        "command -v rpm >/dev/null 2>&1 && echo 'available' || echo 'unavailable'".to_string()
    }

    /// Build command to get extended package info (for filepaths check)
    fn build_extended_query(&self, package_name: &str) -> String {
        format!(
            "rpm -q --qf '%{{FILENAMES}}\\n' '{}' 2>/dev/null | head -20",
            package_name.replace('\'', "'\\''")
        )
    }

    /// Parse rpm query output line into OvalItem
    fn parse_rpm_line(&self, line: &str) -> Option<OvalItem> {
        if line == "not_installed" || line.is_empty() || line.contains("is not installed") {
            return None;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 5 {
            return None;
        }

        let name = parts[0];
        let epoch_str = parts[1];
        let version = parts[2];
        let release = parts[3];
        let arch = parts[4];
        let signature = if parts.len() > 5 { parts[5] } else { "" };

        // Parse epoch (might be "(none)" or empty)
        let epoch = if epoch_str == "(none)" || epoch_str.is_empty() {
            0
        } else {
            epoch_str.parse::<i32>().unwrap_or(0)
        };

        // Build EVR string
        let evr = if epoch > 0 {
            format!("{}:{}-{}", epoch, version, release)
        } else {
            format!("{}-{}", version, release)
        };

        let mut data = HashMap::new();
        data.insert("name".to_string(), OvalValue::String(name.to_string()));
        data.insert("arch".to_string(), OvalValue::String(arch.to_string()));
        data.insert("epoch".to_string(), OvalValue::Int(epoch as i64));
        data.insert("version".to_string(), OvalValue::String(version.to_string()));
        data.insert("release".to_string(), OvalValue::String(release.to_string()));
        data.insert("evr".to_string(), OvalValue::String(evr));

        // Parse signature key ID if present
        if !signature.is_empty() && signature != "(none)" {
            // Extract key ID from signature string
            // Format typically like "RSA/SHA256, Tue 01 Jan 2024, Key ID abc123..."
            if let Some(idx) = signature.find("Key ID") {
                let key_id = signature[idx + 7..].trim().split_whitespace().next().unwrap_or("");
                data.insert("signature_keyid".to_string(), OvalValue::String(key_id.to_string()));
            }
        }

        Some(OvalItem {
            id: generate_item_id(),
            status: ItemStatus::Exists,
            item_type: ObjectType::LinuxRpmInfo,
            data,
        })
    }
}

impl Default for RpmInfoCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UnixCollector for RpmInfoCollector {
    async fn collect(&self, object: &OvalObject, context: &UnixCollectionContext) -> Result<Vec<OvalItem>> {
        if !context.has_credentials() {
            log::warn!("No SSH credentials configured, skipping rpm collection");
            return Ok(vec![]);
        }

        // Check if rpm is available
        let check_cmd = self.build_check_command();
        let check_result = match context.execute_command(&check_cmd).await {
            Ok(out) => out.trim().to_string(),
            Err(e) => {
                log::warn!("Failed to check rpm availability: {}", e);
                return Ok(vec![]);
            }
        };

        if check_result != "available" {
            log::debug!("rpm not available on target system");
            return Ok(vec![]);
        }

        // Extract package name from object
        let package_name = object.data.get("name")
            .and_then(|v| v.as_str());

        // Build and execute the rpm query
        let command = self.build_rpm_query(package_name);
        let output = match context.execute_command(&command).await {
            Ok(out) => out,
            Err(e) => {
                log::warn!("Failed to execute rpm query: {}", e);
                return Ok(vec![]);
            }
        };

        // Parse output
        let mut items = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                if let Some(item) = self.parse_rpm_line(trimmed) {
                    items.push(item);
                }
            }
        }

        // Check for filepath matching if specified
        if let Some(filepath) = object.data.get("filepath").and_then(|v| v.as_str()) {
            // Filter items to only those providing the specified file
            let cmd = format!("rpm -qf '{}' 2>/dev/null || echo 'none'", filepath.replace('\'', "'\\''"));
            if let Ok(pkg_output) = context.execute_command(&cmd).await {
                let providing_pkg = pkg_output.trim();
                if providing_pkg != "none" && !providing_pkg.contains("not owned by any package") {
                    // Get just the package name (without version)
                    let pkg_name = providing_pkg.split('-').take(1).collect::<String>();
                    items.retain(|item| {
                        if let Some(OvalValue::String(name)) = item.data.get("name") {
                            name == providing_pkg || providing_pkg.starts_with(name)
                        } else {
                            false
                        }
                    });
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
                item_type: ObjectType::LinuxRpmInfo,
                data,
            });
        }

        Ok(items)
    }

    fn supported_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::LinuxRpmInfo]
    }
}

#[async_trait]
impl LinuxCollector for RpmInfoCollector {
    async fn is_supported(&self, context: &UnixCollectionContext) -> bool {
        let check_cmd = self.build_check_command();
        context.execute_command(&check_cmd).await
            .map(|out| out.trim() == "available")
            .unwrap_or(false)
    }
}

impl CloneUnixCollector for RpmInfoCollector {
    fn clone_collector(&self) -> Box<dyn CloneUnixCollector> {
        Box::new(self.clone())
    }
}

impl CloneLinuxCollector for RpmInfoCollector {
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
    fn test_parse_rpm_line() {
        let collector = RpmInfoCollector::new();

        // Package with epoch
        let line = "kernel\t5\t5.14.0\t362.24.1.el9_3\tx86_64\t(none)";
        let item = collector.parse_rpm_line(line);
        assert!(item.is_some());

        let item = item.unwrap();
        assert_eq!(item.status, ItemStatus::Exists);

        if let Some(OvalValue::String(name)) = item.data.get("name") {
            assert_eq!(name, "kernel");
        }

        if let Some(OvalValue::Int(epoch)) = item.data.get("epoch") {
            assert_eq!(*epoch, 5);
        }

        // Package without epoch
        let line = "openssl\t(none)\t3.0.7\t25.el9_3\tx86_64\t(none)";
        let item = collector.parse_rpm_line(line);
        assert!(item.is_some());

        let item = item.unwrap();
        if let Some(OvalValue::Int(epoch)) = item.data.get("epoch") {
            assert_eq!(*epoch, 0);
        }
    }

    #[test]
    fn test_build_rpm_query() {
        let collector = RpmInfoCollector::new();

        // Specific package
        let cmd = collector.build_rpm_query(Some("openssl"));
        assert!(cmd.contains("rpm -q"));
        assert!(cmd.contains("openssl"));

        // All packages
        let cmd = collector.build_rpm_query(None);
        assert!(cmd.contains("rpm -qa"));
    }

    #[test]
    fn test_not_installed() {
        let collector = RpmInfoCollector::new();

        let line = "not_installed";
        let item = collector.parse_rpm_line(line);
        assert!(item.is_none());

        let line = "package foo is not installed";
        let item = collector.parse_rpm_line(line);
        assert!(item.is_none());
    }
}
