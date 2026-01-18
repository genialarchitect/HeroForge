//! Unix Uname OVAL Collector
//!
//! Collects system uname information for OVAL evaluation on Unix/Linux systems.

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};
use super::{UnixCollector, UnixCollectionContext, CloneUnixCollector, generate_item_id};

/// Unix uname collector
#[derive(Debug, Clone)]
pub struct UnameCollector;

impl UnameCollector {
    pub fn new() -> Self {
        Self
    }

    /// Build shell command to get all uname information
    fn build_uname_command(&self) -> String {
        // Collect all uname fields in a structured format
        r#"
echo "machine_class:$(uname -m)"
echo "node_name:$(uname -n)"
echo "os_name:$(uname -s)"
echo "os_release:$(uname -r)"
echo "os_version:$(uname -v)"
echo "processor_type:$(uname -p 2>/dev/null || echo 'unknown')"
"#.to_string()
    }

    /// Parse uname output into OvalItem
    fn parse_uname_output(&self, output: &str) -> OvalItem {
        let mut data = HashMap::new();

        for line in output.lines() {
            let trimmed = line.trim();
            if let Some((key, value)) = trimmed.split_once(':') {
                let value = value.trim();
                match key {
                    "machine_class" => {
                        data.insert("machine_class".to_string(), OvalValue::String(value.to_string()));
                    }
                    "node_name" => {
                        data.insert("node_name".to_string(), OvalValue::String(value.to_string()));
                    }
                    "os_name" => {
                        data.insert("os_name".to_string(), OvalValue::String(value.to_string()));
                    }
                    "os_release" => {
                        data.insert("os_release".to_string(), OvalValue::String(value.to_string()));
                    }
                    "os_version" => {
                        data.insert("os_version".to_string(), OvalValue::String(value.to_string()));
                    }
                    "processor_type" => {
                        data.insert("processor_type".to_string(), OvalValue::String(value.to_string()));
                    }
                    _ => {}
                }
            }
        }

        OvalItem {
            id: generate_item_id(),
            status: if data.is_empty() { ItemStatus::Error } else { ItemStatus::Exists },
            item_type: ObjectType::UnixUname,
            data,
        }
    }
}

impl Default for UnameCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UnixCollector for UnameCollector {
    async fn collect(&self, _object: &OvalObject, context: &UnixCollectionContext) -> Result<Vec<OvalItem>> {
        if !context.has_credentials() {
            log::warn!("No SSH credentials configured, skipping uname collection");
            return Ok(vec![]);
        }

        // Build and execute the uname command
        let command = self.build_uname_command();
        let output = match context.execute_command(&command).await {
            Ok(out) => out,
            Err(e) => {
                log::warn!("Failed to execute uname collection command: {}", e);
                return Ok(vec![OvalItem {
                    id: generate_item_id(),
                    status: ItemStatus::Error,
                    item_type: ObjectType::UnixUname,
                    data: HashMap::new(),
                }]);
            }
        };

        // Parse and return single uname item
        Ok(vec![self.parse_uname_output(&output)])
    }

    fn supported_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::UnixUname]
    }
}

impl CloneUnixCollector for UnameCollector {
    fn clone_collector(&self) -> Box<dyn CloneUnixCollector> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uname_output() {
        let collector = UnameCollector::new();

        let output = r#"
machine_class:x86_64
node_name:myhost
os_name:Linux
os_release:5.15.0-91-generic
os_version:#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023
processor_type:x86_64
"#;

        let item = collector.parse_uname_output(output);
        assert_eq!(item.status, ItemStatus::Exists);
        assert_eq!(item.item_type, ObjectType::UnixUname);

        if let Some(OvalValue::String(os)) = item.data.get("os_name") {
            assert_eq!(os, "Linux");
        } else {
            panic!("Expected os_name");
        }

        if let Some(OvalValue::String(arch)) = item.data.get("machine_class") {
            assert_eq!(arch, "x86_64");
        } else {
            panic!("Expected machine_class");
        }
    }
}
