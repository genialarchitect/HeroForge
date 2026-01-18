//! Windows Registry OVAL Collector
//!
//! Collects registry keys and values for OVAL evaluation.

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};
use super::{WindowsCollector, CollectionContext, CloneCollector, RegistryHive, generate_item_id, parse_oval_value};

/// Registry key collector
#[derive(Debug, Clone)]
pub struct RegistryCollector;

impl RegistryCollector {
    pub fn new() -> Self {
        Self
    }

    /// Build PowerShell script to query registry
    fn build_registry_script(&self, hive: &str, key: &str, name: Option<&str>) -> String {
        let hive_obj = RegistryHive::from_str(hive)
            .map(|h| h.powershell_path())
            .unwrap_or("HKLM:");

        let full_path = format!("{}\\{}", hive_obj, key);

        if let Some(value_name) = name {
            // Query specific value
            format!(
                r#"
try {{
    $item = Get-ItemProperty -Path '{}' -Name '{}' -ErrorAction Stop
    $prop = Get-ItemPropertyValue -Path '{}' -Name '{}' -ErrorAction Stop
    $regKey = Get-Item -Path '{}' -ErrorAction Stop
    @{{
        hive = '{}'
        key = '{}'
        name = '{}'
        type = ($regKey.GetValueKind('{}')).ToString()
        value = $prop
        exists = $true
    }} | ConvertTo-Json -Compress
}} catch {{
    @{{
        hive = '{}'
        key = '{}'
        name = '{}'
        exists = $false
        error = $_.Exception.Message
    }} | ConvertTo-Json -Compress
}}
"#,
                full_path, value_name, full_path, value_name, full_path, hive, key, value_name, value_name,
                hive, key, value_name
            )
        } else {
            // Query all values in key
            format!(
                r#"
try {{
    $key = Get-Item -Path '{}' -ErrorAction Stop
    $values = @()
    foreach ($name in $key.GetValueNames()) {{
        $values += @{{
            name = $name
            type = ($key.GetValueKind($name)).ToString()
            value = $key.GetValue($name)
        }}
    }}
    @{{
        hive = '{}'
        key = '{}'
        exists = $true
        values = $values
    }} | ConvertTo-Json -Compress -Depth 3
}} catch {{
    @{{
        hive = '{}'
        key = '{}'
        exists = $false
        error = $_.Exception.Message
    }} | ConvertTo-Json -Compress
}}
"#,
                full_path, hive, key, hive, key
            )
        }
    }

    /// Parse registry value type to OVAL value
    fn parse_registry_value(&self, value: &serde_json::Value, reg_type: &str) -> OvalValue {
        match reg_type.to_uppercase().as_str() {
            "DWORD" | "REG_DWORD" => {
                if let Some(n) = value.as_i64() {
                    OvalValue::Int(n)
                } else if let Some(s) = value.as_str() {
                    parse_oval_value(s, "int")
                } else {
                    OvalValue::String(value.to_string())
                }
            }
            "QWORD" | "REG_QWORD" => {
                if let Some(n) = value.as_i64() {
                    OvalValue::Int(n)
                } else if let Some(s) = value.as_str() {
                    parse_oval_value(s, "int")
                } else {
                    OvalValue::String(value.to_string())
                }
            }
            "BINARY" | "REG_BINARY" => {
                if let Some(s) = value.as_str() {
                    parse_oval_value(s, "binary")
                } else {
                    OvalValue::String(value.to_string())
                }
            }
            "MULTISTRING" | "REG_MULTI_SZ" => {
                if let Some(arr) = value.as_array() {
                    let strings: Vec<OvalValue> = arr
                        .iter()
                        .map(|v| OvalValue::String(v.as_str().unwrap_or("").to_string()))
                        .collect();
                    OvalValue::List(strings)
                } else {
                    OvalValue::String(value.to_string())
                }
            }
            _ => {
                // STRING, EXPANDSTRING, etc.
                OvalValue::String(value.as_str().unwrap_or(&value.to_string()).to_string())
            }
        }
    }

    /// Build item from JSON result
    fn build_item(&self, json: &serde_json::Value) -> Option<OvalItem> {
        let exists = json.get("exists").and_then(|v| v.as_bool()).unwrap_or(false);

        if !exists {
            // Return item indicating key/value doesn't exist
            let mut data = HashMap::new();
            data.insert("hive".to_string(), OvalValue::String(
                json.get("hive").and_then(|v| v.as_str()).unwrap_or("").to_string()
            ));
            data.insert("key".to_string(), OvalValue::String(
                json.get("key").and_then(|v| v.as_str()).unwrap_or("").to_string()
            ));
            if let Some(name) = json.get("name").and_then(|v| v.as_str()) {
                data.insert("name".to_string(), OvalValue::String(name.to_string()));
            }

            return Some(OvalItem {
                id: generate_item_id(),
                status: ItemStatus::DoesNotExist,
                item_type: ObjectType::WinRegistry,
                data,
            });
        }

        let hive = json.get("hive").and_then(|v| v.as_str()).unwrap_or("");
        let key = json.get("key").and_then(|v| v.as_str()).unwrap_or("");

        // Check if this is a single value or multiple values
        if let Some(values) = json.get("values").and_then(|v| v.as_array()) {
            // Multiple values - return one item per value
            // This is handled by the caller
            None
        } else {
            // Single value
            let name = json.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let reg_type = json.get("type").and_then(|v| v.as_str()).unwrap_or("String");
            let value = json.get("value").cloned().unwrap_or(serde_json::Value::Null);

            let mut data = HashMap::new();
            data.insert("hive".to_string(), OvalValue::String(hive.to_string()));
            data.insert("key".to_string(), OvalValue::String(key.to_string()));
            data.insert("name".to_string(), OvalValue::String(name.to_string()));
            data.insert("type".to_string(), OvalValue::String(reg_type.to_string()));
            data.insert("value".to_string(), self.parse_registry_value(&value, reg_type));

            Some(OvalItem {
                id: generate_item_id(),
                status: ItemStatus::Exists,
                item_type: ObjectType::WinRegistry,
                data,
            })
        }
    }

    /// Build multiple items from values array
    fn build_items_from_values(&self, json: &serde_json::Value) -> Vec<OvalItem> {
        let hive = json.get("hive").and_then(|v| v.as_str()).unwrap_or("");
        let key = json.get("key").and_then(|v| v.as_str()).unwrap_or("");

        let mut items = Vec::new();

        if let Some(values) = json.get("values").and_then(|v| v.as_array()) {
            for val in values {
                let name = val.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let reg_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("String");
                let value = val.get("value").cloned().unwrap_or(serde_json::Value::Null);

                let mut data = HashMap::new();
                data.insert("hive".to_string(), OvalValue::String(hive.to_string()));
                data.insert("key".to_string(), OvalValue::String(key.to_string()));
                data.insert("name".to_string(), OvalValue::String(name.to_string()));
                data.insert("type".to_string(), OvalValue::String(reg_type.to_string()));
                data.insert("value".to_string(), self.parse_registry_value(&value, reg_type));

                items.push(OvalItem {
                    id: generate_item_id(),
                    status: ItemStatus::Exists,
                    item_type: ObjectType::WinRegistry,
                    data,
                });
            }
        }

        items
    }
}

impl Default for RegistryCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WindowsCollector for RegistryCollector {
    async fn collect(&self, object: &OvalObject, context: &CollectionContext) -> Result<Vec<OvalItem>> {
        // Check if we have credentials configured
        if !context.has_credentials() {
            log::warn!("No WinRM credentials configured, skipping registry collection");
            return Ok(vec![]);
        }

        // Extract registry object parameters
        let hive = object.data.get("hive")
            .and_then(|v| v.as_str())
            .unwrap_or("HKEY_LOCAL_MACHINE");

        let key = object.data.get("key")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let name = object.data.get("name")
            .and_then(|v| v.as_str());

        // Build the PowerShell script
        let script = self.build_registry_script(hive, key, name);

        // Execute via WinRM
        let output = match context.execute_script(&script).await {
            Ok(out) => out,
            Err(e) => {
                log::warn!("Failed to execute registry collection script: {}", e);
                return Ok(vec![]);
            }
        };

        // Parse the JSON output
        let json: serde_json::Value = match serde_json::from_str(&output) {
            Ok(j) => j,
            Err(e) => {
                log::warn!("Failed to parse registry collection output: {}", e);
                return Ok(vec![]);
            }
        };

        // Build items from the result
        if json.get("values").is_some() {
            // Multiple values returned
            Ok(self.build_items_from_values(&json))
        } else if let Some(item) = self.build_item(&json) {
            Ok(vec![item])
        } else {
            Ok(vec![])
        }
    }

    fn supported_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::WinRegistry]
    }
}

impl CloneCollector for RegistryCollector {
    fn clone_collector(&self) -> Box<dyn CloneCollector> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_registry_script() {
        let collector = RegistryCollector::new();

        // Test with specific value name
        let script = collector.build_registry_script(
            "HKLM",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
            Some("ProgramFilesDir"),
        );
        assert!(script.contains("Get-ItemProperty"));
        assert!(script.contains("ProgramFilesDir"));

        // Test without value name (query all values)
        let script = collector.build_registry_script(
            "HKCU",
            "Software\\Microsoft",
            None,
        );
        assert!(script.contains("GetValueNames"));
    }

    #[test]
    fn test_parse_registry_value() {
        let collector = RegistryCollector::new();

        // Test DWORD
        let dword_val = serde_json::json!(42);
        match collector.parse_registry_value(&dword_val, "DWORD") {
            OvalValue::Int(n) => assert_eq!(n, 42),
            _ => panic!("Expected Int"),
        }

        // Test STRING
        let string_val = serde_json::json!("test value");
        match collector.parse_registry_value(&string_val, "String") {
            OvalValue::String(s) => assert_eq!(s, "test value"),
            _ => panic!("Expected String"),
        }

        // Test MULTI_SZ
        let multi_val = serde_json::json!(["a", "b", "c"]);
        match collector.parse_registry_value(&multi_val, "REG_MULTI_SZ") {
            OvalValue::List(l) => assert_eq!(l.len(), 3),
            _ => panic!("Expected List"),
        }
    }
}
