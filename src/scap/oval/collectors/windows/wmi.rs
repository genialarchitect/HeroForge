//! Windows WMI OVAL Collector
//!
//! Collects WMI query results for OVAL evaluation.

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};
use super::{WindowsCollector, CollectionContext, CloneCollector, generate_item_id};

/// WMI query collector
#[derive(Debug, Clone)]
pub struct WmiCollector;

impl WmiCollector {
    pub fn new() -> Self {
        Self
    }

    /// Build PowerShell script to execute WMI query
    fn build_wmi_script(&self, namespace: &str, wql: &str) -> String {
        format!(
            r#"
$results = @()
try {{
    $query = Get-CimInstance -Namespace '{}' -Query '{}' -ErrorAction Stop
    foreach ($item in $query) {{
        $props = @{{}}
        foreach ($prop in $item.CimInstanceProperties) {{
            $props[$prop.Name] = $prop.Value
        }}
        $props['__exists'] = $true
        $results += $props
    }}
    if ($results.Count -eq 0) {{
        @{{ __exists = $false; __namespace = '{}'; __wql = '{}' }} | ConvertTo-Json -Compress
    }} else {{
        $results | ConvertTo-Json -Compress -Depth 3
    }}
}} catch {{
    @{{
        __exists = $false
        __namespace = '{}'
        __wql = '{}'
        __error = $_.Exception.Message
    }} | ConvertTo-Json -Compress
}}
"#,
            namespace, wql, namespace, wql, namespace, wql
        )
    }

    /// Build PowerShell script using CIM cmdlets (preferred)
    fn build_cim_script(&self, class_name: &str, namespace: &str, filter: Option<&str>) -> String {
        let filter_part = if let Some(f) = filter {
            format!("-Filter \"{}\"", f)
        } else {
            String::new()
        };

        format!(
            r#"
$results = @()
try {{
    $items = Get-CimInstance -ClassName '{}' -Namespace '{}' {} -ErrorAction Stop
    foreach ($item in $items) {{
        $props = @{{}}
        foreach ($prop in $item.CimInstanceProperties) {{
            $props[$prop.Name] = $prop.Value
        }}
        $props['__exists'] = $true
        $props['__class'] = '{}'
        $results += $props
    }}
    if ($results.Count -eq 0) {{
        @{{ __exists = $false; __class = '{}'; __namespace = '{}' }} | ConvertTo-Json -Compress
    }} else {{
        $results | ConvertTo-Json -Compress -Depth 3
    }}
}} catch {{
    @{{
        __exists = $false
        __class = '{}'
        __namespace = '{}'
        __error = $_.Exception.Message
    }} | ConvertTo-Json -Compress
}}
"#,
            class_name, namespace, filter_part,
            class_name, class_name, namespace,
            class_name, namespace
        )
    }

    /// Build item from JSON result
    fn build_item(&self, json: &serde_json::Value) -> Option<OvalItem> {
        let exists = json.get("__exists").and_then(|v| v.as_bool()).unwrap_or(false);

        if !exists {
            let mut data = HashMap::new();
            if let Some(ns) = json.get("__namespace").and_then(|v| v.as_str()) {
                data.insert("namespace".to_string(), OvalValue::String(ns.to_string()));
            }
            if let Some(wql) = json.get("__wql").and_then(|v| v.as_str()) {
                data.insert("wql".to_string(), OvalValue::String(wql.to_string()));
            }
            if let Some(class) = json.get("__class").and_then(|v| v.as_str()) {
                data.insert("class".to_string(), OvalValue::String(class.to_string()));
            }

            return Some(OvalItem {
                id: generate_item_id(),
                status: ItemStatus::DoesNotExist,
                item_type: ObjectType::WinWmi,
                data,
            });
        }

        let mut data = HashMap::new();

        // Add all properties from the WMI result
        if let Some(obj) = json.as_object() {
            for (key, value) in obj {
                // Skip internal metadata fields
                if key.starts_with("__") {
                    continue;
                }

                let oval_value = match value {
                    serde_json::Value::Null => continue,
                    serde_json::Value::Bool(b) => OvalValue::Boolean(*b),
                    serde_json::Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            OvalValue::Int(i)
                        } else if let Some(f) = n.as_f64() {
                            OvalValue::Float(f)
                        } else {
                            OvalValue::String(n.to_string())
                        }
                    }
                    serde_json::Value::String(s) => OvalValue::String(s.clone()),
                    serde_json::Value::Array(arr) => {
                        let items: Vec<OvalValue> = arr.iter()
                            .filter_map(|v| v.as_str().map(|s| OvalValue::String(s.to_string())))
                            .collect();
                        OvalValue::List(items)
                    }
                    serde_json::Value::Object(_) => OvalValue::String(value.to_string()),
                };

                data.insert(key.to_lowercase(), oval_value);
            }
        }

        Some(OvalItem {
            id: generate_item_id(),
            status: ItemStatus::Exists,
            item_type: ObjectType::WinWmi,
            data,
        })
    }
}

impl Default for WmiCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WindowsCollector for WmiCollector {
    async fn collect(&self, object: &OvalObject, context: &CollectionContext) -> Result<Vec<OvalItem>> {
        // Check if we have credentials configured
        if !context.has_credentials() {
            log::warn!("No WinRM credentials configured, skipping WMI collection");
            return Ok(vec![]);
        }

        // Extract WMI object parameters
        let namespace = object.data.get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or(r"root\cimv2");

        let wql = object.data.get("wql")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Build the PowerShell script
        let script = self.build_wmi_script(namespace, wql);

        // Execute via WinRM
        let output = match context.execute_script(&script).await {
            Ok(out) => out,
            Err(e) => {
                log::warn!("Failed to execute WMI collection script: {}", e);
                return Ok(vec![]);
            }
        };

        // Parse the JSON output
        let json: serde_json::Value = match serde_json::from_str(&output) {
            Ok(j) => j,
            Err(e) => {
                log::warn!("Failed to parse WMI collection output: {}", e);
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
        vec![ObjectType::WinWmi]
    }
}

impl CloneCollector for WmiCollector {
    fn clone_collector(&self) -> Box<dyn CloneCollector> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_wmi_script() {
        let collector = WmiCollector::new();

        let script = collector.build_wmi_script(
            r"root\cimv2",
            "SELECT * FROM Win32_OperatingSystem",
        );
        assert!(script.contains("Get-CimInstance"));
        assert!(script.contains("Win32_OperatingSystem"));
    }

    #[test]
    fn test_build_cim_script() {
        let collector = WmiCollector::new();

        // Without filter
        let script = collector.build_cim_script(
            "Win32_Service",
            r"root\cimv2",
            None,
        );
        assert!(script.contains("Get-CimInstance"));
        assert!(script.contains("Win32_Service"));
        assert!(!script.contains("-Filter"));

        // With filter
        let script = collector.build_cim_script(
            "Win32_Service",
            r"root\cimv2",
            Some("Name='wuauserv'"),
        );
        assert!(script.contains("-Filter"));
        assert!(script.contains("wuauserv"));
    }
}
