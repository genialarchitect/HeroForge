//! Windows Service OVAL Collector
//!
//! Collects Windows service information for OVAL evaluation.

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};
use super::{WindowsCollector, CollectionContext, CloneCollector, generate_item_id};

/// Windows service collector
#[derive(Debug, Clone)]
pub struct ServiceCollector;

impl ServiceCollector {
    pub fn new() -> Self {
        Self
    }

    /// Build PowerShell script to query services
    fn build_service_script(&self, service_name: Option<&str>) -> String {
        let filter = if let Some(name) = service_name {
            format!("-Name '{}'", name)
        } else {
            String::new()
        };

        format!(
            r#"
$results = @()
try {{
    $services = Get-Service {} -ErrorAction Stop
    foreach ($svc in $services) {{
        $wmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue

        $results += @{{
            service_name = $svc.Name
            display_name = $svc.DisplayName
            service_type = $svc.ServiceType.ToString()
            start_type = $svc.StartType.ToString()
            current_state = $svc.Status.ToString()
            path = if ($wmi) {{ $wmi.PathName }} else {{ '' }}
            pid = if ($wmi) {{ $wmi.ProcessId }} else {{ 0 }}
            service_account = if ($wmi) {{ $wmi.StartName }} else {{ '' }}
            description = if ($wmi) {{ $wmi.Description }} else {{ '' }}
            dependencies = @($svc.DependentServices.Name)
            exists = $true
        }}
    }}
    if ($results.Count -eq 0) {{
        @{{ exists = $false; service_name = '{}' }} | ConvertTo-Json -Compress
    }} else {{
        $results | ConvertTo-Json -Compress -Depth 2
    }}
}} catch {{
    @{{
        exists = $false
        service_name = '{}'
        error = $_.Exception.Message
    }} | ConvertTo-Json -Compress
}}
"#,
            filter,
            service_name.unwrap_or(""),
            service_name.unwrap_or("")
        )
    }

    /// Build PowerShell script to get service security info
    fn build_service_security_script(&self, service_name: &str) -> String {
        format!(
            r#"
try {{
    $svc = Get-Service -Name '{}' -ErrorAction Stop
    $wmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='{}'" -ErrorAction Stop

    # Get service security descriptor using sc.exe
    $sd = (sc.exe sdshow {}) -join ''

    @{{
        service_name = $svc.Name
        display_name = $svc.DisplayName
        current_state = $svc.Status.ToString()
        start_type = $svc.StartType.ToString()
        path = $wmi.PathName
        service_account = $wmi.StartName
        security_descriptor = $sd
        exists = $true
    }} | ConvertTo-Json -Compress
}} catch {{
    @{{
        exists = $false
        service_name = '{}'
        error = $_.Exception.Message
    }} | ConvertTo-Json -Compress
}}
"#,
            service_name, service_name, service_name, service_name
        )
    }

    /// Build item from JSON result
    fn build_item(&self, json: &serde_json::Value) -> Option<OvalItem> {
        let exists = json.get("exists").and_then(|v| v.as_bool()).unwrap_or(false);

        if !exists {
            let mut data = HashMap::new();
            if let Some(name) = json.get("service_name").and_then(|v| v.as_str()) {
                data.insert("service_name".to_string(), OvalValue::String(name.to_string()));
            }

            return Some(OvalItem {
                id: generate_item_id(),
                status: ItemStatus::DoesNotExist,
                item_type: ObjectType::WinService,
                data,
            });
        }

        let mut data = HashMap::new();

        // Service name (required)
        data.insert("service_name".to_string(), OvalValue::String(
            json.get("service_name").and_then(|v| v.as_str()).unwrap_or("").to_string()
        ));

        // Display name
        if let Some(val) = json.get("display_name").and_then(|v| v.as_str()) {
            data.insert("display_name".to_string(), OvalValue::String(val.to_string()));
        }

        // Service type
        if let Some(val) = json.get("service_type").and_then(|v| v.as_str()) {
            data.insert("service_type".to_string(), OvalValue::String(val.to_string()));
        }

        // Start type
        if let Some(val) = json.get("start_type").and_then(|v| v.as_str()) {
            data.insert("start_type".to_string(), OvalValue::String(val.to_string()));
        }

        // Current state
        if let Some(val) = json.get("current_state").and_then(|v| v.as_str()) {
            data.insert("current_state".to_string(), OvalValue::String(val.to_string()));
        }

        // Path
        if let Some(val) = json.get("path").and_then(|v| v.as_str()) {
            data.insert("path".to_string(), OvalValue::String(val.to_string()));
        }

        // PID
        if let Some(pid) = json.get("pid").and_then(|v| v.as_i64()) {
            data.insert("pid".to_string(), OvalValue::Int(pid));
        }

        // Service account
        if let Some(val) = json.get("service_account").and_then(|v| v.as_str()) {
            data.insert("service_account".to_string(), OvalValue::String(val.to_string()));
        }

        // Description
        if let Some(val) = json.get("description").and_then(|v| v.as_str()) {
            data.insert("description".to_string(), OvalValue::String(val.to_string()));
        }

        // Dependencies
        if let Some(deps) = json.get("dependencies").and_then(|v| v.as_array()) {
            let dep_list: Vec<OvalValue> = deps
                .iter()
                .filter_map(|v| v.as_str().map(|s| OvalValue::String(s.to_string())))
                .collect();
            if !dep_list.is_empty() {
                data.insert("dependencies".to_string(), OvalValue::List(dep_list));
            }
        }

        // Security descriptor
        if let Some(val) = json.get("security_descriptor").and_then(|v| v.as_str()) {
            data.insert("security_descriptor".to_string(), OvalValue::String(val.to_string()));
        }

        Some(OvalItem {
            id: generate_item_id(),
            status: ItemStatus::Exists,
            item_type: ObjectType::WinService,
            data,
        })
    }
}

impl Default for ServiceCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WindowsCollector for ServiceCollector {
    async fn collect(&self, object: &OvalObject, _context: &CollectionContext) -> Result<Vec<OvalItem>> {
        // Extract service object parameters
        let service_name = object.data.get("service_name")
            .and_then(|v| v.as_str());

        // Build the PowerShell script
        let _script = self.build_service_script(service_name);

        // In a real implementation, we would execute this script via WinRM
        // For now, return empty result as placeholder
        // TODO: Integrate with WinRM client from scanner/windows_audit

        Ok(vec![])
    }

    fn supported_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::WinService]
    }
}

impl CloneCollector for ServiceCollector {
    fn clone_collector(&self) -> Box<dyn CloneCollector> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_service_script() {
        let collector = ServiceCollector::new();

        // With specific service
        let script = collector.build_service_script(Some("wuauserv"));
        assert!(script.contains("Get-Service"));
        assert!(script.contains("wuauserv"));
        assert!(script.contains("-Name"));

        // All services
        let script = collector.build_service_script(None);
        assert!(script.contains("Get-Service"));
        assert!(!script.contains("-Name"));
    }

    #[test]
    fn test_build_service_security_script() {
        let collector = ServiceCollector::new();

        let script = collector.build_service_security_script("Spooler");
        assert!(script.contains("sc.exe sdshow"));
        assert!(script.contains("Spooler"));
    }
}
