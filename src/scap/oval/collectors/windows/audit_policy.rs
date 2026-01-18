//! Windows Audit Policy OVAL Collector
//!
//! Collects Windows audit policy settings for OVAL evaluation.

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};
use super::{WindowsCollector, CollectionContext, CloneCollector, generate_item_id};

/// Windows audit policy collector
#[derive(Debug, Clone)]
pub struct AuditPolicyCollector;

impl AuditPolicyCollector {
    pub fn new() -> Self {
        Self
    }

    /// Build PowerShell script to query audit policy
    fn build_audit_policy_script(&self) -> String {
        r#"
$results = @{}
try {
    # Get basic audit policy using auditpol
    $auditpol = auditpol /get /category:* /r 2>$null
    $csv = $auditpol | ConvertFrom-Csv

    foreach ($row in $csv) {
        $category = $row.'Subcategory'
        $setting = $row.'Inclusion Setting'

        $results[$category] = @{
            subcategory = $category
            setting = $setting
            audit_success = $setting -match 'Success'
            audit_failure = $setting -match 'Failure'
        }
    }

    @{
        exists = $true
        policies = $results
    } | ConvertTo-Json -Compress -Depth 3
} catch {
    @{
        exists = $false
        error = $_.Exception.Message
    } | ConvertTo-Json -Compress
}
"#.to_string()
    }

    /// Build PowerShell script to query specific audit subcategory
    fn build_subcategory_script(&self, subcategory: &str) -> String {
        format!(
            r#"
try {{
    $auditpol = auditpol /get /subcategory:"{}" /r 2>$null
    $csv = $auditpol | ConvertFrom-Csv
    $row = $csv | Select-Object -First 1

    if ($row) {{
        @{{
            subcategory = $row.'Subcategory'
            setting = $row.'Inclusion Setting'
            audit_success = $row.'Inclusion Setting' -match 'Success'
            audit_failure = $row.'Inclusion Setting' -match 'Failure'
            exists = $true
        }} | ConvertTo-Json -Compress
    }} else {{
        @{{
            subcategory = '{}'
            exists = $false
        }} | ConvertTo-Json -Compress
    }}
}} catch {{
    @{{
        subcategory = '{}'
        exists = $false
        error = $_.Exception.Message
    }} | ConvertTo-Json -Compress
}}
"#,
            subcategory, subcategory, subcategory
        )
    }

    /// Build PowerShell script for audit event policy (specific events)
    fn build_audit_event_script(&self) -> String {
        r#"
$policies = @{}
try {
    # Account Logon
    $policies['credential_validation'] = (auditpol /get /subcategory:"Credential Validation" /r | ConvertFrom-Csv).'Inclusion Setting'

    # Account Management
    $policies['user_account_management'] = (auditpol /get /subcategory:"User Account Management" /r | ConvertFrom-Csv).'Inclusion Setting'
    $policies['security_group_management'] = (auditpol /get /subcategory:"Security Group Management" /r | ConvertFrom-Csv).'Inclusion Setting'

    # Logon/Logoff
    $policies['logon'] = (auditpol /get /subcategory:"Logon" /r | ConvertFrom-Csv).'Inclusion Setting'
    $policies['logoff'] = (auditpol /get /subcategory:"Logoff" /r | ConvertFrom-Csv).'Inclusion Setting'
    $policies['special_logon'] = (auditpol /get /subcategory:"Special Logon" /r | ConvertFrom-Csv).'Inclusion Setting'

    # Object Access
    $policies['file_system'] = (auditpol /get /subcategory:"File System" /r | ConvertFrom-Csv).'Inclusion Setting'
    $policies['registry'] = (auditpol /get /subcategory:"Registry" /r | ConvertFrom-Csv).'Inclusion Setting'

    # Policy Change
    $policies['audit_policy_change'] = (auditpol /get /subcategory:"Audit Policy Change" /r | ConvertFrom-Csv).'Inclusion Setting'
    $policies['authentication_policy_change'] = (auditpol /get /subcategory:"Authentication Policy Change" /r | ConvertFrom-Csv).'Inclusion Setting'

    # Privilege Use
    $policies['sensitive_privilege_use'] = (auditpol /get /subcategory:"Sensitive Privilege Use" /r | ConvertFrom-Csv).'Inclusion Setting'

    # System
    $policies['security_state_change'] = (auditpol /get /subcategory:"Security State Change" /r | ConvertFrom-Csv).'Inclusion Setting'
    $policies['security_system_extension'] = (auditpol /get /subcategory:"Security System Extension" /r | ConvertFrom-Csv).'Inclusion Setting'

    @{
        exists = $true
        policies = $policies
    } | ConvertTo-Json -Compress -Depth 2
} catch {
    @{
        exists = $false
        error = $_.Exception.Message
    } | ConvertTo-Json -Compress
}
"#.to_string()
    }

    /// Build item from JSON result
    fn build_item(&self, json: &serde_json::Value) -> Option<OvalItem> {
        let exists = json.get("exists").and_then(|v| v.as_bool()).unwrap_or(false);

        if !exists {
            let mut data = HashMap::new();
            if let Some(subcat) = json.get("subcategory").and_then(|v| v.as_str()) {
                data.insert("subcategory".to_string(), OvalValue::String(subcat.to_string()));
            }

            return Some(OvalItem {
                id: generate_item_id(),
                status: ItemStatus::DoesNotExist,
                item_type: ObjectType::WinAuditEventPolicy,
                data,
            });
        }

        // Single subcategory result
        if json.get("subcategory").is_some() {
            let mut data = HashMap::new();

            data.insert("subcategory".to_string(), OvalValue::String(
                json.get("subcategory").and_then(|v| v.as_str()).unwrap_or("").to_string()
            ));

            if let Some(setting) = json.get("setting").and_then(|v| v.as_str()) {
                data.insert("setting".to_string(), OvalValue::String(setting.to_string()));
            }

            if let Some(val) = json.get("audit_success").and_then(|v| v.as_bool()) {
                data.insert("audit_success".to_string(), OvalValue::Boolean(val));
            }

            if let Some(val) = json.get("audit_failure").and_then(|v| v.as_bool()) {
                data.insert("audit_failure".to_string(), OvalValue::Boolean(val));
            }

            return Some(OvalItem {
                id: generate_item_id(),
                status: ItemStatus::Exists,
                item_type: ObjectType::WinAuditEventPolicy,
                data,
            });
        }

        // Multiple policies - handled separately
        None
    }

    /// Build multiple items from policies result
    fn build_items_from_policies(&self, json: &serde_json::Value) -> Vec<OvalItem> {
        let mut items = Vec::new();

        if let Some(policies) = json.get("policies").and_then(|v| v.as_object()) {
            for (key, value) in policies {
                let mut data = HashMap::new();
                data.insert("subcategory".to_string(), OvalValue::String(key.clone()));

                if let Some(setting) = value.get("setting").and_then(|v| v.as_str()) {
                    data.insert("setting".to_string(), OvalValue::String(setting.to_string()));
                } else if let Some(setting) = value.as_str() {
                    data.insert("setting".to_string(), OvalValue::String(setting.to_string()));
                }

                if let Some(val) = value.get("audit_success").and_then(|v| v.as_bool()) {
                    data.insert("audit_success".to_string(), OvalValue::Boolean(val));
                }

                if let Some(val) = value.get("audit_failure").and_then(|v| v.as_bool()) {
                    data.insert("audit_failure".to_string(), OvalValue::Boolean(val));
                }

                items.push(OvalItem {
                    id: generate_item_id(),
                    status: ItemStatus::Exists,
                    item_type: ObjectType::WinAuditEventPolicy,
                    data,
                });
            }
        }

        items
    }
}

impl Default for AuditPolicyCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WindowsCollector for AuditPolicyCollector {
    async fn collect(&self, object: &OvalObject, context: &CollectionContext) -> Result<Vec<OvalItem>> {
        // Check if we have credentials configured
        if !context.has_credentials() {
            log::warn!("No WinRM credentials configured, skipping audit policy collection");
            return Ok(vec![]);
        }

        // Check if a specific subcategory is requested
        let script = if let Some(subcategory) = object.data.get("auditeventpolicy")
            .and_then(|v| v.as_str())
        {
            self.build_subcategory_script(subcategory)
        } else {
            self.build_audit_policy_script()
        };

        // Execute via WinRM
        let output = match context.execute_script(&script).await {
            Ok(out) => out,
            Err(e) => {
                log::warn!("Failed to execute audit policy collection script: {}", e);
                return Ok(vec![]);
            }
        };

        // Parse the JSON output
        let json: serde_json::Value = match serde_json::from_str(&output) {
            Ok(j) => j,
            Err(e) => {
                log::warn!("Failed to parse audit policy collection output: {}", e);
                return Ok(vec![]);
            }
        };

        // Build items from the result
        if json.get("policies").is_some() {
            // Multiple policies returned
            Ok(self.build_items_from_policies(&json))
        } else if let Some(item) = self.build_item(&json) {
            Ok(vec![item])
        } else {
            Ok(vec![])
        }
    }

    fn supported_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::WinAuditEventPolicy]
    }
}

impl CloneCollector for AuditPolicyCollector {
    fn clone_collector(&self) -> Box<dyn CloneCollector> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_audit_policy_script() {
        let collector = AuditPolicyCollector::new();
        let script = collector.build_audit_policy_script();
        assert!(script.contains("auditpol"));
        assert!(script.contains("/get"));
        assert!(script.contains("/category:*"));
    }

    #[test]
    fn test_build_subcategory_script() {
        let collector = AuditPolicyCollector::new();
        let script = collector.build_subcategory_script("Logon");
        assert!(script.contains("/subcategory:"));
        assert!(script.contains("Logon"));
    }

    #[test]
    fn test_build_audit_event_script() {
        let collector = AuditPolicyCollector::new();
        let script = collector.build_audit_event_script();
        assert!(script.contains("credential_validation"));
        assert!(script.contains("user_account_management"));
        assert!(script.contains("logon"));
    }
}
