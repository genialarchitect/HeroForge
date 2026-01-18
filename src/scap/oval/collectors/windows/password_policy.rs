//! Windows Password Policy OVAL Collector
//!
//! Collects Windows password policy settings for OVAL evaluation.

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};
use super::{WindowsCollector, CollectionContext, CloneCollector, generate_item_id};

/// Windows password policy collector
#[derive(Debug, Clone)]
pub struct PasswordPolicyCollector;

impl PasswordPolicyCollector {
    pub fn new() -> Self {
        Self
    }

    /// Build PowerShell script to query password policy
    fn build_password_policy_script(&self) -> String {
        r#"
try {
    # Export security policy to temp file
    $tempFile = [System.IO.Path]::GetTempFileName()
    secedit /export /cfg $tempFile /areas SECURITYPOLICY 2>$null | Out-Null

    $content = Get-Content $tempFile -Raw
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

    # Parse the INI-style content
    $policy = @{
        min_password_length = 0
        password_history_length = 0
        max_password_age = 0
        min_password_age = 0
        password_complexity = $false
        reversible_encryption = $false
    }

    foreach ($line in $content -split "`n") {
        if ($line -match '^MinimumPasswordLength\s*=\s*(\d+)') {
            $policy.min_password_length = [int]$Matches[1]
        }
        elseif ($line -match '^PasswordHistorySize\s*=\s*(\d+)') {
            $policy.password_history_length = [int]$Matches[1]
        }
        elseif ($line -match '^MaximumPasswordAge\s*=\s*(-?\d+)') {
            $policy.max_password_age = [int]$Matches[1]
        }
        elseif ($line -match '^MinimumPasswordAge\s*=\s*(\d+)') {
            $policy.min_password_age = [int]$Matches[1]
        }
        elseif ($line -match '^PasswordComplexity\s*=\s*(\d+)') {
            $policy.password_complexity = ([int]$Matches[1] -eq 1)
        }
        elseif ($line -match '^ClearTextPassword\s*=\s*(\d+)') {
            $policy.reversible_encryption = ([int]$Matches[1] -eq 1)
        }
    }

    $policy['exists'] = $true
    $policy | ConvertTo-Json -Compress
} catch {
    @{
        exists = $false
        error = $_.Exception.Message
    } | ConvertTo-Json -Compress
}
"#.to_string()
    }

    /// Build PowerShell script using net accounts
    fn build_net_accounts_script(&self) -> String {
        r#"
try {
    $output = net accounts
    $policy = @{
        exists = $true
    }

    foreach ($line in $output) {
        if ($line -match 'Minimum password length:\s*(\d+)') {
            $policy['min_password_length'] = [int]$Matches[1]
        }
        elseif ($line -match 'Length of password history maintained:\s*(\d+|None)') {
            $policy['password_history_length'] = if ($Matches[1] -eq 'None') { 0 } else { [int]$Matches[1] }
        }
        elseif ($line -match 'Maximum password age \(days\):\s*(\d+|Unlimited)') {
            $policy['max_password_age'] = if ($Matches[1] -eq 'Unlimited') { -1 } else { [int]$Matches[1] }
        }
        elseif ($line -match 'Minimum password age \(days\):\s*(\d+)') {
            $policy['min_password_age'] = [int]$Matches[1]
        }
    }

    $policy | ConvertTo-Json -Compress
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
            return Some(OvalItem {
                id: generate_item_id(),
                status: ItemStatus::DoesNotExist,
                item_type: ObjectType::WinPasswordPolicy,
                data: HashMap::new(),
            });
        }

        let mut data = HashMap::new();

        // Minimum password length
        if let Some(val) = json.get("min_password_length").and_then(|v| v.as_i64()) {
            data.insert("min_password_length".to_string(), OvalValue::Int(val));
        }

        // Password history length
        if let Some(val) = json.get("password_history_length").and_then(|v| v.as_i64()) {
            data.insert("password_history_length".to_string(), OvalValue::Int(val));
        }

        // Maximum password age
        if let Some(val) = json.get("max_password_age").and_then(|v| v.as_i64()) {
            data.insert("max_password_age".to_string(), OvalValue::Int(val));
        }

        // Minimum password age
        if let Some(val) = json.get("min_password_age").and_then(|v| v.as_i64()) {
            data.insert("min_password_age".to_string(), OvalValue::Int(val));
        }

        // Password complexity
        if let Some(val) = json.get("password_complexity").and_then(|v| v.as_bool()) {
            data.insert("password_complexity".to_string(), OvalValue::Boolean(val));
        }

        // Reversible encryption
        if let Some(val) = json.get("reversible_encryption").and_then(|v| v.as_bool()) {
            data.insert("reversible_encryption".to_string(), OvalValue::Boolean(val));
        }

        Some(OvalItem {
            id: generate_item_id(),
            status: ItemStatus::Exists,
            item_type: ObjectType::WinPasswordPolicy,
            data,
        })
    }
}

impl Default for PasswordPolicyCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WindowsCollector for PasswordPolicyCollector {
    async fn collect(&self, _object: &OvalObject, context: &CollectionContext) -> Result<Vec<OvalItem>> {
        // Check if we have credentials configured
        if !context.has_credentials() {
            log::warn!("No WinRM credentials configured, skipping password policy collection");
            return Ok(vec![]);
        }

        let script = self.build_password_policy_script();

        // Execute via WinRM
        let output = match context.execute_script(&script).await {
            Ok(out) => out,
            Err(e) => {
                log::warn!("Failed to execute password policy collection script: {}", e);
                return Ok(vec![]);
            }
        };

        // Parse the JSON output
        let json: serde_json::Value = match serde_json::from_str(&output) {
            Ok(j) => j,
            Err(e) => {
                log::warn!("Failed to parse password policy collection output: {}", e);
                return Ok(vec![]);
            }
        };

        // Build item from result
        if let Some(item) = self.build_item(&json) {
            Ok(vec![item])
        } else {
            Ok(vec![])
        }
    }

    fn supported_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::WinPasswordPolicy]
    }
}

impl CloneCollector for PasswordPolicyCollector {
    fn clone_collector(&self) -> Box<dyn CloneCollector> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_password_policy_script() {
        let collector = PasswordPolicyCollector::new();
        let script = collector.build_password_policy_script();
        assert!(script.contains("secedit"));
        assert!(script.contains("MinimumPasswordLength"));
        assert!(script.contains("PasswordComplexity"));
    }

    #[test]
    fn test_build_net_accounts_script() {
        let collector = PasswordPolicyCollector::new();
        let script = collector.build_net_accounts_script();
        assert!(script.contains("net accounts"));
        assert!(script.contains("Minimum password length"));
    }

    #[test]
    fn test_build_item() {
        let collector = PasswordPolicyCollector::new();

        let json = serde_json::json!({
            "exists": true,
            "min_password_length": 14,
            "password_history_length": 24,
            "max_password_age": 60,
            "min_password_age": 1,
            "password_complexity": true,
            "reversible_encryption": false
        });

        let item = collector.build_item(&json).unwrap();
        assert_eq!(item.status, ItemStatus::Exists);

        match item.data.get("min_password_length") {
            Some(OvalValue::Int(val)) => assert_eq!(*val, 14),
            _ => panic!("Expected Int"),
        }

        match item.data.get("password_complexity") {
            Some(OvalValue::Boolean(val)) => assert!(*val),
            _ => panic!("Expected Boolean"),
        }
    }
}
