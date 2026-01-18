//! Windows Lockout Policy OVAL Collector
//!
//! Collects Windows account lockout policy settings for OVAL evaluation.

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};
use super::{WindowsCollector, CollectionContext, CloneCollector, generate_item_id};

/// Windows lockout policy collector
#[derive(Debug, Clone)]
pub struct LockoutPolicyCollector;

impl LockoutPolicyCollector {
    pub fn new() -> Self {
        Self
    }

    /// Build PowerShell script to query lockout policy
    fn build_lockout_policy_script(&self) -> String {
        r#"
try {
    # Export security policy to temp file
    $tempFile = [System.IO.Path]::GetTempFileName()
    secedit /export /cfg $tempFile /areas SECURITYPOLICY 2>$null | Out-Null

    $content = Get-Content $tempFile -Raw
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

    # Parse the INI-style content
    $policy = @{
        lockout_threshold = 0
        lockout_duration = 0
        reset_lockout_counter = 0
    }

    foreach ($line in $content -split "`n") {
        if ($line -match '^LockoutBadCount\s*=\s*(\d+)') {
            $policy.lockout_threshold = [int]$Matches[1]
        }
        elseif ($line -match '^LockoutDuration\s*=\s*(-?\d+)') {
            $policy.lockout_duration = [int]$Matches[1]
        }
        elseif ($line -match '^ResetLockoutCount\s*=\s*(\d+)') {
            $policy.reset_lockout_counter = [int]$Matches[1]
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
        if ($line -match 'Lockout threshold:\s*(\d+|Never)') {
            $policy['lockout_threshold'] = if ($Matches[1] -eq 'Never') { 0 } else { [int]$Matches[1] }
        }
        elseif ($line -match 'Lockout duration \(minutes\):\s*(\d+)') {
            $policy['lockout_duration'] = [int]$Matches[1]
        }
        elseif ($line -match 'Lockout observation window \(minutes\):\s*(\d+)') {
            $policy['reset_lockout_counter'] = [int]$Matches[1]
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
                item_type: ObjectType::WinLockoutPolicy,
                data: HashMap::new(),
            });
        }

        let mut data = HashMap::new();

        // Lockout threshold (number of failed attempts)
        if let Some(val) = json.get("lockout_threshold").and_then(|v| v.as_i64()) {
            data.insert("lockout_threshold".to_string(), OvalValue::Int(val));
        }

        // Lockout duration (minutes, 0 = until admin unlocks)
        if let Some(val) = json.get("lockout_duration").and_then(|v| v.as_i64()) {
            data.insert("lockout_duration".to_string(), OvalValue::Int(val));
        }

        // Reset lockout counter after (minutes)
        if let Some(val) = json.get("reset_lockout_counter").and_then(|v| v.as_i64()) {
            data.insert("reset_lockout_counter".to_string(), OvalValue::Int(val));
        }

        Some(OvalItem {
            id: generate_item_id(),
            status: ItemStatus::Exists,
            item_type: ObjectType::WinLockoutPolicy,
            data,
        })
    }
}

impl Default for LockoutPolicyCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WindowsCollector for LockoutPolicyCollector {
    async fn collect(&self, _object: &OvalObject, context: &CollectionContext) -> Result<Vec<OvalItem>> {
        // Check if we have credentials configured
        if !context.has_credentials() {
            log::warn!("No WinRM credentials configured, skipping lockout policy collection");
            return Ok(vec![]);
        }

        let script = self.build_lockout_policy_script();

        // Execute via WinRM
        let output = match context.execute_script(&script).await {
            Ok(out) => out,
            Err(e) => {
                log::warn!("Failed to execute lockout policy collection script: {}", e);
                return Ok(vec![]);
            }
        };

        // Parse the JSON output
        let json: serde_json::Value = match serde_json::from_str(&output) {
            Ok(j) => j,
            Err(e) => {
                log::warn!("Failed to parse lockout policy collection output: {}", e);
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
        vec![ObjectType::WinLockoutPolicy]
    }
}

impl CloneCollector for LockoutPolicyCollector {
    fn clone_collector(&self) -> Box<dyn CloneCollector> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_lockout_policy_script() {
        let collector = LockoutPolicyCollector::new();
        let script = collector.build_lockout_policy_script();
        assert!(script.contains("secedit"));
        assert!(script.contains("LockoutBadCount"));
        assert!(script.contains("LockoutDuration"));
        assert!(script.contains("ResetLockoutCount"));
    }

    #[test]
    fn test_build_net_accounts_script() {
        let collector = LockoutPolicyCollector::new();
        let script = collector.build_net_accounts_script();
        assert!(script.contains("net accounts"));
        assert!(script.contains("Lockout threshold"));
        assert!(script.contains("Lockout duration"));
    }

    #[test]
    fn test_build_item() {
        let collector = LockoutPolicyCollector::new();

        let json = serde_json::json!({
            "exists": true,
            "lockout_threshold": 3,
            "lockout_duration": 15,
            "reset_lockout_counter": 15
        });

        let item = collector.build_item(&json).unwrap();
        assert_eq!(item.status, ItemStatus::Exists);

        match item.data.get("lockout_threshold") {
            Some(OvalValue::Int(val)) => assert_eq!(*val, 3),
            _ => panic!("Expected Int"),
        }

        match item.data.get("lockout_duration") {
            Some(OvalValue::Int(val)) => assert_eq!(*val, 15),
            _ => panic!("Expected Int"),
        }
    }

    #[test]
    fn test_build_item_not_exists() {
        let collector = LockoutPolicyCollector::new();

        let json = serde_json::json!({
            "exists": false,
            "error": "Access denied"
        });

        let item = collector.build_item(&json).unwrap();
        assert_eq!(item.status, ItemStatus::DoesNotExist);
    }
}
