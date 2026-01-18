//! Windows User/Group OVAL Collector
//!
//! Collects user and group information for OVAL evaluation.

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};
use super::{WindowsCollector, CollectionContext, CloneCollector, generate_item_id};

/// Windows user collector
#[derive(Debug, Clone)]
pub struct UserCollector;

impl UserCollector {
    pub fn new() -> Self {
        Self
    }

    /// Build PowerShell script to query users
    fn build_user_script(&self, username: Option<&str>) -> String {
        let filter = if let Some(name) = username {
            format!("| Where-Object {{ $_.Name -eq '{}' }}", name)
        } else {
            String::new()
        };

        format!(
            r#"
$results = @()
try {{
    $users = Get-LocalUser {} -ErrorAction Stop
    foreach ($user in $users) {{
        $groups = (Get-LocalGroup | Where-Object {{
            (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).Name -contains "$env:COMPUTERNAME\$($user.Name)"
        }}).Name

        $results += @{{
            user = $user.Name
            enabled = $user.Enabled
            full_name = $user.FullName
            description = $user.Description
            password_required = $user.PasswordRequired
            password_changeable = $user.UserMayChangePassword
            password_expires = -not $user.PasswordNeverExpires
            password_last_set = if ($user.PasswordLastSet) {{ $user.PasswordLastSet.ToString('o') }} else {{ $null }}
            last_logon = if ($user.LastLogon) {{ $user.LastLogon.ToString('o') }} else {{ $null }}
            account_expires = if ($user.AccountExpires) {{ $user.AccountExpires.ToString('o') }} else {{ $null }}
            groups = $groups
            sid = $user.SID.Value
            exists = $true
        }}
    }}
    if ($results.Count -eq 0) {{
        @{{ exists = $false; user = '{}' }} | ConvertTo-Json -Compress
    }} else {{
        $results | ConvertTo-Json -Compress -Depth 2
    }}
}} catch {{
    @{{
        exists = $false
        user = '{}'
        error = $_.Exception.Message
    }} | ConvertTo-Json -Compress
}}
"#,
            filter,
            username.unwrap_or(""),
            username.unwrap_or("")
        )
    }

    /// Build PowerShell script to query groups
    fn build_group_script(&self, group_name: Option<&str>) -> String {
        let filter = if let Some(name) = group_name {
            format!("-Name '{}'", name)
        } else {
            String::new()
        };

        format!(
            r#"
$results = @()
try {{
    $groups = Get-LocalGroup {} -ErrorAction Stop
    foreach ($group in $groups) {{
        $members = (Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue).Name

        $results += @{{
            group = $group.Name
            description = $group.Description
            sid = $group.SID.Value
            members = $members
            exists = $true
        }}
    }}
    if ($results.Count -eq 0) {{
        @{{ exists = $false; group = '{}' }} | ConvertTo-Json -Compress
    }} else {{
        $results | ConvertTo-Json -Compress -Depth 2
    }}
}} catch {{
    @{{
        exists = $false
        group = '{}'
        error = $_.Exception.Message
    }} | ConvertTo-Json -Compress
}}
"#,
            filter,
            group_name.unwrap_or(""),
            group_name.unwrap_or("")
        )
    }

    /// Build PowerShell script to check group membership
    fn build_membership_script(&self, group: &str, user: &str) -> String {
        format!(
            r#"
try {{
    $members = (Get-LocalGroupMember -Group '{}' -ErrorAction Stop).Name
    $isMember = $members -contains "$env:COMPUTERNAME\{}" -or $members -contains "{}"

    @{{
        group = '{}'
        user = '{}'
        is_member = $isMember
        exists = $true
    }} | ConvertTo-Json -Compress
}} catch {{
    @{{
        group = '{}'
        user = '{}'
        exists = $false
        error = $_.Exception.Message
    }} | ConvertTo-Json -Compress
}}
"#,
            group, user, user, group, user, group, user
        )
    }

    /// Build user item from JSON result
    fn build_user_item(&self, json: &serde_json::Value) -> Option<OvalItem> {
        let exists = json.get("exists").and_then(|v| v.as_bool()).unwrap_or(false);

        if !exists {
            let mut data = HashMap::new();
            if let Some(name) = json.get("user").and_then(|v| v.as_str()) {
                data.insert("user".to_string(), OvalValue::String(name.to_string()));
            }

            return Some(OvalItem {
                id: generate_item_id(),
                status: ItemStatus::DoesNotExist,
                item_type: ObjectType::WinUser,
                data,
            });
        }

        let mut data = HashMap::new();

        // Username (required)
        data.insert("user".to_string(), OvalValue::String(
            json.get("user").and_then(|v| v.as_str()).unwrap_or("").to_string()
        ));

        // Enabled status
        if let Some(val) = json.get("enabled").and_then(|v| v.as_bool()) {
            data.insert("enabled".to_string(), OvalValue::Boolean(val));
        }

        // Full name
        if let Some(val) = json.get("full_name").and_then(|v| v.as_str()) {
            data.insert("full_name".to_string(), OvalValue::String(val.to_string()));
        }

        // Description
        if let Some(val) = json.get("description").and_then(|v| v.as_str()) {
            data.insert("description".to_string(), OvalValue::String(val.to_string()));
        }

        // Password settings
        for field in &["password_required", "password_changeable", "password_expires"] {
            if let Some(val) = json.get(*field).and_then(|v| v.as_bool()) {
                data.insert(field.to_string(), OvalValue::Boolean(val));
            }
        }

        // Timestamps
        for field in &["password_last_set", "last_logon", "account_expires"] {
            if let Some(val) = json.get(*field).and_then(|v| v.as_str()) {
                data.insert(field.to_string(), OvalValue::String(val.to_string()));
            }
        }

        // Groups
        if let Some(groups) = json.get("groups").and_then(|v| v.as_array()) {
            let group_list: Vec<OvalValue> = groups
                .iter()
                .filter_map(|v| v.as_str().map(|s| OvalValue::String(s.to_string())))
                .collect();
            if !group_list.is_empty() {
                data.insert("groups".to_string(), OvalValue::List(group_list));
            }
        }

        // SID
        if let Some(val) = json.get("sid").and_then(|v| v.as_str()) {
            data.insert("sid".to_string(), OvalValue::String(val.to_string()));
        }

        Some(OvalItem {
            id: generate_item_id(),
            status: ItemStatus::Exists,
            item_type: ObjectType::WinUser,
            data,
        })
    }

    /// Build group item from JSON result
    fn build_group_item(&self, json: &serde_json::Value) -> Option<OvalItem> {
        let exists = json.get("exists").and_then(|v| v.as_bool()).unwrap_or(false);

        if !exists {
            let mut data = HashMap::new();
            if let Some(name) = json.get("group").and_then(|v| v.as_str()) {
                data.insert("group".to_string(), OvalValue::String(name.to_string()));
            }

            return Some(OvalItem {
                id: generate_item_id(),
                status: ItemStatus::DoesNotExist,
                item_type: ObjectType::WinGroup,
                data,
            });
        }

        let mut data = HashMap::new();

        // Group name (required)
        data.insert("group".to_string(), OvalValue::String(
            json.get("group").and_then(|v| v.as_str()).unwrap_or("").to_string()
        ));

        // Description
        if let Some(val) = json.get("description").and_then(|v| v.as_str()) {
            data.insert("description".to_string(), OvalValue::String(val.to_string()));
        }

        // SID
        if let Some(val) = json.get("sid").and_then(|v| v.as_str()) {
            data.insert("sid".to_string(), OvalValue::String(val.to_string()));
        }

        // Members
        if let Some(members) = json.get("members").and_then(|v| v.as_array()) {
            let member_list: Vec<OvalValue> = members
                .iter()
                .filter_map(|v| v.as_str().map(|s| OvalValue::String(s.to_string())))
                .collect();
            data.insert("members".to_string(), OvalValue::List(member_list));
        }

        Some(OvalItem {
            id: generate_item_id(),
            status: ItemStatus::Exists,
            item_type: ObjectType::WinGroup,
            data,
        })
    }
}

impl Default for UserCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WindowsCollector for UserCollector {
    async fn collect(&self, object: &OvalObject, context: &CollectionContext) -> Result<Vec<OvalItem>> {
        // Check if we have credentials configured
        if !context.has_credentials() {
            log::warn!("No WinRM credentials configured, skipping user/group collection");
            return Ok(vec![]);
        }

        let script = match object.object_type {
            ObjectType::WinUser => {
                let username = object.data.get("user")
                    .and_then(|v| v.as_str());
                self.build_user_script(username)
            }
            ObjectType::WinGroup => {
                let group_name = object.data.get("group")
                    .and_then(|v| v.as_str());
                self.build_group_script(group_name)
            }
            _ => return Ok(vec![]),
        };

        // Execute via WinRM
        let output = match context.execute_script(&script).await {
            Ok(out) => out,
            Err(e) => {
                log::warn!("Failed to execute user/group collection script: {}", e);
                return Ok(vec![]);
            }
        };

        // Parse the JSON output
        let json: serde_json::Value = match serde_json::from_str(&output) {
            Ok(j) => j,
            Err(e) => {
                log::warn!("Failed to parse user/group collection output: {}", e);
                return Ok(vec![]);
            }
        };

        // Build items based on object type
        let mut items = Vec::new();
        let is_user = object.object_type == ObjectType::WinUser;

        if let Some(arr) = json.as_array() {
            for item in arr {
                let oval_item = if is_user {
                    self.build_user_item(item)
                } else {
                    self.build_group_item(item)
                };
                if let Some(i) = oval_item {
                    items.push(i);
                }
            }
        } else {
            let oval_item = if is_user {
                self.build_user_item(&json)
            } else {
                self.build_group_item(&json)
            };
            if let Some(i) = oval_item {
                items.push(i);
            }
        }

        Ok(items)
    }

    fn supported_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::WinUser, ObjectType::WinGroup]
    }
}

impl CloneCollector for UserCollector {
    fn clone_collector(&self) -> Box<dyn CloneCollector> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_user_script() {
        let collector = UserCollector::new();

        // Specific user
        let script = collector.build_user_script(Some("Administrator"));
        assert!(script.contains("Get-LocalUser"));
        assert!(script.contains("Administrator"));

        // All users
        let script = collector.build_user_script(None);
        assert!(script.contains("Get-LocalUser"));
    }

    #[test]
    fn test_build_group_script() {
        let collector = UserCollector::new();

        // Specific group
        let script = collector.build_group_script(Some("Administrators"));
        assert!(script.contains("Get-LocalGroup"));
        assert!(script.contains("Administrators"));

        // All groups
        let script = collector.build_group_script(None);
        assert!(script.contains("Get-LocalGroup"));
    }

    #[test]
    fn test_build_membership_script() {
        let collector = UserCollector::new();

        let script = collector.build_membership_script("Administrators", "testuser");
        assert!(script.contains("Get-LocalGroupMember"));
        assert!(script.contains("Administrators"));
        assert!(script.contains("testuser"));
    }
}
