//! Remote Execution for OVAL Object Collection

use anyhow::Result;
use std::collections::HashMap;
use crate::scap::ScapCredentials;
use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};

/// Remote execution context for collecting OVAL objects
#[derive(Debug, Clone)]
pub struct RemoteExecutionContext {
    pub host: String,
    pub executor: ExecutorType,
}

/// Executor type for remote commands
#[derive(Debug, Clone)]
pub enum ExecutorType {
    /// SSH executor for Unix/Linux
    Ssh {
        username: String,
        port: u16,
        auth: SshAuth,
    },
    /// WinRM executor for Windows
    WinRm {
        username: String,
        password: String,
        port: u16,
        use_ssl: bool,
        domain: Option<String>,
    },
}

/// SSH authentication method
#[derive(Debug, Clone)]
pub enum SshAuth {
    Password(String),
    PublicKey(String),
}

impl RemoteExecutionContext {
    /// Create from SCAP credentials
    pub fn new(host: &str, credentials: &ScapCredentials) -> Result<Self> {
        let executor = match credentials.auth_type {
            crate::scap::ScapAuthType::SshPassword => {
                ExecutorType::Ssh {
                    username: credentials.username.clone(),
                    port: credentials.port.unwrap_or(22),
                    auth: SshAuth::Password(credentials.password.clone().unwrap_or_default()),
                }
            }
            crate::scap::ScapAuthType::SshKey => {
                ExecutorType::Ssh {
                    username: credentials.username.clone(),
                    port: credentials.port.unwrap_or(22),
                    auth: SshAuth::PublicKey(credentials.ssh_key.clone().unwrap_or_default()),
                }
            }
            crate::scap::ScapAuthType::WinrmNtlm | crate::scap::ScapAuthType::WinrmKerberos => {
                ExecutorType::WinRm {
                    username: credentials.username.clone(),
                    password: credentials.password.clone().unwrap_or_default(),
                    port: credentials.port.unwrap_or(5985),
                    use_ssl: credentials.use_ssl,
                    domain: credentials.domain.clone(),
                }
            }
            crate::scap::ScapAuthType::Local => {
                return Err(anyhow::anyhow!("Local execution doesn't need remote context"));
            }
        };

        Ok(Self {
            host: host.to_string(),
            executor,
        })
    }

    /// Execute a command on the remote host
    pub async fn execute(&self, command: &str) -> Result<String> {
        match &self.executor {
            ExecutorType::Ssh { .. } => {
                // TODO: Implement SSH execution
                Err(anyhow::anyhow!("SSH execution not yet implemented"))
            }
            ExecutorType::WinRm { .. } => {
                // TODO: Implement WinRM execution
                Err(anyhow::anyhow!("WinRM execution not yet implemented"))
            }
        }
    }

    /// Collect OVAL items for an object from the remote host
    pub async fn collect_object(&self, object: &OvalObject) -> Result<Vec<OvalItem>> {
        // Build collection command based on object type
        let command = match object.object_type {
            ObjectType::UnixFile | ObjectType::LinuxRpmInfo | ObjectType::LinuxDpkgInfo |
            ObjectType::UnixPassword | ObjectType::UnixShadow | ObjectType::UnixProcess |
            ObjectType::UnixUname | ObjectType::UnixInterface | ObjectType::UnixSysctl => {
                self.build_unix_collection_command(object)?
            }
            ObjectType::WinRegistry | ObjectType::WinFile | ObjectType::WinWmi |
            ObjectType::WinService | ObjectType::WinUser | ObjectType::WinGroup |
            ObjectType::WinAuditEventPolicy | ObjectType::WinLockoutPolicy |
            ObjectType::WinPasswordPolicy => {
                self.build_windows_collection_command(object)?
            }
            ObjectType::IndFamily | ObjectType::IndTextFileContent |
            ObjectType::IndVariable | ObjectType::IndEnvironmentVariable => {
                self.build_independent_collection_command(object)?
            }
            _ => {
                return Ok(vec![]);
            }
        };

        // Execute the command remotely
        let output = match self.execute(&command).await {
            Ok(out) => out,
            Err(e) => {
                log::warn!("Remote collection failed for {}: {}", object.id, e);
                return Ok(vec![]);
            }
        };

        // Parse the output into OVAL items
        self.parse_collection_output(&output, object)
    }

    fn build_unix_collection_command(&self, object: &OvalObject) -> Result<String> {
        match object.object_type {
            ObjectType::UnixFile => {
                let path = object.data.get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let filename = object.data.get("filename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let full_path = if filename.is_empty() {
                    path.to_string()
                } else {
                    format!("{}/{}", path, filename)
                };
                Ok(format!("stat --printf='%s %a %U %G %Y' '{}' 2>/dev/null || echo 'NOT_FOUND'", full_path))
            }
            ObjectType::UnixUname => {
                Ok("uname -a".to_string())
            }
            ObjectType::LinuxRpmInfo => {
                let name = object.data.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*");
                Ok(format!("rpm -q --queryformat '%{{NAME}}|%{{VERSION}}|%{{RELEASE}}|%{{ARCH}}\\n' {} 2>/dev/null || echo 'NOT_FOUND'", name))
            }
            ObjectType::LinuxDpkgInfo => {
                let name = object.data.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*");
                Ok(format!("dpkg-query -W -f='${{Package}}|${{Version}}|${{Status}}\\n' {} 2>/dev/null || echo 'NOT_FOUND'", name))
            }
            _ => Ok("echo 'UNSUPPORTED'".to_string())
        }
    }

    fn build_windows_collection_command(&self, object: &OvalObject) -> Result<String> {
        match object.object_type {
            ObjectType::WinRegistry => {
                let hive = object.data.get("hive")
                    .and_then(|v| v.as_str())
                    .unwrap_or("HKLM");
                let key = object.data.get("key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let name = object.data.get("name")
                    .and_then(|v| v.as_str());

                if let Some(value_name) = name {
                    Ok(format!(
                        "Get-ItemProperty -Path '{}:\\{}' -Name '{}' | ConvertTo-Json",
                        hive, key, value_name
                    ))
                } else {
                    Ok(format!(
                        "Get-ItemProperty -Path '{}:\\{}' | ConvertTo-Json",
                        hive, key
                    ))
                }
            }
            ObjectType::WinService => {
                let name = object.data.get("service_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*");
                Ok(format!("Get-Service -Name '{}' | Select-Object Name,Status,StartType,DisplayName | ConvertTo-Json", name))
            }
            ObjectType::WinFile => {
                let path = object.data.get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let filename = object.data.get("filename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*");
                Ok(format!("Get-Item -Path '{}\\{}' | Select-Object Name,Length,LastWriteTime | ConvertTo-Json", path, filename))
            }
            _ => Ok("echo 'UNSUPPORTED'".to_string())
        }
    }

    fn build_independent_collection_command(&self, object: &OvalObject) -> Result<String> {
        match object.object_type {
            ObjectType::IndFamily => {
                // Check if Windows or Unix
                Ok("if ($env:OS -match 'Windows') { 'windows' } else { uname -s }".to_string())
            }
            ObjectType::IndTextFileContent => {
                let path = object.data.get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let pattern = object.data.get("pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or(".*");
                Ok(format!("grep -E '{}' '{}' 2>/dev/null || echo 'NOT_FOUND'", pattern, path))
            }
            ObjectType::IndEnvironmentVariable => {
                let name = object.data.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("PATH");
                Ok(format!("echo ${{{name}}} 2>/dev/null || echo %{name}%"))
            }
            _ => Ok("echo 'UNSUPPORTED'".to_string())
        }
    }

    fn parse_collection_output(&self, output: &str, object: &OvalObject) -> Result<Vec<OvalItem>> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);

        if output.trim() == "NOT_FOUND" || output.trim() == "UNSUPPORTED" {
            return Ok(vec![]);
        }

        let mut items = Vec::new();
        let mut item_data = HashMap::new();

        // Parse based on object type
        match object.object_type {
            ObjectType::UnixFile => {
                let parts: Vec<&str> = output.split_whitespace().collect();
                if parts.len() >= 5 {
                    item_data.insert("size".to_string(), OvalValue::Int(parts[0].parse().unwrap_or(0)));
                    item_data.insert("mode".to_string(), OvalValue::String(parts[1].to_string()));
                    item_data.insert("owner".to_string(), OvalValue::String(parts[2].to_string()));
                    item_data.insert("group".to_string(), OvalValue::String(parts[3].to_string()));
                }
            }
            ObjectType::UnixUname => {
                let parts: Vec<&str> = output.split_whitespace().collect();
                if !parts.is_empty() {
                    item_data.insert("os_name".to_string(), OvalValue::String(parts[0].to_string()));
                }
                if parts.len() > 1 {
                    item_data.insert("node_name".to_string(), OvalValue::String(parts[1].to_string()));
                }
                if parts.len() > 2 {
                    item_data.insert("os_release".to_string(), OvalValue::String(parts[2].to_string()));
                }
            }
            _ => {
                // For JSON outputs (Windows), try to parse
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
                    if let Some(obj) = json.as_object() {
                        for (k, v) in obj {
                            let oval_val = match v {
                                serde_json::Value::String(s) => OvalValue::String(s.clone()),
                                serde_json::Value::Number(n) => {
                                    if let Some(i) = n.as_i64() {
                                        OvalValue::Int(i)
                                    } else if let Some(f) = n.as_f64() {
                                        OvalValue::Float(f)
                                    } else {
                                        OvalValue::String(n.to_string())
                                    }
                                }
                                serde_json::Value::Bool(b) => OvalValue::Boolean(*b),
                                _ => OvalValue::String(v.to_string()),
                            };
                            item_data.insert(k.clone(), oval_val);
                        }
                    }
                }
            }
        }

        if !item_data.is_empty() {
            items.push(OvalItem {
                id: COUNTER.fetch_add(1, Ordering::SeqCst),
                status: ItemStatus::Exists,
                item_type: object.object_type,
                data: item_data,
            });
        }

        Ok(items)
    }
}
