//! Unix Process OVAL Collector
//!
//! Collects running process information for OVAL evaluation on Unix/Linux systems.

use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;

use crate::scap::oval::types::{OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType};
use super::{UnixCollector, UnixCollectionContext, CloneUnixCollector, generate_item_id};

/// Unix process collector
#[derive(Debug, Clone)]
pub struct ProcessCollector;

impl ProcessCollector {
    pub fn new() -> Self {
        Self
    }

    /// Build shell command to query process information
    /// Returns: pid, ppid, uid, user, command, tty, start_time, exec_time, scheduling_class
    fn build_process_command(&self, command_pattern: Option<&str>) -> String {
        // Use ps with custom format to get all needed fields
        // pid, ppid, uid, user, tty, start, time, cls (scheduling class), args
        let base_cmd = "ps -eo pid,ppid,uid,user,tty,start,time,cls,args --no-headers";

        if let Some(pattern) = command_pattern {
            // Filter by command pattern using grep
            format!(
                "{} | grep -E '{}' | grep -v 'grep -E'",
                base_cmd,
                pattern.replace('\'', "'\\''")
            )
        } else {
            base_cmd.to_string()
        }
    }

    /// Build command to get detailed info for a specific PID
    fn build_pid_details_command(&self, pid: i64) -> String {
        format!(
            r#"
if [ -d /proc/{} ]; then
    # Get process info from /proc
    exe=$(readlink -f /proc/{}/exe 2>/dev/null || echo "")
    cmdline=$(cat /proc/{}/cmdline 2>/dev/null | tr '\0' ' ')
    loginuid=$(cat /proc/{}/loginuid 2>/dev/null || echo "-1")
    sessionid=$(cat /proc/{}/sessionid 2>/dev/null || echo "0")
    selinux=$(cat /proc/{}/attr/current 2>/dev/null || echo "")
    echo "exe:$exe"
    echo "cmdline:$cmdline"
    echo "loginuid:$loginuid"
    echo "sessionid:$sessionid"
    echo "selinux:$selinux"
fi
"#,
            pid, pid, pid, pid, pid, pid
        )
    }

    /// Parse ps output line into OvalItem
    fn parse_ps_line(&self, line: &str) -> Option<OvalItem> {
        // Format: pid ppid uid user tty start time cls args...
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 9 {
            return None;
        }

        let pid = parts[0].parse::<i64>().ok()?;
        let ppid = parts[1].parse::<i64>().ok()?;
        let uid = parts[2].parse::<i64>().ok()?;
        let user = parts[3];
        let tty = parts[4];
        let start_time = parts[5];
        let exec_time = parts[6];
        let scheduling_class = parts[7];
        // Everything after scheduling class is the command
        let command = parts[8..].join(" ");

        let mut data = HashMap::new();
        data.insert("pid".to_string(), OvalValue::Int(pid));
        data.insert("ppid".to_string(), OvalValue::Int(ppid));
        data.insert("uid".to_string(), OvalValue::Int(uid));
        data.insert("user".to_string(), OvalValue::String(user.to_string()));
        data.insert("command".to_string(), OvalValue::String(command));

        // TTY - convert "?" to empty
        let tty_value = if tty == "?" { "" } else { tty };
        data.insert("tty".to_string(), OvalValue::String(tty_value.to_string()));

        data.insert("start_time".to_string(), OvalValue::String(start_time.to_string()));
        data.insert("exec_time".to_string(), OvalValue::String(exec_time.to_string()));
        data.insert("scheduling_class".to_string(), OvalValue::String(scheduling_class.to_string()));

        Some(OvalItem {
            id: generate_item_id(),
            status: ItemStatus::Exists,
            item_type: ObjectType::UnixProcess,
            data,
        })
    }

    /// Add extended details from /proc to an item
    fn add_proc_details(&self, item: &mut OvalItem, proc_output: &str) {
        for line in proc_output.lines() {
            let trimmed = line.trim();
            if let Some((key, value)) = trimmed.split_once(':') {
                let value = value.trim();
                if !value.is_empty() {
                    match key {
                        "exe" => {
                            item.data.insert("exec".to_string(), OvalValue::String(value.to_string()));
                        }
                        "cmdline" => {
                            // Don't overwrite command from ps, but add full cmdline
                            item.data.insert("command_line".to_string(), OvalValue::String(value.to_string()));
                        }
                        "loginuid" => {
                            if let Ok(uid) = value.parse::<i64>() {
                                item.data.insert("loginuid".to_string(), OvalValue::Int(uid));
                            }
                        }
                        "sessionid" => {
                            if let Ok(sid) = value.parse::<i64>() {
                                item.data.insert("session_id".to_string(), OvalValue::Int(sid));
                            }
                        }
                        "selinux" => {
                            item.data.insert("selinux_domain_label".to_string(), OvalValue::String(value.to_string()));
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UnixCollector for ProcessCollector {
    async fn collect(&self, object: &OvalObject, context: &UnixCollectionContext) -> Result<Vec<OvalItem>> {
        if !context.has_credentials() {
            log::warn!("No SSH credentials configured, skipping process collection");
            return Ok(vec![]);
        }

        // Extract process object parameters
        let command_pattern = object.data.get("command")
            .and_then(|v| v.as_str());

        // Get detailed proc info
        let get_proc_details = object.data.get("behaviors")
            .and_then(|v| v.get("resolve_group"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Build and execute the process listing command
        let command = self.build_process_command(command_pattern);
        let output = match context.execute_command(&command).await {
            Ok(out) => out,
            Err(e) => {
                log::warn!("Failed to execute process collection command: {}", e);
                return Ok(vec![]);
            }
        };

        // Parse output
        let mut items = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                if let Some(mut item) = self.parse_ps_line(trimmed) {
                    // Optionally get extended details from /proc
                    if get_proc_details {
                        if let Some(OvalValue::Int(pid)) = item.data.get("pid") {
                            let proc_cmd = self.build_pid_details_command(*pid);
                            if let Ok(proc_output) = context.execute_command(&proc_cmd).await {
                                self.add_proc_details(&mut item, &proc_output);
                            }
                        }
                    }
                    items.push(item);
                }
            }
        }

        // If searching for specific command and nothing found, return empty
        if command_pattern.is_some() && items.is_empty() {
            let mut data = HashMap::new();
            data.insert("command".to_string(), OvalValue::String(
                command_pattern.unwrap_or_default().to_string()
            ));

            items.push(OvalItem {
                id: generate_item_id(),
                status: ItemStatus::DoesNotExist,
                item_type: ObjectType::UnixProcess,
                data,
            });
        }

        Ok(items)
    }

    fn supported_types(&self) -> Vec<ObjectType> {
        vec![ObjectType::UnixProcess]
    }
}

impl CloneUnixCollector for ProcessCollector {
    fn clone_collector(&self) -> Box<dyn CloneUnixCollector> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_process_command() {
        let collector = ProcessCollector::new();

        // All processes
        let cmd = collector.build_process_command(None);
        assert!(cmd.contains("ps -eo"));
        assert!(!cmd.contains("grep"));

        // Filtered by command
        let cmd = collector.build_process_command(Some("sshd"));
        assert!(cmd.contains("ps -eo"));
        assert!(cmd.contains("grep -E 'sshd'"));
    }

    #[test]
    fn test_parse_ps_line() {
        let collector = ProcessCollector::new();

        // Sample ps output line
        let line = "  1234   567   0 root     pts/0    10:30:00 00:00:01   TS /usr/sbin/sshd -D";
        let item = collector.parse_ps_line(line);

        assert!(item.is_some());
        let item = item.unwrap();
        assert_eq!(item.item_type, ObjectType::UnixProcess);

        if let Some(OvalValue::Int(pid)) = item.data.get("pid") {
            assert_eq!(*pid, 1234);
        } else {
            panic!("Expected pid");
        }

        if let Some(OvalValue::String(cmd)) = item.data.get("command") {
            assert!(cmd.contains("sshd"));
        } else {
            panic!("Expected command");
        }
    }
}
