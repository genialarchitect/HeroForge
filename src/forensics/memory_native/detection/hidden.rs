//! Hidden process and object detection
//!
//! Detect processes and objects hidden via various techniques.

use anyhow::Result;
use std::collections::HashSet;

use crate::forensics::memory_native::dump_parser::ParsedDump;
use crate::forensics::memory_native::types::ProcessInfo;

/// Hidden object detection result
#[derive(Debug, Clone)]
pub struct HiddenObject {
    /// Type of hidden object
    pub object_type: HiddenObjectType,
    /// Object address
    pub address: u64,
    /// Object identifier (PID, handle, etc.)
    pub identifier: String,
    /// How it was hidden
    pub hiding_method: HidingMethod,
    /// Additional details
    pub details: String,
    /// Confidence (0-100)
    pub confidence: u8,
}

/// Type of hidden object
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HiddenObjectType {
    Process,
    Thread,
    Driver,
    Handle,
    Registry,
    File,
    NetworkConnection,
}

/// Method used to hide the object
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HidingMethod {
    /// Unlinked from list
    Dkom,
    /// PspCidTable manipulation
    CidTable,
    /// Handle table manipulation
    HandleTable,
    /// Callback manipulation
    Callbacks,
    /// Hypervisor-based hiding
    Hypervisor,
    /// Unknown method
    Unknown,
}

/// Compare process lists to find hidden processes
pub fn find_hidden_processes(
    list_processes: &[ProcessInfo],
    scan_processes: &[ProcessInfo],
) -> Vec<HiddenObject> {
    let mut hidden = Vec::new();

    // Processes in scan but not in list are potentially hidden via DKOM
    let list_pids: HashSet<u32> = list_processes.iter().map(|p| p.pid).collect();

    for process in scan_processes {
        if !list_pids.contains(&process.pid) {
            hidden.push(HiddenObject {
                object_type: HiddenObjectType::Process,
                address: process.eprocess_addr,
                identifier: format!("PID: {} ({})", process.pid, process.name),
                hiding_method: HidingMethod::Dkom,
                details: format!(
                    "Process found by memory scan but not in ActiveProcessLinks. EPROCESS: {:#x}",
                    process.eprocess_addr
                ),
                confidence: 85,
            });
        }
    }

    // Processes in list but not in scan could indicate orphaned entries
    let scan_pids: HashSet<u32> = scan_processes.iter().map(|p| p.pid).collect();

    for process in list_processes {
        if !scan_pids.contains(&process.pid) && process.pid > 4 {
            hidden.push(HiddenObject {
                object_type: HiddenObjectType::Process,
                address: process.eprocess_addr,
                identifier: format!("PID: {} ({})", process.pid, process.name),
                hiding_method: HidingMethod::Unknown,
                details: "Process in list but EPROCESS not found in memory scan".to_string(),
                confidence: 50,
            });
        }
    }

    hidden
}

/// Find orphaned threads (not attached to any known process)
pub fn find_orphaned_threads(dump: &ParsedDump) -> Result<Vec<HiddenObject>> {
    let mut hidden = Vec::new();

    // Search for ETHREAD structures
    let thread_tag = b"Thre";
    let matches = dump.search_pattern(thread_tag);

    for &offset in matches.iter().take(10000) {
        // Parse potential ETHREAD
        if let Some(data) = dump.read_bytes(offset, 0x100) {
            // Get owning process
            let process_offset = 0x220; // Approximate for Win10
            if process_offset + 8 <= data.len() {
                let owning_process = u64::from_le_bytes([
                    data[process_offset], data[process_offset + 1],
                    data[process_offset + 2], data[process_offset + 3],
                    data[process_offset + 4], data[process_offset + 5],
                    data[process_offset + 6], data[process_offset + 7],
                ]);

                // If owning process is null or points to invalid memory
                if owning_process == 0 {
                    hidden.push(HiddenObject {
                        object_type: HiddenObjectType::Thread,
                        address: offset,
                        identifier: format!("ETHREAD at {:#x}", offset),
                        hiding_method: HidingMethod::Unknown,
                        details: "Thread with null owning process".to_string(),
                        confidence: 40,
                    });
                }
            }
        }
    }

    Ok(hidden)
}

/// Detect handle table manipulation
pub fn detect_handle_hiding(dump: &ParsedDump, processes: &[ProcessInfo]) -> Result<Vec<HiddenObject>> {
    let hidden = Vec::new();

    // For each process, verify handle table integrity
    for process in processes {
        // Would need to:
        // 1. Get ObjectTable from EPROCESS
        // 2. Walk handle table entries
        // 3. Verify each handle points to valid object
        // 4. Check for gaps in handle table that might indicate hidden handles

        // Placeholder for handle table analysis
        let _ = (dump, process);
    }

    Ok(hidden)
}

/// Check for callback manipulation (used to hide from security tools)
pub fn detect_callback_manipulation(dump: &ParsedDump) -> Result<Vec<HiddenObject>> {
    let mut hidden = Vec::new();

    // Windows uses callback arrays for various notifications:
    // - PsSetCreateProcessNotifyRoutine
    // - PsSetCreateThreadNotifyRoutine
    // - PsSetLoadImageNotifyRoutine
    // - CmRegisterCallback (registry)
    // - ObRegisterCallbacks (object manager)

    // Rootkits may modify these to evade detection

    // Search for callback array patterns
    // Callbacks are typically in kernel memory with specific signatures

    // Look for PspCreateProcessNotifyRoutine array
    // This would require finding the symbol or pattern matching

    let callback_patterns: &[&[u8]] = &[
        b"CmpCallBackCount",
        b"PspCreateProcessNotifyRoutine",
        b"PspLoadImageNotifyRoutine",
    ];

    for pattern in callback_patterns {
        let matches = dump.search_pattern(pattern);

        for &offset in matches.iter().take(5) {
            // Read callback array
            if let Some(data) = dump.read_bytes(offset, 0x100) {
                // Check for null entries followed by non-null (gap)
                let mut found_null = false;
                let mut found_gap = false;

                for i in (0..data.len() - 8).step_by(8) {
                    let ptr = u64::from_le_bytes([
                        data[i], data[i + 1], data[i + 2], data[i + 3],
                        data[i + 4], data[i + 5], data[i + 6], data[i + 7],
                    ]);

                    if ptr == 0 {
                        found_null = true;
                    } else if found_null {
                        found_gap = true;
                        break;
                    }
                }

                if found_gap {
                    hidden.push(HiddenObject {
                        object_type: HiddenObjectType::Handle,
                        address: offset,
                        identifier: format!("Callback array at {:#x}", offset),
                        hiding_method: HidingMethod::Callbacks,
                        details: "Gap in callback array may indicate manipulation".to_string(),
                        confidence: 50,
                    });
                }
            }
        }
    }

    Ok(hidden)
}

/// Calculate process tree and find anomalies
pub fn analyze_process_tree(processes: &[ProcessInfo]) -> Vec<ProcessTreeAnomaly> {
    let mut anomalies = Vec::new();

    // Build parent-child relationships
    let pid_map: std::collections::HashMap<u32, &ProcessInfo> = processes
        .iter()
        .map(|p| (p.pid, p))
        .collect();

    for process in processes {
        // Check if parent exists
        if process.ppid > 4 && !pid_map.contains_key(&process.ppid) {
            anomalies.push(ProcessTreeAnomaly {
                pid: process.pid,
                process_name: process.name.clone(),
                anomaly_type: "Orphaned process".to_string(),
                description: format!(
                    "Parent PID {} not found - parent may have exited or be hidden",
                    process.ppid
                ),
            });
        }

        // Check for suspicious parent-child relationships
        let suspicious_spawn = is_suspicious_spawn(process, pid_map.get(&process.ppid).copied());
        if let Some(reason) = suspicious_spawn {
            anomalies.push(ProcessTreeAnomaly {
                pid: process.pid,
                process_name: process.name.clone(),
                anomaly_type: "Suspicious spawn".to_string(),
                description: reason,
            });
        }
    }

    anomalies
}

/// Check for suspicious process spawning patterns
fn is_suspicious_spawn(child: &ProcessInfo, parent: Option<&ProcessInfo>) -> Option<String> {
    let child_name = child.name.to_lowercase();
    let parent_name = parent.map(|p| p.name.to_lowercase()).unwrap_or_default();

    // Suspicious patterns:
    // - cmd.exe/powershell.exe spawned by unusual parents
    // - svchost.exe not spawned by services.exe
    // - lsass.exe not spawned by wininit.exe/smss.exe

    if (child_name == "cmd.exe" || child_name == "powershell.exe") &&
       !["explorer.exe", "cmd.exe", "powershell.exe", "conhost.exe"].contains(&parent_name.as_str())
    {
        return Some(format!(
            "{} spawned by unusual parent: {}",
            child.name, parent.map(|p| &p.name).unwrap_or(&"unknown".to_string())
        ));
    }

    if child_name == "svchost.exe" && parent_name != "services.exe" {
        return Some(format!(
            "svchost.exe should be spawned by services.exe, not {}",
            parent.map(|p| &p.name).unwrap_or(&"unknown".to_string())
        ));
    }

    None
}

/// Process tree anomaly
#[derive(Debug, Clone)]
pub struct ProcessTreeAnomaly {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Type of anomaly
    pub anomaly_type: String,
    /// Description
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_process(pid: u32, ppid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            eprocess_addr: 0,
            pid,
            ppid,
            name: name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_hidden_process_detection() {
        let list_procs = vec![
            make_process(4, 0, "System"),
            make_process(100, 4, "smss.exe"),
        ];

        let scan_procs = vec![
            make_process(4, 0, "System"),
            make_process(100, 4, "smss.exe"),
            make_process(666, 100, "evil.exe"),
        ];

        let hidden = find_hidden_processes(&list_procs, &scan_procs);
        assert_eq!(hidden.len(), 1);
        assert!(hidden[0].identifier.contains("666"));
    }
}
