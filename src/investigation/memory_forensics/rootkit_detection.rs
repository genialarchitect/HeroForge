//! Rootkit Detection Module
//!
//! Detects various rootkit techniques in memory dumps:
//! - DKOM (Direct Kernel Object Manipulation)
//! - Hidden processes
//! - Hooked system calls
//! - Hidden modules/drivers
//! - IDT/SSDT hooks

use crate::investigation::types::RootkitDetection;
use anyhow::Result;
use std::collections::{HashMap, HashSet};

/// Main entry point for rootkit detection
pub fn detect_rootkits(
    processes: &[serde_json::Value],
    network: &[serde_json::Value],
) -> Result<Vec<RootkitDetection>> {
    let mut detections = Vec::new();

    // DKOM (Direct Kernel Object Manipulation) detection
    if let Some(dkom) = detect_dkom(processes)? {
        detections.push(dkom);
    }

    // Hidden process detection
    if let Some(hidden) = detect_hidden_processes(processes)? {
        detections.push(hidden);
    }

    // Unlinked process detection
    if let Some(unlinked) = detect_unlinked_processes(processes)? {
        detections.push(unlinked);
    }

    // Hidden network connections
    if let Some(hidden_net) = detect_hidden_network_connections(processes, network)? {
        detections.push(hidden_net);
    }

    // Hooked system calls detection
    if let Some(hooks) = detect_syscall_hooks(processes)? {
        detections.push(hooks);
    }

    // Hidden kernel modules
    if let Some(hidden_modules) = detect_hidden_modules(processes)? {
        detections.push(hidden_modules);
    }

    Ok(detections)
}

/// Detect DKOM (Direct Kernel Object Manipulation)
/// DKOM involves manipulating kernel data structures to hide processes
fn detect_dkom(processes: &[serde_json::Value]) -> Result<Option<RootkitDetection>> {
    let mut evidence = Vec::new();
    let mut suspicious_count = 0;

    for process in processes {
        // Check for EPROCESS manipulation indicators
        let pid = process.get("pid").and_then(|p| p.as_i64()).unwrap_or(0);
        let ppid = process.get("ppid").and_then(|p| p.as_i64()).unwrap_or(0);
        let name = process
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("unknown");

        // Check for processes with invalid parent PIDs
        if ppid < 0 || (ppid == 0 && pid != 0 && pid != 4 && name != "System") {
            evidence.push(format!(
                "Process '{}' (PID: {}) has suspicious parent PID: {}",
                name, pid, ppid
            ));
            suspicious_count += 1;
        }

        // Check for inconsistent ActiveProcessLinks
        if let Some(flink) = process.get("flink").and_then(|f| f.as_str()) {
            if let Some(blink) = process.get("blink").and_then(|b| b.as_str()) {
                // In a properly linked list, flink and blink should be valid
                if flink == "0x0" || blink == "0x0" {
                    evidence.push(format!(
                        "Process '{}' (PID: {}) has NULL ActiveProcessLinks - possible DKOM",
                        name, pid
                    ));
                    suspicious_count += 1;
                }
            }
        }

        // Check for processes with abnormal creation times
        if let Some(create_time) = process.get("create_time").and_then(|t| t.as_i64()) {
            // Process created before system boot or in the far future
            if create_time < 0 || create_time > i64::MAX / 2 {
                evidence.push(format!(
                    "Process '{}' (PID: {}) has abnormal creation time: {}",
                    name, pid, create_time
                ));
                suspicious_count += 1;
            }
        }

        // Check for PEB manipulation
        if let Some(peb) = process.get("peb") {
            if let Some(peb_addr) = peb.as_str() {
                if peb_addr == "0x0" || peb_addr == "0xffffffff" {
                    evidence.push(format!(
                        "Process '{}' (PID: {}) has invalid PEB address: {}",
                        name, pid, peb_addr
                    ));
                    suspicious_count += 1;
                }
            }
        }

        // Check for handle table manipulation
        if let Some(handles) = process.get("handle_count").and_then(|h| h.as_i64()) {
            if handles < 0 || handles > 100000 {
                evidence.push(format!(
                    "Process '{}' (PID: {}) has suspicious handle count: {}",
                    name, pid, handles
                ));
                suspicious_count += 1;
            }
        }
    }

    if suspicious_count > 0 {
        let severity = if suspicious_count > 5 {
            "critical"
        } else if suspicious_count > 2 {
            "high"
        } else {
            "medium"
        };

        Ok(Some(RootkitDetection {
            detection_type: "DKOM".to_string(),
            description: format!(
                "Direct Kernel Object Manipulation detected. {} suspicious indicators found. \
                 Attacker may be manipulating kernel structures to hide malicious activity.",
                suspicious_count
            ),
            severity: severity.to_string(),
            evidence,
        }))
    } else {
        Ok(None)
    }
}

/// Detect hidden processes using cross-view detection
/// Compares multiple process enumeration methods to find discrepancies
fn detect_hidden_processes(processes: &[serde_json::Value]) -> Result<Option<RootkitDetection>> {
    let mut evidence = Vec::new();

    // Build sets from different views
    let mut pslist_pids: HashSet<i64> = HashSet::new();
    let mut psscan_pids: HashSet<i64> = HashSet::new();
    let mut csrss_pids: HashSet<i64> = HashSet::new();

    for process in processes {
        let pid = process.get("pid").and_then(|p| p.as_i64()).unwrap_or(0);
        let source = process
            .get("source")
            .and_then(|s| s.as_str())
            .unwrap_or("pslist");

        match source {
            "pslist" => {
                pslist_pids.insert(pid);
            }
            "psscan" => {
                psscan_pids.insert(pid);
            }
            "csrss" | "csrss_handles" => {
                csrss_pids.insert(pid);
            }
            _ => {
                pslist_pids.insert(pid);
            }
        }
    }

    // If we have multiple views, compare them
    if !psscan_pids.is_empty() && !pslist_pids.is_empty() {
        // Processes found by psscan but not pslist may be hidden
        let hidden_from_pslist: Vec<i64> = psscan_pids
            .difference(&pslist_pids)
            .copied()
            .collect();

        for pid in &hidden_from_pslist {
            // Find process details
            if let Some(proc) = processes.iter().find(|p| {
                p.get("pid").and_then(|id| id.as_i64()) == Some(*pid)
            }) {
                let name = proc
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown");
                evidence.push(format!(
                    "Hidden process detected: '{}' (PID: {}) found by psscan but not in active process list",
                    name, pid
                ));
            }
        }
    }

    // Check for process hollowing indicators
    for process in processes {
        let pid = process.get("pid").and_then(|p| p.as_i64()).unwrap_or(0);
        let name = process
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("unknown");

        // Check if process image path doesn't match expected location
        if let Some(path) = process.get("path").and_then(|p| p.as_str()) {
            let expected_paths: HashMap<&str, &[&str]> = HashMap::from([
                ("svchost.exe", &["\\windows\\system32\\svchost.exe", "\\windows\\syswow64\\svchost.exe"][..]),
                ("lsass.exe", &["\\windows\\system32\\lsass.exe"][..]),
                ("csrss.exe", &["\\windows\\system32\\csrss.exe"][..]),
                ("smss.exe", &["\\windows\\system32\\smss.exe"][..]),
                ("services.exe", &["\\windows\\system32\\services.exe"][..]),
            ]);

            let name_lower = name.to_lowercase();
            if let Some(expected) = expected_paths.get(name_lower.as_str()) {
                let path_lower = path.to_lowercase();
                if !expected.iter().any(|e| path_lower.ends_with(e)) {
                    evidence.push(format!(
                        "Possible process hollowing: '{}' (PID: {}) running from unexpected path: {}",
                        name, pid, path
                    ));
                }
            }
        }

        // Check for terminated but still in memory
        if let Some(exit_time) = process.get("exit_time") {
            if !exit_time.is_null() && process.get("threads").and_then(|t| t.as_i64()).unwrap_or(0) > 0 {
                evidence.push(format!(
                    "Zombie process detected: '{}' (PID: {}) has exit time but still has active threads",
                    name, pid
                ));
            }
        }
    }

    if !evidence.is_empty() {
        let severity = if evidence.len() > 3 { "critical" } else { "high" };
        Ok(Some(RootkitDetection {
            detection_type: "Hidden Process".to_string(),
            description: format!(
                "Hidden or suspicious processes detected using cross-view analysis. \
                 {} indicators found.",
                evidence.len()
            ),
            severity: severity.to_string(),
            evidence,
        }))
    } else {
        Ok(None)
    }
}

/// Detect unlinked processes (removed from ActiveProcessLinks but still in memory)
fn detect_unlinked_processes(processes: &[serde_json::Value]) -> Result<Option<RootkitDetection>> {
    let mut evidence = Vec::new();

    for process in processes {
        let pid = process.get("pid").and_then(|p| p.as_i64()).unwrap_or(0);
        let name = process
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("unknown");

        // Check if process is marked as unlinked
        if let Some(unlinked) = process.get("unlinked").and_then(|u| u.as_bool()) {
            if unlinked {
                evidence.push(format!(
                    "Unlinked process: '{}' (PID: {}) removed from process list but still in memory",
                    name, pid
                ));
            }
        }

        // Check for orphaned threads without parent process
        if let Some(threads) = process.get("orphan_threads").and_then(|t| t.as_array()) {
            if !threads.is_empty() {
                evidence.push(format!(
                    "Process '{}' (PID: {}) has {} orphaned threads - possible process termination evasion",
                    name, pid, threads.len()
                ));
            }
        }
    }

    if !evidence.is_empty() {
        Ok(Some(RootkitDetection {
            detection_type: "Unlinked Process".to_string(),
            description: "Processes found that have been unlinked from the active process list. \
                         This technique is used to hide processes from standard enumeration."
                .to_string(),
            severity: "high".to_string(),
            evidence,
        }))
    } else {
        Ok(None)
    }
}

/// Detect hidden network connections
fn detect_hidden_network_connections(
    processes: &[serde_json::Value],
    network: &[serde_json::Value],
) -> Result<Option<RootkitDetection>> {
    let mut evidence = Vec::new();

    // Build set of PIDs with network activity
    let network_pids: HashSet<i64> = network
        .iter()
        .filter_map(|n| n.get("pid").and_then(|p| p.as_i64()))
        .collect();

    let process_pids: HashSet<i64> = processes
        .iter()
        .filter_map(|p| p.get("pid").and_then(|id| id.as_i64()))
        .collect();

    // Find network connections with non-existent PIDs
    for conn in network {
        if let Some(pid) = conn.get("pid").and_then(|p| p.as_i64()) {
            if pid > 4 && !process_pids.contains(&pid) {
                let local = conn
                    .get("local_address")
                    .and_then(|a| a.as_str())
                    .unwrap_or("unknown");
                let remote = conn
                    .get("remote_address")
                    .and_then(|a| a.as_str())
                    .unwrap_or("unknown");
                evidence.push(format!(
                    "Hidden connection: PID {} not found in process list. {} -> {}",
                    pid, local, remote
                ));
            }
        }

        // Check for suspicious ports
        if let Some(local_port) = conn.get("local_port").and_then(|p| p.as_i64()) {
            // Common backdoor ports
            let suspicious_ports = [4444, 5555, 6666, 31337, 12345, 54321, 1234, 9999];
            if suspicious_ports.contains(&(local_port as i32)) {
                let pid = conn.get("pid").and_then(|p| p.as_i64()).unwrap_or(0);
                evidence.push(format!(
                    "Suspicious listening port {} associated with PID {}",
                    local_port, pid
                ));
            }
        }
    }

    if !evidence.is_empty() {
        Ok(Some(RootkitDetection {
            detection_type: "Hidden Network Connection".to_string(),
            description: format!(
                "Network connections associated with hidden or non-existent processes. \
                 {} suspicious connections found.",
                evidence.len()
            ),
            severity: "high".to_string(),
            evidence,
        }))
    } else {
        Ok(None)
    }
}

/// Detect hooked system calls (SSDT/IDT hooks)
fn detect_syscall_hooks(processes: &[serde_json::Value]) -> Result<Option<RootkitDetection>> {
    let mut evidence = Vec::new();

    for process in processes {
        // Check for inline hooks in ntdll/kernel32
        if let Some(hooks) = process.get("inline_hooks").and_then(|h| h.as_array()) {
            for hook in hooks {
                let function = hook
                    .get("function")
                    .and_then(|f| f.as_str())
                    .unwrap_or("unknown");
                let module = hook
                    .get("module")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown");
                let hook_addr = hook
                    .get("hook_address")
                    .and_then(|a| a.as_str())
                    .unwrap_or("unknown");

                evidence.push(format!(
                    "Inline hook detected: {}!{} hooked to {}",
                    module, function, hook_addr
                ));
            }
        }

        // Check for IAT hooks
        if let Some(iat_hooks) = process.get("iat_hooks").and_then(|h| h.as_array()) {
            for hook in iat_hooks {
                let function = hook
                    .get("function")
                    .and_then(|f| f.as_str())
                    .unwrap_or("unknown");
                evidence.push(format!("IAT hook detected: {}", function));
            }
        }

        // Check for SSDT hooks (kernel level)
        if let Some(ssdt_hooks) = process.get("ssdt_hooks").and_then(|h| h.as_array()) {
            for hook in ssdt_hooks {
                let syscall = hook
                    .get("syscall")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                let owner = hook
                    .get("owner")
                    .and_then(|o| o.as_str())
                    .unwrap_or("unknown");

                // Known legitimate hooks to exclude
                let known_av = ["avgntflt", "aswsp", "klif", "epfwwfp"];
                if !known_av.iter().any(|av| owner.to_lowercase().contains(av)) {
                    evidence.push(format!(
                        "SSDT hook detected: {} hooked by {}",
                        syscall, owner
                    ));
                }
            }
        }
    }

    if !evidence.is_empty() {
        let severity = if evidence.len() > 5 { "critical" } else { "high" };
        Ok(Some(RootkitDetection {
            detection_type: "System Call Hook".to_string(),
            description: format!(
                "System call hooks detected that may be used to hide malicious activity. \
                 {} hooks found.",
                evidence.len()
            ),
            severity: severity.to_string(),
            evidence,
        }))
    } else {
        Ok(None)
    }
}

/// Detect hidden kernel modules/drivers
fn detect_hidden_modules(processes: &[serde_json::Value]) -> Result<Option<RootkitDetection>> {
    let mut evidence = Vec::new();

    // Look for module-related information in process data
    for process in processes {
        // Check for hidden drivers
        if let Some(drivers) = process.get("hidden_drivers").and_then(|d| d.as_array()) {
            for driver in drivers {
                let name = driver
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown");
                let base = driver
                    .get("base_address")
                    .and_then(|b| b.as_str())
                    .unwrap_or("unknown");
                evidence.push(format!(
                    "Hidden kernel module: {} at base address {}",
                    name, base
                ));
            }
        }

        // Check for unsigned drivers
        if let Some(unsigned) = process.get("unsigned_drivers").and_then(|d| d.as_array()) {
            for driver in unsigned {
                let name = driver
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown");
                let path = driver
                    .get("path")
                    .and_then(|p| p.as_str())
                    .unwrap_or("unknown");
                evidence.push(format!("Unsigned driver: {} ({})", name, path));
            }
        }

        // Check for modules loaded from suspicious paths
        if let Some(modules) = process.get("loaded_modules").and_then(|m| m.as_array()) {
            for module in modules {
                if let Some(path) = module.get("path").and_then(|p| p.as_str()) {
                    let path_lower = path.to_lowercase();
                    let suspicious_paths = ["\\temp\\", "\\tmp\\", "\\appdata\\", "\\users\\public\\"];
                    if suspicious_paths.iter().any(|s| path_lower.contains(s)) {
                        let name = module
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");
                        evidence.push(format!(
                            "Module loaded from suspicious path: {} ({})",
                            name, path
                        ));
                    }
                }
            }
        }
    }

    if !evidence.is_empty() {
        let severity = if evidence.iter().any(|e| e.contains("Hidden kernel")) {
            "critical"
        } else {
            "high"
        };
        Ok(Some(RootkitDetection {
            detection_type: "Hidden Module".to_string(),
            description: format!(
                "Hidden or suspicious kernel modules detected. {} indicators found.",
                evidence.len()
            ),
            severity: severity.to_string(),
            evidence,
        }))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_detect_dkom_clean() {
        let processes = vec![
            json!({
                "pid": 4,
                "ppid": 0,
                "name": "System",
                "create_time": 1000000
            }),
            json!({
                "pid": 100,
                "ppid": 4,
                "name": "smss.exe",
                "create_time": 1000001
            }),
        ];

        let result = detect_dkom(&processes).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_dkom_suspicious() {
        let processes = vec![
            json!({
                "pid": 1234,
                "ppid": -1,
                "name": "malware.exe",
                "create_time": -100
            }),
        ];

        let result = detect_dkom(&processes).unwrap();
        assert!(result.is_some());
        let detection = result.unwrap();
        assert_eq!(detection.detection_type, "DKOM");
    }

    #[test]
    fn test_detect_hidden_network() {
        let processes = vec![json!({"pid": 100, "name": "explorer.exe"})];
        let network = vec![
            json!({
                "pid": 9999,
                "local_address": "192.168.1.1:4444",
                "remote_address": "10.0.0.1:80"
            }),
        ];

        let result = detect_hidden_network_connections(&processes, &network).unwrap();
        assert!(result.is_some());
    }
}
