//! Memory Analysis module for Digital Forensics
//!
//! Provides capabilities for analyzing memory dumps:
//! - Memory dump metadata parsing
//! - Process listing extraction
//! - Network connections extraction
//! - Loaded modules/DLLs listing
//! - Memory strings extraction with filtering

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use regex::Regex;

use crate::forensics::types::AnalysisStatus;

// =============================================================================
// Memory Dump Types
// =============================================================================

/// Memory dump metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDump {
    pub id: String,
    pub case_id: String,
    pub filename: String,
    pub file_hash: String,
    pub file_size: i64,
    pub os_profile: Option<String>,
    pub collected_at: DateTime<Utc>,
    pub analysis_status: AnalysisStatus,
    pub findings_json: Option<serde_json::Value>,
}

/// OS Profile for memory analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsProfile {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub build: Option<String>,
}

impl OsProfile {
    pub fn windows_10_x64() -> Self {
        Self {
            name: "Windows".to_string(),
            version: "10".to_string(),
            architecture: "x64".to_string(),
            build: Some("19041".to_string()),
        }
    }

    pub fn windows_11_x64() -> Self {
        Self {
            name: "Windows".to_string(),
            version: "11".to_string(),
            architecture: "x64".to_string(),
            build: Some("22000".to_string()),
        }
    }

    pub fn linux_x64() -> Self {
        Self {
            name: "Linux".to_string(),
            version: "5.x".to_string(),
            architecture: "x64".to_string(),
            build: None,
        }
    }
}

// =============================================================================
// Process Information
// =============================================================================

/// Process extracted from memory dump
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: Option<String>,
    pub cmdline: Option<String>,
    pub create_time: Option<DateTime<Utc>>,
    pub exit_time: Option<DateTime<Utc>>,
    pub threads: u32,
    pub handles: u32,
    pub wow64: bool,
    pub is_hidden: bool,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

/// Process analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAnalysisResult {
    pub processes: Vec<MemoryProcess>,
    pub hidden_count: u32,
    pub suspicious_count: u32,
    pub total_count: u32,
    pub analysis_notes: Vec<String>,
}

// =============================================================================
// Network Connections
// =============================================================================

/// Network connection state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ConnectionState {
    Established,
    Listen,
    SynSent,
    SynReceived,
    FinWait1,
    FinWait2,
    TimeWait,
    CloseWait,
    LastAck,
    Closing,
    Closed,
    Unknown,
}

impl ConnectionState {
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "ESTABLISHED" => ConnectionState::Established,
            "LISTEN" => ConnectionState::Listen,
            "SYN_SENT" | "SYNSENT" => ConnectionState::SynSent,
            "SYN_RECEIVED" | "SYNRECV" => ConnectionState::SynReceived,
            "FIN_WAIT1" | "FINWAIT1" => ConnectionState::FinWait1,
            "FIN_WAIT2" | "FINWAIT2" => ConnectionState::FinWait2,
            "TIME_WAIT" | "TIMEWAIT" => ConnectionState::TimeWait,
            "CLOSE_WAIT" | "CLOSEWAIT" => ConnectionState::CloseWait,
            "LAST_ACK" | "LASTACK" => ConnectionState::LastAck,
            "CLOSING" => ConnectionState::Closing,
            "CLOSED" => ConnectionState::Closed,
            _ => ConnectionState::Unknown,
        }
    }
}

/// Network connection from memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConnection {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub state: ConnectionState,
    pub pid: u32,
    pub process_name: Option<String>,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

/// Connection analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionAnalysisResult {
    pub connections: Vec<MemoryConnection>,
    pub tcp_count: u32,
    pub udp_count: u32,
    pub suspicious_count: u32,
    pub unique_remote_ips: Vec<String>,
    pub listening_ports: Vec<u16>,
    pub analysis_notes: Vec<String>,
}

// =============================================================================
// Loaded Modules
// =============================================================================

/// Loaded module/DLL from memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedModule {
    pub pid: u32,
    pub process_name: String,
    pub base_address: String,
    pub size: u64,
    pub path: String,
    pub name: String,
    pub version: Option<String>,
    pub is_signed: Option<bool>,
    pub signer: Option<String>,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

/// Module analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleAnalysisResult {
    pub modules: Vec<LoadedModule>,
    pub total_count: u32,
    pub unsigned_count: u32,
    pub suspicious_count: u32,
    pub unique_modules: Vec<String>,
    pub analysis_notes: Vec<String>,
}

// =============================================================================
// Memory Strings
// =============================================================================

/// String category for filtering
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StringCategory {
    Url,
    IpAddress,
    Email,
    FilePath,
    RegistryKey,
    Command,
    Base64,
    Password,
    Interesting,
    All,
}

impl StringCategory {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "url" => StringCategory::Url,
            "ip_address" | "ip" => StringCategory::IpAddress,
            "email" => StringCategory::Email,
            "file_path" | "filepath" | "path" => StringCategory::FilePath,
            "registry_key" | "registry" => StringCategory::RegistryKey,
            "command" | "cmd" => StringCategory::Command,
            "base64" => StringCategory::Base64,
            "password" | "credential" => StringCategory::Password,
            "interesting" => StringCategory::Interesting,
            _ => StringCategory::All,
        }
    }
}

/// Extracted string from memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryString {
    pub offset: u64,
    pub value: String,
    pub category: StringCategory,
    pub encoding: String,
    pub pid: Option<u32>,
    pub is_suspicious: bool,
}

/// String analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringAnalysisResult {
    pub strings: Vec<MemoryString>,
    pub total_count: u32,
    pub by_category: HashMap<String, u32>,
    pub suspicious_count: u32,
    pub analysis_notes: Vec<String>,
}

// =============================================================================
// Memory Analysis Engine
// =============================================================================

/// Memory analyzer with configurable options
pub struct MemoryAnalyzer {
    suspicious_process_names: Vec<String>,
    suspicious_paths: Vec<String>,
    known_malware_hashes: Vec<String>,
    suspicious_ports: Vec<u16>,
}

impl Default for MemoryAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryAnalyzer {
    pub fn new() -> Self {
        Self {
            suspicious_process_names: vec![
                "mimikatz".to_string(),
                "procdump".to_string(),
                "psexec".to_string(),
                "nc.exe".to_string(),
                "netcat".to_string(),
                "ncat".to_string(),
                "powershell_ise".to_string(),
                "wscript".to_string(),
                "cscript".to_string(),
                "mshta".to_string(),
                "regsvr32".to_string(),
                "rundll32".to_string(),
                "certutil".to_string(),
                "bitsadmin".to_string(),
            ],
            suspicious_paths: vec![
                "\\temp\\".to_string(),
                "\\tmp\\".to_string(),
                "\\appdata\\local\\temp".to_string(),
                "\\users\\public".to_string(),
                "\\programdata\\".to_string(),
                "\\recycler\\".to_string(),
                "\\$recycle.bin\\".to_string(),
            ],
            known_malware_hashes: vec![],
            suspicious_ports: vec![
                4444, 5555, 6666, 7777, 8888, 9999, // Common RAT ports
                1337, 31337, // Leet ports
                4545, 6667, 6668, 6669, // IRC/Botnet
            ],
        }
    }

    /// Analyze processes from memory dump metadata
    pub fn analyze_processes(&self, processes: Vec<MemoryProcess>) -> ProcessAnalysisResult {
        let mut result = ProcessAnalysisResult {
            processes: Vec::new(),
            hidden_count: 0,
            suspicious_count: 0,
            total_count: processes.len() as u32,
            analysis_notes: Vec::new(),
        };

        for mut proc in processes {
            // Check for suspicious characteristics
            let mut suspicion_reasons = Vec::new();

            // Check process name
            let name_lower = proc.name.to_lowercase();
            if self.suspicious_process_names.iter().any(|s| name_lower.contains(s)) {
                suspicion_reasons.push(format!("Known suspicious process name: {}", proc.name));
            }

            // Check path
            if let Some(ref path) = proc.path {
                let path_lower = path.to_lowercase();
                for suspicious_path in &self.suspicious_paths {
                    if path_lower.contains(suspicious_path) {
                        suspicion_reasons.push(format!("Suspicious path: {}", path));
                        break;
                    }
                }
            }

            // Check for hidden process
            if proc.is_hidden {
                suspicion_reasons.push("Process is hidden from process list".to_string());
                result.hidden_count += 1;
            }

            // Check for parent-child anomalies (e.g., cmd.exe spawned by Office apps)
            if self.is_unusual_parent_child(&proc) {
                suspicion_reasons.push("Unusual parent-child relationship".to_string());
            }

            proc.is_suspicious = !suspicion_reasons.is_empty();
            proc.suspicion_reasons = suspicion_reasons;

            if proc.is_suspicious {
                result.suspicious_count += 1;
            }

            result.processes.push(proc);
        }

        // Add analysis notes
        if result.hidden_count > 0 {
            result.analysis_notes.push(format!(
                "Found {} hidden process(es) - possible rootkit activity",
                result.hidden_count
            ));
        }

        if result.suspicious_count > 0 {
            result.analysis_notes.push(format!(
                "Found {} suspicious process(es) requiring investigation",
                result.suspicious_count
            ));
        }

        result
    }

    /// Analyze network connections from memory dump
    pub fn analyze_connections(&self, connections: Vec<MemoryConnection>) -> ConnectionAnalysisResult {
        let mut result = ConnectionAnalysisResult {
            connections: Vec::new(),
            tcp_count: 0,
            udp_count: 0,
            suspicious_count: 0,
            unique_remote_ips: Vec::new(),
            listening_ports: Vec::new(),
            analysis_notes: Vec::new(),
        };

        let mut remote_ips: std::collections::HashSet<String> = std::collections::HashSet::new();

        for mut conn in connections {
            // Count by protocol
            match conn.protocol.to_uppercase().as_str() {
                "TCP" | "TCP6" => result.tcp_count += 1,
                "UDP" | "UDP6" => result.udp_count += 1,
                _ => {}
            }

            // Track listening ports
            if conn.state == ConnectionState::Listen {
                result.listening_ports.push(conn.local_port);
            }

            // Track remote IPs
            if let Some(ref remote) = conn.remote_address {
                if remote != "0.0.0.0" && remote != "::" && !remote.starts_with("127.") {
                    remote_ips.insert(remote.clone());
                }
            }

            // Check for suspicious indicators
            let mut suspicion_reasons = Vec::new();

            // Check suspicious ports
            if self.suspicious_ports.contains(&conn.local_port) {
                suspicion_reasons.push(format!("Suspicious local port: {}", conn.local_port));
            }
            if let Some(remote_port) = conn.remote_port {
                if self.suspicious_ports.contains(&remote_port) {
                    suspicion_reasons.push(format!("Suspicious remote port: {}", remote_port));
                }
            }

            // Check for connections to suspicious processes
            if let Some(ref proc_name) = conn.process_name {
                let name_lower = proc_name.to_lowercase();
                if self.suspicious_process_names.iter().any(|s| name_lower.contains(s)) {
                    suspicion_reasons.push(format!("Connection from suspicious process: {}", proc_name));
                }
            }

            conn.is_suspicious = !suspicion_reasons.is_empty();
            conn.suspicion_reasons = suspicion_reasons;

            if conn.is_suspicious {
                result.suspicious_count += 1;
            }

            result.connections.push(conn);
        }

        result.unique_remote_ips = remote_ips.into_iter().collect();
        result.listening_ports.sort();
        result.listening_ports.dedup();

        // Add analysis notes
        if result.suspicious_count > 0 {
            result.analysis_notes.push(format!(
                "Found {} suspicious connection(s)",
                result.suspicious_count
            ));
        }

        result.analysis_notes.push(format!(
            "Total connections: {} TCP, {} UDP",
            result.tcp_count, result.udp_count
        ));

        result.analysis_notes.push(format!(
            "Unique remote IPs: {}",
            result.unique_remote_ips.len()
        ));

        result
    }

    /// Analyze loaded modules
    pub fn analyze_modules(&self, modules: Vec<LoadedModule>) -> ModuleAnalysisResult {
        let mut result = ModuleAnalysisResult {
            modules: Vec::new(),
            total_count: modules.len() as u32,
            unsigned_count: 0,
            suspicious_count: 0,
            unique_modules: Vec::new(),
            analysis_notes: Vec::new(),
        };

        let mut unique: std::collections::HashSet<String> = std::collections::HashSet::new();

        for mut module in modules {
            unique.insert(module.name.to_lowercase());

            let mut suspicion_reasons = Vec::new();

            // Check for unsigned modules
            if module.is_signed == Some(false) {
                result.unsigned_count += 1;
                suspicion_reasons.push("Module is not digitally signed".to_string());
            }

            // Check for modules in suspicious paths
            let path_lower = module.path.to_lowercase();
            for suspicious_path in &self.suspicious_paths {
                if path_lower.contains(suspicious_path) {
                    suspicion_reasons.push(format!("Module loaded from suspicious path: {}", module.path));
                    break;
                }
            }

            module.is_suspicious = !suspicion_reasons.is_empty();
            module.suspicion_reasons = suspicion_reasons;

            if module.is_suspicious {
                result.suspicious_count += 1;
            }

            result.modules.push(module);
        }

        result.unique_modules = unique.into_iter().collect();

        // Add analysis notes
        if result.unsigned_count > 0 {
            result.analysis_notes.push(format!(
                "Found {} unsigned module(s)",
                result.unsigned_count
            ));
        }

        if result.suspicious_count > 0 {
            result.analysis_notes.push(format!(
                "Found {} suspicious module(s)",
                result.suspicious_count
            ));
        }

        result
    }

    /// Extract and analyze strings from memory
    pub fn analyze_strings(
        &self,
        strings: Vec<MemoryString>,
        filter: Option<StringCategory>,
        min_length: Option<usize>,
    ) -> StringAnalysisResult {
        let min_len = min_length.unwrap_or(4);
        let mut result = StringAnalysisResult {
            strings: Vec::new(),
            total_count: 0,
            by_category: HashMap::new(),
            suspicious_count: 0,
            analysis_notes: Vec::new(),
        };

        // Regex patterns for categorization
        let url_regex = Regex::new(r"^https?://[^\s]+$").ok();
        let ip_regex = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").ok();
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").ok();
        let base64_regex = Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").ok();

        for mut s in strings {
            if s.value.len() < min_len {
                continue;
            }

            // Categorize string if not already categorized
            if s.category == StringCategory::All {
                s.category = self.categorize_string(&s.value, &url_regex, &ip_regex, &email_regex, &base64_regex);
            }

            // Apply filter
            if let Some(ref f) = filter {
                if *f != StringCategory::All && s.category != *f {
                    continue;
                }
            }

            // Check if suspicious
            s.is_suspicious = self.is_suspicious_string(&s.value);
            if s.is_suspicious {
                result.suspicious_count += 1;
            }

            // Update category counts
            let cat_name = format!("{:?}", s.category);
            *result.by_category.entry(cat_name).or_insert(0) += 1;

            result.strings.push(s);
            result.total_count += 1;
        }

        result.analysis_notes.push(format!(
            "Extracted {} strings matching criteria",
            result.total_count
        ));

        if result.suspicious_count > 0 {
            result.analysis_notes.push(format!(
                "Found {} potentially suspicious string(s)",
                result.suspicious_count
            ));
        }

        result
    }

    // Helper: Check for unusual parent-child relationships
    fn is_unusual_parent_child(&self, proc: &MemoryProcess) -> bool {
        let name_lower = proc.name.to_lowercase();

        // Examples of suspicious parent-child relationships
        // (simplified - real implementation would check actual parent)
        if name_lower == "cmd.exe" || name_lower == "powershell.exe" {
            // Would check if parent is Office app, etc.
            // For now, just return false
            return false;
        }

        false
    }

    // Helper: Categorize a string
    fn categorize_string(
        &self,
        s: &str,
        url_regex: &Option<Regex>,
        ip_regex: &Option<Regex>,
        email_regex: &Option<Regex>,
        base64_regex: &Option<Regex>,
    ) -> StringCategory {
        if let Some(ref re) = url_regex {
            if re.is_match(s) {
                return StringCategory::Url;
            }
        }

        if let Some(ref re) = ip_regex {
            if re.is_match(s) {
                return StringCategory::IpAddress;
            }
        }

        if let Some(ref re) = email_regex {
            if re.is_match(s) {
                return StringCategory::Email;
            }
        }

        if let Some(ref re) = base64_regex {
            if re.is_match(s) {
                return StringCategory::Base64;
            }
        }

        // Check for file paths
        if s.contains(":\\") || s.starts_with("/") {
            return StringCategory::FilePath;
        }

        // Check for registry keys
        if s.starts_with("HKEY_") || s.starts_with("HKU\\") || s.starts_with("HKLM\\") {
            return StringCategory::RegistryKey;
        }

        StringCategory::All
    }

    // Helper: Check if string is suspicious
    fn is_suspicious_string(&self, s: &str) -> bool {
        let lower = s.to_lowercase();

        // Known suspicious indicators
        let indicators = [
            "mimikatz",
            "sekurlsa",
            "wdigest",
            "kerberos",
            "invoke-",
            "powersploit",
            "empire",
            "cobalt",
            "beacon",
            "meterpreter",
            "metasploit",
            "-encodedcommand",
            "-enc ",
            "frombase64string",
            "downloadstring",
            "invoke-expression",
            "iex(",
            "net user",
            "net localgroup",
            "whoami",
        ];

        for indicator in indicators.iter() {
            if lower.contains(indicator) {
                return true;
            }
        }

        false
    }
}

/// Format process output in Volatility-like style
pub fn format_pslist(processes: &[MemoryProcess]) -> String {
    let mut output = String::new();
    output.push_str("Offset(V)          Name                    PID   PPID   Thds   Hnds   Sess  Wow64 Time\n");
    output.push_str("------------------ -------------------- ------ ------ ------ ------ ------ ------ ----\n");

    for proc in processes {
        output.push_str(&format!(
            "{:<18} {:<20} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {}\n",
            "-", // offset not available in metadata
            if proc.name.len() > 20 { &proc.name[..20] } else { &proc.name },
            proc.pid,
            proc.ppid,
            proc.threads,
            proc.handles,
            "-",
            if proc.wow64 { "True" } else { "False" },
            proc.create_time.map(|t| t.to_rfc3339()).unwrap_or_else(|| "-".to_string())
        ));
    }

    output
}

/// Format connections output in Volatility-like style
pub fn format_netscan(connections: &[MemoryConnection]) -> String {
    let mut output = String::new();
    output.push_str("Proto  Local Address           Foreign Address         State           PID   Process\n");
    output.push_str("------ ----------------------- ----------------------- --------------- ----- -------\n");

    for conn in connections {
        let local = format!("{}:{}", conn.local_address, conn.local_port);
        let remote = match (&conn.remote_address, conn.remote_port) {
            (Some(addr), Some(port)) => format!("{}:{}", addr, port),
            _ => "*:*".to_string(),
        };

        output.push_str(&format!(
            "{:<6} {:<23} {:<23} {:<15} {:>5} {}\n",
            conn.protocol,
            local,
            remote,
            format!("{:?}", conn.state),
            conn.pid,
            conn.process_name.as_deref().unwrap_or("-")
        ));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_analyzer_new() {
        let analyzer = MemoryAnalyzer::new();
        assert!(!analyzer.suspicious_process_names.is_empty());
        assert!(!analyzer.suspicious_ports.is_empty());
    }

    #[test]
    fn test_process_analysis() {
        let analyzer = MemoryAnalyzer::new();
        let processes = vec![
            MemoryProcess {
                pid: 1234,
                ppid: 4,
                name: "mimikatz.exe".to_string(),
                path: Some("C:\\Users\\Public\\mimikatz.exe".to_string()),
                cmdline: None,
                create_time: None,
                exit_time: None,
                threads: 2,
                handles: 50,
                wow64: false,
                is_hidden: false,
                is_suspicious: false,
                suspicion_reasons: vec![],
            },
        ];

        let result = analyzer.analyze_processes(processes);
        assert_eq!(result.suspicious_count, 1);
        assert!(!result.processes[0].suspicion_reasons.is_empty());
    }

    #[test]
    fn test_connection_state_parsing() {
        assert_eq!(ConnectionState::from_str("ESTABLISHED"), ConnectionState::Established);
        assert_eq!(ConnectionState::from_str("LISTEN"), ConnectionState::Listen);
        assert_eq!(ConnectionState::from_str("SYN_SENT"), ConnectionState::SynSent);
    }

    #[test]
    fn test_string_categorization() {
        let analyzer = MemoryAnalyzer::new();
        let url_regex = Regex::new(r"^https?://[^\s]+$").ok();
        let ip_regex = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").ok();
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").ok();
        let base64_regex = Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").ok();

        assert_eq!(
            analyzer.categorize_string("https://malware.com/payload", &url_regex, &ip_regex, &email_regex, &base64_regex),
            StringCategory::Url
        );
        assert_eq!(
            analyzer.categorize_string("192.168.1.1", &url_regex, &ip_regex, &email_regex, &base64_regex),
            StringCategory::IpAddress
        );
    }
}
