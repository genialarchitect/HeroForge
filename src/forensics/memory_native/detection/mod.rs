//! Malware and anomaly detection in memory dumps
//!
//! Detect code injection, rootkits, hidden processes, and other threats.

pub mod injection;
pub mod rootkit;
pub mod hidden;

pub use injection::*;
pub use rootkit::*;
pub use hidden::*;

use super::dump_parser::ParsedDump;
use super::types::{InjectionResult, InjectionType, MemoryAnalysisResult, ProcessInfo};
use anyhow::Result;

/// Run all detection routines
pub fn run_all_detections(
    dump: &ParsedDump,
    processes: &[ProcessInfo],
    result: &mut MemoryAnalysisResult,
) -> Result<()> {
    // Detect code injection
    let injections = detect_all_injections(dump, processes)?;
    result.injections = injections;

    // Detect hidden processes
    // Would need both linked-list and scan-based process lists
    // result.hidden_processes = ...

    // Add detection notes
    if !result.injections.is_empty() {
        result.notes.push(format!(
            "Found {} potential code injection(s)",
            result.injections.len()
        ));
    }

    Ok(())
}

/// Detect all types of code injection across processes
pub fn detect_all_injections(dump: &ParsedDump, processes: &[ProcessInfo]) -> Result<Vec<InjectionResult>> {
    let mut all_injections = Vec::new();

    for process in processes {
        // Skip system process
        if process.pid <= 4 {
            continue;
        }

        // Check for various injection types
        let injections = injection::detect_injections(dump, process)?;
        all_injections.extend(injections);
    }

    Ok(all_injections)
}

/// YARA-like pattern matching for memory
pub struct MemoryScanner {
    /// Patterns to search for
    patterns: Vec<ScanPattern>,
}

/// A pattern to search for
#[derive(Debug, Clone)]
pub struct ScanPattern {
    /// Pattern name
    pub name: String,
    /// Byte pattern (0xFF = wildcard)
    pub bytes: Vec<u8>,
    /// Mask (0xFF = must match, 0x00 = wildcard)
    pub mask: Vec<u8>,
    /// Description
    pub description: String,
    /// Severity (1-10)
    pub severity: u8,
}

impl MemoryScanner {
    /// Create new scanner with default patterns
    pub fn new() -> Self {
        Self {
            patterns: Self::default_patterns(),
        }
    }

    /// Create scanner with custom patterns
    pub fn with_patterns(patterns: Vec<ScanPattern>) -> Self {
        Self { patterns }
    }

    /// Default malware patterns
    fn default_patterns() -> Vec<ScanPattern> {
        vec![
            // Metasploit meterpreter
            ScanPattern {
                name: "Meterpreter_Reverse_TCP".to_string(),
                bytes: vec![0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8],
                mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                description: "Metasploit reverse TCP shellcode".to_string(),
                severity: 9,
            },
            // Cobalt Strike beacon
            ScanPattern {
                name: "Cobalt_Strike_Beacon".to_string(),
                bytes: vec![0x4D, 0x5A, 0x41, 0x52, 0x55, 0x48, 0x89, 0xE5],
                mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                description: "Cobalt Strike beacon header".to_string(),
                severity: 10,
            },
            // Common shellcode NOP sled
            ScanPattern {
                name: "NOP_Sled".to_string(),
                bytes: vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                           0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
                mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                description: "NOP sled (shellcode indicator)".to_string(),
                severity: 5,
            },
            // Mimikatz strings
            ScanPattern {
                name: "Mimikatz_String".to_string(),
                bytes: b"sekurlsa".to_vec(),
                mask: vec![0xFF; 8],
                description: "Mimikatz module name".to_string(),
                severity: 9,
            },
            // PowerShell download cradle
            ScanPattern {
                name: "PowerShell_Download".to_string(),
                bytes: b"DownloadString".to_vec(),
                mask: vec![0xFF; 14],
                description: "PowerShell download method".to_string(),
                severity: 7,
            },
        ]
    }

    /// Scan memory dump for patterns
    pub fn scan(&self, dump: &ParsedDump) -> Vec<ScanMatch> {
        let mut matches = Vec::new();

        for pattern in &self.patterns {
            let found = dump.search_pattern_masked(&pattern.bytes, &pattern.mask);

            for offset in found {
                matches.push(ScanMatch {
                    pattern_name: pattern.name.clone(),
                    offset,
                    severity: pattern.severity,
                    description: pattern.description.clone(),
                });
            }
        }

        // Sort by severity
        matches.sort_by(|a, b| b.severity.cmp(&a.severity));

        matches
    }
}

impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a pattern match
#[derive(Debug, Clone)]
pub struct ScanMatch {
    /// Pattern that matched
    pub pattern_name: String,
    /// Offset in dump
    pub offset: u64,
    /// Severity
    pub severity: u8,
    /// Description
    pub description: String,
}

/// Check memory region characteristics for anomalies
pub fn check_memory_anomalies(dump: &ParsedDump, _process: &ProcessInfo) -> Vec<MemoryAnomaly> {
    let mut anomalies = Vec::new();

    // This would analyze process VADs/VMAs for:
    // - RWX regions
    // - Unbacked executable regions
    // - Suspicious allocations

    // Placeholder - would need VAD/VMA enumeration
    let _ = dump;

    anomalies
}

/// A detected memory anomaly
#[derive(Debug, Clone)]
pub struct MemoryAnomaly {
    /// Address of anomaly
    pub address: u64,
    /// Size of region
    pub size: u64,
    /// Type of anomaly
    pub anomaly_type: String,
    /// Description
    pub description: String,
    /// Severity (1-10)
    pub severity: u8,
}
