//! Native Memory Forensics Engine
//!
//! Pure Rust implementation for memory dump analysis without requiring Volatility.
//!
//! # Features
//!
//! - Memory dump format detection and parsing (Raw, Crash Dump, LiME, VMware, etc.)
//! - Windows process/DLL/credential extraction
//! - Linux task/library extraction
//! - Code injection detection
//! - Rootkit detection
//! - Credential extraction (LSASS, browser, etc.)
//! - Network connection extraction
//!
//! # Example
//!
//! ```ignore
//! use heroforge::forensics::memory_native::{NativeMemoryAnalyzer, AnalysisOptions};
//!
//! let options = AnalysisOptions::default();
//! let analyzer = NativeMemoryAnalyzer::new("/path/to/dump.raw", options)?;
//! let result = analyzer.analyze()?;
//!
//! println!("Found {} processes", result.processes.len());
//! println!("Found {} credentials", result.credentials.len());
//! ```

pub mod types;
pub mod dump_parser;
pub mod windows;
pub mod linux;
pub mod detection;
pub mod extraction;

use anyhow::Result;
use std::path::Path;

pub use types::*;
pub use dump_parser::ParsedDump;

/// Native memory forensics analyzer
pub struct NativeMemoryAnalyzer {
    /// Parsed dump file
    dump: ParsedDump,
    /// Analysis options
    options: AnalysisOptions,
}

/// Analysis options
#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    /// Extract processes
    pub extract_processes: bool,
    /// Extract modules/DLLs
    pub extract_modules: bool,
    /// Extract network connections
    pub extract_network: bool,
    /// Extract credentials
    pub extract_credentials: bool,
    /// Extract registry (Windows)
    pub extract_registry: bool,
    /// Detect code injection
    pub detect_injection: bool,
    /// Detect rootkits
    pub detect_rootkits: bool,
    /// Maximum processes to enumerate
    pub max_processes: usize,
    /// Enable verbose output
    pub verbose: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            extract_processes: true,
            extract_modules: true,
            extract_network: true,
            extract_credentials: true,
            extract_registry: false, // Can be slow
            detect_injection: true,
            detect_rootkits: true,
            max_processes: 10000,
            verbose: false,
        }
    }
}

impl NativeMemoryAnalyzer {
    /// Create a new analyzer for a memory dump file
    pub fn new<P: AsRef<Path>>(path: P, options: AnalysisOptions) -> Result<Self> {
        let dump = ParsedDump::open(path)?;

        Ok(Self { dump, options })
    }

    /// Create analyzer from an already-parsed dump
    pub fn from_parsed_dump(dump: ParsedDump, options: AnalysisOptions) -> Self {
        Self { dump, options }
    }

    /// Run full analysis
    pub fn analyze(&self) -> Result<MemoryAnalysisResult> {
        let mut result = MemoryAnalysisResult {
            dump_info: self.dump.info.clone(),
            ..Default::default()
        };

        // Determine OS type and run appropriate analysis
        match self.dump.info.os_type {
            Some(OsType::Windows) | None if self.dump.info.format == DumpFormat::CrashDump => {
                self.analyze_windows(&mut result)?;
            }
            Some(OsType::Linux) | None if self.dump.info.format == DumpFormat::LiME => {
                self.analyze_linux(&mut result)?;
            }
            _ => {
                // Try Windows analysis as default
                if let Err(_) = self.analyze_windows(&mut result) {
                    // Fall back to Linux
                    self.analyze_linux(&mut result)?;
                }
            }
        }

        // Run cross-platform detections
        if self.options.detect_injection && !result.processes.is_empty() {
            let injections = detection::detect_all_injections(&self.dump, &result.processes)?;
            result.injections = injections;
        }

        Ok(result)
    }

    /// Analyze Windows memory dump
    fn analyze_windows(&self, result: &mut MemoryAnalysisResult) -> Result<()> {
        use windows::WindowsAnalyzer;

        let mut analyzer = WindowsAnalyzer::new(&self.dump);
        analyzer.initialize()?;

        // Extract processes
        if self.options.extract_processes {
            let enumerator = windows::ProcessEnumerator::new(&analyzer);
            result.processes = enumerator.enumerate()?;

            if result.processes.len() > self.options.max_processes {
                result.processes.truncate(self.options.max_processes);
                result.notes.push(format!(
                    "Process list truncated to {} entries",
                    self.options.max_processes
                ));
            }
        }

        // Extract DLLs
        if self.options.extract_modules && !result.processes.is_empty() {
            let dll_enum = windows::DllEnumerator::new(&analyzer);
            result.modules = dll_enum.enumerate_all(&result.processes)?;
        }

        // Extract network connections
        if self.options.extract_network {
            let net_enum = windows::NetworkExtractor::new(&analyzer);
            result.connections = net_enum.extract_connections()?;
        }

        // Extract credentials
        if self.options.extract_credentials {
            let cred_extractor = windows::CredentialExtractor::new(&analyzer);
            result.credentials = cred_extractor.extract_all(&result.processes)?;
        }

        // Extract kernel modules (drivers)
        let kernel_extractor = windows::KernelExtractor::new(&analyzer);
        result.drivers = kernel_extractor.extract_drivers()?;

        // Detect rootkits
        if self.options.detect_rootkits {
            let rootkit_indicators = detection::rootkit::detect_rootkits(&self.dump, &result.drivers)?;

            for indicator in rootkit_indicators {
                result.notes.push(format!(
                    "Rootkit indicator: {} - {} (confidence: {}%)",
                    indicator.indicator_type,
                    indicator.description,
                    indicator.confidence
                ));
            }
        }

        Ok(())
    }

    /// Analyze Linux memory dump
    fn analyze_linux(&self, result: &mut MemoryAnalysisResult) -> Result<()> {
        use linux::LinuxAnalyzer;

        let mut analyzer = LinuxAnalyzer::new(&self.dump);
        analyzer.initialize()?;

        // Extract tasks (processes)
        if self.options.extract_processes {
            let task_enum = linux::TaskEnumerator::new(&analyzer);
            let tasks = task_enum.enumerate()?;

            // Convert LinuxTask to ProcessInfo
            for task in tasks {
                result.processes.push(ProcessInfo {
                    eprocess_addr: task.task_addr,
                    pid: task.pid as u32,
                    ppid: task.ppid as u32,
                    name: task.comm,
                    path: None,
                    cmdline: None,
                    create_time: None,
                    exit_time: None,
                    dtb: task.pgd,
                    peb: 0,
                    session_id: None,
                    is_wow64: false,
                    thread_count: 0,
                    handle_count: 0,
                    exit_status: None,
                    integrity: None,
                    token_user: if task.uid == 0 { Some("root".to_string()) } else { None },
                });
            }
        }

        // Extract network connections
        if self.options.extract_network {
            let net_extractor = linux::NetworkExtractor::new(&analyzer);
            result.connections = net_extractor.extract_connections()?;
        }

        // Extract kernel modules
        let kernel_extractor = linux::KernelExtractor::new(&analyzer);
        let linux_modules = kernel_extractor.extract_modules()?;

        for module in linux_modules {
            result.drivers.push(DriverInfo {
                base_addr: module.base_addr,
                size: module.size,
                name: module.name,
                path: String::new(),
                service_name: None,
                load_order: None,
            });
        }

        Ok(())
    }

    /// Get reference to the parsed dump
    pub fn dump(&self) -> &ParsedDump {
        &self.dump
    }

    /// Get dump info
    pub fn info(&self) -> &DumpInfo {
        &self.dump.info
    }

    /// Search for a pattern in the dump
    pub fn search_pattern(&self, pattern: &[u8]) -> Vec<u64> {
        self.dump.search_pattern(pattern)
    }

    /// Run malware pattern scanning
    pub fn scan_for_malware(&self) -> Vec<detection::ScanMatch> {
        let scanner = detection::MemoryScanner::new();
        scanner.scan(&self.dump)
    }
}

/// Quick analysis function for simple use cases
pub fn analyze_memory_dump<P: AsRef<Path>>(path: P) -> Result<MemoryAnalysisResult> {
    let analyzer = NativeMemoryAnalyzer::new(path, AnalysisOptions::default())?;
    analyzer.analyze()
}

/// Detect dump format from file
pub fn detect_dump_format<P: AsRef<Path>>(path: P) -> Result<DumpFormat> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path)?;
    let mut header = [0u8; 16];
    file.read_exact(&mut header)?;

    Ok(DumpFormat::detect(&header))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_options_default() {
        let options = AnalysisOptions::default();
        assert!(options.extract_processes);
        assert!(options.extract_credentials);
        assert!(options.detect_injection);
    }

    #[test]
    fn test_dump_format_detection() {
        assert_eq!(DumpFormat::detect(b"PAGEDUMP\x00\x00\x00\x00\x00\x00\x00\x00"), DumpFormat::CrashDump);
        assert_eq!(DumpFormat::detect(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DumpFormat::Raw);
    }
}
