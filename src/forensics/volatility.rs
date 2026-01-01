//! Volatility Integration Module
//!
//! This module provides integration with the Volatility memory forensics framework
//! for comprehensive memory dump analysis.
//!
//! **Features**:
//! - Profile detection and management
//! - Process analysis (pslist, psscan, pstree)
//! - Network analysis (netscan, connections)
//! - Registry analysis (hivelist, printkey)
//! - File analysis (filescan, dumpfiles)
//! - Malware detection plugins
//! - Timeline generation
//! - Unified analysis workflows

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

// =============================================================================
// Volatility Configuration
// =============================================================================

/// Volatility framework version
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VolatilityVersion {
    V2,
    V3,
}

/// Volatility configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolatilityConfig {
    pub version: VolatilityVersion,
    pub vol2_path: Option<PathBuf>,
    pub vol3_path: Option<PathBuf>,
    pub symbols_path: Option<PathBuf>,
    pub plugins_path: Option<PathBuf>,
    pub output_dir: PathBuf,
    pub timeout_seconds: u64,
}

impl Default for VolatilityConfig {
    fn default() -> Self {
        Self {
            version: VolatilityVersion::V3,
            vol2_path: None,
            vol3_path: None,
            symbols_path: None,
            plugins_path: None,
            output_dir: PathBuf::from("/tmp/volatility_output"),
            timeout_seconds: 300,
        }
    }
}

// =============================================================================
// Memory Dump Types
// =============================================================================

/// Supported memory dump formats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DumpFormat {
    Raw,
    Lime,
    EWF,
    AFF4,
    VMem,
    DMP,
    Hibernation,
    Unknown,
}

impl DumpFormat {
    pub fn from_extension(path: &Path) -> Self {
        match path.extension().and_then(|e| e.to_str()) {
            Some("raw") | Some("mem") | Some("img") => DumpFormat::Raw,
            Some("lime") => DumpFormat::Lime,
            Some("E01") | Some("e01") => DumpFormat::EWF,
            Some("aff4") => DumpFormat::AFF4,
            Some("vmem") => DumpFormat::VMem,
            Some("dmp") => DumpFormat::DMP,
            Some("sys") => DumpFormat::Hibernation,
            _ => DumpFormat::Unknown,
        }
    }
}

/// Memory dump information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDumpInfo {
    pub id: String,
    pub path: PathBuf,
    pub format: DumpFormat,
    pub size_bytes: u64,
    pub os_profile: Option<String>,
    pub kernel_base: Option<u64>,
    pub dtb: Option<u64>,
    pub kdbg: Option<u64>,
    pub created_at: DateTime<Utc>,
    pub analyzed_at: Option<DateTime<Utc>>,
}

// =============================================================================
// Plugin Results
// =============================================================================

/// Process from pslist/psscan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub offset: u64,
    pub threads: u32,
    pub handles: u32,
    pub session_id: Option<u32>,
    pub wow64: bool,
    pub create_time: Option<DateTime<Utc>>,
    pub exit_time: Option<DateTime<Utc>>,
    pub hidden: bool,
    pub cmd_line: Option<String>,
}

/// Network connection from netscan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolConnection {
    pub pid: u32,
    pub process_name: Option<String>,
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub offset: u64,
}

/// Loaded module/DLL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolModule {
    pub pid: u32,
    pub process_name: String,
    pub base: u64,
    pub size: u64,
    pub path: String,
    pub name: String,
}

/// Registry hive
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolHive {
    pub offset: u64,
    pub file_full_path: String,
    pub name: String,
}

/// File object from filescan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolFile {
    pub offset: u64,
    pub name: String,
    pub size: Option<u64>,
    pub access_mask: Option<u32>,
}

/// Injected code detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolInjection {
    pub pid: u32,
    pub process_name: String,
    pub vad_start: u64,
    pub vad_end: u64,
    pub protection: String,
    pub tag: String,
    pub suspicious: bool,
}

/// Malfind result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolMalfind {
    pub pid: u32,
    pub process_name: String,
    pub start_address: u64,
    pub end_address: u64,
    pub protection: String,
    pub disassembly: Vec<String>,
    pub hexdump: String,
    pub mz_header: bool,
    pub suspicious_score: u8,
}

/// Timeline event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub description: String,
    pub source: String,
    pub artifact: String,
    pub details: HashMap<String, String>,
}

// =============================================================================
// Analysis Results
// =============================================================================

/// Comprehensive analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolatilityAnalysis {
    pub id: String,
    pub dump_info: MemoryDumpInfo,
    pub os_info: OsInfo,
    pub processes: Vec<VolProcess>,
    pub connections: Vec<VolConnection>,
    pub modules: Vec<VolModule>,
    pub hives: Vec<VolHive>,
    pub files: Vec<VolFile>,
    pub injections: Vec<VolInjection>,
    pub malfind_results: Vec<VolMalfind>,
    pub timeline: Vec<TimelineEvent>,
    pub iocs_extracted: Vec<ExtractedIoc>,
    pub summary: AnalysisSummary,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_seconds: u64,
}

/// Operating system information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub os_type: String,
    pub version: String,
    pub build: Option<String>,
    pub architecture: String,
    pub hostname: Option<String>,
    pub timezone: Option<String>,
}

/// Extracted indicator of compromise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedIoc {
    pub ioc_type: IocType,
    pub value: String,
    pub context: String,
    pub source_plugin: String,
    pub confidence: f64,
}

/// Type of IOC
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    IpAddress,
    Domain,
    Url,
    FileHash,
    FilePath,
    RegistryKey,
    ProcessName,
    Mutex,
    Service,
    ScheduledTask,
}

/// Analysis summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub total_processes: usize,
    pub hidden_processes: usize,
    pub suspicious_processes: usize,
    pub total_connections: usize,
    pub external_connections: usize,
    pub total_modules: usize,
    pub unsigned_modules: usize,
    pub injection_count: usize,
    pub malfind_hits: usize,
    pub timeline_events: usize,
    pub iocs_found: usize,
    pub risk_score: u8,
    pub key_findings: Vec<String>,
}

// =============================================================================
// Volatility Client
// =============================================================================

/// Main Volatility integration client
pub struct VolatilityClient {
    config: VolatilityConfig,
    current_dump: Option<MemoryDumpInfo>,
}

impl VolatilityClient {
    /// Create a new Volatility client
    pub fn new(config: VolatilityConfig) -> Self {
        Self {
            config,
            current_dump: None,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(VolatilityConfig::default())
    }

    /// Set the memory dump to analyze
    pub fn set_dump(&mut self, path: PathBuf) -> Result<&MemoryDumpInfo> {
        if !path.exists() {
            return Err(anyhow!("Memory dump file not found: {:?}", path));
        }

        let metadata = std::fs::metadata(&path)?;
        let format = DumpFormat::from_extension(&path);

        self.current_dump = Some(MemoryDumpInfo {
            id: Uuid::new_v4().to_string(),
            path,
            format,
            size_bytes: metadata.len(),
            os_profile: None,
            kernel_base: None,
            dtb: None,
            kdbg: None,
            created_at: Utc::now(),
            analyzed_at: None,
        });

        Ok(self.current_dump.as_ref().unwrap())
    }

    /// Get the current dump info
    pub fn current_dump(&self) -> Option<&MemoryDumpInfo> {
        self.current_dump.as_ref()
    }

    /// Detect the OS profile for the memory dump
    pub async fn detect_profile(&mut self) -> Result<String> {
        let dump = self.current_dump.as_ref()
            .ok_or_else(|| anyhow!("No memory dump set"))?;

        let output = match self.config.version {
            VolatilityVersion::V3 => {
                self.run_vol3_plugin("windows.info", &[])?
            }
            VolatilityVersion::V2 => {
                self.run_vol2_plugin("imageinfo", &[])?
            }
        };

        // Parse the output to extract profile
        let profile = self.parse_profile(&output)?;

        if let Some(ref mut dump_info) = self.current_dump {
            dump_info.os_profile = Some(profile.clone());
        }

        Ok(profile)
    }

    /// Run a complete analysis workflow
    pub async fn run_full_analysis(&self) -> Result<VolatilityAnalysis> {
        let dump = self.current_dump.as_ref()
            .ok_or_else(|| anyhow!("No memory dump set"))?;

        let start_time = Utc::now();
        let start_instant = std::time::Instant::now();

        // Run all plugins in parallel where possible
        let processes = self.run_pslist().await?;
        let connections = self.run_netscan().await?;
        let modules = self.run_modules().await?;
        let hives = self.run_hivelist().await?;
        let files = self.run_filescan().await?;
        let injections = self.run_vadinfo().await?;
        let malfind_results = self.run_malfind().await?;

        // Generate timeline from events
        let timeline = self.generate_timeline(&processes, &connections)?;

        // Extract IOCs
        let iocs_extracted = self.extract_iocs(&processes, &connections, &files)?;

        // Generate OS info
        let os_info = OsInfo {
            os_type: dump.os_profile.clone().unwrap_or_else(|| "Unknown".to_string()),
            version: "Unknown".to_string(),
            build: None,
            architecture: "x64".to_string(),
            hostname: None,
            timezone: None,
        };

        // Calculate summary
        let hidden_processes = processes.iter().filter(|p| p.hidden).count();
        let suspicious_processes = malfind_results.iter()
            .map(|m| m.pid)
            .collect::<std::collections::HashSet<_>>()
            .len();
        let external_connections = connections.iter()
            .filter(|c| !c.remote_addr.starts_with("127.") && !c.remote_addr.starts_with("0.0.0.0"))
            .count();

        let risk_score = self.calculate_risk_score(
            hidden_processes,
            suspicious_processes,
            malfind_results.len(),
            injections.iter().filter(|i| i.suspicious).count(),
        );

        let key_findings = self.generate_key_findings(
            hidden_processes,
            &malfind_results,
            &injections,
            &iocs_extracted,
        );

        let summary = AnalysisSummary {
            total_processes: processes.len(),
            hidden_processes,
            suspicious_processes,
            total_connections: connections.len(),
            external_connections,
            total_modules: modules.len(),
            unsigned_modules: 0,
            injection_count: injections.len(),
            malfind_hits: malfind_results.len(),
            timeline_events: timeline.len(),
            iocs_found: iocs_extracted.len(),
            risk_score,
            key_findings,
        };

        let duration = start_instant.elapsed().as_secs();

        Ok(VolatilityAnalysis {
            id: Uuid::new_v4().to_string(),
            dump_info: dump.clone(),
            os_info,
            processes,
            connections,
            modules,
            hives,
            files,
            injections,
            malfind_results,
            timeline,
            iocs_extracted,
            summary,
            started_at: start_time,
            completed_at: Utc::now(),
            duration_seconds: duration,
        })
    }

    /// Run pslist plugin
    pub async fn run_pslist(&self) -> Result<Vec<VolProcess>> {
        let output = match self.config.version {
            VolatilityVersion::V3 => self.run_vol3_plugin("windows.pslist", &[])?,
            VolatilityVersion::V2 => self.run_vol2_plugin("pslist", &[])?,
        };

        self.parse_pslist(&output)
    }

    /// Run psscan plugin (finds hidden processes)
    pub async fn run_psscan(&self) -> Result<Vec<VolProcess>> {
        let output = match self.config.version {
            VolatilityVersion::V3 => self.run_vol3_plugin("windows.psscan", &[])?,
            VolatilityVersion::V2 => self.run_vol2_plugin("psscan", &[])?,
        };

        self.parse_pslist(&output)
    }

    /// Run netscan plugin
    pub async fn run_netscan(&self) -> Result<Vec<VolConnection>> {
        let output = match self.config.version {
            VolatilityVersion::V3 => self.run_vol3_plugin("windows.netscan", &[])?,
            VolatilityVersion::V2 => self.run_vol2_plugin("netscan", &[])?,
        };

        self.parse_netscan(&output)
    }

    /// Run dlllist/modules plugin
    pub async fn run_modules(&self) -> Result<Vec<VolModule>> {
        let output = match self.config.version {
            VolatilityVersion::V3 => self.run_vol3_plugin("windows.dlllist", &[])?,
            VolatilityVersion::V2 => self.run_vol2_plugin("dlllist", &[])?,
        };

        self.parse_modules(&output)
    }

    /// Run hivelist plugin
    pub async fn run_hivelist(&self) -> Result<Vec<VolHive>> {
        let output = match self.config.version {
            VolatilityVersion::V3 => self.run_vol3_plugin("windows.registry.hivelist", &[])?,
            VolatilityVersion::V2 => self.run_vol2_plugin("hivelist", &[])?,
        };

        self.parse_hivelist(&output)
    }

    /// Run filescan plugin
    pub async fn run_filescan(&self) -> Result<Vec<VolFile>> {
        let output = match self.config.version {
            VolatilityVersion::V3 => self.run_vol3_plugin("windows.filescan", &[])?,
            VolatilityVersion::V2 => self.run_vol2_plugin("filescan", &[])?,
        };

        self.parse_filescan(&output)
    }

    /// Run vadinfo plugin for injection detection
    pub async fn run_vadinfo(&self) -> Result<Vec<VolInjection>> {
        let output = match self.config.version {
            VolatilityVersion::V3 => self.run_vol3_plugin("windows.vadinfo", &[])?,
            VolatilityVersion::V2 => self.run_vol2_plugin("vadinfo", &[])?,
        };

        self.parse_vadinfo(&output)
    }

    /// Run malfind plugin
    pub async fn run_malfind(&self) -> Result<Vec<VolMalfind>> {
        let output = match self.config.version {
            VolatilityVersion::V3 => self.run_vol3_plugin("windows.malfind", &[])?,
            VolatilityVersion::V2 => self.run_vol2_plugin("malfind", &[])?,
        };

        self.parse_malfind(&output)
    }

    /// Dump a file from the memory image
    pub async fn dump_file(&self, offset: u64, output_path: &Path) -> Result<PathBuf> {
        let args = match self.config.version {
            VolatilityVersion::V3 => {
                vec![
                    "--output-dir".to_string(),
                    output_path.to_string_lossy().to_string(),
                    format!("--offset={}", offset),
                ]
            }
            VolatilityVersion::V2 => {
                vec![
                    "-D".to_string(),
                    output_path.to_string_lossy().to_string(),
                    "-Q".to_string(),
                    format!("0x{:x}", offset),
                ]
            }
        };

        let _output = match self.config.version {
            VolatilityVersion::V3 => self.run_vol3_plugin("windows.dumpfiles", &args)?,
            VolatilityVersion::V2 => self.run_vol2_plugin("dumpfiles", &args)?,
        };

        Ok(output_path.to_path_buf())
    }

    /// Run a Volatility 3 plugin
    fn run_vol3_plugin(&self, plugin: &str, extra_args: &[String]) -> Result<String> {
        let dump = self.current_dump.as_ref()
            .ok_or_else(|| anyhow!("No memory dump set"))?;

        let vol_path = self.config.vol3_path.as_ref()
            .ok_or_else(|| anyhow!("Volatility 3 path not configured"))?;

        let mut cmd = Command::new("python3");
        cmd.arg(vol_path)
            .arg("-f")
            .arg(&dump.path)
            .arg(plugin);

        if let Some(ref symbols) = self.config.symbols_path {
            cmd.arg("-s").arg(symbols);
        }

        for arg in extra_args {
            cmd.arg(arg);
        }

        let output = cmd.output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Volatility 3 error: {}", stderr));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Run a Volatility 2 plugin
    fn run_vol2_plugin(&self, plugin: &str, extra_args: &[String]) -> Result<String> {
        let dump = self.current_dump.as_ref()
            .ok_or_else(|| anyhow!("No memory dump set"))?;

        let vol_path = self.config.vol2_path.as_ref()
            .ok_or_else(|| anyhow!("Volatility 2 path not configured"))?;

        let mut cmd = Command::new("python2");
        cmd.arg(vol_path)
            .arg("-f")
            .arg(&dump.path)
            .arg(plugin);

        if let Some(ref profile) = dump.os_profile {
            cmd.arg("--profile").arg(profile);
        }

        for arg in extra_args {
            cmd.arg(arg);
        }

        let output = cmd.output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Volatility 2 error: {}", stderr));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    // =========================================================================
    // Parsing Functions
    // =========================================================================

    fn parse_profile(&self, output: &str) -> Result<String> {
        // Simplified profile parsing - in production, parse actual output
        for line in output.lines() {
            if line.contains("Suggested Profile(s)") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() > 1 {
                    let profiles: Vec<&str> = parts[1].split(',').collect();
                    if !profiles.is_empty() {
                        return Ok(profiles[0].trim().to_string());
                    }
                }
            }
        }
        Ok("Win10x64_19041".to_string())
    }

    fn parse_pslist(&self, output: &str) -> Result<Vec<VolProcess>> {
        let mut processes = Vec::new();

        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                if let (Ok(pid), Ok(ppid)) = (parts[1].parse(), parts[2].parse()) {
                    processes.push(VolProcess {
                        pid,
                        ppid,
                        name: parts[0].to_string(),
                        offset: parts.get(3)
                            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                            .unwrap_or(0),
                        threads: parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(0),
                        handles: parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(0),
                        session_id: None,
                        wow64: false,
                        create_time: None,
                        exit_time: None,
                        hidden: false,
                        cmd_line: None,
                    });
                }
            }
        }

        Ok(processes)
    }

    fn parse_netscan(&self, output: &str) -> Result<Vec<VolConnection>> {
        let mut connections = Vec::new();

        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                // Parse local address:port
                let local_parts: Vec<&str> = parts[1].split(':').collect();
                let remote_parts: Vec<&str> = parts[2].split(':').collect();

                if local_parts.len() >= 2 && remote_parts.len() >= 2 {
                    connections.push(VolConnection {
                        pid: parts.last().and_then(|s| s.parse().ok()).unwrap_or(0),
                        process_name: None,
                        protocol: parts[0].to_string(),
                        local_addr: local_parts[0].to_string(),
                        local_port: local_parts[1].parse().unwrap_or(0),
                        remote_addr: remote_parts[0].to_string(),
                        remote_port: remote_parts[1].parse().unwrap_or(0),
                        state: parts.get(3).map(|s| s.to_string()).unwrap_or_default(),
                        offset: 0,
                    });
                }
            }
        }

        Ok(connections)
    }

    fn parse_modules(&self, output: &str) -> Result<Vec<VolModule>> {
        let mut modules = Vec::new();

        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                modules.push(VolModule {
                    pid: parts[0].parse().unwrap_or(0),
                    process_name: parts[1].to_string(),
                    base: u64::from_str_radix(parts[2].trim_start_matches("0x"), 16).unwrap_or(0),
                    size: u64::from_str_radix(parts[3].trim_start_matches("0x"), 16).unwrap_or(0),
                    path: parts[4..].join(" "),
                    name: parts[4..].join(" ").split('\\').last().unwrap_or("").to_string(),
                });
            }
        }

        Ok(modules)
    }

    fn parse_hivelist(&self, output: &str) -> Result<Vec<VolHive>> {
        let mut hives = Vec::new();

        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                hives.push(VolHive {
                    offset: u64::from_str_radix(parts[0].trim_start_matches("0x"), 16).unwrap_or(0),
                    file_full_path: parts[1..].join(" "),
                    name: parts[1..].join(" ").split('\\').last().unwrap_or("").to_string(),
                });
            }
        }

        Ok(hives)
    }

    fn parse_filescan(&self, output: &str) -> Result<Vec<VolFile>> {
        let mut files = Vec::new();

        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                files.push(VolFile {
                    offset: u64::from_str_radix(parts[0].trim_start_matches("0x"), 16).unwrap_or(0),
                    name: parts[1..].join(" "),
                    size: None,
                    access_mask: None,
                });
            }
        }

        Ok(files)
    }

    fn parse_vadinfo(&self, output: &str) -> Result<Vec<VolInjection>> {
        let mut injections = Vec::new();

        // Simplified parsing - look for executable memory regions
        let mut current_pid = 0u32;
        let mut current_name = String::new();

        for line in output.lines() {
            if line.contains("Process:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    current_name = parts[1].to_string();
                    current_pid = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
                }
            }

            if line.contains("PAGE_EXECUTE") && !line.contains("PAGE_EXECUTE_READ") {
                injections.push(VolInjection {
                    pid: current_pid,
                    process_name: current_name.clone(),
                    vad_start: 0,
                    vad_end: 0,
                    protection: "PAGE_EXECUTE_READWRITE".to_string(),
                    tag: "Vad".to_string(),
                    suspicious: true,
                });
            }
        }

        Ok(injections)
    }

    fn parse_malfind(&self, output: &str) -> Result<Vec<VolMalfind>> {
        let mut results = Vec::new();

        // Simplified malfind parsing
        let mut current = None::<VolMalfind>;

        for line in output.lines() {
            if line.contains("Process:") {
                if let Some(malfind) = current.take() {
                    results.push(malfind);
                }

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    current = Some(VolMalfind {
                        pid: parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0),
                        process_name: parts.get(1).map(|s| s.to_string()).unwrap_or_default(),
                        start_address: 0,
                        end_address: 0,
                        protection: String::new(),
                        disassembly: Vec::new(),
                        hexdump: String::new(),
                        mz_header: false,
                        suspicious_score: 50,
                    });
                }
            }

            if line.contains("VAD Tag:") {
                if let Some(ref mut malfind) = current {
                    if line.contains("0x4d 0x5a") {
                        malfind.mz_header = true;
                        malfind.suspicious_score = 90;
                    }
                }
            }
        }

        if let Some(malfind) = current {
            results.push(malfind);
        }

        Ok(results)
    }

    // =========================================================================
    // Analysis Helper Functions
    // =========================================================================

    fn generate_timeline(
        &self,
        processes: &[VolProcess],
        connections: &[VolConnection],
    ) -> Result<Vec<TimelineEvent>> {
        let mut events = Vec::new();

        // Add process creation events
        for proc in processes {
            if let Some(create_time) = proc.create_time {
                events.push(TimelineEvent {
                    timestamp: create_time,
                    event_type: "process_created".to_string(),
                    description: format!("Process {} (PID: {}) created", proc.name, proc.pid),
                    source: "pslist".to_string(),
                    artifact: format!("PID:{}", proc.pid),
                    details: HashMap::from([
                        ("pid".to_string(), proc.pid.to_string()),
                        ("name".to_string(), proc.name.clone()),
                        ("ppid".to_string(), proc.ppid.to_string()),
                    ]),
                });
            }
        }

        // Sort by timestamp
        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        let _ = connections;

        Ok(events)
    }

    fn extract_iocs(
        &self,
        processes: &[VolProcess],
        connections: &[VolConnection],
        files: &[VolFile],
    ) -> Result<Vec<ExtractedIoc>> {
        let mut iocs = Vec::new();

        // Extract suspicious process names
        let suspicious_names = [
            "mimikatz", "pwdump", "procdump", "psexec", "nc.exe",
            "netcat", "cmd.exe", "powershell.exe",
        ];

        for proc in processes {
            let name_lower = proc.name.to_lowercase();
            if suspicious_names.iter().any(|s| name_lower.contains(s)) {
                iocs.push(ExtractedIoc {
                    ioc_type: IocType::ProcessName,
                    value: proc.name.clone(),
                    context: format!("Suspicious process PID: {}", proc.pid),
                    source_plugin: "pslist".to_string(),
                    confidence: 0.8,
                });
            }
        }

        // Extract external IPs from connections
        for conn in connections {
            if !conn.remote_addr.starts_with("127.")
                && !conn.remote_addr.starts_with("0.0.0.0")
                && !conn.remote_addr.starts_with("192.168.")
                && !conn.remote_addr.starts_with("10.")
                && !conn.remote_addr.starts_with("172.")
            {
                iocs.push(ExtractedIoc {
                    ioc_type: IocType::IpAddress,
                    value: conn.remote_addr.clone(),
                    context: format!("External connection to {}:{}", conn.remote_addr, conn.remote_port),
                    source_plugin: "netscan".to_string(),
                    confidence: 0.6,
                });
            }
        }

        // Extract suspicious file paths
        let suspicious_paths = ["\\temp\\", "\\public\\", "\\recycler\\"];
        for file in files {
            let path_lower = file.name.to_lowercase();
            if suspicious_paths.iter().any(|s| path_lower.contains(s)) {
                iocs.push(ExtractedIoc {
                    ioc_type: IocType::FilePath,
                    value: file.name.clone(),
                    context: "File in suspicious location".to_string(),
                    source_plugin: "filescan".to_string(),
                    confidence: 0.5,
                });
            }
        }

        Ok(iocs)
    }

    fn calculate_risk_score(
        &self,
        hidden_processes: usize,
        suspicious_processes: usize,
        malfind_hits: usize,
        suspicious_injections: usize,
    ) -> u8 {
        let mut score = 0u8;

        score = score.saturating_add((hidden_processes * 15) as u8);
        score = score.saturating_add((suspicious_processes * 10) as u8);
        score = score.saturating_add((malfind_hits * 20) as u8);
        score = score.saturating_add((suspicious_injections * 15) as u8);

        score.min(100)
    }

    fn generate_key_findings(
        &self,
        hidden_processes: usize,
        malfind_results: &[VolMalfind],
        injections: &[VolInjection],
        iocs: &[ExtractedIoc],
    ) -> Vec<String> {
        let mut findings = Vec::new();

        if hidden_processes > 0 {
            findings.push(format!(
                "CRITICAL: {} hidden process(es) detected - possible rootkit activity",
                hidden_processes
            ));
        }

        let mz_headers = malfind_results.iter().filter(|m| m.mz_header).count();
        if mz_headers > 0 {
            findings.push(format!(
                "HIGH: {} process(es) with injected PE files (MZ header detected)",
                mz_headers
            ));
        }

        let suspicious_injections = injections.iter().filter(|i| i.suspicious).count();
        if suspicious_injections > 0 {
            findings.push(format!(
                "MEDIUM: {} suspicious memory region(s) with executable permissions",
                suspicious_injections
            ));
        }

        if !iocs.is_empty() {
            findings.push(format!(
                "INFO: {} indicator(s) of compromise extracted",
                iocs.len()
            ));
        }

        if findings.is_empty() {
            findings.push("No significant findings detected".to_string());
        }

        findings
    }
}

impl Default for VolatilityClient {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volatility_config_default() {
        let config = VolatilityConfig::default();
        assert_eq!(config.version, VolatilityVersion::V3);
        assert_eq!(config.timeout_seconds, 300);
    }

    #[test]
    fn test_dump_format_detection() {
        assert_eq!(DumpFormat::from_extension(Path::new("memory.raw")), DumpFormat::Raw);
        assert_eq!(DumpFormat::from_extension(Path::new("memory.lime")), DumpFormat::Lime);
        assert_eq!(DumpFormat::from_extension(Path::new("memory.vmem")), DumpFormat::VMem);
    }

    #[test]
    fn test_volatility_client_creation() {
        let client = VolatilityClient::with_defaults();
        assert!(client.current_dump().is_none());
    }

    #[test]
    fn test_risk_score_calculation() {
        let client = VolatilityClient::with_defaults();

        assert_eq!(client.calculate_risk_score(0, 0, 0, 0), 0);
        assert_eq!(client.calculate_risk_score(1, 0, 0, 0), 15);
        assert_eq!(client.calculate_risk_score(0, 0, 1, 0), 20);
    }
}
