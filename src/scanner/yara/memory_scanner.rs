//! Memory Scanner for YARA Rules
//!
//! Scans memory dump files with YARA rules, supporting:
//! - Raw memory dump files (.dmp, .raw, .mem)
//! - Windows minidump format
//! - Linux core dumps
//! - Process memory regions with protection tracking
//! - Memory-specific malware indicators (hollowing, injection)

use super::{YaraScanner, YaraMatch, YaraRule, MatchedString};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;

// ============================================================================
// Types
// ============================================================================

/// Memory dump format detection
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryDumpFormat {
    /// Raw memory dump (flat binary)
    Raw,
    /// Windows minidump format
    WindowsMinidump,
    /// Windows full memory dump
    WindowsFullDump,
    /// Linux ELF core dump
    LinuxCoreDump,
    /// VMware memory snapshot
    VmwareSnapshot,
    /// VirtualBox memory dump
    VirtualBoxDump,
    /// Unknown format (treat as raw)
    Unknown,
}

impl std::fmt::Display for MemoryDumpFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryDumpFormat::Raw => write!(f, "raw"),
            MemoryDumpFormat::WindowsMinidump => write!(f, "windows_minidump"),
            MemoryDumpFormat::WindowsFullDump => write!(f, "windows_full_dump"),
            MemoryDumpFormat::LinuxCoreDump => write!(f, "linux_core_dump"),
            MemoryDumpFormat::VmwareSnapshot => write!(f, "vmware_snapshot"),
            MemoryDumpFormat::VirtualBoxDump => write!(f, "virtualbox_dump"),
            MemoryDumpFormat::Unknown => write!(f, "unknown"),
        }
    }
}

/// Memory region protection attributes
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MemoryProtection {
    /// Region is readable
    pub read: bool,
    /// Region is writable
    pub write: bool,
    /// Region is executable
    pub execute: bool,
    /// Region is copy-on-write
    pub copy_on_write: bool,
    /// Region is guard page
    pub guard: bool,
    /// Region is not committed
    pub no_access: bool,
}

impl MemoryProtection {
    /// Create RWX protection
    pub fn rwx() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
            ..Default::default()
        }
    }

    /// Create RW protection (data section)
    pub fn rw() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
            ..Default::default()
        }
    }

    /// Create RX protection (code section)
    pub fn rx() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
            ..Default::default()
        }
    }

    /// Create read-only protection
    pub fn r() -> Self {
        Self {
            read: true,
            ..Default::default()
        }
    }

    /// Check if this region has suspicious permissions (RWX)
    pub fn is_rwx(&self) -> bool {
        self.read && self.write && self.execute
    }

    /// Convert to string representation
    pub fn to_string_short(&self) -> String {
        format!(
            "{}{}{}",
            if self.read { "R" } else { "-" },
            if self.write { "W" } else { "-" },
            if self.execute { "X" } else { "-" }
        )
    }
}

/// State of a memory region
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryState {
    /// Memory is committed and accessible
    Committed,
    /// Memory is reserved but not committed
    Reserved,
    /// Memory region is free
    Free,
    /// Memory is mapped from a file
    Mapped,
    /// Unknown state
    Unknown,
}

impl Default for MemoryState {
    fn default() -> Self {
        Self::Unknown
    }
}

impl std::fmt::Display for MemoryState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryState::Committed => write!(f, "committed"),
            MemoryState::Reserved => write!(f, "reserved"),
            MemoryState::Free => write!(f, "free"),
            MemoryState::Mapped => write!(f, "mapped"),
            MemoryState::Unknown => write!(f, "unknown"),
        }
    }
}

/// Type of memory region
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryType {
    /// Image/module section
    Image,
    /// Private memory allocation
    Private,
    /// Memory-mapped file
    Mapped,
    /// Heap memory
    Heap,
    /// Stack memory
    Stack,
    /// PEB/TEB structures
    ProcessEnvironment,
    /// Unknown type
    Unknown,
}

impl Default for MemoryType {
    fn default() -> Self {
        Self::Unknown
    }
}

impl std::fmt::Display for MemoryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryType::Image => write!(f, "image"),
            MemoryType::Private => write!(f, "private"),
            MemoryType::Mapped => write!(f, "mapped"),
            MemoryType::Heap => write!(f, "heap"),
            MemoryType::Stack => write!(f, "stack"),
            MemoryType::ProcessEnvironment => write!(f, "peb_teb"),
            MemoryType::Unknown => write!(f, "unknown"),
        }
    }
}

/// A memory region within a dump
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Base address of the region
    pub base_address: u64,
    /// Size of the region in bytes
    pub size: u64,
    /// Protection attributes
    pub protection: MemoryProtection,
    /// Memory state
    pub state: MemoryState,
    /// Memory type
    pub memory_type: MemoryType,
    /// Associated module name (if applicable)
    pub module_name: Option<String>,
    /// Offset in the dump file where this region's data starts
    pub file_offset: u64,
    /// Entropy of the region (0.0 - 8.0)
    pub entropy: Option<f64>,
}

/// A YARA match within a memory region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryYaraMatch {
    /// The YARA rule that matched
    pub rule_name: String,
    /// Rule ID
    pub rule_id: Option<String>,
    /// Memory region where match occurred
    pub region: MemoryRegion,
    /// Matched strings with their memory addresses
    pub matched_strings: Vec<MemoryMatchedString>,
    /// Tags from the rule
    pub tags: Vec<String>,
    /// Metadata from the rule
    pub metadata: HashMap<String, String>,
    /// Time of the match
    pub matched_at: DateTime<Utc>,
}

/// A matched string with memory-specific information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMatchedString {
    /// String identifier from the YARA rule
    pub identifier: String,
    /// Virtual memory address of the match
    pub virtual_address: u64,
    /// File offset in the dump
    pub file_offset: u64,
    /// Length of the matched data
    pub length: usize,
    /// The matched data (limited preview)
    pub data: String,
    /// Whether XOR encoding was detected
    pub is_xor: bool,
    /// XOR key if detected
    pub xor_key: Option<u8>,
}

/// Memory scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScanResult {
    /// Detected memory dump format
    pub format: MemoryDumpFormat,
    /// Total size of the dump file
    pub dump_size: u64,
    /// Number of regions identified
    pub region_count: usize,
    /// Total bytes scanned
    pub bytes_scanned: u64,
    /// YARA matches found
    pub matches: Vec<MemoryYaraMatch>,
    /// Regions with suspicious attributes (RWX, etc.)
    pub suspicious_regions: Vec<MemoryRegion>,
    /// Errors encountered during scanning
    pub errors: Vec<String>,
    /// Scan duration in milliseconds
    pub scan_time_ms: u64,
}

/// Memory scan options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScanOptions {
    /// Maximum region size to scan (skip very large regions)
    pub max_region_size: u64,
    /// Minimum region size to scan (skip tiny regions)
    pub min_region_size: u64,
    /// Scan only executable regions
    pub only_executable: bool,
    /// Scan only writable regions
    pub only_writable: bool,
    /// Scan only private memory (not mapped files)
    pub only_private: bool,
    /// Calculate entropy for each region
    pub calculate_entropy: bool,
    /// Flag suspicious RWX regions
    pub flag_rwx_regions: bool,
    /// Treat entire dump as single region (for raw dumps)
    pub raw_scan: bool,
    /// Chunk size for scanning large regions
    pub chunk_size: usize,
}

impl Default for MemoryScanOptions {
    fn default() -> Self {
        Self {
            max_region_size: 100 * 1024 * 1024, // 100 MB
            min_region_size: 64,
            only_executable: false,
            only_writable: false,
            only_private: false,
            calculate_entropy: true,
            flag_rwx_regions: true,
            raw_scan: false,
            chunk_size: 64 * 1024, // 64 KB chunks
        }
    }
}

// ============================================================================
// Memory Scanner
// ============================================================================

/// Memory dump scanner with YARA rule support
pub struct MemoryScanner {
    scanner: YaraScanner,
    options: MemoryScanOptions,
}

impl MemoryScanner {
    /// Create a new memory scanner
    pub fn new() -> Self {
        Self {
            scanner: YaraScanner::new(),
            options: MemoryScanOptions::default(),
        }
    }

    /// Create with custom options
    pub fn with_options(options: MemoryScanOptions) -> Self {
        Self {
            scanner: YaraScanner::new(),
            options,
        }
    }

    /// Load YARA rules into the scanner
    pub fn load_rules(&mut self, rules: Vec<YaraRule>) -> Result<usize> {
        self.scanner.add_rules(rules);
        self.scanner.compile()?;
        Ok(self.scanner.get_rules().len())
    }

    /// Set scan options
    pub fn set_options(&mut self, options: MemoryScanOptions) {
        self.options = options;
    }

    /// Detect the format of a memory dump file
    pub async fn detect_format(path: &str) -> Result<MemoryDumpFormat> {
        let path = Path::new(path);
        if !path.exists() {
            return Err(anyhow!("File not found: {}", path.display()));
        }

        // Read first 4KB for signature detection
        let data = fs::read(path).await?;
        let header = if data.len() >= 4096 {
            &data[..4096]
        } else {
            &data
        };

        Ok(detect_format_from_header(header))
    }

    /// Scan a memory dump file
    pub async fn scan_file(&mut self, path: &str) -> Result<MemoryScanResult> {
        let start_time = std::time::Instant::now();
        let path = Path::new(path);

        if !path.exists() {
            return Err(anyhow!("File not found: {}", path.display()));
        }

        // Read the entire dump
        let data = fs::read(path).await?;
        let dump_size = data.len() as u64;

        // Detect format
        let format = detect_format_from_header(&data);

        // Parse regions based on format
        let regions = if self.options.raw_scan || format == MemoryDumpFormat::Raw || format == MemoryDumpFormat::Unknown {
            // Treat entire dump as a single region
            vec![MemoryRegion {
                base_address: 0,
                size: dump_size,
                protection: MemoryProtection::rwx(),
                state: MemoryState::Committed,
                memory_type: MemoryType::Unknown,
                module_name: None,
                file_offset: 0,
                entropy: if self.options.calculate_entropy {
                    Some(calculate_entropy(&data))
                } else {
                    None
                },
            }]
        } else {
            self.parse_regions(&data, format)?
        };

        let region_count = regions.len();
        let mut matches = Vec::new();
        let mut suspicious_regions = Vec::new();
        let mut errors = Vec::new();
        let mut bytes_scanned = 0u64;

        // Scan each region
        for region in &regions {
            // Check if we should skip this region
            if !self.should_scan_region(region) {
                continue;
            }

            // Flag suspicious RWX regions
            if self.options.flag_rwx_regions && region.protection.is_rwx() {
                suspicious_regions.push(region.clone());
            }

            // Extract region data
            let region_end = region.file_offset + region.size;
            if region_end as usize > data.len() {
                errors.push(format!(
                    "Region at 0x{:x} extends beyond dump size",
                    region.base_address
                ));
                continue;
            }

            let region_data = &data[region.file_offset as usize..region_end as usize];
            bytes_scanned += region_data.len() as u64;

            // Scan the region with YARA rules
            match self.scanner.scan_bytes(region_data).await {
                Ok(yara_matches) => {
                    for yara_match in yara_matches {
                        matches.push(self.convert_to_memory_match(yara_match, region));
                    }
                }
                Err(e) => {
                    errors.push(format!(
                        "Error scanning region at 0x{:x}: {}",
                        region.base_address, e
                    ));
                }
            }
        }

        let scan_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(MemoryScanResult {
            format,
            dump_size,
            region_count,
            bytes_scanned,
            matches,
            suspicious_regions,
            errors,
            scan_time_ms,
        })
    }

    /// Scan raw bytes as a memory dump
    pub async fn scan_bytes(&mut self, data: &[u8]) -> Result<MemoryScanResult> {
        let start_time = std::time::Instant::now();
        let dump_size = data.len() as u64;

        // Detect format
        let format = detect_format_from_header(data);

        // For raw bytes, treat as a single region
        let region = MemoryRegion {
            base_address: 0,
            size: dump_size,
            protection: MemoryProtection::rwx(),
            state: MemoryState::Committed,
            memory_type: MemoryType::Unknown,
            module_name: None,
            file_offset: 0,
            entropy: if self.options.calculate_entropy {
                Some(calculate_entropy(data))
            } else {
                None
            },
        };

        let mut matches = Vec::new();
        let mut suspicious_regions = Vec::new();
        let mut errors = Vec::new();

        // Flag as suspicious if RWX
        if self.options.flag_rwx_regions && region.protection.is_rwx() {
            suspicious_regions.push(region.clone());
        }

        // Scan the data
        match self.scanner.scan_bytes(data).await {
            Ok(yara_matches) => {
                for yara_match in yara_matches {
                    matches.push(self.convert_to_memory_match(yara_match, &region));
                }
            }
            Err(e) => {
                errors.push(format!("Error scanning memory: {}", e));
            }
        }

        let scan_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(MemoryScanResult {
            format,
            dump_size,
            region_count: 1,
            bytes_scanned: dump_size,
            matches,
            suspicious_regions,
            errors,
            scan_time_ms,
        })
    }

    /// Parse memory regions from a dump based on its format
    fn parse_regions(&self, data: &[u8], format: MemoryDumpFormat) -> Result<Vec<MemoryRegion>> {
        match format {
            MemoryDumpFormat::WindowsMinidump => self.parse_minidump_regions(data),
            MemoryDumpFormat::LinuxCoreDump => self.parse_elf_core_regions(data),
            _ => {
                // For unknown formats, treat as raw
                Ok(vec![MemoryRegion {
                    base_address: 0,
                    size: data.len() as u64,
                    protection: MemoryProtection::rwx(),
                    state: MemoryState::Committed,
                    memory_type: MemoryType::Unknown,
                    module_name: None,
                    file_offset: 0,
                    entropy: if self.options.calculate_entropy {
                        Some(calculate_entropy(data))
                    } else {
                        None
                    },
                }])
            }
        }
    }

    /// Parse Windows minidump regions
    fn parse_minidump_regions(&self, data: &[u8]) -> Result<Vec<MemoryRegion>> {
        let mut regions = Vec::new();

        // Check for MDMP signature
        if data.len() < 32 || &data[0..4] != b"MDMP" {
            return Err(anyhow!("Invalid minidump signature"));
        }

        // Parse minidump header (simplified - full parsing would need proper struct)
        // MDMP header: signature (4) + version (4) + stream_count (4) + stream_directory_rva (4) + ...
        let stream_count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let stream_dir_rva = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

        // Look for Memory64ListStream (type 9) or MemoryListStream (type 5)
        for i in 0..stream_count {
            let entry_offset = stream_dir_rva + i * 12;
            if entry_offset + 12 > data.len() {
                break;
            }

            let stream_type = u32::from_le_bytes([
                data[entry_offset],
                data[entry_offset + 1],
                data[entry_offset + 2],
                data[entry_offset + 3],
            ]);

            let stream_size = u32::from_le_bytes([
                data[entry_offset + 4],
                data[entry_offset + 5],
                data[entry_offset + 6],
                data[entry_offset + 7],
            ]) as usize;

            let stream_rva = u32::from_le_bytes([
                data[entry_offset + 8],
                data[entry_offset + 9],
                data[entry_offset + 10],
                data[entry_offset + 11],
            ]) as usize;

            // Memory64ListStream (type 9)
            if stream_type == 9 && stream_rva + 16 <= data.len() {
                let num_ranges = u64::from_le_bytes([
                    data[stream_rva],
                    data[stream_rva + 1],
                    data[stream_rva + 2],
                    data[stream_rva + 3],
                    data[stream_rva + 4],
                    data[stream_rva + 5],
                    data[stream_rva + 6],
                    data[stream_rva + 7],
                ]) as usize;

                let base_rva = u64::from_le_bytes([
                    data[stream_rva + 8],
                    data[stream_rva + 9],
                    data[stream_rva + 10],
                    data[stream_rva + 11],
                    data[stream_rva + 12],
                    data[stream_rva + 13],
                    data[stream_rva + 14],
                    data[stream_rva + 15],
                ]);

                let mut file_offset = base_rva;
                for j in 0..num_ranges {
                    let desc_offset = stream_rva + 16 + j * 16;
                    if desc_offset + 16 > data.len() {
                        break;
                    }

                    let start_va = u64::from_le_bytes([
                        data[desc_offset],
                        data[desc_offset + 1],
                        data[desc_offset + 2],
                        data[desc_offset + 3],
                        data[desc_offset + 4],
                        data[desc_offset + 5],
                        data[desc_offset + 6],
                        data[desc_offset + 7],
                    ]);

                    let data_size = u64::from_le_bytes([
                        data[desc_offset + 8],
                        data[desc_offset + 9],
                        data[desc_offset + 10],
                        data[desc_offset + 11],
                        data[desc_offset + 12],
                        data[desc_offset + 13],
                        data[desc_offset + 14],
                        data[desc_offset + 15],
                    ]);

                    regions.push(MemoryRegion {
                        base_address: start_va,
                        size: data_size,
                        protection: MemoryProtection::default(),
                        state: MemoryState::Committed,
                        memory_type: MemoryType::Unknown,
                        module_name: None,
                        file_offset,
                        entropy: None,
                    });

                    file_offset += data_size;
                }
            }
        }

        // If no regions found, treat the whole dump as one region
        if regions.is_empty() {
            regions.push(MemoryRegion {
                base_address: 0,
                size: data.len() as u64,
                protection: MemoryProtection::rwx(),
                state: MemoryState::Committed,
                memory_type: MemoryType::Unknown,
                module_name: None,
                file_offset: 0,
                entropy: None,
            });
        }

        // Calculate entropy for each region if requested
        if self.options.calculate_entropy {
            for region in &mut regions {
                let end = (region.file_offset + region.size) as usize;
                if end <= data.len() {
                    let region_data = &data[region.file_offset as usize..end];
                    region.entropy = Some(calculate_entropy(region_data));
                }
            }
        }

        Ok(regions)
    }

    /// Parse Linux ELF core dump regions
    fn parse_elf_core_regions(&self, data: &[u8]) -> Result<Vec<MemoryRegion>> {
        let mut regions = Vec::new();

        // Check ELF magic
        if data.len() < 64 || &data[0..4] != b"\x7fELF" {
            return Err(anyhow!("Invalid ELF signature"));
        }

        // Determine 32-bit or 64-bit
        let is_64bit = data[4] == 2;

        if is_64bit {
            // Parse 64-bit ELF header
            let phoff = u64::from_le_bytes([
                data[32], data[33], data[34], data[35],
                data[36], data[37], data[38], data[39],
            ]) as usize;

            let phentsize = u16::from_le_bytes([data[54], data[55]]) as usize;
            let phnum = u16::from_le_bytes([data[56], data[57]]) as usize;

            // Parse program headers (PT_LOAD segments)
            for i in 0..phnum {
                let ph_offset = phoff + i * phentsize;
                if ph_offset + phentsize > data.len() {
                    break;
                }

                let p_type = u32::from_le_bytes([
                    data[ph_offset],
                    data[ph_offset + 1],
                    data[ph_offset + 2],
                    data[ph_offset + 3],
                ]);

                // PT_LOAD = 1
                if p_type == 1 {
                    let p_flags = u32::from_le_bytes([
                        data[ph_offset + 4],
                        data[ph_offset + 5],
                        data[ph_offset + 6],
                        data[ph_offset + 7],
                    ]);

                    let p_offset = u64::from_le_bytes([
                        data[ph_offset + 8], data[ph_offset + 9],
                        data[ph_offset + 10], data[ph_offset + 11],
                        data[ph_offset + 12], data[ph_offset + 13],
                        data[ph_offset + 14], data[ph_offset + 15],
                    ]);

                    let p_vaddr = u64::from_le_bytes([
                        data[ph_offset + 16], data[ph_offset + 17],
                        data[ph_offset + 18], data[ph_offset + 19],
                        data[ph_offset + 20], data[ph_offset + 21],
                        data[ph_offset + 22], data[ph_offset + 23],
                    ]);

                    let p_filesz = u64::from_le_bytes([
                        data[ph_offset + 32], data[ph_offset + 33],
                        data[ph_offset + 34], data[ph_offset + 35],
                        data[ph_offset + 36], data[ph_offset + 37],
                        data[ph_offset + 38], data[ph_offset + 39],
                    ]);

                    let protection = MemoryProtection {
                        read: p_flags & 4 != 0,
                        write: p_flags & 2 != 0,
                        execute: p_flags & 1 != 0,
                        ..Default::default()
                    };

                    regions.push(MemoryRegion {
                        base_address: p_vaddr,
                        size: p_filesz,
                        protection,
                        state: MemoryState::Committed,
                        memory_type: if protection.execute { MemoryType::Image } else { MemoryType::Private },
                        module_name: None,
                        file_offset: p_offset,
                        entropy: None,
                    });
                }
            }
        } else {
            // Parse 32-bit ELF header
            let phoff = u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as usize;
            let phentsize = u16::from_le_bytes([data[42], data[43]]) as usize;
            let phnum = u16::from_le_bytes([data[44], data[45]]) as usize;

            for i in 0..phnum {
                let ph_offset = phoff + i * phentsize;
                if ph_offset + phentsize > data.len() {
                    break;
                }

                let p_type = u32::from_le_bytes([
                    data[ph_offset],
                    data[ph_offset + 1],
                    data[ph_offset + 2],
                    data[ph_offset + 3],
                ]);

                if p_type == 1 {
                    let p_offset = u32::from_le_bytes([
                        data[ph_offset + 4],
                        data[ph_offset + 5],
                        data[ph_offset + 6],
                        data[ph_offset + 7],
                    ]) as u64;

                    let p_vaddr = u32::from_le_bytes([
                        data[ph_offset + 8],
                        data[ph_offset + 9],
                        data[ph_offset + 10],
                        data[ph_offset + 11],
                    ]) as u64;

                    let p_filesz = u32::from_le_bytes([
                        data[ph_offset + 16],
                        data[ph_offset + 17],
                        data[ph_offset + 18],
                        data[ph_offset + 19],
                    ]) as u64;

                    let p_flags = u32::from_le_bytes([
                        data[ph_offset + 24],
                        data[ph_offset + 25],
                        data[ph_offset + 26],
                        data[ph_offset + 27],
                    ]);

                    let protection = MemoryProtection {
                        read: p_flags & 4 != 0,
                        write: p_flags & 2 != 0,
                        execute: p_flags & 1 != 0,
                        ..Default::default()
                    };

                    regions.push(MemoryRegion {
                        base_address: p_vaddr,
                        size: p_filesz,
                        protection,
                        state: MemoryState::Committed,
                        memory_type: if protection.execute { MemoryType::Image } else { MemoryType::Private },
                        module_name: None,
                        file_offset: p_offset,
                        entropy: None,
                    });
                }
            }
        }

        // Calculate entropy for each region if requested
        if self.options.calculate_entropy {
            for region in &mut regions {
                let end = (region.file_offset + region.size) as usize;
                if end <= data.len() {
                    let region_data = &data[region.file_offset as usize..end];
                    region.entropy = Some(calculate_entropy(region_data));
                }
            }
        }

        // If no regions found, treat whole file as one region
        if regions.is_empty() {
            regions.push(MemoryRegion {
                base_address: 0,
                size: data.len() as u64,
                protection: MemoryProtection::rwx(),
                state: MemoryState::Committed,
                memory_type: MemoryType::Unknown,
                module_name: None,
                file_offset: 0,
                entropy: if self.options.calculate_entropy {
                    Some(calculate_entropy(data))
                } else {
                    None
                },
            });
        }

        Ok(regions)
    }

    /// Check if a region should be scanned based on options
    fn should_scan_region(&self, region: &MemoryRegion) -> bool {
        // Size filters
        if region.size < self.options.min_region_size {
            return false;
        }
        if region.size > self.options.max_region_size {
            return false;
        }

        // Protection filters
        if self.options.only_executable && !region.protection.execute {
            return false;
        }
        if self.options.only_writable && !region.protection.write {
            return false;
        }

        // Type filters
        if self.options.only_private && region.memory_type != MemoryType::Private {
            return false;
        }

        true
    }

    /// Convert a standard YARA match to a memory-specific match
    fn convert_to_memory_match(&self, yara_match: YaraMatch, region: &MemoryRegion) -> MemoryYaraMatch {
        let matched_strings: Vec<MemoryMatchedString> = yara_match
            .matched_strings
            .iter()
            .map(|s| MemoryMatchedString {
                identifier: s.identifier.clone(),
                virtual_address: region.base_address + s.offset,
                file_offset: region.file_offset + s.offset,
                length: s.length,
                data: s.data.clone(),
                is_xor: false,
                xor_key: None,
            })
            .collect();

        MemoryYaraMatch {
            rule_name: yara_match.rule_name,
            rule_id: None,
            region: region.clone(),
            matched_strings,
            tags: yara_match.tags,
            metadata: yara_match.metadata.extra,
            matched_at: yara_match.timestamp,
        }
    }
}

impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Detect memory dump format from header bytes
fn detect_format_from_header(data: &[u8]) -> MemoryDumpFormat {
    if data.len() < 4 {
        return MemoryDumpFormat::Unknown;
    }

    // Windows minidump: "MDMP"
    if &data[0..4] == b"MDMP" {
        return MemoryDumpFormat::WindowsMinidump;
    }

    // ELF: "\x7fELF"
    if &data[0..4] == b"\x7fELF" {
        // Check if it's a core dump (e_type = ET_CORE = 4)
        if data.len() >= 18 {
            let e_type = u16::from_le_bytes([data[16], data[17]]);
            if e_type == 4 {
                return MemoryDumpFormat::LinuxCoreDump;
            }
        }
    }

    // VMware VMEM: "VMEM"
    if &data[0..4] == b"VMEM" {
        return MemoryDumpFormat::VmwareSnapshot;
    }

    // Windows full memory dump: "PAGE" or "PAGEDUMP"
    if data.len() >= 8 && &data[0..8] == b"PAGEDUMP" {
        return MemoryDumpFormat::WindowsFullDump;
    }
    if &data[0..4] == b"PAGE" {
        return MemoryDumpFormat::WindowsFullDump;
    }

    // Check for common PE header at start (possibly a process dump)
    if &data[0..2] == b"MZ" {
        return MemoryDumpFormat::Raw;
    }

    MemoryDumpFormat::Unknown
}

/// Calculate Shannon entropy of data (0.0 - 8.0)
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_format() {
        // MDMP
        let mdmp = b"MDMP\x00\x00\x00\x00";
        assert_eq!(detect_format_from_header(mdmp), MemoryDumpFormat::WindowsMinidump);

        // ELF core (type 4)
        let elf_core = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00";
        assert_eq!(detect_format_from_header(elf_core), MemoryDumpFormat::LinuxCoreDump);

        // Unknown
        let unknown = b"\x00\x00\x00\x00";
        assert_eq!(detect_format_from_header(unknown), MemoryDumpFormat::Unknown);
    }

    #[test]
    fn test_calculate_entropy() {
        // Zeros have 0 entropy
        let zeros = vec![0u8; 1000];
        assert_eq!(calculate_entropy(&zeros), 0.0);

        // Random-ish data should have higher entropy
        let mixed: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let entropy = calculate_entropy(&mixed);
        assert!(entropy > 7.0 && entropy <= 8.0);
    }

    #[test]
    fn test_memory_protection() {
        let rwx = MemoryProtection::rwx();
        assert!(rwx.is_rwx());
        assert_eq!(rwx.to_string_short(), "RWX");

        let rx = MemoryProtection::rx();
        assert!(!rx.is_rwx());
        assert_eq!(rx.to_string_short(), "R-X");
    }

    #[tokio::test]
    async fn test_memory_scanner_scan_bytes() {
        use super::super::rules::get_builtin_rules;

        let mut scanner = MemoryScanner::new();
        let rules = get_builtin_rules();
        scanner.load_rules(rules).unwrap();

        // Test data with ransomware extension
        let test_data = b"This file has been encrypted with .locked extension";
        let result = scanner.scan_bytes(test_data).await.unwrap();

        assert_eq!(result.region_count, 1);
        assert!(result.bytes_scanned > 0);
    }
}
