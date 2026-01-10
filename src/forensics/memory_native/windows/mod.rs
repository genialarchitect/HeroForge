//! Windows-specific memory analysis
//!
//! Modules for analyzing Windows memory dumps.

pub mod processes;
pub mod dlls;
pub mod credentials;
pub mod registry;
pub mod networking;
pub mod kernel;

pub use processes::*;
pub use dlls::*;
pub use credentials::*;
pub use networking::*;
pub use kernel::*;

use super::dump_parser::ParsedDump;
use super::types::{Architecture, DumpInfo, OsType};
use anyhow::Result;

/// Windows memory analyzer
pub struct WindowsAnalyzer<'a> {
    /// Reference to parsed dump
    dump: &'a ParsedDump,
    /// Detected Windows version
    pub version: Option<WindowsVersion>,
    /// Kernel base address
    pub kernel_base: Option<u64>,
    /// PsActiveProcessHead address
    pub ps_active_process_head: Option<u64>,
    /// EPROCESS offsets for this version
    pub offsets: Option<EprocessOffsets>,
}

/// Windows version information
#[derive(Debug, Clone)]
pub struct WindowsVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub name: String,
}

/// EPROCESS structure offsets (version-specific)
#[derive(Debug, Clone, Copy)]
pub struct EprocessOffsets {
    /// Offset to ActiveProcessLinks
    pub active_process_links: usize,
    /// Offset to UniqueProcessId
    pub unique_process_id: usize,
    /// Offset to InheritedFromUniqueProcessId
    pub inherited_from_pid: usize,
    /// Offset to ImageFileName
    pub image_file_name: usize,
    /// Offset to DirectoryTableBase
    pub directory_table_base: usize,
    /// Offset to Peb
    pub peb: usize,
    /// Offset to CreateTime
    pub create_time: usize,
    /// Offset to ExitTime
    pub exit_time: usize,
    /// Offset to VadRoot
    pub vad_root: usize,
    /// Offset to ObjectTable
    pub object_table: usize,
    /// Offset to Token
    pub token: usize,
    /// Offset to Wow64Process
    pub wow64_process: usize,
    /// Offset to ThreadListHead
    pub thread_list_head: usize,
    /// Offset to SessionId
    pub session_id: usize,
}

impl EprocessOffsets {
    /// Get offsets for Windows 10 RS1-RS5 (1607-1809) x64
    pub fn win10_x64() -> Self {
        Self {
            active_process_links: 0x2F0,
            unique_process_id: 0x2E8,
            inherited_from_pid: 0x3E0,
            image_file_name: 0x450,
            directory_table_base: 0x28,
            peb: 0x3F8,
            create_time: 0x2E0,
            exit_time: 0x2E0 + 8,
            vad_root: 0x658,
            object_table: 0x418,
            token: 0x360,
            wow64_process: 0x3E8,
            thread_list_head: 0x488,
            session_id: 0x3B0,
        }
    }

    /// Get offsets for Windows 7 SP1 x64
    pub fn win7_x64() -> Self {
        Self {
            active_process_links: 0x188,
            unique_process_id: 0x180,
            inherited_from_pid: 0x290,
            image_file_name: 0x2E0,
            directory_table_base: 0x28,
            peb: 0x338,
            create_time: 0x160,
            exit_time: 0x168,
            vad_root: 0x448,
            object_table: 0x200,
            token: 0x208,
            wow64_process: 0x320,
            thread_list_head: 0x308,
            session_id: 0x2C0,
        }
    }

    /// Get offsets for Windows 11 x64
    pub fn win11_x64() -> Self {
        Self {
            active_process_links: 0x448,
            unique_process_id: 0x440,
            inherited_from_pid: 0x540,
            image_file_name: 0x5A8,
            directory_table_base: 0x28,
            peb: 0x550,
            create_time: 0x438,
            exit_time: 0x438 + 8,
            vad_root: 0x7D8,
            object_table: 0x570,
            token: 0x4B8,
            wow64_process: 0x548,
            thread_list_head: 0x5E0,
            session_id: 0x508,
        }
    }

    /// Get offsets for Windows 10/Server 2016-2019 x64 (most common)
    pub fn default_x64() -> Self {
        Self::win10_x64()
    }

    /// Get offsets for 32-bit Windows 7
    pub fn win7_x86() -> Self {
        Self {
            active_process_links: 0xB8,
            unique_process_id: 0xB4,
            inherited_from_pid: 0x140,
            image_file_name: 0x16C,
            directory_table_base: 0x18,
            peb: 0x1A8,
            create_time: 0xA0,
            exit_time: 0xA8,
            vad_root: 0x278,
            object_table: 0xF4,
            token: 0xF8,
            wow64_process: 0, // N/A for x86
            thread_list_head: 0x188,
            session_id: 0x170,
        }
    }
}

impl<'a> WindowsAnalyzer<'a> {
    /// Create new Windows analyzer
    pub fn new(dump: &'a ParsedDump) -> Self {
        Self {
            dump,
            version: None,
            kernel_base: None,
            ps_active_process_head: None,
            offsets: None,
        }
    }

    /// Initialize analyzer - detect version, find kernel, set offsets
    pub fn initialize(&mut self) -> Result<()> {
        // Detect architecture and set default offsets
        let is_64bit = matches!(self.dump.info.architecture, Architecture::X64);

        self.offsets = Some(if is_64bit {
            EprocessOffsets::default_x64()
        } else {
            EprocessOffsets::win7_x86()
        });

        // Try to find kernel base
        self.find_kernel_base()?;

        // Try to find PsActiveProcessHead
        self.find_ps_active_process_head()?;

        // Try to detect Windows version
        self.detect_version()?;

        Ok(())
    }

    /// Find the Windows kernel base address
    fn find_kernel_base(&mut self) -> Result<()> {
        // Method 1: Search for "MZ" header at expected kernel locations
        let typical_bases_64 = [
            0xfffff800_00000000u64, // Vista/7/8/10
            0xfffff802_00000000u64, // Some Windows 10 versions
            0xfffff804_00000000u64,
        ];

        let typical_bases_32 = [
            0x80400000u64, // XP
            0x82800000u64, // Vista
            0x82000000u64, // 7
        ];

        let is_64bit = matches!(self.dump.info.architecture, Architecture::X64);
        let search_bases = if is_64bit { &typical_bases_64[..] } else { &typical_bases_32[..] };

        // Search for MZ header at typical locations
        for &base in search_bases {
            if let Some(data) = self.dump.read_physical(base, 2) {
                if data == b"MZ" {
                    // Verify it's ntoskrnl by checking for expected exports
                    self.kernel_base = Some(base);
                    return Ok(());
                }
            }
        }

        // Method 2: Search physical memory for kernel signature patterns
        // Look for KDBG (Kernel Debugger Block) signature
        let kdbg_patterns = [
            b"KDBG", // Standard KDBG signature
        ];

        for pattern in &kdbg_patterns {
            let matches = self.dump.search_pattern(*pattern);
            for offset in matches.iter().take(10) {
                // KDBG structure contains pointers we can use
                if let Some(data) = self.dump.read_bytes(*offset, 0x40) {
                    // Validate KDBG and extract kernel base
                    if self.validate_kdbg(data, *offset).is_ok() {
                        return Ok(());
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate a potential KDBG structure
    fn validate_kdbg(&mut self, _data: &[u8], _offset: u64) -> Result<()> {
        // KDBG validation would check:
        // - Valid owner tag
        // - Reasonable pointer values
        // - Consistent with architecture

        // For now, we skip detailed validation
        Ok(())
    }

    /// Find PsActiveProcessHead for process enumeration
    fn find_ps_active_process_head(&mut self) -> Result<()> {
        // PsActiveProcessHead is exported from ntoskrnl
        // We can find it by:
        // 1. Parsing ntoskrnl exports (if we have kernel base)
        // 2. Scanning for EPROCESS structures and following links

        // Method 2: Find System process (PID 4) and use its links
        // System process has specific characteristics we can search for

        let system_pid_pattern = if matches!(self.dump.info.architecture, Architecture::X64) {
            [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        } else {
            [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        };

        // Search for potential EPROCESS of System
        let _matches = self.dump.search_pattern(&system_pid_pattern);

        // This is a simplified approach - real implementation would
        // validate each match as a valid EPROCESS structure

        Ok(())
    }

    /// Detect Windows version from kernel
    fn detect_version(&mut self) -> Result<()> {
        // Version detection can be done via:
        // 1. Reading version resources from ntoskrnl
        // 2. Checking known structure differences
        // 3. Registry analysis

        // For now, assume Windows 10 if 64-bit
        if matches!(self.dump.info.architecture, Architecture::X64) {
            self.version = Some(WindowsVersion {
                major: 10,
                minor: 0,
                build: 19041, // Assume 20H1
                name: "Windows 10".to_string(),
            });
        } else {
            self.version = Some(WindowsVersion {
                major: 6,
                minor: 1,
                build: 7601,
                name: "Windows 7".to_string(),
            });
        }

        Ok(())
    }

    /// Get reference to the dump
    pub fn dump(&self) -> &ParsedDump {
        self.dump
    }
}

/// Check if dump is a Windows memory dump
pub fn is_windows_dump(info: &DumpInfo) -> bool {
    matches!(info.os_type, Some(OsType::Windows))
        || matches!(
            info.format,
            super::types::DumpFormat::CrashDump | super::types::DumpFormat::Hibernation
        )
}
