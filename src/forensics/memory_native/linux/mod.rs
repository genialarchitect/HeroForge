//! Linux-specific memory analysis
//!
//! Modules for analyzing Linux memory dumps.

pub mod tasks;
pub mod libraries;
pub mod networking;
pub mod kernel;

pub use tasks::*;
pub use libraries::*;
pub use networking::*;
pub use kernel::*;

use super::dump_parser::ParsedDump;
use super::types::{Architecture, DumpInfo, OsType};
use anyhow::Result;

/// Linux memory analyzer
pub struct LinuxAnalyzer<'a> {
    /// Reference to parsed dump
    dump: &'a ParsedDump,
    /// Detected kernel version
    pub kernel_version: Option<String>,
    /// Kernel symbols (if found)
    pub kallsyms: Option<KallsymsData>,
    /// task_struct offsets for this kernel
    pub offsets: Option<TaskStructOffsets>,
    /// init_task address
    pub init_task: Option<u64>,
}

/// Kernel symbol table data
#[derive(Debug, Clone, Default)]
pub struct KallsymsData {
    /// Symbol name to address mapping
    pub symbols: std::collections::HashMap<String, u64>,
    /// Number of symbols loaded
    pub count: usize,
}

/// task_struct field offsets (kernel version-specific)
#[derive(Debug, Clone, Copy)]
pub struct TaskStructOffsets {
    /// Offset to tasks list_head
    pub tasks: usize,
    /// Offset to pid
    pub pid: usize,
    /// Offset to tgid
    pub tgid: usize,
    /// Offset to real_parent
    pub real_parent: usize,
    /// Offset to comm (process name)
    pub comm: usize,
    /// Offset to mm (memory descriptor)
    pub mm: usize,
    /// Offset to cred (credentials)
    pub cred: usize,
    /// Offset to fs (filesystem info)
    pub fs: usize,
    /// Offset to files (open files)
    pub files: usize,
    /// Offset to state
    pub state: usize,
    /// Offset to flags
    pub flags: usize,
    /// Offset to start_time
    pub start_time: usize,
}

impl TaskStructOffsets {
    /// Generic offsets for Linux 5.x kernels (x86_64)
    pub fn linux_5x_x64() -> Self {
        Self {
            tasks: 0x498,    // Varies
            pid: 0x4E0,
            tgid: 0x4E4,
            real_parent: 0x4F0,
            comm: 0x670,
            mm: 0x500,
            cred: 0x6B8,
            fs: 0x6D0,
            files: 0x6D8,
            state: 0x0,
            flags: 0x4,
            start_time: 0x620,
        }
    }

    /// Generic offsets for Linux 4.x kernels (x86_64)
    pub fn linux_4x_x64() -> Self {
        Self {
            tasks: 0x3A0,
            pid: 0x448,
            tgid: 0x44C,
            real_parent: 0x458,
            comm: 0x5D8,
            mm: 0x468,
            cred: 0x618,
            fs: 0x630,
            files: 0x638,
            state: 0x0,
            flags: 0x4,
            start_time: 0x590,
        }
    }

    /// Default offsets (best guess for modern kernels)
    pub fn default() -> Self {
        Self::linux_5x_x64()
    }
}

impl<'a> LinuxAnalyzer<'a> {
    /// Create new Linux analyzer
    pub fn new(dump: &'a ParsedDump) -> Self {
        Self {
            dump,
            kernel_version: None,
            kallsyms: None,
            offsets: None,
            init_task: None,
        }
    }

    /// Initialize analyzer - detect kernel version, find symbols, set offsets
    pub fn initialize(&mut self) -> Result<()> {
        // Detect kernel version
        self.detect_kernel_version()?;

        // Set offsets based on version
        self.offsets = Some(TaskStructOffsets::default());

        // Try to find kallsyms in memory
        self.find_kallsyms()?;

        // Try to find init_task
        self.find_init_task()?;

        Ok(())
    }

    /// Detect Linux kernel version from memory
    fn detect_kernel_version(&mut self) -> Result<()> {
        // Search for version string pattern
        let version_pattern = b"Linux version ";
        let matches = self.dump.search_pattern(version_pattern);

        for &offset in matches.iter().take(10) {
            if let Some(data) = self.dump.read_bytes(offset, 256) {
                // Parse version string
                let version_start = version_pattern.len();
                if let Some(end) = data[version_start..].iter().position(|&b| b == b'\n' || b == 0) {
                    let version = String::from_utf8_lossy(&data[version_start..version_start + end]);
                    self.kernel_version = Some(version.to_string());
                    break;
                }
            }
        }

        Ok(())
    }

    /// Try to find kallsyms in memory
    fn find_kallsyms(&mut self) -> Result<()> {
        // kallsyms is a kernel symbol table
        // It may be embedded in the kernel image or available via /proc/kallsyms

        // Search for characteristic patterns:
        // - "kallsyms_" strings
        // - Symbol table format

        let mut symbols = std::collections::HashMap::new();

        // Search for function name patterns that indicate kallsyms presence
        let marker_patterns: &[&[u8]] = &[
            b"swapper",
            b"start_kernel",
            b"sys_read",
            b"do_sys_open",
        ];

        for pattern in marker_patterns {
            let matches = self.dump.search_pattern(pattern);

            for &offset in matches.iter().take(5) {
                // Try to extract surrounding symbol entries
                if let Some(data) = self.dump.read_bytes(offset.saturating_sub(64), 256) {
                    // Look for address-name pairs
                    // Format varies but often has address followed by type and name
                    let _name = String::from_utf8_lossy(data.as_ref());
                    // Would parse kallsyms format here
                }
            }
        }

        if !symbols.is_empty() {
            self.kallsyms = Some(KallsymsData {
                count: symbols.len(),
                symbols,
            });
        }

        Ok(())
    }

    /// Try to find init_task (process 0)
    fn find_init_task(&mut self) -> Result<()> {
        // init_task is the first task_struct, PID 0 (swapper)
        // We can find it by:
        // 1. Looking for kallsyms entry "init_task"
        // 2. Searching for task_struct with comm="swapper/0" or similar
        // 3. Using known offsets from kernel configuration

        if let Some(kallsyms) = &self.kallsyms {
            if let Some(&addr) = kallsyms.symbols.get("init_task") {
                self.init_task = Some(addr);
                return Ok(());
            }
        }

        // Search for "swapper" which is init_task's comm
        let matches = self.dump.search_pattern(b"swapper");

        for &offset in matches.iter().take(100) {
            if let Some(offsets) = &self.offsets {
                // Check if this could be a valid task_struct
                let potential_task = offset - offsets.comm as u64;

                if self.validate_task_struct(potential_task, offsets) {
                    // Check if PID is 0
                    if let Some(pid_bytes) = self.dump.read_physical(potential_task + offsets.pid as u64, 4) {
                        let pid = i32::from_le_bytes([pid_bytes[0], pid_bytes[1], pid_bytes[2], pid_bytes[3]]);
                        if pid == 0 {
                            self.init_task = Some(potential_task);
                            return Ok(());
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate a potential task_struct
    fn validate_task_struct(&self, addr: u64, offsets: &TaskStructOffsets) -> bool {
        // Read potential task_struct
        if let Some(data) = self.dump.read_physical(addr, 0x100) {
            // Check state field (should be small integer)
            let state = i64::from_le_bytes([
                data[offsets.state], data[offsets.state + 1],
                data[offsets.state + 2], data[offsets.state + 3],
                data[offsets.state + 4], data[offsets.state + 5],
                data[offsets.state + 6], data[offsets.state + 7],
            ]);

            // State should be between -1 and ~10
            if state < -1 || state > 20 {
                return false;
            }

            // Check PID (should be reasonable)
            if offsets.pid < data.len() - 4 {
                let pid = i32::from_le_bytes([
                    data[offsets.pid], data[offsets.pid + 1],
                    data[offsets.pid + 2], data[offsets.pid + 3],
                ]);

                if pid < 0 || pid > 4194304 {
                    // PID_MAX_LIMIT
                    return false;
                }
            }

            // Check comm (should be printable ASCII)
            if offsets.comm < data.len() - 16 {
                let comm = &data[offsets.comm..offsets.comm + 16];
                let valid_comm = comm.iter()
                    .take_while(|&&b| b != 0)
                    .all(|&b| b >= 0x20 && b < 0x7F);

                if !valid_comm {
                    return false;
                }
            }

            return true;
        }

        false
    }

    /// Get reference to the dump
    pub fn dump(&self) -> &ParsedDump {
        self.dump
    }
}

/// Check if dump is a Linux memory dump
pub fn is_linux_dump(info: &DumpInfo) -> bool {
    matches!(info.os_type, Some(OsType::Linux))
        || matches!(info.format, super::types::DumpFormat::LiME)
}
