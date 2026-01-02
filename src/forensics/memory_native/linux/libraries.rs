//! Linux shared library analysis from memory
//!
//! Extract loaded shared libraries from Linux memory dumps.

use anyhow::Result;

use super::LinuxAnalyzer;
use crate::forensics::memory_native::dump_parser::ParsedDump;
use crate::forensics::memory_native::types::LinuxTask;

/// Loaded library information
#[derive(Debug, Clone)]
pub struct LinuxLibrary {
    /// Task/process PID
    pub pid: i32,
    /// Base address in process memory
    pub base_addr: u64,
    /// Size of mapping
    pub size: u64,
    /// Library path
    pub path: String,
    /// Is the main executable
    pub is_main: bool,
}

/// VMA (Virtual Memory Area) information
#[derive(Debug, Clone)]
pub struct VmaInfo {
    /// Start address
    pub vm_start: u64,
    /// End address
    pub vm_end: u64,
    /// Protection flags
    pub vm_flags: u64,
    /// File offset
    pub vm_pgoff: u64,
    /// File path (if file-backed)
    pub file_path: Option<String>,
}

/// Library enumerator
pub struct LibraryEnumerator<'a> {
    analyzer: &'a LinuxAnalyzer<'a>,
}

impl<'a> LibraryEnumerator<'a> {
    /// Create new library enumerator
    pub fn new(analyzer: &'a LinuxAnalyzer<'a>) -> Self {
        Self { analyzer }
    }

    /// Enumerate libraries for a specific task
    pub fn enumerate_for_task(&self, task: &LinuxTask) -> Result<Vec<LinuxLibrary>> {
        let dump = self.analyzer.dump();
        let mut libraries = Vec::new();

        if task.mm == 0 {
            // Kernel thread - no user-space mappings
            return Ok(libraries);
        }

        // Walk the VMA list from mm_struct
        let vmas = self.walk_vma_list(dump, task.mm)?;

        for vma in vmas {
            if let Some(path) = &vma.file_path {
                // Check if it's a library or executable
                if path.ends_with(".so") || path.contains(".so.") || vma.vm_pgoff == 0 {
                    let is_main = vma.vm_pgoff == 0 && !path.contains("lib");

                    libraries.push(LinuxLibrary {
                        pid: task.pid,
                        base_addr: vma.vm_start,
                        size: vma.vm_end - vma.vm_start,
                        path: path.clone(),
                        is_main,
                    });
                }
            }
        }

        // Deduplicate by path (keep lowest base address)
        libraries.sort_by_key(|l| (l.path.clone(), l.base_addr));
        libraries.dedup_by(|a, b| a.path == b.path);

        Ok(libraries)
    }

    /// Walk the VMA linked list
    fn walk_vma_list(&self, dump: &ParsedDump, mm_addr: u64) -> Result<Vec<VmaInfo>> {
        let mut vmas = Vec::new();

        // mm_struct->mmap points to the first VMA
        // The VMA list is linked via vm_next
        let mmap_ptr = dump.read_physical(mm_addr + 0x0, 8) // mmap at offset 0
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            .unwrap_or(0);

        if mmap_ptr == 0 {
            return Ok(vmas);
        }

        let mut current = mmap_ptr;
        let mut visited = std::collections::HashSet::new();

        while current != 0 && !visited.contains(&current) {
            visited.insert(current);

            if let Some(vma) = self.parse_vma(dump, current) {
                vmas.push(vma);
            }

            // vm_area_struct->vm_next is at offset ~0x10 (varies)
            current = dump.read_physical(current + 0x10, 8)
                .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
                .unwrap_or(0);

            // Safety limit
            if visited.len() > 10000 {
                break;
            }
        }

        Ok(vmas)
    }

    /// Parse a vm_area_struct
    fn parse_vma(&self, dump: &ParsedDump, vma_addr: u64) -> Option<VmaInfo> {
        // vm_area_struct layout (varies by kernel):
        // +0x00: vm_start
        // +0x08: vm_end
        // +0x10: vm_next
        // +0x18: vm_prev
        // +0x20: vm_rb
        // +0x30: vm_mm
        // +0x38: vm_page_prot
        // +0x40: vm_flags
        // +0x48: vm_pgoff
        // +0xA0: vm_file

        let data = dump.read_physical(vma_addr, 0xB0)?;

        let vm_start = u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);

        let vm_end = u64::from_le_bytes([
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15],
        ]);

        let vm_flags = u64::from_le_bytes([
            data[0x40], data[0x41], data[0x42], data[0x43],
            data[0x44], data[0x45], data[0x46], data[0x47],
        ]);

        let vm_pgoff = u64::from_le_bytes([
            data[0x48], data[0x49], data[0x4A], data[0x4B],
            data[0x4C], data[0x4D], data[0x4E], data[0x4F],
        ]);

        // Get file pointer and extract path
        let vm_file = u64::from_le_bytes([
            data[0xA0], data[0xA1], data[0xA2], data[0xA3],
            data[0xA4], data[0xA5], data[0xA6], data[0xA7],
        ]);

        let file_path = if vm_file != 0 {
            self.get_file_path(dump, vm_file)
        } else {
            None
        };

        Some(VmaInfo {
            vm_start,
            vm_end,
            vm_flags,
            vm_pgoff,
            file_path,
        })
    }

    /// Get file path from file structure
    fn get_file_path(&self, dump: &ParsedDump, file_addr: u64) -> Option<String> {
        // struct file->f_path.dentry->d_name contains the name
        // This is complex - need to walk dentry chain

        // Simplified: Try to find the path by reading nearby memory
        // Real implementation would parse dentry structures

        // file->f_path is at offset ~0x10
        // path->dentry is at offset 0x08
        let path_data = dump.read_physical(file_addr + 0x10, 0x10)?;
        let dentry_ptr = u64::from_le_bytes([
            path_data[8], path_data[9], path_data[10], path_data[11],
            path_data[12], path_data[13], path_data[14], path_data[15],
        ]);

        if dentry_ptr == 0 {
            return None;
        }

        // dentry->d_name.name is a qstr at ~offset 0x20
        // d_iname is the inline name at ~offset 0x38
        let dentry_data = dump.read_physical(dentry_ptr, 0x80)?;

        // Try reading inline name (d_iname at ~0x38)
        let name_offset = 0x38;
        let name_bytes = &dentry_data[name_offset..];
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(32).min(32);

        if end > 0 {
            let name = String::from_utf8_lossy(&name_bytes[..end]).to_string();
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_graphic() || c == '/') {
                return Some(name);
            }
        }

        None
    }

    /// Enumerate all libraries across all tasks
    pub fn enumerate_all(&self, tasks: &[LinuxTask]) -> Result<Vec<LinuxLibrary>> {
        let mut all_libraries = Vec::new();

        for task in tasks {
            if task.mm != 0 {
                if let Ok(libs) = self.enumerate_for_task(task) {
                    all_libraries.extend(libs);
                }
            }
        }

        Ok(all_libraries)
    }
}

/// Detect suspicious libraries
pub fn find_suspicious_libraries(libraries: &[LinuxLibrary]) -> Vec<&LinuxLibrary> {
    let mut suspicious = Vec::new();

    // Legitimate library paths
    let legitimate_paths = [
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/opt",
    ];

    for lib in libraries {
        let is_suspicious =
            // Not in standard paths
            !legitimate_paths.iter().any(|p| lib.path.starts_with(p)) ||
            // In temp directory
            lib.path.starts_with("/tmp") ||
            lib.path.starts_with("/dev/shm") ||
            lib.path.starts_with("/var/tmp") ||
            // Deleted file (suspicious if still loaded)
            lib.path.contains("(deleted)") ||
            // memfd (in-memory file)
            lib.path.starts_with("memfd:");

        if is_suspicious {
            suspicious.push(lib);
        }
    }

    suspicious
}

/// Check for LD_PRELOAD-style injection
pub fn detect_ld_preload_injection(libraries: &[LinuxLibrary]) -> Vec<&LinuxLibrary> {
    // LD_PRELOAD libraries are typically loaded before libc
    // and may be in non-standard locations

    libraries.iter()
        .filter(|lib| {
            !lib.is_main &&
            !lib.path.contains("libc") &&
            !lib.path.contains("ld-linux") &&
            (lib.path.starts_with("/tmp") ||
             lib.path.starts_with("/home") ||
             lib.path.starts_with("/dev/shm"))
        })
        .collect()
}

/// VM flags bit definitions
pub mod vm_flags {
    pub const VM_READ: u64 = 0x00000001;
    pub const VM_WRITE: u64 = 0x00000002;
    pub const VM_EXEC: u64 = 0x00000004;
    pub const VM_SHARED: u64 = 0x00000008;
    pub const VM_MAYREAD: u64 = 0x00000010;
    pub const VM_MAYWRITE: u64 = 0x00000020;
    pub const VM_MAYEXEC: u64 = 0x00000040;
    pub const VM_GROWSDOWN: u64 = 0x00000100;
    pub const VM_DENYWRITE: u64 = 0x00000800;
    pub const VM_EXECUTABLE: u64 = 0x00001000;
    pub const VM_LOCKED: u64 = 0x00002000;
    pub const VM_IO: u64 = 0x00004000;
}

/// Find RWX memory regions (suspicious)
pub fn find_rwx_regions(vmas: &[VmaInfo]) -> Vec<&VmaInfo> {
    vmas.iter()
        .filter(|vma| {
            let flags = vma.vm_flags;
            (flags & vm_flags::VM_READ != 0) &&
            (flags & vm_flags::VM_WRITE != 0) &&
            (flags & vm_flags::VM_EXEC != 0)
        })
        .collect()
}
