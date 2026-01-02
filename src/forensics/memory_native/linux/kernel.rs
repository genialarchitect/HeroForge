//! Linux kernel module analysis from memory
//!
//! Extract kernel modules and detect rootkits.

use anyhow::Result;

use super::LinuxAnalyzer;
use crate::forensics::memory_native::dump_parser::ParsedDump;
use crate::forensics::memory_native::types::LinuxModule;

/// Kernel module extractor
pub struct KernelExtractor<'a> {
    analyzer: &'a LinuxAnalyzer<'a>,
}

/// System call table entry
#[derive(Debug, Clone)]
pub struct SyscallEntry {
    /// Syscall number
    pub number: u32,
    /// Handler address
    pub handler: u64,
    /// Syscall name (if known)
    pub name: Option<String>,
    /// Expected module
    pub expected_module: Option<String>,
    /// Is potentially hooked
    pub is_hooked: bool,
}

impl<'a> KernelExtractor<'a> {
    /// Create new kernel extractor
    pub fn new(analyzer: &'a LinuxAnalyzer<'a>) -> Self {
        Self { analyzer }
    }

    /// Extract all loaded kernel modules
    pub fn extract_modules(&self) -> Result<Vec<LinuxModule>> {
        let dump = self.analyzer.dump();
        let mut modules = Vec::new();

        // Method 1: Walk modules list from kallsyms
        if let Some(kallsyms) = &self.analyzer.kallsyms {
            if let Some(&modules_addr) = kallsyms.symbols.get("modules") {
                let list_modules = self.walk_modules_list(dump, modules_addr)?;
                modules.extend(list_modules);
            }
        }

        // Method 2: Scan for module structures
        let scanned = self.scan_for_modules(dump)?;
        modules.extend(scanned);

        // Deduplicate by base address
        modules.sort_by_key(|m| m.base_addr);
        modules.dedup_by_key(|m| m.base_addr);

        Ok(modules)
    }

    /// Walk the modules linked list
    fn walk_modules_list(&self, dump: &ParsedDump, modules_addr: u64) -> Result<Vec<LinuxModule>> {
        let mut modules = Vec::new();

        // struct module contains:
        // - list (list_head at start)
        // - name (char[MODULE_NAME_LEN])
        // - module_core / core_layout.base
        // - core_size / core_layout.size

        // Read list head
        let list_head = dump.read_physical(modules_addr, 16)
            .ok_or_else(|| anyhow::anyhow!("Failed to read modules list"))?;

        let mut current = u64::from_le_bytes([
            list_head[0], list_head[1], list_head[2], list_head[3],
            list_head[4], list_head[5], list_head[6], list_head[7],
        ]);

        let head = modules_addr;
        let mut visited = std::collections::HashSet::new();

        while current != 0 && current != head && !visited.contains(&current) {
            visited.insert(current);

            if let Some(module) = self.parse_module_struct(dump, current) {
                modules.push(module);
            }

            // Read next pointer
            current = dump.read_physical(current, 8)
                .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
                .unwrap_or(0);

            // Safety limit
            if visited.len() > 1000 {
                break;
            }
        }

        Ok(modules)
    }

    /// Parse a struct module
    fn parse_module_struct(&self, dump: &ParsedDump, module_addr: u64) -> Option<LinuxModule> {
        // struct module layout varies by kernel version
        // Common offsets for 5.x kernels:
        // +0x00: list (list_head, 16 bytes)
        // +0x18: name (char[56] in newer kernels)
        // +0x58: mkobj
        // ...
        // +0x100+: core_layout (struct module_layout)

        let data = dump.read_physical(module_addr, 0x200)?;

        // Skip list_head (16 bytes)
        // Read name (56 bytes typically)
        let name_offset = 0x18;
        let name_bytes = &data[name_offset..name_offset + 56];
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(56);
        let name = String::from_utf8_lossy(&name_bytes[..end]).to_string();

        if name.is_empty() {
            return None;
        }

        // Find core_layout (base address and size)
        // This offset varies - try common values
        let layout_offsets = [0x100, 0x110, 0x120, 0x130, 0x140];

        for &layout_offset in &layout_offsets {
            if layout_offset + 16 > data.len() {
                continue;
            }

            let base = u64::from_le_bytes([
                data[layout_offset], data[layout_offset + 1],
                data[layout_offset + 2], data[layout_offset + 3],
                data[layout_offset + 4], data[layout_offset + 5],
                data[layout_offset + 6], data[layout_offset + 7],
            ]);

            let size = u32::from_le_bytes([
                data[layout_offset + 8], data[layout_offset + 9],
                data[layout_offset + 10], data[layout_offset + 11],
            ]) as u64;

            // Validate base address (should be in kernel module space)
            if base > 0xffffffffa0000000 && base < 0xffffffffc0000000 && size > 0 && size < 0x10000000 {
                // Read taint flags
                let tainted = data.get(0x80).map(|&b| b != 0).unwrap_or(false);

                return Some(LinuxModule {
                    base_addr: base,
                    size,
                    name,
                    args: None,
                    refcount: 0,
                    tainted,
                });
            }
        }

        // If layout not found, return with just name
        Some(LinuxModule {
            base_addr: module_addr,
            size: 0,
            name,
            args: None,
            refcount: 0,
            tainted: false,
        })
    }

    /// Scan memory for module structures
    fn scan_for_modules(&self, dump: &ParsedDump) -> Result<Vec<LinuxModule>> {
        let mut modules = Vec::new();

        // Search for common module name patterns
        let common_modules: &[&[u8]] = &[
            b"e1000",
            b"ext4",
            b"xfs",
            b"nfsd",
            b"nvidia",
            b"vboxdrv",
            b"vmnet",
        ];

        for name in common_modules {
            let matches = dump.search_pattern(name);

            for &offset in matches.iter().take(10) {
                // Try to validate as module name field
                if let Some(data) = dump.read_bytes(offset.saturating_sub(0x18), 0x200) {
                    // Check if offset is at name position in struct
                    let potential_module = offset - 0x18;
                    if let Some(module) = self.parse_module_struct(dump, potential_module) {
                        modules.push(module);
                    }
                }
            }
        }

        Ok(modules)
    }

    /// Check syscall table for hooks
    pub fn check_syscall_hooks(&self) -> Result<Vec<SyscallEntry>> {
        let dump = self.analyzer.dump();
        let mut entries = Vec::new();

        // Find sys_call_table
        let syscall_table_addr = if let Some(kallsyms) = &self.analyzer.kallsyms {
            kallsyms.symbols.get("sys_call_table").copied()
        } else {
            // Search for syscall table pattern
            self.find_syscall_table(dump)
        };

        if let Some(table_addr) = syscall_table_addr {
            // Read syscall table entries
            // x86_64 has ~450 syscalls
            for i in 0..450u32 {
                let entry_addr = table_addr + (i as u64 * 8);

                if let Some(handler_bytes) = dump.read_physical(entry_addr, 8) {
                    let handler = u64::from_le_bytes([
                        handler_bytes[0], handler_bytes[1],
                        handler_bytes[2], handler_bytes[3],
                        handler_bytes[4], handler_bytes[5],
                        handler_bytes[6], handler_bytes[7],
                    ]);

                    // Check if handler is in kernel text section
                    let is_hooked = !is_kernel_text(handler);

                    entries.push(SyscallEntry {
                        number: i,
                        handler,
                        name: syscall_name(i),
                        expected_module: Some("kernel".to_string()),
                        is_hooked,
                    });
                }
            }
        }

        Ok(entries)
    }

    /// Find syscall table by searching for pattern
    fn find_syscall_table(&self, dump: &ParsedDump) -> Option<u64> {
        // Syscall table has characteristic patterns:
        // - Sequential kernel function pointers
        // - sys_read, sys_write, etc. at known offsets

        // Search for "sys_read" and work backwards
        if let Some(kallsyms) = &self.analyzer.kallsyms {
            if let Some(&sys_read) = kallsyms.symbols.get("sys_read") {
                // sys_read is typically syscall 0 on x86_64
                let pattern = sys_read.to_le_bytes();
                let matches = dump.search_pattern(&pattern);

                for &offset in matches.iter().take(10) {
                    // Verify this looks like syscall table
                    if self.verify_syscall_table(dump, offset) {
                        return Some(offset);
                    }
                }
            }
        }

        None
    }

    /// Verify a potential syscall table
    fn verify_syscall_table(&self, dump: &ParsedDump, addr: u64) -> bool {
        // Read several entries and verify they look like kernel pointers
        if let Some(data) = dump.read_physical(addr, 80) {
            for i in 0..10 {
                let ptr = u64::from_le_bytes([
                    data[i * 8], data[i * 8 + 1],
                    data[i * 8 + 2], data[i * 8 + 3],
                    data[i * 8 + 4], data[i * 8 + 5],
                    data[i * 8 + 6], data[i * 8 + 7],
                ]);

                // All entries should be in kernel text
                if !is_kernel_text(ptr) {
                    return false;
                }
            }
            return true;
        }
        false
    }
}

/// Check if address is in kernel text section
fn is_kernel_text(addr: u64) -> bool {
    // Typical kernel text ranges for x86_64
    (addr >= 0xffffffff80000000 && addr < 0xffffffffa0000000) ||
    (addr >= 0xffffffff00000000 && addr < 0xffffffff80000000)
}

/// Get syscall name for number
fn syscall_name(num: u32) -> Option<String> {
    // Common x86_64 syscalls
    let names: &[(u32, &str)] = &[
        (0, "read"),
        (1, "write"),
        (2, "open"),
        (3, "close"),
        (4, "stat"),
        (5, "fstat"),
        (6, "lstat"),
        (7, "poll"),
        (8, "lseek"),
        (9, "mmap"),
        (10, "mprotect"),
        (11, "munmap"),
        (12, "brk"),
        (56, "clone"),
        (57, "fork"),
        (58, "vfork"),
        (59, "execve"),
        (60, "exit"),
        (62, "kill"),
        (101, "ptrace"),
        (102, "getuid"),
        (105, "setuid"),
        (157, "prctl"),
    ];

    names.iter()
        .find(|(n, _)| *n == num)
        .map(|(_, name)| name.to_string())
}

/// Detect potentially malicious modules
pub fn detect_suspicious_modules(modules: &[LinuxModule]) -> Vec<&LinuxModule> {
    let mut suspicious = Vec::new();

    // Known legitimate module prefixes
    let legitimate_prefixes = [
        "e1000", "i40e", "igb", "ixgbe",  // Network drivers
        "xfs", "ext4", "btrfs", "nfs",    // Filesystems
        "nvidia", "amdgpu", "i915",       // Graphics
        "snd_", "usb", "hid",             // Audio/USB/HID
        "kvm", "vhost", "virtio",         // Virtualization
        "nf_", "ip_", "xt_",              // Netfilter
    ];

    for module in modules {
        let name_lower = module.name.to_lowercase();

        let is_suspicious =
            // Very short name (might be hiding)
            module.name.len() < 3 ||
            // Tainted module
            module.tainted ||
            // Random-looking name
            (module.name.chars().filter(|c| c.is_ascii_digit()).count() > 2 &&
             !legitimate_prefixes.iter().any(|p| name_lower.starts_with(p))) ||
            // Hidden (no size info)
            module.size == 0;

        if is_suspicious {
            suspicious.push(module);
        }
    }

    suspicious
}

/// Detect inline hooks in kernel code
pub fn detect_inline_hooks(dump: &ParsedDump, base: u64, size: u64) -> Vec<u64> {
    let mut hooked_addresses = Vec::new();

    if let Some(code) = dump.read_physical(base, size.min(0x100000) as usize) {
        // Look for common hook patterns
        for i in 0..code.len().saturating_sub(12) {
            // JMP rel32 at function start (aligned)
            if i % 16 == 0 && code[i] == 0xE9 {
                hooked_addresses.push(base + i as u64);
            }

            // MOV RAX, imm64; JMP RAX
            if code[i] == 0x48 && code[i + 1] == 0xB8 &&
               i + 12 < code.len() &&
               code[i + 10] == 0xFF && code[i + 11] == 0xE0
            {
                hooked_addresses.push(base + i as u64);
            }
        }
    }

    hooked_addresses
}
