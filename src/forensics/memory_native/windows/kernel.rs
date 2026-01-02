//! Windows kernel module analysis from memory
//!
//! Extract kernel modules (drivers) and detect rootkits.

use anyhow::Result;

use super::WindowsAnalyzer;
use crate::forensics::memory_native::dump_parser::ParsedDump;
use crate::forensics::memory_native::types::DriverInfo;

/// Kernel module extractor
pub struct KernelExtractor<'a> {
    analyzer: &'a WindowsAnalyzer<'a>,
}

/// SSDT (System Service Descriptor Table) entry
#[derive(Debug, Clone)]
pub struct SsdtEntry {
    /// Service number
    pub index: u32,
    /// Function address
    pub address: u64,
    /// Expected module (if known)
    pub expected_module: Option<String>,
    /// Actual module (if resolved)
    pub actual_module: Option<String>,
    /// Is potentially hooked
    pub is_hooked: bool,
}

/// IDT (Interrupt Descriptor Table) entry
#[derive(Debug, Clone)]
pub struct IdtEntry {
    /// Interrupt number
    pub vector: u8,
    /// Handler address
    pub handler: u64,
    /// Segment selector
    pub selector: u16,
    /// Is potentially hooked
    pub is_hooked: bool,
}

impl<'a> KernelExtractor<'a> {
    /// Create new kernel extractor
    pub fn new(analyzer: &'a WindowsAnalyzer<'a>) -> Self {
        Self { analyzer }
    }

    /// Extract all loaded kernel modules (drivers)
    pub fn extract_drivers(&self) -> Result<Vec<DriverInfo>> {
        let dump = self.analyzer.dump();
        let mut drivers = Vec::new();

        // Method 1: Walk PsLoadedModuleList
        if let Some(kernel_base) = self.analyzer.kernel_base {
            if let Ok(list_drivers) = self.walk_loaded_module_list(dump, kernel_base) {
                drivers.extend(list_drivers);
            }
        }

        // Method 2: Scan for driver pool tags
        let pool_drivers = self.scan_driver_pools(dump)?;
        drivers.extend(pool_drivers);

        // Deduplicate by base address
        drivers.sort_by_key(|d| d.base_addr);
        drivers.dedup_by_key(|d| d.base_addr);

        Ok(drivers)
    }

    /// Walk PsLoadedModuleList to enumerate drivers
    fn walk_loaded_module_list(&self, dump: &ParsedDump, kernel_base: u64) -> Result<Vec<DriverInfo>> {
        let mut drivers = Vec::new();

        // PsLoadedModuleList is exported from ntoskrnl
        // We need to find it by parsing exports or searching

        // Search for ntoskrnl.exe in memory to get its base
        // Then parse exports to find PsLoadedModuleList

        // For now, search for LDR_DATA_TABLE_ENTRY structures
        // that look like kernel modules

        // Kernel drivers have characteristic base addresses
        let kernel_ranges = [
            (0xfffff800_00000000u64, 0xfffff880_00000000u64), // Kernel space (typical)
            (0xfffff880_00000000u64, 0xfffff8a0_00000000u64), // Session space
        ];

        // Search for "MZ" headers in kernel space
        for (start, _end) in &kernel_ranges {
            // Sample a few locations
            for offset in (0..0x10000000u64).step_by(0x1000) {
                let addr = start + offset;
                if let Some(header) = dump.read_physical(addr, 2) {
                    if header == b"MZ" {
                        if let Some(driver) = self.try_parse_driver(dump, addr) {
                            drivers.push(driver);
                        }
                    }
                }

                // Limit search
                if drivers.len() >= 500 {
                    break;
                }
            }
        }

        // Ensure ntoskrnl is included
        if let Some(driver) = self.try_parse_driver(dump, kernel_base) {
            if !drivers.iter().any(|d| d.base_addr == kernel_base) {
                drivers.push(driver);
            }
        }

        Ok(drivers)
    }

    /// Try to parse a driver at an address
    fn try_parse_driver(&self, dump: &ParsedDump, base_addr: u64) -> Option<DriverInfo> {
        let header = dump.read_physical(base_addr, 0x400)?;

        // Check DOS header
        if &header[0..2] != b"MZ" {
            return None;
        }

        // Get PE header offset
        let pe_offset = u32::from_le_bytes([
            header[0x3C], header[0x3C + 1], header[0x3C + 2], header[0x3C + 3]
        ]) as usize;

        if pe_offset >= header.len() - 4 {
            return None;
        }

        // Check PE signature
        if &header[pe_offset..pe_offset + 4] != b"PE\x00\x00" {
            return None;
        }

        // Parse PE header
        let machine = u16::from_le_bytes([
            header[pe_offset + 4], header[pe_offset + 5]
        ]);

        // Verify it's a valid machine type
        if machine != 0x8664 && machine != 0x14c {
            return None;
        }

        // Get size of image
        let size_of_image = if machine == 0x8664 {
            // 64-bit: optional header at pe_offset + 0x18
            let opt_header_offset = pe_offset + 0x18;
            if opt_header_offset + 0x50 > header.len() {
                return None;
            }
            u32::from_le_bytes([
                header[opt_header_offset + 0x38],
                header[opt_header_offset + 0x39],
                header[opt_header_offset + 0x3A],
                header[opt_header_offset + 0x3B],
            ]) as u64
        } else {
            // 32-bit
            let opt_header_offset = pe_offset + 0x18;
            if opt_header_offset + 0x40 > header.len() {
                return None;
            }
            u32::from_le_bytes([
                header[opt_header_offset + 0x38],
                header[opt_header_offset + 0x39],
                header[opt_header_offset + 0x3A],
                header[opt_header_offset + 0x3B],
            ]) as u64
        };

        // Try to get driver name from export directory or path
        let name = self.get_module_name(dump, base_addr, &header, pe_offset)
            .unwrap_or_else(|| format!("Unknown_{:016x}", base_addr));

        Some(DriverInfo {
            base_addr,
            size: size_of_image,
            name: name.clone(),
            path: name, // Would need more context for full path
            service_name: None,
            load_order: None,
        })
    }

    /// Try to get module name from PE export directory
    fn get_module_name(&self, dump: &ParsedDump, base: u64, header: &[u8], pe_offset: usize) -> Option<String> {
        // Get export directory RVA from data directory
        let machine = u16::from_le_bytes([header[pe_offset + 4], header[pe_offset + 5]]);
        let opt_header_offset = pe_offset + 0x18;

        let export_dir_rva = if machine == 0x8664 {
            // 64-bit: export directory at optional header + 0x70
            if opt_header_offset + 0x78 > header.len() {
                return None;
            }
            u32::from_le_bytes([
                header[opt_header_offset + 0x70],
                header[opt_header_offset + 0x71],
                header[opt_header_offset + 0x72],
                header[opt_header_offset + 0x73],
            ])
        } else {
            // 32-bit: export directory at optional header + 0x60
            if opt_header_offset + 0x68 > header.len() {
                return None;
            }
            u32::from_le_bytes([
                header[opt_header_offset + 0x60],
                header[opt_header_offset + 0x61],
                header[opt_header_offset + 0x62],
                header[opt_header_offset + 0x63],
            ])
        };

        if export_dir_rva == 0 {
            return None;
        }

        // Read export directory
        let export_dir = dump.read_physical(base + export_dir_rva as u64, 0x28)?;

        // Name RVA at offset 0x0C
        let name_rva = u32::from_le_bytes([
            export_dir[0x0C], export_dir[0x0D], export_dir[0x0E], export_dir[0x0F]
        ]);

        if name_rva == 0 {
            return None;
        }

        // Read name string
        let name_bytes = dump.read_physical(base + name_rva as u64, 256)?;
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(256);
        let name = String::from_utf8_lossy(&name_bytes[..end]).to_string();

        Some(name)
    }

    /// Scan for driver pool allocations
    fn scan_driver_pools(&self, dump: &ParsedDump) -> Result<Vec<DriverInfo>> {
        let mut drivers = Vec::new();

        // Driver object pool tags
        let driver_tags = [
            b"Driv", // DRIVER_OBJECT
            b"Devi", // DEVICE_OBJECT
        ];

        for tag in &driver_tags {
            let matches = dump.search_pattern(*tag);

            for &offset in matches.iter().take(500) {
                // Try to parse as driver object
                if let Some(driver) = self.try_parse_driver_object(dump, offset) {
                    drivers.push(driver);
                }
            }
        }

        Ok(drivers)
    }

    /// Try to parse a DRIVER_OBJECT structure
    fn try_parse_driver_object(&self, dump: &ParsedDump, offset: u64) -> Option<DriverInfo> {
        // DRIVER_OBJECT structure (64-bit):
        // +0x00: Type (CSHORT) = 4
        // +0x02: Size (CSHORT)
        // +0x08: DeviceObject (PDEVICE_OBJECT)
        // +0x10: Flags
        // +0x18: DriverStart (PVOID)
        // +0x20: DriverSize (ULONG)
        // +0x28: DriverSection (PVOID) - LDR_DATA_TABLE_ENTRY
        // +0x30: DriverExtension
        // +0x38: DriverName (UNICODE_STRING)
        // +0x48: HardwareDatabase

        let data = dump.read_bytes(offset, 0x100)?;

        // Check type
        let obj_type = u16::from_le_bytes([data[0], data[1]]);
        if obj_type != 4 {
            return None;
        }

        // Read driver start and size
        let driver_start = u64::from_le_bytes([
            data[0x18], data[0x19], data[0x1A], data[0x1B],
            data[0x1C], data[0x1D], data[0x1E], data[0x1F],
        ]);

        let driver_size = u32::from_le_bytes([
            data[0x20], data[0x21], data[0x22], data[0x23]
        ]) as u64;

        if driver_start == 0 || driver_size == 0 {
            return None;
        }

        // Read driver name (UNICODE_STRING at +0x38)
        let name_len = u16::from_le_bytes([data[0x38], data[0x39]]) as usize;
        let name_buf = u64::from_le_bytes([
            data[0x40], data[0x41], data[0x42], data[0x43],
            data[0x44], data[0x45], data[0x46], data[0x47],
        ]);

        let name = if name_len > 0 && name_len < 512 && name_buf != 0 {
            dump.read_physical(name_buf, name_len)
                .map(|bytes| {
                    let utf16: Vec<u16> = bytes.chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    String::from_utf16_lossy(&utf16)
                })
                .unwrap_or_default()
        } else {
            String::new()
        };

        Some(DriverInfo {
            base_addr: driver_start,
            size: driver_size,
            name: name.clone(),
            path: name,
            service_name: None,
            load_order: None,
        })
    }

    /// Check SSDT for hooks
    pub fn check_ssdt_hooks(&self) -> Result<Vec<SsdtEntry>> {
        let _dump = self.analyzer.dump();
        let mut entries = Vec::new();

        // SSDT is pointed to by KeServiceDescriptorTable
        // Would need to:
        // 1. Find KeServiceDescriptorTable export from ntoskrnl
        // 2. Read the SSDT base address
        // 3. Read service table entries
        // 4. Verify each entry points to ntoskrnl

        // Placeholder - would need kernel base and export parsing
        if let Some(_kernel_base) = self.analyzer.kernel_base {
            // Would enumerate SSDT entries here
            entries.push(SsdtEntry {
                index: 0,
                address: 0,
                expected_module: Some("ntoskrnl.exe".to_string()),
                actual_module: None,
                is_hooked: false,
            });
        }

        Ok(entries)
    }

    /// Check IDT for hooks
    pub fn check_idt_hooks(&self) -> Result<Vec<IdtEntry>> {
        let _dump = self.analyzer.dump();
        let entries = Vec::new();

        // IDT is per-processor, pointed to by IDTR register
        // Would need to:
        // 1. Find KPCR (Kernel Processor Control Region)
        // 2. Read IDT base from KPCR.IdtBase
        // 3. Parse IDT entries
        // 4. Verify handlers are in expected modules

        Ok(entries)
    }
}

/// Detect potentially malicious drivers
pub fn detect_suspicious_drivers(drivers: &[DriverInfo]) -> Vec<&DriverInfo> {
    let mut suspicious = Vec::new();

    // Known legitimate driver prefixes
    let legitimate_prefixes = [
        "ntoskrnl",
        "hal.dll",
        "win32k",
        "ndis",
        "tcpip",
        "fltmgr",
        "ntfs",
        "volmgr",
        "disk",
        "classpnp",
        "partmgr",
        "acpi",
        "pci",
        "fwpkclnt",
    ];

    for driver in drivers {
        let name_lower = driver.name.to_lowercase();

        // Check for suspicious characteristics
        let is_suspicious =
            // Very short name
            driver.name.len() < 4 ||
            // Random-looking name
            driver.name.chars().filter(|c| c.is_ascii_digit()).count() > 3 ||
            // Not in system32/drivers
            (!driver.path.to_lowercase().contains("\\system32\\drivers\\") &&
             !driver.path.to_lowercase().contains("\\sysnative\\") &&
             !driver.path.is_empty()) ||
            // Doesn't match legitimate patterns
            !legitimate_prefixes.iter().any(|p| name_lower.starts_with(p));

        if is_suspicious {
            suspicious.push(driver);
        }
    }

    suspicious
}

/// Check for inline hooks in driver code
pub fn detect_inline_hooks(dump: &ParsedDump, driver: &DriverInfo) -> Vec<u64> {
    let mut hooked_addresses = Vec::new();

    // Read driver code
    if let Some(code) = dump.read_physical(driver.base_addr, driver.size.min(0x100000) as usize) {
        // Look for common hook patterns:
        // - JMP (0xE9) at function start
        // - PUSH + RET (0x68 ... 0xC3)
        // - MOV + JMP (0x48 0xB8 ... 0xFF 0xE0)

        for i in 0..code.len().saturating_sub(5) {
            // Check for JMP at aligned address
            if i % 16 == 0 && code[i] == 0xE9 {
                // Unconditional jump - could be detour
                hooked_addresses.push(driver.base_addr + i as u64);
            }

            // Check for PUSH + RET
            if code[i] == 0x68 && i + 5 < code.len() && code[i + 5] == 0xC3 {
                hooked_addresses.push(driver.base_addr + i as u64);
            }

            // Check for 64-bit MOV RAX + JMP RAX
            if i + 12 < code.len() &&
               code[i] == 0x48 && code[i + 1] == 0xB8 &&
               code[i + 10] == 0xFF && code[i + 11] == 0xE0
            {
                hooked_addresses.push(driver.base_addr + i as u64);
            }
        }
    }

    hooked_addresses
}
