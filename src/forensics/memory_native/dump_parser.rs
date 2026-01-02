//! Memory dump format parsing
//!
//! Parses various memory dump formats to extract analyzable regions.

use anyhow::{anyhow, Result};
use memmap2::Mmap;
use std::fs::File;
use std::path::Path;

use super::types::{Architecture, DumpFormat, DumpInfo, OsType};

/// Memory region descriptor
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Physical address start
    pub physical_start: u64,
    /// Virtual address (if mapped)
    pub virtual_start: Option<u64>,
    /// Size of region in bytes
    pub size: u64,
    /// Offset in dump file
    pub file_offset: u64,
}

/// Parsed memory dump ready for analysis
pub struct ParsedDump {
    /// Memory-mapped file data
    mmap: Mmap,
    /// Dump metadata
    pub info: DumpInfo,
    /// Memory regions available for analysis
    pub regions: Vec<MemoryRegion>,
}

impl ParsedDump {
    /// Open and parse a memory dump file
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref())?;
        let mmap = unsafe { Mmap::map(&file)? };

        let file_size = mmap.len() as u64;

        // Detect format from header
        let format = if mmap.len() >= 16 {
            DumpFormat::detect(&mmap[..16])
        } else {
            DumpFormat::Unknown
        };

        let mut info = DumpInfo {
            format,
            file_size,
            ..Default::default()
        };

        let regions = match format {
            DumpFormat::CrashDump => Self::parse_crash_dump(&mmap, &mut info)?,
            DumpFormat::Hibernation => Self::parse_hibernation(&mmap, &mut info)?,
            DumpFormat::LiME => Self::parse_lime(&mmap, &mut info)?,
            DumpFormat::VMware => Self::parse_vmware(&mmap, &mut info)?,
            DumpFormat::EWF => Self::parse_ewf(&mmap, &mut info)?,
            DumpFormat::Raw | DumpFormat::Unknown => {
                // Raw dump - treat entire file as one region
                vec![MemoryRegion {
                    physical_start: 0,
                    virtual_start: None,
                    size: file_size,
                    file_offset: 0,
                }]
            }
            _ => {
                // Other formats - treat as raw for now
                vec![MemoryRegion {
                    physical_start: 0,
                    virtual_start: None,
                    size: file_size,
                    file_offset: 0,
                }]
            }
        };

        Ok(Self { mmap, info, regions })
    }

    /// Get raw bytes at a file offset
    pub fn read_bytes(&self, offset: u64, size: usize) -> Option<&[u8]> {
        let start = offset as usize;
        let end = start.checked_add(size)?;
        if end <= self.mmap.len() {
            Some(&self.mmap[start..end])
        } else {
            None
        }
    }

    /// Read a u32 at offset (little-endian)
    pub fn read_u32(&self, offset: u64) -> Option<u32> {
        let bytes = self.read_bytes(offset, 4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a u64 at offset (little-endian)
    pub fn read_u64(&self, offset: u64) -> Option<u64> {
        let bytes = self.read_bytes(offset, 8)?;
        Some(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Translate physical address to file offset
    pub fn physical_to_offset(&self, physical_addr: u64) -> Option<u64> {
        for region in &self.regions {
            if physical_addr >= region.physical_start
                && physical_addr < region.physical_start + region.size
            {
                let offset_in_region = physical_addr - region.physical_start;
                return Some(region.file_offset + offset_in_region);
            }
        }
        None
    }

    /// Read bytes from a physical address
    pub fn read_physical(&self, physical_addr: u64, size: usize) -> Option<&[u8]> {
        let offset = self.physical_to_offset(physical_addr)?;
        self.read_bytes(offset, size)
    }

    /// Search for a byte pattern in the dump
    pub fn search_pattern(&self, pattern: &[u8]) -> Vec<u64> {
        let mut results = Vec::new();

        if pattern.is_empty() || pattern.len() > self.mmap.len() {
            return results;
        }

        // Simple sliding window search
        for i in 0..=(self.mmap.len() - pattern.len()) {
            if &self.mmap[i..i + pattern.len()] == pattern {
                results.push(i as u64);
            }
        }

        results
    }

    /// Search for a byte pattern with wildcards (0xFF = wildcard)
    pub fn search_pattern_masked(&self, pattern: &[u8], mask: &[u8]) -> Vec<u64> {
        let mut results = Vec::new();

        if pattern.is_empty() || pattern.len() != mask.len() || pattern.len() > self.mmap.len() {
            return results;
        }

        'outer: for i in 0..=(self.mmap.len() - pattern.len()) {
            for j in 0..pattern.len() {
                if mask[j] == 0xFF {
                    continue; // Wildcard
                }
                if self.mmap[i + j] != pattern[j] {
                    continue 'outer;
                }
            }
            results.push(i as u64);
        }

        results
    }

    /// Parse Windows crash dump format
    fn parse_crash_dump(data: &[u8], info: &mut DumpInfo) -> Result<Vec<MemoryRegion>> {
        // Verify signature
        if data.len() < 0x2000 {
            return Err(anyhow!("Crash dump too small"));
        }

        let signature = &data[0..8];
        let is_64bit = signature == b"PAGEDU64";

        info.architecture = if is_64bit { Architecture::X64 } else { Architecture::X86 };
        info.os_type = Some(OsType::Windows);

        // Parse header fields
        if is_64bit {
            // 64-bit crash dump header
            // Offset 0x10: MajorVersion
            // Offset 0x14: MinorVersion
            // Offset 0x18: DirectoryTableBase (CR3)
            // Offset 0x20: PfnDataBase
            // Offset 0x28: PsLoadedModuleList
            // Offset 0x30: PsActiveProcessHead

            let _major_version = u32::from_le_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]);
            let _minor_version = u32::from_le_bytes([data[0x14], data[0x15], data[0x16], data[0x17]]);

            info.num_processors = Some(u32::from_le_bytes([data[0x38], data[0x39], data[0x3A], data[0x3B]]));

            // Physical memory runs start at offset 0x88 for 64-bit
            let num_runs = u32::from_le_bytes([data[0x88], data[0x89], data[0x8A], data[0x8B]]) as usize;

            let mut regions = Vec::new();
            let mut file_offset = 0x2000u64; // Data starts after header

            for i in 0..num_runs.min(256) {
                let run_offset = 0x90 + i * 16;
                if run_offset + 16 > data.len() {
                    break;
                }

                let base_page = u64::from_le_bytes([
                    data[run_offset], data[run_offset + 1],
                    data[run_offset + 2], data[run_offset + 3],
                    data[run_offset + 4], data[run_offset + 5],
                    data[run_offset + 6], data[run_offset + 7],
                ]);

                let page_count = u64::from_le_bytes([
                    data[run_offset + 8], data[run_offset + 9],
                    data[run_offset + 10], data[run_offset + 11],
                    data[run_offset + 12], data[run_offset + 13],
                    data[run_offset + 14], data[run_offset + 15],
                ]);

                let size = page_count * 0x1000; // 4KB pages

                regions.push(MemoryRegion {
                    physical_start: base_page * 0x1000,
                    virtual_start: None,
                    size,
                    file_offset,
                });

                file_offset += size;
            }

            info.memory_size = Some(regions.iter().map(|r| r.size).sum());

            Ok(regions)
        } else {
            // 32-bit crash dump - simpler structure
            info.num_processors = Some(u32::from_le_bytes([data[0x20], data[0x21], data[0x22], data[0x23]]));

            // For 32-bit, we'll treat it as a contiguous dump for now
            Ok(vec![MemoryRegion {
                physical_start: 0,
                virtual_start: None,
                size: data.len() as u64 - 0x1000,
                file_offset: 0x1000,
            }])
        }
    }

    /// Parse Windows hibernation file
    fn parse_hibernation(data: &[u8], info: &mut DumpInfo) -> Result<Vec<MemoryRegion>> {
        // Hibernation files are compressed and complex
        // For now, return basic info and treat as raw after header

        info.os_type = Some(OsType::Windows);

        // Check for decompressed marker
        if data.len() >= 8 && (&data[0..4] == b"wake" || &data[0..4] == b"WAKE") {
            // Resume header - file may be partially overwritten
        }

        // Hibernation files require decompression
        // For this implementation, we note it's hibernation but treat as raw
        Ok(vec![MemoryRegion {
            physical_start: 0,
            virtual_start: None,
            size: data.len() as u64,
            file_offset: 0,
        }])
    }

    /// Parse LiME (Linux Memory Extractor) format
    fn parse_lime(data: &[u8], info: &mut DumpInfo) -> Result<Vec<MemoryRegion>> {
        info.os_type = Some(OsType::Linux);

        let mut regions = Vec::new();
        let mut offset = 0usize;

        // LiME header structure (32 bytes each):
        // u32 magic (0x4C694D45 = "LiME")
        // u32 version
        // u64 start_addr
        // u64 end_addr
        // u64 reserved

        while offset + 32 <= data.len() {
            let magic = u32::from_le_bytes([
                data[offset], data[offset + 1],
                data[offset + 2], data[offset + 3]
            ]);

            if magic != 0x4C694D45 {
                break;
            }

            let version = u32::from_le_bytes([
                data[offset + 4], data[offset + 5],
                data[offset + 6], data[offset + 7]
            ]);

            if version != 1 {
                // Unsupported version
                break;
            }

            let start_addr = u64::from_le_bytes([
                data[offset + 8], data[offset + 9],
                data[offset + 10], data[offset + 11],
                data[offset + 12], data[offset + 13],
                data[offset + 14], data[offset + 15],
            ]);

            let end_addr = u64::from_le_bytes([
                data[offset + 16], data[offset + 17],
                data[offset + 18], data[offset + 19],
                data[offset + 20], data[offset + 21],
                data[offset + 22], data[offset + 23],
            ]);

            let size = end_addr - start_addr + 1;

            regions.push(MemoryRegion {
                physical_start: start_addr,
                virtual_start: None,
                size,
                file_offset: (offset + 32) as u64,
            });

            offset += 32 + size as usize;
        }

        info.memory_size = Some(regions.iter().map(|r| r.size).sum());

        Ok(regions)
    }

    /// Parse VMware .vmem format
    fn parse_vmware(data: &[u8], info: &mut DumpInfo) -> Result<Vec<MemoryRegion>> {
        // VMware .vmem files are typically raw memory dumps
        // The .vmss/.vmsn files contain metadata

        // For .vmem, treat as raw but try to detect OS/arch from content
        let file_size = data.len() as u64;

        // Try to detect if it's Windows or Linux by looking for signatures
        // Windows: Look for "MZ" header of ntoskrnl
        // Linux: Look for "Linux" string in early pages

        // Default assumptions based on common VM sizes
        if file_size >= 4 * 1024 * 1024 * 1024 {
            // 4GB+, likely 64-bit
            info.architecture = Architecture::X64;
        }

        info.memory_size = Some(file_size);

        Ok(vec![MemoryRegion {
            physical_start: 0,
            virtual_start: None,
            size: file_size,
            file_offset: 0,
        }])
    }

    /// Parse EWF (Expert Witness Format / E01) - stub
    fn parse_ewf(data: &[u8], info: &mut DumpInfo) -> Result<Vec<MemoryRegion>> {
        // EWF is a complex container format used by EnCase
        // Full implementation would require parsing the segment structure

        if data.len() < 13 || &data[0..3] != b"EVF" {
            return Err(anyhow!("Invalid EWF signature"));
        }

        // For now, note the format but can't extract data without full parser
        info.format = DumpFormat::EWF;

        // Return empty - proper EWF parsing is complex
        Ok(vec![])
    }

    /// Get total size of dump data
    pub fn total_size(&self) -> u64 {
        self.info.file_size
    }

    /// Get direct access to memory-mapped data
    pub fn raw_data(&self) -> &[u8] {
        &self.mmap
    }
}

/// Virtual address translation for Windows
pub struct WindowsAddressTranslator {
    /// Directory table base (CR3)
    dtb: u64,
    /// Is 64-bit mode
    is_64bit: bool,
    /// Page size
    page_size: u32,
}

impl WindowsAddressTranslator {
    /// Create new translator for a process
    pub fn new(dtb: u64, is_64bit: bool) -> Self {
        Self {
            dtb,
            is_64bit,
            page_size: 4096,
        }
    }

    /// Translate virtual address to physical address
    pub fn translate(&self, dump: &ParsedDump, virtual_addr: u64) -> Option<u64> {
        if self.is_64bit {
            self.translate_64bit(dump, virtual_addr)
        } else {
            self.translate_32bit(dump, virtual_addr)
        }
    }

    /// 64-bit 4-level page table translation
    fn translate_64bit(&self, dump: &ParsedDump, virtual_addr: u64) -> Option<u64> {
        // Extract page table indices from virtual address
        let pml4_index = ((virtual_addr >> 39) & 0x1FF) as usize;
        let pdpt_index = ((virtual_addr >> 30) & 0x1FF) as usize;
        let pd_index = ((virtual_addr >> 21) & 0x1FF) as usize;
        let pt_index = ((virtual_addr >> 12) & 0x1FF) as usize;
        let page_offset = (virtual_addr & 0xFFF) as u64;

        // Walk PML4
        let pml4_entry_addr = (self.dtb & !0xFFF) + (pml4_index * 8) as u64;
        let pml4_entry = dump.read_physical(pml4_entry_addr, 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))?;

        if pml4_entry & 1 == 0 {
            return None; // Not present
        }

        // Walk PDPT
        let pdpt_base = pml4_entry & 0x000F_FFFF_FFFF_F000;
        let pdpt_entry_addr = pdpt_base + (pdpt_index * 8) as u64;
        let pdpt_entry = dump.read_physical(pdpt_entry_addr, 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))?;

        if pdpt_entry & 1 == 0 {
            return None; // Not present
        }

        // Check for 1GB page
        if pdpt_entry & 0x80 != 0 {
            let page_base = pdpt_entry & 0x000F_FFFF_C000_0000;
            return Some(page_base + (virtual_addr & 0x3FFF_FFFF));
        }

        // Walk PD
        let pd_base = pdpt_entry & 0x000F_FFFF_FFFF_F000;
        let pd_entry_addr = pd_base + (pd_index * 8) as u64;
        let pd_entry = dump.read_physical(pd_entry_addr, 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))?;

        if pd_entry & 1 == 0 {
            return None; // Not present
        }

        // Check for 2MB page
        if pd_entry & 0x80 != 0 {
            let page_base = pd_entry & 0x000F_FFFF_FFE0_0000;
            return Some(page_base + (virtual_addr & 0x1F_FFFF));
        }

        // Walk PT
        let pt_base = pd_entry & 0x000F_FFFF_FFFF_F000;
        let pt_entry_addr = pt_base + (pt_index * 8) as u64;
        let pt_entry = dump.read_physical(pt_entry_addr, 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))?;

        if pt_entry & 1 == 0 {
            return None; // Not present
        }

        let page_base = pt_entry & 0x000F_FFFF_FFFF_F000;
        Some(page_base + page_offset)
    }

    /// 32-bit 2-level page table translation
    fn translate_32bit(&self, dump: &ParsedDump, virtual_addr: u64) -> Option<u64> {
        let virtual_addr = virtual_addr as u32;

        let pd_index = ((virtual_addr >> 22) & 0x3FF) as usize;
        let pt_index = ((virtual_addr >> 12) & 0x3FF) as usize;
        let page_offset = (virtual_addr & 0xFFF) as u64;

        // Read page directory entry
        let pd_entry_addr = (self.dtb as u32 & !0xFFF) + (pd_index * 4) as u32;
        let pd_entry = dump.read_physical(pd_entry_addr as u64, 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))?;

        if pd_entry & 1 == 0 {
            return None; // Not present
        }

        // Check for 4MB large page (PSE)
        if pd_entry & 0x80 != 0 {
            let page_base = (pd_entry & 0xFFC0_0000) as u64;
            return Some(page_base + (virtual_addr & 0x3F_FFFF) as u64);
        }

        // Read page table entry
        let pt_base = pd_entry & 0xFFFF_F000;
        let pt_entry_addr = pt_base + (pt_index * 4) as u32;
        let pt_entry = dump.read_physical(pt_entry_addr as u64, 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))?;

        if pt_entry & 1 == 0 {
            return None; // Not present
        }

        let page_base = (pt_entry & 0xFFFF_F000) as u64;
        Some(page_base + page_offset)
    }

    /// Read bytes from virtual address
    pub fn read_virtual(&self, dump: &ParsedDump, virtual_addr: u64, size: usize) -> Option<Vec<u8>> {
        let mut result = Vec::with_capacity(size);
        let mut remaining = size;
        let mut current_va = virtual_addr;

        while remaining > 0 {
            let physical = self.translate(dump, current_va)?;
            let offset_in_page = (current_va & 0xFFF) as usize;
            let bytes_in_page = (self.page_size as usize - offset_in_page).min(remaining);

            let data = dump.read_physical(physical, bytes_in_page)?;
            result.extend_from_slice(data);

            remaining -= bytes_in_page;
            current_va += bytes_in_page as u64;
        }

        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dump_format_detection() {
        // Test crash dump detection
        let crash_dump_header = b"PAGEDUMP\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(DumpFormat::detect(crash_dump_header), DumpFormat::CrashDump);

        // Test 64-bit crash dump
        let crash_dump_64 = b"PAGEDU64\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(DumpFormat::detect(crash_dump_64), DumpFormat::CrashDump);

        // Test LiME
        let lime_header = [0x45, 0x4D, 0x69, 0x4C, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(DumpFormat::detect(&lime_header), DumpFormat::LiME);
    }
}
