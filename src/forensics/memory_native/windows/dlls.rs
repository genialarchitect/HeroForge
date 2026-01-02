//! Windows DLL enumeration from memory
//!
//! Extract loaded DLL information from Windows memory dumps.

use anyhow::Result;

use super::WindowsAnalyzer;
use crate::forensics::memory_native::dump_parser::{ParsedDump, WindowsAddressTranslator};
use crate::forensics::memory_native::types::{ModuleInfo, ProcessInfo};

/// DLL/Module enumerator
pub struct DllEnumerator<'a> {
    analyzer: &'a WindowsAnalyzer<'a>,
}

impl<'a> DllEnumerator<'a> {
    /// Create new DLL enumerator
    pub fn new(analyzer: &'a WindowsAnalyzer<'a>) -> Self {
        Self { analyzer }
    }

    /// Enumerate DLLs for a specific process
    pub fn enumerate_for_process(&self, process: &ProcessInfo) -> Result<Vec<ModuleInfo>> {
        let dump = self.analyzer.dump();

        if process.peb == 0 || process.dtb == 0 {
            return Ok(Vec::new());
        }

        let translator = WindowsAddressTranslator::new(process.dtb, true);
        let mut modules = Vec::new();

        // Read PEB.Ldr (LDR_DATA)
        let ldr_ptr = translator.read_virtual(dump, process.peb + 0x18, 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            .ok_or_else(|| anyhow::anyhow!("Failed to read PEB.Ldr"))?;

        if ldr_ptr == 0 {
            return Ok(Vec::new());
        }

        // LDR_DATA.InLoadOrderModuleList is at offset 0x10
        // It's a LIST_ENTRY pointing to LDR_DATA_TABLE_ENTRY structures
        let list_head = ldr_ptr + 0x10;

        // Read first entry (Flink)
        let mut current = translator.read_virtual(dump, list_head, 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            .ok_or_else(|| anyhow::anyhow!("Failed to read Flink"))?;

        let mut visited = std::collections::HashSet::new();
        let mut is_first = true;

        while current != 0 && current != list_head && !visited.contains(&current) {
            visited.insert(current);

            // Parse LDR_DATA_TABLE_ENTRY
            if let Ok(module) = self.parse_ldr_entry(dump, &translator, current, process.pid, is_first) {
                modules.push(module);
            }

            is_first = false;

            // Move to next entry
            current = translator.read_virtual(dump, current, 8)
                .and_then(|b| Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])))
                .unwrap_or(0);

            // Safety limit
            if visited.len() > 1000 {
                break;
            }
        }

        Ok(modules)
    }

    /// Parse an LDR_DATA_TABLE_ENTRY structure
    fn parse_ldr_entry(
        &self,
        dump: &ParsedDump,
        translator: &WindowsAddressTranslator,
        entry_addr: u64,
        pid: u32,
        is_main: bool,
    ) -> Result<ModuleInfo> {
        // LDR_DATA_TABLE_ENTRY structure (64-bit):
        // +0x00: InLoadOrderLinks (LIST_ENTRY)
        // +0x10: InMemoryOrderLinks (LIST_ENTRY)
        // +0x20: InInitializationOrderLinks (LIST_ENTRY)
        // +0x30: DllBase
        // +0x38: EntryPoint
        // +0x40: SizeOfImage
        // +0x48: FullDllName (UNICODE_STRING)
        // +0x58: BaseDllName (UNICODE_STRING)

        // Read DllBase
        let base_addr = translator.read_virtual(dump, entry_addr + 0x30, 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            .unwrap_or(0);

        // Read EntryPoint
        let entry_point = translator.read_virtual(dump, entry_addr + 0x38, 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            .unwrap_or(0);

        // Read SizeOfImage
        let size = translator.read_virtual(dump, entry_addr + 0x40, 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64)
            .unwrap_or(0);

        // Read FullDllName
        let full_path = self.read_unicode_string(dump, translator, entry_addr + 0x48)
            .unwrap_or_default();

        // Read BaseDllName
        let name = self.read_unicode_string(dump, translator, entry_addr + 0x58)
            .unwrap_or_default();

        Ok(ModuleInfo {
            pid,
            base_addr,
            size,
            name,
            path: full_path,
            entry_point,
            is_main,
        })
    }

    /// Read a UNICODE_STRING structure
    fn read_unicode_string(
        &self,
        dump: &ParsedDump,
        translator: &WindowsAddressTranslator,
        string_addr: u64,
    ) -> Option<String> {
        // UNICODE_STRING structure (64-bit):
        // +0x00: Length (USHORT)
        // +0x02: MaximumLength (USHORT)
        // +0x04: padding
        // +0x08: Buffer (PWSTR)

        let length = translator.read_virtual(dump, string_addr, 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)?;

        if length == 0 || length > 32768 {
            return None;
        }

        let buffer = translator.read_virtual(dump, string_addr + 8, 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))?;

        if buffer == 0 {
            return None;
        }

        let data = translator.read_virtual(dump, buffer, length)?;

        let utf16: Vec<u16> = data.chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        Some(String::from_utf16_lossy(&utf16))
    }

    /// Enumerate all DLLs across all processes
    pub fn enumerate_all(&self, processes: &[ProcessInfo]) -> Result<Vec<ModuleInfo>> {
        let mut all_modules = Vec::new();

        for process in processes {
            match self.enumerate_for_process(process) {
                Ok(modules) => all_modules.extend(modules),
                Err(_) => continue,
            }
        }

        Ok(all_modules)
    }
}

/// Detect potentially injected DLLs
pub fn detect_suspicious_dlls(modules: &[ModuleInfo]) -> Vec<&ModuleInfo> {
    let mut suspicious = Vec::new();

    for module in modules {
        let name_lower = module.name.to_lowercase();
        let path_lower = module.path.to_lowercase();

        // Check for suspicious characteristics
        let is_suspicious =
            // No path (memory-only DLL)
            module.path.is_empty() ||
            // Path in temp directories
            path_lower.contains("\\temp\\") ||
            path_lower.contains("\\tmp\\") ||
            path_lower.contains("\\appdata\\local\\temp") ||
            // Path doesn't match typical locations
            (!path_lower.contains("\\windows\\") &&
             !path_lower.contains("\\program files") &&
             !path_lower.contains("\\programdata") &&
             !module.path.is_empty()) ||
            // Suspicious names
            name_lower.contains("inject") ||
            name_lower.contains("hook") ||
            name_lower.contains("payload");

        if is_suspicious {
            suspicious.push(module);
        }
    }

    suspicious
}

/// Detect DLLs loaded from unusual locations
pub fn find_dlls_outside_system(modules: &[ModuleInfo]) -> Vec<&ModuleInfo> {
    let system_paths = [
        "c:\\windows\\",
        "c:\\windows\\system32\\",
        "c:\\windows\\syswow64\\",
        "c:\\program files\\",
        "c:\\program files (x86)\\",
    ];

    modules.iter()
        .filter(|m| {
            if m.path.is_empty() {
                return true; // No path is suspicious
            }
            let path_lower = m.path.to_lowercase();
            !system_paths.iter().any(|sys| path_lower.starts_with(sys))
        })
        .collect()
}

/// Check for DLL hollowing (legitimate DLL with suspicious characteristics)
pub fn detect_dll_hollowing(
    dump: &ParsedDump,
    translator: &WindowsAddressTranslator,
    module: &ModuleInfo,
) -> Option<String> {
    // Check if PE header is intact
    if let Some(header) = translator.read_virtual(dump, module.base_addr, 0x400) {
        // Check DOS header
        if header.len() < 2 || &header[0..2] != b"MZ" {
            return Some("Missing or invalid DOS header".to_string());
        }

        // Get PE header offset
        if header.len() < 0x3C + 4 {
            return Some("DOS header too small".to_string());
        }

        let pe_offset = u32::from_le_bytes([
            header[0x3C], header[0x3C + 1], header[0x3C + 2], header[0x3C + 3]
        ]) as usize;

        if pe_offset >= header.len() - 4 || &header[pe_offset..pe_offset + 4] != b"PE\x00\x00" {
            return Some("Missing or invalid PE signature".to_string());
        }

        // Could add more checks:
        // - Section characteristics
        // - Entry point location
        // - Import table validity
    }

    None
}
