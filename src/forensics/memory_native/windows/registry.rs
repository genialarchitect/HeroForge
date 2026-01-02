//! Windows registry extraction from memory
//!
//! Extract registry hives and keys from Windows memory dumps.

use anyhow::Result;

use super::WindowsAnalyzer;
use crate::forensics::memory_native::dump_parser::ParsedDump;
use crate::forensics::memory_native::types::{RegistryKey, RegistryValue};

/// Registry extractor for Windows memory
pub struct RegistryExtractor<'a> {
    analyzer: &'a WindowsAnalyzer<'a>,
}

/// Registry hive information
#[derive(Debug, Clone)]
pub struct RegistryHive {
    /// Hive path (e.g., "\Registry\Machine\SYSTEM")
    pub path: String,
    /// Physical address of CMHIVE structure
    pub cmhive_addr: u64,
    /// HBase block address
    pub hbase_addr: u64,
    /// Hive signature validated
    pub valid: bool,
}

impl<'a> RegistryExtractor<'a> {
    /// Create new registry extractor
    pub fn new(analyzer: &'a WindowsAnalyzer<'a>) -> Self {
        Self { analyzer }
    }

    /// Find all registry hives in memory
    pub fn find_hives(&self) -> Result<Vec<RegistryHive>> {
        let dump = self.analyzer.dump();
        let mut hives = Vec::new();

        // Search for registry hive signature "regf"
        let regf_matches = dump.search_pattern(b"regf");

        for &offset in regf_matches.iter().take(100) {
            if let Some(hive) = self.validate_hive(dump, offset) {
                hives.push(hive);
            }
        }

        // Also search for CMHIVE structures
        // CMHIVE contains pointer to the hive base block

        Ok(hives)
    }

    /// Validate a potential registry hive
    fn validate_hive(&self, dump: &ParsedDump, offset: u64) -> Option<RegistryHive> {
        // Registry hive base block (HBASE_BLOCK) structure:
        // +0x00: Signature ("regf")
        // +0x04: Sequence1
        // +0x08: Sequence2
        // +0x0C: TimeStamp
        // +0x14: Major (should be 1)
        // +0x18: Minor (3, 4, 5, or 6)
        // +0x1C: Type (0 = Primary, 1 = Log)
        // +0x20: Format (1)
        // +0x24: RootCell

        let header = dump.read_bytes(offset, 0x100)?;

        // Check signature
        if &header[0..4] != b"regf" {
            return None;
        }

        // Check version
        let major = u32::from_le_bytes([header[0x14], header[0x15], header[0x16], header[0x17]]);
        let minor = u32::from_le_bytes([header[0x18], header[0x19], header[0x1A], header[0x1B]]);

        if major != 1 || minor > 6 {
            return None;
        }

        // Check type (should be primary = 0)
        let hive_type = u32::from_le_bytes([header[0x1C], header[0x1D], header[0x1E], header[0x1F]]);
        if hive_type > 1 {
            return None;
        }

        // Try to determine hive name from path in memory
        // This requires additional context from CMHIVE structure
        let path = self.determine_hive_path(dump, offset)
            .unwrap_or_else(|| format!("Unknown@{:#x}", offset));

        Some(RegistryHive {
            path,
            cmhive_addr: 0, // Would need to find CMHIVE
            hbase_addr: offset,
            valid: true,
        })
    }

    /// Try to determine hive path from context
    fn determine_hive_path(&self, dump: &ParsedDump, hive_addr: u64) -> Option<String> {
        // Common hive file signatures that might appear nearby
        let common_paths = [
            ("SYSTEM", "\\SystemRoot\\System32\\config\\SYSTEM"),
            ("SOFTWARE", "\\SystemRoot\\System32\\config\\SOFTWARE"),
            ("SAM", "\\SystemRoot\\System32\\config\\SAM"),
            ("SECURITY", "\\SystemRoot\\System32\\config\\SECURITY"),
            ("DEFAULT", "\\SystemRoot\\System32\\config\\DEFAULT"),
            ("NTUSER.DAT", "\\??\\"),
        ];

        // Search nearby for path strings
        if let Some(context) = dump.read_bytes(hive_addr.saturating_sub(0x1000), 0x2000) {
            for (name, _) in &common_paths {
                if let Some(_pos) = context.windows(name.len())
                    .position(|w| w == name.as_bytes())
                {
                    return Some(name.to_string());
                }
            }
        }

        None
    }

    /// Enumerate keys from a specific hive
    pub fn enumerate_keys(&self, hive: &RegistryHive, prefix: &str, max_depth: usize) -> Result<Vec<RegistryKey>> {
        let dump = self.analyzer.dump();
        let mut keys = Vec::new();

        // Read root cell offset from hive header
        let header = dump.read_bytes(hive.hbase_addr, 0x30)
            .ok_or_else(|| anyhow::anyhow!("Failed to read hive header"))?;

        let root_cell_offset = u32::from_le_bytes([
            header[0x24], header[0x25], header[0x26], header[0x27]
        ]);

        // Cells are relative to hive base + 0x1000 (bins start at 0x1000)
        let root_cell_addr = hive.hbase_addr + 0x1000 + root_cell_offset as u64;

        // Recursively enumerate keys
        self.enumerate_key_recursive(dump, hive.hbase_addr, root_cell_addr, prefix, 0, max_depth, &mut keys)?;

        Ok(keys)
    }

    /// Recursively enumerate registry keys
    fn enumerate_key_recursive(
        &self,
        dump: &ParsedDump,
        hive_base: u64,
        cell_addr: u64,
        path: &str,
        depth: usize,
        max_depth: usize,
        keys: &mut Vec<RegistryKey>,
    ) -> Result<()> {
        if depth >= max_depth {
            return Ok(());
        }

        // Read cell header (4 bytes: size, negative = allocated)
        let cell_header = dump.read_bytes(cell_addr, 4)
            .ok_or_else(|| anyhow::anyhow!("Failed to read cell header"))?;

        let cell_size = i32::from_le_bytes([
            cell_header[0], cell_header[1], cell_header[2], cell_header[3]
        ]);

        // Allocated cells have negative size
        if cell_size >= 0 {
            return Ok(()); // Free cell
        }

        let _cell_size = (-cell_size) as usize;

        // Read key node structure (CM_KEY_NODE)
        // +0x00: Cell size
        // +0x04: Signature ("nk" for key node)
        // +0x06: Flags
        // +0x08: LastWriteTime
        // +0x10: AccessBits
        // +0x14: Parent
        // +0x18: SubKeyCount
        // +0x1C: VolatileSubKeyCount
        // +0x20: SubKeyList
        // +0x24: VolatileSubKeyList
        // +0x28: ValueCount
        // +0x2C: ValueList
        // +0x30: SecurityCell
        // +0x34: ClassCell
        // +0x38: MaxNameLen
        // +0x3C: MaxClassLen
        // +0x40: MaxValueNameLen
        // +0x44: MaxValueDataLen
        // +0x48: WorkVar
        // +0x4C: NameLength
        // +0x4E: ClassLength
        // +0x50: Name (variable length)

        let key_node = dump.read_bytes(cell_addr + 4, 0x60)
            .ok_or_else(|| anyhow::anyhow!("Failed to read key node"))?;

        // Check signature
        if &key_node[0..2] != b"nk" {
            return Ok(()); // Not a key node
        }

        // Read name length and name
        let name_len = u16::from_le_bytes([key_node[0x4C], key_node[0x4D]]) as usize;
        let name = if name_len > 0 && name_len < 256 {
            if let Some(name_bytes) = dump.read_bytes(cell_addr + 4 + 0x50, name_len) {
                String::from_utf8_lossy(name_bytes).to_string()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let full_path = if path.is_empty() {
            name.clone()
        } else {
            format!("{}\\{}", path, name)
        };

        // Read metadata
        let subkey_count = u32::from_le_bytes([
            key_node[0x18], key_node[0x19], key_node[0x1A], key_node[0x1B]
        ]);

        let value_count = u32::from_le_bytes([
            key_node[0x28], key_node[0x29], key_node[0x2A], key_node[0x2B]
        ]);

        // Read last write time
        let last_write_filetime = u64::from_le_bytes([
            key_node[0x08], key_node[0x09], key_node[0x0A], key_node[0x0B],
            key_node[0x0C], key_node[0x0D], key_node[0x0E], key_node[0x0F],
        ]);

        let last_write_time = filetime_to_datetime(last_write_filetime);

        keys.push(RegistryKey {
            path: full_path.clone(),
            last_write_time,
            subkey_count,
            value_count,
        });

        // Enumerate subkeys if present
        if subkey_count > 0 {
            let subkey_list_offset = u32::from_le_bytes([
                key_node[0x20], key_node[0x21], key_node[0x22], key_node[0x23]
            ]);

            if subkey_list_offset != 0xFFFFFFFF {
                let subkey_list_addr = hive_base + 0x1000 + subkey_list_offset as u64;
                self.enumerate_subkeys(dump, hive_base, subkey_list_addr, &full_path, depth + 1, max_depth, keys)?;
            }
        }

        Ok(())
    }

    /// Enumerate subkeys from a subkey list
    fn enumerate_subkeys(
        &self,
        dump: &ParsedDump,
        hive_base: u64,
        list_addr: u64,
        parent_path: &str,
        depth: usize,
        max_depth: usize,
        keys: &mut Vec<RegistryKey>,
    ) -> Result<()> {
        // Read list header
        let header = dump.read_bytes(list_addr + 4, 8)
            .ok_or_else(|| anyhow::anyhow!("Failed to read subkey list"))?;

        let sig = &header[0..2];
        let count = u16::from_le_bytes([header[2], header[3]]) as usize;

        // Different list types: lf, lh, li, ri
        match sig {
            b"lf" | b"lh" => {
                // Fast leaf / Hash leaf
                // Each entry is 8 bytes: offset (4) + hash/name (4)
                for i in 0..count.min(1000) {
                    if let Some(entry) = dump.read_bytes(list_addr + 4 + 4 + (i * 8) as u64, 8) {
                        let offset = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
                        if offset != 0xFFFFFFFF {
                            let child_addr = hive_base + 0x1000 + offset as u64;
                            let _ = self.enumerate_key_recursive(dump, hive_base, child_addr, parent_path, depth, max_depth, keys);
                        }
                    }
                }
            }
            b"li" => {
                // Index leaf - just offsets
                for i in 0..count.min(1000) {
                    if let Some(entry) = dump.read_bytes(list_addr + 4 + 4 + (i * 4) as u64, 4) {
                        let offset = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
                        if offset != 0xFFFFFFFF {
                            let child_addr = hive_base + 0x1000 + offset as u64;
                            let _ = self.enumerate_key_recursive(dump, hive_base, child_addr, parent_path, depth, max_depth, keys);
                        }
                    }
                }
            }
            b"ri" => {
                // Index root - points to other lists
                for i in 0..count.min(100) {
                    if let Some(entry) = dump.read_bytes(list_addr + 4 + 4 + (i * 4) as u64, 4) {
                        let offset = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
                        if offset != 0xFFFFFFFF {
                            let child_list_addr = hive_base + 0x1000 + offset as u64;
                            let _ = self.enumerate_subkeys(dump, hive_base, child_list_addr, parent_path, depth, max_depth, keys);
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Read values for a specific key
    pub fn read_key_values(&self, hive: &RegistryHive, key: &RegistryKey) -> Result<Vec<RegistryValue>> {
        // Would need to:
        // 1. Find the key node by path
        // 2. Read the value list offset
        // 3. Parse each value node (CM_KEY_VALUE)
        // 4. Extract value name, type, and data

        let _ = (hive, key); // Suppress unused warnings

        Ok(Vec::new())
    }
}

/// Convert Windows FILETIME to DateTime
fn filetime_to_datetime(filetime: u64) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{TimeZone, Utc};

    if filetime == 0 {
        return None;
    }

    const FILETIME_UNIX_DIFF: u64 = 116444736000000000;

    if filetime < FILETIME_UNIX_DIFF {
        return None;
    }

    let unix_100ns = filetime - FILETIME_UNIX_DIFF;
    let unix_secs = (unix_100ns / 10_000_000) as i64;
    let unix_nanos = ((unix_100ns % 10_000_000) * 100) as u32;

    Utc.timestamp_opt(unix_secs, unix_nanos).single()
}

/// Find interesting registry keys for forensic analysis
pub fn find_forensic_keys(keys: &[RegistryKey]) -> Vec<&RegistryKey> {
    let interesting_paths = [
        // Persistence
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        // Services
        "SYSTEM\\CurrentControlSet\\Services",
        // Shellbags/Explorer
        "SOFTWARE\\Microsoft\\Windows\\Shell\\BagMRU",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        // USB History
        "SYSTEM\\CurrentControlSet\\Enum\\USB",
        "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
        // Network
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList",
        // User accounts
        "SAM\\Domains\\Account\\Users",
        // Security
        "SECURITY\\Policy\\Secrets",
    ];

    keys.iter()
        .filter(|k| {
            let path_upper = k.path.to_uppercase();
            interesting_paths.iter()
                .any(|p| path_upper.contains(&p.to_uppercase()))
        })
        .collect()
}
