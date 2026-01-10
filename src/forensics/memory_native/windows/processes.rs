//! Windows process enumeration from memory
//!
//! Extract process information from Windows memory dumps.

use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};

use super::{EprocessOffsets, WindowsAnalyzer};
use crate::forensics::memory_native::dump_parser::WindowsAddressTranslator;
use crate::forensics::memory_native::types::ProcessInfo;

/// Process enumerator for Windows memory dumps
pub struct ProcessEnumerator<'a> {
    analyzer: &'a WindowsAnalyzer<'a>,
}

impl<'a> ProcessEnumerator<'a> {
    /// Create new process enumerator
    pub fn new(analyzer: &'a WindowsAnalyzer<'a>) -> Self {
        Self { analyzer }
    }

    /// Enumerate all processes from memory
    pub fn enumerate(&self) -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();

        // Get offsets
        let offsets = self.analyzer.offsets.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Offsets not initialized"))?;

        // Find processes by scanning for EPROCESS structures
        let found_eprocess = self.scan_for_eprocess(offsets)?;

        for eprocess_addr in found_eprocess {
            if let Ok(proc) = self.parse_eprocess(eprocess_addr, offsets) {
                processes.push(proc);
            }
        }

        // Sort by PID
        processes.sort_by_key(|p| p.pid);

        Ok(processes)
    }

    /// Scan memory for EPROCESS structures
    fn scan_for_eprocess(&self, offsets: &EprocessOffsets) -> Result<Vec<u64>> {
        let dump = self.analyzer.dump();
        let mut found = Vec::new();

        // Strategy: Look for characteristic EPROCESS patterns
        // - Valid pool tag: "Proc" for process objects
        // - Valid DTB (DirectoryTableBase) - should be page-aligned and in valid range
        // - Valid pointers in ActiveProcessLinks

        // Search for "Proc" pool tag (appears before EPROCESS in pool allocation)
        // The tag is 4 bytes before the object header
        let proc_tag = b"Proc";
        let matches = dump.search_pattern(proc_tag);

        for offset in matches.iter().take(10000) {
            // EPROCESS starts after pool header (typically 0x30 bytes for 64-bit)
            // This varies by Windows version
            let header_sizes = [0x30u64, 0x40, 0x20, 0x38];

            for header_size in header_sizes {
                let potential_eprocess = offset + 4 + header_size;

                if self.validate_eprocess(potential_eprocess, offsets) {
                    found.push(potential_eprocess);
                    break;
                }
            }
        }

        // Also try to walk the ActiveProcessLinks list if we have a starting point
        if let Some(head) = self.analyzer.ps_active_process_head {
            self.walk_process_list(head, offsets, &mut found)?;
        }

        // Deduplicate
        found.sort();
        found.dedup();

        Ok(found)
    }

    /// Validate a potential EPROCESS address
    fn validate_eprocess(&self, addr: u64, offsets: &EprocessOffsets) -> bool {
        let dump = self.analyzer.dump();

        // Check if we can read at the address
        if dump.read_physical(addr, 0x10).is_none() {
            return false;
        }

        // Check DTB - should be page-aligned
        if let Some(dtb_bytes) = dump.read_physical(addr + offsets.directory_table_base as u64, 8) {
            let dtb = u64::from_le_bytes([
                dtb_bytes[0], dtb_bytes[1], dtb_bytes[2], dtb_bytes[3],
                dtb_bytes[4], dtb_bytes[5], dtb_bytes[6], dtb_bytes[7],
            ]);

            // DTB should be page-aligned (lower 12 bits mostly zero for large pages)
            // and within reasonable physical memory range
            if dtb == 0 || dtb & 0xFFF != 0 {
                // Allow some DTBs with flags in lower bits
                if dtb & 0xFF0 != 0 {
                    return false;
                }
            }

            // DTB should be less than ~1TB for most systems
            if dtb > 0x0000_FFFF_FFFF_F000 {
                return false;
            }
        } else {
            return false;
        }

        // Check PID - should be reasonable
        if let Some(pid_bytes) = dump.read_physical(addr + offsets.unique_process_id as u64, 8) {
            let pid = u64::from_le_bytes([
                pid_bytes[0], pid_bytes[1], pid_bytes[2], pid_bytes[3],
                pid_bytes[4], pid_bytes[5], pid_bytes[6], pid_bytes[7],
            ]);

            // PID should be reasonable (typically < 100000)
            // and usually a multiple of 4 on Windows
            if pid > 100000 || (pid > 4 && pid % 4 != 0) {
                return false;
            }
        } else {
            return false;
        }

        // Check ImageFileName - should contain printable ASCII
        if let Some(name_bytes) = dump.read_physical(addr + offsets.image_file_name as u64, 15) {
            let valid_chars = name_bytes.iter()
                .take_while(|&&b| b != 0)
                .all(|&b| b >= 0x20 && b < 0x7F);

            if !valid_chars {
                return false;
            }
        } else {
            return false;
        }

        true
    }

    /// Walk the ActiveProcessLinks doubly-linked list
    fn walk_process_list(&self, head: u64, offsets: &EprocessOffsets, found: &mut Vec<u64>) -> Result<()> {
        let dump = self.analyzer.dump();
        let mut current = head;
        let mut visited = std::collections::HashSet::new();

        loop {
            // Prevent infinite loops
            if visited.contains(&current) {
                break;
            }
            visited.insert(current);

            // Read the Flink
            if let Some(flink_bytes) = dump.read_physical(current, 8) {
                let flink = u64::from_le_bytes([
                    flink_bytes[0], flink_bytes[1], flink_bytes[2], flink_bytes[3],
                    flink_bytes[4], flink_bytes[5], flink_bytes[6], flink_bytes[7],
                ]);

                if flink == 0 || flink == head {
                    break;
                }

                // Calculate EPROCESS from link offset
                let eprocess_addr = flink - offsets.active_process_links as u64;

                if self.validate_eprocess(eprocess_addr, offsets) {
                    found.push(eprocess_addr);
                }

                current = flink;
            } else {
                break;
            }

            // Safety limit
            if visited.len() > 10000 {
                break;
            }
        }

        Ok(())
    }

    /// Parse an EPROCESS structure into ProcessInfo
    fn parse_eprocess(&self, addr: u64, offsets: &EprocessOffsets) -> Result<ProcessInfo> {
        let dump = self.analyzer.dump();

        // Read PID
        let pid = dump.read_physical(addr + offsets.unique_process_id as u64, 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(0);

        // Read PPID
        let ppid = dump.read_physical(addr + offsets.inherited_from_pid as u64, 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(0);

        // Read ImageFileName (15 chars max in EPROCESS)
        let name = dump.read_physical(addr + offsets.image_file_name as u64, 15)
            .map(|b| {
                let end = b.iter().position(|&x| x == 0).unwrap_or(15);
                String::from_utf8_lossy(&b[..end]).to_string()
            })
            .unwrap_or_default();

        // Read DirectoryTableBase
        let dtb = dump.read_physical(addr + offsets.directory_table_base as u64, 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            .unwrap_or(0);

        // Read PEB address
        let peb = dump.read_physical(addr + offsets.peb as u64, 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            .unwrap_or(0);

        // Read CreateTime (Windows FILETIME)
        let create_time = dump.read_physical(addr + offsets.create_time as u64, 8)
            .and_then(|b| {
                let filetime = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                filetime_to_datetime(filetime)
            });

        // Read ExitTime
        let exit_time = dump.read_physical(addr + offsets.exit_time as u64, 8)
            .and_then(|b| {
                let filetime = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if filetime > 0 {
                    filetime_to_datetime(filetime)
                } else {
                    None
                }
            });

        // Check if WoW64
        let is_wow64 = if offsets.wow64_process > 0 {
            dump.read_physical(addr + offsets.wow64_process as u64, 8)
                .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
                .unwrap_or(0) != 0
        } else {
            false
        };

        // Read SessionId
        let session_id = dump.read_physical(addr + offsets.session_id as u64, 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));

        // Try to read command line from PEB
        let cmdline = if peb != 0 && dtb != 0 {
            self.read_command_line(peb, dtb).ok()
        } else {
            None
        };

        // Try to read full path from PEB
        let path = if peb != 0 && dtb != 0 {
            self.read_image_path(peb, dtb).ok()
        } else {
            None
        };

        Ok(ProcessInfo {
            eprocess_addr: addr,
            pid,
            ppid,
            name,
            path,
            cmdline,
            create_time,
            exit_time,
            dtb,
            peb,
            session_id,
            is_wow64,
            thread_count: 0,  // Would need to walk thread list
            handle_count: 0,  // Would need to parse object table
            exit_status: None,
            integrity: None,
            token_user: None,
        })
    }

    /// Read command line from process PEB
    fn read_command_line(&self, peb: u64, dtb: u64) -> Result<String> {
        let dump = self.analyzer.dump();
        let translator = WindowsAddressTranslator::new(dtb, true);

        // PEB structure:
        // +0x20: ProcessParameters (RTL_USER_PROCESS_PARAMETERS*)
        let params_ptr = translator.read_virtual(dump, peb + 0x20, 8)
            .and_then(|b| Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])))
            .ok_or_else(|| anyhow::anyhow!("Failed to read ProcessParameters"))?;

        if params_ptr == 0 {
            return Err(anyhow::anyhow!("Null ProcessParameters"));
        }

        // RTL_USER_PROCESS_PARAMETERS:
        // +0x70: CommandLine (UNICODE_STRING)
        // UNICODE_STRING: Length (2), MaxLength (2), padding (4), Buffer (8)
        let cmdline_len = translator.read_virtual(dump, params_ptr + 0x70, 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .unwrap_or(0) as usize;

        let cmdline_buf = translator.read_virtual(dump, params_ptr + 0x78, 8)
            .and_then(|b| Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])))
            .ok_or_else(|| anyhow::anyhow!("Failed to read CommandLine buffer"))?;

        if cmdline_buf == 0 || cmdline_len == 0 || cmdline_len > 32768 {
            return Err(anyhow::anyhow!("Invalid command line"));
        }

        // Read the actual command line (UTF-16LE)
        let cmdline_bytes = translator.read_virtual(dump, cmdline_buf, cmdline_len)
            .ok_or_else(|| anyhow::anyhow!("Failed to read command line data"))?;

        // Convert UTF-16LE to String
        let utf16: Vec<u16> = cmdline_bytes.chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        Ok(String::from_utf16_lossy(&utf16))
    }

    /// Read image path from process PEB
    fn read_image_path(&self, peb: u64, dtb: u64) -> Result<String> {
        let dump = self.analyzer.dump();
        let translator = WindowsAddressTranslator::new(dtb, true);

        // PEB.ProcessParameters->ImagePathName
        let params_ptr = translator.read_virtual(dump, peb + 0x20, 8)
            .and_then(|b| Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])))
            .ok_or_else(|| anyhow::anyhow!("Failed to read ProcessParameters"))?;

        if params_ptr == 0 {
            return Err(anyhow::anyhow!("Null ProcessParameters"));
        }

        // RTL_USER_PROCESS_PARAMETERS:
        // +0x60: ImagePathName (UNICODE_STRING)
        let path_len = translator.read_virtual(dump, params_ptr + 0x60, 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .unwrap_or(0) as usize;

        let path_buf = translator.read_virtual(dump, params_ptr + 0x68, 8)
            .and_then(|b| Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])))
            .ok_or_else(|| anyhow::anyhow!("Failed to read ImagePathName buffer"))?;

        if path_buf == 0 || path_len == 0 || path_len > 32768 {
            return Err(anyhow::anyhow!("Invalid image path"));
        }

        let path_bytes = translator.read_virtual(dump, path_buf, path_len)
            .ok_or_else(|| anyhow::anyhow!("Failed to read path data"))?;

        let utf16: Vec<u16> = path_bytes.chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        Ok(String::from_utf16_lossy(&utf16))
    }
}

/// Convert Windows FILETIME to DateTime
fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    // FILETIME is 100-nanosecond intervals since January 1, 1601
    // Unix epoch is January 1, 1970
    // Difference: 11644473600 seconds

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

/// Detect hidden processes by comparing methods
pub fn detect_hidden_processes(
    linked_processes: &[ProcessInfo],
    scanned_processes: &[ProcessInfo],
) -> Vec<ProcessInfo> {
    // Processes found by scanning but not in linked list are potentially hidden
    let linked_pids: std::collections::HashSet<_> = linked_processes.iter()
        .map(|p| p.pid)
        .collect();

    scanned_processes
        .iter()
        .filter(|p| !linked_pids.contains(&p.pid))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime_conversion() {
        // Known timestamp: 2020-01-01 00:00:00 UTC
        // FILETIME value: 132224352000000000
        let filetime = 132224352000000000u64;
        let dt = filetime_to_datetime(filetime).unwrap();
        assert_eq!(dt.year(), 2020);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 1);
    }

    #[test]
    fn test_zero_filetime() {
        assert!(filetime_to_datetime(0).is_none());
    }
}

