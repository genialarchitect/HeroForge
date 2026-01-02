//! Linux process/task enumeration from memory
//!
//! Extract task information from Linux memory dumps.

use anyhow::Result;

use super::{LinuxAnalyzer, TaskStructOffsets};
use crate::forensics::memory_native::dump_parser::ParsedDump;
use crate::forensics::memory_native::types::LinuxTask;

/// Task enumerator for Linux memory dumps
pub struct TaskEnumerator<'a> {
    analyzer: &'a LinuxAnalyzer<'a>,
}

/// Linux task state values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Running = 0,
    Interruptible = 1,
    Uninterruptible = 2,
    Stopped = 4,
    Traced = 8,
    Dead = 16,
    Zombie = 32,
    Unknown = -1,
}

impl TaskState {
    pub fn from_i64(value: i64) -> Self {
        match value {
            0 => Self::Running,
            1 => Self::Interruptible,
            2 => Self::Uninterruptible,
            4 => Self::Stopped,
            8 => Self::Traced,
            16 | 32 => Self::Dead,
            64 => Self::Zombie,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "R (running)",
            Self::Interruptible => "S (sleeping)",
            Self::Uninterruptible => "D (disk sleep)",
            Self::Stopped => "T (stopped)",
            Self::Traced => "t (traced)",
            Self::Dead => "X (dead)",
            Self::Zombie => "Z (zombie)",
            Self::Unknown => "? (unknown)",
        }
    }
}

impl<'a> TaskEnumerator<'a> {
    /// Create new task enumerator
    pub fn new(analyzer: &'a LinuxAnalyzer<'a>) -> Self {
        Self { analyzer }
    }

    /// Enumerate all tasks from memory
    pub fn enumerate(&self) -> Result<Vec<LinuxTask>> {
        let mut tasks = Vec::new();

        let offsets = self.analyzer.offsets.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Offsets not initialized"))?;

        // Method 1: Walk from init_task
        if let Some(init_task) = self.analyzer.init_task {
            self.walk_task_list(init_task, offsets, &mut tasks)?;
        }

        // Method 2: Scan for task_struct patterns
        let scanned = self.scan_for_tasks(offsets)?;
        for task in scanned {
            if !tasks.iter().any(|t| t.task_addr == task.task_addr) {
                tasks.push(task);
            }
        }

        // Sort by PID
        tasks.sort_by_key(|t| t.pid);

        Ok(tasks)
    }

    /// Walk the task list from a starting point
    fn walk_task_list(&self, start: u64, offsets: &TaskStructOffsets, tasks: &mut Vec<LinuxTask>) -> Result<()> {
        let dump = self.analyzer.dump();
        let mut current = start;
        let mut visited = std::collections::HashSet::new();

        loop {
            if visited.contains(&current) {
                break;
            }
            visited.insert(current);

            // Parse task_struct
            if let Ok(task) = self.parse_task_struct(dump, current, offsets) {
                tasks.push(task);
            }

            // Read next task from list_head
            // tasks.next points to the next task's tasks member
            if let Some(next_bytes) = dump.read_physical(current + offsets.tasks as u64, 8) {
                let next_tasks_ptr = u64::from_le_bytes([
                    next_bytes[0], next_bytes[1], next_bytes[2], next_bytes[3],
                    next_bytes[4], next_bytes[5], next_bytes[6], next_bytes[7],
                ]);

                if next_tasks_ptr == 0 {
                    break;
                }

                // Calculate task_struct from tasks member
                current = next_tasks_ptr - offsets.tasks as u64;

                // Check if we're back at start
                if current == start {
                    break;
                }
            } else {
                break;
            }

            // Safety limit
            if visited.len() > 100000 {
                break;
            }
        }

        Ok(())
    }

    /// Parse a task_struct into LinuxTask
    fn parse_task_struct(&self, dump: &ParsedDump, addr: u64, offsets: &TaskStructOffsets) -> Result<LinuxTask> {
        // Read state
        let state = dump.read_physical(addr + offsets.state as u64, 8)
            .map(|b| i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            .unwrap_or(-1);

        // Read PID
        let pid = dump.read_physical(addr + offsets.pid as u64, 4)
            .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(-1);

        // Read TGID (thread group ID = main thread's PID)
        let tgid = dump.read_physical(addr + offsets.tgid as u64, 4)
            .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(-1);

        // Read parent pointer and get parent PID
        let ppid = dump.read_physical(addr + offsets.real_parent as u64, 8)
            .and_then(|b| {
                let parent_addr = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if parent_addr != 0 {
                    dump.read_physical(parent_addr + offsets.pid as u64, 4)
                        .map(|p| i32::from_le_bytes([p[0], p[1], p[2], p[3]]))
                } else {
                    Some(0)
                }
            })
            .unwrap_or(0);

        // Read comm (16 bytes max in Linux)
        let comm = dump.read_physical(addr + offsets.comm as u64, 16)
            .map(|b| {
                let end = b.iter().position(|&x| x == 0).unwrap_or(16);
                String::from_utf8_lossy(&b[..end]).to_string()
            })
            .unwrap_or_default();

        // Read mm pointer (memory descriptor)
        let mm = dump.read_physical(addr + offsets.mm as u64, 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            .unwrap_or(0);

        // Read credentials (UID, GID, EUID)
        let (uid, gid, euid) = if offsets.cred > 0 {
            dump.read_physical(addr + offsets.cred as u64, 8)
                .and_then(|b| {
                    let cred_addr = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                    if cred_addr != 0 {
                        self.read_credentials(dump, cred_addr)
                    } else {
                        Some((0, 0, 0))
                    }
                })
                .unwrap_or((0, 0, 0))
        } else {
            (0, 0, 0)
        };

        // Read page table base (pgd) from mm->pgd
        let pgd = if mm != 0 {
            // mm_struct->pgd is at offset ~0x50 (varies by kernel)
            dump.read_physical(mm + 0x50, 8)
                .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
                .unwrap_or(0)
        } else {
            0
        };

        // Read start_time (in nsec since boot)
        let start_time = dump.read_physical(addr + offsets.start_time as u64, 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]));

        Ok(LinuxTask {
            task_addr: addr,
            pid,
            tgid,
            ppid,
            comm,
            state: TaskState::from_i64(state).as_str().to_string(),
            uid,
            gid,
            euid,
            mm,
            pgd,
            start_time,
        })
    }

    /// Read credentials from cred structure
    fn read_credentials(&self, dump: &ParsedDump, cred_addr: u64) -> Option<(u32, u32, u32)> {
        // struct cred has uid/gid at known offsets
        // uid at +0x04, gid at +0x08, euid at +0x14 (approximately)
        let cred_data = dump.read_physical(cred_addr, 0x30)?;

        let uid = u32::from_le_bytes([cred_data[4], cred_data[5], cred_data[6], cred_data[7]]);
        let gid = u32::from_le_bytes([cred_data[8], cred_data[9], cred_data[10], cred_data[11]]);
        let euid = u32::from_le_bytes([cred_data[0x14], cred_data[0x15], cred_data[0x16], cred_data[0x17]]);

        Some((uid, gid, euid))
    }

    /// Scan memory for task_struct patterns
    fn scan_for_tasks(&self, offsets: &TaskStructOffsets) -> Result<Vec<LinuxTask>> {
        let dump = self.analyzer.dump();
        let mut tasks = Vec::new();

        // Common process names to search for
        let common_names: &[&[u8]] = &[
            b"systemd",
            b"init",
            b"kthreadd",
            b"bash",
            b"sshd",
            b"cron",
        ];

        for name in common_names {
            let matches = dump.search_pattern(name);

            for &offset in matches.iter().take(100) {
                // Potential task_struct is at offset - comm offset
                let potential_task = offset - offsets.comm as u64;

                if self.validate_task(dump, potential_task, offsets) {
                    if let Ok(task) = self.parse_task_struct(dump, potential_task, offsets) {
                        tasks.push(task);
                    }
                }
            }
        }

        Ok(tasks)
    }

    /// Validate a potential task_struct
    fn validate_task(&self, dump: &ParsedDump, addr: u64, offsets: &TaskStructOffsets) -> bool {
        // Check if we can read the structure
        let data = match dump.read_physical(addr, 0x100) {
            Some(d) => d,
            None => return false,
        };

        // Validate PID
        let pid = i32::from_le_bytes([
            data[offsets.pid], data[offsets.pid + 1],
            data[offsets.pid + 2], data[offsets.pid + 3],
        ]);

        if pid < 0 || pid > 4194304 {
            return false;
        }

        // Validate TGID
        let tgid = i32::from_le_bytes([
            data[offsets.tgid], data[offsets.tgid + 1],
            data[offsets.tgid + 2], data[offsets.tgid + 3],
        ]);

        if tgid < 0 || tgid > 4194304 {
            return false;
        }

        // For threads, tgid should match the main thread's PID
        // For main threads/processes, pid == tgid
        if tgid != pid && tgid < pid {
            // Thread group leader should have lower or equal PID
        }

        // Validate comm
        let comm = &data[offsets.comm..offsets.comm + 16];
        let has_valid_comm = comm.iter()
            .take_while(|&&b| b != 0)
            .all(|&b| b >= 0x20 && b < 0x7F);

        if !has_valid_comm || comm[0] == 0 {
            return false;
        }

        true
    }
}

/// Detect hidden processes by comparing methods
pub fn detect_hidden_tasks(
    walked_tasks: &[LinuxTask],
    scanned_tasks: &[LinuxTask],
) -> Vec<LinuxTask> {
    // Tasks found by scanning but not in walked list are potentially hidden
    let walked_pids: std::collections::HashSet<_> = walked_tasks.iter()
        .map(|t| t.pid)
        .collect();

    scanned_tasks
        .iter()
        .filter(|t| !walked_pids.contains(&t.pid))
        .cloned()
        .collect()
}

/// Find tasks running with root privileges
pub fn find_root_tasks(tasks: &[LinuxTask]) -> Vec<&LinuxTask> {
    tasks.iter()
        .filter(|t| t.uid == 0 || t.euid == 0)
        .collect()
}

/// Find kernel threads (mm == NULL)
pub fn find_kernel_threads(tasks: &[LinuxTask]) -> Vec<&LinuxTask> {
    tasks.iter()
        .filter(|t| t.mm == 0)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_state() {
        assert_eq!(TaskState::from_i64(0).as_str(), "R (running)");
        assert_eq!(TaskState::from_i64(1).as_str(), "S (sleeping)");
        assert_eq!(TaskState::from_i64(2).as_str(), "D (disk sleep)");
    }
}
