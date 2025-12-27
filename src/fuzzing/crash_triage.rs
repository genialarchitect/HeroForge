//! Crash Triage
//!
//! Analyze crashes to determine type, uniqueness, and exploitability.

use std::process::Output;
use chrono::Utc;
use sha2::{Sha256, Digest};

use crate::fuzzing::types::{
    CrashType, Exploitability, FuzzingCrash, RegisterState,
};

/// Crash triager for analyzing fuzzing crashes
pub struct CrashTriager {
    /// Known crash signatures for deduplication
    known_signatures: std::sync::RwLock<std::collections::HashSet<String>>,
}

impl CrashTriager {
    /// Create a new crash triager
    pub fn new() -> Self {
        Self {
            known_signatures: std::sync::RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Analyze process output for crash indicators
    pub fn analyze_output(&self, output: &Output, input: &[u8]) -> Option<FuzzingCrash> {
        // Check exit code
        let exit_code = output.status.code();

        // Check for crash signals on Unix
        #[cfg(unix)]
        let signal = {
            use std::os::unix::process::ExitStatusExt;
            output.status.signal()
        };
        #[cfg(not(unix))]
        let signal: Option<i32> = None;

        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

        // Determine if this is a crash
        let crash_type = self.determine_crash_type(exit_code, signal, &stderr, &stdout);

        if crash_type == CrashType::Unknown && output.status.success() {
            return None; // Not a crash
        }

        // Calculate crash hash for deduplication
        let crash_hash = self.calculate_crash_hash(&stderr, signal, exit_code);

        // Assess exploitability
        let exploitability = self.assess_exploitability(&crash_type, &stderr, signal);

        // Parse stack trace if available
        let stack_trace = self.extract_stack_trace(&stderr);

        // Parse register state if available
        let registers = self.extract_registers(&stderr);

        Some(FuzzingCrash {
            id: uuid::Uuid::new_v4().to_string(),
            campaign_id: String::new(), // Will be set by caller
            crash_type,
            crash_hash,
            exploitability,
            input_data: input.to_vec(),
            input_size: input.len(),
            stack_trace,
            registers,
            signal,
            exit_code,
            stderr_output: if stderr.is_empty() { None } else { Some(stderr) },
            reproduced: false,
            reproduction_count: 1,
            minimized_input: None,
            notes: None,
            created_at: Utc::now(),
        })
    }

    /// Determine crash type from exit status and output
    fn determine_crash_type(
        &self,
        exit_code: Option<i32>,
        signal: Option<i32>,
        stderr: &str,
        stdout: &str,
    ) -> CrashType {
        // Check signal first
        if let Some(sig) = signal {
            match sig {
                11 => return CrashType::Segfault,       // SIGSEGV
                6 => return CrashType::AssertionFailure, // SIGABRT
                8 => return CrashType::IntegerOverflow,  // SIGFPE
                4 => return CrashType::Unknown,          // SIGILL
                7 => return CrashType::Unknown,          // SIGBUS
                _ => {}
            }
        }

        let combined = format!("{}\n{}", stderr, stdout).to_lowercase();

        // Check for common crash indicators in output
        if combined.contains("heap-buffer-overflow") || combined.contains("heap overflow") {
            return CrashType::HeapOverflow;
        }
        if combined.contains("stack-buffer-overflow") || combined.contains("stack overflow") {
            return CrashType::StackOverflow;
        }
        if combined.contains("use-after-free") || combined.contains("heap-use-after-free") {
            return CrashType::UseAfterFree;
        }
        if combined.contains("double-free") || combined.contains("double free") {
            return CrashType::DoubleFree;
        }
        if combined.contains("null pointer") || combined.contains("nullptr") || combined.contains("null dereference") {
            return CrashType::NullPointerDeref;
        }
        if combined.contains("integer overflow") || combined.contains("integer-overflow") {
            return CrashType::IntegerOverflow;
        }
        if combined.contains("format string") {
            return CrashType::FormatString;
        }
        if combined.contains("buffer-overread") || combined.contains("out-of-bounds-read") {
            return CrashType::BufferOverread;
        }
        if combined.contains("assertion") || combined.contains("assert failed") {
            return CrashType::AssertionFailure;
        }
        if combined.contains("memory leak") {
            return CrashType::MemoryLeak;
        }
        if combined.contains("segmentation fault") || combined.contains("sigsegv") {
            return CrashType::Segfault;
        }

        // Check exit code for abnormal termination
        if let Some(code) = exit_code {
            if code != 0 {
                // Non-zero but not a known signal
                // Might still be a crash
                if code > 128 {
                    // Usually exit_code = 128 + signal_number
                    let implied_signal = code - 128;
                    match implied_signal {
                        11 => return CrashType::Segfault,
                        6 => return CrashType::AssertionFailure,
                        _ => {}
                    }
                }
            }
        }

        CrashType::Unknown
    }

    /// Calculate a hash for crash deduplication
    fn calculate_crash_hash(
        &self,
        stderr: &str,
        signal: Option<i32>,
        exit_code: Option<i32>,
    ) -> String {
        let mut hasher = Sha256::new();

        // Include signal
        if let Some(sig) = signal {
            hasher.update(sig.to_le_bytes());
        }

        // Include exit code
        if let Some(code) = exit_code {
            hasher.update(code.to_le_bytes());
        }

        // Try to extract and hash stack trace frames
        let stack_frames = self.extract_stack_frames(stderr);
        for frame in stack_frames.iter().take(5) {
            hasher.update(frame.as_bytes());
        }

        // If no stack frames, hash the first few lines of stderr
        if stack_frames.is_empty() {
            let lines: Vec<&str> = stderr.lines().take(5).collect();
            for line in lines {
                hasher.update(line.as_bytes());
            }
        }

        format!("{:x}", hasher.finalize())
    }

    /// Extract stack trace frames from stderr
    fn extract_stack_frames(&self, stderr: &str) -> Vec<String> {
        let mut frames = Vec::new();

        for line in stderr.lines() {
            let line_lower = line.to_lowercase();

            // Common stack frame patterns
            if line.contains(" at ") && (line.contains(".c:") || line.contains(".cpp:") || line.contains(".rs:")) {
                frames.push(line.trim().to_string());
            } else if line_lower.starts_with("#") && line.contains(" in ") {
                frames.push(line.trim().to_string());
            } else if line.contains("0x") && (line.contains(" in ") || line.contains("<")) {
                frames.push(line.trim().to_string());
            }
        }

        frames
    }

    /// Extract full stack trace from stderr
    fn extract_stack_trace(&self, stderr: &str) -> Option<String> {
        let frames = self.extract_stack_frames(stderr);
        if frames.is_empty() {
            None
        } else {
            Some(frames.join("\n"))
        }
    }

    /// Extract register state from crash output
    fn extract_registers(&self, stderr: &str) -> Option<RegisterState> {
        let mut regs = RegisterState {
            rax: None, rbx: None, rcx: None, rdx: None,
            rsi: None, rdi: None, rbp: None, rsp: None,
            rip: None, r8: None, r9: None, r10: None,
            r11: None, r12: None, r13: None, r14: None,
            r15: None, eflags: None,
        };

        let mut found_any = false;

        for line in stderr.lines() {
            let line_upper = line.to_uppercase();

            // Parse common register dump formats
            let register_names = [
                "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP",
                "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
            ];

            for reg_name in register_names {
                if let Some(pos) = line_upper.find(reg_name) {
                    // Look for hex value after register name
                    let after = &line[pos + reg_name.len()..];
                    if let Some(hex_start) = after.find("0x") {
                        let hex_str = &after[hex_start + 2..];
                        let hex_end = hex_str.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(hex_str.len());
                        if let Ok(val) = u64::from_str_radix(&hex_str[..hex_end], 16) {
                            match reg_name {
                                "RAX" => regs.rax = Some(val),
                                "RBX" => regs.rbx = Some(val),
                                "RCX" => regs.rcx = Some(val),
                                "RDX" => regs.rdx = Some(val),
                                "RSI" => regs.rsi = Some(val),
                                "RDI" => regs.rdi = Some(val),
                                "RBP" => regs.rbp = Some(val),
                                "RSP" => regs.rsp = Some(val),
                                "RIP" => regs.rip = Some(val),
                                "R8" => regs.r8 = Some(val),
                                "R9" => regs.r9 = Some(val),
                                "R10" => regs.r10 = Some(val),
                                "R11" => regs.r11 = Some(val),
                                "R12" => regs.r12 = Some(val),
                                "R13" => regs.r13 = Some(val),
                                "R14" => regs.r14 = Some(val),
                                "R15" => regs.r15 = Some(val),
                                _ => {}
                            }
                            found_any = true;
                        }
                    }
                }
            }
        }

        if found_any {
            Some(regs)
        } else {
            None
        }
    }

    /// Assess exploitability of a crash
    fn assess_exploitability(
        &self,
        crash_type: &CrashType,
        stderr: &str,
        signal: Option<i32>,
    ) -> Exploitability {
        match crash_type {
            CrashType::HeapOverflow => Exploitability::ProbablyExploitable,
            CrashType::StackOverflow => Exploitability::ProbablyExploitable,
            CrashType::UseAfterFree => Exploitability::Exploitable,
            CrashType::DoubleFree => Exploitability::Exploitable,
            CrashType::FormatString => Exploitability::Exploitable,
            CrashType::IntegerOverflow => Exploitability::ProbablyExploitable,
            CrashType::NullPointerDeref => Exploitability::ProbablyNotExploitable,
            CrashType::BufferOverread => Exploitability::ProbablyNotExploitable,
            CrashType::AssertionFailure => Exploitability::NotExploitable,
            CrashType::Timeout | CrashType::Hang => Exploitability::NotExploitable,
            CrashType::MemoryLeak => Exploitability::NotExploitable,
            CrashType::Segfault => {
                // SIGSEGV can be exploitable depending on context
                let stderr_lower = stderr.to_lowercase();
                if stderr_lower.contains("write") || stderr_lower.contains("store") {
                    Exploitability::ProbablyExploitable
                } else if stderr_lower.contains("read") || stderr_lower.contains("load") {
                    Exploitability::ProbablyNotExploitable
                } else {
                    Exploitability::Unknown
                }
            }
            CrashType::Unknown => Exploitability::Unknown,
        }
    }

    /// Check if a crash is unique (not seen before)
    pub fn is_unique(&self, crash_hash: &str) -> bool {
        let known = self.known_signatures.read().unwrap();
        !known.contains(crash_hash)
    }

    /// Mark a crash hash as seen
    pub fn mark_seen(&self, crash_hash: &str) {
        let mut known = self.known_signatures.write().unwrap();
        known.insert(crash_hash.to_string());
    }

    /// Minimize a crashing input by removing bytes
    pub async fn minimize(&self, input: &[u8], is_crash: impl Fn(&[u8]) -> bool) -> Vec<u8> {
        let mut minimized = input.to_vec();

        // Binary reduction
        let mut step = minimized.len() / 2;
        while step > 0 {
            let mut i = 0;
            while i + step <= minimized.len() {
                let mut candidate = minimized[..i].to_vec();
                candidate.extend_from_slice(&minimized[i + step..]);

                if is_crash(&candidate) {
                    minimized = candidate;
                } else {
                    i += 1;
                }
            }
            step /= 2;
        }

        // Byte-by-byte reduction
        let mut i = 0;
        while i < minimized.len() {
            let mut candidate = minimized[..i].to_vec();
            candidate.extend_from_slice(&minimized[i + 1..]);

            if is_crash(&candidate) {
                minimized = candidate;
            } else {
                i += 1;
            }
        }

        minimized
    }

    /// Try to reproduce a crash
    pub async fn reproduce(
        &self,
        input: &[u8],
        executor: impl Fn(&[u8]) -> std::io::Result<Output>,
        attempts: u32,
    ) -> (bool, u32) {
        let mut successful = 0;

        for _ in 0..attempts {
            if let Ok(output) = executor(input) {
                if self.analyze_output(&output, input).is_some() {
                    successful += 1;
                }
            }
        }

        (successful > 0, successful)
    }
}

impl Default for CrashTriager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn test_determine_crash_type_from_stderr() {
        let triager = CrashTriager::new();

        // Heap overflow
        let crash_type = triager.determine_crash_type(
            Some(1),
            None,
            "ERROR: AddressSanitizer: heap-buffer-overflow on address",
            "",
        );
        assert_eq!(crash_type, CrashType::HeapOverflow);

        // Use after free
        let crash_type = triager.determine_crash_type(
            Some(1),
            None,
            "ERROR: AddressSanitizer: heap-use-after-free on address",
            "",
        );
        assert_eq!(crash_type, CrashType::UseAfterFree);
    }

    #[test]
    fn test_exploitability_assessment() {
        let triager = CrashTriager::new();

        assert_eq!(
            triager.assess_exploitability(&CrashType::UseAfterFree, "", None),
            Exploitability::Exploitable
        );
        assert_eq!(
            triager.assess_exploitability(&CrashType::NullPointerDeref, "", None),
            Exploitability::ProbablyNotExploitable
        );
    }
}
