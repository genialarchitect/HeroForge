//! Code injection detection
//!
//! Detect various forms of code injection in process memory.

use anyhow::Result;

use crate::forensics::memory_native::dump_parser::{ParsedDump, WindowsAddressTranslator};
use crate::forensics::memory_native::types::{InjectionResult, InjectionType, ProcessInfo};

/// Detect code injection in a process
pub fn detect_injections(dump: &ParsedDump, process: &ProcessInfo) -> Result<Vec<InjectionResult>> {
    let mut results = Vec::new();

    if process.dtb == 0 {
        return Ok(results);
    }

    // Detect reflective DLL injection
    if let Ok(reflective) = detect_reflective_dll(dump, process) {
        results.extend(reflective);
    }

    // Detect process hollowing
    if let Ok(hollowing) = detect_process_hollowing(dump, process) {
        results.extend(hollowing);
    }

    // Detect shellcode
    if let Ok(shellcode) = detect_shellcode(dump, process) {
        results.extend(shellcode);
    }

    // Detect API hooks
    if let Ok(hooks) = detect_api_hooks(dump, process) {
        results.extend(hooks);
    }

    Ok(results)
}

/// Detect reflective DLL injection
pub fn detect_reflective_dll(dump: &ParsedDump, process: &ProcessInfo) -> Result<Vec<InjectionResult>> {
    let mut results = Vec::new();

    // Reflective DLLs are loaded without LoadLibrary
    // They have MZ/PE headers but aren't in the loaded module list

    // Search for MZ headers in process memory
    let mz_pattern = b"MZ";
    let mz_matches = dump.search_pattern(mz_pattern);

    for &offset in mz_matches.iter().take(1000) {
        // Check if this could be in the process's virtual space
        // This is simplified - real impl would use VAD enumeration

        if let Some(header) = dump.read_bytes(offset, 0x400) {
            // Verify PE header
            if header.len() < 0x40 {
                continue;
            }

            let pe_offset = u32::from_le_bytes([
                header[0x3C], header[0x3C + 1], header[0x3C + 2], header[0x3C + 3]
            ]) as usize;

            if pe_offset >= header.len() - 4 {
                continue;
            }

            if &header[pe_offset..pe_offset + 4] != b"PE\x00\x00" {
                continue;
            }

            // Check for characteristics of reflective DLL:
            // - Not in loaded module list
            // - No corresponding file on disk
            // - RWX protection

            // Look for reflective loader signature
            if has_reflective_loader_signature(&header) {
                results.push(InjectionResult {
                    pid: process.pid,
                    process_name: process.name.clone(),
                    address: offset,
                    size: 0x10000, // Would need to parse PE for actual size
                    protection: "RWX".to_string(),
                    detection_type: InjectionType::ReflectiveDll,
                    hexdump: hex_dump(&header[..64.min(header.len())]),
                    disasm: None,
                    confidence: 75,
                });
            }
        }
    }

    Ok(results)
}

/// Check for reflective loader signature
fn has_reflective_loader_signature(data: &[u8]) -> bool {
    // Reflective loaders typically have specific patterns:
    // - Call to ReflectiveLoader export
    // - Self-modifying code patterns
    // - Specific API hashing patterns

    // Search for common reflective loader patterns
    let patterns = [
        // GetProcAddress hash lookup pattern
        &[0x48, 0x85, 0xC0, 0x74][..], // test rax, rax; jz
        // Common loader function prologue
        &[0x48, 0x89, 0x5C, 0x24][..], // mov [rsp+X], rbx
    ];

    for pattern in &patterns {
        if data.windows(pattern.len()).any(|w| w == *pattern) {
            return true;
        }
    }

    // Check for "ReflectiveLoader" export name
    if data.windows(16).any(|w| w.starts_with(b"ReflectiveLoader")) {
        return true;
    }

    false
}

/// Detect process hollowing
pub fn detect_process_hollowing(dump: &ParsedDump, process: &ProcessInfo) -> Result<Vec<InjectionResult>> {
    let mut results = Vec::new();

    if process.dtb == 0 || process.peb == 0 {
        return Ok(results);
    }

    let translator = WindowsAddressTranslator::new(process.dtb, true);

    // Process hollowing indicators:
    // 1. PEB.ImageBaseAddress doesn't match actual image
    // 2. Main module headers are inconsistent
    // 3. Entry point is outside main module

    // Read ImageBaseAddress from PEB (+0x10)
    let image_base = translator.read_virtual(dump, process.peb + 0x10, 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .unwrap_or(0);

    if image_base == 0 {
        return Ok(results);
    }

    // Read headers at image base
    if let Some(header) = translator.read_virtual(dump, image_base, 0x400) {
        // Check for valid DOS/PE headers
        if header.len() < 0x40 || &header[0..2] != b"MZ" {
            results.push(InjectionResult {
                pid: process.pid,
                process_name: process.name.clone(),
                address: image_base,
                size: 0,
                protection: "RWX".to_string(),
                detection_type: InjectionType::ProcessHollowing,
                hexdump: hex_dump(&header[..64.min(header.len())]),
                disasm: Some("Invalid DOS header at ImageBaseAddress".to_string()),
                confidence: 90,
            });
            return Ok(results);
        }

        // Verify PE header consistency
        let pe_offset = u32::from_le_bytes([
            header[0x3C], header[0x3C + 1], header[0x3C + 2], header[0x3C + 3]
        ]) as usize;

        if pe_offset >= header.len() - 4 || &header[pe_offset..pe_offset + 4] != b"PE\x00\x00" {
            results.push(InjectionResult {
                pid: process.pid,
                process_name: process.name.clone(),
                address: image_base,
                size: 0,
                protection: "RWX".to_string(),
                detection_type: InjectionType::ProcessHollowing,
                hexdump: hex_dump(&header[..64.min(header.len())]),
                disasm: Some("Invalid PE header".to_string()),
                confidence: 85,
            });
        }
    }

    Ok(results)
}

/// Detect shellcode in process memory
pub fn detect_shellcode(dump: &ParsedDump, process: &ProcessInfo) -> Result<Vec<InjectionResult>> {
    let mut results = Vec::new();

    // Common shellcode patterns
    let shellcode_signatures = [
        // x64 shellcode prologue patterns
        (&[0x48, 0x31, 0xC9][..], "XOR RCX, RCX"),
        (&[0x48, 0x31, 0xD2][..], "XOR RDX, RDX"),
        (&[0x65, 0x48, 0x8B, 0x04, 0x25][..], "MOV RAX, GS:[X] (TEB access)"),
        (&[0xFC, 0x48, 0x83, 0xE4, 0xF0][..], "CLD; AND RSP (Metasploit)"),
        // x86 shellcode patterns
        (&[0x31, 0xC0, 0x50, 0x68][..], "XOR EAX; PUSH; PUSH (WinExec)"),
        (&[0xE8, 0xFF, 0xFF, 0xFF, 0xFF][..], "CALL $+5 (GetPC)"),
        (&[0xD9, 0xEE, 0xD9, 0x74, 0x24][..], "FLDZ; FNSTENV (GetPC FPU)"),
    ];

    for (pattern, description) in &shellcode_signatures {
        let matches = dump.search_pattern(*pattern);

        for &offset in matches.iter().take(100) {
            // Read surrounding context
            if let Some(context) = dump.read_bytes(offset, 64) {
                // Check if this looks like actual shellcode
                // (not just coincidental match in legitimate code)
                if looks_like_shellcode(&context) {
                    results.push(InjectionResult {
                        pid: process.pid,
                        process_name: process.name.clone(),
                        address: offset,
                        size: 64,
                        protection: "RWX".to_string(),
                        detection_type: InjectionType::Shellcode,
                        hexdump: hex_dump(&context[..32.min(context.len())]),
                        disasm: Some(description.to_string()),
                        confidence: 70,
                    });
                }
            }
        }
    }

    Ok(results)
}

/// Heuristic check if bytes look like shellcode
fn looks_like_shellcode(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }

    // Count common shellcode characteristics
    let mut score = 0;

    // High entropy (many different byte values)
    let unique_bytes: std::collections::HashSet<u8> = data.iter().copied().collect();
    if unique_bytes.len() > data.len() / 2 {
        score += 1;
    }

    // Contains null-free sequences (common in shellcode)
    if !data[..16.min(data.len())].contains(&0) {
        score += 1;
    }

    // Contains API hash patterns (common in shellcode)
    for i in 0..data.len().saturating_sub(4) {
        let val = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        // Check for known API hashes (simplified)
        if matches!(val,
            0x0726774C | // kernel32.dll hash
            0x6A4ABC5B | // LoadLibraryA
            0x7802F749   // GetProcAddress
        ) {
            score += 2;
        }
    }

    score >= 2
}

/// Detect API hooks in process
pub fn detect_api_hooks(dump: &ParsedDump, process: &ProcessInfo) -> Result<Vec<InjectionResult>> {
    let mut results = Vec::new();

    if process.dtb == 0 {
        return Ok(results);
    }

    let translator = WindowsAddressTranslator::new(process.dtb, true);

    // Common hooked APIs
    let target_apis = [
        "ntdll.dll:NtAllocateVirtualMemory",
        "ntdll.dll:NtWriteVirtualMemory",
        "ntdll.dll:NtCreateThread",
        "kernel32.dll:VirtualAlloc",
        "kernel32.dll:CreateRemoteThread",
    ];

    // This would require:
    // 1. Finding the IAT/EAT of loaded modules
    // 2. Checking if function prologues are hooked
    // For now, we do a simplified check

    // Search for common hook patterns at aligned addresses
    let hook_patterns = [
        &[0xE9][..],             // JMP rel32
        &[0x68][..],             // PUSH imm32
        &[0x48, 0xB8][..],       // MOV RAX, imm64
    ];

    for pattern in &hook_patterns {
        let matches = dump.search_pattern(*pattern);

        for &offset in matches.iter().take(1000) {
            // Check if aligned (function start)
            if offset % 16 != 0 {
                continue;
            }

            // Read following bytes
            if let Some(code) = dump.read_bytes(offset, 16) {
                // Check if this looks like a hook trampoline
                if is_hook_trampoline(&code) {
                    results.push(InjectionResult {
                        pid: process.pid,
                        process_name: process.name.clone(),
                        address: offset,
                        size: 16,
                        protection: "RX".to_string(),
                        detection_type: InjectionType::ApiHook,
                        hexdump: hex_dump(&code),
                        disasm: Some("Potential API hook".to_string()),
                        confidence: 50,
                    });
                }
            }
        }
    }

    Ok(results)
}

/// Check if bytes look like a hook trampoline
fn is_hook_trampoline(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }

    // JMP rel32 followed by NOPs or other code
    if data[0] == 0xE9 && data[5..].iter().take(3).all(|&b| b == 0x90 || b == 0xCC) {
        return true;
    }

    // PUSH + RET (push address, return to it)
    if data[0] == 0x68 && data[5] == 0xC3 {
        return true;
    }

    // MOV RAX, imm64; JMP RAX (64-bit)
    if data[0] == 0x48 && data[1] == 0xB8 && data[10] == 0xFF && data[11] == 0xE0 {
        return true;
    }

    false
}

/// Create hex dump string
fn hex_dump(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_dump() {
        assert_eq!(hex_dump(&[0x41, 0x42, 0x43]), "41 42 43");
    }

    #[test]
    fn test_hook_detection() {
        // JMP rel32 + NOPs
        let hook1 = [0xE9, 0x00, 0x10, 0x00, 0x00, 0x90, 0x90, 0x90];
        assert!(is_hook_trampoline(&hook1));

        // PUSH + RET
        let hook2 = [0x68, 0x00, 0x10, 0x00, 0x00, 0xC3];
        assert!(is_hook_trampoline(&hook2));

        // Normal code
        let normal = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20];
        assert!(!is_hook_trampoline(&normal));
    }
}
