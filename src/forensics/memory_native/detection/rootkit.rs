//! Rootkit detection
//!
//! Detect kernel-level rootkits and system manipulation.

use anyhow::Result;

use crate::forensics::memory_native::dump_parser::ParsedDump;
use crate::forensics::memory_native::types::DriverInfo;

/// Rootkit detection result
#[derive(Debug, Clone)]
pub struct RootkitIndicator {
    /// Type of rootkit behavior
    pub indicator_type: RootkitType,
    /// Description
    pub description: String,
    /// Related address
    pub address: Option<u64>,
    /// Related driver/module
    pub related_driver: Option<String>,
    /// Confidence (0-100)
    pub confidence: u8,
    /// Severity (1-10)
    pub severity: u8,
}

/// Type of rootkit behavior
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootkitType {
    /// SSDT hook
    SsdtHook,
    /// IDT hook
    IdtHook,
    /// IRP hook
    IrpHook,
    /// DKOM (Direct Kernel Object Manipulation)
    Dkom,
    /// Inline hook in kernel code
    InlineHook,
    /// Hidden driver
    HiddenDriver,
    /// Hypervisor-based
    Hypervisor,
    /// Bootkit indicators
    Bootkit,
    /// Unknown
    Unknown,
}

impl std::fmt::Display for RootkitType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SsdtHook => write!(f, "SSDT Hook"),
            Self::IdtHook => write!(f, "IDT Hook"),
            Self::IrpHook => write!(f, "IRP Hook"),
            Self::Dkom => write!(f, "DKOM"),
            Self::InlineHook => write!(f, "Inline Hook"),
            Self::HiddenDriver => write!(f, "Hidden Driver"),
            Self::Hypervisor => write!(f, "Hypervisor-based"),
            Self::Bootkit => write!(f, "Bootkit"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Detect rootkit indicators
pub fn detect_rootkits(dump: &ParsedDump, drivers: &[DriverInfo]) -> Result<Vec<RootkitIndicator>> {
    let mut indicators = Vec::new();

    // Check for inline hooks in kernel
    let hooks = detect_kernel_inline_hooks(dump)?;
    indicators.extend(hooks);

    // Check for hidden drivers
    let hidden = detect_hidden_drivers(dump, drivers)?;
    indicators.extend(hidden);

    // Check for DKOM
    let dkom = detect_dkom(dump)?;
    indicators.extend(dkom);

    // Check for hypervisor presence
    let hv = detect_hypervisor_rootkit(dump)?;
    indicators.extend(hv);

    Ok(indicators)
}

/// Detect inline hooks in kernel code
fn detect_kernel_inline_hooks(dump: &ParsedDump) -> Result<Vec<RootkitIndicator>> {
    let mut indicators = Vec::new();

    // Search for hook patterns at kernel addresses
    // This would need to know the kernel base address

    // Look for common hook trampolines at aligned addresses
    let hook_pattern = [0x48, 0xB8]; // MOV RAX, imm64 (64-bit)

    let matches = dump.search_pattern(&hook_pattern);

    for &offset in matches.iter() {
        // Check if this is in kernel space
        if !is_kernel_address(offset) {
            continue;
        }

        // Verify it's a complete hook (MOV RAX; JMP RAX)
        if let Some(code) = dump.read_bytes(offset, 14) {
            if code.len() >= 12 && code[10] == 0xFF && code[11] == 0xE0 {
                // JMP RAX follows MOV RAX
                let target = u64::from_le_bytes([
                    code[2], code[3], code[4], code[5],
                    code[6], code[7], code[8], code[9],
                ]);

                indicators.push(RootkitIndicator {
                    indicator_type: RootkitType::InlineHook,
                    description: format!("Inline hook jumping to {:#x}", target),
                    address: Some(offset),
                    related_driver: None,
                    confidence: 70,
                    severity: 8,
                });
            }
        }
    }

    Ok(indicators)
}

/// Check if address is in kernel space
fn is_kernel_address(addr: u64) -> bool {
    // Windows kernel addresses
    (addr >= 0xfffff800_00000000 && addr < 0xfffff880_00000000) ||
    // Linux kernel addresses
    (addr >= 0xffffffff_80000000)
}

/// Detect hidden drivers
fn detect_hidden_drivers(dump: &ParsedDump, known_drivers: &[DriverInfo]) -> Result<Vec<RootkitIndicator>> {
    let mut indicators = Vec::new();

    // Search for driver pool tags that aren't in the known list
    let driver_tag = b"Driv";
    let matches = dump.search_pattern(driver_tag);

    for &offset in matches.iter().take(1000) {
        // Read potential driver object
        if let Some(data) = dump.read_bytes(offset, 0x100) {
            // Extract driver base address
            // This is simplified - real impl would parse DRIVER_OBJECT
            if data.len() >= 0x28 {
                let driver_start = u64::from_le_bytes([
                    data[0x18], data[0x19], data[0x1A], data[0x1B],
                    data[0x1C], data[0x1D], data[0x1E], data[0x1F],
                ]);

                // Check if this driver is in our known list
                if driver_start != 0 && !known_drivers.iter().any(|d| d.base_addr == driver_start) {
                    indicators.push(RootkitIndicator {
                        indicator_type: RootkitType::HiddenDriver,
                        description: format!("Driver at {:#x} not in loaded module list", driver_start),
                        address: Some(driver_start),
                        related_driver: None,
                        confidence: 60,
                        severity: 9,
                    });
                }
            }
        }
    }

    Ok(indicators)
}

/// Detect DKOM (Direct Kernel Object Manipulation)
fn detect_dkom(dump: &ParsedDump) -> Result<Vec<RootkitIndicator>> {
    let mut indicators = Vec::new();

    // DKOM indicators:
    // 1. Broken doubly-linked lists (Flink->Blink != current)
    // 2. Processes in PspCidTable but not in ActiveProcessLinks
    // 3. Threads in scheduler but not in process thread list

    // Search for EPROCESS structures and verify list integrity
    let proc_tag = b"Proc";
    let matches = dump.search_pattern(proc_tag);

    let mut process_links = Vec::new();

    for &offset in matches.iter().take(500) {
        // Get ActiveProcessLinks offsets
        // Simplified - would need actual EPROCESS parsing
        if let Some(links) = dump.read_bytes(offset + 0x100, 16) {
            let flink = u64::from_le_bytes([
                links[0], links[1], links[2], links[3],
                links[4], links[5], links[6], links[7],
            ]);
            let blink = u64::from_le_bytes([
                links[8], links[9], links[10], links[11],
                links[12], links[13], links[14], links[15],
            ]);

            if flink != 0 && blink != 0 {
                process_links.push((offset, flink, blink));
            }
        }
    }

    // Verify list integrity
    for &(addr, flink, blink) in &process_links {
        // Check if flink->blink points back to us
        if let Some(flink_data) = dump.read_bytes(flink, 16) {
            let flink_blink = u64::from_le_bytes([
                flink_data[8], flink_data[9], flink_data[10], flink_data[11],
                flink_data[12], flink_data[13], flink_data[14], flink_data[15],
            ]);

            let expected_addr = addr + 0x100; // Approximate
            if flink_blink != 0 && (flink_blink as i64 - expected_addr as i64).abs() > 0x1000 {
                indicators.push(RootkitIndicator {
                    indicator_type: RootkitType::Dkom,
                    description: "Broken ActiveProcessLinks detected".to_string(),
                    address: Some(addr),
                    related_driver: None,
                    confidence: 80,
                    severity: 9,
                });
            }
        }
    }

    Ok(indicators)
}

/// Detect hypervisor-based rootkit
fn detect_hypervisor_rootkit(dump: &ParsedDump) -> Result<Vec<RootkitIndicator>> {
    let mut indicators = Vec::new();

    // Hypervisor rootkit indicators:
    // 1. VMCALL/VMMCALL instructions in unexpected locations
    // 2. Unusual CPUID results
    // 3. VMX/SVM structures in memory

    // Search for VMCALL instruction (0x0F 0x01 0xC1)
    let vmcall_pattern = [0x0F, 0x01, 0xC1];
    let matches = dump.search_pattern(&vmcall_pattern);

    for &offset in matches.iter() {
        // Check if in kernel code
        if is_kernel_address(offset) {
            // This could be legitimate hypervisor code or rootkit
            // Need more context to determine
            indicators.push(RootkitIndicator {
                indicator_type: RootkitType::Hypervisor,
                description: format!("VMCALL instruction at {:#x}", offset),
                address: Some(offset),
                related_driver: None,
                confidence: 30, // Low confidence without more context
                severity: 7,
            });
        }
    }

    // Search for VMCS structures (would indicate VMX usage)
    // VMCS revision identifier is at the start
    // Common values: 0x17, 0x18, 0x19, etc.

    Ok(indicators)
}

/// Check for known rootkit signatures
pub fn check_known_rootkits(dump: &ParsedDump) -> Vec<RootkitIndicator> {
    let mut indicators = Vec::new();

    // Known rootkit signatures
    let signatures = [
        (&b"Necurs"[..], "Necurs rootkit"),
        (&b"TDL"[..], "TDL/TDSS rootkit"),
        (&b"ZeroAccess"[..], "ZeroAccess rootkit"),
        (&b"Rustock"[..], "Rustock rootkit"),
        (&b"Uroburos"[..], "Uroburos/Snake rootkit"),
        (&b"Turla"[..], "Turla rootkit"),
    ];

    for (sig, name) in &signatures {
        let matches = dump.search_pattern(*sig);

        for &offset in matches.iter().take(10) {
            // Verify with surrounding context
            if let Some(context) = dump.read_bytes(offset.saturating_sub(32), 128) {
                // Additional validation could be added here
                indicators.push(RootkitIndicator {
                    indicator_type: RootkitType::Unknown,
                    description: format!("{} signature found", name),
                    address: Some(offset),
                    related_driver: None,
                    confidence: 50, // Moderate - could be false positive
                    severity: 10,
                });
            }
        }
    }

    indicators
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rootkit_type_display() {
        assert_eq!(format!("{}", RootkitType::SsdtHook), "SSDT Hook");
        assert_eq!(format!("{}", RootkitType::Dkom), "DKOM");
    }
}
