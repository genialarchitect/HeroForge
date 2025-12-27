//! Packer Detection Module
//!
//! Detects common packers, crypters, and protectors using signature-based
//! detection and heuristic analysis.

use super::entropy::thresholds;
use super::types::PackerInfo;

/// Detect if a binary is packed and identify the packer
pub fn detect_packer(data: &[u8], entropy: f64) -> (bool, Option<PackerInfo>) {
    // First, check entropy-based heuristics
    let entropy_suggests_packing = entropy >= thresholds::HIGH_ENTROPY;

    // Check for known packer signatures
    if let Some(packer) = detect_by_signature(data) {
        return (true, Some(packer));
    }

    // Check for section name indicators
    if let Some(packer) = detect_by_section_names(data) {
        return (true, Some(packer));
    }

    // Check for entry point patterns
    if let Some(packer) = detect_by_entry_point(data) {
        return (true, Some(packer));
    }

    // If high entropy but no specific packer found
    if entropy_suggests_packing {
        return (true, Some(PackerInfo {
            name: "Unknown Packer".to_string(),
            version: None,
            confidence: calculate_packing_confidence(entropy, data),
        }));
    }

    (false, None)
}

/// Detect packer by signature patterns
fn detect_by_signature(data: &[u8]) -> Option<PackerInfo> {
    for sig in PACKER_SIGNATURES.iter() {
        if matches_signature(data, sig) {
            return Some(PackerInfo {
                name: sig.name.to_string(),
                version: sig.version.map(|v| v.to_string()),
                confidence: sig.confidence,
            });
        }
    }
    None
}

/// Check if data matches a packer signature
fn matches_signature(data: &[u8], sig: &PackerSignature) -> bool {
    let offset = match sig.offset {
        SignatureOffset::EntryPoint => {
            // Get PE entry point
            if let Some(ep) = get_pe_entry_point_offset(data) {
                ep
            } else {
                return false;
            }
        }
        SignatureOffset::Absolute(off) => off,
        SignatureOffset::PeHeader => {
            // PE header offset
            if data.len() < 64 {
                return false;
            }
            let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
            pe_offset
        }
    };

    if offset + sig.pattern.len() > data.len() {
        return false;
    }

    // Check pattern with optional mask
    for (i, &pattern_byte) in sig.pattern.iter().enumerate() {
        let mask_byte = sig.mask.get(i).copied().unwrap_or(0xFF);
        if mask_byte == 0x00 {
            // Wildcard, skip
            continue;
        }
        let data_byte = data[offset + i];
        if (data_byte & mask_byte) != (pattern_byte & mask_byte) {
            return false;
        }
    }

    true
}

/// Get PE entry point file offset
fn get_pe_entry_point_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 64 {
        return None;
    }

    // Check MZ header
    if data[0] != 0x4D || data[1] != 0x5A {
        return None;
    }

    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if data.len() <= pe_offset + 40 {
        return None;
    }

    // Check PE signature
    if data[pe_offset] != 0x50 || data[pe_offset + 1] != 0x45 {
        return None;
    }

    // Get AddressOfEntryPoint (offset 40 from optional header start)
    let opt_header_offset = pe_offset + 24;
    if data.len() <= opt_header_offset + 20 {
        return None;
    }

    let entry_rva = u32::from_le_bytes([
        data[opt_header_offset + 16],
        data[opt_header_offset + 17],
        data[opt_header_offset + 18],
        data[opt_header_offset + 19],
    ]);

    // Convert RVA to file offset (simplified - would need proper section mapping)
    // For now, return entry RVA as a heuristic
    Some(entry_rva as usize)
}

/// Detect packer by section names
fn detect_by_section_names(data: &[u8]) -> Option<PackerInfo> {
    let section_names = extract_section_names(data);

    for &name in &section_names {
        if let Some(packer) = match_section_name(name) {
            return Some(packer);
        }
    }

    None
}

/// Extract PE section names
fn extract_section_names(data: &[u8]) -> Vec<&str> {
    let mut names = Vec::new();

    if data.len() < 64 {
        return names;
    }

    // Check MZ header
    if data[0] != 0x4D || data[1] != 0x5A {
        return names;
    }

    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if data.len() <= pe_offset + 24 {
        return names;
    }

    // Get number of sections
    let num_sections = u16::from_le_bytes([data[pe_offset + 6], data[pe_offset + 7]]) as usize;
    let optional_header_size = u16::from_le_bytes([
        data[pe_offset + 20],
        data[pe_offset + 21],
    ]) as usize;

    let section_table_offset = pe_offset + 24 + optional_header_size;

    // Parse each section header (40 bytes each)
    for i in 0..num_sections {
        let section_offset = section_table_offset + (i * 40);
        if section_offset + 8 > data.len() {
            break;
        }

        // Section name is first 8 bytes
        if let Ok(name) = std::str::from_utf8(&data[section_offset..section_offset + 8]) {
            let name = name.trim_end_matches('\0');
            if !name.is_empty() {
                names.push(name);
            }
        }
    }

    names
}

/// Match section name to known packers
fn match_section_name(name: &str) -> Option<PackerInfo> {
    let name_lower = name.to_lowercase();

    // UPX
    if name_lower.starts_with("upx") || name == "UPX0" || name == "UPX1" || name == "UPX2" {
        return Some(PackerInfo {
            name: "UPX".to_string(),
            version: None,
            confidence: 0.95,
        });
    }

    // ASPack
    if name_lower == ".aspack" || name_lower == ".adata" {
        return Some(PackerInfo {
            name: "ASPack".to_string(),
            version: None,
            confidence: 0.9,
        });
    }

    // Themida/WinLicense
    if name_lower == ".themida" || name_lower == ".winlice" {
        return Some(PackerInfo {
            name: "Themida".to_string(),
            version: None,
            confidence: 0.95,
        });
    }

    // VMProtect
    if name_lower.starts_with(".vmp") {
        return Some(PackerInfo {
            name: "VMProtect".to_string(),
            version: None,
            confidence: 0.95,
        });
    }

    // PECompact
    if name_lower == ".pec" || name_lower == ".pec2" || name_lower == "pec2" {
        return Some(PackerInfo {
            name: "PECompact".to_string(),
            version: None,
            confidence: 0.9,
        });
    }

    // MEW
    if name_lower == ".mew" {
        return Some(PackerInfo {
            name: "MEW".to_string(),
            version: None,
            confidence: 0.9,
        });
    }

    // MPRESS
    if name_lower == ".mpress" || name_lower == ".mpress1" || name_lower == ".mpress2" {
        return Some(PackerInfo {
            name: "MPRESS".to_string(),
            version: None,
            confidence: 0.9,
        });
    }

    // Obsidium
    if name_lower == ".obsidiu" {
        return Some(PackerInfo {
            name: "Obsidium".to_string(),
            version: None,
            confidence: 0.9,
        });
    }

    // Enigma Protector
    if name_lower == ".enigma" || name_lower == ".enigma1" || name_lower == ".enigma2" {
        return Some(PackerInfo {
            name: "Enigma Protector".to_string(),
            version: None,
            confidence: 0.9,
        });
    }

    // Armadillo
    if name_lower == ".pdata" && name.contains("arma") {
        return Some(PackerInfo {
            name: "Armadillo".to_string(),
            version: None,
            confidence: 0.85,
        });
    }

    // NSPack
    if name_lower == ".nsp0" || name_lower == ".nsp1" || name_lower == ".nsp2" {
        return Some(PackerInfo {
            name: "NSPack".to_string(),
            version: None,
            confidence: 0.9,
        });
    }

    // Petite
    if name_lower == ".petite" {
        return Some(PackerInfo {
            name: "Petite".to_string(),
            version: None,
            confidence: 0.9,
        });
    }

    // Yoda's Crypter
    if name_lower == ".yoda" || name_lower == ".yP" {
        return Some(PackerInfo {
            name: "Yoda's Crypter".to_string(),
            version: None,
            confidence: 0.85,
        });
    }

    None
}

/// Detect packer by entry point code patterns
fn detect_by_entry_point(data: &[u8]) -> Option<PackerInfo> {
    let ep_offset = get_pe_entry_point_offset(data)?;

    // Get entry point code (first 64 bytes)
    if ep_offset + 64 > data.len() {
        return None;
    }

    let ep_code = &data[ep_offset..ep_offset + 64];

    // UPX entry point pattern
    // 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF
    if ep_code.len() >= 16 &&
        ep_code[0] == 0x60 && // PUSHAD
        ep_code[1] == 0xBE    // MOV ESI, ...
    {
        return Some(PackerInfo {
            name: "UPX".to_string(),
            version: None,
            confidence: 0.8,
        });
    }

    // ASPack entry point pattern
    // 60 E8 00 00 00 00 5D
    if ep_code.len() >= 7 &&
        ep_code[0] == 0x60 && // PUSHAD
        ep_code[1] == 0xE8 && // CALL
        ep_code[2] == 0x00 &&
        ep_code[3] == 0x00 &&
        ep_code[4] == 0x00 &&
        ep_code[5] == 0x00 &&
        ep_code[6] == 0x5D    // POP EBP
    {
        return Some(PackerInfo {
            name: "ASPack".to_string(),
            version: None,
            confidence: 0.75,
        });
    }

    // PECompact entry point pattern
    // B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00
    if ep_code.len() >= 13 &&
        ep_code[0] == 0xB8 && // MOV EAX, ...
        ep_code[5] == 0x50 && // PUSH EAX
        ep_code[6] == 0x64 && // FS:
        ep_code[7] == 0xFF &&
        ep_code[8] == 0x35
    {
        return Some(PackerInfo {
            name: "PECompact".to_string(),
            version: None,
            confidence: 0.7,
        });
    }

    None
}

/// Calculate packing confidence based on entropy and other factors
fn calculate_packing_confidence(entropy: f64, data: &[u8]) -> f64 {
    let mut confidence: f64 = 0.0;

    // High entropy is a strong indicator
    if entropy >= 7.5 {
        confidence += 0.5;
    } else if entropy >= 7.0 {
        confidence += 0.3;
    } else if entropy >= 6.5 {
        confidence += 0.1;
    }

    // Check for small code sections (typical of packed files)
    // This would need proper section analysis

    // Check for import table anomalies
    if has_minimal_imports(data) {
        confidence += 0.2;
    }

    confidence.min(0.9) // Cap at 0.9 for unknown packers
}

/// Check if PE has minimal imports (common in packed files)
fn has_minimal_imports(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false;
    }

    // Simple heuristic: check if import directory size is small
    if data[0] != 0x4D || data[1] != 0x5A {
        return false;
    }

    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if data.len() <= pe_offset + 120 {
        return false;
    }

    // Import directory is at offset 104 from optional header start (for PE32)
    let opt_header_offset = pe_offset + 24;
    let import_dir_offset = opt_header_offset + 104;

    if data.len() <= import_dir_offset + 8 {
        return false;
    }

    let import_size = u32::from_le_bytes([
        data[import_dir_offset + 4],
        data[import_dir_offset + 5],
        data[import_dir_offset + 6],
        data[import_dir_offset + 7],
    ]);

    // Packed files often have very small import tables
    import_size < 200
}

/// Signature offset type
#[derive(Debug, Clone, Copy)]
enum SignatureOffset {
    EntryPoint,
    Absolute(usize),
    PeHeader,
}

/// Packer signature definition
struct PackerSignature {
    name: &'static str,
    version: Option<&'static str>,
    offset: SignatureOffset,
    pattern: &'static [u8],
    mask: &'static [u8], // 0x00 = wildcard, 0xFF = exact match
    confidence: f64,
}

/// Known packer signatures
static PACKER_SIGNATURES: &[PackerSignature] = &[
    // UPX 3.x
    PackerSignature {
        name: "UPX",
        version: Some("3.x"),
        offset: SignatureOffset::EntryPoint,
        pattern: &[0x60, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x8D, 0xBE],
        mask: &[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF],
        confidence: 0.95,
    },
    // ASPack 2.12
    PackerSignature {
        name: "ASPack",
        version: Some("2.12"),
        offset: SignatureOffset::EntryPoint,
        pattern: &[0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB],
        mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        confidence: 0.9,
    },
    // FSG 2.0
    PackerSignature {
        name: "FSG",
        version: Some("2.0"),
        offset: SignatureOffset::EntryPoint,
        pattern: &[0x87, 0x25, 0x00, 0x00, 0x00, 0x00, 0x61, 0x94],
        mask: &[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF],
        confidence: 0.85,
    },
    // PECompact 2.x
    PackerSignature {
        name: "PECompact",
        version: Some("2.x"),
        offset: SignatureOffset::EntryPoint,
        pattern: &[0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0xFF, 0x35],
        mask: &[0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
        confidence: 0.85,
    },
    // MPRESS
    PackerSignature {
        name: "MPRESS",
        version: None,
        offset: SignatureOffset::EntryPoint,
        pattern: &[0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x05],
        mask: &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        confidence: 0.85,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_upx_section() {
        let packer = match_section_name("UPX0");
        assert!(packer.is_some());
        assert_eq!(packer.unwrap().name, "UPX");
    }

    #[test]
    fn test_detect_vmprotect_section() {
        let packer = match_section_name(".vmp0");
        assert!(packer.is_some());
        assert_eq!(packer.unwrap().name, "VMProtect");
    }

    #[test]
    fn test_no_packer_detected() {
        let packer = match_section_name(".text");
        assert!(packer.is_none());
    }
}
