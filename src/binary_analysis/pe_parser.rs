//! PE (Portable Executable) File Parser
//!
//! Parses Windows PE files to extract headers, sections, imports, exports,
//! resources, and other metadata.

use super::entropy::calculate_entropy;
use super::types::*;
use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use goblin::pe::PE;

/// Parse a PE file and extract analysis information
pub fn parse_pe(data: &[u8]) -> Result<PeAnalysis> {
    let pe = PE::parse(data).context("Failed to parse PE file")?;

    // Extract machine type
    let machine_type = match pe.header.coff_header.machine {
        0x014c => "I386".to_string(),
        0x8664 => "AMD64".to_string(),
        0x01c0 => "ARM".to_string(),
        0xaa64 => "ARM64".to_string(),
        0x0200 => "IA64".to_string(),
        other => format!("Unknown (0x{:04x})", other),
    };

    // Extract subsystem
    let subsystem = pe.header.optional_header.map(|oh| {
        let sub = oh.windows_fields.subsystem;
        match sub {
            1 => "Native".to_string(),
            2 => "Windows GUI".to_string(),
            3 => "Windows Console".to_string(),
            5 => "OS/2 Console".to_string(),
            7 => "POSIX Console".to_string(),
            9 => "Windows CE GUI".to_string(),
            10 => "EFI Application".to_string(),
            11 => "EFI Boot Service Driver".to_string(),
            12 => "EFI Runtime Driver".to_string(),
            13 => "EFI ROM".to_string(),
            14 => "Xbox".to_string(),
            16 => "Windows Boot Application".to_string(),
            _ => format!("Unknown ({})", sub),
        }
    }).unwrap_or_else(|| "Unknown".to_string());

    // Image base and entry point
    let (image_base, entry_point) = pe.header.optional_header.map(|oh| {
        (oh.windows_fields.image_base, pe.entry as u64)
    }).unwrap_or((0, pe.entry as u64));

    // Timestamp
    let timestamp = {
        let ts = pe.header.coff_header.time_date_stamp;
        if ts > 0 {
            Utc.timestamp_opt(ts as i64, 0).single()
        } else {
            None
        }
    };

    // Check characteristics
    let characteristics = pe.header.coff_header.characteristics;
    let is_dll = (characteristics & 0x2000) != 0; // IMAGE_FILE_DLL
    let is_64bit = pe.is_64;
    let has_debug_info = (characteristics & 0x0200) == 0; // Not stripped

    // Check for TLS
    let has_tls = pe.header.optional_header
        .map(|oh| oh.data_directories.get_tls_table().is_some())
        .unwrap_or(false);

    // Check for rich header (exists between DOS header and PE header)
    let has_rich_header = detect_rich_header(data);

    // Validate checksum
    let checksum_valid = validate_pe_checksum(data, &pe);

    // Parse sections
    let sections: Vec<PeSection> = pe.sections.iter().map(|s| {
        let name = String::from_utf8_lossy(&s.name)
            .trim_end_matches('\0')
            .to_string();

        let section_data = get_section_data(data, s);
        let section_entropy = calculate_entropy(&section_data);

        PeSection {
            name,
            virtual_address: s.virtual_address as u64,
            virtual_size: s.virtual_size as u64,
            raw_size: s.size_of_raw_data as u64,
            raw_offset: s.pointer_to_raw_data as u64,
            characteristics: s.characteristics,
            entropy: section_entropy,
            is_executable: (s.characteristics & 0x20000000) != 0, // IMAGE_SCN_MEM_EXECUTE
            is_writable: (s.characteristics & 0x80000000) != 0,   // IMAGE_SCN_MEM_WRITE
        }
    }).collect();

    // Parse imports - group by DLL name
    let mut import_map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for import in &pe.imports {
        let dll = import.dll.to_string();
        let func_name = import.name.to_string();
        import_map.entry(dll).or_default().push(func_name);
    }
    let imports: Vec<PeImport> = import_map.into_iter()
        .map(|(dll_name, functions)| PeImport { dll_name, functions })
        .collect();

    // Parse exports
    let exports: Vec<PeExport> = pe.exports.iter().enumerate().map(|(i, export)| {
        PeExport {
            name: export.name.unwrap_or("(ordinal)").to_string(),
            ordinal: (i + 1) as u32, // Use index as ordinal approximation
            address: export.rva as u64,
        }
    }).collect();

    // Parse resources (simplified - just count/list types)
    let resources = extract_pe_resources(data, &pe);

    // Extract version info
    let version_info = extract_version_info(data, &pe);

    // Extract certificate info
    let certificates = extract_certificates(data, &pe);

    Ok(PeAnalysis {
        machine_type,
        subsystem,
        image_base,
        entry_point,
        timestamp,
        is_dll,
        is_64bit,
        has_debug_info,
        has_tls,
        has_rich_header,
        checksum_valid,
        sections,
        imports,
        exports,
        resources,
        version_info,
        certificates,
    })
}

/// Get raw data for a section
fn get_section_data<'a>(data: &'a [u8], section: &goblin::pe::section_table::SectionTable) -> &'a [u8] {
    let start = section.pointer_to_raw_data as usize;
    let size = section.size_of_raw_data as usize;
    let end = (start + size).min(data.len());
    if start < data.len() {
        &data[start..end]
    } else {
        &[]
    }
}

/// Detect Rich header presence
fn detect_rich_header(data: &[u8]) -> bool {
    // Rich header is between DOS stub and PE header
    // Look for "Rich" marker followed by XOR key
    if data.len() < 256 {
        return false;
    }

    // Search for "Rich" signature (0x68636952 in little endian)
    for i in 0x80..data.len().min(0x200).saturating_sub(4) {
        if data[i] == 0x52 && data[i+1] == 0x69 && data[i+2] == 0x63 && data[i+3] == 0x68 {
            return true;
        }
    }
    false
}

/// Validate PE checksum
fn validate_pe_checksum(data: &[u8], pe: &PE) -> bool {
    let stored_checksum = pe.header.optional_header
        .map(|oh| oh.windows_fields.check_sum)
        .unwrap_or(0);

    if stored_checksum == 0 {
        return true; // No checksum to validate
    }

    // Calculate checksum
    let calculated = calculate_pe_checksum(data);
    calculated == stored_checksum
}

/// Calculate PE checksum
fn calculate_pe_checksum(data: &[u8]) -> u32 {
    let mut checksum: u64 = 0;
    let checksum_offset = 0x58; // Offset of checksum field in optional header (after PE signature)

    // Get actual checksum offset
    if data.len() < 64 {
        return 0;
    }
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    let actual_checksum_offset = pe_offset + 24 + checksum_offset;

    // Sum all 16-bit words, skipping the checksum field
    let mut i = 0;
    while i + 1 < data.len() {
        if i == actual_checksum_offset || i == actual_checksum_offset + 2 {
            i += 2;
            continue;
        }
        let word = u16::from_le_bytes([data[i], data[i + 1]]) as u64;
        checksum += word;
        if checksum > 0xFFFFFFFF {
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        }
        i += 2;
    }

    // Handle odd byte
    if i < data.len() {
        checksum += data[i] as u64;
    }

    // Fold to 32 bits
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum = (checksum & 0xFFFF) + (checksum >> 16);

    // Add file length
    (checksum as u32).wrapping_add(data.len() as u32)
}

/// Extract PE resources (simplified)
fn extract_pe_resources(_data: &[u8], _pe: &PE) -> Vec<PeResource> {
    // Resource parsing is complex - for now return empty
    // Full implementation would parse the resource directory
    Vec::new()
}

/// Extract version info from resources
fn extract_version_info(_data: &[u8], _pe: &PE) -> Option<VersionInfo> {
    // Version info is in VS_VERSIONINFO resource
    // Full implementation would parse the version resource
    None
}

/// Extract digital certificates
fn extract_certificates(_data: &[u8], _pe: &PE) -> Vec<CertificateInfo> {
    // Certificates are in the security directory
    // Full implementation would parse PKCS#7 data
    Vec::new()
}

/// Compute import hash (imphash)
pub fn compute_imphash(pe: &PE) -> Option<String> {
    use md5::{Md5, Digest};

    let mut import_string = String::new();

    for import in &pe.imports {
        let dll_name = import.dll.to_lowercase();
        // Remove extension
        let dll_base = dll_name.strip_suffix(".dll")
            .or_else(|| dll_name.strip_suffix(".ocx"))
            .or_else(|| dll_name.strip_suffix(".sys"))
            .unwrap_or(&dll_name);

        let func_name = import.name.to_string();
        if !func_name.is_empty() {
            if !import_string.is_empty() {
                import_string.push(',');
            }
            import_string.push_str(dll_base);
            import_string.push('.');
            import_string.push_str(&func_name.to_lowercase());
        }
    }

    if import_string.is_empty() {
        return None;
    }

    let mut hasher = Md5::new();
    hasher.update(import_string.as_bytes());
    let result = hasher.finalize();
    Some(hex::encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rich_header_detection() {
        // Create minimal data with Rich header
        // Rich header search range is 0x80..min(data.len(), 0x200)-4
        // So we need at least 0x84 bytes (132), and place Rich within 0x80..0x84
        let mut data = vec![0u8; 512];
        data[0x80] = 0x52; // R
        data[0x81] = 0x69; // i
        data[0x82] = 0x63; // c
        data[0x83] = 0x68; // h

        assert!(detect_rich_header(&data));
    }

    #[test]
    fn test_no_rich_header() {
        let data = vec![0u8; 256];
        assert!(!detect_rich_header(&data));
    }
}
