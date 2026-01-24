//! PE (Portable Executable) File Parser
//!
//! Parses Windows PE files to extract headers, sections, imports, exports,
//! resources, and other metadata.

use super::entropy::calculate_entropy;
use super::types::*;
use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
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

/// Extract PE resources from the resource directory
fn extract_pe_resources(data: &[u8], pe: &PE) -> Vec<PeResource> {
    let mut resources = Vec::new();

    // Get the resource directory RVA from data directories
    let (res_va, _res_size) = match pe.header.optional_header.map(|oh| {
        oh.data_directories.get_resource_table().map(|d| (d.virtual_address, d.size))
    }).flatten() {
        Some((va, sz)) if va > 0 && sz > 0 => (va, sz),
        _ => return resources,
    };

    // Convert RVA to file offset
    let res_rva = res_va as u64;
    let res_offset = match rva_to_offset(res_rva, &pe.sections) {
        Some(off) => off as usize,
        None => return resources,
    };

    // Parse the root resource directory
    if res_offset + 16 > data.len() {
        return resources;
    }

    let num_named = u16::from_le_bytes([data[res_offset + 12], data[res_offset + 13]]) as usize;
    let num_id = u16::from_le_bytes([data[res_offset + 14], data[res_offset + 15]]) as usize;
    let total_entries = num_named + num_id;

    // Each entry is 8 bytes after the 16-byte directory header
    for i in 0..total_entries.min(64) {
        let entry_offset = res_offset + 16 + (i * 8);
        if entry_offset + 8 > data.len() {
            break;
        }

        let name_or_id = u32::from_le_bytes([
            data[entry_offset], data[entry_offset + 1],
            data[entry_offset + 2], data[entry_offset + 3],
        ]);
        let offset_to_data = u32::from_le_bytes([
            data[entry_offset + 4], data[entry_offset + 5],
            data[entry_offset + 6], data[entry_offset + 7],
        ]);

        let resource_type = get_resource_type_name(name_or_id);

        // If high bit is set, it points to another directory (subdirectory)
        if offset_to_data & 0x80000000 != 0 {
            let sub_offset = res_offset + (offset_to_data & 0x7FFFFFFF) as usize;
            parse_resource_subdirectory(data, res_offset, sub_offset, &resource_type, &mut resources);
        }
    }

    resources
}

/// Parse a resource subdirectory (level 2 - name/ID entries)
fn parse_resource_subdirectory(
    data: &[u8],
    res_base: usize,
    dir_offset: usize,
    resource_type: &str,
    resources: &mut Vec<PeResource>,
) {
    if dir_offset + 16 > data.len() {
        return;
    }

    let num_named = u16::from_le_bytes([data[dir_offset + 12], data[dir_offset + 13]]) as usize;
    let num_id = u16::from_le_bytes([data[dir_offset + 14], data[dir_offset + 15]]) as usize;
    let total = num_named + num_id;

    for i in 0..total.min(256) {
        let entry_offset = dir_offset + 16 + (i * 8);
        if entry_offset + 8 > data.len() {
            break;
        }

        let name_or_id = u32::from_le_bytes([
            data[entry_offset], data[entry_offset + 1],
            data[entry_offset + 2], data[entry_offset + 3],
        ]);
        let offset_to_data = u32::from_le_bytes([
            data[entry_offset + 4], data[entry_offset + 5],
            data[entry_offset + 6], data[entry_offset + 7],
        ]);

        let name = if name_or_id & 0x80000000 != 0 {
            // Named resource - read unicode string
            let name_offset = res_base + (name_or_id & 0x7FFFFFFF) as usize;
            read_resource_name(data, name_offset)
        } else {
            format!("#{}", name_or_id)
        };

        // Follow to language directory (level 3)
        if offset_to_data & 0x80000000 != 0 {
            let lang_dir_offset = res_base + (offset_to_data & 0x7FFFFFFF) as usize;
            parse_resource_language_dir(data, res_base, lang_dir_offset, resource_type, &name, resources);
        } else {
            // Direct data entry
            let data_entry_offset = res_base + offset_to_data as usize;
            if let Some(res) = read_resource_data_entry(data, data_entry_offset, resource_type, &name, 0) {
                resources.push(res);
            }
        }
    }
}

/// Parse the language subdirectory (level 3) to get actual resource data entries
fn parse_resource_language_dir(
    data: &[u8],
    res_base: usize,
    dir_offset: usize,
    resource_type: &str,
    name: &str,
    resources: &mut Vec<PeResource>,
) {
    if dir_offset + 16 > data.len() {
        return;
    }

    let num_named = u16::from_le_bytes([data[dir_offset + 12], data[dir_offset + 13]]) as usize;
    let num_id = u16::from_le_bytes([data[dir_offset + 14], data[dir_offset + 15]]) as usize;
    let total = num_named + num_id;

    for i in 0..total.min(64) {
        let entry_offset = dir_offset + 16 + (i * 8);
        if entry_offset + 8 > data.len() {
            break;
        }

        let language_id = u32::from_le_bytes([
            data[entry_offset], data[entry_offset + 1],
            data[entry_offset + 2], data[entry_offset + 3],
        ]);
        let offset_to_data = u32::from_le_bytes([
            data[entry_offset + 4], data[entry_offset + 5],
            data[entry_offset + 6], data[entry_offset + 7],
        ]);

        // This should be a leaf node pointing to IMAGE_RESOURCE_DATA_ENTRY
        if offset_to_data & 0x80000000 == 0 {
            let data_entry_offset = res_base + offset_to_data as usize;
            if let Some(res) = read_resource_data_entry(data, data_entry_offset, resource_type, name, language_id) {
                resources.push(res);
            }
        }
    }
}

/// Read an IMAGE_RESOURCE_DATA_ENTRY and create a PeResource
fn read_resource_data_entry(
    data: &[u8],
    entry_offset: usize,
    resource_type: &str,
    name: &str,
    language: u32,
) -> Option<PeResource> {
    if entry_offset + 16 > data.len() {
        return None;
    }

    let _data_rva = u32::from_le_bytes([
        data[entry_offset], data[entry_offset + 1],
        data[entry_offset + 2], data[entry_offset + 3],
    ]);
    let size = u32::from_le_bytes([
        data[entry_offset + 4], data[entry_offset + 5],
        data[entry_offset + 6], data[entry_offset + 7],
    ]);

    Some(PeResource {
        resource_type: resource_type.to_string(),
        name: name.to_string(),
        language,
        size: size as u64,
        entropy: 0.0, // Would need to resolve RVA to calculate
    })
}

/// Read a unicode resource name
fn read_resource_name(data: &[u8], offset: usize) -> String {
    if offset + 2 > data.len() {
        return String::new();
    }
    let len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    let chars_start = offset + 2;
    let mut name = String::with_capacity(len);
    for i in 0..len.min(256) {
        let char_offset = chars_start + (i * 2);
        if char_offset + 2 > data.len() {
            break;
        }
        let ch = u16::from_le_bytes([data[char_offset], data[char_offset + 1]]);
        if let Some(c) = char::from_u32(ch as u32) {
            name.push(c);
        }
    }
    name
}

/// Convert resource type ID to human-readable name
fn get_resource_type_name(id: u32) -> String {
    if id & 0x80000000 != 0 {
        return "Named".to_string();
    }
    match id {
        1 => "RT_CURSOR".to_string(),
        2 => "RT_BITMAP".to_string(),
        3 => "RT_ICON".to_string(),
        4 => "RT_MENU".to_string(),
        5 => "RT_DIALOG".to_string(),
        6 => "RT_STRING".to_string(),
        7 => "RT_FONTDIR".to_string(),
        8 => "RT_FONT".to_string(),
        9 => "RT_ACCELERATOR".to_string(),
        10 => "RT_RCDATA".to_string(),
        11 => "RT_MESSAGETABLE".to_string(),
        12 => "RT_GROUP_CURSOR".to_string(),
        14 => "RT_GROUP_ICON".to_string(),
        16 => "RT_VERSION".to_string(),
        17 => "RT_DLGINCLUDE".to_string(),
        19 => "RT_PLUGPLAY".to_string(),
        20 => "RT_VXD".to_string(),
        21 => "RT_ANICURSOR".to_string(),
        22 => "RT_ANIICON".to_string(),
        23 => "RT_HTML".to_string(),
        24 => "RT_MANIFEST".to_string(),
        _ => format!("RT_UNKNOWN({})", id),
    }
}

/// Convert RVA to file offset using section table
fn rva_to_offset(rva: u64, sections: &[goblin::pe::section_table::SectionTable]) -> Option<u64> {
    for section in sections {
        let section_start = section.virtual_address as u64;
        let section_size = std::cmp::max(section.virtual_size, section.size_of_raw_data) as u64;
        if rva >= section_start && rva < section_start + section_size {
            let offset = rva - section_start + section.pointer_to_raw_data as u64;
            return Some(offset);
        }
    }
    None
}

/// Extract version info from the VS_VERSIONINFO resource
fn extract_version_info(data: &[u8], pe: &PE) -> Option<VersionInfo> {
    // Get the resource directory
    let (res_va, res_sz) = pe.header.optional_header.map(|oh| {
        oh.data_directories.get_resource_table().map(|d| (d.virtual_address, d.size))
    }).flatten()?;

    if res_va == 0 || res_sz == 0 {
        return None;
    }

    let res_rva = res_va as u64;
    let res_offset = rva_to_offset(res_rva, &pe.sections)? as usize;

    // Find RT_VERSION (type 16) resource data
    let version_data = find_resource_data(data, res_offset, 16, &pe.sections)?;

    // Parse VS_VERSIONINFO structure
    parse_version_info_data(&version_data)
}

/// Find resource data for a specific resource type
fn find_resource_data(data: &[u8], res_base: usize, resource_type_id: u32, sections: &[goblin::pe::section_table::SectionTable]) -> Option<Vec<u8>> {
    if res_base + 16 > data.len() {
        return None;
    }

    let num_named = u16::from_le_bytes([data[res_base + 12], data[res_base + 13]]) as usize;
    let num_id = u16::from_le_bytes([data[res_base + 14], data[res_base + 15]]) as usize;
    let total = num_named + num_id;

    // Search for the type entry
    for i in 0..total.min(64) {
        let entry_offset = res_base + 16 + (i * 8);
        if entry_offset + 8 > data.len() {
            break;
        }

        let type_id = u32::from_le_bytes([
            data[entry_offset], data[entry_offset + 1],
            data[entry_offset + 2], data[entry_offset + 3],
        ]);
        let offset_to_data = u32::from_le_bytes([
            data[entry_offset + 4], data[entry_offset + 5],
            data[entry_offset + 6], data[entry_offset + 7],
        ]);

        if type_id == resource_type_id && offset_to_data & 0x80000000 != 0 {
            // Navigate subdirectory to find the first data entry
            let sub_offset = res_base + (offset_to_data & 0x7FFFFFFF) as usize;
            return find_first_leaf_data(data, res_base, sub_offset, sections);
        }
    }
    None
}

/// Navigate resource directories to find the first leaf data entry
fn find_first_leaf_data(data: &[u8], res_base: usize, dir_offset: usize, sections: &[goblin::pe::section_table::SectionTable]) -> Option<Vec<u8>> {
    if dir_offset + 16 > data.len() {
        return None;
    }

    let num_named = u16::from_le_bytes([data[dir_offset + 12], data[dir_offset + 13]]) as usize;
    let num_id = u16::from_le_bytes([data[dir_offset + 14], data[dir_offset + 15]]) as usize;
    let total = num_named + num_id;

    if total == 0 {
        return None;
    }

    let entry_offset = dir_offset + 16; // First entry
    if entry_offset + 8 > data.len() {
        return None;
    }

    let offset_to_data = u32::from_le_bytes([
        data[entry_offset + 4], data[entry_offset + 5],
        data[entry_offset + 6], data[entry_offset + 7],
    ]);

    if offset_to_data & 0x80000000 != 0 {
        // Another subdirectory - recurse
        let sub_offset = res_base + (offset_to_data & 0x7FFFFFFF) as usize;
        return find_first_leaf_data(data, res_base, sub_offset, sections);
    }

    // Leaf node - IMAGE_RESOURCE_DATA_ENTRY
    let data_entry_offset = res_base + offset_to_data as usize;
    if data_entry_offset + 16 > data.len() {
        return None;
    }

    let data_rva = u32::from_le_bytes([
        data[data_entry_offset], data[data_entry_offset + 1],
        data[data_entry_offset + 2], data[data_entry_offset + 3],
    ]);
    let size = u32::from_le_bytes([
        data[data_entry_offset + 4], data[data_entry_offset + 5],
        data[data_entry_offset + 6], data[data_entry_offset + 7],
    ]) as usize;

    let file_offset = rva_to_offset(data_rva as u64, sections)? as usize;
    if file_offset + size > data.len() {
        return None;
    }

    Some(data[file_offset..file_offset + size].to_vec())
}

/// Parse VS_VERSIONINFO binary data to extract version strings
fn parse_version_info_data(data: &[u8]) -> Option<VersionInfo> {
    if data.len() < 6 {
        return None;
    }

    let mut info = VersionInfo {
        file_version: None,
        product_version: None,
        company_name: None,
        product_name: None,
        file_description: None,
        original_filename: None,
        internal_name: None,
        legal_copyright: None,
    };

    // Look for VS_FIXEDFILEINFO (signature 0xFEEF04BD)
    if let Some(fixed_pos) = find_dword_in_data(data, 0xFEEF04BD) {
        if fixed_pos + 52 <= data.len() {
            // File version: dwFileVersionMS (offset +8), dwFileVersionLS (offset +12)
            let ver_ms = u32::from_le_bytes([
                data[fixed_pos + 8], data[fixed_pos + 9],
                data[fixed_pos + 10], data[fixed_pos + 11],
            ]);
            let ver_ls = u32::from_le_bytes([
                data[fixed_pos + 12], data[fixed_pos + 13],
                data[fixed_pos + 14], data[fixed_pos + 15],
            ]);
            info.file_version = Some(format!(
                "{}.{}.{}.{}",
                ver_ms >> 16, ver_ms & 0xFFFF,
                ver_ls >> 16, ver_ls & 0xFFFF
            ));

            // Product version: dwProductVersionMS (offset +16), dwProductVersionLS (offset +20)
            let prod_ms = u32::from_le_bytes([
                data[fixed_pos + 16], data[fixed_pos + 17],
                data[fixed_pos + 18], data[fixed_pos + 19],
            ]);
            let prod_ls = u32::from_le_bytes([
                data[fixed_pos + 20], data[fixed_pos + 21],
                data[fixed_pos + 22], data[fixed_pos + 23],
            ]);
            info.product_version = Some(format!(
                "{}.{}.{}.{}",
                prod_ms >> 16, prod_ms & 0xFFFF,
                prod_ls >> 16, prod_ls & 0xFFFF
            ));
        }
    }

    // Extract StringFileInfo values
    let string_keys = [
        ("CompanyName", &mut info.company_name as &mut Option<String>),
        ("ProductName", &mut info.product_name),
        ("FileDescription", &mut info.file_description),
        ("OriginalFilename", &mut info.original_filename),
        ("InternalName", &mut info.internal_name),
        ("LegalCopyright", &mut info.legal_copyright),
    ];

    for (key, target) in string_keys {
        if let Some(value) = find_version_string(data, key) {
            *target = Some(value);
        }
    }

    // Return None if we found nothing useful
    if info.file_version.is_none() && info.company_name.is_none() && info.product_name.is_none() {
        return None;
    }

    Some(info)
}

/// Find a unicode string key in VS_VERSIONINFO data and extract its value
fn find_version_string(data: &[u8], key: &str) -> Option<String> {
    // Convert key to UTF-16LE for searching
    let key_utf16: Vec<u8> = key.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // Search for the key in the data
    let key_len = key_utf16.len();
    for i in 0..data.len().saturating_sub(key_len + 4) {
        if data[i..i + key_len] == key_utf16[..] {
            // Check null terminator after key
            if i + key_len + 2 <= data.len()
                && data[i + key_len] == 0 && data[i + key_len + 1] == 0
            {
                // Value follows after key + null + padding
                let mut value_start = i + key_len + 2;
                // Align to DWORD boundary
                while value_start % 4 != 0 && value_start < data.len() {
                    value_start += 1;
                }
                // Sometimes there's additional padding
                while value_start < data.len().saturating_sub(1)
                    && data[value_start] == 0 && data[value_start + 1] == 0
                {
                    value_start += 2;
                    if value_start % 4 == 0 {
                        break;
                    }
                }

                // Read UTF-16LE string value
                let value = read_utf16le_string(data, value_start);
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    None
}

/// Read a null-terminated UTF-16LE string from data
fn read_utf16le_string(data: &[u8], offset: usize) -> String {
    let mut chars = Vec::new();
    let mut pos = offset;
    while pos + 1 < data.len() {
        let ch = u16::from_le_bytes([data[pos], data[pos + 1]]);
        if ch == 0 {
            break;
        }
        chars.push(ch);
        pos += 2;
        if chars.len() > 512 {
            break; // Safety limit
        }
    }
    String::from_utf16_lossy(&chars)
}

/// Find a DWORD value in binary data
fn find_dword_in_data(data: &[u8], value: u32) -> Option<usize> {
    let needle = value.to_le_bytes();
    for i in 0..data.len().saturating_sub(4) {
        if data[i..i + 4] == needle {
            return Some(i);
        }
    }
    None
}

/// Extract digital certificate information from the security directory
fn extract_certificates(data: &[u8], pe: &PE) -> Vec<CertificateInfo> {
    let mut certs = Vec::new();

    // Security directory entry (index 4) gives file offset (not RVA) and size
    let (cert_va, cert_sz) = match pe.header.optional_header.map(|oh| {
        oh.data_directories.get_certificate_table().map(|d| (d.virtual_address, d.size))
    }).flatten() {
        Some((va, sz)) if va > 0 && sz > 0 => (va, sz),
        _ => return certs,
    };

    // For the security directory, virtual_address is actually a file offset
    let cert_offset = cert_va as usize;
    let cert_size = cert_sz as usize;

    if cert_offset + cert_size > data.len() || cert_size < 8 {
        return certs;
    }

    let cert_data = &data[cert_offset..cert_offset + cert_size];
    let mut pos = 0;

    // Parse WIN_CERTIFICATE structures
    while pos + 8 < cert_data.len() {
        // WIN_CERTIFICATE header
        let length = u32::from_le_bytes([
            cert_data[pos], cert_data[pos + 1],
            cert_data[pos + 2], cert_data[pos + 3],
        ]) as usize;
        let revision = u16::from_le_bytes([cert_data[pos + 4], cert_data[pos + 5]]);
        let cert_type = u16::from_le_bytes([cert_data[pos + 6], cert_data[pos + 7]]);

        if length < 8 || pos + length > cert_data.len() {
            break;
        }

        // WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
        if cert_type == 0x0002 && length > 8 {
            let pkcs7_data = &cert_data[pos + 8..pos + length];
            if let Some(cert_info) = parse_pkcs7_certificate_info(pkcs7_data, revision) {
                certs.push(cert_info);
            }
        }

        // Advance to next certificate (8-byte aligned)
        pos += (length + 7) & !7;
    }

    certs
}

/// Parse certificate information from PKCS#7 signed data
fn parse_pkcs7_certificate_info(pkcs7_data: &[u8], _revision: u16) -> Option<CertificateInfo> {
    // PKCS#7 is ASN.1 DER encoded. We parse enough to extract subject/issuer info.
    // Look for X.509 certificate within the PKCS#7 SignedData structure.

    // Find certificate sequences by looking for common X.509 patterns
    let subject = extract_asn1_string_field(pkcs7_data, "subject");
    let issuer = extract_asn1_string_field(pkcs7_data, "issuer");
    let serial = extract_serial_number(pkcs7_data);
    let (not_before, not_after) = extract_validity_dates(pkcs7_data);
    let sig_algo = extract_signature_algorithm(pkcs7_data);

    // If we couldn't parse anything useful, still report a certificate exists
    let subject = subject.unwrap_or_else(|| "Unknown Subject".to_string());
    let issuer = issuer.unwrap_or_else(|| "Unknown Issuer".to_string());

    Some(CertificateInfo {
        subject,
        issuer,
        serial_number: serial.unwrap_or_else(|| "Unknown".to_string()),
        not_before: not_before.unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap()),
        not_after: not_after.unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap()),
        is_valid: not_after.map(|d| d > Utc::now()).unwrap_or(false),
        signature_algorithm: sig_algo.unwrap_or_else(|| "Unknown".to_string()),
    })
}

/// Extract a human-readable string from ASN.1 DER data by scanning for common OID patterns
fn extract_asn1_string_field(data: &[u8], field_type: &str) -> Option<String> {
    // Common X.509 OIDs we search for:
    // CN (Common Name): 2.5.4.3 = 55 04 03
    // O (Organization): 2.5.4.10 = 55 04 0A
    // OU (Org Unit):    2.5.4.11 = 55 04 0B
    // C (Country):      2.5.4.6  = 55 04 06

    let cn_oid: &[u8] = &[0x55, 0x04, 0x03]; // Common Name
    let o_oid: &[u8] = &[0x55, 0x04, 0x0A];  // Organization

    // For subject, search later in the data; for issuer, search earlier
    let search_oid = cn_oid;
    let mut found_strings: Vec<String> = Vec::new();

    for i in 0..data.len().saturating_sub(5) {
        if data[i..].starts_with(search_oid) {
            // After OID, there should be a string type tag and length
            let str_offset = i + search_oid.len();
            if str_offset + 2 < data.len() {
                let tag = data[str_offset];
                let len = data[str_offset + 1] as usize;
                // PrintableString (0x13), UTF8String (0x0C), IA5String (0x16), BMPString (0x1E)
                if (tag == 0x13 || tag == 0x0C || tag == 0x16) && len > 0 && str_offset + 2 + len <= data.len() {
                    let s = String::from_utf8_lossy(&data[str_offset + 2..str_offset + 2 + len]).to_string();
                    if !s.is_empty() && s.len() < 256 {
                        found_strings.push(s);
                    }
                }
            }
        }
    }

    // Also look for Organization
    for i in 0..data.len().saturating_sub(5) {
        if data[i..].starts_with(o_oid) {
            let str_offset = i + o_oid.len();
            if str_offset + 2 < data.len() {
                let tag = data[str_offset];
                let len = data[str_offset + 1] as usize;
                if (tag == 0x13 || tag == 0x0C || tag == 0x16) && len > 0 && str_offset + 2 + len <= data.len() {
                    let s = String::from_utf8_lossy(&data[str_offset + 2..str_offset + 2 + len]).to_string();
                    if !s.is_empty() && s.len() < 256 && !found_strings.contains(&s) {
                        found_strings.push(s);
                    }
                }
            }
        }
    }

    if found_strings.is_empty() {
        return None;
    }

    // For issuer vs subject: issuer typically appears first in the certificate
    // We return different occurrences for each
    match field_type {
        "issuer" => found_strings.first().cloned(),
        "subject" => {
            if found_strings.len() > 1 {
                found_strings.last().cloned()
            } else {
                found_strings.first().cloned()
            }
        }
        _ => found_strings.first().cloned(),
    }
}

/// Extract serial number from ASN.1 data
fn extract_serial_number(data: &[u8]) -> Option<String> {
    // Serial number is an INTEGER (tag 0x02) early in the TBS certificate
    // It follows the version field (which is context tag [0])
    // Look for pattern: SEQUENCE > SEQUENCE > [0] version > INTEGER serial

    for i in 0..data.len().saturating_sub(20) {
        // Look for context tag [0] (version) followed by INTEGER
        if data[i] == 0xA0 && i + 2 < data.len() {
            let version_len = data[i + 1] as usize;
            let serial_pos = i + 2 + version_len;
            if serial_pos + 2 < data.len() && data[serial_pos] == 0x02 {
                let serial_len = data[serial_pos + 1] as usize;
                if serial_len > 0 && serial_len <= 20 && serial_pos + 2 + serial_len <= data.len() {
                    let serial_bytes = &data[serial_pos + 2..serial_pos + 2 + serial_len];
                    let hex: String = serial_bytes.iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(":");
                    return Some(hex);
                }
            }
        }
    }
    None
}

/// Extract validity dates from ASN.1 data
fn extract_validity_dates(data: &[u8]) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    let mut dates: Vec<DateTime<Utc>> = Vec::new();

    // UTCTime tag = 0x17, GeneralizedTime tag = 0x18
    for i in 0..data.len().saturating_sub(15) {
        if data[i] == 0x17 { // UTCTime
            let len = data[i + 1] as usize;
            if len >= 13 && i + 2 + len <= data.len() {
                if let Some(dt) = parse_utc_time(&data[i + 2..i + 2 + len]) {
                    dates.push(dt);
                    if dates.len() >= 2 {
                        break;
                    }
                }
            }
        } else if data[i] == 0x18 { // GeneralizedTime
            let len = data[i + 1] as usize;
            if len >= 15 && i + 2 + len <= data.len() {
                if let Some(dt) = parse_generalized_time(&data[i + 2..i + 2 + len]) {
                    dates.push(dt);
                    if dates.len() >= 2 {
                        break;
                    }
                }
            }
        }
    }

    let not_before = dates.first().copied();
    let not_after = dates.get(1).copied();
    (not_before, not_after)
}

/// Parse ASN.1 UTCTime (YYMMDDHHMMSSZ)
fn parse_utc_time(data: &[u8]) -> Option<DateTime<Utc>> {
    let s = std::str::from_utf8(data).ok()?;
    if s.len() < 13 {
        return None;
    }
    let year: i32 = s[0..2].parse().ok()?;
    let year = if year >= 50 { 1900 + year } else { 2000 + year };
    let month: u32 = s[2..4].parse().ok()?;
    let day: u32 = s[4..6].parse().ok()?;
    let hour: u32 = s[6..8].parse().ok()?;
    let min: u32 = s[8..10].parse().ok()?;
    let sec: u32 = s[10..12].parse().ok()?;

    Utc.with_ymd_and_hms(year, month, day, hour, min, sec).single()
}

/// Parse ASN.1 GeneralizedTime (YYYYMMDDHHMMSSZ)
fn parse_generalized_time(data: &[u8]) -> Option<DateTime<Utc>> {
    let s = std::str::from_utf8(data).ok()?;
    if s.len() < 15 {
        return None;
    }
    let year: i32 = s[0..4].parse().ok()?;
    let month: u32 = s[4..6].parse().ok()?;
    let day: u32 = s[6..8].parse().ok()?;
    let hour: u32 = s[8..10].parse().ok()?;
    let min: u32 = s[10..12].parse().ok()?;
    let sec: u32 = s[12..14].parse().ok()?;

    Utc.with_ymd_and_hms(year, month, day, hour, min, sec).single()
}

/// Extract signature algorithm OID from certificate
fn extract_signature_algorithm(data: &[u8]) -> Option<String> {
    // Common signature algorithm OIDs
    let known_oids: &[(&[u8], &str)] = &[
        (&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B], "SHA256withRSA"),
        (&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C], "SHA384withRSA"),
        (&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D], "SHA512withRSA"),
        (&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05], "SHA1withRSA"),
        (&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04], "MD5withRSA"),
        (&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02], "SHA256withECDSA"),
        (&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03], "SHA384withECDSA"),
        (&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04], "SHA512withECDSA"),
    ];

    for (oid, name) in known_oids {
        if find_bytes_in_data(data, oid).is_some() {
            return Some(name.to_string());
        }
    }
    None
}

/// Find a byte sequence in data
fn find_bytes_in_data(data: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || data.len() < needle.len() {
        return None;
    }
    for i in 0..=data.len() - needle.len() {
        if data[i..i + needle.len()] == *needle {
            return Some(i);
        }
    }
    None
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
