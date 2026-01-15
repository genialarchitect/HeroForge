//! Binary Analysis Module
//!
//! Provides comprehensive binary file analysis capabilities including:
//! - PE (Windows) and ELF (Linux) file parsing
//! - String extraction with encoding detection
//! - Entropy analysis for packer detection
//! - Hash computation (MD5, SHA1, SHA256, imphash)
//! - Basic disassembly support

pub mod types;
pub mod pe_parser;
pub mod elf_parser;
pub mod strings;
pub mod entropy;
pub mod hashing;
pub mod packer_detection;

pub use types::*;

use anyhow::{Context, Result};
use chrono::Utc;
use std::path::Path;
use uuid::Uuid;

/// Binary analysis engine
pub struct BinaryAnalyzer {
    config: AnalysisConfig,
}

impl BinaryAnalyzer {
    /// Create a new binary analyzer with default configuration
    pub fn new() -> Self {
        Self {
            config: AnalysisConfig::default(),
        }
    }

    /// Create a new binary analyzer with custom configuration
    pub fn with_config(config: AnalysisConfig) -> Self {
        Self { config }
    }

    /// Analyze a binary file and return full analysis results
    pub fn analyze_file(&self, path: &Path, user_id: &str) -> Result<BinarySample> {
        let data = std::fs::read(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;

        self.analyze_bytes(&data, path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string()), user_id)
    }

    /// Analyze binary data directly
    pub fn analyze_bytes(&self, data: &[u8], filename: String, user_id: &str) -> Result<BinarySample> {
        let id = Uuid::new_v4().to_string();
        let file_size = data.len() as u64;

        // Compute hashes
        let hashes = hashing::compute_hashes(data, self.config.compute_imphash);

        // Calculate entropy
        let file_entropy = entropy::calculate_entropy(data);

        // Detect file type
        let file_type = detect_file_type(data);

        // Determine architecture
        let architecture = detect_architecture(data, file_type);

        // Check if packed
        let (is_packed, packer_info) = if self.config.detect_packers {
            packer_detection::detect_packer(data, file_entropy)
        } else {
            (false, None)
        };

        // Parse based on file type
        let (pe_analysis, elf_analysis, imports_count, exports_count) = match file_type {
            BinaryType::Pe => {
                let analysis = pe_parser::parse_pe(data)?;
                let imports = analysis.imports.iter().map(|i| i.functions.len()).sum::<usize>() as u32;
                let exports = analysis.exports.len() as u32;
                (Some(analysis), None, imports, exports)
            }
            BinaryType::Elf => {
                let analysis = elf_parser::parse_elf(data)?;
                let imports = analysis.symbols.iter().filter(|s| s.binding == "GLOBAL").count() as u32;
                let exports = analysis.symbols.len() as u32;
                (None, Some(analysis), imports, exports)
            }
            _ => (None, None, 0, 0),
        };

        // Extract strings
        let strings_count = if self.config.extract_strings {
            let extracted = strings::extract_strings(data, self.config.min_string_length);
            extracted.len().min(self.config.max_strings) as u32
        } else {
            0
        };

        Ok(BinarySample {
            id,
            user_id: user_id.to_string(),
            filename,
            file_size,
            file_type,
            architecture,
            hashes,
            entropy: file_entropy,
            is_packed,
            packer_info,
            analysis_status: AnalysisStatus::Completed,
            pe_analysis,
            elf_analysis,
            strings_count,
            imports_count,
            exports_count,
            created_at: Utc::now(),
            analyzed_at: Some(Utc::now()),
        })
    }

    /// Get a hex dump view of the binary
    pub fn get_hex_view(&self, data: &[u8], offset: u64, length: usize) -> HexViewResponse {
        let total_size = data.len() as u64;
        let offset = offset.min(total_size);
        let length = length.min((total_size - offset) as usize).min(4096); // Max 4KB per request

        let start = offset as usize;
        let end = start + length;
        let chunk = &data[start..end];

        let mut rows = Vec::new();
        for (i, row_bytes) in chunk.chunks(16).enumerate() {
            let row_offset = offset + (i * 16) as u64;
            let hex_bytes: Vec<String> = row_bytes.iter().map(|b| format!("{:02x}", b)).collect();

            let ascii: String = row_bytes
                .iter()
                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                .collect();

            rows.push(HexDumpData {
                offset: row_offset,
                hex_bytes,
                ascii,
            });
        }

        HexViewResponse {
            total_size,
            offset,
            length,
            rows,
        }
    }

    /// Extract strings from binary data
    pub fn extract_strings(&self, data: &[u8]) -> Vec<ExtractedString> {
        strings::extract_strings(data, self.config.min_string_length)
    }
}

impl Default for BinaryAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Detect the type of binary file from its magic bytes
pub fn detect_file_type(data: &[u8]) -> BinaryType {
    if data.len() < 4 {
        return BinaryType::Unknown;
    }

    // PE: MZ header
    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
        // Check for PE signature
        if data.len() >= 64 {
            let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
            if data.len() > pe_offset + 4
                && data[pe_offset] == 0x50
                && data[pe_offset + 1] == 0x45
                && data[pe_offset + 2] == 0x00
                && data[pe_offset + 3] == 0x00
            {
                return BinaryType::Pe;
            }
        }
    }

    // ELF: 0x7F ELF
    if data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46 {
        return BinaryType::Elf;
    }

    // Mach-O: 0xFEEDFACE (32-bit) or 0xFEEDFACF (64-bit)
    if (data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA && (data[3] == 0xCE || data[3] == 0xCF))
        || (data[0] == 0xCF && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE)
        || (data[0] == 0xCE && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE)
    {
        return BinaryType::MachO;
    }

    // Archive formats
    // ZIP: PK
    if data[0] == 0x50 && data[1] == 0x4B {
        return BinaryType::Archive;
    }
    // RAR: Rar!
    if data.len() >= 7 && &data[0..7] == b"Rar!\x1a\x07\x00" {
        return BinaryType::Archive;
    }
    // 7z
    if data.len() >= 6 && &data[0..6] == b"7z\xBC\xAF\x27\x1C" {
        return BinaryType::Archive;
    }

    BinaryType::Unknown
}

/// Detect CPU architecture from binary data
pub fn detect_architecture(data: &[u8], file_type: BinaryType) -> Architecture {
    match file_type {
        BinaryType::Pe => {
            if data.len() < 64 {
                return Architecture::Unknown;
            }
            let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
            if data.len() <= pe_offset + 6 {
                return Architecture::Unknown;
            }
            let machine = u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]);
            match machine {
                0x014c => Architecture::X86,    // IMAGE_FILE_MACHINE_I386
                0x8664 => Architecture::X64,    // IMAGE_FILE_MACHINE_AMD64
                0x01c0 => Architecture::Arm,    // IMAGE_FILE_MACHINE_ARM
                0xaa64 => Architecture::Arm64,  // IMAGE_FILE_MACHINE_ARM64
                _ => Architecture::Unknown,
            }
        }
        BinaryType::Elf => {
            if data.len() < 20 {
                return Architecture::Unknown;
            }
            let machine = u16::from_le_bytes([data[18], data[19]]);
            match machine {
                0x03 => Architecture::X86,     // EM_386
                0x3E => Architecture::X64,     // EM_X86_64
                0x28 => Architecture::Arm,     // EM_ARM
                0xB7 => Architecture::Arm64,   // EM_AARCH64
                0x08 => Architecture::Mips,    // EM_MIPS
                0x14 => Architecture::PowerPc, // EM_PPC
                _ => Architecture::Unknown,
            }
        }
        BinaryType::MachO => {
            if data.len() < 8 {
                return Architecture::Unknown;
            }
            let cpu_type = if data[0] == 0xFE {
                // Big endian
                u32::from_be_bytes([data[4], data[5], data[6], data[7]])
            } else {
                u32::from_le_bytes([data[4], data[5], data[6], data[7]])
            };
            match cpu_type {
                0x01000007 => Architecture::X64, // CPU_TYPE_X86_64 (64-bit)
                0x0100000C => Architecture::Arm64, // CPU_TYPE_ARM64
                _ => match cpu_type & 0xFF {
                    7 => Architecture::X86,
                    12 => Architecture::Arm,
                    _ => Architecture::Unknown,
                }
            }
        }
        _ => Architecture::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_pe() {
        // Minimal PE header
        let mut data = vec![0u8; 256];
        data[0] = 0x4D; // M
        data[1] = 0x5A; // Z
        data[60..64].copy_from_slice(&64u32.to_le_bytes()); // PE offset
        data[64] = 0x50; // P
        data[65] = 0x45; // E
        data[66] = 0x00;
        data[67] = 0x00;

        assert_eq!(detect_file_type(&data), BinaryType::Pe);
    }

    #[test]
    fn test_detect_elf() {
        let data = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        assert_eq!(detect_file_type(&data), BinaryType::Elf);
    }

    #[test]
    fn test_detect_zip() {
        let data = [0x50, 0x4B, 0x03, 0x04];
        assert_eq!(detect_file_type(&data), BinaryType::Archive);
    }
}
