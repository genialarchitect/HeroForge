//! File Format Fuzzer
//!
//! Mutation-based fuzzing for file formats and parsers.

use std::process::Stdio;
use tokio::process::Command;
use tokio::time::{Duration, timeout};
use chrono::Utc;

use crate::fuzzing::types::*;
use crate::fuzzing::mutators::Mutator;
use crate::fuzzing::crash_triage::CrashTriager;

/// File format fuzzer
pub struct FileFuzzer {
    mutator: Mutator,
    triager: CrashTriager,
    temp_dir: String,
}

impl FileFuzzer {
    /// Create a new file fuzzer
    pub fn new() -> Self {
        Self {
            mutator: Mutator::new(),
            triager: CrashTriager::new(),
            temp_dir: std::env::temp_dir().to_string_lossy().to_string(),
        }
    }

    /// Set temp directory for fuzz files
    pub fn with_temp_dir(mut self, dir: &str) -> Self {
        self.temp_dir = dir.to_string();
        self
    }

    /// Fuzz a file parser
    pub async fn fuzz(
        &self,
        command: &str,
        args: &[String],
        seed_files: &[Vec<u8>],
        config: &FuzzerConfig,
        iterations: u64,
    ) -> Vec<FuzzingCrash> {
        let mut crashes = Vec::new();
        let timeout_duration = Duration::from_millis(
            config.max_runtime_secs.unwrap_or(5) * 1000
        );

        for i in 0..iterations {
            // Select and mutate seed
            let seed = if seed_files.is_empty() {
                // Generate random file content
                vec![0u8; 1024]
            } else {
                seed_files[i as usize % seed_files.len()].clone()
            };

            let mutated = self.mutator.mutate(&seed, config);

            // Write to temp file
            let temp_path = format!("{}/fuzz_input_{}", self.temp_dir, uuid::Uuid::new_v4());
            if tokio::fs::write(&temp_path, &mutated).await.is_err() {
                continue;
            }

            // Replace @@ with temp file path
            let actual_args: Vec<String> = args.iter()
                .map(|arg| arg.replace("@@", &temp_path))
                .collect();

            // Execute
            let result = timeout(timeout_duration, async {
                Command::new(command)
                    .args(&actual_args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
                    .await
            }).await;

            // Cleanup temp file
            let _ = tokio::fs::remove_file(&temp_path).await;

            // Analyze result
            match result {
                Ok(Ok(output)) => {
                    if let Some(mut crash) = self.triager.analyze_output(&output, &mutated) {
                        crash.campaign_id = String::new();
                        crashes.push(crash);
                    }
                }
                Ok(Err(e)) => {
                    // Execution error
                    crashes.push(FuzzingCrash {
                        id: uuid::Uuid::new_v4().to_string(),
                        campaign_id: String::new(),
                        crash_type: CrashType::Unknown,
                        crash_hash: self.hash_input(&mutated),
                        exploitability: Exploitability::Unknown,
                        input_data: mutated,
                        input_size: 0,
                        stack_trace: None,
                        registers: None,
                        signal: None,
                        exit_code: None,
                        stderr_output: Some(e.to_string()),
                        reproduced: false,
                        reproduction_count: 1,
                        minimized_input: None,
                        notes: None,
                        created_at: Utc::now(),
                    });
                }
                Err(_) => {
                    // Timeout
                    crashes.push(FuzzingCrash {
                        id: uuid::Uuid::new_v4().to_string(),
                        campaign_id: String::new(),
                        crash_type: CrashType::Hang,
                        crash_hash: self.hash_input(&mutated),
                        exploitability: Exploitability::Unknown,
                        input_data: mutated,
                        input_size: 0,
                        stack_trace: None,
                        registers: None,
                        signal: None,
                        exit_code: None,
                        stderr_output: Some("Process timeout".to_string()),
                        reproduced: false,
                        reproduction_count: 1,
                        minimized_input: None,
                        notes: None,
                        created_at: Utc::now(),
                    });
                }
            }

            // Progress output
            if i % 100 == 0 && i > 0 {
                log::debug!("File fuzzer: {} iterations, {} crashes", i, crashes.len());
            }
        }

        crashes
    }

    /// Create a file format template
    pub fn create_template(&self, format: &str) -> Option<Vec<u8>> {
        match format.to_lowercase().as_str() {
            "png" => Some(self.create_png_template()),
            "jpeg" | "jpg" => Some(self.create_jpeg_template()),
            "gif" => Some(self.create_gif_template()),
            "pdf" => Some(self.create_pdf_template()),
            "zip" => Some(self.create_zip_template()),
            "elf" => Some(self.create_elf_template()),
            "pe" => Some(self.create_pe_template()),
            _ => None,
        }
    }

    /// Create minimal PNG template
    fn create_png_template(&self) -> Vec<u8> {
        vec![
            // PNG signature
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            // IHDR chunk
            0x00, 0x00, 0x00, 0x0D, // Length
            0x49, 0x48, 0x44, 0x52, // Type: IHDR
            0x00, 0x00, 0x00, 0x01, // Width: 1
            0x00, 0x00, 0x00, 0x01, // Height: 1
            0x08, // Bit depth
            0x02, // Color type (RGB)
            0x00, // Compression
            0x00, // Filter
            0x00, // Interlace
            0x90, 0x77, 0x53, 0xDE, // CRC
            // IDAT chunk (minimal)
            0x00, 0x00, 0x00, 0x0C,
            0x49, 0x44, 0x41, 0x54,
            0x08, 0xD7, 0x63, 0xF8, 0xFF, 0xFF, 0xFF, 0x00,
            0x05, 0xFE, 0x02, 0xFE,
            // IEND chunk
            0x00, 0x00, 0x00, 0x00,
            0x49, 0x45, 0x4E, 0x44,
            0xAE, 0x42, 0x60, 0x82,
        ]
    }

    /// Create minimal JPEG template
    fn create_jpeg_template(&self) -> Vec<u8> {
        vec![
            // SOI
            0xFF, 0xD8,
            // APP0 JFIF
            0xFF, 0xE0, 0x00, 0x10,
            0x4A, 0x46, 0x49, 0x46, 0x00, // JFIF
            0x01, 0x01, // Version
            0x00, // Density units
            0x00, 0x01, // X density
            0x00, 0x01, // Y density
            0x00, 0x00, // Thumbnail size
            // DQT
            0xFF, 0xDB, 0x00, 0x43, 0x00,
            0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07,
            0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14,
            0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12, 0x13,
            0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A,
            0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20, 0x22,
            0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29, 0x2C,
            0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39,
            0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34, 0x32,
            // SOF0
            0xFF, 0xC0, 0x00, 0x0B, 0x08,
            0x00, 0x01, // Height
            0x00, 0x01, // Width
            0x01, // Components
            0x01, 0x11, 0x00,
            // DHT
            0xFF, 0xC4, 0x00, 0x1F, 0x00,
            0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            // SOS
            0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00,
            0x3F, 0x00, 0x7F, 0xFF,
            // EOI
            0xFF, 0xD9,
        ]
    }

    /// Create minimal GIF template
    fn create_gif_template(&self) -> Vec<u8> {
        vec![
            // Header
            0x47, 0x49, 0x46, 0x38, 0x39, 0x61, // GIF89a
            // Logical screen descriptor
            0x01, 0x00, // Width
            0x01, 0x00, // Height
            0x00, // Packed (no GCT)
            0x00, // Background
            0x00, // Aspect ratio
            // Image descriptor
            0x2C,
            0x00, 0x00, // Left
            0x00, 0x00, // Top
            0x01, 0x00, // Width
            0x01, 0x00, // Height
            0x00, // Packed
            // Image data
            0x02, // LZW minimum code size
            0x02, 0x44, 0x01, // Sub-block
            0x00, // Block terminator
            // Trailer
            0x3B,
        ]
    }

    /// Create minimal PDF template
    fn create_pdf_template(&self) -> Vec<u8> {
        let pdf = br#"%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
211
%%EOF"#;
        pdf.to_vec()
    }

    /// Create minimal ZIP template
    fn create_zip_template(&self) -> Vec<u8> {
        vec![
            // Local file header
            0x50, 0x4B, 0x03, 0x04, // Signature
            0x0A, 0x00, // Version
            0x00, 0x00, // Flags
            0x00, 0x00, // Compression
            0x00, 0x00, // Mod time
            0x00, 0x00, // Mod date
            0x00, 0x00, 0x00, 0x00, // CRC32
            0x00, 0x00, 0x00, 0x00, // Compressed size
            0x00, 0x00, 0x00, 0x00, // Uncompressed size
            0x05, 0x00, // Filename length
            0x00, 0x00, // Extra field length
            0x74, 0x65, 0x73, 0x74, 0x00, // Filename: test
            // Central directory
            0x50, 0x4B, 0x01, 0x02,
            0x1E, 0x03, 0x0A, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x05, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
            0x74, 0x65, 0x73, 0x74, 0x00,
            // End of central directory
            0x50, 0x4B, 0x05, 0x06,
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00,
            0x33, 0x00, 0x00, 0x00,
            0x27, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]
    }

    /// Create minimal ELF template
    fn create_elf_template(&self) -> Vec<u8> {
        vec![
            // ELF header
            0x7F, 0x45, 0x4C, 0x46, // Magic
            0x02, // 64-bit
            0x01, // Little endian
            0x01, // ELF version
            0x00, // OS/ABI
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
            0x02, 0x00, // Type: EXEC
            0x3E, 0x00, // Machine: x86-64
            0x01, 0x00, 0x00, 0x00, // Version
            0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // Entry point
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Program header offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Section header offset
            0x00, 0x00, 0x00, 0x00, // Flags
            0x40, 0x00, // Header size
            0x38, 0x00, // Program header entry size
            0x01, 0x00, // Number of program headers
            0x00, 0x00, // Section header entry size
            0x00, 0x00, // Number of section headers
            0x00, 0x00, // Section name string table index
            // Program header (LOAD)
            0x01, 0x00, 0x00, 0x00, // Type: LOAD
            0x05, 0x00, 0x00, 0x00, // Flags: R+X
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Offset
            0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // Virtual address
            0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // Physical address
            0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // File size
            0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Memory size
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Alignment
        ]
    }

    /// Create minimal PE template
    fn create_pe_template(&self) -> Vec<u8> {
        vec![
            // DOS header
            0x4D, 0x5A, // MZ signature
            0x90, 0x00, // Bytes on last page
            0x03, 0x00, // Pages in file
            0x00, 0x00, // Relocations
            0x04, 0x00, // Size of header in paragraphs
            0x00, 0x00, // Min extra paragraphs
            0xFF, 0xFF, // Max extra paragraphs
            0x00, 0x00, // Initial SS
            0xB8, 0x00, // Initial SP
            0x00, 0x00, // Checksum
            0x00, 0x00, // Initial IP
            0x00, 0x00, // Initial CS
            0x40, 0x00, // Relocation table offset
            0x00, 0x00, // Overlay number
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00, // OEM ID
            0x00, 0x00, // OEM info
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00, 0x00, 0x00, // Reserved
            0x80, 0x00, 0x00, 0x00, // PE header offset
            // DOS stub (padding)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // PE signature
            0x50, 0x45, 0x00, 0x00,
            // COFF header
            0x64, 0x86, // Machine: AMD64
            0x01, 0x00, // Number of sections
            0x00, 0x00, 0x00, 0x00, // Time stamp
            0x00, 0x00, 0x00, 0x00, // Symbol table pointer
            0x00, 0x00, 0x00, 0x00, // Number of symbols
            0xF0, 0x00, // Size of optional header
            0x22, 0x00, // Characteristics: EXEC, LARGE_ADDRESS_AWARE
        ]
    }

    /// Hash input for deduplication
    fn hash_input(&self, input: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(input);
        format!("{:x}", hasher.finalize())
    }
}

impl Default for FileFuzzer {
    fn default() -> Self {
        Self::new()
    }
}
