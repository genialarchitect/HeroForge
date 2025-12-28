//! File Carving Module
//!
//! Extract files from network streams:
//! - Magic byte detection
//! - HTTP response extraction
//! - SMTP attachment extraction
//! - FTP transfer capture
//! - SMB file transfer capture

use crate::traffic_analysis::types::*;
use chrono::Utc;
use md5::Md5;
use std::collections::HashMap;

/// File carver for network streams
pub struct FileCarver {
    /// Extracted files
    extracted_files: Vec<ExtractedFile>,
    /// Ongoing extractions (session_id -> partial file)
    ongoing: HashMap<String, PartialFile>,
    /// Configuration
    config: CarverConfig,
}

/// Partial file being reassembled
#[derive(Debug)]
struct PartialFile {
    filename: Option<String>,
    mime_type: Option<String>,
    data: Vec<u8>,
    expected_size: Option<usize>,
    extraction_method: ExtractionMethod,
}

/// File carving configuration
#[derive(Debug, Clone)]
pub struct CarverConfig {
    /// Maximum file size to extract
    pub max_file_size: usize,
    /// Storage directory
    pub storage_dir: String,
    /// Extract executables
    pub extract_executables: bool,
    /// Extract documents
    pub extract_documents: bool,
    /// Extract images
    pub extract_images: bool,
    /// Extract archives
    pub extract_archives: bool,
}

impl Default for CarverConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024, // 100MB
            storage_dir: "/tmp/heroforge_carved".to_string(),
            extract_executables: true,
            extract_documents: true,
            extract_images: true,
            extract_archives: true,
        }
    }
}

/// Magic bytes signatures
struct MagicSignature {
    magic: &'static [u8],
    offset: usize,
    mime_type: &'static str,
    extension: &'static str,
    category: FileCategory,
}

#[derive(Debug, Clone, PartialEq)]
enum FileCategory {
    Executable,
    Document,
    Image,
    Archive,
    Script,
    Other,
}

impl FileCarver {
    /// Create a new file carver
    pub fn new() -> Self {
        Self::with_config(CarverConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: CarverConfig) -> Self {
        // Create storage directory
        let _ = std::fs::create_dir_all(&config.storage_dir);

        Self {
            extracted_files: Vec::new(),
            ongoing: HashMap::new(),
            config,
        }
    }

    /// Get magic signatures
    fn get_signatures() -> Vec<MagicSignature> {
        vec![
            // Executables
            MagicSignature { magic: b"MZ", offset: 0, mime_type: "application/x-dosexec", extension: "exe", category: FileCategory::Executable },
            MagicSignature { magic: b"\x7fELF", offset: 0, mime_type: "application/x-elf", extension: "elf", category: FileCategory::Executable },
            MagicSignature { magic: b"\xfe\xed\xfa\xce", offset: 0, mime_type: "application/x-mach-binary", extension: "macho", category: FileCategory::Executable },
            MagicSignature { magic: b"\xfe\xed\xfa\xcf", offset: 0, mime_type: "application/x-mach-binary", extension: "macho", category: FileCategory::Executable },
            MagicSignature { magic: b"\xca\xfe\xba\xbe", offset: 0, mime_type: "application/java-archive", extension: "class", category: FileCategory::Executable },

            // Documents
            MagicSignature { magic: b"%PDF", offset: 0, mime_type: "application/pdf", extension: "pdf", category: FileCategory::Document },
            MagicSignature { magic: b"PK\x03\x04", offset: 0, mime_type: "application/zip", extension: "zip", category: FileCategory::Archive },
            MagicSignature { magic: b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", offset: 0, mime_type: "application/msword", extension: "doc", category: FileCategory::Document },
            MagicSignature { magic: b"{\rtf", offset: 0, mime_type: "application/rtf", extension: "rtf", category: FileCategory::Document },

            // Images
            MagicSignature { magic: b"\xff\xd8\xff", offset: 0, mime_type: "image/jpeg", extension: "jpg", category: FileCategory::Image },
            MagicSignature { magic: b"\x89PNG\r\n\x1a\n", offset: 0, mime_type: "image/png", extension: "png", category: FileCategory::Image },
            MagicSignature { magic: b"GIF87a", offset: 0, mime_type: "image/gif", extension: "gif", category: FileCategory::Image },
            MagicSignature { magic: b"GIF89a", offset: 0, mime_type: "image/gif", extension: "gif", category: FileCategory::Image },
            MagicSignature { magic: b"BM", offset: 0, mime_type: "image/bmp", extension: "bmp", category: FileCategory::Image },
            MagicSignature { magic: b"RIFF", offset: 0, mime_type: "image/webp", extension: "webp", category: FileCategory::Image },

            // Archives
            MagicSignature { magic: b"\x1f\x8b", offset: 0, mime_type: "application/gzip", extension: "gz", category: FileCategory::Archive },
            MagicSignature { magic: b"BZh", offset: 0, mime_type: "application/x-bzip2", extension: "bz2", category: FileCategory::Archive },
            MagicSignature { magic: b"\xfd7zXZ\x00", offset: 0, mime_type: "application/x-xz", extension: "xz", category: FileCategory::Archive },
            MagicSignature { magic: b"Rar!\x1a\x07", offset: 0, mime_type: "application/x-rar-compressed", extension: "rar", category: FileCategory::Archive },
            MagicSignature { magic: b"7z\xbc\xaf\x27\x1c", offset: 0, mime_type: "application/x-7z-compressed", extension: "7z", category: FileCategory::Archive },

            // Scripts
            MagicSignature { magic: b"#!/", offset: 0, mime_type: "text/x-script", extension: "sh", category: FileCategory::Script },
            MagicSignature { magic: b"<?php", offset: 0, mime_type: "application/x-php", extension: "php", category: FileCategory::Script },
            MagicSignature { magic: b"<%", offset: 0, mime_type: "application/x-asp", extension: "asp", category: FileCategory::Script },
        ]
    }

    /// Carve files from raw data
    pub fn carve_from_data(&mut self, session_id: &str, data: &[u8]) -> Vec<ExtractedFile> {
        let mut carved = Vec::new();

        for sig in Self::get_signatures() {
            // Check if category is enabled
            let enabled = match sig.category {
                FileCategory::Executable => self.config.extract_executables,
                FileCategory::Document => self.config.extract_documents,
                FileCategory::Image => self.config.extract_images,
                FileCategory::Archive => self.config.extract_archives,
                FileCategory::Script => self.config.extract_executables,
                FileCategory::Other => true,
            };

            if !enabled {
                continue;
            }

            // Search for magic bytes
            let mut offset = 0;
            while offset + sig.magic.len() <= data.len() {
                if &data[offset + sig.offset..offset + sig.offset + sig.magic.len()] == sig.magic {
                    // Found a file
                    if let Some(file) = self.extract_file(session_id, &data[offset..], &sig) {
                        carved.push(file);
                    }

                    // Move past this match
                    offset += 1;
                } else {
                    offset += 1;
                }
            }
        }

        self.extracted_files.extend(carved.clone());
        carved
    }

    /// Extract a single file from data
    fn extract_file(&self, session_id: &str, data: &[u8], sig: &MagicSignature) -> Option<ExtractedFile> {
        // Determine file size
        let file_size = self.find_file_end(data, sig)?;

        if file_size > self.config.max_file_size {
            return None;
        }

        let file_data = &data[..file_size];

        // Calculate hashes
        use sha2::Digest;
        let md5 = format!("{:x}", Md5::digest(file_data));
        let sha256 = format!("{:x}", sha2::Sha256::digest(file_data));

        // Generate filename
        let filename = format!("{}_{}.{}", &sha256[..8], Utc::now().timestamp(), sig.extension);

        // Save to disk
        let storage_path = format!("{}/{}", self.config.storage_dir, filename);
        if std::fs::write(&storage_path, file_data).is_err() {
            return None;
        }

        // Check if executable
        let is_executable = matches!(sig.category, FileCategory::Executable | FileCategory::Script);

        Some(ExtractedFile {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            filename: Some(filename),
            mime_type: sig.mime_type.to_string(),
            size: file_size as u64,
            md5,
            sha256,
            storage_path,
            extraction_method: ExtractionMethod::MagicCarving,
            is_executable,
            is_malicious: None,
            extracted_at: Utc::now(),
        })
    }

    /// Find the end of a file
    fn find_file_end(&self, data: &[u8], sig: &MagicSignature) -> Option<usize> {
        match sig.extension {
            "jpg" => self.find_jpeg_end(data),
            "png" => self.find_png_end(data),
            "gif" => self.find_gif_end(data),
            "pdf" => self.find_pdf_end(data),
            "zip" => self.find_zip_end(data),
            _ => self.find_generic_end(data, sig),
        }
    }

    /// Find JPEG file end
    fn find_jpeg_end(&self, data: &[u8]) -> Option<usize> {
        // JPEG ends with FF D9
        for i in 2..data.len() {
            if data[i - 1] == 0xff && data[i] == 0xd9 {
                return Some(i + 1);
            }
        }
        None
    }

    /// Find PNG file end
    fn find_png_end(&self, data: &[u8]) -> Option<usize> {
        // PNG ends with IEND chunk
        let iend = b"\x49\x45\x4e\x44\xae\x42\x60\x82";
        for i in 0..data.len().saturating_sub(iend.len()) {
            if &data[i..i + iend.len()] == iend {
                return Some(i + iend.len());
            }
        }
        None
    }

    /// Find GIF file end
    fn find_gif_end(&self, data: &[u8]) -> Option<usize> {
        // GIF ends with 0x3B
        for i in 6..data.len() {
            if data[i] == 0x3b {
                return Some(i + 1);
            }
        }
        None
    }

    /// Find PDF file end
    fn find_pdf_end(&self, data: &[u8]) -> Option<usize> {
        // PDF ends with %%EOF
        let eof = b"%%EOF";
        for i in 0..data.len().saturating_sub(eof.len()) {
            if &data[i..i + eof.len()] == eof {
                return Some(i + eof.len() + 1);
            }
        }
        // If no EOF found, try to find a reasonable size
        Some(data.len().min(self.config.max_file_size))
    }

    /// Find ZIP file end
    fn find_zip_end(&self, data: &[u8]) -> Option<usize> {
        // ZIP End of Central Directory signature: PK\x05\x06
        let eocd = b"PK\x05\x06";
        for i in (0..data.len().saturating_sub(eocd.len())).rev() {
            if &data[i..i + eocd.len()] == eocd {
                // EOCD record is at least 22 bytes
                if i + 22 <= data.len() {
                    // Comment length is at offset 20-21
                    let comment_len = u16::from_le_bytes([data[i + 20], data[i + 21]]) as usize;
                    return Some(i + 22 + comment_len);
                }
            }
        }
        None
    }

    /// Generic file end finder
    fn find_generic_end(&self, data: &[u8], _sig: &MagicSignature) -> Option<usize> {
        // For unknown formats, take a reasonable chunk
        Some(data.len().min(self.config.max_file_size))
    }

    /// Process HTTP response for file extraction
    pub fn process_http_response(
        &mut self,
        session_id: &str,
        content_type: Option<&str>,
        content_disposition: Option<&str>,
        body: &[u8],
    ) -> Option<ExtractedFile> {
        if body.is_empty() || body.len() > self.config.max_file_size {
            return None;
        }

        // Determine MIME type
        let mime_type = content_type
            .map(|ct| ct.split(';').next().unwrap_or(ct).trim().to_string())
            .unwrap_or_else(|| self.detect_mime_type(body));

        // Parse filename from Content-Disposition
        let filename = content_disposition.and_then(|cd| {
            if let Some(start) = cd.find("filename=") {
                let rest = &cd[start + 9..];
                let name = rest.trim_matches('"').split(';').next()?;
                Some(name.to_string())
            } else {
                None
            }
        });

        // Calculate hashes
        use sha2::Digest;
        let md5 = format!("{:x}", Md5::digest(body));
        let sha256 = format!("{:x}", sha2::Sha256::digest(body));

        // Generate filename if not provided
        let filename = filename.unwrap_or_else(|| {
            let ext = self.mime_to_extension(&mime_type);
            format!("{}_{}.{}", &sha256[..8], Utc::now().timestamp(), ext)
        });

        // Save to disk
        let storage_path = format!("{}/{}", self.config.storage_dir, filename);
        if std::fs::write(&storage_path, body).is_err() {
            return None;
        }

        // Check if executable
        let is_executable = self.is_executable_mime(&mime_type) || self.is_executable_data(body);

        let file = ExtractedFile {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            filename: Some(filename),
            mime_type,
            size: body.len() as u64,
            md5,
            sha256,
            storage_path,
            extraction_method: ExtractionMethod::HttpResponse,
            is_executable,
            is_malicious: None,
            extracted_at: Utc::now(),
        };

        self.extracted_files.push(file.clone());
        Some(file)
    }

    /// Detect MIME type from data
    fn detect_mime_type(&self, data: &[u8]) -> String {
        for sig in Self::get_signatures() {
            if data.len() >= sig.offset + sig.magic.len() {
                if &data[sig.offset..sig.offset + sig.magic.len()] == sig.magic {
                    return sig.mime_type.to_string();
                }
            }
        }
        "application/octet-stream".to_string()
    }

    /// Convert MIME type to extension
    fn mime_to_extension(&self, mime: &str) -> &str {
        for sig in Self::get_signatures() {
            if sig.mime_type == mime {
                return sig.extension;
            }
        }
        "bin"
    }

    /// Check if MIME type is executable
    fn is_executable_mime(&self, mime: &str) -> bool {
        mime.contains("executable") ||
        mime.contains("x-dosexec") ||
        mime.contains("x-elf") ||
        mime.contains("x-mach") ||
        mime.contains("javascript") ||
        mime.contains("x-php") ||
        mime.contains("x-python") ||
        mime.contains("x-perl") ||
        mime.contains("x-ruby") ||
        mime.contains("x-sh")
    }

    /// Check if data is executable
    fn is_executable_data(&self, data: &[u8]) -> bool {
        if data.len() >= 2 && &data[..2] == b"MZ" {
            return true;
        }
        if data.len() >= 4 && &data[..4] == b"\x7fELF" {
            return true;
        }
        if data.len() >= 4 && (&data[..4] == b"\xfe\xed\xfa\xce" || &data[..4] == b"\xfe\xed\xfa\xcf") {
            return true;
        }
        if data.len() >= 2 && &data[..2] == b"#!" {
            return true;
        }
        false
    }

    /// Get all extracted files
    pub fn get_extracted_files(&self) -> &[ExtractedFile] {
        &self.extracted_files
    }

    /// Get executable files
    pub fn get_executables(&self) -> Vec<&ExtractedFile> {
        self.extracted_files.iter()
            .filter(|f| f.is_executable)
            .collect()
    }

    /// Get statistics
    pub fn get_statistics(&self) -> CarverStats {
        let total = self.extracted_files.len();
        let executables = self.extracted_files.iter().filter(|f| f.is_executable).count();
        let total_size: u64 = self.extracted_files.iter().map(|f| f.size).sum();

        CarverStats {
            files_extracted: total,
            executables_found: executables,
            total_bytes_extracted: total_size,
        }
    }
}

/// Carver statistics
#[derive(Debug, Clone)]
pub struct CarverStats {
    pub files_extracted: usize,
    pub executables_found: usize,
    pub total_bytes_extracted: u64,
}

impl Default for FileCarver {
    fn default() -> Self {
        Self::new()
    }
}
