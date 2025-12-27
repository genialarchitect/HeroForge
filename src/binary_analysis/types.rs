//! Binary Analysis Types
//!
//! Core data structures for binary file analysis including PE/ELF parsing,
//! string extraction, entropy analysis, and hash computation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Supported binary file types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryType {
    Pe,      // Windows Portable Executable
    Elf,     // Linux ELF
    MachO,   // macOS Mach-O
    Archive, // ZIP, RAR, etc.
    Unknown,
}

impl std::fmt::Display for BinaryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryType::Pe => write!(f, "PE"),
            BinaryType::Elf => write!(f, "ELF"),
            BinaryType::MachO => write!(f, "Mach-O"),
            BinaryType::Archive => write!(f, "Archive"),
            BinaryType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// CPU architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86,
    X64,
    Arm,
    Arm64,
    Mips,
    PowerPc,
    Unknown,
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Architecture::X86 => write!(f, "x86"),
            Architecture::X64 => write!(f, "x64"),
            Architecture::Arm => write!(f, "ARM"),
            Architecture::Arm64 => write!(f, "ARM64"),
            Architecture::Mips => write!(f, "MIPS"),
            Architecture::PowerPc => write!(f, "PowerPC"),
            Architecture::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Analysis status for samples
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

/// String encoding types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// Categorized string types found in binaries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringType {
    Url,
    Ip,
    Email,
    FilePath,
    RegistryKey,
    Command,
    Crypto,      // Crypto-related strings
    Network,     // Network-related strings
    Debug,       // Debug/error messages
    Interesting, // Other interesting strings
    Generic,     // Generic strings
}

/// Hash values for a binary sample
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BinaryHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub ssdeep: Option<String>,
    pub imphash: Option<String>,  // PE import hash
    pub tlsh: Option<String>,     // Trend Micro Locality Sensitive Hash
}

/// PE section information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub raw_offset: u64,
    pub characteristics: u32,
    pub entropy: f64,
    pub is_executable: bool,
    pub is_writable: bool,
}

/// PE import information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeImport {
    pub dll_name: String,
    pub functions: Vec<String>,
}

/// PE export information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeExport {
    pub name: String,
    pub ordinal: u32,
    pub address: u64,
}

/// PE resource information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeResource {
    pub resource_type: String,
    pub name: String,
    pub language: u32,
    pub size: u64,
    pub entropy: f64,
}

/// PE-specific analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeAnalysis {
    pub machine_type: String,
    pub subsystem: String,
    pub image_base: u64,
    pub entry_point: u64,
    pub timestamp: Option<DateTime<Utc>>,
    pub is_dll: bool,
    pub is_64bit: bool,
    pub has_debug_info: bool,
    pub has_tls: bool,
    pub has_rich_header: bool,
    pub checksum_valid: bool,
    pub sections: Vec<PeSection>,
    pub imports: Vec<PeImport>,
    pub exports: Vec<PeExport>,
    pub resources: Vec<PeResource>,
    pub version_info: Option<VersionInfo>,
    pub certificates: Vec<CertificateInfo>,
}

/// Version information from PE resources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    pub company_name: Option<String>,
    pub product_name: Option<String>,
    pub file_description: Option<String>,
    pub original_filename: Option<String>,
    pub internal_name: Option<String>,
    pub legal_copyright: Option<String>,
}

/// Digital certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub is_valid: bool,
    pub signature_algorithm: String,
}

/// ELF section information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfSection {
    pub name: String,
    pub section_type: String,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub flags: u64,
    pub entropy: f64,
    pub is_executable: bool,
    pub is_writable: bool,
}

/// ELF symbol information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfSymbol {
    pub name: String,
    pub symbol_type: String,
    pub binding: String,
    pub address: u64,
    pub size: u64,
    pub section_index: u16,
}

/// ELF dynamic library dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfDynamic {
    pub name: String,
    pub path: Option<String>,
}

/// ELF-specific analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfAnalysis {
    pub machine_type: String,
    pub elf_type: String,           // EXEC, DYN, REL
    pub os_abi: String,
    pub entry_point: u64,
    pub is_64bit: bool,
    pub is_pie: bool,               // Position Independent Executable
    pub has_relro: bool,            // Read-only relocations
    pub has_nx: bool,               // No-execute stack
    pub has_stack_canary: bool,
    pub interpreter: Option<String>,
    pub sections: Vec<ElfSection>,
    pub symbols: Vec<ElfSymbol>,
    pub dynamic_libs: Vec<ElfDynamic>,
}

/// Extracted string with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub value: String,
    pub encoding: StringEncoding,
    pub offset: u64,
    pub section: Option<String>,
    pub string_type: StringType,
    pub is_interesting: bool,
}

/// Known packer/crypter signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerInfo {
    pub name: String,
    pub version: Option<String>,
    pub confidence: f64,  // 0.0 - 1.0
}

/// Binary sample with full analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinarySample {
    pub id: String,
    pub user_id: String,
    pub filename: String,
    pub file_size: u64,
    pub file_type: BinaryType,
    pub architecture: Architecture,
    pub hashes: BinaryHashes,
    pub entropy: f64,
    pub is_packed: bool,
    pub packer_info: Option<PackerInfo>,
    pub analysis_status: AnalysisStatus,
    pub pe_analysis: Option<PeAnalysis>,
    pub elf_analysis: Option<ElfAnalysis>,
    pub strings_count: u32,
    pub imports_count: u32,
    pub exports_count: u32,
    pub created_at: DateTime<Utc>,
    pub analyzed_at: Option<DateTime<Utc>>,
}

/// Simplified sample for list views
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinarySampleSummary {
    pub id: String,
    pub filename: String,
    pub file_size: u64,
    pub file_type: BinaryType,
    pub architecture: Architecture,
    pub sha256: String,
    pub entropy: f64,
    pub is_packed: bool,
    pub analysis_status: AnalysisStatus,
    pub strings_count: u32,
    pub imports_count: u32,
    pub created_at: DateTime<Utc>,
}

/// Upload request for binary analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadBinaryRequest {
    pub filename: String,
    pub analyze_strings: Option<bool>,
    pub analyze_imports: Option<bool>,
    pub min_string_length: Option<usize>,
}

/// Analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub extract_strings: bool,
    pub min_string_length: usize,
    pub max_strings: usize,
    pub compute_imphash: bool,
    pub compute_ssdeep: bool,
    pub detect_packers: bool,
    pub extract_resources: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            extract_strings: true,
            min_string_length: 4,
            max_strings: 10000,
            compute_imphash: true,
            compute_ssdeep: true,
            detect_packers: true,
            extract_resources: true,
        }
    }
}

/// Hex dump view data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexDumpData {
    pub offset: u64,
    pub hex_bytes: Vec<String>,
    pub ascii: String,
}

/// Hex view request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexViewRequest {
    pub offset: u64,
    pub length: usize,
}

/// Hex view response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexViewResponse {
    pub total_size: u64,
    pub offset: u64,
    pub length: usize,
    pub rows: Vec<HexDumpData>,
}

/// Statistics for binary analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BinaryAnalysisStats {
    pub total_samples: u64,
    pub pe_samples: u64,
    pub elf_samples: u64,
    pub packed_samples: u64,
    pub pending_analysis: u64,
    pub total_strings_extracted: u64,
    pub unique_packers_detected: u64,
}

/// Packer detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerSignature {
    pub name: String,
    pub version: Option<String>,
    pub signatures: Vec<PackerPattern>,
}

/// Pattern for packer detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerPattern {
    pub offset: PackerOffset,
    pub pattern: Vec<u8>,
    pub mask: Option<Vec<u8>>,  // None = exact match, Some = wildcard mask
}

/// Offset specification for packer patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackerOffset {
    EntryPoint(i64),  // Relative to entry point
    Absolute(u64),
    SectionStart(String, i64),  // Section name + offset
}

/// Disassembly instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyInstruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

/// Disassembly view response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResponse {
    pub start_address: u64,
    pub instructions: Vec<DisassemblyInstruction>,
    pub total_bytes: usize,
}

/// Cross-reference information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossReference {
    pub from_address: u64,
    pub to_address: u64,
    pub xref_type: XRefType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XRefType {
    Call,
    Jump,
    Data,
}
