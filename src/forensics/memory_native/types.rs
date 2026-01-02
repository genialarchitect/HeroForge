//! Native memory forensics types
//!
//! Core types for native memory dump analysis.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Memory dump format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DumpFormat {
    /// Raw memory dump (dd-style)
    Raw,
    /// Windows crash dump (.dmp)
    CrashDump,
    /// Windows hibernation file (hiberfil.sys)
    Hibernation,
    /// VMware snapshot (.vmem)
    VMware,
    /// VirtualBox snapshot (.sav)
    VirtualBox,
    /// Hyper-V snapshot (.bin/.vsv)
    HyperV,
    /// QEMU snapshot (.qcow2)
    Qemu,
    /// LiME format (Linux)
    LiME,
    /// EWF (Expert Witness Format)
    EWF,
    /// Unknown format
    Unknown,
}

impl DumpFormat {
    /// Detect format from file header
    pub fn detect(header: &[u8]) -> Self {
        if header.len() < 8 {
            return Self::Unknown;
        }

        // Windows crash dump: "PAGEDUMP" or "PAGEDU64"
        if &header[0..8] == b"PAGEDUMP" || &header[0..8] == b"PAGEDU64" {
            return Self::CrashDump;
        }

        // Hibernation file: "hibr" or "HIBR"
        if &header[0..4] == b"hibr" || &header[0..4] == b"HIBR" || &header[0..4] == b"wake" {
            return Self::Hibernation;
        }

        // VMware: specific pattern in .vmem files
        // Usually paired with .vmss/.vmsn snapshot
        if header.starts_with(&[0x00, 0x00, 0x00, 0x00]) && header.len() > 16 {
            // Check for specific VMware patterns - simplified
            // Real detection would check for VMDK/VMEM markers
        }

        // VirtualBox saved state
        if header.len() >= 12 && &header[0..4] == b"VBOX" {
            return Self::VirtualBox;
        }

        // LiME format: specific header
        if header.len() >= 8 {
            if u32::from_le_bytes([header[0], header[1], header[2], header[3]]) == 0x4C694D45 {
                return Self::LiME;
            }
        }

        // EWF (E01): starts with "EVF"
        if header.len() >= 3 && &header[0..3] == b"EVF" {
            return Self::EWF;
        }

        // Default to raw if no signature detected
        Self::Raw
    }

    /// Get file extensions for this format
    pub fn extensions(&self) -> &[&str] {
        match self {
            Self::Raw => &[".raw", ".bin", ".mem", ".dd"],
            Self::CrashDump => &[".dmp", ".dump"],
            Self::Hibernation => &["hiberfil.sys"],
            Self::VMware => &[".vmem", ".vmss", ".vmsn"],
            Self::VirtualBox => &[".sav"],
            Self::HyperV => &[".bin", ".vsv"],
            Self::Qemu => &[".qcow2", ".qcow"],
            Self::LiME => &[".lime"],
            Self::EWF => &[".e01", ".ex01"],
            Self::Unknown => &[],
        }
    }
}

/// Memory dump header info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpInfo {
    /// Detected format
    pub format: DumpFormat,
    /// File size in bytes
    pub file_size: u64,
    /// Expected physical memory size
    pub memory_size: Option<u64>,
    /// Operating system detected
    pub os_type: Option<OsType>,
    /// Architecture
    pub architecture: Architecture,
    /// Number of processors (if detectable)
    pub num_processors: Option<u32>,
    /// Dump timestamp (if available)
    pub timestamp: Option<DateTime<Utc>>,
    /// Page size
    pub page_size: u32,
    /// Kernel base address
    pub kernel_base: Option<u64>,
}

impl Default for DumpInfo {
    fn default() -> Self {
        Self {
            format: DumpFormat::Unknown,
            file_size: 0,
            memory_size: None,
            os_type: None,
            architecture: Architecture::Unknown,
            num_processors: None,
            timestamp: None,
            page_size: 4096,
            kernel_base: None,
        }
    }
}

/// Operating system type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsType {
    Windows,
    Linux,
    MacOS,
    FreeBSD,
    Unknown,
}

/// CPU architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    X86,
    X64,
    Arm,
    Arm64,
    Unknown,
}

/// Windows EPROCESS structure fields we care about
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Virtual address of EPROCESS structure
    pub eprocess_addr: u64,
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Process name (ImageFileName)
    pub name: String,
    /// Full path (if available)
    pub path: Option<String>,
    /// Command line (if available)
    pub cmdline: Option<String>,
    /// Create time
    pub create_time: Option<DateTime<Utc>>,
    /// Exit time (if exited)
    pub exit_time: Option<DateTime<Utc>>,
    /// Process directory table base (CR3)
    pub dtb: u64,
    /// PEB address
    pub peb: u64,
    /// Session ID
    pub session_id: Option<u32>,
    /// Is WoW64 process
    pub is_wow64: bool,
    /// Thread count
    pub thread_count: u32,
    /// Handle count
    pub handle_count: u32,
    /// Exit status
    pub exit_status: Option<u32>,
    /// Integrity level
    pub integrity: Option<String>,
    /// Token information
    pub token_user: Option<String>,
}

/// DLL/module loaded in a process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    /// Process ID
    pub pid: u32,
    /// Base address
    pub base_addr: u64,
    /// Size in bytes
    pub size: u64,
    /// Module name
    pub name: String,
    /// Full path
    pub path: String,
    /// Entry point
    pub entry_point: u64,
    /// Is main executable
    pub is_main: bool,
}

/// Network connection from memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    /// Owning process ID
    pub pid: u32,
    /// Protocol (TCP/UDP)
    pub protocol: String,
    /// Local IP address
    pub local_addr: String,
    /// Local port
    pub local_port: u16,
    /// Remote IP address
    pub remote_addr: Option<String>,
    /// Remote port
    pub remote_port: Option<u16>,
    /// Connection state
    pub state: String,
    /// Create time
    pub create_time: Option<DateTime<Utc>>,
}

/// Kernel module (driver)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverInfo {
    /// Base address
    pub base_addr: u64,
    /// Size
    pub size: u64,
    /// Driver name
    pub name: String,
    /// Full path
    pub path: String,
    /// Service name
    pub service_name: Option<String>,
    /// Load order
    pub load_order: Option<u32>,
}

/// Registry key from memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryKey {
    /// Key path
    pub path: String,
    /// Last write time
    pub last_write_time: Option<DateTime<Utc>>,
    /// Number of subkeys
    pub subkey_count: u32,
    /// Number of values
    pub value_count: u32,
}

/// Registry value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValue {
    /// Parent key path
    pub key_path: String,
    /// Value name
    pub name: String,
    /// Value type (REG_SZ, REG_DWORD, etc.)
    pub value_type: String,
    /// Value data (as hex or string)
    pub data: String,
}

/// Extracted credential from memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedCredential {
    /// Source (lsass, browser, etc.)
    pub source: String,
    /// Credential type
    pub cred_type: CredentialType,
    /// Username
    pub username: Option<String>,
    /// Domain
    pub domain: Option<String>,
    /// Password or hash
    pub secret: String,
    /// Is this a hash or plaintext
    pub is_hash: bool,
    /// Process that held the credential
    pub pid: Option<u32>,
}

/// Type of extracted credential
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    NtHash,
    LmHash,
    Password,
    KerberosTicket,
    WDigest,
    Msv1_0,
    Dpapi,
    Ssp,
    LiveSsp,
    CloudAp,
    Other,
}

/// Injection detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionResult {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Virtual address of suspicious region
    pub address: u64,
    /// Size of region
    pub size: u64,
    /// Memory protection flags
    pub protection: String,
    /// Detection type
    pub detection_type: InjectionType,
    /// Hexdump of first bytes
    pub hexdump: String,
    /// Disassembly (if code)
    pub disasm: Option<String>,
    /// Confidence score (0-100)
    pub confidence: u8,
}

/// Type of code injection detected
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionType {
    /// Classic code injection
    CodeInjection,
    /// Reflective DLL injection
    ReflectiveDll,
    /// Process hollowing
    ProcessHollowing,
    /// API hooking
    ApiHook,
    /// Shellcode
    Shellcode,
    /// AtomBombing
    AtomBombing,
    /// Process doppelgänging
    ProcessDoppelganging,
    /// Unknown/Other
    Unknown,
}

/// Analysis result containing all findings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryAnalysisResult {
    /// Dump information
    pub dump_info: DumpInfo,
    /// Extracted processes
    pub processes: Vec<ProcessInfo>,
    /// Hidden processes detected
    pub hidden_processes: Vec<ProcessInfo>,
    /// Loaded modules
    pub modules: Vec<ModuleInfo>,
    /// Network connections
    pub connections: Vec<NetworkConnection>,
    /// Kernel modules/drivers
    pub drivers: Vec<DriverInfo>,
    /// Extracted credentials
    pub credentials: Vec<ExtractedCredential>,
    /// Injection detections
    pub injections: Vec<InjectionResult>,
    /// Registry keys (selected)
    pub registry_keys: Vec<RegistryKey>,
    /// Analysis warnings/notes
    pub notes: Vec<String>,
    /// Errors encountered
    pub errors: Vec<String>,
}

/// Linux task_struct information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LinuxTask {
    /// Task struct address
    pub task_addr: u64,
    /// Process ID
    pub pid: i32,
    /// Thread group ID
    pub tgid: i32,
    /// Parent PID
    pub ppid: i32,
    /// Process name (comm)
    pub comm: String,
    /// State
    pub state: String,
    /// UID
    pub uid: u32,
    /// GID
    pub gid: u32,
    /// EUID
    pub euid: u32,
    /// mm_struct address
    pub mm: u64,
    /// Page table base
    pub pgd: u64,
    /// Start time
    pub start_time: Option<u64>,
}

/// Linux kernel module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxModule {
    /// Module base address
    pub base_addr: u64,
    /// Module size
    pub size: u64,
    /// Module name
    pub name: String,
    /// Arguments
    pub args: Option<String>,
    /// Reference count
    pub refcount: i32,
    /// Is module tainted
    pub tainted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dump_format_detect() {
        // Crash dump
        assert_eq!(
            DumpFormat::detect(b"PAGEDUMP"),
            DumpFormat::CrashDump
        );

        // 64-bit crash dump
        assert_eq!(
            DumpFormat::detect(b"PAGEDU64"),
            DumpFormat::CrashDump
        );

        // Hibernation
        assert_eq!(
            DumpFormat::detect(b"hibr    "),
            DumpFormat::Hibernation
        );

        // Unknown/raw
        assert_eq!(
            DumpFormat::detect(b"\x00\x00\x00\x00"),
            DumpFormat::Raw
        );
    }

    #[test]
    fn test_dump_format_extensions() {
        assert!(DumpFormat::CrashDump.extensions().contains(&".dmp"));
        assert!(DumpFormat::VMware.extensions().contains(&".vmem"));
        assert!(DumpFormat::Raw.extensions().contains(&".raw"));
    }
}
