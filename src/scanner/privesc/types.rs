use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for privilege escalation scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivescConfig {
    /// Target host (IP or hostname)
    pub target: String,
    /// SSH username for Linux targets
    pub ssh_username: Option<String>,
    /// SSH password (if using password auth)
    pub ssh_password: Option<String>,
    /// SSH private key path (if using key auth)
    pub ssh_key_path: Option<String>,
    /// SSH port (default 22)
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    /// WinRM username for Windows targets
    pub winrm_username: Option<String>,
    /// WinRM password
    pub winrm_password: Option<String>,
    /// WinRM port (default 5985)
    #[serde(default = "default_winrm_port")]
    pub winrm_port: u16,
    /// Use HTTPS for WinRM
    #[serde(default)]
    pub winrm_https: bool,
    /// Target OS type
    #[serde(default)]
    pub os_type: OsType,
    /// Run LinPEAS/WinPEAS
    #[serde(default = "default_true")]
    pub run_peas: bool,
    /// Custom checks to run
    #[serde(default)]
    pub custom_checks: Vec<String>,
    /// Timeout for each check in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_ssh_port() -> u16 {
    22
}

fn default_winrm_port() -> u16 {
    5985
}

fn default_true() -> bool {
    true
}

fn default_timeout() -> u64 {
    300 // 5 minutes for PEAS scripts
}

impl Default for PrivescConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            ssh_username: None,
            ssh_password: None,
            ssh_key_path: None,
            ssh_port: 22,
            winrm_username: None,
            winrm_password: None,
            winrm_port: 5985,
            winrm_https: false,
            os_type: OsType::Linux,
            run_peas: true,
            custom_checks: Vec::new(),
            timeout_secs: 300,
        }
    }
}

/// Target operating system type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OsType {
    #[default]
    Linux,
    Windows,
}

/// Status of a privilege escalation scan
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivescStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl Default for PrivescStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// Severity level for privesc findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivescSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Linux privilege escalation vector types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LinuxPrivescVector {
    /// SUID binary that can be exploited
    SuidBinary {
        path: String,
        owner: String,
        permissions: String,
        exploitable: bool,
        gtfobins_url: Option<String>,
    },
    /// Linux capability on a binary
    Capability {
        binary: String,
        capabilities: Vec<String>,
        exploitable: bool,
    },
    /// Writable cron job
    CronJob {
        path: String,
        schedule: String,
        command: String,
        writable: bool,
    },
    /// Exploitable sudo rule
    SudoRule {
        rule: String,
        exploitable: bool,
        gtfobins_url: Option<String>,
    },
    /// Kernel exploit possibility
    KernelExploit {
        kernel_version: String,
        cve: String,
        exploit_name: String,
        probability: String,
    },
    /// Writable service file
    WritableService {
        service: String,
        path: String,
    },
    /// Docker socket accessible
    DockerSocket {
        socket_path: String,
        user_in_group: bool,
    },
    /// Writable passwd/shadow
    WritablePasswd {
        file: String,
        writable: bool,
    },
    /// SSH key found
    SshKey {
        path: String,
        owner: String,
        accessible: bool,
    },
    /// NFS no_root_squash
    NfsNoRootSquash {
        export: String,
        options: String,
    },
    /// Writable PATH directory
    WritablePath {
        directory: String,
    },
    /// Interesting file found
    InterestingFile {
        path: String,
        description: String,
    },
    /// Password in file
    PasswordInFile {
        path: String,
        line_hint: String,
    },
    /// LD_PRELOAD hijack
    LdPreload {
        env_var: String,
        exploitable: bool,
    },
}

/// Windows privilege escalation vector types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WindowsPrivescVector {
    /// Unquoted service path
    UnquotedServicePath {
        service: String,
        path: String,
        can_restart: bool,
    },
    /// Weak service permissions
    WeakServicePermission {
        service: String,
        permission: String,
        identity: String,
    },
    /// AlwaysInstallElevated registry key
    AlwaysInstallElevated {
        hkcu: bool,
        hklm: bool,
    },
    /// SeImpersonatePrivilege enabled
    SeImpersonatePrivilege {
        user: String,
    },
    /// Token privileges
    TokenPrivilege {
        privilege: String,
        exploitable: bool,
        technique: String,
    },
    /// Unattended install files
    UnattendedInstall {
        path: String,
        contains_credentials: bool,
    },
    /// Scheduled task hijack
    ScheduledTaskHijack {
        task: String,
        path: String,
        writable: bool,
    },
    /// Modifiable service binary
    ModifiableServiceBinary {
        service: String,
        path: String,
    },
    /// Credential in registry
    RegistryCredential {
        path: String,
        value_name: String,
    },
    /// Weak folder permissions
    WeakFolderPermission {
        path: String,
        permission: String,
    },
    /// DLL hijacking opportunity
    DllHijack {
        application: String,
        dll_path: String,
        writable_directory: bool,
    },
    /// UAC bypass opportunity
    UacBypass {
        technique: String,
        binary: String,
    },
    /// Saved credentials
    SavedCredentials {
        target: String,
        username: String,
    },
    /// LOLBAS binary
    LolbasBinary {
        binary: String,
        technique: String,
        lolbas_url: Option<String>,
    },
}

/// A discovered privilege escalation finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivescFinding {
    pub id: String,
    pub severity: PrivescSeverity,
    pub title: String,
    pub description: String,
    pub os_type: OsType,
    /// Linux-specific vector (if Linux)
    pub linux_vector: Option<LinuxPrivescVector>,
    /// Windows-specific vector (if Windows)
    pub windows_vector: Option<WindowsPrivescVector>,
    /// Exploitation steps
    pub exploitation_steps: Vec<String>,
    /// References and URLs
    pub references: Vec<String>,
    /// Raw output from scanner
    pub raw_output: Option<String>,
    /// MITRE ATT&CK technique IDs
    pub mitre_techniques: Vec<String>,
    /// Timestamp
    pub discovered_at: chrono::DateTime<chrono::Utc>,
}

impl PrivescFinding {
    pub fn new_linux(
        severity: PrivescSeverity,
        title: String,
        description: String,
        vector: LinuxPrivescVector,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            severity,
            title,
            description,
            os_type: OsType::Linux,
            linux_vector: Some(vector),
            windows_vector: None,
            exploitation_steps: Vec::new(),
            references: Vec::new(),
            raw_output: None,
            mitre_techniques: Vec::new(),
            discovered_at: chrono::Utc::now(),
        }
    }

    pub fn new_windows(
        severity: PrivescSeverity,
        title: String,
        description: String,
        vector: WindowsPrivescVector,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            severity,
            title,
            description,
            os_type: OsType::Windows,
            linux_vector: None,
            windows_vector: Some(vector),
            exploitation_steps: Vec::new(),
            references: Vec::new(),
            raw_output: None,
            mitre_techniques: Vec::new(),
            discovered_at: chrono::Utc::now(),
        }
    }
}

/// Result of a privilege escalation scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivescResult {
    pub id: String,
    pub target: String,
    pub os_type: OsType,
    pub status: PrivescStatus,
    pub config: PrivescConfig,
    /// All discovered findings
    pub findings: Vec<PrivescFinding>,
    /// Summary statistics
    pub statistics: PrivescStatistics,
    /// System information collected
    pub system_info: SystemInfo,
    /// Raw LinPEAS/WinPEAS output
    pub peas_output: Option<String>,
    /// Errors encountered
    pub errors: Vec<String>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Statistics about the privesc scan
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrivescStatistics {
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub info_findings: usize,
    pub exploitable_count: usize,
    pub suid_binaries: usize,
    pub sudo_rules: usize,
    pub cron_jobs: usize,
    pub kernel_exploits: usize,
    pub service_issues: usize,
    pub credential_findings: usize,
}

/// System information collected during scan
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub architecture: Option<String>,
    pub current_user: Option<String>,
    pub current_groups: Vec<String>,
    pub users: Vec<String>,
    pub environment_variables: HashMap<String, String>,
    pub network_interfaces: Vec<NetworkInterface>,
    pub listening_ports: Vec<ListeningPort>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListeningPort {
    pub port: u16,
    pub protocol: String,
    pub process: Option<String>,
    pub user: Option<String>,
}

/// GTFOBins entry for a binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GtfobinsEntry {
    pub binary: String,
    pub functions: Vec<GtfobinsFunction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GtfobinsFunction {
    pub name: String, // shell, file-read, file-write, suid, sudo, etc.
    pub description: String,
    pub code: String,
}

/// LOLBAS entry for Windows binaries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LolbasEntry {
    pub name: String,
    pub description: String,
    pub author: Option<String>,
    pub commands: Vec<LolbasCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LolbasCommand {
    pub command: String,
    pub description: String,
    pub usecase: String,
    pub category: String,
    pub privileges: String,
    pub mitre_id: Option<String>,
}
