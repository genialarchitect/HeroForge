//! SMB Native Protocol Types
//!
//! Core data structures for native SMB2/3 protocol implementation.

use serde::{Deserialize, Serialize};
use std::fmt;

/// SMB dialect versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmbDialect {
    Smb202,
    Smb210,
    Smb300,
    Smb302,
    Smb311,
}

impl SmbDialect {
    pub fn to_u16(self) -> u16 {
        match self {
            SmbDialect::Smb202 => 0x0202,
            SmbDialect::Smb210 => 0x0210,
            SmbDialect::Smb300 => 0x0300,
            SmbDialect::Smb302 => 0x0302,
            SmbDialect::Smb311 => 0x0311,
        }
    }

    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x0202 => Some(SmbDialect::Smb202),
            0x0210 => Some(SmbDialect::Smb210),
            0x0300 => Some(SmbDialect::Smb300),
            0x0302 => Some(SmbDialect::Smb302),
            0x0311 => Some(SmbDialect::Smb311),
            _ => None,
        }
    }
}

impl fmt::Display for SmbDialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmbDialect::Smb202 => write!(f, "SMB 2.0.2"),
            SmbDialect::Smb210 => write!(f, "SMB 2.1"),
            SmbDialect::Smb300 => write!(f, "SMB 3.0"),
            SmbDialect::Smb302 => write!(f, "SMB 3.0.2"),
            SmbDialect::Smb311 => write!(f, "SMB 3.1.1"),
        }
    }
}

/// SMB2 command codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Smb2Command {
    Negotiate = 0x0000,
    SessionSetup = 0x0001,
    Logoff = 0x0002,
    TreeConnect = 0x0003,
    TreeDisconnect = 0x0004,
    Create = 0x0005,
    Close = 0x0006,
    Flush = 0x0007,
    Read = 0x0008,
    Write = 0x0009,
    Lock = 0x000A,
    Ioctl = 0x000B,
    Cancel = 0x000C,
    Echo = 0x000D,
    QueryDirectory = 0x000E,
    ChangeNotify = 0x000F,
    QueryInfo = 0x0010,
    SetInfo = 0x0011,
    OplockBreak = 0x0012,
}

/// SMB2 header flags
pub mod smb2_flags {
    pub const SERVER_TO_REDIR: u32 = 0x00000001;
    pub const ASYNC_COMMAND: u32 = 0x00000002;
    pub const RELATED_OPERATIONS: u32 = 0x00000004;
    pub const SIGNED: u32 = 0x00000008;
    pub const PRIORITY_MASK: u32 = 0x00000070;
    pub const DFS_OPERATIONS: u32 = 0x10000000;
    pub const REPLAY_OPERATION: u32 = 0x20000000;
}

/// SMB2 negotiate capabilities
pub mod smb2_capabilities {
    pub const DFS: u32 = 0x00000001;
    pub const LEASING: u32 = 0x00000002;
    pub const LARGE_MTU: u32 = 0x00000004;
    pub const MULTI_CHANNEL: u32 = 0x00000008;
    pub const PERSISTENT_HANDLES: u32 = 0x00000010;
    pub const DIRECTORY_LEASING: u32 = 0x00000020;
    pub const ENCRYPTION: u32 = 0x00000040;
}

/// SMB2 session setup flags
pub mod session_flags {
    pub const BINDING: u8 = 0x01;
}

/// SMB2 tree connect flags
pub mod tree_connect_flags {
    pub const CLUSTER_RECONNECT: u16 = 0x0001;
    pub const REDIRECT_TO_OWNER: u16 = 0x0002;
    pub const EXTENSION_PRESENT: u16 = 0x0004;
}

/// SMB share type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShareType {
    Disk,
    Pipe,
    Print,
    Unknown(u8),
}

impl ShareType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0x01 => ShareType::Disk,
            0x02 => ShareType::Pipe,
            0x03 => ShareType::Print,
            other => ShareType::Unknown(other),
        }
    }
}

impl fmt::Display for ShareType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShareType::Disk => write!(f, "Disk"),
            ShareType::Pipe => write!(f, "IPC"),
            ShareType::Print => write!(f, "Print"),
            ShareType::Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

/// SMB share information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbShare {
    pub name: String,
    pub share_type: ShareType,
    pub remark: Option<String>,
    pub path: Option<String>,
    pub max_uses: Option<u32>,
    pub current_uses: Option<u32>,
    pub permissions: Option<u32>,
}

/// SMB session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbSession {
    pub user: String,
    pub client: String,
    pub num_opens: u32,
    pub time: u32,
    pub idle_time: u32,
    pub user_flags: u32,
}

/// SMB connection state
#[derive(Debug, Clone)]
pub struct SmbConnectionState {
    pub dialect: Option<SmbDialect>,
    pub session_id: u64,
    pub tree_id: u32,
    pub message_id: u64,
    pub signing_required: bool,
    pub encryption_supported: bool,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub max_transact_size: u32,
    pub server_guid: [u8; 16],
}

impl Default for SmbConnectionState {
    fn default() -> Self {
        Self {
            dialect: None,
            session_id: 0,
            tree_id: 0,
            message_id: 0,
            signing_required: false,
            encryption_supported: false,
            max_read_size: 65536,
            max_write_size: 65536,
            max_transact_size: 65536,
            server_guid: [0u8; 16],
        }
    }
}

impl SmbConnectionState {
    pub fn next_message_id(&mut self) -> u64 {
        let id = self.message_id;
        self.message_id += 1;
        id
    }
}

/// SMB file attributes
pub mod file_attributes {
    pub const READONLY: u32 = 0x00000001;
    pub const HIDDEN: u32 = 0x00000002;
    pub const SYSTEM: u32 = 0x00000004;
    pub const DIRECTORY: u32 = 0x00000010;
    pub const ARCHIVE: u32 = 0x00000020;
    pub const NORMAL: u32 = 0x00000080;
    pub const TEMPORARY: u32 = 0x00000100;
    pub const SPARSE_FILE: u32 = 0x00000200;
    pub const REPARSE_POINT: u32 = 0x00000400;
    pub const COMPRESSED: u32 = 0x00000800;
    pub const OFFLINE: u32 = 0x00001000;
    pub const NOT_CONTENT_INDEXED: u32 = 0x00002000;
    pub const ENCRYPTED: u32 = 0x00004000;
}

/// File information from directory enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbFileInfo {
    pub name: String,
    pub size: u64,
    pub attributes: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub is_directory: bool,
}

impl SmbFileInfo {
    pub fn is_hidden(&self) -> bool {
        self.attributes & file_attributes::HIDDEN != 0
    }

    pub fn is_system(&self) -> bool {
        self.attributes & file_attributes::SYSTEM != 0
    }

    pub fn is_readonly(&self) -> bool {
        self.attributes & file_attributes::READONLY != 0
    }
}

/// SMB NT Status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtStatus(pub u32);

impl NtStatus {
    pub const SUCCESS: NtStatus = NtStatus(0x00000000);
    pub const MORE_PROCESSING_REQUIRED: NtStatus = NtStatus(0xC0000016);
    pub const INVALID_PARAMETER: NtStatus = NtStatus(0xC000000D);
    pub const NO_SUCH_FILE: NtStatus = NtStatus(0xC000000F);
    pub const ACCESS_DENIED: NtStatus = NtStatus(0xC0000022);
    pub const OBJECT_NAME_NOT_FOUND: NtStatus = NtStatus(0xC0000034);
    pub const OBJECT_NAME_COLLISION: NtStatus = NtStatus(0xC0000035);
    pub const LOGON_FAILURE: NtStatus = NtStatus(0xC000006D);
    pub const ACCOUNT_RESTRICTION: NtStatus = NtStatus(0xC000006E);
    pub const INVALID_LOGON_HOURS: NtStatus = NtStatus(0xC000006F);
    pub const PASSWORD_EXPIRED: NtStatus = NtStatus(0xC0000071);
    pub const ACCOUNT_DISABLED: NtStatus = NtStatus(0xC0000072);
    pub const BUFFER_TOO_SMALL: NtStatus = NtStatus(0xC0000023);
    pub const NOT_SUPPORTED: NtStatus = NtStatus(0xC00000BB);
    pub const NETWORK_NAME_DELETED: NtStatus = NtStatus(0xC00000C9);
    pub const BAD_NETWORK_NAME: NtStatus = NtStatus(0xC00000CC);
    pub const REQUEST_NOT_ACCEPTED: NtStatus = NtStatus(0xC00000D0);
    pub const USER_SESSION_DELETED: NtStatus = NtStatus(0xC0000203);
    pub const NETWORK_SESSION_EXPIRED: NtStatus = NtStatus(0xC000035C);

    pub fn is_success(self) -> bool {
        self.0 == 0
    }

    pub fn is_error(self) -> bool {
        self.0 & 0xC0000000 == 0xC0000000
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::SUCCESS => "Success",
            Self::MORE_PROCESSING_REQUIRED => "More processing required",
            Self::INVALID_PARAMETER => "Invalid parameter",
            Self::NO_SUCH_FILE => "No such file",
            Self::ACCESS_DENIED => "Access denied",
            Self::OBJECT_NAME_NOT_FOUND => "Object name not found",
            Self::OBJECT_NAME_COLLISION => "Object name collision",
            Self::LOGON_FAILURE => "Logon failure",
            Self::ACCOUNT_RESTRICTION => "Account restriction",
            Self::INVALID_LOGON_HOURS => "Invalid logon hours",
            Self::PASSWORD_EXPIRED => "Password expired",
            Self::ACCOUNT_DISABLED => "Account disabled",
            Self::BUFFER_TOO_SMALL => "Buffer too small",
            Self::NOT_SUPPORTED => "Not supported",
            Self::NETWORK_NAME_DELETED => "Network name deleted",
            Self::BAD_NETWORK_NAME => "Bad network name",
            Self::REQUEST_NOT_ACCEPTED => "Request not accepted",
            Self::USER_SESSION_DELETED => "User session deleted",
            Self::NETWORK_SESSION_EXPIRED => "Network session expired",
            _ => "Unknown status",
        }
    }
}

impl fmt::Display for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X} ({})", self.0, self.description())
    }
}

/// SMB error type
#[derive(Debug, thiserror::Error)]
pub enum SmbError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("NT Status error: {0}")]
    NtStatus(NtStatus),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Timeout")]
    Timeout,

    #[error("Not connected")]
    NotConnected,

    #[error("Share not found: {0}")]
    ShareNotFound(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

impl From<NtStatus> for SmbError {
    fn from(status: NtStatus) -> Self {
        match status {
            NtStatus::ACCESS_DENIED => SmbError::AccessDenied("Access denied".to_string()),
            NtStatus::LOGON_FAILURE => {
                SmbError::AuthenticationFailed("Invalid credentials".to_string())
            }
            NtStatus::ACCOUNT_DISABLED => {
                SmbError::AuthenticationFailed("Account disabled".to_string())
            }
            NtStatus::PASSWORD_EXPIRED => {
                SmbError::AuthenticationFailed("Password expired".to_string())
            }
            NtStatus::BAD_NETWORK_NAME => SmbError::ShareNotFound("Bad network name".to_string()),
            _ => SmbError::NtStatus(status),
        }
    }
}

pub type SmbResult<T> = Result<T, SmbError>;
