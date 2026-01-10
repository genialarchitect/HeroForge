//! SMB2/3 Protocol Implementation
//!
//! Implements SMB2 packet construction and parsing for network operations.

use super::types::*;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};

/// SMB2 protocol magic
pub const SMB2_MAGIC: &[u8; 4] = b"\xfeSMB";

/// SMB2 header size
pub const SMB2_HEADER_SIZE: usize = 64;

/// SMB2 header structure
#[derive(Debug, Clone)]
pub struct Smb2Header {
    pub protocol_id: [u8; 4],
    pub structure_size: u16,
    pub credit_charge: u16,
    pub status: NtStatus,
    pub command: u16,
    pub credit_request: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub reserved: u32,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: [u8; 16],
}

impl Default for Smb2Header {
    fn default() -> Self {
        Self {
            protocol_id: *SMB2_MAGIC,
            structure_size: 64,
            credit_charge: 1,
            status: NtStatus::SUCCESS,
            command: 0,
            credit_request: 1,
            flags: 0,
            next_command: 0,
            message_id: 0,
            reserved: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0u8; 16],
        }
    }
}

impl Smb2Header {
    pub fn new(command: Smb2Command, message_id: u64) -> Self {
        Self {
            command: command as u16,
            message_id,
            credit_request: 256, // Request more credits
            ..Default::default()
        }
    }

    pub fn with_session(mut self, session_id: u64) -> Self {
        self.session_id = session_id;
        self
    }

    pub fn with_tree(mut self, tree_id: u32) -> Self {
        self.tree_id = tree_id;
        self
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SMB2_HEADER_SIZE);

        buf.extend_from_slice(&self.protocol_id);
        buf.write_u16::<LittleEndian>(self.structure_size).unwrap();
        buf.write_u16::<LittleEndian>(self.credit_charge).unwrap();
        buf.write_u32::<LittleEndian>(self.status.0).unwrap();
        buf.write_u16::<LittleEndian>(self.command).unwrap();
        buf.write_u16::<LittleEndian>(self.credit_request).unwrap();
        buf.write_u32::<LittleEndian>(self.flags).unwrap();
        buf.write_u32::<LittleEndian>(self.next_command).unwrap();
        buf.write_u64::<LittleEndian>(self.message_id).unwrap();
        buf.write_u32::<LittleEndian>(self.reserved).unwrap();
        buf.write_u32::<LittleEndian>(self.tree_id).unwrap();
        buf.write_u64::<LittleEndian>(self.session_id).unwrap();
        buf.extend_from_slice(&self.signature);

        buf
    }

    pub fn parse(data: &[u8]) -> SmbResult<Self> {
        if data.len() < SMB2_HEADER_SIZE {
            return Err(SmbError::Protocol("Header too short".to_string()));
        }

        let mut cursor = Cursor::new(data);

        let mut protocol_id = [0u8; 4];
        cursor.read_exact(&mut protocol_id)?;

        if &protocol_id != SMB2_MAGIC {
            return Err(SmbError::Protocol("Invalid SMB2 magic".to_string()));
        }

        let structure_size = cursor.read_u16::<LittleEndian>()?;
        let credit_charge = cursor.read_u16::<LittleEndian>()?;
        let status = NtStatus(cursor.read_u32::<LittleEndian>()?);
        let command = cursor.read_u16::<LittleEndian>()?;
        let credit_request = cursor.read_u16::<LittleEndian>()?;
        let flags = cursor.read_u32::<LittleEndian>()?;
        let next_command = cursor.read_u32::<LittleEndian>()?;
        let message_id = cursor.read_u64::<LittleEndian>()?;
        let reserved = cursor.read_u32::<LittleEndian>()?;
        let tree_id = cursor.read_u32::<LittleEndian>()?;
        let session_id = cursor.read_u64::<LittleEndian>()?;

        let mut signature = [0u8; 16];
        cursor.read_exact(&mut signature)?;

        Ok(Self {
            protocol_id,
            structure_size,
            credit_charge,
            status,
            command,
            credit_request,
            flags,
            next_command,
            message_id,
            reserved,
            tree_id,
            session_id,
            signature,
        })
    }
}

/// SMB2 NEGOTIATE request
pub struct Smb2NegotiateRequest {
    pub dialects: Vec<SmbDialect>,
    pub security_mode: u16,
    pub capabilities: u32,
    pub client_guid: [u8; 16],
}

impl Default for Smb2NegotiateRequest {
    fn default() -> Self {
        Self {
            dialects: vec![
                SmbDialect::Smb202,
                SmbDialect::Smb210,
                SmbDialect::Smb300,
                SmbDialect::Smb302,
                SmbDialect::Smb311,
            ],
            security_mode: 0x01, // Signing enabled
            capabilities: smb2_capabilities::DFS | smb2_capabilities::LARGE_MTU,
            client_guid: rand::random(),
        }
    }
}

impl Smb2NegotiateRequest {
    pub fn serialize(&self, message_id: u64) -> Vec<u8> {
        let header = Smb2Header::new(Smb2Command::Negotiate, message_id);
        let mut buf = header.serialize();

        // Structure size (36)
        buf.write_u16::<LittleEndian>(36).unwrap();
        // Dialect count
        buf.write_u16::<LittleEndian>(self.dialects.len() as u16)
            .unwrap();
        // Security mode
        buf.write_u16::<LittleEndian>(self.security_mode).unwrap();
        // Reserved
        buf.write_u16::<LittleEndian>(0).unwrap();
        // Capabilities
        buf.write_u32::<LittleEndian>(self.capabilities).unwrap();
        // Client GUID
        buf.extend_from_slice(&self.client_guid);
        // Negotiate context offset (SMB 3.1.1) - for now, no contexts
        buf.write_u32::<LittleEndian>(0).unwrap();
        // Negotiate context count
        buf.write_u16::<LittleEndian>(0).unwrap();
        // Reserved2
        buf.write_u16::<LittleEndian>(0).unwrap();

        // Dialects
        for dialect in &self.dialects {
            buf.write_u16::<LittleEndian>(dialect.to_u16()).unwrap();
        }

        buf
    }
}

/// SMB2 NEGOTIATE response
#[derive(Debug)]
pub struct Smb2NegotiateResponse {
    pub dialect: SmbDialect,
    pub security_mode: u16,
    pub server_guid: [u8; 16],
    pub capabilities: u32,
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub security_buffer: Vec<u8>,
}

impl Smb2NegotiateResponse {
    pub fn parse(data: &[u8]) -> SmbResult<Self> {
        if data.len() < SMB2_HEADER_SIZE + 65 {
            return Err(SmbError::Protocol(
                "Negotiate response too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(&data[SMB2_HEADER_SIZE..]);

        let _structure_size = cursor.read_u16::<LittleEndian>()?;
        let security_mode = cursor.read_u16::<LittleEndian>()?;
        let dialect_revision = cursor.read_u16::<LittleEndian>()?;
        let _negotiate_context_count = cursor.read_u16::<LittleEndian>()?;

        let mut server_guid = [0u8; 16];
        cursor.read_exact(&mut server_guid)?;

        let capabilities = cursor.read_u32::<LittleEndian>()?;
        let max_transact_size = cursor.read_u32::<LittleEndian>()?;
        let max_read_size = cursor.read_u32::<LittleEndian>()?;
        let max_write_size = cursor.read_u32::<LittleEndian>()?;

        let _system_time = cursor.read_u64::<LittleEndian>()?;
        let _server_start_time = cursor.read_u64::<LittleEndian>()?;

        let security_buffer_offset = cursor.read_u16::<LittleEndian>()?;
        let security_buffer_length = cursor.read_u16::<LittleEndian>()?;

        let _negotiate_context_offset = cursor.read_u32::<LittleEndian>()?;

        let dialect = SmbDialect::from_u16(dialect_revision)
            .ok_or_else(|| SmbError::Protocol(format!("Unknown dialect: 0x{:04x}", dialect_revision)))?;

        // Extract security buffer
        let sec_offset = security_buffer_offset as usize;
        let sec_len = security_buffer_length as usize;
        let security_buffer = if sec_len > 0 && sec_offset < data.len() {
            let end = (sec_offset + sec_len).min(data.len());
            data[sec_offset..end].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            dialect,
            security_mode,
            server_guid,
            capabilities,
            max_transact_size,
            max_read_size,
            max_write_size,
            security_buffer,
        })
    }
}

/// SMB2 SESSION_SETUP request
pub struct Smb2SessionSetupRequest {
    pub flags: u8,
    pub security_mode: u8,
    pub capabilities: u32,
    pub previous_session_id: u64,
    pub security_buffer: Vec<u8>,
}

impl Smb2SessionSetupRequest {
    pub fn new(security_buffer: Vec<u8>) -> Self {
        Self {
            flags: 0,
            security_mode: 0x01, // Signing enabled
            capabilities: 0,
            previous_session_id: 0,
            security_buffer,
        }
    }

    pub fn serialize(&self, message_id: u64, session_id: u64) -> Vec<u8> {
        let header = Smb2Header::new(Smb2Command::SessionSetup, message_id).with_session(session_id);
        let mut buf = header.serialize();

        // Structure size (25)
        buf.write_u16::<LittleEndian>(25).unwrap();
        // Flags
        buf.push(self.flags);
        // Security mode
        buf.push(self.security_mode);
        // Capabilities
        buf.write_u32::<LittleEndian>(self.capabilities).unwrap();
        // Channel
        buf.write_u32::<LittleEndian>(0).unwrap();
        // Security buffer offset (header + fixed part = 64 + 24 = 88)
        buf.write_u16::<LittleEndian>(88).unwrap();
        // Security buffer length
        buf.write_u16::<LittleEndian>(self.security_buffer.len() as u16)
            .unwrap();
        // Previous session id
        buf.write_u64::<LittleEndian>(self.previous_session_id)
            .unwrap();

        // Security buffer
        buf.extend_from_slice(&self.security_buffer);

        buf
    }
}

/// SMB2 SESSION_SETUP response
#[derive(Debug)]
pub struct Smb2SessionSetupResponse {
    pub session_flags: u16,
    pub security_buffer: Vec<u8>,
}

impl Smb2SessionSetupResponse {
    pub fn parse(data: &[u8]) -> SmbResult<Self> {
        if data.len() < SMB2_HEADER_SIZE + 9 {
            return Err(SmbError::Protocol(
                "Session setup response too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(&data[SMB2_HEADER_SIZE..]);

        let _structure_size = cursor.read_u16::<LittleEndian>()?;
        let session_flags = cursor.read_u16::<LittleEndian>()?;
        let security_buffer_offset = cursor.read_u16::<LittleEndian>()?;
        let security_buffer_length = cursor.read_u16::<LittleEndian>()?;

        let sec_offset = security_buffer_offset as usize;
        let sec_len = security_buffer_length as usize;
        let security_buffer = if sec_len > 0 && sec_offset < data.len() {
            let end = (sec_offset + sec_len).min(data.len());
            data[sec_offset..end].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            session_flags,
            security_buffer,
        })
    }
}

/// SMB2 TREE_CONNECT request
pub struct Smb2TreeConnectRequest {
    pub path: String,
}

impl Smb2TreeConnectRequest {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    pub fn serialize(&self, message_id: u64, session_id: u64) -> Vec<u8> {
        let header = Smb2Header::new(Smb2Command::TreeConnect, message_id).with_session(session_id);
        let mut buf = header.serialize();

        // Encode path as UTF-16LE
        let path_bytes: Vec<u8> = self
            .path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        // Structure size (9)
        buf.write_u16::<LittleEndian>(9).unwrap();
        // Flags
        buf.write_u16::<LittleEndian>(0).unwrap();
        // Path offset (header + fixed = 64 + 8 = 72)
        buf.write_u16::<LittleEndian>(72).unwrap();
        // Path length
        buf.write_u16::<LittleEndian>(path_bytes.len() as u16)
            .unwrap();

        // Path buffer
        buf.extend_from_slice(&path_bytes);

        buf
    }
}

/// SMB2 TREE_CONNECT response
#[derive(Debug)]
pub struct Smb2TreeConnectResponse {
    pub share_type: ShareType,
    pub share_flags: u32,
    pub capabilities: u32,
    pub maximal_access: u32,
}

impl Smb2TreeConnectResponse {
    pub fn parse(data: &[u8]) -> SmbResult<Self> {
        if data.len() < SMB2_HEADER_SIZE + 16 {
            return Err(SmbError::Protocol(
                "Tree connect response too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(&data[SMB2_HEADER_SIZE..]);

        let _structure_size = cursor.read_u16::<LittleEndian>()?;
        let share_type = cursor.read_u8()?;
        let _reserved = cursor.read_u8()?;
        let share_flags = cursor.read_u32::<LittleEndian>()?;
        let capabilities = cursor.read_u32::<LittleEndian>()?;
        let maximal_access = cursor.read_u32::<LittleEndian>()?;

        Ok(Self {
            share_type: ShareType::from_u8(share_type),
            share_flags,
            capabilities,
            maximal_access,
        })
    }
}

/// SMB2 TREE_DISCONNECT request
pub struct Smb2TreeDisconnectRequest;

impl Smb2TreeDisconnectRequest {
    pub fn serialize(message_id: u64, session_id: u64, tree_id: u32) -> Vec<u8> {
        let header = Smb2Header::new(Smb2Command::TreeDisconnect, message_id)
            .with_session(session_id)
            .with_tree(tree_id);
        let mut buf = header.serialize();

        // Structure size (4)
        buf.write_u16::<LittleEndian>(4).unwrap();
        // Reserved
        buf.write_u16::<LittleEndian>(0).unwrap();

        buf
    }
}

/// SMB2 IOCTL request for DCE/RPC
pub struct Smb2IoctlRequest {
    pub ctl_code: u32,
    pub file_id: [u8; 16],
    pub input_data: Vec<u8>,
    pub max_output_response: u32,
}

// Common IOCTL codes
pub mod ioctl_codes {
    pub const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011C017;
    pub const FSCTL_PIPE_WAIT: u32 = 0x00110018;
    pub const FSCTL_DFS_GET_REFERRALS: u32 = 0x00060194;
    pub const FSCTL_VALIDATE_NEGOTIATE_INFO: u32 = 0x00140204;
}

impl Smb2IoctlRequest {
    pub fn new(ctl_code: u32, file_id: [u8; 16], input_data: Vec<u8>) -> Self {
        Self {
            ctl_code,
            file_id,
            input_data,
            max_output_response: 65536,
        }
    }

    pub fn serialize(&self, message_id: u64, session_id: u64, tree_id: u32) -> Vec<u8> {
        let header = Smb2Header::new(Smb2Command::Ioctl, message_id)
            .with_session(session_id)
            .with_tree(tree_id);
        let mut buf = header.serialize();

        // Structure size (57)
        buf.write_u16::<LittleEndian>(57).unwrap();
        // Reserved
        buf.write_u16::<LittleEndian>(0).unwrap();
        // Ctl code
        buf.write_u32::<LittleEndian>(self.ctl_code).unwrap();
        // File ID
        buf.extend_from_slice(&self.file_id);
        // Input offset (header + fixed = 64 + 56 = 120)
        buf.write_u32::<LittleEndian>(if self.input_data.is_empty() {
            0
        } else {
            120
        })
        .unwrap();
        // Input count
        buf.write_u32::<LittleEndian>(self.input_data.len() as u32)
            .unwrap();
        // Max input response
        buf.write_u32::<LittleEndian>(0).unwrap();
        // Output offset
        buf.write_u32::<LittleEndian>(0).unwrap();
        // Output count
        buf.write_u32::<LittleEndian>(0).unwrap();
        // Max output response
        buf.write_u32::<LittleEndian>(self.max_output_response)
            .unwrap();
        // Flags (SMB2_0_IOCTL_IS_FSCTL = 1)
        buf.write_u32::<LittleEndian>(1).unwrap();
        // Reserved2
        buf.write_u32::<LittleEndian>(0).unwrap();

        // Input data
        buf.extend_from_slice(&self.input_data);

        buf
    }
}

/// SMB2 IOCTL response
#[derive(Debug)]
pub struct Smb2IoctlResponse {
    pub ctl_code: u32,
    pub file_id: [u8; 16],
    pub output_data: Vec<u8>,
}

impl Smb2IoctlResponse {
    pub fn parse(data: &[u8]) -> SmbResult<Self> {
        if data.len() < SMB2_HEADER_SIZE + 49 {
            return Err(SmbError::Protocol("IOCTL response too short".to_string()));
        }

        let mut cursor = Cursor::new(&data[SMB2_HEADER_SIZE..]);

        let _structure_size = cursor.read_u16::<LittleEndian>()?;
        let _reserved = cursor.read_u16::<LittleEndian>()?;
        let ctl_code = cursor.read_u32::<LittleEndian>()?;

        let mut file_id = [0u8; 16];
        cursor.read_exact(&mut file_id)?;

        let _input_offset = cursor.read_u32::<LittleEndian>()?;
        let _input_count = cursor.read_u32::<LittleEndian>()?;
        let output_offset = cursor.read_u32::<LittleEndian>()?;
        let output_count = cursor.read_u32::<LittleEndian>()?;

        let output_data = if output_count > 0 && (output_offset as usize) < data.len() {
            let start = output_offset as usize;
            let end = (start + output_count as usize).min(data.len());
            data[start..end].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            ctl_code,
            file_id,
            output_data,
        })
    }
}

/// SMB2 CREATE request for opening files/pipes
pub struct Smb2CreateRequest {
    pub requested_oplock_level: u8,
    pub impersonation_level: u32,
    pub desired_access: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub name: String,
}

// Access mask constants
pub mod access_mask {
    pub const FILE_READ_DATA: u32 = 0x00000001;
    pub const FILE_WRITE_DATA: u32 = 0x00000002;
    pub const FILE_APPEND_DATA: u32 = 0x00000004;
    pub const FILE_READ_EA: u32 = 0x00000008;
    pub const FILE_WRITE_EA: u32 = 0x00000010;
    pub const FILE_EXECUTE: u32 = 0x00000020;
    pub const FILE_READ_ATTRIBUTES: u32 = 0x00000080;
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x00000100;
    pub const DELETE: u32 = 0x00010000;
    pub const READ_CONTROL: u32 = 0x00020000;
    pub const WRITE_DAC: u32 = 0x00040000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const SYNCHRONIZE: u32 = 0x00100000;
    pub const GENERIC_ALL: u32 = 0x10000000;
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;
    pub const GENERIC_READ: u32 = 0x80000000;
}

// Share access constants
pub mod share_access {
    pub const FILE_SHARE_READ: u32 = 0x00000001;
    pub const FILE_SHARE_WRITE: u32 = 0x00000002;
    pub const FILE_SHARE_DELETE: u32 = 0x00000004;
}

// Create disposition constants
pub mod create_disposition {
    pub const FILE_SUPERSEDE: u32 = 0x00000000;
    pub const FILE_OPEN: u32 = 0x00000001;
    pub const FILE_CREATE: u32 = 0x00000002;
    pub const FILE_OPEN_IF: u32 = 0x00000003;
    pub const FILE_OVERWRITE: u32 = 0x00000004;
    pub const FILE_OVERWRITE_IF: u32 = 0x00000005;
}

// Create options constants
pub mod create_options {
    pub const FILE_DIRECTORY_FILE: u32 = 0x00000001;
    pub const FILE_WRITE_THROUGH: u32 = 0x00000002;
    pub const FILE_SEQUENTIAL_ONLY: u32 = 0x00000004;
    pub const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x00000008;
    pub const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
    pub const FILE_DELETE_ON_CLOSE: u32 = 0x00001000;
}

impl Smb2CreateRequest {
    pub fn open_pipe(name: &str) -> Self {
        Self {
            requested_oplock_level: 0,
            impersonation_level: 2, // Impersonation
            desired_access: access_mask::GENERIC_READ
                | access_mask::GENERIC_WRITE
                | access_mask::SYNCHRONIZE,
            file_attributes: 0,
            share_access: share_access::FILE_SHARE_READ | share_access::FILE_SHARE_WRITE,
            create_disposition: create_disposition::FILE_OPEN,
            create_options: 0,
            name: name.to_string(),
        }
    }

    pub fn serialize(&self, message_id: u64, session_id: u64, tree_id: u32) -> Vec<u8> {
        let header = Smb2Header::new(Smb2Command::Create, message_id)
            .with_session(session_id)
            .with_tree(tree_id);
        let mut buf = header.serialize();

        // Encode name as UTF-16LE
        let name_bytes: Vec<u8> = self
            .name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        // Structure size (57)
        buf.write_u16::<LittleEndian>(57).unwrap();
        // Security flags
        buf.push(0);
        // Requested oplock level
        buf.push(self.requested_oplock_level);
        // Impersonation level
        buf.write_u32::<LittleEndian>(self.impersonation_level)
            .unwrap();
        // Smb create flags
        buf.write_u64::<LittleEndian>(0).unwrap();
        // Reserved
        buf.write_u64::<LittleEndian>(0).unwrap();
        // Desired access
        buf.write_u32::<LittleEndian>(self.desired_access).unwrap();
        // File attributes
        buf.write_u32::<LittleEndian>(self.file_attributes).unwrap();
        // Share access
        buf.write_u32::<LittleEndian>(self.share_access).unwrap();
        // Create disposition
        buf.write_u32::<LittleEndian>(self.create_disposition)
            .unwrap();
        // Create options
        buf.write_u32::<LittleEndian>(self.create_options).unwrap();
        // Name offset (header + fixed = 64 + 56 = 120)
        buf.write_u16::<LittleEndian>(120).unwrap();
        // Name length
        buf.write_u16::<LittleEndian>(name_bytes.len() as u16)
            .unwrap();
        // Create contexts offset
        buf.write_u32::<LittleEndian>(0).unwrap();
        // Create contexts length
        buf.write_u32::<LittleEndian>(0).unwrap();

        // Name buffer
        buf.extend_from_slice(&name_bytes);

        buf
    }
}

/// SMB2 CREATE response
#[derive(Debug)]
pub struct Smb2CreateResponse {
    pub oplock_level: u8,
    pub flags: u8,
    pub create_action: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32,
    pub file_id: [u8; 16],
}

impl Smb2CreateResponse {
    pub fn parse(data: &[u8]) -> SmbResult<Self> {
        if data.len() < SMB2_HEADER_SIZE + 89 {
            return Err(SmbError::Protocol("Create response too short".to_string()));
        }

        let mut cursor = Cursor::new(&data[SMB2_HEADER_SIZE..]);

        let _structure_size = cursor.read_u16::<LittleEndian>()?;
        let oplock_level = cursor.read_u8()?;
        let flags = cursor.read_u8()?;
        let create_action = cursor.read_u32::<LittleEndian>()?;
        let creation_time = cursor.read_u64::<LittleEndian>()?;
        let last_access_time = cursor.read_u64::<LittleEndian>()?;
        let last_write_time = cursor.read_u64::<LittleEndian>()?;
        let change_time = cursor.read_u64::<LittleEndian>()?;
        let allocation_size = cursor.read_u64::<LittleEndian>()?;
        let end_of_file = cursor.read_u64::<LittleEndian>()?;
        let file_attributes = cursor.read_u32::<LittleEndian>()?;
        let _reserved2 = cursor.read_u32::<LittleEndian>()?;

        let mut file_id = [0u8; 16];
        cursor.read_exact(&mut file_id)?;

        Ok(Self {
            oplock_level,
            flags,
            create_action,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            allocation_size,
            end_of_file,
            file_attributes,
            file_id,
        })
    }
}

/// SMB2 CLOSE request
pub struct Smb2CloseRequest {
    pub file_id: [u8; 16],
}

impl Smb2CloseRequest {
    pub fn new(file_id: [u8; 16]) -> Self {
        Self { file_id }
    }

    pub fn serialize(&self, message_id: u64, session_id: u64, tree_id: u32) -> Vec<u8> {
        let header = Smb2Header::new(Smb2Command::Close, message_id)
            .with_session(session_id)
            .with_tree(tree_id);
        let mut buf = header.serialize();

        // Structure size (24)
        buf.write_u16::<LittleEndian>(24).unwrap();
        // Flags
        buf.write_u16::<LittleEndian>(0).unwrap();
        // Reserved
        buf.write_u32::<LittleEndian>(0).unwrap();
        // File ID
        buf.extend_from_slice(&self.file_id);

        buf
    }
}

/// SMB2 READ request
pub struct Smb2ReadRequest {
    pub file_id: [u8; 16],
    pub offset: u64,
    pub length: u32,
}

impl Smb2ReadRequest {
    pub fn new(file_id: [u8; 16], offset: u64, length: u32) -> Self {
        Self {
            file_id,
            offset,
            length,
        }
    }

    pub fn serialize(&self, message_id: u64, session_id: u64, tree_id: u32) -> Vec<u8> {
        let header = Smb2Header::new(Smb2Command::Read, message_id)
            .with_session(session_id)
            .with_tree(tree_id);
        let mut buf = header.serialize();

        // Structure size (49)
        buf.write_u16::<LittleEndian>(49).unwrap();
        // Padding
        buf.push(0);
        // Flags
        buf.push(0);
        // Length
        buf.write_u32::<LittleEndian>(self.length).unwrap();
        // Offset
        buf.write_u64::<LittleEndian>(self.offset).unwrap();
        // File ID
        buf.extend_from_slice(&self.file_id);
        // Minimum count
        buf.write_u32::<LittleEndian>(1).unwrap();
        // Channel
        buf.write_u32::<LittleEndian>(0).unwrap();
        // Remaining bytes
        buf.write_u32::<LittleEndian>(0).unwrap();
        // Read channel info offset
        buf.write_u16::<LittleEndian>(0).unwrap();
        // Read channel info length
        buf.write_u16::<LittleEndian>(0).unwrap();
        // Buffer (1 byte minimum)
        buf.push(0);

        buf
    }
}

/// SMB2 READ response
#[derive(Debug)]
pub struct Smb2ReadResponse {
    pub data: Vec<u8>,
}

impl Smb2ReadResponse {
    pub fn parse(data: &[u8]) -> SmbResult<Self> {
        if data.len() < SMB2_HEADER_SIZE + 17 {
            return Err(SmbError::Protocol("Read response too short".to_string()));
        }

        let mut cursor = Cursor::new(&data[SMB2_HEADER_SIZE..]);

        let _structure_size = cursor.read_u16::<LittleEndian>()?;
        let data_offset = cursor.read_u8()?;
        let _reserved = cursor.read_u8()?;
        let data_length = cursor.read_u32::<LittleEndian>()?;

        let read_data = if data_length > 0 {
            let start = data_offset as usize;
            let end = (start + data_length as usize).min(data.len());
            if start < data.len() {
                data[start..end].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(Self { data: read_data })
    }
}

/// SMB2 WRITE request
pub struct Smb2WriteRequest {
    pub file_id: [u8; 16],
    pub offset: u64,
    pub data: Vec<u8>,
}

impl Smb2WriteRequest {
    pub fn new(file_id: [u8; 16], offset: u64, data: Vec<u8>) -> Self {
        Self {
            file_id,
            offset,
            data,
        }
    }

    pub fn serialize(&self, message_id: u64, session_id: u64, tree_id: u32) -> Vec<u8> {
        let header = Smb2Header::new(Smb2Command::Write, message_id)
            .with_session(session_id)
            .with_tree(tree_id);
        let mut buf = header.serialize();

        // Structure size (49)
        buf.write_u16::<LittleEndian>(49).unwrap();
        // Data offset (header + fixed = 64 + 48 = 112)
        buf.write_u16::<LittleEndian>(112).unwrap();
        // Length
        buf.write_u32::<LittleEndian>(self.data.len() as u32)
            .unwrap();
        // Offset
        buf.write_u64::<LittleEndian>(self.offset).unwrap();
        // File ID
        buf.extend_from_slice(&self.file_id);
        // Channel
        buf.write_u32::<LittleEndian>(0).unwrap();
        // Remaining bytes
        buf.write_u32::<LittleEndian>(0).unwrap();
        // Write channel info offset
        buf.write_u16::<LittleEndian>(0).unwrap();
        // Write channel info length
        buf.write_u16::<LittleEndian>(0).unwrap();
        // Flags
        buf.write_u32::<LittleEndian>(0).unwrap();

        // Data
        buf.extend_from_slice(&self.data);

        buf
    }
}

/// SMB2 WRITE response
#[derive(Debug)]
pub struct Smb2WriteResponse {
    pub count: u32,
}

impl Smb2WriteResponse {
    pub fn parse(data: &[u8]) -> SmbResult<Self> {
        if data.len() < SMB2_HEADER_SIZE + 17 {
            return Err(SmbError::Protocol("Write response too short".to_string()));
        }

        let mut cursor = Cursor::new(&data[SMB2_HEADER_SIZE..]);

        let _structure_size = cursor.read_u16::<LittleEndian>()?;
        let _reserved = cursor.read_u16::<LittleEndian>()?;
        let count = cursor.read_u32::<LittleEndian>()?;

        Ok(Self { count })
    }
}

/// SMB2 LOGOFF request
pub struct Smb2LogoffRequest;

impl Smb2LogoffRequest {
    pub fn serialize(message_id: u64, session_id: u64) -> Vec<u8> {
        let header = Smb2Header::new(Smb2Command::Logoff, message_id).with_session(session_id);
        let mut buf = header.serialize();

        // Structure size (4)
        buf.write_u16::<LittleEndian>(4).unwrap();
        // Reserved
        buf.write_u16::<LittleEndian>(0).unwrap();

        buf
    }
}

/// Build NetBIOS session service header (TCP transport)
pub fn wrap_netbios(smb_data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + smb_data.len());

    // NetBIOS session message type (0x00 = session message)
    buf.push(0x00);

    // Length (24-bit big-endian)
    let len = smb_data.len() as u32;
    buf.push(((len >> 16) & 0xFF) as u8);
    buf.push(((len >> 8) & 0xFF) as u8);
    buf.push((len & 0xFF) as u8);

    buf.extend_from_slice(smb_data);
    buf
}

/// Parse NetBIOS session service header
pub fn unwrap_netbios(data: &[u8]) -> SmbResult<&[u8]> {
    if data.len() < 4 {
        return Err(SmbError::Protocol("NetBIOS header too short".to_string()));
    }

    let msg_type = data[0];
    if msg_type != 0x00 {
        return Err(SmbError::Protocol(format!(
            "Unexpected NetBIOS message type: 0x{:02x}",
            msg_type
        )));
    }

    let length = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);

    if data.len() < 4 + length {
        return Err(SmbError::Protocol("NetBIOS data truncated".to_string()));
    }

    Ok(&data[4..4 + length])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_serialize_parse() {
        let header = Smb2Header::new(Smb2Command::Negotiate, 1);
        let serialized = header.serialize();

        assert_eq!(serialized.len(), SMB2_HEADER_SIZE);
        assert_eq!(&serialized[0..4], SMB2_MAGIC);

        let parsed = Smb2Header::parse(&serialized).unwrap();
        assert_eq!(parsed.command, Smb2Command::Negotiate as u16);
        assert_eq!(parsed.message_id, 1);
    }

    #[test]
    fn test_netbios_wrap_unwrap() {
        let data = vec![1, 2, 3, 4, 5];
        let wrapped = wrap_netbios(&data);

        assert_eq!(wrapped[0], 0x00);
        assert_eq!(wrapped[1..4], [0x00, 0x00, 0x05]);

        let unwrapped = unwrap_netbios(&wrapped).unwrap();
        assert_eq!(unwrapped, data);
    }
}
