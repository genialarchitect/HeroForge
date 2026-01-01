//! SRVSVC - Server Service RPC Interface
//!
//! Implements share enumeration via MS-SRVS protocol.

use super::types::*;
use crate::scanner::smb_native::types::{SmbError, SmbResult, SmbShare, ShareType};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

/// SRVSVC operation numbers
pub mod srvsvc_opnum {
    pub const NETR_SHARE_ENUM: u16 = 15;
    pub const NETR_SHARE_GET_INFO: u16 = 16;
    pub const NETR_SERVER_GET_INFO: u16 = 21;
    pub const NETR_SESSION_ENUM: u16 = 12;
}

/// SRVSVC interface version
pub const SRVSVC_VERSION: (u16, u16) = (3, 0);

/// Create bind request for SRVSVC
pub fn create_srvsvc_bind(call_id: u32) -> Vec<u8> {
    let context = RpcContextElement::new(0, interfaces::SRVSVC, SRVSVC_VERSION);
    let bind = RpcBindRequest::new(context, call_id);
    bind.serialize()
}

/// Create NetrShareEnum request
pub fn create_share_enum_request(server: &str, call_id: u32) -> Vec<u8> {
    let mut stub = Vec::new();

    // ServerName (unique pointer to string)
    stub.extend_from_slice(&ndr_pointer(&ndr_string(server)));

    // InfoStruct (SHARE_ENUM_STRUCT)
    // Level
    stub.write_u32::<LittleEndian>(1).unwrap(); // Level 1 (SHARE_INFO_1)

    // ShareInfo union (switch on level)
    stub.write_u32::<LittleEndian>(1).unwrap(); // Switch value = 1

    // Container pointer (SHARE_INFO_1_CONTAINER)
    stub.write_u32::<LittleEndian>(0x00020004).unwrap(); // Referent ID

    // EntriesRead
    stub.write_u32::<LittleEndian>(0).unwrap();

    // Buffer (null pointer for enumeration)
    stub.write_u32::<LittleEndian>(0).unwrap();

    // PreferedMaximumLength
    stub.write_u32::<LittleEndian>(0xFFFFFFFF).unwrap();

    // ResumeHandle (unique pointer, null for first call)
    stub.write_u32::<LittleEndian>(0x00020008).unwrap(); // Referent ID
    stub.write_u32::<LittleEndian>(0).unwrap(); // Value = 0

    let request = RpcRequest::new(srvsvc_opnum::NETR_SHARE_ENUM, stub, call_id);
    request.serialize()
}

/// Parse NetrShareEnum response
pub fn parse_share_enum_response(data: &[u8]) -> SmbResult<Vec<SmbShare>> {
    if data.len() < 24 {
        return Err(SmbError::InvalidResponse(
            "Share enum response too short".to_string(),
        ));
    }

    let mut cursor = Cursor::new(data);

    // Level
    let _level = cursor.read_u32::<LittleEndian>()?;

    // Switch value
    let _switch_value = cursor.read_u32::<LittleEndian>()?;

    // Container pointer
    let container_ptr = cursor.read_u32::<LittleEndian>()?;
    if container_ptr == 0 {
        return Ok(Vec::new());
    }

    // EntriesRead
    let entries_read = cursor.read_u32::<LittleEndian>()?;

    // Buffer pointer
    let buffer_ptr = cursor.read_u32::<LittleEndian>()?;
    if buffer_ptr == 0 || entries_read == 0 {
        return Ok(Vec::new());
    }

    // Max count (conformant array)
    let max_count = cursor.read_u32::<LittleEndian>()?;

    let mut shares = Vec::new();
    let mut offset = cursor.position() as usize;

    // First pass: read fixed-size entries
    let mut entries: Vec<(u32, u32, u32)> = Vec::new();
    for _ in 0..max_count.min(entries_read) {
        if offset + 12 > data.len() {
            break;
        }
        let name_ptr = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]));
        let share_type = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]));
        let remark_ptr =
            u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));
        entries.push((name_ptr, share_type, remark_ptr));
        offset += 12;
    }

    // Second pass: read strings
    for (name_ptr, share_type, remark_ptr) in entries {
        let name = if name_ptr != 0 {
            parse_ndr_string(data, &mut offset).unwrap_or_default()
        } else {
            String::new()
        };

        let remark = if remark_ptr != 0 {
            parse_ndr_string(data, &mut offset)
        } else {
            None
        };

        let share_type_enum = match share_type & 0x0FFFFFFF {
            0 => ShareType::Disk,
            1 => ShareType::Print,
            2 | 3 => ShareType::Pipe, // IPC$ and device
            _ => ShareType::Unknown((share_type & 0xFF) as u8),
        };

        shares.push(SmbShare {
            name,
            share_type: share_type_enum,
            remark,
            path: None,
            max_uses: None,
            current_uses: None,
            permissions: None,
        });
    }

    // Check return status at end of stub
    // (skip to end - 4 bytes for NTSTATUS)
    if data.len() >= 4 {
        let status =
            u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap_or([0; 4]));
        if status != 0 {
            log::warn!("NetrShareEnum returned status: 0x{:08x}", status);
        }
    }

    Ok(shares)
}

/// Server info from NetrServerGetInfo
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub name: String,
    pub comment: String,
    pub platform_id: u32,
    pub version_major: u32,
    pub version_minor: u32,
    pub server_type: u32,
}

/// Create NetrServerGetInfo request
pub fn create_server_get_info_request(server: &str, level: u32, call_id: u32) -> Vec<u8> {
    let mut stub = Vec::new();

    // ServerName (unique pointer)
    stub.extend_from_slice(&ndr_pointer(&ndr_string(server)));

    // Level
    stub.write_u32::<LittleEndian>(level).unwrap();

    let request = RpcRequest::new(srvsvc_opnum::NETR_SERVER_GET_INFO, stub, call_id);
    request.serialize()
}

/// Parse NetrServerGetInfo response (level 101)
pub fn parse_server_get_info_response(data: &[u8]) -> SmbResult<ServerInfo> {
    if data.len() < 28 {
        return Err(SmbError::InvalidResponse(
            "Server info response too short".to_string(),
        ));
    }

    let mut cursor = Cursor::new(data);

    // Level
    let _level = cursor.read_u32::<LittleEndian>()?;

    // Switch value
    let _switch = cursor.read_u32::<LittleEndian>()?;

    // Pointer to SERVER_INFO
    let ptr = cursor.read_u32::<LittleEndian>()?;
    if ptr == 0 {
        return Err(SmbError::InvalidResponse(
            "Null server info pointer".to_string(),
        ));
    }

    // SERVER_INFO_101
    let platform_id = cursor.read_u32::<LittleEndian>()?;
    let name_ptr = cursor.read_u32::<LittleEndian>()?;
    let version_major = cursor.read_u32::<LittleEndian>()?;
    let version_minor = cursor.read_u32::<LittleEndian>()?;
    let server_type = cursor.read_u32::<LittleEndian>()?;
    let comment_ptr = cursor.read_u32::<LittleEndian>()?;

    let mut offset = cursor.position() as usize;

    let name = if name_ptr != 0 {
        parse_ndr_string(data, &mut offset).unwrap_or_default()
    } else {
        String::new()
    };

    let comment = if comment_ptr != 0 {
        parse_ndr_string(data, &mut offset).unwrap_or_default()
    } else {
        String::new()
    };

    Ok(ServerInfo {
        name,
        comment,
        platform_id,
        version_major,
        version_minor,
        server_type,
    })
}

/// Session info
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub client: String,
    pub user: String,
    pub num_opens: u32,
    pub time: u32,
    pub idle_time: u32,
    pub user_flags: u32,
}

/// Create NetrSessionEnum request
pub fn create_session_enum_request(server: &str, call_id: u32) -> Vec<u8> {
    let mut stub = Vec::new();

    // ServerName
    stub.extend_from_slice(&ndr_pointer(&ndr_string(server)));

    // ClientName (null)
    stub.write_u32::<LittleEndian>(0).unwrap();

    // UserName (null)
    stub.write_u32::<LittleEndian>(0).unwrap();

    // InfoStruct
    stub.write_u32::<LittleEndian>(10).unwrap(); // Level 10

    // Switch value
    stub.write_u32::<LittleEndian>(10).unwrap();

    // Container pointer
    stub.write_u32::<LittleEndian>(0x00020004).unwrap();

    // EntriesRead
    stub.write_u32::<LittleEndian>(0).unwrap();

    // Buffer
    stub.write_u32::<LittleEndian>(0).unwrap();

    // PreferedMaximumLength
    stub.write_u32::<LittleEndian>(0xFFFFFFFF).unwrap();

    // ResumeHandle
    stub.write_u32::<LittleEndian>(0x00020008).unwrap();
    stub.write_u32::<LittleEndian>(0).unwrap();

    let request = RpcRequest::new(srvsvc_opnum::NETR_SESSION_ENUM, stub, call_id);
    request.serialize()
}

/// Parse NetrSessionEnum response (level 10)
pub fn parse_session_enum_response(data: &[u8]) -> SmbResult<Vec<SessionInfo>> {
    if data.len() < 20 {
        return Err(SmbError::InvalidResponse(
            "Session enum response too short".to_string(),
        ));
    }

    let mut cursor = Cursor::new(data);

    let _level = cursor.read_u32::<LittleEndian>()?;
    let _switch = cursor.read_u32::<LittleEndian>()?;
    let container_ptr = cursor.read_u32::<LittleEndian>()?;

    if container_ptr == 0 {
        return Ok(Vec::new());
    }

    let entries_read = cursor.read_u32::<LittleEndian>()?;
    let buffer_ptr = cursor.read_u32::<LittleEndian>()?;

    if buffer_ptr == 0 || entries_read == 0 {
        return Ok(Vec::new());
    }

    let max_count = cursor.read_u32::<LittleEndian>()?;
    let mut offset = cursor.position() as usize;

    // SESSION_INFO_10 entries
    let mut entries: Vec<(u32, u32, u32, u32)> = Vec::new();
    for _ in 0..max_count.min(entries_read) {
        if offset + 16 > data.len() {
            break;
        }
        let client_ptr =
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]));
        let user_ptr =
            u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap_or([0; 4]));
        let time = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));
        let idle_time =
            u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap_or([0; 4]));
        entries.push((client_ptr, user_ptr, time, idle_time));
        offset += 16;
    }

    let mut sessions = Vec::new();
    for (client_ptr, user_ptr, time, idle_time) in entries {
        let client = if client_ptr != 0 {
            parse_ndr_string(data, &mut offset).unwrap_or_default()
        } else {
            String::new()
        };

        let user = if user_ptr != 0 {
            parse_ndr_string(data, &mut offset).unwrap_or_default()
        } else {
            String::new()
        };

        sessions.push(SessionInfo {
            client,
            user,
            num_opens: 0,
            time,
            idle_time,
            user_flags: 0,
        });
    }

    Ok(sessions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_srvsvc_bind() {
        let bind = create_srvsvc_bind(1);
        assert!(bind.len() > RpcHeader::SIZE);

        let header = RpcHeader::parse(&bind).unwrap();
        assert_eq!(header.packet_type, RpcPacketType::Bind);
    }

    #[test]
    fn test_create_share_enum_request() {
        let req = create_share_enum_request("SERVER", 1);
        assert!(req.len() > RpcHeader::SIZE);

        let header = RpcHeader::parse(&req).unwrap();
        assert_eq!(header.packet_type, RpcPacketType::Request);
    }
}
