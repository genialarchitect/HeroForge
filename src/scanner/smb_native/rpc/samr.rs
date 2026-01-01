//! SAMR - Security Account Manager RPC Interface
//!
//! Implements user and group enumeration via MS-SAMR protocol.

use super::types::*;
use crate::scanner::smb_native::types::{SmbError, SmbResult};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;

/// SAMR operation numbers
pub mod samr_opnum {
    pub const SAMR_CONNECT: u16 = 0;
    pub const SAMR_CLOSE_HANDLE: u16 = 1;
    pub const SAMR_LOOKUP_DOMAIN_IN_SAM_SERVER: u16 = 5;
    pub const SAMR_OPEN_DOMAIN: u16 = 7;
    pub const SAMR_QUERY_INFORMATION_DOMAIN: u16 = 8;
    pub const SAMR_ENUMERATE_DOMAINS_IN_SAM_SERVER: u16 = 6;
    pub const SAMR_ENUMERATE_USERS_IN_DOMAIN: u16 = 13;
    pub const SAMR_ENUMERATE_GROUPS_IN_DOMAIN: u16 = 11;
    pub const SAMR_ENUMERATE_ALIASES_IN_DOMAIN: u16 = 15;
    pub const SAMR_OPEN_USER: u16 = 34;
    pub const SAMR_QUERY_INFORMATION_USER: u16 = 36;
    pub const SAMR_GET_GROUPS_FOR_USER: u16 = 39;
    pub const SAMR_OPEN_GROUP: u16 = 19;
    pub const SAMR_QUERY_INFORMATION_GROUP: u16 = 20;
    pub const SAMR_GET_MEMBERS_IN_GROUP: u16 = 25;
    pub const SAMR_OPEN_ALIAS: u16 = 27;
    pub const SAMR_QUERY_INFORMATION_ALIAS: u16 = 28;
    pub const SAMR_GET_MEMBERS_IN_ALIAS: u16 = 33;
}

/// SAMR interface version
pub const SAMR_VERSION: (u16, u16) = (1, 0);

/// SAMR handle (policy/domain/user/group context)
pub type SamrHandle = [u8; 20];

/// Access masks for SAMR
pub mod samr_access {
    pub const SAM_SERVER_CONNECT: u32 = 0x00000001;
    pub const SAM_SERVER_SHUTDOWN: u32 = 0x00000002;
    pub const SAM_SERVER_INITIALIZE: u32 = 0x00000004;
    pub const SAM_SERVER_CREATE_DOMAIN: u32 = 0x00000008;
    pub const SAM_SERVER_ENUMERATE_DOMAINS: u32 = 0x00000010;
    pub const SAM_SERVER_LOOKUP_DOMAIN: u32 = 0x00000020;
    pub const SAM_SERVER_ALL_ACCESS: u32 = 0x000F003F;
    pub const SAM_SERVER_READ: u32 = 0x00020010;

    pub const DOMAIN_READ_PASSWORD_PARAMETERS: u32 = 0x00000001;
    pub const DOMAIN_WRITE_PASSWORD_PARAMS: u32 = 0x00000002;
    pub const DOMAIN_READ_OTHER_PARAMETERS: u32 = 0x00000004;
    pub const DOMAIN_WRITE_OTHER_PARAMETERS: u32 = 0x00000008;
    pub const DOMAIN_CREATE_USER: u32 = 0x00000010;
    pub const DOMAIN_CREATE_GROUP: u32 = 0x00000020;
    pub const DOMAIN_CREATE_ALIAS: u32 = 0x00000040;
    pub const DOMAIN_GET_ALIAS_MEMBERSHIP: u32 = 0x00000080;
    pub const DOMAIN_LIST_ACCOUNTS: u32 = 0x00000100;
    pub const DOMAIN_LOOKUP: u32 = 0x00000200;
    pub const DOMAIN_ALL_ACCESS: u32 = 0x000F07FF;

    pub const USER_READ_GENERAL: u32 = 0x00000001;
    pub const USER_READ_PREFERENCES: u32 = 0x00000002;
    pub const USER_WRITE_PREFERENCES: u32 = 0x00000004;
    pub const USER_READ_LOGON: u32 = 0x00000008;
    pub const USER_READ_ACCOUNT: u32 = 0x00000010;
    pub const USER_WRITE_ACCOUNT: u32 = 0x00000020;
    pub const USER_CHANGE_PASSWORD: u32 = 0x00000040;
    pub const USER_FORCE_PASSWORD_CHANGE: u32 = 0x00000080;
    pub const USER_LIST_GROUPS: u32 = 0x00000100;
    pub const USER_READ_GROUP_INFORMATION: u32 = 0x00000200;
    pub const USER_ALL_ACCESS: u32 = 0x000F03FF;
}

/// User account control flags
pub mod user_flags {
    pub const ACCOUNT_DISABLED: u32 = 0x00000001;
    pub const HOME_DIR_REQUIRED: u32 = 0x00000002;
    pub const PASSWORD_NOT_REQUIRED: u32 = 0x00000004;
    pub const TEMP_DUPLICATE_ACCOUNT: u32 = 0x00000008;
    pub const NORMAL_ACCOUNT: u32 = 0x00000010;
    pub const MNS_LOGON_ACCOUNT: u32 = 0x00000020;
    pub const INTERDOMAIN_TRUST_ACCOUNT: u32 = 0x00000040;
    pub const WORKSTATION_TRUST_ACCOUNT: u32 = 0x00000080;
    pub const SERVER_TRUST_ACCOUNT: u32 = 0x00000100;
    pub const DONT_EXPIRE_PASSWORD: u32 = 0x00000200;
    pub const ACCOUNT_AUTO_LOCKED: u32 = 0x00000400;
    pub const ENCRYPTED_TEXT_PASSWORD_ALLOWED: u32 = 0x00000800;
    pub const SMARTCARD_REQUIRED: u32 = 0x00001000;
    pub const TRUSTED_FOR_DELEGATION: u32 = 0x00002000;
    pub const NOT_DELEGATED: u32 = 0x00004000;
    pub const USE_DES_KEY_ONLY: u32 = 0x00008000;
    pub const DONT_REQUIRE_PREAUTH: u32 = 0x00010000;
    pub const PASSWORD_EXPIRED: u32 = 0x00020000;
    pub const TRUSTED_TO_AUTH_FOR_DELEGATION: u32 = 0x00040000;
}

/// Create bind request for SAMR
pub fn create_samr_bind(call_id: u32) -> Vec<u8> {
    let context = RpcContextElement::new(0, interfaces::SAMR, SAMR_VERSION);
    let bind = RpcBindRequest::new(context, call_id);
    bind.serialize()
}

/// Create SamrConnect request
pub fn create_samr_connect(server: &str, access_mask: u32, call_id: u32) -> Vec<u8> {
    let mut stub = Vec::new();

    // ServerName (unique pointer to UNICODE_STRING)
    let server_name = format!("\\\\{}", server);
    stub.write_u32::<LittleEndian>(0x00020000).unwrap(); // Referent ID

    // UNICODE_STRING
    let utf16: Vec<u16> = server_name.encode_utf16().collect();
    let byte_len = (utf16.len() * 2) as u16;

    stub.write_u16::<LittleEndian>(byte_len).unwrap(); // Length
    stub.write_u16::<LittleEndian>(byte_len + 2).unwrap(); // MaximumLength
    stub.write_u32::<LittleEndian>(0x00020004).unwrap(); // String pointer

    // String data (conformant array)
    stub.write_u32::<LittleEndian>(utf16.len() as u32 + 1)
        .unwrap(); // MaxCount
    stub.write_u32::<LittleEndian>(0).unwrap(); // Offset
    stub.write_u32::<LittleEndian>(utf16.len() as u32 + 1)
        .unwrap(); // ActualCount

    for c in &utf16 {
        stub.write_u16::<LittleEndian>(*c).unwrap();
    }
    stub.write_u16::<LittleEndian>(0).unwrap(); // Null terminator

    // Padding
    while stub.len() % 4 != 0 {
        stub.push(0);
    }

    // DesiredAccess
    stub.write_u32::<LittleEndian>(access_mask).unwrap();

    let request = RpcRequest::new(samr_opnum::SAMR_CONNECT, stub, call_id);
    request.serialize()
}

/// Parse SamrConnect response to get server handle
pub fn parse_samr_connect_response(data: &[u8]) -> SmbResult<SamrHandle> {
    if data.len() < 24 {
        return Err(SmbError::InvalidResponse(
            "Connect response too short".to_string(),
        ));
    }

    // Handle (20 bytes) followed by NTSTATUS (4 bytes)
    let mut handle = [0u8; 20];
    handle.copy_from_slice(&data[0..20]);

    let status = u32::from_le_bytes(data[20..24].try_into().unwrap_or([0; 4]));
    if status != 0 {
        return Err(SmbError::Protocol(format!(
            "SamrConnect failed: 0x{:08x}",
            status
        )));
    }

    Ok(handle)
}

/// Create SamrEnumerateDomainsInSamServer request
pub fn create_enumerate_domains(server_handle: &SamrHandle, call_id: u32) -> Vec<u8> {
    let mut stub = Vec::new();

    // ServerHandle
    stub.extend_from_slice(server_handle);

    // EnumerationContext
    stub.write_u32::<LittleEndian>(0).unwrap();

    // PreferedMaximumLength
    stub.write_u32::<LittleEndian>(0xFFFFFFFF).unwrap();

    let request = RpcRequest::new(
        samr_opnum::SAMR_ENUMERATE_DOMAINS_IN_SAM_SERVER,
        stub,
        call_id,
    );
    request.serialize()
}

/// Domain entry from enumeration
#[derive(Debug, Clone)]
pub struct DomainEntry {
    pub rid: u32,
    pub name: String,
}

/// Parse SamrEnumerateDomainsInSamServer response
pub fn parse_enumerate_domains_response(data: &[u8]) -> SmbResult<Vec<DomainEntry>> {
    if data.len() < 12 {
        return Err(SmbError::InvalidResponse(
            "Enumerate domains response too short".to_string(),
        ));
    }

    let mut cursor = Cursor::new(data);

    // EnumerationContext (out)
    let _enum_ctx = cursor.read_u32::<LittleEndian>()?;

    // Buffer pointer
    let buffer_ptr = cursor.read_u32::<LittleEndian>()?;
    if buffer_ptr == 0 {
        return Ok(Vec::new());
    }

    // EntriesRead
    let entries_read = cursor.read_u32::<LittleEndian>()?;

    // Array pointer
    let array_ptr = cursor.read_u32::<LittleEndian>()?;
    if array_ptr == 0 {
        return Ok(Vec::new());
    }

    // Max count
    let max_count = cursor.read_u32::<LittleEndian>()?;

    let mut offset = cursor.position() as usize;
    let mut domains = Vec::new();

    // Read RID_NAME entries
    let mut entries: Vec<(u32, u16, u16, u32)> = Vec::new();
    for _ in 0..max_count.min(entries_read) {
        if offset + 12 > data.len() {
            break;
        }
        let rid = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]));
        let name_len = u16::from_le_bytes(data[offset + 4..offset + 6].try_into().unwrap_or([0; 2]));
        let name_max =
            u16::from_le_bytes(data[offset + 6..offset + 8].try_into().unwrap_or([0; 2]));
        let name_ptr = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));
        entries.push((rid, name_len, name_max, name_ptr));
        offset += 12;
    }

    // Read string data
    for (rid, _name_len, _name_max, name_ptr) in entries {
        let name = if name_ptr != 0 {
            parse_ndr_string(data, &mut offset).unwrap_or_default()
        } else {
            String::new()
        };

        domains.push(DomainEntry { rid, name });
    }

    Ok(domains)
}

/// Create SamrLookupDomainInSamServer request
pub fn create_lookup_domain(server_handle: &SamrHandle, domain_name: &str, call_id: u32) -> Vec<u8> {
    let mut stub = Vec::new();

    // ServerHandle
    stub.extend_from_slice(server_handle);

    // Name (UNICODE_STRING)
    let utf16: Vec<u16> = domain_name.encode_utf16().collect();
    let byte_len = (utf16.len() * 2) as u16;

    stub.write_u16::<LittleEndian>(byte_len).unwrap();
    stub.write_u16::<LittleEndian>(byte_len).unwrap();
    stub.write_u32::<LittleEndian>(0x00020000).unwrap();

    // String data
    stub.write_u32::<LittleEndian>(utf16.len() as u32).unwrap();
    stub.write_u32::<LittleEndian>(0).unwrap();
    stub.write_u32::<LittleEndian>(utf16.len() as u32).unwrap();

    for c in &utf16 {
        stub.write_u16::<LittleEndian>(*c).unwrap();
    }

    while stub.len() % 4 != 0 {
        stub.push(0);
    }

    let request = RpcRequest::new(
        samr_opnum::SAMR_LOOKUP_DOMAIN_IN_SAM_SERVER,
        stub,
        call_id,
    );
    request.serialize()
}

/// Parse SamrLookupDomainInSamServer response to get domain SID
pub fn parse_lookup_domain_response(data: &[u8]) -> SmbResult<Vec<u8>> {
    if data.len() < 8 {
        return Err(SmbError::InvalidResponse(
            "Lookup domain response too short".to_string(),
        ));
    }

    let mut cursor = Cursor::new(data);

    // DomainId pointer
    let sid_ptr = cursor.read_u32::<LittleEndian>()?;
    if sid_ptr == 0 {
        return Err(SmbError::InvalidResponse("Null domain SID".to_string()));
    }

    // SubAuthorityCount
    let _revision = cursor.read_u8()?;
    let sub_auth_count = cursor.read_u8()?;

    // Read full SID
    let sid_len = 8 + (sub_auth_count as usize * 4);
    if cursor.position() as usize - 2 + sid_len > data.len() {
        return Err(SmbError::InvalidResponse("SID truncated".to_string()));
    }

    let sid_start = cursor.position() as usize - 2;
    let sid = data[sid_start..sid_start + sid_len].to_vec();

    // Check status
    let status_offset = data.len() - 4;
    let status = u32::from_le_bytes(data[status_offset..].try_into().unwrap_or([0; 4]));
    if status != 0 {
        return Err(SmbError::Protocol(format!(
            "LookupDomain failed: 0x{:08x}",
            status
        )));
    }

    Ok(sid)
}

/// Create SamrOpenDomain request
pub fn create_open_domain(
    server_handle: &SamrHandle,
    domain_sid: &[u8],
    access_mask: u32,
    call_id: u32,
) -> Vec<u8> {
    let mut stub = Vec::new();

    // ServerHandle
    stub.extend_from_slice(server_handle);

    // DesiredAccess
    stub.write_u32::<LittleEndian>(access_mask).unwrap();

    // DomainId (SID)
    stub.write_u32::<LittleEndian>((domain_sid.len() / 4) as u32)
        .unwrap(); // SubAuthority count
    stub.extend_from_slice(domain_sid);

    while stub.len() % 4 != 0 {
        stub.push(0);
    }

    let request = RpcRequest::new(samr_opnum::SAMR_OPEN_DOMAIN, stub, call_id);
    request.serialize()
}

/// Parse SamrOpenDomain response to get domain handle
pub fn parse_open_domain_response(data: &[u8]) -> SmbResult<SamrHandle> {
    if data.len() < 24 {
        return Err(SmbError::InvalidResponse(
            "Open domain response too short".to_string(),
        ));
    }

    let mut handle = [0u8; 20];
    handle.copy_from_slice(&data[0..20]);

    let status = u32::from_le_bytes(data[20..24].try_into().unwrap_or([0; 4]));
    if status != 0 {
        return Err(SmbError::Protocol(format!(
            "OpenDomain failed: 0x{:08x}",
            status
        )));
    }

    Ok(handle)
}

/// User entry from enumeration
#[derive(Debug, Clone)]
pub struct SamrUserEntry {
    pub rid: u32,
    pub name: String,
}

/// Create SamrEnumerateUsersInDomain request
pub fn create_enumerate_users(
    domain_handle: &SamrHandle,
    user_account_control: u32,
    call_id: u32,
) -> Vec<u8> {
    let mut stub = Vec::new();

    // DomainHandle
    stub.extend_from_slice(domain_handle);

    // EnumerationContext
    stub.write_u32::<LittleEndian>(0).unwrap();

    // UserAccountControl (filter)
    stub.write_u32::<LittleEndian>(user_account_control).unwrap();

    // PreferedMaximumLength
    stub.write_u32::<LittleEndian>(0xFFFFFFFF).unwrap();

    let request = RpcRequest::new(samr_opnum::SAMR_ENUMERATE_USERS_IN_DOMAIN, stub, call_id);
    request.serialize()
}

/// Parse SamrEnumerateUsersInDomain response
pub fn parse_enumerate_users_response(data: &[u8]) -> SmbResult<Vec<SamrUserEntry>> {
    if data.len() < 12 {
        return Err(SmbError::InvalidResponse(
            "Enumerate users response too short".to_string(),
        ));
    }

    let mut cursor = Cursor::new(data);

    // EnumerationContext
    let _enum_ctx = cursor.read_u32::<LittleEndian>()?;

    // Buffer pointer
    let buffer_ptr = cursor.read_u32::<LittleEndian>()?;
    if buffer_ptr == 0 {
        return Ok(Vec::new());
    }

    // EntriesRead
    let entries_read = cursor.read_u32::<LittleEndian>()?;

    // Array pointer
    let array_ptr = cursor.read_u32::<LittleEndian>()?;
    if array_ptr == 0 {
        return Ok(Vec::new());
    }

    let max_count = cursor.read_u32::<LittleEndian>()?;

    let mut offset = cursor.position() as usize;
    let mut users = Vec::new();

    // Read entries
    let mut entries: Vec<(u32, u32)> = Vec::new();
    for _ in 0..max_count.min(entries_read) {
        if offset + 12 > data.len() {
            break;
        }
        let rid = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]));
        // Skip UNICODE_STRING inline (len, max, ptr)
        let name_ptr = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));
        entries.push((rid, name_ptr));
        offset += 12;
    }

    for (rid, name_ptr) in entries {
        let name = if name_ptr != 0 {
            parse_ndr_string(data, &mut offset).unwrap_or_default()
        } else {
            String::new()
        };

        users.push(SamrUserEntry { rid, name });
    }

    Ok(users)
}

/// Group entry from enumeration
#[derive(Debug, Clone)]
pub struct SamrGroupEntry {
    pub rid: u32,
    pub name: String,
    pub attributes: u32,
}

/// Create SamrEnumerateGroupsInDomain request
pub fn create_enumerate_groups(domain_handle: &SamrHandle, call_id: u32) -> Vec<u8> {
    let mut stub = Vec::new();

    // DomainHandle
    stub.extend_from_slice(domain_handle);

    // EnumerationContext
    stub.write_u32::<LittleEndian>(0).unwrap();

    // PreferedMaximumLength
    stub.write_u32::<LittleEndian>(0xFFFFFFFF).unwrap();

    let request = RpcRequest::new(samr_opnum::SAMR_ENUMERATE_GROUPS_IN_DOMAIN, stub, call_id);
    request.serialize()
}

/// Parse SamrEnumerateGroupsInDomain response
pub fn parse_enumerate_groups_response(data: &[u8]) -> SmbResult<Vec<SamrGroupEntry>> {
    if data.len() < 12 {
        return Err(SmbError::InvalidResponse(
            "Enumerate groups response too short".to_string(),
        ));
    }

    let mut cursor = Cursor::new(data);

    let _enum_ctx = cursor.read_u32::<LittleEndian>()?;
    let buffer_ptr = cursor.read_u32::<LittleEndian>()?;

    if buffer_ptr == 0 {
        return Ok(Vec::new());
    }

    let entries_read = cursor.read_u32::<LittleEndian>()?;
    let array_ptr = cursor.read_u32::<LittleEndian>()?;

    if array_ptr == 0 {
        return Ok(Vec::new());
    }

    let max_count = cursor.read_u32::<LittleEndian>()?;
    let mut offset = cursor.position() as usize;

    let mut groups = Vec::new();
    let mut entries: Vec<(u32, u32, u32)> = Vec::new();

    for _ in 0..max_count.min(entries_read) {
        if offset + 16 > data.len() {
            break;
        }
        let rid = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]));
        let name_ptr = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));
        let attributes =
            u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap_or([0; 4]));
        entries.push((rid, name_ptr, attributes));
        offset += 16;
    }

    for (rid, name_ptr, attributes) in entries {
        let name = if name_ptr != 0 {
            parse_ndr_string(data, &mut offset).unwrap_or_default()
        } else {
            String::new()
        };

        groups.push(SamrGroupEntry {
            rid,
            name,
            attributes,
        });
    }

    Ok(groups)
}

/// Create SamrCloseHandle request
pub fn create_close_handle(handle: &SamrHandle, call_id: u32) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(handle);

    let request = RpcRequest::new(samr_opnum::SAMR_CLOSE_HANDLE, stub, call_id);
    request.serialize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_samr_bind() {
        let bind = create_samr_bind(1);
        assert!(bind.len() > RpcHeader::SIZE);

        let header = RpcHeader::parse(&bind).unwrap();
        assert_eq!(header.packet_type, RpcPacketType::Bind);
    }

    #[test]
    fn test_user_flags() {
        assert_eq!(user_flags::ACCOUNT_DISABLED, 0x00000001);
        assert_eq!(user_flags::NORMAL_ACCOUNT, 0x00000010);
        assert_eq!(user_flags::DONT_EXPIRE_PASSWORD, 0x00000200);
    }
}
