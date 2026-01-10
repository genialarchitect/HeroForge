//! DCE/RPC Protocol Types
//!
//! Common types and structures for DCE/RPC over SMB.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};

/// DCE/RPC version
pub const RPC_MAJOR_VERSION: u8 = 5;
pub const RPC_MINOR_VERSION: u8 = 0;

/// Maximum RPC fragment size
pub const MAX_XMIT_FRAG: u16 = 4280;
pub const MAX_RECV_FRAG: u16 = 4280;

/// RPC packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RpcPacketType {
    Request = 0,
    Ping = 1,
    Response = 2,
    Fault = 3,
    Working = 4,
    Nocall = 5,
    Reject = 6,
    Ack = 7,
    ClCancel = 8,
    Fack = 9,
    CancelAck = 10,
    Bind = 11,
    BindAck = 12,
    BindNak = 13,
    AlterContext = 14,
    AlterContextResp = 15,
    Shutdown = 17,
    CoCancel = 18,
    Orphaned = 19,
}

impl RpcPacketType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Request),
            1 => Some(Self::Ping),
            2 => Some(Self::Response),
            3 => Some(Self::Fault),
            4 => Some(Self::Working),
            5 => Some(Self::Nocall),
            6 => Some(Self::Reject),
            7 => Some(Self::Ack),
            8 => Some(Self::ClCancel),
            9 => Some(Self::Fack),
            10 => Some(Self::CancelAck),
            11 => Some(Self::Bind),
            12 => Some(Self::BindAck),
            13 => Some(Self::BindNak),
            14 => Some(Self::AlterContext),
            15 => Some(Self::AlterContextResp),
            17 => Some(Self::Shutdown),
            18 => Some(Self::CoCancel),
            19 => Some(Self::Orphaned),
            _ => None,
        }
    }
}

/// RPC packet flags
pub mod rpc_flags {
    pub const PFC_FIRST_FRAG: u8 = 0x01;
    pub const PFC_LAST_FRAG: u8 = 0x02;
    pub const PFC_PENDING_CANCEL: u8 = 0x04;
    pub const PFC_RESERVED_1: u8 = 0x08;
    pub const PFC_CONC_MPX: u8 = 0x10;
    pub const PFC_DID_NOT_EXECUTE: u8 = 0x20;
    pub const PFC_MAYBE: u8 = 0x40;
    pub const PFC_OBJECT_UUID: u8 = 0x80;
}

/// DCE/RPC UUID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcUuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl RpcUuid {
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.write_u32::<LittleEndian>(self.data1).unwrap();
        buf.write_u16::<LittleEndian>(self.data2).unwrap();
        buf.write_u16::<LittleEndian>(self.data3).unwrap();
        buf.extend_from_slice(&self.data4);
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let mut cursor = Cursor::new(data);
        let data1 = cursor.read_u32::<LittleEndian>().ok()?;
        let data2 = cursor.read_u16::<LittleEndian>().ok()?;
        let data3 = cursor.read_u16::<LittleEndian>().ok()?;
        let mut data4 = [0u8; 8];
        cursor.read_exact(&mut data4).ok()?;
        Some(Self {
            data1,
            data2,
            data3,
            data4,
        })
    }
}

/// Well-known interface UUIDs
pub mod interfaces {
    use super::RpcUuid;

    /// SRVSVC - Server Service
    pub const SRVSVC: RpcUuid = RpcUuid::new(
        0x4b324fc8,
        0x1670,
        0x01d3,
        [0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88],
    );

    /// SAMR - Security Account Manager
    pub const SAMR: RpcUuid = RpcUuid::new(
        0x12345778,
        0x1234,
        0xabcd,
        [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab],
    );

    /// LSARPC - Local Security Authority
    pub const LSARPC: RpcUuid = RpcUuid::new(
        0x12345778,
        0x1234,
        0xabcd,
        [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac],
    );

    /// WKSSVC - Workstation Service
    pub const WKSSVC: RpcUuid = RpcUuid::new(
        0x6bffd098,
        0xa112,
        0x3610,
        [0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a],
    );

    /// NDR Transfer Syntax
    pub const NDR_SYNTAX: RpcUuid = RpcUuid::new(
        0x8a885d04,
        0x1ceb,
        0x11c9,
        [0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60],
    );
}

/// Syntax ID (UUID + version)
#[derive(Debug, Clone)]
pub struct RpcSyntaxId {
    pub uuid: RpcUuid,
    pub version: u32,
}

impl RpcSyntaxId {
    pub fn new(uuid: RpcUuid, major: u16, minor: u16) -> Self {
        Self {
            uuid,
            version: ((minor as u32) << 16) | (major as u32),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = self.uuid.serialize();
        buf.write_u32::<LittleEndian>(self.version).unwrap();
        buf
    }
}

/// Context element for bind
#[derive(Debug, Clone)]
pub struct RpcContextElement {
    pub context_id: u16,
    pub abstract_syntax: RpcSyntaxId,
    pub transfer_syntaxes: Vec<RpcSyntaxId>,
}

impl RpcContextElement {
    pub fn new(context_id: u16, interface: RpcUuid, version: (u16, u16)) -> Self {
        Self {
            context_id,
            abstract_syntax: RpcSyntaxId::new(interface, version.0, version.1),
            transfer_syntaxes: vec![RpcSyntaxId::new(interfaces::NDR_SYNTAX, 2, 0)],
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Context ID
        buf.write_u16::<LittleEndian>(self.context_id).unwrap();
        // Number of transfer syntaxes
        buf.write_u8(self.transfer_syntaxes.len() as u8).unwrap();
        // Reserved
        buf.write_u8(0).unwrap();

        // Abstract syntax
        buf.extend_from_slice(&self.abstract_syntax.serialize());

        // Transfer syntaxes
        for ts in &self.transfer_syntaxes {
            buf.extend_from_slice(&ts.serialize());
        }

        buf
    }
}

/// RPC common header
#[derive(Debug, Clone)]
pub struct RpcHeader {
    pub version_major: u8,
    pub version_minor: u8,
    pub packet_type: RpcPacketType,
    pub flags: u8,
    pub data_representation: [u8; 4],
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

impl Default for RpcHeader {
    fn default() -> Self {
        Self {
            version_major: RPC_MAJOR_VERSION,
            version_minor: RPC_MINOR_VERSION,
            packet_type: RpcPacketType::Request,
            flags: rpc_flags::PFC_FIRST_FRAG | rpc_flags::PFC_LAST_FRAG,
            data_representation: [0x10, 0x00, 0x00, 0x00], // Little-endian, ASCII, IEEE float
            frag_length: 0,
            auth_length: 0,
            call_id: 1,
        }
    }
}

impl RpcHeader {
    pub const SIZE: usize = 16;

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);
        buf.write_u8(self.version_major).unwrap();
        buf.write_u8(self.version_minor).unwrap();
        buf.write_u8(self.packet_type as u8).unwrap();
        buf.write_u8(self.flags).unwrap();
        buf.extend_from_slice(&self.data_representation);
        buf.write_u16::<LittleEndian>(self.frag_length).unwrap();
        buf.write_u16::<LittleEndian>(self.auth_length).unwrap();
        buf.write_u32::<LittleEndian>(self.call_id).unwrap();
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        let mut cursor = Cursor::new(data);

        let version_major = cursor.read_u8().ok()?;
        let version_minor = cursor.read_u8().ok()?;
        let packet_type_val = cursor.read_u8().ok()?;
        let flags = cursor.read_u8().ok()?;

        let mut data_representation = [0u8; 4];
        cursor.read_exact(&mut data_representation).ok()?;

        let frag_length = cursor.read_u16::<LittleEndian>().ok()?;
        let auth_length = cursor.read_u16::<LittleEndian>().ok()?;
        let call_id = cursor.read_u32::<LittleEndian>().ok()?;

        Some(Self {
            version_major,
            version_minor,
            packet_type: RpcPacketType::from_u8(packet_type_val)?,
            flags,
            data_representation,
            frag_length,
            auth_length,
            call_id,
        })
    }
}

/// RPC Bind request
#[derive(Debug)]
pub struct RpcBindRequest {
    pub header: RpcHeader,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group: u32,
    pub contexts: Vec<RpcContextElement>,
}

impl RpcBindRequest {
    pub fn new(context: RpcContextElement, call_id: u32) -> Self {
        Self {
            header: RpcHeader {
                packet_type: RpcPacketType::Bind,
                call_id,
                ..Default::default()
            },
            max_xmit_frag: MAX_XMIT_FRAG,
            max_recv_frag: MAX_RECV_FRAG,
            assoc_group: 0,
            contexts: vec![context],
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut body = Vec::new();

        // Bind-specific fields
        body.write_u16::<LittleEndian>(self.max_xmit_frag).unwrap();
        body.write_u16::<LittleEndian>(self.max_recv_frag).unwrap();
        body.write_u32::<LittleEndian>(self.assoc_group).unwrap();

        // Number of context elements
        body.write_u8(self.contexts.len() as u8).unwrap();
        // Reserved
        body.extend_from_slice(&[0u8; 3]);

        // Context elements
        for ctx in &self.contexts {
            body.extend_from_slice(&ctx.serialize());
        }

        // Build complete packet
        let mut header = self.header.clone();
        header.frag_length = (RpcHeader::SIZE + body.len()) as u16;

        let mut packet = header.serialize();
        packet.extend_from_slice(&body);

        packet
    }
}

/// RPC Bind Ack response
#[derive(Debug)]
pub struct RpcBindAck {
    pub header: RpcHeader,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group: u32,
    pub result: u16,
}

impl RpcBindAck {
    pub fn parse(data: &[u8]) -> Option<Self> {
        let header = RpcHeader::parse(data)?;

        if header.packet_type != RpcPacketType::BindAck {
            return None;
        }

        if data.len() < RpcHeader::SIZE + 12 {
            return None;
        }

        let mut cursor = Cursor::new(&data[RpcHeader::SIZE..]);

        let max_xmit_frag = cursor.read_u16::<LittleEndian>().ok()?;
        let max_recv_frag = cursor.read_u16::<LittleEndian>().ok()?;
        let assoc_group = cursor.read_u32::<LittleEndian>().ok()?;

        // Skip secondary address
        let sec_addr_len = cursor.read_u16::<LittleEndian>().ok()?;
        let padding = (4 - ((sec_addr_len + 2) % 4)) % 4;
        let skip = sec_addr_len as usize + padding as usize;
        if cursor.position() as usize + skip > data.len() - RpcHeader::SIZE {
            return None;
        }
        cursor.set_position(cursor.position() + skip as u64);

        // Results
        let _num_results = cursor.read_u8().ok()?;
        let _ = cursor.read_u8().ok()?; // reserved
        let _ = cursor.read_u16::<LittleEndian>().ok()?; // reserved
        let result = cursor.read_u16::<LittleEndian>().ok()?;

        Some(Self {
            header,
            max_xmit_frag,
            max_recv_frag,
            assoc_group,
            result,
        })
    }

    pub fn is_accepted(&self) -> bool {
        self.result == 0
    }
}

/// RPC Request
#[derive(Debug)]
pub struct RpcRequest {
    pub header: RpcHeader,
    pub alloc_hint: u32,
    pub context_id: u16,
    pub opnum: u16,
    pub stub_data: Vec<u8>,
}

impl RpcRequest {
    pub fn new(opnum: u16, stub_data: Vec<u8>, call_id: u32) -> Self {
        Self {
            header: RpcHeader {
                packet_type: RpcPacketType::Request,
                call_id,
                ..Default::default()
            },
            alloc_hint: stub_data.len() as u32,
            context_id: 0,
            opnum,
            stub_data,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut body = Vec::new();

        // Request-specific fields
        body.write_u32::<LittleEndian>(self.alloc_hint).unwrap();
        body.write_u16::<LittleEndian>(self.context_id).unwrap();
        body.write_u16::<LittleEndian>(self.opnum).unwrap();

        // Stub data
        body.extend_from_slice(&self.stub_data);

        // Build complete packet
        let mut header = self.header.clone();
        header.frag_length = (RpcHeader::SIZE + body.len()) as u16;

        let mut packet = header.serialize();
        packet.extend_from_slice(&body);

        packet
    }
}

/// RPC Response
#[derive(Debug)]
pub struct RpcResponse {
    pub header: RpcHeader,
    pub alloc_hint: u32,
    pub context_id: u16,
    pub cancel_count: u8,
    pub stub_data: Vec<u8>,
}

impl RpcResponse {
    pub fn parse(data: &[u8]) -> Option<Self> {
        let header = RpcHeader::parse(data)?;

        if header.packet_type != RpcPacketType::Response {
            return None;
        }

        if data.len() < RpcHeader::SIZE + 8 {
            return None;
        }

        let mut cursor = Cursor::new(&data[RpcHeader::SIZE..]);

        let alloc_hint = cursor.read_u32::<LittleEndian>().ok()?;
        let context_id = cursor.read_u16::<LittleEndian>().ok()?;
        let cancel_count = cursor.read_u8().ok()?;
        let _reserved = cursor.read_u8().ok()?;

        let stub_start = RpcHeader::SIZE + 8;
        let stub_end = header.frag_length as usize - header.auth_length as usize;
        let stub_data = if stub_start < stub_end && stub_end <= data.len() {
            data[stub_start..stub_end].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            header,
            alloc_hint,
            context_id,
            cancel_count,
            stub_data,
        })
    }
}

/// RPC Fault
#[derive(Debug)]
pub struct RpcFault {
    pub header: RpcHeader,
    pub status: u32,
}

impl RpcFault {
    pub fn parse(data: &[u8]) -> Option<Self> {
        let header = RpcHeader::parse(data)?;

        if header.packet_type != RpcPacketType::Fault {
            return None;
        }

        if data.len() < RpcHeader::SIZE + 8 {
            return None;
        }

        let mut cursor = Cursor::new(&data[RpcHeader::SIZE..]);
        let _alloc_hint = cursor.read_u32::<LittleEndian>().ok()?;
        let _context_id = cursor.read_u16::<LittleEndian>().ok()?;
        let _cancel_count = cursor.read_u8().ok()?;
        let _reserved = cursor.read_u8().ok()?;
        let status = cursor.read_u32::<LittleEndian>().ok()?;

        Some(Self { header, status })
    }
}

/// NDR conformant string (used in many RPC calls)
pub fn ndr_string(s: &str) -> Vec<u8> {
    let utf16: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let mut buf = Vec::new();

    // Max count
    buf.write_u32::<LittleEndian>(utf16.len() as u32).unwrap();
    // Offset
    buf.write_u32::<LittleEndian>(0).unwrap();
    // Actual count
    buf.write_u32::<LittleEndian>(utf16.len() as u32).unwrap();

    // String data
    for c in utf16 {
        buf.write_u16::<LittleEndian>(c).unwrap();
    }

    // Padding to 4-byte boundary
    while buf.len() % 4 != 0 {
        buf.push(0);
    }

    buf
}

/// NDR unique pointer
pub fn ndr_pointer(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    // Referent ID (non-zero means valid pointer)
    buf.write_u32::<LittleEndian>(0x00020000).unwrap();
    buf.extend_from_slice(data);
    buf
}

/// Parse NDR conformant string from response
pub fn parse_ndr_string(data: &[u8], offset: &mut usize) -> Option<String> {
    if *offset + 12 > data.len() {
        return None;
    }

    let mut cursor = Cursor::new(&data[*offset..]);
    let max_count = cursor.read_u32::<LittleEndian>().ok()? as usize;
    let _offset_val = cursor.read_u32::<LittleEndian>().ok()?;
    let actual_count = cursor.read_u32::<LittleEndian>().ok()? as usize;

    *offset += 12;

    if actual_count == 0 || max_count == 0 {
        return Some(String::new());
    }

    let byte_len = actual_count * 2;
    if *offset + byte_len > data.len() {
        return None;
    }

    let utf16: Vec<u16> = data[*offset..*offset + byte_len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    *offset += byte_len;
    // Align to 4 bytes
    *offset = (*offset + 3) & !3;

    // Remove trailing null if present
    let s: String = utf16
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
        .collect();

    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_serialize() {
        let uuid = interfaces::SRVSVC;
        let bytes = uuid.serialize();
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn test_rpc_header_serialize_parse() {
        let header = RpcHeader::default();
        let bytes = header.serialize();
        assert_eq!(bytes.len(), RpcHeader::SIZE);

        let parsed = RpcHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.version_major, header.version_major);
        assert_eq!(parsed.call_id, header.call_id);
    }

    #[test]
    fn test_ndr_string() {
        let s = "test";
        let encoded = ndr_string(s);

        // Max count (5 including null), offset (0), actual count (5)
        // Then 5 UTF-16LE characters + padding
        assert!(encoded.len() >= 12);
        assert_eq!(encoded.len() % 4, 0); // Should be aligned
    }
}
