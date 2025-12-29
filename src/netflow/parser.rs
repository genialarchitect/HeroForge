//! NetFlow v5/v9 and IPFIX parser
//! Parses binary flow data from network exporters

use std::collections::HashMap;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::types::*;

/// Parser error types
#[derive(Debug)]
pub enum ParseError {
    InvalidHeader,
    InvalidVersion(u16),
    InsufficientData,
    InvalidTemplate,
    UnknownTemplate(u16),
    InvalidFieldType(u16),
    IoError(std::io::Error),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InvalidHeader => write!(f, "Invalid packet header"),
            ParseError::InvalidVersion(v) => write!(f, "Invalid or unsupported version: {}", v),
            ParseError::InsufficientData => write!(f, "Insufficient data in packet"),
            ParseError::InvalidTemplate => write!(f, "Invalid template definition"),
            ParseError::UnknownTemplate(id) => write!(f, "Unknown template ID: {}", id),
            ParseError::InvalidFieldType(t) => write!(f, "Invalid field type: {}", t),
            ParseError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::IoError(e)
    }
}

/// Parsed flow from any protocol
#[derive(Debug, Clone)]
pub struct ParsedFlow {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub packets: u64,
    pub bytes: u64,
    pub tcp_flags: u8,
    pub tos: u8,
    pub input_iface: u32,
    pub output_iface: u32,
    pub start_time_ms: u64,
    pub end_time_ms: u64,
    pub src_as: u32,
    pub dst_as: u32,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub next_hop: Option<IpAddr>,
    pub direction: Option<u8>,
    pub sampling_rate: u32,
}

/// Template cache for NetFlow v9 and IPFIX
pub struct TemplateCache {
    templates: HashMap<(IpAddr, u16), FlowTemplate>,
}

impl TemplateCache {
    pub fn new() -> Self {
        TemplateCache {
            templates: HashMap::new(),
        }
    }

    pub fn insert(&mut self, exporter: IpAddr, template_id: u16, template: FlowTemplate) {
        self.templates.insert((exporter, template_id), template);
    }

    pub fn get(&self, exporter: IpAddr, template_id: u16) -> Option<&FlowTemplate> {
        self.templates.get(&(exporter, template_id))
    }

    pub fn clear_exporter(&mut self, exporter: IpAddr) {
        self.templates.retain(|(exp, _), _| *exp != exporter);
    }
}

impl Default for TemplateCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Read a big-endian u16 from bytes
fn read_be_u16(data: &[u8], offset: usize) -> Result<u16, ParseError> {
    if offset + 2 > data.len() {
        return Err(ParseError::InsufficientData);
    }
    Ok(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

/// Read a big-endian u32 from bytes
fn read_be_u32(data: &[u8], offset: usize) -> Result<u32, ParseError> {
    if offset + 4 > data.len() {
        return Err(ParseError::InsufficientData);
    }
    Ok(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Read a big-endian u64 from bytes
fn read_be_u64(data: &[u8], offset: usize) -> Result<u64, ParseError> {
    if offset + 8 > data.len() {
        return Err(ParseError::InsufficientData);
    }
    Ok(u64::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}

/// Parse NetFlow v5 packet
pub fn parse_netflow_v5(data: &[u8], exporter: IpAddr) -> Result<(NetflowV5Header, Vec<ParsedFlow>), ParseError> {
    if data.len() < 24 {
        return Err(ParseError::InsufficientData);
    }

    let version = read_be_u16(data, 0)?;
    if version != 5 {
        return Err(ParseError::InvalidVersion(version));
    }

    let count = read_be_u16(data, 2)?;
    let sys_uptime = read_be_u32(data, 4)?;
    let unix_secs = read_be_u32(data, 8)?;
    let unix_nsecs = read_be_u32(data, 12)?;
    let flow_sequence = read_be_u32(data, 16)?;
    let engine_type = data[20];
    let engine_id = data[21];
    let sampling_interval = read_be_u16(data, 22)?;

    let header = NetflowV5Header {
        version,
        count,
        sys_uptime,
        unix_secs,
        unix_nsecs,
        flow_sequence,
        engine_type,
        engine_id,
        sampling_interval,
    };

    // Each v5 record is 48 bytes
    let expected_len = 24 + (count as usize) * 48;
    if data.len() < expected_len {
        return Err(ParseError::InsufficientData);
    }

    let mut flows = Vec::with_capacity(count as usize);
    let boot_time_ms = (unix_secs as u64 * 1000) + (unix_nsecs as u64 / 1_000_000);
    let sampling_rate = (sampling_interval & 0x3FFF) as u32;

    for i in 0..count as usize {
        let offset = 24 + i * 48;

        let src_addr = Ipv4Addr::new(data[offset], data[offset + 1], data[offset + 2], data[offset + 3]);
        let dst_addr = Ipv4Addr::new(data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]);
        let next_hop = Ipv4Addr::new(data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]);

        let input_iface = read_be_u16(data, offset + 12)? as u32;
        let output_iface = read_be_u16(data, offset + 14)? as u32;
        let packets = read_be_u32(data, offset + 16)? as u64;
        let bytes = read_be_u32(data, offset + 20)? as u64;
        let first = read_be_u32(data, offset + 24)?;
        let last = read_be_u32(data, offset + 28)?;
        let src_port = read_be_u16(data, offset + 32)?;
        let dst_port = read_be_u16(data, offset + 34)?;
        // offset + 36 is padding
        let tcp_flags = data[offset + 37];
        let protocol = data[offset + 38];
        let tos = data[offset + 39];
        let src_as = read_be_u16(data, offset + 40)? as u32;
        let dst_as = read_be_u16(data, offset + 42)? as u32;
        let src_mask = data[offset + 44];
        let dst_mask = data[offset + 45];

        // Calculate absolute timestamps
        // first/last are ms since boot, we need to convert to absolute ms
        let start_time_ms = boot_time_ms.saturating_sub((sys_uptime.saturating_sub(first)) as u64);
        let end_time_ms = boot_time_ms.saturating_sub((sys_uptime.saturating_sub(last)) as u64);

        flows.push(ParsedFlow {
            src_addr: IpAddr::V4(src_addr),
            dst_addr: IpAddr::V4(dst_addr),
            src_port,
            dst_port,
            protocol,
            packets,
            bytes,
            tcp_flags,
            tos,
            input_iface,
            output_iface,
            start_time_ms,
            end_time_ms,
            src_as,
            dst_as,
            src_mask,
            dst_mask,
            next_hop: Some(IpAddr::V4(next_hop)),
            direction: None,
            sampling_rate,
        });
    }

    Ok((header, flows))
}

/// NetFlow v9 field types (subset of commonly used)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetflowV9FieldType {
    InBytes = 1,
    InPkts = 2,
    Flows = 3,
    Protocol = 4,
    SrcTos = 5,
    TcpFlags = 6,
    L4SrcPort = 7,
    Ipv4SrcAddr = 8,
    SrcMask = 9,
    InputSnmp = 10,
    L4DstPort = 11,
    Ipv4DstAddr = 12,
    DstMask = 13,
    OutputSnmp = 14,
    Ipv4NextHop = 15,
    SrcAs = 16,
    DstAs = 17,
    LastSwitched = 21,
    FirstSwitched = 22,
    OutBytes = 23,
    OutPkts = 24,
    Ipv6SrcAddr = 27,
    Ipv6DstAddr = 28,
    Ipv6SrcMask = 29,
    Ipv6DstMask = 30,
    FlowLabel = 31,
    IcmpType = 32,
    Direction = 61,
    Ipv6NextHop = 62,
    SamplingInterval = 34,
    SamplerRandomInterval = 50,
    FlowStartMilliseconds = 152,
    FlowEndMilliseconds = 153,
    FlowStartMicroseconds = 154,
    FlowEndMicroseconds = 155,
    Unknown = 65535,
}

impl From<u16> for NetflowV9FieldType {
    fn from(value: u16) -> Self {
        match value {
            1 => NetflowV9FieldType::InBytes,
            2 => NetflowV9FieldType::InPkts,
            3 => NetflowV9FieldType::Flows,
            4 => NetflowV9FieldType::Protocol,
            5 => NetflowV9FieldType::SrcTos,
            6 => NetflowV9FieldType::TcpFlags,
            7 => NetflowV9FieldType::L4SrcPort,
            8 => NetflowV9FieldType::Ipv4SrcAddr,
            9 => NetflowV9FieldType::SrcMask,
            10 => NetflowV9FieldType::InputSnmp,
            11 => NetflowV9FieldType::L4DstPort,
            12 => NetflowV9FieldType::Ipv4DstAddr,
            13 => NetflowV9FieldType::DstMask,
            14 => NetflowV9FieldType::OutputSnmp,
            15 => NetflowV9FieldType::Ipv4NextHop,
            16 => NetflowV9FieldType::SrcAs,
            17 => NetflowV9FieldType::DstAs,
            21 => NetflowV9FieldType::LastSwitched,
            22 => NetflowV9FieldType::FirstSwitched,
            23 => NetflowV9FieldType::OutBytes,
            24 => NetflowV9FieldType::OutPkts,
            27 => NetflowV9FieldType::Ipv6SrcAddr,
            28 => NetflowV9FieldType::Ipv6DstAddr,
            29 => NetflowV9FieldType::Ipv6SrcMask,
            30 => NetflowV9FieldType::Ipv6DstMask,
            31 => NetflowV9FieldType::FlowLabel,
            32 => NetflowV9FieldType::IcmpType,
            34 => NetflowV9FieldType::SamplingInterval,
            50 => NetflowV9FieldType::SamplerRandomInterval,
            61 => NetflowV9FieldType::Direction,
            62 => NetflowV9FieldType::Ipv6NextHop,
            152 => NetflowV9FieldType::FlowStartMilliseconds,
            153 => NetflowV9FieldType::FlowEndMilliseconds,
            154 => NetflowV9FieldType::FlowStartMicroseconds,
            155 => NetflowV9FieldType::FlowEndMicroseconds,
            _ => NetflowV9FieldType::Unknown,
        }
    }
}

/// Parse NetFlow v9 packet
pub fn parse_netflow_v9(
    data: &[u8],
    exporter: IpAddr,
    template_cache: &mut TemplateCache,
) -> Result<Vec<ParsedFlow>, ParseError> {
    if data.len() < 20 {
        return Err(ParseError::InsufficientData);
    }

    let version = read_be_u16(data, 0)?;
    if version != 9 {
        return Err(ParseError::InvalidVersion(version));
    }

    let count = read_be_u16(data, 2)?;  // Number of FlowSets
    let sys_uptime = read_be_u32(data, 4)?;
    let unix_secs = read_be_u32(data, 8)?;
    let sequence = read_be_u32(data, 12)?;
    let source_id = read_be_u32(data, 16)?;

    let boot_time_ms = (unix_secs as u64 * 1000).saturating_sub(sys_uptime as u64);

    let mut flows = Vec::new();
    let mut offset = 20;

    while offset < data.len() {
        if offset + 4 > data.len() {
            break;
        }

        let flowset_id = read_be_u16(data, offset)?;
        let flowset_length = read_be_u16(data, offset + 2)? as usize;

        if flowset_length < 4 || offset + flowset_length > data.len() {
            break;
        }

        if flowset_id == 0 {
            // Template FlowSet
            parse_v9_template_flowset(&data[offset..offset + flowset_length], exporter, template_cache)?;
        } else if flowset_id == 1 {
            // Options Template FlowSet - skip for now
        } else if flowset_id >= 256 {
            // Data FlowSet
            if let Some(template) = template_cache.get(exporter, flowset_id) {
                let parsed = parse_v9_data_flowset(
                    &data[offset + 4..offset + flowset_length],
                    template,
                    boot_time_ms,
                )?;
                flows.extend(parsed);
            }
        }

        offset += flowset_length;
        // Align to 4-byte boundary
        offset = (offset + 3) & !3;
    }

    Ok(flows)
}

/// Parse NetFlow v9 template flowset
fn parse_v9_template_flowset(
    data: &[u8],
    exporter: IpAddr,
    template_cache: &mut TemplateCache,
) -> Result<(), ParseError> {
    let mut offset = 4;  // Skip flowset header

    while offset + 4 <= data.len() {
        let template_id = read_be_u16(data, offset)?;
        let field_count = read_be_u16(data, offset + 2)?;
        offset += 4;

        if template_id < 256 || field_count == 0 {
            break;
        }

        let mut fields = Vec::with_capacity(field_count as usize);
        let mut total_length = 0u16;

        for _ in 0..field_count {
            if offset + 4 > data.len() {
                return Err(ParseError::InsufficientData);
            }

            let field_type = read_be_u16(data, offset)?;
            let field_length = read_be_u16(data, offset + 2)?;
            offset += 4;

            total_length += field_length;
            fields.push(TemplateField {
                field_type,
                field_length,
                enterprise_id: None,
            });
        }

        let template = FlowTemplate {
            template_id,
            field_count,
            fields,
            total_length,
        };

        template_cache.insert(exporter, template_id, template);
    }

    Ok(())
}

/// Parse NetFlow v9 data flowset
fn parse_v9_data_flowset(
    data: &[u8],
    template: &FlowTemplate,
    boot_time_ms: u64,
) -> Result<Vec<ParsedFlow>, ParseError> {
    let record_length = template.total_length as usize;
    if record_length == 0 {
        return Ok(Vec::new());
    }

    let record_count = data.len() / record_length;
    let mut flows = Vec::with_capacity(record_count);

    for i in 0..record_count {
        let record_start = i * record_length;
        let record_data = &data[record_start..record_start + record_length];

        let mut flow = ParsedFlow {
            src_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            packets: 0,
            bytes: 0,
            tcp_flags: 0,
            tos: 0,
            input_iface: 0,
            output_iface: 0,
            start_time_ms: 0,
            end_time_ms: 0,
            src_as: 0,
            dst_as: 0,
            src_mask: 0,
            dst_mask: 0,
            next_hop: None,
            direction: None,
            sampling_rate: 0,
        };

        let mut field_offset = 0;
        for field in &template.fields {
            let field_data = &record_data[field_offset..field_offset + field.field_length as usize];
            parse_v9_field(&mut flow, field.field_type, field_data, boot_time_ms);
            field_offset += field.field_length as usize;
        }

        flows.push(flow);
    }

    Ok(flows)
}

/// Parse a single NetFlow v9 field
fn parse_v9_field(flow: &mut ParsedFlow, field_type: u16, data: &[u8], boot_time_ms: u64) {
    let ft = NetflowV9FieldType::from(field_type);

    match ft {
        NetflowV9FieldType::Ipv4SrcAddr if data.len() >= 4 => {
            flow.src_addr = IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        }
        NetflowV9FieldType::Ipv4DstAddr if data.len() >= 4 => {
            flow.dst_addr = IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        }
        NetflowV9FieldType::Ipv6SrcAddr if data.len() >= 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[0..16]);
            flow.src_addr = IpAddr::V6(Ipv6Addr::from(octets));
        }
        NetflowV9FieldType::Ipv6DstAddr if data.len() >= 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[0..16]);
            flow.dst_addr = IpAddr::V6(Ipv6Addr::from(octets));
        }
        NetflowV9FieldType::L4SrcPort if data.len() >= 2 => {
            flow.src_port = u16::from_be_bytes([data[0], data[1]]);
        }
        NetflowV9FieldType::L4DstPort if data.len() >= 2 => {
            flow.dst_port = u16::from_be_bytes([data[0], data[1]]);
        }
        NetflowV9FieldType::Protocol if !data.is_empty() => {
            flow.protocol = data[0];
        }
        NetflowV9FieldType::InBytes => {
            flow.bytes = read_variable_uint(data);
        }
        NetflowV9FieldType::InPkts => {
            flow.packets = read_variable_uint(data);
        }
        NetflowV9FieldType::OutBytes => {
            flow.bytes = flow.bytes.saturating_add(read_variable_uint(data));
        }
        NetflowV9FieldType::OutPkts => {
            flow.packets = flow.packets.saturating_add(read_variable_uint(data));
        }
        NetflowV9FieldType::TcpFlags if !data.is_empty() => {
            flow.tcp_flags = data[0];
        }
        NetflowV9FieldType::SrcTos if !data.is_empty() => {
            flow.tos = data[0];
        }
        NetflowV9FieldType::InputSnmp => {
            flow.input_iface = read_variable_uint(data) as u32;
        }
        NetflowV9FieldType::OutputSnmp => {
            flow.output_iface = read_variable_uint(data) as u32;
        }
        NetflowV9FieldType::FirstSwitched if data.len() >= 4 => {
            let uptime_ms = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64;
            flow.start_time_ms = boot_time_ms + uptime_ms;
        }
        NetflowV9FieldType::LastSwitched if data.len() >= 4 => {
            let uptime_ms = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64;
            flow.end_time_ms = boot_time_ms + uptime_ms;
        }
        NetflowV9FieldType::FlowStartMilliseconds if data.len() >= 8 => {
            flow.start_time_ms = read_variable_uint(data);
        }
        NetflowV9FieldType::FlowEndMilliseconds if data.len() >= 8 => {
            flow.end_time_ms = read_variable_uint(data);
        }
        NetflowV9FieldType::SrcAs => {
            flow.src_as = read_variable_uint(data) as u32;
        }
        NetflowV9FieldType::DstAs => {
            flow.dst_as = read_variable_uint(data) as u32;
        }
        NetflowV9FieldType::SrcMask if !data.is_empty() => {
            flow.src_mask = data[0];
        }
        NetflowV9FieldType::DstMask if !data.is_empty() => {
            flow.dst_mask = data[0];
        }
        NetflowV9FieldType::Ipv4NextHop if data.len() >= 4 => {
            flow.next_hop = Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])));
        }
        NetflowV9FieldType::Ipv6NextHop if data.len() >= 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[0..16]);
            flow.next_hop = Some(IpAddr::V6(Ipv6Addr::from(octets)));
        }
        NetflowV9FieldType::Direction if !data.is_empty() => {
            flow.direction = Some(data[0]);
        }
        NetflowV9FieldType::SamplingInterval => {
            flow.sampling_rate = read_variable_uint(data) as u32;
        }
        _ => {}
    }
}

/// Read a variable-length unsigned integer
fn read_variable_uint(data: &[u8]) -> u64 {
    match data.len() {
        1 => data[0] as u64,
        2 => u16::from_be_bytes([data[0], data[1]]) as u64,
        4 => u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64,
        8 => u64::from_be_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]),
        _ => 0,
    }
}

/// Parse IPFIX (NetFlow v10) packet
pub fn parse_ipfix(
    data: &[u8],
    exporter: IpAddr,
    template_cache: &mut TemplateCache,
) -> Result<Vec<ParsedFlow>, ParseError> {
    if data.len() < 16 {
        return Err(ParseError::InsufficientData);
    }

    let version = read_be_u16(data, 0)?;
    if version != 10 {
        return Err(ParseError::InvalidVersion(version));
    }

    let message_length = read_be_u16(data, 2)? as usize;
    let export_time = read_be_u32(data, 4)?;
    let sequence_number = read_be_u32(data, 8)?;
    let observation_domain_id = read_be_u32(data, 12)?;

    if data.len() < message_length {
        return Err(ParseError::InsufficientData);
    }

    let export_time_ms = export_time as u64 * 1000;
    let mut flows = Vec::new();
    let mut offset = 16;

    while offset < message_length {
        if offset + 4 > data.len() {
            break;
        }

        let set_id = read_be_u16(data, offset)?;
        let set_length = read_be_u16(data, offset + 2)? as usize;

        if set_length < 4 || offset + set_length > data.len() {
            break;
        }

        if set_id == 2 {
            // Template Set
            parse_ipfix_template_set(&data[offset..offset + set_length], exporter, template_cache)?;
        } else if set_id == 3 {
            // Options Template Set - skip
        } else if set_id >= 256 {
            // Data Set
            if let Some(template) = template_cache.get(exporter, set_id) {
                let parsed = parse_ipfix_data_set(
                    &data[offset + 4..offset + set_length],
                    template,
                    export_time_ms,
                )?;
                flows.extend(parsed);
            }
        }

        offset += set_length;
    }

    Ok(flows)
}

/// Parse IPFIX template set
fn parse_ipfix_template_set(
    data: &[u8],
    exporter: IpAddr,
    template_cache: &mut TemplateCache,
) -> Result<(), ParseError> {
    let mut offset = 4;  // Skip set header

    while offset + 4 <= data.len() {
        let template_id = read_be_u16(data, offset)?;
        let field_count = read_be_u16(data, offset + 2)?;
        offset += 4;

        if template_id < 256 || field_count == 0 {
            break;
        }

        let mut fields = Vec::with_capacity(field_count as usize);
        let mut total_length = 0u16;

        for _ in 0..field_count {
            if offset + 4 > data.len() {
                return Err(ParseError::InsufficientData);
            }

            let field_type = read_be_u16(data, offset)?;
            let field_length = read_be_u16(data, offset + 2)?;
            offset += 4;

            // Check for enterprise bit
            let enterprise_id = if field_type & 0x8000 != 0 {
                if offset + 4 > data.len() {
                    return Err(ParseError::InsufficientData);
                }
                let eid = read_be_u32(data, offset)?;
                offset += 4;
                Some(eid)
            } else {
                None
            };

            total_length += field_length;
            fields.push(TemplateField {
                field_type: field_type & 0x7FFF,  // Clear enterprise bit
                field_length,
                enterprise_id,
            });
        }

        let template = FlowTemplate {
            template_id,
            field_count,
            fields,
            total_length,
        };

        template_cache.insert(exporter, template_id, template);
    }

    Ok(())
}

/// Parse IPFIX data set
fn parse_ipfix_data_set(
    data: &[u8],
    template: &FlowTemplate,
    export_time_ms: u64,
) -> Result<Vec<ParsedFlow>, ParseError> {
    // Same structure as v9, reuse the parser
    parse_v9_data_flowset(data, template, export_time_ms)
}

/// Parse sFlow v5 packet
pub fn parse_sflow(data: &[u8], exporter: IpAddr) -> Result<Vec<ParsedFlow>, ParseError> {
    if data.len() < 28 {
        return Err(ParseError::InsufficientData);
    }

    let version = read_be_u32(data, 0)?;
    if version != 5 {
        return Err(ParseError::InvalidVersion(version as u16));
    }

    let address_type = read_be_u32(data, 4)?;
    let agent_addr_len = if address_type == 1 { 4 } else { 16 };
    let mut offset = 8 + agent_addr_len;

    if offset + 12 > data.len() {
        return Err(ParseError::InsufficientData);
    }

    let sub_agent_id = read_be_u32(data, offset)?;
    let sequence_number = read_be_u32(data, offset + 4)?;
    let uptime = read_be_u32(data, offset + 8)?;
    let sample_count = read_be_u32(data, offset + 12)?;
    offset += 16;

    let mut flows = Vec::new();

    for _ in 0..sample_count {
        if offset + 8 > data.len() {
            break;
        }

        let sample_type = read_be_u32(data, offset)?;
        let sample_length = read_be_u32(data, offset + 4)? as usize;
        offset += 8;

        if offset + sample_length > data.len() {
            break;
        }

        // Only process flow samples (type 1 or expanded type 3)
        if sample_type == 1 || sample_type == 3 {
            if let Ok(flow) = parse_sflow_sample(&data[offset..offset + sample_length], sample_type) {
                flows.push(flow);
            }
        }

        offset += sample_length;
    }

    Ok(flows)
}

/// Parse sFlow flow sample
fn parse_sflow_sample(data: &[u8], sample_type: u32) -> Result<ParsedFlow, ParseError> {
    let header_size = if sample_type == 1 { 32 } else { 44 };  // Regular vs expanded
    if data.len() < header_size {
        return Err(ParseError::InsufficientData);
    }

    let mut offset = 0;

    // Parse sample header
    let (sequence, source_id, sampling_rate, sample_pool, drops, input_if, output_if, record_count) =
        if sample_type == 1 {
            // Regular flow sample
            let seq = read_be_u32(data, 0)?;
            let src_id = read_be_u32(data, 4)?;
            let rate = read_be_u32(data, 8)?;
            let pool = read_be_u32(data, 12)?;
            let drp = read_be_u32(data, 16)?;
            let in_if = read_be_u32(data, 20)?;
            let out_if = read_be_u32(data, 24)?;
            let rec_cnt = read_be_u32(data, 28)?;
            offset = 32;
            (seq, src_id, rate, pool, drp, in_if, out_if, rec_cnt)
        } else {
            // Expanded flow sample
            let seq = read_be_u32(data, 0)?;
            let src_id_type = read_be_u32(data, 4)?;
            let src_id_idx = read_be_u32(data, 8)?;
            let rate = read_be_u32(data, 12)?;
            let pool = read_be_u32(data, 16)?;
            let drp = read_be_u32(data, 20)?;
            let in_if_fmt = read_be_u32(data, 24)?;
            let in_if_val = read_be_u32(data, 28)?;
            let out_if_fmt = read_be_u32(data, 32)?;
            let out_if_val = read_be_u32(data, 36)?;
            let rec_cnt = read_be_u32(data, 40)?;
            offset = 44;
            (seq, src_id_idx, rate, pool, drp, in_if_val, out_if_val, rec_cnt)
        };

    let mut flow = ParsedFlow {
        src_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        dst_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        src_port: 0,
        dst_port: 0,
        protocol: 0,
        packets: 1,  // sFlow samples represent sampled packets
        bytes: 0,
        tcp_flags: 0,
        tos: 0,
        input_iface: input_if,
        output_iface: output_if,
        start_time_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        end_time_ms: 0,
        src_as: 0,
        dst_as: 0,
        src_mask: 0,
        dst_mask: 0,
        next_hop: None,
        direction: None,
        sampling_rate,
    };
    flow.end_time_ms = flow.start_time_ms;

    // Parse flow records
    for _ in 0..record_count {
        if offset + 8 > data.len() {
            break;
        }

        let record_format = read_be_u32(data, offset)?;
        let record_length = read_be_u32(data, offset + 4)? as usize;
        offset += 8;

        if offset + record_length > data.len() {
            break;
        }

        let record_data = &data[offset..offset + record_length];

        // Raw packet header (format 1)
        if record_format == 1 && record_length >= 16 {
            let protocol = read_be_u32(record_data, 0)?;
            let frame_length = read_be_u32(record_data, 4)?;
            let stripped = read_be_u32(record_data, 8)?;
            let header_length = read_be_u32(record_data, 12)? as usize;

            flow.bytes = (frame_length * sampling_rate) as u64;

            // Parse Ethernet + IP + TCP/UDP if available
            if header_length >= 34 && record_length >= 16 + header_length {
                let header = &record_data[16..16 + header_length];
                parse_packet_header(&mut flow, header);
            }
        }

        offset += record_length;
    }

    Ok(flow)
}

/// Parse packet header (Ethernet + IP + TCP/UDP)
fn parse_packet_header(flow: &mut ParsedFlow, header: &[u8]) {
    // Skip to EtherType (bytes 12-13)
    if header.len() < 14 {
        return;
    }

    let ethertype = u16::from_be_bytes([header[12], header[13]]);
    let ip_offset = match ethertype {
        0x0800 => 14,  // IPv4
        0x86DD => 14,  // IPv6
        0x8100 => 18,  // 802.1Q VLAN
        _ => return,
    };

    if header.len() < ip_offset + 20 {
        return;
    }

    let ip_header = &header[ip_offset..];
    let version = ip_header[0] >> 4;

    match version {
        4 => {
            // IPv4
            let ihl = ((ip_header[0] & 0x0F) * 4) as usize;
            flow.tos = ip_header[1];
            flow.protocol = ip_header[9];
            flow.src_addr = IpAddr::V4(Ipv4Addr::new(
                ip_header[12], ip_header[13], ip_header[14], ip_header[15]
            ));
            flow.dst_addr = IpAddr::V4(Ipv4Addr::new(
                ip_header[16], ip_header[17], ip_header[18], ip_header[19]
            ));

            // Parse TCP/UDP ports
            if ip_header.len() >= ihl + 4 {
                let transport = &ip_header[ihl..];
                flow.src_port = u16::from_be_bytes([transport[0], transport[1]]);
                flow.dst_port = u16::from_be_bytes([transport[2], transport[3]]);

                if flow.protocol == 6 && transport.len() >= 14 {
                    // TCP flags
                    flow.tcp_flags = transport[13];
                }
            }
        }
        6 => {
            // IPv6
            if ip_header.len() < 40 {
                return;
            }
            flow.tos = ((ip_header[0] & 0x0F) << 4) | (ip_header[1] >> 4);
            flow.protocol = ip_header[6];  // Next header

            let mut src_octets = [0u8; 16];
            let mut dst_octets = [0u8; 16];
            src_octets.copy_from_slice(&ip_header[8..24]);
            dst_octets.copy_from_slice(&ip_header[24..40]);

            flow.src_addr = IpAddr::V6(Ipv6Addr::from(src_octets));
            flow.dst_addr = IpAddr::V6(Ipv6Addr::from(dst_octets));

            // Parse TCP/UDP ports
            if ip_header.len() >= 44 {
                let transport = &ip_header[40..];
                flow.src_port = u16::from_be_bytes([transport[0], transport[1]]);
                flow.dst_port = u16::from_be_bytes([transport[2], transport[3]]);

                if flow.protocol == 6 && transport.len() >= 14 {
                    flow.tcp_flags = transport[13];
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_be_u16() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_be_u16(&data, 0).unwrap(), 0x0102);
        assert_eq!(read_be_u16(&data, 2).unwrap(), 0x0304);
    }

    #[test]
    fn test_read_be_u32() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_be_u32(&data, 0).unwrap(), 0x01020304);
        assert_eq!(read_be_u32(&data, 4).unwrap(), 0x05060708);
    }

    #[test]
    fn test_tcp_flags() {
        let flags = TcpFlags::from(0x12);  // SYN+ACK
        assert!(flags.syn);
        assert!(flags.ack);
        assert!(!flags.fin);
        assert!(!flags.rst);
        assert_eq!(flags.to_string(), "SA");
    }

    #[test]
    fn test_template_cache() {
        let mut cache = TemplateCache::new();
        let exporter = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let template = FlowTemplate {
            template_id: 256,
            field_count: 2,
            fields: vec![
                TemplateField { field_type: 8, field_length: 4, enterprise_id: None },
                TemplateField { field_type: 12, field_length: 4, enterprise_id: None },
            ],
            total_length: 8,
        };

        cache.insert(exporter, 256, template);
        assert!(cache.get(exporter, 256).is_some());
        assert!(cache.get(exporter, 257).is_none());

        cache.clear_exporter(exporter);
        assert!(cache.get(exporter, 256).is_none());
    }

    #[test]
    fn test_port_to_application() {
        assert_eq!(port_to_application(80, 6), Some("HTTP"));
        assert_eq!(port_to_application(443, 6), Some("HTTPS"));
        assert_eq!(port_to_application(22, 6), Some("SSH"));
        assert_eq!(port_to_application(53, 17), Some("DNS"));
        assert_eq!(port_to_application(12345, 6), None);
    }

    #[test]
    fn test_is_suspicious_port() {
        assert!(is_suspicious_port(4444, 6));
        assert!(is_suspicious_port(31337, 6));
        assert!(!is_suspicious_port(80, 6));
        assert!(!is_suspicious_port(443, 6));
    }

    #[test]
    fn test_beaconing_detection() {
        // Regular intervals (every 60 seconds)
        let regular = vec![60000, 60100, 59900, 60050, 60000, 59950, 60100, 60000];
        let score = analyze_beaconing(&regular);
        assert!(score.is_some());
        assert!(score.unwrap() > 0.8);

        // Random intervals
        let random = vec![10000, 120000, 5000, 300000, 15000];
        let score = analyze_beaconing(&random);
        assert!(score.is_none() || score.unwrap() < 0.3);
    }
}
