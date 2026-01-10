use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use tokio::sync::mpsc;
use log::{debug, info, warn, error};

use crate::data_lake::types::DataRecord;

/// NetFlow connector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetFlowConnector {
    pub listen_address: String,
    pub listen_port: u16,
    pub version: NetFlowVersion,
    pub buffer_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetFlowVersion {
    V5,
    V9,
    IPFIX,
}

impl NetFlowConnector {
    pub fn new(listen_address: String, listen_port: u16, version: NetFlowVersion) -> Self {
        Self {
            listen_address,
            listen_port,
            version,
            buffer_size: 65535,
        }
    }

    /// Start listening for NetFlow data
    pub async fn start(&self, tx: mpsc::Sender<DataRecord>) -> Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.listen_address, self.listen_port).parse()?;

        info!(
            "Starting NetFlow {:?} listener on {}",
            self.version, addr
        );

        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;

        let version = self.version.clone();
        let buffer_size = self.buffer_size;

        tokio::spawn(async move {
            let mut buf = vec![0u8; buffer_size];

            loop {
                match socket.recv_from(&mut buf) {
                    Ok((len, src)) => {
                        let packet_data = &buf[..len];
                        let source_id = format!("netflow_{}", src.ip());

                        match version {
                            NetFlowVersion::V5 => {
                                if let Ok(records) = parse_netflow_v5(&source_id, packet_data) {
                                    for record in records {
                                        if tx.send(record).await.is_err() {
                                            error!("Failed to send NetFlow record");
                                            return;
                                        }
                                    }
                                }
                            }
                            NetFlowVersion::V9 => {
                                if let Ok(records) = parse_netflow_v9(&source_id, packet_data) {
                                    for record in records {
                                        if tx.send(record).await.is_err() {
                                            error!("Failed to send NetFlow record");
                                            return;
                                        }
                                    }
                                }
                            }
                            NetFlowVersion::IPFIX => {
                                if let Ok(records) = parse_ipfix(&source_id, packet_data) {
                                    for record in records {
                                        if tx.send(record).await.is_err() {
                                            error!("Failed to send IPFIX record");
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No data available, sleep briefly
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        error!("NetFlow socket error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Parse NetFlow packet into DataRecord
    pub fn parse_packet(&self, source_id: &str, packet_data: &[u8]) -> Result<Vec<DataRecord>> {
        match self.version {
            NetFlowVersion::V5 => parse_netflow_v5(source_id, packet_data),
            NetFlowVersion::V9 => parse_netflow_v9(source_id, packet_data),
            NetFlowVersion::IPFIX => parse_ipfix(source_id, packet_data),
        }
    }
}

/// Parse NetFlow v5 packet
fn parse_netflow_v5(source_id: &str, data: &[u8]) -> Result<Vec<DataRecord>> {
    if data.len() < 24 {
        return Err(anyhow!("NetFlow v5 header too short"));
    }

    // NetFlow v5 header
    let version = u16::from_be_bytes([data[0], data[1]]);
    if version != 5 {
        return Err(anyhow!("Not a NetFlow v5 packet: version {}", version));
    }

    let count = u16::from_be_bytes([data[2], data[3]]) as usize;
    let sys_uptime = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let unix_secs = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let unix_nsecs = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let flow_sequence = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    let engine_type = data[20];
    let engine_id = data[21];

    debug!(
        "NetFlow v5: {} flows, seq {}, engine {}/{}",
        count, flow_sequence, engine_type, engine_id
    );

    let mut records = Vec::with_capacity(count);
    let header_len = 24;
    let record_len = 48;

    // Timestamp from header
    let timestamp = DateTime::from_timestamp(unix_secs as i64, unix_nsecs)
        .unwrap_or_else(Utc::now);

    for i in 0..count {
        let offset = header_len + (i * record_len);
        if offset + record_len > data.len() {
            warn!("NetFlow v5 packet truncated at record {}", i);
            break;
        }

        let record_data = &data[offset..offset + record_len];

        // Parse flow record fields
        let src_ip = Ipv4Addr::new(record_data[0], record_data[1], record_data[2], record_data[3]);
        let dst_ip = Ipv4Addr::new(record_data[4], record_data[5], record_data[6], record_data[7]);
        let next_hop = Ipv4Addr::new(record_data[8], record_data[9], record_data[10], record_data[11]);

        let input_iface = u16::from_be_bytes([record_data[12], record_data[13]]);
        let output_iface = u16::from_be_bytes([record_data[14], record_data[15]]);

        let packets = u32::from_be_bytes([record_data[16], record_data[17], record_data[18], record_data[19]]);
        let bytes = u32::from_be_bytes([record_data[20], record_data[21], record_data[22], record_data[23]]);

        let first_uptime = u32::from_be_bytes([record_data[24], record_data[25], record_data[26], record_data[27]]);
        let last_uptime = u32::from_be_bytes([record_data[28], record_data[29], record_data[30], record_data[31]]);

        let src_port = u16::from_be_bytes([record_data[32], record_data[33]]);
        let dst_port = u16::from_be_bytes([record_data[34], record_data[35]]);

        let tcp_flags = record_data[37];
        let protocol = record_data[38];
        let tos = record_data[39];

        let src_as = u16::from_be_bytes([record_data[40], record_data[41]]);
        let dst_as = u16::from_be_bytes([record_data[42], record_data[43]]);
        let src_mask = record_data[44];
        let dst_mask = record_data[45];

        // Calculate flow duration
        let duration_ms = if last_uptime > first_uptime {
            last_uptime - first_uptime
        } else {
            0
        };

        records.push(DataRecord {
            id: uuid::Uuid::new_v4().to_string(),
            source_id: source_id.to_string(),
            timestamp,
            data: serde_json::json!({
                "flow_type": "netflow_v5",
                "src_ip": src_ip.to_string(),
                "dst_ip": dst_ip.to_string(),
                "next_hop": next_hop.to_string(),
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "protocol_name": protocol_to_name(protocol),
                "packets": packets,
                "bytes": bytes,
                "tcp_flags": tcp_flags,
                "tcp_flags_str": tcp_flags_to_string(tcp_flags),
                "tos": tos,
                "input_iface": input_iface,
                "output_iface": output_iface,
                "src_as": src_as,
                "dst_as": dst_as,
                "src_mask": src_mask,
                "dst_mask": dst_mask,
                "duration_ms": duration_ms,
                "sys_uptime": sys_uptime,
                "flow_sequence": flow_sequence
            }),
            metadata: serde_json::json!({
                "source_type": "netflow_v5",
                "engine_type": engine_type,
                "engine_id": engine_id
            }),
        });
    }

    Ok(records)
}

/// Parse NetFlow v9 packet
fn parse_netflow_v9(source_id: &str, data: &[u8]) -> Result<Vec<DataRecord>> {
    if data.len() < 20 {
        return Err(anyhow!("NetFlow v9 header too short"));
    }

    let version = u16::from_be_bytes([data[0], data[1]]);
    if version != 9 {
        return Err(anyhow!("Not a NetFlow v9 packet: version {}", version));
    }

    let count = u16::from_be_bytes([data[2], data[3]]) as usize;
    let sys_uptime = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let unix_secs = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let sequence = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let source_id_field = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);

    let timestamp = DateTime::from_timestamp(unix_secs as i64, 0)
        .unwrap_or_else(Utc::now);

    debug!(
        "NetFlow v9: {} flowsets, seq {}, source_id {}",
        count, sequence, source_id_field
    );

    let mut records = Vec::new();
    let mut offset = 20;

    // Parse flowsets (simplified - in production, handle templates)
    while offset + 4 <= data.len() {
        let flowset_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let flowset_length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if flowset_length < 4 || offset + flowset_length > data.len() {
            break;
        }

        // Flowset ID 0 = Template, 1 = Options Template, 256+ = Data
        if flowset_id >= 256 {
            // Data flowset - create basic record
            records.push(DataRecord {
                id: uuid::Uuid::new_v4().to_string(),
                source_id: source_id.to_string(),
                timestamp,
                data: serde_json::json!({
                    "flow_type": "netflow_v9",
                    "flowset_id": flowset_id,
                    "flowset_length": flowset_length,
                    "sequence": sequence,
                    "sys_uptime": sys_uptime,
                    "raw_data": hex::encode(&data[offset + 4..offset + flowset_length])
                }),
                metadata: serde_json::json!({
                    "source_type": "netflow_v9",
                    "source_id": source_id_field,
                    "template_required": true
                }),
            });
        }

        offset += flowset_length;
    }

    Ok(records)
}

/// Parse IPFIX (NetFlow v10) packet
fn parse_ipfix(source_id: &str, data: &[u8]) -> Result<Vec<DataRecord>> {
    if data.len() < 16 {
        return Err(anyhow!("IPFIX header too short"));
    }

    let version = u16::from_be_bytes([data[0], data[1]]);
    if version != 10 {
        return Err(anyhow!("Not an IPFIX packet: version {}", version));
    }

    let length = u16::from_be_bytes([data[2], data[3]]) as usize;
    let export_time = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let sequence = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let observation_domain = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

    let timestamp = DateTime::from_timestamp(export_time as i64, 0)
        .unwrap_or_else(Utc::now);

    debug!(
        "IPFIX: length {}, seq {}, domain {}",
        length, sequence, observation_domain
    );

    let mut records = Vec::new();
    let mut offset = 16;

    // Parse message sets
    while offset + 4 <= data.len() && offset < length {
        let set_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let set_length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if set_length < 4 || offset + set_length > data.len() {
            break;
        }

        // Set ID 2 = Template, 3 = Options Template, 256+ = Data
        if set_id >= 256 {
            records.push(DataRecord {
                id: uuid::Uuid::new_v4().to_string(),
                source_id: source_id.to_string(),
                timestamp,
                data: serde_json::json!({
                    "flow_type": "ipfix",
                    "set_id": set_id,
                    "set_length": set_length,
                    "sequence": sequence,
                    "observation_domain": observation_domain,
                    "raw_data": hex::encode(&data[offset + 4..offset + set_length])
                }),
                metadata: serde_json::json!({
                    "source_type": "ipfix",
                    "template_required": true
                }),
            });
        }

        offset += set_length;
    }

    Ok(records)
}

/// sFlow connector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SFlowConnector {
    pub listen_address: String,
    pub listen_port: u16,
}

impl SFlowConnector {
    pub fn new(listen_address: String, listen_port: u16) -> Self {
        Self {
            listen_address,
            listen_port,
        }
    }

    /// Start listening for sFlow data
    pub async fn start(&self, tx: mpsc::Sender<DataRecord>) -> Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.listen_address, self.listen_port).parse()?;

        info!("Starting sFlow listener on {}", addr);

        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];

            loop {
                match socket.recv_from(&mut buf) {
                    Ok((len, src)) => {
                        let packet_data = &buf[..len];
                        let source_id = format!("sflow_{}", src.ip());

                        if let Ok(records) = parse_sflow(&source_id, packet_data) {
                            for record in records {
                                if tx.send(record).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        error!("sFlow socket error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }
}

/// Parse sFlow packet
fn parse_sflow(source_id: &str, data: &[u8]) -> Result<Vec<DataRecord>> {
    if data.len() < 28 {
        return Err(anyhow!("sFlow header too short"));
    }

    let version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if version != 5 {
        return Err(anyhow!("Unsupported sFlow version: {}", version));
    }

    let agent_address_type = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let agent_ip = match agent_address_type {
        1 => IpAddr::V4(Ipv4Addr::new(data[8], data[9], data[10], data[11])),
        _ => return Err(anyhow!("Unsupported agent address type")),
    };

    let sub_agent_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let sequence = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    let uptime = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
    let num_samples = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

    debug!(
        "sFlow v5: {} samples from agent {}, seq {}",
        num_samples, agent_ip, sequence
    );

    let mut records = Vec::new();
    let timestamp = Utc::now();

    // Create summary record for sFlow datagram
    records.push(DataRecord {
        id: uuid::Uuid::new_v4().to_string(),
        source_id: source_id.to_string(),
        timestamp,
        data: serde_json::json!({
            "flow_type": "sflow",
            "version": version,
            "agent_ip": agent_ip.to_string(),
            "sub_agent_id": sub_agent_id,
            "sequence": sequence,
            "uptime": uptime,
            "num_samples": num_samples
        }),
        metadata: serde_json::json!({
            "source_type": "sflow",
            "packet_size": data.len()
        }),
    });

    Ok(records)
}

/// PCAP file connector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PCAPConnector {
    pub file_path: String,
    pub read_timeout_ms: u64,
}

impl PCAPConnector {
    pub fn new(file_path: String) -> Self {
        Self {
            file_path,
            read_timeout_ms: 1000,
        }
    }

    /// Ingest PCAP file
    pub async fn ingest(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        info!("Ingesting PCAP file: {}", self.file_path);

        let path = Path::new(&self.file_path);
        if !path.exists() {
            return Err(anyhow!("PCAP file not found: {}", self.file_path));
        }

        let file_data = tokio::fs::read(&self.file_path).await?;
        self.parse_pcap(source_id, &file_data)
    }

    /// Parse PCAP file data
    fn parse_pcap(&self, source_id: &str, data: &[u8]) -> Result<Vec<DataRecord>> {
        if data.len() < 24 {
            return Err(anyhow!("PCAP file too short"));
        }

        // Check magic number
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let (swapped, nano) = match magic {
            0xa1b2c3d4 => (false, false), // Standard pcap, microseconds
            0xd4c3b2a1 => (true, false),  // Swapped byte order
            0xa1b23c4d => (false, true),  // Nanosecond pcap
            0x4d3cb2a1 => (true, true),   // Swapped nanosecond
            _ => return Err(anyhow!("Invalid PCAP magic number: {:08x}", magic)),
        };

        // Parse global header
        let read_u16 = |d: &[u8], offset: usize| -> u16 {
            if swapped {
                u16::from_be_bytes([d[offset], d[offset + 1]])
            } else {
                u16::from_le_bytes([d[offset], d[offset + 1]])
            }
        };

        let read_u32 = |d: &[u8], offset: usize| -> u32 {
            if swapped {
                u32::from_be_bytes([d[offset], d[offset + 1], d[offset + 2], d[offset + 3]])
            } else {
                u32::from_le_bytes([d[offset], d[offset + 1], d[offset + 2], d[offset + 3]])
            }
        };

        let version_major = read_u16(data, 4);
        let version_minor = read_u16(data, 6);
        let _thiszone = read_u32(data, 8) as i32;
        let _sigfigs = read_u32(data, 12);
        let snaplen = read_u32(data, 16);
        let network = read_u32(data, 20);

        debug!(
            "PCAP version {}.{}, snaplen {}, linktype {}",
            version_major, version_minor, snaplen, network
        );

        let mut records = Vec::new();
        let mut offset = 24; // Global header size
        let mut packet_num = 0;

        // Parse packet records
        while offset + 16 <= data.len() {
            let ts_sec = read_u32(data, offset);
            let ts_subsec = read_u32(data, offset + 4);
            let incl_len = read_u32(data, offset + 8) as usize;
            let _orig_len = read_u32(data, offset + 12);

            offset += 16;

            if offset + incl_len > data.len() {
                warn!("Truncated PCAP packet at offset {}", offset);
                break;
            }

            let packet_data = &data[offset..offset + incl_len];
            offset += incl_len;
            packet_num += 1;

            // Calculate timestamp
            let nanos = if nano { ts_subsec } else { ts_subsec * 1000 };
            let timestamp = DateTime::from_timestamp(ts_sec as i64, nanos)
                .unwrap_or_else(Utc::now);

            // Parse Ethernet frame if linktype is 1 (Ethernet)
            if network == 1 && incl_len >= 14 {
                if let Some(flow_data) = parse_ethernet_frame(packet_data) {
                    records.push(DataRecord {
                        id: uuid::Uuid::new_v4().to_string(),
                        source_id: source_id.to_string(),
                        timestamp,
                        data: flow_data,
                        metadata: serde_json::json!({
                            "source_type": "pcap",
                            "file_path": self.file_path,
                            "packet_num": packet_num,
                            "incl_len": incl_len
                        }),
                    });
                }
            } else {
                // Raw packet record
                records.push(DataRecord {
                    id: uuid::Uuid::new_v4().to_string(),
                    source_id: source_id.to_string(),
                    timestamp,
                    data: serde_json::json!({
                        "flow_type": "raw_packet",
                        "linktype": network,
                        "length": incl_len,
                        "data_preview": hex::encode(&packet_data[..packet_data.len().min(64)])
                    }),
                    metadata: serde_json::json!({
                        "source_type": "pcap",
                        "packet_num": packet_num
                    }),
                });
            }
        }

        info!("Parsed {} packets from PCAP file", records.len());
        Ok(records)
    }
}

/// Parse Ethernet frame and extract flow information
fn parse_ethernet_frame(data: &[u8]) -> Option<serde_json::Value> {
    if data.len() < 14 {
        return None;
    }

    let _dst_mac = &data[0..6];
    let _src_mac = &data[6..12];
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    // Check for 802.1Q VLAN tag
    let (ethertype, ip_offset) = if ethertype == 0x8100 && data.len() >= 18 {
        (u16::from_be_bytes([data[16], data[17]]), 18)
    } else {
        (ethertype, 14)
    };

    // Parse IPv4 (0x0800) or IPv6 (0x86DD)
    if ethertype == 0x0800 && data.len() >= ip_offset + 20 {
        return parse_ipv4_packet(&data[ip_offset..]);
    }

    None
}

/// Parse IPv4 packet
fn parse_ipv4_packet(data: &[u8]) -> Option<serde_json::Value> {
    if data.len() < 20 {
        return None;
    }

    let version = data[0] >> 4;
    if version != 4 {
        return None;
    }

    let ihl = (data[0] & 0x0F) as usize * 4;
    let _tos = data[1];
    let total_length = u16::from_be_bytes([data[2], data[3]]);
    let _identification = u16::from_be_bytes([data[4], data[5]]);
    let _flags = data[6] >> 5;
    let ttl = data[8];
    let protocol = data[9];
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let (src_port, dst_port, tcp_flags) = if data.len() >= ihl + 4 {
        let transport = &data[ihl..];
        let src_port = u16::from_be_bytes([transport[0], transport[1]]);
        let dst_port = u16::from_be_bytes([transport[2], transport[3]]);

        let tcp_flags = if protocol == 6 && transport.len() >= 14 {
            transport[13]
        } else {
            0
        };

        (src_port, dst_port, tcp_flags)
    } else {
        (0, 0, 0)
    };

    Some(serde_json::json!({
        "flow_type": "packet",
        "src_ip": src_ip.to_string(),
        "dst_ip": dst_ip.to_string(),
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "protocol_name": protocol_to_name(protocol),
        "ttl": ttl,
        "length": total_length,
        "tcp_flags": tcp_flags,
        "tcp_flags_str": tcp_flags_to_string(tcp_flags)
    }))
}

/// Network connector factory
#[allow(dead_code)]
pub enum NetworkConnector {
    NetFlow(NetFlowConnector),
    SFlow(SFlowConnector),
    PCAP(PCAPConnector),
}

impl NetworkConnector {
    /// Start the network connector
    pub async fn start(&self, tx: mpsc::Sender<DataRecord>) -> Result<()> {
        match self {
            NetworkConnector::NetFlow(connector) => connector.start(tx).await,
            NetworkConnector::SFlow(connector) => connector.start(tx).await,
            NetworkConnector::PCAP(_) => {
                // PCAP is file-based, not a listener
                Ok(())
            }
        }
    }

    /// Ingest data from the network connector
    pub async fn ingest(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        match self {
            NetworkConnector::PCAP(connector) => connector.ingest(source_id).await,
            _ => {
                // For listeners, this would be called as data arrives
                Ok(Vec::new())
            }
        }
    }
}

/// Convert protocol number to name
fn protocol_to_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        132 => "SCTP",
        _ => "Unknown",
    }
}

/// Convert TCP flags to string representation
fn tcp_flags_to_string(flags: u8) -> String {
    let mut result = String::new();
    if flags & 0x01 != 0 { result.push_str("FIN "); }
    if flags & 0x02 != 0 { result.push_str("SYN "); }
    if flags & 0x04 != 0 { result.push_str("RST "); }
    if flags & 0x08 != 0 { result.push_str("PSH "); }
    if flags & 0x10 != 0 { result.push_str("ACK "); }
    if flags & 0x20 != 0 { result.push_str("URG "); }
    result.trim().to_string()
}

/// Parse network flow into DataRecord
pub fn parse_network_flow(
    source_id: &str,
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    bytes: u64,
) -> DataRecord {
    DataRecord {
        id: uuid::Uuid::new_v4().to_string(),
        source_id: source_id.to_string(),
        timestamp: Utc::now(),
        data: serde_json::json!({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "protocol_name": protocol_to_name(protocol),
            "bytes": bytes
        }),
        metadata: serde_json::json!({
            "source_type": "network_flow"
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netflow_connector_creation() {
        let connector = NetFlowConnector::new(
            "0.0.0.0".to_string(),
            2055,
            NetFlowVersion::V9,
        );

        assert_eq!(connector.listen_port, 2055);
        assert_eq!(connector.version, NetFlowVersion::V9);
    }

    #[test]
    fn test_parse_network_flow() {
        let record = parse_network_flow(
            "source1",
            "192.168.1.100",
            "10.0.0.1",
            12345,
            80,
            6,
            1024,
        );

        assert_eq!(record.source_id, "source1");
        assert_eq!(record.data["src_ip"], "192.168.1.100");
        assert_eq!(record.data["bytes"], 1024);
        assert_eq!(record.data["protocol_name"], "TCP");
    }

    #[test]
    fn test_protocol_to_name() {
        assert_eq!(protocol_to_name(6), "TCP");
        assert_eq!(protocol_to_name(17), "UDP");
        assert_eq!(protocol_to_name(1), "ICMP");
    }

    #[test]
    fn test_tcp_flags() {
        assert_eq!(tcp_flags_to_string(0x02), "SYN");
        assert_eq!(tcp_flags_to_string(0x12), "SYN ACK");
        assert_eq!(tcp_flags_to_string(0x01), "FIN");
    }
}
