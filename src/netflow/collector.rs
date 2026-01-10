//! Flow Collector - UDP listener for NetFlow/IPFIX/sFlow packets
//!
//! Receives flow packets from network devices and parses them into flow records.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, RwLock};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use uuid::Uuid;

use super::types::{CollectorType, FlowCollector, FlowRecord};
use super::parser::{ParsedFlow, TemplateCache, parse_netflow_v5, parse_netflow_v9, parse_ipfix, parse_sflow};

/// Maximum UDP packet size for flow protocols
const MAX_PACKET_SIZE: usize = 65535;

/// Flow collector manager
pub struct FlowCollectorManager {
    collectors: Arc<RwLock<HashMap<String, CollectorInstance>>>,
    flow_sender: mpsc::Sender<Vec<FlowRecord>>,
    shutdown_sender: broadcast::Sender<()>,
}

/// Instance of a running collector
struct CollectorInstance {
    config: FlowCollector,
    shutdown: broadcast::Sender<()>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Collector statistics
#[derive(Debug, Clone, Default)]
pub struct CollectorStats {
    pub packets_received: u64,
    pub flows_parsed: u64,
    pub parse_errors: u64,
    pub bytes_received: u64,
    pub last_packet_at: Option<DateTime<Utc>>,
    pub exporters_seen: Vec<IpAddr>,
}

impl FlowCollectorManager {
    /// Create a new flow collector manager
    pub fn new(flow_sender: mpsc::Sender<Vec<FlowRecord>>) -> Self {
        let (shutdown_sender, _) = broadcast::channel(1);
        Self {
            collectors: Arc::new(RwLock::new(HashMap::new())),
            flow_sender,
            shutdown_sender,
        }
    }

    /// Start a new collector
    pub async fn start_collector(&self, config: FlowCollector) -> Result<(), CollectorError> {
        let mut collectors = self.collectors.write().await;

        if collectors.contains_key(&config.id) {
            return Err(CollectorError::AlreadyRunning(config.id.clone()));
        }

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let flow_sender = self.flow_sender.clone();
        let collector_id = config.id.clone();
        let collector_type = config.collector_type.clone();
        let listen_addr = format!("{}:{}", config.listen_address, config.listen_port);

        // Spawn the collector task
        let task_handle = tokio::spawn(async move {
            if let Err(e) = run_collector(
                collector_id.clone(),
                collector_type,
                listen_addr,
                flow_sender,
                shutdown_rx,
            ).await {
                error!("Collector {} error: {}", collector_id, e);
            }
        });

        collectors.insert(config.id.clone(), CollectorInstance {
            config,
            shutdown: shutdown_tx,
            task_handle: Some(task_handle),
        });

        Ok(())
    }

    /// Stop a running collector
    pub async fn stop_collector(&self, collector_id: &str) -> Result<(), CollectorError> {
        let mut collectors = self.collectors.write().await;

        if let Some(mut instance) = collectors.remove(collector_id) {
            // Send shutdown signal
            let _ = instance.shutdown.send(());

            // Wait for task to complete
            if let Some(handle) = instance.task_handle.take() {
                let _ = handle.await;
            }

            Ok(())
        } else {
            Err(CollectorError::NotFound(collector_id.to_string()))
        }
    }

    /// Get status of all collectors
    pub async fn get_collectors(&self) -> Vec<FlowCollector> {
        let collectors = self.collectors.read().await;
        collectors.values().map(|i| i.config.clone()).collect()
    }

    /// Get a specific collector
    pub async fn get_collector(&self, collector_id: &str) -> Option<FlowCollector> {
        let collectors = self.collectors.read().await;
        collectors.get(collector_id).map(|i| i.config.clone())
    }

    /// Shutdown all collectors
    pub async fn shutdown(&self) {
        let _ = self.shutdown_sender.send(());

        let mut collectors = self.collectors.write().await;
        for (_, mut instance) in collectors.drain() {
            let _ = instance.shutdown.send(());
            if let Some(handle) = instance.task_handle.take() {
                let _ = handle.await;
            }
        }
    }
}

/// Run a single collector
async fn run_collector(
    collector_id: String,
    collector_type: CollectorType,
    listen_addr: String,
    flow_sender: mpsc::Sender<Vec<FlowRecord>>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<(), CollectorError> {
    let socket = UdpSocket::bind(&listen_addr).await
        .map_err(|e| CollectorError::BindError(listen_addr.clone(), e.to_string()))?;

    info!("Flow collector {} listening on {}", collector_id, listen_addr);

    let mut buf = vec![0u8; MAX_PACKET_SIZE];
    let mut template_cache = TemplateCache::new();
    let mut stats = CollectorStats::default();

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Collector {} shutting down", collector_id);
                break;
            }
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, src_addr)) => {
                        stats.packets_received += 1;
                        stats.bytes_received += len as u64;
                        stats.last_packet_at = Some(Utc::now());

                        let exporter_ip = src_addr.ip();
                        if !stats.exporters_seen.contains(&exporter_ip) {
                            stats.exporters_seen.push(exporter_ip);
                        }

                        // Parse the packet based on collector type
                        let parsed_flows = parse_packet(
                            &buf[..len],
                            exporter_ip,
                            &collector_type,
                            &mut template_cache,
                        );

                        match parsed_flows {
                            Ok(flows) if !flows.is_empty() => {
                                stats.flows_parsed += flows.len() as u64;

                                // Convert to FlowRecords
                                let records: Vec<FlowRecord> = flows.into_iter()
                                    .map(|f| parsed_to_record(&collector_id, exporter_ip, f))
                                    .collect();

                                if let Err(e) = flow_sender.send(records).await {
                                    warn!("Failed to send flows: {}", e);
                                }
                            }
                            Ok(_) => {} // No flows parsed (e.g., template only)
                            Err(e) => {
                                stats.parse_errors += 1;
                                debug!("Parse error from {}: {:?}", src_addr, e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Receive error: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Parse a packet based on collector type
fn parse_packet(
    data: &[u8],
    exporter: IpAddr,
    collector_type: &CollectorType,
    template_cache: &mut TemplateCache,
) -> Result<Vec<ParsedFlow>, super::parser::ParseError> {
    match collector_type {
        CollectorType::NetflowV5 => {
            let (_, flows) = parse_netflow_v5(data, exporter)?;
            Ok(flows)
        }
        CollectorType::NetflowV9 => {
            parse_netflow_v9(data, exporter, template_cache)
        }
        CollectorType::Ipfix => {
            parse_ipfix(data, exporter, template_cache)
        }
        CollectorType::Sflow => {
            parse_sflow(data, exporter)
        }
    }
}

/// Convert a parsed flow to a flow record
fn parsed_to_record(collector_id: &str, exporter_ip: IpAddr, flow: ParsedFlow) -> FlowRecord {
    use chrono::TimeZone;

    // Convert milliseconds to DateTime<Utc>
    let start_time = if flow.start_time_ms > 0 {
        Utc.timestamp_millis_opt(flow.start_time_ms as i64).single().unwrap_or_else(Utc::now)
    } else {
        Utc::now()
    };

    let end_time = if flow.end_time_ms > 0 {
        Utc.timestamp_millis_opt(flow.end_time_ms as i64).single().unwrap_or_else(Utc::now)
    } else {
        Utc::now()
    };

    let duration_ms = if flow.end_time_ms >= flow.start_time_ms {
        (flow.end_time_ms - flow.start_time_ms) as i64
    } else {
        0
    };

    FlowRecord {
        id: Uuid::new_v4().to_string(),
        collector_id: collector_id.to_string(),
        exporter_ip,
        src_ip: flow.src_addr,
        dst_ip: flow.dst_addr,
        src_port: flow.src_port,
        dst_port: flow.dst_port,
        protocol: flow.protocol,
        packets: flow.packets as i64,
        bytes: flow.bytes as i64,
        tcp_flags: Some(flow.tcp_flags),
        start_time,
        end_time,
        duration_ms,
        src_as: if flow.src_as > 0 { Some(flow.src_as as i64) } else { None },
        dst_as: if flow.dst_as > 0 { Some(flow.dst_as as i64) } else { None },
        input_interface: if flow.input_iface > 0 { Some(flow.input_iface as i32) } else { None },
        output_interface: if flow.output_iface > 0 { Some(flow.output_iface as i32) } else { None },
        tos: Some(flow.tos),
        application: super::types::port_to_application(flow.dst_port, flow.protocol)
            .map(|s| s.to_string()),
        src_geo: None,
        dst_geo: None,
        is_suspicious: super::types::is_suspicious_port(flow.dst_port, flow.protocol),
        created_at: Utc::now(),
    }
}

/// Collector errors
#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("Collector {0} is already running")]
    AlreadyRunning(String),

    #[error("Collector {0} not found")]
    NotFound(String),

    #[error("Failed to bind to {0}: {1}")]
    BindError(String, String),

    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Auto-detect flow protocol from packet header
pub fn detect_flow_protocol(data: &[u8]) -> Option<CollectorType> {
    if data.len() < 4 {
        return None;
    }

    // Check version field (first 2 bytes in big-endian)
    let version = ((data[0] as u16) << 8) | (data[1] as u16);

    match version {
        5 => Some(CollectorType::NetflowV5),
        9 => Some(CollectorType::NetflowV9),
        10 => Some(CollectorType::Ipfix),
        // sFlow has different header structure - version is at bytes 0-3
        _ => {
            if data.len() >= 8 {
                let sflow_version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                if sflow_version == 5 {
                    return Some(CollectorType::Sflow);
                }
            }
            None
        }
    }
}

/// Universal collector that auto-detects protocol
pub struct UniversalCollector {
    socket: UdpSocket,
    template_cache: TemplateCache,
    stats: CollectorStats,
}

impl UniversalCollector {
    /// Create a new universal collector
    pub async fn new(listen_addr: &str) -> Result<Self, CollectorError> {
        let socket = UdpSocket::bind(listen_addr).await
            .map_err(|e| CollectorError::BindError(listen_addr.to_string(), e.to_string()))?;

        Ok(Self {
            socket,
            template_cache: TemplateCache::new(),
            stats: CollectorStats::default(),
        })
    }

    /// Receive and parse a single packet
    pub async fn receive_packet(&mut self) -> Result<(SocketAddr, Vec<ParsedFlow>), CollectorError> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        let (len, src_addr) = self.socket.recv_from(&mut buf).await
            .map_err(|e| CollectorError::ParseError(e.to_string()))?;

        self.stats.packets_received += 1;
        self.stats.bytes_received += len as u64;
        self.stats.last_packet_at = Some(Utc::now());

        let exporter = src_addr.ip();
        if !self.stats.exporters_seen.contains(&exporter) {
            self.stats.exporters_seen.push(exporter);
        }

        // Auto-detect protocol
        let protocol = detect_flow_protocol(&buf[..len])
            .ok_or_else(|| CollectorError::ParseError("Unknown flow protocol".into()))?;

        let flows = parse_packet(&buf[..len], exporter, &protocol, &mut self.template_cache)
            .map_err(|e| CollectorError::ParseError(format!("{:?}", e)))?;

        self.stats.flows_parsed += flows.len() as u64;

        Ok((src_addr, flows))
    }

    /// Get collector statistics
    pub fn stats(&self) -> &CollectorStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = CollectorStats::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_netflow_v5() {
        // NetFlow v5 header (version 5 at bytes 0-1)
        let data = [0x00, 0x05, 0x00, 0x01]; // version=5, count=1
        assert_eq!(detect_flow_protocol(&data), Some(CollectorType::NetflowV5));
    }

    #[test]
    fn test_detect_netflow_v9() {
        // NetFlow v9 header (version 9 at bytes 0-1)
        let data = [0x00, 0x09, 0x00, 0x02]; // version=9, count=2
        assert_eq!(detect_flow_protocol(&data), Some(CollectorType::NetflowV9));
    }

    #[test]
    fn test_detect_ipfix() {
        // IPFIX header (version 10 at bytes 0-1)
        let data = [0x00, 0x0a, 0x00, 0x50]; // version=10, length=80
        assert_eq!(detect_flow_protocol(&data), Some(CollectorType::Ipfix));
    }

    #[test]
    fn test_detect_sflow() {
        // sFlow v5 header (version 5 at bytes 0-3 as u32)
        let data = [0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(detect_flow_protocol(&data), Some(CollectorType::Sflow));
    }

    #[test]
    fn test_detect_unknown() {
        let data = [0x00, 0xff, 0x00, 0x00];
        assert_eq!(detect_flow_protocol(&data), None);
    }
}
