//! Flow Analyzer - Aggregation, top talkers, and anomaly detection
//!
//! Provides analysis capabilities for network flow data.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use chrono::{DateTime, Utc, Duration, Timelike};
use uuid::Uuid;

use super::types::{
    FlowRecord, FlowAggregate, AggregationPeriod, TopTalker, PortCount,
    ProtocolDistribution, FlowAnomaly, FlowAnomalyType, FlowStats,
    FlowTimelineEntry, BandwidthUtilization, IpProtocol, analyze_beaconing,
};

/// Flow analyzer for aggregation and anomaly detection
pub struct FlowAnalyzer {
    /// Detection thresholds
    config: AnalyzerConfig,
    /// Historical baselines for anomaly detection
    baselines: HashMap<String, Baseline>,
}

/// Configuration for the analyzer
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Threshold for port scan detection (unique ports per source)
    pub port_scan_threshold: u32,
    /// Threshold for network scan detection (unique hosts per source)
    pub network_scan_threshold: u32,
    /// Threshold for DDoS detection (packets per second to single destination)
    pub ddos_pps_threshold: u64,
    /// Threshold for data exfiltration (bytes per flow)
    pub exfiltration_bytes_threshold: u64,
    /// Beaconing regularity threshold (coefficient of variation)
    pub beaconing_cv_threshold: f64,
    /// Top N for top talkers analysis
    pub top_n: usize,
    /// Baseline window for anomaly detection
    pub baseline_window_hours: u32,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            port_scan_threshold: 100,
            network_scan_threshold: 50,
            ddos_pps_threshold: 100_000,
            exfiltration_bytes_threshold: 100_000_000, // 100 MB
            beaconing_cv_threshold: 0.15,
            top_n: 10,
            baseline_window_hours: 24,
        }
    }
}

/// Historical baseline for anomaly detection
#[derive(Debug, Clone, Default)]
struct Baseline {
    avg_bytes_per_hour: f64,
    avg_flows_per_hour: f64,
    avg_packets_per_hour: f64,
    std_dev_bytes: f64,
    std_dev_flows: f64,
    sample_count: u32,
}

impl FlowAnalyzer {
    /// Create a new flow analyzer
    pub fn new(config: AnalyzerConfig) -> Self {
        Self {
            config,
            baselines: HashMap::new(),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(AnalyzerConfig::default())
    }

    /// Aggregate flows by time period
    pub fn aggregate_flows(
        &self,
        flows: &[FlowRecord],
        period: AggregationPeriod,
    ) -> Vec<FlowAggregate> {
        let mut aggregates: HashMap<String, FlowAggregate> = HashMap::new();

        for flow in flows {
            let period_start = truncate_time(&flow.start_time, &period);
            let key = period_start.to_rfc3339();

            let agg = aggregates.entry(key).or_insert_with(|| FlowAggregate {
                id: Uuid::new_v4().to_string(),
                period: period.clone(),
                period_start,
                period_end: add_period(&period_start, &period),
                total_flows: 0,
                total_bytes: 0,
                total_packets: 0,
                unique_sources: 0,
                unique_destinations: 0,
                unique_source_ports: 0,
                unique_destination_ports: 0,
                top_sources: vec![],
                top_destinations: vec![],
                top_source_ports: vec![],
                top_destination_ports: vec![],
                protocol_distribution: vec![],
                avg_flow_duration_ms: 0.0,
                created_at: Utc::now(),
            });

            agg.total_flows += 1;
            agg.total_bytes += flow.bytes;
            agg.total_packets += flow.packets;
        }

        // Calculate unique counts and top talkers for each aggregate
        let mut result: Vec<FlowAggregate> = aggregates.into_values().collect();

        for agg in &mut result {
            let period_flows: Vec<&FlowRecord> = flows.iter()
                .filter(|f| {
                    let t = truncate_time(&f.start_time, &period);
                    t == agg.period_start
                })
                .collect();

            // Calculate unique counts
            let unique_srcs: HashSet<IpAddr> = period_flows.iter().map(|f| f.src_ip).collect();
            let unique_dsts: HashSet<IpAddr> = period_flows.iter().map(|f| f.dst_ip).collect();
            let unique_src_ports: HashSet<u16> = period_flows.iter().map(|f| f.src_port).collect();
            let unique_dst_ports: HashSet<u16> = period_flows.iter().map(|f| f.dst_port).collect();

            agg.unique_sources = unique_srcs.len() as i64;
            agg.unique_destinations = unique_dsts.len() as i64;
            agg.unique_source_ports = unique_src_ports.len() as i64;
            agg.unique_destination_ports = unique_dst_ports.len() as i64;

            // Calculate top sources
            agg.top_sources = self.calculate_top_talkers(&period_flows, true);
            agg.top_destinations = self.calculate_top_talkers(&period_flows, false);
            agg.top_source_ports = self.calculate_top_ports(&period_flows, true);
            agg.top_destination_ports = self.calculate_top_ports(&period_flows, false);
            agg.protocol_distribution = self.calculate_protocol_distribution(&period_flows);

            // Calculate average flow duration
            let total_duration: i64 = period_flows.iter().map(|f| f.duration_ms).sum();
            if !period_flows.is_empty() {
                agg.avg_flow_duration_ms = total_duration as f64 / period_flows.len() as f64;
            }
        }

        result.sort_by(|a, b| a.period_start.cmp(&b.period_start));
        result
    }

    /// Calculate top talkers (sources or destinations)
    fn calculate_top_talkers(&self, flows: &[&FlowRecord], by_source: bool) -> Vec<TopTalker> {
        let mut talkers: HashMap<IpAddr, (i64, i64, i64)> = HashMap::new();

        for flow in flows {
            let ip = if by_source { flow.src_ip } else { flow.dst_ip };
            let entry = talkers.entry(ip).or_insert((0, 0, 0));
            entry.0 += flow.bytes;
            entry.1 += flow.packets;
            entry.2 += 1;
        }

        let mut sorted: Vec<_> = talkers.into_iter().collect();
        sorted.sort_by(|a, b| b.1.0.cmp(&a.1.0)); // Sort by bytes descending

        sorted.into_iter()
            .take(self.config.top_n)
            .map(|(ip, (bytes, packets, flows))| TopTalker {
                ip_address: ip,
                total_bytes: bytes,
                total_packets: packets,
                flow_count: flows,
                percentage: 0.0, // Calculated later
                geo_location: None,
                as_number: None,
                as_name: None,
            })
            .collect()
    }

    /// Calculate top ports
    fn calculate_top_ports(&self, flows: &[&FlowRecord], source: bool) -> Vec<PortCount> {
        let mut ports: HashMap<u16, (i64, i64)> = HashMap::new();

        for flow in flows {
            let port = if source { flow.src_port } else { flow.dst_port };
            let entry = ports.entry(port).or_insert((0, 0));
            entry.0 += flow.bytes;
            entry.1 += 1;
        }

        let mut sorted: Vec<_> = ports.into_iter().collect();
        sorted.sort_by(|a, b| b.1.1.cmp(&a.1.1)); // Sort by flow count descending

        sorted.into_iter()
            .take(self.config.top_n)
            .map(|(port, (bytes, flow_count))| {
                let service = super::types::port_to_application(port, 6)
                    .map(|s| s.to_string());
                PortCount {
                    port,
                    service,
                    count: flow_count,
                    bytes,
                    percentage: 0.0,
                }
            })
            .collect()
    }

    /// Calculate protocol distribution
    fn calculate_protocol_distribution(&self, flows: &[&FlowRecord]) -> Vec<ProtocolDistribution> {
        let mut protocols: HashMap<u8, (i64, i64, i64)> = HashMap::new();

        for flow in flows {
            let entry = protocols.entry(flow.protocol).or_insert((0, 0, 0));
            entry.0 += flow.bytes;
            entry.1 += flow.packets;
            entry.2 += 1;
        }

        let total_bytes: i64 = protocols.values().map(|v| v.0).sum();

        protocols.into_iter()
            .map(|(proto, (bytes, packets, flows))| {
                let protocol_name = IpProtocol::try_from(proto)
                    .map(|p| format!("{:?}", p))
                    .unwrap_or_else(|_| format!("Protocol {}", proto));

                ProtocolDistribution {
                    protocol: proto,
                    protocol_name,
                    bytes,
                    packets,
                    flow_count: flows,
                    percentage: if total_bytes > 0 {
                        (bytes as f64 / total_bytes as f64) * 100.0
                    } else {
                        0.0
                    },
                }
            })
            .collect()
    }

    /// Detect anomalies in flow data
    pub fn detect_anomalies(&self, flows: &[FlowRecord]) -> Vec<FlowAnomaly> {
        let mut anomalies = Vec::new();

        // Detect port scans
        anomalies.extend(self.detect_port_scans(flows));

        // Detect network scans
        anomalies.extend(self.detect_network_scans(flows));

        // Detect DDoS patterns
        anomalies.extend(self.detect_ddos(flows));

        // Detect data exfiltration
        anomalies.extend(self.detect_exfiltration(flows));

        // Detect beaconing
        anomalies.extend(self.detect_beaconing(flows));

        // Detect unusual protocols
        anomalies.extend(self.detect_unusual_protocols(flows));

        // Detect DNS tunneling
        anomalies.extend(self.detect_dns_tunneling(flows));

        anomalies
    }

    /// Detect port scanning activity
    fn detect_port_scans(&self, flows: &[FlowRecord]) -> Vec<FlowAnomaly> {
        let mut anomalies = Vec::new();

        // Group flows by source IP
        let mut source_ports: HashMap<IpAddr, HashSet<u16>> = HashMap::new();
        let mut source_targets: HashMap<IpAddr, HashSet<IpAddr>> = HashMap::new();

        for flow in flows {
            source_ports.entry(flow.src_ip).or_default().insert(flow.dst_port);
            source_targets.entry(flow.src_ip).or_default().insert(flow.dst_ip);
        }

        for (src_ip, ports) in source_ports {
            let port_count = ports.len();
            if port_count as u32 >= self.config.port_scan_threshold {
                let targets = source_targets.get(&src_ip).map(|t| t.len()).unwrap_or(0);

                anomalies.push(FlowAnomaly {
                    id: Uuid::new_v4().to_string(),
                    anomaly_type: FlowAnomalyType::PortScan,
                    severity: if port_count > 500 { "high".to_string() } else { "medium".to_string() },
                    title: format!("Port scan detected from {}", src_ip),
                    description: format!(
                        "Source {} scanned {} unique ports across {} targets",
                        src_ip, port_count, targets
                    ),
                    source_ip: Some(src_ip),
                    destination_ip: None,
                    affected_ports: ports.into_iter().collect(),
                    evidence: serde_json::json!({
                        "unique_ports": port_count,
                        "target_count": targets,
                    }),
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    flow_count: 0,
                    total_bytes: 0,
                    total_packets: 0,
                    is_acknowledged: false,
                    acknowledged_by: None,
                    acknowledged_at: None,
                    created_at: Utc::now(),
                });
            }
        }

        anomalies
    }

    /// Detect network scanning activity
    fn detect_network_scans(&self, flows: &[FlowRecord]) -> Vec<FlowAnomaly> {
        let mut anomalies = Vec::new();

        // Group by source IP and destination port
        let mut scans: HashMap<(IpAddr, u16), HashSet<IpAddr>> = HashMap::new();

        for flow in flows {
            scans.entry((flow.src_ip, flow.dst_port)).or_default().insert(flow.dst_ip);
        }

        for ((src_ip, port), targets) in scans {
            if targets.len() as u32 >= self.config.network_scan_threshold {
                anomalies.push(FlowAnomaly {
                    id: Uuid::new_v4().to_string(),
                    anomaly_type: FlowAnomalyType::NetworkScan,
                    severity: if targets.len() > 200 { "high".to_string() } else { "medium".to_string() },
                    title: format!("Network scan detected from {}", src_ip),
                    description: format!(
                        "Source {} scanned {} unique hosts on port {}",
                        src_ip, targets.len(), port
                    ),
                    source_ip: Some(src_ip),
                    destination_ip: None,
                    affected_ports: vec![port],
                    evidence: serde_json::json!({
                        "target_count": targets.len(),
                        "port": port,
                        "sample_targets": targets.iter().take(10).collect::<Vec<_>>(),
                    }),
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    flow_count: 0,
                    total_bytes: 0,
                    total_packets: 0,
                    is_acknowledged: false,
                    acknowledged_by: None,
                    acknowledged_at: None,
                    created_at: Utc::now(),
                });
            }
        }

        anomalies
    }

    /// Detect DDoS attack patterns
    fn detect_ddos(&self, flows: &[FlowRecord]) -> Vec<FlowAnomaly> {
        let mut anomalies = Vec::new();

        // Group by destination IP
        let mut dst_stats: HashMap<IpAddr, (i64, i64, i64)> = HashMap::new(); // (packets, bytes, flows)

        for flow in flows {
            let entry = dst_stats.entry(flow.dst_ip).or_insert((0, 0, 0));
            entry.0 += flow.packets;
            entry.1 += flow.bytes;
            entry.2 += 1;
        }

        // Check for high traffic volumes to single destinations
        for (dst_ip, (packets, bytes, flow_count)) in dst_stats {
            // Simple check: if packets per flow is very high, might be DDoS
            if packets as u64 >= self.config.ddos_pps_threshold {
                anomalies.push(FlowAnomaly {
                    id: Uuid::new_v4().to_string(),
                    anomaly_type: FlowAnomalyType::DdosAttack,
                    severity: "critical".to_string(),
                    title: format!("Potential DDoS attack targeting {}", dst_ip),
                    description: format!(
                        "High traffic volume detected: {} packets, {} bytes across {} flows",
                        packets, bytes, flow_count
                    ),
                    source_ip: None,
                    destination_ip: Some(dst_ip),
                    affected_ports: vec![],
                    evidence: serde_json::json!({
                        "total_packets": packets,
                        "total_bytes": bytes,
                        "flow_count": flow_count,
                    }),
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    flow_count,
                    total_bytes: bytes,
                    total_packets: packets,
                    is_acknowledged: false,
                    acknowledged_by: None,
                    acknowledged_at: None,
                    created_at: Utc::now(),
                });
            }
        }

        anomalies
    }

    /// Detect data exfiltration patterns
    fn detect_exfiltration(&self, flows: &[FlowRecord]) -> Vec<FlowAnomaly> {
        let mut anomalies = Vec::new();

        for flow in flows {
            // Check for large outbound transfers
            if flow.bytes as u64 >= self.config.exfiltration_bytes_threshold {
                // Check if it's to an external IP (simplified - RFC1918 check)
                if !is_private_ip(&flow.dst_ip) {
                    anomalies.push(FlowAnomaly {
                        id: Uuid::new_v4().to_string(),
                        anomaly_type: FlowAnomalyType::DataExfiltration,
                        severity: "high".to_string(),
                        title: format!("Large data transfer detected to {}", flow.dst_ip),
                        description: format!(
                            "Transfer of {} bytes from {} to external IP {}",
                            flow.bytes, flow.src_ip, flow.dst_ip
                        ),
                        source_ip: Some(flow.src_ip),
                        destination_ip: Some(flow.dst_ip),
                        affected_ports: vec![flow.dst_port],
                        evidence: serde_json::json!({
                            "bytes": flow.bytes,
                            "packets": flow.packets,
                            "duration_ms": flow.duration_ms,
                            "protocol": flow.protocol,
                        }),
                        first_seen: flow.start_time,
                        last_seen: flow.end_time,
                        flow_count: 1,
                        total_bytes: flow.bytes,
                        total_packets: flow.packets,
                        is_acknowledged: false,
                        acknowledged_by: None,
                        acknowledged_at: None,
                        created_at: Utc::now(),
                    });
                }
            }
        }

        anomalies
    }

    /// Detect beaconing behavior (regular interval communications)
    fn detect_beaconing(&self, flows: &[FlowRecord]) -> Vec<FlowAnomaly> {
        let mut anomalies = Vec::new();

        // Group flows by source-destination pair
        let mut pairs: HashMap<(IpAddr, IpAddr), Vec<&FlowRecord>> = HashMap::new();

        for flow in flows {
            pairs.entry((flow.src_ip, flow.dst_ip)).or_default().push(flow);
        }

        for ((src, dst), pair_flows) in pairs {
            if pair_flows.len() < 10 {
                continue; // Need enough samples
            }

            // Sort by time and calculate intervals
            let mut sorted_flows: Vec<_> = pair_flows.into_iter().collect();
            sorted_flows.sort_by(|a, b| a.start_time.cmp(&b.start_time));

            let intervals: Vec<u64> = sorted_flows.windows(2)
                .map(|w| (w[1].start_time - w[0].start_time).num_milliseconds().unsigned_abs())
                .collect();

            if intervals.is_empty() {
                continue;
            }

            // Check for beaconing pattern
            if let Some(cv) = analyze_beaconing(&intervals) {
                if cv < self.config.beaconing_cv_threshold {
                    let avg_interval: f64 = intervals.iter().sum::<u64>() as f64 / intervals.len() as f64;

                    anomalies.push(FlowAnomaly {
                        id: Uuid::new_v4().to_string(),
                        anomaly_type: FlowAnomalyType::Beaconing,
                        severity: "medium".to_string(),
                        title: format!("Beaconing behavior detected from {} to {}", src, dst),
                        description: format!(
                            "Regular communication pattern detected with ~{:.0}ms interval (CV: {:.3})",
                            avg_interval, cv
                        ),
                        source_ip: Some(src),
                        destination_ip: Some(dst),
                        affected_ports: vec![],
                        evidence: serde_json::json!({
                            "coefficient_of_variation": cv,
                            "average_interval_ms": avg_interval,
                            "sample_count": intervals.len(),
                        }),
                        first_seen: sorted_flows.first().map(|f| f.start_time).unwrap_or_else(Utc::now),
                        last_seen: sorted_flows.last().map(|f| f.start_time).unwrap_or_else(Utc::now),
                        flow_count: sorted_flows.len() as i64,
                        total_bytes: sorted_flows.iter().map(|f| f.bytes).sum(),
                        total_packets: sorted_flows.iter().map(|f| f.packets).sum(),
                        is_acknowledged: false,
                        acknowledged_by: None,
                        acknowledged_at: None,
                        created_at: Utc::now(),
                    });
                }
            }
        }

        anomalies
    }

    /// Detect unusual protocol usage
    fn detect_unusual_protocols(&self, flows: &[FlowRecord]) -> Vec<FlowAnomaly> {
        let mut anomalies = Vec::new();

        // Unusual protocol numbers (not TCP, UDP, ICMP)
        let unusual_protocols: HashSet<u8> = [
            47,  // GRE
            50,  // ESP (IPsec)
            51,  // AH (IPsec)
            89,  // OSPF
            112, // VRRP
            132, // SCTP
        ].into_iter().collect();

        let mut protocol_flows: HashMap<u8, Vec<&FlowRecord>> = HashMap::new();
        for flow in flows {
            if unusual_protocols.contains(&flow.protocol) {
                protocol_flows.entry(flow.protocol).or_default().push(flow);
            }
        }

        for (proto, proto_flows) in protocol_flows {
            if proto_flows.len() >= 5 {
                let proto_name = IpProtocol::try_from(proto)
                    .map(|p| format!("{:?}", p))
                    .unwrap_or_else(|_| format!("Protocol {}", proto));

                let total_bytes: i64 = proto_flows.iter().map(|f| f.bytes).sum();
                let total_packets: i64 = proto_flows.iter().map(|f| f.packets).sum();

                anomalies.push(FlowAnomaly {
                    id: Uuid::new_v4().to_string(),
                    anomaly_type: FlowAnomalyType::UnusualProtocol,
                    severity: "low".to_string(),
                    title: format!("Unusual protocol {} detected", proto_name),
                    description: format!(
                        "{} flows using {} protocol detected",
                        proto_flows.len(), proto_name
                    ),
                    source_ip: None,
                    destination_ip: None,
                    affected_ports: vec![],
                    evidence: serde_json::json!({
                        "protocol": proto,
                        "protocol_name": proto_name,
                        "flow_count": proto_flows.len(),
                        "total_bytes": total_bytes,
                    }),
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    flow_count: proto_flows.len() as i64,
                    total_bytes,
                    total_packets,
                    is_acknowledged: false,
                    acknowledged_by: None,
                    acknowledged_at: None,
                    created_at: Utc::now(),
                });
            }
        }

        anomalies
    }

    /// Detect DNS tunneling patterns
    fn detect_dns_tunneling(&self, flows: &[FlowRecord]) -> Vec<FlowAnomaly> {
        let mut anomalies = Vec::new();

        // Filter DNS flows (port 53)
        let dns_flows: Vec<&FlowRecord> = flows.iter()
            .filter(|f| f.dst_port == 53 || f.src_port == 53)
            .collect();

        // Group by source
        let mut source_dns: HashMap<IpAddr, (i64, i64)> = HashMap::new();
        for flow in &dns_flows {
            let entry = source_dns.entry(flow.src_ip).or_insert((0, 0));
            entry.0 += flow.bytes;
            entry.1 += 1;
        }

        // DNS tunneling indicators: high bytes per query or many queries
        for (src, (bytes, queries)) in source_dns {
            let avg_bytes = bytes as f64 / queries as f64;

            // Flag if average DNS response is unusually large (>500 bytes) or many queries
            if avg_bytes > 500.0 || queries > 1000 {
                anomalies.push(FlowAnomaly {
                    id: Uuid::new_v4().to_string(),
                    anomaly_type: FlowAnomalyType::DnsTunneling,
                    severity: if avg_bytes > 1000.0 { "high".to_string() } else { "medium".to_string() },
                    title: format!("Potential DNS tunneling from {}", src),
                    description: format!(
                        "Unusual DNS traffic: {} queries, {:.0} avg bytes/query",
                        queries, avg_bytes
                    ),
                    source_ip: Some(src),
                    destination_ip: None,
                    affected_ports: vec![53],
                    evidence: serde_json::json!({
                        "total_queries": queries,
                        "total_bytes": bytes,
                        "avg_bytes_per_query": avg_bytes,
                    }),
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    flow_count: queries,
                    total_bytes: bytes,
                    total_packets: 0,
                    is_acknowledged: false,
                    acknowledged_by: None,
                    acknowledged_at: None,
                    created_at: Utc::now(),
                });
            }
        }

        anomalies
    }

    /// Calculate overall flow statistics
    pub fn calculate_stats(&self, flows: &[FlowRecord]) -> FlowStats {
        if flows.is_empty() {
            return FlowStats::default();
        }

        let total_flows = flows.len() as i64;
        let total_bytes: i64 = flows.iter().map(|f| f.bytes).sum();
        let total_packets: i64 = flows.iter().map(|f| f.packets).sum();

        let unique_sources: HashSet<IpAddr> = flows.iter().map(|f| f.src_ip).collect();
        let unique_destinations: HashSet<IpAddr> = flows.iter().map(|f| f.dst_ip).collect();

        let start = flows.iter().map(|f| f.start_time).min();
        let end = flows.iter().map(|f| f.end_time).max();

        let duration_secs = match (start, end) {
            (Some(s), Some(e)) => (e - s).num_seconds().max(1),
            _ => 1,
        };

        let bytes_per_second = total_bytes as f64 / duration_secs as f64;
        let packets_per_second = total_packets as f64 / duration_secs as f64;
        let flows_per_second = total_flows as f64 / duration_secs as f64;

        FlowStats {
            total_flows,
            total_bytes,
            total_packets,
            unique_sources: unique_sources.len() as i64,
            unique_destinations: unique_destinations.len() as i64,
            bytes_per_second,
            packets_per_second,
            flows_per_second,
            avg_flow_size: total_bytes as f64 / total_flows as f64,
            avg_packet_size: if total_packets > 0 {
                total_bytes as f64 / total_packets as f64
            } else {
                0.0
            },
            tcp_flows: flows.iter().filter(|f| f.protocol == 6).count() as i64,
            udp_flows: flows.iter().filter(|f| f.protocol == 17).count() as i64,
            icmp_flows: flows.iter().filter(|f| f.protocol == 1).count() as i64,
            other_flows: flows.iter().filter(|f| f.protocol != 6 && f.protocol != 17 && f.protocol != 1).count() as i64,
            period_start: start,
            period_end: end,
        }
    }

    /// Generate timeline data for visualization
    pub fn generate_timeline(
        &self,
        flows: &[FlowRecord],
        period: AggregationPeriod,
    ) -> Vec<FlowTimelineEntry> {
        let aggregates = self.aggregate_flows(flows, period);

        aggregates.into_iter()
            .map(|agg| FlowTimelineEntry {
                timestamp: agg.period_start,
                flows: agg.total_flows,
                bytes: agg.total_bytes,
                packets: agg.total_packets,
                unique_sources: agg.unique_sources,
                unique_destinations: agg.unique_destinations,
            })
            .collect()
    }

    /// Calculate bandwidth utilization over time
    pub fn calculate_bandwidth_utilization(
        &self,
        flows: &[FlowRecord],
        interface_bandwidth_bps: u64,
    ) -> Vec<BandwidthUtilization> {
        let timeline = self.generate_timeline(flows, AggregationPeriod::Minute);

        timeline.into_iter()
            .map(|entry| {
                // Convert bytes to bits per second for the minute
                let bits_per_second = (entry.bytes * 8) as f64 / 60.0;
                let utilization_percent = (bits_per_second / interface_bandwidth_bps as f64) * 100.0;

                BandwidthUtilization {
                    timestamp: entry.timestamp,
                    inbound_bytes: entry.bytes / 2, // Simplified: assume half in/out
                    outbound_bytes: entry.bytes / 2,
                    inbound_packets: entry.packets / 2,
                    outbound_packets: entry.packets / 2,
                    utilization_percent,
                }
            })
            .collect()
    }
}

/// Check if an IP address is in a private range
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_unspecified()
        }
    }
}

/// Truncate a datetime to the start of a period
fn truncate_time(dt: &DateTime<Utc>, period: &AggregationPeriod) -> DateTime<Utc> {
    match period {
        AggregationPeriod::Minute => {
            dt.with_second(0).unwrap().with_nanosecond(0).unwrap()
        }
        AggregationPeriod::FiveMinutes => {
            let minute = (dt.minute() / 5) * 5;
            dt.with_minute(minute).unwrap().with_second(0).unwrap().with_nanosecond(0).unwrap()
        }
        AggregationPeriod::FifteenMinutes => {
            let minute = (dt.minute() / 15) * 15;
            dt.with_minute(minute).unwrap().with_second(0).unwrap().with_nanosecond(0).unwrap()
        }
        AggregationPeriod::Hour => {
            dt.with_minute(0).unwrap().with_second(0).unwrap().with_nanosecond(0).unwrap()
        }
        AggregationPeriod::Day => {
            dt.with_hour(0).unwrap().with_minute(0).unwrap().with_second(0).unwrap().with_nanosecond(0).unwrap()
        }
    }
}

/// Add a period duration to a datetime
fn add_period(dt: &DateTime<Utc>, period: &AggregationPeriod) -> DateTime<Utc> {
    match period {
        AggregationPeriod::Minute => *dt + Duration::minutes(1),
        AggregationPeriod::FiveMinutes => *dt + Duration::minutes(5),
        AggregationPeriod::FifteenMinutes => *dt + Duration::minutes(15),
        AggregationPeriod::Hour => *dt + Duration::hours(1),
        AggregationPeriod::Day => *dt + Duration::days(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_flow(src: &str, dst: &str, src_port: u16, dst_port: u16, bytes: i64) -> FlowRecord {
        FlowRecord {
            id: Uuid::new_v4().to_string(),
            collector_id: "test".to_string(),
            exporter_ip: "10.0.0.1".parse().unwrap(),
            src_ip: src.parse().unwrap(),
            dst_ip: dst.parse().unwrap(),
            src_port,
            dst_port,
            protocol: 6, // TCP
            packets: 100,
            bytes,
            tcp_flags: None,
            start_time: Utc::now(),
            end_time: Utc::now(),
            duration_ms: 1000,
            src_as: None,
            dst_as: None,
            input_interface: None,
            output_interface: None,
            tos: None,
            application: None,
            src_geo: None,
            dst_geo: None,
            is_suspicious: false,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_calculate_stats() {
        let analyzer = FlowAnalyzer::with_defaults();
        let flows = vec![
            create_test_flow("192.168.1.1", "10.0.0.1", 12345, 80, 1000),
            create_test_flow("192.168.1.2", "10.0.0.2", 12346, 443, 2000),
        ];

        let stats = analyzer.calculate_stats(&flows);
        assert_eq!(stats.total_flows, 2);
        assert_eq!(stats.total_bytes, 3000);
        assert_eq!(stats.unique_sources, 2);
        assert_eq!(stats.unique_destinations, 2);
    }

    #[test]
    fn test_detect_port_scan() {
        let mut analyzer = FlowAnalyzer::with_defaults();
        analyzer.config.port_scan_threshold = 5; // Lower threshold for test

        // Create flows from one source to many ports
        let mut flows = Vec::new();
        for port in 1..10 {
            flows.push(create_test_flow("192.168.1.1", "10.0.0.1", 12345, port, 100));
        }

        let anomalies = analyzer.detect_anomalies(&flows);
        assert!(!anomalies.is_empty());
        assert!(anomalies.iter().any(|a| matches!(a.anomaly_type, FlowAnomalyType::PortScan)));
    }

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
    }
}
