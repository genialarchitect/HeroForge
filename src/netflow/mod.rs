//! NetFlow/IPFIX/sFlow Analysis Module
//!
//! Provides network flow collection, parsing, aggregation, and anomaly detection.
//!
//! ## Supported Protocols
//!
//! - **NetFlow v5**: Classic fixed-format flow protocol
//! - **NetFlow v9**: Template-based flow protocol
//! - **IPFIX (NetFlow v10)**: IETF standard based on NetFlow v9
//! - **sFlow v5**: Packet sampling protocol
//!
//! ## Features
//!
//! - Flow collection via UDP listeners
//! - Real-time flow parsing and normalization
//! - Flow aggregation by time periods (minute, 5-min, 15-min, hour, day)
//! - Top talkers analysis
//! - Protocol distribution
//! - Anomaly detection:
//!   - Port scanning
//!   - Network scanning
//!   - DDoS attacks
//!   - Data exfiltration
//!   - Beaconing (C2 communication)
//!   - DNS tunneling
//!   - Unusual protocol usage
//!
//! ## Example
//!
//! ```rust,no_run
//! use heroforge::netflow::{FlowAnalyzer, AnalyzerConfig, AggregationPeriod};
//!
//! let analyzer = FlowAnalyzer::with_defaults();
//!
//! // Aggregate flows by hour
//! let aggregates = analyzer.aggregate_flows(&flows, AggregationPeriod::Hour);
//!
//! // Detect anomalies
//! let anomalies = analyzer.detect_anomalies(&flows);
//!
//! // Get overall statistics
//! let stats = analyzer.calculate_stats(&flows);
//! ```

pub mod types;
pub mod parser;
pub mod collector;
pub mod analyzer;

// Re-export main types
pub use types::{
    CollectorType,
    CollectorStatus,
    FlowCollector,
    IpProtocol,
    TcpFlags,
    GeoLocation,
    FlowRecord,
    FlowRecordRow,
    AggregationPeriod,
    FlowAggregate,
    TopTalker,
    PortCount,
    ProtocolDistribution,
    FlowAnomalyType,
    FlowAnomaly,
    BandwidthUtilization,
    FlowStats,
    FlowTimelineEntry,
    port_to_application,
    is_suspicious_port,
};

pub use parser::{
    ParseError,
    ParsedFlow,
    TemplateCache,
    parse_netflow_v5,
    parse_netflow_v9,
    parse_ipfix,
    parse_sflow,
};

pub use collector::{
    FlowCollectorManager,
    CollectorStats,
    CollectorError,
    UniversalCollector,
    detect_flow_protocol,
};

pub use analyzer::{
    FlowAnalyzer,
    AnalyzerConfig,
};
