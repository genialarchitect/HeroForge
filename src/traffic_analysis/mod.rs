//! Traffic Analysis Module
//!
//! Comprehensive network traffic analysis including:
//! - PCAP file parsing and session reconstruction
//! - Protocol dissection (HTTP, DNS, TLS, SMB, etc.)
//! - IDS rule matching (Suricata/Snort format)
//! - JA3/JA3S TLS fingerprinting
//! - Beacon detection and C2 analysis
//! - File carving from network streams
//! - Traffic replay capabilities

pub mod types;
pub mod pcap;
pub mod protocols;
pub mod ids;
pub mod fingerprinting;
pub mod beacon;
pub mod carving;

pub use types::*;
pub use pcap::PcapParser;
pub use protocols::ProtocolAnalyzer;
pub use ids::{IdsEngine, load_emerging_threats_rules};
pub use fingerprinting::Ja3Fingerprinter;
pub use beacon::BeaconDetector;
pub use carving::FileCarver;
