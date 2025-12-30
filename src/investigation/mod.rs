//! Investigation Module - Advanced Investigation Tools for Deep-Dive Analysis
//!
//! This module provides cutting-edge investigation tools for security analysts:
//! - Timeline analysis and attack timeline reconstruction
//! - Entity relationship graphs and attack path visualization
//! - Memory forensics with Volatility integration
//! - Advanced PCAP analysis and network forensics

pub mod timeline;
pub mod graph;
pub mod memory_forensics;
pub mod pcap_analysis;
pub mod types;

pub use types::*;
