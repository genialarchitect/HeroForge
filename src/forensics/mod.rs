//! Digital Forensics module for HeroForge Blue Team
//!
//! This module provides comprehensive digital forensics capabilities:
//! - Memory analysis (dump parsing, process extraction, network connections)
//! - Disk analysis (timeline, deleted files, registry, browser artifacts)
//! - Network analysis (PCAP parsing, protocol statistics, suspicious indicators)
//! - Artifact collection (Windows, Linux, Web artifacts)

pub mod memory;
pub mod disk;
pub mod network;
pub mod artifacts;
pub mod types;

pub use types::*;
pub use memory::*;
pub use disk::*;
pub use network::*;
pub use artifacts::*;
