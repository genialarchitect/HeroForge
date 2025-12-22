//! C2 Framework Integration Module
//!
//! Provides integration with popular Command & Control frameworks including:
//! - Sliver
//! - Havoc (planned)
//! - Mythic (planned)
//!
//! This module enables:
//! - Managing C2 server connections
//! - Listener creation and management
//! - Implant/beacon generation
//! - Session tracking and interaction
//! - Task queuing and results
//! - Credential extraction

pub mod types;
pub mod sliver;
pub mod manager;

pub use manager::C2Manager;
pub use types::*;
