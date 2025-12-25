//! C2 Framework Integration Module
//!
//! Provides integration with popular Command & Control frameworks including:
//! - Cobalt Strike (External C2 specification)
//! - Sliver (Operator API)
//! - Havoc (WebSocket teamserver)
//! - Mythic (GraphQL API)
//! - Custom (Simple HTTP-based protocol)
//!
//! This module enables:
//! - Managing C2 server connections
//! - Listener creation and management
//! - Implant/beacon generation
//! - Session tracking and interaction
//! - Task queuing and results
//! - Credential extraction

pub mod types;
pub mod cobaltstrike;
pub mod sliver;
pub mod havoc;
pub mod mythic;
pub mod custom;
pub mod manager;

pub use manager::C2Manager;
#[allow(unused_imports)]
pub use types::*;

// Re-export client types for convenience
#[allow(unused_imports)]
pub use cobaltstrike::CobaltStrikeClient;
#[allow(unused_imports)]
pub use sliver::SliverClient;
#[allow(unused_imports)]
pub use havoc::HavocClient;
#[allow(unused_imports)]
pub use mythic::MythicClient;
#[allow(unused_imports)]
pub use custom::{CustomC2Client, CustomC2Server};
