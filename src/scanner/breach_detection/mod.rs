//! Breach/Leak Detection Module
//!
//! This module provides functionality to check emails and domains against
//! known data breach databases to identify credential exposure.
//!
//! Supported data sources:
//! - Have I Been Pwned API (HIBP)
//! - Dehashed API (optional, requires API key)
//! - Local breach database (for imported breach compilations)

pub mod types;
pub mod hibp;
pub mod dehashed;
pub mod local_db;
pub mod engine;

pub use types::*;
pub use engine::BreachDetectionEngine;
