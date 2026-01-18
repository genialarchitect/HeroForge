//! Legal Documents Module
//!
//! This module provides functionality for creating, managing, and signing
//! pre-engagement legal documents including:
//! - Rules of Engagement (ROE)
//! - Authorization to Test (ATO)
//! - Non-Disclosure Agreement (NDA)
//! - Statement of Work (SOW)
//! - Master Service Agreement (MSA)

pub mod types;
pub mod placeholders;
pub mod pdf;
pub mod templates;

pub use types::*;
pub use placeholders::PlaceholderEngine;
