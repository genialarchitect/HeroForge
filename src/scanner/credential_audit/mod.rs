//! Credential Auditing Module
//!
//! This module provides credential testing capabilities for penetration testing.
//! It checks for default and weak credentials across various services.
//!
//! **WARNING: This tool is for AUTHORIZED SECURITY TESTING ONLY.**
//! Unauthorized access to computer systems is illegal. Only use this tool
//! on systems you have explicit permission to test.

pub mod types;
pub mod wordlists;
pub mod testers;
pub mod engine;

pub use types::*;
pub use engine::CredentialAuditEngine;
