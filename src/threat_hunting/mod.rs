//! Threat Hunting Module for Blue Team Operations
//!
//! This module provides comprehensive threat hunting capabilities including:
//! - **IOC Management**: Indicators of Compromise (IP, domain, hash, URL, email, filename, registry key)
//! - **MITRE ATT&CK Integration**: Full matrix support with technique mapping
//! - **Hunting Playbooks**: Structured hunting procedures with built-in templates
//! - **Retrospective Search**: Historical log analysis for IOC detection

#![allow(dead_code)]

pub mod ioc;
pub mod mitre;
pub mod playbooks;
pub mod retrospective;

pub use ioc::*;
pub use mitre::*;
pub use playbooks::*;
pub use retrospective::*;
