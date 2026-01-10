//! Threat Hunting Module for Blue Team Operations
//!
//! This module provides comprehensive threat hunting capabilities including:
//! - **IOC Management**: Indicators of Compromise (IP, domain, hash, URL, email, filename, registry key)
//! - **MITRE ATT&CK Integration**: Full matrix support with technique mapping
//! - **Hunting Playbooks**: Structured hunting procedures with built-in templates
//! - **Retrospective Search**: Historical log analysis for IOC detection
//! - **Hypothesis-Driven Hunting**: Structured hypothesis testing and validation
//! - **Hunt Query DSL**: Custom query language for threat hunting
//! - **Hunt Analytics**: Effectiveness metrics and ROI tracking
//! - **Hunt Automation**: Scheduled hunts and automated execution
//! - **Collaborative Hunting**: Team workspaces and shared notebooks

#![allow(dead_code)]

pub mod ioc;
pub mod mitre;
pub mod playbooks;
pub mod retrospective;
pub mod types;
pub mod hypothesis;
pub mod query_dsl;
pub mod analytics;
pub mod automation;
pub mod collaboration;

