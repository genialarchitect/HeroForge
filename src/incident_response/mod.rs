//! Incident Response Module for HeroForge Blue Team
//!
//! This module provides comprehensive incident response capabilities:
//! - Incident lifecycle management (detected -> triaged -> contained -> eradicated -> recovered -> closed)
//! - Event timeline builder with multiple sources
//! - Evidence collection with chain of custody tracking
//! - SOAR-lite automation with response playbooks

#![allow(dead_code)]

pub mod incidents;
pub mod timeline;
pub mod evidence;
pub mod automation;
pub mod types;

