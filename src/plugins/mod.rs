//! Plugin System for HeroForge
//!
//! This module provides the plugin marketplace foundation, enabling extensibility
//! through scanner plugins, detector plugins, reporter plugins, and integrations.
//!
//! ## Architecture
//!
//! - `types.rs` - Core plugin types and data structures
//! - `manifest.rs` - TOML manifest parsing and validation
//! - `api.rs` - Plugin API traits that plugins implement
//! - `loader.rs` - Plugin loading and validation
//! - `registry.rs` - Plugin registry for tracking installed plugins

#![allow(dead_code)]

pub mod api;
pub mod distribution;
pub mod loader;
pub mod manifest;
pub mod marketplace;
pub mod registry;
pub mod sandboxing;
pub mod sdk;
pub mod types;

// Re-export commonly used types
pub use loader::PluginLoader;
pub use registry::PluginRegistry;
