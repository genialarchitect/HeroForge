//! IDE Integration Module
//!
//! Provides functionality for integrating HeroForge with IDEs:
//! - Real-time file scanning
//! - Inline security hints
//! - Quick fixes and code actions
//! - Session management

pub mod scanner;
pub mod types;

pub use scanner::*;
pub use types::*;
