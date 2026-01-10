//! Event Bus Module
//!
//! Provides a centralized event bus for cross-team communication and real-time updates.

pub mod types;
pub mod publisher;
pub mod subscriber;
pub mod handler;

pub use types::*;
pub use publisher::EventPublisher;
