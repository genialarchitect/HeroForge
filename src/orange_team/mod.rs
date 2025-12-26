//! Orange Team - Security Awareness & Training
//!
//! Provides security awareness training, gamification, phishing campaign analytics,
//! and just-in-time training capabilities.

pub mod types;
pub mod training;
pub mod gamification;
pub mod phishing_analytics;
pub mod jit_training;
pub mod compliance_training;

pub use types::*;
pub use training::*;
pub use gamification::*;
pub use phishing_analytics::*;
pub use jit_training::*;
pub use compliance_training::*;
