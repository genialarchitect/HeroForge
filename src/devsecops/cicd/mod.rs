//! CI/CD Pipeline Integration Module
//!
//! Provides functionality for integrating HeroForge with CI/CD systems:
//! - Pipeline configuration and management
//! - Security workflow templates (GitHub Actions, GitLab CI, Jenkins, Azure DevOps)
//! - Quality gate policies
//! - Pipeline run tracking

pub mod policies;
pub mod templates;
pub mod types;

pub use policies::*;
pub use templates::*;
pub use types::*;
