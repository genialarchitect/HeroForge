//! Customer Portal API
//!
//! Provides access for customers to view their engagements,
//! vulnerabilities, reports, and discovered assets. Includes collaboration
//! features like discussions, severity disputes, and acknowledgments.
//! Uses separate authentication from the main app.

pub mod auth;
pub mod dashboard;
pub mod engagements;
pub mod vulnerabilities;
pub mod reports;
pub mod assets;
pub mod collaboration;
