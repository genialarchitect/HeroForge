//! Customer Portal API
//!
//! Provides read-only access for customers to view their engagements,
//! vulnerabilities, reports, and discovered assets. Uses separate authentication from the main app.

pub mod auth;
pub mod dashboard;
pub mod engagements;
pub mod vulnerabilities;
pub mod reports;
pub mod assets;
