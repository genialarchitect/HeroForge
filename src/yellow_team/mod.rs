//! Yellow Team - Security Architecture & DevSecOps
//!
//! This module provides comprehensive DevSecOps capabilities including:
//! - Static Application Security Testing (SAST)
//! - Software Bill of Materials (SBOM) generation
//! - Software Composition Analysis (SCA) with vulnerability detection
//! - API Security scanning
//! - Architecture threat modeling (STRIDE)
//! - DevSecOps metrics dashboard

pub mod types;
pub mod sast;
pub mod sbom;
pub mod sca;
pub mod api_security;
pub mod architecture;
pub mod dashboard;
pub mod devsecops;

pub use types::*;
pub use devsecops::*;
pub use sca::{ScaAnalyzer, Ecosystem, ScaProject, ScaDependency, ScaVulnerability};
// Selectively re-export from architecture to avoid conflicts with types.rs
pub use architecture::{
    ArchitectureReviewEngine, StrideAnalysisResult, SecurityRecommendation,
    ArchitectureDiagram, ArchitectureComponent,
};
