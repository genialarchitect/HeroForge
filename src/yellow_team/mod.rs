//! Yellow Team - Secure Development & DevSecOps
//!
//! This module provides a unified facade for all secure development capabilities.
//! Yellow Team focuses on building security into the development lifecycle,
//! from code to deployment.
//!
//! ## Core Capabilities
//!
//! ### Static Application Security Testing (SAST)
//! - Multi-language support (Rust, JavaScript, Python, Go, Java, etc.)
//! - CWE classification of findings
//! - Custom rule support
//! - IDE integration recommendations
//!
//! ### Software Composition Analysis (SCA)
//! - Dependency vulnerability scanning
//! - License compliance checking
//! - Ecosystem support (npm, PyPI, crates.io, Maven, etc.)
//! - Transitive dependency analysis
//!
//! ### Software Bill of Materials (SBOM)
//! - CycloneDX and SPDX format generation
//! - Component inventory
//! - Vulnerability correlation
//! - Export capabilities
//!
//! ### API Security
//! - OpenAPI/Swagger analysis
//! - Authentication testing
//! - Rate limiting verification
//! - Security header checks
//!
//! ### Architecture Review
//! - STRIDE threat modeling
//! - Security design review
//! - Component security analysis
//! - Attack surface assessment
//!
//! ### DevSecOps Metrics
//! - Security debt tracking
//! - Mean time to remediate
//! - Vulnerability trends
//! - Developer security engagement
//!
//! ## Usage
//!
//! ```rust,ignore
//! use heroforge::yellow_team;
//!
//! // Run SAST analysis
//! let findings = yellow_team::sast::SastAnalyzer::analyze(&project_path)?;
//!
//! // Generate SBOM
//! let sbom = yellow_team::sbom::generate_sbom(&project_path, Format::CycloneDx)?;
//!
//! // Run SCA
//! let vulnerabilities = yellow_team::ScaAnalyzer::new(pool).scan(&deps).await?;
//! ```

#![allow(unused_imports)]

// =============================================================================
// CORE YELLOW TEAM MODULES
// =============================================================================

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

// =============================================================================
// INTEGRATION RE-EXPORTS
// =============================================================================

/// CI/CD pipeline security scanning
pub mod cicd {
    //! CI/CD security integration

    pub use crate::scanner::cicd::*;
}

/// Infrastructure as Code security
pub mod iac {
    //! Terraform, CloudFormation, ARM template scanning

    pub use crate::scanner::iac::*;
}

/// Git repository security
pub mod git_security {
    //! Git repository reconnaissance and secret detection

    pub use crate::scanner::git_recon::*;
    pub use crate::scanner::secret_detection::*;
}

/// Container security for development
pub mod container_dev {
    //! Container security for the development pipeline

    pub use crate::scanner::container::{
        ContainerScan, ContainerScanConfig, ContainerScanType, ContainerScanner,
        ContainerImage, ContainerFinding, ContainerFindingSeverity, ContainerFindingType,
        DockerfileAnalysis, K8sManifestAnalysis, K8sResource, K8sResourceType,
        ImageVulnSummary, FindingStatus,
    };
}

/// Supply chain security
pub mod supply_chain {
    //! Software supply chain security

    pub use crate::supply_chain::*;
}
