//! White Team - Governance, Risk & Compliance (GRC)
//!
//! This module provides a unified facade for all GRC capabilities.
//! White Team focuses on governance, risk management, compliance,
//! and audit functions.
//!
//! ## Core Capabilities
//!
//! ### Policy Management
//! - Document lifecycle management
//! - Version control and history
//! - Approval workflows
//! - Employee acknowledgment tracking
//! - Policy templates
//!
//! ### Risk Management
//! - Risk register maintenance
//! - Risk assessments (qualitative/quantitative)
//! - FAIR analysis support
//! - Risk treatment plans
//! - Risk appetite and tolerance
//!
//! ### Control Framework
//! - Control library management
//! - Framework mapping (NIST, ISO, SOC2, etc.)
//! - Control testing and validation
//! - Framework crosswalk
//! - Control effectiveness tracking
//!
//! ### Audit Management
//! - Audit planning and scheduling
//! - Audit execution tracking
//! - Finding management
//! - Evidence collection
//! - Remediation tracking
//!
//! ### Vendor Risk Management
//! - Third-party risk assessments
//! - Security questionnaires
//! - Continuous monitoring
//! - Contract security requirements
//! - SLA compliance
//!
//! ## Usage
//!
//! ```rust,ignore
//! use heroforge::white_team;
//!
//! // Manage policies
//! let policy = white_team::policy::Policy::create(&pool, new_policy).await?;
//!
//! // Assess risks
//! let risk = white_team::risk::RiskAssessment::perform(&pool, asset_id).await?;
//!
//! // Track audits
//! let audit = white_team::audit::Audit::create(&pool, audit_plan).await?;
//! ```

#![allow(unused_imports)]

// =============================================================================
// CORE WHITE TEAM MODULES
// =============================================================================

pub mod types;
pub mod policy;
pub mod risk;
pub mod controls;
pub mod audit;
pub mod vendor;

pub use types::*;
pub use policy::*;
pub use risk::*;
pub use controls::*;
pub use audit::*;
pub use vendor::*;

// =============================================================================
// INTEGRATION RE-EXPORTS
// =============================================================================

/// Compliance frameworks integration
pub mod compliance {
    //! Compliance framework support (PCI-DSS, NIST, HIPAA, SOC2, etc.)

    pub use crate::compliance::{
        analyzer::*, scanner::*, scoring::*,
        frameworks::*, controls::*, evidence::*,
        manual_assessment::*,
    };
}

/// Reporting capabilities
pub mod reports {
    //! GRC reporting and documentation

    pub use crate::reports::*;
}

/// Evidence management
pub mod evidence {
    //! Evidence collection and management

    pub use crate::compliance::evidence::*;
}
