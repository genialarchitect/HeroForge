//! Compliance Framework Definitions
//!
//! This module contains the control definitions for each supported
//! compliance framework. Each framework module exports:
//!
//! - A list of controls (`CONTROLS`)
//! - Vulnerability-to-control mapping functions
//! - Framework-specific check implementations

// Allow dead code for framework helper functions - kept for future API expansion
#![allow(dead_code)]

pub mod cis;
pub mod nist_800_53;
pub mod nist_csf;
pub mod pci_dss;
pub mod hipaa;
pub mod ferpa;
pub mod soc2;
pub mod owasp;
pub mod hitrust;
pub mod iso27001;
pub mod gdpr;

use super::types::{ComplianceControl, ComplianceFramework};

/// Get all controls for a framework
pub fn get_controls(framework: ComplianceFramework) -> Vec<ComplianceControl> {
    match framework {
        ComplianceFramework::CisBenchmarks => cis::get_controls(),
        ComplianceFramework::Nist80053 => nist_800_53::get_controls(),
        ComplianceFramework::NistCsf => nist_csf::get_controls(),
        ComplianceFramework::PciDss4 => pci_dss::get_controls(),
        ComplianceFramework::Hipaa => hipaa::get_controls(),
        ComplianceFramework::Ferpa => ferpa::get_controls(),
        ComplianceFramework::Soc2 => soc2::get_controls(),
        ComplianceFramework::OwaspTop10 => owasp::get_controls(),
        ComplianceFramework::HitrustCsf => hitrust::get_controls(),
        ComplianceFramework::Iso27001 => iso27001::get_controls(),
        ComplianceFramework::Gdpr => gdpr::get_controls(),
    }
}

/// Get the control count for a framework
pub fn get_control_count(framework: ComplianceFramework) -> usize {
    match framework {
        ComplianceFramework::CisBenchmarks => cis::CONTROL_COUNT,
        ComplianceFramework::Nist80053 => nist_800_53::CONTROL_COUNT,
        ComplianceFramework::NistCsf => nist_csf::CONTROL_COUNT,
        ComplianceFramework::PciDss4 => pci_dss::CONTROL_COUNT,
        ComplianceFramework::Hipaa => hipaa::CONTROL_COUNT,
        ComplianceFramework::Ferpa => ferpa::CONTROL_COUNT,
        ComplianceFramework::Soc2 => soc2::CONTROL_COUNT,
        ComplianceFramework::OwaspTop10 => owasp::CONTROL_COUNT,
        ComplianceFramework::HitrustCsf => hitrust::CONTROL_COUNT,
        ComplianceFramework::Iso27001 => iso27001::CONTROL_COUNT,
        ComplianceFramework::Gdpr => gdpr::CONTROL_COUNT,
    }
}

/// Get the percentage of controls that can be automatically assessed
pub fn get_automated_percentage(framework: ComplianceFramework) -> f32 {
    match framework {
        ComplianceFramework::CisBenchmarks => 60.0,
        ComplianceFramework::Nist80053 => 30.0,
        ComplianceFramework::NistCsf => 40.0,
        ComplianceFramework::PciDss4 => 50.0,
        ComplianceFramework::Hipaa => 40.0,
        ComplianceFramework::Ferpa => 30.0,
        ComplianceFramework::Soc2 => 45.0,
        ComplianceFramework::OwaspTop10 => 70.0,
        ComplianceFramework::HitrustCsf => 55.0,  // ~85 of 156 controls automatable
        ComplianceFramework::Iso27001 => 45.0,   // ~42 of 93 controls automatable
        ComplianceFramework::Gdpr => 40.0,       // ~18 of 45 controls automatable
    }
}

/// Get controls by category for a framework
pub fn get_controls_by_category(
    framework: ComplianceFramework,
    category: &str,
) -> Vec<ComplianceControl> {
    get_controls(framework)
        .into_iter()
        .filter(|c| c.category.eq_ignore_ascii_case(category))
        .collect()
}

/// Get all categories for a framework
pub fn get_categories(framework: ComplianceFramework) -> Vec<String> {
    let controls = get_controls(framework);
    let mut categories: Vec<String> = controls.iter().map(|c| c.category.clone()).collect();
    categories.sort();
    categories.dedup();
    categories
}

/// Find a specific control by ID
pub fn find_control(framework: ComplianceFramework, control_id: &str) -> Option<ComplianceControl> {
    get_controls(framework)
        .into_iter()
        .find(|c| c.control_id == control_id || c.id == control_id)
}
