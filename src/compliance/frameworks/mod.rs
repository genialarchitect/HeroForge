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
pub mod nist_800_61;
pub mod nist_800_82;
pub mod nist_800_171;
pub mod nist_csf;
pub mod nist_privacy;
pub mod pci_dss;
pub mod hipaa;
pub mod ferpa;
pub mod soc2;
pub mod owasp;
pub mod hitrust;
pub mod iso27001;
pub mod gdpr;
pub mod dod_stig;
pub mod dod_zero_trust;
pub mod disa_srg;
pub mod fisma;
pub mod rmf;
pub mod cisa_cpgs;
pub mod dfars;
pub mod ear;
pub mod icd_503;
pub mod cyber_essentials;
pub mod cmmc;
pub mod cnssi_1253;
pub mod csa_ccm;
pub mod itar;
pub mod ism_australia;
pub mod glba;
pub mod iec_62443;
pub mod bsi_grundschutz;
pub mod sox;
pub mod nis2;
pub mod stateramp;
pub mod nerc_cip;
pub mod fedramp;
pub mod tsa_pipeline;
pub mod eo_14028;
pub mod ens_spain;
pub mod c5;
pub mod secnumcloud;
pub mod nato_cyber;
pub mod irap;

use super::types::{ComplianceControl, ComplianceFramework};

/// Get all controls for a framework
pub fn get_controls(framework: ComplianceFramework) -> Vec<ComplianceControl> {
    match framework {
        ComplianceFramework::CisBenchmarks => cis::get_controls(),
        ComplianceFramework::Nist80053 => nist_800_53::get_controls(),
        ComplianceFramework::Nist80061 => nist_800_61::get_controls(),
        ComplianceFramework::Nist80082 => nist_800_82::get_controls(),
        ComplianceFramework::Nist800171 => nist_800_171::get_controls(),
        ComplianceFramework::NistCsf => nist_csf::get_controls(),
        ComplianceFramework::NistPrivacy => nist_privacy::get_controls(),
        ComplianceFramework::PciDss4 => pci_dss::get_controls(),
        ComplianceFramework::Hipaa => hipaa::get_controls(),
        ComplianceFramework::Ferpa => ferpa::get_controls(),
        ComplianceFramework::Soc2 => soc2::get_controls(),
        ComplianceFramework::OwaspTop10 => owasp::get_controls(),
        ComplianceFramework::HitrustCsf => hitrust::get_controls(),
        ComplianceFramework::Iso27001 => iso27001::get_controls(),
        ComplianceFramework::Gdpr => gdpr::get_controls(),
        ComplianceFramework::DodStig => dod_stig::get_controls(),
        ComplianceFramework::DodZeroTrust => dod_zero_trust::get_controls(),
        ComplianceFramework::DisaCloudSrg => disa_srg::get_controls(),
        ComplianceFramework::Fisma => fisma::get_controls(),
        ComplianceFramework::Rmf => rmf::get_controls(),
        ComplianceFramework::CisaCpgs => cisa_cpgs::get_controls(),
        ComplianceFramework::Dfars => dfars::get_controls(),
        ComplianceFramework::Icd503 => icd_503::get_controls(),
        ComplianceFramework::CyberEssentials => cyber_essentials::get_controls(),
        ComplianceFramework::Cmmc => cmmc::get_controls(),
        ComplianceFramework::IsmAustralia => ism_australia::get_controls(),
        ComplianceFramework::Cnssi1253 => cnssi_1253::get_controls(),
        ComplianceFramework::Glba => glba::get_controls(),
        ComplianceFramework::CsaCcm => csa_ccm::get_controls(),
        ComplianceFramework::Itar => itar::get_controls(),
        ComplianceFramework::Nis2 => nis2::get_controls(),
        ComplianceFramework::StateRamp => stateramp::get_controls(),
        ComplianceFramework::NercCip => nerc_cip::get_controls(),
        ComplianceFramework::Sox => sox::get_controls(),
        ComplianceFramework::Iec62443 => iec_62443::get_controls(),
        ComplianceFramework::FedRamp => fedramp::get_controls(),
        ComplianceFramework::TsaPipeline => tsa_pipeline::get_controls(),
        ComplianceFramework::Eo14028 => eo_14028::get_controls(),
        ComplianceFramework::EnsSpain => ens_spain::get_controls(),
        ComplianceFramework::C5 => c5::get_controls(),
        ComplianceFramework::SecNumCloud => secnumcloud::get_controls(),
        ComplianceFramework::NatoCyber => nato_cyber::get_controls(),
        ComplianceFramework::Irap => irap::get_controls(),
        ComplianceFramework::BsiGrundschutz => bsi_grundschutz::get_controls(),
        ComplianceFramework::Ear => ear::get_controls(),
    }
}

/// Get the control count for a framework
pub fn get_control_count(framework: ComplianceFramework) -> usize {
    match framework {
        ComplianceFramework::CisBenchmarks => cis::CONTROL_COUNT,
        ComplianceFramework::Nist80053 => nist_800_53::CONTROL_COUNT,
        ComplianceFramework::Nist80061 => nist_800_61::CONTROL_COUNT,
        ComplianceFramework::Nist80082 => nist_800_82::CONTROL_COUNT,
        ComplianceFramework::Nist800171 => nist_800_171::CONTROL_COUNT,
        ComplianceFramework::NistCsf => nist_csf::CONTROL_COUNT,
        ComplianceFramework::NistPrivacy => nist_privacy::CONTROL_COUNT,
        ComplianceFramework::PciDss4 => pci_dss::CONTROL_COUNT,
        ComplianceFramework::Hipaa => hipaa::CONTROL_COUNT,
        ComplianceFramework::Ferpa => ferpa::CONTROL_COUNT,
        ComplianceFramework::Soc2 => soc2::CONTROL_COUNT,
        ComplianceFramework::OwaspTop10 => owasp::CONTROL_COUNT,
        ComplianceFramework::HitrustCsf => hitrust::CONTROL_COUNT,
        ComplianceFramework::Iso27001 => iso27001::CONTROL_COUNT,
        ComplianceFramework::Gdpr => gdpr::CONTROL_COUNT,
        ComplianceFramework::DodStig => dod_stig::CONTROL_COUNT,
        ComplianceFramework::DodZeroTrust => dod_zero_trust::CONTROL_COUNT,
        ComplianceFramework::DisaCloudSrg => disa_srg::CONTROL_COUNT,
        ComplianceFramework::Cmmc => cmmc::CONTROL_COUNT,
        ComplianceFramework::IsmAustralia => ism_australia::CONTROL_COUNT,
        ComplianceFramework::Cnssi1253 => cnssi_1253::CONTROL_COUNT,
        ComplianceFramework::Glba => glba::CONTROL_COUNT,
        ComplianceFramework::CsaCcm => csa_ccm::CONTROL_COUNT,
        ComplianceFramework::CyberEssentials => cyber_essentials::CONTROL_COUNT,
        ComplianceFramework::Itar => itar::CONTROL_COUNT,
        ComplianceFramework::Nis2 => nis2::CONTROL_COUNT,
        ComplianceFramework::Dfars => dfars::CONTROL_COUNT,
        ComplianceFramework::Fisma => fisma::CONTROL_COUNT,
        ComplianceFramework::Rmf => rmf::CONTROL_COUNT,
        ComplianceFramework::CisaCpgs => cisa_cpgs::CONTROL_COUNT,
        ComplianceFramework::Icd503 => icd_503::CONTROL_COUNT,
        ComplianceFramework::StateRamp => stateramp::CONTROL_COUNT,
        ComplianceFramework::NercCip => nerc_cip::CONTROL_COUNT,
        ComplianceFramework::Sox => sox::CONTROL_COUNT,
        ComplianceFramework::Iec62443 => iec_62443::CONTROL_COUNT,
        ComplianceFramework::FedRamp => fedramp::CONTROL_COUNT,
        ComplianceFramework::TsaPipeline => tsa_pipeline::CONTROL_COUNT,
        ComplianceFramework::Eo14028 => eo_14028::CONTROL_COUNT,
        ComplianceFramework::EnsSpain => ens_spain::CONTROL_COUNT,
        ComplianceFramework::C5 => c5::CONTROL_COUNT,
        ComplianceFramework::SecNumCloud => secnumcloud::CONTROL_COUNT,
        ComplianceFramework::NatoCyber => nato_cyber::CONTROL_COUNT,
        ComplianceFramework::Irap => irap::CONTROL_COUNT,
        ComplianceFramework::BsiGrundschutz => bsi_grundschutz::CONTROL_COUNT,
        ComplianceFramework::Ear => ear::CONTROL_COUNT,
    }
}

/// Get the percentage of controls that can be automatically assessed
pub fn get_automated_percentage(framework: ComplianceFramework) -> f32 {
    match framework {
        ComplianceFramework::CisBenchmarks => 60.0,
        ComplianceFramework::Nist80053 => 30.0,
        ComplianceFramework::Nist800171 => 55.0,  // ~60 of 110 controls automatable (CUI protection)
        ComplianceFramework::NistCsf => 40.0,
        ComplianceFramework::NistPrivacy => 55.0,  // ~25 of 45 controls automatable (privacy technical controls)
        ComplianceFramework::PciDss4 => 50.0,
        ComplianceFramework::Hipaa => 40.0,
        ComplianceFramework::Ferpa => 30.0,
        ComplianceFramework::Soc2 => 45.0,
        ComplianceFramework::OwaspTop10 => 70.0,
        ComplianceFramework::HitrustCsf => 55.0,  // ~85 of 156 controls automatable
        ComplianceFramework::Iso27001 => 45.0,   // ~42 of 93 controls automatable
        ComplianceFramework::Gdpr => 40.0,       // ~18 of 45 controls automatable
        ComplianceFramework::DodStig => 75.0,    // ~117 of 156 controls automatable (technical checks)
        ComplianceFramework::DodZeroTrust => 90.0, // ~45 of 50 controls automatable (zero trust technical checks)
        ComplianceFramework::DisaCloudSrg => 65.0, // ~39 of 60 controls automatable (IL4/IL5 technical)
        ComplianceFramework::IsmAustralia => 55.0, // ~44 of 80 controls automatable (technical checks)
        ComplianceFramework::Cnssi1253 => 55.0,   // ~33 of 60 controls automatable (NSS technical checks)
        ComplianceFramework::Glba => 45.0,       // ~20 of 45 controls automatable (technical safeguards)
        ComplianceFramework::CsaCcm => 55.0,      // ~44 of 80 controls automatable (cloud-focused technical checks)
        ComplianceFramework::CyberEssentials => 85.0, // ~36 of 42 controls automatable (UK cyber hygiene)
        ComplianceFramework::Nis2 => 50.0,           // ~30 of 60 controls automatable (EU critical infrastructure)
        ComplianceFramework::CisaCpgs => 71.0,        // ~30 of 42 controls automatable (critical infrastructure CPGs)
        ComplianceFramework::StateRamp => 50.0,           // ~25 of 50 controls automatable (FedRAMP-based state/local)
        ComplianceFramework::NercCip => 45.0,               // ~28 of 62 controls automatable (bulk electric system security)
        ComplianceFramework::Sox => 52.0,                    // ~26 of 50 controls automatable (ITGC technical checks)
        ComplianceFramework::Iec62443 => 65.0,               // ~44 of 67 controls automatable (OT/ICS technical checks)
        ComplianceFramework::FedRamp => 55.0,                // ~180 of 325 controls automatable (NIST-based cloud)
        ComplianceFramework::TsaPipeline => 60.0,            // ~30 of 50 controls automatable (pipeline security)
        ComplianceFramework::Eo14028 => 70.0,                // ~28 of 40 controls automatable (software supply chain)
        ComplianceFramework::EnsSpain => 50.0,               // ~42 of 85 controls automatable (Spanish government)
        ComplianceFramework::C5 => 55.0,                     // ~55 of 100 controls automatable (German cloud)
        ComplianceFramework::SecNumCloud => 55.0,            // ~44 of 80 controls automatable (French cloud)
        ComplianceFramework::NatoCyber => 60.0,              // ~42 of 70 controls automatable (NATO cyber defence)
        ComplianceFramework::Irap => 55.0,                   // ~44 of 80 controls automatable (Australian government)
        ComplianceFramework::BsiGrundschutz => 45.0,         // ~54 of 120 controls automatable (German IT baseline)
        ComplianceFramework::Ear => 35.0,                    // ~9 of 25 controls automatable (export admin)
        ComplianceFramework::Nist80061 => 40.0,              // ~20 of 50 controls automatable (incident response)
        ComplianceFramework::Nist80082 => 55.0,              // ~44 of 80 controls automatable (ICS security)
        _ => 40.0, // Default for other frameworks
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
