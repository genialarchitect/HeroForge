//! Emerging Technology Security Module (Phase 4 Sprint 12)
//!
//! Security for emerging technologies: 5G, AI/ML adversarial, quantum readiness, XR

pub mod fiveg;
pub mod adversarial_ml;
pub mod quantum;
pub mod xr;
pub mod types;

pub use types::*;
use anyhow::Result;

/// Run comprehensive emerging technology security assessment
pub async fn run_emerging_tech_assessment(config: &EmergingTechConfig) -> Result<EmergingTechAssessment> {
    let mut assessment = EmergingTechAssessment::default();

    // 5G security
    if config.assess_5g {
        assessment.fiveg_findings = fiveg::assess_5g_security(&config.fiveg_config).await?;
    }

    // AI/ML adversarial security
    if config.assess_adversarial_ml {
        assessment.adversarial_ml_findings = adversarial_ml::assess_ml_security(&config.ml_models).await?;
    }

    // Quantum readiness
    if config.assess_quantum {
        assessment.quantum_readiness = quantum::assess_quantum_readiness(&config.crypto_inventory).await?;
    }

    // Extended Reality (XR) security
    if config.assess_xr {
        assessment.xr_findings = xr::assess_xr_security(&config.xr_devices).await?;
    }

    Ok(assessment)
}
