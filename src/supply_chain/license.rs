//! License compliance and risk analysis

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub struct LicenseAnalyzer {}

impl LicenseAnalyzer {
    pub fn new() -> Self {
        Self {}
    }

    /// Analyze license risk
    pub fn analyze_risk(&self, license: &str) -> LicenseRisk {
        match license {
            "GPL-3.0" | "GPL-2.0" | "AGPL-3.0" => LicenseRisk::High,
            "LGPL-3.0" | "LGPL-2.1" | "MPL-2.0" => LicenseRisk::Medium,
            "MIT" | "Apache-2.0" | "BSD-3-Clause" => LicenseRisk::Low,
            _ => LicenseRisk::Unknown,
        }
    }

    /// Check license compatibility
    pub fn check_compatibility(&self, license1: &str, license2: &str) -> Result<bool> {
        // TODO: Implement license compatibility matrix
        Ok(true)
    }

    /// Detect copyleft licenses
    pub fn is_copyleft(&self, license: &str) -> bool {
        matches!(license, "GPL-3.0" | "GPL-2.0" | "AGPL-3.0" | "LGPL-3.0" | "LGPL-2.1")
    }
}

impl Default for LicenseAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseRisk {
    High,
    Medium,
    Low,
    Unknown,
}
