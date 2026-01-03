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
    ///
    /// This implements a license compatibility matrix based on common open source license
    /// compatibility rules. Returns true if license2 can be combined with license1 in a
    /// derivative work.
    pub fn check_compatibility(&self, license1: &str, license2: &str) -> Result<bool> {
        // Normalize license identifiers
        let l1 = self.normalize_license(license1);
        let l2 = self.normalize_license(license2);

        // Same license is always compatible
        if l1 == l2 {
            return Ok(true);
        }

        // Define license categories for compatibility checking
        let permissive = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense", "CC0-1.0", "0BSD"];
        let weak_copyleft = ["LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-2.0"];
        let strong_copyleft = ["GPL-2.0", "GPL-3.0", "AGPL-3.0"];

        let l1_is_permissive = permissive.contains(&l1.as_str());
        let l2_is_permissive = permissive.contains(&l2.as_str());
        let l1_is_weak_copyleft = weak_copyleft.contains(&l1.as_str());
        let l2_is_weak_copyleft = weak_copyleft.contains(&l2.as_str());
        let l1_is_strong_copyleft = strong_copyleft.contains(&l1.as_str());
        let l2_is_strong_copyleft = strong_copyleft.contains(&l2.as_str());

        // Compatibility rules:

        // 1. Permissive licenses are compatible with everything
        if l2_is_permissive {
            return Ok(true);
        }

        // 2. If the project is permissive, it can only incorporate permissive code
        if l1_is_permissive && !l2_is_permissive {
            return Ok(false);
        }

        // 3. Weak copyleft licenses can incorporate permissive code
        if l1_is_weak_copyleft && l2_is_permissive {
            return Ok(true);
        }

        // 4. GPL-3.0 is not compatible with GPL-2.0-only
        if (l1 == "GPL-3.0" && l2 == "GPL-2.0") || (l1 == "GPL-2.0" && l2 == "GPL-3.0") {
            // GPL-2.0-or-later would be compatible, but we assume GPL-2.0 means -only
            return Ok(false);
        }

        // 5. AGPL-3.0 is compatible with GPL-3.0 (AGPL can include GPL code)
        if l1 == "AGPL-3.0" && (l2 == "GPL-3.0" || l2_is_permissive || l2_is_weak_copyleft) {
            return Ok(true);
        }

        // 6. GPL can incorporate LGPL and permissive code
        if l1_is_strong_copyleft && (l2_is_permissive || l2_is_weak_copyleft) {
            return Ok(true);
        }

        // 7. Weak copyleft licenses - LGPL can incorporate LGPL
        if l1_is_weak_copyleft && l2_is_weak_copyleft {
            // Same family is compatible
            if (l1.starts_with("LGPL") && l2.starts_with("LGPL")) ||
               (l1.starts_with("MPL") && l2.starts_with("MPL")) ||
               (l1.starts_with("EPL") && l2.starts_with("EPL")) {
                return Ok(true);
            }
        }

        // 8. Strong copyleft cannot incorporate other strong copyleft (except same family)
        if l1_is_strong_copyleft && l2_is_strong_copyleft {
            // GPL family
            if l1.starts_with("GPL") && l2.starts_with("GPL") {
                // GPL-3.0 can incorporate GPL-2.0-or-later
                return Ok(l1 == l2);
            }
            // AGPL can incorporate GPL-3.0
            if l1 == "AGPL-3.0" && l2 == "GPL-3.0" {
                return Ok(true);
            }
            return Ok(false);
        }

        // 9. Apache-2.0 has a patent clause that makes it incompatible with GPL-2.0
        if l1 == "GPL-2.0" && l2 == "Apache-2.0" {
            return Ok(false);
        }

        // Default to false for unknown combinations
        Ok(false)
    }

    /// Normalize license identifier to canonical form
    fn normalize_license(&self, license: &str) -> String {
        let normalized = license.trim().to_uppercase();

        // Handle common variations
        match normalized.as_str() {
            "MIT LICENSE" | "MIT-LICENSE" => "MIT".to_string(),
            "APACHE 2.0" | "APACHE2" | "APACHE-2" => "Apache-2.0".to_string(),
            "GPL3" | "GPL-3" | "GPL V3" | "GPLV3" => "GPL-3.0".to_string(),
            "GPL2" | "GPL-2" | "GPL V2" | "GPLV2" => "GPL-2.0".to_string(),
            "LGPL3" | "LGPL-3" | "LGPL V3" | "LGPLV3" => "LGPL-3.0".to_string(),
            "LGPL2.1" | "LGPL-2.1" | "LGPL V2.1" | "LGPLV2.1" => "LGPL-2.1".to_string(),
            "BSD" | "BSD-NEW" | "BSD-SIMPLIFIED" => "BSD-3-Clause".to_string(),
            "BSD2" | "BSD-2" | "BSD 2-CLAUSE" => "BSD-2-Clause".to_string(),
            "MPL" | "MPL2" | "MPL-2" | "MOZILLA" => "MPL-2.0".to_string(),
            "AGPL" | "AGPL3" | "AGPL-3" => "AGPL-3.0".to_string(),
            "UNLICENSED" | "PUBLIC DOMAIN" => "Unlicense".to_string(),
            _ => license.to_string(),
        }
    }

    /// Get detailed compatibility information between two licenses
    pub fn get_compatibility_details(&self, license1: &str, license2: &str) -> LicenseCompatibility {
        let compatible = self.check_compatibility(license1, license2).unwrap_or(false);
        let risk1 = self.analyze_risk(license1);
        let risk2 = self.analyze_risk(license2);

        let (issues, recommendations) = if !compatible {
            let issues = vec![
                format!("License '{}' is not compatible with '{}'", license2, license1),
                if self.is_copyleft(license2) {
                    format!("'{}' is a copyleft license with strong obligations", license2)
                } else {
                    String::new()
                },
            ].into_iter().filter(|s| !s.is_empty()).collect();

            let recommendations = vec![
                "Consider finding an alternative dependency with a compatible license".to_string(),
                "Consult with legal counsel before proceeding".to_string(),
                if self.is_copyleft(license1) {
                    "Your project uses a copyleft license; ensure compliance with its terms".to_string()
                } else {
                    "Consider whether you can isolate the incompatible dependency".to_string()
                },
            ];

            (issues, recommendations)
        } else {
            (vec![], vec![])
        };

        LicenseCompatibility {
            license1: license1.to_string(),
            license2: license2.to_string(),
            compatible,
            risk_level: if risk1 > risk2 { risk1 } else { risk2 },
            issues,
            recommendations,
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LicenseRisk {
    High,
    Medium,
    Low,
    Unknown,
}

/// Detailed license compatibility information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseCompatibility {
    pub license1: String,
    pub license2: String,
    pub compatible: bool,
    pub risk_level: LicenseRisk,
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
}
