//! Dependency firewall - package allowlist/blocklist
//!
//! This module provides:
//! - Package allowlist/blocklist management
//! - Typosquatting detection
//! - Dependency confusion detection
//! - Malicious package identification

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Dependency firewall for supply chain security
pub struct DependencyFirewall {
    /// Allowed packages (if non-empty, only these are allowed)
    allowlist: HashSet<String>,
    /// Blocked packages (always blocked)
    blocklist: HashSet<String>,
    /// Known typosquatting patterns
    typosquat_patterns: Vec<TyposquatPattern>,
    /// Private registry configurations
    private_registries: Vec<PrivateRegistry>,
    /// Enable dependency confusion detection
    detect_confusion: bool,
}

/// Typosquatting pattern
#[derive(Debug, Clone)]
struct TyposquatPattern {
    /// Original legitimate package
    legitimate: String,
    /// Known typosquat variants
    variants: Vec<String>,
}

/// Private registry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateRegistry {
    /// Registry URL
    pub url: String,
    /// Package scope/namespace prefix
    pub scope: Option<String>,
    /// Priority (higher = checked first)
    pub priority: i32,
}

/// Dependency analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyAnalysis {
    /// Package name
    pub package: String,
    /// Is the package allowed
    pub allowed: bool,
    /// Is the package blocked
    pub blocked: bool,
    /// Typosquatting warnings
    pub typosquat_warnings: Vec<String>,
    /// Dependency confusion risk
    pub confusion_risk: Option<ConfusionRisk>,
    /// Recommended action
    pub action: RecommendedAction,
}

/// Dependency confusion risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfusionRisk {
    /// Risk level
    pub level: RiskLevel,
    /// Reason for the risk assessment
    pub reason: String,
    /// Public package that may conflict
    pub public_conflict: Option<String>,
}

/// Risk level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Recommended action for a dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendedAction {
    Allow,
    Block,
    Review,
    Pin,
}

impl DependencyFirewall {
    pub fn new() -> Self {
        Self {
            allowlist: HashSet::new(),
            blocklist: HashSet::new(),
            typosquat_patterns: Self::default_typosquat_patterns(),
            private_registries: Vec::new(),
            detect_confusion: true,
        }
    }

    /// Load configuration from struct
    pub fn with_config(config: FirewallConfig) -> Self {
        let mut firewall = Self::new();
        firewall.allowlist = config.allowlist.into_iter().collect();
        firewall.blocklist = config.blocklist.into_iter().collect();
        firewall.private_registries = config.private_registries;
        firewall.detect_confusion = config.detect_confusion;
        firewall
    }

    /// Check if package is allowed
    pub fn is_allowed(&self, package: &str) -> bool {
        // First check blocklist
        if self.blocklist.contains(package) {
            return false;
        }

        // If allowlist is empty, allow all (except blocklisted)
        // If allowlist is not empty, only allow listed packages
        self.allowlist.is_empty() || self.allowlist.contains(package)
    }

    /// Add package to allowlist
    pub fn allow(&mut self, package: String) {
        self.blocklist.remove(&package);
        self.allowlist.insert(package);
    }

    /// Add package to blocklist
    pub fn block(&mut self, package: String) {
        self.allowlist.remove(&package);
        self.blocklist.insert(package);
    }

    /// Add multiple packages to allowlist
    pub fn allow_all(&mut self, packages: impl IntoIterator<Item = String>) {
        for package in packages {
            self.allow(package);
        }
    }

    /// Add multiple packages to blocklist
    pub fn block_all(&mut self, packages: impl IntoIterator<Item = String>) {
        for package in packages {
            self.block(package);
        }
    }

    /// Configure private registry
    pub fn add_private_registry(&mut self, registry: PrivateRegistry) {
        self.private_registries.push(registry);
        self.private_registries.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Detect typosquatting attempts
    ///
    /// Returns list of legitimate packages that the given package may be impersonating
    pub fn detect_typosquatting(&self, package: &str) -> Result<Vec<String>> {
        let mut warnings = Vec::new();
        let normalized = package.to_lowercase();

        // Check against known patterns
        for pattern in &self.typosquat_patterns {
            if pattern.variants.iter().any(|v| v == &normalized) {
                warnings.push(format!(
                    "Package '{}' may be a typosquat of '{}'",
                    package, pattern.legitimate
                ));
            }
        }

        // Apply general typosquatting detection heuristics
        warnings.extend(self.detect_typosquat_heuristics(package));

        Ok(warnings)
    }

    /// Apply heuristic typosquatting detection
    fn detect_typosquat_heuristics(&self, package: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        let normalized = package.to_lowercase();

        // Common typosquatting techniques:

        // 1. Character substitution (0 for o, 1 for l, etc.)
        let substitutions = [
            ('0', 'o'), ('o', '0'),
            ('1', 'l'), ('l', '1'),
            ('1', 'i'), ('i', '1'),
            ('5', 's'), ('s', '5'),
            ('3', 'e'), ('e', '3'),
        ];

        // 2. Character omission/addition
        // 3. Character transposition
        // 4. Hyphen/underscore confusion

        // Check against popular packages
        let popular_packages = [
            "lodash", "express", "react", "axios", "moment",
            "requests", "numpy", "pandas", "django", "flask",
            "serde", "tokio", "actix", "reqwest", "anyhow",
            "left-pad", "colors", "is-odd", "is-even",
        ];

        for popular in &popular_packages {
            let distance = levenshtein_distance(&normalized, popular);

            // If edit distance is 1-2 and not an exact match, it's suspicious
            if distance > 0 && distance <= 2 {
                warnings.push(format!(
                    "Package '{}' is similar to popular package '{}' (edit distance: {})",
                    package, popular, distance
                ));
            }

            // Check for separator confusion
            let hyphen_version = popular.replace('_', "-");
            let underscore_version = popular.replace('-', "_");

            if normalized == hyphen_version || normalized == underscore_version {
                if &normalized != *popular {
                    warnings.push(format!(
                        "Package '{}' uses different separators than '{}' - potential typosquat",
                        package, popular
                    ));
                }
            }
        }

        // Check for suspicious prefixes/suffixes
        let suspicious_affixes = [
            "-dev", "-test", "-fixed", "-secure", "-patched",
            "python-", "py-", "node-", "js-",
            "-js", "-py", "-rs",
        ];

        for popular in &popular_packages {
            for affix in &suspicious_affixes {
                let with_prefix = format!("{}{}", affix.trim_end_matches('-'), popular);
                let with_suffix = format!("{}{}", popular, affix.trim_start_matches('-'));

                if normalized == with_prefix || normalized == with_suffix {
                    warnings.push(format!(
                        "Package '{}' adds affix to popular package '{}' - verify authenticity",
                        package, popular
                    ));
                }
            }
        }

        warnings
    }

    /// Detect dependency confusion vulnerability
    ///
    /// Checks if a private package name exists in public registries,
    /// which could lead to dependency confusion attacks
    pub fn detect_dependency_confusion(&self, package: &str) -> Result<bool> {
        if !self.detect_confusion {
            return Ok(false);
        }

        // Check if package appears to be internal/private
        let appears_private = self.appears_private(package);

        if !appears_private {
            return Ok(false);
        }

        // Check if package exists in private registries
        let in_private = self.private_registries.iter()
            .any(|r| r.scope.as_ref().map(|s| package.starts_with(s)).unwrap_or(false));

        if !in_private {
            // Package appears private but isn't registered - high risk
            return Ok(true);
        }

        Ok(false)
    }

    /// Check if package name appears to be private/internal
    fn appears_private(&self, package: &str) -> bool {
        // Common patterns for internal packages
        let internal_patterns = [
            "@internal/", "@private/", "@corp/", "@company/",
            "internal-", "private-", "corp-", "company-",
            "-internal", "-private",
        ];

        let lower = package.to_lowercase();

        internal_patterns.iter().any(|p| lower.contains(p))
    }

    /// Analyze a dependency comprehensively
    pub fn analyze(&self, package: &str) -> Result<DependencyAnalysis> {
        let allowed = self.is_allowed(package);
        let blocked = self.blocklist.contains(package);
        let typosquat_warnings = self.detect_typosquatting(package)?;
        let has_confusion_risk = self.detect_dependency_confusion(package)?;

        let confusion_risk = if has_confusion_risk {
            Some(ConfusionRisk {
                level: RiskLevel::High,
                reason: "Package name appears internal but may exist in public registry".to_string(),
                public_conflict: None,
            })
        } else {
            None
        };

        let action = if blocked {
            RecommendedAction::Block
        } else if !typosquat_warnings.is_empty() {
            RecommendedAction::Review
        } else if has_confusion_risk {
            RecommendedAction::Pin
        } else if allowed {
            RecommendedAction::Allow
        } else {
            RecommendedAction::Review
        };

        Ok(DependencyAnalysis {
            package: package.to_string(),
            allowed,
            blocked,
            typosquat_warnings,
            confusion_risk,
            action,
        })
    }

    /// Analyze multiple dependencies
    pub fn analyze_all(&self, packages: &[&str]) -> Result<Vec<DependencyAnalysis>> {
        packages.iter().map(|p| self.analyze(p)).collect()
    }

    /// Get known malicious packages
    pub fn known_malicious() -> HashSet<String> {
        // Well-known malicious packages (examples)
        let packages = [
            // npm
            "event-stream",  // Compromised
            "ua-parser-js",  // Compromised version
            "coa",           // Compromised version
            "rc",            // Compromised version
            "colors",        // Sabotaged

            // PyPI
            "python3-dateutil",    // Typosquat
            "jeIlyfish",           // Typosquat (capital I)
            "python-sqlite",       // Typosquat

            // RubyGems
            "atlas-client",   // Malicious

            // Cargo (hypothetical examples for testing)
            "crates-typosquat-test",
        ];

        packages.iter().map(|s| s.to_string()).collect()
    }

    /// Default typosquatting patterns for popular packages
    fn default_typosquat_patterns() -> Vec<TyposquatPattern> {
        vec![
            TyposquatPattern {
                legitimate: "lodash".to_string(),
                variants: vec!["l0dash".to_string(), "1odash".to_string(), "lodahs".to_string()],
            },
            TyposquatPattern {
                legitimate: "express".to_string(),
                variants: vec!["expres".to_string(), "expresss".to_string(), "3xpress".to_string()],
            },
            TyposquatPattern {
                legitimate: "requests".to_string(),
                variants: vec!["request".to_string(), "reqeusts".to_string(), "requets".to_string()],
            },
            TyposquatPattern {
                legitimate: "numpy".to_string(),
                variants: vec!["numpi".to_string(), "numppy".to_string(), "nunpy".to_string()],
            },
            TyposquatPattern {
                legitimate: "pandas".to_string(),
                variants: vec!["panda".to_string(), "pandass".to_string(), "panadas".to_string()],
            },
            TyposquatPattern {
                legitimate: "serde".to_string(),
                variants: vec!["sered".to_string(), "serdes".to_string()],
            },
            TyposquatPattern {
                legitimate: "tokio".to_string(),
                variants: vec!["toki0".to_string(), "tokiio".to_string()],
            },
            TyposquatPattern {
                legitimate: "axios".to_string(),
                variants: vec!["axois".to_string(), "axi0s".to_string(), "axioss".to_string()],
            },
        ]
    }
}

impl Default for DependencyFirewall {
    fn default() -> Self {
        Self::new()
    }
}

/// Firewall configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FirewallConfig {
    pub allowlist: Vec<String>,
    pub blocklist: Vec<String>,
    pub private_registries: Vec<PrivateRegistry>,
    pub detect_confusion: bool,
}

/// Calculate Levenshtein edit distance between two strings
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();

    let len1 = s1_chars.len();
    let len2 = s2_chars.len();

    if len1 == 0 {
        return len2;
    }
    if len2 == 0 {
        return len1;
    }

    let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];

    for i in 0..=len1 {
        matrix[i][0] = i;
    }
    for j in 0..=len2 {
        matrix[0][j] = j;
    }

    for i in 1..=len1 {
        for j in 1..=len2 {
            let cost = if s1_chars[i - 1] == s2_chars[j - 1] { 0 } else { 1 };

            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    matrix[len1][len2]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowlist_blocklist() {
        let mut firewall = DependencyFirewall::new();

        // Empty lists - allow all
        assert!(firewall.is_allowed("any-package"));

        // Add to blocklist
        firewall.block("malicious-pkg".to_string());
        assert!(!firewall.is_allowed("malicious-pkg"));
        assert!(firewall.is_allowed("other-pkg"));

        // Add to allowlist
        firewall.allow("approved-pkg".to_string());
        assert!(firewall.is_allowed("approved-pkg"));
        assert!(!firewall.is_allowed("other-pkg")); // Now restricted
    }

    #[test]
    fn test_typosquatting_detection() {
        let firewall = DependencyFirewall::new();

        // Known typosquat
        let warnings = firewall.detect_typosquatting("l0dash").unwrap();
        assert!(!warnings.is_empty());

        // Similar to popular package
        let warnings = firewall.detect_typosquatting("lodas").unwrap();
        assert!(!warnings.is_empty());

        // Legitimate package
        let warnings = firewall.detect_typosquatting("completely-unique-name").unwrap();
        // May have some heuristic warnings but shouldn't match known patterns
    }

    #[test]
    fn test_dependency_confusion() {
        let mut firewall = DependencyFirewall::new();

        // Package that appears internal
        assert!(firewall.detect_dependency_confusion("@internal/my-package").unwrap());
        assert!(firewall.detect_dependency_confusion("private-company-utils").unwrap());

        // Regular public package
        assert!(!firewall.detect_dependency_confusion("lodash").unwrap());

        // Add private registry
        firewall.add_private_registry(PrivateRegistry {
            url: "https://npm.mycompany.com".to_string(),
            scope: Some("@company/".to_string()),
            priority: 100,
        });

        // Now @company/ packages are known to be private
        // (still may flag if not properly configured in real scenario)
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("", ""), 0);
        assert_eq!(levenshtein_distance("abc", "abc"), 0);
        assert_eq!(levenshtein_distance("abc", "ab"), 1);
        assert_eq!(levenshtein_distance("abc", "abd"), 1);
        assert_eq!(levenshtein_distance("abc", "def"), 3);
        assert_eq!(levenshtein_distance("lodash", "l0dash"), 1);
    }

    #[test]
    fn test_comprehensive_analysis() {
        let mut firewall = DependencyFirewall::new();
        firewall.block("blocked-pkg".to_string());

        // Blocked package
        let analysis = firewall.analyze("blocked-pkg").unwrap();
        assert!(analysis.blocked);
        assert!(matches!(analysis.action, RecommendedAction::Block));

        // Potential typosquat
        let analysis = firewall.analyze("l0dash").unwrap();
        assert!(!analysis.typosquat_warnings.is_empty());
        assert!(matches!(analysis.action, RecommendedAction::Review));

        // Normal package
        let analysis = firewall.analyze("unique-package-name").unwrap();
        assert!(analysis.allowed);
    }

    #[test]
    fn test_known_malicious() {
        let malicious = DependencyFirewall::known_malicious();
        assert!(malicious.contains("event-stream"));
        assert!(malicious.contains("colors"));
    }
}
