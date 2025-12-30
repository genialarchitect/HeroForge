//! Dependency firewall - package allowlist/blocklist

use anyhow::Result;
use std::collections::HashSet;

pub struct DependencyFirewall {
    allowlist: HashSet<String>,
    blocklist: HashSet<String>,
}

impl DependencyFirewall {
    pub fn new() -> Self {
        Self {
            allowlist: HashSet::new(),
            blocklist: HashSet::new(),
        }
    }

    /// Check if package is allowed
    pub fn is_allowed(&self, package: &str) -> bool {
        !self.blocklist.contains(package) &&
        (self.allowlist.is_empty() || self.allowlist.contains(package))
    }

    /// Add package to allowlist
    pub fn allow(&mut self, package: String) {
        self.allowlist.insert(package);
    }

    /// Add package to blocklist
    pub fn block(&mut self, package: String) {
        self.blocklist.insert(package);
    }

    /// Detect typosquatting attempts
    pub fn detect_typosquatting(&self, package: &str) -> Result<Vec<String>> {
        // TODO: Check for common typosquatting patterns
        Ok(vec![])
    }

    /// Detect dependency confusion
    pub fn detect_dependency_confusion(&self, package: &str) -> Result<bool> {
        // TODO: Check for dependency confusion vulnerabilities
        Ok(false)
    }
}

impl Default for DependencyFirewall {
    fn default() -> Self {
        Self::new()
    }
}
