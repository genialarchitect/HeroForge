//! Enhanced Terraform Security Rules
//!
//! Comprehensive security rules for Terraform configurations organized by cloud provider.
//! Based on CIS Benchmarks, AWS/Azure/GCP best practices, and common misconfiguration patterns.

pub mod aws;
pub mod azure;
pub mod gcp;

use super::rules::{RuleMatcher, RuleMatch};
use super::types::*;
use std::collections::HashMap;

/// Get all enhanced Terraform rules
pub fn get_enhanced_rules() -> Vec<Box<dyn RuleMatcher>> {
    let mut rules: Vec<Box<dyn RuleMatcher>> = Vec::new();

    // AWS rules
    rules.extend(aws::get_aws_rules());

    // Azure rules
    rules.extend(azure::get_azure_rules());

    // GCP rules
    rules.extend(gcp::get_gcp_rules());

    rules
}

/// Get rules filtered by provider
pub fn get_rules_by_provider(provider: IacCloudProvider) -> Vec<Box<dyn RuleMatcher>> {
    match provider {
        IacCloudProvider::Aws => aws::get_aws_rules(),
        IacCloudProvider::Azure => azure::get_azure_rules(),
        IacCloudProvider::Gcp => gcp::get_gcp_rules(),
        IacCloudProvider::Multi | IacCloudProvider::None => get_enhanced_rules(),
    }
}

/// Get rules filtered by category
pub fn get_rules_by_category(category: &str) -> Vec<Box<dyn RuleMatcher>> {
    get_enhanced_rules()
        .into_iter()
        .filter(|r| r.category().to_string().to_lowercase() == category.to_lowercase())
        .collect()
}

/// Enhanced rule statistics
#[derive(Debug, Clone, Default)]
pub struct RuleStatistics {
    pub total_rules: usize,
    pub by_provider: HashMap<String, usize>,
    pub by_severity: HashMap<String, usize>,
    pub by_category: HashMap<String, usize>,
}

/// Get statistics about available rules
pub fn get_rule_statistics() -> RuleStatistics {
    let rules = get_enhanced_rules();
    let mut stats = RuleStatistics {
        total_rules: rules.len(),
        ..Default::default()
    };

    for rule in &rules {
        for provider in rule.providers() {
            *stats.by_provider.entry(provider.to_string()).or_insert(0) += 1;
        }
        *stats.by_severity.entry(rule.severity().to_string()).or_insert(0) += 1;
        *stats.by_category.entry(rule.category().to_string()).or_insert(0) += 1;
    }

    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_enhanced_rules() {
        let rules = get_enhanced_rules();
        // Should have at least 100 rules
        assert!(rules.len() >= 100, "Expected at least 100 rules, got {}", rules.len());
    }

    #[test]
    fn test_rules_have_ids() {
        let rules = get_enhanced_rules();
        for rule in &rules {
            assert!(!rule.id().is_empty(), "Rule must have an ID");
            assert!(!rule.name().is_empty(), "Rule must have a name");
            assert!(!rule.description().is_empty(), "Rule must have a description");
            assert!(!rule.remediation().is_empty(), "Rule must have remediation");
        }
    }

    #[test]
    fn test_get_rules_by_provider() {
        let aws_rules = get_rules_by_provider(IacCloudProvider::Aws);
        let azure_rules = get_rules_by_provider(IacCloudProvider::Azure);
        let gcp_rules = get_rules_by_provider(IacCloudProvider::Gcp);

        assert!(!aws_rules.is_empty());
        assert!(!azure_rules.is_empty());
        assert!(!gcp_rules.is_empty());
    }
}
