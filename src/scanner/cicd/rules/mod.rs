//! CI/CD Security Rules
//!
//! This module provides a unified interface to access all CI/CD security rules
//! across different platforms (GitHub Actions, GitLab CI, Jenkins).

use super::types::*;
use super::github_actions::GitHubActionsScanner;
use super::gitlab_ci::GitLabCIScanner;
use super::jenkins::JenkinsScanner;

/// Get all security rules for a specific platform
pub fn get_rules_for_platform(platform: &CiCdPlatform) -> Vec<CiCdRule> {
    match platform {
        CiCdPlatform::GitHubActions => GitHubActionsScanner::new().get_rules(),
        CiCdPlatform::GitLabCI => GitLabCIScanner::new().get_rules(),
        CiCdPlatform::Jenkins => JenkinsScanner::new().get_rules(),
        _ => Vec::new(),
    }
}

/// Get all security rules across all platforms
pub fn get_all_rules() -> Vec<CiCdRule> {
    let mut rules = Vec::new();
    rules.extend(GitHubActionsScanner::new().get_rules());
    rules.extend(GitLabCIScanner::new().get_rules());
    rules.extend(JenkinsScanner::new().get_rules());
    rules
}

/// Get rules filtered by category
pub fn get_rules_by_category(category: &CiCdCategory) -> Vec<CiCdRule> {
    get_all_rules()
        .into_iter()
        .filter(|r| &r.category == category)
        .collect()
}

/// Get rules filtered by severity
pub fn get_rules_by_severity(min_severity: &CiCdSeverity) -> Vec<CiCdRule> {
    get_all_rules()
        .into_iter()
        .filter(|r| &r.severity >= min_severity)
        .collect()
}

/// Get a specific rule by ID
pub fn get_rule_by_id(rule_id: &str) -> Option<CiCdRule> {
    get_all_rules().into_iter().find(|r| r.id == rule_id)
}

/// Summary of available rules
#[derive(Debug, Clone, Default)]
pub struct RuleSummary {
    pub total: usize,
    pub by_platform: std::collections::HashMap<String, usize>,
    pub by_category: std::collections::HashMap<String, usize>,
    pub by_severity: std::collections::HashMap<String, usize>,
}

/// Get a summary of all available rules
pub fn get_rules_summary() -> RuleSummary {
    let rules = get_all_rules();
    let mut summary = RuleSummary {
        total: rules.len(),
        ..Default::default()
    };

    for rule in &rules {
        *summary.by_platform
            .entry(rule.platform.to_string())
            .or_insert(0) += 1;
        *summary.by_category
            .entry(rule.category.to_string())
            .or_insert(0) += 1;
        *summary.by_severity
            .entry(rule.severity.to_string())
            .or_insert(0) += 1;
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_all_rules() {
        let rules = get_all_rules();
        assert!(!rules.is_empty());
        assert!(rules.len() >= 30); // At least 10 per platform
    }

    #[test]
    fn test_get_rules_for_github_actions() {
        let rules = get_rules_for_platform(&CiCdPlatform::GitHubActions);
        assert!(!rules.is_empty());
        assert!(rules.iter().all(|r| r.platform == CiCdPlatform::GitHubActions));
    }

    #[test]
    fn test_get_rules_by_category() {
        let rules = get_rules_by_category(&CiCdCategory::Secrets);
        assert!(!rules.is_empty());
        assert!(rules.iter().all(|r| r.category == CiCdCategory::Secrets));
    }

    #[test]
    fn test_get_rule_by_id() {
        let rule = get_rule_by_id("ACTIONS001");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().id, "ACTIONS001");
    }

    #[test]
    fn test_rules_summary() {
        let summary = get_rules_summary();
        assert!(summary.total >= 30);
        assert_eq!(summary.by_platform.len(), 3);
    }
}
