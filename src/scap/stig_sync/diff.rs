//! STIG Diff Reports
//!
//! This module provides functionality to compare two versions of a STIG
//! and generate detailed diff reports showing changes between versions.
//!
//! # Features
//!
//! - **Rule Comparison**: Detect added, removed, and modified rules
//! - **Profile Comparison**: Track changes to profile selections
//! - **Severity Changes**: Highlight severity changes across versions
//! - **Multiple Output Formats**: JSON, HTML, Markdown reports
//!
//! # Usage
//!
//! ```rust,ignore
//! use heroforge::scap::stig_sync::diff::StigDiff;
//!
//! let diff = StigDiff::compare(&old_benchmark, &new_benchmark)?;
//! let html_report = diff.to_html();
//! let json_report = diff.to_json();
//! ```

use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use anyhow::Result;

use crate::scap::{ScapSeverity, LocalizedText};
use crate::scap::xccdf::{XccdfBenchmark, XccdfRule, XccdfProfile, XccdfValue, XccdfGroup};

/// STIG comparison result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigDiff {
    /// Old benchmark info
    pub old_benchmark: BenchmarkInfo,
    /// New benchmark info
    pub new_benchmark: BenchmarkInfo,
    /// When the diff was generated
    pub generated_at: DateTime<Utc>,
    /// Summary statistics
    pub summary: DiffSummary,
    /// Added rules (present in new, not in old)
    pub added_rules: Vec<RuleSummary>,
    /// Removed rules (present in old, not in new)
    pub removed_rules: Vec<RuleSummary>,
    /// Modified rules (present in both with changes)
    pub modified_rules: Vec<RuleDiff>,
    /// Added profiles
    pub added_profiles: Vec<ProfileSummary>,
    /// Removed profiles
    pub removed_profiles: Vec<ProfileSummary>,
    /// Modified profiles
    pub modified_profiles: Vec<ProfileDiff>,
    /// Added values
    pub added_values: Vec<ValueSummary>,
    /// Removed values
    pub removed_values: Vec<ValueSummary>,
    /// Modified values
    pub modified_values: Vec<ValueDiff>,
}

/// Basic benchmark information for comparison header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkInfo {
    pub id: String,
    pub title: String,
    pub version: String,
    pub rule_count: usize,
    pub profile_count: usize,
    pub value_count: usize,
}

impl From<&XccdfBenchmark> for BenchmarkInfo {
    fn from(benchmark: &XccdfBenchmark) -> Self {
        Self {
            id: benchmark.id.clone(),
            title: benchmark.title.text.clone(),
            version: benchmark.version.clone(),
            rule_count: benchmark.rules.len(),
            profile_count: benchmark.profiles.len(),
            value_count: benchmark.values.len(),
        }
    }
}

/// Summary statistics for the diff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub total_changes: usize,
    pub rules_added: usize,
    pub rules_removed: usize,
    pub rules_modified: usize,
    pub severity_upgrades: usize,
    pub severity_downgrades: usize,
    pub profiles_added: usize,
    pub profiles_removed: usize,
    pub profiles_modified: usize,
    pub values_added: usize,
    pub values_removed: usize,
    pub values_modified: usize,
}

/// Summary of a rule for added/removed lists
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSummary {
    pub id: String,
    pub version: String,
    pub title: String,
    pub severity: ScapSeverity,
    pub cci_refs: Vec<String>,
}

impl From<&XccdfRule> for RuleSummary {
    fn from(rule: &XccdfRule) -> Self {
        Self {
            id: rule.id.clone(),
            version: rule.version.clone(),
            title: rule.title.text.clone(),
            severity: rule.severity,
            cci_refs: rule.idents.iter()
                .filter(|i| i.system.contains("cci"))
                .map(|i| i.value.clone())
                .collect(),
        }
    }
}

/// Detailed diff for a modified rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDiff {
    pub id: String,
    pub old_version: String,
    pub new_version: String,
    pub title: String,
    pub changes: Vec<RuleChange>,
}

/// Individual change within a rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleChange {
    pub field: String,
    pub change_type: ChangeType,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Type of change
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
    SeverityUpgrade,
    SeverityDowngrade,
}

impl std::fmt::Display for ChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Added => write!(f, "added"),
            Self::Removed => write!(f, "removed"),
            Self::Modified => write!(f, "modified"),
            Self::SeverityUpgrade => write!(f, "severity_upgrade"),
            Self::SeverityDowngrade => write!(f, "severity_downgrade"),
        }
    }
}

/// Summary of a profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub id: String,
    pub title: String,
    pub selected_rules: usize,
}

impl From<&XccdfProfile> for ProfileSummary {
    fn from(profile: &XccdfProfile) -> Self {
        Self {
            id: profile.id.clone(),
            title: profile.title.text.clone(),
            selected_rules: profile.selects.iter().filter(|s| s.selected).count(),
        }
    }
}

/// Diff for a modified profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDiff {
    pub id: String,
    pub title: String,
    pub added_selections: Vec<String>,
    pub removed_selections: Vec<String>,
    pub changed_values: Vec<(String, String, String)>, // (id, old, new)
}

/// Summary of a value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueSummary {
    pub id: String,
    pub title: String,
    pub value: String,
}

impl From<&XccdfValue> for ValueSummary {
    fn from(value: &XccdfValue) -> Self {
        Self {
            id: value.id.clone(),
            title: value.title.text.clone(),
            value: value.value.clone(),
        }
    }
}

/// Diff for a modified value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueDiff {
    pub id: String,
    pub title: String,
    pub old_value: String,
    pub new_value: String,
    pub description_changed: bool,
}

impl StigDiff {
    /// Compare two benchmarks and generate a diff report
    pub fn compare(old: &XccdfBenchmark, new: &XccdfBenchmark) -> Result<Self> {
        let old_rules: HashMap<&str, &XccdfRule> = old.rules.iter()
            .map(|r| (r.id.as_str(), r))
            .collect();
        let new_rules: HashMap<&str, &XccdfRule> = new.rules.iter()
            .map(|r| (r.id.as_str(), r))
            .collect();

        let old_rule_ids: HashSet<&str> = old_rules.keys().copied().collect();
        let new_rule_ids: HashSet<&str> = new_rules.keys().copied().collect();

        // Find added, removed, and common rules
        let added_ids: Vec<&str> = new_rule_ids.difference(&old_rule_ids).copied().collect();
        let removed_ids: Vec<&str> = old_rule_ids.difference(&new_rule_ids).copied().collect();
        let common_ids: Vec<&str> = old_rule_ids.intersection(&new_rule_ids).copied().collect();

        // Build added rules list
        let added_rules: Vec<RuleSummary> = added_ids.iter()
            .filter_map(|id| new_rules.get(id))
            .map(|r| RuleSummary::from(*r))
            .collect();

        // Build removed rules list
        let removed_rules: Vec<RuleSummary> = removed_ids.iter()
            .filter_map(|id| old_rules.get(id))
            .map(|r| RuleSummary::from(*r))
            .collect();

        // Build modified rules list
        let mut modified_rules = Vec::new();
        let mut severity_upgrades = 0;
        let mut severity_downgrades = 0;

        for id in common_ids {
            if let (Some(old_rule), Some(new_rule)) = (old_rules.get(id), new_rules.get(id)) {
                let changes = Self::compare_rules(old_rule, new_rule);
                if !changes.is_empty() {
                    // Count severity changes
                    for change in &changes {
                        match change.change_type {
                            ChangeType::SeverityUpgrade => severity_upgrades += 1,
                            ChangeType::SeverityDowngrade => severity_downgrades += 1,
                            _ => {}
                        }
                    }

                    modified_rules.push(RuleDiff {
                        id: new_rule.id.clone(),
                        old_version: old_rule.version.clone(),
                        new_version: new_rule.version.clone(),
                        title: new_rule.title.text.clone(),
                        changes,
                    });
                }
            }
        }

        // Compare profiles
        let (added_profiles, removed_profiles, modified_profiles) =
            Self::compare_profiles(&old.profiles, &new.profiles);

        // Compare values
        let (added_values, removed_values, modified_values) =
            Self::compare_values(&old.values, &new.values);

        // Build summary
        let summary = DiffSummary {
            total_changes: added_rules.len() + removed_rules.len() + modified_rules.len() +
                          added_profiles.len() + removed_profiles.len() + modified_profiles.len() +
                          added_values.len() + removed_values.len() + modified_values.len(),
            rules_added: added_rules.len(),
            rules_removed: removed_rules.len(),
            rules_modified: modified_rules.len(),
            severity_upgrades,
            severity_downgrades,
            profiles_added: added_profiles.len(),
            profiles_removed: removed_profiles.len(),
            profiles_modified: modified_profiles.len(),
            values_added: added_values.len(),
            values_removed: removed_values.len(),
            values_modified: modified_values.len(),
        };

        Ok(Self {
            old_benchmark: BenchmarkInfo::from(old),
            new_benchmark: BenchmarkInfo::from(new),
            generated_at: Utc::now(),
            summary,
            added_rules,
            removed_rules,
            modified_rules,
            added_profiles,
            removed_profiles,
            modified_profiles,
            added_values,
            removed_values,
            modified_values,
        })
    }

    /// Compare two rules and return list of changes
    fn compare_rules(old: &XccdfRule, new: &XccdfRule) -> Vec<RuleChange> {
        let mut changes = Vec::new();

        // Check version change
        if old.version != new.version {
            changes.push(RuleChange {
                field: "version".to_string(),
                change_type: ChangeType::Modified,
                old_value: Some(old.version.clone()),
                new_value: Some(new.version.clone()),
            });
        }

        // Check severity change
        if old.severity != new.severity {
            let change_type = if Self::severity_rank(new.severity) > Self::severity_rank(old.severity) {
                ChangeType::SeverityUpgrade
            } else {
                ChangeType::SeverityDowngrade
            };
            changes.push(RuleChange {
                field: "severity".to_string(),
                change_type,
                old_value: Some(format!("{:?}", old.severity)),
                new_value: Some(format!("{:?}", new.severity)),
            });
        }

        // Check weight change
        if (old.weight - new.weight).abs() > f64::EPSILON {
            changes.push(RuleChange {
                field: "weight".to_string(),
                change_type: ChangeType::Modified,
                old_value: Some(old.weight.to_string()),
                new_value: Some(new.weight.to_string()),
            });
        }

        // Check title change
        if old.title.text != new.title.text {
            changes.push(RuleChange {
                field: "title".to_string(),
                change_type: ChangeType::Modified,
                old_value: Some(old.title.text.clone()),
                new_value: Some(new.title.text.clone()),
            });
        }

        // Check description change
        let old_desc = old.description.as_ref().map(|d| &d.text);
        let new_desc = new.description.as_ref().map(|d| &d.text);
        if old_desc != new_desc {
            changes.push(RuleChange {
                field: "description".to_string(),
                change_type: ChangeType::Modified,
                old_value: old_desc.cloned(),
                new_value: new_desc.cloned(),
            });
        }

        // Check rationale change
        let old_rationale = old.rationale.as_ref().map(|r| &r.text);
        let new_rationale = new.rationale.as_ref().map(|r| &r.text);
        if old_rationale != new_rationale {
            changes.push(RuleChange {
                field: "rationale".to_string(),
                change_type: ChangeType::Modified,
                old_value: old_rationale.cloned(),
                new_value: new_rationale.cloned(),
            });
        }

        // Check fixtext change
        let old_fixtext = old.fixtext.as_ref().map(|f| &f.text);
        let new_fixtext = new.fixtext.as_ref().map(|f| &f.text);
        if old_fixtext != new_fixtext {
            changes.push(RuleChange {
                field: "fixtext".to_string(),
                change_type: ChangeType::Modified,
                old_value: old_fixtext.cloned(),
                new_value: new_fixtext.cloned(),
            });
        }

        // Check CCI reference changes
        let old_ccis: HashSet<&str> = old.idents.iter()
            .filter(|i| i.system.contains("cci"))
            .map(|i| i.value.as_str())
            .collect();
        let new_ccis: HashSet<&str> = new.idents.iter()
            .filter(|i| i.system.contains("cci"))
            .map(|i| i.value.as_str())
            .collect();

        let added_ccis: Vec<&str> = new_ccis.difference(&old_ccis).copied().collect();
        let removed_ccis: Vec<&str> = old_ccis.difference(&new_ccis).copied().collect();

        if !added_ccis.is_empty() {
            changes.push(RuleChange {
                field: "cci_refs".to_string(),
                change_type: ChangeType::Added,
                old_value: None,
                new_value: Some(added_ccis.join(", ")),
            });
        }

        if !removed_ccis.is_empty() {
            changes.push(RuleChange {
                field: "cci_refs".to_string(),
                change_type: ChangeType::Removed,
                old_value: Some(removed_ccis.join(", ")),
                new_value: None,
            });
        }

        changes
    }

    /// Get numeric rank for severity comparison
    fn severity_rank(severity: ScapSeverity) -> u8 {
        match severity {
            ScapSeverity::Info => 1,
            ScapSeverity::Low => 2,
            ScapSeverity::Medium => 3,
            ScapSeverity::High => 4,
            ScapSeverity::Critical => 5,
            ScapSeverity::Unknown => 0,
        }
    }

    /// Compare profiles between benchmarks
    fn compare_profiles(
        old: &[XccdfProfile],
        new: &[XccdfProfile],
    ) -> (Vec<ProfileSummary>, Vec<ProfileSummary>, Vec<ProfileDiff>) {
        let old_map: HashMap<&str, &XccdfProfile> = old.iter()
            .map(|p| (p.id.as_str(), p))
            .collect();
        let new_map: HashMap<&str, &XccdfProfile> = new.iter()
            .map(|p| (p.id.as_str(), p))
            .collect();

        let old_ids: HashSet<&str> = old_map.keys().copied().collect();
        let new_ids: HashSet<&str> = new_map.keys().copied().collect();

        let added: Vec<ProfileSummary> = new_ids.difference(&old_ids)
            .filter_map(|id| new_map.get(id))
            .map(|p| ProfileSummary::from(*p))
            .collect();

        let removed: Vec<ProfileSummary> = old_ids.difference(&new_ids)
            .filter_map(|id| old_map.get(id))
            .map(|p| ProfileSummary::from(*p))
            .collect();

        let mut modified = Vec::new();
        for id in old_ids.intersection(&new_ids) {
            if let (Some(old_profile), Some(new_profile)) = (old_map.get(id), new_map.get(id)) {
                let diff = Self::compare_single_profile(old_profile, new_profile);
                if !diff.added_selections.is_empty() ||
                   !diff.removed_selections.is_empty() ||
                   !diff.changed_values.is_empty() {
                    modified.push(diff);
                }
            }
        }

        (added, removed, modified)
    }

    /// Compare a single profile
    fn compare_single_profile(old: &XccdfProfile, new: &XccdfProfile) -> ProfileDiff {
        let old_selected: HashSet<&str> = old.selects.iter()
            .filter(|s| s.selected)
            .map(|s| s.id_ref.as_str())
            .collect();
        let new_selected: HashSet<&str> = new.selects.iter()
            .filter(|s| s.selected)
            .map(|s| s.id_ref.as_str())
            .collect();

        let added_selections: Vec<String> = new_selected.difference(&old_selected)
            .map(|s| s.to_string())
            .collect();
        let removed_selections: Vec<String> = old_selected.difference(&new_selected)
            .map(|s| s.to_string())
            .collect();

        // Compare set-values
        let old_values: HashMap<&str, &str> = old.set_values.iter()
            .map(|v| (v.id_ref.as_str(), v.value.as_str()))
            .collect();
        let new_values: HashMap<&str, &str> = new.set_values.iter()
            .map(|v| (v.id_ref.as_str(), v.value.as_str()))
            .collect();

        let mut changed_values = Vec::new();
        for (id, new_val) in &new_values {
            if let Some(old_val) = old_values.get(id) {
                if old_val != new_val {
                    changed_values.push((id.to_string(), old_val.to_string(), new_val.to_string()));
                }
            }
        }

        ProfileDiff {
            id: new.id.clone(),
            title: new.title.text.clone(),
            added_selections,
            removed_selections,
            changed_values,
        }
    }

    /// Compare values between benchmarks
    fn compare_values(
        old: &[XccdfValue],
        new: &[XccdfValue],
    ) -> (Vec<ValueSummary>, Vec<ValueSummary>, Vec<ValueDiff>) {
        let old_map: HashMap<&str, &XccdfValue> = old.iter()
            .map(|v| (v.id.as_str(), v))
            .collect();
        let new_map: HashMap<&str, &XccdfValue> = new.iter()
            .map(|v| (v.id.as_str(), v))
            .collect();

        let old_ids: HashSet<&str> = old_map.keys().copied().collect();
        let new_ids: HashSet<&str> = new_map.keys().copied().collect();

        let added: Vec<ValueSummary> = new_ids.difference(&old_ids)
            .filter_map(|id| new_map.get(id))
            .map(|v| ValueSummary::from(*v))
            .collect();

        let removed: Vec<ValueSummary> = old_ids.difference(&new_ids)
            .filter_map(|id| old_map.get(id))
            .map(|v| ValueSummary::from(*v))
            .collect();

        let mut modified = Vec::new();
        for id in old_ids.intersection(&new_ids) {
            if let (Some(old_val), Some(new_val)) = (old_map.get(id), new_map.get(id)) {
                if old_val.value != new_val.value {
                    let old_desc = old_val.description.as_ref().map(|d| &d.text);
                    let new_desc = new_val.description.as_ref().map(|d| &d.text);

                    modified.push(ValueDiff {
                        id: new_val.id.clone(),
                        title: new_val.title.text.clone(),
                        old_value: old_val.value.clone(),
                        new_value: new_val.value.clone(),
                        description_changed: old_desc != new_desc,
                    });
                }
            }
        }

        (added, removed, modified)
    }

    /// Convert diff to JSON string
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Generate HTML report
    pub fn to_html(&self) -> String {
        let mut html = String::new();

        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("<meta charset=\"UTF-8\">\n");
        html.push_str("<title>STIG Diff Report</title>\n");
        html.push_str("<style>\n");
        html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; }\n");
        html.push_str(".header { background: #1a1a2e; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }\n");
        html.push_str(".summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 20px; }\n");
        html.push_str(".stat { background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }\n");
        html.push_str(".stat-value { font-size: 24px; font-weight: bold; }\n");
        html.push_str(".stat-label { color: #6c757d; font-size: 14px; }\n");
        html.push_str(".added { color: #28a745; }\n");
        html.push_str(".removed { color: #dc3545; }\n");
        html.push_str(".modified { color: #fd7e14; }\n");
        html.push_str(".severity-upgrade { background: #fff3cd; }\n");
        html.push_str(".severity-downgrade { background: #d4edda; }\n");
        html.push_str("table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }\n");
        html.push_str("th, td { padding: 10px; text-align: left; border-bottom: 1px solid #dee2e6; }\n");
        html.push_str("th { background: #e9ecef; }\n");
        html.push_str(".section { margin-bottom: 30px; }\n");
        html.push_str(".section-title { font-size: 20px; font-weight: bold; margin-bottom: 15px; border-bottom: 2px solid #1a1a2e; padding-bottom: 10px; }\n");
        html.push_str(".change-badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; }\n");
        html.push_str(".badge-critical { background: #dc3545; color: white; }\n");
        html.push_str(".badge-high { background: #fd7e14; color: white; }\n");
        html.push_str(".badge-medium { background: #ffc107; color: black; }\n");
        html.push_str(".badge-low { background: #28a745; color: white; }\n");
        html.push_str("</style>\n</head>\n<body>\n");

        // Header
        html.push_str("<div class=\"header\">\n");
        html.push_str("<h1>STIG Version Comparison Report</h1>\n");
        html.push_str(&format!(
            "<p>{} v{} → v{}</p>\n",
            self.new_benchmark.title,
            self.old_benchmark.version,
            self.new_benchmark.version
        ));
        html.push_str(&format!(
            "<p>Generated: {}</p>\n",
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        html.push_str("</div>\n");

        // Summary stats
        html.push_str("<div class=\"summary\">\n");
        html.push_str(&format!(
            "<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Total Changes</div></div>\n",
            self.summary.total_changes
        ));
        html.push_str(&format!(
            "<div class=\"stat\"><div class=\"stat-value added\">+{}</div><div class=\"stat-label\">Rules Added</div></div>\n",
            self.summary.rules_added
        ));
        html.push_str(&format!(
            "<div class=\"stat\"><div class=\"stat-value removed\">-{}</div><div class=\"stat-label\">Rules Removed</div></div>\n",
            self.summary.rules_removed
        ));
        html.push_str(&format!(
            "<div class=\"stat\"><div class=\"stat-value modified\">~{}</div><div class=\"stat-label\">Rules Modified</div></div>\n",
            self.summary.rules_modified
        ));
        html.push_str(&format!(
            "<div class=\"stat\"><div class=\"stat-value\">↑{}</div><div class=\"stat-label\">Severity Upgrades</div></div>\n",
            self.summary.severity_upgrades
        ));
        html.push_str(&format!(
            "<div class=\"stat\"><div class=\"stat-value\">↓{}</div><div class=\"stat-label\">Severity Downgrades</div></div>\n",
            self.summary.severity_downgrades
        ));
        html.push_str("</div>\n");

        // Added Rules
        if !self.added_rules.is_empty() {
            html.push_str("<div class=\"section\">\n");
            html.push_str("<div class=\"section-title added\">Added Rules</div>\n");
            html.push_str("<table>\n<tr><th>Rule ID</th><th>Title</th><th>Severity</th><th>CCI References</th></tr>\n");
            for rule in &self.added_rules {
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    rule.id,
                    Self::escape_html(&rule.title),
                    Self::severity_badge(rule.severity),
                    rule.cci_refs.join(", ")
                ));
            }
            html.push_str("</table>\n</div>\n");
        }

        // Removed Rules
        if !self.removed_rules.is_empty() {
            html.push_str("<div class=\"section\">\n");
            html.push_str("<div class=\"section-title removed\">Removed Rules</div>\n");
            html.push_str("<table>\n<tr><th>Rule ID</th><th>Title</th><th>Severity</th><th>CCI References</th></tr>\n");
            for rule in &self.removed_rules {
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    rule.id,
                    Self::escape_html(&rule.title),
                    Self::severity_badge(rule.severity),
                    rule.cci_refs.join(", ")
                ));
            }
            html.push_str("</table>\n</div>\n");
        }

        // Modified Rules
        if !self.modified_rules.is_empty() {
            html.push_str("<div class=\"section\">\n");
            html.push_str("<div class=\"section-title modified\">Modified Rules</div>\n");
            html.push_str("<table>\n<tr><th>Rule ID</th><th>Title</th><th>Version</th><th>Changes</th></tr>\n");
            for rule in &self.modified_rules {
                let changes_html: Vec<String> = rule.changes.iter()
                    .map(|c| format!("{}: {}", c.field, c.change_type))
                    .collect();
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{} → {}</td><td>{}</td></tr>\n",
                    rule.id,
                    Self::escape_html(&rule.title),
                    rule.old_version,
                    rule.new_version,
                    changes_html.join(", ")
                ));
            }
            html.push_str("</table>\n</div>\n");
        }

        html.push_str("</body>\n</html>");
        html
    }

    /// Generate Markdown report
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str("# STIG Version Comparison Report\n\n");
        md.push_str(&format!(
            "**{}**\n\nVersion {} → Version {}\n\n",
            self.new_benchmark.title,
            self.old_benchmark.version,
            self.new_benchmark.version
        ));
        md.push_str(&format!(
            "Generated: {}\n\n",
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Summary
        md.push_str("## Summary\n\n");
        md.push_str("| Metric | Count |\n");
        md.push_str("|--------|-------|\n");
        md.push_str(&format!("| Total Changes | {} |\n", self.summary.total_changes));
        md.push_str(&format!("| Rules Added | +{} |\n", self.summary.rules_added));
        md.push_str(&format!("| Rules Removed | -{} |\n", self.summary.rules_removed));
        md.push_str(&format!("| Rules Modified | ~{} |\n", self.summary.rules_modified));
        md.push_str(&format!("| Severity Upgrades | ↑{} |\n", self.summary.severity_upgrades));
        md.push_str(&format!("| Severity Downgrades | ↓{} |\n", self.summary.severity_downgrades));
        md.push_str("\n");

        // Added Rules
        if !self.added_rules.is_empty() {
            md.push_str("## Added Rules\n\n");
            md.push_str("| Rule ID | Title | Severity |\n");
            md.push_str("|---------|-------|----------|\n");
            for rule in &self.added_rules {
                md.push_str(&format!(
                    "| {} | {} | {:?} |\n",
                    rule.id,
                    rule.title.replace('|', "\\|"),
                    rule.severity
                ));
            }
            md.push_str("\n");
        }

        // Removed Rules
        if !self.removed_rules.is_empty() {
            md.push_str("## Removed Rules\n\n");
            md.push_str("| Rule ID | Title | Severity |\n");
            md.push_str("|---------|-------|----------|\n");
            for rule in &self.removed_rules {
                md.push_str(&format!(
                    "| {} | {} | {:?} |\n",
                    rule.id,
                    rule.title.replace('|', "\\|"),
                    rule.severity
                ));
            }
            md.push_str("\n");
        }

        // Modified Rules
        if !self.modified_rules.is_empty() {
            md.push_str("## Modified Rules\n\n");
            md.push_str("| Rule ID | Title | Changes |\n");
            md.push_str("|---------|-------|--------|\n");
            for rule in &self.modified_rules {
                let changes: Vec<String> = rule.changes.iter()
                    .map(|c| format!("{}: {}", c.field, c.change_type))
                    .collect();
                md.push_str(&format!(
                    "| {} | {} | {} |\n",
                    rule.id,
                    rule.title.replace('|', "\\|"),
                    changes.join(", ")
                ));
            }
            md.push_str("\n");
        }

        md
    }

    /// Escape HTML special characters
    fn escape_html(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }

    /// Generate severity badge HTML
    fn severity_badge(severity: ScapSeverity) -> String {
        let (class, text) = match severity {
            ScapSeverity::Critical => ("badge-critical", "Critical"),
            ScapSeverity::High => ("badge-high", "High"),
            ScapSeverity::Medium => ("badge-medium", "Medium"),
            ScapSeverity::Low => ("badge-low", "Low"),
            ScapSeverity::Info => ("badge-low", "Info"),
            ScapSeverity::Unknown => ("badge-medium", "Unknown"),
        };
        format!("<span class=\"change-badge {}\">{}</span>", class, text)
    }

    /// Check if the diff has any changes
    pub fn has_changes(&self) -> bool {
        self.summary.total_changes > 0
    }

    /// Get a compact summary string
    pub fn summary_string(&self) -> String {
        format!(
            "{} v{} → v{}: +{} rules, -{} rules, ~{} modified ({} severity changes)",
            self.new_benchmark.title,
            self.old_benchmark.version,
            self.new_benchmark.version,
            self.summary.rules_added,
            self.summary.rules_removed,
            self.summary.rules_modified,
            self.summary.severity_upgrades + self.summary.severity_downgrades
        )
    }
}

/// Compare two STIGs by their bundle paths
pub async fn compare_stig_bundles(
    old_path: &str,
    new_path: &str,
) -> Result<StigDiff> {
    use crate::scap::content::ContentLoader;

    let loader = ContentLoader::new();

    // Load both bundles
    let old_content = loader.load_from_file(old_path, crate::scap::ScapContentSource::Custom).await?;
    let new_content = loader.load_from_file(new_path, crate::scap::ScapContentSource::Custom).await?;

    // Parse full content
    let old_data = tokio::fs::read(old_path).await?;
    let new_data = tokio::fs::read(new_path).await?;

    let old_parsed = loader.parse_full(&old_data).await?;
    let new_parsed = loader.parse_full(&new_data).await?;

    // Compare first benchmark from each
    if old_parsed.benchmarks.is_empty() {
        anyhow::bail!("Old STIG has no benchmarks");
    }
    if new_parsed.benchmarks.is_empty() {
        anyhow::bail!("New STIG has no benchmarks");
    }

    StigDiff::compare(&old_parsed.benchmarks[0], &new_parsed.benchmarks[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_benchmark(id: &str, version: &str, rules: Vec<XccdfRule>) -> XccdfBenchmark {
        XccdfBenchmark {
            id: id.to_string(),
            version: version.to_string(),
            title: LocalizedText { text: format!("Test Benchmark {}", id), lang: None },
            rules,
            ..Default::default()
        }
    }

    fn create_test_rule(id: &str, severity: ScapSeverity, title: &str) -> XccdfRule {
        XccdfRule {
            id: id.to_string(),
            version: "1".to_string(),
            severity,
            title: LocalizedText { text: title.to_string(), lang: None },
            ..Default::default()
        }
    }

    #[test]
    fn test_added_rules() {
        let old = create_test_benchmark("test", "1.0", vec![
            create_test_rule("SV-001", ScapSeverity::Medium, "Rule 1"),
        ]);
        let new = create_test_benchmark("test", "2.0", vec![
            create_test_rule("SV-001", ScapSeverity::Medium, "Rule 1"),
            create_test_rule("SV-002", ScapSeverity::High, "Rule 2"),
        ]);

        let diff = StigDiff::compare(&old, &new).unwrap();
        assert_eq!(diff.summary.rules_added, 1);
        assert_eq!(diff.added_rules[0].id, "SV-002");
    }

    #[test]
    fn test_removed_rules() {
        let old = create_test_benchmark("test", "1.0", vec![
            create_test_rule("SV-001", ScapSeverity::Medium, "Rule 1"),
            create_test_rule("SV-002", ScapSeverity::High, "Rule 2"),
        ]);
        let new = create_test_benchmark("test", "2.0", vec![
            create_test_rule("SV-001", ScapSeverity::Medium, "Rule 1"),
        ]);

        let diff = StigDiff::compare(&old, &new).unwrap();
        assert_eq!(diff.summary.rules_removed, 1);
        assert_eq!(diff.removed_rules[0].id, "SV-002");
    }

    #[test]
    fn test_severity_upgrade() {
        let old = create_test_benchmark("test", "1.0", vec![
            create_test_rule("SV-001", ScapSeverity::Medium, "Rule 1"),
        ]);
        let new = create_test_benchmark("test", "2.0", vec![
            create_test_rule("SV-001", ScapSeverity::High, "Rule 1"),
        ]);

        let diff = StigDiff::compare(&old, &new).unwrap();
        assert_eq!(diff.summary.severity_upgrades, 1);
        assert_eq!(diff.summary.rules_modified, 1);
    }

    #[test]
    fn test_no_changes() {
        let old = create_test_benchmark("test", "1.0", vec![
            create_test_rule("SV-001", ScapSeverity::Medium, "Rule 1"),
        ]);
        let new = create_test_benchmark("test", "1.0", vec![
            create_test_rule("SV-001", ScapSeverity::Medium, "Rule 1"),
        ]);

        let diff = StigDiff::compare(&old, &new).unwrap();
        assert!(!diff.has_changes());
    }

    #[test]
    fn test_summary_string() {
        let old = create_test_benchmark("test", "1.0", vec![]);
        let new = create_test_benchmark("test", "2.0", vec![
            create_test_rule("SV-001", ScapSeverity::High, "New Rule"),
        ]);

        let diff = StigDiff::compare(&old, &new).unwrap();
        let summary = diff.summary_string();
        assert!(summary.contains("v1.0 → v2.0"));
        assert!(summary.contains("+1 rules"));
    }
}
