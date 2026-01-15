//! XCCDF - Extensible Configuration Checklist Description Format
//!
//! Implements XCCDF 1.2 for benchmark and profile management.

mod types;
mod parser;
mod scoring;

pub use types::*;
pub use parser::XccdfParser;
pub use scoring::{calculate_score, calculate_max_score};

use crate::scap::ScapSeverity;

/// Resolve which rules are selected by a profile
pub fn resolve_profile_selections(
    benchmark: &XccdfBenchmark,
    profile: &XccdfProfile,
) -> Vec<XccdfRule> {
    let mut selected_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Start with all rules
    for rule in &benchmark.rules {
        selected_ids.insert(rule.id.clone());
    }

    // Apply profile selections
    for select in &profile.selects {
        if select.selected {
            selected_ids.insert(select.id_ref.clone());
        } else {
            selected_ids.remove(&select.id_ref);
        }
    }

    // Return selected rules
    benchmark
        .rules
        .iter()
        .filter(|r| selected_ids.contains(&r.id))
        .cloned()
        .collect()
}
