//! XCCDF Scoring

use super::types::*;

/// Calculate the score for a set of rule results
pub fn calculate_score(results: &[RuleResult], model: &ScoringModel) -> f64 {
    match model {
        ScoringModel::Default | ScoringModel::Flat => {
            // Weighted scoring
            let mut weighted_sum = 0.0;
            let mut weight_sum = 0.0;

            for result in results {
                if result.result == XccdfResultType::NotApplicable
                    || result.result == XccdfResultType::NotSelected
                {
                    continue;
                }

                let weight = result.weight;
                weight_sum += weight;

                if result.result.is_pass() {
                    weighted_sum += weight;
                }
            }

            if weight_sum > 0.0 {
                (weighted_sum / weight_sum) * 100.0
            } else {
                0.0
            }
        }
        ScoringModel::FlatUnweighted => {
            // Simple pass percentage
            let applicable: Vec<_> = results
                .iter()
                .filter(|r| {
                    r.result != XccdfResultType::NotApplicable
                        && r.result != XccdfResultType::NotSelected
                })
                .collect();

            if applicable.is_empty() {
                return 0.0;
            }

            let passed = applicable.iter().filter(|r| r.result.is_pass()).count();
            (passed as f64 / applicable.len() as f64) * 100.0
        }
        ScoringModel::Absolute => {
            // All must pass
            let applicable: Vec<_> = results
                .iter()
                .filter(|r| {
                    r.result != XccdfResultType::NotApplicable
                        && r.result != XccdfResultType::NotSelected
                })
                .collect();

            if applicable.iter().all(|r| r.result.is_pass()) {
                100.0
            } else {
                0.0
            }
        }
    }
}

/// Calculate maximum possible score
pub fn calculate_max_score(rules: &[XccdfRule], model: &ScoringModel) -> f64 {
    match model {
        ScoringModel::Default | ScoringModel::Flat => {
            // Sum of all weights
            rules.iter().map(|r| r.weight).sum::<f64>() * 100.0 / rules.len() as f64
        }
        ScoringModel::FlatUnweighted | ScoringModel::Absolute => 100.0,
    }
}
