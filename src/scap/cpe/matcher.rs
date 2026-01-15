//! CPE Matcher

use super::types::*;

/// Matcher for CPE platform applicability
pub struct CpeMatcher;

impl CpeMatcher {
    /// Check if a source CPE matches a target CPE
    pub fn matches(source: &Cpe, target: &Cpe) -> bool {
        if source.part != target.part {
            return false;
        }

        Self::attribute_matches(&source.vendor, &target.vendor)
            && Self::attribute_matches(&source.product, &target.product)
            && Self::attribute_matches(&source.version, &target.version)
            && Self::attribute_matches(&source.update, &target.update)
            && Self::attribute_matches(&source.edition, &target.edition)
            && Self::attribute_matches(&source.language, &target.language)
            && Self::attribute_matches(&source.sw_edition, &target.sw_edition)
            && Self::attribute_matches(&source.target_sw, &target.target_sw)
            && Self::attribute_matches(&source.target_hw, &target.target_hw)
            && Self::attribute_matches(&source.other, &target.other)
    }

    fn attribute_matches(source: &WfnAttribute, target: &WfnAttribute) -> bool {
        match (source, target) {
            (WfnAttribute::Any, _) => true,
            (_, WfnAttribute::Any) => true,
            (WfnAttribute::NotApplicable, WfnAttribute::NotApplicable) => true,
            (WfnAttribute::Value(s), WfnAttribute::Value(t)) => {
                s.to_lowercase() == t.to_lowercase()
            }
            _ => false,
        }
    }

    /// Evaluate a CPE logical test against a set of installed CPEs
    pub fn evaluate_platform(test: &CpeLogicalTest, installed: &[Cpe]) -> bool {
        match test {
            CpeLogicalTest::FactRef(fact) => {
                let found = installed.iter().any(|cpe| Self::matches(&fact.cpe, cpe));
                if fact.check_existence {
                    found
                } else {
                    !found
                }
            }
            CpeLogicalTest::And(tests) => tests.iter().all(|t| Self::evaluate_platform(t, installed)),
            CpeLogicalTest::Or(tests) => tests.iter().any(|t| Self::evaluate_platform(t, installed)),
            CpeLogicalTest::Negate(test) => !Self::evaluate_platform(test, installed),
        }
    }
}
