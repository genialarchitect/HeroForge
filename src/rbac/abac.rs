//! Attribute-Based Access Control (ABAC) engine (Sprint 10)

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABACPolicy {
    pub id: String,
    pub name: String,
    pub rules: Vec<ABACRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABACRule {
    pub subject_attributes: HashMap<String, AttributeValue>,
    pub resource_attributes: HashMap<String, AttributeValue>,
    pub environment_attributes: HashMap<String, AttributeValue>,
    pub action: String,
    pub effect: Effect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttributeValue {
    String(String),
    Number(f64),
    Boolean(bool),
    List(Vec<String>),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct EvaluationContext {
    pub subject_attrs: HashMap<String, AttributeValue>,
    pub resource_attrs: HashMap<String, AttributeValue>,
    pub environment_attrs: HashMap<String, AttributeValue>,
    pub requested_action: String,
}

pub fn evaluate_policy(policy: &ABACPolicy, context: &EvaluationContext) -> bool {
    for rule in &policy.rules {
        if matches_context(rule, context) {
            return matches!(rule.effect, Effect::Allow);
        }
    }
    false
}

fn matches_context(rule: &ABACRule, context: &EvaluationContext) -> bool {
    // Check if all required attributes match
    if rule.action != context.requested_action {
        return false;
    }

    // Check subject attributes
    for (key, value) in &rule.subject_attributes {
        if !context.subject_attrs.get(key).map_or(false, |v| attributes_match(v, value)) {
            return false;
        }
    }

    // Check resource attributes
    for (key, value) in &rule.resource_attributes {
        if !context.resource_attrs.get(key).map_or(false, |v| attributes_match(v, value)) {
            return false;
        }
    }

    true
}

fn attributes_match(a: &AttributeValue, b: &AttributeValue) -> bool {
    match (a, b) {
        (AttributeValue::String(s1), AttributeValue::String(s2)) => s1 == s2,
        (AttributeValue::Number(n1), AttributeValue::Number(n2)) => (n1 - n2).abs() < f64::EPSILON,
        (AttributeValue::Boolean(b1), AttributeValue::Boolean(b2)) => b1 == b2,
        (AttributeValue::List(l1), AttributeValue::List(l2)) => {
            l1.iter().any(|item| l2.contains(item))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abac_evaluation() {
        let policy = ABACPolicy {
            id: "test-policy".to_string(),
            name: "Test Policy".to_string(),
            rules: vec![ABACRule {
                subject_attributes: {
                    let mut attrs = HashMap::new();
                    attrs.insert("role".to_string(), AttributeValue::String("admin".to_string()));
                    attrs
                },
                resource_attributes: HashMap::new(),
                environment_attributes: HashMap::new(),
                action: "read".to_string(),
                effect: Effect::Allow,
            }],
        };

        let context = EvaluationContext {
            subject_attrs: {
                let mut attrs = HashMap::new();
                attrs.insert("role".to_string(), AttributeValue::String("admin".to_string()));
                attrs
            },
            resource_attrs: HashMap::new(),
            environment_attrs: HashMap::new(),
            requested_action: "read".to_string(),
        };

        assert!(evaluate_policy(&policy, &context));
    }
}
