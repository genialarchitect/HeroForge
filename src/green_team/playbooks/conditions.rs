//! Condition evaluation for playbook steps

use super::ExecutionContext;
use crate::green_team::types::{ConditionOperator, StepCondition};
use regex::Regex;

/// Evaluate a step condition against the execution context
pub fn evaluate_condition(condition: &StepCondition, context: &ExecutionContext) -> bool {
    let field_value = get_field_value(&condition.field, context);

    match &condition.operator {
        ConditionOperator::Equals => compare_equals(&field_value, &condition.value),
        ConditionOperator::NotEquals => !compare_equals(&field_value, &condition.value),
        ConditionOperator::Contains => compare_contains(&field_value, &condition.value),
        ConditionOperator::NotContains => !compare_contains(&field_value, &condition.value),
        ConditionOperator::GreaterThan => compare_greater_than(&field_value, &condition.value),
        ConditionOperator::LessThan => compare_less_than(&field_value, &condition.value),
        ConditionOperator::GreaterThanOrEqual => {
            compare_greater_than(&field_value, &condition.value)
                || compare_equals(&field_value, &condition.value)
        }
        ConditionOperator::LessThanOrEqual => {
            compare_less_than(&field_value, &condition.value)
                || compare_equals(&field_value, &condition.value)
        }
        ConditionOperator::Matches => compare_matches(&field_value, &condition.value),
        ConditionOperator::IsNull => field_value.is_none(),
        ConditionOperator::IsNotNull => field_value.is_some(),
        ConditionOperator::In => compare_in(&field_value, &condition.value),
        ConditionOperator::NotIn => !compare_in(&field_value, &condition.value),
    }
}

/// Get a field value from the context using dot notation
fn get_field_value(field: &str, context: &ExecutionContext) -> Option<serde_json::Value> {
    let parts: Vec<&str> = field.split('.').collect();

    if parts.is_empty() {
        return None;
    }

    match parts[0] {
        "input" => {
            if let Some(ref input) = context.input_data {
                get_nested_value(input, &parts[1..])
            } else {
                None
            }
        }
        "variables" => {
            if parts.len() > 1 {
                context.get_variable(parts[1]).cloned()
            } else {
                None
            }
        }
        "steps" => {
            if parts.len() > 2 {
                let step_id = parts[1];
                if let Some(output) = context.get_step_output(step_id) {
                    get_nested_value(output, &parts[2..])
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => {
            // Try as a variable name directly
            context.get_variable(field).cloned()
        }
    }
}

/// Get a nested value from a JSON object
fn get_nested_value(value: &serde_json::Value, path: &[&str]) -> Option<serde_json::Value> {
    if path.is_empty() {
        return Some(value.clone());
    }

    match value {
        serde_json::Value::Object(obj) => {
            if let Some(next_value) = obj.get(path[0]) {
                get_nested_value(next_value, &path[1..])
            } else {
                None
            }
        }
        serde_json::Value::Array(arr) => {
            if let Ok(index) = path[0].parse::<usize>() {
                if index < arr.len() {
                    get_nested_value(&arr[index], &path[1..])
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => {
            if path.is_empty() {
                Some(value.clone())
            } else {
                None
            }
        }
    }
}

fn compare_equals(field: &Option<serde_json::Value>, value: &serde_json::Value) -> bool {
    match field {
        Some(field_val) => field_val == value,
        None => value.is_null(),
    }
}

fn compare_contains(field: &Option<serde_json::Value>, value: &serde_json::Value) -> bool {
    match (field, value) {
        (Some(serde_json::Value::String(field_str)), serde_json::Value::String(value_str)) => {
            field_str.contains(value_str.as_str())
        }
        (Some(serde_json::Value::Array(arr)), value) => arr.contains(value),
        _ => false,
    }
}

fn compare_greater_than(field: &Option<serde_json::Value>, value: &serde_json::Value) -> bool {
    match (field, value) {
        (Some(serde_json::Value::Number(field_num)), serde_json::Value::Number(value_num)) => {
            field_num.as_f64().unwrap_or(0.0) > value_num.as_f64().unwrap_or(0.0)
        }
        (Some(serde_json::Value::String(field_str)), serde_json::Value::String(value_str)) => {
            field_str > value_str
        }
        _ => false,
    }
}

fn compare_less_than(field: &Option<serde_json::Value>, value: &serde_json::Value) -> bool {
    match (field, value) {
        (Some(serde_json::Value::Number(field_num)), serde_json::Value::Number(value_num)) => {
            field_num.as_f64().unwrap_or(0.0) < value_num.as_f64().unwrap_or(0.0)
        }
        (Some(serde_json::Value::String(field_str)), serde_json::Value::String(value_str)) => {
            field_str < value_str
        }
        _ => false,
    }
}

fn compare_matches(field: &Option<serde_json::Value>, value: &serde_json::Value) -> bool {
    match (field, value) {
        (Some(serde_json::Value::String(field_str)), serde_json::Value::String(pattern)) => {
            Regex::new(pattern)
                .map(|re| re.is_match(field_str))
                .unwrap_or(false)
        }
        _ => false,
    }
}

fn compare_in(field: &Option<serde_json::Value>, value: &serde_json::Value) -> bool {
    match (field, value) {
        (Some(field_val), serde_json::Value::Array(arr)) => arr.contains(field_val),
        _ => false,
    }
}

/// Builder for creating conditions
pub struct ConditionBuilder {
    field: String,
    operator: Option<ConditionOperator>,
    value: Option<serde_json::Value>,
}

impl ConditionBuilder {
    /// Create a new condition builder for a field
    pub fn new(field: &str) -> Self {
        Self {
            field: field.to_string(),
            operator: None,
            value: None,
        }
    }

    /// Set equals operator
    pub fn equals(mut self, value: impl Into<serde_json::Value>) -> Self {
        self.operator = Some(ConditionOperator::Equals);
        self.value = Some(value.into());
        self
    }

    /// Set not equals operator
    pub fn not_equals(mut self, value: impl Into<serde_json::Value>) -> Self {
        self.operator = Some(ConditionOperator::NotEquals);
        self.value = Some(value.into());
        self
    }

    /// Set contains operator
    pub fn contains(mut self, value: impl Into<serde_json::Value>) -> Self {
        self.operator = Some(ConditionOperator::Contains);
        self.value = Some(value.into());
        self
    }

    /// Set greater than operator
    pub fn greater_than(mut self, value: impl Into<serde_json::Value>) -> Self {
        self.operator = Some(ConditionOperator::GreaterThan);
        self.value = Some(value.into());
        self
    }

    /// Set less than operator
    pub fn less_than(mut self, value: impl Into<serde_json::Value>) -> Self {
        self.operator = Some(ConditionOperator::LessThan);
        self.value = Some(value.into());
        self
    }

    /// Set matches operator
    pub fn matches(mut self, pattern: &str) -> Self {
        self.operator = Some(ConditionOperator::Matches);
        self.value = Some(serde_json::Value::String(pattern.to_string()));
        self
    }

    /// Set is null operator
    pub fn is_null(mut self) -> Self {
        self.operator = Some(ConditionOperator::IsNull);
        self.value = Some(serde_json::Value::Null);
        self
    }

    /// Set is not null operator
    pub fn is_not_null(mut self) -> Self {
        self.operator = Some(ConditionOperator::IsNotNull);
        self.value = Some(serde_json::Value::Null);
        self
    }

    /// Set in operator
    pub fn is_in(mut self, values: Vec<serde_json::Value>) -> Self {
        self.operator = Some(ConditionOperator::In);
        self.value = Some(serde_json::Value::Array(values));
        self
    }

    /// Build the condition
    pub fn build(self) -> Option<StepCondition> {
        match (self.operator, self.value) {
            (Some(operator), Some(value)) => Some(StepCondition {
                field: self.field,
                operator,
                value,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_condition_equals() {
        let mut ctx = ExecutionContext::new(Uuid::new_v4(), None);
        ctx.set_variable("severity", serde_json::json!("high"));

        let condition = StepCondition {
            field: "severity".to_string(),
            operator: ConditionOperator::Equals,
            value: serde_json::json!("high"),
        };

        assert!(evaluate_condition(&condition, &ctx));
    }

    #[test]
    fn test_condition_greater_than() {
        let mut ctx = ExecutionContext::new(Uuid::new_v4(), None);
        ctx.set_variable("score", serde_json::json!(85));

        let condition = StepCondition {
            field: "score".to_string(),
            operator: ConditionOperator::GreaterThan,
            value: serde_json::json!(80),
        };

        assert!(evaluate_condition(&condition, &ctx));
    }

    #[test]
    fn test_condition_matches() {
        let mut ctx = ExecutionContext::new(Uuid::new_v4(), None);
        ctx.set_variable("ip", serde_json::json!("192.168.1.100"));

        let condition = StepCondition {
            field: "ip".to_string(),
            operator: ConditionOperator::Matches,
            value: serde_json::json!(r"192\.168\.\d+\.\d+"),
        };

        assert!(evaluate_condition(&condition, &ctx));
    }

    #[test]
    fn test_condition_builder() {
        let condition = ConditionBuilder::new("severity")
            .equals("critical")
            .build()
            .unwrap();

        assert_eq!(condition.field, "severity");
        assert!(matches!(condition.operator, ConditionOperator::Equals));
    }
}
