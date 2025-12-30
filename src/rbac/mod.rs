//! Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC) system

pub mod abac;

pub use abac::{ABACPolicy, ABACRule, AttributeValue, Effect, EvaluationContext, evaluate_policy};
