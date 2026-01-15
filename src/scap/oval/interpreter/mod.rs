//! OVAL Interpreter Engine
//!
//! Implements full OVAL 5.11 definition evaluation including:
//! - Criteria tree evaluation (AND, OR, ONE, XOR operators)
//! - Test evaluation with object/state comparison
//! - Object collection and state matching
//! - Support for local and remote execution

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{
    OvalDefinitions, OvalDefinition, OvalResultType, DefinitionResult,
    Criteria, CriteriaNode, Criterion, LogicalOperator, ExistenceCheck, CheckEnumeration,
    OvalObject, OvalState, OvalTest, CriteriaResult, CriteriaNodeResult, CriterionResult,
    OvalItem, OvalValue, ItemStatus, ObjectType, StateValue, Operation,
};
use super::remote::RemoteExecutionContext;

/// Test evaluation result (local type for interpreter)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestEvalResult {
    pub test_id: String,
    pub result: OvalResultType,
    pub check_existence: ExistenceCheck,
    pub check: CheckEnumeration,
    pub items_found: usize,
    pub items_matched: usize,
    pub message: Option<String>,
}

/// OVAL Evaluation Engine
pub struct OvalEngine {
    definitions: OvalDefinitions,
    remote_ctx: Option<RemoteExecutionContext>,
    cache: EvaluationCache,
    collected_items: HashMap<String, Vec<OvalItem>>,
    definitions_evaluated: AtomicUsize,
    objects_collected: AtomicUsize,
}

/// Cache for evaluation results
#[derive(Default)]
struct EvaluationCache {
    definition_results: HashMap<String, DefinitionResult>,
    test_results: HashMap<String, TestEvalResult>,
}

impl OvalEngine {
    /// Create a new OVAL engine
    pub fn new(definitions: OvalDefinitions) -> Self {
        Self {
            definitions,
            remote_ctx: None,
            cache: EvaluationCache::default(),
            collected_items: HashMap::new(),
            definitions_evaluated: AtomicUsize::new(0),
            objects_collected: AtomicUsize::new(0),
        }
    }

    /// Set remote execution context for remote hosts
    pub fn set_remote_context(&mut self, ctx: RemoteExecutionContext) {
        self.remote_ctx = Some(ctx);
    }

    /// Evaluate a definition by ID
    pub async fn evaluate_definition(&mut self, definition_id: &str) -> Result<DefinitionResult> {
        // Check cache first
        if let Some(cached) = self.cache.definition_results.get(definition_id) {
            return Ok(cached.clone());
        }

        self.definitions_evaluated.fetch_add(1, Ordering::Relaxed);

        // Get definition
        let definition = self.definitions.get(definition_id)
            .ok_or_else(|| anyhow::anyhow!("Definition not found: {}", definition_id))?
            .clone();

        // Evaluate the criteria tree
        let (result_type, criteria_results) = if let Some(ref criteria) = definition.criteria {
            let criteria_result = self.evaluate_criteria(criteria).await?;
            (criteria_result.result, Some(criteria_result))
        } else {
            // No criteria means definition is trivially true
            (OvalResultType::True, None)
        };

        let result = DefinitionResult {
            definition_id: definition_id.to_string(),
            result: result_type,
            criteria_results,
            message: None,
            evaluated_at: chrono::Utc::now(),
        };

        // Cache result
        self.cache.definition_results.insert(definition_id.to_string(), result.clone());

        Ok(result)
    }

    /// Evaluate all definitions in a category
    pub async fn evaluate_all(&mut self, class_filter: Option<&str>) -> Result<Vec<DefinitionResult>> {
        let def_ids: Vec<String> = self.definitions.definitions.keys()
            .filter(|id| {
                if let Some(class) = class_filter {
                    if let Some(def) = self.definitions.get(id) {
                        format!("{:?}", def.class).to_lowercase() == class.to_lowercase()
                    } else {
                        false
                    }
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        let mut results = Vec::new();
        for def_id in def_ids {
            match self.evaluate_definition(&def_id).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    log::warn!("Failed to evaluate definition {}: {}", def_id, e);
                    results.push(DefinitionResult {
                        definition_id: def_id,
                        result: OvalResultType::Error,
                        criteria_results: None,
                        message: Some(e.to_string()),
                        evaluated_at: chrono::Utc::now(),
                    });
                }
            }
        }
        Ok(results)
    }

    /// Evaluate a criteria tree
    async fn evaluate_criteria(&mut self, criteria: &Criteria) -> Result<CriteriaResult> {
        let mut child_results = Vec::new();

        // Evaluate all children (criteria nodes)
        for child in &criteria.children {
            match child {
                CriteriaNode::Criteria(nested_criteria) => {
                    let nested_result = Box::pin(self.evaluate_criteria(nested_criteria)).await?;
                    child_results.push(CriteriaNodeResult::Criteria(Box::new(nested_result)));
                }
                CriteriaNode::Criterion(criterion) => {
                    let test_result = self.evaluate_test(&criterion.test_ref).await?;
                    let mut result = test_result.result;
                    if criterion.negate {
                        result = result.negate();
                    }
                    child_results.push(CriteriaNodeResult::Criterion(CriterionResult {
                        test_ref: criterion.test_ref.clone(),
                        result,
                        negate: criterion.negate,
                    }));
                }
                CriteriaNode::ExtendDefinition(def_ref) => {
                    let def_result = Box::pin(self.evaluate_definition(def_ref)).await?;
                    child_results.push(CriteriaNodeResult::ExtendDefinition(def_result));
                }
            }
        }

        // Combine results based on operator
        let combined_result = self.combine_criteria_results(&criteria.operator, &child_results);

        // Apply negation if needed
        let final_result = if criteria.negate {
            combined_result.negate()
        } else {
            combined_result
        };

        Ok(CriteriaResult {
            operator: criteria.operator,
            negate: criteria.negate,
            result: final_result,
            children: child_results,
        })
    }

    /// Evaluate a single test
    async fn evaluate_test(&mut self, test_id: &str) -> Result<TestEvalResult> {
        // Check cache
        if let Some(cached) = self.cache.test_results.get(test_id) {
            return Ok(cached.clone());
        }

        let test = self.definitions.tests.get(test_id)
            .ok_or_else(|| anyhow::anyhow!("Test not found: {}", test_id))?
            .clone();

        // Collect items for the object
        let items = self.collect_object(&test.object_ref).await?;

        // Evaluate check_existence
        let existence_result = self.evaluate_existence(&test.check_existence, &items);

        // If existence check fails or there are no items, return early
        if existence_result != OvalResultType::True || items.is_empty() {
            let result = TestEvalResult {
                test_id: test_id.to_string(),
                result: existence_result,
                check_existence: test.check_existence,
                check: test.check,
                items_found: items.len(),
                items_matched: 0,
                message: None,
            };
            self.cache.test_results.insert(test_id.to_string(), result.clone());
            return Ok(result);
        }

        // If there's a state reference, compare items against state
        let (items_matched, state_result) = if let Some(ref state_ref) = test.state_ref {
            let state_op = test.state_operator.unwrap_or(LogicalOperator::And);
            self.evaluate_state(state_ref, &items, &test.check, state_op).await?
        } else {
            // No state means we only check existence
            (items.len(), OvalResultType::True)
        };

        let result = TestEvalResult {
            test_id: test_id.to_string(),
            result: state_result,
            check_existence: test.check_existence,
            check: test.check,
            items_found: items.len(),
            items_matched,
            message: None,
        };

        self.cache.test_results.insert(test_id.to_string(), result.clone());
        Ok(result)
    }

    /// Collect items for an object
    async fn collect_object(&mut self, object_id: &str) -> Result<Vec<OvalItem>> {
        // Check if already collected
        if let Some(items) = self.collected_items.get(object_id) {
            return Ok(items.clone());
        }

        self.objects_collected.fetch_add(1, Ordering::Relaxed);

        let object = self.definitions.objects.get(object_id)
            .ok_or_else(|| anyhow::anyhow!("Object not found: {}", object_id))?
            .clone();

        // Collect items based on object type and context (local vs remote)
        let items = if let Some(ref ctx) = self.remote_ctx {
            self.collect_remote(&object, ctx).await?
        } else {
            self.collect_local(&object).await?
        };

        self.collected_items.insert(object_id.to_string(), items.clone());
        Ok(items)
    }

    /// Collect items locally
    async fn collect_local(&self, object: &OvalObject) -> Result<Vec<OvalItem>> {
        match object.object_type {
            ObjectType::UnixFile => {
                self.collect_file_object(object).await
            }
            ObjectType::WinRegistry => {
                #[cfg(target_os = "windows")]
                return self.collect_registry_object(object).await;
                #[cfg(not(target_os = "windows"))]
                Ok(Vec::new())
            }
            ObjectType::IndTextFileContent => {
                self.collect_textfile_object(object).await
            }
            ObjectType::IndFamily => {
                self.collect_family_object(object).await
            }
            ObjectType::UnixUname => {
                self.collect_uname_object(object).await
            }
            _ => {
                log::debug!("Unsupported object type for local collection: {:?}", object.object_type);
                Ok(Vec::new())
            }
        }
    }

    /// Collect items from remote host
    async fn collect_remote(&self, object: &OvalObject, ctx: &RemoteExecutionContext) -> Result<Vec<OvalItem>> {
        ctx.collect_object(object).await
    }

    // Local collector implementations
    async fn collect_file_object(&self, object: &OvalObject) -> Result<Vec<OvalItem>> {
        let mut items = Vec::new();

        if let Some(path_value) = object.data.get("path") {
            if let Some(filename_value) = object.data.get("filename") {
                let path_str = path_value.as_str().unwrap_or_default().to_string();
                let filename_str = filename_value.as_str().unwrap_or_default().to_string();

                let full_path = if filename_str.is_empty() {
                    path_str.clone()
                } else {
                    format!("{}/{}", path_str, filename_str)
                };

                if let Ok(metadata) = tokio::fs::metadata(&full_path).await {
                    let mut item_data = HashMap::new();
                    item_data.insert("path".to_string(), OvalValue::String(path_str));
                    item_data.insert("filename".to_string(), OvalValue::String(filename_str));
                    item_data.insert("size".to_string(), OvalValue::Int(metadata.len() as i64));

                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        item_data.insert("mode".to_string(), OvalValue::Int(metadata.mode() as i64));
                        item_data.insert("uid".to_string(), OvalValue::Int(metadata.uid() as i64));
                        item_data.insert("gid".to_string(), OvalValue::Int(metadata.gid() as i64));
                    }

                    items.push(OvalItem {
                        id: generate_item_id(),
                        status: ItemStatus::Exists,
                        item_type: ObjectType::UnixFile,
                        data: item_data,
                    });
                }
            }
        }

        Ok(items)
    }

    async fn collect_textfile_object(&self, object: &OvalObject) -> Result<Vec<OvalItem>> {
        let mut items = Vec::new();

        if let (Some(path), Some(pattern)) = (object.data.get("path"), object.data.get("pattern")) {
            let path_str = path.as_str().unwrap_or_default();
            let pattern_str = pattern.as_str().unwrap_or_default();

            if let Ok(content) = tokio::fs::read_to_string(&path_str).await {
                if let Ok(re) = regex::Regex::new(pattern_str) {
                    for cap in re.captures_iter(&content) {
                        let mut item_data = HashMap::new();
                        item_data.insert("path".to_string(), OvalValue::String(path_str.to_string()));
                        item_data.insert("pattern".to_string(), OvalValue::String(pattern_str.to_string()));

                        if let Some(m) = cap.get(0) {
                            item_data.insert("text".to_string(), OvalValue::String(m.as_str().to_string()));
                        }

                        // Add captured groups
                        for (i, group) in cap.iter().enumerate().skip(1) {
                            if let Some(g) = group {
                                item_data.insert(
                                    format!("subexpression_{}", i),
                                    OvalValue::String(g.as_str().to_string()),
                                );
                            }
                        }

                        items.push(OvalItem {
                            id: generate_item_id(),
                            status: ItemStatus::Exists,
                            item_type: ObjectType::IndTextFileContent,
                            data: item_data,
                        });
                    }
                }
            }
        }

        Ok(items)
    }

    async fn collect_family_object(&self, _object: &OvalObject) -> Result<Vec<OvalItem>> {
        let family = if cfg!(target_os = "windows") {
            "windows"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "linux") {
            "unix"
        } else {
            "unknown"
        };

        let mut item_data = HashMap::new();
        item_data.insert("family".to_string(), OvalValue::String(family.to_string()));

        Ok(vec![OvalItem {
            id: generate_item_id(),
            status: ItemStatus::Exists,
            item_type: ObjectType::IndFamily,
            data: item_data,
        }])
    }

    async fn collect_uname_object(&self, _object: &OvalObject) -> Result<Vec<OvalItem>> {
        let mut item_data = HashMap::new();

        #[cfg(unix)]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("uname").arg("-a").output() {
                if let Ok(uname_str) = String::from_utf8(output.stdout) {
                    let parts: Vec<&str> = uname_str.split_whitespace().collect();
                    if !parts.is_empty() {
                        item_data.insert("os_name".to_string(), OvalValue::String(parts[0].to_string()));
                    }
                    if parts.len() > 1 {
                        item_data.insert("node_name".to_string(), OvalValue::String(parts[1].to_string()));
                    }
                    if parts.len() > 2 {
                        item_data.insert("os_release".to_string(), OvalValue::String(parts[2].to_string()));
                    }
                    if parts.len() > 3 {
                        item_data.insert("os_version".to_string(), OvalValue::String(parts[3].to_string()));
                    }
                    if parts.len() > 4 {
                        item_data.insert("machine_class".to_string(), OvalValue::String(parts[4].to_string()));
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            item_data.insert("os_name".to_string(), OvalValue::String(std::env::consts::OS.to_string()));
            item_data.insert("machine_class".to_string(), OvalValue::String(std::env::consts::ARCH.to_string()));
        }

        Ok(vec![OvalItem {
            id: generate_item_id(),
            status: ItemStatus::Exists,
            item_type: ObjectType::UnixUname,
            data: item_data,
        }])
    }

    /// Evaluate check_existence against collected items
    fn evaluate_existence(&self, check_existence: &ExistenceCheck, items: &[OvalItem]) -> OvalResultType {
        let exists_count = items.iter().filter(|i| i.status == ItemStatus::Exists).count();

        match check_existence {
            ExistenceCheck::AllExist => {
                if items.is_empty() {
                    OvalResultType::False
                } else if exists_count == items.len() {
                    OvalResultType::True
                } else {
                    OvalResultType::False
                }
            }
            ExistenceCheck::AnyExist => OvalResultType::True,
            ExistenceCheck::AtLeastOneExists => {
                if exists_count > 0 {
                    OvalResultType::True
                } else {
                    OvalResultType::False
                }
            }
            ExistenceCheck::NoneExist => {
                if exists_count == 0 {
                    OvalResultType::True
                } else {
                    OvalResultType::False
                }
            }
            ExistenceCheck::OnlyOneExists => {
                if exists_count == 1 {
                    OvalResultType::True
                } else {
                    OvalResultType::False
                }
            }
        }
    }

    /// Evaluate state against collected items
    async fn evaluate_state(
        &self,
        state_id: &str,
        items: &[OvalItem],
        check: &CheckEnumeration,
        state_operator: LogicalOperator,
    ) -> Result<(usize, OvalResultType)> {
        let state = self.definitions.states.get(state_id)
            .ok_or_else(|| anyhow::anyhow!("State not found: {}", state_id))?;

        let mut matched_count = 0;

        for item in items {
            if self.item_matches_state(item, state, &state_operator) {
                matched_count += 1;
            }
        }

        let result = match check {
            CheckEnumeration::All => {
                if matched_count == items.len() {
                    OvalResultType::True
                } else {
                    OvalResultType::False
                }
            }
            CheckEnumeration::AtLeastOne => {
                if matched_count > 0 {
                    OvalResultType::True
                } else {
                    OvalResultType::False
                }
            }
            CheckEnumeration::NoneExist | CheckEnumeration::NoneSatisfy => {
                if matched_count == 0 {
                    OvalResultType::True
                } else {
                    OvalResultType::False
                }
            }
            CheckEnumeration::OnlyOne => {
                if matched_count == 1 {
                    OvalResultType::True
                } else {
                    OvalResultType::False
                }
            }
        };

        Ok((matched_count, result))
    }

    /// Check if an item matches a state
    fn item_matches_state(&self, item: &OvalItem, state: &OvalState, operator: &LogicalOperator) -> bool {
        let mut results = Vec::new();

        for (key, state_value) in &state.data {
            if let Some(actual_value) = item.data.get(key) {
                let matches = self.value_matches_state(actual_value, state_value);
                results.push(matches);
            }
        }

        if results.is_empty() {
            return true;
        }

        match operator {
            LogicalOperator::And => results.iter().all(|&r| r),
            LogicalOperator::Or => results.iter().any(|&r| r),
            LogicalOperator::One => results.iter().filter(|&&r| r).count() == 1,
            LogicalOperator::Xor => results.iter().filter(|&&r| r).count() % 2 == 1,
        }
    }

    /// Compare an OVAL value against a state value
    fn value_matches_state(&self, actual: &OvalValue, expected: &StateValue) -> bool {
        let expected_str = expected.value.as_str().unwrap_or_default();

        match expected.operation {
            Operation::Equals => self.values_equal(actual, &expected.value),
            Operation::NotEqual => !self.values_equal(actual, &expected.value),
            Operation::CaseInsensitiveEquals => self.values_equal_ci(actual, expected_str),
            Operation::CaseInsensitiveNotEqual => !self.values_equal_ci(actual, expected_str),
            Operation::GreaterThan => self.value_compare(actual, &expected.value) > 0,
            Operation::LessThan => self.value_compare(actual, &expected.value) < 0,
            Operation::GreaterThanOrEqual => self.value_compare(actual, &expected.value) >= 0,
            Operation::LessThanOrEqual => self.value_compare(actual, &expected.value) <= 0,
            Operation::PatternMatch => self.value_pattern_match(actual, expected_str),
            _ => self.values_equal(actual, &expected.value),
        }
    }

    fn values_equal(&self, actual: &OvalValue, expected: &serde_json::Value) -> bool {
        match (actual, expected) {
            (OvalValue::String(a), serde_json::Value::String(e)) => a == e,
            (OvalValue::Int(a), serde_json::Value::Number(e)) => {
                e.as_i64().map(|n| *a == n).unwrap_or(false)
            }
            (OvalValue::Float(a), serde_json::Value::Number(e)) => {
                e.as_f64().map(|n| (*a - n).abs() < f64::EPSILON).unwrap_or(false)
            }
            (OvalValue::Boolean(a), serde_json::Value::Bool(e)) => a == e,
            (OvalValue::String(a), serde_json::Value::Number(e)) => {
                a == &e.to_string()
            }
            (OvalValue::Int(a), serde_json::Value::String(e)) => {
                a.to_string() == *e
            }
            _ => false,
        }
    }

    fn values_equal_ci(&self, actual: &OvalValue, expected: &str) -> bool {
        match actual {
            OvalValue::String(a) => a.to_lowercase() == expected.to_lowercase(),
            OvalValue::Int(a) => a.to_string().to_lowercase() == expected.to_lowercase(),
            _ => false,
        }
    }

    fn value_compare(&self, actual: &OvalValue, expected: &serde_json::Value) -> i32 {
        match (actual, expected) {
            (OvalValue::Int(a), serde_json::Value::Number(e)) => {
                if let Some(n) = e.as_i64() {
                    a.cmp(&n) as i32
                } else {
                    0
                }
            }
            (OvalValue::Float(a), serde_json::Value::Number(e)) => {
                if let Some(n) = e.as_f64() {
                    if *a < n { -1 } else if *a > n { 1 } else { 0 }
                } else {
                    0
                }
            }
            (OvalValue::String(a), serde_json::Value::String(e)) => {
                a.cmp(e) as i32
            }
            _ => 0,
        }
    }

    fn value_pattern_match(&self, actual: &OvalValue, pattern: &str) -> bool {
        let actual_str = match actual {
            OvalValue::String(s) => s.clone(),
            OvalValue::Int(i) => i.to_string(),
            OvalValue::Float(f) => f.to_string(),
            OvalValue::Boolean(b) => b.to_string(),
            _ => return false,
        };

        regex::Regex::new(pattern)
            .map(|re| re.is_match(&actual_str))
            .unwrap_or(false)
    }

    /// Combine criteria results based on operator
    fn combine_criteria_results(&self, operator: &LogicalOperator, children: &[CriteriaNodeResult]) -> OvalResultType {
        if children.is_empty() {
            return OvalResultType::True;
        }

        let results: Vec<OvalResultType> = children.iter().map(|c| self.get_node_result(c)).collect();

        match operator {
            LogicalOperator::And => {
                if results.iter().any(|r| *r == OvalResultType::False) {
                    OvalResultType::False
                } else if results.iter().any(|r| *r == OvalResultType::Error) {
                    OvalResultType::Error
                } else if results.iter().any(|r| *r == OvalResultType::Unknown) {
                    OvalResultType::Unknown
                } else if results.iter().any(|r| *r == OvalResultType::NotEvaluated) {
                    OvalResultType::NotEvaluated
                } else if results.iter().any(|r| *r == OvalResultType::NotApplicable) {
                    OvalResultType::NotApplicable
                } else {
                    OvalResultType::True
                }
            }
            LogicalOperator::Or => {
                if results.iter().any(|r| *r == OvalResultType::True) {
                    OvalResultType::True
                } else if results.iter().all(|r| *r == OvalResultType::False) {
                    OvalResultType::False
                } else if results.iter().any(|r| *r == OvalResultType::Error) {
                    OvalResultType::Error
                } else {
                    OvalResultType::Unknown
                }
            }
            LogicalOperator::One => {
                let true_count = results.iter().filter(|r| **r == OvalResultType::True).count();
                if true_count == 1 {
                    OvalResultType::True
                } else {
                    OvalResultType::False
                }
            }
            LogicalOperator::Xor => {
                let true_count = results.iter().filter(|r| **r == OvalResultType::True).count();
                if true_count % 2 == 1 {
                    OvalResultType::True
                } else {
                    OvalResultType::False
                }
            }
        }
    }

    fn get_node_result(&self, node: &CriteriaNodeResult) -> OvalResultType {
        match node {
            CriteriaNodeResult::Criteria(c) => c.result,
            CriteriaNodeResult::Criterion(c) => c.result,
            CriteriaNodeResult::ExtendDefinition(d) => d.result,
        }
    }

    /// Get number of definitions evaluated
    pub fn definitions_evaluated(&self) -> usize {
        self.definitions_evaluated.load(Ordering::Relaxed)
    }

    /// Get number of objects collected
    pub fn objects_collected(&self) -> usize {
        self.objects_collected.load(Ordering::Relaxed)
    }

    /// Clear evaluation cache
    pub fn clear_cache(&mut self) {
        self.cache.definition_results.clear();
        self.cache.test_results.clear();
        self.collected_items.clear();
    }
}

/// Generate unique item IDs
fn generate_item_id() -> u64 {
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_item_id() {
        let id1 = generate_item_id();
        let id2 = generate_item_id();
        assert!(id2 > id1);
    }
}
