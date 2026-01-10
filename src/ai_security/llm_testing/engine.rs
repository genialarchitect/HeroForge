//! LLM Security Testing Engine
//!
//! Orchestrates security testing of LLM-based applications.

use anyhow::Result;
use log::{error, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};

use super::analysis::ResponseAnalyzer;
use super::payloads::{get_builtin_test_cases, get_test_cases_by_category, BuiltinTestCase};
use super::super::types::{
    LLMSecurityTest, LLMTargetConfig, LLMTestCategory, LLMTestResult,
    LLMTestStatus, LLMTestSummary, LLMTestType, TestCaseSeverity,
};

/// Progress update during test execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestProgress {
    pub test_id: String,
    pub current_test: usize,
    pub total_tests: usize,
    pub current_category: LLMTestCategory,
    pub status: LLMTestStatus,
    pub vulnerabilities_found: usize,
}

/// Test execution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestExecutionConfig {
    /// Delay between requests in milliseconds
    pub delay_ms: u64,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Maximum concurrent requests
    pub max_concurrent: usize,
    /// Stop on first critical vulnerability
    pub stop_on_critical: bool,
    /// Categories to test
    pub categories: Option<Vec<LLMTestCategory>>,
    /// Maximum tests per category
    pub max_tests_per_category: Option<usize>,
}

impl Default for TestExecutionConfig {
    fn default() -> Self {
        Self {
            delay_ms: 500,
            timeout_secs: 30,
            max_concurrent: 3,
            stop_on_critical: false,
            categories: None,
            max_tests_per_category: None,
        }
    }
}

/// LLM Security Testing Engine
pub struct LLMTestingEngine {
    http_client: Client,
    analyzer: ResponseAnalyzer,
    config: TestExecutionConfig,
    custom_test_cases: Vec<BuiltinTestCase>,
}

impl LLMTestingEngine {
    /// Create a new testing engine
    pub fn new() -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            http_client,
            analyzer: ResponseAnalyzer::new(),
            config: TestExecutionConfig::default(),
            custom_test_cases: Vec::new(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: TestExecutionConfig) -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            http_client,
            analyzer: ResponseAnalyzer::new(),
            config,
            custom_test_cases: Vec::new(),
        }
    }

    /// Add custom test cases
    pub fn add_custom_tests(&mut self, tests: Vec<BuiltinTestCase>) {
        self.custom_test_cases.extend(tests);
    }

    /// Get test cases to run based on test type
    fn get_test_cases(&self, test_type: LLMTestType) -> Vec<BuiltinTestCase> {
        let mut cases = match test_type {
            LLMTestType::PromptInjection => {
                get_test_cases_by_category(LLMTestCategory::PromptInjection)
            }
            LLMTestType::Jailbreak => {
                get_test_cases_by_category(LLMTestCategory::Jailbreak)
            }
            LLMTestType::DataExtraction => {
                get_test_cases_by_category(LLMTestCategory::DataExtraction)
            }
            LLMTestType::All => {
                get_builtin_test_cases()
            }
        };

        // Add custom test cases
        if test_type == LLMTestType::All {
            cases.extend(self.custom_test_cases.clone());
        } else {
            let category = match test_type {
                LLMTestType::PromptInjection => LLMTestCategory::PromptInjection,
                LLMTestType::Jailbreak => LLMTestCategory::Jailbreak,
                LLMTestType::DataExtraction => LLMTestCategory::DataExtraction,
                _ => return cases,
            };
            cases.extend(
                self.custom_test_cases
                    .iter()
                    .filter(|c| c.category == category)
                    .cloned(),
            );
        }

        // Apply category filter if specified
        if let Some(ref categories) = self.config.categories {
            cases.retain(|c| categories.contains(&c.category));
        }

        // Apply max tests per category
        if let Some(max) = self.config.max_tests_per_category {
            let mut category_counts: HashMap<LLMTestCategory, usize> = HashMap::new();
            cases.retain(|c| {
                let count = category_counts.entry(c.category).or_insert(0);
                if *count < max {
                    *count += 1;
                    true
                } else {
                    false
                }
            });
        }

        cases
    }

    /// Execute a security test against an LLM target
    pub async fn execute_test(
        &self,
        test: &LLMSecurityTest,
        progress_tx: Option<mpsc::Sender<TestProgress>>,
    ) -> Result<(Vec<LLMTestResult>, LLMTestSummary)> {
        let target_config = test.target_config.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Target configuration is required"))?;

        let test_cases = self.get_test_cases(test.test_type);
        let total_tests = test_cases.len();

        info!(
            "Starting LLM security test {} with {} test cases against {}",
            test.id, total_tests, test.target_name
        );

        let mut results: Vec<LLMTestResult> = Vec::new();
        let mut vulnerabilities_found = 0;

        for (index, test_case) in test_cases.iter().enumerate() {
            // Send progress update
            if let Some(ref tx) = progress_tx {
                let _ = tx.send(TestProgress {
                    test_id: test.id.clone(),
                    current_test: index + 1,
                    total_tests,
                    current_category: test_case.category,
                    status: LLMTestStatus::Running,
                    vulnerabilities_found,
                }).await;
            }

            // Execute single test
            let result = match self.execute_single_test(target_config, test_case).await {
                Ok(r) => r,
                Err(e) => {
                    warn!("Test case {} failed: {}", test_case.id, e);
                    // Create a failed result
                    LLMTestResult {
                        test_case_id: test_case.id.to_string(),
                        test_case_name: test_case.name.to_string(),
                        category: test_case.category,
                        payload_sent: test_case.payload.to_string(),
                        response_received: format!("Error: {}", e),
                        vulnerable: false,
                        severity: test_case.severity,
                        confidence: 0.0,
                        indicators: vec![format!("Test execution failed: {}", e)],
                        cwe_id: test_case.cwe_id.map(|s| s.to_string()),
                        remediation: None,
                    }
                }
            };

            if result.vulnerable {
                vulnerabilities_found += 1;
                info!(
                    "Vulnerability found: {} ({})",
                    test_case.name, test_case.category
                );

                // Check for critical stop
                if self.config.stop_on_critical && result.severity == TestCaseSeverity::Critical {
                    warn!("Stopping test due to critical vulnerability: {}", test_case.name);
                    results.push(result);
                    break;
                }
            }

            results.push(result);

            // Rate limiting delay
            if index < total_tests - 1 {
                tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
            }
        }

        // Generate summary
        let summary = self.analyzer.generate_summary(&results);

        info!(
            "LLM security test {} completed: {}/{} tests, {} vulnerabilities",
            test.id, results.len(), total_tests, vulnerabilities_found
        );

        Ok((results, summary))
    }

    /// Execute a single test case
    async fn execute_single_test(
        &self,
        config: &LLMTargetConfig,
        test_case: &BuiltinTestCase,
    ) -> Result<LLMTestResult> {
        // Build request based on target type
        let response = self.send_payload(config, test_case.payload).await?;

        // Analyze response
        let result = self.analyzer.to_test_result(
            test_case.id,
            test_case.name,
            test_case.category,
            test_case.payload,
            &response,
            test_case.severity,
            test_case.cwe_id.map(|s| s.to_string()),
        );

        Ok(result)
    }

    /// Send payload to target LLM
    async fn send_payload(&self, config: &LLMTargetConfig, payload: &str) -> Result<String> {
        // Build request body using template or default format
        let body = if let Some(ref template) = config.request_template {
            template.replace("{{payload}}", payload)
                .replace("{{message}}", payload)
                .replace("{{input}}", payload)
        } else {
            // Default OpenAI-compatible format
            serde_json::json!({
                "model": "gpt-4",
                "messages": [
                    {"role": "user", "content": payload}
                ],
                "temperature": 0.0,
                "max_tokens": 1000
            }).to_string()
        };

        // Build request
        let mut request = self.http_client.post(&config.endpoint)
            .header("Content-Type", "application/json");

        // Add authentication
        if let Some(ref api_key) = config.api_key {
            if config.auth_type.as_deref() == Some("bearer") {
                request = request.header("Authorization", format!("Bearer {}", api_key));
            } else if config.auth_type.as_deref() == Some("api_key") {
                request = request.header("x-api-key", api_key);
            } else {
                // Default to Bearer
                request = request.header("Authorization", format!("Bearer {}", api_key));
            }
        }

        // Add custom headers
        if let Some(ref headers) = config.headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        // Send request
        let response = request.body(body).send().await?;

        // Check status
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "API request failed with status {}: {}",
                status,
                text
            ));
        }

        // Parse response
        let response_text = response.text().await?;

        // Extract content from response using response_path if configured
        if let Some(ref path) = config.response_path {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response_text) {
                // Simple path extraction (e.g., "choices.0.message.content")
                let content = self.extract_json_path(&json, path);
                if let Some(content) = content {
                    return Ok(content);
                }
            }
        }

        // Try to extract content from common response formats
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response_text) {
            // OpenAI format
            if let Some(content) = json.get("choices")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("message"))
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_str())
            {
                return Ok(content.to_string());
            }

            // Anthropic format
            if let Some(content) = json.get("content")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("text"))
                .and_then(|t| t.as_str())
            {
                return Ok(content.to_string());
            }

            // Simple text field
            if let Some(text) = json.get("text").and_then(|t| t.as_str()) {
                return Ok(text.to_string());
            }

            // Response field
            if let Some(response) = json.get("response").and_then(|r| r.as_str()) {
                return Ok(response.to_string());
            }
        }

        // Return raw response if parsing fails
        Ok(response_text)
    }

    /// Extract value from JSON using dot-notation path
    fn extract_json_path(&self, json: &serde_json::Value, path: &str) -> Option<String> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = json;

        for part in parts {
            if let Ok(index) = part.parse::<usize>() {
                current = current.get(index)?;
            } else {
                current = current.get(part)?;
            }
        }

        current.as_str().map(|s| s.to_string())
    }

    /// Run a quick test with a single payload
    pub async fn quick_test(
        &self,
        config: &LLMTargetConfig,
        payload: &str,
        category: LLMTestCategory,
    ) -> Result<LLMTestResult> {
        let response = self.send_payload(config, payload).await?;

        Ok(self.analyzer.to_test_result(
            "quick-test",
            "Quick Test",
            category,
            payload,
            &response,
            TestCaseSeverity::Medium,
            None,
        ))
    }

    /// Validate target configuration by sending a benign request
    pub async fn validate_target(&self, config: &LLMTargetConfig) -> Result<bool> {
        let test_payload = "Hello, please respond with 'OK' if you can read this message.";

        match self.send_payload(config, test_payload).await {
            Ok(response) => {
                // Check if we got a reasonable response
                let response_lower = response.to_lowercase();
                let valid = response.len() > 0
                    && (response_lower.contains("ok")
                        || response_lower.contains("hello")
                        || response_lower.contains("yes")
                        || response_lower.contains("hi")
                        || response.len() > 10);
                Ok(valid)
            }
            Err(e) => {
                error!("Target validation failed: {}", e);
                Err(e)
            }
        }
    }
}

impl Default for LLMTestingEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// LLM Security Test Manager (for database-backed tests)
pub struct LLMTestManager {
    engine: LLMTestingEngine,
    active_tests: Arc<RwLock<HashMap<String, tokio::task::JoinHandle<()>>>>,
}

impl LLMTestManager {
    /// Create a new test manager
    pub fn new() -> Self {
        Self {
            engine: LLMTestingEngine::new(),
            active_tests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with custom engine configuration
    pub fn with_engine(engine: LLMTestingEngine) -> Self {
        Self {
            engine,
            active_tests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the testing engine
    pub fn engine(&self) -> &LLMTestingEngine {
        &self.engine
    }

    /// Check if a test is running
    pub async fn is_test_running(&self, test_id: &str) -> bool {
        let tests = self.active_tests.read().await;
        tests.get(test_id).map(|h| !h.is_finished()).unwrap_or(false)
    }

    /// Cancel a running test
    pub async fn cancel_test(&self, test_id: &str) -> bool {
        let mut tests = self.active_tests.write().await;
        if let Some(handle) = tests.remove(test_id) {
            handle.abort();
            true
        } else {
            false
        }
    }

    /// Get count of active tests
    pub async fn active_test_count(&self) -> usize {
        let tests = self.active_tests.read().await;
        tests.values().filter(|h| !h.is_finished()).count()
    }

    /// Cleanup finished tests
    pub async fn cleanup_finished(&self) {
        let mut tests = self.active_tests.write().await;
        tests.retain(|_, handle| !handle.is_finished());
    }
}

impl Default for LLMTestManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_test_cases() {
        let engine = LLMTestingEngine::new();

        let all_cases = engine.get_test_cases(LLMTestType::All);
        assert!(!all_cases.is_empty());

        let injection_cases = engine.get_test_cases(LLMTestType::PromptInjection);
        assert!(injection_cases.iter().all(|c| c.category == LLMTestCategory::PromptInjection));

        let jailbreak_cases = engine.get_test_cases(LLMTestType::Jailbreak);
        assert!(jailbreak_cases.iter().all(|c| c.category == LLMTestCategory::Jailbreak));
    }

    #[test]
    fn test_category_filtering() {
        let config = TestExecutionConfig {
            categories: Some(vec![LLMTestCategory::PromptInjection]),
            ..Default::default()
        };
        let engine = LLMTestingEngine::with_config(config);

        let cases = engine.get_test_cases(LLMTestType::All);
        assert!(cases.iter().all(|c| c.category == LLMTestCategory::PromptInjection));
    }

    #[test]
    fn test_max_tests_per_category() {
        let config = TestExecutionConfig {
            max_tests_per_category: Some(3),
            ..Default::default()
        };
        let engine = LLMTestingEngine::with_config(config);

        let cases = engine.get_test_cases(LLMTestType::All);

        // Count per category
        let mut counts: HashMap<LLMTestCategory, usize> = HashMap::new();
        for case in cases {
            *counts.entry(case.category).or_insert(0) += 1;
        }

        for (_, count) in counts {
            assert!(count <= 3);
        }
    }
}
