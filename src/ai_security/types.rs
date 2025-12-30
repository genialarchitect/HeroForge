//! Core types for AI/ML Security Operations
//!
//! Contains data structures for ML models, predictions, AI queries, and LLM security testing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

// ============================================================================
// ML Models
// ============================================================================

/// Type of ML model
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MLModelType {
    /// Classification model (e.g., binary or multi-class)
    Classification,
    /// Anomaly detection model
    AnomalyDetection,
    /// Natural language processing model
    Nlp,
    /// Regression model
    Regression,
}

impl std::fmt::Display for MLModelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLModelType::Classification => write!(f, "classification"),
            MLModelType::AnomalyDetection => write!(f, "anomaly_detection"),
            MLModelType::Nlp => write!(f, "nlp"),
            MLModelType::Regression => write!(f, "regression"),
        }
    }
}

/// Purpose of the ML model
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MLModelPurpose {
    /// Alert priority scoring
    AlertPriority,
    /// False positive prediction
    FpPrediction,
    /// Attack pattern detection
    AttackPattern,
    /// Anomaly detection
    AnomalyDetection,
    /// Query understanding
    QueryUnderstanding,
}

impl std::fmt::Display for MLModelPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLModelPurpose::AlertPriority => write!(f, "alert_priority"),
            MLModelPurpose::FpPrediction => write!(f, "fp_prediction"),
            MLModelPurpose::AttackPattern => write!(f, "attack_pattern"),
            MLModelPurpose::AnomalyDetection => write!(f, "anomaly_detection"),
            MLModelPurpose::QueryUnderstanding => write!(f, "query_understanding"),
        }
    }
}

/// Status of the ML model
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MLModelStatus {
    /// Model is being trained
    Training,
    /// Model is active and ready for predictions
    Active,
    /// Model has been retired
    Retired,
    /// Model training failed
    Failed,
}

impl std::fmt::Display for MLModelStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MLModelStatus::Training => write!(f, "training"),
            MLModelStatus::Active => write!(f, "active"),
            MLModelStatus::Retired => write!(f, "retired"),
            MLModelStatus::Failed => write!(f, "failed"),
        }
    }
}

/// ML Model definition
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MLModel {
    pub id: String,
    pub name: String,
    pub model_type: MLModelType,
    pub purpose: MLModelPurpose,
    pub version: String,
    pub algorithm: Option<String>,
    pub training_data_size: Option<i64>,
    pub accuracy: Option<f64>,
    pub precision_score: Option<f64>,
    pub recall_score: Option<f64>,
    pub f1_score: Option<f64>,
    pub model_path: Option<String>,
    pub status: MLModelStatus,
    pub trained_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Database record for ML model
#[derive(Debug, Clone, FromRow)]
pub struct MLModelRecord {
    pub id: String,
    pub name: String,
    pub model_type: String,
    pub purpose: String,
    pub version: String,
    pub algorithm: Option<String>,
    pub training_data_size: Option<i64>,
    pub accuracy: Option<f64>,
    pub precision_score: Option<f64>,
    pub recall_score: Option<f64>,
    pub f1_score: Option<f64>,
    pub model_path: Option<String>,
    pub status: String,
    pub trained_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<MLModelRecord> for MLModel {
    fn from(r: MLModelRecord) -> Self {
        let model_type = match r.model_type.as_str() {
            "classification" => MLModelType::Classification,
            "anomaly_detection" => MLModelType::AnomalyDetection,
            "nlp" => MLModelType::Nlp,
            "regression" => MLModelType::Regression,
            _ => MLModelType::Classification,
        };
        let purpose = match r.purpose.as_str() {
            "alert_priority" => MLModelPurpose::AlertPriority,
            "fp_prediction" => MLModelPurpose::FpPrediction,
            "attack_pattern" => MLModelPurpose::AttackPattern,
            "anomaly_detection" => MLModelPurpose::AnomalyDetection,
            "query_understanding" => MLModelPurpose::QueryUnderstanding,
            _ => MLModelPurpose::AlertPriority,
        };
        let status = match r.status.as_str() {
            "training" => MLModelStatus::Training,
            "active" => MLModelStatus::Active,
            "retired" => MLModelStatus::Retired,
            "failed" => MLModelStatus::Failed,
            _ => MLModelStatus::Training,
        };
        Self {
            id: r.id,
            name: r.name,
            model_type,
            purpose,
            version: r.version,
            algorithm: r.algorithm,
            training_data_size: r.training_data_size,
            accuracy: r.accuracy,
            precision_score: r.precision_score,
            recall_score: r.recall_score,
            f1_score: r.f1_score,
            model_path: r.model_path,
            status,
            trained_at: r.trained_at,
            last_used_at: r.last_used_at,
            created_at: r.created_at,
        }
    }
}

// ============================================================================
// ML Predictions
// ============================================================================

/// Feedback type for predictions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PredictionFeedback {
    Correct,
    Incorrect,
}

impl std::fmt::Display for PredictionFeedback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PredictionFeedback::Correct => write!(f, "correct"),
            PredictionFeedback::Incorrect => write!(f, "incorrect"),
        }
    }
}

/// Entity type for predictions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PredictionEntityType {
    Alert,
    Finding,
    Event,
    Vulnerability,
}

impl std::fmt::Display for PredictionEntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PredictionEntityType::Alert => write!(f, "alert"),
            PredictionEntityType::Finding => write!(f, "finding"),
            PredictionEntityType::Event => write!(f, "event"),
            PredictionEntityType::Vulnerability => write!(f, "vulnerability"),
        }
    }
}

/// ML Prediction result
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MLPrediction {
    pub id: String,
    pub model_id: String,
    pub entity_type: PredictionEntityType,
    pub entity_id: String,
    pub prediction: serde_json::Value,
    pub confidence: f64,
    pub explanation: Option<serde_json::Value>,
    pub feedback: Option<PredictionFeedback>,
    pub created_at: DateTime<Utc>,
}

/// Database record for ML prediction
#[derive(Debug, Clone, FromRow)]
pub struct MLPredictionRecord {
    pub id: String,
    pub model_id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub prediction: String,
    pub confidence: f64,
    pub explanation: Option<String>,
    pub feedback: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<MLPredictionRecord> for MLPrediction {
    fn from(r: MLPredictionRecord) -> Self {
        let entity_type = match r.entity_type.as_str() {
            "alert" => PredictionEntityType::Alert,
            "finding" => PredictionEntityType::Finding,
            "event" => PredictionEntityType::Event,
            "vulnerability" => PredictionEntityType::Vulnerability,
            _ => PredictionEntityType::Alert,
        };
        let feedback = r.feedback.as_ref().map(|f| match f.as_str() {
            "correct" => PredictionFeedback::Correct,
            "incorrect" => PredictionFeedback::Incorrect,
            _ => PredictionFeedback::Correct,
        });
        Self {
            id: r.id,
            model_id: r.model_id,
            entity_type,
            entity_id: r.entity_id,
            prediction: serde_json::from_str(&r.prediction).unwrap_or(serde_json::Value::Null),
            confidence: r.confidence,
            explanation: r.explanation.and_then(|e| serde_json::from_str(&e).ok()),
            feedback,
            created_at: r.created_at,
        }
    }
}

// ============================================================================
// AI Queries (Natural Language)
// ============================================================================

/// Type of AI query
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AIQueryType {
    Search,
    Analysis,
    Report,
    Remediation,
    Investigation,
}

impl std::fmt::Display for AIQueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AIQueryType::Search => write!(f, "search"),
            AIQueryType::Analysis => write!(f, "analysis"),
            AIQueryType::Report => write!(f, "report"),
            AIQueryType::Remediation => write!(f, "remediation"),
            AIQueryType::Investigation => write!(f, "investigation"),
        }
    }
}

/// Parsed intent from natural language query
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ParsedIntent {
    pub query_type: AIQueryType,
    pub entities: Vec<ExtractedEntity>,
    pub filters: Vec<QueryFilter>,
    pub time_range: Option<TimeRange>,
    pub confidence: f64,
}

/// Extracted entity from query
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ExtractedEntity {
    pub entity_type: String,
    pub value: String,
    pub start_pos: usize,
    pub end_pos: usize,
    pub confidence: f64,
}

/// Query filter
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct QueryFilter {
    pub field: String,
    pub operator: String,
    pub value: serde_json::Value,
}

/// Time range for queries
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TimeRange {
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub relative: Option<String>,
}

/// AI Query record
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AIQuery {
    pub id: String,
    pub user_id: String,
    pub query_text: String,
    pub query_type: Option<AIQueryType>,
    pub parsed_intent: Option<ParsedIntent>,
    pub results: Option<serde_json::Value>,
    pub feedback: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Database record for AI query
#[derive(Debug, Clone, FromRow)]
pub struct AIQueryRecord {
    pub id: String,
    pub user_id: String,
    pub query_text: String,
    pub query_type: Option<String>,
    pub parsed_intent: Option<String>,
    pub results: Option<String>,
    pub feedback: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<AIQueryRecord> for AIQuery {
    fn from(r: AIQueryRecord) -> Self {
        let query_type = r.query_type.as_ref().map(|qt| match qt.as_str() {
            "search" => AIQueryType::Search,
            "analysis" => AIQueryType::Analysis,
            "report" => AIQueryType::Report,
            "remediation" => AIQueryType::Remediation,
            "investigation" => AIQueryType::Investigation,
            _ => AIQueryType::Search,
        });
        Self {
            id: r.id,
            user_id: r.user_id,
            query_text: r.query_text,
            query_type,
            parsed_intent: r.parsed_intent.and_then(|p| serde_json::from_str(&p).ok()),
            results: r.results.and_then(|r| serde_json::from_str(&r).ok()),
            feedback: r.feedback,
            created_at: r.created_at,
        }
    }
}

// ============================================================================
// LLM Security Testing
// ============================================================================

/// Type of LLM target being tested
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LLMTargetType {
    Api,
    Chatbot,
    Application,
    Embeddings,
    AgentSystem,
}

impl std::fmt::Display for LLMTargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LLMTargetType::Api => write!(f, "api"),
            LLMTargetType::Chatbot => write!(f, "chatbot"),
            LLMTargetType::Application => write!(f, "application"),
            LLMTargetType::Embeddings => write!(f, "embeddings"),
            LLMTargetType::AgentSystem => write!(f, "agent_system"),
        }
    }
}

/// Type of LLM security test
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LLMTestType {
    PromptInjection,
    Jailbreak,
    DataExtraction,
    All,
}

impl std::fmt::Display for LLMTestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LLMTestType::PromptInjection => write!(f, "prompt_injection"),
            LLMTestType::Jailbreak => write!(f, "jailbreak"),
            LLMTestType::DataExtraction => write!(f, "data_extraction"),
            LLMTestType::All => write!(f, "all"),
        }
    }
}

/// Status of an LLM security test
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LLMTestStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for LLMTestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LLMTestStatus::Pending => write!(f, "pending"),
            LLMTestStatus::Running => write!(f, "running"),
            LLMTestStatus::Completed => write!(f, "completed"),
            LLMTestStatus::Failed => write!(f, "failed"),
            LLMTestStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// LLM target configuration
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LLMTargetConfig {
    /// API endpoint URL
    pub endpoint: String,
    /// Authentication method
    pub auth_type: Option<String>,
    /// API key or token (masked in responses)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Custom headers
    pub headers: Option<std::collections::HashMap<String, String>>,
    /// Request template (e.g., for chat APIs)
    pub request_template: Option<String>,
    /// Response path to extract LLM output
    pub response_path: Option<String>,
    /// Rate limit (requests per minute)
    pub rate_limit: Option<u32>,
    /// Timeout in seconds
    pub timeout: Option<u32>,
}

/// LLM Security Test
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LLMSecurityTest {
    pub id: String,
    pub user_id: String,
    pub target_name: String,
    pub target_type: LLMTargetType,
    pub target_config: Option<LLMTargetConfig>,
    pub test_type: LLMTestType,
    pub status: LLMTestStatus,
    pub tests_run: i64,
    pub vulnerabilities_found: i64,
    pub results: Option<serde_json::Value>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Database record for LLM security test
#[derive(Debug, Clone, FromRow)]
pub struct LLMSecurityTestRecord {
    pub id: String,
    pub user_id: String,
    pub target_name: String,
    pub target_type: String,
    pub target_config: Option<String>,
    pub test_type: String,
    pub status: String,
    pub tests_run: i64,
    pub vulnerabilities_found: i64,
    pub results: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<LLMSecurityTestRecord> for LLMSecurityTest {
    fn from(r: LLMSecurityTestRecord) -> Self {
        let target_type = match r.target_type.as_str() {
            "api" => LLMTargetType::Api,
            "chatbot" => LLMTargetType::Chatbot,
            "application" => LLMTargetType::Application,
            "embeddings" => LLMTargetType::Embeddings,
            "agent_system" => LLMTargetType::AgentSystem,
            _ => LLMTargetType::Api,
        };
        let test_type = match r.test_type.as_str() {
            "prompt_injection" => LLMTestType::PromptInjection,
            "jailbreak" => LLMTestType::Jailbreak,
            "data_extraction" => LLMTestType::DataExtraction,
            "all" => LLMTestType::All,
            _ => LLMTestType::All,
        };
        let status = match r.status.as_str() {
            "pending" => LLMTestStatus::Pending,
            "running" => LLMTestStatus::Running,
            "completed" => LLMTestStatus::Completed,
            "failed" => LLMTestStatus::Failed,
            "cancelled" => LLMTestStatus::Cancelled,
            _ => LLMTestStatus::Pending,
        };
        Self {
            id: r.id,
            user_id: r.user_id,
            target_name: r.target_name,
            target_type,
            target_config: r.target_config.and_then(|c| serde_json::from_str(&c).ok()),
            test_type,
            status,
            tests_run: r.tests_run,
            vulnerabilities_found: r.vulnerabilities_found,
            results: r.results.and_then(|r| serde_json::from_str(&r).ok()),
            started_at: r.started_at,
            completed_at: r.completed_at,
            customer_id: r.customer_id,
            engagement_id: r.engagement_id,
            created_at: r.created_at,
        }
    }
}

// ============================================================================
// LLM Test Cases
// ============================================================================

/// Category of LLM test case
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LLMTestCategory {
    PromptInjection,
    Jailbreak,
    Encoding,
    ContextManipulation,
    DataExtraction,
    RoleConfusion,
    ChainOfThought,
    IndirectInjection,
}

impl std::fmt::Display for LLMTestCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LLMTestCategory::PromptInjection => write!(f, "prompt_injection"),
            LLMTestCategory::Jailbreak => write!(f, "jailbreak"),
            LLMTestCategory::Encoding => write!(f, "encoding"),
            LLMTestCategory::ContextManipulation => write!(f, "context_manipulation"),
            LLMTestCategory::DataExtraction => write!(f, "data_extraction"),
            LLMTestCategory::RoleConfusion => write!(f, "role_confusion"),
            LLMTestCategory::ChainOfThought => write!(f, "chain_of_thought"),
            LLMTestCategory::IndirectInjection => write!(f, "indirect_injection"),
        }
    }
}

/// Severity of a test case
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TestCaseSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for TestCaseSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestCaseSeverity::Critical => write!(f, "critical"),
            TestCaseSeverity::High => write!(f, "high"),
            TestCaseSeverity::Medium => write!(f, "medium"),
            TestCaseSeverity::Low => write!(f, "low"),
            TestCaseSeverity::Info => write!(f, "info"),
        }
    }
}

/// LLM Test Case definition
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LLMTestCase {
    pub id: String,
    pub category: LLMTestCategory,
    pub name: String,
    pub description: Option<String>,
    pub payload: String,
    pub expected_behavior: Option<String>,
    pub severity: TestCaseSeverity,
    pub cwe_id: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

/// Database record for LLM test case
#[derive(Debug, Clone, FromRow)]
pub struct LLMTestCaseRecord {
    pub id: String,
    pub category: String,
    pub name: String,
    pub description: Option<String>,
    pub payload: String,
    pub expected_behavior: Option<String>,
    pub severity: Option<String>,
    pub cwe_id: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

impl From<LLMTestCaseRecord> for LLMTestCase {
    fn from(r: LLMTestCaseRecord) -> Self {
        let category = match r.category.as_str() {
            "prompt_injection" => LLMTestCategory::PromptInjection,
            "jailbreak" => LLMTestCategory::Jailbreak,
            "encoding" => LLMTestCategory::Encoding,
            "context_manipulation" => LLMTestCategory::ContextManipulation,
            "data_extraction" => LLMTestCategory::DataExtraction,
            "role_confusion" => LLMTestCategory::RoleConfusion,
            "chain_of_thought" => LLMTestCategory::ChainOfThought,
            "indirect_injection" => LLMTestCategory::IndirectInjection,
            _ => LLMTestCategory::PromptInjection,
        };
        let severity = r.severity.as_ref().map(|s| match s.as_str() {
            "critical" => TestCaseSeverity::Critical,
            "high" => TestCaseSeverity::High,
            "medium" => TestCaseSeverity::Medium,
            "low" => TestCaseSeverity::Low,
            "info" => TestCaseSeverity::Info,
            _ => TestCaseSeverity::Medium,
        }).unwrap_or(TestCaseSeverity::Medium);
        Self {
            id: r.id,
            category,
            name: r.name,
            description: r.description,
            payload: r.payload,
            expected_behavior: r.expected_behavior,
            severity,
            cwe_id: r.cwe_id,
            enabled: r.enabled,
            created_at: r.created_at,
        }
    }
}

// ============================================================================
// API Request/Response Types
// ============================================================================

/// Request to create a prediction
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreatePredictionRequest {
    pub model_id: Option<String>,
    pub entity_type: PredictionEntityType,
    pub entity_id: String,
    pub entity_data: Option<serde_json::Value>,
}

/// Batch prediction request
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BatchPredictionRequest {
    pub model_id: Option<String>,
    pub entity_type: PredictionEntityType,
    pub entity_ids: Vec<String>,
}

/// Prediction feedback request
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PredictionFeedbackRequest {
    pub prediction_id: String,
    pub feedback: PredictionFeedback,
    pub notes: Option<String>,
}

/// Natural language query request
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AIQueryRequest {
    pub query: String,
    pub context: Option<serde_json::Value>,
}

/// Request to start an LLM security test
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct StartLLMTestRequest {
    pub target_name: String,
    pub target_type: LLMTargetType,
    pub target_config: LLMTargetConfig,
    pub test_type: LLMTestType,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Request to create a custom LLM test case
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateTestCaseRequest {
    pub category: LLMTestCategory,
    pub name: String,
    pub description: Option<String>,
    pub payload: String,
    pub expected_behavior: Option<String>,
    pub severity: TestCaseSeverity,
    pub cwe_id: Option<String>,
}

/// AI Dashboard data
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AIDashboard {
    /// Total predictions made
    pub total_predictions: i64,
    /// Prediction accuracy (based on feedback)
    pub prediction_accuracy: f64,
    /// Active models count
    pub active_models: i64,
    /// Total LLM tests run
    pub llm_tests_run: i64,
    /// LLM vulnerabilities found
    pub llm_vulns_found: i64,
    /// Anomalies detected
    pub anomalies_detected: i64,
    /// False positive rate
    pub false_positive_rate: f64,
    /// Model performance metrics
    pub model_metrics: Vec<ModelMetrics>,
    /// Recent predictions
    pub recent_predictions: Vec<MLPrediction>,
    /// Recent LLM tests
    pub recent_llm_tests: Vec<LLMSecurityTest>,
}

/// Model performance metrics
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ModelMetrics {
    pub model_id: String,
    pub model_name: String,
    pub model_type: MLModelType,
    pub predictions_count: i64,
    pub accuracy: Option<f64>,
    pub avg_confidence: f64,
    pub feedback_count: i64,
}

/// Security recommendation from AI
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SecurityRecommendation {
    pub id: String,
    pub title: String,
    pub description: String,
    pub priority: String,
    pub category: String,
    pub affected_entities: Vec<String>,
    pub remediation_steps: Vec<String>,
    pub confidence: f64,
    pub source: String,
}

/// LLM Test Result
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LLMTestResult {
    pub test_case_id: String,
    pub test_case_name: String,
    pub category: LLMTestCategory,
    pub payload_sent: String,
    pub response_received: String,
    pub vulnerable: bool,
    pub severity: TestCaseSeverity,
    pub confidence: f64,
    pub indicators: Vec<String>,
    pub cwe_id: Option<String>,
    pub remediation: Option<String>,
}

/// LLM Test Summary
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LLMTestSummary {
    pub total_tests: i64,
    pub passed: i64,
    pub failed: i64,
    pub vulnerabilities_by_category: std::collections::HashMap<String, i64>,
    pub vulnerabilities_by_severity: std::collections::HashMap<String, i64>,
    pub overall_risk_score: f64,
}
