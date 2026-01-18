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

// ============================================================================
// Multi-Turn Conversation Testing
// ============================================================================

/// Message role in a conversation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    User,
    Assistant,
    System,
}

impl std::fmt::Display for MessageRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageRole::User => write!(f, "user"),
            MessageRole::Assistant => write!(f, "assistant"),
            MessageRole::System => write!(f, "system"),
        }
    }
}

/// A single turn in a multi-turn conversation test
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConversationTurn {
    /// Turn number (0-indexed)
    pub turn_number: usize,
    /// Role of the message sender
    pub role: MessageRole,
    /// Content of the message
    pub content: String,
    /// Whether to wait for a response before continuing
    pub wait_for_response: bool,
    /// Whether to analyze the response for vulnerabilities
    pub analyze_response: bool,
    /// Patterns indicating successful attack at this turn
    pub success_indicators: Vec<String>,
    /// Patterns that indicate the attack should be aborted
    pub abort_indicators: Vec<String>,
}

/// Success criteria for a conversation test
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SuccessCriteria {
    /// Minimum number of turns that must succeed
    pub min_successful_turns: usize,
    /// Whether all turns must succeed
    pub require_all_turns: bool,
    /// Specific turn that must succeed for the test to pass
    pub critical_turn: Option<usize>,
    /// Patterns in final response indicating overall success
    pub final_success_patterns: Vec<String>,
}

/// Multi-turn conversation test definition
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConversationTest {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: LLMTestCategory,
    pub turns: Vec<ConversationTurn>,
    pub success_criteria: SuccessCriteria,
    pub severity: TestCaseSeverity,
    /// Whether this is a built-in test
    pub is_builtin: bool,
    pub created_at: DateTime<Utc>,
}

/// Result of a single turn in a conversation test
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TurnResult {
    pub turn_number: usize,
    pub prompt_sent: String,
    pub response_received: String,
    pub success_indicators_matched: Vec<String>,
    pub abort_indicators_matched: Vec<String>,
    pub analysis: Option<TurnAnalysis>,
    pub duration_ms: u64,
}

/// Analysis results for a single turn
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TurnAnalysis {
    pub vulnerable: bool,
    pub confidence: f64,
    pub indicators: Vec<String>,
    pub risk_score: f64,
}

/// Result of a multi-turn conversation test
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConversationTestResult {
    pub test_id: String,
    pub test_name: String,
    pub category: LLMTestCategory,
    pub turns_executed: Vec<TurnResult>,
    pub final_status: ConversationTestStatus,
    pub vulnerability_detected_at_turn: Option<usize>,
    pub conversation_history: Vec<(String, String)>,
    pub overall_confidence: f64,
    pub severity: TestCaseSeverity,
    pub remediation: Option<String>,
    pub duration_ms: u64,
}

/// Status of a conversation test
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConversationTestStatus {
    Passed,
    Failed,
    Aborted,
    Error,
    Timeout,
}

impl std::fmt::Display for ConversationTestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConversationTestStatus::Passed => write!(f, "passed"),
            ConversationTestStatus::Failed => write!(f, "failed"),
            ConversationTestStatus::Aborted => write!(f, "aborted"),
            ConversationTestStatus::Error => write!(f, "error"),
            ConversationTestStatus::Timeout => write!(f, "timeout"),
        }
    }
}

// ============================================================================
// Agent/Tool Exploitation Testing
// ============================================================================

/// Tool definition for agent testing
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    /// JSON Schema for tool parameters
    pub parameters: serde_json::Value,
    /// Whether this tool is potentially dangerous
    pub dangerous: bool,
    /// Expected tool behaviors to test
    pub test_behaviors: Option<Vec<String>>,
}

/// Function calling format used by the LLM
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FunctionCallingFormat {
    /// OpenAI format: {"name": "...", "arguments": "..."}
    OpenAI,
    /// Anthropic format: <tool_use>...</tool_use>
    Anthropic,
    /// Google Gemini format
    Gemini,
    /// Custom format (defined in agent config)
    Custom,
}

impl Default for FunctionCallingFormat {
    fn default() -> Self {
        FunctionCallingFormat::OpenAI
    }
}

impl std::fmt::Display for FunctionCallingFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FunctionCallingFormat::OpenAI => write!(f, "openai"),
            FunctionCallingFormat::Anthropic => write!(f, "anthropic"),
            FunctionCallingFormat::Gemini => write!(f, "gemini"),
            FunctionCallingFormat::Custom => write!(f, "custom"),
        }
    }
}

/// Configuration for testing LLM agents
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AgentTestConfig {
    /// Target ID this config is associated with
    pub target_id: String,
    /// Tools available to the agent
    pub tools: Vec<ToolDefinition>,
    /// RAG endpoint for testing document injection
    pub rag_endpoint: Option<String>,
    /// Format used for function calling
    pub function_calling_format: FunctionCallingFormat,
    /// Custom function calling template (for Custom format)
    pub custom_function_template: Option<String>,
    /// Whether the agent has memory/state
    pub memory_enabled: bool,
    /// Endpoint for memory operations (if applicable)
    pub memory_endpoint: Option<String>,
    /// System prompt used by the agent (if known)
    pub system_prompt: Option<String>,
}

/// Agent test case category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentTestCategory {
    /// Tool parameter injection attacks
    ToolParameterInjection,
    /// Forcing unintended tool sequences
    ToolChaining,
    /// RAG context poisoning
    RagPoisoning,
    /// Hijacking function call outputs
    FunctionCallHijacking,
    /// Corrupting agent memory/state
    MemoryPoisoning,
    /// Injecting via tool responses
    ToolOutputInjection,
    /// Using tools to escalate privileges
    PrivilegeEscalation,
    /// Chaining tools to exfiltrate data
    DataExfiltration,
    /// Attempting to invoke system tools
    SystemToolInvocation,
    /// Injecting prompts via RAG documents
    IndirectPromptInjection,
}

impl std::fmt::Display for AgentTestCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentTestCategory::ToolParameterInjection => write!(f, "tool_parameter_injection"),
            AgentTestCategory::ToolChaining => write!(f, "tool_chaining"),
            AgentTestCategory::RagPoisoning => write!(f, "rag_poisoning"),
            AgentTestCategory::FunctionCallHijacking => write!(f, "function_call_hijacking"),
            AgentTestCategory::MemoryPoisoning => write!(f, "memory_poisoning"),
            AgentTestCategory::ToolOutputInjection => write!(f, "tool_output_injection"),
            AgentTestCategory::PrivilegeEscalation => write!(f, "privilege_escalation"),
            AgentTestCategory::DataExfiltration => write!(f, "data_exfiltration"),
            AgentTestCategory::SystemToolInvocation => write!(f, "system_tool_invocation"),
            AgentTestCategory::IndirectPromptInjection => write!(f, "indirect_prompt_injection"),
        }
    }
}

/// Agent-specific test case
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AgentTestCase {
    pub id: String,
    pub category: AgentTestCategory,
    pub name: String,
    pub description: String,
    /// Prompt to send to the agent
    pub prompt: String,
    /// Expected tool calls (for verification)
    pub expected_tool_calls: Option<Vec<ExpectedToolCall>>,
    /// Injected document content (for RAG tests)
    pub injected_document: Option<String>,
    /// Fake tool response to inject
    pub fake_tool_response: Option<String>,
    pub severity: TestCaseSeverity,
    pub cwe_id: Option<String>,
}

/// Expected tool call for verification
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ExpectedToolCall {
    pub tool_name: String,
    /// Parameters that indicate a successful attack
    pub malicious_parameters: Vec<String>,
    /// Whether this call should have been blocked
    pub should_be_blocked: bool,
}

/// Result of an agent exploitation test
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AgentTestResult {
    pub test_case_id: String,
    pub test_case_name: String,
    pub category: AgentTestCategory,
    pub prompt_sent: String,
    pub response_received: String,
    /// Tool calls made by the agent
    pub tool_calls: Vec<DetectedToolCall>,
    pub vulnerable: bool,
    pub severity: TestCaseSeverity,
    pub confidence: f64,
    pub indicators: Vec<String>,
    pub cwe_id: Option<String>,
    pub remediation: Option<String>,
}

/// Tool call detected in agent response
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DetectedToolCall {
    pub tool_name: String,
    pub arguments: serde_json::Value,
    /// Whether this call appears malicious
    pub is_malicious: bool,
    /// Reason for malicious classification
    pub malicious_reason: Option<String>,
}

// ============================================================================
// Model Fingerprinting
// ============================================================================

/// Model fingerprint information
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ModelFingerprint {
    /// Most likely model family (GPT, Claude, Llama, etc.)
    pub likely_model_family: String,
    /// Specific model version if detectable
    pub likely_model_version: Option<String>,
    /// Confidence in the identification
    pub confidence: f64,
    /// Indicators that led to this identification
    pub indicators: Vec<String>,
    /// Known vulnerabilities for this model family
    pub known_vulnerabilities: Vec<String>,
    /// Estimated context window size
    pub estimated_context_window: Option<usize>,
    /// Detected safety mechanisms
    pub safety_mechanisms: Vec<SafetyMechanism>,
}

/// Safety mechanism detected in a model
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SafetyMechanism {
    pub mechanism_type: String,
    pub description: String,
    pub strength: SafetyStrength,
    /// Test cases that were blocked by this mechanism
    pub blocked_test_count: usize,
}

/// Strength of a safety mechanism
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SafetyStrength {
    Weak,
    Moderate,
    Strong,
    VeryStrong,
}

impl std::fmt::Display for SafetyStrength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SafetyStrength::Weak => write!(f, "weak"),
            SafetyStrength::Moderate => write!(f, "moderate"),
            SafetyStrength::Strong => write!(f, "strong"),
            SafetyStrength::VeryStrong => write!(f, "very_strong"),
        }
    }
}

// ============================================================================
// Remediation
// ============================================================================

/// Detailed remediation guidance
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Remediation {
    pub category: String,
    pub severity: TestCaseSeverity,
    /// Brief description of the vulnerability
    pub vulnerability_description: String,
    /// Impact assessment
    pub impact: String,
    /// Step-by-step remediation instructions
    pub remediation_steps: Vec<String>,
    /// Code examples for remediation
    pub code_examples: Vec<CodeExample>,
    /// OWASP LLM Top 10 mapping
    pub owasp_llm_mapping: Option<String>,
    /// CWE ID mapping
    pub cwe_mapping: Option<String>,
    /// Priority level (1-5, 1 being highest)
    pub priority: u8,
    /// Estimated effort to remediate
    pub effort_estimate: EffortEstimate,
    /// References and resources
    pub references: Vec<String>,
}

/// Code example for remediation
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CodeExample {
    pub language: String,
    pub description: String,
    pub code: String,
}

/// Estimated effort to remediate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EffortEstimate {
    Low,
    Medium,
    High,
    VeryHigh,
}

impl std::fmt::Display for EffortEstimate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EffortEstimate::Low => write!(f, "low"),
            EffortEstimate::Medium => write!(f, "medium"),
            EffortEstimate::High => write!(f, "high"),
            EffortEstimate::VeryHigh => write!(f, "very_high"),
        }
    }
}

// ============================================================================
// API Request Types for New Features
// ============================================================================

/// Request to start a conversation test
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct StartConversationTestRequest {
    pub target_id: String,
    pub test_ids: Option<Vec<String>>,
    pub categories: Option<Vec<LLMTestCategory>>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Request to configure agent testing
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConfigureAgentTestRequest {
    pub target_id: String,
    pub tools: Vec<ToolDefinition>,
    pub rag_endpoint: Option<String>,
    pub function_calling_format: FunctionCallingFormat,
    pub custom_function_template: Option<String>,
    pub memory_enabled: bool,
    pub memory_endpoint: Option<String>,
    pub system_prompt: Option<String>,
}

/// Request to run agent exploitation tests
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct StartAgentTestRequest {
    pub target_id: String,
    pub categories: Option<Vec<AgentTestCategory>>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Request to run model fingerprinting
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FingerprintRequest {
    pub target_id: String,
}

/// Request to generate an LLM security report
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct GenerateLLMReportRequest {
    pub test_id: String,
    pub format: LLMReportFormat,
    pub include_conversation_transcripts: bool,
    pub include_remediation: bool,
}

/// Report format for LLM security reports
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LLMReportFormat {
    Pdf,
    Html,
    Markdown,
    Json,
}

impl std::fmt::Display for LLMReportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LLMReportFormat::Pdf => write!(f, "pdf"),
            LLMReportFormat::Html => write!(f, "html"),
            LLMReportFormat::Markdown => write!(f, "markdown"),
            LLMReportFormat::Json => write!(f, "json"),
        }
    }
}

// ============================================================================
// Database Record Types for New Features
// ============================================================================

/// Database record for conversation test
#[derive(Debug, Clone, FromRow)]
pub struct ConversationTestRecord {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub turns: String,
    pub success_criteria: String,
    pub severity: String,
    pub is_builtin: bool,
    pub created_at: DateTime<Utc>,
}

impl From<ConversationTestRecord> for ConversationTest {
    fn from(r: ConversationTestRecord) -> Self {
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
        let severity = match r.severity.as_str() {
            "critical" => TestCaseSeverity::Critical,
            "high" => TestCaseSeverity::High,
            "medium" => TestCaseSeverity::Medium,
            "low" => TestCaseSeverity::Low,
            "info" => TestCaseSeverity::Info,
            _ => TestCaseSeverity::Medium,
        };
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            category,
            turns: serde_json::from_str(&r.turns).unwrap_or_default(),
            success_criteria: serde_json::from_str(&r.success_criteria).unwrap_or(SuccessCriteria {
                min_successful_turns: 1,
                require_all_turns: false,
                critical_turn: None,
                final_success_patterns: vec![],
            }),
            severity,
            is_builtin: r.is_builtin,
            created_at: r.created_at,
        }
    }
}

/// Database record for conversation test result
#[derive(Debug, Clone, FromRow)]
pub struct ConversationResultRecord {
    pub id: String,
    pub test_run_id: String,
    pub conversation_test_id: String,
    pub turns_executed: String,
    pub final_status: String,
    pub vulnerability_at_turn: Option<i64>,
    pub full_transcript: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Database record for agent test config
#[derive(Debug, Clone, FromRow)]
pub struct AgentConfigRecord {
    pub id: String,
    pub target_id: String,
    pub tools: Option<String>,
    pub rag_endpoint: Option<String>,
    pub function_format: String,
    pub custom_function_template: Option<String>,
    pub memory_enabled: bool,
    pub memory_endpoint: Option<String>,
    pub system_prompt: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Database record for model fingerprint
#[derive(Debug, Clone, FromRow)]
pub struct ModelFingerprintRecord {
    pub id: String,
    pub target_id: String,
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
}
