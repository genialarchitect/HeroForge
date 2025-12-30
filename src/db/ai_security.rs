//! Database operations for AI/ML Security Operations
//!
//! Provides storage and retrieval for ML models, predictions, AI queries, and LLM security tests.

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;

use crate::ai_security::types::{
    AIDashboard, AIQuery, AIQueryRecord, LLMSecurityTest, LLMSecurityTestRecord,
    LLMTestCase, LLMTestCaseRecord, LLMTestStatus, MLModel, MLModelRecord,
    MLModelStatus, MLPrediction, MLPredictionRecord, ModelMetrics, SecurityRecommendation,
};

// ============================================================================
// ML Models
// ============================================================================

/// List all ML models
pub async fn list_ml_models(pool: &SqlitePool) -> Result<Vec<MLModel>> {
    let records: Vec<MLModelRecord> = sqlx::query_as(
        r#"
        SELECT id, name, model_type, purpose, version, algorithm,
               training_data_size, accuracy, precision_score, recall_score, f1_score,
               model_path, status, trained_at, last_used_at, created_at
        FROM ml_models
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(records.into_iter().map(|r| r.into()).collect())
}

/// Get ML model by ID
pub async fn get_ml_model(pool: &SqlitePool, model_id: &str) -> Result<Option<MLModel>> {
    let record: Option<MLModelRecord> = sqlx::query_as(
        r#"
        SELECT id, name, model_type, purpose, version, algorithm,
               training_data_size, accuracy, precision_score, recall_score, f1_score,
               model_path, status, trained_at, last_used_at, created_at
        FROM ml_models
        WHERE id = ?1
        "#,
    )
    .bind(model_id)
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|r| r.into()))
}

/// Update model status
pub async fn update_model_status(pool: &SqlitePool, model_id: &str, status: MLModelStatus) -> Result<()> {
    sqlx::query("UPDATE ml_models SET status = ?1 WHERE id = ?2")
        .bind(status.to_string())
        .bind(model_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get model prediction statistics
pub async fn get_model_prediction_stats(pool: &SqlitePool, model_id: &str) -> Result<serde_json::Value> {
    let stats: Option<(i64, i64, i64)> = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN feedback = 'correct' THEN 1 ELSE 0 END) as correct,
            SUM(CASE WHEN feedback = 'incorrect' THEN 1 ELSE 0 END) as incorrect
        FROM ml_predictions
        WHERE model_id = ?1
        "#,
    )
    .bind(model_id)
    .fetch_optional(pool)
    .await?;

    Ok(match stats {
        Some((total, correct, incorrect)) => serde_json::json!({
            "total_predictions": total,
            "correct_predictions": correct,
            "incorrect_predictions": incorrect,
            "accuracy": if total > 0 { (correct as f64 / total as f64) * 100.0 } else { 0.0 }
        }),
        None => serde_json::json!({
            "total_predictions": 0,
            "correct_predictions": 0,
            "incorrect_predictions": 0,
            "accuracy": 0.0
        }),
    })
}

// ============================================================================
// ML Predictions
// ============================================================================

/// Store a prediction
pub async fn store_prediction(
    pool: &SqlitePool,
    id: &str,
    model_id: &str,
    entity_type: &str,
    entity_id: &str,
    prediction: &serde_json::Value,
    confidence: f64,
    explanation: Option<&serde_json::Value>,
) -> Result<()> {
    let now = Utc::now();
    let prediction_str = serde_json::to_string(prediction)?;
    let explanation_str = explanation.map(|e| serde_json::to_string(e).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO ml_predictions (id, model_id, entity_type, entity_id, prediction, confidence, explanation, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
    )
    .bind(id)
    .bind(model_id)
    .bind(entity_type)
    .bind(entity_id)
    .bind(&prediction_str)
    .bind(confidence)
    .bind(&explanation_str)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update prediction feedback
pub async fn update_prediction_feedback(pool: &SqlitePool, prediction_id: &str, feedback: &str) -> Result<()> {
    sqlx::query("UPDATE ml_predictions SET feedback = ?1 WHERE id = ?2")
        .bind(feedback)
        .bind(prediction_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ============================================================================
// AI Queries
// ============================================================================

/// Store an AI query
pub async fn store_ai_query(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    query_text: &str,
    query_type: &str,
    parsed_intent: &str,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO ai_queries (id, user_id, query_text, query_type, parsed_intent, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(query_text)
    .bind(query_type)
    .bind(parsed_intent)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// List user's AI queries
pub async fn list_user_queries(pool: &SqlitePool, user_id: &str, limit: i64, offset: i64) -> Result<Vec<AIQuery>> {
    let records: Vec<AIQueryRecord> = sqlx::query_as(
        r#"
        SELECT id, user_id, query_text, query_type, parsed_intent, results, feedback, created_at
        FROM ai_queries
        WHERE user_id = ?1
        ORDER BY created_at DESC
        LIMIT ?2 OFFSET ?3
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(records.into_iter().map(|r| r.into()).collect())
}

// ============================================================================
// LLM Security Tests
// ============================================================================

/// Create LLM security test
pub async fn create_llm_test(pool: &SqlitePool, test: &LLMSecurityTest) -> Result<()> {
    let config_str = test.target_config.as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO llm_security_tests (
            id, user_id, target_name, target_type, target_config, test_type,
            status, tests_run, vulnerabilities_found, results,
            started_at, completed_at, customer_id, engagement_id, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
        "#,
    )
    .bind(&test.id)
    .bind(&test.user_id)
    .bind(&test.target_name)
    .bind(test.target_type.to_string())
    .bind(&config_str)
    .bind(test.test_type.to_string())
    .bind(test.status.to_string())
    .bind(test.tests_run)
    .bind(test.vulnerabilities_found)
    .bind(test.results.as_ref().map(|r| serde_json::to_string(r).unwrap_or_default()))
    .bind(test.started_at)
    .bind(test.completed_at)
    .bind(&test.customer_id)
    .bind(&test.engagement_id)
    .bind(test.created_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get LLM security test by ID
pub async fn get_llm_test(pool: &SqlitePool, test_id: &str) -> Result<Option<LLMSecurityTest>> {
    let record: Option<LLMSecurityTestRecord> = sqlx::query_as(
        r#"
        SELECT id, user_id, target_name, target_type, target_config, test_type,
               status, tests_run, vulnerabilities_found, results,
               started_at, completed_at, customer_id, engagement_id, created_at
        FROM llm_security_tests
        WHERE id = ?1
        "#,
    )
    .bind(test_id)
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|r| r.into()))
}

/// List user's LLM security tests
pub async fn list_user_llm_tests(pool: &SqlitePool, user_id: &str, limit: i64, offset: i64) -> Result<Vec<LLMSecurityTest>> {
    let records: Vec<LLMSecurityTestRecord> = sqlx::query_as(
        r#"
        SELECT id, user_id, target_name, target_type, target_config, test_type,
               status, tests_run, vulnerabilities_found, results,
               started_at, completed_at, customer_id, engagement_id, created_at
        FROM llm_security_tests
        WHERE user_id = ?1
        ORDER BY created_at DESC
        LIMIT ?2 OFFSET ?3
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(records.into_iter().map(|r| r.into()).collect())
}

/// List all LLM security tests (admin)
pub async fn list_all_llm_tests(pool: &SqlitePool, limit: i64, offset: i64) -> Result<Vec<LLMSecurityTest>> {
    let records: Vec<LLMSecurityTestRecord> = sqlx::query_as(
        r#"
        SELECT id, user_id, target_name, target_type, target_config, test_type,
               status, tests_run, vulnerabilities_found, results,
               started_at, completed_at, customer_id, engagement_id, created_at
        FROM llm_security_tests
        ORDER BY created_at DESC
        LIMIT ?1 OFFSET ?2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(records.into_iter().map(|r| r.into()).collect())
}

/// Update LLM test status
pub async fn update_llm_test_status(pool: &SqlitePool, test_id: &str, status: LLMTestStatus) -> Result<()> {
    let now = if status == LLMTestStatus::Completed || status == LLMTestStatus::Failed || status == LLMTestStatus::Cancelled {
        Some(Utc::now())
    } else {
        None
    };

    sqlx::query("UPDATE llm_security_tests SET status = ?1, completed_at = ?2 WHERE id = ?3")
        .bind(status.to_string())
        .bind(now)
        .bind(test_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update LLM test results
pub async fn update_llm_test_results(
    pool: &SqlitePool,
    test_id: &str,
    tests_run: i64,
    vulnerabilities_found: i64,
    results: &serde_json::Value,
) -> Result<()> {
    let results_str = serde_json::to_string(results)?;

    sqlx::query(
        r#"
        UPDATE llm_security_tests
        SET tests_run = ?1, vulnerabilities_found = ?2, results = ?3
        WHERE id = ?4
        "#,
    )
    .bind(tests_run)
    .bind(vulnerabilities_found)
    .bind(&results_str)
    .bind(test_id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// LLM Test Cases
// ============================================================================

/// List test cases
pub async fn list_test_cases(pool: &SqlitePool, category: Option<&str>, enabled_only: bool) -> Result<Vec<LLMTestCase>> {
    let mut query = String::from(
        r#"
        SELECT id, category, name, description, payload, expected_behavior, severity, cwe_id, enabled, created_at
        FROM llm_test_cases
        WHERE 1=1
        "#,
    );

    if let Some(_) = category {
        query.push_str(" AND category = ?1");
    }

    if enabled_only {
        query.push_str(" AND enabled = 1");
    }

    query.push_str(" ORDER BY category, name");

    let records: Vec<LLMTestCaseRecord> = if let Some(cat) = category {
        sqlx::query_as(&query)
            .bind(cat)
            .fetch_all(pool)
            .await?
    } else {
        sqlx::query_as(&query)
            .fetch_all(pool)
            .await?
    };

    Ok(records.into_iter().map(|r| r.into()).collect())
}

/// Create test case
pub async fn create_test_case(
    pool: &SqlitePool,
    id: &str,
    category: &str,
    name: &str,
    description: Option<&str>,
    payload: &str,
    expected_behavior: Option<&str>,
    severity: &str,
    cwe_id: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO llm_test_cases (id, category, name, description, payload, expected_behavior, severity, cwe_id, enabled, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)
        "#,
    )
    .bind(id)
    .bind(category)
    .bind(name)
    .bind(description)
    .bind(payload)
    .bind(expected_behavior)
    .bind(severity)
    .bind(cwe_id)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Dashboard
// ============================================================================

/// Get dashboard statistics
pub async fn get_dashboard_stats(pool: &SqlitePool) -> Result<AIDashboard> {
    // Get prediction counts
    let (total_predictions, correct_count, incorrect_count): (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN feedback = 'correct' THEN 1 ELSE 0 END) as correct,
            SUM(CASE WHEN feedback = 'incorrect' THEN 1 ELSE 0 END) as incorrect
        FROM ml_predictions
        "#,
    )
    .fetch_one(pool)
    .await
    .unwrap_or((0, 0, 0));

    let prediction_accuracy = if correct_count + incorrect_count > 0 {
        (correct_count as f64 / (correct_count + incorrect_count) as f64) * 100.0
    } else {
        0.0
    };

    // Get active models count
    let (active_models,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ml_models WHERE status = 'active'"
    )
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    // Get LLM test stats
    let (llm_tests_run, llm_vulns_found): (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COALESCE(SUM(tests_run), 0),
            COALESCE(SUM(vulnerabilities_found), 0)
        FROM llm_security_tests
        "#,
    )
    .fetch_one(pool)
    .await
    .unwrap_or((0, 0));

    // Get model metrics
    let model_metrics: Vec<ModelMetrics> = Vec::new(); // Would be populated from actual model data

    // Get recent predictions
    let recent_predictions: Vec<MLPrediction> = Vec::new(); // Would be populated from DB

    // Get recent LLM tests
    let recent_llm_tests: Vec<LLMSecurityTest> = list_all_llm_tests(pool, 5, 0).await?;

    Ok(AIDashboard {
        total_predictions,
        prediction_accuracy,
        active_models,
        llm_tests_run,
        llm_vulns_found,
        anomalies_detected: 0, // Would be populated from anomaly detection
        false_positive_rate: 0.0, // Would be calculated
        model_metrics,
        recent_predictions,
        recent_llm_tests,
    })
}

/// Get security recommendations
pub async fn get_security_recommendations(pool: &SqlitePool) -> Result<Vec<SecurityRecommendation>> {
    let mut recommendations = Vec::new();

    // Check for critical vulnerabilities
    let (critical_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM vulnerability_tracking WHERE severity = 'critical' AND status = 'open'"
    )
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    if critical_count > 0 {
        recommendations.push(SecurityRecommendation {
            id: uuid::Uuid::new_v4().to_string(),
            title: "Critical Vulnerabilities Detected".to_string(),
            description: format!("{} critical vulnerabilities require immediate attention", critical_count),
            priority: "critical".to_string(),
            category: "vulnerability".to_string(),
            affected_entities: Vec::new(),
            remediation_steps: vec![
                "Review critical vulnerabilities immediately".to_string(),
                "Prioritize patching based on exposure".to_string(),
                "Implement temporary mitigations if needed".to_string(),
            ],
            confidence: 0.95,
            source: "vulnerability_analysis".to_string(),
        });
    }

    // Check for LLM security issues
    let (llm_vulns,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(vulnerabilities_found), 0) FROM llm_security_tests WHERE status = 'completed'"
    )
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    if llm_vulns > 0 {
        recommendations.push(SecurityRecommendation {
            id: uuid::Uuid::new_v4().to_string(),
            title: "LLM Security Issues Found".to_string(),
            description: format!("{} vulnerabilities found in LLM security tests", llm_vulns),
            priority: "high".to_string(),
            category: "llm_security".to_string(),
            affected_entities: Vec::new(),
            remediation_steps: vec![
                "Review LLM test results".to_string(),
                "Implement prompt injection defenses".to_string(),
                "Add output filtering and validation".to_string(),
            ],
            confidence: 0.85,
            source: "llm_security_testing".to_string(),
        });
    }

    Ok(recommendations)
}
