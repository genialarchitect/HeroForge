//! AI Security Operations API Endpoints
//!
//! Provides REST endpoints for AI/ML security features including:
//! - ML model management
//! - Predictions and feedback
//! - Natural language queries
//! - LLM security testing

use actix_web::{web, HttpResponse};
use chrono::Utc;
use sqlx::SqlitePool;

use crate::ai_security::{
    AlertFeatures, AlertPriorityScorer, AnomalyDetector, FPFeatures, FPPredictor,
    QueryParser,
    types::{
        AIQueryRequest, AIDashboard, BatchPredictionRequest, CreatePredictionRequest,
        CreateTestCaseRequest, LLMSecurityTest, LLMTestStatus,
        MLModel, MLModelStatus, MLPrediction, PredictionFeedbackRequest, StartLLMTestRequest,
    },
};
use crate::ai_security::llm_testing::LLMTestingEngine;
use crate::web::auth;
use crate::web::error::{ApiError, ApiErrorKind};

/// Configure AI security routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/ai-security")
            // ML Models
            .route("/models", web::get().to(list_models))
            .route("/models/{id}", web::get().to(get_model))
            .route("/models/{id}/train", web::post().to(train_model))
            .route("/models/{id}/metrics", web::get().to(get_model_metrics))
            // ML Predictions
            .route("/predict", web::post().to(create_prediction))
            .route("/predict/batch", web::post().to(batch_predict))
            .route("/feedback", web::post().to(submit_feedback))
            // Alert Priority
            .route("/alerts/prioritize", web::post().to(prioritize_alert))
            .route("/alerts/prioritize/batch", web::post().to(batch_prioritize_alerts))
            // Anomaly Detection
            .route("/anomaly/detect", web::post().to(detect_anomalies))
            .route("/anomaly/baseline", web::post().to(update_baseline))
            // False Positive Prediction
            .route("/fp-predict", web::post().to(predict_false_positive))
            .route("/fp-predict/batch", web::post().to(batch_predict_fp))
            // AI Queries
            .route("/query", web::post().to(ai_query))
            .route("/queries", web::get().to(list_queries))
            // LLM Security Testing
            .route("/llm-security/test", web::post().to(start_llm_test))
            .route("/llm-security/tests", web::get().to(list_llm_tests))
            .route("/llm-security/tests/{id}", web::get().to(get_llm_test))
            .route("/llm-security/tests/{id}/cancel", web::post().to(cancel_llm_test))
            .route("/llm-security/test-cases", web::get().to(list_test_cases))
            .route("/llm-security/test-cases", web::post().to(create_test_case))
            .route("/llm-security/validate-target", web::post().to(validate_llm_target))
            // LLM Targets
            .route("/llm-security/targets", web::get().to(list_llm_targets))
            .route("/llm-security/targets", web::post().to(create_llm_target))
            .route("/llm-security/targets/{id}", web::get().to(get_llm_target))
            .route("/llm-security/targets/{id}", web::put().to(update_llm_target))
            .route("/llm-security/targets/{id}", web::delete().to(delete_llm_target))
            // Multi-turn Conversation Tests
            .route("/llm-security/conversation-tests", web::get().to(list_conversation_tests))
            .route("/llm-security/conversation-test", web::post().to(start_conversation_test))
            // Agent Testing
            .route("/llm-security/agent-configs", web::get().to(list_agent_configs))
            .route("/llm-security/agent-configs", web::post().to(create_agent_config))
            .route("/llm-security/agent-configs/{id}", web::get().to(get_agent_config))
            .route("/llm-security/agent-configs/{id}", web::put().to(update_agent_config))
            .route("/llm-security/agent-configs/{id}", web::delete().to(delete_agent_config))
            .route("/llm-security/agent-test-cases", web::get().to(list_agent_test_cases))
            .route("/llm-security/agent-test", web::post().to(start_agent_test))
            // Model Fingerprinting
            .route("/llm-security/fingerprint/{target_id}", web::post().to(fingerprint_model))
            .route("/llm-security/fingerprints/{target_id}", web::get().to(get_fingerprint))
            // Reports
            .route("/llm-security/tests/{id}/report", web::post().to(generate_llm_report))
            .route("/llm-security/reports/{id}", web::get().to(get_llm_report))
            // Remediation Guidance
            .route("/llm-security/remediation/{category}", web::get().to(get_remediation))
            // Dashboard
            .route("/dashboard", web::get().to(get_dashboard))
            .route("/recommendations", web::get().to(get_recommendations)),
    );
}

// ============================================================================
// ML Models
// ============================================================================

/// GET /api/ai-security/models
#[utoipa::path(
    get,
    path = "/api/ai-security/models",
    tag = "AI Security",
    responses(
        (status = 200, description = "List of ML models", body = Vec<MLModel>),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_models(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let models = crate::db::ai_security::list_ml_models(&pool).await?;
    Ok(HttpResponse::Ok().json(models))
}

/// GET /api/ai-security/models/{id}
#[utoipa::path(
    get,
    path = "/api/ai-security/models/{id}",
    tag = "AI Security",
    params(
        ("id" = String, Path, description = "Model ID"),
    ),
    responses(
        (status = 200, description = "Model details", body = MLModel),
        (status = 404, description = "Model not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_model(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let model_id = path.into_inner();
    let model = crate::db::ai_security::get_ml_model(&pool, &model_id).await?
        .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Model not found".to_string()))?;
    Ok(HttpResponse::Ok().json(model))
}

/// POST /api/ai-security/models/{id}/train
#[utoipa::path(
    post,
    path = "/api/ai-security/models/{id}/train",
    tag = "AI Security",
    params(
        ("id" = String, Path, description = "Model ID"),
    ),
    responses(
        (status = 200, description = "Training started"),
        (status = 404, description = "Model not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn train_model(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let model_id = path.into_inner();
    let user_id = &claims.sub;

    // Verify model exists
    let _model = crate::db::ai_security::get_ml_model(&pool, &model_id).await?
        .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Model not found".to_string()))?;

    // Update model status to training
    crate::db::ai_security::update_model_status(&pool, &model_id, MLModelStatus::Training).await?;

    // Log the action
    crate::db::log_audit(&pool, user_id, "ml_model_train", Some("ml_model"), Some(&model_id), Some("Started model training"), None).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Model training started",
        "model_id": model_id
    })))
}

/// GET /api/ai-security/models/{id}/metrics
pub async fn get_model_metrics(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let model_id = path.into_inner();
    let model = crate::db::ai_security::get_ml_model(&pool, &model_id).await?
        .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Model not found".to_string()))?;

    // Get prediction statistics
    let stats = crate::db::ai_security::get_model_prediction_stats(&pool, &model_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "model_id": model_id,
        "accuracy": model.accuracy,
        "precision": model.precision_score,
        "recall": model.recall_score,
        "f1_score": model.f1_score,
        "prediction_stats": stats
    })))
}

// ============================================================================
// ML Predictions
// ============================================================================

/// POST /api/ai-security/predict
#[utoipa::path(
    post,
    path = "/api/ai-security/predict",
    tag = "AI Security",
    request_body = CreatePredictionRequest,
    responses(
        (status = 200, description = "Prediction result", body = MLPrediction),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_prediction(
    pool: web::Data<SqlitePool>,
    body: web::Json<CreatePredictionRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let _user_id = &claims.sub;

    // For now, use rule-based scoring (can be replaced with actual ML model)
    let prediction = match body.entity_type {
        crate::ai_security::types::PredictionEntityType::Alert => {
            // Extract alert features from entity_data
            let features: AlertFeatures = body.entity_data.as_ref()
                .and_then(|d| serde_json::from_value(d.clone()).ok())
                .unwrap_or_default();

            let scorer = AlertPriorityScorer::new();
            let score = scorer.calculate_score(&body.entity_id, &features)?;

            serde_json::json!({
                "priority": score.priority,
                "score": score.score,
                "factors": score.factors,
                "recommendations": score.recommendations
            })
        }
        _ => {
            serde_json::json!({
                "score": 0.5,
                "label": "uncertain"
            })
        }
    };

    // Store prediction
    let prediction_id = uuid::Uuid::new_v4().to_string();
    crate::db::ai_security::store_prediction(
        &pool,
        &prediction_id,
        body.model_id.as_deref().unwrap_or("rule_based"),
        &body.entity_type.to_string(),
        &body.entity_id,
        &prediction,
        0.75,
        None,
    ).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "prediction_id": prediction_id,
        "prediction": prediction,
        "confidence": 0.75
    })))
}

/// POST /api/ai-security/predict/batch
pub async fn batch_predict(
    pool: web::Data<SqlitePool>,
    body: web::Json<BatchPredictionRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let scorer = AlertPriorityScorer::new();
    let mut results = Vec::new();

    for entity_id in &body.entity_ids {
        // Get entity data from database or use defaults
        let features = AlertFeatures::default();
        let score = scorer.calculate_score(entity_id, &features)?;

        results.push(serde_json::json!({
            "entity_id": entity_id,
            "prediction": {
                "priority": score.priority,
                "score": score.score
            },
            "confidence": score.confidence
        }));
    }

    Ok(HttpResponse::Ok().json(results))
}

/// POST /api/ai-security/feedback
pub async fn submit_feedback(
    pool: web::Data<SqlitePool>,
    body: web::Json<PredictionFeedbackRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    crate::db::ai_security::update_prediction_feedback(
        &pool,
        &body.prediction_id,
        &body.feedback.to_string(),
    ).await?;

    crate::db::log_audit(&pool, user_id, "ml_feedback", Some("prediction"), Some(&body.prediction_id), Some("Submitted prediction feedback"), None).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Feedback submitted successfully"
    })))
}

// ============================================================================
// Alert Priority
// ============================================================================

/// POST /api/ai-security/alerts/prioritize
pub async fn prioritize_alert(
    _pool: web::Data<SqlitePool>,
    body: web::Json<AlertFeatures>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let scorer = AlertPriorityScorer::new();
    let score = scorer.calculate_score("inline", &body)?;

    Ok(HttpResponse::Ok().json(score))
}

/// POST /api/ai-security/alerts/prioritize/batch
pub async fn batch_prioritize_alerts(
    _pool: web::Data<SqlitePool>,
    body: web::Json<Vec<(String, AlertFeatures)>>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let scorer = AlertPriorityScorer::new();
    let scores = scorer.calculate_scores(&body);

    Ok(HttpResponse::Ok().json(scores))
}

// ============================================================================
// Anomaly Detection
// ============================================================================

/// Anomaly detection request
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct AnomalyRequest {
    pub metric_name: String,
    pub current_value: f64,
    pub previous_value: Option<f64>,
    pub historical_values: Option<Vec<f64>>,
}

/// POST /api/ai-security/anomaly/detect
pub async fn detect_anomalies(
    _pool: web::Data<SqlitePool>,
    body: web::Json<AnomalyRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let mut detector = AnomalyDetector::new();

    // Update baseline if historical values provided
    if let Some(ref values) = body.historical_values {
        detector.update_baseline(&body.metric_name, values);
    }

    let anomalies = detector.detect_all_anomalies(
        &body.metric_name,
        body.current_value,
        body.previous_value,
    );

    let isolation_score = detector.isolation_score(&body.metric_name, body.current_value);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "anomalies": anomalies,
        "isolation_score": isolation_score,
        "is_anomaly": !anomalies.is_empty() || isolation_score > 0.7
    })))
}

/// Baseline update request
#[derive(Debug, serde::Deserialize)]
pub struct BaselineUpdateRequest {
    pub metric_name: String,
    pub values: Vec<f64>,
}

/// POST /api/ai-security/anomaly/baseline
pub async fn update_baseline(
    _pool: web::Data<SqlitePool>,
    body: web::Json<BaselineUpdateRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let mut detector = AnomalyDetector::new();
    detector.update_baseline(&body.metric_name, &body.values);

    if let Some(baseline) = detector.get_baseline(&body.metric_name) {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Baseline updated",
            "metric_name": body.metric_name,
            "mean": baseline.mean,
            "stddev": baseline.stddev,
            "sample_count": baseline.sample_count
        })))
    } else {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Failed to create baseline - insufficient data"
        })))
    }
}

// ============================================================================
// False Positive Prediction
// ============================================================================

/// POST /api/ai-security/fp-predict
pub async fn predict_false_positive(
    _pool: web::Data<SqlitePool>,
    body: web::Json<FPFeatures>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let predictor = FPPredictor::new();
    let prediction = predictor.predict("inline", &body)?;

    Ok(HttpResponse::Ok().json(prediction))
}

/// POST /api/ai-security/fp-predict/batch
pub async fn batch_predict_fp(
    _pool: web::Data<SqlitePool>,
    body: web::Json<Vec<(String, FPFeatures)>>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let predictor = FPPredictor::new();
    let predictions = predictor.predict_batch(&body);

    Ok(HttpResponse::Ok().json(predictions))
}

// ============================================================================
// AI Queries
// ============================================================================

/// POST /api/ai-security/query
#[utoipa::path(
    post,
    path = "/api/ai-security/query",
    tag = "AI Security",
    request_body = AIQueryRequest,
    responses(
        (status = 200, description = "Query results"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn ai_query(
    pool: web::Data<SqlitePool>,
    body: web::Json<AIQueryRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let parser = QueryParser::new();

    // Parse the query
    let parsed = parser.parse(&body.query)?;

    // Generate suggestions
    let suggestions = parser.suggest_improvements(&body.query, &parsed);

    // Store the query
    let query_id = uuid::Uuid::new_v4().to_string();
    crate::db::ai_security::store_ai_query(
        &pool,
        &query_id,
        user_id,
        &body.query,
        parsed.query_type.to_string().as_str(),
        &serde_json::to_string(&parsed)?,
    ).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "query_id": query_id,
        "parsed_intent": parsed,
        "suggestions": suggestions
    })))
}

/// GET /api/ai-security/queries
pub async fn list_queries(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<PaginationQuery>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let queries = crate::db::ai_security::list_user_queries(
        &pool,
        user_id,
        query.limit.unwrap_or(50),
        query.offset.unwrap_or(0),
    ).await?;

    Ok(HttpResponse::Ok().json(queries))
}

// ============================================================================
// LLM Security Testing
// ============================================================================

/// POST /api/ai-security/llm-security/test
#[utoipa::path(
    post,
    path = "/api/ai-security/llm-security/test",
    tag = "AI Security",
    request_body = StartLLMTestRequest,
    responses(
        (status = 200, description = "Test started", body = LLMSecurityTest),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn start_llm_test(
    pool: web::Data<SqlitePool>,
    body: web::Json<StartLLMTestRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let test_id = uuid::Uuid::new_v4().to_string();

    // Create test record
    let test = LLMSecurityTest {
        id: test_id.clone(),
        user_id: user_id.clone(),
        target_name: body.target_name.clone(),
        target_type: body.target_type,
        target_config: Some(body.target_config.clone()),
        test_type: body.test_type,
        status: LLMTestStatus::Pending,
        tests_run: 0,
        vulnerabilities_found: 0,
        results: None,
        started_at: None,
        completed_at: None,
        customer_id: body.customer_id.clone(),
        engagement_id: body.engagement_id.clone(),
        created_at: Utc::now(),
    };

    // Store in database
    crate::db::ai_security::create_llm_test(&pool, &test).await?;

    // Log the action
    crate::db::log_audit(&pool, user_id, "llm_security_test_start", Some("llm_test"), Some(&test_id), Some(&format!("Started LLM security test against {}", body.target_name)), None).await?;

    // Return immediately - test runs asynchronously
    // In production, this would spawn a background task
    Ok(HttpResponse::Ok().json(test))
}

/// GET /api/ai-security/llm-security/tests
pub async fn list_llm_tests(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<PaginationQuery>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    // Check if admin
    let is_admin = crate::db::has_permission(&pool, user_id, "can_view_all_scans").await?;

    let tests = if is_admin {
        crate::db::ai_security::list_all_llm_tests(&pool, query.limit.unwrap_or(50), query.offset.unwrap_or(0)).await?
    } else {
        crate::db::ai_security::list_user_llm_tests(&pool, user_id, query.limit.unwrap_or(50), query.offset.unwrap_or(0)).await?
    };

    Ok(HttpResponse::Ok().json(tests))
}

/// GET /api/ai-security/llm-security/tests/{id}
pub async fn get_llm_test(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let test_id = path.into_inner();
    let user_id = &claims.sub;

    let test = crate::db::ai_security::get_llm_test(&pool, &test_id).await?
        .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Test not found".to_string()))?;

    // Check permission
    let is_admin = crate::db::has_permission(&pool, user_id, "can_view_all_scans").await?;
    if test.user_id != *user_id && !is_admin {
        return Err(ApiError::new(ApiErrorKind::Forbidden(String::new()), "Access denied".to_string()));
    }

    Ok(HttpResponse::Ok().json(test))
}

/// POST /api/ai-security/llm-security/tests/{id}/cancel
pub async fn cancel_llm_test(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let test_id = path.into_inner();
    let user_id = &claims.sub;

    let test = crate::db::ai_security::get_llm_test(&pool, &test_id).await?
        .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Test not found".to_string()))?;

    // Check permission
    if test.user_id != *user_id {
        let is_admin = crate::db::has_permission(&pool, user_id, "can_manage_settings").await?;
        if !is_admin {
            return Err(ApiError::new(ApiErrorKind::Forbidden(String::new()), "Access denied".to_string()));
        }
    }

    // Update status
    crate::db::ai_security::update_llm_test_status(&pool, &test_id, LLMTestStatus::Cancelled).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Test cancelled"
    })))
}

/// GET /api/ai-security/llm-security/test-cases
pub async fn list_test_cases(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<TestCaseQuery>,
) -> Result<HttpResponse, ApiError> {
    let test_cases = crate::db::ai_security::list_test_cases(
        &pool,
        query.category.as_deref(),
        query.enabled_only.unwrap_or(false),
    ).await?;

    Ok(HttpResponse::Ok().json(test_cases))
}

/// POST /api/ai-security/llm-security/test-cases
pub async fn create_test_case(
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateTestCaseRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let test_case_id = uuid::Uuid::new_v4().to_string();

    crate::db::ai_security::create_test_case(
        &pool,
        &test_case_id,
        &body.category.to_string(),
        &body.name,
        body.description.as_deref(),
        &body.payload,
        body.expected_behavior.as_deref(),
        &body.severity.to_string(),
        body.cwe_id.as_deref(),
    ).await?;

    crate::db::log_audit(&pool, user_id, "llm_test_case_create", Some("llm_test_case"), Some(&test_case_id), Some(&format!("Created LLM test case: {}", body.name)), None).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": test_case_id,
        "message": "Test case created"
    })))
}

/// POST /api/ai-security/llm-security/validate-target
pub async fn validate_llm_target(
    _pool: web::Data<SqlitePool>,
    body: web::Json<crate::ai_security::types::LLMTargetConfig>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let engine = LLMTestingEngine::new();
    let valid = engine.validate_target(&body).await.unwrap_or(false);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "valid": valid,
        "message": if valid { "Target is accessible" } else { "Target validation failed" }
    })))
}

// ============================================================================
// Dashboard
// ============================================================================

/// GET /api/ai-security/dashboard
#[utoipa::path(
    get,
    path = "/api/ai-security/dashboard",
    tag = "AI Security",
    responses(
        (status = 200, description = "AI dashboard data", body = AIDashboard),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_dashboard(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let dashboard = crate::db::ai_security::get_dashboard_stats(&pool).await?;
    Ok(HttpResponse::Ok().json(dashboard))
}

/// GET /api/ai-security/recommendations
pub async fn get_recommendations(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let recommendations = crate::db::ai_security::get_security_recommendations(&pool).await?;
    Ok(HttpResponse::Ok().json(recommendations))
}

// ============================================================================
// LLM Targets
// ============================================================================

/// LLM Target stored in database
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct LLMTarget {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub endpoint: String,
    pub model_type: String,
    pub description: Option<String>,
    pub api_key_encrypted: Option<String>,
    #[sqlx(default)]
    pub headers: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Request to create a new LLM target
#[derive(Debug, serde::Deserialize)]
pub struct CreateLLMTargetRequest {
    pub name: String,
    pub endpoint: String,
    pub model_type: String,
    pub description: Option<String>,
    pub api_key: Option<String>,
    pub headers: Option<serde_json::Value>,
}

/// Request to update an LLM target
#[derive(Debug, serde::Deserialize)]
pub struct UpdateLLMTargetRequest {
    pub name: Option<String>,
    pub endpoint: Option<String>,
    pub model_type: Option<String>,
    pub description: Option<String>,
    pub api_key: Option<String>,
    pub headers: Option<serde_json::Value>,
    pub enabled: Option<bool>,
}

/// GET /api/ai-security/llm-security/targets
pub async fn list_llm_targets(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<PaginationQuery>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let targets = sqlx::query_as::<_, LLMTarget>(
        r#"
        SELECT id, user_id, name, endpoint, model_type, description,
               api_key_encrypted, headers, enabled, created_at, updated_at
        FROM llm_targets
        WHERE user_id = ?1
        ORDER BY created_at DESC
        LIMIT ?2 OFFSET ?3
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch targets".to_string()))?;

    Ok(HttpResponse::Ok().json(targets))
}

/// POST /api/ai-security/llm-security/targets
pub async fn create_llm_target(
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateLLMTargetRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let target_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // For simplicity, we store the API key as-is for now
    // In production, this should be encrypted
    let api_key_encrypted = body.api_key.clone();
    let headers_json = body.headers.as_ref().map(|h| h.to_string());

    sqlx::query(
        r#"
        INSERT INTO llm_targets (id, user_id, name, endpoint, model_type, description, api_key_encrypted, headers, enabled, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?9)
        "#
    )
    .bind(&target_id)
    .bind(user_id)
    .bind(&body.name)
    .bind(&body.endpoint)
    .bind(&body.model_type)
    .bind(&body.description)
    .bind(&api_key_encrypted)
    .bind(&headers_json)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to create target".to_string()))?;

    crate::db::log_audit(
        &pool,
        user_id,
        "llm_target_create",
        Some("llm_target"),
        Some(&target_id),
        Some(&format!("Created LLM target: {}", body.name)),
        None,
    )
    .await?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": target_id,
        "message": "Target created successfully"
    })))
}

/// GET /api/ai-security/llm-security/targets/{id}
pub async fn get_llm_target(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let target_id = path.into_inner();
    let user_id = &claims.sub;

    let target = sqlx::query_as::<_, LLMTarget>(
        r#"
        SELECT id, user_id, name, endpoint, model_type, description,
               api_key_encrypted, headers, enabled, created_at, updated_at
        FROM llm_targets
        WHERE id = ?1 AND user_id = ?2
        "#,
    )
    .bind(&target_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch target".to_string()))?
    .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Target not found".to_string()))?;

    Ok(HttpResponse::Ok().json(target))
}

/// PUT /api/ai-security/llm-security/targets/{id}
pub async fn update_llm_target(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateLLMTargetRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let target_id = path.into_inner();
    let user_id = &claims.sub;

    // First verify the target exists and belongs to user
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM llm_targets WHERE id = ?1 AND user_id = ?2"
    )
    .bind(&target_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch target".to_string()))?;

    let existing = existing
        .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Target not found".to_string()))?;

    // Update each field individually if provided
    if let Some(ref name) = body.name {
        sqlx::query("UPDATE llm_targets SET name = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(name)
            .bind(Utc::now().to_rfc3339())
            .bind(&existing.0)
            .bind(user_id)
            .execute(pool.get_ref())
            .await?;
    }
    if let Some(ref endpoint) = body.endpoint {
        sqlx::query("UPDATE llm_targets SET endpoint = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(endpoint)
            .bind(Utc::now().to_rfc3339())
            .bind(&existing.0)
            .bind(user_id)
            .execute(pool.get_ref())
            .await?;
    }
    if let Some(ref model_type) = body.model_type {
        sqlx::query("UPDATE llm_targets SET model_type = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(model_type)
            .bind(Utc::now().to_rfc3339())
            .bind(&existing.0)
            .bind(user_id)
            .execute(pool.get_ref())
            .await?;
    }
    if let Some(ref description) = body.description {
        sqlx::query("UPDATE llm_targets SET description = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(description)
            .bind(Utc::now().to_rfc3339())
            .bind(&existing.0)
            .bind(user_id)
            .execute(pool.get_ref())
            .await?;
    }
    if let Some(ref api_key) = body.api_key {
        sqlx::query("UPDATE llm_targets SET api_key_encrypted = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(api_key)
            .bind(Utc::now().to_rfc3339())
            .bind(&existing.0)
            .bind(user_id)
            .execute(pool.get_ref())
            .await?;
    }
    if let Some(ref headers) = body.headers {
        sqlx::query("UPDATE llm_targets SET headers = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(headers.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(&existing.0)
            .bind(user_id)
            .execute(pool.get_ref())
            .await?;
    }
    if let Some(enabled) = body.enabled {
        sqlx::query("UPDATE llm_targets SET enabled = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4")
            .bind(enabled)
            .bind(Utc::now().to_rfc3339())
            .bind(&existing.0)
            .bind(user_id)
            .execute(pool.get_ref())
            .await?;
    }

    crate::db::log_audit(
        &pool,
        user_id,
        "llm_target_update",
        Some("llm_target"),
        Some(&target_id),
        Some("Updated LLM target"),
        None,
    )
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": target_id,
        "message": "Target updated successfully"
    })))
}

/// DELETE /api/ai-security/llm-security/targets/{id}
pub async fn delete_llm_target(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let target_id = path.into_inner();
    let user_id = &claims.sub;

    let result = sqlx::query("DELETE FROM llm_targets WHERE id = ?1 AND user_id = ?2")
        .bind(&target_id)
        .bind(user_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to delete target".to_string()))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::new(ApiErrorKind::NotFound(String::new()), "Target not found".to_string()));
    }

    crate::db::log_audit(
        &pool,
        user_id,
        "llm_target_delete",
        Some("llm_target"),
        Some(&target_id),
        Some("Deleted LLM target"),
        None,
    )
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Target deleted successfully"
    })))
}

// ============================================================================
// Multi-turn Conversation Tests
// ============================================================================

/// Request to start a conversation test
#[derive(Debug, serde::Deserialize)]
pub struct StartConversationTestRequest {
    pub target_id: String,
    pub conversation_test_ids: Option<Vec<String>>,  // If None, run all
    pub categories: Option<Vec<String>>,  // Filter by category
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// GET /api/ai-security/llm-security/conversation-tests
pub async fn list_conversation_tests(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<TestCaseQuery>,
) -> Result<HttpResponse, ApiError> {
    // Get tests from database
    let mut tests = sqlx::query_as::<_, ConversationTestRow>(
        r#"
        SELECT id, name, description, category, turns, success_criteria, severity, is_builtin, enabled, created_at
        FROM llm_conversation_tests
        WHERE enabled = 1
        ORDER BY category, name
        "#,
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch conversation tests".to_string()))?;

    // Filter by category if specified
    if let Some(ref category) = query.category {
        tests.retain(|t| t.category.eq_ignore_ascii_case(category));
    }

    Ok(HttpResponse::Ok().json(tests))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct ConversationTestRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub category: String,
    pub turns: String,  // JSON
    pub success_criteria: Option<String>,  // JSON
    pub severity: String,
    pub is_builtin: bool,
    pub enabled: bool,
    pub created_at: String,
}

/// POST /api/ai-security/llm-security/conversation-test
pub async fn start_conversation_test(
    pool: web::Data<SqlitePool>,
    body: web::Json<StartConversationTestRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let test_run_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    // Verify target exists
    let target = sqlx::query_as::<_, LLMTarget>(
        "SELECT * FROM llm_targets WHERE id = ?1 AND user_id = ?2"
    )
    .bind(&body.target_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch target".to_string()))?
    .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Target not found".to_string()))?;

    // Create test run record
    let test = LLMSecurityTest {
        id: test_run_id.clone(),
        user_id: user_id.clone(),
        target_name: target.name.clone(),
        target_type: crate::ai_security::types::LLMTargetType::Api,
        target_config: Some(crate::ai_security::types::LLMTargetConfig {
            endpoint: target.endpoint.clone(),
            auth_type: Some("api_key".to_string()),
            api_key: target.api_key_encrypted.clone(),
            headers: target.headers.as_ref().and_then(|h| serde_json::from_str(h).ok()),
            request_template: None,
            response_path: None,
            rate_limit: None,
            timeout: Some(30),
        }),
        test_type: crate::ai_security::types::LLMTestType::All,
        status: LLMTestStatus::Running,
        tests_run: 0,
        vulnerabilities_found: 0,
        results: None,
        started_at: Some(now),
        completed_at: None,
        customer_id: body.customer_id.clone(),
        engagement_id: body.engagement_id.clone(),
        created_at: now,
    };

    crate::db::ai_security::create_llm_test(&pool, &test).await?;

    crate::db::log_audit(
        &pool,
        user_id,
        "llm_conversation_test_start",
        Some("llm_test"),
        Some(&test_run_id),
        Some(&format!("Started conversation test against {}", target.name)),
        None,
    )
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "test_run_id": test_run_id,
        "status": "running",
        "message": "Conversation test started"
    })))
}

// ============================================================================
// Agent Testing
// ============================================================================

/// Agent config stored in database
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct AgentConfigRow {
    pub id: String,
    pub target_id: String,
    pub name: String,
    pub description: Option<String>,
    pub tools: String,  // JSON array
    pub rag_endpoint: Option<String>,
    pub function_format: String,
    pub memory_enabled: bool,
    pub max_tool_calls: i32,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Request to create an agent config
#[derive(Debug, serde::Deserialize)]
pub struct CreateAgentConfigRequest {
    pub target_id: String,
    pub name: String,
    pub description: Option<String>,
    pub tools: Vec<serde_json::Value>,
    pub rag_endpoint: Option<String>,
    pub function_format: Option<String>,
    pub memory_enabled: Option<bool>,
    pub max_tool_calls: Option<i32>,
}

/// Request to update an agent config
#[derive(Debug, serde::Deserialize)]
pub struct UpdateAgentConfigRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub tools: Option<Vec<serde_json::Value>>,
    pub rag_endpoint: Option<String>,
    pub function_format: Option<String>,
    pub memory_enabled: Option<bool>,
    pub max_tool_calls: Option<i32>,
    pub enabled: Option<bool>,
}

/// Request to start an agent test
#[derive(Debug, serde::Deserialize)]
pub struct StartAgentTestRequest {
    pub agent_config_id: String,
    pub test_case_ids: Option<Vec<String>>,  // If None, run all
    pub categories: Option<Vec<String>>,  // Filter by category
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// GET /api/ai-security/llm-security/agent-configs
pub async fn list_agent_configs(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<PaginationQuery>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let configs = sqlx::query_as::<_, AgentConfigRow>(
        r#"
        SELECT ac.id, ac.target_id, ac.name, ac.description, ac.tools, ac.rag_endpoint,
               ac.function_format, ac.memory_enabled, ac.max_tool_calls, ac.enabled,
               ac.created_at, ac.updated_at
        FROM llm_agent_configs ac
        INNER JOIN llm_targets t ON ac.target_id = t.id
        WHERE t.user_id = ?1
        ORDER BY ac.created_at DESC
        LIMIT ?2 OFFSET ?3
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch agent configs".to_string()))?;

    Ok(HttpResponse::Ok().json(configs))
}

/// POST /api/ai-security/llm-security/agent-configs
pub async fn create_agent_config(
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateAgentConfigRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let config_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Verify target belongs to user
    let _target = sqlx::query_as::<_, LLMTarget>(
        "SELECT * FROM llm_targets WHERE id = ?1 AND user_id = ?2"
    )
    .bind(&body.target_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to verify target".to_string()))?
    .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Target not found".to_string()))?;

    let tools_json = serde_json::to_string(&body.tools).unwrap_or_else(|_| "[]".to_string());

    sqlx::query(
        r#"
        INSERT INTO llm_agent_configs (id, target_id, name, description, tools, rag_endpoint,
            function_format, memory_enabled, max_tool_calls, enabled, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?10)
        "#
    )
    .bind(&config_id)
    .bind(&body.target_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&tools_json)
    .bind(&body.rag_endpoint)
    .bind(body.function_format.as_deref().unwrap_or("openai"))
    .bind(body.memory_enabled.unwrap_or(false))
    .bind(body.max_tool_calls.unwrap_or(10))
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to create agent config".to_string()))?;

    crate::db::log_audit(&pool, user_id, "llm_agent_config_create", Some("llm_agent_config"), Some(&config_id), Some(&format!("Created agent config: {}", body.name)), None).await?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": config_id,
        "message": "Agent config created successfully"
    })))
}

/// GET /api/ai-security/llm-security/agent-configs/{id}
pub async fn get_agent_config(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();
    let user_id = &claims.sub;

    let config = sqlx::query_as::<_, AgentConfigRow>(
        r#"
        SELECT ac.id, ac.target_id, ac.name, ac.description, ac.tools, ac.rag_endpoint,
               ac.function_format, ac.memory_enabled, ac.max_tool_calls, ac.enabled,
               ac.created_at, ac.updated_at
        FROM llm_agent_configs ac
        INNER JOIN llm_targets t ON ac.target_id = t.id
        WHERE ac.id = ?1 AND t.user_id = ?2
        "#,
    )
    .bind(&config_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch agent config".to_string()))?
    .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Agent config not found".to_string()))?;

    Ok(HttpResponse::Ok().json(config))
}

/// PUT /api/ai-security/llm-security/agent-configs/{id}
pub async fn update_agent_config(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateAgentConfigRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();

    // Verify config exists and belongs to user's target
    let existing = sqlx::query_as::<_, AgentConfigRow>(
        r#"
        SELECT ac.* FROM llm_agent_configs ac
        INNER JOIN llm_targets t ON ac.target_id = t.id
        WHERE ac.id = ?1 AND t.user_id = ?2
        "#,
    )
    .bind(&config_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch agent config".to_string()))?
    .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Agent config not found".to_string()))?;

    // Update fields
    if let Some(ref name) = body.name {
        sqlx::query("UPDATE llm_agent_configs SET name = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(name).bind(&now).bind(&existing.id).execute(pool.get_ref()).await?;
    }
    if let Some(ref description) = body.description {
        sqlx::query("UPDATE llm_agent_configs SET description = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(description).bind(&now).bind(&existing.id).execute(pool.get_ref()).await?;
    }
    if let Some(ref tools) = body.tools {
        let tools_json = serde_json::to_string(tools).unwrap_or_else(|_| "[]".to_string());
        sqlx::query("UPDATE llm_agent_configs SET tools = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(&tools_json).bind(&now).bind(&existing.id).execute(pool.get_ref()).await?;
    }
    if let Some(ref rag_endpoint) = body.rag_endpoint {
        sqlx::query("UPDATE llm_agent_configs SET rag_endpoint = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(rag_endpoint).bind(&now).bind(&existing.id).execute(pool.get_ref()).await?;
    }
    if let Some(ref function_format) = body.function_format {
        sqlx::query("UPDATE llm_agent_configs SET function_format = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(function_format).bind(&now).bind(&existing.id).execute(pool.get_ref()).await?;
    }
    if let Some(memory_enabled) = body.memory_enabled {
        sqlx::query("UPDATE llm_agent_configs SET memory_enabled = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(memory_enabled).bind(&now).bind(&existing.id).execute(pool.get_ref()).await?;
    }
    if let Some(max_tool_calls) = body.max_tool_calls {
        sqlx::query("UPDATE llm_agent_configs SET max_tool_calls = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(max_tool_calls).bind(&now).bind(&existing.id).execute(pool.get_ref()).await?;
    }
    if let Some(enabled) = body.enabled {
        sqlx::query("UPDATE llm_agent_configs SET enabled = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(enabled).bind(&now).bind(&existing.id).execute(pool.get_ref()).await?;
    }

    crate::db::log_audit(&pool, user_id, "llm_agent_config_update", Some("llm_agent_config"), Some(&config_id), Some("Updated agent config"), None).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": config_id,
        "message": "Agent config updated successfully"
    })))
}

/// DELETE /api/ai-security/llm-security/agent-configs/{id}
pub async fn delete_agent_config(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();
    let user_id = &claims.sub;

    // Verify config belongs to user's target before deleting
    let result = sqlx::query(
        r#"
        DELETE FROM llm_agent_configs WHERE id = ?1 AND target_id IN (
            SELECT id FROM llm_targets WHERE user_id = ?2
        )
        "#
    )
    .bind(&config_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to delete agent config".to_string()))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::new(ApiErrorKind::NotFound(String::new()), "Agent config not found".to_string()));
    }

    crate::db::log_audit(&pool, user_id, "llm_agent_config_delete", Some("llm_agent_config"), Some(&config_id), Some("Deleted agent config"), None).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Agent config deleted successfully"
    })))
}

/// GET /api/ai-security/llm-security/agent-test-cases
pub async fn list_agent_test_cases(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<TestCaseQuery>,
) -> Result<HttpResponse, ApiError> {
    let mut test_cases = sqlx::query_as::<_, AgentTestCaseRow>(
        r#"
        SELECT id, category, name, description, payload, target_tools, expected_behavior,
               severity, cwe_id, is_builtin, enabled, created_at
        FROM llm_agent_test_cases
        WHERE enabled = 1
        ORDER BY category, name
        "#,
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch agent test cases".to_string()))?;

    if let Some(ref category) = query.category {
        test_cases.retain(|t| t.category.eq_ignore_ascii_case(category));
    }

    Ok(HttpResponse::Ok().json(test_cases))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct AgentTestCaseRow {
    pub id: String,
    pub category: String,
    pub name: String,
    pub description: Option<String>,
    pub payload: String,
    pub target_tools: String,  // JSON array
    pub expected_behavior: Option<String>,
    pub severity: String,
    pub cwe_id: Option<String>,
    pub is_builtin: bool,
    pub enabled: bool,
    pub created_at: String,
}

/// POST /api/ai-security/llm-security/agent-test
pub async fn start_agent_test(
    pool: web::Data<SqlitePool>,
    body: web::Json<StartAgentTestRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let test_run_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    // Verify agent config exists and belongs to user
    let config = sqlx::query_as::<_, AgentConfigRow>(
        r#"
        SELECT ac.* FROM llm_agent_configs ac
        INNER JOIN llm_targets t ON ac.target_id = t.id
        WHERE ac.id = ?1 AND t.user_id = ?2
        "#,
    )
    .bind(&body.agent_config_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch agent config".to_string()))?
    .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Agent config not found".to_string()))?;

    // Get target info
    let target = sqlx::query_as::<_, LLMTarget>(
        "SELECT * FROM llm_targets WHERE id = ?1"
    )
    .bind(&config.target_id)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch target".to_string()))?;

    // Create test run record
    let test = LLMSecurityTest {
        id: test_run_id.clone(),
        user_id: user_id.clone(),
        target_name: format!("{} ({})", target.name, config.name),
        target_type: crate::ai_security::types::LLMTargetType::AgentSystem,
        target_config: Some(crate::ai_security::types::LLMTargetConfig {
            endpoint: target.endpoint.clone(),
            auth_type: Some("api_key".to_string()),
            api_key: target.api_key_encrypted.clone(),
            headers: target.headers.as_ref().and_then(|h| serde_json::from_str(h).ok()),
            request_template: None,
            response_path: None,
            rate_limit: None,
            timeout: Some(30),
        }),
        test_type: crate::ai_security::types::LLMTestType::All,
        status: LLMTestStatus::Running,
        tests_run: 0,
        vulnerabilities_found: 0,
        results: None,
        started_at: Some(now),
        completed_at: None,
        customer_id: body.customer_id.clone(),
        engagement_id: body.engagement_id.clone(),
        created_at: now,
    };

    crate::db::ai_security::create_llm_test(&pool, &test).await?;

    crate::db::log_audit(
        &pool,
        user_id,
        "llm_agent_test_start",
        Some("llm_test"),
        Some(&test_run_id),
        Some(&format!("Started agent test against {}", target.name)),
        None,
    )
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "test_run_id": test_run_id,
        "status": "running",
        "message": "Agent test started"
    })))
}

// ============================================================================
// Model Fingerprinting
// ============================================================================

/// POST /api/ai-security/llm-security/fingerprint/{target_id}
pub async fn fingerprint_model(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let target_id = path.into_inner();
    let user_id = &claims.sub;

    // Verify target belongs to user
    let target = sqlx::query_as::<_, LLMTarget>(
        "SELECT * FROM llm_targets WHERE id = ?1 AND user_id = ?2"
    )
    .bind(&target_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch target".to_string()))?
    .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Target not found".to_string()))?;

    // Run fingerprinting
    use crate::ai_security::llm_testing::fingerprinting::ModelFingerprinter;

    let fingerprinter = ModelFingerprinter::new();
    let config = crate::ai_security::types::LLMTargetConfig {
        endpoint: target.endpoint.clone(),
        auth_type: Some("api_key".to_string()),
        api_key: target.api_key_encrypted.clone(),
        headers: target.headers.as_ref().and_then(|h| serde_json::from_str(h).ok()),
        request_template: None,
        response_path: None,
        rate_limit: Some(10),
        timeout: Some(60),
    };

    let fingerprint = fingerprinter.fingerprint_model(&config).await
        .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Fingerprinting failed".to_string()))?;

    // Store fingerprint in database
    let fingerprint_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let expires = (Utc::now() + chrono::Duration::days(7)).to_rfc3339();

    let indicators_json = serde_json::to_string(&fingerprint.indicators).unwrap_or_else(|_| "[]".to_string());
    let vulns_json = serde_json::to_string(&fingerprint.known_vulnerabilities).unwrap_or_else(|_| "[]".to_string());
    let safety_json = serde_json::to_string(&fingerprint.safety_mechanisms).unwrap_or_else(|_| "{}".to_string());

    sqlx::query(
        r#"
        INSERT INTO llm_model_fingerprints (id, target_id, model_family, confidence, indicators,
            known_vulnerabilities, context_window_estimate, safety_mechanisms, fingerprint_version,
            created_at, expires_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '1.0', ?9, ?10)
        "#
    )
    .bind(&fingerprint_id)
    .bind(&target_id)
    .bind(&fingerprint.likely_model_family)
    .bind(fingerprint.confidence)
    .bind(&indicators_json)
    .bind(&vulns_json)
    .bind(fingerprint.estimated_context_window.map(|c| c as i64))
    .bind(&safety_json)
    .bind(&now)
    .bind(&expires)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to store fingerprint".to_string()))?;

    crate::db::log_audit(&pool, user_id, "llm_fingerprint", Some("llm_fingerprint"), Some(&fingerprint_id), Some(&format!("Fingerprinted model: {}", fingerprint.likely_model_family)), None).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": fingerprint_id,
        "fingerprint": fingerprint
    })))
}

/// GET /api/ai-security/llm-security/fingerprints/{target_id}
pub async fn get_fingerprint(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let target_id = path.into_inner();
    let user_id = &claims.sub;

    // Verify target belongs to user
    let _target = sqlx::query_as::<_, LLMTarget>(
        "SELECT * FROM llm_targets WHERE id = ?1 AND user_id = ?2"
    )
    .bind(&target_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch target".to_string()))?
    .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Target not found".to_string()))?;

    // Get latest fingerprint
    let fingerprint = sqlx::query_as::<_, FingerprintRow>(
        r#"
        SELECT id, target_id, model_family, confidence, indicators, known_vulnerabilities,
               context_window_estimate, safety_mechanisms, fingerprint_version, created_at, expires_at
        FROM llm_model_fingerprints
        WHERE target_id = ?1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&target_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch fingerprint".to_string()))?;

    match fingerprint {
        Some(fp) => Ok(HttpResponse::Ok().json(fp)),
        None => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "No fingerprint found. Run fingerprinting first."
        }))),
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct FingerprintRow {
    pub id: String,
    pub target_id: String,
    pub model_family: Option<String>,
    pub confidence: Option<f64>,
    pub indicators: String,  // JSON
    pub known_vulnerabilities: String,  // JSON
    pub context_window_estimate: Option<i64>,
    pub safety_mechanisms: String,  // JSON
    pub fingerprint_version: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

// ============================================================================
// LLM Security Reports
// ============================================================================

/// Request to generate an LLM security report
#[derive(Debug, serde::Deserialize)]
pub struct GenerateReportRequest {
    pub name: Option<String>,
    pub format: Option<String>,  // "markdown", "html", "pdf"
    pub include_transcripts: Option<bool>,
    pub include_remediation: Option<bool>,
}

/// POST /api/ai-security/llm-security/tests/{id}/report
pub async fn generate_llm_report(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<GenerateReportRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let test_id = path.into_inner();
    let user_id = &claims.sub;

    // Verify test exists and belongs to user
    let test = crate::db::ai_security::get_llm_test(&pool, &test_id).await?
        .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Test not found".to_string()))?;

    let is_admin = crate::db::has_permission(&pool, user_id, "can_view_all_scans").await?;
    if test.user_id != *user_id && !is_admin {
        return Err(ApiError::new(ApiErrorKind::Forbidden(String::new()), "Access denied".to_string()));
    }

    let report_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let report_name = body.name.clone().unwrap_or_else(|| format!("LLM Security Report - {}", test.target_name));
    let format = body.format.clone().unwrap_or_else(|| "markdown".to_string());

    // Create report record
    sqlx::query(
        r#"
        INSERT INTO llm_security_reports (id, test_run_id, name, format, status, created_at)
        VALUES (?1, ?2, ?3, ?4, 'generating', ?5)
        "#
    )
    .bind(&report_id)
    .bind(&test_id)
    .bind(&report_name)
    .bind(&format)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to create report".to_string()))?;

    // Generate report content using LLMReportGenerator
    use crate::reports::llm_security::LLMReportGenerator;
    use crate::ai_security::types::LLMReportFormat;

    let report_format = match format.as_str() {
        "html" => LLMReportFormat::Html,
        "pdf" => LLMReportFormat::Pdf,
        "json" => LLMReportFormat::Json,
        _ => LLMReportFormat::Markdown,
    };

    let generator = LLMReportGenerator::new();

    // Get test results for the report
    let single_turn_results: Vec<crate::ai_security::types::LLMTestResult> = test.results
        .as_ref()
        .and_then(|r| serde_json::from_value(r.clone()).ok())
        .unwrap_or_default();

    let report_data = generator.generate_report(
        &test,
        single_turn_results,
        Vec::new(),  // conversation_results
        Vec::new(),  // agent_results
        None,        // fingerprint
        None,        // customer_name
    );

    let content = generator.generate_formatted(&report_data, report_format)
        .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to generate report".to_string()))?;

    // Save report file
    let reports_dir = std::env::var("REPORTS_DIR").unwrap_or_else(|_| "./reports".to_string());
    let extension = match format.as_str() {
        "html" => "html",
        "json" => "json",
        "pdf" => "md",  // PDF generation would need additional processing
        _ => "md",
    };
    let file_path = format!("{}/llm_security_{}_{}.{}", reports_dir, test_id, report_id, extension);

    // Create reports directory if needed
    let _ = std::fs::create_dir_all(&reports_dir);
    std::fs::write(&file_path, &content)
        .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to write report".to_string()))?;

    let file_size = content.len() as i64;

    // Calculate summary statistics
    let total_tests = report_data.test_summary.total_tests;
    let risk_score = report_data.executive_summary.overall_risk_score;
    let critical_count = report_data.executive_summary.critical_count;
    let high_count = report_data.executive_summary.high_count;
    let medium_count = report_data.executive_summary.medium_count;
    let low_count = report_data.executive_summary.low_count;

    // Update report record
    let completed_at = Utc::now().to_rfc3339();
    let exec_summary = format!(
        "Risk Level: {:?} | {} tests run, {} vulnerabilities found",
        report_data.executive_summary.overall_risk_level,
        total_tests,
        report_data.executive_summary.vulnerabilities_found
    );
    sqlx::query(
        r#"
        UPDATE llm_security_reports
        SET status = 'completed', file_path = ?1, file_size = ?2, risk_score = ?3,
            findings_count = ?4, critical_count = ?5, high_count = ?6, medium_count = ?7, low_count = ?8,
            executive_summary = ?9, completed_at = ?10
        WHERE id = ?11
        "#
    )
    .bind(&file_path)
    .bind(file_size)
    .bind(risk_score)
    .bind(total_tests as i32)
    .bind(critical_count as i32)
    .bind(high_count as i32)
    .bind(medium_count as i32)
    .bind(low_count as i32)
    .bind(&exec_summary)
    .bind(&completed_at)
    .bind(&report_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to update report".to_string()))?;

    crate::db::log_audit(&pool, user_id, "llm_report_generate", Some("llm_report"), Some(&report_id), Some(&format!("Generated LLM security report: {}", report_name)), None).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "report_id": report_id,
        "file_path": file_path,
        "format": format,
        "risk_score": risk_score,
        "findings_count": total_tests,
        "status": "completed"
    })))
}

/// GET /api/ai-security/llm-security/reports/{id}
pub async fn get_llm_report(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let report_id = path.into_inner();
    let user_id = &claims.sub;

    let report = sqlx::query_as::<_, LLMReportRow>(
        r#"
        SELECT r.id, r.test_run_id, r.name, r.format, r.file_path, r.file_size,
               r.executive_summary, r.risk_score, r.findings_count, r.critical_count,
               r.high_count, r.medium_count, r.low_count, r.status, r.created_at, r.completed_at
        FROM llm_security_reports r
        INNER JOIN llm_security_tests t ON r.test_run_id = t.id
        WHERE r.id = ?1 AND t.user_id = ?2
        "#,
    )
    .bind(&report_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch report".to_string()))?;

    match report {
        Some(r) => Ok(HttpResponse::Ok().json(r)),
        None => {
            // Check if user is admin
            let is_admin = crate::db::has_permission(&pool, user_id, "can_view_all_scans").await?;
            if is_admin {
                let report = sqlx::query_as::<_, LLMReportRow>(
                    r#"
                    SELECT id, test_run_id, name, format, file_path, file_size,
                           executive_summary, risk_score, findings_count, critical_count,
                           high_count, medium_count, low_count, status, created_at, completed_at
                    FROM llm_security_reports
                    WHERE id = ?1
                    "#,
                )
                .bind(&report_id)
                .fetch_optional(pool.get_ref())
                .await
                .map_err(|e| ApiError::new(ApiErrorKind::InternalError(e.to_string()), "Failed to fetch report".to_string()))?
                .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Report not found".to_string()))?;
                Ok(HttpResponse::Ok().json(report))
            } else {
                Err(ApiError::new(ApiErrorKind::NotFound(String::new()), "Report not found".to_string()))
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct LLMReportRow {
    pub id: String,
    pub test_run_id: String,
    pub name: String,
    pub format: String,
    pub file_path: Option<String>,
    pub file_size: Option<i64>,
    pub executive_summary: Option<String>,
    pub risk_score: Option<f64>,
    pub findings_count: Option<i32>,
    pub critical_count: Option<i32>,
    pub high_count: Option<i32>,
    pub medium_count: Option<i32>,
    pub low_count: Option<i32>,
    pub status: String,
    pub created_at: String,
    pub completed_at: Option<String>,
}

// ============================================================================
// Remediation Guidance
// ============================================================================

/// GET /api/ai-security/llm-security/remediation/{category}
pub async fn get_remediation(
    _pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let category = path.into_inner().to_lowercase();

    use crate::ai_security::llm_testing::remediation::{get_llm_remediation, get_agent_remediation};
    use crate::ai_security::types::{LLMTestCategory, AgentTestCategory, TestCaseSeverity};

    // Match LLM categories
    let llm_cat = match category.as_str() {
        "prompt_injection" | "promptinjection" => Some(LLMTestCategory::PromptInjection),
        "jailbreak" => Some(LLMTestCategory::Jailbreak),
        "data_extraction" | "dataextraction" => Some(LLMTestCategory::DataExtraction),
        "encoding" => Some(LLMTestCategory::Encoding),
        "context_manipulation" | "contextmanipulation" => Some(LLMTestCategory::ContextManipulation),
        "role_confusion" | "roleconfusion" => Some(LLMTestCategory::RoleConfusion),
        "indirect_injection" | "indirectinjection" => Some(LLMTestCategory::IndirectInjection),
        "chain_of_thought" | "chainofthought" => Some(LLMTestCategory::ChainOfThought),
        _ => None,
    };

    if let Some(cat) = llm_cat {
        let remediation = get_llm_remediation(&cat, &TestCaseSeverity::High);
        return Ok(HttpResponse::Ok().json(remediation));
    }

    // Match agent categories
    let agent_cat = match category.as_str() {
        "tool_parameter_injection" | "toolparameterinjection" => Some(AgentTestCategory::ToolParameterInjection),
        "tool_chaining" | "toolchaining" => Some(AgentTestCategory::ToolChaining),
        "rag_poisoning" | "ragpoisoning" => Some(AgentTestCategory::RagPoisoning),
        "function_call_hijacking" | "functioncallhijacking" => Some(AgentTestCategory::FunctionCallHijacking),
        "memory_poisoning" | "memorypoisoning" => Some(AgentTestCategory::MemoryPoisoning),
        "tool_output_injection" | "tooloutputinjection" => Some(AgentTestCategory::ToolOutputInjection),
        "privilege_escalation" | "privilegeescalation" => Some(AgentTestCategory::PrivilegeEscalation),
        "data_exfiltration" | "dataexfiltration" => Some(AgentTestCategory::DataExfiltration),
        "system_tool_invocation" | "systemtoolinvocation" => Some(AgentTestCategory::SystemToolInvocation),
        "indirect_prompt_injection" | "indirectpromptinjection" => Some(AgentTestCategory::IndirectPromptInjection),
        _ => None,
    };

    if let Some(cat) = agent_cat {
        let remediation = get_agent_remediation(&cat, &TestCaseSeverity::High);
        return Ok(HttpResponse::Ok().json(remediation));
    }

    // Return all remediation guidance if category not found or "all" requested
    let all_llm: Vec<_> = [
        LLMTestCategory::PromptInjection,
        LLMTestCategory::Jailbreak,
        LLMTestCategory::DataExtraction,
        LLMTestCategory::Encoding,
        LLMTestCategory::ContextManipulation,
        LLMTestCategory::RoleConfusion,
        LLMTestCategory::IndirectInjection,
        LLMTestCategory::ChainOfThought,
    ].iter().map(|c| get_llm_remediation(c, &TestCaseSeverity::High)).collect();

    let all_agent: Vec<_> = [
        AgentTestCategory::ToolParameterInjection,
        AgentTestCategory::ToolChaining,
        AgentTestCategory::RagPoisoning,
        AgentTestCategory::FunctionCallHijacking,
        AgentTestCategory::MemoryPoisoning,
        AgentTestCategory::ToolOutputInjection,
        AgentTestCategory::PrivilegeEscalation,
        AgentTestCategory::DataExfiltration,
        AgentTestCategory::SystemToolInvocation,
        AgentTestCategory::IndirectPromptInjection,
    ].iter().map(|c| get_agent_remediation(c, &TestCaseSeverity::High)).collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "llm_categories": all_llm,
        "agent_categories": all_agent
    })))
}

// ============================================================================
// Query Parameters
// ============================================================================

#[derive(Debug, serde::Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, serde::Deserialize)]
pub struct TestCaseQuery {
    pub category: Option<String>,
    pub enabled_only: Option<bool>,
}
