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
