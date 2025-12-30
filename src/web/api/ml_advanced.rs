//! Advanced ML API endpoints (XAI, MLOps, Federated Learning)

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use anyhow::Result;

use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;
use crate::ml::{xai, mlops, federated};

// ============================================================================
// XAI Endpoints
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ExplainPredictionRequest {
    pub model_id: String,
    pub prediction_id: String,
    pub config: xai::XAIConfig,
}

/// Get explanation for a model prediction
pub async fn explain_prediction(
    _claims: Claims,
    _pool: web::Data<SqlitePool>,
    req: web::Json<ExplainPredictionRequest>,
) -> Result<HttpResponse, ApiError> {
    let explanation = xai::explain_prediction(&req.model_id, &req.prediction_id, &req.config)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(explanation))
}

// ============================================================================
// MLOps Endpoints
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct TrainModelRequest {
    pub config: mlops::AutoTrainingConfig,
}

/// Trigger automated model training
pub async fn train_model(
    _claims: Claims,
    _pool: web::Data<SqlitePool>,
    req: web::Json<TrainModelRequest>,
) -> Result<HttpResponse, ApiError> {
    let result = mlops::train_model_automated(&req.config)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Debug, Deserialize)]
pub struct DeployModelRequest {
    pub config: mlops::DeploymentConfig,
}

/// Deploy model to production
pub async fn deploy_model(
    _claims: Claims,
    pool: web::Data<SqlitePool>,
    req: web::Json<DeployModelRequest>,
) -> Result<HttpResponse, ApiError> {
    let result = mlops::deploy_model(&req.config)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Store deployment in database
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        r#"
        INSERT INTO mlops_deployments (id, model_id, deployment_strategy, endpoint_url, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&result.deployment_id)
    .bind(&req.config.model_id)
    .bind(format!("{:?}", req.config.deployment_strategy))
    .bind(&result.endpoint_url)
    .bind(format!("{:?}", result.status))
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(result))
}

/// Get model monitoring metrics
pub async fn get_monitoring_metrics(
    _claims: Claims,
    _pool: web::Data<SqlitePool>,
    model_id: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let metrics = mlops::monitor_model(&model_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(metrics))
}

// ============================================================================
// Federated Learning Endpoints
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateFederationRequest {
    pub config: federated::FederatedLearningConfig,
}

/// Create a new federated learning federation
pub async fn create_federation(
    claims: Claims,
    pool: web::Data<SqlitePool>,
    req: web::Json<CreateFederationRequest>,
) -> Result<HttpResponse, ApiError> {
    let model = federated::train_federated_model(&req.config)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Store federation in database
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        r#"
        INSERT INTO ml_federated_federations
        (id, name, aggregation_strategy, min_participants, secure_aggregation, differential_privacy, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&model.federation_id)
    .bind(&req.config.federation_id)
    .bind(format!("{:?}", req.config.aggregation_strategy))
    .bind(req.config.min_participants_per_round as i64)
    .bind(req.config.secure_aggregation)
    .bind(req.config.differential_privacy.is_some())
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(model))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/ml")
            .route("/xai/explain", web::post().to(explain_prediction))
            .route("/mlops/train", web::post().to(train_model))
            .route("/mlops/deploy", web::post().to(deploy_model))
            .route("/mlops/monitoring/{model_id}", web::get().to(get_monitoring_metrics))
            .route("/federated/create", web::post().to(create_federation)),
    );
}
