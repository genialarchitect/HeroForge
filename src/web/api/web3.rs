//! Web3 security API endpoints

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use anyhow::Result;

use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;
use crate::web3;

#[derive(Debug, Deserialize)]
pub struct CreateWeb3AssessmentRequest {
    pub assessment_name: String,
    pub config: web3::Web3AssessmentConfig,
}

#[derive(Debug, Serialize)]
pub struct Web3AssessmentResponse {
    pub id: String,
    pub assessment_name: String,
    pub status: String,
    pub created_at: String,
}

/// Create a new Web3 security assessment
pub async fn create_assessment(
    claims: Claims,
    pool: web::Data<SqlitePool>,
    req: web::Json<CreateWeb3AssessmentRequest>,
) -> Result<HttpResponse, ApiError> {
    let assessment_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    // Store assessment in database
    sqlx::query(
        r#"
        INSERT INTO web3_assessments (id, user_id, assessment_name, blockchain_network, created_at, status)
        VALUES (?, ?, ?, ?, ?, 'pending')
        "#,
    )
    .bind(&assessment_id)
    .bind(&claims.sub)
    .bind(&req.assessment_name)
    .bind(format!("{:?}", req.config.chain))
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // TODO: Queue assessment for background processing

    Ok(HttpResponse::Ok().json(Web3AssessmentResponse {
        id: assessment_id,
        assessment_name: req.assessment_name.clone(),
        status: "pending".to_string(),
        created_at: now,
    }))
}

/// Get Web3 assessment by ID
pub async fn get_assessment(
    _claims: Claims,
    pool: web::Data<SqlitePool>,
    assessment_id: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let assessment = sqlx::query_as::<_, (String, String, String, String, String)>(
        r#"
        SELECT id, assessment_name, blockchain_network, status, created_at
        FROM web3_assessments
        WHERE id = ?
        "#,
    )
    .bind(assessment_id.as_str())
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .ok_or(ApiError::not_found("Assessment not found"))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": assessment.0,
        "assessment_name": assessment.1,
        "blockchain_network": assessment.2,
        "status": assessment.3,
        "created_at": assessment.4,
    })))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/web3")
            .route("/assessments", web::post().to(create_assessment))
            .route("/assessments/{id}", web::get().to(get_assessment)),
    );
}
