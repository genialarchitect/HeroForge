//! Emerging technology security API endpoints

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use anyhow::Result;

use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;
use crate::emerging_tech;

#[derive(Debug, Deserialize)]
pub struct CreateEmergingTechAssessmentRequest {
    pub assessment_name: String,
    pub config: emerging_tech::EmergingTechConfig,
}

#[derive(Debug, Serialize)]
pub struct EmergingTechAssessmentResponse {
    pub id: String,
    pub assessment_name: String,
    pub status: String,
    pub created_at: String,
}

/// Create a new emerging technology security assessment
pub async fn create_assessment(
    claims: Claims,
    pool: web::Data<SqlitePool>,
    req: web::Json<CreateEmergingTechAssessmentRequest>,
) -> Result<HttpResponse, ApiError> {
    let assessment_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let assessment_types = serde_json::to_string(&serde_json::json!({
        "5g": req.config.assess_5g,
        "adversarial_ml": req.config.assess_adversarial_ml,
        "quantum": req.config.assess_quantum,
        "xr": req.config.assess_xr,
    }))
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // Store assessment in database
    sqlx::query(
        r#"
        INSERT INTO emerging_tech_assessments (id, user_id, assessment_name, assessment_types, created_at, status)
        VALUES (?, ?, ?, ?, ?, 'pending')
        "#,
    )
    .bind(&assessment_id)
    .bind(&claims.sub)
    .bind(&req.assessment_name)
    .bind(&assessment_types)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // TODO: Queue assessment for background processing

    Ok(HttpResponse::Ok().json(EmergingTechAssessmentResponse {
        id: assessment_id,
        assessment_name: req.assessment_name.clone(),
        status: "pending".to_string(),
        created_at: now,
    }))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/emerging-tech")
            .route("/assessments", web::post().to(create_assessment)),
    );
}
