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

    // Queue assessment for background processing
    let pool_clone = pool.get_ref().clone();
    let assessment_id_clone = assessment_id.clone();
    let config_clone = req.config.clone();

    tokio::spawn(async move {
        log::info!("Starting emerging tech assessment: {}", assessment_id_clone);

        // Update status to running
        let _ = sqlx::query(
            "UPDATE emerging_tech_assessments SET status = 'running' WHERE id = ?"
        )
        .bind(&assessment_id_clone)
        .execute(&pool_clone)
        .await;

        // Run the assessment
        match emerging_tech::run_emerging_tech_assessment(&config_clone).await {
            Ok(assessment) => {
                // Store results
                let results_json = serde_json::to_string(&assessment).unwrap_or_default();
                let findings_count = assessment.fiveg_findings.len()
                    + assessment.adversarial_ml_findings.len()
                    + assessment.xr_findings.len();

                let completed_at = chrono::Utc::now().to_rfc3339();

                let _ = sqlx::query(
                    r#"
                    UPDATE emerging_tech_assessments
                    SET status = 'completed', results = ?, findings_count = ?, completed_at = ?
                    WHERE id = ?
                    "#,
                )
                .bind(&results_json)
                .bind(findings_count as i32)
                .bind(&completed_at)
                .bind(&assessment_id_clone)
                .execute(&pool_clone)
                .await;

                log::info!(
                    "Emerging tech assessment {} completed with {} findings",
                    assessment_id_clone,
                    findings_count
                );
            }
            Err(e) => {
                log::error!("Emerging tech assessment {} failed: {}", assessment_id_clone, e);

                let _ = sqlx::query(
                    "UPDATE emerging_tech_assessments SET status = 'failed', error_message = ? WHERE id = ?"
                )
                .bind(format!("{}", e))
                .bind(&assessment_id_clone)
                .execute(&pool_clone)
                .await;
            }
        }
    });

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
