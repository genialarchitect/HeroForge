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

    // Queue assessment for background processing
    let pool_clone = pool.get_ref().clone();
    let assessment_id_clone = assessment_id.clone();
    let config_clone = req.config.clone();

    tokio::spawn(async move {
        log::info!("Starting Web3 assessment: {}", assessment_id_clone);

        // Update status to running
        let _ = sqlx::query(
            "UPDATE web3_assessments SET status = 'running' WHERE id = ?"
        )
        .bind(&assessment_id_clone)
        .execute(&pool_clone)
        .await;

        // Run the assessment
        match web3::run_web3_assessment(&config_clone).await {
            Ok(assessment) => {
                // Store results
                let results_json = serde_json::to_string(&assessment).unwrap_or_default();
                let findings_count = assessment.smart_contract_findings.len()
                    + assessment.defi_findings.len()
                    + assessment.nft_findings.len()
                    + assessment.dapp_findings.len()
                    + assessment.wallet_findings.len()
                    + assessment.exchange_findings.len()
                    + assessment.staking_findings.len()
                    + assessment.cross_chain_findings.len();

                let completed_at = chrono::Utc::now().to_rfc3339();

                let _ = sqlx::query(
                    r#"
                    UPDATE web3_assessments
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
                    "Web3 assessment {} completed with {} findings",
                    assessment_id_clone,
                    findings_count
                );
            }
            Err(e) => {
                log::error!("Web3 assessment {} failed: {}", assessment_id_clone, e);

                let _ = sqlx::query(
                    "UPDATE web3_assessments SET status = 'failed', error_message = ? WHERE id = ?"
                )
                .bind(format!("{}", e))
                .bind(&assessment_id_clone)
                .execute(&pool_clone)
                .await;
            }
        }
    });

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
