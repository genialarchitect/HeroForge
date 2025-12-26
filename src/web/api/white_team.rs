// White Team API - Governance, Risk & Compliance (GRC)
//
// Provides REST API endpoints for:
// - Policy Management
// - Risk Management
// - Control Framework
// - Audit Management
// - Vendor Risk Management

use actix_web::{web, HttpResponse, Scope};
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::web::auth;

// ============================================================================
// Request/Response Types
// ============================================================================

// Policy Types
#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePolicyRequest {
    pub title: String,
    pub category: String,
    pub content: String,
    pub summary: Option<String>,
    pub effective_date: Option<NaiveDate>,
    pub review_date: Option<NaiveDate>,
    pub requires_acknowledgment: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdatePolicyRequest {
    pub title: Option<String>,
    pub content: Option<String>,
    pub summary: Option<String>,
    pub change_summary: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyApprovalRequest {
    pub approved: bool,
    pub comments: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitForApprovalRequest {
    pub approver_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateExceptionRequest {
    pub title: String,
    pub description: String,
    pub justification: String,
    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecideExceptionRequest {
    pub approved: bool,
    pub risk_accepted: Option<String>,
    pub compensating_controls: Option<String>,
}

// Risk Types
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRiskRequest {
    pub title: String,
    pub description: String,
    pub category: String,
    pub inherent_likelihood: i32,
    pub inherent_impact: i32,
    pub source: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssessRiskRequest {
    pub assessment_type: String,
    pub likelihood: i32,
    pub impact: i32,
    pub likelihood_rationale: Option<String>,
    pub impact_rationale: Option<String>,
    pub threats: Option<Vec<String>>,
    pub vulnerabilities: Option<Vec<String>>,
    pub recommendations: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetTreatmentRequest {
    pub strategy: String,
    pub plan: Option<String>,
    pub target_date: Option<NaiveDate>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FairAnalysisRequest {
    pub tef_min: f64,
    pub tef_likely: f64,
    pub tef_max: f64,
    pub vulnerability: f64,
    pub loss_min: f64,
    pub loss_likely: f64,
    pub loss_max: f64,
    pub currency: String,
    pub confidence: f64,
}

// Control Types
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateControlRequest {
    pub title: String,
    pub description: String,
    pub category: String,
    pub control_type: String,
    pub domain: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddMappingRequest {
    pub framework: String,
    pub framework_control_id: String,
    pub framework_control_name: Option<String>,
    pub mapping_notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecordTestRequest {
    pub test_type: String,
    pub test_procedure: String,
    pub result: String,
    pub findings: Option<String>,
    pub sample_size: Option<i32>,
    pub evidence_refs: Option<Vec<String>>,
}

// Audit Types
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAuditRequest {
    pub title: String,
    pub audit_type: String,
    pub scope: String,
    pub objectives: Option<String>,
    pub planned_start_date: Option<NaiveDate>,
    pub planned_end_date: Option<NaiveDate>,
    pub frameworks: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateFindingRequest {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub recommendation: String,
    pub control_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateFindingRequest {
    pub root_cause: Option<String>,
    pub management_response: Option<String>,
    pub remediation_owner_id: Option<String>,
    pub remediation_due_date: Option<NaiveDate>,
    pub status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddEvidenceRequest {
    pub name: String,
    pub description: Option<String>,
    pub evidence_type: String,
    pub file_path: Option<String>,
    pub file_hash: Option<String>,
    pub finding_id: Option<String>,
}

// Vendor Types
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateVendorRequest {
    pub name: String,
    pub category: String,
    pub tier: String,
    pub services_provided: Option<String>,
    pub data_access_level: String,
    pub data_types_accessed: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateVendorRequest {
    pub contact_name: Option<String>,
    pub contact_email: Option<String>,
    pub contract_start_date: Option<NaiveDate>,
    pub contract_end_date: Option<NaiveDate>,
    pub contract_value: Option<f64>,
    pub soc2_report: Option<bool>,
    pub iso_27001_certified: Option<bool>,
    pub other_certifications: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAssessmentRequest {
    pub assessment_type: String,
    pub questionnaire_id: Option<String>,
    pub questionnaire_score: Option<f64>,
    pub risk_areas: Option<Vec<String>>,
    pub findings: Option<Vec<String>>,
    pub recommendations: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecideAssessmentRequest {
    pub approved: bool,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateQuestionnaireRequest {
    pub name: String,
    pub description: Option<String>,
    pub questions: Vec<serde_json::Value>,
    pub scoring_method: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitResponseRequest {
    pub questionnaire_id: String,
    pub assessment_id: Option<String>,
    pub responses: serde_json::Value,
}

// Query Types
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub status: Option<String>,
    pub category: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

// ============================================================================
// Policy Management Handlers
// ============================================================================

async fn list_policies(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<ListQuery>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let result = sqlx::query(
        r#"
        SELECT id, policy_number, title, category, status, version, summary,
               owner_id, effective_date, review_date, requires_acknowledgment,
               created_at, updated_at
        FROM grc_policies
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await;

    match result {
        Ok(rows) => {
            let policies: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    serde_json::json!({
                        "id": row.get::<String, _>("id"),
                        "policy_number": row.get::<String, _>("policy_number"),
                        "title": row.get::<String, _>("title"),
                        "category": row.get::<String, _>("category"),
                        "status": row.get::<String, _>("status"),
                        "version": row.get::<String, _>("version"),
                        "summary": row.get::<Option<String>, _>("summary"),
                        "owner_id": row.get::<String, _>("owner_id"),
                        "effective_date": row.get::<Option<String>, _>("effective_date"),
                        "review_date": row.get::<Option<String>, _>("review_date"),
                        "requires_acknowledgment": row.get::<bool, _>("requires_acknowledgment"),
                        "created_at": row.get::<String, _>("created_at"),
                        "updated_at": row.get::<String, _>("updated_at"),
                    })
                })
                .collect();

            HttpResponse::Ok().json(serde_json::json!({ "policies": policies }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to list policies: {}", e)
        })),
    }
}

async fn create_policy(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreatePolicyRequest>,
) -> HttpResponse {
    let id = Uuid::new_v4().to_string();
    let policy_number = format!("POL-{}", &id[..8].to_uppercase());
    let now = Utc::now();

    let result = sqlx::query(
        r#"
        INSERT INTO grc_policies (
            id, policy_number, title, category, status, version, content, summary,
            owner_id, effective_date, review_date, requires_acknowledgment,
            created_at, updated_at
        )
        VALUES (?, ?, ?, ?, 'draft', '1.0', ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&policy_number)
    .bind(&body.title)
    .bind(&body.category)
    .bind(&body.content)
    .bind(&body.summary)
    .bind(&claims.sub)
    .bind(&body.effective_date)
    .bind(&body.review_date)
    .bind(body.requires_acknowledgment.unwrap_or(true))
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => {
            // Create initial version
            let version_id = Uuid::new_v4().to_string();
            let _ = sqlx::query(
                r#"
                INSERT INTO grc_policy_versions (id, policy_id, version, content, change_summary, created_by, created_at)
                VALUES (?, ?, '1.0', ?, 'Initial version', ?, ?)
                "#,
            )
            .bind(&version_id)
            .bind(&id)
            .bind(&body.content)
            .bind(&claims.sub)
            .bind(now.to_rfc3339())
            .execute(pool.get_ref())
            .await;

            HttpResponse::Created().json(serde_json::json!({
                "id": id,
                "policy_number": policy_number,
                "message": "Policy created successfully"
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create policy: {}", e)
        })),
    }
}

async fn get_policy(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let policy_id = path.into_inner();

    let result = sqlx::query(
        r#"
        SELECT id, policy_number, title, category, status, version, content, summary,
               owner_id, effective_date, review_date, expiry_date, parent_policy_id,
               requires_acknowledgment, created_at, updated_at
        FROM grc_policies
        WHERE id = ?
        "#,
    )
    .bind(&policy_id)
    .fetch_optional(pool.get_ref())
    .await;

    match result {
        Ok(Some(row)) => {
            HttpResponse::Ok().json(serde_json::json!({
                "id": row.get::<String, _>("id"),
                "policy_number": row.get::<String, _>("policy_number"),
                "title": row.get::<String, _>("title"),
                "category": row.get::<String, _>("category"),
                "status": row.get::<String, _>("status"),
                "version": row.get::<String, _>("version"),
                "content": row.get::<String, _>("content"),
                "summary": row.get::<Option<String>, _>("summary"),
                "owner_id": row.get::<String, _>("owner_id"),
                "effective_date": row.get::<Option<String>, _>("effective_date"),
                "review_date": row.get::<Option<String>, _>("review_date"),
                "expiry_date": row.get::<Option<String>, _>("expiry_date"),
                "parent_policy_id": row.get::<Option<String>, _>("parent_policy_id"),
                "requires_acknowledgment": row.get::<bool, _>("requires_acknowledgment"),
                "created_at": row.get::<String, _>("created_at"),
                "updated_at": row.get::<String, _>("updated_at"),
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Policy not found"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get policy: {}", e)
        })),
    }
}

async fn submit_for_review(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let policy_id = path.into_inner();
    let now = Utc::now();

    let result = sqlx::query(
        "UPDATE grc_policies SET status = 'pending_review', updated_at = ? WHERE id = ? AND status = 'draft'",
    )
    .bind(now.to_rfc3339())
    .bind(&policy_id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Policy submitted for review"
            }))
        }
        Ok(_) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Policy not found or not in draft status"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to submit policy: {}", e)
        })),
    }
}

async fn submit_for_approval(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<SubmitForApprovalRequest>,
) -> HttpResponse {
    let policy_id = path.into_inner();
    let now = Utc::now();

    // Get current version
    let version_result = sqlx::query("SELECT version FROM grc_policies WHERE id = ?")
        .bind(&policy_id)
        .fetch_optional(pool.get_ref())
        .await;

    let version = match version_result {
        Ok(Some(row)) => row.get::<String, _>("version"),
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Policy not found"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get policy: {}", e)
            }));
        }
    };

    // Update status
    let _ = sqlx::query(
        "UPDATE grc_policies SET status = 'pending_approval', updated_at = ? WHERE id = ?",
    )
    .bind(now.to_rfc3339())
    .bind(&policy_id)
    .execute(pool.get_ref())
    .await;

    // Create approval records
    for approver_id in &body.approver_ids {
        let approval_id = Uuid::new_v4().to_string();
        let _ = sqlx::query(
            r#"
            INSERT INTO grc_policy_approvals (id, policy_id, version, approver_id, status, created_at)
            VALUES (?, ?, ?, ?, 'pending', ?)
            "#,
        )
        .bind(&approval_id)
        .bind(&policy_id)
        .bind(&version)
        .bind(approver_id)
        .bind(now.to_rfc3339())
        .execute(pool.get_ref())
        .await;
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Policy submitted for approval",
        "approvers_count": body.approver_ids.len()
    }))
}

async fn acknowledge_policy(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let policy_id = path.into_inner();
    let now = Utc::now();

    // Get current version
    let version_result = sqlx::query("SELECT version, status FROM grc_policies WHERE id = ?")
        .bind(&policy_id)
        .fetch_optional(pool.get_ref())
        .await;

    let version = match version_result {
        Ok(Some(row)) => {
            let status: String = row.get("status");
            if status != "approved" {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Can only acknowledge approved policies"
                }));
            }
            row.get::<String, _>("version")
        }
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Policy not found"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get policy: {}", e)
            }));
        }
    };

    let id = Uuid::new_v4().to_string();
    let result = sqlx::query(
        r#"
        INSERT INTO grc_policy_acknowledgments (id, policy_id, user_id, version, acknowledged_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&policy_id)
    .bind(&claims.sub)
    .bind(&version)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Policy acknowledged",
            "acknowledgment_id": id
        })),
        Err(e) if e.to_string().contains("UNIQUE constraint") => {
            HttpResponse::Conflict().json(serde_json::json!({
                "error": "Policy already acknowledged"
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to acknowledge policy: {}", e)
        })),
    }
}

// ============================================================================
// Risk Management Handlers
// ============================================================================

async fn list_risks(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<ListQuery>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let result = sqlx::query(
        r#"
        SELECT id, risk_id, title, description, category, status, owner_id,
               inherent_likelihood, inherent_impact, inherent_risk_score,
               residual_likelihood, residual_impact, residual_risk_score,
               treatment_strategy, target_date, last_assessed_at, next_review_date,
               created_at, updated_at
        FROM grc_risks
        ORDER BY inherent_risk_score DESC, created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await;

    match result {
        Ok(rows) => {
            let risks: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    serde_json::json!({
                        "id": row.get::<String, _>("id"),
                        "risk_id": row.get::<String, _>("risk_id"),
                        "title": row.get::<String, _>("title"),
                        "description": row.get::<String, _>("description"),
                        "category": row.get::<String, _>("category"),
                        "status": row.get::<String, _>("status"),
                        "owner_id": row.get::<String, _>("owner_id"),
                        "inherent_likelihood": row.get::<i32, _>("inherent_likelihood"),
                        "inherent_impact": row.get::<i32, _>("inherent_impact"),
                        "inherent_risk_score": row.get::<Option<i32>, _>("inherent_risk_score"),
                        "residual_likelihood": row.get::<Option<i32>, _>("residual_likelihood"),
                        "residual_impact": row.get::<Option<i32>, _>("residual_impact"),
                        "residual_risk_score": row.get::<Option<i32>, _>("residual_risk_score"),
                        "treatment_strategy": row.get::<Option<String>, _>("treatment_strategy"),
                        "target_date": row.get::<Option<String>, _>("target_date"),
                        "last_assessed_at": row.get::<Option<String>, _>("last_assessed_at"),
                        "next_review_date": row.get::<Option<String>, _>("next_review_date"),
                        "created_at": row.get::<String, _>("created_at"),
                        "updated_at": row.get::<String, _>("updated_at"),
                    })
                })
                .collect();

            HttpResponse::Ok().json(serde_json::json!({ "risks": risks }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to list risks: {}", e)
        })),
    }
}

async fn create_risk(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateRiskRequest>,
) -> HttpResponse {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Generate risk ID
    let count_result = sqlx::query("SELECT COUNT(*) as count FROM grc_risks")
        .fetch_one(pool.get_ref())
        .await;

    let risk_number = count_result
        .map(|row| row.get::<i32, _>("count") + 1)
        .unwrap_or(1);

    let risk_id = format!("RISK-{:04}", risk_number);
    let inherent_score = body.inherent_likelihood * body.inherent_impact;
    let tags_json = body.tags.as_ref().map(|t| serde_json::to_string(t).unwrap_or_default());

    let result = sqlx::query(
        r#"
        INSERT INTO grc_risks (
            id, risk_id, title, description, category, status, source, owner_id,
            inherent_likelihood, inherent_impact, inherent_risk_score, tags,
            created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&risk_id)
    .bind(&body.title)
    .bind(&body.description)
    .bind(&body.category)
    .bind(&body.source)
    .bind(&claims.sub)
    .bind(body.inherent_likelihood)
    .bind(body.inherent_impact)
    .bind(inherent_score)
    .bind(&tags_json)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": id,
            "risk_id": risk_id,
            "inherent_risk_score": inherent_score,
            "message": "Risk created successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create risk: {}", e)
        })),
    }
}

async fn assess_risk(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<AssessRiskRequest>,
) -> HttpResponse {
    let risk_id = path.into_inner();
    let now = Utc::now();
    let assessment_id = Uuid::new_v4().to_string();
    let risk_score = body.likelihood * body.impact;

    let threats_json = body.threats.as_ref().map(|t| serde_json::to_string(t).unwrap_or_default());
    let vulns_json = body.vulnerabilities.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default());

    // Create assessment
    let result = sqlx::query(
        r#"
        INSERT INTO grc_risk_assessments (
            id, risk_id, assessment_type, assessor_id, likelihood, impact, risk_score,
            likelihood_rationale, impact_rationale, threats_identified,
            vulnerabilities_identified, recommendations, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&assessment_id)
    .bind(&risk_id)
    .bind(&body.assessment_type)
    .bind(&claims.sub)
    .bind(body.likelihood)
    .bind(body.impact)
    .bind(risk_score)
    .bind(&body.likelihood_rationale)
    .bind(&body.impact_rationale)
    .bind(&threats_json)
    .bind(&vulns_json)
    .bind(&body.recommendations)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await;

    if let Err(e) = result {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create assessment: {}", e)
        }));
    }

    // Update risk with residual values
    let _ = sqlx::query(
        r#"
        UPDATE grc_risks
        SET residual_likelihood = ?, residual_impact = ?, residual_risk_score = ?,
            last_assessed_at = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(body.likelihood)
    .bind(body.impact)
    .bind(risk_score)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(&risk_id)
    .execute(pool.get_ref())
    .await;

    HttpResponse::Created().json(serde_json::json!({
        "assessment_id": assessment_id,
        "risk_score": risk_score,
        "message": "Risk assessment recorded"
    }))
}

async fn set_treatment(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<SetTreatmentRequest>,
) -> HttpResponse {
    let risk_id = path.into_inner();
    let now = Utc::now();

    // Determine new status based on strategy
    let new_status = match body.strategy.as_str() {
        "mitigate" => "mitigating",
        "accept" => "accepted",
        "transfer" => "transferred",
        "avoid" => "closed",
        _ => "open",
    };

    let result = sqlx::query(
        r#"
        UPDATE grc_risks
        SET treatment_strategy = ?, treatment_plan = ?, target_date = ?,
            status = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&body.strategy)
    .bind(&body.plan)
    .bind(&body.target_date)
    .bind(new_status)
    .bind(now.to_rfc3339())
    .bind(&risk_id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Risk treatment set",
                "new_status": new_status
            }))
        }
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Risk not found"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to set treatment: {}", e)
        })),
    }
}

async fn get_risk_dashboard(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Get risk counts by status and severity
    let stats = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status != 'closed' THEN 1 ELSE 0 END) as open,
            SUM(CASE WHEN inherent_risk_score >= 20 THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN inherent_risk_score >= 15 AND inherent_risk_score < 20 THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN inherent_risk_score >= 9 AND inherent_risk_score < 15 THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN inherent_risk_score < 9 THEN 1 ELSE 0 END) as low,
            AVG(CASE WHEN status != 'closed' THEN inherent_risk_score ELSE NULL END) as avg_score,
            SUM(COALESCE(annualized_loss_expectancy, 0)) as total_ale
        FROM grc_risks
        "#,
    )
    .fetch_one(pool.get_ref())
    .await;

    match stats {
        Ok(row) => HttpResponse::Ok().json(serde_json::json!({
            "total_risks": row.get::<i32, _>("total"),
            "open_risks": row.get::<i32, _>("open"),
            "critical_risks": row.get::<i32, _>("critical"),
            "high_risks": row.get::<i32, _>("high"),
            "medium_risks": row.get::<i32, _>("medium"),
            "low_risks": row.get::<i32, _>("low"),
            "avg_risk_score": row.get::<Option<f64>, _>("avg_score"),
            "total_ale": row.get::<f64, _>("total_ale")
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get dashboard: {}", e)
        })),
    }
}

// ============================================================================
// Control Framework Handlers
// ============================================================================

async fn list_controls(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<ListQuery>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let result = sqlx::query(
        r#"
        SELECT id, control_id, title, description, category, type, domain,
               owner_id, implementation_status, effectiveness, testing_frequency,
               last_tested_at, next_test_date, automation_status, created_at, updated_at
        FROM grc_controls
        ORDER BY control_id
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await;

    match result {
        Ok(rows) => {
            let controls: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    serde_json::json!({
                        "id": row.get::<String, _>("id"),
                        "control_id": row.get::<String, _>("control_id"),
                        "title": row.get::<String, _>("title"),
                        "description": row.get::<String, _>("description"),
                        "category": row.get::<String, _>("category"),
                        "type": row.get::<String, _>("type"),
                        "domain": row.get::<String, _>("domain"),
                        "owner_id": row.get::<Option<String>, _>("owner_id"),
                        "implementation_status": row.get::<String, _>("implementation_status"),
                        "effectiveness": row.get::<Option<String>, _>("effectiveness"),
                        "testing_frequency": row.get::<Option<String>, _>("testing_frequency"),
                        "last_tested_at": row.get::<Option<String>, _>("last_tested_at"),
                        "next_test_date": row.get::<Option<String>, _>("next_test_date"),
                        "automation_status": row.get::<String, _>("automation_status"),
                        "created_at": row.get::<String, _>("created_at"),
                        "updated_at": row.get::<String, _>("updated_at"),
                    })
                })
                .collect();

            HttpResponse::Ok().json(serde_json::json!({ "controls": controls }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to list controls: {}", e)
        })),
    }
}

async fn create_control(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateControlRequest>,
) -> HttpResponse {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Generate control ID
    let domain_prefix: String = body.domain.chars().take(3).collect::<String>().to_uppercase();
    let count_result = sqlx::query("SELECT COUNT(*) as count FROM grc_controls WHERE domain = ?")
        .bind(&body.domain)
        .fetch_one(pool.get_ref())
        .await;

    let control_number = count_result
        .map(|row| row.get::<i32, _>("count") + 1)
        .unwrap_or(1);

    let control_id = format!("CTRL-{}-{:03}", domain_prefix, control_number);

    let result = sqlx::query(
        r#"
        INSERT INTO grc_controls (
            id, control_id, title, description, category, type, domain,
            implementation_status, automation_status, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 'not_implemented', 'manual', ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&control_id)
    .bind(&body.title)
    .bind(&body.description)
    .bind(&body.category)
    .bind(&body.control_type)
    .bind(&body.domain)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": id,
            "control_id": control_id,
            "message": "Control created successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create control: {}", e)
        })),
    }
}

async fn add_control_mapping(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<AddMappingRequest>,
) -> HttpResponse {
    let control_id = path.into_inner();
    let mapping_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let result = sqlx::query(
        r#"
        INSERT INTO grc_control_mappings (
            id, control_id, framework, framework_control_id, framework_control_name,
            mapping_notes, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&mapping_id)
    .bind(&control_id)
    .bind(&body.framework)
    .bind(&body.framework_control_id)
    .bind(&body.framework_control_name)
    .bind(&body.mapping_notes)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "mapping_id": mapping_id,
            "message": "Mapping added successfully"
        })),
        Err(e) if e.to_string().contains("UNIQUE constraint") => {
            HttpResponse::Conflict().json(serde_json::json!({
                "error": "Mapping already exists"
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to add mapping: {}", e)
        })),
    }
}

async fn record_control_test(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<RecordTestRequest>,
) -> HttpResponse {
    let control_id = path.into_inner();
    let test_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let today = now.date_naive();

    let evidence_json = body.evidence_refs.as_ref().map(|e| serde_json::to_string(e).unwrap_or_default());
    let remediation_required = body.result == "fail" || body.result == "partial";

    let result = sqlx::query(
        r#"
        INSERT INTO grc_control_tests (
            id, control_id, test_date, tester_id, test_type, test_procedure,
            sample_size, result, findings, evidence_refs, remediation_required, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&test_id)
    .bind(&control_id)
    .bind(today.to_string())
    .bind(&claims.sub)
    .bind(&body.test_type)
    .bind(&body.test_procedure)
    .bind(body.sample_size)
    .bind(&body.result)
    .bind(&body.findings)
    .bind(&evidence_json)
    .bind(remediation_required)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await;

    if let Err(e) = result {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to record test: {}", e)
        }));
    }

    // Update control effectiveness
    let effectiveness = match body.result.as_str() {
        "pass" => "effective",
        "partial" => "partially_effective",
        "fail" => "ineffective",
        _ => "not_tested",
    };

    let _ = sqlx::query(
        r#"
        UPDATE grc_controls
        SET effectiveness = ?, last_tested_at = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(effectiveness)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(&control_id)
    .execute(pool.get_ref())
    .await;

    HttpResponse::Created().json(serde_json::json!({
        "test_id": test_id,
        "effectiveness": effectiveness,
        "remediation_required": remediation_required,
        "message": "Test recorded successfully"
    }))
}

async fn get_control_dashboard(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let stats = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN implementation_status = 'implemented' THEN 1 ELSE 0 END) as implemented,
            SUM(CASE WHEN implementation_status = 'partially_implemented' THEN 1 ELSE 0 END) as partial,
            SUM(CASE WHEN implementation_status = 'not_implemented' THEN 1 ELSE 0 END) as not_implemented,
            SUM(CASE WHEN effectiveness = 'effective' THEN 1 ELSE 0 END) as effective,
            SUM(CASE WHEN next_test_date <= date('now') THEN 1 ELSE 0 END) as due_testing
        FROM grc_controls
        "#,
    )
    .fetch_one(pool.get_ref())
    .await;

    match stats {
        Ok(row) => HttpResponse::Ok().json(serde_json::json!({
            "total_controls": row.get::<i32, _>("total"),
            "implemented_controls": row.get::<i32, _>("implemented"),
            "partially_implemented": row.get::<i32, _>("partial"),
            "not_implemented": row.get::<i32, _>("not_implemented"),
            "effective_controls": row.get::<i32, _>("effective"),
            "controls_due_testing": row.get::<i32, _>("due_testing")
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get dashboard: {}", e)
        })),
    }
}

// ============================================================================
// Audit Management Handlers
// ============================================================================

async fn list_audits(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<ListQuery>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let result = sqlx::query(
        r#"
        SELECT id, audit_number, title, audit_type, scope, status,
               lead_auditor_id, planned_start_date, planned_end_date,
               actual_start_date, actual_end_date, created_at, updated_at
        FROM grc_audits
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await;

    match result {
        Ok(rows) => {
            let audits: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    serde_json::json!({
                        "id": row.get::<String, _>("id"),
                        "audit_number": row.get::<String, _>("audit_number"),
                        "title": row.get::<String, _>("title"),
                        "audit_type": row.get::<String, _>("audit_type"),
                        "scope": row.get::<String, _>("scope"),
                        "status": row.get::<String, _>("status"),
                        "lead_auditor_id": row.get::<String, _>("lead_auditor_id"),
                        "planned_start_date": row.get::<Option<String>, _>("planned_start_date"),
                        "planned_end_date": row.get::<Option<String>, _>("planned_end_date"),
                        "actual_start_date": row.get::<Option<String>, _>("actual_start_date"),
                        "actual_end_date": row.get::<Option<String>, _>("actual_end_date"),
                        "created_at": row.get::<String, _>("created_at"),
                        "updated_at": row.get::<String, _>("updated_at"),
                    })
                })
                .collect();

            HttpResponse::Ok().json(serde_json::json!({ "audits": audits }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to list audits: {}", e)
        })),
    }
}

async fn create_audit(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateAuditRequest>,
) -> HttpResponse {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Generate audit number
    let count_result = sqlx::query("SELECT COUNT(*) as count FROM grc_audits")
        .fetch_one(pool.get_ref())
        .await;

    let audit_number = count_result
        .map(|row| format!("AUD-{:04}", row.get::<i32, _>("count") + 1))
        .unwrap_or_else(|_| "AUD-0001".to_string());

    let frameworks_json = body.frameworks.as_ref().map(|f| serde_json::to_string(f).unwrap_or_default());

    let result = sqlx::query(
        r#"
        INSERT INTO grc_audits (
            id, audit_number, title, audit_type, scope, objectives, status,
            lead_auditor_id, planned_start_date, planned_end_date, frameworks,
            created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 'planning', ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&audit_number)
    .bind(&body.title)
    .bind(&body.audit_type)
    .bind(&body.scope)
    .bind(&body.objectives)
    .bind(&claims.sub)
    .bind(&body.planned_start_date)
    .bind(&body.planned_end_date)
    .bind(&frameworks_json)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": id,
            "audit_number": audit_number,
            "message": "Audit created successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create audit: {}", e)
        })),
    }
}

async fn create_finding(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<CreateFindingRequest>,
) -> HttpResponse {
    let audit_id = path.into_inner();
    let finding_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Get audit number and count findings
    let audit_result = sqlx::query("SELECT audit_number FROM grc_audits WHERE id = ?")
        .bind(&audit_id)
        .fetch_optional(pool.get_ref())
        .await;

    let audit_number = match audit_result {
        Ok(Some(row)) => row.get::<String, _>("audit_number"),
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Audit not found"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get audit: {}", e)
            }));
        }
    };

    let count_result = sqlx::query("SELECT COUNT(*) as count FROM grc_audit_findings WHERE audit_id = ?")
        .bind(&audit_id)
        .fetch_one(pool.get_ref())
        .await;

    let finding_number = count_result
        .map(|row| format!("{}-F{:02}", audit_number, row.get::<i32, _>("count") + 1))
        .unwrap_or_else(|_| format!("{}-F01", audit_number));

    let result = sqlx::query(
        r#"
        INSERT INTO grc_audit_findings (
            id, audit_id, finding_number, title, description, severity,
            status, control_id, recommendation, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)
        "#,
    )
    .bind(&finding_id)
    .bind(&audit_id)
    .bind(&finding_number)
    .bind(&body.title)
    .bind(&body.description)
    .bind(&body.severity)
    .bind(&body.control_id)
    .bind(&body.recommendation)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "finding_id": finding_id,
            "finding_number": finding_number,
            "message": "Finding created successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create finding: {}", e)
        })),
    }
}

async fn get_audit_dashboard(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let stats = sqlx::query(
        r#"
        SELECT
            (SELECT COUNT(*) FROM grc_audits) as total_audits,
            (SELECT COUNT(*) FROM grc_audits WHERE status != 'closed') as active_audits,
            (SELECT COUNT(*) FROM grc_audit_findings WHERE status = 'open') as open_findings,
            (SELECT COUNT(*) FROM grc_audit_findings WHERE status = 'open' AND severity = 'critical') as critical_findings,
            (SELECT COUNT(*) FROM grc_audit_findings WHERE status = 'open' AND severity = 'high') as high_findings,
            (SELECT COUNT(*) FROM grc_audit_findings WHERE status = 'open' AND remediation_due_date < date('now')) as overdue
        "#,
    )
    .fetch_one(pool.get_ref())
    .await;

    match stats {
        Ok(row) => HttpResponse::Ok().json(serde_json::json!({
            "total_audits": row.get::<i32, _>("total_audits"),
            "active_audits": row.get::<i32, _>("active_audits"),
            "open_findings": row.get::<i32, _>("open_findings"),
            "critical_findings": row.get::<i32, _>("critical_findings"),
            "high_findings": row.get::<i32, _>("high_findings"),
            "overdue_remediations": row.get::<i32, _>("overdue")
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get dashboard: {}", e)
        })),
    }
}

// ============================================================================
// Vendor Risk Management Handlers
// ============================================================================

async fn list_vendors(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<ListQuery>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let result = sqlx::query(
        r#"
        SELECT id, vendor_id, name, category, tier, status,
               primary_contact_name, primary_contact_email, services_provided,
               data_access_level, inherent_risk_score, residual_risk_score,
               last_assessment_date, next_assessment_date, soc2_report,
               iso_27001_certified, created_at, updated_at
        FROM grc_vendors
        ORDER BY tier, name
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await;

    match result {
        Ok(rows) => {
            let vendors: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    serde_json::json!({
                        "id": row.get::<String, _>("id"),
                        "vendor_id": row.get::<String, _>("vendor_id"),
                        "name": row.get::<String, _>("name"),
                        "category": row.get::<String, _>("category"),
                        "tier": row.get::<String, _>("tier"),
                        "status": row.get::<String, _>("status"),
                        "primary_contact_name": row.get::<Option<String>, _>("primary_contact_name"),
                        "primary_contact_email": row.get::<Option<String>, _>("primary_contact_email"),
                        "services_provided": row.get::<Option<String>, _>("services_provided"),
                        "data_access_level": row.get::<Option<String>, _>("data_access_level"),
                        "inherent_risk_score": row.get::<Option<i32>, _>("inherent_risk_score"),
                        "residual_risk_score": row.get::<Option<i32>, _>("residual_risk_score"),
                        "last_assessment_date": row.get::<Option<String>, _>("last_assessment_date"),
                        "next_assessment_date": row.get::<Option<String>, _>("next_assessment_date"),
                        "soc2_report": row.get::<bool, _>("soc2_report"),
                        "iso_27001_certified": row.get::<bool, _>("iso_27001_certified"),
                        "created_at": row.get::<String, _>("created_at"),
                        "updated_at": row.get::<String, _>("updated_at"),
                    })
                })
                .collect();

            HttpResponse::Ok().json(serde_json::json!({ "vendors": vendors }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to list vendors: {}", e)
        })),
    }
}

async fn create_vendor(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateVendorRequest>,
) -> HttpResponse {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Generate vendor ID
    let count_result = sqlx::query("SELECT COUNT(*) as count FROM grc_vendors")
        .fetch_one(pool.get_ref())
        .await;

    let vendor_id = count_result
        .map(|row| format!("VND-{:04}", row.get::<i32, _>("count") + 1))
        .unwrap_or_else(|_| "VND-0001".to_string());

    let data_types_json = body.data_types_accessed.as_ref().map(|d| serde_json::to_string(d).unwrap_or_default());

    let result = sqlx::query(
        r#"
        INSERT INTO grc_vendors (
            id, vendor_id, name, category, tier, status, services_provided,
            data_access_level, data_types_accessed, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, 'prospective', ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&vendor_id)
    .bind(&body.name)
    .bind(&body.category)
    .bind(&body.tier)
    .bind(&body.services_provided)
    .bind(&body.data_access_level)
    .bind(&data_types_json)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": id,
            "vendor_id": vendor_id,
            "message": "Vendor created successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create vendor: {}", e)
        })),
    }
}

async fn create_vendor_assessment(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<CreateAssessmentRequest>,
) -> HttpResponse {
    let vendor_id = path.into_inner();
    let assessment_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let today = now.date_naive();

    // Calculate risk rating based on score
    let score = body.questionnaire_score.unwrap_or(50.0);
    let risk_rating = match score as i32 {
        0..=40 => "critical",
        41..=60 => "high",
        61..=80 => "medium",
        _ => "low",
    };

    let risk_areas_json = body.risk_areas.as_ref().map(|r| serde_json::to_string(r).unwrap_or_default());
    let findings_json = body.findings.as_ref().map(|f| serde_json::to_string(f).unwrap_or_default());

    let result = sqlx::query(
        r#"
        INSERT INTO grc_vendor_assessments (
            id, vendor_id, assessment_type, assessment_date, assessor_id,
            questionnaire_id, questionnaire_score, risk_areas, findings,
            recommendations, overall_risk_rating, approval_status, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        "#,
    )
    .bind(&assessment_id)
    .bind(&vendor_id)
    .bind(&body.assessment_type)
    .bind(today.to_string())
    .bind(&claims.sub)
    .bind(&body.questionnaire_id)
    .bind(body.questionnaire_score)
    .bind(&risk_areas_json)
    .bind(&findings_json)
    .bind(&body.recommendations)
    .bind(risk_rating)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await;

    if let Err(e) = result {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create assessment: {}", e)
        }));
    }

    // Update vendor risk scores
    let residual_score = match risk_rating {
        "critical" => 20,
        "high" => 15,
        "medium" => 10,
        _ => 5,
    };

    let _ = sqlx::query(
        r#"
        UPDATE grc_vendors
        SET residual_risk_score = ?, last_assessment_date = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(residual_score)
    .bind(today.to_string())
    .bind(now.to_rfc3339())
    .bind(&vendor_id)
    .execute(pool.get_ref())
    .await;

    HttpResponse::Created().json(serde_json::json!({
        "assessment_id": assessment_id,
        "overall_risk_rating": risk_rating,
        "message": "Assessment created successfully"
    }))
}

async fn get_vendor_dashboard(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let stats = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
            SUM(CASE WHEN category = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN residual_risk_score >= 15 THEN 1 ELSE 0 END) as high_risk,
            SUM(CASE WHEN next_assessment_date <= date('now') THEN 1 ELSE 0 END) as due_assessment,
            AVG(residual_risk_score) as avg_score
        FROM grc_vendors
        "#,
    )
    .fetch_one(pool.get_ref())
    .await;

    match stats {
        Ok(row) => HttpResponse::Ok().json(serde_json::json!({
            "total_vendors": row.get::<i32, _>("total"),
            "active_vendors": row.get::<i32, _>("active"),
            "critical_vendors": row.get::<i32, _>("critical"),
            "high_risk_vendors": row.get::<i32, _>("high_risk"),
            "vendors_due_assessment": row.get::<i32, _>("due_assessment"),
            "avg_vendor_risk_score": row.get::<Option<f64>, _>("avg_score")
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get dashboard: {}", e)
        })),
    }
}

// ============================================================================
// GRC Dashboard
// ============================================================================

async fn get_grc_dashboard(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Aggregate all GRC metrics
    let policy_stats = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as active,
            SUM(CASE WHEN status = 'pending_review' THEN 1 ELSE 0 END) as pending_review,
            SUM(CASE WHEN status = 'pending_approval' THEN 1 ELSE 0 END) as pending_approval
        FROM grc_policies
        "#,
    )
    .fetch_one(pool.get_ref())
    .await;

    let risk_stats = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status != 'closed' THEN 1 ELSE 0 END) as open,
            SUM(CASE WHEN inherent_risk_score >= 20 THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN inherent_risk_score >= 15 AND inherent_risk_score < 20 THEN 1 ELSE 0 END) as high
        FROM grc_risks
        "#,
    )
    .fetch_one(pool.get_ref())
    .await;

    let control_stats = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN implementation_status = 'implemented' THEN 1 ELSE 0 END) as implemented,
            SUM(CASE WHEN effectiveness = 'effective' THEN 1 ELSE 0 END) as effective
        FROM grc_controls
        "#,
    )
    .fetch_one(pool.get_ref())
    .await;

    let audit_stats = sqlx::query(
        r#"
        SELECT
            (SELECT COUNT(*) FROM grc_audits WHERE status != 'closed') as active_audits,
            (SELECT COUNT(*) FROM grc_audit_findings WHERE status = 'open') as open_findings
        "#,
    )
    .fetch_one(pool.get_ref())
    .await;

    let vendor_stats = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
            SUM(CASE WHEN residual_risk_score >= 15 THEN 1 ELSE 0 END) as high_risk
        FROM grc_vendors
        "#,
    )
    .fetch_one(pool.get_ref())
    .await;

    let mut dashboard = serde_json::json!({});

    if let Ok(row) = policy_stats {
        dashboard["policies"] = serde_json::json!({
            "total": row.get::<i32, _>("total"),
            "active": row.get::<i32, _>("active"),
            "pending_review": row.get::<i32, _>("pending_review"),
            "pending_approval": row.get::<i32, _>("pending_approval")
        });
    }

    if let Ok(row) = risk_stats {
        dashboard["risks"] = serde_json::json!({
            "total": row.get::<i32, _>("total"),
            "open": row.get::<i32, _>("open"),
            "critical": row.get::<i32, _>("critical"),
            "high": row.get::<i32, _>("high")
        });
    }

    if let Ok(row) = control_stats {
        dashboard["controls"] = serde_json::json!({
            "total": row.get::<i32, _>("total"),
            "implemented": row.get::<i32, _>("implemented"),
            "effective": row.get::<i32, _>("effective")
        });
    }

    if let Ok(row) = audit_stats {
        dashboard["audits"] = serde_json::json!({
            "active_audits": row.get::<i32, _>("active_audits"),
            "open_findings": row.get::<i32, _>("open_findings")
        });
    }

    if let Ok(row) = vendor_stats {
        dashboard["vendors"] = serde_json::json!({
            "total": row.get::<i32, _>("total"),
            "active": row.get::<i32, _>("active"),
            "high_risk": row.get::<i32, _>("high_risk")
        });
    }

    HttpResponse::Ok().json(dashboard)
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/white-team")
            // GRC Dashboard
            .route("/dashboard", web::get().to(get_grc_dashboard))
            // Policy Management
            .route("/policies", web::get().to(list_policies))
            .route("/policies", web::post().to(create_policy))
            .route("/policies/{id}", web::get().to(get_policy))
            .route("/policies/{id}/submit-review", web::post().to(submit_for_review))
            .route("/policies/{id}/submit-approval", web::post().to(submit_for_approval))
            .route("/policies/{id}/acknowledge", web::post().to(acknowledge_policy))
            // Risk Management
            .route("/risks", web::get().to(list_risks))
            .route("/risks", web::post().to(create_risk))
            .route("/risks/dashboard", web::get().to(get_risk_dashboard))
            .route("/risks/{id}/assess", web::post().to(assess_risk))
            .route("/risks/{id}/treatment", web::post().to(set_treatment))
            // Control Framework
            .route("/controls", web::get().to(list_controls))
            .route("/controls", web::post().to(create_control))
            .route("/controls/dashboard", web::get().to(get_control_dashboard))
            .route("/controls/{id}/mappings", web::post().to(add_control_mapping))
            .route("/controls/{id}/tests", web::post().to(record_control_test))
            // Audit Management
            .route("/audits", web::get().to(list_audits))
            .route("/audits", web::post().to(create_audit))
            .route("/audits/dashboard", web::get().to(get_audit_dashboard))
            .route("/audits/{id}/findings", web::post().to(create_finding))
            // Vendor Risk Management
            .route("/vendors", web::get().to(list_vendors))
            .route("/vendors", web::post().to(create_vendor))
            .route("/vendors/dashboard", web::get().to(get_vendor_dashboard))
            .route("/vendors/{id}/assessments", web::post().to(create_vendor_assessment)),
    );
}
