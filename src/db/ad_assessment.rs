//! Database operations for Active Directory assessments
//!
//! This module provides CRUD operations for AD assessments and findings.

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use utoipa::ToSchema;
use uuid::Uuid;

// ============================================================================
// Data Models
// ============================================================================

/// AD Assessment record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct AdAssessmentRecord {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub domain_controller: String,
    pub port: i64,
    pub use_ldaps: i64,
    pub status: String,
    pub domain_name: Option<String>,
    pub netbios_name: Option<String>,
    pub forest_name: Option<String>,
    pub domain_level: Option<String>,
    pub forest_level: Option<String>,
    pub base_dn: Option<String>,
    pub total_users: Option<i64>,
    pub total_groups: Option<i64>,
    pub total_computers: Option<i64>,
    pub kerberoastable_accounts: Option<i64>,
    pub asrep_roastable_accounts: Option<i64>,
    pub unconstrained_delegation: Option<i64>,
    pub critical_findings: Option<i64>,
    pub high_findings: Option<i64>,
    pub medium_findings: Option<i64>,
    pub low_findings: Option<i64>,
    pub overall_risk_score: Option<i64>,
    pub results_json: Option<String>,
    pub error_message: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub created_at: String,
}

/// AD Finding record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct AdFindingRecord {
    pub id: String,
    pub assessment_id: String,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub category: String,
    pub mitre_attack_ids: Option<String>,
    pub affected_objects: Option<String>,
    pub affected_count: Option<i64>,
    pub remediation: Option<String>,
    pub risk_score: Option<i64>,
    pub evidence: Option<String>,
    pub references_json: Option<String>,
    pub created_at: String,
}

/// Request to create a new AD assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAdAssessmentRequest {
    pub name: String,
    pub domain_controller: String,
    pub port: Option<i32>,
    pub use_ldaps: Option<bool>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Summary of an AD assessment for listing
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct AdAssessmentSummary {
    pub id: String,
    pub name: String,
    pub domain_controller: String,
    pub status: String,
    pub domain_name: Option<String>,
    pub total_users: Option<i64>,
    pub total_computers: Option<i64>,
    pub critical_findings: Option<i64>,
    pub high_findings: Option<i64>,
    pub overall_risk_score: Option<i64>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

// ============================================================================
// CRUD Operations
// ============================================================================

/// Create a new AD assessment
pub async fn create_ad_assessment(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateAdAssessmentRequest,
) -> Result<AdAssessmentRecord> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let port = request.port.unwrap_or(389) as i64;
    let use_ldaps = if request.use_ldaps.unwrap_or(false) { 1i64 } else { 0i64 };

    sqlx::query(
        r#"
        INSERT INTO ad_assessments (id, user_id, name, domain_controller, port, use_ldaps,
                                    status, customer_id, engagement_id, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8, ?9)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.domain_controller)
    .bind(port)
    .bind(use_ldaps)
    .bind(&request.customer_id)
    .bind(&request.engagement_id)
    .bind(&now)
    .execute(pool)
    .await?;

    get_ad_assessment_by_id(pool, &id, user_id).await
}

/// Get an AD assessment by ID
pub async fn get_ad_assessment_by_id(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
) -> Result<AdAssessmentRecord> {
    let assessment = sqlx::query_as::<_, AdAssessmentRecord>(
        "SELECT * FROM ad_assessments WHERE id = ?1 AND user_id = ?2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(assessment)
}

/// Get all AD assessments for a user
pub async fn get_user_ad_assessments(
    pool: &SqlitePool,
    user_id: &str,
    status: Option<&str>,
) -> Result<Vec<AdAssessmentSummary>> {
    let assessments = if let Some(status) = status {
        sqlx::query_as::<_, AdAssessmentSummary>(
            r#"
            SELECT id, name, domain_controller, status, domain_name, total_users,
                   total_computers, critical_findings, high_findings, overall_risk_score,
                   created_at, completed_at
            FROM ad_assessments
            WHERE user_id = ?1 AND status = ?2
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .bind(status)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, AdAssessmentSummary>(
            r#"
            SELECT id, name, domain_controller, status, domain_name, total_users,
                   total_computers, critical_findings, high_findings, overall_risk_score,
                   created_at, completed_at
            FROM ad_assessments
            WHERE user_id = ?1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?
    };

    Ok(assessments)
}

/// Update AD assessment status
pub async fn update_ad_assessment_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    if status == "running" {
        sqlx::query("UPDATE ad_assessments SET status = ?1, started_at = ?2 WHERE id = ?3")
            .bind(status)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    } else if status == "completed" || status == "failed" {
        sqlx::query("UPDATE ad_assessments SET status = ?1, completed_at = ?2 WHERE id = ?3")
            .bind(status)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    } else {
        sqlx::query("UPDATE ad_assessments SET status = ?1 WHERE id = ?2")
            .bind(status)
            .bind(id)
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Update AD assessment with results
pub async fn update_ad_assessment_results(
    pool: &SqlitePool,
    id: &str,
    domain_name: Option<&str>,
    netbios_name: Option<&str>,
    forest_name: Option<&str>,
    domain_level: Option<&str>,
    forest_level: Option<&str>,
    base_dn: Option<&str>,
    total_users: i32,
    total_groups: i32,
    total_computers: i32,
    kerberoastable: i32,
    asrep_roastable: i32,
    unconstrained: i32,
    critical: i32,
    high: i32,
    medium: i32,
    low: i32,
    risk_score: i32,
    results_json: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE ad_assessments SET
            status = 'completed',
            domain_name = ?1,
            netbios_name = ?2,
            forest_name = ?3,
            domain_level = ?4,
            forest_level = ?5,
            base_dn = ?6,
            total_users = ?7,
            total_groups = ?8,
            total_computers = ?9,
            kerberoastable_accounts = ?10,
            asrep_roastable_accounts = ?11,
            unconstrained_delegation = ?12,
            critical_findings = ?13,
            high_findings = ?14,
            medium_findings = ?15,
            low_findings = ?16,
            overall_risk_score = ?17,
            results_json = ?18,
            completed_at = ?19
        WHERE id = ?20
        "#,
    )
    .bind(domain_name)
    .bind(netbios_name)
    .bind(forest_name)
    .bind(domain_level)
    .bind(forest_level)
    .bind(base_dn)
    .bind(total_users)
    .bind(total_groups)
    .bind(total_computers)
    .bind(kerberoastable)
    .bind(asrep_roastable)
    .bind(unconstrained)
    .bind(critical)
    .bind(high)
    .bind(medium)
    .bind(low)
    .bind(risk_score)
    .bind(results_json)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update AD assessment with error
pub async fn update_ad_assessment_error(
    pool: &SqlitePool,
    id: &str,
    error_message: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE ad_assessments SET status = 'failed', error_message = ?1, completed_at = ?2 WHERE id = ?3",
    )
    .bind(error_message)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete an AD assessment
pub async fn delete_ad_assessment(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM ad_assessments WHERE id = ?1 AND user_id = ?2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Create AD finding
pub async fn create_ad_finding(
    pool: &SqlitePool,
    assessment_id: &str,
    title: &str,
    description: Option<&str>,
    severity: &str,
    category: &str,
    mitre_ids: Option<&str>,
    affected_objects: Option<&str>,
    affected_count: i32,
    remediation: Option<&str>,
    risk_score: i32,
    evidence: Option<&str>,
    references: Option<&str>,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO ad_findings (id, assessment_id, title, description, severity, category,
                                 mitre_attack_ids, affected_objects, affected_count, remediation,
                                 risk_score, evidence, references_json, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        "#,
    )
    .bind(&id)
    .bind(assessment_id)
    .bind(title)
    .bind(description)
    .bind(severity)
    .bind(category)
    .bind(mitre_ids)
    .bind(affected_objects)
    .bind(affected_count)
    .bind(remediation)
    .bind(risk_score)
    .bind(evidence)
    .bind(references)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get findings for an assessment
pub async fn get_ad_findings(
    pool: &SqlitePool,
    assessment_id: &str,
) -> Result<Vec<AdFindingRecord>> {
    let findings = sqlx::query_as::<_, AdFindingRecord>(
        "SELECT * FROM ad_findings WHERE assessment_id = ?1 ORDER BY
         CASE severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            ELSE 5
         END, created_at DESC",
    )
    .bind(assessment_id)
    .fetch_all(pool)
    .await?;

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_request_default_port() {
        let request = CreateAdAssessmentRequest {
            name: "Test".to_string(),
            domain_controller: "dc.test.local".to_string(),
            port: None,
            use_ldaps: None,
            customer_id: None,
            engagement_id: None,
        };
        assert_eq!(request.port.unwrap_or(389), 389);
    }
}
