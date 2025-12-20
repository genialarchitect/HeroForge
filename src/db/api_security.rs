//! Database operations for API Security Scanning
//!
//! This module provides CRUD operations for API security scans, endpoints, and findings.

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

// ============================================================================
// Data Models
// ============================================================================

/// API Scan record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiScan {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub target_url: String,
    pub spec_type: Option<String>,
    pub spec_content: Option<String>,
    pub auth_config: Option<String>,
    pub scan_options: Option<String>,
    pub status: String,
    pub endpoints_discovered: i64,
    pub endpoints_tested: i64,
    pub findings_count: i64,
    pub error_message: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// API Endpoint record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiEndpointRecord {
    pub id: String,
    pub scan_id: String,
    pub path: String,
    pub method: String,
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub parameters: Option<String>,
    pub request_body_schema: Option<String>,
    pub response_schema: Option<String>,
    pub auth_required: i64,
    pub tested: i64,
    pub created_at: String,
}

/// API Finding record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiFinding {
    pub id: String,
    pub scan_id: String,
    pub endpoint_id: Option<String>,
    pub finding_type: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub request: Option<String>,
    pub response: Option<String>,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
    pub cwe_ids: Option<String>,
    pub owasp_category: Option<String>,
    pub status: String,
    pub created_at: String,
}

// ============================================================================
// Request/Response DTOs
// ============================================================================

/// Request to create a new API security scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApiScanRequest {
    pub name: String,
    pub target_url: String,
    pub spec_type: Option<String>,
    pub spec_content: Option<String>,
    pub auth_config: Option<serde_json::Value>,
    pub scan_options: Option<serde_json::Value>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Summary of an API scan for listing
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiScanSummary {
    pub id: String,
    pub name: String,
    pub target_url: String,
    pub status: String,
    pub endpoints_discovered: i64,
    pub endpoints_tested: i64,
    pub findings_count: i64,
    pub created_at: String,
    pub completed_at: Option<String>,
}

/// Statistics for API security findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSecurityStats {
    pub total_scans: i64,
    pub total_findings: i64,
    pub critical_findings: i64,
    pub high_findings: i64,
    pub medium_findings: i64,
    pub low_findings: i64,
    pub endpoints_discovered: i64,
}

// ============================================================================
// Scan Operations
// ============================================================================

/// Create a new API security scan
pub async fn create_api_scan(
    pool: &SqlitePool,
    user_id: &str,
    request: CreateApiScanRequest,
) -> Result<ApiScan> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let auth_config = request
        .auth_config
        .map(|v| serde_json::to_string(&v).unwrap_or_default());
    let scan_options = request
        .scan_options
        .map(|v| serde_json::to_string(&v).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO api_scans (
            id, user_id, name, target_url, spec_type, spec_content,
            auth_config, scan_options, status, endpoints_discovered,
            endpoints_tested, findings_count, created_at, customer_id, engagement_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, 0, 0, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.target_url)
    .bind(&request.spec_type)
    .bind(&request.spec_content)
    .bind(&auth_config)
    .bind(&scan_options)
    .bind(&now)
    .bind(&request.customer_id)
    .bind(&request.engagement_id)
    .execute(pool)
    .await?;

    get_api_scan_by_id(pool, &id).await
}

/// Get an API scan by ID
pub async fn get_api_scan_by_id(pool: &SqlitePool, id: &str) -> Result<ApiScan> {
    let scan = sqlx::query_as::<_, ApiScan>(
        r#"
        SELECT * FROM api_scans WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(scan)
}

/// Get API scans for a user
pub async fn get_user_api_scans(pool: &SqlitePool, user_id: &str) -> Result<Vec<ApiScanSummary>> {
    let scans = sqlx::query_as::<_, ApiScanSummary>(
        r#"
        SELECT
            id, name, target_url, status, endpoints_discovered,
            endpoints_tested, findings_count, created_at, completed_at
        FROM api_scans
        WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(scans)
}

/// Update API scan status
pub async fn update_api_scan_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    error_message: Option<&str>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    if status == "running" {
        sqlx::query(
            r#"
            UPDATE api_scans
            SET status = ?, started_at = ?
            WHERE id = ?
            "#,
        )
        .bind(status)
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;
    } else if status == "completed" || status == "failed" {
        sqlx::query(
            r#"
            UPDATE api_scans
            SET status = ?, completed_at = ?, error_message = ?
            WHERE id = ?
            "#,
        )
        .bind(status)
        .bind(&now)
        .bind(error_message)
        .bind(id)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            r#"
            UPDATE api_scans
            SET status = ?
            WHERE id = ?
            "#,
        )
        .bind(status)
        .bind(id)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Update API scan results (endpoints and findings counts)
pub async fn update_api_scan_results(
    pool: &SqlitePool,
    id: &str,
    endpoints_discovered: i64,
    endpoints_tested: i64,
    findings_count: i64,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE api_scans
        SET endpoints_discovered = ?, endpoints_tested = ?, findings_count = ?
        WHERE id = ?
        "#,
    )
    .bind(endpoints_discovered)
    .bind(endpoints_tested)
    .bind(findings_count)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete an API scan and all related data
pub async fn delete_api_scan(pool: &SqlitePool, id: &str, user_id: &str) -> Result<bool> {
    // Verify ownership
    let result = sqlx::query(
        r#"
        DELETE FROM api_scans WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Endpoint Operations
// ============================================================================

/// Store discovered API endpoints
pub async fn store_api_endpoints(
    pool: &SqlitePool,
    scan_id: &str,
    endpoints: &[crate::scanner::api_security::discovery::ApiEndpoint],
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    for endpoint in endpoints {
        let id = Uuid::new_v4().to_string();
        let parameters = serde_json::to_string(&endpoint.parameters).ok();
        let request_body_schema = endpoint
            .request_body_schema
            .as_ref()
            .map(|s| serde_json::to_string(s).unwrap_or_default());
        let response_schema = endpoint
            .response_schema
            .as_ref()
            .map(|s| serde_json::to_string(s).unwrap_or_default());

        sqlx::query(
            r#"
            INSERT INTO api_endpoints (
                id, scan_id, path, method, operation_id, summary,
                parameters, request_body_schema, response_schema,
                auth_required, tested, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            "#,
        )
        .bind(&id)
        .bind(scan_id)
        .bind(&endpoint.path)
        .bind(&endpoint.method)
        .bind(&endpoint.operation_id)
        .bind(&endpoint.summary)
        .bind(&parameters)
        .bind(&request_body_schema)
        .bind(&response_schema)
        .bind(endpoint.auth_required as i64)
        .bind(&now)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Get endpoints for a scan
pub async fn get_api_endpoints(pool: &SqlitePool, scan_id: &str) -> Result<Vec<ApiEndpointRecord>> {
    let endpoints = sqlx::query_as::<_, ApiEndpointRecord>(
        r#"
        SELECT * FROM api_endpoints WHERE scan_id = ? ORDER BY path, method
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(endpoints)
}

/// Mark an endpoint as tested
pub async fn mark_endpoint_tested(pool: &SqlitePool, endpoint_id: &str) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE api_endpoints SET tested = 1 WHERE id = ?
        "#,
    )
    .bind(endpoint_id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Finding Operations
// ============================================================================

/// Store API security findings
pub async fn store_api_findings(
    pool: &SqlitePool,
    scan_id: &str,
    findings: &[crate::scanner::api_security::ApiSecurityFinding],
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    for finding in findings {
        let id = Uuid::new_v4().to_string();
        let evidence = serde_json::to_string(&finding.evidence).ok();
        let cwe_ids = serde_json::to_string(&finding.cwe_ids).ok();
        let owasp_category = finding
            .owasp_category
            .as_ref()
            .map(|c| format!("{:?}", c));

        sqlx::query(
            r#"
            INSERT INTO api_findings (
                id, scan_id, endpoint_id, finding_type, severity,
                title, description, request, response, evidence,
                remediation, cwe_ids, owasp_category, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
            "#,
        )
        .bind(&id)
        .bind(scan_id)
        .bind(&finding.endpoint_path) // Using path as a reference for now
        .bind(format!("{:?}", finding.finding_type))
        .bind(format!("{:?}", finding.severity))
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(&finding.request)
        .bind(&finding.response)
        .bind(&evidence)
        .bind(&finding.remediation)
        .bind(&cwe_ids)
        .bind(&owasp_category)
        .bind(&now)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Get findings for a scan
pub async fn get_api_findings(pool: &SqlitePool, scan_id: &str) -> Result<Vec<ApiFinding>> {
    let findings = sqlx::query_as::<_, ApiFinding>(
        r#"
        SELECT * FROM api_findings
        WHERE scan_id = ?
        ORDER BY
            CASE severity
                WHEN 'Critical' THEN 1
                WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 4
                ELSE 5
            END,
            created_at DESC
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(findings)
}

/// Get a single finding by ID
pub async fn get_api_finding_by_id(pool: &SqlitePool, id: &str) -> Result<ApiFinding> {
    let finding = sqlx::query_as::<_, ApiFinding>(
        r#"
        SELECT * FROM api_findings WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(finding)
}

/// Update finding status
pub async fn update_api_finding_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE api_findings SET status = ? WHERE id = ?
        "#,
    )
    .bind(status)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Statistics
// ============================================================================

/// Get API security statistics for a user
pub async fn get_api_security_stats(pool: &SqlitePool, user_id: &str) -> Result<ApiSecurityStats> {
    let total_scans: (i64,) = sqlx::query_as(
        r#"SELECT COUNT(*) FROM api_scans WHERE user_id = ?"#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let findings_counts: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT f.severity, COUNT(*) as count
        FROM api_findings f
        JOIN api_scans s ON f.scan_id = s.id
        WHERE s.user_id = ?
        GROUP BY f.severity
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let endpoints_count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM api_endpoints e
        JOIN api_scans s ON e.scan_id = s.id
        WHERE s.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let mut critical = 0i64;
    let mut high = 0i64;
    let mut medium = 0i64;
    let mut low = 0i64;
    let mut total_findings = 0i64;

    for (severity, count) in findings_counts {
        total_findings += count;
        match severity.to_lowercase().as_str() {
            "critical" => critical = count,
            "high" => high = count,
            "medium" => medium = count,
            "low" | "info" => low += count,
            _ => {}
        }
    }

    Ok(ApiSecurityStats {
        total_scans: total_scans.0,
        total_findings,
        critical_findings: critical,
        high_findings: high,
        medium_findings: medium,
        low_findings: low,
        endpoints_discovered: endpoints_count.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_request_serialization() {
        let request = CreateApiScanRequest {
            name: "Test Scan".to_string(),
            target_url: "https://api.example.com".to_string(),
            spec_type: Some("openapi3".to_string()),
            spec_content: None,
            auth_config: Some(serde_json::json!({
                "auth_type": "bearer",
                "credentials": {"token": "test"}
            })),
            scan_options: None,
            customer_id: None,
            engagement_id: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("Test Scan"));
        assert!(json.contains("https://api.example.com"));
    }
}
