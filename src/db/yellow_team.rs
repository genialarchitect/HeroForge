//! Database operations for Yellow Team API Security module
//!
//! Provides CRUD operations for:
//! - API security scans
//! - API endpoints
//! - Security findings

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::yellow_team::types::{
    ApiEndpoint, ApiSecurityFinding, ApiSecurityFindingType, ApiSpecFormat,
    ScanStatus, Severity,
};

// ============================================================================
// Database Models
// ============================================================================

/// API Security Scan record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiSecurityScanRecord {
    pub id: String,
    pub user_id: String,
    pub api_name: String,
    pub spec_type: String,
    pub spec_version: Option<String>,
    pub base_url: Option<String>,
    pub spec_content: Option<String>,
    pub status: String,
    pub total_endpoints: i64,
    pub endpoints_with_auth: i64,
    pub endpoints_without_auth: i64,
    pub total_findings: i64,
    pub critical_findings: i64,
    pub high_findings: i64,
    pub medium_findings: i64,
    pub low_findings: i64,
    pub info_findings: i64,
    pub security_score: f64,
    pub error_message: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// API Security Scan summary for listing
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiSecurityScanSummary {
    pub id: String,
    pub api_name: String,
    pub spec_type: String,
    pub status: String,
    pub total_endpoints: i64,
    pub total_findings: i64,
    pub critical_findings: i64,
    pub high_findings: i64,
    pub security_score: f64,
    pub created_at: String,
    pub completed_at: Option<String>,
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
    pub description: Option<String>,
    pub security_requirements: Option<String>,
    pub parameters: Option<String>,
    pub request_body: Option<String>,
    pub responses: Option<String>,
    pub has_auth: i64,
    pub tags: Option<String>,
    pub deprecated: i64,
    pub created_at: String,
}

/// API Security Finding record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiSecurityFindingRecord {
    pub id: String,
    pub scan_id: String,
    pub endpoint_id: Option<String>,
    pub category: String,
    pub severity: String,
    pub endpoint_path: Option<String>,
    pub endpoint_method: Option<String>,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub cwe_id: Option<String>,
    pub owasp_api_id: Option<String>,
    pub evidence: Option<String>,
    pub affected_parameters: Option<String>,
    pub remediation_effort: String,
    pub status: String,
    pub created_at: String,
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to create a new API security scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApiSecurityScanRequest {
    pub api_name: String,
    pub spec_type: String,
    pub spec_content: Option<String>,
    pub base_url: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Statistics for Yellow Team API Security
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct YellowTeamApiSecurityStats {
    pub total_scans: i64,
    pub completed_scans: i64,
    pub total_endpoints: i64,
    pub total_findings: i64,
    pub critical_findings: i64,
    pub high_findings: i64,
    pub medium_findings: i64,
    pub low_findings: i64,
    pub average_security_score: f64,
    pub endpoints_with_auth: i64,
    pub endpoints_without_auth: i64,
    pub top_categories: Vec<CategoryCount>,
}

/// Category count for statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryCount {
    pub category: String,
    pub count: i64,
}

// ============================================================================
// Migration
// ============================================================================

/// Run migrations for Yellow Team API Security tables
pub async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    // Create api_security_scans table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS yt_api_security_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            api_name TEXT NOT NULL,
            spec_type TEXT NOT NULL,
            spec_version TEXT,
            base_url TEXT,
            spec_content TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            total_endpoints INTEGER NOT NULL DEFAULT 0,
            endpoints_with_auth INTEGER NOT NULL DEFAULT 0,
            endpoints_without_auth INTEGER NOT NULL DEFAULT 0,
            total_findings INTEGER NOT NULL DEFAULT 0,
            critical_findings INTEGER NOT NULL DEFAULT 0,
            high_findings INTEGER NOT NULL DEFAULT 0,
            medium_findings INTEGER NOT NULL DEFAULT 0,
            low_findings INTEGER NOT NULL DEFAULT 0,
            info_findings INTEGER NOT NULL DEFAULT 0,
            security_score REAL NOT NULL DEFAULT 100.0,
            error_message TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            customer_id TEXT,
            engagement_id TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for scans
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_yt_api_security_scans_user_id ON yt_api_security_scans(user_id)"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_yt_api_security_scans_status ON yt_api_security_scans(status)"
    )
    .execute(pool)
    .await?;

    // Create api_security_endpoints table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS yt_api_security_endpoints (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            path TEXT NOT NULL,
            method TEXT NOT NULL,
            operation_id TEXT,
            summary TEXT,
            description TEXT,
            security_requirements TEXT,
            parameters TEXT,
            request_body TEXT,
            responses TEXT,
            has_auth INTEGER NOT NULL DEFAULT 0,
            tags TEXT,
            deprecated INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES yt_api_security_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for endpoints
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_yt_api_security_endpoints_scan_id ON yt_api_security_endpoints(scan_id)"
    )
    .execute(pool)
    .await?;

    // Create api_security_findings table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS yt_api_security_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            endpoint_id TEXT,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            endpoint_path TEXT,
            endpoint_method TEXT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            cwe_id TEXT,
            owasp_api_id TEXT,
            evidence TEXT,
            affected_parameters TEXT,
            remediation_effort TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES yt_api_security_scans(id) ON DELETE CASCADE,
            FOREIGN KEY (endpoint_id) REFERENCES yt_api_security_endpoints(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for findings
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_yt_api_security_findings_scan_id ON yt_api_security_findings(scan_id)"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_yt_api_security_findings_severity ON yt_api_security_findings(severity)"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_yt_api_security_findings_category ON yt_api_security_findings(category)"
    )
    .execute(pool)
    .await?;

    // Initialize threat modeling tables
    crate::db::threat_modeling::init_threat_modeling_tables(pool).await?;

    Ok(())
}

// ============================================================================
// Scan Operations
// ============================================================================

/// Create a new API security scan
pub async fn create_scan(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateApiSecurityScanRequest,
) -> Result<ApiSecurityScanRecord> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO yt_api_security_scans (
            id, user_id, api_name, spec_type, spec_content, base_url,
            status, created_at, customer_id, engagement_id
        ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.api_name)
    .bind(&request.spec_type)
    .bind(&request.spec_content)
    .bind(&request.base_url)
    .bind(&now)
    .bind(&request.customer_id)
    .bind(&request.engagement_id)
    .execute(pool)
    .await?;

    get_scan_by_id(pool, &id).await
}

/// Get a scan by ID
pub async fn get_scan_by_id(pool: &SqlitePool, id: &str) -> Result<ApiSecurityScanRecord> {
    let scan = sqlx::query_as::<_, ApiSecurityScanRecord>(
        "SELECT * FROM yt_api_security_scans WHERE id = ?"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(scan)
}

/// Get scans for a user
pub async fn get_user_scans(pool: &SqlitePool, user_id: &str) -> Result<Vec<ApiSecurityScanSummary>> {
    let scans = sqlx::query_as::<_, ApiSecurityScanSummary>(
        r#"
        SELECT
            id, api_name, spec_type, status, total_endpoints,
            total_findings, critical_findings, high_findings,
            security_score, created_at, completed_at
        FROM yt_api_security_scans
        WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(scans)
}

/// Update scan status
pub async fn update_scan_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    error_message: Option<&str>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    if status == "completed" || status == "failed" {
        sqlx::query(
            r#"
            UPDATE yt_api_security_scans
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
            "UPDATE yt_api_security_scans SET status = ? WHERE id = ?"
        )
        .bind(status)
        .bind(id)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Update scan results (summary statistics)
pub async fn update_scan_results(
    pool: &SqlitePool,
    id: &str,
    spec_version: Option<&str>,
    total_endpoints: i64,
    endpoints_with_auth: i64,
    endpoints_without_auth: i64,
    total_findings: i64,
    critical_findings: i64,
    high_findings: i64,
    medium_findings: i64,
    low_findings: i64,
    info_findings: i64,
    security_score: f64,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE yt_api_security_scans
        SET spec_version = ?,
            total_endpoints = ?,
            endpoints_with_auth = ?,
            endpoints_without_auth = ?,
            total_findings = ?,
            critical_findings = ?,
            high_findings = ?,
            medium_findings = ?,
            low_findings = ?,
            info_findings = ?,
            security_score = ?
        WHERE id = ?
        "#,
    )
    .bind(spec_version)
    .bind(total_endpoints)
    .bind(endpoints_with_auth)
    .bind(endpoints_without_auth)
    .bind(total_findings)
    .bind(critical_findings)
    .bind(high_findings)
    .bind(medium_findings)
    .bind(low_findings)
    .bind(info_findings)
    .bind(security_score)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a scan and all related data
pub async fn delete_scan(pool: &SqlitePool, id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM yt_api_security_scans WHERE id = ? AND user_id = ?"
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

/// Store discovered endpoints
pub async fn store_endpoints(
    pool: &SqlitePool,
    scan_id: &str,
    endpoints: &[ApiEndpoint],
) -> Result<Vec<String>> {
    let now = Utc::now().to_rfc3339();
    let mut endpoint_ids = Vec::new();

    for endpoint in endpoints {
        let id = Uuid::new_v4().to_string();

        let security_requirements = serde_json::to_string(&endpoint.security_requirements).ok();
        let parameters = serde_json::to_string(&endpoint.parameters).ok();
        let request_body = endpoint.request_body.as_ref()
            .and_then(|rb| serde_json::to_string(rb).ok());
        let responses = serde_json::to_string(&endpoint.responses).ok();
        let tags = serde_json::to_string(&endpoint.tags).ok();

        sqlx::query(
            r#"
            INSERT INTO yt_api_security_endpoints (
                id, scan_id, path, method, operation_id, summary, description,
                security_requirements, parameters, request_body, responses,
                has_auth, tags, deprecated, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(scan_id)
        .bind(&endpoint.path)
        .bind(endpoint.method.to_string())
        .bind(&endpoint.operation_id)
        .bind(&endpoint.summary)
        .bind(&endpoint.description)
        .bind(&security_requirements)
        .bind(&parameters)
        .bind(&request_body)
        .bind(&responses)
        .bind(endpoint.has_auth as i64)
        .bind(&tags)
        .bind(endpoint.deprecated as i64)
        .bind(&now)
        .execute(pool)
        .await?;

        endpoint_ids.push(id);
    }

    Ok(endpoint_ids)
}

/// Get endpoints for a scan
pub async fn get_scan_endpoints(pool: &SqlitePool, scan_id: &str) -> Result<Vec<ApiEndpointRecord>> {
    let endpoints = sqlx::query_as::<_, ApiEndpointRecord>(
        "SELECT * FROM yt_api_security_endpoints WHERE scan_id = ? ORDER BY path, method"
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(endpoints)
}

// ============================================================================
// Finding Operations
// ============================================================================

/// Store security findings
pub async fn store_findings(
    pool: &SqlitePool,
    scan_id: &str,
    findings: &[ApiSecurityFinding],
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    for finding in findings {
        let id = finding.id.to_string();
        let affected_parameters = serde_json::to_string(&finding.affected_parameters).ok();

        sqlx::query(
            r#"
            INSERT INTO yt_api_security_findings (
                id, scan_id, category, severity, endpoint_path, endpoint_method,
                title, description, recommendation, cwe_id, owasp_api_id,
                evidence, affected_parameters, remediation_effort, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
            "#,
        )
        .bind(&id)
        .bind(scan_id)
        .bind(format!("{:?}", finding.category))
        .bind(format!("{:?}", finding.severity))
        .bind(&finding.endpoint)
        .bind(finding.method.map(|m| m.to_string()))
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(&finding.recommendation)
        .bind(&finding.cwe_id)
        .bind(&finding.owasp_api_id)
        .bind(&finding.evidence)
        .bind(&affected_parameters)
        .bind(format!("{:?}", finding.remediation_effort))
        .bind(&now)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Get findings for a scan
pub async fn get_scan_findings(pool: &SqlitePool, scan_id: &str) -> Result<Vec<ApiSecurityFindingRecord>> {
    let findings = sqlx::query_as::<_, ApiSecurityFindingRecord>(
        r#"
        SELECT * FROM yt_api_security_findings
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
pub async fn get_finding_by_id(pool: &SqlitePool, id: &str) -> Result<ApiSecurityFindingRecord> {
    let finding = sqlx::query_as::<_, ApiSecurityFindingRecord>(
        "SELECT * FROM yt_api_security_findings WHERE id = ?"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(finding)
}

/// Update finding status
pub async fn update_finding_status(pool: &SqlitePool, id: &str, status: &str) -> Result<()> {
    sqlx::query(
        "UPDATE yt_api_security_findings SET status = ? WHERE id = ?"
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

/// Get Yellow Team API Security statistics for a user
pub async fn get_stats(pool: &SqlitePool, user_id: &str) -> Result<YellowTeamApiSecurityStats> {
    // Get basic counts
    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) as total_scans,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_scans,
            SUM(total_endpoints) as total_endpoints,
            SUM(total_findings) as total_findings
        FROM yt_api_security_scans
        WHERE user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0, 0, 0, 0));

    // Get severity counts
    let severity_counts: (i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            SUM(critical_findings) as critical,
            SUM(high_findings) as high,
            SUM(medium_findings) as medium,
            SUM(low_findings) as low
        FROM yt_api_security_scans
        WHERE user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0, 0, 0, 0));

    // Get auth counts
    let auth_counts: (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            SUM(endpoints_with_auth) as with_auth,
            SUM(endpoints_without_auth) as without_auth
        FROM yt_api_security_scans
        WHERE user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0, 0));

    // Get average security score
    let avg_score: (f64,) = sqlx::query_as(
        r#"
        SELECT COALESCE(AVG(security_score), 100.0)
        FROM yt_api_security_scans
        WHERE user_id = ? AND status = 'completed'
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((100.0,));

    // Get top finding categories
    let top_categories: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT f.category, COUNT(*) as count
        FROM yt_api_security_findings f
        JOIN yt_api_security_scans s ON f.scan_id = s.id
        WHERE s.user_id = ?
        GROUP BY f.category
        ORDER BY count DESC
        LIMIT 5
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    Ok(YellowTeamApiSecurityStats {
        total_scans: counts.0,
        completed_scans: counts.1,
        total_endpoints: counts.2,
        total_findings: counts.3,
        critical_findings: severity_counts.0,
        high_findings: severity_counts.1,
        medium_findings: severity_counts.2,
        low_findings: severity_counts.3,
        average_security_score: avg_score.0,
        endpoints_with_auth: auth_counts.0,
        endpoints_without_auth: auth_counts.1,
        top_categories: top_categories
            .into_iter()
            .map(|(category, count)| CategoryCount { category, count })
            .collect(),
    })
}

// ============================================================================
// SAST (Static Application Security Testing) Database Operations
// ============================================================================

/// SAST Scan record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SastScanRecord {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub repository_url: Option<String>,
    pub branch: Option<String>,
    pub languages: String,
    pub status: String,
    pub total_findings: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub info_count: i64,
    pub files_scanned: i64,
    pub lines_analyzed: i64,
    pub error_message: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub created_at: String,
}

/// SAST Scan summary for listing
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SastScanSummary {
    pub id: String,
    pub name: String,
    pub languages: String,
    pub status: String,
    pub total_findings: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub files_scanned: i64,
    pub created_at: String,
    pub completed_at: Option<String>,
}

/// SAST Finding record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SastFindingRecord {
    pub id: String,
    pub scan_id: String,
    pub rule_id: String,
    pub file_path: String,
    pub line_number: i64,
    pub column_number: Option<i64>,
    pub code_snippet: Option<String>,
    pub severity: String,
    pub category: String,
    pub message: String,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
    pub remediation: Option<String>,
    pub status: String,
    pub false_positive: i64,
    pub suppression_reason: Option<String>,
    pub created_at: String,
}

/// SAST Rule record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SastRuleRecord {
    pub id: String,
    pub language: String,
    pub name: String,
    pub pattern: String,
    pub severity: String,
    pub category: String,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
    pub description: Option<String>,
    pub remediation: Option<String>,
    pub enabled: i64,
    pub custom: i64,
    pub created_by: Option<String>,
    pub created_at: String,
}

/// Request to create a new SAST scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSastScanRequest {
    pub name: String,
    pub repository_url: Option<String>,
    pub branch: Option<String>,
    pub languages: Vec<String>,
}

/// Request to create a custom SAST rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSastRuleRequest {
    pub language: String,
    pub name: String,
    pub pattern: String,
    pub severity: String,
    pub category: String,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
    pub description: Option<String>,
    pub remediation: Option<String>,
}

/// Request to update a SAST finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSastFindingRequest {
    pub status: Option<String>,
    pub false_positive: Option<bool>,
    pub suppression_reason: Option<String>,
}

/// Statistics for SAST scans
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SastStats {
    pub total_scans: i64,
    pub completed_scans: i64,
    pub total_findings: i64,
    pub critical_findings: i64,
    pub high_findings: i64,
    pub medium_findings: i64,
    pub low_findings: i64,
    pub info_findings: i64,
    pub total_files_scanned: i64,
    pub total_lines_analyzed: i64,
    pub top_categories: Vec<CategoryCount>,
    pub findings_by_language: Vec<CategoryCount>,
}

// SAST Scan Operations

/// Create a new SAST scan
pub async fn create_sast_scan(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateSastScanRequest,
) -> Result<SastScanRecord> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let languages_json = serde_json::to_string(&request.languages)?;

    sqlx::query(
        r#"
        INSERT INTO sast_scans (id, user_id, name, repository_url, branch, languages, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.repository_url)
    .bind(&request.branch)
    .bind(&languages_json)
    .bind(&now)
    .execute(pool)
    .await?;

    get_sast_scan_by_id(pool, &id).await
}

/// Get a SAST scan by ID
pub async fn get_sast_scan_by_id(pool: &SqlitePool, id: &str) -> Result<SastScanRecord> {
    let scan = sqlx::query_as::<_, SastScanRecord>(
        r#"
        SELECT id, user_id, name, repository_url, branch, languages, status,
               total_findings, critical_count, high_count, medium_count, low_count, info_count,
               files_scanned, lines_analyzed, error_message, started_at, completed_at, created_at
        FROM sast_scans
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(scan)
}

/// List SAST scans for a user
pub async fn list_sast_scans(pool: &SqlitePool, user_id: &str) -> Result<Vec<SastScanSummary>> {
    let scans = sqlx::query_as::<_, SastScanSummary>(
        r#"
        SELECT id, name, languages, status, total_findings, critical_count, high_count,
               files_scanned, created_at, completed_at
        FROM sast_scans
        WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(scans)
}

/// Update SAST scan status
pub async fn update_sast_scan_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    error_message: Option<&str>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    if status == "running" {
        sqlx::query(
            "UPDATE sast_scans SET status = ?, started_at = ? WHERE id = ?"
        )
        .bind(status)
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;
    } else if status == "completed" || status == "failed" {
        sqlx::query(
            "UPDATE sast_scans SET status = ?, completed_at = ?, error_message = ? WHERE id = ?"
        )
        .bind(status)
        .bind(&now)
        .bind(error_message)
        .bind(id)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE sast_scans SET status = ? WHERE id = ?"
        )
        .bind(status)
        .bind(id)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Update SAST scan results after completion
pub async fn update_sast_scan_results(
    pool: &SqlitePool,
    id: &str,
    total_findings: i64,
    critical_count: i64,
    high_count: i64,
    medium_count: i64,
    low_count: i64,
    info_count: i64,
    files_scanned: i64,
    lines_analyzed: i64,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE sast_scans SET
            status = 'completed',
            total_findings = ?,
            critical_count = ?,
            high_count = ?,
            medium_count = ?,
            low_count = ?,
            info_count = ?,
            files_scanned = ?,
            lines_analyzed = ?,
            completed_at = ?
        WHERE id = ?
        "#,
    )
    .bind(total_findings)
    .bind(critical_count)
    .bind(high_count)
    .bind(medium_count)
    .bind(low_count)
    .bind(info_count)
    .bind(files_scanned)
    .bind(lines_analyzed)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a SAST scan
pub async fn delete_sast_scan(pool: &SqlitePool, id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM sast_scans WHERE id = ? AND user_id = ?"
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

// SAST Finding Operations

/// Create a SAST finding
pub async fn create_sast_finding(
    pool: &SqlitePool,
    scan_id: &str,
    rule_id: &str,
    file_path: &str,
    line_number: i64,
    column_number: Option<i64>,
    code_snippet: Option<&str>,
    severity: &str,
    category: &str,
    message: &str,
    cwe_id: Option<&str>,
    owasp_category: Option<&str>,
    remediation: Option<&str>,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO sast_findings (
            id, scan_id, rule_id, file_path, line_number, column_number,
            code_snippet, severity, category, message, cwe_id, owasp_category,
            remediation, status, false_positive, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 0, ?)
        "#,
    )
    .bind(&id)
    .bind(scan_id)
    .bind(rule_id)
    .bind(file_path)
    .bind(line_number)
    .bind(column_number)
    .bind(code_snippet)
    .bind(severity)
    .bind(category)
    .bind(message)
    .bind(cwe_id)
    .bind(owasp_category)
    .bind(remediation)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get SAST findings for a scan
pub async fn get_sast_findings(pool: &SqlitePool, scan_id: &str) -> Result<Vec<SastFindingRecord>> {
    let findings = sqlx::query_as::<_, SastFindingRecord>(
        r#"
        SELECT id, scan_id, rule_id, file_path, line_number, column_number,
               code_snippet, severity, category, message, cwe_id, owasp_category,
               remediation, status, false_positive, suppression_reason, created_at
        FROM sast_findings
        WHERE scan_id = ?
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            file_path, line_number
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(findings)
}

/// Get a specific SAST finding by ID
pub async fn get_sast_finding_by_id(pool: &SqlitePool, id: &str) -> Result<SastFindingRecord> {
    let finding = sqlx::query_as::<_, SastFindingRecord>(
        r#"
        SELECT id, scan_id, rule_id, file_path, line_number, column_number,
               code_snippet, severity, category, message, cwe_id, owasp_category,
               remediation, status, false_positive, suppression_reason, created_at
        FROM sast_findings
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(finding)
}

/// Update a SAST finding (mark as false positive, change status, etc.)
pub async fn update_sast_finding(
    pool: &SqlitePool,
    id: &str,
    request: &UpdateSastFindingRequest,
) -> Result<()> {
    if let Some(status) = &request.status {
        sqlx::query("UPDATE sast_findings SET status = ? WHERE id = ?")
            .bind(status)
            .bind(id)
            .execute(pool)
            .await?;
    }

    if let Some(false_positive) = request.false_positive {
        let fp_value = if false_positive { 1 } else { 0 };
        let status = if false_positive { "false_positive" } else { "open" };
        sqlx::query("UPDATE sast_findings SET false_positive = ?, status = ? WHERE id = ?")
            .bind(fp_value)
            .bind(status)
            .bind(id)
            .execute(pool)
            .await?;
    }

    if let Some(reason) = &request.suppression_reason {
        sqlx::query("UPDATE sast_findings SET suppression_reason = ? WHERE id = ?")
            .bind(reason)
            .bind(id)
            .execute(pool)
            .await?;
    }

    Ok(())
}

// SAST Rule Operations

/// Get all SAST rules (built-in and custom)
pub async fn get_sast_rules(pool: &SqlitePool, language: Option<&str>) -> Result<Vec<SastRuleRecord>> {
    let rules = if let Some(lang) = language {
        sqlx::query_as::<_, SastRuleRecord>(
            r#"
            SELECT id, language, name, pattern, severity, category, cwe_id,
                   owasp_category, description, remediation, enabled, custom,
                   created_by, created_at
            FROM sast_rules
            WHERE language = ? AND enabled = 1
            ORDER BY severity, name
            "#,
        )
        .bind(lang)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, SastRuleRecord>(
            r#"
            SELECT id, language, name, pattern, severity, category, cwe_id,
                   owasp_category, description, remediation, enabled, custom,
                   created_by, created_at
            FROM sast_rules
            WHERE enabled = 1
            ORDER BY language, severity, name
            "#,
        )
        .fetch_all(pool)
        .await?
    };

    Ok(rules)
}

/// Create a custom SAST rule
pub async fn create_sast_rule(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateSastRuleRequest,
) -> Result<SastRuleRecord> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO sast_rules (
            id, language, name, pattern, severity, category, cwe_id,
            owasp_category, description, remediation, enabled, custom,
            created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&request.language)
    .bind(&request.name)
    .bind(&request.pattern)
    .bind(&request.severity)
    .bind(&request.category)
    .bind(&request.cwe_id)
    .bind(&request.owasp_category)
    .bind(&request.description)
    .bind(&request.remediation)
    .bind(user_id)
    .bind(&now)
    .execute(pool)
    .await?;

    get_sast_rule_by_id(pool, &id).await
}

/// Get a SAST rule by ID
pub async fn get_sast_rule_by_id(pool: &SqlitePool, id: &str) -> Result<SastRuleRecord> {
    let rule = sqlx::query_as::<_, SastRuleRecord>(
        r#"
        SELECT id, language, name, pattern, severity, category, cwe_id,
               owasp_category, description, remediation, enabled, custom,
               created_by, created_at
        FROM sast_rules
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(rule)
}

/// Toggle a SAST rule enabled/disabled
pub async fn toggle_sast_rule(pool: &SqlitePool, id: &str, enabled: bool) -> Result<()> {
    let enabled_val = if enabled { 1 } else { 0 };
    sqlx::query("UPDATE sast_rules SET enabled = ? WHERE id = ?")
        .bind(enabled_val)
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Delete a custom SAST rule (only custom rules can be deleted)
pub async fn delete_sast_rule(pool: &SqlitePool, id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM sast_rules WHERE id = ? AND created_by = ? AND custom = 1"
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Get SAST statistics for a user
pub async fn get_sast_stats(pool: &SqlitePool, user_id: &str) -> Result<SastStats> {
    // Get basic counts
    let counts: (i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) as total_scans,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_scans,
            SUM(total_findings) as total_findings,
            SUM(critical_count) as critical,
            SUM(high_count) as high,
            SUM(medium_count) as medium,
            SUM(low_count) as low,
            SUM(info_count) as info
        FROM sast_scans
        WHERE user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0, 0, 0, 0, 0, 0, 0, 0));

    // Get file/line counts
    let file_counts: (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            SUM(files_scanned) as files,
            SUM(lines_analyzed) as lines
        FROM sast_scans
        WHERE user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0, 0));

    // Get top finding categories
    let top_categories: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT f.category, COUNT(*) as count
        FROM sast_findings f
        JOIN sast_scans s ON f.scan_id = s.id
        WHERE s.user_id = ?
        GROUP BY f.category
        ORDER BY count DESC
        LIMIT 10
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // Get findings by language (from scan languages)
    let by_language: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT s.languages, SUM(s.total_findings) as count
        FROM sast_scans s
        WHERE s.user_id = ?
        GROUP BY s.languages
        ORDER BY count DESC
        LIMIT 10
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    Ok(SastStats {
        total_scans: counts.0,
        completed_scans: counts.1,
        total_findings: counts.2,
        critical_findings: counts.3,
        high_findings: counts.4,
        medium_findings: counts.5,
        low_findings: counts.6,
        info_findings: counts.7,
        total_files_scanned: file_counts.0,
        total_lines_analyzed: file_counts.1,
        top_categories: top_categories
            .into_iter()
            .map(|(category, count)| CategoryCount { category, count })
            .collect(),
        findings_by_language: by_language
            .into_iter()
            .map(|(category, count)| CategoryCount { category, count })
            .collect(),
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_scan_request_serialization() {
        let request = CreateApiSecurityScanRequest {
            api_name: "Test API".to_string(),
            spec_type: "openapi3".to_string(),
            spec_content: Some("{\"openapi\": \"3.0.0\"}".to_string()),
            base_url: Some("https://api.example.com".to_string()),
            customer_id: None,
            engagement_id: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("Test API"));
        assert!(json.contains("openapi3"));
    }

    #[test]
    fn test_stats_default() {
        let stats = YellowTeamApiSecurityStats::default();
        assert_eq!(stats.total_scans, 0);
        assert_eq!(stats.average_security_score, 0.0);
    }

    #[test]
    fn test_sast_scan_request_serialization() {
        let request = CreateSastScanRequest {
            name: "Test SAST Scan".to_string(),
            repository_url: Some("https://github.com/test/repo".to_string()),
            branch: Some("main".to_string()),
            languages: vec!["python".to_string(), "javascript".to_string()],
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("Test SAST Scan"));
        assert!(json.contains("python"));
    }

    #[test]
    fn test_sast_rule_request_serialization() {
        let request = CreateSastRuleRequest {
            language: "python".to_string(),
            name: "Custom SQL Injection Rule".to_string(),
            pattern: r#"execute\s*\("#.to_string(),
            severity: "critical".to_string(),
            category: "injection".to_string(),
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: Some("A03:2021".to_string()),
            description: Some("Detects potential SQL injection".to_string()),
            remediation: Some("Use parameterized queries".to_string()),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("Custom SQL Injection Rule"));
        assert!(json.contains("CWE-89"));
    }

    #[test]
    fn test_sast_stats_default() {
        let stats = SastStats::default();
        assert_eq!(stats.total_scans, 0);
        assert_eq!(stats.total_findings, 0);
    }
}
