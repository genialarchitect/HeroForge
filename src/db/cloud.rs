//! Database operations for cloud infrastructure scanning
//!
//! This module provides CRUD operations for cloud scans, resources, and findings.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;

use crate::scanner::cloud::{
    CloudFinding, CloudProvider, CloudResource, CloudResourceType, CloudScan, CloudScanStatus,
    CloudScanSummary, CloudScanType, ComplianceMapping, FindingEvidence, FindingSeverity,
    FindingStatus, FindingType,
};

// ============================================================================
// Database Models
// ============================================================================

/// Database model for cloud scan records
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CloudScanRow {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub provider: String,
    pub regions: Option<String>,       // JSON array
    pub scan_types: Option<String>,    // JSON array
    pub status: String,
    pub credentials_id: Option<String>,
    pub findings_count: i32,
    pub resources_count: i32,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

impl CloudScanRow {
    /// Convert database row to domain model
    pub fn to_cloud_scan(&self) -> CloudScan {
        let regions: Vec<String> = self
            .regions
            .as_ref()
            .and_then(|r| serde_json::from_str(r).ok())
            .unwrap_or_default();

        let scan_types: Vec<CloudScanType> = self
            .scan_types
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();

        let provider = self.provider.parse().unwrap_or(CloudProvider::Aws);
        let status = self.status.parse().unwrap_or(CloudScanStatus::Pending);

        CloudScan {
            id: self.id.clone(),
            user_id: self.user_id.clone(),
            name: self.name.clone(),
            provider,
            regions,
            scan_types,
            status,
            credentials_id: self.credentials_id.clone(),
            findings_count: self.findings_count,
            resources_count: self.resources_count,
            error_message: self.error_message.clone(),
            created_at: self.created_at,
            started_at: self.started_at,
            completed_at: self.completed_at,
            customer_id: self.customer_id.clone(),
            engagement_id: self.engagement_id.clone(),
        }
    }
}

/// Database model for cloud resource records
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CloudResourceRow {
    pub id: String,
    pub scan_id: String,
    pub provider: String,
    pub resource_type: String,
    pub resource_id: String,
    pub region: Option<String>,
    pub name: Option<String>,
    pub arn: Option<String>,
    pub tags: Option<String>,     // JSON object
    pub metadata: Option<String>, // JSON object
    pub state: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl CloudResourceRow {
    /// Convert database row to domain model
    pub fn to_cloud_resource(&self) -> CloudResource {
        let tags = self
            .tags
            .as_ref()
            .and_then(|t| serde_json::from_str(t).ok())
            .unwrap_or_default();

        let metadata = self
            .metadata
            .as_ref()
            .and_then(|m| serde_json::from_str(m).ok())
            .unwrap_or(serde_json::json!({}));

        let provider = self.provider.parse().unwrap_or(CloudProvider::Aws);
        let resource_type = parse_resource_type(&self.resource_type);

        CloudResource {
            id: self.id.clone(),
            resource_id: self.resource_id.clone(),
            resource_type,
            provider,
            region: self.region.clone(),
            name: self.name.clone(),
            arn: self.arn.clone(),
            tags,
            metadata,
            state: self.state.clone(),
            discovered_at: self.created_at,
        }
    }
}

/// Database model for cloud finding records
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CloudFindingRow {
    pub id: String,
    pub scan_id: String,
    pub resource_id: Option<String>,
    pub finding_type: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub remediation: Option<String>,
    pub compliance_mappings: Option<String>, // JSON array
    pub affected_resource_arn: Option<String>,
    pub evidence: Option<String>, // JSON object
    pub status: String,
    pub created_at: DateTime<Utc>,
}

impl CloudFindingRow {
    /// Convert database row to domain model
    pub fn to_cloud_finding(&self) -> CloudFinding {
        let finding_type = parse_finding_type(&self.finding_type);
        let severity = self.severity.parse().unwrap_or(FindingSeverity::Medium);
        let status = self.status.parse().unwrap_or(FindingStatus::Open);

        let compliance_mappings: Vec<ComplianceMapping> = self
            .compliance_mappings
            .as_ref()
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or_default();

        let evidence: Option<FindingEvidence> = self
            .evidence
            .as_ref()
            .and_then(|e| serde_json::from_str(e).ok());

        CloudFinding {
            id: self.id.clone(),
            scan_id: self.scan_id.clone(),
            resource_id: self.resource_id.clone(),
            finding_type,
            severity,
            title: self.title.clone(),
            description: self.description.clone().unwrap_or_default(),
            remediation: self.remediation.clone(),
            compliance_mappings,
            affected_resource_arn: self.affected_resource_arn.clone(),
            evidence,
            status,
            created_at: self.created_at,
        }
    }
}

// ============================================================================
// Request/Response DTOs
// ============================================================================

/// Request to create a cloud scan
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCloudScanRequest {
    pub name: String,
    pub provider: String,
    pub regions: Vec<String>,
    pub scan_types: Vec<String>,
    pub credentials_id: Option<String>,
    #[serde(default)]
    pub demo_mode: bool,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Request to update finding status
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateFindingStatusRequest {
    pub status: String,
}

/// Query parameters for listing scans
#[derive(Debug, Deserialize)]
pub struct ListCloudScansQuery {
    pub provider: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Query parameters for listing findings
#[derive(Debug, Deserialize)]
pub struct ListFindingsQuery {
    pub severity: Option<String>,
    pub finding_type: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_resource_type(s: &str) -> CloudResourceType {
    match s {
        "ec2_instance" => CloudResourceType::Ec2Instance,
        "security_group" => CloudResourceType::SecurityGroup,
        "s3_bucket" => CloudResourceType::S3Bucket,
        "rds_instance" => CloudResourceType::RdsInstance,
        "iam_user" => CloudResourceType::IamUser,
        "iam_role" => CloudResourceType::IamRole,
        "iam_policy" => CloudResourceType::IamPolicy,
        "lambda" => CloudResourceType::Lambda,
        "virtual_machine" => CloudResourceType::VirtualMachine,
        "network_security_group" => CloudResourceType::NetworkSecurityGroup,
        "storage_account" => CloudResourceType::StorageAccount,
        "sql_server" => CloudResourceType::SqlServer,
        "compute_instance" => CloudResourceType::ComputeInstance,
        "firewall_rule" => CloudResourceType::FirewallRule,
        "cloud_storage" => CloudResourceType::CloudStorage,
        "cloud_sql" => CloudResourceType::CloudSql,
        "service_account" => CloudResourceType::ServiceAccount,
        other => CloudResourceType::Other(other.to_string()),
    }
}

fn parse_finding_type(s: &str) -> FindingType {
    match s {
        "misconfiguration" => FindingType::Misconfiguration,
        "vulnerability" => FindingType::Vulnerability,
        "exposure" => FindingType::Exposure,
        "policy_violation" => FindingType::PolicyViolation,
        "best_practice" => FindingType::BestPractice,
        _ => FindingType::Misconfiguration,
    }
}

// ============================================================================
// Database Operations - Scans
// ============================================================================

/// Create a new cloud scan record
pub async fn create_cloud_scan(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateCloudScanRequest,
) -> Result<CloudScan> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let regions_json = serde_json::to_string(&request.regions)?;
    let scan_types_json = serde_json::to_string(&request.scan_types)?;

    sqlx::query(
        r#"
        INSERT INTO cloud_scans (
            id, user_id, name, provider, regions, scan_types, status,
            credentials_id, findings_count, resources_count, created_at,
            customer_id, engagement_id
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.provider)
    .bind(&regions_json)
    .bind(&scan_types_json)
    .bind("pending")
    .bind(&request.credentials_id)
    .bind(0)
    .bind(0)
    .bind(now)
    .bind(&request.customer_id)
    .bind(&request.engagement_id)
    .execute(pool)
    .await?;

    let row = sqlx::query_as::<_, CloudScanRow>("SELECT * FROM cloud_scans WHERE id = ?1")
        .bind(&id)
        .fetch_one(pool)
        .await?;

    Ok(row.to_cloud_scan())
}

/// Get a cloud scan by ID
pub async fn get_cloud_scan(
    pool: &SqlitePool,
    scan_id: &str,
    user_id: &str,
) -> Result<Option<CloudScan>> {
    let row = sqlx::query_as::<_, CloudScanRow>(
        "SELECT * FROM cloud_scans WHERE id = ?1 AND user_id = ?2",
    )
    .bind(scan_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.to_cloud_scan()))
}

/// List cloud scans for a user
pub async fn list_cloud_scans(
    pool: &SqlitePool,
    user_id: &str,
    query: &ListCloudScansQuery,
) -> Result<Vec<CloudScan>> {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from("SELECT * FROM cloud_scans WHERE user_id = ?1");
    let mut param_index = 2;

    if query.provider.is_some() {
        sql.push_str(&format!(" AND provider = ?{}", param_index));
        param_index += 1;
    }

    if query.status.is_some() {
        sql.push_str(&format!(" AND status = ?{}", param_index));
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

    let mut q = sqlx::query_as::<_, CloudScanRow>(&sql).bind(user_id);

    if let Some(provider) = &query.provider {
        q = q.bind(provider);
    }

    if let Some(status) = &query.status {
        q = q.bind(status);
    }

    q = q.bind(limit).bind(offset);

    let rows = q.fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.to_cloud_scan()).collect())
}

/// Update cloud scan status
pub async fn update_cloud_scan_status(
    pool: &SqlitePool,
    scan_id: &str,
    status: CloudScanStatus,
    error_message: Option<&str>,
) -> Result<()> {
    let now = Utc::now();
    let status_str = status.to_string();

    match status {
        CloudScanStatus::Running => {
            sqlx::query("UPDATE cloud_scans SET status = ?1, started_at = ?2 WHERE id = ?3")
                .bind(&status_str)
                .bind(now)
                .bind(scan_id)
                .execute(pool)
                .await?;
        }
        CloudScanStatus::Completed | CloudScanStatus::Failed => {
            sqlx::query(
                "UPDATE cloud_scans SET status = ?1, completed_at = ?2, error_message = ?3 WHERE id = ?4",
            )
            .bind(&status_str)
            .bind(now)
            .bind(error_message)
            .bind(scan_id)
            .execute(pool)
            .await?;
        }
        _ => {
            sqlx::query("UPDATE cloud_scans SET status = ?1 WHERE id = ?2")
                .bind(&status_str)
                .bind(scan_id)
                .execute(pool)
                .await?;
        }
    }

    Ok(())
}

/// Update cloud scan counts
pub async fn update_cloud_scan_counts(
    pool: &SqlitePool,
    scan_id: &str,
    resources_count: i32,
    findings_count: i32,
) -> Result<()> {
    sqlx::query(
        "UPDATE cloud_scans SET resources_count = ?1, findings_count = ?2 WHERE id = ?3",
    )
    .bind(resources_count)
    .bind(findings_count)
    .bind(scan_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a cloud scan and its resources/findings
pub async fn delete_cloud_scan(pool: &SqlitePool, scan_id: &str, user_id: &str) -> Result<bool> {
    // Verify ownership
    let scan = get_cloud_scan(pool, scan_id, user_id).await?;
    if scan.is_none() {
        return Ok(false);
    }

    // CASCADE will handle findings and resources
    let result = sqlx::query("DELETE FROM cloud_scans WHERE id = ?1 AND user_id = ?2")
        .bind(scan_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Database Operations - Resources
// ============================================================================

/// Store cloud resources from a scan
pub async fn store_cloud_resources(
    pool: &SqlitePool,
    scan_id: &str,
    resources: &[CloudResource],
) -> Result<()> {
    let now = Utc::now();

    for resource in resources {
        let tags_json = serde_json::to_string(&resource.tags)?;
        let metadata_json = serde_json::to_string(&resource.metadata)?;

        sqlx::query(
            r#"
            INSERT INTO cloud_resources (
                id, scan_id, provider, resource_type, resource_id,
                region, name, arn, tags, metadata, state, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
        )
        .bind(&resource.id)
        .bind(scan_id)
        .bind(resource.provider.to_string())
        .bind(resource.resource_type.to_string())
        .bind(&resource.resource_id)
        .bind(&resource.region)
        .bind(&resource.name)
        .bind(&resource.arn)
        .bind(&tags_json)
        .bind(&metadata_json)
        .bind(&resource.state)
        .bind(now)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Get resources for a scan
pub async fn get_cloud_resources(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Vec<CloudResource>> {
    let rows = sqlx::query_as::<_, CloudResourceRow>(
        "SELECT * FROM cloud_resources WHERE scan_id = ?1 ORDER BY resource_type, name",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.to_cloud_resource()).collect())
}

// ============================================================================
// Database Operations - Findings
// ============================================================================

/// Store cloud findings from a scan
pub async fn store_cloud_findings(
    pool: &SqlitePool,
    scan_id: &str,
    findings: &[CloudFinding],
) -> Result<()> {
    let now = Utc::now();

    for finding in findings {
        let compliance_json = serde_json::to_string(&finding.compliance_mappings)?;
        let evidence_json = finding
            .evidence
            .as_ref()
            .map(|e| serde_json::to_string(e))
            .transpose()?;

        sqlx::query(
            r#"
            INSERT INTO cloud_findings (
                id, scan_id, resource_id, finding_type, severity, title,
                description, remediation, compliance_mappings, affected_resource_arn,
                evidence, status, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
        )
        .bind(&finding.id)
        .bind(scan_id)
        .bind(&finding.resource_id)
        .bind(finding.finding_type.to_string())
        .bind(finding.severity.to_string())
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(&finding.remediation)
        .bind(&compliance_json)
        .bind(&finding.affected_resource_arn)
        .bind(&evidence_json)
        .bind(finding.status.to_string())
        .bind(now)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Get findings for a scan
pub async fn get_cloud_findings(
    pool: &SqlitePool,
    scan_id: &str,
    query: &ListFindingsQuery,
) -> Result<Vec<CloudFinding>> {
    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from("SELECT * FROM cloud_findings WHERE scan_id = ?1");
    let mut param_index = 2;

    if query.severity.is_some() {
        sql.push_str(&format!(" AND severity = ?{}", param_index));
        param_index += 1;
    }

    if query.finding_type.is_some() {
        sql.push_str(&format!(" AND finding_type = ?{}", param_index));
        param_index += 1;
    }

    if query.status.is_some() {
        sql.push_str(&format!(" AND status = ?{}", param_index));
    }

    // Order by severity (critical first) then by title
    sql.push_str(
        " ORDER BY CASE severity \
            WHEN 'critical' THEN 1 \
            WHEN 'high' THEN 2 \
            WHEN 'medium' THEN 3 \
            WHEN 'low' THEN 4 \
            ELSE 5 END, title \
        LIMIT ? OFFSET ?",
    );

    let mut q = sqlx::query_as::<_, CloudFindingRow>(&sql).bind(scan_id);

    if let Some(severity) = &query.severity {
        q = q.bind(severity);
    }

    if let Some(finding_type) = &query.finding_type {
        q = q.bind(finding_type);
    }

    if let Some(status) = &query.status {
        q = q.bind(status);
    }

    q = q.bind(limit).bind(offset);

    let rows = q.fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.to_cloud_finding()).collect())
}

/// Get a single finding
pub async fn get_cloud_finding(
    pool: &SqlitePool,
    finding_id: &str,
) -> Result<Option<CloudFinding>> {
    let row = sqlx::query_as::<_, CloudFindingRow>(
        "SELECT * FROM cloud_findings WHERE id = ?1",
    )
    .bind(finding_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.to_cloud_finding()))
}

/// Update finding status
pub async fn update_finding_status(
    pool: &SqlitePool,
    finding_id: &str,
    status: FindingStatus,
) -> Result<bool> {
    let result = sqlx::query("UPDATE cloud_findings SET status = ?1 WHERE id = ?2")
        .bind(status.to_string())
        .bind(finding_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Get scan summary statistics
pub async fn get_cloud_scan_summary(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Option<CloudScanSummary>> {
    let scan_row = sqlx::query_as::<_, CloudScanRow>(
        "SELECT * FROM cloud_scans WHERE id = ?1",
    )
    .bind(scan_id)
    .fetch_optional(pool)
    .await?;

    let scan_row = match scan_row {
        Some(r) => r,
        None => return Ok(None),
    };

    // Get findings by severity
    let severity_counts: Vec<(String, i32)> = sqlx::query_as(
        "SELECT severity, COUNT(*) as count FROM cloud_findings WHERE scan_id = ?1 GROUP BY severity",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    let mut findings_by_severity = std::collections::HashMap::new();
    for (severity, count) in severity_counts {
        findings_by_severity.insert(severity, count);
    }

    // Get resources by type
    let type_counts: Vec<(String, i32)> = sqlx::query_as(
        "SELECT resource_type, COUNT(*) as count FROM cloud_resources WHERE scan_id = ?1 GROUP BY resource_type",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    let mut resources_by_type = std::collections::HashMap::new();
    for (resource_type, count) in type_counts {
        resources_by_type.insert(resource_type, count);
    }

    let provider = scan_row.provider.parse().unwrap_or(CloudProvider::Aws);
    let status = scan_row.status.parse().unwrap_or(CloudScanStatus::Pending);

    Ok(Some(CloudScanSummary {
        id: scan_row.id,
        name: scan_row.name,
        provider,
        status,
        findings_count: scan_row.findings_count,
        resources_count: scan_row.resources_count,
        created_at: scan_row.created_at,
        completed_at: scan_row.completed_at,
        findings_by_severity,
        resources_by_type,
    }))
}
