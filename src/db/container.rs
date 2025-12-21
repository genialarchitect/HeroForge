//! Container scanning database operations
//!
//! This module provides CRUD operations for container scanning data:
//! - Container scans
//! - Container images
//! - Kubernetes resources
//! - Container findings

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;

use crate::scanner::container::{
    ContainerFinding, ContainerFindingSeverity, ContainerFindingType, ContainerImage,
    ContainerScan, ContainerScanStatus, ContainerScanSummary, ContainerScanType, FindingStatus,
    ImageVulnSummary, K8sResource, K8sResourceType,
};

// Database row struct for ContainerImage (uses sqlx::FromRow)
#[derive(Debug, sqlx::FromRow)]
struct ContainerImageRow {
    id: String,
    scan_id: String,
    image_ref: String,
    digest: Option<String>,
    registry: Option<String>,
    repository: String,
    tag: String,
    os: Option<String>,
    architecture: Option<String>,
    created: Option<String>,
    size_bytes: Option<i64>,
    layer_count: i32,
    labels: String,
    vuln_count: i32,
    critical_count: i32,
    high_count: i32,
    discovered_at: String,
}

impl ContainerImageRow {
    fn into_container_image(self) -> ContainerImage {
        let labels: HashMap<String, String> = serde_json::from_str(&self.labels).unwrap_or_default();
        ContainerImage {
            id: self.id,
            scan_id: self.scan_id,
            image_ref: self.image_ref,
            digest: self.digest,
            registry: self.registry,
            repository: self.repository,
            tag: self.tag,
            os: self.os,
            architecture: self.architecture,
            created: self.created.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            size_bytes: self.size_bytes,
            layer_count: self.layer_count,
            labels,
            vuln_count: self.vuln_count,
            critical_count: self.critical_count,
            high_count: self.high_count,
            discovered_at: chrono::DateTime::parse_from_rfc3339(&self.discovered_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

// Database row struct for ContainerFinding (uses sqlx::FromRow to avoid 20-tuple limit)
#[derive(Debug, sqlx::FromRow)]
struct ContainerFindingRow {
    id: String,
    scan_id: String,
    image_id: Option<String>,
    resource_id: Option<String>,
    finding_type: String,
    severity: String,
    title: String,
    description: String,
    cve_id: Option<String>,
    cvss_score: Option<f64>,
    cwe_ids: String,
    package_name: Option<String>,
    package_version: Option<String>,
    fixed_version: Option<String>,
    file_path: Option<String>,
    line_number: Option<i32>,
    remediation: Option<String>,
    references: String,
    status: String,
    created_at: String,
}

impl ContainerFindingRow {
    fn into_container_finding(self) -> ContainerFinding {
        let finding_type = match self.finding_type.as_str() {
            "vulnerability" => ContainerFindingType::Vulnerability,
            "best_practice" => ContainerFindingType::BestPractice,
            "misconfiguration" => ContainerFindingType::Misconfiguration,
            "secret_exposure" => ContainerFindingType::SecretExposure,
            "privilege_escalation" => ContainerFindingType::PrivilegeEscalation,
            "network_exposure" => ContainerFindingType::NetworkExposure,
            "policy_violation" => ContainerFindingType::PolicyViolation,
            "outdated" => ContainerFindingType::Outdated,
            _ => ContainerFindingType::Misconfiguration,
        };

        let severity = match self.severity.as_str() {
            "critical" => ContainerFindingSeverity::Critical,
            "high" => ContainerFindingSeverity::High,
            "medium" => ContainerFindingSeverity::Medium,
            "low" => ContainerFindingSeverity::Low,
            _ => ContainerFindingSeverity::Info,
        };

        let status = match self.status.as_str() {
            "open" => FindingStatus::Open,
            "resolved" => FindingStatus::Resolved,
            "false_positive" => FindingStatus::FalsePositive,
            "accepted" => FindingStatus::Accepted,
            "in_progress" => FindingStatus::InProgress,
            _ => FindingStatus::Open,
        };

        let cwe_ids: Vec<String> = serde_json::from_str(&self.cwe_ids).unwrap_or_default();
        let references: Vec<String> = serde_json::from_str(&self.references).unwrap_or_default();

        ContainerFinding {
            id: self.id,
            scan_id: self.scan_id,
            image_id: self.image_id,
            resource_id: self.resource_id,
            finding_type,
            severity,
            title: self.title,
            description: self.description,
            cve_id: self.cve_id,
            cvss_score: self.cvss_score,
            cwe_ids,
            package_name: self.package_name,
            package_version: self.package_version,
            fixed_version: self.fixed_version,
            file_path: self.file_path,
            line_number: self.line_number,
            remediation: self.remediation,
            references,
            status,
            created_at: chrono::DateTime::parse_from_rfc3339(&self.created_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to create a container scan
#[derive(Debug, Deserialize)]
pub struct CreateContainerScanRequest {
    pub name: String,
    pub scan_types: Vec<String>,
    #[serde(default)]
    pub demo_mode: bool,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Query parameters for listing container scans
#[derive(Debug, Deserialize)]
pub struct ListContainerScansQuery {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub limit: Option<i32>,
    #[serde(default)]
    pub offset: Option<i32>,
}

/// Query parameters for listing findings
#[derive(Debug, Deserialize)]
pub struct ListFindingsQuery {
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub finding_type: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub limit: Option<i32>,
    #[serde(default)]
    pub offset: Option<i32>,
}

/// Request to update finding status
#[derive(Debug, Deserialize)]
pub struct UpdateFindingStatusRequest {
    pub status: String,
}

// ============================================================================
// Scan Operations
// ============================================================================

/// Create a new container scan
pub async fn create_container_scan(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateContainerScanRequest,
) -> Result<ContainerScan> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let scan_types_json = serde_json::to_string(&request.scan_types)?;

    sqlx::query(
        r#"
        INSERT INTO container_scans (id, user_id, name, scan_types, status, created_at, customer_id, engagement_id)
        VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6, ?7)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&scan_types_json)
    .bind(now)
    .bind(&request.customer_id)
    .bind(&request.engagement_id)
    .execute(pool)
    .await?;

    Ok(ContainerScan {
        id,
        user_id: user_id.to_string(),
        name: request.name.clone(),
        scan_types: request.scan_types.iter()
            .filter_map(|s| s.parse().ok())
            .collect(),
        status: ContainerScanStatus::Pending,
        images_count: 0,
        resources_count: 0,
        findings_count: 0,
        critical_count: 0,
        high_count: 0,
        error_message: None,
        created_at: now,
        started_at: None,
        completed_at: None,
        customer_id: request.customer_id.clone(),
        engagement_id: request.engagement_id.clone(),
    })
}

/// List container scans for a user
pub async fn list_container_scans(
    pool: &SqlitePool,
    user_id: &str,
    query: &ListContainerScansQuery,
) -> Result<Vec<ContainerScan>> {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let scans: Vec<(
        String, String, String, String, String, i32, i32, i32, i32, i32,
        Option<String>, String, Option<String>, Option<String>, Option<String>, Option<String>,
    )> = if let Some(status) = &query.status {
        sqlx::query_as(
            r#"
            SELECT id, user_id, name, scan_types, status, images_count, resources_count,
                   findings_count, critical_count, high_count, error_message, created_at,
                   started_at, completed_at, customer_id, engagement_id
            FROM container_scans
            WHERE user_id = ?1 AND status = ?2
            ORDER BY created_at DESC
            LIMIT ?3 OFFSET ?4
            "#,
        )
        .bind(user_id)
        .bind(status)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT id, user_id, name, scan_types, status, images_count, resources_count,
                   findings_count, critical_count, high_count, error_message, created_at,
                   started_at, completed_at, customer_id, engagement_id
            FROM container_scans
            WHERE user_id = ?1
            ORDER BY created_at DESC
            LIMIT ?2 OFFSET ?3
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    };

    Ok(scans.into_iter().map(|row| {
        let scan_types: Vec<ContainerScanType> = serde_json::from_str(&row.3)
            .unwrap_or_default();
        let status: ContainerScanStatus = row.4.parse().unwrap_or(ContainerScanStatus::Pending);

        ContainerScan {
            id: row.0,
            user_id: row.1,
            name: row.2,
            scan_types,
            status,
            images_count: row.5,
            resources_count: row.6,
            findings_count: row.7,
            critical_count: row.8,
            high_count: row.9,
            error_message: row.10,
            created_at: chrono::DateTime::parse_from_rfc3339(&row.11)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            started_at: row.12.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            completed_at: row.13.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            customer_id: row.14,
            engagement_id: row.15,
        }
    }).collect())
}

/// Get a single container scan by ID
pub async fn get_container_scan(
    pool: &SqlitePool,
    scan_id: &str,
    user_id: &str,
) -> Result<Option<ContainerScan>> {
    let row: Option<(
        String, String, String, String, String, i32, i32, i32, i32, i32,
        Option<String>, String, Option<String>, Option<String>, Option<String>, Option<String>,
    )> = sqlx::query_as(
        r#"
        SELECT id, user_id, name, scan_types, status, images_count, resources_count,
               findings_count, critical_count, high_count, error_message, created_at,
               started_at, completed_at, customer_id, engagement_id
        FROM container_scans
        WHERE id = ?1 AND user_id = ?2
        "#,
    )
    .bind(scan_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| {
        let scan_types: Vec<ContainerScanType> = serde_json::from_str(&row.3)
            .unwrap_or_default();
        let status: ContainerScanStatus = row.4.parse().unwrap_or(ContainerScanStatus::Pending);

        ContainerScan {
            id: row.0,
            user_id: row.1,
            name: row.2,
            scan_types,
            status,
            images_count: row.5,
            resources_count: row.6,
            findings_count: row.7,
            critical_count: row.8,
            high_count: row.9,
            error_message: row.10,
            created_at: chrono::DateTime::parse_from_rfc3339(&row.11)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            started_at: row.12.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            completed_at: row.13.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            customer_id: row.14,
            engagement_id: row.15,
        }
    }))
}

/// Update container scan status
pub async fn update_container_scan_status(
    pool: &SqlitePool,
    scan_id: &str,
    status: ContainerScanStatus,
    error_message: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    match status {
        ContainerScanStatus::Running => {
            sqlx::query(
                "UPDATE container_scans SET status = ?1, started_at = ?2 WHERE id = ?3"
            )
            .bind(status.to_string())
            .bind(now)
            .bind(scan_id)
            .execute(pool)
            .await?;
        }
        ContainerScanStatus::Completed | ContainerScanStatus::Failed => {
            sqlx::query(
                "UPDATE container_scans SET status = ?1, completed_at = ?2, error_message = ?3 WHERE id = ?4"
            )
            .bind(status.to_string())
            .bind(now)
            .bind(error_message)
            .bind(scan_id)
            .execute(pool)
            .await?;
        }
        _ => {
            sqlx::query("UPDATE container_scans SET status = ?1 WHERE id = ?2")
                .bind(status.to_string())
                .bind(scan_id)
                .execute(pool)
                .await?;
        }
    }

    Ok(())
}

/// Update scan counts
pub async fn update_container_scan_counts(
    pool: &SqlitePool,
    scan_id: &str,
    images_count: i32,
    resources_count: i32,
    findings_count: i32,
    critical_count: i32,
    high_count: i32,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE container_scans
        SET images_count = ?1, resources_count = ?2, findings_count = ?3,
            critical_count = ?4, high_count = ?5
        WHERE id = ?6
        "#,
    )
    .bind(images_count)
    .bind(resources_count)
    .bind(findings_count)
    .bind(critical_count)
    .bind(high_count)
    .bind(scan_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a container scan
pub async fn delete_container_scan(
    pool: &SqlitePool,
    scan_id: &str,
    user_id: &str,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM container_scans WHERE id = ?1 AND user_id = ?2")
        .bind(scan_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Image Operations
// ============================================================================

/// Store container images from a scan
pub async fn store_container_images(
    pool: &SqlitePool,
    scan_id: &str,
    images: &[ContainerImage],
) -> Result<()> {
    for image in images {
        let labels_json = serde_json::to_string(&image.labels)?;

        sqlx::query(
            r#"
            INSERT INTO container_images (
                id, scan_id, image_ref, digest, registry, repository, tag, os, architecture,
                created, size_bytes, layer_count, labels, vuln_count, critical_count, high_count, discovered_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
            "#,
        )
        .bind(&image.id)
        .bind(scan_id)
        .bind(&image.image_ref)
        .bind(&image.digest)
        .bind(&image.registry)
        .bind(&image.repository)
        .bind(&image.tag)
        .bind(&image.os)
        .bind(&image.architecture)
        .bind(image.created.map(|d| d.to_rfc3339()))
        .bind(image.size_bytes)
        .bind(image.layer_count)
        .bind(&labels_json)
        .bind(image.vuln_count)
        .bind(image.critical_count)
        .bind(image.high_count)
        .bind(image.discovered_at)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Get images for a scan
pub async fn get_container_images(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Vec<ContainerImage>> {
    let rows: Vec<ContainerImageRow> = sqlx::query_as(
        r#"
        SELECT id, scan_id, image_ref, digest, registry, repository, tag, os, architecture,
               created, size_bytes, layer_count, labels, vuln_count, critical_count, high_count, discovered_at
        FROM container_images
        WHERE scan_id = ?1
        ORDER BY discovered_at
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|row| row.into_container_image()).collect())
}

// ============================================================================
// K8s Resource Operations
// ============================================================================

/// Store K8s resources from a scan
pub async fn store_k8s_resources(
    pool: &SqlitePool,
    scan_id: &str,
    resources: &[K8sResource],
) -> Result<()> {
    for resource in resources {
        let labels_json = serde_json::to_string(&resource.labels)?;
        let annotations_json = serde_json::to_string(&resource.annotations)?;
        let manifest_json = serde_json::to_string(&resource.manifest)?;

        sqlx::query(
            r#"
            INSERT INTO k8s_resources (
                id, scan_id, resource_type, api_version, name, namespace, labels, annotations,
                manifest, finding_count, discovered_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
        )
        .bind(&resource.id)
        .bind(scan_id)
        .bind(resource.resource_type.to_string())
        .bind(&resource.api_version)
        .bind(&resource.name)
        .bind(&resource.namespace)
        .bind(&labels_json)
        .bind(&annotations_json)
        .bind(&manifest_json)
        .bind(resource.finding_count)
        .bind(resource.discovered_at)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Get K8s resources for a scan
pub async fn get_k8s_resources(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Vec<K8sResource>> {
    let rows: Vec<(
        String, String, String, String, String, Option<String>, String, String, String, i32, String,
    )> = sqlx::query_as(
        r#"
        SELECT id, scan_id, resource_type, api_version, name, namespace, labels, annotations,
               manifest, finding_count, discovered_at
        FROM k8s_resources
        WHERE scan_id = ?1
        ORDER BY resource_type, name
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|row| {
        let labels: HashMap<String, String> = serde_json::from_str(&row.6).unwrap_or_default();
        let annotations: HashMap<String, String> = serde_json::from_str(&row.7).unwrap_or_default();
        let manifest: serde_json::Value = serde_json::from_str(&row.8).unwrap_or(serde_json::json!({}));

        let resource_type = match row.2.as_str() {
            "pod" => K8sResourceType::Pod,
            "deployment" => K8sResourceType::Deployment,
            "statefulset" => K8sResourceType::StatefulSet,
            "daemonset" => K8sResourceType::DaemonSet,
            "service" => K8sResourceType::Service,
            "ingress" => K8sResourceType::Ingress,
            "configmap" => K8sResourceType::ConfigMap,
            "secret" => K8sResourceType::Secret,
            "serviceaccount" => K8sResourceType::ServiceAccount,
            "role" => K8sResourceType::Role,
            "clusterrole" => K8sResourceType::ClusterRole,
            "rolebinding" => K8sResourceType::RoleBinding,
            "clusterrolebinding" => K8sResourceType::ClusterRoleBinding,
            "networkpolicy" => K8sResourceType::NetworkPolicy,
            "namespace" => K8sResourceType::Namespace,
            other => K8sResourceType::Other(other.to_string()),
        };

        K8sResource {
            id: row.0,
            scan_id: row.1,
            resource_type,
            api_version: row.3,
            name: row.4,
            namespace: row.5,
            labels,
            annotations,
            manifest,
            finding_count: row.9,
            discovered_at: chrono::DateTime::parse_from_rfc3339(&row.10)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }).collect())
}

// ============================================================================
// Finding Operations
// ============================================================================

/// Store container findings from a scan
pub async fn store_container_findings(
    pool: &SqlitePool,
    scan_id: &str,
    findings: &[ContainerFinding],
) -> Result<()> {
    for finding in findings {
        let cwe_ids_json = serde_json::to_string(&finding.cwe_ids)?;
        let references_json = serde_json::to_string(&finding.references)?;

        sqlx::query(
            r#"
            INSERT INTO container_findings (
                id, scan_id, image_id, resource_id, finding_type, severity, title, description,
                cve_id, cvss_score, cwe_ids, package_name, package_version, fixed_version,
                file_path, line_number, remediation, "references", status, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
            "#,
        )
        .bind(&finding.id)
        .bind(scan_id)
        .bind(&finding.image_id)
        .bind(&finding.resource_id)
        .bind(finding.finding_type.to_string())
        .bind(finding.severity.to_string())
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(&finding.cve_id)
        .bind(finding.cvss_score)
        .bind(&cwe_ids_json)
        .bind(&finding.package_name)
        .bind(&finding.package_version)
        .bind(&finding.fixed_version)
        .bind(&finding.file_path)
        .bind(finding.line_number)
        .bind(&finding.remediation)
        .bind(&references_json)
        .bind(finding.status.to_string())
        .bind(finding.created_at)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Get findings for a scan
pub async fn get_container_findings(
    pool: &SqlitePool,
    scan_id: &str,
    query: &ListFindingsQuery,
) -> Result<Vec<ContainerFinding>> {
    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);

    // Build dynamic query based on filters
    let mut sql = String::from(
        r#"
        SELECT id, scan_id, image_id, resource_id, finding_type, severity, title, description,
               cve_id, cvss_score, cwe_ids, package_name, package_version, fixed_version,
               file_path, line_number, remediation, "references", status, created_at
        FROM container_findings
        WHERE scan_id = ?1
        "#
    );

    let mut bind_idx = 2;
    if query.severity.is_some() {
        sql.push_str(&format!(" AND severity = ?{}", bind_idx));
        bind_idx += 1;
    }
    if query.finding_type.is_some() {
        sql.push_str(&format!(" AND finding_type = ?{}", bind_idx));
        bind_idx += 1;
    }
    if query.status.is_some() {
        sql.push_str(&format!(" AND status = ?{}", bind_idx));
        bind_idx += 1;
    }

    sql.push_str(&format!(" ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at DESC LIMIT ?{} OFFSET ?{}", bind_idx, bind_idx + 1));

    let mut query_builder = sqlx::query_as::<_, ContainerFindingRow>(&sql);

    query_builder = query_builder.bind(scan_id);

    if let Some(severity) = &query.severity {
        query_builder = query_builder.bind(severity);
    }
    if let Some(finding_type) = &query.finding_type {
        query_builder = query_builder.bind(finding_type);
    }
    if let Some(status) = &query.status {
        query_builder = query_builder.bind(status);
    }

    query_builder = query_builder.bind(limit).bind(offset);

    let rows = query_builder.fetch_all(pool).await?;

    Ok(rows.into_iter().map(|row| row.into_container_finding()).collect())
}

/// Get a single finding by ID
pub async fn get_container_finding(
    pool: &SqlitePool,
    finding_id: &str,
) -> Result<Option<ContainerFinding>> {
    let row: Option<ContainerFindingRow> = sqlx::query_as(
        r#"
        SELECT id, scan_id, image_id, resource_id, finding_type, severity, title, description,
               cve_id, cvss_score, cwe_ids, package_name, package_version, fixed_version,
               file_path, line_number, remediation, "references", status, created_at
        FROM container_findings
        WHERE id = ?1
        "#,
    )
    .bind(finding_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.into_container_finding()))
}

/// Update finding status
pub async fn update_finding_status(
    pool: &SqlitePool,
    finding_id: &str,
    status: FindingStatus,
) -> Result<bool> {
    let result = sqlx::query("UPDATE container_findings SET status = ?1 WHERE id = ?2")
        .bind(status.to_string())
        .bind(finding_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Get scan summary
pub async fn get_container_scan_summary(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Option<ContainerScanSummary>> {
    // Get basic scan info
    let scan_row: Option<(String, String, String, String, i32, i32, i32, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT id, name, scan_types, status, images_count, resources_count, findings_count, created_at, completed_at
        FROM container_scans
        WHERE id = ?1
        "#,
    )
    .bind(scan_id)
    .fetch_optional(pool)
    .await?;

    let scan_row = match scan_row {
        Some(row) => row,
        None => return Ok(None),
    };

    // Get findings by severity
    let severity_counts: Vec<(String, i32)> = sqlx::query_as(
        "SELECT severity, COUNT(*) as count FROM container_findings WHERE scan_id = ?1 GROUP BY severity"
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    let mut findings_by_severity: HashMap<String, i32> = HashMap::new();
    for (severity, count) in severity_counts {
        findings_by_severity.insert(severity, count);
    }

    // Get findings by type
    let type_counts: Vec<(String, i32)> = sqlx::query_as(
        "SELECT finding_type, COUNT(*) as count FROM container_findings WHERE scan_id = ?1 GROUP BY finding_type"
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    let mut findings_by_type: HashMap<String, i32> = HashMap::new();
    for (finding_type, count) in type_counts {
        findings_by_type.insert(finding_type, count);
    }

    // Get top vulnerable images
    let image_vulns: Vec<(String, i32, i32, i32, i32)> = sqlx::query_as(
        r#"
        SELECT ci.image_ref,
               COALESCE(SUM(CASE WHEN cf.severity = 'critical' THEN 1 ELSE 0 END), 0) as critical,
               COALESCE(SUM(CASE WHEN cf.severity = 'high' THEN 1 ELSE 0 END), 0) as high,
               COALESCE(SUM(CASE WHEN cf.severity = 'medium' THEN 1 ELSE 0 END), 0) as medium,
               COALESCE(SUM(CASE WHEN cf.severity = 'low' OR cf.severity = 'info' THEN 1 ELSE 0 END), 0) as low
        FROM container_images ci
        LEFT JOIN container_findings cf ON ci.id = cf.image_id
        WHERE ci.scan_id = ?1
        GROUP BY ci.id, ci.image_ref
        ORDER BY critical DESC, high DESC, medium DESC
        LIMIT 5
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    let top_vulnerable_images: Vec<ImageVulnSummary> = image_vulns
        .into_iter()
        .map(|(image_ref, critical, high, medium, low)| ImageVulnSummary {
            image_ref,
            critical,
            high,
            medium,
            low,
        })
        .collect();

    let scan_types: Vec<ContainerScanType> = serde_json::from_str(&scan_row.2).unwrap_or_default();
    let status: ContainerScanStatus = scan_row.3.parse().unwrap_or(ContainerScanStatus::Pending);

    Ok(Some(ContainerScanSummary {
        id: scan_row.0,
        name: scan_row.1,
        status,
        scan_types,
        images_count: scan_row.4,
        resources_count: scan_row.5,
        findings_count: scan_row.6,
        created_at: chrono::DateTime::parse_from_rfc3339(&scan_row.7)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        completed_at: scan_row.8.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
        findings_by_severity,
        findings_by_type,
        top_vulnerable_images,
    }))
}
