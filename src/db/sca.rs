//! Database operations for Software Composition Analysis (SCA)
//!
//! Provides CRUD operations for:
//! - SCA projects
//! - Dependencies
//! - Vulnerabilities
//! - Statistics and dashboards

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

// ============================================================================
// Database Models
// ============================================================================

/// SCA Project record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScaProjectRecord {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub repository_url: Option<String>,
    pub ecosystem: String,
    pub manifest_files: Option<String>,
    pub last_scan_at: Option<String>,
    pub total_dependencies: i64,
    pub vulnerable_dependencies: i64,
    pub license_issues: i64,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// SCA Project summary for listing
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScaProjectSummary {
    pub id: String,
    pub name: String,
    pub ecosystem: String,
    pub total_dependencies: i64,
    pub vulnerable_dependencies: i64,
    pub license_issues: i64,
    pub last_scan_at: Option<String>,
    pub created_at: String,
}

/// SCA Dependency record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScaDependencyRecord {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub purl: Option<String>,
    pub is_direct: i64,
    pub parent_id: Option<String>,
    pub depth: i64,
    pub license: Option<String>,
    pub license_risk: String,
    pub latest_version: Option<String>,
    pub update_available: i64,
    pub created_at: String,
}

/// SCA Vulnerability record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScaVulnerabilityRecord {
    pub id: String,
    pub dependency_id: String,
    pub project_id: String,
    pub vuln_id: String,
    pub source: String,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub epss_score: Option<f64>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub affected_versions: Option<String>,
    pub fixed_version: Option<String>,
    pub references_json: Option<String>,
    pub exploited_in_wild: i64,
    pub status: String,
    pub created_at: String,
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to create an SCA project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScaProjectRequest {
    pub name: String,
    pub repository_url: Option<String>,
    pub ecosystem: String,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Request to update an SCA project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateScaProjectRequest {
    pub name: Option<String>,
    pub repository_url: Option<String>,
    pub ecosystem: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Request to create a dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDependencyRequest {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub purl: Option<String>,
    pub is_direct: bool,
    pub parent_id: Option<String>,
    pub depth: i32,
    pub license: Option<String>,
    pub license_risk: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
}

/// Request to create a vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVulnerabilityRequest {
    pub dependency_id: String,
    pub vuln_id: String,
    pub source: String,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub epss_score: Option<f64>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub affected_versions: Option<String>,
    pub fixed_version: Option<String>,
    pub references: Vec<String>,
    pub exploited_in_wild: bool,
}

/// SCA Statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScaStats {
    pub total_projects: i64,
    pub total_dependencies: i64,
    pub direct_dependencies: i64,
    pub transitive_dependencies: i64,
    pub total_vulnerabilities: i64,
    pub critical_vulns: i64,
    pub high_vulns: i64,
    pub medium_vulns: i64,
    pub low_vulns: i64,
    pub license_issues: i64,
    pub outdated_dependencies: i64,
}

/// Vulnerability by ecosystem count
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VulnsByEcosystem {
    pub ecosystem: String,
    pub count: i64,
}

/// Top vulnerable package
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TopVulnerablePackage {
    pub name: String,
    pub ecosystem: String,
    pub vuln_count: i64,
    pub project_count: i64,
}

// ============================================================================
// Project Operations
// ============================================================================

/// Create a new SCA project
pub async fn create_project(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateScaProjectRequest,
) -> Result<ScaProjectRecord> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO sca_projects (id, user_id, name, repository_url, ecosystem, customer_id, engagement_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.repository_url)
    .bind(&request.ecosystem)
    .bind(&request.customer_id)
    .bind(&request.engagement_id)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_project_by_id(pool, &id).await
}

/// Get an SCA project by ID
pub async fn get_project_by_id(pool: &SqlitePool, id: &str) -> Result<ScaProjectRecord> {
    let project = sqlx::query_as::<_, ScaProjectRecord>(
        "SELECT * FROM sca_projects WHERE id = ?",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(project)
}

/// Get all SCA projects for a user
pub async fn get_user_projects(pool: &SqlitePool, user_id: &str) -> Result<Vec<ScaProjectSummary>> {
    let projects = sqlx::query_as::<_, ScaProjectSummary>(
        r#"
        SELECT id, name, ecosystem, total_dependencies, vulnerable_dependencies,
               license_issues, last_scan_at, created_at
        FROM sca_projects
        WHERE user_id = ?
        ORDER BY updated_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(projects)
}

/// Update an SCA project
pub async fn update_project(
    pool: &SqlitePool,
    id: &str,
    request: &UpdateScaProjectRequest,
) -> Result<ScaProjectRecord> {
    let now = Utc::now().to_rfc3339();

    // Build dynamic update query
    let mut updates = vec!["updated_at = ?".to_string()];
    let mut has_update = false;

    if request.name.is_some() {
        updates.push("name = ?".to_string());
        has_update = true;
    }
    if request.repository_url.is_some() {
        updates.push("repository_url = ?".to_string());
        has_update = true;
    }
    if request.ecosystem.is_some() {
        updates.push("ecosystem = ?".to_string());
        has_update = true;
    }

    if !has_update {
        return get_project_by_id(pool, id).await;
    }

    // Execute update (simplified - in production would use dynamic query builder)
    if let Some(name) = &request.name {
        sqlx::query("UPDATE sca_projects SET name = ?, updated_at = ? WHERE id = ?")
            .bind(name)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    }

    if let Some(repo) = &request.repository_url {
        sqlx::query("UPDATE sca_projects SET repository_url = ?, updated_at = ? WHERE id = ?")
            .bind(repo)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    }

    if let Some(eco) = &request.ecosystem {
        sqlx::query("UPDATE sca_projects SET ecosystem = ?, updated_at = ? WHERE id = ?")
            .bind(eco)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    }

    get_project_by_id(pool, id).await
}

/// Update project statistics after analysis
pub async fn update_project_stats(
    pool: &SqlitePool,
    id: &str,
    total_deps: i64,
    vuln_deps: i64,
    license_issues: i64,
    manifest_files: &[String],
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let manifest_json = serde_json::to_string(manifest_files)?;

    sqlx::query(
        r#"
        UPDATE sca_projects
        SET total_dependencies = ?,
            vulnerable_dependencies = ?,
            license_issues = ?,
            manifest_files = ?,
            last_scan_at = ?,
            updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(total_deps)
    .bind(vuln_deps)
    .bind(license_issues)
    .bind(&manifest_json)
    .bind(&now)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete an SCA project
pub async fn delete_project(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM sca_projects WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Dependency Operations
// ============================================================================

/// Create a new dependency
pub async fn create_dependency(
    pool: &SqlitePool,
    project_id: &str,
    request: &CreateDependencyRequest,
) -> Result<ScaDependencyRecord> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO sca_dependencies (id, project_id, name, version, ecosystem, purl, is_direct,
            parent_id, depth, license, license_risk, latest_version, update_available, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(project_id)
    .bind(&request.name)
    .bind(&request.version)
    .bind(&request.ecosystem)
    .bind(&request.purl)
    .bind(request.is_direct as i64)
    .bind(&request.parent_id)
    .bind(request.depth as i64)
    .bind(&request.license)
    .bind(&request.license_risk)
    .bind(&request.latest_version)
    .bind(request.update_available as i64)
    .bind(&now)
    .execute(pool)
    .await?;

    get_dependency_by_id(pool, &id).await
}

/// Create dependencies in bulk
pub async fn create_dependencies_bulk(
    pool: &SqlitePool,
    project_id: &str,
    requests: &[CreateDependencyRequest],
) -> Result<i64> {
    let now = Utc::now().to_rfc3339();
    let mut count = 0i64;

    for request in requests {
        let id = Uuid::new_v4().to_string();

        let result = sqlx::query(
            r#"
            INSERT OR IGNORE INTO sca_dependencies (id, project_id, name, version, ecosystem, purl, is_direct,
                parent_id, depth, license, license_risk, latest_version, update_available, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(project_id)
        .bind(&request.name)
        .bind(&request.version)
        .bind(&request.ecosystem)
        .bind(&request.purl)
        .bind(request.is_direct as i64)
        .bind(&request.parent_id)
        .bind(request.depth as i64)
        .bind(&request.license)
        .bind(&request.license_risk)
        .bind(&request.latest_version)
        .bind(request.update_available as i64)
        .bind(&now)
        .execute(pool)
        .await?;

        count += result.rows_affected() as i64;
    }

    Ok(count)
}

/// Get a dependency by ID
pub async fn get_dependency_by_id(pool: &SqlitePool, id: &str) -> Result<ScaDependencyRecord> {
    let dep = sqlx::query_as::<_, ScaDependencyRecord>(
        "SELECT * FROM sca_dependencies WHERE id = ?",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(dep)
}

/// Get all dependencies for a project
pub async fn get_project_dependencies(
    pool: &SqlitePool,
    project_id: &str,
    is_direct: Option<bool>,
    has_vulns: Option<bool>,
    license_risk: Option<&str>,
    update_available: Option<bool>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<ScaDependencyRecord>> {
    let mut query = String::from("SELECT d.* FROM sca_dependencies d WHERE d.project_id = ?");
    let mut params: Vec<String> = vec![project_id.to_string()];

    if let Some(direct) = is_direct {
        query.push_str(" AND d.is_direct = ?");
        params.push((direct as i64).to_string());
    }

    if let Some(true) = has_vulns {
        query.push_str(" AND EXISTS (SELECT 1 FROM sca_vulnerabilities v WHERE v.dependency_id = d.id)");
    }

    if let Some(risk) = license_risk {
        query.push_str(" AND d.license_risk = ?");
        params.push(risk.to_string());
    }

    if let Some(update) = update_available {
        query.push_str(" AND d.update_available = ?");
        params.push((update as i64).to_string());
    }

    query.push_str(" ORDER BY d.name ASC");

    if let Some(lim) = limit {
        query.push_str(&format!(" LIMIT {}", lim));
    }
    if let Some(off) = offset {
        query.push_str(&format!(" OFFSET {}", off));
    }

    // Build query with dynamic parameters
    let mut q = sqlx::query_as::<_, ScaDependencyRecord>(&query);
    for param in &params {
        q = q.bind(param);
    }

    let deps = q.fetch_all(pool).await?;
    Ok(deps)
}

/// Delete all dependencies for a project
pub async fn delete_project_dependencies(pool: &SqlitePool, project_id: &str) -> Result<i64> {
    let result = sqlx::query("DELETE FROM sca_dependencies WHERE project_id = ?")
        .bind(project_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() as i64)
}

// ============================================================================
// Vulnerability Operations
// ============================================================================

/// Create a new vulnerability
pub async fn create_vulnerability(
    pool: &SqlitePool,
    project_id: &str,
    request: &CreateVulnerabilityRequest,
) -> Result<ScaVulnerabilityRecord> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let refs_json = serde_json::to_string(&request.references)?;

    sqlx::query(
        r#"
        INSERT INTO sca_vulnerabilities (id, dependency_id, project_id, vuln_id, source, severity,
            cvss_score, cvss_vector, epss_score, title, description, affected_versions, fixed_version,
            references_json, exploited_in_wild, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)
        "#,
    )
    .bind(&id)
    .bind(&request.dependency_id)
    .bind(project_id)
    .bind(&request.vuln_id)
    .bind(&request.source)
    .bind(&request.severity)
    .bind(request.cvss_score)
    .bind(&request.cvss_vector)
    .bind(request.epss_score)
    .bind(&request.title)
    .bind(&request.description)
    .bind(&request.affected_versions)
    .bind(&request.fixed_version)
    .bind(&refs_json)
    .bind(request.exploited_in_wild as i64)
    .bind(&now)
    .execute(pool)
    .await?;

    get_vulnerability_by_id(pool, &id).await
}

/// Create vulnerabilities in bulk
pub async fn create_vulnerabilities_bulk(
    pool: &SqlitePool,
    project_id: &str,
    requests: &[CreateVulnerabilityRequest],
) -> Result<i64> {
    let now = Utc::now().to_rfc3339();
    let mut count = 0i64;

    for request in requests {
        let id = Uuid::new_v4().to_string();
        let refs_json = serde_json::to_string(&request.references)?;

        let result = sqlx::query(
            r#"
            INSERT INTO sca_vulnerabilities (id, dependency_id, project_id, vuln_id, source, severity,
                cvss_score, cvss_vector, epss_score, title, description, affected_versions, fixed_version,
                references_json, exploited_in_wild, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)
            "#,
        )
        .bind(&id)
        .bind(&request.dependency_id)
        .bind(project_id)
        .bind(&request.vuln_id)
        .bind(&request.source)
        .bind(&request.severity)
        .bind(request.cvss_score)
        .bind(&request.cvss_vector)
        .bind(request.epss_score)
        .bind(&request.title)
        .bind(&request.description)
        .bind(&request.affected_versions)
        .bind(&request.fixed_version)
        .bind(&refs_json)
        .bind(request.exploited_in_wild as i64)
        .bind(&now)
        .execute(pool)
        .await?;

        count += result.rows_affected() as i64;
    }

    Ok(count)
}

/// Get a vulnerability by ID
pub async fn get_vulnerability_by_id(pool: &SqlitePool, id: &str) -> Result<ScaVulnerabilityRecord> {
    let vuln = sqlx::query_as::<_, ScaVulnerabilityRecord>(
        "SELECT * FROM sca_vulnerabilities WHERE id = ?",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(vuln)
}

/// Get all vulnerabilities for a project
pub async fn get_project_vulnerabilities(
    pool: &SqlitePool,
    project_id: &str,
    severity: Option<&str>,
    status: Option<&str>,
    exploited: Option<bool>,
    has_fix: Option<bool>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<ScaVulnerabilityRecord>> {
    let mut query = String::from("SELECT * FROM sca_vulnerabilities WHERE project_id = ?");

    if let Some(sev) = severity {
        query.push_str(&format!(" AND severity = '{}'", sev));
    }

    if let Some(st) = status {
        query.push_str(&format!(" AND status = '{}'", st));
    }

    if let Some(exp) = exploited {
        query.push_str(&format!(" AND exploited_in_wild = {}", exp as i64));
    }

    if let Some(fix) = has_fix {
        if fix {
            query.push_str(" AND fixed_version IS NOT NULL");
        } else {
            query.push_str(" AND fixed_version IS NULL");
        }
    }

    query.push_str(" ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at DESC");

    if let Some(lim) = limit {
        query.push_str(&format!(" LIMIT {}", lim));
    }
    if let Some(off) = offset {
        query.push_str(&format!(" OFFSET {}", off));
    }

    let vulns = sqlx::query_as::<_, ScaVulnerabilityRecord>(&query)
        .bind(project_id)
        .fetch_all(pool)
        .await?;

    Ok(vulns)
}

/// Update vulnerability status
pub async fn update_vulnerability_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
) -> Result<ScaVulnerabilityRecord> {
    sqlx::query("UPDATE sca_vulnerabilities SET status = ? WHERE id = ?")
        .bind(status)
        .bind(id)
        .execute(pool)
        .await?;

    get_vulnerability_by_id(pool, id).await
}

/// Delete all vulnerabilities for a project
pub async fn delete_project_vulnerabilities(pool: &SqlitePool, project_id: &str) -> Result<i64> {
    let result = sqlx::query("DELETE FROM sca_vulnerabilities WHERE project_id = ?")
        .bind(project_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() as i64)
}

// ============================================================================
// Statistics Operations
// ============================================================================

/// Get SCA statistics for a user
pub async fn get_user_stats(pool: &SqlitePool, user_id: &str) -> Result<ScaStats> {
    // Get project counts
    let project_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sca_projects WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Get dependency counts
    let dep_counts: (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*),
            SUM(CASE WHEN is_direct = 1 THEN 1 ELSE 0 END),
            SUM(CASE WHEN is_direct = 0 THEN 1 ELSE 0 END)
        FROM sca_dependencies d
        JOIN sca_projects p ON d.project_id = p.id
        WHERE p.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0, 0, 0));

    // Get vulnerability counts by severity
    let vuln_counts: (i64, i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*),
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END)
        FROM sca_vulnerabilities v
        JOIN sca_projects p ON v.project_id = p.id
        WHERE p.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0, 0, 0, 0, 0));

    // Get license issues count
    let license_issues: (i64,) = sqlx::query_as(
        r#"
        SELECT SUM(license_issues) FROM sca_projects WHERE user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    // Get outdated dependencies count
    let outdated: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM sca_dependencies d
        JOIN sca_projects p ON d.project_id = p.id
        WHERE p.user_id = ? AND d.update_available = 1
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    Ok(ScaStats {
        total_projects: project_count.0,
        total_dependencies: dep_counts.0,
        direct_dependencies: dep_counts.1,
        transitive_dependencies: dep_counts.2,
        total_vulnerabilities: vuln_counts.0,
        critical_vulns: vuln_counts.1,
        high_vulns: vuln_counts.2,
        medium_vulns: vuln_counts.3,
        low_vulns: vuln_counts.4,
        license_issues: license_issues.0,
        outdated_dependencies: outdated.0,
    })
}

/// Get vulnerabilities by ecosystem
pub async fn get_vulns_by_ecosystem(pool: &SqlitePool, user_id: &str) -> Result<Vec<VulnsByEcosystem>> {
    let vulns = sqlx::query_as::<_, VulnsByEcosystem>(
        r#"
        SELECT d.ecosystem, COUNT(v.id) as count
        FROM sca_vulnerabilities v
        JOIN sca_dependencies d ON v.dependency_id = d.id
        JOIN sca_projects p ON v.project_id = p.id
        WHERE p.user_id = ?
        GROUP BY d.ecosystem
        ORDER BY count DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(vulns)
}

/// Get top vulnerable packages
pub async fn get_top_vulnerable_packages(
    pool: &SqlitePool,
    user_id: &str,
    limit: i64,
) -> Result<Vec<TopVulnerablePackage>> {
    let packages = sqlx::query_as::<_, TopVulnerablePackage>(
        r#"
        SELECT d.name, d.ecosystem,
               COUNT(DISTINCT v.vuln_id) as vuln_count,
               COUNT(DISTINCT p.id) as project_count
        FROM sca_dependencies d
        JOIN sca_vulnerabilities v ON v.dependency_id = d.id
        JOIN sca_projects p ON d.project_id = p.id
        WHERE p.user_id = ?
        GROUP BY d.name, d.ecosystem
        ORDER BY vuln_count DESC
        LIMIT ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(packages)
}

/// Check if user owns the project
pub async fn user_owns_project(pool: &SqlitePool, user_id: &str, project_id: &str) -> Result<bool> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sca_projects WHERE id = ? AND user_id = ?",
    )
    .bind(project_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(count.0 > 0)
}
