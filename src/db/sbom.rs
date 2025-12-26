//! SBOM (Software Bill of Materials) database operations
//!
//! This module provides CRUD operations for SBOM data:
//! - SBOM records (metadata)
//! - SBOM components (dependencies)
//! - Component vulnerabilities
//! - License tracking

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use uuid::Uuid;

use crate::yellow_team::types::{
    ComponentType, ComponentVuln, DependencyRelation, DependencyType,
    ExternalReference, LicenseInfo, LicenseRisk, Sbom, SbomComponent,
    SbomFormat, SbomProject, SbomStats, SourceFile, VulnSeverity,
};

// ============================================================================
// Request/Response Types
// ============================================================================

/// Query parameters for listing SBOMs
#[derive(Debug, Deserialize)]
pub struct ListSbomsQuery {
    #[serde(default)]
    pub project_name: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub limit: Option<i32>,
    #[serde(default)]
    pub offset: Option<i32>,
}

/// Query parameters for listing components
#[derive(Debug, Deserialize)]
pub struct ListComponentsQuery {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub has_vulns: Option<bool>,
    #[serde(default)]
    pub limit: Option<i32>,
    #[serde(default)]
    pub offset: Option<i32>,
}

/// Query parameters for listing vulnerabilities
#[derive(Debug, Deserialize)]
pub struct ListVulnsQuery {
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub has_fix: Option<bool>,
    #[serde(default)]
    pub limit: Option<i32>,
    #[serde(default)]
    pub offset: Option<i32>,
}

/// Summary response for SBOM
#[derive(Debug, Serialize)]
pub struct SbomSummary {
    pub id: String,
    pub project_name: String,
    pub project_version: Option<String>,
    pub format: String,
    pub total_components: i32,
    pub total_vulnerabilities: i32,
    pub critical_vulns: i32,
    pub high_vulns: i32,
    pub copyleft_licenses: i32,
    pub generated_at: String,
}

// ============================================================================
// Database Row Types
// ============================================================================

#[derive(Debug, sqlx::FromRow)]
struct SbomRow {
    id: String,
    user_id: String,
    project_name: String,
    project_version: Option<String>,
    format: String,
    stats_json: String,
    source_files_json: String,
    generated_at: String,
    created_at: String,
}

#[derive(Debug, sqlx::FromRow)]
struct SbomComponentRow {
    id: String,
    sbom_id: String,
    name: String,
    version: String,
    purl: String,
    component_type: String,
    supplier: Option<String>,
    licenses_json: String,
    hashes_json: String,
    description: Option<String>,
    dependency_type: String,
    cpe: Option<String>,
    external_refs_json: String,
}

#[derive(Debug, sqlx::FromRow)]
struct ComponentVulnRow {
    id: String,
    sbom_id: String,
    component_purl: String,
    cve_id: String,
    cvss_score: Option<f64>,
    severity: String,
    description: String,
    fixed_version: Option<String>,
    references_json: String,
}

#[derive(Debug, sqlx::FromRow)]
struct LicenseInfoRow {
    id: String,
    sbom_id: String,
    spdx_id: String,
    name: String,
    risk_level: String,
    url: Option<String>,
    component_count: i32,
}

// ============================================================================
// SBOM Operations
// ============================================================================

/// Create a new SBOM record
pub async fn create_sbom(pool: &SqlitePool, sbom: &Sbom) -> Result<()> {
    let stats_json = serde_json::to_string(&sbom.stats)?;
    let source_files_json = serde_json::to_string(&sbom.source_files)?;
    let now = Utc::now();

    // Insert SBOM record
    sqlx::query(
        r#"
        INSERT INTO sbom_records (id, user_id, project_name, project_version, format, stats_json, source_files_json, generated_at, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(sbom.id.to_string())
    .bind(sbom.user_id.to_string())
    .bind(&sbom.project_name)
    .bind(&sbom.project_version)
    .bind(sbom.format.to_string())
    .bind(&stats_json)
    .bind(&source_files_json)
    .bind(sbom.generated_at.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    // Insert components
    for component in &sbom.components {
        store_component(pool, &sbom.id.to_string(), component).await?;
    }

    // Insert vulnerabilities
    for vuln in &sbom.vulnerabilities {
        store_vulnerability(pool, &sbom.id.to_string(), vuln).await?;
    }

    // Insert license info
    for license in &sbom.licenses {
        store_license(pool, &sbom.id.to_string(), license).await?;
    }

    // Insert dependencies
    for dep in &sbom.dependencies {
        store_dependency(pool, &sbom.id.to_string(), dep).await?;
    }

    Ok(())
}

/// Store a single component
async fn store_component(pool: &SqlitePool, sbom_id: &str, component: &SbomComponent) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let licenses_json = serde_json::to_string(&component.licenses)?;
    let hashes_json = serde_json::to_string(&component.hashes)?;
    let external_refs_json = serde_json::to_string(&component.external_refs)?;

    sqlx::query(
        r#"
        INSERT INTO sbom_components (id, sbom_id, name, version, purl, component_type, supplier, licenses_json, hashes_json, description, dependency_type, cpe, external_refs_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
        "#,
    )
    .bind(&id)
    .bind(sbom_id)
    .bind(&component.name)
    .bind(&component.version)
    .bind(&component.purl)
    .bind(component.component_type.to_string())
    .bind(&component.supplier)
    .bind(&licenses_json)
    .bind(&hashes_json)
    .bind(&component.description)
    .bind(component.dependency_type.to_string())
    .bind(&component.cpe)
    .bind(&external_refs_json)
    .execute(pool)
    .await?;

    Ok(())
}

/// Store a vulnerability
async fn store_vulnerability(pool: &SqlitePool, sbom_id: &str, vuln: &ComponentVuln) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let references_json = serde_json::to_string(&vuln.references)?;

    sqlx::query(
        r#"
        INSERT INTO sbom_vulnerabilities (id, sbom_id, component_purl, cve_id, cvss_score, severity, description, fixed_version, references_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(&id)
    .bind(sbom_id)
    .bind(&vuln.component_purl)
    .bind(&vuln.cve_id)
    .bind(vuln.cvss_score)
    .bind(format!("{:?}", vuln.severity).to_lowercase())
    .bind(&vuln.description)
    .bind(&vuln.fixed_version)
    .bind(&references_json)
    .execute(pool)
    .await?;

    Ok(())
}

/// Store license info
async fn store_license(pool: &SqlitePool, sbom_id: &str, license: &LicenseInfo) -> Result<()> {
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT INTO sbom_licenses (id, sbom_id, spdx_id, name, risk_level, url, component_count)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
    )
    .bind(&id)
    .bind(sbom_id)
    .bind(&license.spdx_id)
    .bind(&license.name)
    .bind(format!("{:?}", license.risk_level).to_lowercase())
    .bind(&license.url)
    .bind(license.component_count as i32)
    .execute(pool)
    .await?;

    Ok(())
}

/// Store dependency relation
async fn store_dependency(pool: &SqlitePool, sbom_id: &str, dep: &DependencyRelation) -> Result<()> {
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT INTO sbom_dependencies (id, sbom_id, parent_purl, child_purl, dependency_type)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
    )
    .bind(&id)
    .bind(sbom_id)
    .bind(&dep.parent)
    .bind(&dep.child)
    .bind(dep.dependency_type.to_string())
    .execute(pool)
    .await?;

    Ok(())
}

/// List SBOMs for a user
pub async fn list_sboms(
    pool: &SqlitePool,
    user_id: &str,
    query: &ListSbomsQuery,
) -> Result<Vec<SbomSummary>> {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let rows: Vec<(String, String, Option<String>, String, String, String)> = if let Some(ref project_name) = query.project_name {
        sqlx::query_as(
            r#"
            SELECT id, project_name, project_version, format, stats_json, generated_at
            FROM sbom_records
            WHERE user_id = ?1 AND project_name LIKE ?2
            ORDER BY generated_at DESC
            LIMIT ?3 OFFSET ?4
            "#,
        )
        .bind(user_id)
        .bind(format!("%{}%", project_name))
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT id, project_name, project_version, format, stats_json, generated_at
            FROM sbom_records
            WHERE user_id = ?1
            ORDER BY generated_at DESC
            LIMIT ?2 OFFSET ?3
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    };

    let summaries = rows
        .into_iter()
        .map(|(id, project_name, project_version, format, stats_json, generated_at)| {
            let stats: SbomStats = serde_json::from_str(&stats_json).unwrap_or_default();
            SbomSummary {
                id,
                project_name,
                project_version,
                format,
                total_components: stats.total_components as i32,
                total_vulnerabilities: stats.vulnerabilities_found as i32,
                critical_vulns: stats.critical_vulns as i32,
                high_vulns: stats.high_vulns as i32,
                copyleft_licenses: stats.copyleft_licenses as i32,
                generated_at,
            }
        })
        .collect();

    Ok(summaries)
}

/// Get a single SBOM by ID
pub async fn get_sbom(pool: &SqlitePool, sbom_id: &str, user_id: &str) -> Result<Option<Sbom>> {
    let row: Option<SbomRow> = sqlx::query_as(
        r#"
        SELECT id, user_id, project_name, project_version, format, stats_json, source_files_json, generated_at, created_at
        FROM sbom_records
        WHERE id = ?1 AND user_id = ?2
        "#,
    )
    .bind(sbom_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    let row = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    // Parse format
    let format: SbomFormat = row.format.parse().unwrap_or(SbomFormat::CycloneDX);

    // Parse stats and source files
    let stats: SbomStats = serde_json::from_str(&row.stats_json).unwrap_or_default();
    let source_files: Vec<SourceFile> = serde_json::from_str(&row.source_files_json).unwrap_or_default();

    // Get components
    let components = get_sbom_components(pool, sbom_id).await?;

    // Get vulnerabilities
    let vulnerabilities = get_sbom_vulnerabilities(pool, sbom_id, &ListVulnsQuery::default()).await?;

    // Get licenses
    let licenses = get_sbom_licenses(pool, sbom_id).await?;

    // Get dependencies
    let dependencies = get_sbom_dependencies(pool, sbom_id).await?;

    Ok(Some(Sbom {
        id: row.id,
        user_id: row.user_id,
        project_name: row.project_name,
        project_version: row.project_version,
        format,
        components,
        dependencies,
        vulnerabilities,
        licenses,
        generated_at: DateTime::parse_from_rfc3339(&row.generated_at)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        source_files,
        stats,
        created_at: DateTime::parse_from_rfc3339(&row.created_at)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    }))
}

/// Get components for an SBOM
pub async fn get_sbom_components(pool: &SqlitePool, sbom_id: &str) -> Result<Vec<SbomComponent>> {
    let rows: Vec<SbomComponentRow> = sqlx::query_as(
        r#"
        SELECT id, sbom_id, name, version, purl, component_type, supplier, licenses_json, hashes_json, description, dependency_type, cpe, external_refs_json
        FROM sbom_components
        WHERE sbom_id = ?1
        ORDER BY name, version
        "#,
    )
    .bind(sbom_id)
    .fetch_all(pool)
    .await?;

    let components = rows
        .into_iter()
        .map(|row| {
            let component_type = match row.component_type.as_str() {
                "library" => ComponentType::Library,
                "framework" => ComponentType::Framework,
                "application" => ComponentType::Application,
                "container" => ComponentType::Container,
                _ => ComponentType::Library,
            };

            let dependency_type = match row.dependency_type.as_str() {
                "direct" => DependencyType::Direct,
                "transitive" => DependencyType::Transitive,
                "development" => DependencyType::Development,
                "optional" => DependencyType::Optional,
                "build" => DependencyType::Build,
                _ => DependencyType::Direct,
            };

            let licenses: Vec<LicenseInfo> = serde_json::from_str(&row.licenses_json).unwrap_or_default();
            let hashes: std::collections::HashMap<String, String> = serde_json::from_str(&row.hashes_json).unwrap_or_default();
            let external_refs: Vec<ExternalReference> = serde_json::from_str(&row.external_refs_json).unwrap_or_default();

            SbomComponent {
                id: row.id.clone(),
                project_id: row.sbom_id.clone(),
                name: row.name,
                version: row.version,
                purl: row.purl,
                component_type,
                supplier: row.supplier,
                licenses,
                hashes,
                description: row.description,
                dependency_type,
                cpe: row.cpe,
                external_refs,
                vulnerabilities: Vec::new(),
                created_at: Utc::now(),
            }
        })
        .collect();

    Ok(components)
}

/// Get components for an SBOM with filtering
pub async fn get_sbom_components_filtered(
    pool: &SqlitePool,
    sbom_id: &str,
    query: &ListComponentsQuery,
) -> Result<Vec<SbomComponent>> {
    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from(
        r#"
        SELECT id, sbom_id, name, version, purl, component_type, supplier, licenses_json, hashes_json, description, dependency_type, cpe, external_refs_json
        FROM sbom_components
        WHERE sbom_id = ?1
        "#
    );

    if query.name.is_some() {
        sql.push_str(" AND name LIKE ?2");
    }

    sql.push_str(" ORDER BY name, version LIMIT ?3 OFFSET ?4");

    let mut query_builder = sqlx::query_as::<_, SbomComponentRow>(&sql);
    query_builder = query_builder.bind(sbom_id);

    if let Some(ref name) = query.name {
        query_builder = query_builder.bind(format!("%{}%", name));
    }

    query_builder = query_builder.bind(limit).bind(offset);

    let rows = query_builder.fetch_all(pool).await?;

    let components = rows
        .into_iter()
        .map(|row| {
            let component_type = match row.component_type.as_str() {
                "library" => ComponentType::Library,
                "framework" => ComponentType::Framework,
                "application" => ComponentType::Application,
                _ => ComponentType::Library,
            };

            let dependency_type = match row.dependency_type.as_str() {
                "direct" => DependencyType::Direct,
                "transitive" => DependencyType::Transitive,
                "development" => DependencyType::Development,
                _ => DependencyType::Direct,
            };

            let licenses: Vec<LicenseInfo> = serde_json::from_str(&row.licenses_json).unwrap_or_default();
            let hashes: std::collections::HashMap<String, String> = serde_json::from_str(&row.hashes_json).unwrap_or_default();
            let external_refs: Vec<ExternalReference> = serde_json::from_str(&row.external_refs_json).unwrap_or_default();

            SbomComponent {
                id: row.id.clone(),
                project_id: row.sbom_id.clone(),
                name: row.name,
                version: row.version,
                purl: row.purl,
                component_type,
                supplier: row.supplier,
                licenses,
                hashes,
                description: row.description,
                dependency_type,
                cpe: row.cpe,
                external_refs,
                vulnerabilities: Vec::new(),
                created_at: Utc::now(),
            }
        })
        .collect();

    Ok(components)
}

/// Get vulnerabilities for an SBOM
pub async fn get_sbom_vulnerabilities(
    pool: &SqlitePool,
    sbom_id: &str,
    query: &ListVulnsQuery,
) -> Result<Vec<ComponentVuln>> {
    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from(
        r#"
        SELECT id, sbom_id, component_purl, cve_id, cvss_score, severity, description, fixed_version, references_json
        FROM sbom_vulnerabilities
        WHERE sbom_id = ?1
        "#
    );

    if query.severity.is_some() {
        sql.push_str(" AND severity = ?2");
    }

    sql.push_str(" ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END");
    sql.push_str(" LIMIT ?3 OFFSET ?4");

    let mut query_builder = sqlx::query_as::<_, ComponentVulnRow>(&sql);
    query_builder = query_builder.bind(sbom_id);

    if let Some(ref sev) = query.severity {
        query_builder = query_builder.bind(sev.to_lowercase());
    }

    // Adjust bind indices based on whether severity was provided
    if query.severity.is_some() {
        query_builder = query_builder.bind(limit).bind(offset);
    } else {
        // Rebind with correct parameter indices
        let rows: Vec<ComponentVulnRow> = sqlx::query_as(
            r#"
            SELECT id, sbom_id, component_purl, cve_id, cvss_score, severity, description, fixed_version, references_json
            FROM sbom_vulnerabilities
            WHERE sbom_id = ?1
            ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
            LIMIT ?2 OFFSET ?3
            "#,
        )
        .bind(sbom_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        return Ok(rows
            .into_iter()
            .map(|row| {
                let severity = match row.severity.as_str() {
                    "critical" => VulnSeverity::Critical,
                    "high" => VulnSeverity::High,
                    "medium" => VulnSeverity::Medium,
                    "low" => VulnSeverity::Low,
                    _ => VulnSeverity::Unknown,
                };

                let references: Vec<String> = serde_json::from_str(&row.references_json).unwrap_or_default();

                ComponentVuln {
                    cve_id: row.cve_id,
                    component_purl: row.component_purl,
                    cvss_score: row.cvss_score,
                    severity,
                    description: row.description,
                    fixed_version: row.fixed_version,
                    references,
                }
            })
            .collect());
    }

    let rows = query_builder.fetch_all(pool).await?;

    let vulns = rows
        .into_iter()
        .map(|row| {
            let severity = match row.severity.as_str() {
                "critical" => VulnSeverity::Critical,
                "high" => VulnSeverity::High,
                "medium" => VulnSeverity::Medium,
                "low" => VulnSeverity::Low,
                _ => VulnSeverity::Unknown,
            };

            let references: Vec<String> = serde_json::from_str(&row.references_json).unwrap_or_default();

            ComponentVuln {
                cve_id: row.cve_id,
                component_purl: row.component_purl,
                cvss_score: row.cvss_score,
                severity,
                description: row.description,
                fixed_version: row.fixed_version,
                references,
            }
        })
        .collect();

    Ok(vulns)
}

/// Get licenses for an SBOM
pub async fn get_sbom_licenses(pool: &SqlitePool, sbom_id: &str) -> Result<Vec<LicenseInfo>> {
    let rows: Vec<LicenseInfoRow> = sqlx::query_as(
        r#"
        SELECT id, sbom_id, spdx_id, name, risk_level, url, component_count
        FROM sbom_licenses
        WHERE sbom_id = ?1
        ORDER BY component_count DESC
        "#,
    )
    .bind(sbom_id)
    .fetch_all(pool)
    .await?;

    let licenses = rows
        .into_iter()
        .map(|row| {
            let risk_level = match row.risk_level.as_str() {
                "copyleft" => LicenseRisk::Copyleft,
                "weakcopyleft" => LicenseRisk::WeakCopyleft,
                "permissive" => LicenseRisk::Permissive,
                "proprietary" => LicenseRisk::Proprietary,
                "publicdomain" => LicenseRisk::PublicDomain,
                _ => LicenseRisk::Unknown,
            };

            LicenseInfo {
                spdx_id: row.spdx_id,
                name: row.name,
                risk_level,
                url: row.url,
                component_count: row.component_count as u32,
            }
        })
        .collect();

    Ok(licenses)
}

/// Get dependency relations for an SBOM
async fn get_sbom_dependencies(pool: &SqlitePool, sbom_id: &str) -> Result<Vec<DependencyRelation>> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        r#"
        SELECT parent_purl, child_purl, dependency_type
        FROM sbom_dependencies
        WHERE sbom_id = ?1
        "#,
    )
    .bind(sbom_id)
    .fetch_all(pool)
    .await?;

    let deps = rows
        .into_iter()
        .map(|(parent, child, dep_type)| {
            let dependency_type = match dep_type.as_str() {
                "direct" => DependencyType::Direct,
                "transitive" => DependencyType::Transitive,
                "development" => DependencyType::Development,
                _ => DependencyType::Direct,
            };

            DependencyRelation {
                parent,
                child,
                dependency_type,
            }
        })
        .collect();

    Ok(deps)
}

/// Delete an SBOM and all related data
pub async fn delete_sbom(pool: &SqlitePool, sbom_id: &str, user_id: &str) -> Result<bool> {
    // Verify ownership first
    let count: (i32,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sbom_records WHERE id = ?1 AND user_id = ?2"
    )
    .bind(sbom_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    if count.0 == 0 {
        return Ok(false);
    }

    // Delete related data (cascading)
    sqlx::query("DELETE FROM sbom_dependencies WHERE sbom_id = ?1")
        .bind(sbom_id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM sbom_licenses WHERE sbom_id = ?1")
        .bind(sbom_id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM sbom_vulnerabilities WHERE sbom_id = ?1")
        .bind(sbom_id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM sbom_components WHERE sbom_id = ?1")
        .bind(sbom_id)
        .execute(pool)
        .await?;

    // Delete the SBOM record
    let result = sqlx::query("DELETE FROM sbom_records WHERE id = ?1 AND user_id = ?2")
        .bind(sbom_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Add vulnerabilities to an existing SBOM (for vulnerability correlation)
pub async fn add_sbom_vulnerabilities(
    pool: &SqlitePool,
    sbom_id: &str,
    user_id: &str,
    vulns: &[ComponentVuln],
) -> Result<()> {
    // Verify ownership
    let count: (i32,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sbom_records WHERE id = ?1 AND user_id = ?2"
    )
    .bind(sbom_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    if count.0 == 0 {
        return Err(anyhow::anyhow!("SBOM not found or access denied"));
    }

    for vuln in vulns {
        store_vulnerability(pool, sbom_id, vuln).await?;
    }

    // Update stats
    let vuln_stats: (i32, i32, i32, i32, i32) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*),
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END)
        FROM sbom_vulnerabilities
        WHERE sbom_id = ?1
        "#,
    )
    .bind(sbom_id)
    .fetch_one(pool)
    .await?;

    // Update the stats JSON
    let row: (String,) = sqlx::query_as(
        "SELECT stats_json FROM sbom_records WHERE id = ?1"
    )
    .bind(sbom_id)
    .fetch_one(pool)
    .await?;

    let mut stats: SbomStats = serde_json::from_str(&row.0).unwrap_or_default();
    stats.vulnerabilities_found = vuln_stats.0 as i32;
    stats.critical_vulns = vuln_stats.1 as i32;
    stats.high_vulns = vuln_stats.2 as i32;
    stats.medium_vulns = vuln_stats.3 as i32;
    stats.low_vulns = vuln_stats.4 as i32;

    let stats_json = serde_json::to_string(&stats)?;

    sqlx::query("UPDATE sbom_records SET stats_json = ?1 WHERE id = ?2")
        .bind(&stats_json)
        .bind(sbom_id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Implement Default for ListVulnsQuery
// ============================================================================

impl Default for ListVulnsQuery {
    fn default() -> Self {
        Self {
            severity: None,
            has_fix: None,
            limit: Some(100),
            offset: Some(0),
        }
    }
}

impl Default for ListComponentsQuery {
    fn default() -> Self {
        Self {
            name: None,
            license: None,
            has_vulns: None,
            limit: Some(100),
            offset: Some(0),
        }
    }
}

// ============================================================================
// Rescan Support Functions
// ============================================================================

/// Get full SBOM data without user verification (for internal use)
/// Used by rescan functionality after ownership has been verified
pub async fn get_full_sbom(pool: &SqlitePool, sbom_id: &str) -> Result<Option<Sbom>> {
    let row: Option<SbomRow> = sqlx::query_as(
        r#"
        SELECT id, user_id, project_name, project_version, format, stats_json, source_files_json, generated_at, created_at
        FROM sbom_records
        WHERE id = ?1
        "#,
    )
    .bind(sbom_id)
    .fetch_optional(pool)
    .await?;

    let row = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    // Parse format
    let format: SbomFormat = row.format.parse().unwrap_or(SbomFormat::CycloneDX);

    // Parse stats and source files
    let stats: SbomStats = serde_json::from_str(&row.stats_json).unwrap_or_default();
    let source_files: Vec<SourceFile> = serde_json::from_str(&row.source_files_json).unwrap_or_default();

    // Get components
    let components = get_sbom_components(pool, sbom_id).await?;

    // Get vulnerabilities
    let vulnerabilities = get_sbom_vulnerabilities(pool, sbom_id, &ListVulnsQuery::default()).await?;

    // Get licenses
    let licenses = get_sbom_licenses(pool, sbom_id).await?;

    // Get dependencies
    let dependencies = get_sbom_dependencies(pool, sbom_id).await?;

    Ok(Some(Sbom {
        id: row.id,
        user_id: row.user_id,
        project_name: row.project_name,
        project_version: row.project_version,
        format,
        components,
        dependencies,
        vulnerabilities,
        licenses,
        generated_at: DateTime::parse_from_rfc3339(&row.generated_at)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        source_files,
        stats,
        created_at: DateTime::parse_from_rfc3339(&row.created_at)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    }))
}

/// Delete all vulnerabilities for an SBOM (used before rescan)
pub async fn delete_sbom_vulnerabilities(pool: &SqlitePool, sbom_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM sbom_vulnerabilities WHERE sbom_id = ?1")
        .bind(sbom_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Add a single vulnerability (used during rescan)
pub async fn add_sbom_vulnerability(pool: &SqlitePool, sbom_id: &str, vuln: &ComponentVuln) -> Result<()> {
    store_vulnerability(pool, sbom_id, vuln).await
}

/// Update SBOM vulnerability statistics after rescan
pub async fn update_sbom_vuln_stats(
    pool: &SqlitePool,
    sbom_id: &str,
    _vulnerable_components: i64, // Count of components with vulnerabilities
    critical: i64,
    high: i64,
    medium: i64,
    low: i64,
) -> Result<()> {
    // Get current stats
    let row: (String,) = sqlx::query_as(
        "SELECT stats_json FROM sbom_records WHERE id = ?1"
    )
    .bind(sbom_id)
    .fetch_one(pool)
    .await?;

    let mut stats: SbomStats = serde_json::from_str(&row.0).unwrap_or_default();
    stats.vulnerabilities_found = (critical + high + medium + low) as i32;
    stats.critical_vulns = critical as i32;
    stats.high_vulns = high as i32;
    stats.medium_vulns = medium as i32;
    stats.low_vulns = low as i32;

    let stats_json = serde_json::to_string(&stats)?;

    sqlx::query("UPDATE sbom_records SET stats_json = ?1 WHERE id = ?2")
        .bind(&stats_json)
        .bind(sbom_id)
        .execute(pool)
        .await?;

    Ok(())
}
