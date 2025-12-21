//! Database operations for IaC security scanning
//!
//! This module provides CRUD operations for IaC scans, files, findings, and rules.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;

use crate::scanner::iac::{
    IacCloudProvider, IacFile, IacFinding, IacFindingCategory, IacFindingStatus, IacPlatform,
    IacRule, IacScan, IacScanStatus, IacScanSummary, IacSeverity, RulePatternType,
};

/// Create a new IaC scan record
pub async fn create_scan(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    name: &str,
    source_type: &str,
    source_url: Option<&str>,
    customer_id: Option<&str>,
    engagement_id: Option<&str>,
) -> Result<IacScan> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO iac_scans (id, user_id, name, source_type, source_url, status,
                               customer_id, engagement_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(source_type)
    .bind(source_url)
    .bind("pending")
    .bind(customer_id)
    .bind(engagement_id)
    .bind(&now)
    .execute(pool)
    .await?;

    get_scan(pool, id).await?.ok_or_else(|| anyhow::anyhow!("Failed to create scan"))
}

/// Get a scan by ID
pub async fn get_scan(pool: &SqlitePool, id: &str) -> Result<Option<IacScan>> {
    let row: Option<IacScanRow> = sqlx::query_as(
        r#"
        SELECT id, user_id, name, source_type, source_url, platforms, providers, status,
               file_count, resource_count, finding_count, critical_count, high_count,
               medium_count, low_count, info_count, error_message, created_at, started_at,
               completed_at, customer_id, engagement_id
        FROM iac_scans
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.into()))
}

/// List scans for a user
pub async fn list_scans(
    pool: &SqlitePool,
    user_id: &str,
    limit: i32,
    offset: i32,
) -> Result<Vec<IacScan>> {
    let rows: Vec<IacScanRow> = sqlx::query_as(
        r#"
        SELECT id, user_id, name, source_type, source_url, platforms, providers, status,
               file_count, resource_count, finding_count, critical_count, high_count,
               medium_count, low_count, info_count, error_message, created_at, started_at,
               completed_at, customer_id, engagement_id
        FROM iac_scans
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Update scan status
pub async fn update_scan_status(
    pool: &SqlitePool,
    id: &str,
    status: IacScanStatus,
    error_message: Option<&str>,
) -> Result<()> {
    let now = match status {
        IacScanStatus::Running => Some(Utc::now().to_rfc3339()),
        _ => None,
    };

    let completed = match status {
        IacScanStatus::Completed | IacScanStatus::Failed => Some(Utc::now().to_rfc3339()),
        _ => None,
    };

    sqlx::query(
        r#"
        UPDATE iac_scans
        SET status = ?,
            error_message = COALESCE(?, error_message),
            started_at = COALESCE(?, started_at),
            completed_at = COALESCE(?, completed_at)
        WHERE id = ?
        "#,
    )
    .bind(status.to_string())
    .bind(error_message)
    .bind(&now)
    .bind(&completed)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update scan results
pub async fn update_scan_results(
    pool: &SqlitePool,
    id: &str,
    platforms: &[IacPlatform],
    providers: &[IacCloudProvider],
    file_count: i32,
    resource_count: i32,
    finding_count: i32,
    critical_count: i32,
    high_count: i32,
    medium_count: i32,
    low_count: i32,
    info_count: i32,
) -> Result<()> {
    let platforms_json = serde_json::to_string(platforms)?;
    let providers_json = serde_json::to_string(providers)?;

    sqlx::query(
        r#"
        UPDATE iac_scans
        SET platforms = ?,
            providers = ?,
            file_count = ?,
            resource_count = ?,
            finding_count = ?,
            critical_count = ?,
            high_count = ?,
            medium_count = ?,
            low_count = ?,
            info_count = ?
        WHERE id = ?
        "#,
    )
    .bind(platforms_json)
    .bind(providers_json)
    .bind(file_count)
    .bind(resource_count)
    .bind(finding_count)
    .bind(critical_count)
    .bind(high_count)
    .bind(medium_count)
    .bind(low_count)
    .bind(info_count)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a scan and all related data
pub async fn delete_scan(pool: &SqlitePool, id: &str) -> Result<()> {
    // Delete findings first (foreign key)
    sqlx::query("DELETE FROM iac_findings WHERE scan_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    // Delete files
    sqlx::query("DELETE FROM iac_files WHERE scan_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    // Delete scan
    sqlx::query("DELETE FROM iac_scans WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Create an IaC file record
pub async fn create_file(pool: &SqlitePool, file: &IacFile) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO iac_files (id, scan_id, filename, path, content, platform, provider,
                               size_bytes, line_count, resource_count, finding_count, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&file.id)
    .bind(&file.scan_id)
    .bind(&file.filename)
    .bind(&file.path)
    .bind(&file.content)
    .bind(file.platform.to_string())
    .bind(file.provider.to_string())
    .bind(file.size_bytes)
    .bind(file.line_count)
    .bind(file.resource_count)
    .bind(file.finding_count)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get files for a scan
pub async fn get_files_for_scan(pool: &SqlitePool, scan_id: &str) -> Result<Vec<IacFile>> {
    let rows: Vec<IacFileRow> = sqlx::query_as(
        r#"
        SELECT id, scan_id, filename, path, content, platform, provider, size_bytes,
               line_count, resource_count, finding_count, created_at
        FROM iac_files
        WHERE scan_id = ?
        ORDER BY filename
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Create an IaC finding
pub async fn create_finding(pool: &SqlitePool, finding: &IacFinding) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let compliance_json = serde_json::to_string(&finding.compliance_mappings)?;
    let resource_type = finding.resource_type.as_ref().map(|rt| rt.to_string());

    sqlx::query(
        r#"
        INSERT INTO iac_findings (id, scan_id, file_id, rule_id, severity, category, title,
                                  description, resource_type, resource_name, line_start, line_end,
                                  code_snippet, remediation, documentation_url, compliance_mappings,
                                  status, suppressed, suppression_reason, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&finding.id)
    .bind(&finding.scan_id)
    .bind(&finding.file_id)
    .bind(&finding.rule_id)
    .bind(finding.severity.to_string())
    .bind(finding.category.to_string())
    .bind(&finding.title)
    .bind(&finding.description)
    .bind(&resource_type)
    .bind(&finding.resource_name)
    .bind(finding.line_start)
    .bind(finding.line_end)
    .bind(&finding.code_snippet)
    .bind(&finding.remediation)
    .bind(&finding.documentation_url)
    .bind(&compliance_json)
    .bind(finding.status.to_string())
    .bind(finding.suppressed)
    .bind(&finding.suppression_reason)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get findings for a scan
pub async fn get_findings_for_scan(pool: &SqlitePool, scan_id: &str) -> Result<Vec<IacFinding>> {
    let rows: Vec<IacFindingRow> = sqlx::query_as(
        r#"
        SELECT id, scan_id, file_id, rule_id, severity, category, title, description,
               resource_type, resource_name, line_start, line_end, code_snippet, remediation,
               documentation_url, compliance_mappings, status, suppressed, suppression_reason, created_at
        FROM iac_findings
        WHERE scan_id = ?
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            line_start
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Get findings for a file
pub async fn get_findings_for_file(pool: &SqlitePool, file_id: &str) -> Result<Vec<IacFinding>> {
    let rows: Vec<IacFindingRow> = sqlx::query_as(
        r#"
        SELECT id, scan_id, file_id, rule_id, severity, category, title, description,
               resource_type, resource_name, line_start, line_end, code_snippet, remediation,
               documentation_url, compliance_mappings, status, suppressed, suppression_reason, created_at
        FROM iac_findings
        WHERE file_id = ?
        ORDER BY line_start
        "#,
    )
    .bind(file_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Update finding status
pub async fn update_finding_status(
    pool: &SqlitePool,
    id: &str,
    status: IacFindingStatus,
    suppression_reason: Option<&str>,
) -> Result<()> {
    let suppressed = status == IacFindingStatus::Suppressed;

    sqlx::query(
        r#"
        UPDATE iac_findings
        SET status = ?, suppressed = ?, suppression_reason = ?
        WHERE id = ?
        "#,
    )
    .bind(status.to_string())
    .bind(suppressed)
    .bind(suppression_reason)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Create a custom rule
pub async fn create_rule(pool: &SqlitePool, rule: &IacRule) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let platforms_json = serde_json::to_string(&rule.platforms)?;
    let providers_json = serde_json::to_string(&rule.providers)?;
    let resource_types_json = serde_json::to_string(&rule.resource_types)?;
    let compliance_json = serde_json::to_string(&rule.compliance_mappings)?;

    sqlx::query(
        r#"
        INSERT INTO iac_rules (id, name, description, severity, category, platforms, providers,
                               resource_types, pattern, pattern_type, remediation, documentation_url,
                               compliance_mappings, is_builtin, is_enabled, user_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&rule.id)
    .bind(&rule.name)
    .bind(&rule.description)
    .bind(rule.severity.to_string())
    .bind(rule.category.to_string())
    .bind(&platforms_json)
    .bind(&providers_json)
    .bind(&resource_types_json)
    .bind(&rule.pattern)
    .bind(rule.pattern_type.to_string())
    .bind(&rule.remediation)
    .bind(&rule.documentation_url)
    .bind(&compliance_json)
    .bind(rule.is_builtin)
    .bind(rule.is_enabled)
    .bind(&rule.user_id)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get a rule by ID
pub async fn get_rule(pool: &SqlitePool, id: &str) -> Result<Option<IacRule>> {
    let row: Option<IacRuleRow> = sqlx::query_as(
        r#"
        SELECT id, name, description, severity, category, platforms, providers, resource_types,
               pattern, pattern_type, remediation, documentation_url, compliance_mappings,
               is_builtin, is_enabled, user_id, created_at, updated_at
        FROM iac_rules
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.into()))
}

/// List all rules (builtin + user's custom rules)
pub async fn list_rules(pool: &SqlitePool, user_id: Option<&str>) -> Result<Vec<IacRule>> {
    let rows: Vec<IacRuleRow> = sqlx::query_as(
        r#"
        SELECT id, name, description, severity, category, platforms, providers, resource_types,
               pattern, pattern_type, remediation, documentation_url, compliance_mappings,
               is_builtin, is_enabled, user_id, created_at, updated_at
        FROM iac_rules
        WHERE is_builtin = 1 OR user_id = ?
        ORDER BY is_builtin DESC, name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Update a custom rule
pub async fn update_rule(
    pool: &SqlitePool,
    id: &str,
    name: Option<&str>,
    description: Option<&str>,
    severity: Option<IacSeverity>,
    category: Option<&str>,
    pattern: Option<&str>,
    remediation: Option<&str>,
    is_enabled: Option<bool>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    // Build dynamic update query
    let mut updates = Vec::new();
    let mut bindings: Vec<Box<dyn std::any::Any>> = Vec::new();

    if let Some(n) = name {
        updates.push("name = ?");
        bindings.push(Box::new(n.to_string()));
    }
    if let Some(d) = description {
        updates.push("description = ?");
        bindings.push(Box::new(d.to_string()));
    }
    if let Some(s) = severity {
        updates.push("severity = ?");
        bindings.push(Box::new(s.to_string()));
    }
    if let Some(c) = category {
        updates.push("category = ?");
        bindings.push(Box::new(c.to_string()));
    }
    if let Some(p) = pattern {
        updates.push("pattern = ?");
        bindings.push(Box::new(p.to_string()));
    }
    if let Some(r) = remediation {
        updates.push("remediation = ?");
        bindings.push(Box::new(r.to_string()));
    }
    if let Some(e) = is_enabled {
        updates.push("is_enabled = ?");
        bindings.push(Box::new(e));
    }

    if updates.is_empty() {
        return Ok(());
    }

    updates.push("updated_at = ?");

    // For simplicity, rebuild with specific fields
    sqlx::query(&format!(
        "UPDATE iac_rules SET {} WHERE id = ? AND is_builtin = 0",
        updates.join(", ")
    ))
    .bind(name.unwrap_or(""))
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a custom rule
pub async fn delete_rule(pool: &SqlitePool, id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM iac_rules WHERE id = ? AND user_id = ? AND is_builtin = 0",
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Seed builtin rules if they don't exist
pub async fn seed_builtin_rules(pool: &SqlitePool) -> Result<()> {
    // Check if builtin rules already exist
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM iac_rules WHERE is_builtin = 1")
        .fetch_one(pool)
        .await?;

    if count.0 > 0 {
        return Ok(());
    }

    // Insert builtin rules
    let rules = crate::scanner::iac::get_builtin_iac_rules();
    for rule in rules {
        if let Err(e) = create_rule(pool, &rule).await {
            log::warn!("Failed to seed builtin rule {}: {}", rule.id, e);
        }
    }

    Ok(())
}

// Row types for sqlx

#[derive(sqlx::FromRow)]
struct IacScanRow {
    id: String,
    user_id: String,
    name: String,
    source_type: String,
    source_url: Option<String>,
    platforms: Option<String>,
    providers: Option<String>,
    status: String,
    file_count: i32,
    resource_count: i32,
    finding_count: i32,
    critical_count: i32,
    high_count: i32,
    medium_count: i32,
    low_count: i32,
    info_count: i32,
    error_message: Option<String>,
    created_at: String,
    started_at: Option<String>,
    completed_at: Option<String>,
    customer_id: Option<String>,
    engagement_id: Option<String>,
}

impl From<IacScanRow> for IacScan {
    fn from(row: IacScanRow) -> Self {
        let platforms: Vec<IacPlatform> = row
            .platforms
            .and_then(|p| serde_json::from_str(&p).ok())
            .unwrap_or_default();

        let providers: Vec<IacCloudProvider> = row
            .providers
            .and_then(|p| serde_json::from_str(&p).ok())
            .unwrap_or_default();

        let status = row.status.parse().unwrap_or(IacScanStatus::Pending);

        IacScan {
            id: row.id,
            user_id: row.user_id,
            name: row.name,
            source_type: row.source_type,
            source_url: row.source_url,
            platforms,
            providers,
            status,
            file_count: row.file_count,
            resource_count: row.resource_count,
            finding_count: row.finding_count,
            critical_count: row.critical_count,
            high_count: row.high_count,
            medium_count: row.medium_count,
            low_count: row.low_count,
            info_count: row.info_count,
            error_message: row.error_message,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            started_at: row.started_at.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .ok()
            }),
            completed_at: row.completed_at.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .ok()
            }),
            customer_id: row.customer_id,
            engagement_id: row.engagement_id,
        }
    }
}

#[derive(sqlx::FromRow)]
struct IacFileRow {
    id: String,
    scan_id: String,
    filename: String,
    path: String,
    content: Option<String>,
    platform: String,
    provider: String,
    size_bytes: i64,
    line_count: i32,
    resource_count: i32,
    finding_count: i32,
    created_at: String,
}

impl From<IacFileRow> for IacFile {
    fn from(row: IacFileRow) -> Self {
        IacFile {
            id: row.id,
            scan_id: row.scan_id,
            filename: row.filename,
            path: row.path,
            content: row.content,
            platform: row.platform.parse().unwrap_or(IacPlatform::Terraform),
            provider: row.provider.parse().unwrap_or(IacCloudProvider::None),
            size_bytes: row.size_bytes,
            line_count: row.line_count,
            resource_count: row.resource_count,
            finding_count: row.finding_count,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(sqlx::FromRow)]
struct IacFindingRow {
    id: String,
    scan_id: String,
    file_id: String,
    rule_id: String,
    severity: String,
    category: String,
    title: String,
    description: String,
    resource_type: Option<String>,
    resource_name: Option<String>,
    line_start: i32,
    line_end: i32,
    code_snippet: Option<String>,
    remediation: String,
    documentation_url: Option<String>,
    compliance_mappings: String,
    status: String,
    suppressed: bool,
    suppression_reason: Option<String>,
    created_at: String,
}

impl From<IacFindingRow> for IacFinding {
    fn from(row: IacFindingRow) -> Self {
        use crate::scanner::iac::IacComplianceMapping;

        let resource_type = row.resource_type.and_then(|rt| {
            // Try to parse known resource types, fallback to Other
            Some(crate::scanner::iac::IacResourceType::Other(rt))
        });

        let compliance_mappings: Vec<IacComplianceMapping> =
            serde_json::from_str(&row.compliance_mappings).unwrap_or_default();

        let category = match row.category.as_str() {
            "hardcoded_secret" => IacFindingCategory::HardcodedSecret,
            "iam_misconfiguration" => IacFindingCategory::IamMisconfiguration,
            "public_storage" => IacFindingCategory::PublicStorage,
            "missing_encryption" => IacFindingCategory::MissingEncryption,
            "missing_logging" => IacFindingCategory::MissingLogging,
            "network_exposure" => IacFindingCategory::NetworkExposure,
            "missing_tags" => IacFindingCategory::MissingTags,
            "deprecated_resource" => IacFindingCategory::DeprecatedResource,
            "weak_cryptography" => IacFindingCategory::WeakCryptography,
            "insecure_default" => IacFindingCategory::InsecureDefault,
            "compliance_violation" => IacFindingCategory::ComplianceViolation,
            _ => IacFindingCategory::BestPractice,
        };

        let status = match row.status.as_str() {
            "resolved" => IacFindingStatus::Resolved,
            "false_positive" => IacFindingStatus::FalsePositive,
            "accepted" => IacFindingStatus::Accepted,
            "suppressed" => IacFindingStatus::Suppressed,
            _ => IacFindingStatus::Open,
        };

        IacFinding {
            id: row.id,
            scan_id: row.scan_id,
            file_id: row.file_id,
            rule_id: row.rule_id,
            severity: row.severity.parse().unwrap_or(IacSeverity::Medium),
            category,
            title: row.title,
            description: row.description,
            resource_type,
            resource_name: row.resource_name,
            line_start: row.line_start,
            line_end: row.line_end,
            code_snippet: row.code_snippet,
            remediation: row.remediation,
            documentation_url: row.documentation_url,
            compliance_mappings,
            status,
            suppressed: row.suppressed,
            suppression_reason: row.suppression_reason,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(sqlx::FromRow)]
struct IacRuleRow {
    id: String,
    name: String,
    description: String,
    severity: String,
    category: String,
    platforms: String,
    providers: String,
    resource_types: String,
    pattern: String,
    pattern_type: String,
    remediation: String,
    documentation_url: Option<String>,
    compliance_mappings: String,
    is_builtin: bool,
    is_enabled: bool,
    user_id: Option<String>,
    created_at: String,
    updated_at: String,
}

impl From<IacRuleRow> for IacRule {
    fn from(row: IacRuleRow) -> Self {
        use crate::scanner::iac::IacComplianceMapping;

        let platforms: Vec<IacPlatform> = serde_json::from_str(&row.platforms).unwrap_or_default();
        let providers: Vec<IacCloudProvider> = serde_json::from_str(&row.providers).unwrap_or_default();
        let resource_types: Vec<String> = serde_json::from_str(&row.resource_types).unwrap_or_default();
        let compliance_mappings: Vec<IacComplianceMapping> =
            serde_json::from_str(&row.compliance_mappings).unwrap_or_default();

        let category = match row.category.as_str() {
            "hardcoded_secret" => IacFindingCategory::HardcodedSecret,
            "iam_misconfiguration" => IacFindingCategory::IamMisconfiguration,
            "public_storage" => IacFindingCategory::PublicStorage,
            "missing_encryption" => IacFindingCategory::MissingEncryption,
            "missing_logging" => IacFindingCategory::MissingLogging,
            "network_exposure" => IacFindingCategory::NetworkExposure,
            "missing_tags" => IacFindingCategory::MissingTags,
            "deprecated_resource" => IacFindingCategory::DeprecatedResource,
            "weak_cryptography" => IacFindingCategory::WeakCryptography,
            "insecure_default" => IacFindingCategory::InsecureDefault,
            "compliance_violation" => IacFindingCategory::ComplianceViolation,
            _ => IacFindingCategory::BestPractice,
        };

        let pattern_type = match row.pattern_type.as_str() {
            "regex" => RulePatternType::Regex,
            "jsonpath" => RulePatternType::JsonPath,
            _ => RulePatternType::Custom,
        };

        IacRule {
            id: row.id,
            name: row.name,
            description: row.description,
            severity: row.severity.parse().unwrap_or(IacSeverity::Medium),
            category,
            platforms,
            providers,
            resource_types,
            pattern: row.pattern,
            pattern_type,
            remediation: row.remediation,
            documentation_url: row.documentation_url,
            compliance_mappings,
            is_builtin: row.is_builtin,
            is_enabled: row.is_enabled,
            user_id: row.user_id,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

impl std::str::FromStr for IacCloudProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aws" => Ok(IacCloudProvider::Aws),
            "azure" => Ok(IacCloudProvider::Azure),
            "gcp" => Ok(IacCloudProvider::Gcp),
            "multi" => Ok(IacCloudProvider::Multi),
            "none" => Ok(IacCloudProvider::None),
            _ => Ok(IacCloudProvider::None),
        }
    }
}
