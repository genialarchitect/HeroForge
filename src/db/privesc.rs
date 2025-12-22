use anyhow::Result;
use sqlx::SqlitePool;

use crate::scanner::privesc::{
    OsType, PrivescConfig, PrivescFinding, PrivescResult, PrivescSeverity, PrivescStatistics,
    PrivescStatus, SystemInfo,
};

/// Database row for privesc scans
#[derive(Debug, sqlx::FromRow)]
pub struct PrivescScanRow {
    pub id: String,
    pub user_id: String,
    pub target: String,
    pub os_type: String,
    pub status: String,
    pub config: String,
    pub statistics: String,
    pub system_info: String,
    pub peas_output: Option<String>,
    pub errors: String,
    pub created_at: String,
    pub completed_at: Option<String>,
}

/// Database row for privesc findings
#[derive(Debug, sqlx::FromRow)]
pub struct PrivescFindingRow {
    pub id: String,
    pub scan_id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub os_type: String,
    pub vector_data: String,
    pub exploitation_steps: String,
    pub references: String,
    pub mitre_techniques: String,
    pub raw_output: Option<String>,
    pub created_at: String,
}

/// Create a new privesc scan record
pub async fn create_privesc_scan(
    pool: &SqlitePool,
    user_id: &str,
    config: &PrivescConfig,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let config_json = serde_json::to_string(config)?;
    let os_type = match config.os_type {
        OsType::Linux => "linux",
        OsType::Windows => "windows",
    };

    sqlx::query(
        r#"
        INSERT INTO privesc_scans (id, user_id, target, os_type, status, config, statistics, system_info, errors, created_at)
        VALUES (?, ?, ?, ?, 'pending', ?, '{}', '{}', '[]', ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&config.target)
    .bind(os_type)
    .bind(&config_json)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Update scan status
pub async fn update_scan_status(
    pool: &SqlitePool,
    scan_id: &str,
    status: PrivescStatus,
) -> Result<()> {
    let status_str = match status {
        PrivescStatus::Pending => "pending",
        PrivescStatus::Running => "running",
        PrivescStatus::Completed => "completed",
        PrivescStatus::Failed => "failed",
        PrivescStatus::Cancelled => "cancelled",
    };

    let completed_at = if status == PrivescStatus::Completed || status == PrivescStatus::Failed {
        Some(chrono::Utc::now().to_rfc3339())
    } else {
        None
    };

    sqlx::query(
        r#"
        UPDATE privesc_scans SET status = ?, completed_at = ? WHERE id = ?
        "#,
    )
    .bind(status_str)
    .bind(&completed_at)
    .bind(scan_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Save scan results
pub async fn save_scan_results(pool: &SqlitePool, result: &PrivescResult) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    let statistics_json = serde_json::to_string(&result.statistics)?;
    let system_info_json = serde_json::to_string(&result.system_info)?;
    let errors_json = serde_json::to_string(&result.errors)?;
    let status_str = match result.status {
        PrivescStatus::Pending => "pending",
        PrivescStatus::Running => "running",
        PrivescStatus::Completed => "completed",
        PrivescStatus::Failed => "failed",
        PrivescStatus::Cancelled => "cancelled",
    };

    // Update scan record
    sqlx::query(
        r#"
        UPDATE privesc_scans
        SET status = ?, statistics = ?, system_info = ?, peas_output = ?, errors = ?, completed_at = ?
        WHERE id = ?
        "#,
    )
    .bind(status_str)
    .bind(&statistics_json)
    .bind(&system_info_json)
    .bind(&result.peas_output)
    .bind(&errors_json)
    .bind(&now)
    .bind(&result.id)
    .execute(pool)
    .await?;

    // Insert findings
    for finding in &result.findings {
        save_finding(pool, &result.id, finding).await?;
    }

    Ok(())
}

/// Save a single finding
pub async fn save_finding(pool: &SqlitePool, scan_id: &str, finding: &PrivescFinding) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    let severity_str = match finding.severity {
        PrivescSeverity::Critical => "critical",
        PrivescSeverity::High => "high",
        PrivescSeverity::Medium => "medium",
        PrivescSeverity::Low => "low",
        PrivescSeverity::Info => "info",
    };
    let os_type_str = match finding.os_type {
        OsType::Linux => "linux",
        OsType::Windows => "windows",
    };

    // Serialize vector data
    let vector_data = if let Some(ref vector) = finding.linux_vector {
        serde_json::to_string(vector)?
    } else if let Some(ref vector) = finding.windows_vector {
        serde_json::to_string(vector)?
    } else {
        "null".to_string()
    };

    let steps_json = serde_json::to_string(&finding.exploitation_steps)?;
    let refs_json = serde_json::to_string(&finding.references)?;
    let mitre_json = serde_json::to_string(&finding.mitre_techniques)?;

    sqlx::query(
        r#"
        INSERT INTO privesc_findings
        (id, scan_id, severity, title, description, os_type, vector_data, exploitation_steps,
         "references", mitre_techniques, raw_output, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&finding.id)
    .bind(scan_id)
    .bind(severity_str)
    .bind(&finding.title)
    .bind(&finding.description)
    .bind(os_type_str)
    .bind(&vector_data)
    .bind(&steps_json)
    .bind(&refs_json)
    .bind(&mitre_json)
    .bind(&finding.raw_output)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get scan by ID
pub async fn get_scan_by_id(pool: &SqlitePool, scan_id: &str) -> Result<Option<PrivescScanRow>> {
    let row = sqlx::query_as::<_, PrivescScanRow>(
        "SELECT * FROM privesc_scans WHERE id = ?",
    )
    .bind(scan_id)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

/// Get scans for user
pub async fn get_user_scans(
    pool: &SqlitePool,
    user_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<PrivescScanRow>> {
    let rows = sqlx::query_as::<_, PrivescScanRow>(
        "SELECT * FROM privesc_scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Get findings for scan
pub async fn get_scan_findings(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Vec<PrivescFindingRow>> {
    let rows = sqlx::query_as::<_, PrivescFindingRow>(
        "SELECT * FROM privesc_findings WHERE scan_id = ? ORDER BY
         CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Delete scan and findings
pub async fn delete_scan(pool: &SqlitePool, scan_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM privesc_findings WHERE scan_id = ?")
        .bind(scan_id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM privesc_scans WHERE id = ?")
        .bind(scan_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Convert row to PrivescResult
pub fn row_to_result(
    scan: PrivescScanRow,
    findings: Vec<PrivescFindingRow>,
) -> Result<PrivescResult> {
    let config: PrivescConfig = serde_json::from_str(&scan.config)?;
    let statistics: PrivescStatistics = serde_json::from_str(&scan.statistics)?;
    let system_info: SystemInfo = serde_json::from_str(&scan.system_info)?;
    let errors: Vec<String> = serde_json::from_str(&scan.errors)?;

    let os_type = match scan.os_type.as_str() {
        "windows" => OsType::Windows,
        _ => OsType::Linux,
    };

    let status = match scan.status.as_str() {
        "running" => PrivescStatus::Running,
        "completed" => PrivescStatus::Completed,
        "failed" => PrivescStatus::Failed,
        "cancelled" => PrivescStatus::Cancelled,
        _ => PrivescStatus::Pending,
    };

    let converted_findings: Vec<PrivescFinding> = findings
        .into_iter()
        .filter_map(|f| row_to_finding(f).ok())
        .collect();

    Ok(PrivescResult {
        id: scan.id,
        target: scan.target,
        os_type,
        status,
        config,
        findings: converted_findings,
        statistics,
        system_info,
        peas_output: scan.peas_output,
        errors,
        started_at: chrono::DateTime::parse_from_rfc3339(&scan.created_at)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now()),
        completed_at: scan
            .completed_at
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc)),
    })
}

/// Convert row to PrivescFinding
pub fn row_to_finding(row: PrivescFindingRow) -> Result<PrivescFinding> {
    let severity = match row.severity.as_str() {
        "critical" => PrivescSeverity::Critical,
        "high" => PrivescSeverity::High,
        "medium" => PrivescSeverity::Medium,
        "low" => PrivescSeverity::Low,
        _ => PrivescSeverity::Info,
    };

    let os_type = match row.os_type.as_str() {
        "windows" => OsType::Windows,
        _ => OsType::Linux,
    };

    let exploitation_steps: Vec<String> = serde_json::from_str(&row.exploitation_steps)?;
    let references: Vec<String> = serde_json::from_str(&row.references)?;
    let mitre_techniques: Vec<String> = serde_json::from_str(&row.mitre_techniques)?;

    // Parse vector based on OS type
    let linux_vector = if os_type == OsType::Linux && row.vector_data != "null" {
        serde_json::from_str(&row.vector_data).ok()
    } else {
        None
    };

    let windows_vector = if os_type == OsType::Windows && row.vector_data != "null" {
        serde_json::from_str(&row.vector_data).ok()
    } else {
        None
    };

    Ok(PrivescFinding {
        id: row.id,
        severity,
        title: row.title,
        description: row.description,
        os_type,
        linux_vector,
        windows_vector,
        exploitation_steps,
        references,
        raw_output: row.raw_output,
        mitre_techniques,
        discovered_at: chrono::DateTime::parse_from_rfc3339(&row.created_at)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now()),
    })
}
