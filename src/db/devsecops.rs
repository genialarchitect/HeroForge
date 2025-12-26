//! DevSecOps Database Operations
//!
//! This module provides database operations for:
//! - DevSecOps metrics storage and retrieval
//! - Pipeline gate configuration
//! - Gate evaluation history
//! - Trend analysis queries

use sqlx::SqlitePool;
use anyhow::Result;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use uuid::Uuid;

use crate::yellow_team::devsecops::{
    DevSecOpsMetrics, DevSecOpsMetricsRow, DevSecOpsDashboard, MetricsTrends,
    MetricsHistoryPoint, TrendDirection, VulnSummary, VulnSummaryRow,
    ProjectHealth, ProjectHealthRow, RecentFix, RecentFixRow,
    SlaBreach, SlaBreachRow, PipelineGate, PipelineGateRow,
    GateRule, GateEvaluation, GateEvaluationRow, RuleEvaluationResult,
    CreatePipelineGateRequest, UpdatePipelineGateRequest, MetricsQuery,
    Severity, SlaStatus, GateStatus, calculate_change_pct, calculate_security_debt,
};

// ============================================================================
// Metrics Operations
// ============================================================================

/// Record a DevSecOps metrics snapshot
pub async fn record_metrics(
    pool: &SqlitePool,
    org_id: Option<&str>,
    project_id: Option<&str>,
    metric_date: NaiveDate,
    mttr_critical_hours: Option<f64>,
    mttr_high_hours: Option<f64>,
    mttr_medium_hours: Option<f64>,
    mttr_low_hours: Option<f64>,
    vulnerability_density: f64,
    fix_rate: f64,
    sla_compliance_rate: f64,
    open_critical: u32,
    open_high: u32,
    open_medium: u32,
    open_low: u32,
    security_debt_hours: f64,
    pipeline_pass_rate: f64,
    scan_coverage: f64,
) -> Result<DevSecOpsMetrics> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let date_str = metric_date.to_string();

    sqlx::query(
        r#"
        INSERT INTO devsecops_metrics (
            id, org_id, project_id, metric_date, mttr_critical_hours, mttr_high_hours,
            mttr_medium_hours, mttr_low_hours, vulnerability_density, fix_rate,
            sla_compliance_rate, open_critical, open_high, open_medium, open_low,
            security_debt_hours, pipeline_pass_rate, scan_coverage, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
        "#,
    )
    .bind(&id)
    .bind(org_id)
    .bind(project_id)
    .bind(&date_str)
    .bind(mttr_critical_hours)
    .bind(mttr_high_hours)
    .bind(mttr_medium_hours)
    .bind(mttr_low_hours)
    .bind(vulnerability_density)
    .bind(fix_rate)
    .bind(sla_compliance_rate)
    .bind(open_critical as i32)
    .bind(open_high as i32)
    .bind(open_medium as i32)
    .bind(open_low as i32)
    .bind(security_debt_hours)
    .bind(pipeline_pass_rate)
    .bind(scan_coverage)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(DevSecOpsMetrics {
        id: Uuid::parse_str(&id).unwrap_or_default(),
        org_id: org_id.and_then(|s| Uuid::parse_str(s).ok()),
        project_id: project_id.and_then(|s| Uuid::parse_str(s).ok()),
        metric_date,
        mttr_critical_hours,
        mttr_high_hours,
        mttr_medium_hours,
        mttr_low_hours,
        vulnerability_density,
        fix_rate,
        sla_compliance_rate,
        open_critical,
        open_high,
        open_medium,
        open_low,
        security_debt_hours,
        pipeline_pass_rate,
        scan_coverage,
        created_at: Utc::now(),
    })
}

/// Get the latest metrics snapshot
pub async fn get_latest_metrics(
    pool: &SqlitePool,
    org_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<Option<DevSecOpsMetrics>> {
    let row: Option<DevSecOpsMetricsRow> = if let Some(pid) = project_id {
        sqlx::query_as(
            r#"
            SELECT * FROM devsecops_metrics
            WHERE project_id = ?1
            ORDER BY metric_date DESC
            LIMIT 1
            "#,
        )
        .bind(pid)
        .fetch_optional(pool)
        .await?
    } else if let Some(oid) = org_id {
        sqlx::query_as(
            r#"
            SELECT * FROM devsecops_metrics
            WHERE org_id = ?1 AND project_id IS NULL
            ORDER BY metric_date DESC
            LIMIT 1
            "#,
        )
        .bind(oid)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT * FROM devsecops_metrics
            WHERE org_id IS NULL AND project_id IS NULL
            ORDER BY metric_date DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(pool)
        .await?
    };

    Ok(row.map(row_to_metrics))
}

/// Get metrics history for trend analysis
pub async fn get_metrics_history(
    pool: &SqlitePool,
    org_id: Option<&str>,
    project_id: Option<&str>,
    start_date: Option<NaiveDate>,
    end_date: Option<NaiveDate>,
    limit: Option<i32>,
) -> Result<Vec<DevSecOpsMetrics>> {
    let limit = limit.unwrap_or(30);
    let start = start_date
        .unwrap_or_else(|| (Utc::now() - Duration::days(30)).date_naive())
        .to_string();
    let end = end_date
        .unwrap_or_else(|| Utc::now().date_naive())
        .to_string();

    let rows: Vec<DevSecOpsMetricsRow> = if let Some(pid) = project_id {
        sqlx::query_as(
            r#"
            SELECT * FROM devsecops_metrics
            WHERE project_id = ?1 AND metric_date BETWEEN ?2 AND ?3
            ORDER BY metric_date DESC
            LIMIT ?4
            "#,
        )
        .bind(pid)
        .bind(&start)
        .bind(&end)
        .bind(limit)
        .fetch_all(pool)
        .await?
    } else if let Some(oid) = org_id {
        sqlx::query_as(
            r#"
            SELECT * FROM devsecops_metrics
            WHERE org_id = ?1 AND project_id IS NULL AND metric_date BETWEEN ?2 AND ?3
            ORDER BY metric_date DESC
            LIMIT ?4
            "#,
        )
        .bind(oid)
        .bind(&start)
        .bind(&end)
        .bind(limit)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT * FROM devsecops_metrics
            WHERE org_id IS NULL AND project_id IS NULL AND metric_date BETWEEN ?1 AND ?2
            ORDER BY metric_date DESC
            LIMIT ?3
            "#,
        )
        .bind(&start)
        .bind(&end)
        .bind(limit)
        .fetch_all(pool)
        .await?
    };

    Ok(rows.into_iter().map(row_to_metrics).collect())
}

/// Calculate MTTR from vulnerability data
pub async fn calculate_mttr_from_vulns(
    pool: &SqlitePool,
    org_id: Option<&str>,
    severity: &str,
    days: i32,
) -> Result<Option<f64>> {
    let cutoff = (Utc::now() - Duration::days(days as i64)).to_rfc3339();

    let result: Option<(Option<f64>,)> = if let Some(oid) = org_id {
        sqlx::query_as(
            r#"
            SELECT AVG((julianday(resolved_at) - julianday(created_at)) * 24) as avg_hours
            FROM vulnerability_tracking
            WHERE organization_id = ?1
              AND severity = ?2
              AND status IN ('resolved', 'verified')
              AND resolved_at > ?3
            "#,
        )
        .bind(oid)
        .bind(severity)
        .bind(&cutoff)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT AVG((julianday(resolved_at) - julianday(created_at)) * 24) as avg_hours
            FROM vulnerability_tracking
            WHERE severity = ?1
              AND status IN ('resolved', 'verified')
              AND resolved_at > ?2
            "#,
        )
        .bind(severity)
        .bind(&cutoff)
        .fetch_optional(pool)
        .await?
    };

    Ok(result.and_then(|(avg,)| avg))
}

/// Get MTTR breakdown by severity
pub async fn get_mttr_breakdown(
    pool: &SqlitePool,
    org_id: Option<&str>,
    days: i32,
) -> Result<(Option<f64>, Option<f64>, Option<f64>, Option<f64>)> {
    let critical = calculate_mttr_from_vulns(pool, org_id, "critical", days).await?;
    let high = calculate_mttr_from_vulns(pool, org_id, "high", days).await?;
    let medium = calculate_mttr_from_vulns(pool, org_id, "medium", days).await?;
    let low = calculate_mttr_from_vulns(pool, org_id, "low", days).await?;

    Ok((critical, high, medium, low))
}

/// Get vulnerability counts by severity
pub async fn get_vulnerability_counts(
    pool: &SqlitePool,
    org_id: Option<&str>,
) -> Result<(u32, u32, u32, u32)> {
    let counts: (i64, i64, i64, i64) = if let Some(oid) = org_id {
        sqlx::query_as(
            r#"
            SELECT
                SUM(CASE WHEN severity = 'critical' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'high' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'medium' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'low' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END)
            FROM vulnerability_tracking
            WHERE organization_id = ?1
            "#,
        )
        .bind(oid)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT
                SUM(CASE WHEN severity = 'critical' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'high' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'medium' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'low' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END)
            FROM vulnerability_tracking
            "#,
        )
        .fetch_one(pool)
        .await?
    };

    Ok((
        counts.0 as u32,
        counts.1 as u32,
        counts.2 as u32,
        counts.3 as u32,
    ))
}

/// Get SLA compliance statistics
pub async fn get_sla_statistics(
    pool: &SqlitePool,
    org_id: Option<&str>,
    days: i32,
) -> Result<(u32, u32, f64)> {
    let cutoff = (Utc::now() - Duration::days(days as i64)).to_rfc3339();

    // SLA defaults: Critical=24h, High=72h, Medium=168h (7d), Low=720h (30d)
    let result: (i64, i64) = if let Some(oid) = org_id {
        sqlx::query_as(
            r#"
            SELECT
                SUM(CASE
                    WHEN (severity = 'critical' AND (julianday(resolved_at) - julianday(created_at)) * 24 <= 24)
                      OR (severity = 'high' AND (julianday(resolved_at) - julianday(created_at)) * 24 <= 72)
                      OR (severity = 'medium' AND (julianday(resolved_at) - julianday(created_at)) * 24 <= 168)
                      OR (severity = 'low' AND (julianday(resolved_at) - julianday(created_at)) * 24 <= 720)
                    THEN 1 ELSE 0
                END) as within_sla,
                COUNT(*) as total
            FROM vulnerability_tracking
            WHERE organization_id = ?1
              AND status IN ('resolved', 'verified')
              AND resolved_at > ?2
            "#,
        )
        .bind(oid)
        .bind(&cutoff)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT
                SUM(CASE
                    WHEN (severity = 'critical' AND (julianday(resolved_at) - julianday(created_at)) * 24 <= 24)
                      OR (severity = 'high' AND (julianday(resolved_at) - julianday(created_at)) * 24 <= 72)
                      OR (severity = 'medium' AND (julianday(resolved_at) - julianday(created_at)) * 24 <= 168)
                      OR (severity = 'low' AND (julianday(resolved_at) - julianday(created_at)) * 24 <= 720)
                    THEN 1 ELSE 0
                END) as within_sla,
                COUNT(*) as total
            FROM vulnerability_tracking
            WHERE status IN ('resolved', 'verified')
              AND resolved_at > ?1
            "#,
        )
        .bind(&cutoff)
        .fetch_one(pool)
        .await?
    };

    let compliance_rate = if result.1 > 0 {
        (result.0 as f64 / result.1 as f64) * 100.0
    } else {
        100.0
    };

    Ok((result.0 as u32, result.1 as u32, compliance_rate))
}

/// Get security debt calculation
pub async fn get_security_debt(
    pool: &SqlitePool,
    org_id: Option<&str>,
) -> Result<f64> {
    let (critical, high, medium, low) = get_vulnerability_counts(pool, org_id).await?;
    Ok(calculate_security_debt(critical, high, medium, low))
}

/// Get SLA breaches
pub async fn get_sla_breaches(
    pool: &SqlitePool,
    org_id: Option<&str>,
    limit: Option<i32>,
) -> Result<Vec<SlaBreach>> {
    let limit = limit.unwrap_or(20);
    let now = Utc::now().to_rfc3339();

    let rows: Vec<SlaBreachRow> = if let Some(oid) = org_id {
        sqlx::query_as(
            r#"
            SELECT
                vt.id as vuln_id,
                COALESCE(vt.vulnerability_id, vt.id) as title,
                vt.severity,
                CAST(julianday(?1) - julianday(vt.due_date) AS INTEGER) as days_overdue,
                NULL as project_name,
                u.username as assignee
            FROM vulnerability_tracking vt
            LEFT JOIN users u ON vt.assignee_id = u.id
            WHERE vt.organization_id = ?2
              AND vt.due_date IS NOT NULL
              AND vt.due_date < ?1
              AND vt.status NOT IN ('resolved', 'verified', 'accepted_risk', 'false_positive')
            ORDER BY days_overdue DESC
            LIMIT ?3
            "#,
        )
        .bind(&now)
        .bind(oid)
        .bind(limit)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT
                vt.id as vuln_id,
                COALESCE(vt.vulnerability_id, vt.id) as title,
                vt.severity,
                CAST(julianday(?1) - julianday(vt.due_date) AS INTEGER) as days_overdue,
                NULL as project_name,
                u.username as assignee
            FROM vulnerability_tracking vt
            LEFT JOIN users u ON vt.assignee_id = u.id
            WHERE vt.due_date IS NOT NULL
              AND vt.due_date < ?1
              AND vt.status NOT IN ('resolved', 'verified', 'accepted_risk', 'false_positive')
            ORDER BY days_overdue DESC
            LIMIT ?2
            "#,
        )
        .bind(&now)
        .bind(limit)
        .fetch_all(pool)
        .await?
    };

    Ok(rows.into_iter().map(|r| SlaBreach {
        vuln_id: Uuid::parse_str(&r.vuln_id).unwrap_or_default(),
        title: r.title,
        severity: r.severity.parse().unwrap_or(Severity::Medium),
        days_overdue: r.days_overdue.max(0) as u32,
        project_name: r.project_name,
        assignee: r.assignee,
    }).collect())
}

/// Get recent fixes
pub async fn get_recent_fixes(
    pool: &SqlitePool,
    org_id: Option<&str>,
    limit: Option<i32>,
) -> Result<Vec<RecentFix>> {
    let limit = limit.unwrap_or(10);

    let rows: Vec<RecentFixRow> = if let Some(oid) = org_id {
        sqlx::query_as(
            r#"
            SELECT
                vt.id as vuln_id,
                COALESCE(vt.vulnerability_id, vt.id) as title,
                vt.severity,
                u.username as fixed_by,
                vt.resolved_at as fixed_at,
                (julianday(vt.resolved_at) - julianday(vt.created_at)) * 24 as resolution_time_hours
            FROM vulnerability_tracking vt
            LEFT JOIN users u ON vt.assignee_id = u.id
            WHERE vt.organization_id = ?1
              AND vt.status IN ('resolved', 'verified')
              AND vt.resolved_at IS NOT NULL
            ORDER BY vt.resolved_at DESC
            LIMIT ?2
            "#,
        )
        .bind(oid)
        .bind(limit)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT
                vt.id as vuln_id,
                COALESCE(vt.vulnerability_id, vt.id) as title,
                vt.severity,
                u.username as fixed_by,
                vt.resolved_at as fixed_at,
                (julianday(vt.resolved_at) - julianday(vt.created_at)) * 24 as resolution_time_hours
            FROM vulnerability_tracking vt
            LEFT JOIN users u ON vt.assignee_id = u.id
            WHERE vt.status IN ('resolved', 'verified')
              AND vt.resolved_at IS NOT NULL
            ORDER BY vt.resolved_at DESC
            LIMIT ?1
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await?
    };

    Ok(rows.into_iter().map(|r| RecentFix {
        vuln_id: Uuid::parse_str(&r.vuln_id).unwrap_or_default(),
        title: r.title,
        severity: r.severity.parse().unwrap_or(Severity::Medium),
        fixed_by: r.fixed_by,
        fixed_at: DateTime::parse_from_rfc3339(&r.fixed_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        resolution_time_hours: r.resolution_time_hours,
    }).collect())
}

/// Get top vulnerabilities by risk
pub async fn get_top_vulnerabilities(
    pool: &SqlitePool,
    org_id: Option<&str>,
    limit: Option<i32>,
) -> Result<Vec<VulnSummary>> {
    let limit = limit.unwrap_or(10);
    let now = Utc::now().to_rfc3339();

    let rows: Vec<VulnSummaryRow> = if let Some(oid) = org_id {
        sqlx::query_as(
            r#"
            SELECT
                vt.id,
                COALESCE(vt.vulnerability_id, vt.id) as title,
                vt.severity,
                NULL as project_name,
                CAST(julianday(?1) - julianday(vt.created_at) AS INTEGER) as age_days,
                CASE
                    WHEN vt.due_date IS NULL THEN 'no_sla'
                    WHEN vt.due_date < ?1 THEN 'breached'
                    WHEN julianday(vt.due_date) - julianday(?1) <= 2 THEN 'at_risk'
                    ELSE 'on_track'
                END as sla_status
            FROM vulnerability_tracking vt
            WHERE vt.organization_id = ?2
              AND vt.status NOT IN ('resolved', 'verified', 'false_positive')
            ORDER BY
                CASE vt.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                age_days DESC
            LIMIT ?3
            "#,
        )
        .bind(&now)
        .bind(oid)
        .bind(limit)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT
                vt.id,
                COALESCE(vt.vulnerability_id, vt.id) as title,
                vt.severity,
                NULL as project_name,
                CAST(julianday(?1) - julianday(vt.created_at) AS INTEGER) as age_days,
                CASE
                    WHEN vt.due_date IS NULL THEN 'no_sla'
                    WHEN vt.due_date < ?1 THEN 'breached'
                    WHEN julianday(vt.due_date) - julianday(?1) <= 2 THEN 'at_risk'
                    ELSE 'on_track'
                END as sla_status
            FROM vulnerability_tracking vt
            WHERE vt.status NOT IN ('resolved', 'verified', 'false_positive')
            ORDER BY
                CASE vt.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                age_days DESC
            LIMIT ?2
            "#,
        )
        .bind(&now)
        .bind(limit)
        .fetch_all(pool)
        .await?
    };

    Ok(rows.into_iter().map(|r| VulnSummary {
        id: Uuid::parse_str(&r.id).unwrap_or_default(),
        title: r.title,
        severity: r.severity.parse().unwrap_or(Severity::Medium),
        project_name: r.project_name,
        age_days: r.age_days.max(0) as u32,
        sla_status: r.sla_status.parse().unwrap_or(SlaStatus::NoSla),
    }).collect())
}

// ============================================================================
// Pipeline Gate Operations
// ============================================================================

/// Create a new pipeline gate
pub async fn create_pipeline_gate(
    pool: &SqlitePool,
    request: CreatePipelineGateRequest,
) -> Result<PipelineGate> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let project_id = request.project_id.map(|p| p.to_string());
    let rules_json = serde_json::to_string(&request.rules)?;

    sqlx::query(
        r#"
        INSERT INTO devsecops_pipeline_gates (
            id, project_id, name, description, rules_json, is_blocking, is_active, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8)
        "#,
    )
    .bind(&id)
    .bind(&project_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&rules_json)
    .bind(request.is_blocking)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(PipelineGate {
        id: Uuid::parse_str(&id).unwrap_or_default(),
        project_id: request.project_id,
        name: request.name,
        description: request.description,
        rules: request.rules,
        is_blocking: request.is_blocking,
        is_active: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    })
}

/// Get pipeline gate by ID
pub async fn get_pipeline_gate(
    pool: &SqlitePool,
    gate_id: &str,
) -> Result<Option<PipelineGate>> {
    let row: Option<PipelineGateRow> = sqlx::query_as(
        "SELECT * FROM devsecops_pipeline_gates WHERE id = ?1",
    )
    .bind(gate_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(row_to_gate))
}

/// List pipeline gates
pub async fn list_pipeline_gates(
    pool: &SqlitePool,
    project_id: Option<&str>,
) -> Result<Vec<PipelineGate>> {
    let rows: Vec<PipelineGateRow> = if let Some(pid) = project_id {
        sqlx::query_as(
            r#"
            SELECT * FROM devsecops_pipeline_gates
            WHERE project_id = ?1 OR project_id IS NULL
            ORDER BY project_id NULLS LAST, name
            "#,
        )
        .bind(pid)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT * FROM devsecops_pipeline_gates ORDER BY project_id NULLS LAST, name",
        )
        .fetch_all(pool)
        .await?
    };

    Ok(rows.into_iter().map(row_to_gate).collect())
}

/// Update pipeline gate
pub async fn update_pipeline_gate(
    pool: &SqlitePool,
    gate_id: &str,
    request: UpdatePipelineGateRequest,
) -> Result<PipelineGate> {
    let now = Utc::now().to_rfc3339();

    // Build dynamic update
    let mut updates = vec!["updated_at = ?1"];
    let mut params: Vec<String> = vec![now.clone()];
    let mut param_idx = 2;

    if let Some(name) = &request.name {
        updates.push("name = ?");
        params.push(name.clone());
        param_idx += 1;
    }
    if let Some(desc) = &request.description {
        updates.push("description = ?");
        params.push(desc.clone());
        param_idx += 1;
    }
    if let Some(rules) = &request.rules {
        updates.push("rules_json = ?");
        params.push(serde_json::to_string(rules)?);
        param_idx += 1;
    }
    if let Some(blocking) = request.is_blocking {
        updates.push("is_blocking = ?");
        params.push(if blocking { "1" } else { "0" }.to_string());
        param_idx += 1;
    }
    if let Some(active) = request.is_active {
        updates.push("is_active = ?");
        params.push(if active { "1" } else { "0" }.to_string());
        let _ = param_idx; // Suppress unused warning
    }

    let query = format!(
        "UPDATE devsecops_pipeline_gates SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut q = sqlx::query(&query);
    for param in &params {
        q = q.bind(param);
    }
    q = q.bind(gate_id);
    q.execute(pool).await?;

    get_pipeline_gate(pool, gate_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Gate not found after update"))
}

/// Delete pipeline gate
pub async fn delete_pipeline_gate(pool: &SqlitePool, gate_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM devsecops_pipeline_gates WHERE id = ?1")
        .bind(gate_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Evaluate a gate against scan results
pub async fn evaluate_gate(
    pool: &SqlitePool,
    gate_id: &str,
    scan_id: &str,
) -> Result<GateEvaluation> {
    let gate = get_pipeline_gate(pool, gate_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Gate not found"))?;

    // Get vulnerability counts from the scan
    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END),
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END),
            COUNT(*)
        FROM vulnerability_tracking
        WHERE scan_id = ?1
          AND status NOT IN ('false_positive', 'accepted_risk')
        "#,
    )
    .bind(scan_id)
    .fetch_one(pool)
    .await?;

    let critical = counts.0 as u32;
    let high = counts.1 as u32;
    let medium = counts.2 as u32;
    let total = counts.3 as u32;

    // Evaluate each rule
    let mut rule_results = Vec::new();
    let mut all_passed = true;

    for rule in &gate.rules {
        let (actual_value, passed, message) = match rule.rule_type {
            crate::yellow_team::devsecops::GateRuleType::MaxCritical => {
                let passed = critical <= rule.threshold;
                (critical, passed, format!("Critical vulns: {} (max: {})", critical, rule.threshold))
            }
            crate::yellow_team::devsecops::GateRuleType::MaxHigh => {
                let passed = high <= rule.threshold;
                (high, passed, format!("High vulns: {} (max: {})", high, rule.threshold))
            }
            crate::yellow_team::devsecops::GateRuleType::MaxMedium => {
                let passed = medium <= rule.threshold;
                (medium, passed, format!("Medium vulns: {} (max: {})", medium, rule.threshold))
            }
            crate::yellow_team::devsecops::GateRuleType::MaxTotal => {
                let passed = total <= rule.threshold;
                (total, passed, format!("Total vulns: {} (max: {})", total, rule.threshold))
            }
            _ => (0, true, "Rule not evaluated".to_string()),
        };

        if !passed && matches!(rule.action, crate::yellow_team::devsecops::GateAction::Block) {
            all_passed = false;
        }

        rule_results.push(RuleEvaluationResult {
            rule_type: rule.rule_type,
            threshold: rule.threshold,
            actual_value,
            passed,
            action: rule.action,
            message,
        });
    }

    // Record evaluation
    let eval_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let rule_results_json = serde_json::to_string(&rule_results)?;
    let project_id = gate.project_id.map(|p| p.to_string());

    sqlx::query(
        r#"
        INSERT INTO devsecops_gate_evaluations (
            id, gate_id, scan_id, project_id, passed, rule_results_json, evaluated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
    )
    .bind(&eval_id)
    .bind(gate_id)
    .bind(scan_id)
    .bind(&project_id)
    .bind(all_passed)
    .bind(&rule_results_json)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(GateEvaluation {
        id: Uuid::parse_str(&eval_id).unwrap_or_default(),
        gate_id: Uuid::parse_str(gate_id).unwrap_or_default(),
        scan_id: Uuid::parse_str(scan_id).unwrap_or_default(),
        project_id: gate.project_id,
        passed: all_passed,
        rule_results,
        evaluated_at: Utc::now(),
    })
}

/// Get gate evaluation history
pub async fn get_gate_evaluations(
    pool: &SqlitePool,
    gate_id: &str,
    limit: Option<i32>,
) -> Result<Vec<GateEvaluation>> {
    let limit = limit.unwrap_or(20);

    let rows: Vec<GateEvaluationRow> = sqlx::query_as(
        r#"
        SELECT * FROM devsecops_gate_evaluations
        WHERE gate_id = ?1
        ORDER BY evaluated_at DESC
        LIMIT ?2
        "#,
    )
    .bind(gate_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(row_to_evaluation).collect())
}

// ============================================================================
// Dashboard Assembly
// ============================================================================

/// Build the complete DevSecOps dashboard
pub async fn build_dashboard(
    pool: &SqlitePool,
    org_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<DevSecOpsDashboard> {
    // Get current metrics or compute them
    let current_metrics = match get_latest_metrics(pool, org_id, project_id).await? {
        Some(m) => m,
        None => compute_current_metrics(pool, org_id, project_id).await?,
    };

    // Get historical data for trends
    let history = get_metrics_history(pool, org_id, project_id, None, None, Some(30)).await?;
    let trends = compute_trends(&current_metrics, &history);

    // Get supporting data
    let top_vulnerabilities = get_top_vulnerabilities(pool, org_id, Some(10)).await?;
    let project_health = get_project_health_list(pool, org_id, Some(10)).await?;
    let recent_fixes = get_recent_fixes(pool, org_id, Some(10)).await?;
    let sla_breaches = get_sla_breaches(pool, org_id, Some(10)).await?;

    Ok(DevSecOpsDashboard {
        current_metrics,
        trends,
        top_vulnerabilities,
        project_health,
        recent_fixes,
        sla_breaches,
    })
}

/// Compute current metrics from vulnerability data
async fn compute_current_metrics(
    pool: &SqlitePool,
    org_id: Option<&str>,
    _project_id: Option<&str>,
) -> Result<DevSecOpsMetrics> {
    let (critical, high, medium, low) = get_vulnerability_counts(pool, org_id).await?;
    let (mttr_critical, mttr_high, mttr_medium, mttr_low) = get_mttr_breakdown(pool, org_id, 30).await?;
    let (_, _, sla_compliance) = get_sla_statistics(pool, org_id, 30).await?;
    let security_debt = calculate_security_debt(critical, high, medium, low);

    // Calculate fix rate
    let fix_stats: (i64, i64) = if let Some(oid) = org_id {
        sqlx::query_as(
            r#"
            SELECT
                SUM(CASE WHEN status IN ('resolved', 'verified') THEN 1 ELSE 0 END),
                COUNT(*)
            FROM vulnerability_tracking
            WHERE organization_id = ?1
            "#,
        )
        .bind(oid)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT SUM(CASE WHEN status IN ('resolved', 'verified') THEN 1 ELSE 0 END), COUNT(*) FROM vulnerability_tracking",
        )
        .fetch_one(pool)
        .await?
    };

    let fix_rate = if fix_stats.1 > 0 {
        (fix_stats.0 as f64 / fix_stats.1 as f64) * 100.0
    } else {
        100.0
    };

    Ok(DevSecOpsMetrics {
        id: Uuid::new_v4(),
        org_id: org_id.and_then(|s| Uuid::parse_str(s).ok()),
        project_id: None,
        metric_date: Utc::now().date_naive(),
        mttr_critical_hours: mttr_critical,
        mttr_high_hours: mttr_high,
        mttr_medium_hours: mttr_medium,
        mttr_low_hours: mttr_low,
        vulnerability_density: 0.0, // Would need LOC data
        fix_rate,
        sla_compliance_rate: sla_compliance,
        open_critical: critical,
        open_high: high,
        open_medium: medium,
        open_low: low,
        security_debt_hours: security_debt,
        pipeline_pass_rate: 100.0, // Would need CI/CD data
        scan_coverage: 0.0, // Would need asset/repo data
        created_at: Utc::now(),
    })
}

/// Compute trends from historical data
fn compute_trends(current: &DevSecOpsMetrics, history: &[DevSecOpsMetrics]) -> MetricsTrends {
    if history.is_empty() {
        return MetricsTrends::default();
    }

    // Get oldest entry for comparison
    let oldest = history.last().unwrap();

    let current_mttr = current.overall_mttr_hours();
    let oldest_mttr = oldest.overall_mttr_hours();
    let mttr_change = calculate_change_pct(oldest_mttr, current_mttr);

    let density_change = calculate_change_pct(oldest.vulnerability_density, current.vulnerability_density);
    let fix_rate_change = calculate_change_pct(oldest.fix_rate, current.fix_rate);
    let debt_change = calculate_change_pct(oldest.security_debt_hours, current.security_debt_hours);

    let history_points: Vec<MetricsHistoryPoint> = history.iter().map(|m| {
        MetricsHistoryPoint {
            date: m.metric_date,
            mttr_hours: m.overall_mttr_hours(),
            vulnerability_density: m.vulnerability_density,
            fix_rate: m.fix_rate,
            security_debt_hours: m.security_debt_hours,
            open_vulns: m.total_open_vulns(),
        }
    }).collect();

    MetricsTrends {
        mttr_trend: TrendDirection::from_change_lower_is_better(mttr_change),
        mttr_change_pct: mttr_change,
        vuln_density_trend: TrendDirection::from_change_lower_is_better(density_change),
        vuln_density_change_pct: density_change,
        fix_rate_trend: TrendDirection::from_change_higher_is_better(fix_rate_change),
        fix_rate_change_pct: fix_rate_change,
        debt_trend: TrendDirection::from_change_lower_is_better(debt_change),
        debt_change_pct: debt_change,
        history: history_points,
    }
}

/// Get project health list
async fn get_project_health_list(
    pool: &SqlitePool,
    _org_id: Option<&str>,
    limit: Option<i32>,
) -> Result<Vec<ProjectHealth>> {
    // For now, return empty - would need project/repo data
    let _ = pool;
    let _ = limit;
    Ok(Vec::new())
}

// ============================================================================
// Conversion Helpers
// ============================================================================

fn row_to_metrics(row: DevSecOpsMetricsRow) -> DevSecOpsMetrics {
    DevSecOpsMetrics {
        id: Uuid::parse_str(&row.id).unwrap_or_default(),
        org_id: row.org_id.and_then(|s| Uuid::parse_str(&s).ok()),
        project_id: row.project_id.and_then(|s| Uuid::parse_str(&s).ok()),
        metric_date: NaiveDate::parse_from_str(&row.metric_date, "%Y-%m-%d")
            .unwrap_or_else(|_| Utc::now().date_naive()),
        mttr_critical_hours: row.mttr_critical_hours,
        mttr_high_hours: row.mttr_high_hours,
        mttr_medium_hours: row.mttr_medium_hours,
        mttr_low_hours: row.mttr_low_hours,
        vulnerability_density: row.vulnerability_density,
        fix_rate: row.fix_rate,
        sla_compliance_rate: row.sla_compliance_rate,
        open_critical: row.open_critical as u32,
        open_high: row.open_high as u32,
        open_medium: row.open_medium as u32,
        open_low: row.open_low as u32,
        security_debt_hours: row.security_debt_hours,
        pipeline_pass_rate: row.pipeline_pass_rate,
        scan_coverage: row.scan_coverage,
        created_at: DateTime::parse_from_rfc3339(&row.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    }
}

fn row_to_gate(row: PipelineGateRow) -> PipelineGate {
    PipelineGate {
        id: Uuid::parse_str(&row.id).unwrap_or_default(),
        project_id: row.project_id.and_then(|s| Uuid::parse_str(&s).ok()),
        name: row.name,
        description: row.description,
        rules: serde_json::from_str(&row.rules_json).unwrap_or_default(),
        is_blocking: row.is_blocking,
        is_active: row.is_active,
        created_at: DateTime::parse_from_rfc3339(&row.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    }
}

fn row_to_evaluation(row: GateEvaluationRow) -> GateEvaluation {
    GateEvaluation {
        id: Uuid::parse_str(&row.id).unwrap_or_default(),
        gate_id: Uuid::parse_str(&row.gate_id).unwrap_or_default(),
        scan_id: Uuid::parse_str(&row.scan_id).unwrap_or_default(),
        project_id: row.project_id.and_then(|s| Uuid::parse_str(&s).ok()),
        passed: row.passed,
        rule_results: serde_json::from_str(&row.rule_results_json).unwrap_or_default(),
        evaluated_at: DateTime::parse_from_rfc3339(&row.evaluated_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    }
}

// ============================================================================
// Finding Resolution Operations (for MTTR calculation)
// ============================================================================

use crate::yellow_team::devsecops::{
    SecurityCoverage, SecurityCoverageRow, FindingResolution, FindingResolutionRow,
    CreateFindingResolutionRequest, SecurityDebtItem, SecurityDebtRow,
    TrendPoint, TrendPointRow, FindingsTrend, MttrBreakdown, SecurityDebtSummary,
    SeverityDebtBreakdown, DebtCategory, SourceDebtBreakdown,
    REMEDIATION_HOURS_CRITICAL, REMEDIATION_HOURS_HIGH, REMEDIATION_HOURS_MEDIUM, REMEDIATION_HOURS_LOW,
};

/// Create a finding resolution record (when a finding is discovered)
pub async fn create_finding_resolution(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateFindingResolutionRequest,
) -> Result<FindingResolution> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO finding_resolutions (
            id, finding_id, finding_type, severity, user_id, project_name, source, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
    )
    .bind(&id)
    .bind(&request.finding_id)
    .bind(&request.finding_type)
    .bind(&request.severity)
    .bind(user_id)
    .bind(&request.project_name)
    .bind(&request.source)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(FindingResolution {
        id: Uuid::parse_str(&id).unwrap_or_default(),
        finding_id: request.finding_id.clone(),
        finding_type: request.finding_type.clone(),
        severity: request.severity.parse().unwrap_or(Severity::Medium),
        user_id: Some(Uuid::parse_str(user_id).unwrap_or_default()),
        org_id: None,
        project_name: request.project_name.clone(),
        created_at: Utc::now(),
        resolved_at: None,
        resolution_hours: None,
        source: request.source.clone(),
    })
}

/// Mark a finding as resolved and calculate resolution time
pub async fn resolve_finding(
    pool: &SqlitePool,
    finding_id: &str,
) -> Result<Option<f64>> {
    let now = Utc::now().to_rfc3339();

    // Get the finding and calculate resolution time
    let row: Option<FindingResolutionRow> = sqlx::query_as(
        "SELECT * FROM finding_resolutions WHERE finding_id = ?1 AND resolved_at IS NULL"
    )
    .bind(finding_id)
    .fetch_optional(pool)
    .await?;

    if let Some(row) = row {
        // Calculate resolution hours
        let created_at = DateTime::parse_from_rfc3339(&row.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let resolved_at = Utc::now();
        let resolution_hours = (resolved_at - created_at).num_hours() as f64;

        sqlx::query(
            r#"
            UPDATE finding_resolutions
            SET resolved_at = ?1, resolution_hours = ?2
            WHERE finding_id = ?3 AND resolved_at IS NULL
            "#,
        )
        .bind(&now)
        .bind(resolution_hours)
        .bind(finding_id)
        .execute(pool)
        .await?;

        Ok(Some(resolution_hours))
    } else {
        Ok(None)
    }
}

/// Calculate MTTR from finding_resolutions table
pub async fn calculate_mttr_from_resolutions(
    pool: &SqlitePool,
    user_id: &str,
    severity: &str,
    days: i32,
) -> Result<(Option<f64>, u32)> {
    let cutoff = (Utc::now() - Duration::days(days as i64)).to_rfc3339();

    let result: Option<(Option<f64>, i64)> = sqlx::query_as(
        r#"
        SELECT AVG(resolution_hours), COUNT(*) as sample_size
        FROM finding_resolutions
        WHERE user_id = ?1
          AND LOWER(severity) = LOWER(?2)
          AND resolved_at IS NOT NULL
          AND resolved_at > ?3
        "#,
    )
    .bind(user_id)
    .bind(severity)
    .bind(&cutoff)
    .fetch_optional(pool)
    .await?;

    match result {
        Some((avg, count)) => Ok((avg, count as u32)),
        None => Ok((None, 0)),
    }
}

/// Get detailed MTTR breakdown with sample sizes
pub async fn get_detailed_mttr_breakdown(
    pool: &SqlitePool,
    user_id: &str,
    days: i32,
) -> Result<MttrBreakdown> {
    let (mttr_critical, sample_critical) = calculate_mttr_from_resolutions(pool, user_id, "critical", days).await?;
    let (mttr_high, sample_high) = calculate_mttr_from_resolutions(pool, user_id, "high", days).await?;
    let (mttr_medium, sample_medium) = calculate_mttr_from_resolutions(pool, user_id, "medium", days).await?;
    let (mttr_low, sample_low) = calculate_mttr_from_resolutions(pool, user_id, "low", days).await?;

    // Get previous period for trend comparison
    let previous_days = days * 2;
    let previous_cutoff_start = (Utc::now() - Duration::days(previous_days as i64)).to_rfc3339();
    let previous_cutoff_end = (Utc::now() - Duration::days(days as i64)).to_rfc3339();

    let previous_mttr: Option<(Option<f64>,)> = sqlx::query_as(
        r#"
        SELECT AVG(resolution_hours)
        FROM finding_resolutions
        WHERE user_id = ?1
          AND resolved_at IS NOT NULL
          AND resolved_at > ?2
          AND resolved_at <= ?3
        "#,
    )
    .bind(user_id)
    .bind(&previous_cutoff_start)
    .bind(&previous_cutoff_end)
    .fetch_optional(pool)
    .await?;

    let mut breakdown = MttrBreakdown {
        mttr_critical,
        mttr_high,
        mttr_medium,
        mttr_low,
        overall_mttr: None,
        period_days: days as u32,
        sample_size_critical: sample_critical,
        sample_size_high: sample_high,
        sample_size_medium: sample_medium,
        sample_size_low: sample_low,
        trend: TrendDirection::Stable,
        previous_mttr: previous_mttr.and_then(|(avg,)| avg),
    };

    breakdown.overall_mttr = breakdown.calculate_overall();

    // Calculate trend
    if let (Some(current), Some(previous)) = (breakdown.overall_mttr, breakdown.previous_mttr) {
        let change_pct = calculate_change_pct(previous, current);
        breakdown.trend = TrendDirection::from_change_lower_is_better(change_pct);
    }

    Ok(breakdown)
}

// ============================================================================
// Security Coverage Operations
// ============================================================================

/// Get security coverage for a user/project
pub async fn get_security_coverage(
    pool: &SqlitePool,
    user_id: &str,
    project_name: Option<&str>,
) -> Result<SecurityCoverage> {
    let row: Option<SecurityCoverageRow> = if let Some(project) = project_name {
        sqlx::query_as(
            "SELECT * FROM security_coverage WHERE user_id = ?1 AND project_name = ?2"
        )
        .bind(user_id)
        .bind(project)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT * FROM security_coverage WHERE user_id = ?1 AND project_name IS NULL"
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await?
    };

    match row {
        Some(r) => Ok(row_to_coverage(r)),
        None => {
            // Compute coverage from actual scan data
            compute_security_coverage(pool, user_id, project_name).await
        }
    }
}

/// Compute security coverage from actual scan data
pub async fn compute_security_coverage(
    pool: &SqlitePool,
    user_id: &str,
    _project_name: Option<&str>,
) -> Result<SecurityCoverage> {
    // Check if user has SAST scans
    let sast_scan: Option<(String,)> = sqlx::query_as(
        "SELECT created_at FROM sast_scans WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    // Check if user has SBOMs
    let sbom_scan: Option<(String,)> = sqlx::query_as(
        "SELECT created_at FROM sbom_records WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    // Check if user has API security scans
    let api_scan: Option<(String,)> = sqlx::query_as(
        "SELECT created_at FROM yt_api_security_scans WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    // Check if user has threat models
    let threat_model: Option<(String,)> = sqlx::query_as(
        "SELECT created_at FROM threat_models WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    // Check if user has container scans
    let container_scan: Option<(String,)> = sqlx::query_as(
        "SELECT created_at FROM container_scans WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    // Check if user has IaC scans
    let iac_scan: Option<(String,)> = sqlx::query_as(
        "SELECT created_at FROM iac_scans WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    // Check if user has secret scans
    let secret_scan: Option<(String,)> = sqlx::query_as(
        "SELECT created_at FROM secret_scans WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    Ok(SecurityCoverage {
        sast_enabled: sast_scan.is_some(),
        sbom_generated: sbom_scan.is_some(),
        api_security_scanned: api_scan.is_some(),
        threat_model_exists: threat_model.is_some(),
        dast_enabled: false, // Would need DAST table
        container_scanning_enabled: container_scan.is_some(),
        iac_scanning_enabled: iac_scan.is_some(),
        secret_scanning_enabled: secret_scan.is_some(),
        last_sast_scan: sast_scan.map(|(d,)| d),
        last_sbom_scan: sbom_scan.map(|(d,)| d),
        last_api_scan: api_scan.map(|(d,)| d),
        last_dast_scan: None,
        last_container_scan: container_scan.map(|(d,)| d),
        last_iac_scan: iac_scan.map(|(d,)| d),
        last_secret_scan: secret_scan.map(|(d,)| d),
    })
}

/// Update security coverage record
pub async fn update_security_coverage(
    pool: &SqlitePool,
    user_id: &str,
    project_name: Option<&str>,
    coverage: &SecurityCoverage,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO security_coverage (
            id, user_id, project_name, sast_enabled, sbom_generated,
            api_security_scanned, threat_model_exists, dast_enabled,
            container_scanning_enabled, iac_scanning_enabled, secret_scanning_enabled,
            last_sast_scan, last_sbom_scan, last_api_scan, last_dast_scan,
            last_container_scan, last_iac_scan, last_secret_scan, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
        ON CONFLICT(user_id, project_name) DO UPDATE SET
            sast_enabled = excluded.sast_enabled,
            sbom_generated = excluded.sbom_generated,
            api_security_scanned = excluded.api_security_scanned,
            threat_model_exists = excluded.threat_model_exists,
            dast_enabled = excluded.dast_enabled,
            container_scanning_enabled = excluded.container_scanning_enabled,
            iac_scanning_enabled = excluded.iac_scanning_enabled,
            secret_scanning_enabled = excluded.secret_scanning_enabled,
            last_sast_scan = excluded.last_sast_scan,
            last_sbom_scan = excluded.last_sbom_scan,
            last_api_scan = excluded.last_api_scan,
            last_dast_scan = excluded.last_dast_scan,
            last_container_scan = excluded.last_container_scan,
            last_iac_scan = excluded.last_iac_scan,
            last_secret_scan = excluded.last_secret_scan,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(project_name)
    .bind(coverage.sast_enabled)
    .bind(coverage.sbom_generated)
    .bind(coverage.api_security_scanned)
    .bind(coverage.threat_model_exists)
    .bind(coverage.dast_enabled)
    .bind(coverage.container_scanning_enabled)
    .bind(coverage.iac_scanning_enabled)
    .bind(coverage.secret_scanning_enabled)
    .bind(&coverage.last_sast_scan)
    .bind(&coverage.last_sbom_scan)
    .bind(&coverage.last_api_scan)
    .bind(&coverage.last_dast_scan)
    .bind(&coverage.last_container_scan)
    .bind(&coverage.last_iac_scan)
    .bind(&coverage.last_secret_scan)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

fn row_to_coverage(row: SecurityCoverageRow) -> SecurityCoverage {
    SecurityCoverage {
        sast_enabled: row.sast_enabled,
        sbom_generated: row.sbom_generated,
        api_security_scanned: row.api_security_scanned,
        threat_model_exists: row.threat_model_exists,
        dast_enabled: row.dast_enabled,
        container_scanning_enabled: row.container_scanning_enabled,
        iac_scanning_enabled: row.iac_scanning_enabled,
        secret_scanning_enabled: row.secret_scanning_enabled,
        last_sast_scan: row.last_sast_scan,
        last_sbom_scan: row.last_sbom_scan,
        last_api_scan: row.last_api_scan,
        last_dast_scan: row.last_dast_scan,
        last_container_scan: row.last_container_scan,
        last_iac_scan: row.last_iac_scan,
        last_secret_scan: row.last_secret_scan,
    }
}

// ============================================================================
// Security Debt Operations
// ============================================================================

/// Get security debt items (open findings with age)
pub async fn get_security_debt_items(
    pool: &SqlitePool,
    user_id: &str,
    limit: Option<i32>,
) -> Result<Vec<SecurityDebtItem>> {
    let limit = limit.unwrap_or(50);
    let now = Utc::now().to_rfc3339();

    // Query open findings from finding_resolutions
    let rows: Vec<SecurityDebtRow> = sqlx::query_as(
        r#"
        SELECT
            finding_id,
            finding_type,
            severity,
            NULL as title,
            CAST(julianday(?1) - julianday(created_at) AS INTEGER) as age_days,
            COALESCE(source, 'unknown') as source,
            project_name,
            CASE
                WHEN LOWER(severity) = 'critical' AND (julianday(?1) - julianday(created_at)) > 1 THEN 'breached'
                WHEN LOWER(severity) = 'high' AND (julianday(?1) - julianday(created_at)) > 3 THEN 'breached'
                WHEN LOWER(severity) = 'medium' AND (julianday(?1) - julianday(created_at)) > 7 THEN 'breached'
                WHEN LOWER(severity) = 'low' AND (julianday(?1) - julianday(created_at)) > 30 THEN 'breached'
                WHEN LOWER(severity) = 'critical' AND (julianday(?1) - julianday(created_at)) > 0.5 THEN 'at_risk'
                WHEN LOWER(severity) = 'high' AND (julianday(?1) - julianday(created_at)) > 2 THEN 'at_risk'
                WHEN LOWER(severity) = 'medium' AND (julianday(?1) - julianday(created_at)) > 5 THEN 'at_risk'
                WHEN LOWER(severity) = 'low' AND (julianday(?1) - julianday(created_at)) > 20 THEN 'at_risk'
                ELSE 'on_track'
            END as sla_status
        FROM finding_resolutions
        WHERE user_id = ?2
          AND resolved_at IS NULL
        ORDER BY
            CASE LOWER(severity)
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            age_days DESC
        LIMIT ?3
        "#,
    )
    .bind(&now)
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|row| {
        let severity: Severity = row.severity.parse().unwrap_or(Severity::Medium);
        let estimated_hours = match severity {
            Severity::Critical => REMEDIATION_HOURS_CRITICAL,
            Severity::High => REMEDIATION_HOURS_HIGH,
            Severity::Medium => REMEDIATION_HOURS_MEDIUM,
            Severity::Low => REMEDIATION_HOURS_LOW,
            Severity::Info => 0.5,
        };

        SecurityDebtItem {
            finding_id: row.finding_id,
            finding_type: row.finding_type,
            severity,
            title: row.title,
            age_days: row.age_days.max(0) as u32,
            estimated_hours,
            source: row.source,
            project_name: row.project_name,
            sla_status: row.sla_status.parse().unwrap_or(SlaStatus::NoSla),
        }
    }).collect())
}

/// Get security debt summary
pub async fn get_security_debt_summary(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<SecurityDebtSummary> {
    // Get counts by severity
    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            SUM(CASE WHEN LOWER(severity) = 'critical' THEN 1 ELSE 0 END),
            SUM(CASE WHEN LOWER(severity) = 'high' THEN 1 ELSE 0 END),
            SUM(CASE WHEN LOWER(severity) = 'medium' THEN 1 ELSE 0 END),
            SUM(CASE WHEN LOWER(severity) = 'low' THEN 1 ELSE 0 END)
        FROM finding_resolutions
        WHERE user_id = ?1 AND resolved_at IS NULL
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0, 0, 0, 0));

    let (critical, high, medium, low) = counts;

    // Calculate hours
    let critical_hours = critical as f64 * REMEDIATION_HOURS_CRITICAL;
    let high_hours = high as f64 * REMEDIATION_HOURS_HIGH;
    let medium_hours = medium as f64 * REMEDIATION_HOURS_MEDIUM;
    let low_hours = low as f64 * REMEDIATION_HOURS_LOW;
    let total_hours = critical_hours + high_hours + medium_hours + low_hours;

    // Get counts by source
    let source_counts: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT COALESCE(source, 'unknown'), COUNT(*)
        FROM finding_resolutions
        WHERE user_id = ?1 AND resolved_at IS NULL
        GROUP BY source
        ORDER BY COUNT(*) DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let by_source: Vec<SourceDebtBreakdown> = source_counts
        .into_iter()
        .map(|(source, count)| {
            let hours = count as f64 * REMEDIATION_HOURS_MEDIUM; // Average estimate
            let percentage = if total_hours > 0.0 { (hours / total_hours) * 100.0 } else { 0.0 };
            SourceDebtBreakdown {
                source,
                count: count as u32,
                hours,
                percentage,
            }
        })
        .collect();

    // Get top debt items
    let top_items = get_security_debt_items(pool, user_id, Some(10)).await?;

    Ok(SecurityDebtSummary {
        total_debt_hours: total_hours,
        total_debt_days: total_hours / 8.0,
        by_severity: SeverityDebtBreakdown {
            critical: DebtCategory {
                count: critical as u32,
                hours: critical_hours,
                percentage: if total_hours > 0.0 { (critical_hours / total_hours) * 100.0 } else { 0.0 },
            },
            high: DebtCategory {
                count: high as u32,
                hours: high_hours,
                percentage: if total_hours > 0.0 { (high_hours / total_hours) * 100.0 } else { 0.0 },
            },
            medium: DebtCategory {
                count: medium as u32,
                hours: medium_hours,
                percentage: if total_hours > 0.0 { (medium_hours / total_hours) * 100.0 } else { 0.0 },
            },
            low: DebtCategory {
                count: low as u32,
                hours: low_hours,
                percentage: if total_hours > 0.0 { (low_hours / total_hours) * 100.0 } else { 0.0 },
            },
        },
        by_source,
        top_items,
        trend: TrendDirection::Stable, // Would need historical data to calculate
    })
}

// ============================================================================
// Trend Operations
// ============================================================================

/// Get findings trend over time
pub async fn get_findings_trend(
    pool: &SqlitePool,
    user_id: &str,
    days: i32,
) -> Result<FindingsTrend> {
    let cutoff = (Utc::now() - Duration::days(days as i64)).to_rfc3339();

    // Get daily counts
    let rows: Vec<TrendPointRow> = sqlx::query_as(
        r#"
        SELECT
            DATE(created_at) as date,
            SUM(CASE WHEN LOWER(severity) = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN LOWER(severity) = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN LOWER(severity) = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN LOWER(severity) = 'low' THEN 1 ELSE 0 END) as low
        FROM finding_resolutions
        WHERE user_id = ?1 AND created_at > ?2
        GROUP BY DATE(created_at)
        ORDER BY date ASC
        "#,
    )
    .bind(user_id)
    .bind(&cutoff)
    .fetch_all(pool)
    .await?;

    let trend_points: Vec<TrendPoint> = rows
        .into_iter()
        .map(|row| TrendPoint {
            date: row.date,
            critical: row.critical as u32,
            high: row.high as u32,
            medium: row.medium as u32,
            low: row.low as u32,
            total: (row.critical + row.high + row.medium + row.low) as u32,
        })
        .collect();

    Ok(FindingsTrend::from_points(trend_points, days as u32))
}

/// Record a finding for trend tracking (when discovered from scans)
pub async fn record_finding_for_trends(
    pool: &SqlitePool,
    user_id: &str,
    finding_id: &str,
    finding_type: &str,
    severity: &str,
    project_name: Option<&str>,
    source: Option<&str>,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO finding_resolutions (
            id, finding_id, finding_type, severity, user_id, project_name, source, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(&id)
    .bind(finding_id)
    .bind(finding_type)
    .bind(severity)
    .bind(user_id)
    .bind(project_name)
    .bind(source)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}
