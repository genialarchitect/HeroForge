//! Scheduled Reports Database Operations
//!
//! This module provides CRUD operations for scheduled reports that are
//! automatically generated and emailed to recipients on a schedule.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

use super::models::{ScheduledReport, CreateScheduledReportRequest, UpdateScheduledReportRequest};

/// Create a new scheduled report
pub async fn create_scheduled_report(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateScheduledReportRequest,
) -> Result<ScheduledReport> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let recipients_json = serde_json::to_string(&request.recipients)?;
    let filters_json = request.filters.as_ref().map(|f| serde_json::to_string(f)).transpose()?;

    // Calculate next run time from cron schedule
    let next_run_at = calculate_next_run_from_cron(&request.schedule)?;

    sqlx::query(
        r#"
        INSERT INTO scheduled_reports (
            id, user_id, name, description, report_type, format, schedule,
            recipients, filters, include_charts, next_run_at, is_active,
            created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&request.report_type)
    .bind(&request.format)
    .bind(&request.schedule)
    .bind(&recipients_json)
    .bind(&filters_json)
    .bind(request.include_charts.unwrap_or(true))
    .bind(next_run_at.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    get_scheduled_report_by_id(pool, &id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to retrieve created scheduled report"))
}

/// Get all scheduled reports for a user
pub async fn get_user_scheduled_reports(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<ScheduledReport>> {
    let reports = sqlx::query_as::<_, ScheduledReport>(
        r#"
        SELECT id, user_id, name, description, report_type, format, schedule,
               recipients, filters, include_charts, last_run_at, next_run_at,
               is_active, created_at, updated_at
        FROM scheduled_reports
        WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(reports)
}

/// Get a scheduled report by ID
pub async fn get_scheduled_report_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<ScheduledReport>> {
    let report = sqlx::query_as::<_, ScheduledReport>(
        r#"
        SELECT id, user_id, name, description, report_type, format, schedule,
               recipients, filters, include_charts, last_run_at, next_run_at,
               is_active, created_at, updated_at
        FROM scheduled_reports
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(report)
}

/// Update a scheduled report
pub async fn update_scheduled_report(
    pool: &SqlitePool,
    id: &str,
    request: &UpdateScheduledReportRequest,
) -> Result<ScheduledReport> {
    let existing = get_scheduled_report_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Scheduled report not found"))?;

    let now = Utc::now();
    let name = request.name.as_ref().unwrap_or(&existing.name);
    let description = request.description.clone().or(existing.description);
    let report_type = request.report_type.as_ref().unwrap_or(&existing.report_type);
    let format = request.format.as_ref().unwrap_or(&existing.format);
    let schedule = request.schedule.as_ref().unwrap_or(&existing.schedule);
    let is_active = request.is_active.unwrap_or(existing.is_active);
    let include_charts = request.include_charts.unwrap_or(existing.include_charts);

    let recipients_json = if let Some(ref recipients) = request.recipients {
        serde_json::to_string(recipients)?
    } else {
        existing.recipients.clone()
    };

    let filters_json = if let Some(ref filters) = request.filters {
        Some(serde_json::to_string(filters)?)
    } else {
        existing.filters.clone()
    };

    // Recalculate next run time if schedule changed
    let next_run_at = if request.schedule.is_some() {
        calculate_next_run_from_cron(schedule)?
    } else {
        existing.next_run_at
    };

    sqlx::query(
        r#"
        UPDATE scheduled_reports
        SET name = ?, description = ?, report_type = ?, format = ?, schedule = ?,
            recipients = ?, filters = ?, include_charts = ?, next_run_at = ?,
            is_active = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(name)
    .bind(&description)
    .bind(report_type)
    .bind(format)
    .bind(schedule)
    .bind(&recipients_json)
    .bind(&filters_json)
    .bind(include_charts)
    .bind(next_run_at.to_rfc3339())
    .bind(is_active)
    .bind(now.to_rfc3339())
    .bind(id)
    .execute(pool)
    .await?;

    get_scheduled_report_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to retrieve updated scheduled report"))
}

/// Delete a scheduled report
pub async fn delete_scheduled_report(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM scheduled_reports WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get all scheduled reports that are due to run
pub async fn get_due_scheduled_reports(pool: &SqlitePool) -> Result<Vec<ScheduledReport>> {
    let now = Utc::now();

    let reports = sqlx::query_as::<_, ScheduledReport>(
        r#"
        SELECT id, user_id, name, description, report_type, format, schedule,
               recipients, filters, include_charts, last_run_at, next_run_at,
               is_active, created_at, updated_at
        FROM scheduled_reports
        WHERE is_active = 1
          AND next_run_at <= ?
        ORDER BY next_run_at ASC
        "#,
    )
    .bind(now.to_rfc3339())
    .fetch_all(pool)
    .await?;

    Ok(reports)
}

/// Update a scheduled report after execution
pub async fn update_scheduled_report_execution(
    pool: &SqlitePool,
    id: &str,
) -> Result<()> {
    let now = Utc::now();

    // Get current schedule to calculate next run
    let report = get_scheduled_report_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Scheduled report not found"))?;

    let next_run_at = calculate_next_run_from_cron(&report.schedule)?;

    sqlx::query(
        r#"
        UPDATE scheduled_reports
        SET last_run_at = ?, next_run_at = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(now.to_rfc3339())
    .bind(next_run_at.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Calculate the next run time from a cron expression
fn calculate_next_run_from_cron(cron_expr: &str) -> Result<DateTime<Utc>> {
    use cron::Schedule;
    use std::str::FromStr;

    // Handle preset schedules
    let effective_cron = match cron_expr {
        "daily_8am" => "0 8 * * *",
        "weekly_monday_8am" => "0 8 * * 1",
        "monthly_1st_8am" => "0 8 1 * *",
        _ => cron_expr,
    };

    // cron crate expects 6-field cron (with seconds) or 7-field (with years)
    // Convert 5-field to 6-field by prepending "0" for seconds
    let cron_6field = if effective_cron.split_whitespace().count() == 5 {
        format!("0 {}", effective_cron)
    } else {
        effective_cron.to_string()
    };

    let schedule = Schedule::from_str(&cron_6field)
        .map_err(|e| anyhow::anyhow!("Invalid cron expression '{}': {}", effective_cron, e))?;

    let next = schedule
        .upcoming(Utc)
        .next()
        .ok_or_else(|| anyhow::anyhow!("Could not calculate next run time"))?;

    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_next_run_daily() {
        let result = calculate_next_run_from_cron("0 8 * * *");
        assert!(result.is_ok());
        let next_run = result.unwrap();
        assert!(next_run > Utc::now());
    }

    #[test]
    fn test_calculate_next_run_weekly() {
        let result = calculate_next_run_from_cron("0 8 * * 1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_calculate_next_run_monthly() {
        let result = calculate_next_run_from_cron("0 8 1 * *");
        assert!(result.is_ok());
    }

    #[test]
    fn test_preset_daily_8am() {
        let result = calculate_next_run_from_cron("daily_8am");
        assert!(result.is_ok());
    }
}
