//! Organization quota management
//! Handles quota limits and usage tracking for multi-tenant organizations

use anyhow::Result;
use chrono::{DateTime, Datelike, Duration, NaiveDate, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;

/// Quota type identifiers for tracking usage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaType {
    ScansPerDay,
    ConcurrentScans,
    ReportsPerMonth,
    ApiRequestsPerHour,
    StorageMb,
    Users,
    Assets,
    ScheduledScans,
    Teams,
    Departments,
    CustomRoles,
}

impl QuotaType {
    pub fn as_str(&self) -> &'static str {
        match self {
            QuotaType::ScansPerDay => "scans_per_day",
            QuotaType::ConcurrentScans => "concurrent_scans",
            QuotaType::ReportsPerMonth => "reports_per_month",
            QuotaType::ApiRequestsPerHour => "api_requests_per_hour",
            QuotaType::StorageMb => "storage_mb",
            QuotaType::Users => "users",
            QuotaType::Assets => "assets",
            QuotaType::ScheduledScans => "scheduled_scans",
            QuotaType::Teams => "teams",
            QuotaType::Departments => "departments",
            QuotaType::CustomRoles => "custom_roles",
        }
    }

    /// Get the period duration for this quota type
    pub fn period_duration(&self) -> Option<Duration> {
        match self {
            QuotaType::ScansPerDay => Some(Duration::days(1)),
            QuotaType::ReportsPerMonth => Some(Duration::days(30)),
            QuotaType::ApiRequestsPerHour => Some(Duration::hours(1)),
            // These don't have time periods - they're absolute limits
            QuotaType::ConcurrentScans
            | QuotaType::StorageMb
            | QuotaType::Users
            | QuotaType::Assets
            | QuotaType::ScheduledScans
            | QuotaType::Teams
            | QuotaType::Departments
            | QuotaType::CustomRoles => None,
        }
    }

    /// Check if this quota type is periodic (resets over time)
    pub fn is_periodic(&self) -> bool {
        self.period_duration().is_some()
    }
}

impl std::str::FromStr for QuotaType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "scans_per_day" => Ok(QuotaType::ScansPerDay),
            "concurrent_scans" => Ok(QuotaType::ConcurrentScans),
            "reports_per_month" => Ok(QuotaType::ReportsPerMonth),
            "api_requests_per_hour" => Ok(QuotaType::ApiRequestsPerHour),
            "storage_mb" => Ok(QuotaType::StorageMb),
            "users" => Ok(QuotaType::Users),
            "assets" => Ok(QuotaType::Assets),
            "scheduled_scans" => Ok(QuotaType::ScheduledScans),
            "teams" => Ok(QuotaType::Teams),
            "departments" => Ok(QuotaType::Departments),
            "custom_roles" => Ok(QuotaType::CustomRoles),
            _ => Err(anyhow::anyhow!("Unknown quota type: {}", s)),
        }
    }
}

/// Organization quota limits
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OrganizationQuotas {
    pub id: String,
    pub organization_id: String,
    pub max_users: i64,
    pub max_scans_per_day: i64,
    pub max_concurrent_scans: i64,
    pub max_assets: i64,
    pub max_reports_per_month: i64,
    pub max_storage_mb: i64,
    pub max_api_requests_per_hour: i64,
    pub max_scheduled_scans: i64,
    pub max_teams: i64,
    pub max_departments: i64,
    pub max_custom_roles: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Quota usage record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct QuotaUsage {
    pub id: String,
    pub organization_id: String,
    pub quota_type: String,
    pub current_value: i64,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to update organization quotas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateQuotasRequest {
    pub max_users: Option<i64>,
    pub max_scans_per_day: Option<i64>,
    pub max_concurrent_scans: Option<i64>,
    pub max_assets: Option<i64>,
    pub max_reports_per_month: Option<i64>,
    pub max_storage_mb: Option<i64>,
    pub max_api_requests_per_hour: Option<i64>,
    pub max_scheduled_scans: Option<i64>,
    pub max_teams: Option<i64>,
    pub max_departments: Option<i64>,
    pub max_custom_roles: Option<i64>,
}

/// Quota usage summary for an organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaUsageSummary {
    pub organization_id: String,
    pub quotas: OrganizationQuotas,
    pub usage: Vec<QuotaUsageItem>,
}

/// Individual quota usage item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaUsageItem {
    pub quota_type: String,
    pub limit: i64,
    pub current: i64,
    pub percentage: f64,
    pub period_start: Option<DateTime<Utc>>,
    pub period_end: Option<DateTime<Utc>>,
    pub is_exceeded: bool,
}

/// Result of a quota check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaCheckResult {
    pub allowed: bool,
    pub quota_type: String,
    pub limit: i64,
    pub current: i64,
    pub remaining: i64,
    pub message: Option<String>,
}

// ============================================================================
// Quota Management Functions
// ============================================================================

/// Get quotas for an organization
pub async fn get_org_quotas(
    pool: &SqlitePool,
    organization_id: &str,
) -> Result<Option<OrganizationQuotas>> {
    let quotas = sqlx::query_as::<_, OrganizationQuotas>(
        "SELECT * FROM organization_quotas WHERE organization_id = ?1",
    )
    .bind(organization_id)
    .fetch_optional(pool)
    .await?;

    Ok(quotas)
}

/// Create default quotas for an organization
pub async fn create_default_quotas(
    pool: &SqlitePool,
    organization_id: &str,
) -> Result<OrganizationQuotas> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let quotas = sqlx::query_as::<_, OrganizationQuotas>(
        r#"
        INSERT INTO organization_quotas (
            id, organization_id, max_users, max_scans_per_day, max_concurrent_scans,
            max_assets, max_reports_per_month, max_storage_mb, max_api_requests_per_hour,
            max_scheduled_scans, max_teams, max_departments, max_custom_roles,
            created_at, updated_at
        )
        VALUES (?1, ?2, 10, 50, 5, 1000, 100, 5120, 1000, 20, 10, 5, 10, ?3, ?3)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(organization_id)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(quotas)
}

/// Update quotas for an organization (owner only)
pub async fn update_org_quotas(
    pool: &SqlitePool,
    organization_id: &str,
    request: &UpdateQuotasRequest,
) -> Result<OrganizationQuotas> {
    let now = Utc::now();

    // Build dynamic update query
    let mut updates = Vec::new();
    let mut params: Vec<Box<dyn sqlx::Encode<'_, sqlx::Sqlite> + Send + Sync>> = Vec::new();

    if let Some(v) = request.max_users {
        updates.push("max_users = ?");
        params.push(Box::new(v));
    }
    if let Some(v) = request.max_scans_per_day {
        updates.push("max_scans_per_day = ?");
        params.push(Box::new(v));
    }
    if let Some(v) = request.max_concurrent_scans {
        updates.push("max_concurrent_scans = ?");
        params.push(Box::new(v));
    }
    if let Some(v) = request.max_assets {
        updates.push("max_assets = ?");
        params.push(Box::new(v));
    }
    if let Some(v) = request.max_reports_per_month {
        updates.push("max_reports_per_month = ?");
        params.push(Box::new(v));
    }
    if let Some(v) = request.max_storage_mb {
        updates.push("max_storage_mb = ?");
        params.push(Box::new(v));
    }
    if let Some(v) = request.max_api_requests_per_hour {
        updates.push("max_api_requests_per_hour = ?");
        params.push(Box::new(v));
    }
    if let Some(v) = request.max_scheduled_scans {
        updates.push("max_scheduled_scans = ?");
        params.push(Box::new(v));
    }
    if let Some(v) = request.max_teams {
        updates.push("max_teams = ?");
        params.push(Box::new(v));
    }
    if let Some(v) = request.max_departments {
        updates.push("max_departments = ?");
        params.push(Box::new(v));
    }
    if let Some(v) = request.max_custom_roles {
        updates.push("max_custom_roles = ?");
        params.push(Box::new(v));
    }

    // Use a simpler approach - update all fields that are Some
    let quotas = sqlx::query_as::<_, OrganizationQuotas>(
        r#"
        UPDATE organization_quotas SET
            max_users = COALESCE(?1, max_users),
            max_scans_per_day = COALESCE(?2, max_scans_per_day),
            max_concurrent_scans = COALESCE(?3, max_concurrent_scans),
            max_assets = COALESCE(?4, max_assets),
            max_reports_per_month = COALESCE(?5, max_reports_per_month),
            max_storage_mb = COALESCE(?6, max_storage_mb),
            max_api_requests_per_hour = COALESCE(?7, max_api_requests_per_hour),
            max_scheduled_scans = COALESCE(?8, max_scheduled_scans),
            max_teams = COALESCE(?9, max_teams),
            max_departments = COALESCE(?10, max_departments),
            max_custom_roles = COALESCE(?11, max_custom_roles),
            updated_at = ?12
        WHERE organization_id = ?13
        RETURNING *
        "#,
    )
    .bind(request.max_users)
    .bind(request.max_scans_per_day)
    .bind(request.max_concurrent_scans)
    .bind(request.max_assets)
    .bind(request.max_reports_per_month)
    .bind(request.max_storage_mb)
    .bind(request.max_api_requests_per_hour)
    .bind(request.max_scheduled_scans)
    .bind(request.max_teams)
    .bind(request.max_departments)
    .bind(request.max_custom_roles)
    .bind(now)
    .bind(organization_id)
    .fetch_one(pool)
    .await?;

    Ok(quotas)
}

/// Check if a quota allows an operation
pub async fn check_quota(
    pool: &SqlitePool,
    organization_id: &str,
    quota_type: QuotaType,
) -> Result<QuotaCheckResult> {
    // Get quota limits
    let quotas = get_org_quotas(pool, organization_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Organization quotas not found"))?;

    let limit = get_quota_limit(&quotas, quota_type);
    let current = get_current_usage(pool, organization_id, quota_type).await?;

    let allowed = current < limit;
    let remaining = (limit - current).max(0);

    Ok(QuotaCheckResult {
        allowed,
        quota_type: quota_type.as_str().to_string(),
        limit,
        current,
        remaining,
        message: if !allowed {
            Some(format!(
                "Quota exceeded: {} limit is {}, current usage is {}",
                quota_type.as_str(),
                limit,
                current
            ))
        } else {
            None
        },
    })
}

/// Get current usage for a quota type
pub async fn get_current_usage(
    pool: &SqlitePool,
    organization_id: &str,
    quota_type: QuotaType,
) -> Result<i64> {
    if quota_type.is_periodic() {
        // Get usage from the quota_usage table for the current period
        let (period_start, period_end) = get_current_period(quota_type);

        let usage: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT current_value FROM organization_quota_usage
            WHERE organization_id = ?1 AND quota_type = ?2
            AND period_start = ?3 AND period_end = ?4
            "#,
        )
        .bind(organization_id)
        .bind(quota_type.as_str())
        .bind(period_start)
        .bind(period_end)
        .fetch_optional(pool)
        .await?;

        Ok(usage.map(|(v,)| v).unwrap_or(0))
    } else {
        // For non-periodic quotas, count actual resources
        let count = match quota_type {
            QuotaType::Users => count_org_users(pool, organization_id).await?,
            QuotaType::Assets => count_org_assets(pool, organization_id).await?,
            QuotaType::ScheduledScans => count_org_scheduled_scans(pool, organization_id).await?,
            QuotaType::Teams => count_org_teams(pool, organization_id).await?,
            QuotaType::Departments => count_org_departments(pool, organization_id).await?,
            QuotaType::CustomRoles => count_org_custom_roles(pool, organization_id).await?,
            QuotaType::ConcurrentScans => count_concurrent_scans(pool, organization_id).await?,
            QuotaType::StorageMb => get_storage_usage(pool, organization_id).await?,
            _ => 0,
        };
        Ok(count)
    }
}

/// Increment usage for a periodic quota
pub async fn increment_quota_usage(
    pool: &SqlitePool,
    organization_id: &str,
    quota_type: QuotaType,
    amount: i64,
) -> Result<()> {
    if !quota_type.is_periodic() {
        return Ok(()); // Non-periodic quotas don't need explicit tracking
    }

    let (period_start, period_end) = get_current_period(quota_type);
    let now = Utc::now();
    let id = Uuid::new_v4().to_string();

    // Upsert the usage record
    sqlx::query(
        r#"
        INSERT INTO organization_quota_usage (id, organization_id, quota_type, current_value, period_start, period_end, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(organization_id, quota_type, period_start) DO UPDATE SET
            current_value = current_value + ?4,
            updated_at = ?7
        "#,
    )
    .bind(&id)
    .bind(organization_id)
    .bind(quota_type.as_str())
    .bind(amount)
    .bind(period_start)
    .bind(period_end)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Decrement usage for a periodic quota (e.g., when a scan is cancelled)
pub async fn decrement_quota_usage(
    pool: &SqlitePool,
    organization_id: &str,
    quota_type: QuotaType,
    amount: i64,
) -> Result<()> {
    if !quota_type.is_periodic() {
        return Ok(());
    }

    let (period_start, _period_end) = get_current_period(quota_type);
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE organization_quota_usage
        SET current_value = MAX(0, current_value - ?1), updated_at = ?2
        WHERE organization_id = ?3 AND quota_type = ?4 AND period_start = ?5
        "#,
    )
    .bind(amount)
    .bind(now)
    .bind(organization_id)
    .bind(quota_type.as_str())
    .bind(period_start)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get quota usage summary for an organization
pub async fn get_quota_usage_summary(
    pool: &SqlitePool,
    organization_id: &str,
) -> Result<QuotaUsageSummary> {
    let quotas = get_org_quotas(pool, organization_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Organization quotas not found"))?;

    let quota_types = [
        QuotaType::ScansPerDay,
        QuotaType::ConcurrentScans,
        QuotaType::ReportsPerMonth,
        QuotaType::ApiRequestsPerHour,
        QuotaType::StorageMb,
        QuotaType::Users,
        QuotaType::Assets,
        QuotaType::ScheduledScans,
        QuotaType::Teams,
        QuotaType::Departments,
        QuotaType::CustomRoles,
    ];

    let mut usage = Vec::new();

    for qt in quota_types {
        let limit = get_quota_limit(&quotas, qt);
        let current = get_current_usage(pool, organization_id, qt).await.unwrap_or(0);
        let percentage = if limit > 0 {
            (current as f64 / limit as f64) * 100.0
        } else {
            0.0
        };

        let (period_start, period_end) = if qt.is_periodic() {
            let (start, end) = get_current_period(qt);
            (Some(start), Some(end))
        } else {
            (None, None)
        };

        usage.push(QuotaUsageItem {
            quota_type: qt.as_str().to_string(),
            limit,
            current,
            percentage,
            period_start,
            period_end,
            is_exceeded: current >= limit,
        });
    }

    Ok(QuotaUsageSummary {
        organization_id: organization_id.to_string(),
        quotas,
        usage,
    })
}

/// Reset periodic quotas (called by scheduler)
pub async fn reset_expired_quotas(pool: &SqlitePool) -> Result<i64> {
    let now = Utc::now();

    // Delete expired quota usage records
    let result = sqlx::query(
        "DELETE FROM organization_quota_usage WHERE period_end < ?1",
    )
    .bind(now)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() as i64)
}

// ============================================================================
// Helper Functions
// ============================================================================

fn get_quota_limit(quotas: &OrganizationQuotas, quota_type: QuotaType) -> i64 {
    match quota_type {
        QuotaType::ScansPerDay => quotas.max_scans_per_day,
        QuotaType::ConcurrentScans => quotas.max_concurrent_scans,
        QuotaType::ReportsPerMonth => quotas.max_reports_per_month,
        QuotaType::ApiRequestsPerHour => quotas.max_api_requests_per_hour,
        QuotaType::StorageMb => quotas.max_storage_mb,
        QuotaType::Users => quotas.max_users,
        QuotaType::Assets => quotas.max_assets,
        QuotaType::ScheduledScans => quotas.max_scheduled_scans,
        QuotaType::Teams => quotas.max_teams,
        QuotaType::Departments => quotas.max_departments,
        QuotaType::CustomRoles => quotas.max_custom_roles,
    }
}

fn get_current_period(quota_type: QuotaType) -> (DateTime<Utc>, DateTime<Utc>) {
    let now = Utc::now();

    match quota_type {
        QuotaType::ScansPerDay => {
            // Day starts at midnight UTC
            let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
            let end = start + chrono::Duration::days(1);
            (
                DateTime::from_naive_utc_and_offset(start, Utc),
                DateTime::from_naive_utc_and_offset(end, Utc),
            )
        }
        QuotaType::ReportsPerMonth => {
            // Month starts on the 1st
            let start = NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap();
            let end = if now.month() == 12 {
                NaiveDate::from_ymd_opt(now.year() + 1, 1, 1)
            } else {
                NaiveDate::from_ymd_opt(now.year(), now.month() + 1, 1)
            }
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
            (
                DateTime::from_naive_utc_and_offset(start, Utc),
                DateTime::from_naive_utc_and_offset(end, Utc),
            )
        }
        QuotaType::ApiRequestsPerHour => {
            // Hour starts at the top of the hour
            let start = now.date_naive().and_hms_opt(now.hour(), 0, 0).unwrap();
            let end = start + chrono::Duration::hours(1);
            (
                DateTime::from_naive_utc_and_offset(start, Utc),
                DateTime::from_naive_utc_and_offset(end, Utc),
            )
        }
        _ => {
            // Non-periodic - return arbitrary period
            (now, now)
        }
    }
}

// Resource counting functions

async fn count_org_users(pool: &SqlitePool, organization_id: &str) -> Result<i64> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM user_organizations WHERE organization_id = ?1",
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await?;
    Ok(count.0)
}

async fn count_org_assets(pool: &SqlitePool, organization_id: &str) -> Result<i64> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM assets WHERE organization_id = ?1",
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await?;
    Ok(count.0)
}

async fn count_org_scheduled_scans(pool: &SqlitePool, organization_id: &str) -> Result<i64> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM scheduled_scans WHERE organization_id = ?1 AND is_active = 1",
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await?;
    Ok(count.0)
}

async fn count_org_teams(pool: &SqlitePool, organization_id: &str) -> Result<i64> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM teams WHERE department_id IN (SELECT id FROM departments WHERE organization_id = ?1)",
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await?;
    Ok(count.0)
}

async fn count_org_departments(pool: &SqlitePool, organization_id: &str) -> Result<i64> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM departments WHERE organization_id = ?1",
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await?;
    Ok(count.0)
}

async fn count_org_custom_roles(pool: &SqlitePool, organization_id: &str) -> Result<i64> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM custom_roles WHERE organization_id = ?1",
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await?;
    Ok(count.0)
}

async fn count_concurrent_scans(pool: &SqlitePool, organization_id: &str) -> Result<i64> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM scan_results WHERE organization_id = ?1 AND status = 'running'",
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await?;
    Ok(count.0)
}

async fn get_storage_usage(_pool: &SqlitePool, _organization_id: &str) -> Result<i64> {
    // TODO: Implement actual storage calculation
    // This would sum up report file sizes, scan result sizes, etc.
    Ok(0)
}
