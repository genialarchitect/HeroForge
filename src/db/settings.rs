//! System settings, notifications, API keys, and SIEM integration database operations

use sqlx::sqlite::SqlitePool;
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use super::models;
use super::BCRYPT_COST;

// ============================================================================
// Audit Logging Functions
// ============================================================================

pub async fn create_audit_log(pool: &SqlitePool, log: &models::AuditLog) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO audit_logs (id, user_id, action, target_type, target_id, details, ip_address, user_agent, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(&log.id)
    .bind(&log.user_id)
    .bind(&log.action)
    .bind(&log.target_type)
    .bind(&log.target_id)
    .bind(&log.details)
    .bind(&log.ip_address)
    .bind(&log.user_agent)
    .bind(&log.created_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Convenience function to create audit log with individual fields (7 args, no user_agent)
pub async fn log_audit(
    pool: &SqlitePool,
    user_id: &str,
    action: &str,
    target_type: Option<&str>,
    target_id: Option<&str>,
    details: Option<&str>,
    ip_address: Option<&str>,
) -> Result<()> {
    log_audit_full(pool, user_id, action, target_type, target_id, details, ip_address, None).await
}

/// Convenience function to create audit log with all fields (8 args, includes user_agent)
pub async fn log_audit_full(
    pool: &SqlitePool,
    user_id: &str,
    action: &str,
    target_type: Option<&str>,
    target_id: Option<&str>,
    details: Option<&str>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<()> {
    let log = models::AuditLog {
        id: Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        action: action.to_string(),
        target_type: target_type.map(|s| s.to_string()),
        target_id: target_id.map(|s| s.to_string()),
        details: details.map(|s| s.to_string()),
        ip_address: ip_address.map(|s| s.to_string()),
        user_agent: user_agent.map(|s| s.to_string()),
        created_at: Utc::now(),
    };
    create_audit_log(pool, &log).await
}

pub async fn get_audit_logs(
    pool: &SqlitePool,
    limit: i64,
    offset: i64,
) -> Result<Vec<models::AuditLog>> {
    let logs = sqlx::query_as::<_, models::AuditLog>(
        "SELECT id, user_id, action, target_type, target_id, details, ip_address, user_agent, created_at FROM audit_logs ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(logs)
}

/// Get filtered audit logs with pagination and user information
pub async fn get_audit_logs_filtered(
    pool: &SqlitePool,
    filter: &models::AuditLogFilter,
) -> Result<models::AuditLogResponse> {
    let limit = filter.limit.unwrap_or(100);
    let offset = filter.offset.unwrap_or(0);

    // Build dynamic query for filtering
    let mut conditions = Vec::new();
    let mut params: Vec<String> = Vec::new();

    if let Some(ref user_id) = filter.user_id {
        conditions.push(format!("a.user_id = ?{}", params.len() + 1));
        params.push(user_id.clone());
    }

    if let Some(ref action) = filter.action {
        // Support prefix matching for action categories (e.g., "user" matches "user.create", "user.delete")
        conditions.push(format!("a.action LIKE ?{}", params.len() + 1));
        params.push(format!("{}%", action));
    }

    if let Some(ref target_type) = filter.target_type {
        conditions.push(format!("a.target_type = ?{}", params.len() + 1));
        params.push(target_type.clone());
    }

    if let Some(ref start_date) = filter.start_date {
        conditions.push(format!("a.created_at >= ?{}", params.len() + 1));
        params.push(start_date.to_rfc3339());
    }

    if let Some(ref end_date) = filter.end_date {
        conditions.push(format!("a.created_at <= ?{}", params.len() + 1));
        params.push(end_date.to_rfc3339());
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    // Get total count
    let count_query = format!(
        "SELECT COUNT(*) FROM audit_logs a {}",
        where_clause
    );

    // Execute count query dynamically
    let total: i64 = {
        let mut q = sqlx::query_scalar::<_, i64>(&count_query);
        for param in &params {
            q = q.bind(param);
        }
        q.fetch_one(pool).await?
    };

    // Get logs with user information
    let logs_query = format!(
        r#"
        SELECT
            a.id,
            a.user_id,
            COALESCE(u.username, 'Unknown') as username,
            a.action,
            a.target_type,
            a.target_id,
            a.details,
            a.ip_address,
            a.user_agent,
            a.created_at
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        {}
        ORDER BY a.created_at DESC
        LIMIT ?{} OFFSET ?{}
        "#,
        where_clause,
        params.len() + 1,
        params.len() + 2
    );

    // Execute logs query dynamically
    let logs: Vec<models::AuditLogWithUser> = {
        let mut q = sqlx::query_as::<_, models::AuditLogWithUser>(&logs_query);
        for param in &params {
            q = q.bind(param);
        }
        q = q.bind(limit).bind(offset);
        q.fetch_all(pool).await?
    };

    Ok(models::AuditLogResponse {
        logs,
        total,
        limit,
        offset,
    })
}

/// Get distinct action types for filtering UI
pub async fn get_audit_action_types(pool: &SqlitePool) -> Result<Vec<String>> {
    // Extract action category (e.g., "user" from "user.create")
    let actions: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT DISTINCT
            CASE
                WHEN INSTR(action, '.') > 0 THEN SUBSTR(action, 1, INSTR(action, '.') - 1)
                ELSE action
            END as action_category
        FROM audit_logs
        ORDER BY action_category
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(actions.into_iter().map(|(a,)| a).collect())
}

/// Get all users who have audit log entries (for filtering)
pub async fn get_audit_users(pool: &SqlitePool) -> Result<Vec<models::UserInfo>> {
    let users = sqlx::query_as::<_, models::UserInfo>(
        r#"
        SELECT DISTINCT u.id, u.username, u.email
        FROM audit_logs a
        INNER JOIN users u ON a.user_id = u.id
        ORDER BY u.username
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(users)
}

// ============================================================================
// System Settings Functions
// ============================================================================

pub async fn get_all_settings(pool: &SqlitePool) -> Result<Vec<models::SystemSetting>> {
    let settings = sqlx::query_as::<_, models::SystemSetting>(
        "SELECT * FROM system_settings ORDER BY key",
    )
    .fetch_all(pool)
    .await?;

    Ok(settings)
}

pub async fn get_setting(
    pool: &SqlitePool,
    key: &str,
) -> Result<Option<models::SystemSetting>> {
    let setting = sqlx::query_as::<_, models::SystemSetting>(
        "SELECT * FROM system_settings WHERE key = ?1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?;

    Ok(setting)
}

pub async fn update_setting(
    pool: &SqlitePool,
    key: &str,
    value: &str,
    updated_by: &str,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        "UPDATE system_settings SET value = ?1, updated_by = ?2, updated_at = ?3 WHERE key = ?4",
    )
    .bind(value)
    .bind(updated_by)
    .bind(now)
    .bind(key)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Notification Settings Functions
// ============================================================================

/// Get system-level notification settings (from first admin or any configured settings)
/// Used for system notifications like workflow events where there's no specific user context
pub async fn get_system_notification_settings(
    pool: &SqlitePool,
) -> Result<models::NotificationSettings> {
    // First try to find any notification settings with webhooks configured
    if let Some(settings) = sqlx::query_as::<_, models::NotificationSettings>(
        "SELECT * FROM notification_settings WHERE slack_webhook_url IS NOT NULL OR teams_webhook_url IS NOT NULL LIMIT 1",
    )
    .fetch_optional(pool)
    .await?
    {
        return Ok(settings);
    }

    // Fall back to first admin's settings
    if let Some(admin) = sqlx::query_as::<_, models::User>(
        "SELECT * FROM users WHERE roles LIKE '%admin%' LIMIT 1",
    )
    .fetch_optional(pool)
    .await?
    {
        return get_notification_settings(pool, &admin.id).await;
    }

    // If no admin, return default empty settings
    Ok(models::NotificationSettings {
        user_id: "system".to_string(),
        email_on_scan_complete: false,
        email_on_critical_vuln: false,
        email_address: String::new(),
        slack_webhook_url: None,
        teams_webhook_url: None,
        notify_on_workflow_action: Some(false),
        notify_on_sla_breach: Some(false),
        notification_email: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    })
}

/// Get notification settings for a user (creates default if not exists)
pub async fn get_notification_settings(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<models::NotificationSettings> {
    // Try to get existing settings
    if let Some(settings) = sqlx::query_as::<_, models::NotificationSettings>(
        "SELECT * FROM notification_settings WHERE user_id = ?1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    {
        return Ok(settings);
    }

    // If not exists, get user email and create default settings
    let user = sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE id = ?1")
        .bind(user_id)
        .fetch_one(pool)
        .await?;

    let now = Utc::now();
    let settings = sqlx::query_as::<_, models::NotificationSettings>(
        r#"
        INSERT INTO notification_settings (user_id, email_on_scan_complete, email_on_critical_vuln, email_address, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(false) // Default: don't send on scan complete
    .bind(true)  // Default: send on critical vulnerabilities
    .bind(&user.email)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(settings)
}

/// Update notification settings for a user
pub async fn update_notification_settings(
    pool: &SqlitePool,
    user_id: &str,
    request: &models::UpdateNotificationSettingsRequest,
) -> Result<models::NotificationSettings> {
    // Validate email if provided
    if let Some(ref email_address) = request.email_address {
        crate::email_validation::validate_email(email_address)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }

    let now = Utc::now();

    // Ensure settings exist first
    let _ = get_notification_settings(pool, user_id).await?;

    if let Some(email_on_scan_complete) = request.email_on_scan_complete {
        sqlx::query(
            "UPDATE notification_settings SET email_on_scan_complete = ?1, updated_at = ?2 WHERE user_id = ?3",
        )
        .bind(email_on_scan_complete)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(email_on_critical_vuln) = request.email_on_critical_vuln {
        sqlx::query(
            "UPDATE notification_settings SET email_on_critical_vuln = ?1, updated_at = ?2 WHERE user_id = ?3",
        )
        .bind(email_on_critical_vuln)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(email_address) = &request.email_address {
        sqlx::query(
            "UPDATE notification_settings SET email_address = ?1, updated_at = ?2 WHERE user_id = ?3",
        )
        .bind(email_address)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(ref slack_webhook_url) = request.slack_webhook_url {
        sqlx::query(
            "UPDATE notification_settings SET slack_webhook_url = ?1, updated_at = ?2 WHERE user_id = ?3",
        )
        .bind(slack_webhook_url)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(ref teams_webhook_url) = request.teams_webhook_url {
        sqlx::query(
            "UPDATE notification_settings SET teams_webhook_url = ?1, updated_at = ?2 WHERE user_id = ?3",
        )
        .bind(teams_webhook_url)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    let settings = sqlx::query_as::<_, models::NotificationSettings>(
        "SELECT * FROM notification_settings WHERE user_id = ?1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(settings)
}

// ============================================================================
// API Keys Management Functions
// ============================================================================

/// Generate a new API key with format hf_<random_32_chars>
fn generate_api_key() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let key: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    format!("hf_{}", key)
}

/// Create a new API key for a user
pub async fn create_api_key(
    pool: &SqlitePool,
    user_id: &str,
    request: &models::CreateApiKeyRequest,
) -> Result<models::CreateApiKeyResponse> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Generate API key
    let key = generate_api_key();
    let prefix = key.chars().take(8).collect::<String>();
    let key_hash = bcrypt::hash(&key, *BCRYPT_COST)?;

    // Serialize permissions to JSON
    let permissions_json = request.permissions
        .as_ref()
        .map(|p| serde_json::to_string(p).ok())
        .flatten();

    let api_key = sqlx::query_as::<_, models::ApiKey>(
        r#"
        INSERT INTO api_keys (id, user_id, name, key_hash, prefix, permissions, created_at, expires_at, is_active)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&key_hash)
    .bind(&prefix)
    .bind(&permissions_json)
    .bind(now)
    .bind(&request.expires_at)
    .bind(true)
    .fetch_one(pool)
    .await?;

    Ok(models::CreateApiKeyResponse {
        id: api_key.id,
        name: api_key.name,
        key, // Return full key only once
        prefix: api_key.prefix,
        permissions: request.permissions.clone(),
        created_at: api_key.created_at,
        expires_at: api_key.expires_at,
    })
}

/// Get all API keys for a user (without key_hash)
pub async fn get_user_api_keys(pool: &SqlitePool, user_id: &str) -> Result<Vec<models::ApiKey>> {
    let keys = sqlx::query_as::<_, models::ApiKey>(
        "SELECT * FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(keys)
}

/// Get API key by ID (for a specific user)
pub async fn get_api_key_by_id(
    pool: &SqlitePool,
    key_id: &str,
    user_id: &str,
) -> Result<Option<models::ApiKey>> {
    let key = sqlx::query_as::<_, models::ApiKey>(
        "SELECT * FROM api_keys WHERE id = ?1 AND user_id = ?2",
    )
    .bind(key_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(key)
}

/// Verify an API key and return the user_id if valid
pub async fn verify_api_key(pool: &SqlitePool, api_key: &str) -> Result<Option<String>> {
    // Get the prefix (first 8 chars)
    if api_key.len() < 8 {
        return Ok(None);
    }
    let prefix = api_key.chars().take(8).collect::<String>();

    // Find keys with matching prefix
    let keys = sqlx::query_as::<_, models::ApiKey>(
        "SELECT * FROM api_keys WHERE prefix = ?1 AND is_active = 1",
    )
    .bind(&prefix)
    .fetch_all(pool)
    .await?;

    // Check each key with bcrypt
    for key in keys {
        // Check if expired
        if let Some(expires_at) = key.expires_at {
            if expires_at < Utc::now() {
                continue;
            }
        }

        // Verify hash
        if bcrypt::verify(api_key, &key.key_hash).unwrap_or(false) {
            // Update last_used_at
            let _ = update_api_key_last_used(pool, &key.id).await;
            return Ok(Some(key.user_id));
        }
    }

    Ok(None)
}

/// Update last_used_at timestamp for an API key
async fn update_api_key_last_used(pool: &SqlitePool, key_id: &str) -> Result<()> {
    let now = Utc::now();
    sqlx::query("UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2")
        .bind(now)
        .bind(key_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update an API key (name or permissions)
pub async fn update_api_key(
    pool: &SqlitePool,
    key_id: &str,
    user_id: &str,
    request: &models::UpdateApiKeyRequest,
) -> Result<models::ApiKey> {
    let _now = Utc::now();

    if let Some(name) = &request.name {
        sqlx::query("UPDATE api_keys SET name = ?1 WHERE id = ?2 AND user_id = ?3")
            .bind(name)
            .bind(key_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    if let Some(permissions) = &request.permissions {
        let permissions_json = serde_json::to_string(permissions)?;
        sqlx::query("UPDATE api_keys SET permissions = ?1 WHERE id = ?2 AND user_id = ?3")
            .bind(&permissions_json)
            .bind(key_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    let key = sqlx::query_as::<_, models::ApiKey>(
        "SELECT * FROM api_keys WHERE id = ?1 AND user_id = ?2",
    )
    .bind(key_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(key)
}

/// Delete (revoke) an API key
pub async fn delete_api_key(pool: &SqlitePool, key_id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM api_keys WHERE id = ?1 AND user_id = ?2")
        .bind(key_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// SIEM Settings Functions
// ============================================================================

/// Get SIEM settings for a user
pub async fn get_siem_settings(pool: &SqlitePool, user_id: &str) -> Result<Vec<models::SiemSettings>> {
    let settings = sqlx::query_as::<_, models::SiemSettings>(
        "SELECT * FROM siem_settings WHERE user_id = ?1 ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(settings)
}

/// Get SIEM settings by ID
pub async fn get_siem_settings_by_id(
    pool: &SqlitePool,
    settings_id: &str,
    user_id: &str,
) -> Result<Option<models::SiemSettings>> {
    let settings = sqlx::query_as::<_, models::SiemSettings>(
        "SELECT * FROM siem_settings WHERE id = ?1 AND user_id = ?2"
    )
    .bind(settings_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(settings)
}

/// Create SIEM settings
pub async fn create_siem_settings(
    pool: &SqlitePool,
    user_id: &str,
    request: &models::CreateSiemSettingsRequest,
) -> Result<models::SiemSettings> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let settings = sqlx::query_as::<_, models::SiemSettings>(
        r#"
        INSERT INTO siem_settings (
            id, user_id, siem_type, endpoint_url, api_key, protocol,
            enabled, export_on_scan_complete, export_on_critical_vuln,
            created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.siem_type)
    .bind(&request.endpoint_url)
    .bind(&request.api_key)
    .bind(&request.protocol)
    .bind(request.enabled)
    .bind(request.export_on_scan_complete)
    .bind(request.export_on_critical_vuln)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(settings)
}

/// Update SIEM settings
pub async fn update_siem_settings(
    pool: &SqlitePool,
    settings_id: &str,
    user_id: &str,
    request: &models::UpdateSiemSettingsRequest,
) -> Result<models::SiemSettings> {
    let now = Utc::now();

    if let Some(endpoint_url) = &request.endpoint_url {
        sqlx::query(
            "UPDATE siem_settings SET endpoint_url = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4"
        )
        .bind(endpoint_url)
        .bind(now)
        .bind(settings_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(api_key) = &request.api_key {
        sqlx::query(
            "UPDATE siem_settings SET api_key = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4"
        )
        .bind(api_key)
        .bind(now)
        .bind(settings_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(protocol) = &request.protocol {
        sqlx::query(
            "UPDATE siem_settings SET protocol = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4"
        )
        .bind(protocol)
        .bind(now)
        .bind(settings_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(enabled) = request.enabled {
        sqlx::query(
            "UPDATE siem_settings SET enabled = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4"
        )
        .bind(enabled)
        .bind(now)
        .bind(settings_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(export_on_scan_complete) = request.export_on_scan_complete {
        sqlx::query(
            "UPDATE siem_settings SET export_on_scan_complete = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4"
        )
        .bind(export_on_scan_complete)
        .bind(now)
        .bind(settings_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(export_on_critical_vuln) = request.export_on_critical_vuln {
        sqlx::query(
            "UPDATE siem_settings SET export_on_critical_vuln = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4"
        )
        .bind(export_on_critical_vuln)
        .bind(now)
        .bind(settings_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    let settings = sqlx::query_as::<_, models::SiemSettings>(
        "SELECT * FROM siem_settings WHERE id = ?1 AND user_id = ?2"
    )
    .bind(settings_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(settings)
}

/// Delete SIEM settings
pub async fn delete_siem_settings(
    pool: &SqlitePool,
    settings_id: &str,
    user_id: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM siem_settings WHERE id = ?1 AND user_id = ?2"
    )
    .bind(settings_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}
