//! User-related database operations

use sqlx::sqlite::SqlitePool;
use anyhow::Result;
use chrono::Utc;

use super::models;
use super::BCRYPT_COST;

pub async fn create_user(pool: &SqlitePool, user: &models::CreateUser) -> Result<models::User> {
    crate::email_validation::validate_email(&user.email).map_err(|e| anyhow::anyhow!("{}", e))?;
    crate::password_validation::validate_password(&user.password).map_err(|e| anyhow::anyhow!("{}", e))?;
    if !user.accept_terms {
        return Err(anyhow::anyhow!("You must accept the terms and conditions to create an account"));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let password_hash = bcrypt::hash(&user.password, *BCRYPT_COST)?;
    let now = chrono::Utc::now();
    let terms_version = "1.0";
    let user = sqlx::query_as::<_, models::User>(
        r#"INSERT INTO users (id, username, email, password_hash, created_at, is_active, accepted_terms_at, terms_version, first_name, last_name) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) RETURNING *"#,
    ).bind(&id).bind(&user.username).bind(&user.email).bind(&password_hash).bind(now).bind(true).bind(now).bind(terms_version).bind(&user.first_name).bind(&user.last_name).fetch_one(pool).await?;
    Ok(user)
}

pub async fn get_user_by_username(pool: &SqlitePool, username: &str) -> Result<Option<models::User>> {
    let user = sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE username = ?1").bind(username).fetch_optional(pool).await?;
    Ok(user)
}

pub async fn get_user_by_id(pool: &SqlitePool, user_id: &str) -> Result<Option<models::User>> {
    let user = sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE id = ?1").bind(user_id).fetch_optional(pool).await?;
    Ok(user)
}

pub async fn get_user_by_email(pool: &SqlitePool, email: &str) -> Result<Option<models::User>> {
    let user = sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE email = ?1").bind(email).fetch_optional(pool).await?;
    Ok(user)
}

pub async fn update_user_profile(pool: &SqlitePool, user_id: &str, updates: &models::UpdateProfileRequest) -> Result<models::User> {
    if let Some(ref email) = updates.email {
        crate::email_validation::validate_email(email).map_err(|e| anyhow::anyhow!("{}", e))?;
    }
    let mut query = String::from("UPDATE users SET ");
    let mut params: Vec<String> = Vec::new();
    let mut set_clauses: Vec<String> = Vec::new();
    if let Some(ref email) = updates.email {
        set_clauses.push(format!("email = ?{}", params.len() + 1));
        params.push(email.clone());
    }
    if set_clauses.is_empty() {
        return get_user_by_id(pool, user_id).await?.ok_or_else(|| anyhow::anyhow!("User not found"));
    }
    query.push_str(&set_clauses.join(", "));
    query.push_str(&format!(" WHERE id = ?{} RETURNING *", params.len() + 1));
    let mut q = sqlx::query_as::<_, models::User>(&query);
    for param in &params { q = q.bind(param); }
    q = q.bind(user_id);
    let user = q.fetch_one(pool).await?;
    Ok(user)
}

pub async fn update_user_password(pool: &SqlitePool, user_id: &str, password_hash: &str) -> Result<()> {
    sqlx::query("UPDATE users SET password_hash = ?1 WHERE id = ?2").bind(password_hash).bind(user_id).execute(pool).await?;
    Ok(())
}

pub async fn delete_user(pool: &SqlitePool, user_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM users WHERE id = ?1").bind(user_id).execute(pool).await?;
    Ok(())
}

pub async fn get_user_roles(pool: &SqlitePool, user_id: &str) -> Result<Vec<models::Role>> {
    let roles = sqlx::query_as::<_, models::Role>(r#"SELECT r.* FROM roles r INNER JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = ?1"#).bind(user_id).fetch_all(pool).await?;
    Ok(roles)
}

pub async fn assign_role_to_user(pool: &SqlitePool, user_id: &str, role_id: &str, assigned_by: &str) -> Result<()> {
    let now = Utc::now();
    sqlx::query(r#"INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_at, assigned_by) VALUES (?1, ?2, ?3, ?4)"#).bind(user_id).bind(role_id).bind(now).bind(assigned_by).execute(pool).await?;
    Ok(())
}

pub async fn remove_role_from_user(pool: &SqlitePool, user_id: &str, role_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM user_roles WHERE user_id = ?1 AND role_id = ?2").bind(user_id).bind(role_id).execute(pool).await?;
    Ok(())
}

pub async fn has_permission(pool: &SqlitePool, user_id: &str, permission: &str) -> Result<bool> {
    let roles = get_user_roles(pool, user_id).await?;
    for role in roles {
        let has_perm = match permission {
            "manage_users" => role.can_manage_users,
            "manage_scans" => role.can_manage_scans,
            "view_all_scans" => role.can_view_all_scans,
            "delete_any_scan" => role.can_delete_any_scan,
            "view_audit_logs" => role.can_view_audit_logs,
            "manage_settings" => role.can_manage_settings,
            _ => false,
        };
        if has_perm { return Ok(true); }
    }
    Ok(false)
}

pub async fn get_all_users(pool: &SqlitePool) -> Result<Vec<models::User>> {
    let users = sqlx::query_as::<_, models::User>("SELECT * FROM users ORDER BY created_at DESC").fetch_all(pool).await?;
    Ok(users)
}

pub async fn update_user(pool: &SqlitePool, user_id: &str, updates: &models::UpdateUserRequest) -> Result<models::User> {
    if let Some(ref email) = updates.email {
        crate::email_validation::validate_email(email).map_err(|e| anyhow::anyhow!("{}", e))?;
    }
    if let Some(email) = &updates.email {
        sqlx::query("UPDATE users SET email = ?1 WHERE id = ?2").bind(email).bind(user_id).execute(pool).await?;
    }
    if let Some(is_active) = updates.is_active {
        sqlx::query("UPDATE users SET is_active = ?1 WHERE id = ?2").bind(is_active).bind(user_id).execute(pool).await?;
    }
    let user = sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE id = ?1").bind(user_id).fetch_one(pool).await?;
    Ok(user)
}

pub async fn accept_terms(pool: &SqlitePool, user_id: &str) -> Result<models::User> {
    let now = Utc::now();
    let terms_version = "1.0";
    let user = sqlx::query_as::<_, models::User>("UPDATE users SET accepted_terms_at = ?1, terms_version = ?2 WHERE id = ?3 RETURNING *").bind(now).bind(terms_version).bind(user_id).fetch_one(pool).await?;
    Ok(user)
}

pub async fn export_user_data(pool: &SqlitePool, user_id: &str) -> Result<models::UserDataExport> {
    let user = get_user_by_id(pool, user_id).await?.ok_or_else(|| anyhow::anyhow!("User not found"))?;
    let scans = super::scans::get_user_scans(pool, user_id).await?;
    let reports = super::scans::get_user_reports(pool, user_id).await?;
    let templates = super::scans::get_user_templates(pool, user_id).await?;
    let target_groups = super::scans::get_user_target_groups(pool, user_id).await?;
    let scheduled_scans = super::scans::get_user_scheduled_scans(pool, user_id).await?;
    let notification_settings = super::settings::get_notification_settings(pool, user_id).await.ok();
    Ok(models::UserDataExport {
        user: models::UserExportData { id: user.id, username: user.username, email: user.email, first_name: user.first_name, last_name: user.last_name, created_at: user.created_at, is_active: user.is_active, accepted_terms_at: user.accepted_terms_at, terms_version: user.terms_version },
        scans, reports, templates, target_groups, scheduled_scans, notification_settings,
    })
}

pub async fn delete_user_account(pool: &SqlitePool, user_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM reports WHERE user_id = ?1").bind(user_id).execute(pool).await?;
    sqlx::query("DELETE FROM scan_results WHERE user_id = ?1").bind(user_id).execute(pool).await?;
    sqlx::query("DELETE FROM scan_templates WHERE user_id = ?1").bind(user_id).execute(pool).await?;
    sqlx::query("DELETE FROM target_groups WHERE user_id = ?1").bind(user_id).execute(pool).await?;
    sqlx::query("DELETE FROM scheduled_scans WHERE user_id = ?1").bind(user_id).execute(pool).await?;
    sqlx::query("DELETE FROM notification_settings WHERE user_id = ?1").bind(user_id).execute(pool).await?;
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?1").bind(user_id).execute(pool).await?;
    sqlx::query("DELETE FROM user_roles WHERE user_id = ?1").bind(user_id).execute(pool).await?;
    sqlx::query("DELETE FROM users WHERE id = ?1").bind(user_id).execute(pool).await?;
    Ok(())
}
