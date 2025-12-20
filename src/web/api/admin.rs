use actix_web::{web, HttpRequest, HttpResponse, Result};
use sqlx::SqlitePool;
use uuid::Uuid;
use chrono::Utc;

use crate::db::{self, models};
use crate::web::auth;
use crate::web::rate_limit_stats;

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract client IP address from request headers or peer address
fn get_client_ip(req: &HttpRequest) -> Option<String> {
    // Check X-Forwarded-For header first (for reverse proxy)
    if let Some(forwarded) = req.headers().get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            // Take the first IP in the chain
            if let Some(ip) = forwarded_str.split(',').next() {
                return Some(ip.trim().to_string());
            }
        }
    }
    // Check X-Real-IP header
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        if let Ok(ip_str) = real_ip.to_str() {
            return Some(ip_str.to_string());
        }
    }
    // Fall back to peer address
    req.peer_addr().map(|addr| addr.ip().to_string())
}

// ============================================================================
// User Management Endpoints
// ============================================================================

pub async fn list_users(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "manage_users").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    match db::get_all_users(&pool).await {
        Ok(users) => {
            // For each user, fetch their roles and lockout status
            let mut users_with_roles = Vec::new();
            let now = chrono::Utc::now();

            for user in users {
                let roles = db::get_user_roles(&pool, &user.id).await.unwrap_or_default();
                let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

                // Check lockout status
                let lockout = db::get_user_lockout_status(&pool, &user.username).await.ok().flatten();
                let is_locked = lockout.as_ref().map(|l| l.locked_until > now).unwrap_or(false);
                let locked_until = if is_locked { lockout.as_ref().map(|l| l.locked_until) } else { None };
                let failed_attempts = lockout.as_ref().map(|l| l.attempt_count).unwrap_or(0);

                users_with_roles.push(serde_json::json!({
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "is_active": user.is_active,
                    "created_at": user.created_at,
                    "roles": role_names,
                    "is_locked": is_locked,
                    "locked_until": locked_until,
                    "failed_attempts": failed_attempts
                }));
            }

            Ok(HttpResponse::Ok().json(users_with_roles))
        }
        Err(e) => {
            log::error!("Database error in list_users: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "An internal error occurred. Please try again later."
            })))
        },
    }
}

pub async fn get_user(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    user_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "manage_users").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    match sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE id = ?1")
        .bind(user_id.as_str())
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(user)) => {
            let roles = db::get_user_roles(&pool, &user.id).await.unwrap_or_default();
            let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "is_active": user.is_active,
                "created_at": user.created_at,
                "roles": role_names
            })))
        }
        Ok(None) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "User not found"
        }))),
        Err(e) => {
            log::error!("Database error in get_user: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "An internal error occurred. Please try again later."
            })))
        },
    }
}

pub async fn update_user(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    user_id: web::Path<String>,
    updates: web::Json<models::UpdateUserRequest>,
    req: HttpRequest,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "manage_users").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    match db::update_user(&pool, &user_id, &updates).await {
        Ok(user) => {
            // Log audit
            let log = models::AuditLog {
                id: Uuid::new_v4().to_string(),
                user_id: claims.sub.clone(),
                action: "user.update".to_string(),
                target_type: Some("user".to_string()),
                target_id: Some(user.id.clone()),
                details: Some(serde_json::to_string(&updates.into_inner()).unwrap_or_default()),
                ip_address: get_client_ip(&req),
                user_agent: req.headers().get("User-Agent").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
                created_at: Utc::now(),
            };
            let _ = db::create_audit_log(&pool, &log).await;

            Ok(HttpResponse::Ok().json(user))
        }
        Err(e) => {
            log::error!("Failed to update user: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Update failed. Please try again."
            })))
        },
    }
}

pub async fn delete_user(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    user_id: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "manage_users").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    // Prevent self-deletion
    if claims.sub == *user_id {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Cannot delete your own account"
        })));
    }

    match db::delete_user(&pool, &user_id).await {
        Ok(_) => {
            // Log audit
            let log = models::AuditLog {
                id: Uuid::new_v4().to_string(),
                user_id: claims.sub.clone(),
                action: "user.delete".to_string(),
                target_type: Some("user".to_string()),
                target_id: Some(user_id.to_string()),
                details: None,
                ip_address: get_client_ip(&req),
                user_agent: req.headers().get("User-Agent").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
                created_at: Utc::now(),
            };
            let _ = db::create_audit_log(&pool, &log).await;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "User deleted successfully"
            })))
        }
        Err(e) => {
            log::error!("Failed to delete user: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Delete failed. Please try again."
            })))
        },
    }
}

pub async fn assign_role(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    user_id: web::Path<String>,
    role_data: web::Json<models::AssignRoleRequest>,
    req: HttpRequest,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "manage_users").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    match db::assign_role_to_user(&pool, &user_id, &role_data.role_id, &claims.sub).await {
        Ok(_) => {
            // Log audit
            let log = models::AuditLog {
                id: Uuid::new_v4().to_string(),
                user_id: claims.sub.clone(),
                action: "role.assign".to_string(),
                target_type: Some("user".to_string()),
                target_id: Some(user_id.to_string()),
                details: Some(serde_json::to_string(&role_data.into_inner()).unwrap_or_default()),
                ip_address: get_client_ip(&req),
                user_agent: req.headers().get("User-Agent").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
                created_at: Utc::now(),
            };
            let _ = db::create_audit_log(&pool, &log).await;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "Role assigned successfully"
            })))
        }
        Err(e) => {
            log::error!("Failed to assign role: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to assign role. Please try again."
            })))
        },
    }
}

pub async fn remove_role(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<(String, String)>,
    req: HttpRequest,
) -> Result<HttpResponse> {
    let (user_id, role_id) = path.into_inner();

    // Check permission
    if !db::has_permission(&pool, &claims.sub, "manage_users").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    // Prevent removing own admin role
    if claims.sub == user_id && role_id == "admin" {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Cannot remove your own admin role"
        })));
    }

    match db::remove_role_from_user(&pool, &user_id, &role_id).await {
        Ok(_) => {
            // Log audit
            let log = models::AuditLog {
                id: Uuid::new_v4().to_string(),
                user_id: claims.sub.clone(),
                action: "role.remove".to_string(),
                target_type: Some("user".to_string()),
                target_id: Some(user_id),
                details: Some(role_id),
                ip_address: get_client_ip(&req),
                user_agent: req.headers().get("User-Agent").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
                created_at: Utc::now(),
            };
            let _ = db::create_audit_log(&pool, &log).await;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "Role removed successfully"
            })))
        }
        Err(e) => {
            log::error!("Failed to remove role: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to remove role. Please try again."
            })))
        },
    }
}

// ============================================================================
// Account Lockout Management
// ============================================================================

pub async fn unlock_user(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    user_id: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "manage_users").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    // Get the user to find their username
    let user = match sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE id = ?1")
        .bind(user_id.as_str())
        .fetch_optional(pool.get_ref())
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            })));
        }
        Err(e) => {
            log::error!("Database error finding user: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to find user"
            })));
        }
    };

    // Unlock the account
    match db::unlock_user_account(&pool, &user.username).await {
        Ok(_) => {
            // Log audit
            let log = models::AuditLog {
                id: Uuid::new_v4().to_string(),
                user_id: claims.sub.clone(),
                action: "user.unlock".to_string(),
                target_type: Some("user".to_string()),
                target_id: Some(user_id.to_string()),
                details: Some(format!("Unlocked account for user: {}", user.username)),
                ip_address: get_client_ip(&req),
                user_agent: req.headers().get("User-Agent").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
                created_at: Utc::now(),
            };
            let _ = db::create_audit_log(&pool, &log).await;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "Account unlocked successfully"
            })))
        }
        Err(e) => {
            log::error!("Failed to unlock user account: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to unlock account"
            })))
        }
    }
}

pub async fn get_locked_accounts(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "manage_users").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    match db::get_all_locked_accounts(&pool).await {
        Ok(lockouts) => Ok(HttpResponse::Ok().json(lockouts)),
        Err(e) => {
            log::error!("Database error in get_locked_accounts: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get locked accounts"
            })))
        }
    }
}

// ============================================================================
// Scan Management Endpoints
// ============================================================================

pub async fn list_all_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "view_all_scans").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    match db::get_all_scans(&pool).await {
        Ok(scans) => Ok(HttpResponse::Ok().json(scans)),
        Err(e) => {
            log::error!("Database error in list_all_scans: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "An internal error occurred. Please try again later."
            })))
        },
    }
}

pub async fn delete_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "delete_any_scan").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    match db::delete_scan_admin(&pool, &scan_id).await {
        Ok(_) => {
            // Log audit
            let log = models::AuditLog {
                id: Uuid::new_v4().to_string(),
                user_id: claims.sub.clone(),
                action: "scan.delete".to_string(),
                target_type: Some("scan".to_string()),
                target_id: Some(scan_id.to_string()),
                details: None,
                ip_address: get_client_ip(&req),
                user_agent: req.headers().get("User-Agent").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
                created_at: Utc::now(),
            };
            let _ = db::create_audit_log(&pool, &log).await;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "Scan deleted successfully"
            })))
        }
        Err(e) => {
            log::error!("Failed to delete scan: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Delete failed. Please try again."
            })))
        },
    }
}

// ============================================================================
// Audit Log Endpoints
// ============================================================================

/// Query parameters for audit log filtering
#[derive(Debug, serde::Deserialize)]
pub struct AuditLogQuery {
    pub user_id: Option<String>,
    pub action: Option<String>,
    pub target_type: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Get filtered and paginated audit logs with user information
pub async fn get_audit_logs(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<AuditLogQuery>,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "view_audit_logs").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    // Parse date strings to DateTime
    let start_date = query.start_date.as_ref().and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    });

    let end_date = query.end_date.as_ref().and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    });

    let filter = models::AuditLogFilter {
        user_id: query.user_id.clone(),
        action: query.action.clone(),
        target_type: query.target_type.clone(),
        start_date,
        end_date,
        limit: query.limit,
        offset: query.offset,
    };

    match db::get_audit_logs_filtered(&pool, &filter).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            log::error!("Database error in get_audit_logs: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "An internal error occurred. Please try again later."
            })))
        },
    }
}

/// Get distinct action types for filtering dropdown
pub async fn get_audit_action_types(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "view_audit_logs").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    match db::get_audit_action_types(&pool).await {
        Ok(actions) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "actions": actions
        }))),
        Err(e) => {
            log::error!("Database error in get_audit_action_types: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "An internal error occurred. Please try again later."
            })))
        },
    }
}

/// Get users who have audit log entries for filtering dropdown
pub async fn get_audit_users(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "view_audit_logs").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    match db::get_audit_users(&pool).await {
        Ok(users) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "users": users
        }))),
        Err(e) => {
            log::error!("Database error in get_audit_users: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "An internal error occurred. Please try again later."
            })))
        },
    }
}

/// Export audit logs as CSV
pub async fn export_audit_logs(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<AuditLogQuery>,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "view_audit_logs").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    // Parse date strings to DateTime
    let start_date = query.start_date.as_ref().and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    });

    let end_date = query.end_date.as_ref().and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    });

    // Get all matching logs (no pagination for export)
    let filter = models::AuditLogFilter {
        user_id: query.user_id.clone(),
        action: query.action.clone(),
        target_type: query.target_type.clone(),
        start_date,
        end_date,
        limit: Some(10000), // Cap at 10000 records for export
        offset: Some(0),
    };

    match db::get_audit_logs_filtered(&pool, &filter).await {
        Ok(response) => {
            // Build CSV content
            let mut csv = String::from("Timestamp,User,Action,Resource Type,Resource ID,IP Address,User Agent,Details\n");

            for log in response.logs {
                let details = log.details
                    .map(|d| d.replace('"', "'").replace('\n', " "))
                    .unwrap_or_default();

                csv.push_str(&format!(
                    "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                    log.created_at.to_rfc3339(),
                    log.username,
                    log.action,
                    log.target_type.unwrap_or_default(),
                    log.target_id.unwrap_or_default(),
                    log.ip_address.unwrap_or_default(),
                    log.user_agent.unwrap_or_default().replace('"', "'"),
                    details,
                ));
            }

            let filename = format!("audit_logs_{}.csv", chrono::Utc::now().format("%Y%m%d_%H%M%S"));

            Ok(HttpResponse::Ok()
                .content_type("text/csv")
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .body(csv))
        }
        Err(e) => {
            log::error!("Database error in export_audit_logs: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "An internal error occurred. Please try again later."
            })))
        },
    }
}

// ============================================================================
// System Settings Endpoints
// ============================================================================

pub async fn list_settings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "manage_settings").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    match db::get_all_settings(&pool).await {
        Ok(settings) => Ok(HttpResponse::Ok().json(settings)),
        Err(e) => {
            log::error!("Database error in list_settings: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "An internal error occurred. Please try again later."
            })))
        },
    }
}

pub async fn update_setting(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    key: web::Path<String>,
    update_data: web::Json<models::UpdateSettingRequest>,
    req: HttpRequest,
) -> Result<HttpResponse> {
    // Check permission
    if !db::has_permission(&pool, &claims.sub, "manage_settings").await.unwrap_or(false) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    match db::update_setting(&pool, &key, &update_data.value, &claims.sub).await {
        Ok(_) => {
            // Log audit
            let log = models::AuditLog {
                id: Uuid::new_v4().to_string(),
                user_id: claims.sub.clone(),
                action: "setting.update".to_string(),
                target_type: Some("setting".to_string()),
                target_id: Some(key.to_string()),
                details: Some(serde_json::to_string(&update_data.into_inner()).unwrap_or_default()),
                ip_address: get_client_ip(&req),
                user_agent: req.headers().get("User-Agent").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
                created_at: Utc::now(),
            };
            let _ = db::create_audit_log(&pool, &log).await;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "Setting updated successfully"
            })))
        }
        Err(e) => {
            log::error!("Failed to update setting: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Update failed. Please try again."
            })))
        },
    }
}

// ============================================================================
// Rate Limit Dashboard
// ============================================================================

/// Get rate limit dashboard data
pub async fn get_rate_limit_dashboard(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    // Check permission - require view_audit_logs or manage_settings
    let has_audit_perm = db::has_permission(&pool, &claims.sub, "view_audit_logs").await.unwrap_or(false);
    let has_settings_perm = db::has_permission(&pool, &claims.sub, "manage_settings").await.unwrap_or(false);

    if !has_audit_perm && !has_settings_perm {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Insufficient permissions"
        })));
    }

    let dashboard_data = rate_limit_stats::get_dashboard_data();
    Ok(HttpResponse::Ok().json(dashboard_data))
}

// ============================================================================
// Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            // User management
            .route("/users", web::get().to(list_users))
            .route("/users/{id}", web::get().to(get_user))
            .route("/users/{id}", web::patch().to(update_user))
            .route("/users/{id}", web::delete().to(delete_user))
            .route("/users/{id}/roles", web::post().to(assign_role))
            .route("/users/{id}/roles/{role_id}", web::delete().to(remove_role))
            .route("/users/{id}/unlock", web::post().to(unlock_user))

            // Account lockout management
            .route("/locked-accounts", web::get().to(get_locked_accounts))

            // Scan management
            .route("/scans", web::get().to(list_all_scans))
            .route("/scans/{id}", web::delete().to(delete_scan))

            // Audit logs
            .route("/audit-logs", web::get().to(get_audit_logs))
            .route("/audit-logs/export", web::get().to(export_audit_logs))
            .route("/audit-logs/action-types", web::get().to(get_audit_action_types))
            .route("/audit-logs/users", web::get().to(get_audit_users))

            // System settings
            .route("/settings", web::get().to(list_settings))
            .route("/settings/{key}", web::patch().to(update_setting))

            // Rate limit dashboard
            .route("/rate-limits", web::get().to(get_rate_limit_dashboard))
    );
}
