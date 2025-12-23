//! Role and permission management API endpoints

use actix_web::{delete, get, post, put, web, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::db;
use crate::db::permissions::{
    AddPermissionOverrideRequest, AssignRoleRequest, CheckPermissionRequest,
    CreateCustomRoleRequest, PermissionContext, RoleType, ShareResourceRequest,
    UpdateCustomRoleRequest, OwnerType,
};
use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;

// ============================================================================
// Role Templates
// ============================================================================

/// List all role templates
#[get("/role-templates")]
pub async fn list_role_templates(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let templates = db::permissions::roles::list_role_templates(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(templates))
}

/// Get role template details
#[get("/role-templates/{id}")]
pub async fn get_role_template(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    let template = db::permissions::roles::get_role_template_info(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Role template not found".to_string()))?;

    Ok(HttpResponse::Ok().json(template))
}

/// Get role template permissions
#[get("/role-templates/{id}/permissions")]
pub async fn get_role_template_permissions(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    let permissions = db::permissions::roles::get_template_permissions(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(permissions))
}

// ============================================================================
// Custom Roles
// ============================================================================

/// Create a custom role
#[post("/organizations/{org_id}/roles")]
pub async fn create_custom_role(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    req: web::Json<CreateCustomRoleRequest>,
) -> Result<HttpResponse, ApiError> {
    let org_id = path.into_inner();

    // Verify user is admin
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    let role = db::permissions::roles::create_custom_role(
        pool.get_ref(),
        &org_id,
        &req.into_inner(),
        &claims.sub,
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "role.create",
        Some("role"),
        Some(&role.id),
        Some(&format!("Created custom role: {}", role.display_name)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Created().json(role))
}

/// List custom roles in organization
#[get("/organizations/{org_id}/roles")]
pub async fn list_custom_roles(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let org_id = path.into_inner();

    // Verify user is member
    let user_role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if user_role.is_none() {
        return Err(ApiError::not_found("Organization not found".to_string()));
    }

    let roles = db::permissions::roles::list_custom_roles(pool.get_ref(), &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(roles))
}

/// Get custom role details
#[get("/organizations/{org_id}/roles/{role_id}")]
pub async fn get_custom_role(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (org_id, role_id) = path.into_inner();

    // Verify user is member
    let user_role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if user_role.is_none() {
        return Err(ApiError::not_found("Organization not found".to_string()));
    }

    let role = db::permissions::roles::get_custom_role_by_id(pool.get_ref(), &role_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Role not found".to_string()))?;

    if role.organization_id != org_id {
        return Err(ApiError::not_found("Role not found".to_string()));
    }

    Ok(HttpResponse::Ok().json(role))
}

/// Update custom role
#[put("/organizations/{org_id}/roles/{role_id}")]
pub async fn update_custom_role(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
    req: web::Json<UpdateCustomRoleRequest>,
) -> Result<HttpResponse, ApiError> {
    let (org_id, role_id) = path.into_inner();

    // Verify user is admin
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    // Verify role belongs to org
    let existing = db::permissions::roles::get_custom_role_by_id(pool.get_ref(), &role_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Role not found".to_string()))?;

    if existing.organization_id != org_id {
        return Err(ApiError::not_found("Role not found".to_string()));
    }

    let role = db::permissions::roles::update_custom_role(pool.get_ref(), &role_id, &req.into_inner())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "role.update",
        Some("role"),
        Some(&role_id),
        Some(&format!("Updated custom role: {}", role.display_name)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Ok().json(role))
}

/// Delete custom role
#[delete("/organizations/{org_id}/roles/{role_id}")]
pub async fn delete_custom_role(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (org_id, role_id) = path.into_inner();

    // Verify user is admin
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    // Verify role belongs to org
    let existing = db::permissions::roles::get_custom_role_by_id(pool.get_ref(), &role_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Role not found".to_string()))?;

    if existing.organization_id != org_id {
        return Err(ApiError::not_found("Role not found".to_string()));
    }

    db::permissions::roles::delete_custom_role(pool.get_ref(), &role_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "role.delete",
        Some("role"),
        Some(&role_id),
        Some("Deleted custom role"),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::NoContent().finish())
}

/// Clone custom role request
#[derive(Debug, Deserialize)]
pub struct CloneRoleRequest {
    pub new_name: String,
    pub new_display_name: String,
}

/// Clone a custom role
#[post("/organizations/{org_id}/roles/{role_id}/clone")]
pub async fn clone_custom_role(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
    req: web::Json<CloneRoleRequest>,
) -> Result<HttpResponse, ApiError> {
    let (org_id, role_id) = path.into_inner();

    // Verify user is admin
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    let role = db::permissions::roles::clone_custom_role(
        pool.get_ref(),
        &role_id,
        &req.new_name,
        &req.new_display_name,
        &claims.sub,
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "role.clone",
        Some("role"),
        Some(&role.id),
        Some(&format!("Cloned role {} to {}", role_id, role.display_name)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Created().json(role))
}

// ============================================================================
// Role Assignments
// ============================================================================

/// Assign a role to a user
#[post("/users/{user_id}/roles")]
pub async fn assign_user_role(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    req: web::Json<AssignRoleRequest>,
    query: web::Query<OrgQuery>,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();
    let org_id = &query.org_id;

    // Verify requester is admin
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    let assignment = db::permissions::roles::assign_role_to_user(
        pool.get_ref(),
        &user_id,
        org_id,
        &req.into_inner(),
        Some(&claims.sub),
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "role.assign",
        Some("role_assignment"),
        Some(&assignment.id),
        Some(&format!("Assigned role {} to user {}", assignment.role_id, user_id)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Created().json(assignment))
}

/// List user's role assignments
#[get("/users/{user_id}/roles")]
pub async fn list_user_roles(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    query: web::Query<OrgQuery>,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();
    let org_id = &query.org_id;

    // Users can view their own roles, admins can view any user's roles
    let is_self = claims.sub == user_id;
    let is_admin = db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if !is_self && !is_admin {
        return Err(ApiError::forbidden("Not authorized".to_string()));
    }

    let assignments = db::permissions::roles::list_user_role_assignments(pool.get_ref(), &user_id, org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(assignments))
}

/// Remove a role assignment
#[delete("/users/{user_id}/roles/{assignment_id}")]
pub async fn remove_user_role(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
    query: web::Query<OrgQuery>,
) -> Result<HttpResponse, ApiError> {
    let (user_id, assignment_id) = path.into_inner();
    let org_id = &query.org_id;

    // Verify requester is admin
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    db::permissions::roles::remove_role_assignment(pool.get_ref(), &assignment_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "role.unassign",
        Some("role_assignment"),
        Some(&assignment_id),
        Some(&format!("Removed role assignment from user {}", user_id)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Permission Overrides
// ============================================================================

/// Add a permission override for a user
#[post("/users/{user_id}/permissions")]
pub async fn add_permission_override(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    req: web::Json<AddPermissionOverrideRequest>,
    query: web::Query<OrgQuery>,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();
    let org_id = &query.org_id;

    // Verify requester is admin
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    let override_rec = db::permissions::roles::add_user_permission_override(
        pool.get_ref(),
        &user_id,
        org_id,
        &req.into_inner(),
        &claims.sub,
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "permission.override.add",
        Some("permission_override"),
        Some(&override_rec.id),
        Some(&format!(
            "Added permission override for user {}: {} = {}",
            user_id, override_rec.permission_id, override_rec.granted
        )),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Created().json(override_rec))
}

/// List user's permission overrides
#[get("/users/{user_id}/permissions/overrides")]
pub async fn list_permission_overrides(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    query: web::Query<OrgQuery>,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();
    let org_id = &query.org_id;

    // Users can view their own overrides, admins can view any user's
    let is_self = claims.sub == user_id;
    let is_admin = db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if !is_self && !is_admin {
        return Err(ApiError::forbidden("Not authorized".to_string()));
    }

    let overrides = db::permissions::roles::list_user_permission_overrides(pool.get_ref(), &user_id, org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(overrides))
}

/// Remove a permission override
#[delete("/users/{user_id}/permissions/{override_id}")]
pub async fn remove_permission_override(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
    query: web::Query<OrgQuery>,
) -> Result<HttpResponse, ApiError> {
    let (user_id, override_id) = path.into_inner();
    let org_id = &query.org_id;

    // Verify requester is admin
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    db::permissions::roles::remove_user_permission_override(pool.get_ref(), &override_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "permission.override.remove",
        Some("permission_override"),
        Some(&override_id),
        Some(&format!("Removed permission override from user {}", user_id)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Permission Checking
// ============================================================================

/// Get user's effective permissions
#[get("/users/{user_id}/permissions")]
pub async fn get_effective_permissions(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    query: web::Query<OrgQuery>,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();
    let org_id = &query.org_id;

    // Users can view their own permissions, admins can view any user's
    let is_self = claims.sub == user_id;
    let is_admin = db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if !is_self && !is_admin {
        return Err(ApiError::forbidden("Not authorized".to_string()));
    }

    let permissions = db::permissions::evaluation::get_effective_permissions(pool.get_ref(), &user_id, org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(permissions))
}

/// Check permission query params
#[derive(Debug, Deserialize)]
pub struct CheckPermissionQuery {
    pub org_id: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
}

/// Check if current user has a specific permission
#[get("/users/{user_id}/permissions/check")]
pub async fn check_permission(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    query: web::Query<CheckPermissionQuery>,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    // Only allow checking own permissions (or admin can check others)
    let is_self = claims.sub == user_id;
    let is_admin = db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &query.org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if !is_self && !is_admin {
        return Err(ApiError::forbidden("Not authorized".to_string()));
    }

    let mut ctx = PermissionContext::new(&user_id, &query.org_id, &query.action, &query.resource_type);
    if let Some(rid) = &query.resource_id {
        ctx = ctx.with_resource(rid);
    }

    let result = db::permissions::evaluation::check_permission(pool.get_ref(), &ctx)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(result))
}

// ============================================================================
// Resource Sharing
// ============================================================================

/// Share a resource
#[post("/resources/{resource_type}/{resource_id}/shares")]
pub async fn share_resource(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
    req: web::Json<ShareResourceRequest>,
) -> Result<HttpResponse, ApiError> {
    let (resource_type, resource_id) = path.into_inner();

    // TODO: Verify user has permission to share this resource
    // For now, just allow it

    let share = db::permissions::evaluation::share_resource(
        pool.get_ref(),
        &resource_type,
        &resource_id,
        &req.into_inner(),
        &claims.sub,
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "resource.share",
        Some(&resource_type),
        Some(&resource_id),
        Some(&format!("Shared {} with {}", resource_type, share.shared_with_id)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Created().json(share))
}

/// List shares for a resource
#[get("/resources/{resource_type}/{resource_id}/shares")]
pub async fn list_resource_shares(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (resource_type, resource_id) = path.into_inner();

    // TODO: Verify user has permission to view shares

    let shares = db::permissions::evaluation::list_resource_shares(pool.get_ref(), &resource_type, &resource_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(shares))
}

/// Unshare resource request
#[derive(Debug, Deserialize)]
pub struct UnshareRequest {
    pub shared_with_type: String,
    pub shared_with_id: String,
}

/// Remove a resource share
#[delete("/resources/{resource_type}/{resource_id}/shares")]
pub async fn unshare_resource(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
    req: web::Json<UnshareRequest>,
) -> Result<HttpResponse, ApiError> {
    let (resource_type, resource_id) = path.into_inner();

    let shared_with_type = OwnerType::from_str(&req.shared_with_type)
        .ok_or_else(|| ApiError::bad_request("Invalid shared_with_type".to_string()))?;

    // TODO: Verify user has permission to manage shares

    db::permissions::evaluation::unshare_resource(
        pool.get_ref(),
        &resource_type,
        &resource_id,
        shared_with_type,
        &req.shared_with_id,
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "resource.unshare",
        Some(&resource_type),
        Some(&resource_id),
        Some(&format!("Removed share from {}", req.shared_with_id)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Permissions & Policies Listing
// ============================================================================

/// List all permissions
#[get("/permissions")]
pub async fn list_permissions(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let permissions = db::permissions::roles::list_permissions(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(permissions))
}

/// List all resource types
#[get("/permissions/resource-types")]
pub async fn list_resource_types(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let types = db::permissions::roles::list_resource_types(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(types))
}

/// List all actions
#[get("/permissions/actions")]
pub async fn list_actions(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let actions = db::permissions::roles::list_actions(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(actions))
}

/// List all policies
#[get("/policies")]
pub async fn list_policies(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let policies = db::permissions::roles::list_policies(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(policies))
}

// ============================================================================
// Cache Management
// ============================================================================

/// Get cache statistics (admin only)
#[get("/permissions/cache/stats")]
pub async fn get_cache_stats(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiError> {
    // Check if user is system admin
    // For now, require manage_users permission as a proxy for admin
    if !db::has_permission(pool.get_ref(), &claims.sub, "manage_users").await.unwrap_or(false) {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    let stats = db::permissions::cache::get_cache_stats(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(stats))
}

/// Clear expired cache entries (admin only)
#[post("/permissions/cache/cleanup")]
pub async fn cleanup_cache(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiError> {
    // Check if user is system admin
    if !db::has_permission(pool.get_ref(), &claims.sub, "manage_users").await.unwrap_or(false) {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    let cleaned = db::permissions::cache::cleanup_expired_cache(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "entries_cleaned": cleaned
    })))
}

// ============================================================================
// Helpers
// ============================================================================

/// Organization ID query parameter
#[derive(Debug, Deserialize)]
pub struct OrgQuery {
    pub org_id: String,
}

/// Configure permission routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(list_role_templates)
        .service(get_role_template)
        .service(get_role_template_permissions)
        .service(create_custom_role)
        .service(list_custom_roles)
        .service(get_custom_role)
        .service(update_custom_role)
        .service(delete_custom_role)
        .service(clone_custom_role)
        .service(assign_user_role)
        .service(list_user_roles)
        .service(remove_user_role)
        .service(add_permission_override)
        .service(list_permission_overrides)
        .service(remove_permission_override)
        .service(get_effective_permissions)
        .service(check_permission)
        .service(share_resource)
        .service(list_resource_shares)
        .service(unshare_resource)
        .service(list_permissions)
        .service(list_resource_types)
        .service(list_actions)
        .service(list_policies)
        .service(get_cache_stats)
        .service(cleanup_cache);
}
