//! Organization, department, and team API endpoints

use actix_web::{delete, get, post, put, web, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::db;
use crate::db::permissions::{
    CreateDepartmentRequest, CreateOrganizationRequest, CreateTeamRequest,
    OrgRole, TeamRole, UpdateDepartmentRequest, UpdateOrganizationRequest, UpdateTeamRequest,
};
use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;

// ============================================================================
// Organizations
// ============================================================================

/// Create a new organization
#[post("/organizations")]
pub async fn create_organization(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    req: web::Json<CreateOrganizationRequest>,
) -> Result<HttpResponse, ApiError> {
    let org = db::permissions::organizations::create_organization(
        pool.get_ref(),
        &req.into_inner(),
        &claims.sub,
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "organization.create",
        Some("organization"),
        Some(&org.id),
        Some(&format!("Created organization: {}", org.name)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Created().json(org))
}

/// List user's organizations
#[get("/organizations")]
pub async fn list_organizations(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let orgs = db::permissions::organizations::list_user_organizations(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(orgs))
}

/// Get organization by ID
#[get("/organizations/{id}")]
pub async fn get_organization(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    // Verify user is member of org
    let user_role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if user_role.is_none() {
        return Err(ApiError::not_found("Organization not found".to_string()));
    }

    let org = db::permissions::organizations::get_organization_by_id(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Organization not found".to_string()))?;

    Ok(HttpResponse::Ok().json(org))
}

/// Update organization
#[put("/organizations/{id}")]
pub async fn update_organization(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    req: web::Json<UpdateOrganizationRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    // Verify user is admin or owner
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    let org = db::permissions::organizations::update_organization(pool.get_ref(), &id, &req.into_inner())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "organization.update",
        Some("organization"),
        Some(&id),
        Some(&format!("Updated organization: {}", org.name)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Ok().json(org))
}

/// Delete organization
#[delete("/organizations/{id}")]
pub async fn delete_organization(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    // Verify user is owner
    let user_role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if !matches!(user_role, Some(OrgRole::Owner)) {
        return Err(ApiError::forbidden("Only organization owner can delete".to_string()));
    }

    db::permissions::organizations::delete_organization(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "organization.delete",
        Some("organization"),
        Some(&id),
        Some("Deleted organization"),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::NoContent().finish())
}

/// List organization members
#[get("/organizations/{id}/members")]
pub async fn list_organization_members(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    // Verify user is member
    let user_role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if user_role.is_none() {
        return Err(ApiError::not_found("Organization not found".to_string()));
    }

    let members = db::permissions::organizations::list_organization_members(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Convert to response format
    let response: Vec<_> = members
        .into_iter()
        .map(|(user, role, joined_at)| serde_json::json!({
            "user": user,
            "role": role.as_str(),
            "joined_at": joined_at
        }))
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Add member to organization request
#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub user_id: String,
    pub role: String,
}

/// Add member to organization
#[post("/organizations/{id}/members")]
pub async fn add_organization_member(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    req: web::Json<AddMemberRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    // Verify user is admin
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    let role = OrgRole::from_str(&req.role)
        .ok_or_else(|| ApiError::bad_request("Invalid role".to_string()))?;

    // Can't add owners unless you're an owner
    let current_role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if matches!(role, OrgRole::Owner) && !matches!(current_role, Some(OrgRole::Owner)) {
        return Err(ApiError::forbidden("Only owners can add other owners".to_string()));
    }

    db::permissions::organizations::add_user_to_organization(
        pool.get_ref(),
        &req.user_id,
        &id,
        role,
        Some(&claims.sub),
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "organization.member.add",
        Some("organization"),
        Some(&id),
        Some(&format!("Added user {} as {}", req.user_id, req.role)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Created().json(serde_json::json!({"message": "Member added"})))
}

/// Remove member from organization
#[delete("/organizations/{org_id}/members/{user_id}")]
pub async fn remove_organization_member(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (org_id, user_id) = path.into_inner();

    // Verify user is admin
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    // Can't remove self if owner
    if user_id == claims.sub {
        let role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &org_id)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;

        if matches!(role, Some(OrgRole::Owner)) {
            return Err(ApiError::bad_request("Owner cannot remove themselves".to_string()));
        }
    }

    db::permissions::organizations::remove_user_from_organization(pool.get_ref(), &user_id, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "organization.member.remove",
        Some("organization"),
        Some(&org_id),
        Some(&format!("Removed user {}", user_id)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Departments
// ============================================================================

/// Create a department
#[post("/organizations/{org_id}/departments")]
pub async fn create_department(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    req: web::Json<CreateDepartmentRequest>,
) -> Result<HttpResponse, ApiError> {
    let org_id = path.into_inner();

    // Verify user is admin
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    let dept = db::permissions::organizations::create_department(pool.get_ref(), &org_id, &req.into_inner())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "department.create",
        Some("department"),
        Some(&dept.id),
        Some(&format!("Created department: {}", dept.name)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Created().json(dept))
}

/// List departments in organization
#[get("/organizations/{org_id}/departments")]
pub async fn list_departments(
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

    let depts = db::permissions::organizations::list_departments(pool.get_ref(), &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(depts))
}

/// Get department by ID
#[get("/departments/{id}")]
pub async fn get_department(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    let dept = db::permissions::organizations::get_department_by_id(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Department not found".to_string()))?;

    // Verify user is member of org
    let user_role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &dept.organization_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if user_role.is_none() {
        return Err(ApiError::not_found("Department not found".to_string()));
    }

    Ok(HttpResponse::Ok().json(dept))
}

/// Update department
#[put("/departments/{id}")]
pub async fn update_department(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    req: web::Json<UpdateDepartmentRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    let dept = db::permissions::organizations::get_department_by_id(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Department not found".to_string()))?;

    // Verify user is admin
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &dept.organization_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    let updated = db::permissions::organizations::update_department(pool.get_ref(), &id, &req.into_inner())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "department.update",
        Some("department"),
        Some(&id),
        Some(&format!("Updated department: {}", updated.name)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Ok().json(updated))
}

/// Delete department
#[delete("/departments/{id}")]
pub async fn delete_department(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    let dept = db::permissions::organizations::get_department_by_id(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Department not found".to_string()))?;

    // Verify user is admin
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &dept.organization_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    db::permissions::organizations::delete_department(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "department.delete",
        Some("department"),
        Some(&id),
        Some("Deleted department"),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Teams
// ============================================================================

/// Create a team
#[post("/departments/{dept_id}/teams")]
pub async fn create_team(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    req: web::Json<CreateTeamRequest>,
) -> Result<HttpResponse, ApiError> {
    let dept_id = path.into_inner();

    // Get department to verify org
    let dept = db::permissions::organizations::get_department_by_id(pool.get_ref(), &dept_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Department not found".to_string()))?;

    // Verify user is admin
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &dept.organization_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    let team = db::permissions::organizations::create_team(pool.get_ref(), &dept_id, &req.into_inner())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "team.create",
        Some("team"),
        Some(&team.id),
        Some(&format!("Created team: {}", team.name)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Created().json(team))
}

/// List teams in department
#[get("/departments/{dept_id}/teams")]
pub async fn list_teams_in_department(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let dept_id = path.into_inner();

    // Get department to verify org
    let dept = db::permissions::organizations::get_department_by_id(pool.get_ref(), &dept_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Department not found".to_string()))?;

    // Verify user is member
    let user_role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &dept.organization_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if user_role.is_none() {
        return Err(ApiError::not_found("Department not found".to_string()));
    }

    let teams = db::permissions::organizations::list_teams_in_department(pool.get_ref(), &dept_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(teams))
}

/// List all teams in organization
#[get("/organizations/{org_id}/teams")]
pub async fn list_teams_in_organization(
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

    let teams = db::permissions::organizations::list_teams_in_organization(pool.get_ref(), &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(teams))
}

/// Get team by ID
#[get("/teams/{id}")]
pub async fn get_team(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    let team = db::permissions::organizations::get_team_by_id(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Team not found".to_string()))?;

    // Get org for the team
    let org_id = db::permissions::organizations::get_team_org_id(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Team not found".to_string()))?;

    // Verify user is member of org
    let user_role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if user_role.is_none() {
        return Err(ApiError::not_found("Team not found".to_string()));
    }

    Ok(HttpResponse::Ok().json(team))
}

/// Update team
#[put("/teams/{id}")]
pub async fn update_team(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    req: web::Json<UpdateTeamRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    // Get org for the team
    let org_id = db::permissions::organizations::get_team_org_id(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Team not found".to_string()))?;

    // Allow org admin or team lead
    let is_admin = db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let is_lead = db::permissions::organizations::is_team_lead(pool.get_ref(), &claims.sub, &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if !is_admin && !is_lead {
        return Err(ApiError::forbidden("Admin or team lead access required".to_string()));
    }

    let updated = db::permissions::organizations::update_team(pool.get_ref(), &id, &req.into_inner())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "team.update",
        Some("team"),
        Some(&id),
        Some(&format!("Updated team: {}", updated.name)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Ok().json(updated))
}

/// Delete team
#[delete("/teams/{id}")]
pub async fn delete_team(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    // Get org for the team
    let org_id = db::permissions::organizations::get_team_org_id(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Team not found".to_string()))?;

    // Only org admin can delete teams
    if !db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    {
        return Err(ApiError::forbidden("Admin access required".to_string()));
    }

    db::permissions::organizations::delete_team(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "team.delete",
        Some("team"),
        Some(&id),
        Some("Deleted team"),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::NoContent().finish())
}

/// List team members
#[get("/teams/{id}/members")]
pub async fn list_team_members(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    // Get org for the team
    let org_id = db::permissions::organizations::get_team_org_id(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Team not found".to_string()))?;

    // Verify user is member of org
    let user_role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if user_role.is_none() {
        return Err(ApiError::not_found("Team not found".to_string()));
    }

    let members = db::permissions::organizations::list_team_members(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(members))
}

/// Add member to team request
#[derive(Debug, Deserialize)]
pub struct AddTeamMemberRequest {
    pub user_id: String,
    pub role: String,
}

/// Add member to team
#[post("/teams/{id}/members")]
pub async fn add_team_member(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    req: web::Json<AddTeamMemberRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    // Get org for the team
    let org_id = db::permissions::organizations::get_team_org_id(pool.get_ref(), &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Team not found".to_string()))?;

    // Allow org admin or team lead
    let is_admin = db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let is_lead = db::permissions::organizations::is_team_lead(pool.get_ref(), &claims.sub, &id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if !is_admin && !is_lead {
        return Err(ApiError::forbidden("Admin or team lead access required".to_string()));
    }

    let role = TeamRole::from_str(&req.role)
        .ok_or_else(|| ApiError::bad_request("Invalid role".to_string()))?;

    db::permissions::organizations::add_user_to_team(
        pool.get_ref(),
        &req.user_id,
        &id,
        role,
        Some(&claims.sub),
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "team.member.add",
        Some("team"),
        Some(&id),
        Some(&format!("Added user {} as {}", req.user_id, req.role)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Created().json(serde_json::json!({"message": "Member added"})))
}

/// Update team member role request
#[derive(Debug, Deserialize)]
pub struct UpdateTeamMemberRequest {
    pub role: String,
}

/// Update team member role
#[put("/teams/{team_id}/members/{user_id}")]
pub async fn update_team_member(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
    req: web::Json<UpdateTeamMemberRequest>,
) -> Result<HttpResponse, ApiError> {
    let (team_id, user_id) = path.into_inner();

    // Get org for the team
    let org_id = db::permissions::organizations::get_team_org_id(pool.get_ref(), &team_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Team not found".to_string()))?;

    // Only org admin or team lead can update roles
    let is_admin = db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let is_lead = db::permissions::organizations::is_team_lead(pool.get_ref(), &claims.sub, &team_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if !is_admin && !is_lead {
        return Err(ApiError::forbidden("Admin or team lead access required".to_string()));
    }

    let role = TeamRole::from_str(&req.role)
        .ok_or_else(|| ApiError::bad_request("Invalid role".to_string()))?;

    db::permissions::organizations::update_user_team_role(pool.get_ref(), &user_id, &team_id, role)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "team.member.update",
        Some("team"),
        Some(&team_id),
        Some(&format!("Updated user {} role to {}", user_id, req.role)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Role updated"})))
}

/// Remove member from team
#[delete("/teams/{team_id}/members/{user_id}")]
pub async fn remove_team_member(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (team_id, user_id) = path.into_inner();

    // Get org for the team
    let org_id = db::permissions::organizations::get_team_org_id(pool.get_ref(), &team_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Team not found".to_string()))?;

    // Allow org admin, team lead, or self-removal
    let is_admin = db::permissions::organizations::is_org_admin(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let is_lead = db::permissions::organizations::is_team_lead(pool.get_ref(), &claims.sub, &team_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let is_self = claims.sub == user_id;

    if !is_admin && !is_lead && !is_self {
        return Err(ApiError::forbidden("Not authorized to remove member".to_string()));
    }

    db::permissions::organizations::remove_user_from_team(pool.get_ref(), &user_id, &team_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "team.member.remove",
        Some("team"),
        Some(&team_id),
        Some(&format!("Removed user {}", user_id)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::NoContent().finish())
}

/// Get current user's teams
#[get("/users/me/teams")]
pub async fn get_my_teams(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let teams = db::permissions::organizations::get_user_teams(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let response: Vec<_> = teams
        .into_iter()
        .map(|(id, role)| serde_json::json!({
            "team_id": id,
            "role": role.as_str()
        }))
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

// ============================================================================
// Organization Quotas
// ============================================================================

/// Get quotas for an organization
#[get("/organizations/{org_id}/quotas")]
pub async fn get_organization_quotas(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let org_id = path.into_inner();

    // Verify user is member of org
    let user_role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if user_role.is_none() {
        return Err(ApiError::not_found("Organization not found".to_string()));
    }

    let quotas = db::quotas::get_org_quotas(pool.get_ref(), &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("Organization quotas not found".to_string()))?;

    Ok(HttpResponse::Ok().json(quotas))
}

/// Update quotas for an organization (owner only)
#[put("/organizations/{org_id}/quotas")]
pub async fn update_organization_quotas(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    req: web::Json<db::quotas::UpdateQuotasRequest>,
) -> Result<HttpResponse, ApiError> {
    let org_id = path.into_inner();

    // Verify user is owner (only owners can change quotas)
    let user_role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    match user_role {
        Some(OrgRole::Owner) => {}
        _ => return Err(ApiError::forbidden("Only organization owners can modify quotas".to_string())),
    }

    let quotas = db::quotas::update_org_quotas(pool.get_ref(), &org_id, &req.into_inner())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "organization.quotas.update",
        Some("organization"),
        Some(&org_id),
        Some("Updated organization quotas"),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Ok().json(quotas))
}

/// Get quota usage summary for an organization
#[get("/organizations/{org_id}/quotas/usage")]
pub async fn get_organization_quota_usage(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let org_id = path.into_inner();

    // Verify user is member of org
    let user_role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if user_role.is_none() {
        return Err(ApiError::not_found("Organization not found".to_string()));
    }

    let usage = db::quotas::get_quota_usage_summary(pool.get_ref(), &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(usage))
}

/// Check a specific quota for an organization
#[get("/organizations/{org_id}/quotas/check/{quota_type}")]
pub async fn check_organization_quota(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (org_id, quota_type_str) = path.into_inner();

    // Verify user is member of org
    let user_role = db::permissions::organizations::get_user_org_role(pool.get_ref(), &claims.sub, &org_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if user_role.is_none() {
        return Err(ApiError::not_found("Organization not found".to_string()));
    }

    let quota_type: db::quotas::QuotaType = quota_type_str
        .parse()
        .map_err(|e: anyhow::Error| ApiError::bad_request(e.to_string()))?;

    let result = db::quotas::check_quota(pool.get_ref(), &org_id, quota_type)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(result))
}

/// Configure organization routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(create_organization)
        .service(list_organizations)
        .service(get_organization)
        .service(update_organization)
        .service(delete_organization)
        .service(list_organization_members)
        .service(add_organization_member)
        .service(remove_organization_member)
        .service(create_department)
        .service(list_departments)
        .service(get_department)
        .service(update_department)
        .service(delete_department)
        .service(create_team)
        .service(list_teams_in_department)
        .service(list_teams_in_organization)
        .service(get_team)
        .service(update_team)
        .service(delete_team)
        .service(list_team_members)
        .service(add_team_member)
        .service(update_team_member)
        .service(remove_team_member)
        .service(get_my_teams)
        // Quota endpoints
        .service(get_organization_quotas)
        .service(update_organization_quotas)
        .service(get_organization_quota_usage)
        .service(check_organization_quota);
}
