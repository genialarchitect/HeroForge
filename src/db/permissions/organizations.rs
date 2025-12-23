//! Organization, department, and team CRUD operations

use anyhow::{anyhow, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use super::types::*;

// ============================================================================
// Organizations
// ============================================================================

/// Create a new organization
pub async fn create_organization(
    pool: &SqlitePool,
    req: &CreateOrganizationRequest,
    created_by: &str,
) -> Result<Organization> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let slug = req.slug.clone().unwrap_or_else(|| slugify(&req.name));
    let settings = req.settings.as_ref().map(|s| s.to_string());

    sqlx::query(
        r#"
        INSERT INTO organizations (id, name, slug, description, settings, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&slug)
    .bind(&req.description)
    .bind(&settings)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    // Add creator as owner
    sqlx::query(
        r#"
        INSERT INTO user_organizations (user_id, organization_id, org_role, joined_at, invited_by)
        VALUES (?, ?, 'owner', ?, NULL)
        "#,
    )
    .bind(created_by)
    .bind(&id)
    .bind(&now)
    .execute(pool)
    .await?;

    get_organization_by_id(pool, &id)
        .await?
        .ok_or_else(|| anyhow!("Failed to create organization"))
}

/// Get organization by ID
pub async fn get_organization_by_id(pool: &SqlitePool, id: &str) -> Result<Option<Organization>> {
    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(org)
}

/// Get organization by slug
pub async fn get_organization_by_slug(pool: &SqlitePool, slug: &str) -> Result<Option<Organization>> {
    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE slug = ?",
    )
    .bind(slug)
    .fetch_optional(pool)
    .await?;

    Ok(org)
}

/// List organizations for a user
pub async fn list_user_organizations(pool: &SqlitePool, user_id: &str) -> Result<Vec<OrganizationSummary>> {
    let orgs = sqlx::query_as::<_, (String, String, String, String, i64, i64)>(
        r#"
        SELECT
            o.id, o.name, o.slug, uo.org_role,
            (SELECT COUNT(*) FROM user_organizations WHERE organization_id = o.id) as member_count,
            (SELECT COUNT(*) FROM teams t
             JOIN departments d ON t.department_id = d.id
             WHERE d.organization_id = o.id) as team_count
        FROM organizations o
        JOIN user_organizations uo ON o.id = uo.organization_id
        WHERE uo.user_id = ? AND o.is_active = 1
        ORDER BY o.name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(orgs
        .into_iter()
        .map(|(id, name, slug, role, member_count, team_count)| OrganizationSummary {
            id,
            name,
            slug,
            role: OrgRole::from_str(&role).unwrap_or(OrgRole::Member),
            member_count,
            team_count,
        })
        .collect())
}

/// Update an organization
pub async fn update_organization(
    pool: &SqlitePool,
    id: &str,
    req: &UpdateOrganizationRequest,
) -> Result<Organization> {
    let now = Utc::now().to_rfc3339();
    let existing = get_organization_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow!("Organization not found"))?;

    let name = req.name.as_ref().unwrap_or(&existing.name);
    let description = req.description.as_ref().or(existing.description.as_ref());
    let settings = req.settings.as_ref().map(|s| s.to_string()).or(existing.settings);
    let is_active = req.is_active.unwrap_or(existing.is_active);

    sqlx::query(
        r#"
        UPDATE organizations
        SET name = ?, description = ?, settings = ?, is_active = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(name)
    .bind(description)
    .bind(&settings)
    .bind(is_active)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    get_organization_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow!("Organization not found"))
}

/// Delete an organization (soft delete by deactivating)
pub async fn delete_organization(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE organizations SET is_active = 0, updated_at = ? WHERE id = ?",
    )
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Check if user is org admin or owner
pub async fn is_org_admin(pool: &SqlitePool, user_id: &str, org_id: &str) -> Result<bool> {
    let result = sqlx::query_scalar::<_, i32>(
        r#"
        SELECT COUNT(*) FROM user_organizations
        WHERE user_id = ? AND organization_id = ? AND org_role IN ('owner', 'admin')
        "#,
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_one(pool)
    .await?;

    Ok(result > 0)
}

/// Get user's role in organization
pub async fn get_user_org_role(pool: &SqlitePool, user_id: &str, org_id: &str) -> Result<Option<OrgRole>> {
    let role = sqlx::query_scalar::<_, String>(
        "SELECT org_role FROM user_organizations WHERE user_id = ? AND organization_id = ?",
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_optional(pool)
    .await?;

    Ok(role.and_then(|r| OrgRole::from_str(&r)))
}

/// Add user to organization
pub async fn add_user_to_organization(
    pool: &SqlitePool,
    user_id: &str,
    org_id: &str,
    role: OrgRole,
    invited_by: Option<&str>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT OR REPLACE INTO user_organizations (user_id, organization_id, org_role, joined_at, invited_by)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(user_id)
    .bind(org_id)
    .bind(role.as_str())
    .bind(&now)
    .bind(invited_by)
    .execute(pool)
    .await?;

    Ok(())
}

/// Remove user from organization
pub async fn remove_user_from_organization(pool: &SqlitePool, user_id: &str, org_id: &str) -> Result<()> {
    // First remove from all teams in this org
    sqlx::query(
        r#"
        DELETE FROM user_teams WHERE user_id = ? AND team_id IN (
            SELECT t.id FROM teams t
            JOIN departments d ON t.department_id = d.id
            WHERE d.organization_id = ?
        )
        "#,
    )
    .bind(user_id)
    .bind(org_id)
    .execute(pool)
    .await?;

    // Remove role assignments
    sqlx::query(
        "DELETE FROM user_role_assignments WHERE user_id = ? AND organization_id = ?",
    )
    .bind(user_id)
    .bind(org_id)
    .execute(pool)
    .await?;

    // Remove permission overrides
    sqlx::query(
        "DELETE FROM user_permission_overrides WHERE user_id = ? AND organization_id = ?",
    )
    .bind(user_id)
    .bind(org_id)
    .execute(pool)
    .await?;

    // Remove from organization
    sqlx::query(
        "DELETE FROM user_organizations WHERE user_id = ? AND organization_id = ?",
    )
    .bind(user_id)
    .bind(org_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// List organization members
pub async fn list_organization_members(pool: &SqlitePool, org_id: &str) -> Result<Vec<(UserSummary, OrgRole, String)>> {
    let members = sqlx::query_as::<_, (String, String, Option<String>, String, String)>(
        r#"
        SELECT u.id, u.username, u.email, uo.org_role, uo.joined_at
        FROM users u
        JOIN user_organizations uo ON u.id = uo.user_id
        WHERE uo.organization_id = ?
        ORDER BY uo.org_role, u.username
        "#,
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    Ok(members
        .into_iter()
        .map(|(id, username, email, role, joined_at)| {
            (
                UserSummary { id, username, email },
                OrgRole::from_str(&role).unwrap_or(OrgRole::Member),
                joined_at,
            )
        })
        .collect())
}

// ============================================================================
// Departments
// ============================================================================

/// Create a department
pub async fn create_department(
    pool: &SqlitePool,
    org_id: &str,
    req: &CreateDepartmentRequest,
) -> Result<Department> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let slug = req.slug.clone().unwrap_or_else(|| slugify(&req.name));

    sqlx::query(
        r#"
        INSERT INTO departments (id, organization_id, name, slug, description, parent_department_id, manager_user_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(org_id)
    .bind(&req.name)
    .bind(&slug)
    .bind(&req.description)
    .bind(&req.parent_department_id)
    .bind(&req.manager_user_id)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_department_by_id(pool, &id)
        .await?
        .ok_or_else(|| anyhow!("Failed to create department"))
}

/// Get department by ID
pub async fn get_department_by_id(pool: &SqlitePool, id: &str) -> Result<Option<Department>> {
    let dept = sqlx::query_as::<_, Department>(
        "SELECT * FROM departments WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(dept)
}

/// List departments in an organization
pub async fn list_departments(pool: &SqlitePool, org_id: &str) -> Result<Vec<DepartmentSummary>> {
    let depts = sqlx::query_as::<_, (String, String, String, i64, i64, Option<String>, Option<String>, Option<String>)>(
        r#"
        SELECT
            d.id, d.name, d.slug,
            (SELECT COUNT(*) FROM teams WHERE department_id = d.id) as team_count,
            (SELECT COUNT(DISTINCT ut.user_id) FROM user_teams ut
             JOIN teams t ON ut.team_id = t.id
             WHERE t.department_id = d.id) as member_count,
            d.manager_user_id,
            u.username,
            u.email
        FROM departments d
        LEFT JOIN users u ON d.manager_user_id = u.id
        WHERE d.organization_id = ?
        ORDER BY d.name
        "#,
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    Ok(depts
        .into_iter()
        .map(|(id, name, slug, team_count, member_count, manager_id, manager_username, manager_email)| {
            DepartmentSummary {
                id,
                name,
                slug,
                team_count,
                member_count,
                manager: manager_id.map(|mid| UserSummary {
                    id: mid,
                    username: manager_username.unwrap_or_default(),
                    email: manager_email,
                }),
            }
        })
        .collect())
}

/// Update a department
pub async fn update_department(
    pool: &SqlitePool,
    id: &str,
    req: &UpdateDepartmentRequest,
) -> Result<Department> {
    let now = Utc::now().to_rfc3339();
    let existing = get_department_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow!("Department not found"))?;

    let name = req.name.as_ref().unwrap_or(&existing.name);
    let description = req.description.as_ref().or(existing.description.as_ref());
    let parent_id = req.parent_department_id.as_ref().or(existing.parent_department_id.as_ref());
    let manager_id = req.manager_user_id.as_ref().or(existing.manager_user_id.as_ref());

    sqlx::query(
        r#"
        UPDATE departments
        SET name = ?, description = ?, parent_department_id = ?, manager_user_id = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(name)
    .bind(description)
    .bind(parent_id)
    .bind(manager_id)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    get_department_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow!("Department not found"))
}

/// Delete a department
pub async fn delete_department(pool: &SqlitePool, id: &str) -> Result<()> {
    // Check for child departments
    let child_count = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM departments WHERE parent_department_id = ?",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    if child_count > 0 {
        return Err(anyhow!("Cannot delete department with child departments"));
    }

    // Check for teams
    let team_count = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM teams WHERE department_id = ?",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    if team_count > 0 {
        return Err(anyhow!("Cannot delete department with teams. Delete teams first."));
    }

    sqlx::query("DELETE FROM departments WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get department's organization ID
pub async fn get_department_org_id(pool: &SqlitePool, dept_id: &str) -> Result<Option<String>> {
    let org_id = sqlx::query_scalar::<_, String>(
        "SELECT organization_id FROM departments WHERE id = ?",
    )
    .bind(dept_id)
    .fetch_optional(pool)
    .await?;

    Ok(org_id)
}

// ============================================================================
// Teams
// ============================================================================

/// Create a team
pub async fn create_team(
    pool: &SqlitePool,
    dept_id: &str,
    req: &CreateTeamRequest,
) -> Result<Team> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let slug = req.slug.clone().unwrap_or_else(|| slugify(&req.name));

    sqlx::query(
        r#"
        INSERT INTO teams (id, department_id, name, slug, description, team_lead_user_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(dept_id)
    .bind(&req.name)
    .bind(&slug)
    .bind(&req.description)
    .bind(&req.team_lead_user_id)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_team_by_id(pool, &id)
        .await?
        .ok_or_else(|| anyhow!("Failed to create team"))
}

/// Get team by ID
pub async fn get_team_by_id(pool: &SqlitePool, id: &str) -> Result<Option<Team>> {
    let team = sqlx::query_as::<_, Team>(
        "SELECT * FROM teams WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(team)
}

/// List teams in a department
pub async fn list_teams_in_department(pool: &SqlitePool, dept_id: &str) -> Result<Vec<TeamSummary>> {
    let teams = sqlx::query_as::<_, (String, String, String, String, i64, Option<String>, Option<String>, Option<String>)>(
        r#"
        SELECT
            t.id, t.name, t.slug, d.name as dept_name,
            (SELECT COUNT(*) FROM user_teams WHERE team_id = t.id) as member_count,
            t.team_lead_user_id,
            u.username,
            u.email
        FROM teams t
        JOIN departments d ON t.department_id = d.id
        LEFT JOIN users u ON t.team_lead_user_id = u.id
        WHERE t.department_id = ?
        ORDER BY t.name
        "#,
    )
    .bind(dept_id)
    .fetch_all(pool)
    .await?;

    Ok(teams
        .into_iter()
        .map(|(id, name, slug, dept_name, member_count, lead_id, lead_username, lead_email)| {
            TeamSummary {
                id,
                name,
                slug,
                department_name: dept_name,
                member_count,
                lead: lead_id.map(|lid| UserSummary {
                    id: lid,
                    username: lead_username.unwrap_or_default(),
                    email: lead_email,
                }),
            }
        })
        .collect())
}

/// List all teams in an organization
pub async fn list_teams_in_organization(pool: &SqlitePool, org_id: &str) -> Result<Vec<TeamSummary>> {
    let teams = sqlx::query_as::<_, (String, String, String, String, i64, Option<String>, Option<String>, Option<String>)>(
        r#"
        SELECT
            t.id, t.name, t.slug, d.name as dept_name,
            (SELECT COUNT(*) FROM user_teams WHERE team_id = t.id) as member_count,
            t.team_lead_user_id,
            u.username,
            u.email
        FROM teams t
        JOIN departments d ON t.department_id = d.id
        LEFT JOIN users u ON t.team_lead_user_id = u.id
        WHERE d.organization_id = ?
        ORDER BY d.name, t.name
        "#,
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    Ok(teams
        .into_iter()
        .map(|(id, name, slug, dept_name, member_count, lead_id, lead_username, lead_email)| {
            TeamSummary {
                id,
                name,
                slug,
                department_name: dept_name,
                member_count,
                lead: lead_id.map(|lid| UserSummary {
                    id: lid,
                    username: lead_username.unwrap_or_default(),
                    email: lead_email,
                }),
            }
        })
        .collect())
}

/// Update a team
pub async fn update_team(pool: &SqlitePool, id: &str, req: &UpdateTeamRequest) -> Result<Team> {
    let now = Utc::now().to_rfc3339();
    let existing = get_team_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow!("Team not found"))?;

    let name = req.name.as_ref().unwrap_or(&existing.name);
    let description = req.description.as_ref().or(existing.description.as_ref());
    let lead_id = req.team_lead_user_id.as_ref().or(existing.team_lead_user_id.as_ref());

    sqlx::query(
        r#"
        UPDATE teams SET name = ?, description = ?, team_lead_user_id = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(name)
    .bind(description)
    .bind(lead_id)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    get_team_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow!("Team not found"))
}

/// Delete a team
pub async fn delete_team(pool: &SqlitePool, id: &str) -> Result<()> {
    // Remove all team members first
    sqlx::query("DELETE FROM user_teams WHERE team_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    // Remove team-scoped role assignments
    sqlx::query("DELETE FROM user_role_assignments WHERE scope_type = 'team' AND scope_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    // Delete the team
    sqlx::query("DELETE FROM teams WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get team's organization ID
pub async fn get_team_org_id(pool: &SqlitePool, team_id: &str) -> Result<Option<String>> {
    let org_id = sqlx::query_scalar::<_, String>(
        r#"
        SELECT d.organization_id FROM teams t
        JOIN departments d ON t.department_id = d.id
        WHERE t.id = ?
        "#,
    )
    .bind(team_id)
    .fetch_optional(pool)
    .await?;

    Ok(org_id)
}

/// Get team's department ID
pub async fn get_team_dept_id(pool: &SqlitePool, team_id: &str) -> Result<Option<String>> {
    let dept_id = sqlx::query_scalar::<_, String>(
        "SELECT department_id FROM teams WHERE id = ?",
    )
    .bind(team_id)
    .fetch_optional(pool)
    .await?;

    Ok(dept_id)
}

// ============================================================================
// Team Membership
// ============================================================================

/// Add user to team
pub async fn add_user_to_team(
    pool: &SqlitePool,
    user_id: &str,
    team_id: &str,
    role: TeamRole,
    added_by: Option<&str>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    // Verify user is in the same org as the team
    let team_org = get_team_org_id(pool, team_id).await?;
    if let Some(org_id) = team_org {
        let user_in_org = sqlx::query_scalar::<_, i32>(
            "SELECT COUNT(*) FROM user_organizations WHERE user_id = ? AND organization_id = ?",
        )
        .bind(user_id)
        .bind(&org_id)
        .fetch_one(pool)
        .await?;

        if user_in_org == 0 {
            return Err(anyhow!("User must be a member of the organization to join this team"));
        }
    }

    sqlx::query(
        r#"
        INSERT OR REPLACE INTO user_teams (user_id, team_id, team_role, joined_at, added_by)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(user_id)
    .bind(team_id)
    .bind(role.as_str())
    .bind(&now)
    .bind(added_by)
    .execute(pool)
    .await?;

    Ok(())
}

/// Remove user from team
pub async fn remove_user_from_team(pool: &SqlitePool, user_id: &str, team_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM user_teams WHERE user_id = ? AND team_id = ?")
        .bind(user_id)
        .bind(team_id)
        .execute(pool)
        .await?;

    // Also remove team-scoped role assignments for this user
    sqlx::query(
        "DELETE FROM user_role_assignments WHERE user_id = ? AND scope_type = 'team' AND scope_id = ?",
    )
    .bind(user_id)
    .bind(team_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update user's team role
pub async fn update_user_team_role(
    pool: &SqlitePool,
    user_id: &str,
    team_id: &str,
    role: TeamRole,
) -> Result<()> {
    sqlx::query("UPDATE user_teams SET team_role = ? WHERE user_id = ? AND team_id = ?")
        .bind(role.as_str())
        .bind(user_id)
        .bind(team_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// List team members
pub async fn list_team_members(pool: &SqlitePool, team_id: &str) -> Result<Vec<TeamMember>> {
    let members = sqlx::query_as::<_, (String, String, Option<String>, String, String, Option<String>)>(
        r#"
        SELECT u.id, u.username, u.email, ut.team_role, ut.joined_at, ut.added_by
        FROM users u
        JOIN user_teams ut ON u.id = ut.user_id
        WHERE ut.team_id = ?
        ORDER BY ut.team_role DESC, u.username
        "#,
    )
    .bind(team_id)
    .fetch_all(pool)
    .await?;

    Ok(members
        .into_iter()
        .map(|(id, username, email, role, joined_at, added_by)| TeamMember {
            user: UserSummary { id, username, email },
            team_role: TeamRole::from_str(&role).unwrap_or(TeamRole::Member),
            joined_at,
            added_by,
        })
        .collect())
}

/// Get user's teams
pub async fn get_user_teams(pool: &SqlitePool, user_id: &str) -> Result<Vec<(String, TeamRole)>> {
    let teams = sqlx::query_as::<_, (String, String)>(
        "SELECT team_id, team_role FROM user_teams WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(teams
        .into_iter()
        .map(|(id, role)| (id, TeamRole::from_str(&role).unwrap_or(TeamRole::Member)))
        .collect())
}

/// Get user's teams in an organization
pub async fn get_user_teams_in_org(pool: &SqlitePool, user_id: &str, org_id: &str) -> Result<Vec<String>> {
    let teams = sqlx::query_scalar::<_, String>(
        r#"
        SELECT ut.team_id FROM user_teams ut
        JOIN teams t ON ut.team_id = t.id
        JOIN departments d ON t.department_id = d.id
        WHERE ut.user_id = ? AND d.organization_id = ?
        "#,
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    Ok(teams)
}

/// Check if user is team lead
pub async fn is_team_lead(pool: &SqlitePool, user_id: &str, team_id: &str) -> Result<bool> {
    let result = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM user_teams WHERE user_id = ? AND team_id = ? AND team_role = 'lead'",
    )
    .bind(user_id)
    .bind(team_id)
    .fetch_one(pool)
    .await?;

    Ok(result > 0)
}

/// Check if user is member of team
pub async fn is_team_member(pool: &SqlitePool, user_id: &str, team_id: &str) -> Result<bool> {
    let result = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM user_teams WHERE user_id = ? AND team_id = ?",
    )
    .bind(user_id)
    .bind(team_id)
    .fetch_one(pool)
    .await?;

    Ok(result > 0)
}

// ============================================================================
// Utilities
// ============================================================================

/// Convert a name to a URL-friendly slug
fn slugify(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("My Organization"), "my-organization");
        assert_eq!(slugify("Security Team 1"), "security-team-1");
        assert_eq!(slugify("IT & Security"), "it-security");
        assert_eq!(slugify("  Multiple   Spaces  "), "multiple-spaces");
    }

    #[test]
    fn test_org_role_privilege() {
        assert!(OrgRole::Owner.has_privilege_over(&OrgRole::Admin));
        assert!(OrgRole::Owner.has_privilege_over(&OrgRole::Member));
        assert!(OrgRole::Admin.has_privilege_over(&OrgRole::Member));
        assert!(!OrgRole::Member.has_privilege_over(&OrgRole::Admin));
        assert!(!OrgRole::Admin.has_privilege_over(&OrgRole::Owner));
    }

    #[test]
    fn test_share_permission_includes() {
        assert!(SharePermissionLevel::Admin.includes(&SharePermissionLevel::Edit));
        assert!(SharePermissionLevel::Admin.includes(&SharePermissionLevel::View));
        assert!(SharePermissionLevel::Edit.includes(&SharePermissionLevel::View));
        assert!(!SharePermissionLevel::View.includes(&SharePermissionLevel::Edit));
        assert!(!SharePermissionLevel::Edit.includes(&SharePermissionLevel::Admin));
    }
}
