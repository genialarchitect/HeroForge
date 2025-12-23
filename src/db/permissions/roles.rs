//! Role templates and custom role management

use anyhow::{anyhow, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use super::types::*;

// ============================================================================
// Resource Types and Actions
// ============================================================================

/// List all resource types
pub async fn list_resource_types(pool: &SqlitePool) -> Result<Vec<ResourceType>> {
    let types = sqlx::query_as::<_, ResourceType>(
        "SELECT * FROM resource_types ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    Ok(types)
}

/// List all actions
pub async fn list_actions(pool: &SqlitePool) -> Result<Vec<Action>> {
    let actions = sqlx::query_as::<_, Action>(
        "SELECT * FROM actions ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    Ok(actions)
}

/// List all permissions
pub async fn list_permissions(pool: &SqlitePool) -> Result<Vec<PermissionInfo>> {
    let perms = sqlx::query_as::<_, (String, String, Option<String>, String, String, bool)>(
        r#"
        SELECT p.id, p.name, p.description, rt.name, a.name, p.is_system
        FROM permissions p
        JOIN resource_types rt ON p.resource_type_id = rt.id
        JOIN actions a ON p.action_id = a.id
        ORDER BY rt.name, a.name
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(perms
        .into_iter()
        .map(|(id, name, description, resource_type, action, is_system)| PermissionInfo {
            id,
            name,
            description,
            resource_type,
            action,
            is_system,
        })
        .collect())
}

/// Get permission by ID
pub async fn get_permission_by_id(pool: &SqlitePool, id: &str) -> Result<Option<Permission>> {
    let perm = sqlx::query_as::<_, Permission>(
        "SELECT * FROM permissions WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(perm)
}

/// Find permission by resource type and action names
pub async fn find_permission(
    pool: &SqlitePool,
    resource_type: &str,
    action: &str,
) -> Result<Option<Permission>> {
    let perm = sqlx::query_as::<_, Permission>(
        r#"
        SELECT p.* FROM permissions p
        JOIN resource_types rt ON p.resource_type_id = rt.id
        JOIN actions a ON p.action_id = a.id
        WHERE rt.name = ? AND a.name = ?
        "#,
    )
    .bind(resource_type)
    .bind(action)
    .fetch_optional(pool)
    .await?;

    Ok(perm)
}

// ============================================================================
// Role Templates
// ============================================================================

/// List all role templates
pub async fn list_role_templates(pool: &SqlitePool) -> Result<Vec<RoleTemplate>> {
    let templates = sqlx::query_as::<_, RoleTemplate>(
        "SELECT * FROM role_templates ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Get role template by ID
pub async fn get_role_template_by_id(pool: &SqlitePool, id: &str) -> Result<Option<RoleTemplate>> {
    let template = sqlx::query_as::<_, RoleTemplate>(
        "SELECT * FROM role_templates WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(template)
}

/// Get role template by name
pub async fn get_role_template_by_name(pool: &SqlitePool, name: &str) -> Result<Option<RoleTemplate>> {
    let template = sqlx::query_as::<_, RoleTemplate>(
        "SELECT * FROM role_templates WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;

    Ok(template)
}

/// Get template with full permission and policy info
pub async fn get_role_template_info(pool: &SqlitePool, id: &str) -> Result<Option<RoleTemplateInfo>> {
    let template = get_role_template_by_id(pool, id).await?;

    match template {
        Some(t) => {
            let permissions = get_template_permissions(pool, id).await?;
            let policies = get_template_policies(pool, id).await?;

            Ok(Some(RoleTemplateInfo {
                id: t.id,
                name: t.name,
                display_name: t.display_name,
                description: t.description,
                icon: t.icon,
                color: t.color,
                permissions,
                policies,
                is_system: t.is_system,
            }))
        }
        None => Ok(None),
    }
}

/// Get permissions for a role template
pub async fn get_template_permissions(pool: &SqlitePool, template_id: &str) -> Result<Vec<PermissionInfo>> {
    let perms = sqlx::query_as::<_, (String, String, Option<String>, String, String, bool)>(
        r#"
        SELECT p.id, p.name, p.description, rt.name, a.name, p.is_system
        FROM permissions p
        JOIN resource_types rt ON p.resource_type_id = rt.id
        JOIN actions a ON p.action_id = a.id
        JOIN role_template_permissions rtp ON p.id = rtp.permission_id
        WHERE rtp.template_id = ?
        ORDER BY rt.name, a.name
        "#,
    )
    .bind(template_id)
    .fetch_all(pool)
    .await?;

    Ok(perms
        .into_iter()
        .map(|(id, name, description, resource_type, action, is_system)| PermissionInfo {
            id,
            name,
            description,
            resource_type,
            action,
            is_system,
        })
        .collect())
}

/// Get policies for a role template
pub async fn get_template_policies(pool: &SqlitePool, template_id: &str) -> Result<Vec<PolicyInfo>> {
    let policies = sqlx::query_as::<_, (String, String, Option<String>, String, String, i32, String, bool, bool)>(
        r#"
        SELECT p.id, p.name, p.description, rt.name, p.effect, p.priority, p.conditions, p.is_active, p.is_system
        FROM policies p
        JOIN resource_types rt ON p.resource_type_id = rt.id
        JOIN role_template_policies rtp ON p.id = rtp.policy_id
        WHERE rtp.template_id = ?
        ORDER BY p.priority
        "#,
    )
    .bind(template_id)
    .fetch_all(pool)
    .await?;

    let mut result = Vec::new();
    for (id, name, description, resource_type, effect, priority, conditions, is_active, is_system) in policies {
        // Get actions for this policy
        let actions = sqlx::query_scalar::<_, String>(
            r#"
            SELECT a.name FROM actions a
            JOIN policy_actions pa ON a.id = pa.action_id
            WHERE pa.policy_id = ?
            "#,
        )
        .bind(&id)
        .fetch_all(pool)
        .await?;

        let cond: PolicyConditions = serde_json::from_str(&conditions).unwrap_or_default();

        result.push(PolicyInfo {
            id,
            name,
            description,
            resource_type,
            effect: PolicyEffect::from_str(&effect).unwrap_or(PolicyEffect::Allow),
            priority,
            conditions: cond,
            actions,
            is_active,
            is_system,
        });
    }

    Ok(result)
}

// ============================================================================
// Custom Roles
// ============================================================================

/// Create a custom role
pub async fn create_custom_role(
    pool: &SqlitePool,
    org_id: &str,
    req: &CreateCustomRoleRequest,
    created_by: &str,
) -> Result<CustomRole> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Check for duplicate name in org
    let existing = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM custom_roles WHERE organization_id = ? AND name = ?",
    )
    .bind(org_id)
    .bind(&req.name)
    .fetch_one(pool)
    .await?;

    if existing > 0 {
        return Err(anyhow!("A role with this name already exists in the organization"));
    }

    sqlx::query(
        r#"
        INSERT INTO custom_roles (id, organization_id, based_on_template_id, name, display_name, description, is_active, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(org_id)
    .bind(&req.based_on_template_id)
    .bind(&req.name)
    .bind(&req.display_name)
    .bind(&req.description)
    .bind(created_by)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    // Apply permission overrides if provided
    if let Some(overrides) = &req.permission_overrides {
        for override_req in overrides {
            sqlx::query(
                r#"
                INSERT INTO custom_role_permissions (role_id, permission_id, granted)
                VALUES (?, ?, ?)
                "#,
            )
            .bind(&id)
            .bind(&override_req.permission_id)
            .bind(override_req.granted)
            .execute(pool)
            .await?;
        }
    }

    get_custom_role_by_id(pool, &id)
        .await?
        .ok_or_else(|| anyhow!("Failed to create custom role"))
}

/// Get custom role by ID
pub async fn get_custom_role_by_id(pool: &SqlitePool, id: &str) -> Result<Option<CustomRole>> {
    let role = sqlx::query_as::<_, CustomRole>(
        "SELECT * FROM custom_roles WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(role)
}

/// List custom roles in an organization
pub async fn list_custom_roles(pool: &SqlitePool, org_id: &str) -> Result<Vec<CustomRole>> {
    let roles = sqlx::query_as::<_, CustomRole>(
        "SELECT * FROM custom_roles WHERE organization_id = ? AND is_active = 1 ORDER BY name",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    Ok(roles)
}

/// Update a custom role
pub async fn update_custom_role(
    pool: &SqlitePool,
    id: &str,
    req: &UpdateCustomRoleRequest,
) -> Result<CustomRole> {
    let now = Utc::now().to_rfc3339();
    let existing = get_custom_role_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow!("Custom role not found"))?;

    let display_name = req.display_name.as_ref().unwrap_or(&existing.display_name);
    let description = req.description.as_ref().or(existing.description.as_ref());
    let is_active = req.is_active.unwrap_or(existing.is_active);

    sqlx::query(
        r#"
        UPDATE custom_roles SET display_name = ?, description = ?, is_active = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(display_name)
    .bind(description)
    .bind(is_active)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    // Update permission overrides if provided
    if let Some(overrides) = &req.permission_overrides {
        // Clear existing overrides
        sqlx::query("DELETE FROM custom_role_permissions WHERE role_id = ?")
            .bind(id)
            .execute(pool)
            .await?;

        // Add new overrides
        for override_req in overrides {
            sqlx::query(
                r#"
                INSERT INTO custom_role_permissions (role_id, permission_id, granted)
                VALUES (?, ?, ?)
                "#,
            )
            .bind(id)
            .bind(&override_req.permission_id)
            .bind(override_req.granted)
            .execute(pool)
            .await?;
        }
    }

    get_custom_role_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow!("Custom role not found"))
}

/// Delete a custom role
pub async fn delete_custom_role(pool: &SqlitePool, id: &str) -> Result<()> {
    // Check if role is in use
    let assignments = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM user_role_assignments WHERE role_type = 'custom' AND role_id = ? AND is_active = 1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    if assignments > 0 {
        return Err(anyhow!("Cannot delete role that is currently assigned to users"));
    }

    // Delete permission overrides
    sqlx::query("DELETE FROM custom_role_permissions WHERE role_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    // Delete role
    sqlx::query("DELETE FROM custom_roles WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Clone a custom role
pub async fn clone_custom_role(
    pool: &SqlitePool,
    source_id: &str,
    new_name: &str,
    new_display_name: &str,
    created_by: &str,
) -> Result<CustomRole> {
    let source = get_custom_role_by_id(pool, source_id)
        .await?
        .ok_or_else(|| anyhow!("Source role not found"))?;

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO custom_roles (id, organization_id, based_on_template_id, name, display_name, description, is_active, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&source.organization_id)
    .bind(&source.based_on_template_id)
    .bind(new_name)
    .bind(new_display_name)
    .bind(&source.description)
    .bind(created_by)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    // Copy permission overrides
    sqlx::query(
        r#"
        INSERT INTO custom_role_permissions (role_id, permission_id, granted)
        SELECT ?, permission_id, granted FROM custom_role_permissions WHERE role_id = ?
        "#,
    )
    .bind(&id)
    .bind(source_id)
    .execute(pool)
    .await?;

    get_custom_role_by_id(pool, &id)
        .await?
        .ok_or_else(|| anyhow!("Failed to clone role"))
}

/// Get effective permissions for a custom role (template + overrides)
pub async fn get_custom_role_permissions(pool: &SqlitePool, role_id: &str) -> Result<Vec<(PermissionInfo, bool)>> {
    let role = get_custom_role_by_id(pool, role_id)
        .await?
        .ok_or_else(|| anyhow!("Custom role not found"))?;

    // Start with template permissions if based on one
    let mut permissions: std::collections::HashMap<String, (PermissionInfo, bool)> = std::collections::HashMap::new();

    if let Some(template_id) = &role.based_on_template_id {
        for perm in get_template_permissions(pool, template_id).await? {
            permissions.insert(perm.id.clone(), (perm, true));
        }
    }

    // Apply custom overrides
    let overrides = sqlx::query_as::<_, (String, String, Option<String>, String, String, bool, bool)>(
        r#"
        SELECT p.id, p.name, p.description, rt.name, a.name, p.is_system, crp.granted
        FROM permissions p
        JOIN resource_types rt ON p.resource_type_id = rt.id
        JOIN actions a ON p.action_id = a.id
        JOIN custom_role_permissions crp ON p.id = crp.permission_id
        WHERE crp.role_id = ?
        "#,
    )
    .bind(role_id)
    .fetch_all(pool)
    .await?;

    for (id, name, description, resource_type, action, is_system, granted) in overrides {
        let perm_info = PermissionInfo {
            id: id.clone(),
            name,
            description,
            resource_type,
            action,
            is_system,
        };
        permissions.insert(id, (perm_info, granted));
    }

    Ok(permissions.into_values().collect())
}

// ============================================================================
// Role Assignments
// ============================================================================

/// Assign a role to a user
pub async fn assign_role_to_user(
    pool: &SqlitePool,
    user_id: &str,
    org_id: &str,
    req: &AssignRoleRequest,
    assigned_by: Option<&str>,
) -> Result<UserRoleAssignment> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Validate role exists
    match req.role_type {
        RoleType::Template => {
            get_role_template_by_id(pool, &req.role_id)
                .await?
                .ok_or_else(|| anyhow!("Role template not found"))?;
        }
        RoleType::Custom => {
            let role = get_custom_role_by_id(pool, &req.role_id)
                .await?
                .ok_or_else(|| anyhow!("Custom role not found"))?;

            if role.organization_id != org_id {
                return Err(anyhow!("Custom role belongs to a different organization"));
            }
        }
    }

    // Validate scope if provided
    let scope_type_str = req.scope_type.map(|s| s.as_str().to_string());
    if let (Some(st), Some(sid)) = (&req.scope_type, &req.scope_id) {
        match st {
            ScopeType::Department => {
                let dept_org = super::organizations::get_department_org_id(pool, sid).await?;
                if dept_org.as_deref() != Some(org_id) {
                    return Err(anyhow!("Department does not belong to this organization"));
                }
            }
            ScopeType::Team => {
                let team_org = super::organizations::get_team_org_id(pool, sid).await?;
                if team_org.as_deref() != Some(org_id) {
                    return Err(anyhow!("Team does not belong to this organization"));
                }
            }
            ScopeType::Organization => {
                // No additional validation needed
            }
        }
    }

    let expires_at = req.expires_at.map(|dt| dt.to_rfc3339());

    sqlx::query(
        r#"
        INSERT INTO user_role_assignments (id, user_id, organization_id, role_type, role_id, scope_type, scope_id, assigned_at, assigned_by, expires_at, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(org_id)
    .bind(req.role_type.as_str())
    .bind(&req.role_id)
    .bind(&scope_type_str)
    .bind(&req.scope_id)
    .bind(&now)
    .bind(assigned_by)
    .bind(&expires_at)
    .execute(pool)
    .await?;

    // Invalidate permission cache for this user
    super::cache::invalidate_user_cache(pool, user_id, org_id).await?;

    get_role_assignment_by_id(pool, &id)
        .await?
        .ok_or_else(|| anyhow!("Failed to create role assignment"))
}

/// Get role assignment by ID
pub async fn get_role_assignment_by_id(pool: &SqlitePool, id: &str) -> Result<Option<UserRoleAssignment>> {
    let assignment = sqlx::query_as::<_, UserRoleAssignment>(
        "SELECT * FROM user_role_assignments WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(assignment)
}

/// List role assignments for a user
pub async fn list_user_role_assignments(
    pool: &SqlitePool,
    user_id: &str,
    org_id: &str,
) -> Result<Vec<RoleAssignmentInfo>> {
    let assignments = sqlx::query_as::<_, UserRoleAssignment>(
        r#"
        SELECT * FROM user_role_assignments
        WHERE user_id = ? AND organization_id = ? AND is_active = 1
        AND (expires_at IS NULL OR expires_at > datetime('now'))
        ORDER BY assigned_at DESC
        "#,
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    let mut result = Vec::new();
    for a in assignments {
        // Get role name/display_name
        let (role_name, role_display_name) = match RoleType::from_str(&a.role_type) {
            Some(RoleType::Template) => {
                if let Some(t) = get_role_template_by_id(pool, &a.role_id).await? {
                    (t.name, t.display_name)
                } else {
                    continue;
                }
            }
            Some(RoleType::Custom) => {
                if let Some(r) = get_custom_role_by_id(pool, &a.role_id).await? {
                    (r.name, r.display_name)
                } else {
                    continue;
                }
            }
            None => continue,
        };

        // Get scope name if applicable
        let scope_name = match (ScopeType::from_str(a.scope_type.as_deref().unwrap_or("")), &a.scope_id) {
            (Some(ScopeType::Department), Some(id)) => {
                super::organizations::get_department_by_id(pool, id)
                    .await?
                    .map(|d| d.name)
            }
            (Some(ScopeType::Team), Some(id)) => {
                super::organizations::get_team_by_id(pool, id)
                    .await?
                    .map(|t| t.name)
            }
            _ => None,
        };

        result.push(RoleAssignmentInfo {
            id: a.id,
            role_type: RoleType::from_str(&a.role_type).unwrap_or(RoleType::Template),
            role_id: a.role_id,
            role_name,
            role_display_name,
            scope_type: a.scope_type.and_then(|s| ScopeType::from_str(&s)),
            scope_id: a.scope_id,
            scope_name,
            assigned_at: a.assigned_at,
            assigned_by: a.assigned_by,
            expires_at: a.expires_at,
            is_active: a.is_active,
        });
    }

    Ok(result)
}

/// Remove a role assignment
pub async fn remove_role_assignment(pool: &SqlitePool, assignment_id: &str) -> Result<()> {
    // Get assignment to find user for cache invalidation
    let assignment = get_role_assignment_by_id(pool, assignment_id).await?;

    sqlx::query("UPDATE user_role_assignments SET is_active = 0 WHERE id = ?")
        .bind(assignment_id)
        .execute(pool)
        .await?;

    // Invalidate cache
    if let Some(a) = assignment {
        super::cache::invalidate_user_cache(pool, &a.user_id, &a.organization_id).await?;
    }

    Ok(())
}

/// Get all active role assignments for a user (for permission evaluation)
pub async fn get_active_role_assignments(
    pool: &SqlitePool,
    user_id: &str,
    org_id: &str,
) -> Result<Vec<UserRoleAssignment>> {
    let assignments = sqlx::query_as::<_, UserRoleAssignment>(
        r#"
        SELECT * FROM user_role_assignments
        WHERE user_id = ? AND organization_id = ? AND is_active = 1
        AND (expires_at IS NULL OR expires_at > datetime('now'))
        "#,
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    Ok(assignments)
}

// ============================================================================
// User Permission Overrides
// ============================================================================

/// Add a permission override for a user
pub async fn add_user_permission_override(
    pool: &SqlitePool,
    user_id: &str,
    org_id: &str,
    req: &AddPermissionOverrideRequest,
    granted_by: &str,
) -> Result<UserPermissionOverride> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Validate permission exists
    get_permission_by_id(pool, &req.permission_id)
        .await?
        .ok_or_else(|| anyhow!("Permission not found"))?;

    let expires_at = req.expires_at.map(|dt| dt.to_rfc3339());

    // Remove any existing override for this permission
    sqlx::query(
        "DELETE FROM user_permission_overrides WHERE user_id = ? AND organization_id = ? AND permission_id = ?",
    )
    .bind(user_id)
    .bind(org_id)
    .bind(&req.permission_id)
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO user_permission_overrides (id, user_id, organization_id, permission_id, granted, reason, granted_by, granted_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(org_id)
    .bind(&req.permission_id)
    .bind(req.granted)
    .bind(&req.reason)
    .bind(granted_by)
    .bind(&now)
    .bind(&expires_at)
    .execute(pool)
    .await?;

    // Invalidate cache
    super::cache::invalidate_user_cache(pool, user_id, org_id).await?;

    get_user_permission_override_by_id(pool, &id)
        .await?
        .ok_or_else(|| anyhow!("Failed to create override"))
}

/// Get user permission override by ID
pub async fn get_user_permission_override_by_id(pool: &SqlitePool, id: &str) -> Result<Option<UserPermissionOverride>> {
    let override_rec = sqlx::query_as::<_, UserPermissionOverride>(
        "SELECT * FROM user_permission_overrides WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(override_rec)
}

/// List user permission overrides
pub async fn list_user_permission_overrides(
    pool: &SqlitePool,
    user_id: &str,
    org_id: &str,
) -> Result<Vec<UserPermissionOverride>> {
    let overrides = sqlx::query_as::<_, UserPermissionOverride>(
        r#"
        SELECT * FROM user_permission_overrides
        WHERE user_id = ? AND organization_id = ?
        AND (expires_at IS NULL OR expires_at > datetime('now'))
        ORDER BY granted_at DESC
        "#,
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    Ok(overrides)
}

/// Remove a user permission override
pub async fn remove_user_permission_override(pool: &SqlitePool, override_id: &str) -> Result<()> {
    // Get override for cache invalidation
    let override_rec = get_user_permission_override_by_id(pool, override_id).await?;

    sqlx::query("DELETE FROM user_permission_overrides WHERE id = ?")
        .bind(override_id)
        .execute(pool)
        .await?;

    // Invalidate cache
    if let Some(o) = override_rec {
        super::cache::invalidate_user_cache(pool, &o.user_id, &o.organization_id).await?;
    }

    Ok(())
}

/// Get active permission overrides for a user (for permission evaluation)
pub async fn get_active_permission_overrides(
    pool: &SqlitePool,
    user_id: &str,
    org_id: &str,
) -> Result<Vec<UserPermissionOverride>> {
    let overrides = sqlx::query_as::<_, UserPermissionOverride>(
        r#"
        SELECT * FROM user_permission_overrides
        WHERE user_id = ? AND organization_id = ?
        AND (expires_at IS NULL OR expires_at > datetime('now'))
        "#,
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    Ok(overrides)
}

// ============================================================================
// Policies
// ============================================================================

/// List all active policies
pub async fn list_policies(pool: &SqlitePool) -> Result<Vec<PolicyInfo>> {
    let policies = sqlx::query_as::<_, (String, String, Option<String>, String, String, i32, String, bool, bool)>(
        r#"
        SELECT p.id, p.name, p.description, rt.name, p.effect, p.priority, p.conditions, p.is_active, p.is_system
        FROM policies p
        JOIN resource_types rt ON p.resource_type_id = rt.id
        WHERE p.is_active = 1
        ORDER BY p.priority
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut result = Vec::new();
    for (id, name, description, resource_type, effect, priority, conditions, is_active, is_system) in policies {
        let actions = sqlx::query_scalar::<_, String>(
            r#"
            SELECT a.name FROM actions a
            JOIN policy_actions pa ON a.id = pa.action_id
            WHERE pa.policy_id = ?
            "#,
        )
        .bind(&id)
        .fetch_all(pool)
        .await?;

        let cond: PolicyConditions = serde_json::from_str(&conditions).unwrap_or_default();

        result.push(PolicyInfo {
            id,
            name,
            description,
            resource_type,
            effect: PolicyEffect::from_str(&effect).unwrap_or(PolicyEffect::Allow),
            priority,
            conditions: cond,
            actions,
            is_active,
            is_system,
        });
    }

    Ok(result)
}

/// Get policies for a resource type
pub async fn get_policies_for_resource(pool: &SqlitePool, resource_type: &str) -> Result<Vec<Policy>> {
    let policies = sqlx::query_as::<_, Policy>(
        r#"
        SELECT p.* FROM policies p
        JOIN resource_types rt ON p.resource_type_id = rt.id
        WHERE rt.name = ? AND p.is_active = 1
        ORDER BY p.priority
        "#,
    )
    .bind(resource_type)
    .fetch_all(pool)
    .await?;

    Ok(policies)
}

/// Get policy actions
pub async fn get_policy_actions(pool: &SqlitePool, policy_id: &str) -> Result<Vec<String>> {
    let actions = sqlx::query_scalar::<_, String>(
        r#"
        SELECT a.name FROM actions a
        JOIN policy_actions pa ON a.id = pa.action_id
        WHERE pa.policy_id = ?
        "#,
    )
    .bind(policy_id)
    .fetch_all(pool)
    .await?;

    Ok(actions)
}
