//! Permission evaluation algorithm
//!
//! Implements ABAC (Attribute-Based Access Control) permission checking
//! with hierarchical role inheritance.
//!
//! # Evaluation Order (highest to lowest priority)
//!
//! 1. User permission overrides (explicit grants/denies)
//! 2. Team-scoped role assignments
//! 3. Department-scoped role assignments
//! 4. Organization-wide role assignments
//! 5. ABAC policies
//! 6. Resource ownership/sharing
//! 7. Default deny

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use std::collections::HashSet;

use super::cache;
use super::organizations;
use super::roles;
use super::types::*;

/// Check if a user has permission to perform an action
pub async fn check_permission(
    pool: &SqlitePool,
    ctx: &PermissionContext,
) -> Result<PermissionResult> {
    // 1. Check cache
    if let Some(cached) = cache::get_cached_permission(pool, ctx).await? {
        return Ok(cached);
    }

    // 2. Evaluate permission
    let result = evaluate_permission(pool, ctx).await?;

    // 3. Cache the result
    cache::cache_permission(pool, ctx, &result).await?;

    Ok(result)
}

/// Core permission evaluation logic
async fn evaluate_permission(
    pool: &SqlitePool,
    ctx: &PermissionContext,
) -> Result<PermissionResult> {
    // Check if user is system admin (has 'admin' role template at org level)
    if is_system_admin(pool, &ctx.user_id, &ctx.organization_id).await? {
        return Ok(PermissionResult::allowed(PermissionReason::SystemAdmin));
    }

    // Check if user is org owner/admin (bypass for org management)
    let org_role = organizations::get_user_org_role(pool, &ctx.user_id, &ctx.organization_id).await?;
    if matches!(org_role, Some(OrgRole::Owner)) {
        return Ok(PermissionResult::allowed(PermissionReason::OrgAdminBypass));
    }

    // Find the permission by resource type and action
    let permission = roles::find_permission(pool, &ctx.resource_type, &ctx.action).await?;
    let permission_id = match &permission {
        Some(p) => p.id.clone(),
        None => {
            // Unknown permission = denied
            return Ok(PermissionResult::denied(PermissionReason::NoPermission));
        }
    };

    // 1. Check user permission overrides (highest priority)
    let overrides = roles::get_active_permission_overrides(pool, &ctx.user_id, &ctx.organization_id).await?;
    for override_rec in &overrides {
        if override_rec.permission_id == permission_id {
            if override_rec.granted {
                return Ok(PermissionResult::allowed(PermissionReason::UserOverride));
            } else {
                return Ok(PermissionResult::denied(PermissionReason::UserOverrideDeny));
            }
        }
    }

    // Get user's teams for scope checking
    let user_teams = organizations::get_user_teams_in_org(pool, &ctx.user_id, &ctx.organization_id).await?;

    // 2. Check role assignments (hierarchical: team → dept → org)
    let assignments = roles::get_active_role_assignments(pool, &ctx.user_id, &ctx.organization_id).await?;

    // Sort by scope specificity (team > department > org)
    let mut sorted_assignments = assignments.clone();
    sorted_assignments.sort_by(|a, b| {
        let scope_priority = |s: &Option<String>| match s.as_deref() {
            Some("team") => 0,
            Some("department") => 1,
            _ => 2,
        };
        scope_priority(&a.scope_type).cmp(&scope_priority(&b.scope_type))
    });

    for assignment in &sorted_assignments {
        // Check if assignment scope matches context
        if !scope_matches(pool, &assignment, &user_teams, ctx.resource_id.as_deref()).await? {
            continue;
        }

        // Check if this role grants the permission
        let has_perm = match RoleType::from_str(&assignment.role_type) {
            Some(RoleType::Template) => {
                check_template_has_permission(pool, &assignment.role_id, &permission_id).await?
            }
            Some(RoleType::Custom) => {
                check_custom_role_has_permission(pool, &assignment.role_id, &permission_id).await?
            }
            None => false,
        };

        if has_perm {
            let role_name = get_role_name(pool, &assignment.role_type, &assignment.role_id).await?;
            return Ok(PermissionResult::allowed(PermissionReason::RoleGrant { role_name })
                .with_role(&assignment.role_id));
        }
    }

    // 3. Check ABAC policies
    let policies = roles::get_policies_for_resource(pool, &ctx.resource_type).await?;
    for policy in &policies {
        // Check if policy applies to this action
        let policy_actions = roles::get_policy_actions(pool, &policy.id).await?;
        if !policy_actions.iter().any(|a| a == &ctx.action || a == "*") {
            continue;
        }

        // Evaluate policy conditions
        let conditions: PolicyConditions = serde_json::from_str(&policy.conditions).unwrap_or_default();
        let matches = evaluate_policy_conditions(pool, ctx, &conditions).await?;

        if matches {
            match PolicyEffect::from_str(&policy.effect) {
                Some(PolicyEffect::Allow) => {
                    return Ok(PermissionResult::allowed(PermissionReason::PolicyAllow)
                        .with_policy(&policy.id, &policy.name));
                }
                Some(PolicyEffect::Deny) => {
                    return Ok(PermissionResult::denied(PermissionReason::PolicyDeny)
                        .with_policy(&policy.id, &policy.name));
                }
                None => {}
            }
        }
    }

    // 4. Check resource ownership (if resource_id is provided)
    if let Some(resource_id) = &ctx.resource_id {
        // Check if user owns the resource
        if is_resource_owner(pool, &ctx.user_id, &ctx.resource_type, resource_id).await? {
            return Ok(PermissionResult::allowed(PermissionReason::ResourceOwner));
        }

        // Check if resource is shared with user
        if let Some(share_level) = get_share_permission(pool, &ctx.user_id, &user_teams, &ctx.resource_type, resource_id).await? {
            // Map action to required share level
            let required_level = match ctx.action.as_str() {
                "read" | "export" => SharePermissionLevel::View,
                "update" | "execute" => SharePermissionLevel::Edit,
                "delete" | "share" => SharePermissionLevel::Admin,
                _ => SharePermissionLevel::Admin,
            };

            if share_level.includes(&required_level) {
                return Ok(PermissionResult::allowed(PermissionReason::SharedAccess {
                    level: share_level.as_str().to_string(),
                }));
            }
        }
    }

    // 5. Default deny
    Ok(PermissionResult::denied(PermissionReason::NoPermission))
}

/// Check if a role assignment's scope matches the current context
async fn scope_matches(
    pool: &SqlitePool,
    assignment: &UserRoleAssignment,
    user_teams: &[String],
    resource_id: Option<&str>,
) -> Result<bool> {
    match (assignment.scope_type.as_deref(), &assignment.scope_id) {
        // Team-scoped: user must be in that team
        (Some("team"), Some(team_id)) => {
            Ok(user_teams.contains(team_id))
        }
        // Department-scoped: user must be in a team in that department
        (Some("department"), Some(dept_id)) => {
            for team_id in user_teams {
                if let Some(team_dept) = organizations::get_team_dept_id(pool, team_id).await? {
                    if &team_dept == dept_id {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        // Organization-wide or no scope: always matches
        _ => Ok(true),
    }
}

/// Check if a template has a specific permission
async fn check_template_has_permission(
    pool: &SqlitePool,
    template_id: &str,
    permission_id: &str,
) -> Result<bool> {
    let count = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM role_template_permissions WHERE template_id = ? AND permission_id = ?",
    )
    .bind(template_id)
    .bind(permission_id)
    .fetch_one(pool)
    .await?;

    Ok(count > 0)
}

/// Check if a custom role has a specific permission (considering template + overrides)
async fn check_custom_role_has_permission(
    pool: &SqlitePool,
    role_id: &str,
    permission_id: &str,
) -> Result<bool> {
    let role = roles::get_custom_role_by_id(pool, role_id).await?;
    let role = match role {
        Some(r) => r,
        None => return Ok(false),
    };

    // Check explicit override first
    let override_rec = sqlx::query_as::<_, (bool,)>(
        "SELECT granted FROM custom_role_permissions WHERE role_id = ? AND permission_id = ?",
    )
    .bind(role_id)
    .bind(permission_id)
    .fetch_optional(pool)
    .await?;

    if let Some((granted,)) = override_rec {
        return Ok(granted);
    }

    // Fall back to template
    if let Some(template_id) = &role.based_on_template_id {
        return check_template_has_permission(pool, template_id, permission_id).await;
    }

    Ok(false)
}

/// Get role name for logging
async fn get_role_name(pool: &SqlitePool, role_type: &str, role_id: &str) -> Result<String> {
    match role_type {
        "template" => {
            if let Some(t) = roles::get_role_template_by_id(pool, role_id).await? {
                Ok(t.display_name)
            } else {
                Ok("Unknown".to_string())
            }
        }
        "custom" => {
            if let Some(r) = roles::get_custom_role_by_id(pool, role_id).await? {
                Ok(r.display_name)
            } else {
                Ok("Unknown".to_string())
            }
        }
        _ => Ok("Unknown".to_string()),
    }
}

/// Evaluate ABAC policy conditions
async fn evaluate_policy_conditions(
    pool: &SqlitePool,
    ctx: &PermissionContext,
    conditions: &PolicyConditions,
) -> Result<bool> {
    // Empty conditions = always matches
    if conditions.owner == false
        && conditions.team_member == false
        && conditions.department_member == false
        && conditions.organization_member == false
        && conditions.required_roles.is_empty()
        && conditions.required_team_roles.is_empty()
        && conditions.required_org_roles.is_empty()
        && conditions.attributes.is_empty()
        && conditions.time_conditions.is_none()
        && conditions.ip_conditions.is_none()
    {
        return Ok(true);
    }

    // Check owner condition
    if conditions.owner {
        if let Some(resource_id) = &ctx.resource_id {
            if !is_resource_owner(pool, &ctx.user_id, &ctx.resource_type, resource_id).await? {
                return Ok(false);
            }
        } else {
            // Can't check ownership without resource_id
            return Ok(false);
        }
    }

    // Check organization membership
    if conditions.organization_member {
        let is_member = organizations::get_user_org_role(pool, &ctx.user_id, &ctx.organization_id)
            .await?
            .is_some();
        if !is_member {
            return Ok(false);
        }
    }

    // Check team membership
    if conditions.team_member {
        if let Some(resource_id) = &ctx.resource_id {
            let owner_team = get_resource_owner_team(pool, &ctx.resource_type, resource_id).await?;
            if let Some(team_id) = owner_team {
                let user_teams = organizations::get_user_teams_in_org(pool, &ctx.user_id, &ctx.organization_id).await?;
                if !user_teams.contains(&team_id) {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }
    }

    // Check required org roles
    if !conditions.required_org_roles.is_empty() {
        let user_role = organizations::get_user_org_role(pool, &ctx.user_id, &ctx.organization_id).await?;
        let has_role = user_role
            .map(|r| conditions.required_org_roles.contains(&r.as_str().to_string()))
            .unwrap_or(false);
        if !has_role {
            return Ok(false);
        }
    }

    // Check required team roles
    if !conditions.required_team_roles.is_empty() {
        let user_teams = organizations::get_user_teams(pool, &ctx.user_id).await?;
        let has_role = user_teams
            .iter()
            .any(|(_, role)| conditions.required_team_roles.contains(&role.as_str().to_string()));
        if !has_role {
            return Ok(false);
        }
    }

    // Check time conditions
    if let Some(time_cond) = &conditions.time_conditions {
        if !evaluate_time_conditions(time_cond)? {
            return Ok(false);
        }
    }

    // Check IP conditions
    if let Some(ip_cond) = &conditions.ip_conditions {
        if let Some(ip) = &ctx.ip_address {
            if !evaluate_ip_conditions(ip_cond, ip)? {
                return Ok(false);
            }
        } else {
            // No IP provided but IP conditions exist
            return Ok(false);
        }
    }

    Ok(true)
}

/// Evaluate time-based conditions
fn evaluate_time_conditions(cond: &TimeConditions) -> Result<bool> {
    let now = Utc::now();

    // Check day of week
    if let Some(allowed_days) = &cond.allowed_days {
        let current_day = now.format("%w").to_string().parse::<u8>()?;
        if !allowed_days.contains(&current_day) {
            return Ok(false);
        }
    }

    // Check hour range
    let current_hour = now.format("%H").to_string().parse::<u8>()?;
    if let (Some(start), Some(end)) = (cond.start_hour, cond.end_hour) {
        if start <= end {
            // Normal range (e.g., 9-17)
            if current_hour < start || current_hour > end {
                return Ok(false);
            }
        } else {
            // Overnight range (e.g., 22-6)
            if current_hour < start && current_hour > end {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

/// Evaluate IP-based conditions
fn evaluate_ip_conditions(cond: &IpConditions, ip: &str) -> Result<bool> {
    // Parse the IP address
    let addr: std::net::IpAddr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return Ok(false),
    };

    // Check blocked ranges first
    if let Some(blocked) = &cond.blocked_ranges {
        for cidr in blocked {
            if ip_in_cidr(&addr, cidr) {
                return Ok(false);
            }
        }
    }

    // Check allowed ranges (if specified, must be in one of them)
    if let Some(allowed) = &cond.allowed_ranges {
        if !allowed.is_empty() {
            let mut in_allowed = false;
            for cidr in allowed {
                if ip_in_cidr(&addr, cidr) {
                    in_allowed = true;
                    break;
                }
            }
            if !in_allowed {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

/// Check if an IP is in a CIDR range
fn ip_in_cidr(addr: &std::net::IpAddr, cidr: &str) -> bool {
    // Simple CIDR check - in production, use ipnetwork crate
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let network: std::net::IpAddr = match parts[0].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    let prefix_len: u8 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    match (addr, network) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(n)) => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            let a_bits = u32::from(*a);
            let n_bits = u32::from(n);
            (a_bits & mask) == (n_bits & mask)
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(n)) => {
            let mask = if prefix_len == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix_len)
            };
            let a_bits = u128::from(*a);
            let n_bits = u128::from(n);
            (a_bits & mask) == (n_bits & mask)
        }
        _ => false,
    }
}

/// Check if user is a system admin
async fn is_system_admin(pool: &SqlitePool, user_id: &str, org_id: &str) -> Result<bool> {
    let count = sqlx::query_scalar::<_, i32>(
        r#"
        SELECT COUNT(*) FROM user_role_assignments
        WHERE user_id = ? AND organization_id = ?
        AND role_type = 'template' AND role_id = 'admin'
        AND is_active = 1
        AND (expires_at IS NULL OR expires_at > datetime('now'))
        "#,
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_one(pool)
    .await?;

    Ok(count > 0)
}

/// Check if user owns a resource
async fn is_resource_owner(
    pool: &SqlitePool,
    user_id: &str,
    resource_type: &str,
    resource_id: &str,
) -> Result<bool> {
    let count = sqlx::query_scalar::<_, i32>(
        r#"
        SELECT COUNT(*) FROM resource_ownership
        WHERE resource_type = ? AND resource_id = ? AND owner_type = 'user' AND owner_id = ?
        "#,
    )
    .bind(resource_type)
    .bind(resource_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(count > 0)
}

/// Get the team that owns a resource
async fn get_resource_owner_team(
    pool: &SqlitePool,
    resource_type: &str,
    resource_id: &str,
) -> Result<Option<String>> {
    let team = sqlx::query_scalar::<_, String>(
        r#"
        SELECT owner_id FROM resource_ownership
        WHERE resource_type = ? AND resource_id = ? AND owner_type = 'team'
        "#,
    )
    .bind(resource_type)
    .bind(resource_id)
    .fetch_optional(pool)
    .await?;

    Ok(team)
}

/// Get share permission level for a user on a resource
async fn get_share_permission(
    pool: &SqlitePool,
    user_id: &str,
    user_teams: &[String],
    resource_type: &str,
    resource_id: &str,
) -> Result<Option<SharePermissionLevel>> {
    // Check direct user share
    let user_share = sqlx::query_scalar::<_, String>(
        r#"
        SELECT permission_level FROM resource_shares
        WHERE resource_type = ? AND resource_id = ? AND shared_with_type = 'user' AND shared_with_id = ?
        AND (expires_at IS NULL OR expires_at > datetime('now'))
        "#,
    )
    .bind(resource_type)
    .bind(resource_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    if let Some(level) = user_share {
        return Ok(SharePermissionLevel::from_str(&level));
    }

    // Check team shares
    if !user_teams.is_empty() {
        let placeholders = user_teams.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let query = format!(
            r#"
            SELECT permission_level FROM resource_shares
            WHERE resource_type = ? AND resource_id = ? AND shared_with_type = 'team' AND shared_with_id IN ({})
            AND (expires_at IS NULL OR expires_at > datetime('now'))
            ORDER BY CASE permission_level WHEN 'admin' THEN 1 WHEN 'edit' THEN 2 ELSE 3 END
            LIMIT 1
            "#,
            placeholders
        );

        let mut query_builder = sqlx::query_scalar::<_, String>(&query)
            .bind(resource_type)
            .bind(resource_id);

        for team_id in user_teams {
            query_builder = query_builder.bind(team_id);
        }

        if let Some(level) = query_builder.fetch_optional(pool).await? {
            return Ok(SharePermissionLevel::from_str(&level));
        }
    }

    Ok(None)
}

// ============================================================================
// Effective Permissions
// ============================================================================

/// Compute all effective permissions for a user
pub async fn get_effective_permissions(
    pool: &SqlitePool,
    user_id: &str,
    org_id: &str,
) -> Result<EffectivePermissions> {
    let mut granted: HashSet<String> = HashSet::new();
    let mut denied: HashSet<String> = HashSet::new();

    // Get all permissions for building the set
    let all_permissions = roles::list_permissions(pool).await?;

    // Check user permission overrides
    let overrides = roles::get_active_permission_overrides(pool, user_id, org_id).await?;
    for override_rec in &overrides {
        if override_rec.granted {
            granted.insert(override_rec.permission_id.clone());
        } else {
            denied.insert(override_rec.permission_id.clone());
        }
    }

    // Get role assignments and their permissions
    let assignments = roles::get_active_role_assignments(pool, user_id, org_id).await?;
    for assignment in &assignments {
        let perm_ids = match RoleType::from_str(&assignment.role_type) {
            Some(RoleType::Template) => {
                get_template_permission_ids(pool, &assignment.role_id).await?
            }
            Some(RoleType::Custom) => {
                get_custom_role_permission_ids(pool, &assignment.role_id).await?
            }
            None => vec![],
        };

        for perm_id in perm_ids {
            if !denied.contains(&perm_id) {
                granted.insert(perm_id);
            }
        }
    }

    // Build role assignment info
    let roles = roles::list_user_role_assignments(pool, user_id, org_id).await?;

    // Get active policies
    let policies = roles::list_policies(pool).await?;

    Ok(EffectivePermissions {
        user_id: user_id.to_string(),
        organization_id: org_id.to_string(),
        granted,
        denied,
        roles,
        policies,
        computed_at: Utc::now(),
    })
}

/// Get permission IDs for a template
async fn get_template_permission_ids(pool: &SqlitePool, template_id: &str) -> Result<Vec<String>> {
    let ids = sqlx::query_scalar::<_, String>(
        "SELECT permission_id FROM role_template_permissions WHERE template_id = ?",
    )
    .bind(template_id)
    .fetch_all(pool)
    .await?;

    Ok(ids)
}

/// Get permission IDs for a custom role (considering overrides)
async fn get_custom_role_permission_ids(pool: &SqlitePool, role_id: &str) -> Result<Vec<String>> {
    let role = roles::get_custom_role_by_id(pool, role_id).await?;
    let role = match role {
        Some(r) => r,
        None => return Ok(vec![]),
    };

    let mut granted: HashSet<String> = HashSet::new();

    // Start with template permissions
    if let Some(template_id) = &role.based_on_template_id {
        for id in get_template_permission_ids(pool, template_id).await? {
            granted.insert(id);
        }
    }

    // Apply overrides
    let overrides = sqlx::query_as::<_, (String, bool)>(
        "SELECT permission_id, granted FROM custom_role_permissions WHERE role_id = ?",
    )
    .bind(role_id)
    .fetch_all(pool)
    .await?;

    for (perm_id, is_granted) in overrides {
        if is_granted {
            granted.insert(perm_id);
        } else {
            granted.remove(&perm_id);
        }
    }

    Ok(granted.into_iter().collect())
}

// ============================================================================
// Resource Ownership Management
// ============================================================================

/// Set resource ownership
pub async fn set_resource_owner(
    pool: &SqlitePool,
    resource_type: &str,
    resource_id: &str,
    owner_type: OwnerType,
    owner_id: &str,
    created_by: Option<&str>,
) -> Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Remove existing ownership
    sqlx::query("DELETE FROM resource_ownership WHERE resource_type = ? AND resource_id = ?")
        .bind(resource_type)
        .bind(resource_id)
        .execute(pool)
        .await?;

    // Set new ownership
    sqlx::query(
        r#"
        INSERT INTO resource_ownership (id, resource_type, resource_id, owner_type, owner_id, created_at, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(resource_type)
    .bind(resource_id)
    .bind(owner_type.as_str())
    .bind(owner_id)
    .bind(&now)
    .bind(created_by)
    .execute(pool)
    .await?;

    Ok(())
}

/// Share a resource with a user or team
pub async fn share_resource(
    pool: &SqlitePool,
    resource_type: &str,
    resource_id: &str,
    req: &ShareResourceRequest,
    shared_by: &str,
) -> Result<ResourceShare> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let expires_at = req.expires_at.map(|dt| dt.to_rfc3339());

    // Remove existing share for same target
    sqlx::query(
        r#"
        DELETE FROM resource_shares
        WHERE resource_type = ? AND resource_id = ? AND shared_with_type = ? AND shared_with_id = ?
        "#,
    )
    .bind(resource_type)
    .bind(resource_id)
    .bind(req.shared_with_type.as_str())
    .bind(&req.shared_with_id)
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO resource_shares (id, resource_type, resource_id, shared_with_type, shared_with_id, permission_level, shared_by, shared_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(resource_type)
    .bind(resource_id)
    .bind(req.shared_with_type.as_str())
    .bind(&req.shared_with_id)
    .bind(req.permission_level.as_str())
    .bind(shared_by)
    .bind(&now)
    .bind(&expires_at)
    .execute(pool)
    .await?;

    let share = sqlx::query_as::<_, ResourceShare>("SELECT * FROM resource_shares WHERE id = ?")
        .bind(&id)
        .fetch_one(pool)
        .await?;

    Ok(share)
}

/// Remove a resource share
pub async fn unshare_resource(
    pool: &SqlitePool,
    resource_type: &str,
    resource_id: &str,
    shared_with_type: OwnerType,
    shared_with_id: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        DELETE FROM resource_shares
        WHERE resource_type = ? AND resource_id = ? AND shared_with_type = ? AND shared_with_id = ?
        "#,
    )
    .bind(resource_type)
    .bind(resource_id)
    .bind(shared_with_type.as_str())
    .bind(shared_with_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// List shares for a resource
pub async fn list_resource_shares(
    pool: &SqlitePool,
    resource_type: &str,
    resource_id: &str,
) -> Result<Vec<ResourceShare>> {
    let shares = sqlx::query_as::<_, ResourceShare>(
        r#"
        SELECT * FROM resource_shares
        WHERE resource_type = ? AND resource_id = ?
        AND (expires_at IS NULL OR expires_at > datetime('now'))
        ORDER BY shared_at DESC
        "#,
    )
    .bind(resource_type)
    .bind(resource_id)
    .fetch_all(pool)
    .await?;

    Ok(shares)
}

// ============================================================================
// Backward Compatibility
// ============================================================================

/// Legacy permission check (maps old permission names to new system)
pub async fn has_permission_legacy(pool: &SqlitePool, user_id: &str, permission: &str) -> Result<bool> {
    // Map old permission names to (action, resource_type)
    let (action, resource_type) = match permission {
        "manage_users" => ("update", "users"),
        "manage_scans" => ("execute", "scans"),
        "view_all_scans" => ("read", "scans"),
        "delete_any_scan" => ("delete", "scans"),
        "view_audit_logs" => ("read", "audit_logs"),
        "manage_settings" => ("update", "settings"),
        _ => return Ok(false),
    };

    // Get user's default organization (first one they belong to)
    let orgs = organizations::list_user_organizations(pool, user_id).await?;
    let org_id = match orgs.first() {
        Some(org) => org.id.clone(),
        None => return Ok(false),
    };

    let ctx = PermissionContext::new(user_id, &org_id, action, resource_type);
    let result = check_permission(pool, &ctx).await?;

    Ok(result.allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_in_cidr() {
        let addr: std::net::IpAddr = "192.168.1.100".parse().unwrap();
        assert!(ip_in_cidr(&addr, "192.168.1.0/24"));
        assert!(ip_in_cidr(&addr, "192.168.0.0/16"));
        assert!(!ip_in_cidr(&addr, "192.168.2.0/24"));
        assert!(!ip_in_cidr(&addr, "10.0.0.0/8"));
    }

    #[test]
    fn test_ip_in_cidr_v6() {
        let addr: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert!(ip_in_cidr(&addr, "2001:db8::/32"));
        assert!(!ip_in_cidr(&addr, "2001:db9::/32"));
    }
}
