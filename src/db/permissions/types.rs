//! Permission system types for ABAC (Attribute-Based Access Control)
//!
//! This module defines the core types for the hierarchical organization
//! and permission system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::{HashMap, HashSet};

// ============================================================================
// Organizational Hierarchy
// ============================================================================

/// Top-level organization (tenant)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub settings: Option<String>, // JSON
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Request to create an organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub slug: Option<String>,
    pub description: Option<String>,
    pub settings: Option<serde_json::Value>,
}

/// Request to update an organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateOrganizationRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub settings: Option<serde_json::Value>,
    pub is_active: Option<bool>,
}

/// Department within an organization
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Department {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub parent_department_id: Option<String>,
    pub manager_user_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Request to create a department
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDepartmentRequest {
    pub name: String,
    pub slug: Option<String>,
    pub description: Option<String>,
    pub parent_department_id: Option<String>,
    pub manager_user_id: Option<String>,
}

/// Request to update a department
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDepartmentRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub parent_department_id: Option<String>,
    pub manager_user_id: Option<String>,
}

/// Team within a department
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Team {
    pub id: String,
    pub department_id: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub team_lead_user_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Request to create a team
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTeamRequest {
    pub name: String,
    pub slug: Option<String>,
    pub description: Option<String>,
    pub team_lead_user_id: Option<String>,
}

/// Request to update a team
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTeamRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub team_lead_user_id: Option<String>,
}

/// User's organization membership
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserOrganization {
    pub user_id: String,
    pub organization_id: String,
    pub org_role: String, // owner, admin, member
    pub joined_at: String,
    pub invited_by: Option<String>,
}

/// Organization role enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrgRole {
    Owner,
    Admin,
    Member,
}

impl OrgRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrgRole::Owner => "owner",
            OrgRole::Admin => "admin",
            OrgRole::Member => "member",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(OrgRole::Owner),
            "admin" => Some(OrgRole::Admin),
            "member" => Some(OrgRole::Member),
            _ => None,
        }
    }

    /// Check if this role has higher or equal privileges than another
    pub fn has_privilege_over(&self, other: &OrgRole) -> bool {
        match (self, other) {
            (OrgRole::Owner, _) => true,
            (OrgRole::Admin, OrgRole::Admin | OrgRole::Member) => true,
            (OrgRole::Member, OrgRole::Member) => true,
            _ => false,
        }
    }
}

/// User's team membership
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserTeam {
    pub user_id: String,
    pub team_id: String,
    pub team_role: String, // lead, member
    pub joined_at: String,
    pub added_by: Option<String>,
}

/// Team role enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TeamRole {
    Lead,
    Member,
}

impl TeamRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            TeamRole::Lead => "lead",
            TeamRole::Member => "member",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "lead" => Some(TeamRole::Lead),
            "member" => Some(TeamRole::Member),
            _ => None,
        }
    }
}

// ============================================================================
// Permission Core Types
// ============================================================================

/// Resource type (e.g., scans, reports, assets)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ResourceType {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
}

/// Action that can be performed on a resource
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Action {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
}

/// Atomic permission (resource type + action)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Permission {
    pub id: String,
    pub resource_type_id: String,
    pub action_id: String,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub created_at: String,
}

/// Permission with resolved names (for API responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionInfo {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub resource_type: String,
    pub action: String,
    pub is_system: bool,
}

// ============================================================================
// ABAC Policies
// ============================================================================

/// Policy effect
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

impl PolicyEffect {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyEffect::Allow => "allow",
            PolicyEffect::Deny => "deny",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(PolicyEffect::Allow),
            "deny" => Some(PolicyEffect::Deny),
            _ => None,
        }
    }
}

/// ABAC Policy
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub resource_type_id: String,
    pub effect: String, // allow, deny
    pub priority: i32,
    pub conditions: String, // JSON
    pub is_active: bool,
    pub is_system: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Policy with resolved info (for API responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInfo {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub resource_type: String,
    pub effect: PolicyEffect,
    pub priority: i32,
    pub conditions: PolicyConditions,
    pub actions: Vec<String>,
    pub is_active: bool,
    pub is_system: bool,
}

/// Policy conditions for ABAC
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConditions {
    /// User must be the owner of the resource
    #[serde(default)]
    pub owner: bool,
    /// User must be a member of the same team as the resource owner
    #[serde(default)]
    pub team_member: bool,
    /// User must be in the same department as the resource owner
    #[serde(default)]
    pub department_member: bool,
    /// User must be in the same organization as the resource
    #[serde(default)]
    pub organization_member: bool,
    /// User must have one of these roles
    #[serde(default)]
    pub required_roles: Vec<String>,
    /// User must have one of these team roles
    #[serde(default)]
    pub required_team_roles: Vec<String>,
    /// User must have one of these org roles
    #[serde(default)]
    pub required_org_roles: Vec<String>,
    /// Custom attribute conditions (key -> expected value)
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,
    /// Time-based conditions
    #[serde(default)]
    pub time_conditions: Option<TimeConditions>,
    /// IP-based conditions
    #[serde(default)]
    pub ip_conditions: Option<IpConditions>,
}

/// Time-based access conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeConditions {
    /// Allowed days of week (0 = Sunday, 6 = Saturday)
    pub allowed_days: Option<Vec<u8>>,
    /// Start hour (0-23)
    pub start_hour: Option<u8>,
    /// End hour (0-23)
    pub end_hour: Option<u8>,
    /// Timezone for time checks
    pub timezone: Option<String>,
}

/// IP-based access conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpConditions {
    /// Allowed IP ranges (CIDR notation)
    pub allowed_ranges: Option<Vec<String>>,
    /// Blocked IP ranges (CIDR notation)
    pub blocked_ranges: Option<Vec<String>>,
}

/// Policy-action mapping
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PolicyAction {
    pub policy_id: String,
    pub action_id: String,
}

// ============================================================================
// Role Templates and Custom Roles
// ============================================================================

/// Predefined role template
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RoleTemplate {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub is_system: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Role template with its permissions and policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleTemplateInfo {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub permissions: Vec<PermissionInfo>,
    pub policies: Vec<PolicyInfo>,
    pub is_system: bool,
}

/// Template-permission mapping
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RoleTemplatePermission {
    pub template_id: String,
    pub permission_id: String,
    pub include_conditions: bool,
}

/// Template-policy mapping
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RoleTemplatePolicy {
    pub template_id: String,
    pub policy_id: String,
}

/// Custom role (organization-specific)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CustomRole {
    pub id: String,
    pub organization_id: String,
    pub based_on_template_id: Option<String>,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub is_active: bool,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Request to create a custom role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCustomRoleRequest {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub based_on_template_id: Option<String>,
    pub permission_overrides: Option<Vec<PermissionOverride>>,
}

/// Permission override for custom roles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionOverride {
    pub permission_id: String,
    pub granted: bool,
}

/// Request to update a custom role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCustomRoleRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub is_active: Option<bool>,
    pub permission_overrides: Option<Vec<PermissionOverride>>,
}

/// Custom role-permission mapping
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CustomRolePermission {
    pub role_id: String,
    pub permission_id: String,
    pub granted: bool,
}

// ============================================================================
// Role Assignments
// ============================================================================

/// User role assignment
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserRoleAssignment {
    pub id: String,
    pub user_id: String,
    pub organization_id: String,
    pub role_type: String, // template, custom
    pub role_id: String,
    pub scope_type: Option<String>, // NULL, department, team
    pub scope_id: Option<String>,
    pub assigned_at: String,
    pub assigned_by: Option<String>,
    pub expires_at: Option<String>,
    pub is_active: bool,
}

/// Role type enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoleType {
    Template,
    Custom,
}

impl RoleType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RoleType::Template => "template",
            RoleType::Custom => "custom",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "template" => Some(RoleType::Template),
            "custom" => Some(RoleType::Custom),
            _ => None,
        }
    }
}

/// Scope type for role assignments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeType {
    Organization,
    Department,
    Team,
}

impl ScopeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScopeType::Organization => "organization",
            ScopeType::Department => "department",
            ScopeType::Team => "team",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "organization" => Some(ScopeType::Organization),
            "department" => Some(ScopeType::Department),
            "team" => Some(ScopeType::Team),
            _ => None,
        }
    }
}

/// Request to assign a role to a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignRoleRequest {
    pub role_type: RoleType,
    pub role_id: String,
    pub scope_type: Option<ScopeType>,
    pub scope_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Role assignment with resolved info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignmentInfo {
    pub id: String,
    pub role_type: RoleType,
    pub role_id: String,
    pub role_name: String,
    pub role_display_name: String,
    pub scope_type: Option<ScopeType>,
    pub scope_id: Option<String>,
    pub scope_name: Option<String>,
    pub assigned_at: String,
    pub assigned_by: Option<String>,
    pub expires_at: Option<String>,
    pub is_active: bool,
}

// ============================================================================
// User Permission Overrides
// ============================================================================

/// User-specific permission override
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserPermissionOverride {
    pub id: String,
    pub user_id: String,
    pub organization_id: String,
    pub permission_id: String,
    pub granted: bool,
    pub reason: Option<String>,
    pub granted_by: String,
    pub granted_at: String,
    pub expires_at: Option<String>,
}

/// Request to add a permission override
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPermissionOverrideRequest {
    pub permission_id: String,
    pub granted: bool,
    pub reason: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

// ============================================================================
// Resource Ownership
// ============================================================================

/// Resource ownership record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ResourceOwnership {
    pub id: String,
    pub resource_type: String,
    pub resource_id: String,
    pub owner_type: String, // user, team, department, organization
    pub owner_id: String,
    pub created_at: String,
    pub created_by: Option<String>,
}

/// Owner type enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OwnerType {
    User,
    Team,
    Department,
    Organization,
}

impl OwnerType {
    pub fn as_str(&self) -> &'static str {
        match self {
            OwnerType::User => "user",
            OwnerType::Team => "team",
            OwnerType::Department => "department",
            OwnerType::Organization => "organization",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "user" => Some(OwnerType::User),
            "team" => Some(OwnerType::Team),
            "department" => Some(OwnerType::Department),
            "organization" => Some(OwnerType::Organization),
            _ => None,
        }
    }
}

/// Resource share record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ResourceShare {
    pub id: String,
    pub resource_type: String,
    pub resource_id: String,
    pub shared_with_type: String, // user, team, department
    pub shared_with_id: String,
    pub permission_level: String, // view, edit, admin
    pub shared_by: String,
    pub shared_at: String,
    pub expires_at: Option<String>,
}

/// Share permission level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SharePermissionLevel {
    View,
    Edit,
    Admin,
}

impl SharePermissionLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            SharePermissionLevel::View => "view",
            SharePermissionLevel::Edit => "edit",
            SharePermissionLevel::Admin => "admin",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "view" => Some(SharePermissionLevel::View),
            "edit" => Some(SharePermissionLevel::Edit),
            "admin" => Some(SharePermissionLevel::Admin),
            _ => None,
        }
    }

    /// Check if this level includes the permissions of another level
    pub fn includes(&self, other: &SharePermissionLevel) -> bool {
        match (self, other) {
            (SharePermissionLevel::Admin, _) => true,
            (SharePermissionLevel::Edit, SharePermissionLevel::Edit | SharePermissionLevel::View) => true,
            (SharePermissionLevel::View, SharePermissionLevel::View) => true,
            _ => false,
        }
    }
}

/// Request to share a resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareResourceRequest {
    pub shared_with_type: OwnerType,
    pub shared_with_id: String,
    pub permission_level: SharePermissionLevel,
    pub expires_at: Option<DateTime<Utc>>,
}

// ============================================================================
// Permission Evaluation
// ============================================================================

/// Context for permission evaluation
#[derive(Debug, Clone, Default)]
pub struct PermissionContext {
    /// The user making the request
    pub user_id: String,
    /// Current organization context
    pub organization_id: String,
    /// The action being performed
    pub action: String,
    /// The resource type
    pub resource_type: String,
    /// Specific resource ID (if applicable)
    pub resource_id: Option<String>,
    /// User's current IP address
    pub ip_address: Option<String>,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
    /// Additional context attributes
    pub attributes: HashMap<String, serde_json::Value>,
}

impl PermissionContext {
    pub fn new(user_id: &str, organization_id: &str, action: &str, resource_type: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            organization_id: organization_id.to_string(),
            action: action.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: None,
            ip_address: None,
            timestamp: Utc::now(),
            attributes: HashMap::new(),
        }
    }

    pub fn with_resource(mut self, resource_id: &str) -> Self {
        self.resource_id = Some(resource_id.to_string());
        self
    }

    pub fn with_ip(mut self, ip: &str) -> Self {
        self.ip_address = Some(ip.to_string());
        self
    }

    pub fn with_attribute(mut self, key: &str, value: serde_json::Value) -> Self {
        self.attributes.insert(key.to_string(), value);
        self
    }
}

/// Result of a permission check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionResult {
    /// Whether access is allowed
    pub allowed: bool,
    /// Reason for the decision
    pub reason: PermissionReason,
    /// Policy that made the decision (if any)
    pub policy_id: Option<String>,
    /// Policy name for debugging
    pub policy_name: Option<String>,
    /// Role that granted the permission (if any)
    pub role_id: Option<String>,
    /// Whether this was from cache
    pub from_cache: bool,
}

impl PermissionResult {
    pub fn allowed(reason: PermissionReason) -> Self {
        Self {
            allowed: true,
            reason,
            policy_id: None,
            policy_name: None,
            role_id: None,
            from_cache: false,
        }
    }

    pub fn denied(reason: PermissionReason) -> Self {
        Self {
            allowed: false,
            reason,
            policy_id: None,
            policy_name: None,
            role_id: None,
            from_cache: false,
        }
    }

    pub fn with_policy(mut self, id: &str, name: &str) -> Self {
        self.policy_id = Some(id.to_string());
        self.policy_name = Some(name.to_string());
        self
    }

    pub fn with_role(mut self, id: &str) -> Self {
        self.role_id = Some(id.to_string());
        self
    }

    pub fn cached(mut self) -> Self {
        self.from_cache = true;
        self
    }
}

/// Reason for permission decision
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PermissionReason {
    /// User has explicit override granting permission
    UserOverride,
    /// User has a role granting the permission
    RoleGrant { role_name: String },
    /// User is the resource owner
    ResourceOwner,
    /// User has shared access to the resource
    SharedAccess { level: String },
    /// Policy explicitly allows
    PolicyAllow,
    /// Policy explicitly denies
    PolicyDeny,
    /// User has explicit override denying permission
    UserOverrideDeny,
    /// No permission found (default deny)
    NoPermission,
    /// Permission expired
    Expired,
    /// Condition not met (ABAC)
    ConditionNotMet { condition: String },
    /// Organization admin bypass
    OrgAdminBypass,
    /// System admin bypass
    SystemAdmin,
}

/// Effective permissions for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivePermissions {
    pub user_id: String,
    pub organization_id: String,
    /// All permissions explicitly granted
    pub granted: HashSet<String>,
    /// All permissions explicitly denied
    pub denied: HashSet<String>,
    /// Role assignments contributing to permissions
    pub roles: Vec<RoleAssignmentInfo>,
    /// Active policies
    pub policies: Vec<PolicyInfo>,
    /// Computed at
    pub computed_at: DateTime<Utc>,
}

// ============================================================================
// Permission Cache
// ============================================================================

/// Permission cache entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PermissionCache {
    pub id: String,
    pub user_id: String,
    pub organization_id: String,
    pub cache_key: String,
    pub effective_permissions: String, // JSON
    pub computed_at: String,
    pub expires_at: String,
}

/// Cache key builder
impl PermissionCache {
    /// Build a cache key for a permission check
    pub fn build_key(user_id: &str, org_id: &str, action: &str, resource_type: &str) -> String {
        format!("{}:{}:{}:{}", user_id, org_id, action, resource_type)
    }

    /// Build a cache key for effective permissions
    pub fn build_effective_key(user_id: &str, org_id: &str) -> String {
        format!("effective:{}:{}", user_id, org_id)
    }
}

// ============================================================================
// API Response Types
// ============================================================================

/// Organization summary for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationSummary {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub role: OrgRole,
    pub member_count: i64,
    pub team_count: i64,
}

/// Department summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepartmentSummary {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub team_count: i64,
    pub member_count: i64,
    pub manager: Option<UserSummary>,
}

/// Team summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamSummary {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub department_name: String,
    pub member_count: i64,
    pub lead: Option<UserSummary>,
}

/// User summary for team/org context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSummary {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
}

/// Team member with role info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMember {
    pub user: UserSummary,
    pub team_role: TeamRole,
    pub joined_at: String,
    pub added_by: Option<String>,
}

/// Permission check request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckPermissionRequest {
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
}

/// Batch permission check request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCheckPermissionRequest {
    pub checks: Vec<CheckPermissionRequest>,
}

/// Batch permission check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCheckPermissionResponse {
    pub results: Vec<PermissionResult>,
}
