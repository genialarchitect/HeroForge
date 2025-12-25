use actix_web::{dev::Payload, Error as ActixError, FromRequest, HttpMessage, HttpRequest};
use futures_util::future::{ready, Ready};
use serde::{Deserialize, Serialize};

/// Organization context for multi-tenant data isolation.
/// Extracted from X-Organization-Id header or JWT claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationContext {
    /// The organization ID for scoping data queries
    pub organization_id: Option<String>,
    /// User's role in this organization (owner/admin/member)
    pub org_role: Option<String>,
    /// Team IDs the user belongs to in this organization
    pub teams: Vec<String>,
    /// Whether the user can access all organizations (e.g., super admin)
    pub is_super_admin: bool,
}

impl OrganizationContext {
    /// Create a new organization context
    pub fn new(
        organization_id: Option<String>,
        org_role: Option<String>,
        teams: Vec<String>,
        is_super_admin: bool,
    ) -> Self {
        Self {
            organization_id,
            org_role,
            teams,
            is_super_admin,
        }
    }

    /// Check if user is an owner of the current organization
    #[allow(dead_code)]
    pub fn is_owner(&self) -> bool {
        self.org_role.as_deref() == Some("owner")
    }

    /// Check if user is an admin of the current organization
    #[allow(dead_code)]
    pub fn is_admin(&self) -> bool {
        matches!(self.org_role.as_deref(), Some("owner") | Some("admin"))
    }

    /// Check if user has any role in the current organization
    #[allow(dead_code)]
    pub fn is_member(&self) -> bool {
        self.org_role.is_some()
    }

    /// Get the organization ID, or None if not in an org context
    pub fn org_id(&self) -> Option<&str> {
        self.organization_id.as_deref()
    }

    /// Check if a specific team is accessible to the user
    #[allow(dead_code)]
    pub fn has_team(&self, team_id: &str) -> bool {
        self.teams.contains(&team_id.to_string())
    }
}

impl Default for OrganizationContext {
    fn default() -> Self {
        Self {
            organization_id: None,
            org_role: None,
            teams: Vec::new(),
            is_super_admin: false,
        }
    }
}

// Implement FromRequest for OrganizationContext to allow direct extraction from route handlers
impl FromRequest for OrganizationContext {
    type Error = ActixError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Extract OrganizationContext from request extensions (placed there by OrgContextMiddleware)
        if let Some(ctx) = req.extensions().get::<OrganizationContext>() {
            ready(Ok(ctx.clone()))
        } else {
            // Return a default context if not set (allows unauthenticated routes to work)
            ready(Ok(OrganizationContext::default()))
        }
    }
}

/// Header name for organization context override
pub const ORG_HEADER: &str = "X-Organization-Id";
