//! OpenAPI/Swagger documentation for HeroForge API
//!
//! This module provides OpenAPI 3.0 specification for the HeroForge REST API,
//! including authentication, scan management, and vulnerability management endpoints.

#![allow(dead_code)]

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

// ============================================================================
// Request/Response Schemas for OpenAPI
// ============================================================================

/// User registration request
#[derive(ToSchema)]
#[schema(example = json!({
    "username": "johndoe",
    "email": "johndoe@example.com",
    "password": "SecurePassword123!",
    "accept_terms": true
}))]
pub struct CreateUserSchema {
    /// Username for the new account
    pub username: String,
    /// Email address
    pub email: String,
    /// Password (must meet security requirements)
    pub password: String,
    /// Accept terms and conditions
    pub accept_terms: bool,
}

/// Login request
#[derive(ToSchema)]
#[schema(example = json!({
    "username": "johndoe",
    "password": "SecurePassword123!"
}))]
pub struct LoginRequestSchema {
    /// Username or email
    pub username: String,
    /// Password
    pub password: String,
}

/// Login response (successful authentication)
#[derive(ToSchema)]
#[schema(example = json!({
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "username": "johndoe",
        "email": "johndoe@example.com"
    }
}))]
pub struct LoginResponseSchema {
    /// JWT access token
    pub token: String,
    /// Refresh token for obtaining new access tokens
    pub refresh_token: String,
    /// User information
    pub user: UserInfoSchema,
}

/// User information
#[derive(ToSchema)]
pub struct UserInfoSchema {
    /// Unique user ID
    pub id: String,
    /// Username
    pub username: String,
    /// Email address
    pub email: String,
}

/// MFA login response (when MFA is required)
#[derive(ToSchema)]
#[schema(example = json!({
    "mfa_required": true,
    "mfa_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}))]
pub struct MfaLoginResponseSchema {
    /// Indicates MFA verification is required
    pub mfa_required: bool,
    /// Temporary token for MFA verification
    pub mfa_token: Option<String>,
}

/// MFA verification request
#[derive(ToSchema)]
#[schema(example = json!({
    "mfa_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "totp_code": "123456"
}))]
pub struct MfaVerifyRequestSchema {
    /// Temporary MFA token from login response
    pub mfa_token: String,
    /// 6-digit TOTP code from authenticator app
    pub totp_code: Option<String>,
    /// Recovery code (alternative to TOTP)
    pub recovery_code: Option<String>,
}

/// Refresh token request
#[derive(ToSchema)]
#[schema(example = json!({
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}))]
pub struct RefreshTokenRequestSchema {
    /// Refresh token
    pub refresh_token: String,
}

/// Refresh token response
#[derive(ToSchema)]
#[schema(example = json!({
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}))]
pub struct RefreshTokenResponseSchema {
    /// New JWT access token
    pub access_token: String,
}

/// Create scan request
#[derive(ToSchema)]
#[schema(example = json!({
    "name": "Network Security Scan",
    "targets": ["192.168.1.0/24", "example.com"],
    "port_range": [1, 1024],
    "threads": 100,
    "enable_os_detection": true,
    "enable_service_detection": true,
    "enable_vuln_scan": true,
    "enable_enumeration": false,
    "scan_type": "tcp_connect"
}))]
pub struct CreateScanRequestSchema {
    /// Name for the scan
    pub name: String,
    /// List of targets (IPs, CIDR ranges, or hostnames)
    pub targets: Vec<String>,
    /// Port range to scan (start, end)
    pub port_range: (u16, u16),
    /// Number of concurrent threads
    pub threads: usize,
    /// Enable OS fingerprinting
    pub enable_os_detection: bool,
    /// Enable service/version detection
    pub enable_service_detection: bool,
    /// Enable vulnerability scanning
    pub enable_vuln_scan: bool,
    /// Enable service enumeration
    pub enable_enumeration: bool,
    /// Enumeration depth: "passive", "light", "aggressive"
    pub enum_depth: Option<String>,
    /// Services to enumerate
    pub enum_services: Option<Vec<String>>,
    /// Scan type: "tcp_connect", "tcp_syn", "udp", "comprehensive"
    pub scan_type: Option<String>,
    /// UDP port range (for UDP and comprehensive scans)
    pub udp_port_range: Option<(u16, u16)>,
    /// Number of UDP retries
    pub udp_retries: Option<u8>,
    /// VPN configuration ID to connect through for this scan
    pub vpn_config_id: Option<String>,
}

/// Scan result
#[derive(ToSchema)]
#[schema(example = json!({
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "user_id": "550e8400-e29b-41d4-a716-446655440001",
    "name": "Network Security Scan",
    "targets": "192.168.1.0/24",
    "status": "completed",
    "created_at": "2024-01-15T10:30:00Z",
    "completed_at": "2024-01-15T10:45:00Z"
}))]
pub struct ScanResultSchema {
    /// Unique scan ID
    pub id: String,
    /// Owner user ID
    pub user_id: String,
    /// Scan name
    pub name: String,
    /// Comma-separated targets
    pub targets: String,
    /// Status: pending, running, completed, failed
    pub status: String,
    /// JSON string of scan results
    pub results: Option<String>,
    /// Creation timestamp
    pub created_at: String,
    /// Start timestamp
    pub started_at: Option<String>,
    /// Completion timestamp
    pub completed_at: Option<String>,
    /// Error message (if failed)
    pub error_message: Option<String>,
}

/// Vulnerability tracking record
#[derive(ToSchema)]
#[schema(example = json!({
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "scan_id": "550e8400-e29b-41d4-a716-446655440001",
    "host_ip": "192.168.1.100",
    "port": 443,
    "vulnerability_id": "CVE-2021-44228",
    "severity": "critical",
    "status": "open",
    "created_at": "2024-01-15T10:30:00Z"
}))]
pub struct VulnerabilityTrackingSchema {
    /// Unique tracking ID
    pub id: String,
    /// Associated scan ID
    pub scan_id: String,
    /// Host IP address
    pub host_ip: String,
    /// Port number (if applicable)
    pub port: Option<i32>,
    /// CVE or vulnerability identifier
    pub vulnerability_id: String,
    /// Severity: critical, high, medium, low, info
    pub severity: String,
    /// Status: open, in_progress, resolved, false_positive, accepted_risk
    pub status: String,
    /// Assigned user ID
    pub assignee_id: Option<String>,
    /// Notes
    pub notes: Option<String>,
    /// Due date for remediation
    pub due_date: Option<String>,
    /// Creation timestamp
    pub created_at: String,
    /// Last update timestamp
    pub updated_at: String,
    /// Resolution timestamp
    pub resolved_at: Option<String>,
    /// User who resolved
    pub resolved_by: Option<String>,
}

/// Update vulnerability request
#[derive(ToSchema)]
#[schema(example = json!({
    "status": "in_progress",
    "assignee_id": "550e8400-e29b-41d4-a716-446655440000",
    "notes": "Investigating this vulnerability",
    "priority": "high"
}))]
pub struct UpdateVulnerabilityRequestSchema {
    /// New status
    pub status: Option<String>,
    /// Assignee user ID
    pub assignee_id: Option<String>,
    /// Notes
    pub notes: Option<String>,
    /// Due date
    pub due_date: Option<String>,
    /// Priority: critical, high, medium, low
    pub priority: Option<String>,
    /// Remediation steps
    pub remediation_steps: Option<String>,
    /// Estimated effort in hours
    pub estimated_effort: Option<i32>,
}

/// Vulnerability statistics
#[derive(ToSchema)]
#[schema(example = json!({
    "total": 150,
    "open": 45,
    "in_progress": 30,
    "resolved": 65,
    "false_positive": 5,
    "accepted_risk": 5,
    "critical": 10,
    "high": 25,
    "medium": 50,
    "low": 65
}))]
pub struct VulnerabilityStatsSchema {
    /// Total vulnerabilities
    pub total: i64,
    /// Open vulnerabilities
    pub open: i64,
    /// In progress
    pub in_progress: i64,
    /// Resolved
    pub resolved: i64,
    /// Marked as false positive
    pub false_positive: i64,
    /// Accepted risk
    pub accepted_risk: i64,
    /// Critical severity count
    pub critical: i64,
    /// High severity count
    pub high: i64,
    /// Medium severity count
    pub medium: i64,
    /// Low severity count
    pub low: i64,
}

/// Generic error response
#[derive(ToSchema)]
#[schema(example = json!({
    "error": "Invalid credentials"
}))]
pub struct ErrorResponse {
    /// Error message
    pub error: String,
}

/// Generic success response
#[derive(ToSchema)]
#[schema(example = json!({
    "message": "Operation completed successfully"
}))]
pub struct SuccessResponse {
    /// Success message
    pub message: String,
}

/// Bulk delete request
#[derive(ToSchema)]
#[schema(example = json!({
    "scan_ids": ["550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440001"]
}))]
pub struct BulkDeleteRequestSchema {
    /// List of scan IDs to delete
    pub scan_ids: Vec<String>,
}

/// Bulk update vulnerabilities request
#[derive(ToSchema)]
#[schema(example = json!({
    "vulnerability_ids": ["id1", "id2"],
    "status": "in_progress",
    "assignee_id": "user-id"
}))]
pub struct BulkUpdateVulnerabilitiesRequestSchema {
    /// List of vulnerability IDs
    pub vulnerability_ids: Vec<String>,
    /// New status
    pub status: Option<String>,
    /// Assignee user ID
    pub assignee_id: Option<String>,
}

/// Add comment request
#[derive(ToSchema)]
#[schema(example = json!({
    "comment": "Started investigation on this vulnerability"
}))]
pub struct AddCommentRequestSchema {
    /// Comment text
    pub comment: String,
}

// ============================================================================
// Security Scheme for JWT Authentication
// ============================================================================

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("JWT access token obtained from /api/auth/login"))
                        .build(),
                ),
            );
        }
    }
}

// ============================================================================
// OpenAPI Documentation
// ============================================================================

#[derive(OpenApi)]
#[openapi(
    info(
        title = "HeroForge API",
        version = "1.0.0",
        description = "HeroForge is a network reconnaissance and vulnerability scanning tool for authorized penetration testing. This API provides endpoints for user authentication, scan management, vulnerability tracking, and reporting.",
        contact(
            name = "HeroForge Support",
            email = "support@heroforge.io"
        ),
        license(
            name = "Proprietary",
            url = "https://heroforge.io/license"
        )
    ),
    servers(
        (url = "https://heroforge.genialarchitect.io", description = "Production server"),
        (url = "http://localhost:8080", description = "Local development server")
    ),
    tags(
        (name = "Authentication", description = "User authentication and session management"),
        (name = "MFA", description = "Multi-factor authentication management"),
        (name = "Scans", description = "Network scan operations"),
        (name = "Vulnerabilities", description = "Vulnerability tracking and management"),
        (name = "Reports", description = "Report generation and download"),
        (name = "Templates", description = "Scan template management"),
        (name = "Target Groups", description = "Target group management"),
        (name = "Scheduled Scans", description = "Scheduled scan management"),
        (name = "Analytics", description = "Dashboard analytics and statistics"),
        (name = "Assets", description = "Asset inventory management"),
        (name = "Admin", description = "Administrative operations (admin role required)")
    ),
    paths(
        // Authentication endpoints
        crate::web::api::auth::register,
        crate::web::api::auth::login,
        crate::web::api::auth::refresh,
        crate::web::api::auth::logout,
        crate::web::api::auth::me,
        crate::web::api::auth::update_profile,
        crate::web::api::auth::change_password,
        // MFA endpoints
        crate::web::api::mfa::verify_mfa,
        crate::web::api::mfa::setup_mfa,
        crate::web::api::mfa::verify_setup,
        crate::web::api::mfa::disable_mfa,
        // Scan endpoints
        crate::web::api::scans::create_scan,
        crate::web::api::scans::get_scans,
        crate::web::api::scans::get_scan,
        crate::web::api::scans::get_scan_results,
        crate::web::api::scans::delete_scan,
        crate::web::api::scans::bulk_delete_scans,
        crate::web::api::scans::bulk_export_scans,
        // Vulnerability endpoints
        crate::web::api::vulnerabilities::list_vulnerabilities,
        crate::web::api::vulnerabilities::get_vulnerability,
        crate::web::api::vulnerabilities::update_vulnerability,
        crate::web::api::vulnerabilities::add_comment,
        crate::web::api::vulnerabilities::bulk_update_vulnerabilities,
        crate::web::api::vulnerabilities::get_vulnerability_stats,
        crate::web::api::vulnerabilities::get_vulnerability_timeline,
        crate::web::api::vulnerabilities::mark_for_verification,
        crate::web::api::vulnerabilities::bulk_assign,
    ),
    components(
        schemas(
            CreateUserSchema,
            LoginRequestSchema,
            LoginResponseSchema,
            UserInfoSchema,
            MfaLoginResponseSchema,
            MfaVerifyRequestSchema,
            RefreshTokenRequestSchema,
            RefreshTokenResponseSchema,
            CreateScanRequestSchema,
            ScanResultSchema,
            VulnerabilityTrackingSchema,
            UpdateVulnerabilityRequestSchema,
            VulnerabilityStatsSchema,
            ErrorResponse,
            SuccessResponse,
            BulkDeleteRequestSchema,
            BulkUpdateVulnerabilitiesRequestSchema,
            AddCommentRequestSchema,
        )
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;
