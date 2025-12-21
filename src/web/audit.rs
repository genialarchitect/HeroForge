#![allow(dead_code)]
//! Audit logging helper module for tracking user actions
//!
//! This module provides structured audit logging with typed actions,
//! helper functions for creating audit entries, and integration with the HTTP request context.

use actix_web::HttpRequest;
use chrono::Utc;
use serde::Serialize;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::db::models::AuditLog;
use crate::db;

/// Enumeration of all trackable audit actions
///
/// Actions follow the format `category.action` for consistent filtering and grouping.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // Authentication actions
    Login,
    LoginFailed,
    Logout,
    PasswordChange,
    PasswordReset,

    // MFA actions
    MfaEnabled,
    MfaDisabled,
    MfaRecoveryCodesRegenerated,

    // User management actions
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserUnlocked,
    RoleAssigned,
    RoleRemoved,

    // Scan actions
    ScanCreated,
    ScanDeleted,
    ScanExported,
    ScanBulkDeleted,
    ScanBulkExported,

    // Vulnerability actions
    VulnerabilityUpdated,
    VulnerabilityAssigned,
    VulnerabilityBulkUpdated,
    VulnerabilityBulkAssigned,
    VulnerabilityVerified,
    VulnerabilityRetestRequested,
    VulnerabilityRetestCompleted,
    VulnerabilityCommentAdded,

    // Report actions
    ReportGenerated,
    ReportDeleted,
    ReportDownloaded,

    // Template actions
    TemplateCreated,
    TemplateUpdated,
    TemplateDeleted,

    // Target group actions
    TargetGroupCreated,
    TargetGroupUpdated,
    TargetGroupDeleted,

    // Scheduled scan actions
    ScheduledScanCreated,
    ScheduledScanUpdated,
    ScheduledScanDeleted,

    // API key actions
    ApiKeyCreated,
    ApiKeyUpdated,
    ApiKeyDeleted,

    // Settings actions
    SettingsChanged,
    NotificationSettingsChanged,
    JiraSettingsChanged,
    SiemSettingsChanged,

    // Asset actions
    AssetUpdated,
    AssetDeleted,

    // Compliance actions
    ComplianceAnalyzed,
    ComplianceReportGenerated,
    ManualAssessmentCreated,
    ManualAssessmentSubmitted,
    ManualAssessmentApproved,
    ManualAssessmentRejected,

    // Integration actions
    JiraTicketCreated,
    SiemExportTriggered,

    // VPN actions
    VpnConfigCreated,
    VpnConfigUpdated,
    VpnConfigDeleted,
    VpnConnected,
    VpnDisconnected,

    // Account actions
    AccountExportRequested,
    AccountDeleted,
    TermsAccepted,
}

impl AuditAction {
    /// Returns the action as a dot-notation string (e.g., "user.created")
    pub fn as_str(&self) -> &'static str {
        match self {
            // Authentication
            AuditAction::Login => "auth.login",
            AuditAction::LoginFailed => "auth.login_failed",
            AuditAction::Logout => "auth.logout",
            AuditAction::PasswordChange => "auth.password_change",
            AuditAction::PasswordReset => "auth.password_reset",

            // MFA
            AuditAction::MfaEnabled => "mfa.enabled",
            AuditAction::MfaDisabled => "mfa.disabled",
            AuditAction::MfaRecoveryCodesRegenerated => "mfa.recovery_codes_regenerated",

            // User management
            AuditAction::UserCreated => "user.created",
            AuditAction::UserUpdated => "user.updated",
            AuditAction::UserDeleted => "user.deleted",
            AuditAction::UserUnlocked => "user.unlocked",
            AuditAction::RoleAssigned => "role.assigned",
            AuditAction::RoleRemoved => "role.removed",

            // Scans
            AuditAction::ScanCreated => "scan.created",
            AuditAction::ScanDeleted => "scan.deleted",
            AuditAction::ScanExported => "scan.exported",
            AuditAction::ScanBulkDeleted => "scan.bulk_deleted",
            AuditAction::ScanBulkExported => "scan.bulk_exported",

            // Vulnerabilities
            AuditAction::VulnerabilityUpdated => "vulnerability.updated",
            AuditAction::VulnerabilityAssigned => "vulnerability.assigned",
            AuditAction::VulnerabilityBulkUpdated => "vulnerability.bulk_updated",
            AuditAction::VulnerabilityBulkAssigned => "vulnerability.bulk_assigned",
            AuditAction::VulnerabilityVerified => "vulnerability.verified",
            AuditAction::VulnerabilityRetestRequested => "vulnerability.retest_requested",
            AuditAction::VulnerabilityRetestCompleted => "vulnerability.retest_completed",
            AuditAction::VulnerabilityCommentAdded => "vulnerability.comment_added",

            // Reports
            AuditAction::ReportGenerated => "report.generated",
            AuditAction::ReportDeleted => "report.deleted",
            AuditAction::ReportDownloaded => "report.downloaded",

            // Templates
            AuditAction::TemplateCreated => "template.created",
            AuditAction::TemplateUpdated => "template.updated",
            AuditAction::TemplateDeleted => "template.deleted",

            // Target groups
            AuditAction::TargetGroupCreated => "target_group.created",
            AuditAction::TargetGroupUpdated => "target_group.updated",
            AuditAction::TargetGroupDeleted => "target_group.deleted",

            // Scheduled scans
            AuditAction::ScheduledScanCreated => "scheduled_scan.created",
            AuditAction::ScheduledScanUpdated => "scheduled_scan.updated",
            AuditAction::ScheduledScanDeleted => "scheduled_scan.deleted",

            // API keys
            AuditAction::ApiKeyCreated => "api_key.created",
            AuditAction::ApiKeyUpdated => "api_key.updated",
            AuditAction::ApiKeyDeleted => "api_key.deleted",

            // Settings
            AuditAction::SettingsChanged => "settings.changed",
            AuditAction::NotificationSettingsChanged => "settings.notification_changed",
            AuditAction::JiraSettingsChanged => "settings.jira_changed",
            AuditAction::SiemSettingsChanged => "settings.siem_changed",

            // Assets
            AuditAction::AssetUpdated => "asset.updated",
            AuditAction::AssetDeleted => "asset.deleted",

            // Compliance
            AuditAction::ComplianceAnalyzed => "compliance.analyzed",
            AuditAction::ComplianceReportGenerated => "compliance.report_generated",
            AuditAction::ManualAssessmentCreated => "compliance.assessment_created",
            AuditAction::ManualAssessmentSubmitted => "compliance.assessment_submitted",
            AuditAction::ManualAssessmentApproved => "compliance.assessment_approved",
            AuditAction::ManualAssessmentRejected => "compliance.assessment_rejected",

            // Integrations
            AuditAction::JiraTicketCreated => "integration.jira_ticket_created",
            AuditAction::SiemExportTriggered => "integration.siem_export",

            // VPN
            AuditAction::VpnConfigCreated => "vpn.config_created",
            AuditAction::VpnConfigUpdated => "vpn.config_updated",
            AuditAction::VpnConfigDeleted => "vpn.config_deleted",
            AuditAction::VpnConnected => "vpn.connected",
            AuditAction::VpnDisconnected => "vpn.disconnected",

            // Account
            AuditAction::AccountExportRequested => "account.export_requested",
            AuditAction::AccountDeleted => "account.deleted",
            AuditAction::TermsAccepted => "account.terms_accepted",
        }
    }

    /// Returns the resource type category (e.g., "user", "scan", "auth")
    pub fn resource_type(&self) -> &'static str {
        match self {
            AuditAction::Login
            | AuditAction::LoginFailed
            | AuditAction::Logout
            | AuditAction::PasswordChange
            | AuditAction::PasswordReset => "auth",

            AuditAction::MfaEnabled
            | AuditAction::MfaDisabled
            | AuditAction::MfaRecoveryCodesRegenerated => "mfa",

            AuditAction::UserCreated
            | AuditAction::UserUpdated
            | AuditAction::UserDeleted
            | AuditAction::UserUnlocked
            | AuditAction::RoleAssigned
            | AuditAction::RoleRemoved => "user",

            AuditAction::ScanCreated
            | AuditAction::ScanDeleted
            | AuditAction::ScanExported
            | AuditAction::ScanBulkDeleted
            | AuditAction::ScanBulkExported => "scan",

            AuditAction::VulnerabilityUpdated
            | AuditAction::VulnerabilityAssigned
            | AuditAction::VulnerabilityBulkUpdated
            | AuditAction::VulnerabilityBulkAssigned
            | AuditAction::VulnerabilityVerified
            | AuditAction::VulnerabilityRetestRequested
            | AuditAction::VulnerabilityRetestCompleted
            | AuditAction::VulnerabilityCommentAdded => "vulnerability",

            AuditAction::ReportGenerated
            | AuditAction::ReportDeleted
            | AuditAction::ReportDownloaded => "report",

            AuditAction::TemplateCreated
            | AuditAction::TemplateUpdated
            | AuditAction::TemplateDeleted => "template",

            AuditAction::TargetGroupCreated
            | AuditAction::TargetGroupUpdated
            | AuditAction::TargetGroupDeleted => "target_group",

            AuditAction::ScheduledScanCreated
            | AuditAction::ScheduledScanUpdated
            | AuditAction::ScheduledScanDeleted => "scheduled_scan",

            AuditAction::ApiKeyCreated
            | AuditAction::ApiKeyUpdated
            | AuditAction::ApiKeyDeleted => "api_key",

            AuditAction::SettingsChanged
            | AuditAction::NotificationSettingsChanged
            | AuditAction::JiraSettingsChanged
            | AuditAction::SiemSettingsChanged => "settings",

            AuditAction::AssetUpdated | AuditAction::AssetDeleted => "asset",

            AuditAction::ComplianceAnalyzed
            | AuditAction::ComplianceReportGenerated
            | AuditAction::ManualAssessmentCreated
            | AuditAction::ManualAssessmentSubmitted
            | AuditAction::ManualAssessmentApproved
            | AuditAction::ManualAssessmentRejected => "compliance",

            AuditAction::JiraTicketCreated | AuditAction::SiemExportTriggered => "integration",

            AuditAction::VpnConfigCreated
            | AuditAction::VpnConfigUpdated
            | AuditAction::VpnConfigDeleted
            | AuditAction::VpnConnected
            | AuditAction::VpnDisconnected => "vpn",

            AuditAction::AccountExportRequested
            | AuditAction::AccountDeleted
            | AuditAction::TermsAccepted => "account",
        }
    }
}

/// Extract client IP address from request headers or peer address
pub fn get_client_ip(req: &HttpRequest) -> Option<String> {
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

/// Extract user agent from request headers
pub fn get_user_agent(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("User-Agent")
        .and_then(|ua| ua.to_str().ok())
        .map(|s| {
            // Truncate user agent if too long (max 512 chars)
            if s.len() > 512 {
                format!("{}...", &s[..509])
            } else {
                s.to_string()
            }
        })
}

/// Log an audit event with full context from HTTP request
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `user_id` - ID of the user performing the action
/// * `action` - The audit action type
/// * `resource_id` - Optional ID of the resource being acted upon
/// * `details` - Optional JSON-serializable details about the action
/// * `req` - The HTTP request for extracting IP and user agent
///
/// # Example
/// ```ignore
/// log_audit(
///     &pool,
///     &claims.sub,
///     AuditAction::ScanCreated,
///     Some(&scan.id),
///     Some(serde_json::json!({ "name": scan.name, "targets": scan.targets })),
///     &req,
/// ).await;
/// ```
pub async fn log_audit(
    pool: &SqlitePool,
    user_id: &str,
    action: AuditAction,
    resource_id: Option<&str>,
    details: Option<serde_json::Value>,
    req: &HttpRequest,
) {
    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        action: action.as_str().to_string(),
        target_type: Some(action.resource_type().to_string()),
        target_id: resource_id.map(|s| s.to_string()),
        details: details.map(|d| d.to_string()),
        ip_address: get_client_ip(req),
        user_agent: get_user_agent(req),
        created_at: Utc::now(),
    };

    if let Err(e) = db::create_audit_log(pool, &log).await {
        log::error!("Failed to create audit log entry: {}", e);
    }
}

/// Log an audit event without HTTP request context (for background tasks)
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `user_id` - ID of the user performing the action
/// * `action` - The audit action type
/// * `resource_id` - Optional ID of the resource being acted upon
/// * `details` - Optional JSON-serializable details about the action
pub async fn log_audit_no_request(
    pool: &SqlitePool,
    user_id: &str,
    action: AuditAction,
    resource_id: Option<&str>,
    details: Option<serde_json::Value>,
) {
    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        action: action.as_str().to_string(),
        target_type: Some(action.resource_type().to_string()),
        target_id: resource_id.map(|s| s.to_string()),
        details: details.map(|d| d.to_string()),
        ip_address: None,
        user_agent: None,
        created_at: Utc::now(),
    };

    if let Err(e) = db::create_audit_log(pool, &log).await {
        log::error!("Failed to create audit log entry: {}", e);
    }
}

/// Builder for creating audit logs with fluent API
#[derive(Default)]
pub struct AuditLogBuilder {
    user_id: Option<String>,
    action: Option<AuditAction>,
    resource_id: Option<String>,
    details: Option<serde_json::Value>,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

impl AuditLogBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn user(mut self, user_id: &str) -> Self {
        self.user_id = Some(user_id.to_string());
        self
    }

    pub fn action(mut self, action: AuditAction) -> Self {
        self.action = Some(action);
        self
    }

    pub fn resource(mut self, resource_id: &str) -> Self {
        self.resource_id = Some(resource_id.to_string());
        self
    }

    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn from_request(mut self, req: &HttpRequest) -> Self {
        self.ip_address = get_client_ip(req);
        self.user_agent = get_user_agent(req);
        self
    }

    pub async fn save(self, pool: &SqlitePool) -> Result<(), anyhow::Error> {
        let action = self.action.ok_or_else(|| anyhow::anyhow!("Action is required"))?;
        let user_id = self.user_id.ok_or_else(|| anyhow::anyhow!("User ID is required"))?;

        let log = AuditLog {
            id: Uuid::new_v4().to_string(),
            user_id,
            action: action.as_str().to_string(),
            target_type: Some(action.resource_type().to_string()),
            target_id: self.resource_id,
            details: self.details.map(|d| d.to_string()),
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            created_at: Utc::now(),
        };

        db::create_audit_log(pool, &log).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_as_str() {
        assert_eq!(AuditAction::Login.as_str(), "auth.login");
        assert_eq!(AuditAction::ScanCreated.as_str(), "scan.created");
        assert_eq!(AuditAction::UserDeleted.as_str(), "user.deleted");
    }

    #[test]
    fn test_action_resource_type() {
        assert_eq!(AuditAction::Login.resource_type(), "auth");
        assert_eq!(AuditAction::ScanCreated.resource_type(), "scan");
        assert_eq!(AuditAction::UserDeleted.resource_type(), "user");
    }
}
