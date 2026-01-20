//! Database module for HeroForge
//!
//! This module provides all database operations organized into domain-specific submodules:
//! - `users`: User management, roles, permissions, GDPR compliance
//! - `scans`: Scan operations, reports, templates, target groups, scheduled scans
//! - `vulnerabilities`: Vulnerability tracking, remediation workflow, statistics
//! - `auth`: Authentication - refresh tokens, account lockout, MFA, password history
//! - `settings`: System settings, notifications, API keys, SIEM integration
//! - `analytics`: Dashboard analytics and statistics
//! - `assets`: Asset inventory management
//! - `manual_assessments`: Manual compliance assessment operations
//! - `migrations`: Database schema migrations
//! - `models`: Data models and DTOs

#![allow(dead_code)]
#![allow(unused_imports)]

// Submodules
pub mod ad_assessment;
pub mod agent_mesh;
pub mod agents;
pub mod ai;
pub mod ai_security;
pub mod analytics;
pub mod api_governance;
pub mod api_security;
pub mod asm;
pub mod asset_discovery;
pub mod assets;
pub mod attack_paths;
pub mod auth;
pub mod bas;
pub mod bi;
pub mod bloodhound;
pub mod breach;
pub mod chat;
pub mod cicd;
pub mod cloud;
pub mod cloud_discovery;
pub mod compliance_automation;
pub mod container;
pub mod cracking;
pub mod credential_audit;
pub mod crm;
pub mod cross_team;
pub mod crm_asset_sync;
pub mod data_lake;
pub mod deception;
pub mod dlp;
pub mod dorking;
pub mod engagement_templates;
pub mod evidence;
pub mod exclusions;
pub mod exploits;
pub mod finding_templates;
pub mod iac;
pub mod insider_threat;
pub mod iot;
pub mod k8s_security;
pub mod manual_assessments;
pub mod methodology;
pub mod migrations;
pub mod models;
pub mod optimization;
pub mod permissions;
pub mod models_dashboard;
pub mod nuclei;
pub mod plugin_marketplace;
pub mod plugins;
pub mod privesc;
pub mod purple_team;
pub mod push_tokens;
pub mod quotas;
pub mod scans;
pub mod scheduled_reports;
pub mod secret_findings;
pub mod servicenow;
pub mod settings;
pub mod shodan_cache;
pub mod supply_chain;
pub mod threat_feeds;
pub mod threat_intel;
pub mod users;
pub mod vulnerabilities;
pub mod vpn;
pub mod webhooks;
pub mod workflows;
pub mod remediation;
pub mod executive_dashboard;
pub mod report_templates;
pub mod yara;
pub mod detection_engineering;
pub mod threat_hunting;
pub mod devsecops;
pub mod sbom;
pub mod sca;
pub mod threat_modeling;
pub mod yellow_team;
pub mod ot_ics;
pub mod soar_cases;
// Phase 4 Sprint 2-10 database modules
pub mod investigation;
pub mod threat_intel_enhanced;
pub mod cti_automation;
pub mod patch_management;
pub mod orchestration;
pub mod predictive_security;
// Phase 4 Sprint 11-18 database modules
pub mod web3;
pub mod emerging_tech;
pub mod ml_advanced;
pub mod performance;
pub mod analytics_engine;
pub mod intelligence_platform;
pub mod client_compliance;
// ACAS-inspired modules
pub mod scap;
pub mod windows_audit;
pub mod emass;
pub mod audit_files;
// Legal documents module
pub mod legal_documents;
// Academy LMS module
pub mod academy;

// Core imports used by this module
use sqlx::sqlite::SqlitePool;
use anyhow::Result;
use once_cell::sync::Lazy;

/// Configurable bcrypt cost factor (defaults to 12, range 10-16)
/// Set via BCRYPT_COST environment variable
pub static BCRYPT_COST: Lazy<u32> = Lazy::new(|| {
    std::env::var("BCRYPT_COST")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(|cost: u32| {
            if cost < 10 {
                log::warn!("BCRYPT_COST {} is too low, using minimum of 10", cost);
                10
            } else if cost > 16 {
                log::warn!("BCRYPT_COST {} is too high, using maximum of 16", cost);
                16
            } else {
                cost
            }
        })
        .unwrap_or(12)
});

// ============================================================================
// Database Initialization
// ============================================================================

pub async fn init_database(database_url: &str) -> Result<SqlitePool> {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    // Check for encryption key in environment variable
    let encryption_key = std::env::var("DATABASE_ENCRYPTION_KEY").ok();

    // Parse the database URL
    let mut connect_options = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .shared_cache(true);

    // Check if database encryption is required (for production deployments)
    let require_encryption = std::env::var("REQUIRE_DB_ENCRYPTION")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false);

    // Apply encryption key if provided via PRAGMA key
    // SQLCipher will encrypt the database with AES-256 using this key
    // Using SQLCipher 4.x defaults: 256000 KDF iterations, HMAC_SHA512, PBKDF2_HMAC_SHA512
    if let Some(key) = &encryption_key {
        log::info!("Database encryption is ENABLED via DATABASE_ENCRYPTION_KEY");
        // Key must be quoted for SQLCipher PRAGMA key syntax
        connect_options = connect_options.pragma("key", format!("'{}'", key));
        // Using SQLCipher 4.x defaults - no additional cipher pragmas needed
    } else if require_encryption {
        // SECURITY: Fail startup if encryption is required but no key is provided
        return Err(anyhow::anyhow!(
            "Database encryption is REQUIRED (REQUIRE_DB_ENCRYPTION=true) but DATABASE_ENCRYPTION_KEY is not set.\n\
             Generate a key with: openssl rand -hex 32\n\
             Then set: DATABASE_ENCRYPTION_KEY=<generated_key>"
        ));
    } else {
        log::warn!("Database encryption is DISABLED. Set DATABASE_ENCRYPTION_KEY environment variable to enable encryption.");
        log::warn!("For production use, set REQUIRE_DB_ENCRYPTION=true to enforce encryption.");
    }

    // Get pool size from environment or use default
    let max_connections: u32 = std::env::var("DB_POOL_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .idle_timeout(Some(std::time::Duration::from_secs(600)))
        .connect_with(connect_options)
        .await?;

    // Configure SQLite pragmas for optimal performance and reliability
    sqlx::query("PRAGMA journal_mode=WAL").execute(&pool).await?;
    sqlx::query("PRAGMA synchronous=NORMAL").execute(&pool).await?;
    sqlx::query("PRAGMA foreign_keys=ON").execute(&pool).await?;
    sqlx::query("PRAGMA busy_timeout=10000").execute(&pool).await?;
    // Cache size: negative value = KB, positive = pages. -32000 = ~32MB cache
    sqlx::query("PRAGMA cache_size=-32000").execute(&pool).await?;
    // Memory-mapped I/O for improved read performance
    sqlx::query("PRAGMA mmap_size=268435456").execute(&pool).await?; // 256MB
    // Temp store in memory for faster temp table operations
    sqlx::query("PRAGMA temp_store=MEMORY").execute(&pool).await?;

    // Run migrations
    run_migrations(&pool).await?;

    Ok(pool)
}

async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    // Create users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT 1
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Add is_active column if it doesn't exist (for databases created before this column was added)
    let has_is_active: bool = sqlx::query_scalar(
        "SELECT COUNT(*) > 0 FROM pragma_table_info('users') WHERE name = 'is_active'"
    )
    .fetch_one(pool)
    .await?;

    if !has_is_active {
        sqlx::query("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
            .execute(pool)
            .await?;
    }

    // Create scan_results table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scan_results (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            targets TEXT NOT NULL,
            status TEXT NOT NULL,
            results TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            error_message TEXT,
            customer_id TEXT,
            engagement_id TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scan_results(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scans_status ON scan_results(status)")
        .execute(pool)
        .await?;

    // Run admin console migrations
    migrations::run_migrations(pool).await?;

    // Run Yellow Team API Security migrations
    yellow_team::run_migrations(pool).await?;

    // Run deception technology migrations (Sprint 7)
    deception::run_migrations(pool).await?;

    // Run insider threat migrations (Sprint 8)
    insider_threat::run_migrations(pool).await?;

    // Run DLP migrations (Sprint 8)
    dlp::run_migrations(pool).await?;

    // Run Phase 3 migrations (Sprints 11-20)
    api_governance::init_tables(pool).await?;
    compliance_automation::init_tables(pool).await?;
    k8s_security::init_tables(pool).await?;
    supply_chain::init_tables(pool).await?;
    plugin_marketplace::init_tables(pool).await?;
    threat_feeds::init_tables(pool).await?;
    bi::init_tables(pool).await?;

    // Run Phase 4 migrations (Sprints 2-10)
    investigation::run_migrations(pool).await?;
    threat_intel_enhanced::init_tables(pool).await?;
    cti_automation::init_tables(pool).await?;
    patch_management::init_tables(pool).await?;
    orchestration::init_tables(pool).await?;
    predictive_security::init_tables(pool).await?;

    // Run Phase 4 migrations (Sprints 11-18)
    web3::init_tables(pool).await?;
    emerging_tech::init_tables(pool).await?;
    ml_advanced::init_tables(pool).await?;
    performance::init_tables(pool).await?;
    analytics_engine::init_tables(pool).await?;
    intelligence_platform::init_tables(pool).await?;

    // Run Cross-Team Data Flow migrations
    cross_team::run_migrations(pool).await?;

    // Note: ACAS tables (scap, windows_audit, emass, audit_files) are already
    // created by migrations::run_migrations(), so we don't call their init_tables
    // here to avoid schema conflicts.

    // Initialize legal documents tables
    legal_documents::init_tables(pool).await?;

    // Initialize Academy LMS tables
    academy::init_tables(pool).await?;

    Ok(())
}

// ============================================================================
// Re-exports from users module
// ============================================================================

pub use users::{
    create_user,
    get_user_by_username,
    get_user_by_id,
    get_user_by_email,
    update_user_profile,
    update_user_password,
    delete_user,
    get_user_roles,
    assign_role_to_user,
    remove_role_from_user,
    has_permission,
    get_all_users,
    update_user,
    accept_terms,
    export_user_data,
    delete_user_account,
};

// ============================================================================
// Re-exports from scans module
// ============================================================================

pub use scans::{
    create_scan,
    get_user_scans,
    get_scan_by_id,
    update_scan_status,
    get_all_scans,
    delete_scan_admin,
    delete_scan,
    create_report,
    get_user_reports,
    get_scan_reports,
    get_report_by_id,
    update_report_status,
    delete_report,
    get_all_reports,
    // Report operator notes functions
    update_report_notes,
    get_report_notes,
    upsert_finding_note,
    delete_finding_note,
    get_finding_notes_map,
    // Template functions
    create_template,
    get_user_templates,
    get_user_custom_templates,
    get_system_templates,
    get_templates_by_category,
    get_scan_template_categories,
    get_template_by_id,
    get_default_template,
    set_default_template,
    increment_template_use_count,
    clone_template as clone_scan_template,
    update_template,
    delete_template,
    // Target group functions
    create_target_group,
    get_user_target_groups,
    get_target_group_by_id,
    update_target_group,
    delete_target_group,
    create_scheduled_scan,
    get_user_scheduled_scans,
    get_scheduled_scan_by_id,
    update_scheduled_scan,
    delete_scheduled_scan,
    get_due_scheduled_scans,
    update_scheduled_scan_execution,
    calculate_next_run,
    create_execution_record,
    complete_execution_record,
    get_execution_history,
    cleanup_old_executions,
    update_scheduled_scan_retry,
    reset_scheduled_scan_retry,
};

// ============================================================================
// Re-exports from vulnerabilities module
// ============================================================================

pub use vulnerabilities::{
    create_vulnerability_tracking,
    get_vulnerability_tracking_by_scan,
    get_vulnerability_detail,
    get_remediation_timeline,
    update_vulnerability_status,
    add_vulnerability_comment,
    get_vulnerability_comments,
    get_vulnerability_comments_with_user,
    delete_vulnerability_comment,
    update_vulnerability_comment,
    bulk_update_vulnerability_status,
    mark_vulnerability_for_verification,
    bulk_assign_vulnerabilities,
    validate_status_transition,
    get_vulnerability_statistics,
    // Retest workflow functions
    request_vulnerability_retest,
    bulk_request_retests,
    complete_vulnerability_retest,
    get_vulnerabilities_pending_retest,
    get_retest_history,
    // Additional bulk operations
    bulk_update_severity,
    bulk_delete_vulnerabilities,
    bulk_add_tags,
    verify_vulnerability_ids,
    // Vulnerability assignment functions
    get_user_assignments,
    get_vulnerabilities_with_assignments,
    assign_vulnerability,
    unassign_vulnerability,
    get_user_assignment_stats,
};

// ============================================================================
// Re-exports from finding_templates module
// ============================================================================

pub use finding_templates::{
    list_finding_templates,
    get_finding_template,
    create_finding_template,
    update_finding_template,
    delete_finding_template,
    clone_finding_template,
    get_template_categories,
    // New enhanced finding template functions
    list_finding_template_categories,
    get_finding_template_category,
    create_finding_template_category,
    delete_finding_template_category,
    increment_template_use_count as increment_finding_template_use_count,
    get_popular_templates,
    search_templates,
    get_templates_by_owasp,
    get_templates_by_mitre,
};

// ============================================================================
// Re-exports from auth module
// ============================================================================

pub use auth::{
    store_refresh_token,
    get_refresh_token,
    revoke_refresh_token,
    revoke_all_user_refresh_tokens,
    cleanup_expired_refresh_tokens,
    record_login_attempt,
    check_account_locked,
    increment_failed_attempts,
    reset_failed_attempts,
    unlock_user_account,
    get_user_lockout_status,
    get_all_locked_accounts,
    get_recent_login_attempts,
    store_totp_secret,
    get_totp_secret,
    enable_mfa,
    disable_mfa,
    is_mfa_enabled,
    store_recovery_codes,
    verify_and_consume_recovery_code,
    check_password_history,
    add_password_to_history,
};

// ============================================================================
// Re-exports from settings module
// ============================================================================

pub use settings::{
    create_audit_log,
    log_audit,
    log_audit_full,
    get_audit_logs,
    get_audit_logs_filtered,
    get_audit_action_types,
    get_audit_users,
    get_all_settings,
    get_setting,
    update_setting,
    get_notification_settings,
    get_system_notification_settings,
    update_notification_settings,
    create_api_key,
    get_user_api_keys,
    get_api_key_by_id,
    verify_api_key,
    update_api_key,
    delete_api_key,
    get_siem_settings,
    get_siem_settings_by_id,
    create_siem_settings,
    update_siem_settings,
    delete_siem_settings,
};

// ============================================================================
// Re-export Analytics Functions
// ============================================================================

pub use analytics::{
    get_analytics_summary,
    get_hosts_over_time,
    get_vulnerabilities_over_time,
    get_top_services,
    get_scan_frequency,
    // Executive analytics
    get_customer_security_trends,
    get_customer_executive_summary,
    get_remediation_velocity,
    get_risk_trends,
    get_methodology_coverage,
    get_executive_dashboard,
    // Vulnerability trends analytics
    get_vulnerability_trends,
    get_severity_distribution_over_time,
    get_remediation_rate,
    get_top_recurring_vulns,
    get_vulnerability_trends_dashboard,
    // Vulnerability trends types
    DailyVulnerabilityCount,
    RemediationRatePoint,
    RecurringVulnerability,
    VulnerabilityTrendsData,
    VulnerabilityTrendsSummary,
};

// ============================================================================
// Re-exports from vpn module
// ============================================================================

pub use vpn::{
    create_vpn_config,
    get_user_vpn_configs,
    get_vpn_config_by_id,
    update_vpn_config,
    update_vpn_config_last_used,
    delete_vpn_config,
    get_default_vpn_config,
    create_vpn_connection,
    update_vpn_connection_connected,
    update_vpn_connection_disconnected,
    update_vpn_connection_error,
    get_active_vpn_connection,
    get_vpn_connection_history,
    cleanup_stale_connections,
};

// ============================================================================
// Re-exports from methodology module
// ============================================================================

pub use methodology::{
    list_methodology_templates,
    get_methodology_template,
    get_methodology_template_with_items,
    get_methodology_template_item,
    create_checklist,
    get_user_checklists,
    get_checklist,
    get_checklist_with_items,
    update_checklist,
    delete_checklist,
    update_checklist_item,
    get_checklist_progress,
    get_checklist_item,
    recalculate_checklist_progress,
    ChecklistItemWithTemplate,
};

// ============================================================================
// Re-exports from exclusions module
// ============================================================================

pub use exclusions::{
    create_exclusion,
    get_user_exclusions,
    get_global_exclusions,
    get_exclusion_by_id,
    update_exclusion,
    delete_exclusion,
    get_exclusions_by_ids,
    should_exclude_target,
    should_exclude_port,
    ScanExclusion,
    CreateExclusionRequest,
    UpdateExclusionRequest,
    ExclusionType,
    ExclusionRule,
};

// ============================================================================
// Re-exports from webhooks module
// ============================================================================

pub use webhooks::{
    create_webhook,
    get_user_webhooks,
    get_webhook_by_id,
    get_webhook_by_id_internal,
    update_webhook,
    delete_webhook,
    get_webhooks_for_event,
    update_webhook_status,
    disable_webhook,
    log_delivery,
    get_delivery_history,
    cleanup_old_deliveries,
    get_webhook_stats,
    Webhook,
    WebhookResponse,
    WebhookDelivery,
    CreateWebhookRequest,
    UpdateWebhookRequest,
    WebhookStats,
};

// ============================================================================
// Re-exports from scheduled_reports module
// ============================================================================

pub use scheduled_reports::{
    create_scheduled_report,
    get_user_scheduled_reports,
    get_scheduled_report_by_id,
    update_scheduled_report,
    delete_scheduled_report,
    get_due_scheduled_reports,
    update_scheduled_report_execution,
};

// ============================================================================
// Re-exports from permissions module
// ============================================================================

pub use permissions::{
    // Types
    Organization,
    Department,
    Team,
    OrgRole,
    TeamRole,
    Permission,
    PermissionInfo,
    Policy,
    PolicyInfo,
    PolicyConditions,
    PolicyEffect,
    RoleTemplate,
    RoleTemplateInfo,
    CustomRole,
    UserRoleAssignment,
    RoleAssignmentInfo,
    UserPermissionOverride,
    PermissionContext,
    PermissionResult,
    PermissionReason,
    EffectivePermissions,
    ResourceOwnership,
    ResourceShare,
    OwnerType,
    SharePermissionLevel,
    OrganizationSummary,
    DepartmentSummary,
    TeamSummary,
    TeamMember,
    UserSummary,
    // Request types
    CreateOrganizationRequest,
    UpdateOrganizationRequest,
    CreateDepartmentRequest,
    UpdateDepartmentRequest,
    CreateTeamRequest,
    UpdateTeamRequest,
    CreateCustomRoleRequest,
    UpdateCustomRoleRequest,
    AssignRoleRequest,
    AddPermissionOverrideRequest,
    ShareResourceRequest,
    CheckPermissionRequest,
    // Organization functions
    organizations::create_organization,
    organizations::get_organization_by_id,
    organizations::get_organization_by_slug,
    organizations::list_user_organizations,
    organizations::update_organization,
    organizations::delete_organization,
    organizations::is_org_admin,
    organizations::get_user_org_role,
    organizations::add_user_to_organization,
    organizations::remove_user_from_organization,
    organizations::list_organization_members,
    // Department functions
    organizations::create_department,
    organizations::get_department_by_id,
    organizations::list_departments,
    organizations::update_department,
    organizations::delete_department,
    // Team functions
    organizations::create_team,
    organizations::get_team_by_id,
    organizations::list_teams_in_department,
    organizations::list_teams_in_organization,
    organizations::update_team,
    organizations::delete_team,
    organizations::add_user_to_team,
    organizations::remove_user_from_team,
    organizations::update_user_team_role,
    organizations::list_team_members,
    organizations::get_user_teams,
    organizations::is_team_lead,
    organizations::is_team_member,
    // Role functions
    roles::list_resource_types,
    roles::list_actions,
    roles::list_permissions,
    roles::list_role_templates,
    roles::get_role_template_by_id,
    roles::get_role_template_info,
    roles::get_template_permissions,
    roles::create_custom_role,
    roles::get_custom_role_by_id,
    roles::list_custom_roles,
    roles::update_custom_role,
    roles::delete_custom_role,
    roles::clone_custom_role,
    roles::assign_role_to_user as assign_permission_role_to_user,
    roles::list_user_role_assignments,
    roles::remove_role_assignment,
    roles::add_user_permission_override,
    roles::list_user_permission_overrides,
    roles::remove_user_permission_override,
    roles::list_policies,
    // Permission evaluation
    evaluation::check_permission,
    evaluation::get_effective_permissions,
    evaluation::has_permission_legacy,
    evaluation::set_resource_owner,
    evaluation::share_resource,
    evaluation::unshare_resource,
    evaluation::list_resource_shares,
    // Cache functions
    cache::invalidate_user_cache,
    cache::invalidate_org_cache,
    cache::cleanup_expired_cache,
    cache::get_cache_stats,
    cache::warmup_user_cache,
    cache::CacheStats,
};

// ============================================================================
// Re-exports from soar_cases module
// ============================================================================

pub use soar_cases::{
    // Types
    SoarCaseRow,
    CaseTaskRow,
    CaseEvidenceRow,
    CaseCommentRow,
    CaseTimelineRow,
    CaseStats,
    CaseFilter,
    // Request types
    CreateCaseRequest as SoarCreateCaseRequest,
    UpdateCaseRequest as SoarUpdateCaseRequest,
    CreateTaskRequest as SoarCreateTaskRequest,
    AddEvidenceRequest as SoarAddEvidenceRequest,
    // Case operations
    create_case as create_soar_case,
    get_case_by_id as get_soar_case_by_id,
    get_case_by_number as get_soar_case_by_number,
    list_cases as list_soar_cases,
    update_case as update_soar_case,
    update_case_status as update_soar_case_status,
    assign_case as assign_soar_case,
    resolve_case as resolve_soar_case,
    delete_case as delete_soar_case,
    // Task operations
    add_task as add_soar_task,
    get_case_tasks as get_soar_case_tasks,
    update_task_status as update_soar_task_status,
    // Evidence operations
    add_evidence as add_soar_evidence,
    get_case_evidence as get_soar_case_evidence,
    // Comment operations
    add_comment as add_soar_comment,
    get_case_comments as get_soar_case_comments,
    // Timeline operations
    add_timeline_event as add_soar_timeline_event,
    get_case_timeline as get_soar_case_timeline,
    // Statistics
    get_case_stats as get_soar_case_stats,
    user_can_access_case,
};

// ============================================================================
// SOAR Playbook Scheduling Functions
// ============================================================================

/// Scheduled playbook model
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScheduledPlaybook {
    pub id: String,
    pub playbook_id: String,
    pub user_id: String,
    pub cron_expression: String,
    pub timezone: String,
    pub next_run_at: chrono::DateTime<chrono::Utc>,
    pub last_run_at: Option<chrono::DateTime<chrono::Utc>>,
    pub is_active: bool,
    pub auto_approve_low_risk: bool,
    pub input_data: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Get all scheduled playbooks that are due to run
pub async fn get_due_scheduled_playbooks(pool: &SqlitePool) -> Result<Vec<ScheduledPlaybook>> {
    let now = chrono::Utc::now();

    let playbooks = sqlx::query_as::<_, ScheduledPlaybook>(
        r#"
        SELECT sp.id, sp.playbook_id, sp.user_id, sp.cron_expression, sp.timezone,
               sp.next_run_at, sp.last_run_at, sp.is_active, sp.auto_approve_low_risk,
               sp.input_data, sp.created_at, sp.updated_at
        FROM soar_scheduled_playbooks sp
        INNER JOIN soar_playbooks p ON sp.playbook_id = p.id
        WHERE sp.is_active = 1
          AND sp.next_run_at <= ?
          AND p.is_active = 1
        ORDER BY sp.next_run_at ASC
        "#,
    )
    .bind(now.to_rfc3339())
    .fetch_all(pool)
    .await?;

    Ok(playbooks)
}

/// Update playbook next run time after execution
pub async fn update_playbook_next_run(
    pool: &SqlitePool,
    scheduled_playbook_id: &str,
    next_run: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let now = chrono::Utc::now();

    sqlx::query(
        r#"
        UPDATE soar_scheduled_playbooks
        SET next_run_at = ?,
            last_run_at = ?,
            updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(next_run.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(scheduled_playbook_id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Re-exports from client_compliance module
// ============================================================================

pub use client_compliance::{
    // Types
    ClientComplianceChecklist,
    ClientComplianceItem,
    ClientComplianceEvidence,
    ClientComplianceHistory,
    ChecklistStatus,
    ControlStatus,
    EvidenceType,
    CustomerComplianceSummary,
    FrameworkSummary,
    // Request types
    CreateChecklistRequest,
    UpdateChecklistRequest,
    UpdateItemRequest,
    AddEvidenceRequest,
    // Checklist functions
    create_checklist as create_client_checklist,
    get_checklist as get_client_checklist,
    list_checklists_for_customer,
    list_checklists_for_engagement,
    list_all_checklists as list_all_client_checklists,
    update_checklist as update_client_checklist,
    delete_checklist as delete_client_checklist,
    // Item functions
    add_checklist_item as add_client_checklist_item,
    get_checklist_item as get_client_checklist_item,
    list_checklist_items as list_client_checklist_items,
    update_checklist_item as update_client_checklist_item,
    bulk_update_checkboxes,
    // Evidence functions
    add_evidence as add_client_evidence,
    get_evidence as get_client_evidence,
    list_evidence_for_item,
    list_evidence_for_checklist,
    list_evidence_for_customer,
    delete_evidence as delete_client_evidence,
    // History functions
    add_history as add_client_compliance_history,
    get_checklist_history as get_client_checklist_history,
    get_item_history as get_client_item_history,
    // Statistics
    recalculate_checklist_stats,
    get_customer_compliance_summary,
    // Framework population
    populate_checklist_from_framework,
};
