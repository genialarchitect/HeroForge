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
pub mod analytics;
pub mod api_security;
pub mod assets;
pub mod attack_paths;
pub mod auth;
pub mod bas;
pub mod cicd;
pub mod cloud;
pub mod container;
pub mod credential_audit;
pub mod crm;
pub mod evidence;
pub mod exclusions;
pub mod finding_templates;
pub mod iac;
pub mod manual_assessments;
pub mod methodology;
pub mod migrations;
pub mod models;
pub mod models_dashboard;
pub mod plugins;
pub mod push_tokens;
pub mod scans;
pub mod scheduled_reports;
pub mod secret_findings;
pub mod servicenow;
pub mod settings;
pub mod threat_intel;
pub mod users;
pub mod vulnerabilities;
pub mod vpn;
pub mod webhooks;
pub mod workflows;

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
    if let Some(key) = &encryption_key {
        log::info!("Database encryption is ENABLED via DATABASE_ENCRYPTION_KEY");
        connect_options = connect_options.pragma("key", key.clone());

        // Set SQLCipher configuration for maximum security
        // PBKDF2 HMAC SHA512 with 256,000 iterations (FIPS 140-2 compliant)
        connect_options = connect_options
            .pragma("cipher_page_size", "4096")
            .pragma("kdf_iter", "256000")
            .pragma("cipher_hmac_algorithm", "HMAC_SHA512")
            .pragma("cipher_kdf_algorithm", "PBKDF2_HMAC_SHA512");
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

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connect_options)
        .await?;

    // Configure SQLite pragmas for optimal performance and reliability
    sqlx::query("PRAGMA journal_mode=WAL").execute(&pool).await?;
    sqlx::query("PRAGMA synchronous=NORMAL").execute(&pool).await?;
    sqlx::query("PRAGMA foreign_keys=ON").execute(&pool).await?;
    sqlx::query("PRAGMA busy_timeout=5000").execute(&pool).await?;

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
