use sqlx::SqlitePool;
use anyhow::Result;

/// Run all database migrations
pub async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    create_roles_table(pool).await?;
    create_user_roles_table(pool).await?;
    create_audit_logs_table(pool).await?;
    create_system_settings_table(pool).await?;
    create_cve_cache_table(pool).await?;
    create_reports_table(pool).await?;
    create_scheduled_scans_table(pool).await?;
    create_scheduled_scan_executions_table(pool).await?;
    create_scan_templates_table(pool).await?;
    create_target_groups_table(pool).await?;
    create_notification_settings_table(pool).await?;
    create_login_attempts_table(pool).await?;
    create_account_lockouts_table(pool).await?;
    create_refresh_tokens_table(pool).await?;
    create_password_history_table(pool).await?;
    create_vulnerability_tracking_table(pool).await?;
    create_vulnerability_comments_table(pool).await?;
    create_remediation_timeline_table(pool).await?;
    create_api_keys_table(pool).await?;
    create_user_dashboard_config_table(pool).await?;
    create_assets_table(pool).await?;
    create_asset_ports_table(pool).await?;
    create_asset_history_table(pool).await?;
    create_jira_settings_table(pool).await?;
    add_jira_ticket_id_to_vulnerability_tracking(pool).await?;
    create_siem_settings_table(pool).await?;
    add_notification_webhook_columns(pool).await?;
    create_dns_recon_results_table(pool).await?;
    seed_default_roles(pool).await?;
    seed_default_settings(pool).await?;
    add_gdpr_consent_columns(pool).await?;
    add_mfa_columns_to_users(pool).await?;
    // Manual compliance assessment system tables
    create_compliance_rubrics_table(pool).await?;
    create_manual_assessments_table(pool).await?;
    create_assessment_evidence_table(pool).await?;
    create_assessment_history_table(pool).await?;
    create_assessment_campaigns_table(pool).await?;
    create_campaign_assessments_table(pool).await?;
    // VPN configuration tables
    create_vpn_configs_table(pool).await?;
    create_vpn_connections_table(pool).await?;
    // CRM tables
    create_customers_table(pool).await?;
    create_contacts_table(pool).await?;
    create_engagements_table(pool).await?;
    create_engagement_milestones_table(pool).await?;
    create_contracts_table(pool).await?;
    create_sla_definitions_table(pool).await?;
    create_time_entries_table(pool).await?;
    create_communications_table(pool).await?;
    create_portal_users_table(pool).await?;
    add_crm_columns_to_existing_tables(pool).await?;
    // Portal password reset tokens
    create_portal_password_reset_tokens_table(pool).await?;
    // Finding templates library
    create_finding_templates_table(pool).await?;
    // Tier 1 feature tables
    create_attack_paths_tables(pool).await?;
    create_cloud_scan_tables(pool).await?;
    create_api_security_scan_tables(pool).await?;
    create_methodology_tables(pool).await?;
    // Portal user roles
    add_role_column_to_portal_users(pool).await?;
    // Enhanced audit logging
    enhance_audit_logs_table(pool).await?;
    // Scan tags system
    create_scan_tags_table(pool).await?;
    create_scan_tag_mappings_table(pool).await?;
    // Asset tags system
    create_asset_tags_table(pool).await?;
    create_asset_tag_mappings_table(pool).await?;
    // AD Assessment tables
    create_ad_assessment_tables(pool).await?;
    // Credential Audit tables
    create_credential_audit_tables(pool).await?;
    Ok(())
}

/// Create roles table
async fn create_roles_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS roles (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            can_manage_users INTEGER DEFAULT 0,
            can_manage_scans INTEGER DEFAULT 0,
            can_view_all_scans INTEGER DEFAULT 0,
            can_delete_any_scan INTEGER DEFAULT 0,
            can_view_audit_logs INTEGER DEFAULT 0,
            can_manage_settings INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Create user_roles junction table
async fn create_user_roles_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id TEXT NOT NULL,
            role_id TEXT NOT NULL,
            assigned_at TEXT NOT NULL,
            assigned_by TEXT,
            PRIMARY KEY (user_id, role_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Create audit_logs table
async fn create_audit_logs_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            details TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Create system_settings table
async fn create_system_settings_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            description TEXT,
            updated_by TEXT,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (updated_by) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Create CVE cache table for storing API-fetched vulnerability data
async fn create_cve_cache_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cve_cache (
            cve_id TEXT PRIMARY KEY,
            product TEXT NOT NULL,
            version_pattern TEXT,
            severity TEXT NOT NULL,
            cvss_score REAL,
            title TEXT NOT NULL,
            description TEXT,
            published_date TEXT,
            last_updated TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for product lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cve_cache_product ON cve_cache(product)")
        .execute(pool)
        .await?;

    // Create index for expiration cleanup
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cve_cache_expires ON cve_cache(expires_at)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create reports table for storing generated reports
async fn create_reports_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            format TEXT NOT NULL,
            template_id TEXT NOT NULL,
            sections TEXT NOT NULL,
            file_path TEXT,
            file_size INTEGER,
            status TEXT NOT NULL,
            error_message TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            expires_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (scan_id) REFERENCES scan_results(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Seed default roles
async fn seed_default_roles(pool: &SqlitePool) -> Result<()> {
    // Check if roles already exist
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM roles")
        .fetch_one(pool)
        .await?;

    if count.0 > 0 {
        return Ok(()); // Roles already seeded
    }

    // Insert default roles
    sqlx::query(
        r#"
        INSERT INTO roles (id, name, description, can_manage_users, can_manage_scans,
                           can_view_all_scans, can_delete_any_scan, can_view_audit_logs,
                           can_manage_settings, created_at)
        VALUES
            ('admin', 'admin', 'Full system access', 1, 1, 1, 1, 1, 1, datetime('now')),
            ('user', 'user', 'Standard user access', 0, 0, 0, 0, 0, 0, datetime('now')),
            ('auditor', 'auditor', 'Read-only access to all scans and logs', 0, 0, 1, 0, 1, 0, datetime('now')),
            ('viewer', 'viewer', 'View-only access to own scans', 0, 0, 0, 0, 0, 0, datetime('now'))
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Seed default system settings
async fn seed_default_settings(pool: &SqlitePool) -> Result<()> {
    // Check if settings already exist
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM system_settings")
        .fetch_one(pool)
        .await?;

    if count.0 > 0 {
        return Ok(()); // Settings already seeded
    }

    // Insert default settings
    sqlx::query(
        r#"
        INSERT INTO system_settings (key, value, description, updated_at)
        VALUES
            ('max_scans_per_user', '100', 'Maximum scans per user', datetime('now')),
            ('scan_retention_days', '90', 'Auto-delete scans older than N days', datetime('now')),
            ('allow_registration', 'true', 'Allow new user registration', datetime('now'))
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Create scheduled_scans table for recurring scan jobs
async fn create_scheduled_scans_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            config TEXT NOT NULL,
            schedule_type TEXT NOT NULL,
            schedule_value TEXT NOT NULL,
            next_run_at TEXT NOT NULL,
            last_run_at TEXT,
            last_scan_id TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            run_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (last_scan_id) REFERENCES scan_results(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scheduled_scans_user_id ON scheduled_scans(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scheduled_scans_next_run ON scheduled_scans(next_run_at)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scheduled_scans_active ON scheduled_scans(is_active)")
        .execute(pool)
        .await?;

    // Add retry columns for existing tables (if they don't exist)
    add_scheduled_scans_retry_columns(pool).await?;

    Ok(())
}

/// Add retry-related columns to scheduled_scans table for existing databases
async fn add_scheduled_scans_retry_columns(pool: &SqlitePool) -> Result<()> {
    // Check if columns already exist (SQLite doesn't support IF NOT EXISTS for ALTER TABLE)
    let table_info: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(scheduled_scans)")
        .fetch_all(pool)
        .await?;

    let has_retry_count = table_info.iter().any(|(_, name, _, _, _, _)| name == "retry_count");
    let has_max_retries = table_info.iter().any(|(_, name, _, _, _, _)| name == "max_retries");
    let has_last_error = table_info.iter().any(|(_, name, _, _, _, _)| name == "last_error");

    if !has_retry_count {
        sqlx::query("ALTER TABLE scheduled_scans ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await?;
    }

    if !has_max_retries {
        sqlx::query("ALTER TABLE scheduled_scans ADD COLUMN max_retries INTEGER NOT NULL DEFAULT 3")
            .execute(pool)
            .await?;
    }

    if !has_last_error {
        sqlx::query("ALTER TABLE scheduled_scans ADD COLUMN last_error TEXT")
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Create scheduled_scan_executions table for tracking execution history
async fn create_scheduled_scan_executions_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scheduled_scan_executions (
            id TEXT PRIMARY KEY,
            scheduled_scan_id TEXT NOT NULL,
            scan_result_id TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT NOT NULL,
            error_message TEXT,
            retry_attempt INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (scheduled_scan_id) REFERENCES scheduled_scans(id) ON DELETE CASCADE,
            FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_executions_scheduled_scan_id ON scheduled_scan_executions(scheduled_scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_executions_started_at ON scheduled_scan_executions(started_at)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_executions_status ON scheduled_scan_executions(status)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create scan_templates table for reusable scan configurations
async fn create_scan_templates_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scan_templates (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            config TEXT NOT NULL,
            is_default INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_templates_user_id ON scan_templates(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_templates_is_default ON scan_templates(is_default)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create target_groups table for organizing scan targets
async fn create_target_groups_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS target_groups (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            targets TEXT NOT NULL,
            color TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_target_groups_user_id ON target_groups(user_id)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create notification_settings table for user email notification preferences
async fn create_notification_settings_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS notification_settings (
            user_id TEXT PRIMARY KEY,
            email_on_scan_complete INTEGER NOT NULL DEFAULT 0,
            email_on_critical_vuln INTEGER NOT NULL DEFAULT 1,
            email_address TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Create login_attempts table for tracking failed login attempts (NIST 800-53 AC-7)
async fn create_login_attempts_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            attempt_time TEXT NOT NULL,
            success INTEGER NOT NULL,
            ip_address TEXT,
            user_agent TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for efficient username lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)")
        .execute(pool)
        .await?;

    // Create index for time-based queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(attempt_time)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create account_lockouts table for tracking locked accounts (NIST 800-53 AC-7, CIS Controls 16.11)
async fn create_account_lockouts_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS account_lockouts (
            username TEXT PRIMARY KEY,
            locked_until TEXT NOT NULL,
            attempt_count INTEGER NOT NULL,
            first_failed_attempt TEXT NOT NULL,
            last_failed_attempt TEXT NOT NULL,
            lockout_reason TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for efficient time-based lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_account_lockouts_locked_until ON account_lockouts(locked_until)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create refresh_tokens table for JWT refresh token management (NIST 800-63B)
async fn create_refresh_tokens_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Add GDPR consent tracking columns to users table
async fn add_gdpr_consent_columns(pool: &SqlitePool) -> Result<()> {
    // Check if columns already exist (SQLite doesn't support IF NOT EXISTS for ALTER TABLE)
    let table_info: Vec<(i64, String, String, i64, Option<String>, i64)> = sqlx::query_as("PRAGMA table_info(users)")
        .fetch_all(pool)
        .await?;

    let has_accepted_terms_at = table_info.iter().any(|(_, name, _, _, _, _)| name == "accepted_terms_at");
    let has_terms_version = table_info.iter().any(|(_, name, _, _, _, _)| name == "terms_version");

    if !has_accepted_terms_at {
        sqlx::query("ALTER TABLE users ADD COLUMN accepted_terms_at TEXT")
            .execute(pool)
            .await?;
    }

    if !has_terms_version {
        sqlx::query("ALTER TABLE users ADD COLUMN terms_version TEXT")
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Add MFA (TOTP) columns to users table for Two-Factor Authentication
async fn add_mfa_columns_to_users(pool: &SqlitePool) -> Result<()> {
    // Check if columns already exist (SQLite doesn't support IF NOT EXISTS for ALTER TABLE)
    let table_info: Vec<(i64, String, String, i64, Option<String>, i64)> = sqlx::query_as("PRAGMA table_info(users)")
        .fetch_all(pool)
        .await?;

    let has_totp_secret = table_info.iter().any(|(_, name, _, _, _, _)| name == "totp_secret");
    let has_totp_enabled = table_info.iter().any(|(_, name, _, _, _, _)| name == "totp_enabled");
    let has_totp_verified_at = table_info.iter().any(|(_, name, _, _, _, _)| name == "totp_verified_at");
    let has_recovery_codes = table_info.iter().any(|(_, name, _, _, _, _)| name == "recovery_codes");

    if !has_totp_secret {
        sqlx::query("ALTER TABLE users ADD COLUMN totp_secret TEXT")
            .execute(pool)
            .await?;
    }

    if !has_totp_enabled {
        sqlx::query("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await?;
    }

    if !has_totp_verified_at {
        sqlx::query("ALTER TABLE users ADD COLUMN totp_verified_at TEXT")
            .execute(pool)
            .await?;
    }

    if !has_recovery_codes {
        sqlx::query("ALTER TABLE users ADD COLUMN recovery_codes TEXT")
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Create password_history table for preventing password reuse (NIST 800-63B)
async fn create_password_history_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for efficient user lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id)")
        .execute(pool)
        .await?;

    // Create index for created_at to efficiently find oldest entries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_password_history_created_at ON password_history(user_id, created_at)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create vulnerability_tracking table for vulnerability management
async fn create_vulnerability_tracking_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vulnerability_tracking (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            host_ip TEXT NOT NULL,
            port INTEGER,
            vulnerability_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            assignee_id TEXT,
            notes TEXT,
            due_date TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            resolved_at TEXT,
            resolved_by TEXT,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE,
            FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vuln_tracking_scan_id ON vulnerability_tracking(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vuln_tracking_status ON vulnerability_tracking(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vuln_tracking_severity ON vulnerability_tracking(severity)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vuln_tracking_assignee ON vulnerability_tracking(assignee_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vuln_tracking_host_ip ON vulnerability_tracking(host_ip)")
        .execute(pool)
        .await?;

    // Add remediation workflow columns for existing tables (if they don't exist)
    add_remediation_workflow_columns(pool).await?;

    Ok(())
}

/// Add remediation workflow columns to vulnerability_tracking table
async fn add_remediation_workflow_columns(pool: &SqlitePool) -> Result<()> {
    // Check if columns already exist (SQLite doesn't support IF NOT EXISTS for ALTER TABLE)
    let table_info: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(vulnerability_tracking)")
        .fetch_all(pool)
        .await?;

    let has_priority = table_info.iter().any(|(_, name, _, _, _, _)| name == "priority");
    let has_remediation_steps = table_info.iter().any(|(_, name, _, _, _, _)| name == "remediation_steps");
    let has_estimated_effort = table_info.iter().any(|(_, name, _, _, _, _)| name == "estimated_effort");
    let has_actual_effort = table_info.iter().any(|(_, name, _, _, _, _)| name == "actual_effort");
    let has_verification_scan_id = table_info.iter().any(|(_, name, _, _, _, _)| name == "verification_scan_id");
    let has_verified_at = table_info.iter().any(|(_, name, _, _, _, _)| name == "verified_at");
    let has_verified_by = table_info.iter().any(|(_, name, _, _, _, _)| name == "verified_by");

    if !has_priority {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN priority TEXT DEFAULT 'medium'")
            .execute(pool)
            .await?;
    }

    if !has_remediation_steps {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN remediation_steps TEXT")
            .execute(pool)
            .await?;
    }

    if !has_estimated_effort {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN estimated_effort INTEGER")
            .execute(pool)
            .await?;
    }

    if !has_actual_effort {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN actual_effort INTEGER")
            .execute(pool)
            .await?;
    }

    if !has_verification_scan_id {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN verification_scan_id TEXT")
            .execute(pool)
            .await?;
    }

    if !has_verified_at {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN verified_at TEXT")
            .execute(pool)
            .await?;
    }

    if !has_verified_by {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN verified_by TEXT")
            .execute(pool)
            .await?;
    }

    // Retest workflow columns
    let has_retest_requested_at = table_info.iter().any(|(_, name, _, _, _, _)| name == "retest_requested_at");
    let has_retest_completed_at = table_info.iter().any(|(_, name, _, _, _, _)| name == "retest_completed_at");
    let has_retest_result = table_info.iter().any(|(_, name, _, _, _, _)| name == "retest_result");
    let has_retest_scan_id = table_info.iter().any(|(_, name, _, _, _, _)| name == "retest_scan_id");
    let has_retest_requested_by = table_info.iter().any(|(_, name, _, _, _, _)| name == "retest_requested_by");

    if !has_retest_requested_at {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN retest_requested_at TEXT")
            .execute(pool)
            .await?;
    }

    if !has_retest_completed_at {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN retest_completed_at TEXT")
            .execute(pool)
            .await?;
    }

    if !has_retest_result {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN retest_result TEXT")
            .execute(pool)
            .await?;
    }

    if !has_retest_scan_id {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN retest_scan_id TEXT")
            .execute(pool)
            .await?;
    }

    if !has_retest_requested_by {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN retest_requested_by TEXT")
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Create vulnerability_comments table for vulnerability discussion
async fn create_vulnerability_comments_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vulnerability_comments (
            id TEXT PRIMARY KEY,
            vulnerability_tracking_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (vulnerability_tracking_id) REFERENCES vulnerability_tracking(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for efficient comment retrieval
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vuln_comments_vuln_id ON vulnerability_comments(vulnerability_tracking_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vuln_comments_user_id ON vulnerability_comments(user_id)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create remediation_timeline table for tracking vulnerability remediation history
async fn create_remediation_timeline_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS remediation_timeline (
            id TEXT PRIMARY KEY,
            vulnerability_tracking_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            comment TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (vulnerability_tracking_id) REFERENCES vulnerability_tracking(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient timeline retrieval
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_remediation_timeline_vuln_id ON remediation_timeline(vulnerability_tracking_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_remediation_timeline_created_at ON remediation_timeline(created_at)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create api_keys table for user-managed API keys
async fn create_api_keys_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL UNIQUE,
            prefix TEXT NOT NULL,
            permissions TEXT,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            expires_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create assets table for persistent asset inventory
async fn create_assets_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            hostname TEXT,
            mac_address TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            scan_count INTEGER NOT NULL DEFAULT 1,
            os_family TEXT,
            os_version TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            tags TEXT NOT NULL DEFAULT '[]',
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, ip_address)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assets_user_id ON assets(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assets_ip_address ON assets(ip_address)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create asset_ports table for tracking ports on assets
async fn create_asset_ports_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asset_ports (
            id TEXT PRIMARY KEY,
            asset_id TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            service_name TEXT,
            service_version TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            current_state TEXT NOT NULL,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
            UNIQUE(asset_id, port, protocol)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_ports_asset_id ON asset_ports(asset_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_ports_port ON asset_ports(port)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_ports_state ON asset_ports(current_state)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create asset_history table for tracking changes over time
async fn create_asset_history_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asset_history (
            id TEXT PRIMARY KEY,
            asset_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            changes TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_history_asset_id ON asset_history(asset_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_history_scan_id ON asset_history(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_history_recorded_at ON asset_history(recorded_at)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create jira_settings table for JIRA integration configuration
async fn create_jira_settings_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS jira_settings (
            user_id TEXT PRIMARY KEY,
            jira_url TEXT NOT NULL,
            username TEXT NOT NULL,
            api_token TEXT NOT NULL,
            project_key TEXT NOT NULL,
            issue_type TEXT NOT NULL,
            default_assignee TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Add jira_ticket_id column to vulnerability_tracking table
async fn add_jira_ticket_id_to_vulnerability_tracking(pool: &SqlitePool) -> Result<()> {
    // Check if column already exists (SQLite doesn't support IF NOT EXISTS for ALTER TABLE)
    let table_info: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(vulnerability_tracking)")
        .fetch_all(pool)
        .await?;

    let has_jira_ticket_id = table_info.iter().any(|(_, name, _, _, _, _)| name == "jira_ticket_id");
    let has_jira_ticket_key = table_info.iter().any(|(_, name, _, _, _, _)| name == "jira_ticket_key");

    if !has_jira_ticket_id {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN jira_ticket_id TEXT")
            .execute(pool)
            .await?;
    }

    if !has_jira_ticket_key {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN jira_ticket_key TEXT")
            .execute(pool)
            .await?;
    }

    // Create index for JIRA ticket lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vuln_tracking_jira_ticket ON vulnerability_tracking(jira_ticket_id)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create siem_settings table for SIEM integration configuration
async fn create_siem_settings_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS siem_settings (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            siem_type TEXT NOT NULL,
            endpoint_url TEXT NOT NULL,
            api_key TEXT,
            protocol TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            export_on_scan_complete INTEGER NOT NULL DEFAULT 0,
            export_on_critical_vuln INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for efficient user lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_settings_user_id ON siem_settings(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_settings_enabled ON siem_settings(enabled)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create dns_recon_results table for DNS reconnaissance results
async fn create_dns_recon_results_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dns_recon_results (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_dns_recon_user_id ON dns_recon_results(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_dns_recon_domain ON dns_recon_results(domain)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_dns_recon_created_at ON dns_recon_results(created_at)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create user_dashboard_config table for storing dashboard widget configurations
async fn create_user_dashboard_config_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_dashboard_config (
            user_id TEXT PRIMARY KEY,
            widgets TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Add webhook columns to notification_settings table for Slack and Teams integration
async fn add_notification_webhook_columns(pool: &SqlitePool) -> Result<()> {
    // Check if columns already exist (SQLite doesn't support IF NOT EXISTS for ALTER TABLE)
    let table_info: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(notification_settings)")
        .fetch_all(pool)
        .await?;

    let has_slack_webhook_url = table_info.iter().any(|(_, name, _, _, _, _)| name == "slack_webhook_url");
    let has_teams_webhook_url = table_info.iter().any(|(_, name, _, _, _, _)| name == "teams_webhook_url");

    if !has_slack_webhook_url {
        sqlx::query("ALTER TABLE notification_settings ADD COLUMN slack_webhook_url TEXT")
            .execute(pool)
            .await?;
    }

    if !has_teams_webhook_url {
        sqlx::query("ALTER TABLE notification_settings ADD COLUMN teams_webhook_url TEXT")
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Create compliance_rubrics table for manual assessment templates
async fn create_compliance_rubrics_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS compliance_rubrics (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            criteria TEXT NOT NULL,
            rating_scale TEXT NOT NULL,
            evidence_requirements TEXT NOT NULL,
            guidance TEXT,
            weight REAL NOT NULL DEFAULT 1.0,
            is_template INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_compliance_rubrics_user_id ON compliance_rubrics(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_compliance_rubrics_framework_id ON compliance_rubrics(framework_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_compliance_rubrics_control_id ON compliance_rubrics(control_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_compliance_rubrics_is_template ON compliance_rubrics(is_template)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create manual_assessments table for user-submitted compliance assessments
async fn create_manual_assessments_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS manual_assessments (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            rubric_id TEXT NOT NULL,
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            scan_id TEXT,
            rating TEXT NOT NULL,
            score REAL,
            findings TEXT,
            recommendations TEXT,
            compensating_controls TEXT,
            status TEXT NOT NULL DEFAULT 'draft',
            assessed_by TEXT NOT NULL,
            assessed_at TEXT NOT NULL,
            reviewed_by TEXT,
            reviewed_at TEXT,
            approved_by TEXT,
            approved_at TEXT,
            valid_until TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (rubric_id) REFERENCES compliance_rubrics(id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE SET NULL,
            FOREIGN KEY (assessed_by) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_manual_assessments_user_id ON manual_assessments(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_manual_assessments_rubric_id ON manual_assessments(rubric_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_manual_assessments_framework_id ON manual_assessments(framework_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_manual_assessments_control_id ON manual_assessments(control_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_manual_assessments_scan_id ON manual_assessments(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_manual_assessments_status ON manual_assessments(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_manual_assessments_assessed_by ON manual_assessments(assessed_by)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_manual_assessments_valid_until ON manual_assessments(valid_until)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create assessment_evidence table for file attachments and evidence links
async fn create_assessment_evidence_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS assessment_evidence (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            file_path TEXT,
            file_name TEXT,
            file_size INTEGER,
            file_mime_type TEXT,
            url TEXT,
            screenshot_path TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (assessment_id) REFERENCES manual_assessments(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assessment_evidence_assessment_id ON assessment_evidence(assessment_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assessment_evidence_user_id ON assessment_evidence(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assessment_evidence_type ON assessment_evidence(evidence_type)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create assessment_history table for audit trail of assessment changes
async fn create_assessment_history_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS assessment_history (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            field_name TEXT,
            old_value TEXT,
            new_value TEXT,
            comment TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (assessment_id) REFERENCES manual_assessments(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assessment_history_assessment_id ON assessment_history(assessment_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assessment_history_user_id ON assessment_history(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assessment_history_action ON assessment_history(action)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assessment_history_created_at ON assessment_history(created_at)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create assessment_campaigns table for grouping assessments together
async fn create_assessment_campaigns_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS assessment_campaigns (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            framework_id TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            target_completion_date TEXT,
            scope TEXT,
            objectives TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assessment_campaigns_user_id ON assessment_campaigns(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assessment_campaigns_framework_id ON assessment_campaigns(framework_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assessment_campaigns_status ON assessment_campaigns(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_assessment_campaigns_start_date ON assessment_campaigns(start_date)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create campaign_assessments junction table to link campaigns to assessments
async fn create_campaign_assessments_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS campaign_assessments (
            campaign_id TEXT NOT NULL,
            assessment_id TEXT NOT NULL,
            added_at TEXT NOT NULL,
            added_by TEXT NOT NULL,
            PRIMARY KEY (campaign_id, assessment_id),
            FOREIGN KEY (campaign_id) REFERENCES assessment_campaigns(id) ON DELETE CASCADE,
            FOREIGN KEY (assessment_id) REFERENCES manual_assessments(id) ON DELETE CASCADE,
            FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_campaign_assessments_campaign_id ON campaign_assessments(campaign_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_campaign_assessments_assessment_id ON campaign_assessments(assessment_id)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create vpn_configs table for storing VPN configuration files
async fn create_vpn_configs_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vpn_configs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            vpn_type TEXT NOT NULL,
            config_file_path TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            encrypted_credentials TEXT,
            requires_credentials INTEGER NOT NULL DEFAULT 0,
            is_default INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_used_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, name)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vpn_configs_user_id ON vpn_configs(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vpn_configs_vpn_type ON vpn_configs(vpn_type)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vpn_configs_is_default ON vpn_configs(is_default)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create vpn_connections table for tracking active and historical VPN connections
async fn create_vpn_connections_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vpn_connections (
            id TEXT PRIMARY KEY,
            vpn_config_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            connection_mode TEXT NOT NULL,
            scan_id TEXT,
            status TEXT NOT NULL,
            process_id INTEGER,
            interface_name TEXT,
            assigned_ip TEXT,
            connected_at TEXT,
            disconnected_at TEXT,
            error_message TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (vpn_config_id) REFERENCES vpn_configs(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vpn_connections_user_id ON vpn_connections(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vpn_connections_status ON vpn_connections(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vpn_connections_scan_id ON vpn_connections(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vpn_connections_vpn_config_id ON vpn_connections(vpn_config_id)")
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// CRM Tables
// ============================================================================

/// Create customers table for CRM
async fn create_customers_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS customers (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            industry TEXT,
            company_size TEXT,
            website TEXT,
            address TEXT,
            notes TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_customers_user_id ON customers(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_customers_status ON customers(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_customers_name ON customers(name)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create contacts table for customer contacts
async fn create_contacts_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS contacts (
            id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            title TEXT,
            is_primary INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_contacts_customer_id ON contacts(customer_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(email)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_contacts_is_primary ON contacts(is_primary)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create engagements table for project/engagement tracking
async fn create_engagements_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS engagements (
            id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL,
            name TEXT NOT NULL,
            engagement_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'planning',
            scope TEXT,
            start_date TEXT,
            end_date TEXT,
            budget REAL,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_engagements_customer_id ON engagements(customer_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_engagements_status ON engagements(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_engagements_engagement_type ON engagements(engagement_type)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_engagements_start_date ON engagements(start_date)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create engagement_milestones table for tracking project milestones
async fn create_engagement_milestones_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS engagement_milestones (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            due_date TEXT,
            completed_at TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_milestones_engagement_id ON engagement_milestones(engagement_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_milestones_status ON engagement_milestones(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_milestones_due_date ON engagement_milestones(due_date)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create contracts table for contract management
async fn create_contracts_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS contracts (
            id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL,
            engagement_id TEXT,
            contract_type TEXT NOT NULL,
            name TEXT NOT NULL,
            value REAL,
            start_date TEXT,
            end_date TEXT,
            status TEXT NOT NULL DEFAULT 'draft',
            file_path TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
            FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_contracts_customer_id ON contracts(customer_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_contracts_engagement_id ON contracts(engagement_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_contracts_status ON contracts(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_contracts_contract_type ON contracts(contract_type)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create sla_definitions table for SLA templates and customer SLAs
async fn create_sla_definitions_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sla_definitions (
            id TEXT PRIMARY KEY,
            customer_id TEXT,
            name TEXT NOT NULL,
            description TEXT,
            response_time_critical INTEGER,
            response_time_high INTEGER,
            response_time_medium INTEGER,
            response_time_low INTEGER,
            resolution_time_critical INTEGER,
            resolution_time_high INTEGER,
            resolution_time_medium INTEGER,
            resolution_time_low INTEGER,
            is_template INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sla_definitions_customer_id ON sla_definitions(customer_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sla_definitions_is_template ON sla_definitions(is_template)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create time_entries table for time tracking
async fn create_time_entries_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS time_entries (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            description TEXT NOT NULL,
            hours REAL NOT NULL,
            billable INTEGER NOT NULL DEFAULT 1,
            date TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_time_entries_engagement_id ON time_entries(engagement_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_time_entries_user_id ON time_entries(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_time_entries_date ON time_entries(date)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_time_entries_billable ON time_entries(billable)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create communications table for logging customer communications
async fn create_communications_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS communications (
            id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL,
            engagement_id TEXT,
            contact_id TEXT,
            user_id TEXT NOT NULL,
            comm_type TEXT NOT NULL,
            subject TEXT,
            content TEXT,
            comm_date TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
            FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE SET NULL,
            FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE SET NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_communications_customer_id ON communications(customer_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_communications_engagement_id ON communications(engagement_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_communications_user_id ON communications(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_communications_comm_date ON communications(comm_date)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_communications_comm_type ON communications(comm_type)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create portal_users table for customer portal authentication
async fn create_portal_users_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS portal_users (
            id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL,
            contact_id TEXT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            last_login TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
            FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_portal_users_customer_id ON portal_users(customer_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_portal_users_email ON portal_users(email)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_portal_users_is_active ON portal_users(is_active)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Add CRM columns to existing tables (scan_results, reports, vulnerability_tracking)
async fn add_crm_columns_to_existing_tables(pool: &SqlitePool) -> Result<()> {
    // Add customer_id and engagement_id to scan_results
    let scan_results_info: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(scan_results)")
        .fetch_all(pool)
        .await?;

    let has_customer_id = scan_results_info.iter().any(|(_, name, _, _, _, _)| name == "customer_id");
    let has_engagement_id = scan_results_info.iter().any(|(_, name, _, _, _, _)| name == "engagement_id");

    if !has_customer_id {
        sqlx::query("ALTER TABLE scan_results ADD COLUMN customer_id TEXT REFERENCES customers(id)")
            .execute(pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_results_customer_id ON scan_results(customer_id)")
            .execute(pool)
            .await?;
    }

    if !has_engagement_id {
        sqlx::query("ALTER TABLE scan_results ADD COLUMN engagement_id TEXT REFERENCES engagements(id)")
            .execute(pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_results_engagement_id ON scan_results(engagement_id)")
            .execute(pool)
            .await?;
    }

    // Add engagement_id to reports
    let reports_info: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(reports)")
        .fetch_all(pool)
        .await?;

    let reports_has_engagement_id = reports_info.iter().any(|(_, name, _, _, _, _)| name == "engagement_id");

    if !reports_has_engagement_id {
        sqlx::query("ALTER TABLE reports ADD COLUMN engagement_id TEXT REFERENCES engagements(id)")
            .execute(pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_reports_engagement_id ON reports(engagement_id)")
            .execute(pool)
            .await?;
    }

    // Add customer_id to vulnerability_tracking
    let vuln_info: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(vulnerability_tracking)")
        .fetch_all(pool)
        .await?;

    let vuln_has_customer_id = vuln_info.iter().any(|(_, name, _, _, _, _)| name == "customer_id");

    if !vuln_has_customer_id {
        sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN customer_id TEXT REFERENCES customers(id)")
            .execute(pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_vuln_tracking_customer_id ON vulnerability_tracking(customer_id)")
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Create portal_password_reset_tokens table for password reset functionality
async fn create_portal_password_reset_tokens_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS portal_password_reset_tokens (
            id TEXT PRIMARY KEY,
            portal_user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (portal_user_id) REFERENCES portal_users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_reset_tokens_portal_user_id ON portal_password_reset_tokens(portal_user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_reset_tokens_token_hash ON portal_password_reset_tokens(token_hash)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_reset_tokens_expires_at ON portal_password_reset_tokens(expires_at)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Create finding_templates table for pre-written vulnerability descriptions
async fn create_finding_templates_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS finding_templates (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            impact TEXT,
            remediation TEXT,
            "references" TEXT,
            cwe_ids TEXT,
            cvss_vector TEXT,
            cvss_score REAL,
            tags TEXT,
            is_system INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_finding_templates_category ON finding_templates(category)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_finding_templates_severity ON finding_templates(severity)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_finding_templates_user_id ON finding_templates(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_finding_templates_is_system ON finding_templates(is_system)")
        .execute(pool)
        .await?;

    // Full-text search on title and description
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_finding_templates_title ON finding_templates(title)")
        .execute(pool)
        .await?;

    // Seed default system templates
    seed_finding_templates(pool).await?;

    Ok(())
}

/// Seed default finding templates
async fn seed_finding_templates(pool: &SqlitePool) -> Result<()> {
    // Check if system templates already exist
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM finding_templates WHERE is_system = 1")
        .fetch_one(pool)
        .await?;

    if count.0 > 0 {
        return Ok(()); // Templates already seeded
    }

    let now = chrono::Utc::now().to_rfc3339();
    let templates = vec![
        // Web Application Vulnerabilities
        (
            "SQL Injection",
            "web",
            "critical",
            "SQL Injection vulnerability allows attackers to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve, including data belonging to other users, or any other data that the application itself is able to access. In many cases, an attacker can modify or delete this data.",
            "Complete compromise of the database, unauthorized access to sensitive data, data manipulation or destruction, potential for lateral movement to other systems.",
            "Use parameterized queries (prepared statements) with bound, typed parameters. Implement input validation using allowlists. Apply the principle of least privilege to database accounts. Consider using stored procedures.",
            "[\"https://owasp.org/www-community/attacks/SQL_Injection\", \"https://cwe.mitre.org/data/definitions/89.html\"]",
            "[89]",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            9.8,
            "[\"owasp-top10\", \"injection\", \"database\"]",
        ),
        (
            "Cross-Site Scripting (XSS) - Reflected",
            "web",
            "high",
            "Reflected Cross-Site Scripting (XSS) occurs when an application includes unvalidated and unescaped user input as part of HTML output. A successful attack can allow the attacker to execute arbitrary JavaScript in the victim's browser, potentially leading to session hijacking, defacement, or redirecting the user to malicious sites.",
            "Session hijacking, credential theft, phishing attacks, malware distribution, website defacement.",
            "Encode output data appropriately for the context (HTML, JavaScript, URL, CSS). Implement Content Security Policy (CSP). Use HttpOnly and Secure flags on session cookies. Validate and sanitize all user input.",
            "[\"https://owasp.org/www-community/attacks/xss/\", \"https://cwe.mitre.org/data/definitions/79.html\"]",
            "[79]",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            6.1,
            "[\"owasp-top10\", \"xss\", \"client-side\"]",
        ),
        (
            "Cross-Site Scripting (XSS) - Stored",
            "web",
            "high",
            "Stored Cross-Site Scripting (XSS) occurs when user-supplied data is permanently stored on the target server (e.g., in a database, message forum, visitor log, comment field, etc.) and then displayed to users without proper sanitization. This is more dangerous than reflected XSS as it does not require tricking users into clicking a malicious link.",
            "Persistent attacks affecting all users who view the compromised content, session hijacking at scale, credential theft, worm propagation.",
            "Encode output data appropriately for the context. Implement Content Security Policy (CSP). Sanitize HTML input using a well-tested library. Use HttpOnly and Secure flags on session cookies.",
            "[\"https://owasp.org/www-community/attacks/xss/\", \"https://cwe.mitre.org/data/definitions/79.html\"]",
            "[79]",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
            5.4,
            "[\"owasp-top10\", \"xss\", \"stored\"]",
        ),
        (
            "Insecure Direct Object Reference (IDOR)",
            "web",
            "high",
            "Insecure Direct Object References (IDOR) occur when an application exposes a reference to an internal implementation object, such as a file, directory, database record, or key, as a URL or form parameter. Attackers can manipulate these references to access unauthorized data.",
            "Unauthorized access to other users' data, horizontal privilege escalation, data leakage, privacy violations.",
            "Implement proper access control checks for all object references. Use indirect references (e.g., mapping tables) instead of direct references. Validate user authorization for each data access request. Log and monitor access attempts.",
            "[\"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References\", \"https://cwe.mitre.org/data/definitions/639.html\"]",
            "[639]",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            6.5,
            "[\"owasp-top10\", \"broken-access-control\", \"authorization\"]",
        ),
        (
            "Server-Side Request Forgery (SSRF)",
            "web",
            "high",
            "Server-Side Request Forgery (SSRF) allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing. In typical SSRF examples, the attacker might cause the server to make a connection back to itself, or to other web-based services within the organization's infrastructure, or to external third-party systems.",
            "Access to internal services, cloud metadata exposure, port scanning of internal networks, data exfiltration, potential for remote code execution in some cases.",
            "Validate and sanitize all user-supplied input URLs. Use allowlists for permitted domains and protocols. Disable unnecessary URL schemas (file://, dict://, etc.). Implement network segmentation. Block requests to internal/private IP ranges.",
            "[\"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery\", \"https://cwe.mitre.org/data/definitions/918.html\"]",
            "[918]",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            8.6,
            "[\"owasp-top10\", \"ssrf\", \"server-side\"]",
        ),
        // Network Vulnerabilities
        (
            "Missing SSL/TLS Certificate Validation",
            "network",
            "high",
            "The application does not properly validate SSL/TLS certificates, making it vulnerable to man-in-the-middle attacks. An attacker positioned between the client and server can intercept, read, and modify all traffic.",
            "Complete compromise of encrypted communications, credential theft, session hijacking, data manipulation.",
            "Implement proper certificate validation including chain of trust verification, hostname verification, and certificate expiration checks. Use certificate pinning for high-security applications. Keep TLS libraries updated.",
            "[\"https://cwe.mitre.org/data/definitions/295.html\", \"https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication\"]",
            "[295]",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            7.4,
            "[\"tls\", \"ssl\", \"encryption\", \"mitm\"]",
        ),
        (
            "Weak SSL/TLS Configuration",
            "network",
            "medium",
            "The server's SSL/TLS configuration supports weak cipher suites or protocols that are known to be vulnerable. This includes support for SSLv2, SSLv3, TLS 1.0, TLS 1.1, or cipher suites using DES, RC4, or export-grade encryption.",
            "Potential for traffic decryption through protocol downgrade attacks (POODLE, BEAST, etc.), increased risk of successful cryptographic attacks.",
            "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Enable only TLS 1.2 and TLS 1.3. Configure strong cipher suites (AES-GCM, ChaCha20-Poly1305). Enable Perfect Forward Secrecy (ECDHE key exchange). Use tools like Mozilla SSL Configuration Generator.",
            "[\"https://wiki.mozilla.org/Security/Server_Side_TLS\", \"https://cwe.mitre.org/data/definitions/326.html\"]",
            "[326, 327]",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            5.9,
            "[\"tls\", \"ssl\", \"configuration\", \"cryptography\"]",
        ),
        (
            "Open SSH with Password Authentication",
            "network",
            "medium",
            "The SSH service is configured to allow password authentication, which is susceptible to brute-force attacks. Combined with weak passwords or exposed credentials, this can lead to unauthorized system access.",
            "Unauthorized system access, lateral movement within the network, data exfiltration, system compromise.",
            "Disable password authentication in SSH configuration. Use key-based authentication only. Implement fail2ban or similar tools to prevent brute-force attacks. Use strong, unique keys for each user. Consider using SSH certificates for large deployments.",
            "[\"https://www.ssh.com/academy/ssh/key\", \"https://cwe.mitre.org/data/definitions/521.html\"]",
            "[521, 307]",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            5.3,
            "[\"ssh\", \"authentication\", \"brute-force\"]",
        ),
        // Infrastructure Vulnerabilities
        (
            "Outdated Software with Known Vulnerabilities",
            "infrastructure",
            "high",
            "The system is running software versions with publicly known vulnerabilities. Exploit code or detailed attack information may be publicly available, significantly lowering the barrier for attackers.",
            "Varies based on specific vulnerabilities. May include remote code execution, privilege escalation, denial of service, or data disclosure.",
            "Update affected software to the latest patched version. If updates are not immediately possible, implement compensating controls such as web application firewalls, network segmentation, or disabling vulnerable features. Establish a regular patch management program.",
            "[\"https://nvd.nist.gov/\", \"https://cwe.mitre.org/data/definitions/1104.html\"]",
            "[1104]",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            9.8,
            "[\"patching\", \"cve\", \"outdated\"]",
        ),
        (
            "Default Credentials in Use",
            "infrastructure",
            "critical",
            "The system or application is using default credentials that are publicly known or easily guessable. Many devices and applications ship with default usernames and passwords that are documented in manuals or available online.",
            "Complete system compromise, unauthorized access to sensitive data, ability to modify system configuration, potential for lateral movement.",
            "Change all default credentials immediately upon deployment. Implement a policy requiring strong, unique passwords. Use a password manager for credential storage. Implement multi-factor authentication where possible. Regularly audit for default credentials.",
            "[\"https://cwe.mitre.org/data/definitions/1392.html\", \"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials\"]",
            "[1392, 798]",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            9.8,
            "[\"credentials\", \"default\", \"authentication\"]",
        ),
        // Cloud Vulnerabilities
        (
            "Publicly Accessible S3 Bucket",
            "cloud",
            "high",
            "An Amazon S3 bucket is configured to allow public access, potentially exposing sensitive data to unauthorized users. This misconfiguration can lead to data breaches and compliance violations.",
            "Data exposure, regulatory compliance violations (GDPR, HIPAA, PCI-DSS), reputational damage, potential for data modification or deletion if write access is enabled.",
            "Review and restrict S3 bucket policies and ACLs. Enable S3 Block Public Access at the account level. Use AWS IAM policies to control access. Enable bucket logging and monitoring. Consider using AWS Macie for sensitive data discovery.",
            "[\"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html\", \"https://cwe.mitre.org/data/definitions/732.html\"]",
            "[732]",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            7.5,
            "[\"aws\", \"s3\", \"cloud\", \"misconfiguration\"]",
        ),
        (
            "Overly Permissive IAM Policy",
            "cloud",
            "high",
            "An IAM policy grants excessive permissions, violating the principle of least privilege. This can allow users or services to perform actions beyond their required scope, increasing the blast radius of potential compromises.",
            "Privilege escalation, unauthorized access to resources, data exfiltration, resource manipulation, increased impact of credential compromise.",
            "Review and restrict IAM policies to minimum required permissions. Use AWS IAM Access Analyzer to identify overly permissive policies. Implement service control policies (SCPs) for guardrails. Use permission boundaries for delegated administration. Regular access reviews.",
            "[\"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html\", \"https://cwe.mitre.org/data/definitions/250.html\"]",
            "[250, 269]",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            8.1,
            "[\"aws\", \"iam\", \"cloud\", \"permissions\"]",
        ),
        // API Vulnerabilities
        (
            "Broken Object Level Authorization (BOLA)",
            "api",
            "high",
            "The API does not properly validate that the requesting user is authorized to access the requested object. By manipulating object identifiers in API requests, attackers can access data belonging to other users.",
            "Unauthorized access to other users' data, privacy violations, horizontal privilege escalation, potential for mass data harvesting.",
            "Implement authorization checks for every object access request. Do not rely on client-supplied object IDs alone. Use random, unpredictable object identifiers (UUIDs). Log and monitor access patterns for anomalies.",
            "[\"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/\", \"https://cwe.mitre.org/data/definitions/639.html\"]",
            "[639]",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            6.5,
            "[\"api\", \"authorization\", \"owasp-api-top10\"]",
        ),
        (
            "Missing Rate Limiting",
            "api",
            "medium",
            "The API does not implement rate limiting, allowing unlimited requests from a single source. This makes the API vulnerable to denial of service attacks, brute-force attacks, and resource exhaustion.",
            "Denial of service, brute-force attacks on authentication, resource exhaustion, increased infrastructure costs, degraded service for legitimate users.",
            "Implement rate limiting based on user identity, API key, or IP address. Use sliding window or token bucket algorithms. Return appropriate HTTP 429 responses with Retry-After headers. Consider different rate limits for authenticated vs. unauthenticated requests.",
            "[\"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/\", \"https://cwe.mitre.org/data/definitions/770.html\"]",
            "[770]",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            5.3,
            "[\"api\", \"dos\", \"rate-limiting\"]",
        ),
    ];

    let template_count = templates.len();
    for (title, category, severity, description, impact, remediation, references, cwe_ids, cvss_vector, cvss_score, tags) in templates {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO finding_templates (id, category, title, severity, description, impact, remediation, "references", cwe_ids, cvss_vector, cvss_score, tags, is_system, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1, ?13, ?13)
            "#,
        )
        .bind(&id)
        .bind(category)
        .bind(title)
        .bind(severity)
        .bind(description)
        .bind(impact)
        .bind(remediation)
        .bind(references)
        .bind(cwe_ids)
        .bind(cvss_vector)
        .bind(cvss_score)
        .bind(tags)
        .bind(&now)
        .execute(pool)
        .await?;
    }

    log::info!("Seeded {} default finding templates", template_count);
    Ok(())
}

// ============================================================================
// Tier 1 Feature Migrations
// ============================================================================

/// Create attack path analysis tables
async fn create_attack_paths_tables(pool: &SqlitePool) -> Result<()> {
    // Attack paths table - stores complete attack chains
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS attack_paths (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            name TEXT,
            risk_level TEXT NOT NULL,           -- critical/high/medium/low
            probability REAL,                   -- likelihood of exploitation
            total_cvss REAL,                    -- cumulative CVSS score
            path_length INTEGER,                -- number of nodes in path
            description TEXT,
            mitigation_steps TEXT,              -- JSON array of remediation steps
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for attack_paths
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_attack_paths_scan_id ON attack_paths(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_attack_paths_user_id ON attack_paths(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_attack_paths_risk_level ON attack_paths(risk_level)")
        .execute(pool)
        .await?;

    // Attack nodes table - hosts/services in the path
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS attack_nodes (
            id TEXT PRIMARY KEY,
            path_id TEXT NOT NULL,
            host_ip TEXT,
            port INTEGER,
            service TEXT,
            vulnerability_ids TEXT,             -- JSON array of vulnerability IDs
            node_type TEXT NOT NULL,            -- entry/pivot/target
            position_x REAL,                    -- for visualization
            position_y REAL,
            metadata TEXT,                      -- JSON object for additional data
            FOREIGN KEY (path_id) REFERENCES attack_paths(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_attack_nodes_path_id ON attack_nodes(path_id)")
        .execute(pool)
        .await?;

    // Attack edges table - connections between nodes
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS attack_edges (
            id TEXT PRIMARY KEY,
            path_id TEXT NOT NULL,
            source_node_id TEXT NOT NULL,
            target_node_id TEXT NOT NULL,
            attack_technique TEXT,              -- e.g., MITRE ATT&CK technique
            technique_id TEXT,                  -- e.g., T1021
            likelihood REAL,                    -- probability of successful exploitation
            impact REAL,                        -- impact if exploited (0-10)
            description TEXT,
            FOREIGN KEY (path_id) REFERENCES attack_paths(id) ON DELETE CASCADE,
            FOREIGN KEY (source_node_id) REFERENCES attack_nodes(id) ON DELETE CASCADE,
            FOREIGN KEY (target_node_id) REFERENCES attack_nodes(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_attack_edges_path_id ON attack_edges(path_id)")
        .execute(pool)
        .await?;

    log::info!("Created attack path analysis tables");
    Ok(())
}

/// Create cloud infrastructure scanning tables
async fn create_cloud_scan_tables(pool: &SqlitePool) -> Result<()> {
    // Cloud scans table - main scan record
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cloud_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            provider TEXT NOT NULL,             -- aws/azure/gcp
            regions TEXT,                       -- JSON array of regions
            scan_types TEXT,                    -- JSON array: iam/storage/compute/network
            status TEXT NOT NULL,               -- pending/running/completed/failed
            credentials_id TEXT,                -- reference to stored credentials
            findings_count INTEGER DEFAULT 0,
            resources_count INTEGER DEFAULT 0,
            error_message TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            customer_id TEXT,                   -- CRM customer reference
            engagement_id TEXT,                 -- CRM engagement reference
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cloud_scans_user_id ON cloud_scans(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cloud_scans_provider ON cloud_scans(provider)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cloud_scans_status ON cloud_scans(status)")
        .execute(pool)
        .await?;

    // Cloud resources table - discovered cloud resources
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cloud_resources (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            resource_type TEXT NOT NULL,        -- ec2/s3/rds/lambda/iam_user/etc
            resource_id TEXT NOT NULL,          -- provider's resource ID
            region TEXT,
            name TEXT,
            arn TEXT,                           -- AWS ARN or equivalent
            tags TEXT,                          -- JSON object of tags
            metadata TEXT,                      -- JSON object of provider-specific data
            state TEXT,                         -- running/stopped/available/etc
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES cloud_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cloud_resources_scan_id ON cloud_resources(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cloud_resources_type ON cloud_resources(resource_type)")
        .execute(pool)
        .await?;

    // Cloud findings table - security findings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cloud_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            resource_id TEXT,
            finding_type TEXT NOT NULL,         -- misconfiguration/vulnerability/exposure
            severity TEXT NOT NULL,             -- critical/high/medium/low/info
            title TEXT NOT NULL,
            description TEXT,
            remediation TEXT,
            compliance_mappings TEXT,           -- JSON: CIS, SOC2, PCI-DSS, etc.
            affected_resource_arn TEXT,
            evidence TEXT,                      -- JSON object of finding evidence
            status TEXT DEFAULT 'open',         -- open/resolved/false_positive
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES cloud_scans(id) ON DELETE CASCADE,
            FOREIGN KEY (resource_id) REFERENCES cloud_resources(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cloud_findings_scan_id ON cloud_findings(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cloud_findings_severity ON cloud_findings(severity)")
        .execute(pool)
        .await?;

    // Cloud credentials table - encrypted credential storage
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cloud_credentials (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            provider TEXT NOT NULL,             -- aws/azure/gcp
            credential_type TEXT NOT NULL,      -- access_key/role/service_account
            encrypted_credentials TEXT NOT NULL, -- AES-256 encrypted JSON
            is_default INTEGER DEFAULT 0,
            last_used_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cloud_credentials_user_id ON cloud_credentials(user_id)")
        .execute(pool)
        .await?;

    log::info!("Created cloud infrastructure scanning tables");
    Ok(())
}

/// Create API security testing tables
async fn create_api_security_scan_tables(pool: &SqlitePool) -> Result<()> {
    // API scans table - main scan record
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS api_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            target_url TEXT NOT NULL,
            spec_type TEXT,                     -- openapi3/swagger2/postman/none
            spec_content TEXT,                  -- uploaded API specification
            auth_config TEXT,                   -- JSON: auth type, tokens, headers
            scan_options TEXT,                  -- JSON: which tests to run
            status TEXT NOT NULL,               -- pending/running/completed/failed
            endpoints_discovered INTEGER DEFAULT 0,
            endpoints_tested INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            error_message TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            customer_id TEXT,
            engagement_id TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_api_scans_user_id ON api_scans(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_api_scans_status ON api_scans(status)")
        .execute(pool)
        .await?;

    // API endpoints table - discovered endpoints
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS api_endpoints (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            path TEXT NOT NULL,
            method TEXT NOT NULL,               -- GET/POST/PUT/DELETE/PATCH
            operation_id TEXT,                  -- from OpenAPI spec
            summary TEXT,
            parameters TEXT,                    -- JSON array of parameters
            request_body_schema TEXT,           -- JSON schema
            response_schema TEXT,               -- JSON schema
            auth_required INTEGER DEFAULT 0,
            tested INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES api_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_api_endpoints_scan_id ON api_endpoints(scan_id)")
        .execute(pool)
        .await?;

    // API findings table - security findings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS api_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            endpoint_id TEXT,
            finding_type TEXT NOT NULL,         -- bola/bfla/injection/auth_bypass/rate_limit/etc
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            request TEXT,                       -- HTTP request that triggered finding
            response TEXT,                      -- HTTP response
            evidence TEXT,                      -- JSON object of evidence
            remediation TEXT,
            cwe_ids TEXT,                       -- JSON array of CWE IDs
            owasp_category TEXT,                -- OWASP API Top 10 category
            status TEXT DEFAULT 'open',
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES api_scans(id) ON DELETE CASCADE,
            FOREIGN KEY (endpoint_id) REFERENCES api_endpoints(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_api_findings_scan_id ON api_findings(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_api_findings_severity ON api_findings(severity)")
        .execute(pool)
        .await?;

    log::info!("Created API security testing tables");
    Ok(())
}

/// Create methodology checklists tables
async fn create_methodology_tables(pool: &SqlitePool) -> Result<()> {
    // Methodology templates table - built-in methodology frameworks
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS methodology_templates (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,                 -- PTES, OWASP WSTG, OSSTMM, etc.
            version TEXT,
            description TEXT,
            categories TEXT,                    -- JSON array of category names
            item_count INTEGER DEFAULT 0,
            is_system INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Methodology template items table - individual checklist items in a template
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS methodology_template_items (
            id TEXT PRIMARY KEY,
            template_id TEXT NOT NULL,
            category TEXT NOT NULL,
            item_id TEXT,                       -- e.g., WSTG-INFO-01
            title TEXT NOT NULL,
            description TEXT,
            guidance TEXT,                      -- how to test
            expected_evidence TEXT,             -- what evidence to collect
            tools TEXT,                         -- JSON array of recommended tools
            "references" TEXT,                    -- JSON array of reference URLs
            sort_order INTEGER DEFAULT 0,
            FOREIGN KEY (template_id) REFERENCES methodology_templates(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_methodology_items_template_id ON methodology_template_items(template_id)")
        .execute(pool)
        .await?;

    // Methodology checklists table - user's checklist instances
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS methodology_checklists (
            id TEXT PRIMARY KEY,
            template_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            scan_id TEXT,                       -- optional link to a scan
            engagement_id TEXT,                 -- optional link to CRM engagement
            name TEXT NOT NULL,
            description TEXT,
            progress_percent REAL DEFAULT 0.0,
            status TEXT DEFAULT 'in_progress',  -- in_progress/completed/archived
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (template_id) REFERENCES methodology_templates(id) ON DELETE RESTRICT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_methodology_checklists_user_id ON methodology_checklists(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_methodology_checklists_template_id ON methodology_checklists(template_id)")
        .execute(pool)
        .await?;

    // Checklist items table - user's progress on individual items
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS checklist_items (
            id TEXT PRIMARY KEY,
            checklist_id TEXT NOT NULL,
            template_item_id TEXT NOT NULL,
            status TEXT DEFAULT 'not_started',  -- not_started/in_progress/pass/fail/na
            notes TEXT,
            evidence TEXT,                      -- file paths or descriptions
            findings TEXT,                      -- JSON array of linked finding IDs
            tested_at TEXT,
            tester_id TEXT,
            FOREIGN KEY (checklist_id) REFERENCES methodology_checklists(id) ON DELETE CASCADE,
            FOREIGN KEY (template_item_id) REFERENCES methodology_template_items(id) ON DELETE RESTRICT
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_checklist_items_checklist_id ON checklist_items(checklist_id)")
        .execute(pool)
        .await?;

    // Seed default methodology templates
    seed_methodology_templates(pool).await?;

    log::info!("Created methodology checklists tables");
    Ok(())
}

/// Seed default methodology templates (PTES, OWASP WSTG)
async fn seed_methodology_templates(pool: &SqlitePool) -> Result<()> {
    // Check if already seeded
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM methodology_templates WHERE is_system = 1")
        .fetch_one(pool)
        .await?;

    if count.0 > 0 {
        log::info!("Methodology templates already seeded");
        return Ok(());
    }

    let now = chrono::Utc::now().to_rfc3339();

    // PTES (Penetration Testing Execution Standard)
    let ptes_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO methodology_templates (id, name, version, description, categories, item_count, is_system, created_at, updated_at)
        VALUES (?1, 'PTES', '1.0', 'Penetration Testing Execution Standard - A standard for conducting penetration tests',
                '["Pre-engagement Interactions", "Intelligence Gathering", "Threat Modeling", "Vulnerability Analysis", "Exploitation", "Post Exploitation", "Reporting"]',
                35, 1, ?2, ?2)
        "#,
    )
    .bind(&ptes_id)
    .bind(&now)
    .execute(pool)
    .await?;

    // Add PTES items (abbreviated set)
    let ptes_items = [
        ("Pre-engagement Interactions", "PTES-PE-01", "Scope Definition", "Define the scope of the engagement including IP ranges, domains, and testing boundaries."),
        ("Pre-engagement Interactions", "PTES-PE-02", "Rules of Engagement", "Establish clear rules of engagement including testing windows, escalation procedures, and emergency contacts."),
        ("Pre-engagement Interactions", "PTES-PE-03", "Authorization Documentation", "Obtain and verify proper authorization documentation before beginning testing."),
        ("Intelligence Gathering", "PTES-IG-01", "Passive Reconnaissance", "Gather information using passive techniques (OSINT, DNS, WHOIS, etc.) without directly interacting with target systems."),
        ("Intelligence Gathering", "PTES-IG-02", "Active Reconnaissance", "Perform active information gathering including port scanning, service enumeration, and network mapping."),
        ("Intelligence Gathering", "PTES-IG-03", "Target Identification", "Identify and document all in-scope targets, services, and potential entry points."),
        ("Threat Modeling", "PTES-TM-01", "Asset Identification", "Identify critical assets and their value to the organization."),
        ("Threat Modeling", "PTES-TM-02", "Attack Surface Analysis", "Map the attack surface and identify potential attack vectors."),
        ("Vulnerability Analysis", "PTES-VA-01", "Automated Scanning", "Run automated vulnerability scanners against identified targets."),
        ("Vulnerability Analysis", "PTES-VA-02", "Manual Testing", "Perform manual vulnerability testing and verification."),
        ("Vulnerability Analysis", "PTES-VA-03", "Vulnerability Verification", "Verify and validate discovered vulnerabilities to eliminate false positives."),
        ("Exploitation", "PTES-EX-01", "Exploitation Planning", "Plan exploitation attempts based on discovered vulnerabilities."),
        ("Exploitation", "PTES-EX-02", "Controlled Exploitation", "Execute controlled exploitation of verified vulnerabilities."),
        ("Exploitation", "PTES-EX-03", "Credential Harvesting", "Attempt to harvest credentials from compromised systems."),
        ("Post Exploitation", "PTES-PO-01", "Privilege Escalation", "Attempt to escalate privileges on compromised systems."),
        ("Post Exploitation", "PTES-PO-02", "Lateral Movement", "Test ability to move laterally within the network."),
        ("Post Exploitation", "PTES-PO-03", "Data Exfiltration", "Test data exfiltration capabilities (with proper authorization)."),
        ("Reporting", "PTES-RE-01", "Finding Documentation", "Document all findings with proper evidence and severity ratings."),
        ("Reporting", "PTES-RE-02", "Executive Summary", "Prepare executive summary of key findings and risks."),
        ("Reporting", "PTES-RE-03", "Remediation Recommendations", "Provide detailed remediation recommendations for each finding."),
    ];

    for (category, item_id, title, description) in ptes_items {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO methodology_template_items (id, template_id, category, item_id, title, description)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(&id)
        .bind(&ptes_id)
        .bind(category)
        .bind(item_id)
        .bind(title)
        .bind(description)
        .execute(pool)
        .await?;
    }

    // OWASP WSTG (Web Security Testing Guide)
    let wstg_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO methodology_templates (id, name, version, description, categories, item_count, is_system, created_at, updated_at)
        VALUES (?1, 'OWASP WSTG', '4.2', 'OWASP Web Security Testing Guide - Comprehensive guide for web application security testing',
                '["Information Gathering", "Configuration Management", "Identity Management", "Authentication", "Authorization", "Session Management", "Input Validation", "Error Handling", "Cryptography", "Business Logic", "Client-side"]',
                42, 1, ?2, ?2)
        "#,
    )
    .bind(&wstg_id)
    .bind(&now)
    .execute(pool)
    .await?;

    // Add OWASP WSTG items (abbreviated set)
    let wstg_items = [
        ("Information Gathering", "WSTG-INFO-01", "Conduct Search Engine Discovery", "Search for potentially sensitive information indexed by search engines."),
        ("Information Gathering", "WSTG-INFO-02", "Fingerprint Web Server", "Identify the web server software and version."),
        ("Information Gathering", "WSTG-INFO-03", "Review Webserver Metafiles", "Analyze robots.txt, sitemap.xml, and other metafiles."),
        ("Information Gathering", "WSTG-INFO-04", "Enumerate Applications", "Enumerate all applications hosted on the web server."),
        ("Configuration Management", "WSTG-CONF-01", "Test Network Infrastructure", "Test network infrastructure configuration and security."),
        ("Configuration Management", "WSTG-CONF-02", "Test Application Platform", "Test application platform configuration (framework, language)."),
        ("Configuration Management", "WSTG-CONF-03", "Test File Extension Handling", "Test how the server handles different file extensions."),
        ("Configuration Management", "WSTG-CONF-04", "Review Old Backup Files", "Search for backup and unreferenced files."),
        ("Identity Management", "WSTG-IDNT-01", "Test Role Definitions", "Test user role definitions and separation of privileges."),
        ("Identity Management", "WSTG-IDNT-02", "Test User Registration", "Test user registration process for security weaknesses."),
        ("Authentication", "WSTG-ATHN-01", "Test for Credentials Transport", "Test if credentials are transmitted over encrypted channel."),
        ("Authentication", "WSTG-ATHN-02", "Test for Default Credentials", "Test for default or easily guessable credentials."),
        ("Authentication", "WSTG-ATHN-03", "Test for Weak Lockout", "Test account lockout mechanism strength."),
        ("Authentication", "WSTG-ATHN-04", "Test for Bypassing Auth", "Test for authentication bypass vulnerabilities."),
        ("Authorization", "WSTG-ATHZ-01", "Test Directory Traversal", "Test for path traversal vulnerabilities."),
        ("Authorization", "WSTG-ATHZ-02", "Test for Privilege Escalation", "Test for vertical and horizontal privilege escalation."),
        ("Authorization", "WSTG-ATHZ-03", "Test for IDOR", "Test for Insecure Direct Object References."),
        ("Session Management", "WSTG-SESS-01", "Test Session Management Schema", "Analyze the session management schema."),
        ("Session Management", "WSTG-SESS-02", "Test Cookies Attributes", "Test cookie security attributes (HttpOnly, Secure, SameSite)."),
        ("Session Management", "WSTG-SESS-03", "Test for Session Fixation", "Test for session fixation vulnerabilities."),
        ("Input Validation", "WSTG-INPV-01", "Test for Reflected XSS", "Test for reflected cross-site scripting."),
        ("Input Validation", "WSTG-INPV-02", "Test for Stored XSS", "Test for stored cross-site scripting."),
        ("Input Validation", "WSTG-INPV-03", "Test for SQL Injection", "Test for SQL injection vulnerabilities."),
        ("Input Validation", "WSTG-INPV-04", "Test for Command Injection", "Test for OS command injection."),
        ("Error Handling", "WSTG-ERRH-01", "Test for Error Codes", "Analyze error codes and messages for information disclosure."),
        ("Error Handling", "WSTG-ERRH-02", "Test for Stack Traces", "Test for stack trace disclosure."),
        ("Cryptography", "WSTG-CRYP-01", "Test for Weak TLS", "Test for weak TLS/SSL configurations."),
        ("Cryptography", "WSTG-CRYP-02", "Test for Sensitive Data", "Test for unencrypted sensitive data exposure."),
        ("Business Logic", "WSTG-BUSL-01", "Test Business Logic Flaws", "Test for business logic vulnerabilities."),
        ("Business Logic", "WSTG-BUSL-02", "Test Upload Functionality", "Test file upload functionality for security issues."),
        ("Client-side", "WSTG-CLNT-01", "Test for DOM XSS", "Test for DOM-based cross-site scripting."),
        ("Client-side", "WSTG-CLNT-02", "Test for Clickjacking", "Test for clickjacking vulnerabilities."),
    ];

    for (category, item_id, title, description) in wstg_items {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO methodology_template_items (id, template_id, category, item_id, title, description)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(&id)
        .bind(&wstg_id)
        .bind(category)
        .bind(item_id)
        .bind(title)
        .bind(description)
        .execute(pool)
        .await?;
    }

    log::info!("Seeded PTES and OWASP WSTG methodology templates");
    Ok(())
}

/// Add role column to portal_users table
/// Supports: 'admin', 'member', 'viewer' roles
async fn add_role_column_to_portal_users(pool: &SqlitePool) -> Result<()> {
    // Check if column already exists
    let table_info: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(portal_users)")
        .fetch_all(pool)
        .await?;

    let has_role = table_info.iter().any(|(_, name, _, _, _, _)| name == "role");

    if !has_role {
        sqlx::query("ALTER TABLE portal_users ADD COLUMN role TEXT NOT NULL DEFAULT 'member'")
            .execute(pool)
            .await?;
        log::info!("Added role column to portal_users table");
    }

    Ok(())
}

/// Enhance audit_logs table with user_agent column and indexes for efficient querying
async fn enhance_audit_logs_table(pool: &SqlitePool) -> Result<()> {
    // Check if user_agent column already exists
    let table_info: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as("PRAGMA table_info(audit_logs)")
        .fetch_all(pool)
        .await?;

    let has_user_agent = table_info.iter().any(|(_, name, _, _, _, _)| name == "user_agent");

    if !has_user_agent {
        sqlx::query("ALTER TABLE audit_logs ADD COLUMN user_agent TEXT")
            .execute(pool)
            .await?;
        log::info!("Added user_agent column to audit_logs table");
    }

    // Create indexes for efficient querying
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_logs_target_type ON audit_logs(target_type)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)")
        .execute(pool)
        .await?;

    // Compound index for common filter combinations
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_logs_user_action ON audit_logs(user_id, action)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_logs_action_created ON audit_logs(action, created_at)")
        .execute(pool)
        .await?;

    log::info!("Enhanced audit_logs table with indexes");
    Ok(())
}

/// Create scan_tags table for categorizing scans
async fn create_scan_tags_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scan_tags (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            color TEXT NOT NULL DEFAULT '#06b6d4',
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for name lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_tags_name ON scan_tags(name)")
        .execute(pool)
        .await?;

    log::info!("Created scan_tags table");
    Ok(())
}

/// Create scan_tag_mappings junction table for scan-tag associations
async fn create_scan_tag_mappings_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scan_tag_mappings (
            scan_id TEXT NOT NULL,
            tag_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (scan_id, tag_id),
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id) REFERENCES scan_tags(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_tag_mappings_scan_id ON scan_tag_mappings(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_tag_mappings_tag_id ON scan_tag_mappings(tag_id)")
        .execute(pool)
        .await?;

    log::info!("Created scan_tag_mappings table");
    Ok(())
}

// ============================================================================
// Asset Tags Migration Functions
// ============================================================================

/// Create asset_tags table for categorizing and organizing assets
async fn create_asset_tags_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asset_tags (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            color TEXT NOT NULL DEFAULT '#06b6d4',
            category TEXT NOT NULL DEFAULT 'custom',
            description TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, name)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_tags_user_id ON asset_tags(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_tags_category ON asset_tags(category)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_tags_name ON asset_tags(user_id, name)")
        .execute(pool)
        .await?;

    log::info!("Created asset_tags table");
    Ok(())
}

/// Create asset_tag_mappings junction table for asset-tag associations
async fn create_asset_tag_mappings_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asset_tag_mappings (
            asset_id TEXT NOT NULL,
            tag_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (asset_id, tag_id),
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id) REFERENCES asset_tags(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_tag_mappings_asset_id ON asset_tag_mappings(asset_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_tag_mappings_tag_id ON asset_tag_mappings(tag_id)")
        .execute(pool)
        .await?;

    log::info!("Created asset_tag_mappings table");
    Ok(())
}

/// Create AD Assessment tables for storing Active Directory assessments
async fn create_ad_assessment_tables(pool: &SqlitePool) -> Result<()> {
    // Main assessment table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ad_assessments (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            domain_controller TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 389,
            use_ldaps INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            domain_name TEXT,
            netbios_name TEXT,
            forest_name TEXT,
            domain_level TEXT,
            forest_level TEXT,
            base_dn TEXT,
            total_users INTEGER DEFAULT 0,
            total_groups INTEGER DEFAULT 0,
            total_computers INTEGER DEFAULT 0,
            kerberoastable_accounts INTEGER DEFAULT 0,
            asrep_roastable_accounts INTEGER DEFAULT 0,
            unconstrained_delegation INTEGER DEFAULT 0,
            critical_findings INTEGER DEFAULT 0,
            high_findings INTEGER DEFAULT 0,
            medium_findings INTEGER DEFAULT 0,
            low_findings INTEGER DEFAULT 0,
            overall_risk_score INTEGER DEFAULT 0,
            results_json TEXT,
            error_message TEXT,
            customer_id TEXT,
            engagement_id TEXT,
            started_at TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL,
            FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ad_assessments_user_id ON ad_assessments(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ad_assessments_status ON ad_assessments(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ad_assessments_domain_controller ON ad_assessments(domain_controller)")
        .execute(pool)
        .await?;

    // AD Findings table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ad_findings (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            mitre_attack_ids TEXT,
            affected_objects TEXT,
            affected_count INTEGER DEFAULT 0,
            remediation TEXT,
            risk_score INTEGER DEFAULT 0,
            evidence TEXT,
            references_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (assessment_id) REFERENCES ad_assessments(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ad_findings_assessment_id ON ad_findings(assessment_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ad_findings_severity ON ad_findings(severity)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ad_findings_category ON ad_findings(category)")
        .execute(pool)
        .await?;

    log::info!("Created AD assessment tables");
    Ok(())
}

/// Create Credential Audit tables for storing credential testing results
async fn create_credential_audit_tables(pool: &SqlitePool) -> Result<()> {
    // Main audit table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS credential_audits (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            config_json TEXT NOT NULL,
            total_targets INTEGER DEFAULT 0,
            total_attempts INTEGER DEFAULT 0,
            successful_logins INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            connection_errors INTEGER DEFAULT 0,
            services_tested TEXT,
            error_message TEXT,
            customer_id TEXT,
            engagement_id TEXT,
            started_at TEXT,
            completed_at TEXT,
            duration_secs REAL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL,
            FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_credential_audits_user_id ON credential_audits(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_credential_audits_status ON credential_audits(status)")
        .execute(pool)
        .await?;

    // Target results table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS credential_audit_targets (
            id TEXT PRIMARY KEY,
            audit_id TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            service_type TEXT NOT NULL,
            use_ssl INTEGER DEFAULT 0,
            path TEXT,
            successful_credentials TEXT,
            failed_attempts INTEGER DEFAULT 0,
            connection_errors INTEGER DEFAULT 0,
            error_message TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (audit_id) REFERENCES credential_audits(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_credential_audit_targets_audit_id ON credential_audit_targets(audit_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_credential_audit_targets_host ON credential_audit_targets(host)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_credential_audit_targets_service_type ON credential_audit_targets(service_type)")
        .execute(pool)
        .await?;

    log::info!("Created credential audit tables");
    Ok(())
}

