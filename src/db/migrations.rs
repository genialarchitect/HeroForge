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

