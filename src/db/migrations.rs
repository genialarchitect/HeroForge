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
    seed_default_roles(pool).await?;
    seed_default_settings(pool).await?;
    add_gdpr_consent_columns(pool).await?;
    add_mfa_columns_to_users(pool).await?;
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
