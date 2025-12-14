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
    create_scan_templates_table(pool).await?;
    create_target_groups_table(pool).await?;
    create_notification_settings_table(pool).await?;
    seed_default_roles(pool).await?;
    seed_default_settings(pool).await?;
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
