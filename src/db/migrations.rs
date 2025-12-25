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
    // Asset Groups tables
    create_asset_groups_table(pool).await?;
    create_asset_group_members_table(pool).await?;
    // Scan Exclusions tables
    create_scan_exclusions_table(pool).await?;
    // Add updated_at column to vulnerability_comments
    add_updated_at_to_vulnerability_comments(pool).await?;
    // Scheduled reports table
    create_scheduled_reports_table(pool).await?;
    // Enhanced scan templates (profiles/presets)
    enhance_scan_templates_table(pool).await?;
    seed_system_scan_templates(pool).await?;
    // ServiceNow integration tables
    create_servicenow_settings_table(pool).await?;
    create_servicenow_tickets_table(pool).await?;
    // Secret findings table
    create_secret_findings_table(pool).await?;
    // AI Prioritization tables
    create_ai_prioritization_tables(pool).await?;
    // CI/CD integration tables
    create_cicd_tokens_table(pool).await?;
    create_cicd_runs_table(pool).await?;
    create_quality_gates_table(pool).await?;
    // Remediation workflow tables
    create_workflow_tables(pool).await?;
    // Agent-based scanning tables
    create_agent_tables(pool).await?;
    // SSO (SAML/OIDC) authentication tables
    create_sso_providers_table(pool).await?;
    create_sso_sessions_table(pool).await?;
    // Container/Kubernetes scanning tables
    create_container_scan_tables(pool).await?;
    // IaC (Infrastructure-as-Code) scanning tables
    create_iac_scan_tables(pool).await?;
    // Push notification device tokens for mobile app
    create_push_device_tokens_table(pool).await?;
    // Plugin marketplace tables
    create_plugins_table(pool).await?;
    create_plugin_settings_table(pool).await?;
    // Agent mesh networking tables
    create_agent_mesh_tables(pool).await?;
    // SIEM (Full SIEM Capabilities) tables
    create_siem_tables(pool).await?;
    // Compliance Evidence Collection tables
    create_compliance_evidence_tables(pool).await?;
    // Breach & Attack Simulation (BAS) tables
    create_bas_tables(pool).await?;
    // Exploitation framework tables
    create_exploitation_tables(pool).await?;
    // Nuclei scanner tables
    create_nuclei_tables(pool).await?;
    // Asset discovery tables
    create_asset_discovery_tables(pool).await?;
    // Privilege escalation scanner tables
    create_privesc_tables(pool).await?;
    // BloodHound integration tables
    create_bloodhound_tables(pool).await?;
    // Phishing campaign tables
    create_phishing_tables(pool).await?;
    // SMS phishing (smishing) campaign tables
    create_sms_phishing_tables(pool).await?;
    // Vishing (voice phishing) and pretexting tables
    create_vishing_tables(pool).await?;
    // C2 framework integration tables
    create_c2_tables(pool).await?;
    // Wireless security tables
    create_wireless_tables(pool).await?;
    // Exploitation safeguards - customer/asset binding
    add_exploitation_safeguards(pool).await?;
    // Enhanced finding templates with categories, evidence placeholders, and seed data
    enhance_finding_templates(pool).await?;
    seed_enhanced_finding_templates(pool).await?;
    // Password cracking tables
    create_cracking_tables(pool).await?;
    // Attack Surface Management tables
    create_asm_tables(pool).await?;
    // Purple Team Mode tables
    super::purple_team::init_purple_team_tables(pool).await?;
    // AI Chat tables
    create_chat_tables(pool).await?;
    // SSO user profile sync tables
    add_sso_profile_fields(pool).await?;
    // ABAC permissions and organization hierarchy
    create_permissions_system(pool).await?;
    // Multi-tenant data isolation - add organization_id to data tables
    add_organization_id_to_data_tables(pool).await?;
    // Organization quotas and usage tracking
    create_organization_quotas_tables(pool).await?;
    // Enhanced secret scanning tables (git, filesystem, entropy)
    create_enhanced_secret_scanning_tables(pool).await?;
    // CI/CD Pipeline Security scanning tables
    create_cicd_pipeline_scan_tables(pool).await?;
    // Kubernetes Security scanning tables
    create_k8s_security_tables(pool).await?;
    // Sprint 8: Enhanced Remediation Workflows + Executive Dashboard
    create_remediation_workflow_tables(pool).await?;
    create_executive_dashboard_tables(pool).await?;
    // Sprint 9: Custom Report Templates
    create_custom_report_templates_tables(pool).await?;
    // Sprint 10: External Integrations (Scanner Import, Slack/Teams Bots)
    create_scanner_import_tables(pool).await?;
    create_integration_bot_tables(pool).await?;
    // Shodan integration cache and query history
    super::shodan_cache::create_shodan_cache_table(pool).await?;
    super::shodan_cache::create_shodan_queries_table(pool).await?;
    // Email security analysis results
    create_email_security_results_table(pool).await?;
    // Domain intelligence cache
    create_domain_intel_cache_table(pool).await?;
    // Google Dorking automation tables
    create_google_dorking_tables(pool).await?;
    // Breach check history tables
    create_breach_check_tables(pool).await?;
    // Git repository reconnaissance tables (GitHub/GitLab API scanning)
    create_git_recon_tables(pool).await?;
    // Cloud asset discovery tables
    super::cloud_discovery::create_cloud_discovery_tables(pool).await?;
    // QR code phishing (quishing) tables
    create_qr_phishing_tables(pool).await?;
    // Tunneling framework tables (DNS, HTTPS, ICMP tunneling for exfiltration defense testing)
    create_tunneling_tables(pool).await?;
    // AV/EDR Evasion analysis tables
    create_evasion_tables(pool).await?;
    // Payload encoding jobs table
    create_encoding_jobs_table(pool).await?;
    Ok(())
}

/// Add SSO profile fields to users table and create SSO group membership tracking
async fn add_sso_profile_fields(pool: &SqlitePool) -> Result<()> {
    // Add display_name column
    let _ = sqlx::query(
        "ALTER TABLE users ADD COLUMN display_name TEXT"
    )
    .execute(pool)
    .await;

    // Add first_name column
    let _ = sqlx::query(
        "ALTER TABLE users ADD COLUMN first_name TEXT"
    )
    .execute(pool)
    .await;

    // Add last_name column
    let _ = sqlx::query(
        "ALTER TABLE users ADD COLUMN last_name TEXT"
    )
    .execute(pool)
    .await;

    // Add sso_provider_id to track which SSO provider the user authenticated with
    let _ = sqlx::query(
        "ALTER TABLE users ADD COLUMN sso_provider_id TEXT REFERENCES sso_providers(id)"
    )
    .execute(pool)
    .await;

    // Add sso_subject to store the unique identifier from the IdP
    let _ = sqlx::query(
        "ALTER TABLE users ADD COLUMN sso_subject TEXT"
    )
    .execute(pool)
    .await;

    // Add last_sso_sync to track when profile was last synced
    let _ = sqlx::query(
        "ALTER TABLE users ADD COLUMN last_sso_sync TEXT"
    )
    .execute(pool)
    .await;

    // Create SSO group memberships table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sso_group_memberships (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            group_name TEXT NOT NULL,
            synced_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (provider_id) REFERENCES sso_providers(id) ON DELETE CASCADE,
            UNIQUE(user_id, provider_id, group_name)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for efficient group queries
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sso_group_memberships_user ON sso_group_memberships(user_id)"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sso_group_memberships_provider ON sso_group_memberships(provider_id)"
    )
    .execute(pool)
    .await?;

    // Create SSO profile sync audit log table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sso_profile_sync_log (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            changes TEXT NOT NULL,
            synced_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (provider_id) REFERENCES sso_providers(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sso_profile_sync_log_user ON sso_profile_sync_log(user_id)"
    )
    .execute(pool)
    .await?;

    log::info!("Added SSO profile fields and group membership tracking");
    Ok(())
}

/// Add customer_id and asset_ids columns to exploitation_campaigns for safety
async fn add_exploitation_safeguards(pool: &SqlitePool) -> Result<()> {
    // Add customer_id column (required for all exploitation campaigns)
    let _ = sqlx::query(
        "ALTER TABLE exploitation_campaigns ADD COLUMN customer_id TEXT REFERENCES customers(id)"
    )
    .execute(pool)
    .await;

    // Add asset_ids column (JSON array of asset IDs that are targets)
    let _ = sqlx::query(
        "ALTER TABLE exploitation_campaigns ADD COLUMN asset_ids TEXT DEFAULT '[]'"
    )
    .execute(pool)
    .await;

    // Add engagement_id column (optional - tie to specific engagement)
    let _ = sqlx::query(
        "ALTER TABLE exploitation_campaigns ADD COLUMN engagement_id TEXT REFERENCES engagements(id)"
    )
    .execute(pool)
    .await;

    // Create index for customer lookups
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_exploitation_campaigns_customer ON exploitation_campaigns(customer_id)"
    )
    .execute(pool)
    .await?;

    // Create index for engagement lookups
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_exploitation_campaigns_engagement ON exploitation_campaigns(engagement_id)"
    )
    .execute(pool)
    .await?;

    // Add customer_id to generated_payloads for tracking
    let _ = sqlx::query(
        "ALTER TABLE generated_payloads ADD COLUMN customer_id TEXT REFERENCES customers(id)"
    )
    .execute(pool)
    .await;

    let _ = sqlx::query(
        "ALTER TABLE generated_payloads ADD COLUMN asset_id TEXT REFERENCES assets(id)"
    )
    .execute(pool)
    .await;

    log::info!("Added exploitation safeguards (customer/asset binding)");
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

// ============================================================================
// Asset Groups Migration Functions
// ============================================================================

/// Create asset_groups table for organizing assets into logical groups
async fn create_asset_groups_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asset_groups (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            color TEXT NOT NULL DEFAULT '#3b82f6',
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
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_groups_user_id ON asset_groups(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_groups_name ON asset_groups(user_id, name)")
        .execute(pool)
        .await?;

    log::info!("Created asset_groups table");
    Ok(())
}

/// Create asset_group_members junction table for asset-group associations
async fn create_asset_group_members_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asset_group_members (
            asset_group_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            added_at TEXT NOT NULL,
            PRIMARY KEY (asset_group_id, asset_id),
            FOREIGN KEY (asset_group_id) REFERENCES asset_groups(id) ON DELETE CASCADE,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_group_members_group_id ON asset_group_members(asset_group_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_group_members_asset_id ON asset_group_members(asset_id)")
        .execute(pool)
        .await?;

    log::info!("Created asset_group_members table");
    Ok(())
}

// ============================================================================
// Scan Exclusions Migration Functions
// ============================================================================

/// Create scan_exclusions table for host/port exclusion rules
async fn create_scan_exclusions_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scan_exclusions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            exclusion_type TEXT NOT NULL,
            value TEXT NOT NULL,
            is_global INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_exclusions_user_id ON scan_exclusions(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_exclusions_is_global ON scan_exclusions(user_id, is_global)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_exclusions_type ON scan_exclusions(exclusion_type)")
        .execute(pool)
        .await?;

    log::info!("Created scan_exclusions table");
    Ok(())
}

/// Add updated_at column to vulnerability_comments for editing support
async fn add_updated_at_to_vulnerability_comments(pool: &SqlitePool) -> Result<()> {
    // Check if the column already exists using proper tuple structure
    // PRAGMA table_info returns: (cid, name, type, notnull, dflt_value, pk)
    let columns: Vec<(i32, String, String, i32, Option<String>, i32)> =
        sqlx::query_as("PRAGMA table_info(vulnerability_comments)")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    let has_updated_at = columns.iter().any(|(_, name, _, _, _, _)| name == "updated_at");

    if !has_updated_at {
        sqlx::query("ALTER TABLE vulnerability_comments ADD COLUMN updated_at TEXT")
            .execute(pool)
            .await?;
        log::info!("Added updated_at column to vulnerability_comments table");
    }

    Ok(())
}

// ============================================================================
// Webhooks (Outbound) Migration Functions
// ============================================================================

/// Create webhooks table for storing webhook configurations
async fn create_webhooks_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS webhooks (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            secret TEXT,
            events TEXT NOT NULL,
            headers TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            last_triggered_at TEXT,
            last_status_code INTEGER,
            failure_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_webhooks_user_id ON webhooks(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_webhooks_is_active ON webhooks(user_id, is_active)")
        .execute(pool)
        .await?;

    log::info!("Created webhooks table");
    Ok(())
}

/// Create webhook_deliveries table for storing delivery history
async fn create_webhook_deliveries_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            id TEXT PRIMARY KEY,
            webhook_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            response_status INTEGER,
            response_body TEXT,
            error TEXT,
            delivered_at TEXT NOT NULL,
            FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_event_type ON webhook_deliveries(event_type)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_delivered_at ON webhook_deliveries(delivered_at)")
        .execute(pool)
        .await?;

    log::info!("Created webhook_deliveries table");
    Ok(())
}

// ============================================================================
// Scheduled Reports Migration Functions
// ============================================================================

/// Create scheduled_reports table for automated report generation and email delivery
async fn create_scheduled_reports_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scheduled_reports (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            report_type TEXT NOT NULL,
            format TEXT NOT NULL,
            schedule TEXT NOT NULL,
            recipients TEXT NOT NULL,
            filters TEXT,
            include_charts INTEGER DEFAULT 1,
            last_run_at TEXT,
            next_run_at TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scheduled_reports_user_id ON scheduled_reports(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scheduled_reports_next_run ON scheduled_reports(next_run_at)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scheduled_reports_is_active ON scheduled_reports(is_active)")
        .execute(pool)
        .await?;

    log::info!("Created scheduled_reports table");
    Ok(())
}

// ============================================================================
// Enhanced Scan Templates (Profiles/Presets) Migration
// ============================================================================

/// Add enhanced columns to scan_templates for profiles/presets feature
async fn enhance_scan_templates_table(pool: &SqlitePool) -> Result<()> {
    // Check if the columns already exist
    let columns: Vec<(i32, String, String, i32, Option<String>, i32)> =
        sqlx::query_as("PRAGMA table_info(scan_templates)")
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    let has_is_system = columns.iter().any(|(_, name, _, _, _, _)| name == "is_system");
    let has_category = columns.iter().any(|(_, name, _, _, _, _)| name == "category");
    let has_estimated_duration = columns.iter().any(|(_, name, _, _, _, _)| name == "estimated_duration_mins");
    let has_use_count = columns.iter().any(|(_, name, _, _, _, _)| name == "use_count");
    let has_last_used_at = columns.iter().any(|(_, name, _, _, _, _)| name == "last_used_at");

    if !has_is_system {
        sqlx::query("ALTER TABLE scan_templates ADD COLUMN is_system INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await?;
        log::info!("Added is_system column to scan_templates table");
    }

    if !has_category {
        sqlx::query("ALTER TABLE scan_templates ADD COLUMN category TEXT NOT NULL DEFAULT 'custom'")
            .execute(pool)
            .await?;
        log::info!("Added category column to scan_templates table");
    }

    if !has_estimated_duration {
        sqlx::query("ALTER TABLE scan_templates ADD COLUMN estimated_duration_mins INTEGER")
            .execute(pool)
            .await?;
        log::info!("Added estimated_duration_mins column to scan_templates table");
    }

    if !has_use_count {
        sqlx::query("ALTER TABLE scan_templates ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await?;
        log::info!("Added use_count column to scan_templates table");
    }

    if !has_last_used_at {
        sqlx::query("ALTER TABLE scan_templates ADD COLUMN last_used_at TEXT")
            .execute(pool)
            .await?;
        log::info!("Added last_used_at column to scan_templates table");
    }

    // Create indexes for new columns
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_templates_category ON scan_templates(category)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_templates_is_system ON scan_templates(is_system)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Seed system scan templates (profiles/presets)
async fn seed_system_scan_templates(pool: &SqlitePool) -> Result<()> {
    use uuid::Uuid;
    use chrono::Utc;

    // Check if system templates already exist
    let existing_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM scan_templates WHERE is_system = 1"
    )
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    if existing_count.0 > 0 {
        log::info!("System scan templates already exist, skipping seed");
        return Ok(());
    }

    let now = Utc::now();
    let system_user_id = "system"; // Special user ID for system templates

    // Ensure system user exists (needed for foreign key constraint)
    let system_user_exists: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM users WHERE id = 'system'"
    )
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    if system_user_exists.0 == 0 {
        // Create system user with a random password hash (it will never be used for login)
        sqlx::query(
            r#"
            INSERT INTO users (id, username, email, password_hash, created_at, is_active, accepted_terms_at, terms_version)
            VALUES ('system', 'system', 'system@heroforge.local', '$2b$12$system.placeholder.hash.never.used', ?1, 0, ?1, '1.0')
            "#
        )
        .bind(now.to_rfc3339())
        .execute(pool)
        .await?;
        log::info!("Created system user for system templates");
    }

    // Define system templates
    let templates = vec![
        (
            "Quick Scan",
            "Fast reconnaissance scan targeting common ports. Ideal for initial discovery.",
            "quick",
            5, // estimated minutes
            r#"{"port_range":[1,100],"threads":100,"enable_os_detection":false,"enable_service_detection":false,"enable_vuln_scan":false,"enable_enumeration":false,"enum_depth":null,"enum_services":null,"scan_type":"tcp_connect","udp_port_range":null,"udp_retries":2,"target_group_id":null}"#,
        ),
        (
            "Standard Scan",
            "Balanced scan with service detection on top 1000 ports. Good for routine assessments.",
            "standard",
            30, // estimated minutes
            r#"{"port_range":[1,1000],"threads":50,"enable_os_detection":true,"enable_service_detection":true,"enable_vuln_scan":true,"enable_enumeration":false,"enum_depth":null,"enum_services":null,"scan_type":"tcp_connect","udp_port_range":null,"udp_retries":2,"target_group_id":null}"#,
        ),
        (
            "Comprehensive Scan",
            "Full port scan with deep service detection, OS fingerprinting, and vulnerability scanning. Thorough but slow.",
            "comprehensive",
            120, // estimated minutes
            r#"{"port_range":[1,65535],"threads":25,"enable_os_detection":true,"enable_service_detection":true,"enable_vuln_scan":true,"enable_enumeration":true,"enum_depth":"aggressive","enum_services":["http","https","smb","ftp","ssh","mysql","postgresql"],"scan_type":"comprehensive","udp_port_range":[1,1000],"udp_retries":3,"target_group_id":null}"#,
        ),
        (
            "Web Focus",
            "Optimized for web application targets. Scans common web ports with HTTP enumeration enabled.",
            "web",
            45, // estimated minutes
            r#"{"port_range":[80,443],"threads":30,"enable_os_detection":false,"enable_service_detection":true,"enable_vuln_scan":true,"enable_enumeration":true,"enum_depth":"light","enum_services":["http","https"],"scan_type":"tcp_connect","udp_port_range":null,"udp_retries":2,"target_group_id":null}"#,
        ),
        (
            "Stealth Scan",
            "Low and slow SYN scan designed to minimize detection. Uses reduced threads and timing.",
            "stealth",
            180, // estimated minutes
            r#"{"port_range":[1,1000],"threads":5,"enable_os_detection":false,"enable_service_detection":true,"enable_vuln_scan":false,"enable_enumeration":false,"enum_depth":null,"enum_services":null,"scan_type":"syn","udp_port_range":null,"udp_retries":1,"target_group_id":null}"#,
        ),
    ];

    let template_count = templates.len();
    for (name, description, category, estimated_duration, config) in templates {
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO scan_templates (id, user_id, name, description, config, is_default, is_system, category, estimated_duration_mins, use_count, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, 0, 1, ?6, ?7, 0, ?8, ?9)
            "#,
        )
        .bind(&id)
        .bind(system_user_id)
        .bind(name)
        .bind(description)
        .bind(config)
        .bind(category)
        .bind(estimated_duration)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;
    }

    log::info!("Seeded {} system scan templates", template_count);
    Ok(())
}

// ============================================================================
// ServiceNow Integration Migrations
// ============================================================================

/// Create servicenow_settings table for storing user ServiceNow configuration
async fn create_servicenow_settings_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS servicenow_settings (
            user_id TEXT PRIMARY KEY,
            instance_url TEXT NOT NULL,
            username TEXT NOT NULL,
            password_encrypted TEXT NOT NULL,
            default_assignment_group TEXT,
            default_category TEXT,
            default_impact INTEGER DEFAULT 3,
            default_urgency INTEGER DEFAULT 3,
            enabled INTEGER DEFAULT 1,
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

/// Create servicenow_tickets table for tracking tickets created from vulnerabilities
async fn create_servicenow_tickets_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS servicenow_tickets (
            id TEXT PRIMARY KEY,
            vulnerability_id TEXT NOT NULL,
            ticket_number TEXT NOT NULL,
            ticket_type TEXT NOT NULL,
            ticket_sys_id TEXT NOT NULL,
            ticket_url TEXT NOT NULL,
            status TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_tracking(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for efficient lookups by vulnerability
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_servicenow_tickets_vuln_id ON servicenow_tickets(vulnerability_id)")
        .execute(pool)
        .await?;

    // Create index for efficient lookups by ticket number
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_servicenow_tickets_number ON servicenow_tickets(ticket_number)")
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Secret Findings Migrations
// ============================================================================

/// Create secret_findings table for storing detected secrets in scans
async fn create_secret_findings_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS secret_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            host_ip TEXT NOT NULL,
            port INTEGER,
            secret_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            redacted_value TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_location TEXT NOT NULL,
            line_number INTEGER,
            context TEXT,
            confidence REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            resolved_at TEXT,
            resolved_by TEXT,
            false_positive INTEGER DEFAULT 0,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE,
            FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_secret_findings_scan_id ON secret_findings(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_secret_findings_host ON secret_findings(host_ip)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_secret_findings_type ON secret_findings(secret_type)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_secret_findings_severity ON secret_findings(severity)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_secret_findings_status ON secret_findings(status)")
        .execute(pool)
        .await?;

    log::info!("Created secret_findings table");
    Ok(())
}

// ============================================================================
// AI Prioritization Migrations
// ============================================================================

/// Create AI prioritization tables
async fn create_ai_prioritization_tables(pool: &SqlitePool) -> Result<()> {
    // AI Scores table - stores calculated AI scores for each vulnerability
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ai_scores (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            vulnerability_id TEXT NOT NULL,
            effective_risk_score REAL NOT NULL,
            risk_category TEXT NOT NULL,
            factor_scores TEXT NOT NULL,
            remediation_priority INTEGER NOT NULL,
            estimated_effort TEXT NOT NULL,
            confidence REAL NOT NULL,
            calculated_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE,
            UNIQUE(scan_id, vulnerability_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for AI scores
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ai_scores_scan_id ON ai_scores(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ai_scores_vuln_id ON ai_scores(vulnerability_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ai_scores_risk_category ON ai_scores(risk_category)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ai_scores_priority ON ai_scores(remediation_priority)")
        .execute(pool)
        .await?;

    // AI Prioritization Results table - stores summary results per scan
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ai_prioritization_results (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL UNIQUE,
            total_vulnerabilities INTEGER NOT NULL,
            critical_count INTEGER NOT NULL,
            high_count INTEGER NOT NULL,
            medium_count INTEGER NOT NULL,
            low_count INTEGER NOT NULL,
            average_risk_score REAL NOT NULL,
            highest_risk_score REAL NOT NULL,
            summary_json TEXT NOT NULL,
            calculated_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // AI Model Configuration table - stores scoring weight configurations
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ai_model_config (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            weights TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ai_model_config_active ON ai_model_config(is_active)")
        .execute(pool)
        .await?;

    // AI Feedback table - stores user feedback for learning
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ai_feedback (
            id TEXT PRIMARY KEY,
            vulnerability_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            priority_appropriate INTEGER NOT NULL,
            priority_adjustment INTEGER NOT NULL,
            effort_accurate INTEGER NOT NULL,
            actual_effort_hours INTEGER,
            notes TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ai_feedback_vuln_id ON ai_feedback(vulnerability_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ai_feedback_user_id ON ai_feedback(user_id)")
        .execute(pool)
        .await?;

    log::info!("Created AI prioritization tables");
    Ok(())
}

// ============================================================================
// CI/CD Integration Migrations
// ============================================================================

/// Create cicd_tokens table for CI/CD API tokens with restricted permissions
async fn create_cicd_tokens_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cicd_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            token_prefix TEXT NOT NULL,
            platform TEXT NOT NULL,
            permissions TEXT NOT NULL,
            last_used_at TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_tokens_user_id ON cicd_tokens(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_tokens_token_hash ON cicd_tokens(token_hash)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_tokens_is_active ON cicd_tokens(is_active)")
        .execute(pool)
        .await?;

    log::info!("Created cicd_tokens table");
    Ok(())
}

/// Create cicd_runs table for tracking CI/CD triggered scans
async fn create_cicd_runs_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cicd_runs (
            id TEXT PRIMARY KEY,
            token_id TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            ci_ref TEXT,
            ci_branch TEXT,
            ci_url TEXT,
            repository TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            quality_gate_passed INTEGER,
            quality_gate_details TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (token_id) REFERENCES cicd_tokens(id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_runs_token_id ON cicd_runs(token_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_runs_scan_id ON cicd_runs(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_runs_status ON cicd_runs(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_runs_started_at ON cicd_runs(started_at)")
        .execute(pool)
        .await?;

    log::info!("Created cicd_runs table");
    Ok(())
}

/// Create quality_gates table for configurable thresholds
async fn create_quality_gates_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS quality_gates (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            fail_on_severity TEXT NOT NULL DEFAULT 'high',
            max_vulnerabilities INTEGER,
            max_critical INTEGER,
            max_high INTEGER,
            max_medium INTEGER,
            max_low INTEGER,
            fail_on_new_vulns INTEGER NOT NULL DEFAULT 0,
            baseline_scan_id TEXT,
            is_default INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (baseline_scan_id) REFERENCES scan_results(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_quality_gates_user_id ON quality_gates(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_quality_gates_is_default ON quality_gates(is_default)")
        .execute(pool)
        .await?;

    // Seed a default quality gate
    seed_default_quality_gate(pool).await?;

    log::info!("Created quality_gates table");
    Ok(())
}

/// Seed a default quality gate for new installations
async fn seed_default_quality_gate(pool: &SqlitePool) -> Result<()> {
    // Check if any quality gates exist already
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM quality_gates")
        .fetch_one(pool)
        .await?;

    if count.0 > 0 {
        return Ok(()); // Quality gates already exist
    }

    // Note: This creates a "system" quality gate that is not owned by any user
    // Users can create their own quality gates or admins can modify this one
    sqlx::query(
        r#"
        INSERT INTO quality_gates (id, user_id, name, fail_on_severity, max_critical, max_high, is_default, created_at, updated_at)
        VALUES ('default', 'system', 'Default Quality Gate', 'high', 0, NULL, 1, datetime('now'), datetime('now'))
        "#,
    )
    .execute(pool)
    .await?;

    log::info!("Seeded default quality gate");
    Ok(())
}

/// Create remediation workflow tables
async fn create_workflow_tables(pool: &SqlitePool) -> Result<()> {
    // Workflow templates table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS workflow_templates (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            is_system INTEGER NOT NULL DEFAULT 0,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Workflow stages table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS workflow_stages (
            id TEXT PRIMARY KEY,
            template_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            stage_order INTEGER NOT NULL,
            stage_type TEXT NOT NULL,
            required_approvals INTEGER NOT NULL DEFAULT 0,
            approver_role TEXT,
            approver_user_ids TEXT,
            sla_hours INTEGER,
            notify_on_enter INTEGER NOT NULL DEFAULT 1,
            notify_on_sla_breach INTEGER NOT NULL DEFAULT 1,
            auto_advance_conditions TEXT,
            FOREIGN KEY (template_id) REFERENCES workflow_templates(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for efficient stage lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_workflow_stages_template ON workflow_stages(template_id, stage_order)")
        .execute(pool)
        .await?;

    // Workflow instances table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS workflow_instances (
            id TEXT PRIMARY KEY,
            template_id TEXT NOT NULL,
            vulnerability_id TEXT NOT NULL,
            current_stage_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            started_by TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            notes TEXT,
            FOREIGN KEY (template_id) REFERENCES workflow_templates(id),
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_tracking(id),
            FOREIGN KEY (current_stage_id) REFERENCES workflow_stages(id),
            FOREIGN KEY (started_by) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for workflow instances
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_workflow_instances_vuln ON workflow_instances(vulnerability_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_workflow_instances_status ON workflow_instances(status)")
        .execute(pool)
        .await?;

    // Workflow stage instances table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS workflow_stage_instances (
            id TEXT PRIMARY KEY,
            instance_id TEXT NOT NULL,
            stage_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            entered_at TEXT NOT NULL,
            completed_at TEXT,
            sla_deadline TEXT,
            sla_breached INTEGER NOT NULL DEFAULT 0,
            approvals_received INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            FOREIGN KEY (instance_id) REFERENCES workflow_instances(id) ON DELETE CASCADE,
            FOREIGN KEY (stage_id) REFERENCES workflow_stages(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for stage instances
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_workflow_stage_instances_instance ON workflow_stage_instances(instance_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_workflow_stage_instances_sla ON workflow_stage_instances(sla_deadline) WHERE sla_breached = 0")
        .execute(pool)
        .await?;

    // Workflow approvals table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS workflow_approvals (
            id TEXT PRIMARY KEY,
            stage_instance_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            approved INTEGER NOT NULL,
            comment TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (stage_instance_id) REFERENCES workflow_stage_instances(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for approval lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_workflow_approvals_stage ON workflow_approvals(stage_instance_id)")
        .execute(pool)
        .await?;

    // Workflow transitions table (audit trail)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS workflow_transitions (
            id TEXT PRIMARY KEY,
            instance_id TEXT NOT NULL,
            from_stage_id TEXT,
            to_stage_id TEXT NOT NULL,
            action TEXT NOT NULL,
            performed_by TEXT NOT NULL,
            comment TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (instance_id) REFERENCES workflow_instances(id) ON DELETE CASCADE,
            FOREIGN KEY (from_stage_id) REFERENCES workflow_stages(id),
            FOREIGN KEY (to_stage_id) REFERENCES workflow_stages(id),
            FOREIGN KEY (performed_by) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for transition lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_workflow_transitions_instance ON workflow_transitions(instance_id)")
        .execute(pool)
        .await?;

    // Add workflow notification setting if it doesn't exist
    sqlx::query(
        r#"
        INSERT OR IGNORE INTO system_settings (key, value, description, updated_at)
        VALUES ('notify_on_workflow_action', 'true', 'Send notifications for workflow actions', datetime('now'))
        "#,
    )
    .execute(pool)
    .await?;

    // Add notify_on_workflow_action column to notification_settings if it doesn't exist
    let columns: Vec<(String,)> = sqlx::query_as(
        "SELECT name FROM pragma_table_info('notification_settings') WHERE name = 'notify_on_workflow_action'"
    )
    .fetch_all(pool)
    .await?;

    if columns.is_empty() {
        sqlx::query(
            "ALTER TABLE notification_settings ADD COLUMN notify_on_workflow_action INTEGER DEFAULT 1"
        )
        .execute(pool)
        .await?;
    }

    log::info!("Created workflow tables");
    Ok(())
}

// ============================================================================
// Agent-Based Scanning Migrations
// ============================================================================

/// Create all agent-related tables
async fn create_agent_tables(pool: &SqlitePool) -> Result<()> {
    // Scan agents table - registered agents
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scan_agents (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            token_hash TEXT NOT NULL,
            token_prefix TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            version TEXT,
            hostname TEXT,
            ip_address TEXT,
            os_info TEXT,
            capabilities TEXT,
            network_zones TEXT,
            max_concurrent_tasks INTEGER NOT NULL DEFAULT 1,
            current_tasks INTEGER NOT NULL DEFAULT 0,
            last_heartbeat_at TEXT,
            last_task_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_agents_user_id ON scan_agents(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_agents_status ON scan_agents(status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_agents_token_prefix ON scan_agents(token_prefix)")
        .execute(pool)
        .await?;

    // Agent groups table - logical groupings for network segmentation
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS agent_groups (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            network_ranges TEXT,
            color TEXT NOT NULL DEFAULT '#06b6d4',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, name)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_groups_user_id ON agent_groups(user_id)")
        .execute(pool)
        .await?;

    // Agent group members - junction table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS agent_group_members (
            agent_id TEXT NOT NULL,
            group_id TEXT NOT NULL,
            added_at TEXT NOT NULL,
            PRIMARY KEY (agent_id, group_id),
            FOREIGN KEY (agent_id) REFERENCES scan_agents(id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES agent_groups(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_group_members_agent_id ON agent_group_members(agent_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_group_members_group_id ON agent_group_members(group_id)")
        .execute(pool)
        .await?;

    // Agent tasks table - distributed tasks
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS agent_tasks (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            agent_id TEXT,
            group_id TEXT,
            user_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            task_type TEXT NOT NULL,
            config TEXT NOT NULL,
            targets TEXT NOT NULL,
            priority INTEGER NOT NULL DEFAULT 1,
            timeout_seconds INTEGER NOT NULL DEFAULT 3600,
            retry_count INTEGER NOT NULL DEFAULT 0,
            max_retries INTEGER NOT NULL DEFAULT 3,
            error_message TEXT,
            assigned_at TEXT,
            started_at TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE,
            FOREIGN KEY (agent_id) REFERENCES scan_agents(id) ON DELETE SET NULL,
            FOREIGN KEY (group_id) REFERENCES agent_groups(id) ON DELETE SET NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_tasks_scan_id ON agent_tasks(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_tasks_agent_id ON agent_tasks(agent_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_tasks_status ON agent_tasks(status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_tasks_user_id ON agent_tasks(user_id)")
        .execute(pool)
        .await?;

    // Agent results table - collected results
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS agent_results (
            id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            result_data TEXT NOT NULL,
            hosts_discovered INTEGER NOT NULL DEFAULT 0,
            ports_found INTEGER NOT NULL DEFAULT 0,
            vulnerabilities_found INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (task_id) REFERENCES agent_tasks(id) ON DELETE CASCADE,
            FOREIGN KEY (agent_id) REFERENCES scan_agents(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_results_task_id ON agent_results(task_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_results_agent_id ON agent_results(agent_id)")
        .execute(pool)
        .await?;

    // Agent heartbeats table - health tracking
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS agent_heartbeats (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            cpu_usage REAL,
            memory_usage REAL,
            disk_usage REAL,
            active_tasks INTEGER NOT NULL DEFAULT 0,
            queued_tasks INTEGER NOT NULL DEFAULT 0,
            latency_ms INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES scan_agents(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_heartbeats_agent_id ON agent_heartbeats(agent_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_heartbeats_created_at ON agent_heartbeats(created_at)")
        .execute(pool)
        .await?;

    log::info!("Created agent-based scanning tables");
    Ok(())
}

// ============================================================================
// SSO (SAML/OIDC) Authentication Migrations
// ============================================================================

/// Create sso_providers table for storing SSO identity provider configurations
async fn create_sso_providers_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sso_providers (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            provider_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'disabled',
            icon TEXT,
            config TEXT NOT NULL,
            attribute_mappings TEXT,
            group_mappings TEXT,
            jit_provisioning INTEGER NOT NULL DEFAULT 0,
            default_role TEXT NOT NULL DEFAULT 'user',
            update_on_login INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_used_at TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sso_providers_name ON sso_providers(name)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sso_providers_status ON sso_providers(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sso_providers_type ON sso_providers(provider_type)")
        .execute(pool)
        .await?;

    log::info!("Created sso_providers table");
    Ok(())
}

/// Create sso_sessions table for tracking SSO sessions (for SLO support)
async fn create_sso_sessions_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sso_sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            session_index TEXT,
            name_id TEXT,
            name_id_format TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            logged_out_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (provider_id) REFERENCES sso_providers(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sso_sessions_user_id ON sso_sessions(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sso_sessions_provider_id ON sso_sessions(provider_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sso_sessions_expires_at ON sso_sessions(expires_at)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sso_sessions_logged_out_at ON sso_sessions(logged_out_at)")
        .execute(pool)
        .await?;

    log::info!("Created sso_sessions table");
    Ok(())
}

// ============================================================================
// IaC (Infrastructure-as-Code) Scanning Migrations
// ============================================================================

/// Create IaC scanning tables for Terraform, CloudFormation, and ARM templates
async fn create_iac_scan_tables(pool: &SqlitePool) -> Result<()> {
    // Main IaC scans table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS iac_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_url TEXT,
            platforms TEXT,
            providers TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            file_count INTEGER DEFAULT 0,
            resource_count INTEGER DEFAULT 0,
            finding_count INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            info_count INTEGER DEFAULT 0,
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

    // Create indexes for iac_scans
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iac_scans_user_id ON iac_scans(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iac_scans_status ON iac_scans(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iac_scans_created_at ON iac_scans(created_at)")
        .execute(pool)
        .await?;

    // IaC files table - stores scanned files
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS iac_files (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            path TEXT NOT NULL,
            content TEXT,
            platform TEXT NOT NULL,
            provider TEXT NOT NULL,
            size_bytes INTEGER DEFAULT 0,
            line_count INTEGER DEFAULT 0,
            resource_count INTEGER DEFAULT 0,
            finding_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES iac_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iac_files_scan_id ON iac_files(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iac_files_platform ON iac_files(platform)")
        .execute(pool)
        .await?;

    // IaC findings table - stores security issues found
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS iac_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            file_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            resource_type TEXT,
            resource_name TEXT,
            line_start INTEGER DEFAULT 0,
            line_end INTEGER DEFAULT 0,
            code_snippet TEXT,
            remediation TEXT NOT NULL,
            documentation_url TEXT,
            compliance_mappings TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            suppressed INTEGER DEFAULT 0,
            suppression_reason TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES iac_scans(id) ON DELETE CASCADE,
            FOREIGN KEY (file_id) REFERENCES iac_files(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iac_findings_scan_id ON iac_findings(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iac_findings_file_id ON iac_findings(file_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iac_findings_severity ON iac_findings(severity)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iac_findings_category ON iac_findings(category)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iac_findings_status ON iac_findings(status)")
        .execute(pool)
        .await?;

    // IaC rules table - stores built-in and custom security rules
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS iac_rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            platforms TEXT NOT NULL,
            providers TEXT NOT NULL,
            resource_types TEXT,
            pattern TEXT,
            pattern_type TEXT NOT NULL,
            remediation TEXT NOT NULL,
            documentation_url TEXT,
            compliance_mappings TEXT,
            is_builtin INTEGER DEFAULT 0,
            is_enabled INTEGER DEFAULT 1,
            user_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iac_rules_is_builtin ON iac_rules(is_builtin)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iac_rules_is_enabled ON iac_rules(is_enabled)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iac_rules_user_id ON iac_rules(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iac_rules_severity ON iac_rules(severity)")
        .execute(pool)
        .await?;

    log::info!("Created IaC scanning tables");
    Ok(())
}

// ============================================================================
// Container/Kubernetes Scanning Migrations
// ============================================================================

/// Create container scanning tables for Docker and Kubernetes security scanning
async fn create_container_scan_tables(pool: &SqlitePool) -> Result<()> {
    // Container scans table - main scan records
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS container_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            scan_types TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            images_count INTEGER DEFAULT 0,
            resources_count INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
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

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_container_scans_user_id ON container_scans(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_container_scans_status ON container_scans(status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_container_scans_created_at ON container_scans(created_at)")
        .execute(pool)
        .await?;

    // Container images table - discovered Docker images
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS container_images (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            image_ref TEXT NOT NULL,
            digest TEXT,
            registry TEXT,
            repository TEXT NOT NULL,
            tag TEXT NOT NULL,
            os TEXT,
            architecture TEXT,
            created TEXT,
            size_bytes INTEGER,
            layer_count INTEGER DEFAULT 0,
            labels TEXT,
            vuln_count INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            discovered_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES container_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_container_images_scan_id ON container_images(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_container_images_image_ref ON container_images(image_ref)")
        .execute(pool)
        .await?;

    // K8s resources table - Kubernetes resources analyzed
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS k8s_resources (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            api_version TEXT NOT NULL,
            name TEXT NOT NULL,
            namespace TEXT,
            labels TEXT,
            annotations TEXT,
            manifest TEXT,
            finding_count INTEGER DEFAULT 0,
            discovered_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES container_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_resources_scan_id ON k8s_resources(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_resources_resource_type ON k8s_resources(resource_type)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_resources_namespace ON k8s_resources(namespace)")
        .execute(pool)
        .await?;

    // Container findings table - security findings from scans
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS container_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            image_id TEXT,
            resource_id TEXT,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            cve_id TEXT,
            cvss_score REAL,
            cwe_ids TEXT,
            package_name TEXT,
            package_version TEXT,
            fixed_version TEXT,
            file_path TEXT,
            line_number INTEGER,
            remediation TEXT,
            "references" TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES container_scans(id) ON DELETE CASCADE,
            FOREIGN KEY (image_id) REFERENCES container_images(id) ON DELETE SET NULL,
            FOREIGN KEY (resource_id) REFERENCES k8s_resources(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_container_findings_scan_id ON container_findings(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_container_findings_image_id ON container_findings(image_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_container_findings_resource_id ON container_findings(resource_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_container_findings_severity ON container_findings(severity)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_container_findings_status ON container_findings(status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_container_findings_cve_id ON container_findings(cve_id)")
        .execute(pool)
        .await?;

    log::info!("Created container/Kubernetes scanning tables");
    Ok(())
}

/// Create push device tokens table for mobile push notifications
async fn create_push_device_tokens_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS push_device_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            device_token TEXT NOT NULL,
            platform TEXT NOT NULL,
            device_name TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Index for efficient user token lookup
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_push_tokens_user_id ON push_device_tokens(user_id)")
        .execute(pool)
        .await?;

    // Index for efficient token lookup (e.g., when invalidating)
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_push_tokens_device_token ON push_device_tokens(device_token)")
        .execute(pool)
        .await?;

    // Compound index for finding active tokens per user
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_push_tokens_user_active ON push_device_tokens(user_id, is_active)")
        .execute(pool)
        .await?;

    log::info!("Created push device tokens table");
    Ok(())
}

// ============================================================================
// Plugin Marketplace Tables
// ============================================================================

/// Create plugins table for installed plugins
async fn create_plugins_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS plugins (
            id TEXT PRIMARY KEY,
            plugin_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            plugin_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'disabled',
            manifest TEXT NOT NULL,
            install_path TEXT NOT NULL,
            installed_by TEXT NOT NULL,
            installed_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            error_message TEXT,
            checksum TEXT,
            FOREIGN KEY (installed_by) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Index for plugin lookups by plugin_id
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_plugins_plugin_id ON plugins(plugin_id)")
        .execute(pool)
        .await?;

    // Index for filtering by type
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_plugins_type ON plugins(plugin_type)")
        .execute(pool)
        .await?;

    // Index for filtering by status
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_plugins_status ON plugins(status)")
        .execute(pool)
        .await?;

    log::info!("Created plugins table");
    Ok(())
}

/// Create plugin_settings table for per-user plugin settings
async fn create_plugin_settings_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS plugin_settings (
            id TEXT PRIMARY KEY,
            plugin_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            settings TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(plugin_id, user_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Index for efficient plugin settings lookup
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_plugin_settings_plugin_id ON plugin_settings(plugin_id)")
        .execute(pool)
        .await?;

    // Index for user's plugin settings
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_plugin_settings_user_id ON plugin_settings(user_id)")
        .execute(pool)
        .await?;

    log::info!("Created plugin_settings table");
    Ok(())
}

// ============================================================================
// Agent Mesh Networking Tables
// ============================================================================

/// Create agent mesh networking tables for distributed scanning
async fn create_agent_mesh_tables(pool: &SqlitePool) -> Result<()> {
    // Agent mesh configuration table - per-agent mesh settings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS agent_mesh_config (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL UNIQUE,
            enabled INTEGER NOT NULL DEFAULT 0,
            mesh_port INTEGER NOT NULL DEFAULT 9876,
            external_address TEXT,
            cluster_id TEXT,
            cluster_role TEXT,
            config_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES scan_agents(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Index for agent mesh config lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_mesh_config_agent_id ON agent_mesh_config(agent_id)")
        .execute(pool)
        .await?;

    // Index for finding mesh-enabled agents
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_mesh_config_enabled ON agent_mesh_config(enabled)")
        .execute(pool)
        .await?;

    // Index for cluster membership
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_mesh_config_cluster_id ON agent_mesh_config(cluster_id)")
        .execute(pool)
        .await?;

    // Agent clusters table - cluster definitions
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS agent_clusters (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            leader_agent_id TEXT,
            config_json TEXT,
            health_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (leader_agent_id) REFERENCES scan_agents(id) ON DELETE SET NULL,
            UNIQUE(user_id, name)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Index for user's clusters
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_clusters_user_id ON agent_clusters(user_id)")
        .execute(pool)
        .await?;

    // Index for finding cluster by leader
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_clusters_leader ON agent_clusters(leader_agent_id)")
        .execute(pool)
        .await?;

    // Agent peer connections table - connection history between agents
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS agent_peer_connections (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            peer_agent_id TEXT NOT NULL,
            peer_address TEXT NOT NULL,
            peer_port INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'unknown',
            latency_ms INTEGER,
            successful_pings INTEGER NOT NULL DEFAULT 0,
            failed_pings INTEGER NOT NULL DEFAULT 0,
            last_connected_at TEXT,
            last_attempt_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES scan_agents(id) ON DELETE CASCADE,
            UNIQUE(agent_id, peer_agent_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Index for agent's peer connections
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_peer_connections_agent_id ON agent_peer_connections(agent_id)")
        .execute(pool)
        .await?;

    // Index for peer connections
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_peer_connections_peer_agent_id ON agent_peer_connections(peer_agent_id)")
        .execute(pool)
        .await?;

    // Index for connection status filtering
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_peer_connections_status ON agent_peer_connections(status)")
        .execute(pool)
        .await?;

    // Index for cleanup of old connections
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_agent_peer_connections_last_attempt ON agent_peer_connections(last_attempt_at)")
        .execute(pool)
        .await?;

    log::info!("Created agent mesh networking tables");
    Ok(())
}

/// Create compliance evidence collection tables
async fn create_compliance_evidence_tables(pool: &SqlitePool) -> Result<()> {
    // Main compliance evidence table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS compliance_evidence (
            id TEXT PRIMARY KEY,
            evidence_type TEXT NOT NULL,
            control_ids TEXT NOT NULL DEFAULT '[]',
            framework_ids TEXT NOT NULL DEFAULT '[]',
            title TEXT NOT NULL,
            description TEXT,
            content_hash TEXT NOT NULL,
            content TEXT NOT NULL DEFAULT '{"content_type":"none"}',
            collection_source TEXT NOT NULL DEFAULT 'manual_upload',
            status TEXT NOT NULL DEFAULT 'active',
            version INTEGER NOT NULL DEFAULT 1,
            previous_version_id TEXT,
            collected_at TEXT NOT NULL,
            collected_by TEXT NOT NULL,
            expires_at TEXT,
            retention_policy TEXT NOT NULL DEFAULT '{"type":"framework_default"}',
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (collected_by) REFERENCES users(id),
            FOREIGN KEY (previous_version_id) REFERENCES compliance_evidence(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Indexes for compliance_evidence
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_compliance_evidence_collected_by ON compliance_evidence(collected_by)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_compliance_evidence_status ON compliance_evidence(status)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_compliance_evidence_collection_source ON compliance_evidence(collection_source)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_compliance_evidence_collected_at ON compliance_evidence(collected_at)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_compliance_evidence_expires_at ON compliance_evidence(expires_at)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_compliance_evidence_content_hash ON compliance_evidence(content_hash)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_compliance_evidence_previous_version ON compliance_evidence(previous_version_id)",
    )
    .execute(pool)
    .await?;

    // Evidence to control mappings table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS evidence_control_mapping (
            id TEXT PRIMARY KEY,
            evidence_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            framework_id TEXT NOT NULL,
            coverage_score REAL NOT NULL DEFAULT 1.0,
            notes TEXT,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            FOREIGN KEY (evidence_id) REFERENCES compliance_evidence(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id),
            UNIQUE(evidence_id, control_id, framework_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Indexes for evidence_control_mapping
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_evidence_control_mapping_evidence ON evidence_control_mapping(evidence_id)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_evidence_control_mapping_control ON evidence_control_mapping(framework_id, control_id)",
    )
    .execute(pool)
    .await?;

    // Scheduled evidence collection table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS evidence_collection_schedule (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            collection_source TEXT NOT NULL,
            cron_expression TEXT NOT NULL,
            control_ids TEXT NOT NULL DEFAULT '[]',
            framework_ids TEXT NOT NULL DEFAULT '[]',
            enabled INTEGER NOT NULL DEFAULT 1,
            last_run_at TEXT,
            next_run_at TEXT,
            config TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Indexes for evidence_collection_schedule
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_evidence_collection_schedule_user ON evidence_collection_schedule(user_id)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_evidence_collection_schedule_enabled ON evidence_collection_schedule(enabled)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_evidence_collection_schedule_next_run ON evidence_collection_schedule(next_run_at)",
    )
    .execute(pool)
    .await?;

    log::info!("Created compliance evidence collection tables");
    Ok(())
}

// ============================================================================
// SIEM (Security Information and Event Management) Tables
// ============================================================================

/// Create SIEM tables for full SIEM capabilities
async fn create_siem_tables(pool: &SqlitePool) -> Result<()> {
    // Log sources table - configured log sources
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS siem_log_sources (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            source_type TEXT NOT NULL,
            host TEXT,
            format TEXT NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            last_seen TEXT,
            log_count INTEGER NOT NULL DEFAULT 0,
            logs_per_hour INTEGER NOT NULL DEFAULT 0,
            custom_patterns TEXT,
            field_mappings TEXT,
            tags TEXT NOT NULL DEFAULT '[]',
            auto_enrich INTEGER NOT NULL DEFAULT 1,
            retention_days INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            created_by TEXT,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Index for source lookups by name
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_log_sources_name ON siem_log_sources(name)")
        .execute(pool)
        .await?;

    // Index for filtering by status
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_log_sources_status ON siem_log_sources(status)")
        .execute(pool)
        .await?;

    // Index for filtering by type
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_log_sources_type ON siem_log_sources(source_type)")
        .execute(pool)
        .await?;

    // Log entries table - main log storage with date-based partitioning support
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS siem_log_entries (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            received_at TEXT NOT NULL,
            severity TEXT NOT NULL,
            facility INTEGER,
            format TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            hostname TEXT,
            application TEXT,
            pid INTEGER,
            message_id TEXT,
            structured_data TEXT NOT NULL DEFAULT '{}',
            message TEXT NOT NULL,
            raw TEXT NOT NULL,
            category TEXT,
            action TEXT,
            outcome TEXT,
            user TEXT,
            tags TEXT NOT NULL DEFAULT '[]',
            alerted INTEGER NOT NULL DEFAULT 0,
            alert_ids TEXT NOT NULL DEFAULT '[]',
            partition_date TEXT NOT NULL,
            FOREIGN KEY (source_id) REFERENCES siem_log_sources(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Primary index for time-based queries (most common)
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_log_entries_timestamp ON siem_log_entries(timestamp)")
        .execute(pool)
        .await?;

    // Index for partition-based queries (date-based partitioning)
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_log_entries_partition ON siem_log_entries(partition_date)")
        .execute(pool)
        .await?;

    // Index for source-based filtering
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_log_entries_source ON siem_log_entries(source_id)")
        .execute(pool)
        .await?;

    // Index for severity-based filtering
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_log_entries_severity ON siem_log_entries(severity)")
        .execute(pool)
        .await?;

    // Index for source IP lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_log_entries_source_ip ON siem_log_entries(source_ip)")
        .execute(pool)
        .await?;

    // Index for destination IP lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_log_entries_dest_ip ON siem_log_entries(destination_ip)")
        .execute(pool)
        .await?;

    // Index for hostname lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_log_entries_hostname ON siem_log_entries(hostname)")
        .execute(pool)
        .await?;

    // Index for application filtering
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_log_entries_app ON siem_log_entries(application)")
        .execute(pool)
        .await?;

    // Index for user-based queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_log_entries_user ON siem_log_entries(user)")
        .execute(pool)
        .await?;

    // Index for finding alerted entries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_log_entries_alerted ON siem_log_entries(alerted)")
        .execute(pool)
        .await?;

    // Composite index for common query patterns (source + time range)
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_log_entries_source_time ON siem_log_entries(source_id, timestamp)")
        .execute(pool)
        .await?;

    // Detection rules table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS siem_rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            rule_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'disabled',
            definition TEXT NOT NULL,
            source_ids TEXT NOT NULL DEFAULT '[]',
            categories TEXT NOT NULL DEFAULT '[]',
            mitre_tactics TEXT NOT NULL DEFAULT '[]',
            mitre_techniques TEXT NOT NULL DEFAULT '[]',
            false_positive_rate REAL,
            trigger_count INTEGER NOT NULL DEFAULT 0,
            last_triggered TEXT,
            tags TEXT NOT NULL DEFAULT '[]',
            response_actions TEXT NOT NULL DEFAULT '[]',
            time_window_seconds INTEGER,
            threshold_count INTEGER,
            group_by_fields TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            created_by TEXT,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Index for rule name lookups
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_rules_name ON siem_rules(name)")
        .execute(pool)
        .await?;

    // Index for filtering enabled rules
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_rules_status ON siem_rules(status)")
        .execute(pool)
        .await?;

    // Index for rule type filtering
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_rules_type ON siem_rules(rule_type)")
        .execute(pool)
        .await?;

    // Index for severity-based filtering
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_rules_severity ON siem_rules(severity)")
        .execute(pool)
        .await?;

    // Alerts table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS siem_alerts (
            id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new',
            title TEXT NOT NULL,
            description TEXT,
            log_entry_ids TEXT NOT NULL DEFAULT '[]',
            event_count INTEGER NOT NULL DEFAULT 1,
            source_ips TEXT NOT NULL DEFAULT '[]',
            destination_ips TEXT NOT NULL DEFAULT '[]',
            users TEXT NOT NULL DEFAULT '[]',
            hosts TEXT NOT NULL DEFAULT '[]',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            assigned_to TEXT,
            resolved_by TEXT,
            resolved_at TEXT,
            resolution_notes TEXT,
            mitre_tactics TEXT NOT NULL DEFAULT '[]',
            mitre_techniques TEXT NOT NULL DEFAULT '[]',
            tags TEXT NOT NULL DEFAULT '[]',
            context TEXT NOT NULL DEFAULT '{}',
            related_alert_ids TEXT NOT NULL DEFAULT '[]',
            external_ticket_id TEXT,
            FOREIGN KEY (rule_id) REFERENCES siem_rules(id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Index for rule-based alert filtering
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_alerts_rule ON siem_alerts(rule_id)")
        .execute(pool)
        .await?;

    // Index for status filtering (most common query)
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_alerts_status ON siem_alerts(status)")
        .execute(pool)
        .await?;

    // Index for severity filtering
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_alerts_severity ON siem_alerts(severity)")
        .execute(pool)
        .await?;

    // Index for time-based queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_alerts_created ON siem_alerts(created_at)")
        .execute(pool)
        .await?;

    // Index for assigned alerts
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_alerts_assigned ON siem_alerts(assigned_to)")
        .execute(pool)
        .await?;

    // Composite index for common query (status + severity)
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_alerts_status_severity ON siem_alerts(status, severity)")
        .execute(pool)
        .await?;

    // Composite index for time range queries on open alerts
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_siem_alerts_status_created ON siem_alerts(status, created_at)")
        .execute(pool)
        .await?;

    log::info!("Created SIEM tables (siem_log_sources, siem_log_entries, siem_rules, siem_alerts)");
    Ok(())
}

// ============================================================================
// Breach & Attack Simulation (BAS) Migrations
// ============================================================================

/// Create BAS tables for breach and attack simulation
async fn create_bas_tables(pool: &SqlitePool) -> Result<()> {
    // BAS scenarios table - predefined attack scenarios
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS bas_scenarios (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            tactics TEXT NOT NULL,
            techniques TEXT NOT NULL,
            execution_mode TEXT NOT NULL DEFAULT 'dry_run',
            timeout_secs INTEGER NOT NULL DEFAULT 300,
            created_by TEXT,
            is_builtin INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bas_scenarios_created_by ON bas_scenarios(created_by)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bas_scenarios_is_builtin ON bas_scenarios(is_builtin)")
        .execute(pool)
        .await?;

    // BAS simulations table - execution records
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS bas_simulations (
            id TEXT PRIMARY KEY,
            scenario_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            execution_mode TEXT NOT NULL,
            target_host TEXT,
            techniques_total INTEGER DEFAULT 0,
            techniques_executed INTEGER DEFAULT 0,
            techniques_detected INTEGER DEFAULT 0,
            techniques_failed INTEGER DEFAULT 0,
            detection_rate REAL,
            gap_count INTEGER DEFAULT 0,
            error_message TEXT,
            started_at TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scenario_id) REFERENCES bas_scenarios(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bas_simulations_scenario_id ON bas_simulations(scenario_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bas_simulations_user_id ON bas_simulations(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bas_simulations_status ON bas_simulations(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bas_simulations_created_at ON bas_simulations(created_at)")
        .execute(pool)
        .await?;

    // BAS technique executions table - individual technique results
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS bas_technique_executions (
            id TEXT PRIMARY KEY,
            simulation_id TEXT NOT NULL,
            technique_id TEXT NOT NULL,
            technique_name TEXT NOT NULL,
            tactic TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            payload_type TEXT,
            payload_data TEXT,
            was_detected INTEGER DEFAULT 0,
            detection_source TEXT,
            detection_time_ms INTEGER,
            error_message TEXT,
            artifacts TEXT,
            started_at TEXT,
            completed_at TEXT,
            FOREIGN KEY (simulation_id) REFERENCES bas_simulations(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bas_technique_executions_simulation_id ON bas_technique_executions(simulation_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bas_technique_executions_technique_id ON bas_technique_executions(technique_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bas_technique_executions_status ON bas_technique_executions(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bas_technique_executions_was_detected ON bas_technique_executions(was_detected)")
        .execute(pool)
        .await?;

    // BAS detection gaps table - undetected techniques requiring attention
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS bas_detection_gaps (
            id TEXT PRIMARY KEY,
            simulation_id TEXT NOT NULL,
            execution_id TEXT NOT NULL,
            technique_id TEXT NOT NULL,
            technique_name TEXT NOT NULL,
            tactic TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'medium',
            recommendation TEXT,
            is_acknowledged INTEGER DEFAULT 0,
            acknowledged_by TEXT,
            acknowledged_at TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (simulation_id) REFERENCES bas_simulations(id) ON DELETE CASCADE,
            FOREIGN KEY (execution_id) REFERENCES bas_technique_executions(id) ON DELETE CASCADE,
            FOREIGN KEY (acknowledged_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bas_detection_gaps_simulation_id ON bas_detection_gaps(simulation_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bas_detection_gaps_technique_id ON bas_detection_gaps(technique_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bas_detection_gaps_is_acknowledged ON bas_detection_gaps(is_acknowledged)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bas_detection_gaps_severity ON bas_detection_gaps(severity)")
        .execute(pool)
        .await?;

    log::info!("Created BAS tables (bas_scenarios, bas_simulations, bas_technique_executions, bas_detection_gaps)");
    Ok(())
}

// ============================================================================
// Exploitation Framework Migrations
// ============================================================================

/// Create exploitation framework tables
async fn create_exploitation_tables(pool: &SqlitePool) -> Result<()> {
    // Exploitation campaigns table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS exploitation_campaigns (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            config TEXT NOT NULL,
            targets TEXT NOT NULL,
            results_count INTEGER DEFAULT 0,
            successful_count INTEGER DEFAULT 0,
            error_message TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exploitation_campaigns_user_id ON exploitation_campaigns(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exploitation_campaigns_status ON exploitation_campaigns(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exploitation_campaigns_attack_type ON exploitation_campaigns(attack_type)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exploitation_campaigns_created_at ON exploitation_campaigns(created_at)")
        .execute(pool)
        .await?;

    // Exploitation results table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS exploitation_results (
            id TEXT PRIMARY KEY,
            campaign_id TEXT NOT NULL,
            target TEXT NOT NULL,
            result_type TEXT NOT NULL,
            data TEXT NOT NULL,
            severity TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            FOREIGN KEY (campaign_id) REFERENCES exploitation_campaigns(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exploitation_results_campaign_id ON exploitation_results(campaign_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exploitation_results_result_type ON exploitation_results(result_type)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exploitation_results_expires_at ON exploitation_results(expires_at)")
        .execute(pool)
        .await?;

    // Generated payloads table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS generated_payloads (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            payload_type TEXT NOT NULL,
            platform TEXT NOT NULL,
            format TEXT NOT NULL,
            config TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_generated_payloads_user_id ON generated_payloads(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_generated_payloads_payload_type ON generated_payloads(payload_type)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_generated_payloads_created_at ON generated_payloads(created_at)")
        .execute(pool)
        .await?;

    // Exploitation audit log table (separate from main audit for security)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS exploitation_audit_logs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            campaign_id TEXT,
            action TEXT NOT NULL,
            target TEXT,
            details TEXT NOT NULL,
            ip_address TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (campaign_id) REFERENCES exploitation_campaigns(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exploitation_audit_logs_user_id ON exploitation_audit_logs(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exploitation_audit_logs_campaign_id ON exploitation_audit_logs(campaign_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exploitation_audit_logs_action ON exploitation_audit_logs(action)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exploitation_audit_logs_created_at ON exploitation_audit_logs(created_at)")
        .execute(pool)
        .await?;

    log::info!("Created exploitation tables (exploitation_campaigns, exploitation_results, generated_payloads, exploitation_audit_logs)");
    Ok(())
}

/// Create Nuclei scanner tables
async fn create_nuclei_tables(pool: &SqlitePool) -> Result<()> {
    // Nuclei scans table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS nuclei_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT,
            targets TEXT NOT NULL,
            config TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            results_count INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            info_count INTEGER DEFAULT 0,
            error_message TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_nuclei_scans_user_id ON nuclei_scans(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_nuclei_scans_status ON nuclei_scans(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_nuclei_scans_created_at ON nuclei_scans(created_at)")
        .execute(pool)
        .await?;

    // Nuclei results table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS nuclei_results (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            template_id TEXT NOT NULL,
            template_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            host TEXT NOT NULL,
            matched_at TEXT,
            check_type TEXT NOT NULL,
            extracted_results TEXT,
            request TEXT,
            response TEXT,
            curl_command TEXT,
            ip TEXT,
            matcher_name TEXT,
            cve_id TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES nuclei_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_nuclei_results_scan_id ON nuclei_results(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_nuclei_results_template_id ON nuclei_results(template_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_nuclei_results_severity ON nuclei_results(severity)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_nuclei_results_host ON nuclei_results(host)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_nuclei_results_cve_id ON nuclei_results(cve_id)")
        .execute(pool)
        .await?;

    log::info!("Created Nuclei scanner tables (nuclei_scans, nuclei_results)");
    Ok(())
}

/// Create Asset Discovery tables
async fn create_asset_discovery_tables(pool: &SqlitePool) -> Result<()> {
    // Asset discovery scans table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asset_discovery_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            config TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            whois_data TEXT,
            statistics TEXT NOT NULL,
            errors TEXT NOT NULL DEFAULT '[]',
            started_at TEXT NOT NULL,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_discovery_scans_user_id ON asset_discovery_scans(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_discovery_scans_domain ON asset_discovery_scans(domain)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asset_discovery_scans_status ON asset_discovery_scans(status)")
        .execute(pool)
        .await?;

    // Discovered assets table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS discovered_assets (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            ip_addresses TEXT NOT NULL DEFAULT '[]',
            sources TEXT NOT NULL DEFAULT '[]',
            ports TEXT NOT NULL DEFAULT '[]',
            technologies TEXT NOT NULL DEFAULT '[]',
            certificates TEXT NOT NULL DEFAULT '[]',
            dns_records TEXT NOT NULL DEFAULT '{}',
            asn TEXT,
            asn_org TEXT,
            country TEXT,
            city TEXT,
            tags TEXT NOT NULL DEFAULT '[]',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES asset_discovery_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_discovered_assets_scan_id ON discovered_assets(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_discovered_assets_hostname ON discovered_assets(hostname)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_discovered_assets_last_seen ON discovered_assets(last_seen)")
        .execute(pool)
        .await?;

    log::info!("Created Asset Discovery tables (asset_discovery_scans, discovered_assets)");
    Ok(())
}


/// Create Privilege Escalation scanner tables
async fn create_privesc_tables(pool: &SqlitePool) -> Result<()> {
    // Privesc scans table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS privesc_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            target TEXT NOT NULL,
            os_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            config TEXT NOT NULL,
            statistics TEXT NOT NULL DEFAULT '{}',
            system_info TEXT NOT NULL DEFAULT '{}',
            peas_output TEXT,
            errors TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_privesc_scans_user_id ON privesc_scans(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_privesc_scans_status ON privesc_scans(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_privesc_scans_target ON privesc_scans(target)")
        .execute(pool)
        .await?;

    // Privesc findings table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS privesc_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            os_type TEXT NOT NULL,
            vector_data TEXT NOT NULL,
            exploitation_steps TEXT NOT NULL DEFAULT '[]',
            "references" TEXT NOT NULL DEFAULT '[]',
            mitre_techniques TEXT NOT NULL DEFAULT '[]',
            raw_output TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES privesc_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_privesc_findings_scan_id ON privesc_findings(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_privesc_findings_severity ON privesc_findings(severity)")
        .execute(pool)
        .await?;

    log::info!("Created Privilege Escalation tables (privesc_scans, privesc_findings)");
    Ok(())
}

/// Create BloodHound integration tables
async fn create_bloodhound_tables(pool: &SqlitePool) -> Result<()> {
    // Main imports table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS bloodhound_imports (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            statistics TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bloodhound_imports_user_id ON bloodhound_imports(user_id)")
        .execute(pool)
        .await?;

    // Attack paths table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS bloodhound_attack_paths (
            id TEXT PRIMARY KEY,
            import_id TEXT NOT NULL,
            start_node TEXT NOT NULL,
            end_node TEXT NOT NULL,
            path_json TEXT NOT NULL,
            path_length INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            techniques TEXT NOT NULL DEFAULT '[]',
            description TEXT,
            FOREIGN KEY (import_id) REFERENCES bloodhound_imports(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bloodhound_paths_import_id ON bloodhound_attack_paths(import_id)")
        .execute(pool)
        .await?;

    // High-value targets table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS bloodhound_high_value_targets (
            id TEXT PRIMARY KEY,
            import_id TEXT NOT NULL,
            object_id TEXT NOT NULL,
            name TEXT NOT NULL,
            object_type TEXT NOT NULL,
            domain TEXT NOT NULL,
            reason TEXT NOT NULL,
            paths_to_target INTEGER DEFAULT 0,
            FOREIGN KEY (import_id) REFERENCES bloodhound_imports(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Kerberoastable users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS bloodhound_kerberoastable (
            id TEXT PRIMARY KEY,
            import_id TEXT NOT NULL,
            object_id TEXT NOT NULL,
            name TEXT NOT NULL,
            domain TEXT NOT NULL,
            spns TEXT NOT NULL DEFAULT '[]',
            is_admin INTEGER DEFAULT 0,
            password_last_set TEXT,
            description TEXT,
            FOREIGN KEY (import_id) REFERENCES bloodhound_imports(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // AS-REP roastable users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS bloodhound_asrep_roastable (
            id TEXT PRIMARY KEY,
            import_id TEXT NOT NULL,
            object_id TEXT NOT NULL,
            name TEXT NOT NULL,
            domain TEXT NOT NULL,
            is_enabled INTEGER DEFAULT 1,
            is_admin INTEGER DEFAULT 0,
            description TEXT,
            FOREIGN KEY (import_id) REFERENCES bloodhound_imports(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Unconstrained delegation table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS bloodhound_unconstrained_delegation (
            id TEXT PRIMARY KEY,
            import_id TEXT NOT NULL,
            object_id TEXT NOT NULL,
            name TEXT NOT NULL,
            object_type TEXT NOT NULL,
            domain TEXT NOT NULL,
            is_dc INTEGER DEFAULT 0,
            description TEXT,
            FOREIGN KEY (import_id) REFERENCES bloodhound_imports(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    log::info!("Created BloodHound integration tables");
    Ok(())
}

/// Create phishing campaign tables
async fn create_phishing_tables(pool: &SqlitePool) -> Result<()> {
    // Phishing campaigns table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS phishing_campaigns (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'draft',
            email_template_id TEXT NOT NULL,
            landing_page_id TEXT,
            smtp_profile_id TEXT NOT NULL,
            tracking_domain TEXT NOT NULL,
            awareness_training INTEGER DEFAULT 0,
            training_url TEXT,
            launch_date TEXT,
            end_date TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Email templates table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS phishing_email_templates (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            subject TEXT NOT NULL,
            html_body TEXT NOT NULL,
            text_body TEXT,
            from_name TEXT NOT NULL,
            from_email TEXT NOT NULL,
            envelope_sender TEXT,
            attachments TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Landing pages table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS phishing_landing_pages (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            html_content TEXT NOT NULL,
            capture_credentials INTEGER DEFAULT 0,
            capture_fields TEXT NOT NULL DEFAULT '[]',
            redirect_url TEXT,
            redirect_delay INTEGER DEFAULT 0,
            cloned_from TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // SMTP profiles table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS phishing_smtp_profiles (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            username TEXT,
            password TEXT,
            use_tls INTEGER DEFAULT 0,
            use_starttls INTEGER DEFAULT 1,
            from_address TEXT NOT NULL,
            ignore_cert_errors INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Phishing targets table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS phishing_targets (
            id TEXT PRIMARY KEY,
            campaign_id TEXT NOT NULL,
            email TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            position TEXT,
            department TEXT,
            tracking_id TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            email_sent_at TEXT,
            email_opened_at TEXT,
            link_clicked_at TEXT,
            credentials_submitted_at TEXT,
            reported_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (campaign_id) REFERENCES phishing_campaigns(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on tracking_id for fast lookups
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_phishing_targets_tracking_id ON phishing_targets(tracking_id)"
    )
    .execute(pool)
    .await?;

    // Target events table (timeline)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS phishing_target_events (
            id TEXT PRIMARY KEY,
            target_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            details TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (target_id) REFERENCES phishing_targets(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Captured credentials table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS phishing_captured_credentials (
            id TEXT PRIMARY KEY,
            campaign_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            landing_page_id TEXT,
            fields TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (campaign_id) REFERENCES phishing_campaigns(id) ON DELETE CASCADE,
            FOREIGN KEY (target_id) REFERENCES phishing_targets(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Target groups table (for bulk imports)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS phishing_target_groups (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            targets TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    log::info!("Created phishing campaign tables");
    Ok(())
}

/// Create SMS phishing (smishing) campaign tables
async fn create_sms_phishing_tables(pool: &SqlitePool) -> Result<()> {
    // SMS campaigns table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sms_campaigns (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'draft',
            template_id TEXT NOT NULL,
            twilio_config_id TEXT NOT NULL,
            tracking_domain TEXT NOT NULL,
            awareness_training INTEGER DEFAULT 0,
            training_url TEXT,
            launch_date TEXT,
            end_date TEXT,
            rate_limit_per_minute INTEGER DEFAULT 30,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // SMS templates table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sms_templates (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Twilio configuration table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sms_twilio_configs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            account_sid TEXT NOT NULL,
            auth_token TEXT NOT NULL,
            from_number TEXT NOT NULL,
            messaging_service_sid TEXT,
            rate_limit_per_second INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // SMS targets table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sms_targets (
            id TEXT PRIMARY KEY,
            campaign_id TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            company TEXT,
            department TEXT,
            tracking_id TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            message_sid TEXT,
            delivery_status TEXT,
            sent_at TEXT,
            delivered_at TEXT,
            clicked_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (campaign_id) REFERENCES sms_campaigns(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on tracking_id for fast lookups
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sms_targets_tracking_id ON sms_targets(tracking_id)"
    )
    .execute(pool)
    .await?;

    // Create index on phone_number for lookups
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sms_targets_phone ON sms_targets(phone_number)"
    )
    .execute(pool)
    .await?;

    // SMS click events table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sms_click_events (
            id TEXT PRIMARY KEY,
            target_id TEXT NOT NULL,
            campaign_id TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            referrer TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (target_id) REFERENCES sms_targets(id) ON DELETE CASCADE,
            FOREIGN KEY (campaign_id) REFERENCES sms_campaigns(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on click events for campaign statistics
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_sms_clicks_campaign ON sms_click_events(campaign_id)"
    )
    .execute(pool)
    .await?;

    log::info!("Created SMS phishing (smishing) campaign tables");
    Ok(())
}

/// Create vishing (voice phishing) and pretexting tables
async fn create_vishing_tables(pool: &SqlitePool) -> Result<()> {
    // Pretext templates table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS pretext_templates (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            difficulty TEXT NOT NULL DEFAULT 'medium',
            scenario TEXT NOT NULL,
            objectives TEXT NOT NULL DEFAULT '[]',
            script TEXT NOT NULL,
            prerequisites TEXT NOT NULL DEFAULT '[]',
            success_criteria TEXT NOT NULL DEFAULT '[]',
            red_flags TEXT NOT NULL DEFAULT '[]',
            tips TEXT NOT NULL DEFAULT '[]',
            tags TEXT NOT NULL DEFAULT '[]',
            is_builtin INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on category for filtering
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_pretext_templates_category ON pretext_templates(category)"
    )
    .execute(pool)
    .await?;

    // Vishing scripts table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vishing_scripts (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            difficulty TEXT NOT NULL DEFAULT 'medium',
            persona TEXT NOT NULL,
            caller_id TEXT,
            script TEXT NOT NULL,
            call_flow TEXT NOT NULL DEFAULT '[]',
            objection_handling TEXT NOT NULL DEFAULT '{}',
            red_flags TEXT NOT NULL DEFAULT '[]',
            success_indicators TEXT NOT NULL DEFAULT '[]',
            caller_tips TEXT NOT NULL DEFAULT '[]',
            pretext_template_id TEXT,
            is_builtin INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (pretext_template_id) REFERENCES pretext_templates(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on category
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_vishing_scripts_category ON vishing_scripts(category)"
    )
    .execute(pool)
    .await?;

    // Vishing campaigns table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vishing_campaigns (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'draft',
            script_id TEXT NOT NULL,
            pretext_template_id TEXT,
            caller_id TEXT,
            start_date TEXT,
            end_date TEXT,
            target_organization TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (script_id) REFERENCES vishing_scripts(id) ON DELETE RESTRICT,
            FOREIGN KEY (pretext_template_id) REFERENCES pretext_templates(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on status for filtering
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_vishing_campaigns_status ON vishing_campaigns(status)"
    )
    .execute(pool)
    .await?;

    // Vishing targets table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vishing_targets (
            id TEXT PRIMARY KEY,
            campaign_id TEXT NOT NULL,
            name TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            email TEXT,
            job_title TEXT,
            department TEXT,
            notes TEXT,
            called INTEGER DEFAULT 0,
            last_outcome TEXT,
            attempt_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (campaign_id) REFERENCES vishing_campaigns(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on campaign_id for faster lookups
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_vishing_targets_campaign ON vishing_targets(campaign_id)"
    )
    .execute(pool)
    .await?;

    // Create index on phone_number for lookups
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_vishing_targets_phone ON vishing_targets(phone_number)"
    )
    .execute(pool)
    .await?;

    // Vishing call logs table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vishing_call_logs (
            id TEXT PRIMARY KEY,
            campaign_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            caller_id TEXT,
            script_id TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            duration_seconds INTEGER,
            outcome TEXT NOT NULL,
            information_gathered TEXT NOT NULL DEFAULT '{}',
            notes TEXT,
            target_suspicious INTEGER DEFAULT 0,
            verification_requested INTEGER DEFAULT 0,
            stages_completed INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (campaign_id) REFERENCES vishing_campaigns(id) ON DELETE CASCADE,
            FOREIGN KEY (target_id) REFERENCES vishing_targets(id) ON DELETE CASCADE,
            FOREIGN KEY (script_id) REFERENCES vishing_scripts(id) ON DELETE RESTRICT
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on campaign_id for statistics
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_vishing_calls_campaign ON vishing_call_logs(campaign_id)"
    )
    .execute(pool)
    .await?;

    // Create index on outcome for filtering
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_vishing_calls_outcome ON vishing_call_logs(outcome)"
    )
    .execute(pool)
    .await?;

    log::info!("Created vishing (voice phishing) and pretexting tables");
    Ok(())
}

/// Create C2 framework integration tables
async fn create_c2_tables(pool: &SqlitePool) -> Result<()> {
    // C2 server configurations
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS c2_configs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            framework TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            api_token TEXT,
            mtls_cert TEXT,
            mtls_key TEXT,
            ca_cert TEXT,
            verify_ssl INTEGER NOT NULL DEFAULT 1,
            user_id TEXT NOT NULL,
            connected INTEGER NOT NULL DEFAULT 0,
            last_connected TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // C2 listeners
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS c2_listeners (
            id TEXT PRIMARY KEY,
            c2_config_id TEXT NOT NULL,
            name TEXT NOT NULL,
            protocol TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'stopped',
            domains TEXT,
            website TEXT,
            config TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (c2_config_id) REFERENCES c2_configs(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // C2 implants
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS c2_implants (
            id TEXT PRIMARY KEY,
            c2_config_id TEXT NOT NULL,
            name TEXT NOT NULL,
            platform TEXT NOT NULL,
            arch TEXT NOT NULL,
            format TEXT NOT NULL,
            implant_type TEXT NOT NULL DEFAULT 'beacon',
            listener_id TEXT,
            file_path TEXT,
            file_hash TEXT,
            file_size INTEGER,
            download_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (c2_config_id) REFERENCES c2_configs(id) ON DELETE CASCADE,
            FOREIGN KEY (listener_id) REFERENCES c2_listeners(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // C2 sessions/beacons
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS c2_sessions (
            id TEXT PRIMARY KEY,
            c2_config_id TEXT NOT NULL,
            c2_session_id TEXT NOT NULL,
            implant_id TEXT,
            name TEXT NOT NULL,
            hostname TEXT NOT NULL,
            username TEXT NOT NULL,
            domain TEXT,
            ip_address TEXT NOT NULL,
            external_ip TEXT,
            os TEXT NOT NULL,
            os_version TEXT,
            arch TEXT NOT NULL,
            pid INTEGER NOT NULL,
            process_name TEXT NOT NULL,
            integrity TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            is_elevated INTEGER NOT NULL DEFAULT 0,
            locale TEXT,
            first_seen TEXT NOT NULL,
            last_checkin TEXT NOT NULL,
            next_checkin TEXT,
            notes TEXT,
            FOREIGN KEY (c2_config_id) REFERENCES c2_configs(id) ON DELETE CASCADE,
            FOREIGN KEY (implant_id) REFERENCES c2_implants(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on session status for quick lookups
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_c2_sessions_status ON c2_sessions(status)"
    )
    .execute(pool)
    .await?;

    // C2 tasks
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS c2_tasks (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            c2_task_id TEXT,
            task_type TEXT NOT NULL,
            command TEXT NOT NULL,
            args TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            output TEXT,
            error TEXT,
            created_at TEXT NOT NULL,
            sent_at TEXT,
            completed_at TEXT,
            FOREIGN KEY (session_id) REFERENCES c2_sessions(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on task status
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_c2_tasks_status ON c2_tasks(status)"
    )
    .execute(pool)
    .await?;

    // C2 credentials
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS c2_credentials (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            credential_type TEXT NOT NULL,
            username TEXT NOT NULL,
            domain TEXT,
            secret TEXT NOT NULL,
            source TEXT NOT NULL,
            target TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES c2_sessions(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // C2 downloaded files
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS c2_downloaded_files (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            remote_path TEXT NOT NULL,
            local_path TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            file_hash TEXT NOT NULL,
            downloaded_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES c2_sessions(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // C2 screenshots
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS c2_screenshots (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            file_path TEXT NOT NULL,
            width INTEGER NOT NULL,
            height INTEGER NOT NULL,
            captured_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES c2_sessions(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    log::info!("Created C2 framework integration tables");
    Ok(())
}

/// Create wireless security tables
async fn create_wireless_tables(pool: &SqlitePool) -> Result<()> {
    // Wireless scans
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS wireless_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            interface TEXT NOT NULL,
            config TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            networks_found INTEGER NOT NULL DEFAULT 0,
            clients_found INTEGER NOT NULL DEFAULT 0,
            handshakes_captured INTEGER NOT NULL DEFAULT 0,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on status
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_wireless_scans_status ON wireless_scans(status)"
    )
    .execute(pool)
    .await?;

    // Wireless networks
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS wireless_networks (
            bssid TEXT NOT NULL,
            user_id TEXT NOT NULL,
            ssid TEXT NOT NULL,
            channel INTEGER NOT NULL,
            frequency INTEGER NOT NULL,
            signal_strength INTEGER NOT NULL,
            encryption TEXT NOT NULL,
            cipher TEXT,
            auth TEXT,
            wps_enabled INTEGER NOT NULL DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY (bssid, user_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on encryption for vulnerability queries
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_wireless_networks_encryption ON wireless_networks(encryption)"
    )
    .execute(pool)
    .await?;

    // Wireless clients
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS wireless_clients (
            mac_address TEXT NOT NULL,
            user_id TEXT NOT NULL,
            associated_bssid TEXT,
            signal_strength INTEGER NOT NULL,
            packets INTEGER NOT NULL DEFAULT 0,
            probes TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY (mac_address, user_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Wireless handshakes
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS wireless_handshakes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            bssid TEXT NOT NULL,
            ssid TEXT NOT NULL,
            client_mac TEXT NOT NULL,
            capture_file TEXT NOT NULL,
            eapol_messages INTEGER NOT NULL,
            is_complete INTEGER NOT NULL DEFAULT 0,
            cracked INTEGER NOT NULL DEFAULT 0,
            password TEXT,
            captured_at TEXT NOT NULL,
            cracked_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for handshakes
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_wireless_handshakes_cracked ON wireless_handshakes(cracked)"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_wireless_handshakes_bssid ON wireless_handshakes(bssid)"
    )
    .execute(pool)
    .await?;

    // Wireless PMKIDs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS wireless_pmkids (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            bssid TEXT NOT NULL,
            ssid TEXT NOT NULL,
            pmkid TEXT NOT NULL,
            capture_file TEXT NOT NULL,
            cracked INTEGER NOT NULL DEFAULT 0,
            password TEXT,
            captured_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Wireless attacks
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS wireless_attacks (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            target_bssid TEXT NOT NULL,
            target_ssid TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            result TEXT,
            capture_file TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            error TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Wireless crack jobs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS wireless_crack_jobs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            capture_id TEXT NOT NULL,
            capture_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            wordlist TEXT NOT NULL,
            keys_tested INTEGER NOT NULL DEFAULT 0,
            keys_per_second REAL NOT NULL DEFAULT 0,
            password TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    log::info!("Created wireless security tables");
    Ok(())
}

/// Enhance finding templates with additional fields for evidence, OWASP, MITRE, compliance
async fn enhance_finding_templates(pool: &SqlitePool) -> Result<()> {
    // Add evidence_placeholders column (JSON array)
    let _ = sqlx::query(
        "ALTER TABLE finding_templates ADD COLUMN evidence_placeholders TEXT"
    ).execute(pool).await;

    // Add testing_steps column (markdown text)
    let _ = sqlx::query(
        "ALTER TABLE finding_templates ADD COLUMN testing_steps TEXT"
    ).execute(pool).await;

    // Add owasp_category column
    let _ = sqlx::query(
        "ALTER TABLE finding_templates ADD COLUMN owasp_category TEXT"
    ).execute(pool).await;

    // Add mitre_attack_ids column (JSON array)
    let _ = sqlx::query(
        "ALTER TABLE finding_templates ADD COLUMN mitre_attack_ids TEXT"
    ).execute(pool).await;

    // Add compliance_mappings column (JSON object)
    let _ = sqlx::query(
        "ALTER TABLE finding_templates ADD COLUMN compliance_mappings TEXT"
    ).execute(pool).await;

    // Add use_count column for tracking template usage
    let _ = sqlx::query(
        "ALTER TABLE finding_templates ADD COLUMN use_count INTEGER DEFAULT 0"
    ).execute(pool).await;

    // Add last_used_at column
    let _ = sqlx::query(
        "ALTER TABLE finding_templates ADD COLUMN last_used_at TEXT"
    ).execute(pool).await;

    // Add affected_components column (JSON array)
    let _ = sqlx::query(
        "ALTER TABLE finding_templates ADD COLUMN affected_components TEXT"
    ).execute(pool).await;

    // Create finding_template_categories table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS finding_template_categories (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            parent_id TEXT REFERENCES finding_template_categories(id),
            description TEXT,
            icon TEXT,
            color TEXT,
            sort_order INTEGER DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#
    ).execute(pool).await?;

    // Seed default categories
    let categories = [
        ("web", "Web Application", None::<&str>, "Web application vulnerabilities including OWASP Top 10", "globe", "#3b82f6"),
        ("injection", "Injection", Some("web"), "SQL, Command, LDAP, and other injection attacks", "terminal", "#ef4444"),
        ("xss", "Cross-Site Scripting", Some("web"), "Reflected, Stored, and DOM-based XSS", "code", "#f97316"),
        ("auth", "Authentication", Some("web"), "Authentication and session management flaws", "lock", "#8b5cf6"),
        ("network", "Network", None, "Network infrastructure vulnerabilities", "network", "#22c55e"),
        ("ad", "Active Directory", None, "Windows Active Directory and Kerberos issues", "server", "#6366f1"),
        ("cloud", "Cloud Security", None, "AWS, Azure, GCP misconfigurations", "cloud", "#0ea5e9"),
        ("api", "API Security", None, "REST, GraphQL, and API-specific vulnerabilities", "code-2", "#14b8a6"),
        ("mobile", "Mobile", None, "iOS and Android application security", "smartphone", "#a855f7"),
        ("configuration", "Configuration", None, "Misconfigurations and hardening issues", "settings", "#64748b"),
        ("cryptography", "Cryptography", None, "Weak encryption and certificate issues", "key", "#eab308"),
        ("access-control", "Access Control", None, "Authorization and privilege escalation", "shield", "#ec4899"),
    ];

    for (id, name, parent_id, description, icon, color) in categories {
        let _ = sqlx::query(
            r#"
            INSERT OR IGNORE INTO finding_template_categories (id, name, parent_id, description, icon, color, sort_order)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#
        )
        .bind(id)
        .bind(name)
        .bind(parent_id)
        .bind(description)
        .bind(icon)
        .bind(color)
        .bind(0)
        .execute(pool)
        .await;
    }

    // Create index for template usage tracking
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_finding_templates_use_count ON finding_templates(use_count DESC)"
    ).execute(pool).await;

    log::info!("Enhanced finding templates table with additional fields");
    Ok(())
}

/// Seed enhanced built-in finding templates with full metadata
async fn seed_enhanced_finding_templates(pool: &SqlitePool) -> Result<()> {
    use chrono::Utc;
    use uuid::Uuid;

    // Check if we already have system templates
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM finding_templates WHERE is_system = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

    if count.0 > 10 {
        log::info!("System finding templates already seeded");
        return Ok(());
    }

    let now = Utc::now();

    // Define built-in templates
    let templates = vec![
        // SQL Injection
        (
            "sql-injection", "injection", "SQL Injection", "critical",
            r#"A SQL injection vulnerability was identified that allows an attacker to inject malicious SQL statements into application queries. This vulnerability occurs when user-supplied input is incorporated into SQL queries without proper sanitization or parameterization.

The application constructs SQL queries by concatenating user input directly into the query string, enabling attackers to modify the query logic, bypass authentication, access unauthorized data, or execute administrative operations on the database."#,
            "An attacker can exploit this vulnerability to:\n- Extract sensitive data from the database including user credentials, personal information, and business data\n- Modify or delete data, causing data integrity issues\n- Bypass authentication mechanisms\n- Execute administrative operations on the database\n- In some cases, execute operating system commands on the database server",
            r#"1. **Use Parameterized Queries**: Replace dynamic SQL with parameterized queries (prepared statements) that separate SQL code from data.

2. **Input Validation**: Implement strict input validation using allowlists for expected data formats.

3. **Least Privilege**: Ensure database accounts used by the application have minimum necessary privileges.

4. **Error Handling**: Implement generic error messages that don't expose database structure.

Example of secure parameterized query:
```python
# Instead of:
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# Use:
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```"#,
            r#"["https://owasp.org/www-community/attacks/SQL_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/89.html"]"#,
            r#"[89]"#,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8,
            "A03:2021-Injection",
            r#"["T1190"]"#,
            r#"{"pci_dss": ["6.5.1"], "owasp_top_10": ["A03:2021"], "cis": ["18.9"]}"#,
            r#"[{"id": "request", "label": "Vulnerable Request", "placeholder_type": "request_response", "description": "HTTP request showing the SQL injection payload", "required": true}, {"id": "response", "label": "Response Evidence", "placeholder_type": "request_response", "description": "Response showing successful injection", "required": true}, {"id": "screenshot", "label": "Screenshot", "placeholder_type": "screenshot", "description": "Visual proof of exploitation", "required": false}]"#,
        ),
        // XSS Reflected
        (
            "xss-reflected", "xss", "Cross-Site Scripting (XSS) - Reflected", "high",
            r#"A reflected cross-site scripting (XSS) vulnerability was identified where user-supplied input is returned in the HTTP response without proper encoding or validation. This allows an attacker to inject malicious JavaScript code that executes in the context of the victim's browser session.

Reflected XSS occurs when the malicious script is part of the victim's request and is immediately reflected back in the response. The attack typically requires social engineering to trick users into clicking a malicious link."#,
            "An attacker can exploit this vulnerability to:\n- Steal session cookies and hijack user accounts\n- Capture user credentials through fake login forms\n- Redirect users to malicious websites\n- Deface the web application for the victim\n- Perform actions on behalf of the authenticated user\n- Install browser-based keyloggers or cryptominers",
            r#"1. **Output Encoding**: Encode all user-supplied data before rendering in HTML, JavaScript, CSS, or URL contexts.

2. **Content Security Policy**: Implement a strict CSP header to prevent inline script execution.

3. **Input Validation**: Validate and sanitize input on the server side.

4. **HTTPOnly Cookies**: Set the HTTPOnly flag on session cookies to prevent JavaScript access.

5. **Use Security Libraries**: Leverage framework-provided encoding functions.

Example CSP header:
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
```"#,
            r#"["https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/79.html"]"#,
            r#"[79]"#,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1,
            "A03:2021-Injection",
            r#"["T1189"]"#,
            r#"{"pci_dss": ["6.5.7"], "owasp_top_10": ["A03:2021"]}"#,
            r#"[{"id": "payload", "label": "XSS Payload", "placeholder_type": "code_snippet", "description": "The XSS payload used", "required": true}, {"id": "screenshot", "label": "Alert Box Screenshot", "placeholder_type": "screenshot", "description": "Screenshot showing JavaScript execution", "required": true}]"#,
        ),
        // Kerberoasting
        (
            "kerberoasting", "ad", "Kerberoastable Service Account", "high",
            r#"A service account with a Service Principal Name (SPN) was identified that is vulnerable to Kerberoasting. Any authenticated domain user can request a Kerberos TGS ticket for this service, which is encrypted with the service account's NTLM hash. The ticket can then be cracked offline to recover the plaintext password.

Service accounts with weak passwords are particularly vulnerable as they can be cracked quickly using dictionary attacks or brute force."#,
            "An attacker with any valid domain credentials can:\n- Request TGS tickets for the vulnerable service account\n- Crack the ticket offline without generating additional authentication events\n- Obtain the service account's plaintext password\n- Use the compromised account for lateral movement\n- If the service account has elevated privileges, gain domain admin access",
            r#"1. **Use Strong Passwords**: Ensure service account passwords are at least 25 characters with high complexity.

2. **Use Group Managed Service Accounts (gMSA)**: Implement gMSA which automatically rotates passwords.

3. **Limit SPN Assignments**: Only assign SPNs to accounts that require them.

4. **Monitor Kerberos Events**: Enable auditing for Kerberos ticket requests (Event ID 4769).

5. **Implement AES Encryption**: Configure accounts to use AES-256 encryption instead of RC4.

PowerShell to find Kerberoastable accounts:
```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```"#,
            r#"["https://attack.mitre.org/techniques/T1558/003/", "https://adsecurity.org/?p=2293", "https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/"]"#,
            r#"[522]"#,
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1,
            "",
            r#"["T1558.003"]"#,
            r#"{"mitre_attack": ["T1558.003"], "nist_800_53": ["IA-5", "AC-2"]}"#,
            r#"[{"id": "spn", "label": "Service Principal Name", "placeholder_type": "code_snippet", "description": "The vulnerable SPN", "required": true}, {"id": "hash", "label": "TGS Hash", "placeholder_type": "code_snippet", "description": "The extracted Kerberos ticket hash", "required": true}]"#,
        ),
        // Weak SSL/TLS
        (
            "weak-ssl-tls", "cryptography", "Weak SSL/TLS Configuration", "medium",
            r#"The server's SSL/TLS configuration supports outdated protocols or weak cipher suites that are vulnerable to known attacks. This includes support for SSLv3, TLS 1.0, TLS 1.1, or weak ciphers such as RC4, DES, or export-grade cryptography.

Modern security standards require TLS 1.2 or higher with strong cipher suites to protect data in transit from eavesdropping and man-in-the-middle attacks."#,
            "The weak SSL/TLS configuration exposes the application to:\n- BEAST, POODLE, and other protocol downgrade attacks\n- Cipher suite vulnerabilities allowing traffic decryption\n- Man-in-the-middle attacks compromising data confidentiality\n- Non-compliance with PCI DSS and other security standards\n- Potential data breaches exposing sensitive information",
            r#"1. **Disable Legacy Protocols**: Remove support for SSLv2, SSLv3, TLS 1.0, and TLS 1.1.

2. **Use Strong Cipher Suites**: Configure the server to use only strong ciphers with Perfect Forward Secrecy (PFS).

3. **Enable HSTS**: Implement HTTP Strict Transport Security to prevent protocol downgrade attacks.

4. **Regular Updates**: Keep SSL/TLS libraries updated to patch vulnerabilities.

Recommended Nginx configuration:
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers on;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```"#,
            r#"["https://wiki.mozilla.org/Security/Server_Side_TLS", "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"]"#,
            r#"[326, 327]"#,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9,
            "A02:2021-Cryptographic Failures",
            r#"["T1557"]"#,
            r#"{"pci_dss": ["4.1"], "nist_800_53": ["SC-8", "SC-13"]}"#,
            r#"[{"id": "scan_output", "label": "SSL Scan Output", "placeholder_type": "code_snippet", "description": "Output from SSL scanner (testssl.sh, sslyze)", "required": true}]"#,
        ),
        // Missing Security Headers
        (
            "missing-security-headers", "configuration", "Missing Security Headers", "low",
            r#"The web application is missing important HTTP security headers that help protect against common web attacks. Security headers instruct the browser to enable built-in security features and restrict potentially dangerous behaviors.

Missing headers leave the application vulnerable to various client-side attacks that could otherwise be mitigated through proper header configuration."#,
            "Missing security headers increase exposure to:\n- Cross-site scripting (XSS) attacks without CSP\n- Clickjacking attacks without X-Frame-Options\n- MIME type confusion attacks without X-Content-Type-Options\n- Information disclosure through Referrer header\n- Protocol downgrade attacks without HSTS",
            r#"Implement the following security headers:

1. **Content-Security-Policy (CSP)**
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

2. **X-Frame-Options**
```
X-Frame-Options: DENY
```

3. **X-Content-Type-Options**
```
X-Content-Type-Options: nosniff
```

4. **Strict-Transport-Security (HSTS)**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

5. **Referrer-Policy**
```
Referrer-Policy: strict-origin-when-cross-origin
```

6. **Permissions-Policy**
```
Permissions-Policy: geolocation=(), microphone=(), camera=()
```"#,
            r#"["https://owasp.org/www-project-secure-headers/", "https://securityheaders.com/"]"#,
            r#"[693, 1021]"#,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3,
            "A05:2021-Security Misconfiguration",
            r#"[]"#,
            r#"{"owasp_top_10": ["A05:2021"], "pci_dss": ["6.5.10"]}"#,
            r#"[{"id": "headers", "label": "Response Headers", "placeholder_type": "code_snippet", "description": "HTTP response headers showing missing security headers", "required": true}]"#,
        ),
        // IDOR
        (
            "idor", "access-control", "Insecure Direct Object Reference (IDOR)", "high",
            r#"An Insecure Direct Object Reference (IDOR) vulnerability was identified where the application exposes internal object identifiers (such as database IDs) and does not properly verify that the requesting user is authorized to access the referenced object.

By manipulating the object identifier in requests, an attacker can access or modify resources belonging to other users without proper authorization checks."#,
            "An attacker can exploit this vulnerability to:\n- Access other users' personal information and data\n- Modify or delete resources belonging to other users\n- Escalate privileges by accessing admin functionality\n- Exfiltrate sensitive business data\n- Compromise the integrity of the application",
            r#"1. **Implement Proper Authorization**: Verify user permissions before granting access to any resource.

2. **Use Indirect References**: Map internal IDs to per-user indirect references.

3. **Access Control Checks**: Implement server-side access control for every function.

4. **Logging and Monitoring**: Log access attempts and monitor for suspicious patterns.

Example authorization check:
```python
def get_document(document_id, current_user):
    document = Document.query.get(document_id)
    if document.owner_id != current_user.id:
        raise PermissionDenied("Access denied")
    return document
```"#,
            r#"["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References", "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"]"#,
            r#"[639]"#,
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1,
            "A01:2021-Broken Access Control",
            r#"["T1087"]"#,
            r#"{"owasp_top_10": ["A01:2021"], "pci_dss": ["7.1", "7.2"]}"#,
            r#"[{"id": "original", "label": "Original Request", "placeholder_type": "request_response", "description": "Legitimate request with authorized ID", "required": true}, {"id": "modified", "label": "Modified Request", "placeholder_type": "request_response", "description": "Request with another user's ID", "required": true}]"#,
        ),
        // Default Credentials
        (
            "default-credentials", "auth", "Default Credentials", "critical",
            r#"The system is accessible using default, well-known, or easily guessable credentials. These credentials are often documented in product manuals or widely known, allowing attackers to gain unauthorized access without sophisticated attack techniques.

Default credentials are a common attack vector for initial access and often provide administrative-level access to systems."#,
            "Access with default credentials can allow an attacker to:\n- Gain complete administrative control of the system\n- Access, modify, or delete sensitive data\n- Use the compromised system as a pivot point for further attacks\n- Deploy malware or establish persistence\n- Disrupt business operations",
            r#"1. **Change Default Credentials**: Immediately change all default passwords upon deployment.

2. **Force Password Change**: Require users to change passwords on first login.

3. **Password Policy**: Implement strong password requirements.

4. **Account Lockout**: Enable account lockout after failed attempts.

5. **Credential Scanning**: Regularly scan for default credentials in the environment.

6. **Inventory Management**: Maintain an inventory of all systems and their credential status."#,
            r#"["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials", "https://cwe.mitre.org/data/definitions/798.html"]"#,
            r#"[798, 1392]"#,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8,
            "A07:2021-Identification and Authentication Failures",
            r#"["T1078.001"]"#,
            r#"{"owasp_top_10": ["A07:2021"], "pci_dss": ["2.1", "8.2.3"]}"#,
            r#"[{"id": "credentials", "label": "Default Credentials Used", "placeholder_type": "code_snippet", "description": "The default username/password combination", "required": true}, {"id": "screenshot", "label": "Access Screenshot", "placeholder_type": "screenshot", "description": "Screenshot showing successful access", "required": true}]"#,
        ),
        // Open S3 Bucket
        (
            "open-s3-bucket", "cloud", "Publicly Accessible S3 Bucket", "critical",
            r#"An Amazon S3 bucket was identified with overly permissive access control settings, allowing public read and/or write access. This misconfiguration exposes stored objects to unauthorized access and potential data breaches.

S3 buckets often contain sensitive data including backups, configuration files, user uploads, and application data that should not be publicly accessible."#,
            "A publicly accessible S3 bucket can lead to:\n- Exposure of sensitive customer data and PII\n- Unauthorized access to internal documents and backups\n- Compliance violations (GDPR, HIPAA, PCI DSS)\n- Reputational damage from data breaches\n- Data manipulation or deletion if write access is allowed\n- Cryptocurrency mining or malware distribution",
            r#"1. **Block Public Access**: Enable S3 Block Public Access settings at the account level.

2. **Review Bucket Policies**: Audit and restrict bucket policies to necessary principals.

3. **Use IAM Policies**: Implement least-privilege IAM policies for access.

4. **Enable Logging**: Enable S3 access logging for audit trails.

5. **Encryption**: Enable server-side encryption for all objects.

AWS CLI to check bucket ACL:
```bash
aws s3api get-bucket-acl --bucket bucket-name
aws s3api get-bucket-policy --bucket bucket-name
```

Block public access:
```bash
aws s3api put-public-access-block --bucket bucket-name \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```"#,
            r#"["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html", "https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/"]"#,
            r#"[732, 200]"#,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1,
            "A01:2021-Broken Access Control",
            r#"["T1530"]"#,
            r#"{"aws_cis": ["2.1.1", "2.1.2"], "pci_dss": ["7.1"], "nist_800_53": ["AC-3", "AC-6"]}"#,
            r#"[{"id": "bucket", "label": "Bucket Name", "placeholder_type": "code_snippet", "description": "The S3 bucket identifier", "required": true}, {"id": "listing", "label": "Directory Listing", "placeholder_type": "screenshot", "description": "Screenshot showing public bucket contents", "required": false}]"#,
        ),
        // Hardcoded Secrets
        (
            "hardcoded-secrets", "configuration", "Hardcoded Secrets in Source Code", "high",
            r#"Sensitive credentials, API keys, or secrets were found hardcoded in the application source code or configuration files. This practice violates security best practices and exposes secrets to anyone with access to the codebase, including version control history.

Hardcoded secrets are often accidentally committed to public repositories or exposed through source code leaks, leading to unauthorized access to external services and systems."#,
            "Hardcoded secrets can lead to:\n- Unauthorized access to third-party services and APIs\n- Compromise of cloud infrastructure and databases\n- Financial losses from abuse of paid services\n- Data breaches through compromised integrations\n- Difficulty rotating credentials after exposure\n- Supply chain attacks",
            r#"1. **Use Environment Variables**: Store secrets in environment variables, not code.

2. **Secrets Management**: Implement a secrets manager (HashiCorp Vault, AWS Secrets Manager).

3. **Git Pre-commit Hooks**: Use tools like git-secrets to prevent committing secrets.

4. **Secret Scanning**: Regularly scan repositories for exposed secrets.

5. **Rotate Credentials**: Immediately rotate any exposed credentials.

Example using environment variables:
```python
# Instead of:
API_KEY = "sk-1234567890abcdef"

# Use:
import os
API_KEY = os.environ.get('API_KEY')
```"#,
            r#"["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/798.html"]"#,
            r#"[798, 259]"#,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 7.1,
            "A02:2021-Cryptographic Failures",
            r#"["T1552.001"]"#,
            r#"{"owasp_top_10": ["A02:2021"], "soc2": ["CC6.1"]}"#,
            r#"[{"id": "secret", "label": "Secret Location", "placeholder_type": "code_snippet", "description": "File and line where secret was found (redact actual value)", "required": true}]"#,
        ),
        // Path Traversal
        (
            "path-traversal", "web", "Path Traversal", "high",
            r#"A path traversal vulnerability was identified that allows an attacker to access files and directories outside the intended web root. By manipulating file path parameters with sequences like "../", an attacker can read sensitive files from the server filesystem.

This vulnerability can expose configuration files, source code, system files, and other sensitive data that should not be accessible through the web application."#,
            "An attacker can exploit path traversal to:\n- Read sensitive system files (/etc/passwd, /etc/shadow)\n- Access application configuration and credentials\n- View source code and discover additional vulnerabilities\n- Read database files and backups\n- Access other users' files in multi-tenant environments",
            r#"1. **Input Validation**: Validate and sanitize all file path inputs.

2. **Use Allowlists**: Only allow access to specific, known files or directories.

3. **Canonicalization**: Resolve the full path and verify it's within allowed directories.

4. **Chroot/Jail**: Run the application in a restricted directory environment.

5. **Least Privilege**: Run the application with minimal filesystem permissions.

Example secure file access:
```python
import os

ALLOWED_DIR = '/var/www/files'

def get_file(filename):
    # Remove path traversal sequences
    safe_name = os.path.basename(filename)
    full_path = os.path.join(ALLOWED_DIR, safe_name)

    # Verify the resolved path is within allowed directory
    if not os.path.realpath(full_path).startswith(os.path.realpath(ALLOWED_DIR)):
        raise SecurityError("Path traversal detected")

    return open(full_path, 'rb').read()
```"#,
            r#"["https://owasp.org/www-community/attacks/Path_Traversal", "https://cwe.mitre.org/data/definitions/22.html"]"#,
            r#"[22, 23]"#,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5,
            "A01:2021-Broken Access Control",
            r#"["T1083"]"#,
            r#"{"owasp_top_10": ["A01:2021"], "pci_dss": ["6.5.8"]}"#,
            r#"[{"id": "request", "label": "Traversal Request", "placeholder_type": "request_response", "description": "HTTP request with path traversal payload", "required": true}, {"id": "response", "label": "File Contents", "placeholder_type": "code_snippet", "description": "Contents of accessed file", "required": true}]"#,
        ),
    ];

    let template_count = templates.len();
    for (id, category, title, severity, description, impact, remediation, references, cwe_ids, cvss_vector, cvss_score, owasp_category, mitre_attack_ids, compliance_mappings, evidence_placeholders) in templates {
        let template_id = format!("system-{}", id);
        let _ = sqlx::query(
            r#"
            INSERT OR IGNORE INTO finding_templates (
                id, user_id, category, title, severity, description, impact, remediation,
                "references", cwe_ids, cvss_vector, cvss_score, tags, is_system,
                owasp_category, mitre_attack_ids, compliance_mappings, evidence_placeholders,
                created_at, updated_at
            )
            VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, '[]', 1, ?12, ?13, ?14, ?15, ?16, ?16)
            "#
        )
        .bind(&template_id)
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
        .bind(owasp_category)
        .bind(mitre_attack_ids)
        .bind(compliance_mappings)
        .bind(evidence_placeholders)
        .bind(now)
        .execute(pool)
        .await;
    }

    log::info!("Seeded {} built-in finding templates", template_count);
    Ok(())
}

/// Create password cracking tables
async fn create_cracking_tables(pool: &SqlitePool) -> Result<()> {
    // Cracking jobs table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cracking_jobs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            hash_type INTEGER NOT NULL,
            cracker_type TEXT NOT NULL DEFAULT 'hashcat',
            hashes_json TEXT NOT NULL,
            config_json TEXT NOT NULL DEFAULT '{}',
            progress_json TEXT,
            results_json TEXT,
            error_message TEXT,
            source_campaign_id TEXT,
            customer_id TEXT,
            engagement_id TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (customer_id) REFERENCES customers(id),
            FOREIGN KEY (engagement_id) REFERENCES engagements(id)
        )
        "#
    )
    .execute(pool)
    .await?;

    // Indexes for cracking_jobs
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_cracking_jobs_user ON cracking_jobs(user_id)")
        .execute(pool)
        .await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_cracking_jobs_status ON cracking_jobs(status)")
        .execute(pool)
        .await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_cracking_jobs_customer ON cracking_jobs(customer_id)")
        .execute(pool)
        .await;

    // Cracked credentials table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cracked_credentials (
            id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            hash TEXT NOT NULL,
            plaintext TEXT NOT NULL,
            hash_type INTEGER,
            username TEXT,
            domain TEXT,
            asset_id TEXT,
            cracked_at TEXT NOT NULL,
            FOREIGN KEY (job_id) REFERENCES cracking_jobs(id) ON DELETE CASCADE,
            FOREIGN KEY (asset_id) REFERENCES assets(id),
            UNIQUE(hash, job_id)
        )
        "#
    )
    .execute(pool)
    .await?;

    // Indexes for cracked_credentials
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_cracked_creds_job ON cracked_credentials(job_id)")
        .execute(pool)
        .await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_cracked_creds_asset ON cracked_credentials(asset_id)")
        .execute(pool)
        .await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_cracked_creds_hash ON cracked_credentials(hash)")
        .execute(pool)
        .await;

    // Wordlists table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cracking_wordlists (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            name TEXT NOT NULL,
            description TEXT,
            file_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            line_count INTEGER NOT NULL DEFAULT 0,
            is_builtin INTEGER NOT NULL DEFAULT 0,
            category TEXT NOT NULL DEFAULT 'custom',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#
    )
    .execute(pool)
    .await?;

    // Rule files table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cracking_rules (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            name TEXT NOT NULL,
            description TEXT,
            file_path TEXT NOT NULL,
            rule_count INTEGER NOT NULL DEFAULT 0,
            cracker_type TEXT NOT NULL DEFAULT 'hashcat',
            is_builtin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#
    )
    .execute(pool)
    .await?;

    log::info!("Created password cracking tables");
    Ok(())
}

/// Create Attack Surface Management tables
async fn create_asm_tables(pool: &SqlitePool) -> Result<()> {
    // ASM monitors table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asm_monitors (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            domains TEXT NOT NULL,
            discovery_config TEXT NOT NULL,
            schedule TEXT NOT NULL,
            alert_config TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            last_run_at TEXT,
            next_run_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // ASM baselines table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asm_baselines (
            id TEXT PRIMARY KEY,
            monitor_id TEXT NOT NULL,
            assets TEXT NOT NULL,
            summary TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (monitor_id) REFERENCES asm_monitors(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // ASM changes table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asm_changes (
            id TEXT PRIMARY KEY,
            monitor_id TEXT NOT NULL,
            baseline_id TEXT NOT NULL,
            change_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            hostname TEXT NOT NULL,
            details TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            acknowledged INTEGER DEFAULT 0,
            acknowledged_by TEXT,
            acknowledged_at TEXT,
            FOREIGN KEY (monitor_id) REFERENCES asm_monitors(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // ASM authorized assets table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asm_authorized_assets (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            hostname_pattern TEXT NOT NULL,
            ip_ranges TEXT,
            description TEXT,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // ASM risk scores table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS asm_risk_scores (
            id TEXT PRIMARY KEY,
            asset_id TEXT,
            hostname TEXT NOT NULL,
            overall_score INTEGER NOT NULL,
            factors TEXT NOT NULL,
            calculated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asm_monitors_user_id ON asm_monitors(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asm_baselines_monitor_id ON asm_baselines(monitor_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asm_changes_monitor_id ON asm_changes(monitor_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asm_changes_detected_at ON asm_changes(detected_at)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asm_changes_acknowledged ON asm_changes(acknowledged)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_asm_risk_scores_hostname ON asm_risk_scores(hostname)")
        .execute(pool)
        .await?;

    log::info!("Created ASM tables");
    Ok(())
}

/// Create AI chat tables
async fn create_chat_tables(pool: &SqlitePool) -> Result<()> {
    // Chat conversations table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS chat_conversations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            title TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Chat messages table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS chat_messages (
            id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            context_summary TEXT,
            tokens_used INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (conversation_id) REFERENCES chat_conversations(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_chat_conversations_user ON chat_conversations(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation ON chat_messages(conversation_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at ON chat_messages(created_at)")
        .execute(pool)
        .await?;

    log::info!("Created AI chat tables");
    Ok(())
}

/// Create ABAC permissions system and organization hierarchy tables
async fn create_permissions_system(pool: &SqlitePool) -> Result<()> {
    // =========================================================================
    // Organizational Hierarchy Tables
    // =========================================================================

    // Organizations (top-level tenant)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS organizations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            description TEXT,
            settings TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Departments within organizations
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS departments (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            name TEXT NOT NULL,
            slug TEXT NOT NULL,
            description TEXT,
            parent_department_id TEXT,
            manager_user_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (parent_department_id) REFERENCES departments(id) ON DELETE SET NULL,
            FOREIGN KEY (manager_user_id) REFERENCES users(id) ON DELETE SET NULL,
            UNIQUE(organization_id, slug)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Teams within departments
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS teams (
            id TEXT PRIMARY KEY,
            department_id TEXT NOT NULL,
            name TEXT NOT NULL,
            slug TEXT NOT NULL,
            description TEXT,
            team_lead_user_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE CASCADE,
            FOREIGN KEY (team_lead_user_id) REFERENCES users(id) ON DELETE SET NULL,
            UNIQUE(department_id, slug)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // User-Organization membership
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_organizations (
            user_id TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            org_role TEXT NOT NULL DEFAULT 'member',
            joined_at TEXT NOT NULL,
            invited_by TEXT,
            PRIMARY KEY (user_id, organization_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // User-Team membership
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_teams (
            user_id TEXT NOT NULL,
            team_id TEXT NOT NULL,
            team_role TEXT NOT NULL DEFAULT 'member',
            joined_at TEXT NOT NULL,
            added_by TEXT,
            PRIMARY KEY (user_id, team_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
            FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Indexes for hierarchy queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_departments_org ON departments(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_departments_parent ON departments(parent_department_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_teams_department ON teams(department_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_orgs_user ON user_organizations(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_orgs_org ON user_organizations(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_teams_user ON user_teams(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_teams_team ON user_teams(team_id)")
        .execute(pool)
        .await?;

    // =========================================================================
    // Permission and Policy Tables
    // =========================================================================

    // Resource types
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS resource_types (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Actions
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS actions (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Permissions (atomic units)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS permissions (
            id TEXT PRIMARY KEY,
            resource_type_id TEXT NOT NULL,
            action_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            is_system INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (resource_type_id) REFERENCES resource_types(id) ON DELETE CASCADE,
            FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE,
            UNIQUE(resource_type_id, action_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // ABAC Policies
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS policies (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            resource_type_id TEXT NOT NULL,
            effect TEXT NOT NULL DEFAULT 'allow',
            priority INTEGER NOT NULL DEFAULT 100,
            conditions TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            is_system INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (resource_type_id) REFERENCES resource_types(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Policy-Action mappings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS policy_actions (
            policy_id TEXT NOT NULL,
            action_id TEXT NOT NULL,
            PRIMARY KEY (policy_id, action_id),
            FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE,
            FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Indexes for permission queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource_type_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_policies_resource ON policies(resource_type_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_policies_priority ON policies(priority DESC)")
        .execute(pool)
        .await?;

    // =========================================================================
    // Role Templates and Custom Roles
    // =========================================================================

    // Role templates (predefined, system-managed)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS role_templates (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            description TEXT,
            icon TEXT,
            color TEXT,
            is_system INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Template-Permission mappings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS role_template_permissions (
            template_id TEXT NOT NULL,
            permission_id TEXT NOT NULL,
            include_conditions INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (template_id, permission_id),
            FOREIGN KEY (template_id) REFERENCES role_templates(id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Template-Policy mappings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS role_template_policies (
            template_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            PRIMARY KEY (template_id, policy_id),
            FOREIGN KEY (template_id) REFERENCES role_templates(id) ON DELETE CASCADE,
            FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Custom roles (organization-specific)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS custom_roles (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            based_on_template_id TEXT,
            name TEXT NOT NULL,
            display_name TEXT NOT NULL,
            description TEXT,
            icon TEXT,
            color TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (based_on_template_id) REFERENCES role_templates(id) ON DELETE SET NULL,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
            UNIQUE(organization_id, name)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Custom role permissions (overrides)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS custom_role_permissions (
            role_id TEXT NOT NULL,
            permission_id TEXT NOT NULL,
            granted INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (role_id, permission_id),
            FOREIGN KEY (role_id) REFERENCES custom_roles(id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Custom role policies
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS custom_role_policies (
            role_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            PRIMARY KEY (role_id, policy_id),
            FOREIGN KEY (role_id) REFERENCES custom_roles(id) ON DELETE CASCADE,
            FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // User role assignments
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_role_assignments (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            role_type TEXT NOT NULL,
            role_id TEXT NOT NULL,
            scope_type TEXT,
            scope_id TEXT,
            assigned_at TEXT NOT NULL,
            assigned_by TEXT,
            expires_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // User permission overrides (exceptions)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_permission_overrides (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            permission_id TEXT NOT NULL,
            granted INTEGER NOT NULL,
            reason TEXT,
            granted_by TEXT NOT NULL,
            granted_at TEXT NOT NULL,
            expires_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
            FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Indexes for role queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_custom_roles_org ON custom_roles(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_role_assignments_user ON user_role_assignments(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_role_assignments_org ON user_role_assignments(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_permission_overrides_user ON user_permission_overrides(user_id)")
        .execute(pool)
        .await?;

    // =========================================================================
    // Resource Ownership and Sharing
    // =========================================================================

    // Resource ownership tracking
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS resource_ownership (
            id TEXT PRIMARY KEY,
            resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            owner_type TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
            UNIQUE(resource_type, resource_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Resource sharing
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS resource_shares (
            id TEXT PRIMARY KEY,
            resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            shared_with_type TEXT NOT NULL,
            shared_with_id TEXT NOT NULL,
            permission_level TEXT NOT NULL,
            shared_by TEXT NOT NULL,
            shared_at TEXT NOT NULL,
            expires_at TEXT,
            FOREIGN KEY (shared_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Permission cache
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS permission_cache (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            cache_key TEXT NOT NULL,
            effective_permissions TEXT NOT NULL,
            computed_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            UNIQUE(user_id, organization_id, cache_key)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Indexes for ownership/sharing queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_resource_ownership_type_id ON resource_ownership(resource_type, resource_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_resource_ownership_owner ON resource_ownership(owner_type, owner_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_resource_shares_resource ON resource_shares(resource_type, resource_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_resource_shares_shared_with ON resource_shares(shared_with_type, shared_with_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_permission_cache_user ON permission_cache(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_permission_cache_expires ON permission_cache(expires_at)")
        .execute(pool)
        .await?;

    // =========================================================================
    // Seed Data
    // =========================================================================

    // Seed resource types
    let now = chrono::Utc::now();
    let resource_types = vec![
        ("scans", "Network and vulnerability scans"),
        ("reports", "Generated reports"),
        ("assets", "Asset inventory"),
        ("vulnerabilities", "Vulnerability tracking"),
        ("users", "User accounts"),
        ("settings", "System settings"),
        ("customers", "CRM customers"),
        ("engagements", "Customer engagements"),
        ("audit_logs", "Audit logs"),
    ];

    for (name, desc) in resource_types {
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO resource_types (id, name, description, created_at) VALUES (?, ?, ?, ?)"
        )
        .bind(name)
        .bind(name)
        .bind(desc)
        .bind(now)
        .execute(pool)
        .await;
    }

    // Seed actions
    let actions = vec![
        ("create", "Create new resources"),
        ("read", "View resources"),
        ("update", "Modify existing resources"),
        ("delete", "Remove resources"),
        ("execute", "Execute/run resources"),
        ("share", "Share resources with others"),
        ("export", "Export/download resources"),
    ];

    for (name, desc) in actions {
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO actions (id, name, description, created_at) VALUES (?, ?, ?, ?)"
        )
        .bind(name)
        .bind(name)
        .bind(desc)
        .bind(now)
        .execute(pool)
        .await;
    }

    // Seed permissions (resource_type:action combinations)
    let permissions = vec![
        ("scans:create", "scans", "create", "Create Scans"),
        ("scans:read", "scans", "read", "View Scans"),
        ("scans:update", "scans", "update", "Update Scans"),
        ("scans:delete", "scans", "delete", "Delete Scans"),
        ("scans:execute", "scans", "execute", "Execute Scans"),
        ("scans:share", "scans", "share", "Share Scans"),
        ("scans:export", "scans", "export", "Export Scans"),
        ("reports:create", "reports", "create", "Create Reports"),
        ("reports:read", "reports", "read", "View Reports"),
        ("reports:update", "reports", "update", "Update Reports"),
        ("reports:delete", "reports", "delete", "Delete Reports"),
        ("reports:export", "reports", "export", "Export Reports"),
        ("assets:create", "assets", "create", "Create Assets"),
        ("assets:read", "assets", "read", "View Assets"),
        ("assets:update", "assets", "update", "Update Assets"),
        ("assets:delete", "assets", "delete", "Delete Assets"),
        ("vulnerabilities:read", "vulnerabilities", "read", "View Vulnerabilities"),
        ("vulnerabilities:update", "vulnerabilities", "update", "Update Vulnerabilities"),
        ("users:create", "users", "create", "Create Users"),
        ("users:read", "users", "read", "View Users"),
        ("users:update", "users", "update", "Update Users"),
        ("users:delete", "users", "delete", "Delete Users"),
        ("settings:read", "settings", "read", "View Settings"),
        ("settings:update", "settings", "update", "Update Settings"),
        ("customers:create", "customers", "create", "Create Customers"),
        ("customers:read", "customers", "read", "View Customers"),
        ("customers:update", "customers", "update", "Update Customers"),
        ("customers:delete", "customers", "delete", "Delete Customers"),
        ("engagements:create", "engagements", "create", "Create Engagements"),
        ("engagements:read", "engagements", "read", "View Engagements"),
        ("engagements:update", "engagements", "update", "Update Engagements"),
        ("engagements:delete", "engagements", "delete", "Delete Engagements"),
        ("audit_logs:read", "audit_logs", "read", "View Audit Logs"),
    ];

    for (id, resource_type, action, name) in permissions {
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO permissions (id, resource_type_id, action_id, name, is_system, created_at) VALUES (?, ?, ?, ?, 1, ?)"
        )
        .bind(id)
        .bind(resource_type)
        .bind(action)
        .bind(name)
        .bind(now)
        .execute(pool)
        .await;
    }

    // Seed role templates
    let role_templates = vec![
        ("admin", "Administrator", "Full system access", "shield", "#ef4444"),
        ("analyst", "Security Analyst", "Scans, reports, and vulnerability management", "search", "#3b82f6"),
        ("viewer", "Viewer", "Read-only access to own resources", "eye", "#6b7280"),
        ("auditor", "Auditor", "Read-only access for compliance auditing", "clipboard-check", "#8b5cf6"),
        ("engineer", "Security Engineer", "Scans and asset management", "wrench", "#10b981"),
        ("manager", "Team Manager", "Team resources management", "users", "#f59e0b"),
    ];

    for (id, display_name, desc, icon, color) in role_templates {
        let _ = sqlx::query(
            r#"INSERT OR IGNORE INTO role_templates
               (id, name, display_name, description, icon, color, is_system, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)"#
        )
        .bind(id)
        .bind(id)
        .bind(display_name)
        .bind(desc)
        .bind(icon)
        .bind(color)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await;
    }

    // Seed default policies
    let policies = vec![
        ("owner_full_access", "Owner Full Access", "scans", r#"{"type":"owner","field":"owner_id","operator":"eq","value":"$user_id"}"#),
        ("team_member_read", "Team Member Read", "scans", r#"{"type":"team_member","field":"owner_team_id","operator":"in","value":"$user_teams"}"#),
    ];

    for (id, name, resource_type, conditions) in policies {
        let _ = sqlx::query(
            r#"INSERT OR IGNORE INTO policies
               (id, name, description, resource_type_id, effect, priority, conditions, is_active, is_system, created_at, updated_at)
               VALUES (?, ?, ?, ?, 'allow', 100, ?, 1, 1, ?, ?)"#
        )
        .bind(id)
        .bind(name)
        .bind(name)
        .bind(resource_type)
        .bind(conditions)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await;
    }

    // Assign all permissions to admin template
    let _ = sqlx::query(
        r#"INSERT OR IGNORE INTO role_template_permissions (template_id, permission_id, include_conditions)
           SELECT 'admin', id, 0 FROM permissions"#
    )
    .execute(pool)
    .await;

    // Assign basic permissions to analyst template
    let analyst_perms = vec![
        "scans:create", "scans:read", "scans:update", "scans:delete", "scans:execute", "scans:export",
        "reports:create", "reports:read", "reports:update", "reports:delete", "reports:export",
        "assets:read", "vulnerabilities:read", "vulnerabilities:update",
    ];
    for perm in analyst_perms {
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO role_template_permissions (template_id, permission_id, include_conditions) VALUES ('analyst', ?, 1)"
        )
        .bind(perm)
        .execute(pool)
        .await;
    }

    // Assign read permissions to viewer template (with conditions)
    let viewer_perms = vec!["scans:read", "reports:read", "assets:read", "vulnerabilities:read"];
    for perm in viewer_perms {
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO role_template_permissions (template_id, permission_id, include_conditions) VALUES ('viewer', ?, 1)"
        )
        .bind(perm)
        .execute(pool)
        .await;
    }

    // Assign audit permissions to auditor template (no conditions - can view all)
    let auditor_perms = vec![
        "scans:read", "reports:read", "assets:read", "vulnerabilities:read", "audit_logs:read",
        "customers:read", "engagements:read", "users:read",
    ];
    for perm in auditor_perms {
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO role_template_permissions (template_id, permission_id, include_conditions) VALUES ('auditor', ?, 0)"
        )
        .bind(perm)
        .execute(pool)
        .await;
    }

    // Assign permissions to engineer template
    let engineer_perms = vec![
        "scans:create", "scans:read", "scans:update", "scans:execute", "scans:export",
        "assets:create", "assets:read", "assets:update", "assets:delete",
        "vulnerabilities:read",
    ];
    for perm in engineer_perms {
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO role_template_permissions (template_id, permission_id, include_conditions) VALUES ('engineer', ?, 1)"
        )
        .bind(perm)
        .execute(pool)
        .await;
    }

    // Assign permissions to manager template
    let manager_perms = vec![
        "scans:read", "scans:update", "scans:share",
        "reports:create", "reports:read", "reports:update", "reports:share", "reports:export",
        "users:read", "customers:read", "engagements:read",
    ];
    for perm in manager_perms {
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO role_template_permissions (template_id, permission_id, include_conditions) VALUES ('manager', ?, 1)"
        )
        .bind(perm)
        .execute(pool)
        .await;
    }

    // =========================================================================
    // Migrate Existing Data
    // =========================================================================

    // Create default organization for existing users
    let default_org_id = "org_default";
    let _ = sqlx::query(
        r#"INSERT OR IGNORE INTO organizations (id, name, slug, description, is_active, created_at, updated_at)
           VALUES (?, 'Default Organization', 'default', 'Auto-created for existing users', 1, ?, ?)"#
    )
    .bind(default_org_id)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await;

    // Add existing users to default organization
    let _ = sqlx::query(
        r#"INSERT OR IGNORE INTO user_organizations (user_id, organization_id, org_role, joined_at)
           SELECT id, ?, 'member', ? FROM users"#
    )
    .bind(default_org_id)
    .bind(now)
    .execute(pool)
    .await;

    // Migrate existing user_roles to user_role_assignments
    let _ = sqlx::query(
        r#"INSERT OR IGNORE INTO user_role_assignments (id, user_id, organization_id, role_type, role_id, assigned_at, assigned_by, is_active)
           SELECT
               hex(randomblob(16)),
               ur.user_id,
               ?,
               'template',
               ur.role_id,
               ur.assigned_at,
               ur.assigned_by,
               1
           FROM user_roles ur
           WHERE ur.role_id IN ('admin', 'user', 'auditor', 'viewer')"#
    )
    .bind(default_org_id)
    .execute(pool)
    .await;

    // Map old 'user' role to 'analyst' template
    let _ = sqlx::query(
        r#"UPDATE user_role_assignments SET role_id = 'analyst' WHERE role_id = 'user'"#
    )
    .execute(pool)
    .await;

    // Create resource ownership for existing scans
    let _ = sqlx::query(
        r#"INSERT OR IGNORE INTO resource_ownership (id, resource_type, resource_id, owner_type, owner_id, created_at, created_by)
           SELECT
               hex(randomblob(16)),
               'scans',
               id,
               'user',
               user_id,
               created_at,
               user_id
           FROM scan_results
           WHERE user_id IS NOT NULL"#
    )
    .execute(pool)
    .await;

    log::info!("Created ABAC permissions system tables and seeded data");
    Ok(())
}

/// Add organization_id to data tables for multi-tenant isolation
async fn add_organization_id_to_data_tables(pool: &SqlitePool) -> Result<()> {
    // Helper function to check if column exists
    async fn has_column(pool: &SqlitePool, table: &str, column: &str) -> bool {
        let query = format!("PRAGMA table_info({})", table);
        let info: Vec<(i64, String, String, i64, Option<String>, i64)> =
            sqlx::query_as(&query)
                .fetch_all(pool)
                .await
                .unwrap_or_default();
        info.iter().any(|(_, name, _, _, _, _)| name == column)
    }

    // Get default organization id for migrating existing data
    let default_org: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM organizations WHERE slug = 'default-org' LIMIT 1"
    )
    .fetch_optional(pool)
    .await?;
    let default_org_id = default_org.map(|(id,)| id);

    // Tables to add organization_id to
    let tables = [
        "scan_results",
        "reports",
        "assets",
        "vulnerability_tracking",
        "scan_templates",
        "target_groups",
        "scheduled_scans",
        "finding_templates",
        "scheduled_reports",
        "asset_groups",
        "dns_recon_results",
    ];

    for table in tables {
        if !has_column(pool, table, "organization_id").await {
            // Add the column
            let alter_query = format!(
                "ALTER TABLE {} ADD COLUMN organization_id TEXT REFERENCES organizations(id)",
                table
            );
            let _ = sqlx::query(&alter_query).execute(pool).await;

            // Create index for efficient org-scoped queries
            let index_query = format!(
                "CREATE INDEX IF NOT EXISTS idx_{}_organization_id ON {}(organization_id)",
                table, table
            );
            let _ = sqlx::query(&index_query).execute(pool).await;

            // Migrate existing data to default organization
            if let Some(ref org_id) = default_org_id {
                let update_query = format!(
                    "UPDATE {} SET organization_id = ? WHERE organization_id IS NULL",
                    table
                );
                let _ = sqlx::query(&update_query)
                    .bind(org_id)
                    .execute(pool)
                    .await;
            }
        }
    }

    // Add compound indexes for common query patterns
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_scans_org_status ON scan_results(organization_id, status)"
    ).execute(pool).await;

    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_scans_org_created ON scan_results(organization_id, created_at)"
    ).execute(pool).await;

    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_assets_org_type ON assets(organization_id, asset_type)"
    ).execute(pool).await;

    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_vuln_org_status ON vulnerability_tracking(organization_id, status)"
    ).execute(pool).await;

    log::info!("Added organization_id to data tables for multi-tenant isolation");
    Ok(())
}

/// Create organization quotas and usage tracking tables
async fn create_organization_quotas_tables(pool: &SqlitePool) -> Result<()> {
    // Organization quotas table - defines limits for each organization
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS organization_quotas (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL UNIQUE,
            max_users INTEGER NOT NULL DEFAULT 10,
            max_scans_per_day INTEGER NOT NULL DEFAULT 50,
            max_concurrent_scans INTEGER NOT NULL DEFAULT 5,
            max_assets INTEGER NOT NULL DEFAULT 1000,
            max_reports_per_month INTEGER NOT NULL DEFAULT 100,
            max_storage_mb INTEGER NOT NULL DEFAULT 5120,
            max_api_requests_per_hour INTEGER NOT NULL DEFAULT 1000,
            max_scheduled_scans INTEGER NOT NULL DEFAULT 20,
            max_teams INTEGER NOT NULL DEFAULT 10,
            max_departments INTEGER NOT NULL DEFAULT 5,
            max_custom_roles INTEGER NOT NULL DEFAULT 10,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Quota usage tracking table - tracks actual usage per period
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS organization_quota_usage (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            quota_type TEXT NOT NULL,
            current_value INTEGER NOT NULL DEFAULT 0,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            UNIQUE(organization_id, quota_type, period_start)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient lookups
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_org_quotas_org_id ON organization_quotas(organization_id)"
    ).execute(pool).await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_quota_usage_org_type ON organization_quota_usage(organization_id, quota_type)"
    ).execute(pool).await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_quota_usage_period ON organization_quota_usage(period_start, period_end)"
    ).execute(pool).await?;

    // Create default quotas for existing organizations that don't have quotas
    let _ = sqlx::query(
        r#"
        INSERT OR IGNORE INTO organization_quotas (
            id, organization_id, max_users, max_scans_per_day, max_concurrent_scans,
            max_assets, max_reports_per_month, max_storage_mb, max_api_requests_per_hour,
            max_scheduled_scans, max_teams, max_departments, max_custom_roles,
            created_at, updated_at
        )
        SELECT
            hex(randomblob(16)),
            id,
            10, 50, 5, 1000, 100, 5120, 1000, 20, 10, 5, 10,
            datetime('now'),
            datetime('now')
        FROM organizations
        WHERE id NOT IN (SELECT organization_id FROM organization_quotas)
        "#,
    )
    .execute(pool)
    .await;

    log::info!("Created organization quotas tables");
    Ok(())
}

// ============================================================================
// Enhanced Secret Scanning Tables
// ============================================================================

/// Create enhanced secret scanning tables for git, filesystem, and entropy-based detection
async fn create_enhanced_secret_scanning_tables(pool: &SqlitePool) -> Result<()> {
    // Add new columns to existing secret_findings table
    let _ = sqlx::query("ALTER TABLE secret_findings ADD COLUMN entropy_score REAL")
        .execute(pool)
        .await;

    let _ = sqlx::query("ALTER TABLE secret_findings ADD COLUMN detection_method TEXT DEFAULT 'pattern'")
        .execute(pool)
        .await;

    // Create git_secret_scans table for tracking git repository scan jobs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS git_secret_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            repository_url TEXT,
            repository_path TEXT,
            branch TEXT DEFAULT 'HEAD',
            scan_history INTEGER NOT NULL DEFAULT 0,
            history_depth INTEGER DEFAULT 100,
            status TEXT NOT NULL DEFAULT 'pending',
            finding_count INTEGER DEFAULT 0,
            files_scanned INTEGER DEFAULT 0,
            commits_scanned INTEGER DEFAULT 0,
            error_message TEXT,
            started_at TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create git_secret_findings table to extend secret findings with git-specific info
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS git_secret_findings (
            id TEXT PRIMARY KEY,
            git_scan_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            commit_sha TEXT NOT NULL,
            commit_author TEXT,
            commit_email TEXT,
            commit_date TEXT,
            commit_message TEXT,
            file_path TEXT NOT NULL,
            is_current INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (git_scan_id) REFERENCES git_secret_scans(id) ON DELETE CASCADE,
            FOREIGN KEY (finding_id) REFERENCES secret_findings(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create filesystem_secret_scans table for tracking filesystem scan jobs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS filesystem_secret_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            scan_paths TEXT NOT NULL,
            recursive INTEGER NOT NULL DEFAULT 1,
            max_depth INTEGER DEFAULT 0,
            include_patterns TEXT,
            exclude_patterns TEXT,
            max_file_size INTEGER DEFAULT 10485760,
            entropy_detection INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'pending',
            finding_count INTEGER DEFAULT 0,
            files_scanned INTEGER DEFAULT 0,
            bytes_scanned INTEGER DEFAULT 0,
            files_skipped INTEGER DEFAULT 0,
            directories_scanned INTEGER DEFAULT 0,
            error_message TEXT,
            started_at TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create filesystem_secret_findings table to extend secret findings with file-specific info
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS filesystem_secret_findings (
            id TEXT PRIMARY KEY,
            fs_scan_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            file_path TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            file_modified TEXT,
            file_owner TEXT,
            file_permissions TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (fs_scan_id) REFERENCES filesystem_secret_scans(id) ON DELETE CASCADE,
            FOREIGN KEY (finding_id) REFERENCES secret_findings(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_secret_scans_user ON git_secret_scans(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_secret_scans_status ON git_secret_scans(status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_secret_findings_scan ON git_secret_findings(git_scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_secret_findings_commit ON git_secret_findings(commit_sha)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_fs_secret_scans_user ON filesystem_secret_scans(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_fs_secret_scans_status ON filesystem_secret_scans(status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_fs_secret_findings_scan ON filesystem_secret_findings(fs_scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_secret_findings_detection ON secret_findings(detection_method)")
        .execute(pool)
        .await?;

    log::info!("Created enhanced secret scanning tables");
    Ok(())
}

/// Create CI/CD Pipeline Security scanning tables
async fn create_cicd_pipeline_scan_tables(pool: &SqlitePool) -> Result<()> {
    // Create cicd_pipeline_scans table for tracking pipeline scan jobs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cicd_pipeline_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            organization_id TEXT,
            scan_type TEXT NOT NULL,
            repository_url TEXT,
            branch TEXT,
            commit_sha TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            finding_count INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            info_count INTEGER DEFAULT 0,
            files_scanned INTEGER DEFAULT 0,
            duration_ms INTEGER DEFAULT 0,
            error_message TEXT,
            started_at TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create cicd_pipeline_findings table for individual findings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cicd_pipeline_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            workflow_file TEXT NOT NULL,
            job_name TEXT,
            step_name TEXT,
            line_number INTEGER,
            column_number INTEGER,
            code_snippet TEXT,
            remediation TEXT NOT NULL,
            cwe_id TEXT,
            status TEXT DEFAULT 'open',
            false_positive INTEGER DEFAULT 0,
            suppressed INTEGER DEFAULT 0,
            suppressed_by TEXT,
            suppressed_at TEXT,
            suppression_reason TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES cicd_pipeline_scans(id) ON DELETE CASCADE,
            FOREIGN KEY (suppressed_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create cicd_pipeline_rules table for custom rules and rule metadata
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cicd_pipeline_rules (
            id TEXT PRIMARY KEY,
            platform TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            remediation TEXT NOT NULL,
            cwe_id TEXT,
            reference_urls TEXT,
            is_enabled INTEGER DEFAULT 1,
            is_custom INTEGER DEFAULT 0,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create cicd_rule_suppressions table for global rule suppressions
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS cicd_rule_suppressions (
            id TEXT PRIMARY KEY,
            organization_id TEXT,
            rule_id TEXT NOT NULL,
            repository_pattern TEXT,
            reason TEXT NOT NULL,
            expires_at TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_scans_user ON cicd_pipeline_scans(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_scans_org ON cicd_pipeline_scans(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_scans_status ON cicd_pipeline_scans(status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_scans_type ON cicd_pipeline_scans(scan_type)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_findings_scan ON cicd_pipeline_findings(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_findings_severity ON cicd_pipeline_findings(severity)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_findings_status ON cicd_pipeline_findings(status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_cicd_findings_rule ON cicd_pipeline_findings(rule_id)")
        .execute(pool)
        .await?;

    log::info!("Created CI/CD Pipeline Security scanning tables");
    Ok(())
}

/// Create Kubernetes Security scanning tables
async fn create_k8s_security_tables(pool: &SqlitePool) -> Result<()> {
    // Main K8s security scan table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS k8s_security_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            organization_id TEXT,
            cluster_name TEXT,
            cluster_version TEXT,
            k8s_context TEXT,
            namespaces TEXT,
            scan_types TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            total_findings INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            info_count INTEGER DEFAULT 0,
            cis_score REAL,
            pss_compliant_baseline INTEGER DEFAULT 0,
            pss_compliant_restricted INTEGER DEFAULT 0,
            rbac_findings_count INTEGER DEFAULT 0,
            network_policy_findings_count INTEGER DEFAULT 0,
            workloads_analyzed INTEGER DEFAULT 0,
            policies_analyzed INTEGER DEFAULT 0,
            roles_analyzed INTEGER DEFAULT 0,
            bindings_analyzed INTEGER DEFAULT 0,
            error_message TEXT,
            started_at TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // CIS Benchmark findings table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS k8s_cis_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            control_title TEXT NOT NULL,
            section TEXT NOT NULL,
            section_title TEXT,
            status TEXT NOT NULL,
            severity TEXT NOT NULL,
            scored INTEGER DEFAULT 1,
            level INTEGER DEFAULT 1,
            description TEXT,
            actual_value TEXT,
            expected_value TEXT,
            remediation TEXT,
            reference_url TEXT,
            resource_name TEXT,
            resource_kind TEXT,
            namespace TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES k8s_security_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // RBAC findings table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS k8s_rbac_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            subject_kind TEXT,
            subject_name TEXT,
            subject_namespace TEXT,
            role_name TEXT,
            binding_name TEXT,
            namespace TEXT,
            permissions TEXT,
            description TEXT NOT NULL,
            remediation TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES k8s_security_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Network policy findings table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS k8s_network_policy_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            namespace TEXT NOT NULL,
            policy_name TEXT,
            affected_pods TEXT,
            description TEXT NOT NULL,
            remediation TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES k8s_security_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Pod Security Standards findings table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS k8s_pss_findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            violation_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            profile TEXT NOT NULL,
            workload_name TEXT NOT NULL,
            workload_kind TEXT NOT NULL,
            namespace TEXT NOT NULL,
            container_name TEXT,
            field_path TEXT NOT NULL,
            current_value TEXT NOT NULL,
            description TEXT NOT NULL,
            remediation TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES k8s_security_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // K8s resources analyzed table (for reference)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS k8s_resources (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            name TEXT NOT NULL,
            namespace TEXT,
            api_version TEXT,
            labels TEXT,
            annotations TEXT,
            spec_hash TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES k8s_security_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Namespace coverage summary table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS k8s_namespace_coverage (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            namespace TEXT NOT NULL,
            total_pods INTEGER DEFAULT 0,
            covered_pods INTEGER DEFAULT 0,
            has_default_deny_ingress INTEGER DEFAULT 0,
            has_default_deny_egress INTEGER DEFAULT 0,
            policy_count INTEGER DEFAULT 0,
            pss_baseline_compliant INTEGER DEFAULT 0,
            pss_restricted_compliant INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES k8s_security_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_scans_user ON k8s_security_scans(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_scans_org ON k8s_security_scans(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_scans_status ON k8s_security_scans(status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_cis_findings_scan ON k8s_cis_findings(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_cis_findings_control ON k8s_cis_findings(control_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_cis_findings_severity ON k8s_cis_findings(severity)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_rbac_findings_scan ON k8s_rbac_findings(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_rbac_findings_type ON k8s_rbac_findings(finding_type)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_netpol_findings_scan ON k8s_network_policy_findings(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_pss_findings_scan ON k8s_pss_findings(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_pss_findings_profile ON k8s_pss_findings(profile)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_resources_scan ON k8s_resources(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_k8s_namespace_coverage_scan ON k8s_namespace_coverage(scan_id)")
        .execute(pool)
        .await?;

    log::info!("Created Kubernetes Security scanning tables");
    Ok(())
}

// ============================================================================
// Sprint 8: Enhanced Remediation Workflows
// ============================================================================

/// Create enhanced remediation workflow tables for verification and ticket sync
async fn create_remediation_workflow_tables(pool: &SqlitePool) -> Result<()> {
    // Add new columns to vulnerability_tracking for enhanced remediation
    let _ = sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN due_date TEXT")
        .execute(pool)
        .await;

    let _ = sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN remediation_status TEXT DEFAULT 'open'")
        .execute(pool)
        .await;

    let _ = sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN assigned_at TEXT")
        .execute(pool)
        .await;

    let _ = sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN priority INTEGER DEFAULT 0")
        .execute(pool)
        .await;

    let _ = sqlx::query("ALTER TABLE vulnerability_tracking ADD COLUMN sla_breach_at TEXT")
        .execute(pool)
        .await;

    // Create verification_requests table for retest/verification workflow
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS verification_requests (
            id TEXT PRIMARY KEY,
            vulnerability_id TEXT NOT NULL,
            requested_by TEXT NOT NULL,
            assigned_to TEXT,
            scan_id TEXT,
            verification_type TEXT NOT NULL DEFAULT 'retest',
            status TEXT NOT NULL DEFAULT 'pending',
            priority INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            verification_evidence TEXT,
            result TEXT,
            result_details TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_tracking(id) ON DELETE CASCADE,
            FOREIGN KEY (requested_by) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create ticket_sync table for JIRA/ServiceNow bidirectional sync
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ticket_sync (
            id TEXT PRIMARY KEY,
            vulnerability_id TEXT NOT NULL,
            integration_type TEXT NOT NULL,
            external_id TEXT NOT NULL,
            external_url TEXT,
            external_status TEXT,
            external_priority TEXT,
            external_assignee TEXT,
            sync_status TEXT NOT NULL DEFAULT 'synced',
            sync_direction TEXT NOT NULL DEFAULT 'bidirectional',
            last_synced_at TEXT,
            last_sync_error TEXT,
            field_mappings TEXT,
            auto_sync_enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_tracking(id) ON DELETE CASCADE,
            UNIQUE(vulnerability_id, integration_type)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create ticket_sync_history for tracking sync operations
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ticket_sync_history (
            id TEXT PRIMARY KEY,
            ticket_sync_id TEXT NOT NULL,
            sync_direction TEXT NOT NULL,
            sync_type TEXT NOT NULL,
            fields_updated TEXT,
            status TEXT NOT NULL,
            error_message TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (ticket_sync_id) REFERENCES ticket_sync(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create SLA configuration table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS remediation_sla_configs (
            id TEXT PRIMARY KEY,
            organization_id TEXT,
            name TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL,
            target_days INTEGER NOT NULL,
            warning_threshold_days INTEGER,
            escalation_emails TEXT,
            is_default INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create remediation assignments history table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS remediation_assignments (
            id TEXT PRIMARY KEY,
            vulnerability_id TEXT NOT NULL,
            assigned_by TEXT NOT NULL,
            assigned_to TEXT NOT NULL,
            previous_assignee TEXT,
            reason TEXT,
            due_date TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_tracking(id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create remediation escalations table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS remediation_escalations (
            id TEXT PRIMARY KEY,
            vulnerability_id TEXT NOT NULL,
            escalation_level INTEGER NOT NULL DEFAULT 1,
            escalation_reason TEXT NOT NULL,
            escalated_to TEXT,
            escalated_by TEXT,
            notes TEXT,
            acknowledged_at TEXT,
            acknowledged_by TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_tracking(id) ON DELETE CASCADE,
            FOREIGN KEY (escalated_to) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (escalated_by) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (acknowledged_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_verification_requests_vuln ON verification_requests(vulnerability_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_verification_requests_status ON verification_requests(status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_verification_requests_assignee ON verification_requests(assigned_to)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ticket_sync_vuln ON ticket_sync(vulnerability_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ticket_sync_external ON ticket_sync(integration_type, external_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ticket_sync_status ON ticket_sync(sync_status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_remediation_sla_org ON remediation_sla_configs(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_remediation_sla_severity ON remediation_sla_configs(severity)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_remediation_assignments_vuln ON remediation_assignments(vulnerability_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_remediation_escalations_vuln ON remediation_escalations(vulnerability_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vuln_tracking_due_date ON vulnerability_tracking(due_date)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_vuln_tracking_sla_breach ON vulnerability_tracking(sla_breach_at)")
        .execute(pool)
        .await?;

    // Seed default SLA configurations
    let now = chrono::Utc::now().to_rfc3339();
    let sla_defaults = vec![
        ("critical", 1, 0),   // Critical: 1 day, warn immediately
        ("high", 7, 2),       // High: 7 days, warn at day 2
        ("medium", 30, 7),    // Medium: 30 days, warn at day 7
        ("low", 90, 14),      // Low: 90 days, warn at day 14
        ("info", 180, 30),    // Info: 180 days, warn at day 30
    ];

    for (severity, target_days, warning_days) in sla_defaults {
        let _ = sqlx::query(
            r#"INSERT OR IGNORE INTO remediation_sla_configs
               (id, name, description, severity, target_days, warning_threshold_days, is_default, is_active, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?, ?)"#
        )
        .bind(format!("sla_default_{}", severity))
        .bind(format!("Default {} SLA", severity.to_uppercase()))
        .bind(format!("Default remediation SLA for {} severity vulnerabilities", severity))
        .bind(severity)
        .bind(target_days)
        .bind(warning_days)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await;
    }

    log::info!("Created enhanced remediation workflow tables");
    Ok(())
}

// ============================================================================
// Sprint 8: Executive Dashboard
// ============================================================================

/// Create executive dashboard configuration and metrics caching tables
async fn create_executive_dashboard_tables(pool: &SqlitePool) -> Result<()> {
    // Create executive_dashboard_config table for user-specific dashboard layouts
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS executive_dashboard_config (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT 'Default Dashboard',
            layout TEXT NOT NULL,
            widgets TEXT NOT NULL,
            default_timeframe_days INTEGER NOT NULL DEFAULT 30,
            auto_refresh_seconds INTEGER DEFAULT 300,
            theme TEXT DEFAULT 'light',
            filters TEXT,
            is_default INTEGER NOT NULL DEFAULT 0,
            is_shared INTEGER NOT NULL DEFAULT 0,
            shared_with TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create dashboard_metrics_cache table for pre-computed metrics
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS dashboard_metrics_cache (
            id TEXT PRIMARY KEY,
            organization_id TEXT,
            metric_type TEXT NOT NULL,
            metric_key TEXT NOT NULL,
            timeframe TEXT NOT NULL,
            computed_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            data TEXT NOT NULL,
            computation_time_ms INTEGER,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            UNIQUE(organization_id, metric_type, metric_key, timeframe)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create executive_reports table for scheduled executive summaries
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS executive_reports (
            id TEXT PRIMARY KEY,
            organization_id TEXT,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            report_type TEXT NOT NULL DEFAULT 'executive_summary',
            template_config TEXT,
            schedule_cron TEXT,
            recipients TEXT,
            last_generated_at TEXT,
            last_report_id TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (last_report_id) REFERENCES reports(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create executive_kpis table for tracking key performance indicators
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS executive_kpis (
            id TEXT PRIMARY KEY,
            organization_id TEXT,
            kpi_type TEXT NOT NULL,
            kpi_name TEXT NOT NULL,
            target_value REAL,
            current_value REAL,
            unit TEXT,
            trend TEXT,
            trend_percentage REAL,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            computed_at TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create risk_score_history table for tracking risk trends over time
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS risk_score_history (
            id TEXT PRIMARY KEY,
            organization_id TEXT,
            scan_id TEXT,
            overall_risk_score REAL NOT NULL,
            critical_count INTEGER NOT NULL DEFAULT 0,
            high_count INTEGER NOT NULL DEFAULT 0,
            medium_count INTEGER NOT NULL DEFAULT 0,
            low_count INTEGER NOT NULL DEFAULT 0,
            info_count INTEGER NOT NULL DEFAULT 0,
            asset_count INTEGER NOT NULL DEFAULT 0,
            compliant_assets INTEGER NOT NULL DEFAULT 0,
            factors TEXT,
            computed_at TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create compliance_posture table for tracking compliance status over time
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS compliance_posture (
            id TEXT PRIMARY KEY,
            organization_id TEXT,
            framework_id TEXT NOT NULL,
            framework_name TEXT NOT NULL,
            total_controls INTEGER NOT NULL DEFAULT 0,
            passing_controls INTEGER NOT NULL DEFAULT 0,
            failing_controls INTEGER NOT NULL DEFAULT 0,
            not_applicable INTEGER NOT NULL DEFAULT 0,
            compliance_percentage REAL NOT NULL DEFAULT 0.0,
            previous_percentage REAL,
            trend TEXT,
            details TEXT,
            computed_at TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create mttr_metrics table (Mean Time to Remediate)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS mttr_metrics (
            id TEXT PRIMARY KEY,
            organization_id TEXT,
            severity TEXT NOT NULL,
            period_type TEXT NOT NULL,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            avg_mttr_hours REAL NOT NULL,
            min_mttr_hours REAL,
            max_mttr_hours REAL,
            p50_mttr_hours REAL,
            p90_mttr_hours REAL,
            sample_count INTEGER NOT NULL DEFAULT 0,
            trend_percentage REAL,
            computed_at TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create scan_coverage table for tracking scan coverage metrics
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scan_coverage (
            id TEXT PRIMARY KEY,
            organization_id TEXT,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            total_assets INTEGER NOT NULL DEFAULT 0,
            scanned_assets INTEGER NOT NULL DEFAULT 0,
            coverage_percentage REAL NOT NULL DEFAULT 0.0,
            scan_types TEXT,
            avg_scan_frequency_days REAL,
            last_full_scan_at TEXT,
            stale_asset_count INTEGER DEFAULT 0,
            computed_at TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exec_dashboard_user ON executive_dashboard_config(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exec_dashboard_shared ON executive_dashboard_config(is_shared)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_metrics_cache_org ON dashboard_metrics_cache(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_metrics_cache_type ON dashboard_metrics_cache(metric_type)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_metrics_cache_expires ON dashboard_metrics_cache(expires_at)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exec_reports_org ON executive_reports(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exec_reports_user ON executive_reports(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exec_kpis_org ON executive_kpis(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exec_kpis_type ON executive_kpis(kpi_type)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_risk_score_org ON risk_score_history(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_risk_score_computed ON risk_score_history(computed_at)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_compliance_posture_org ON compliance_posture(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_compliance_posture_framework ON compliance_posture(framework_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_mttr_metrics_org ON mttr_metrics(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_mttr_metrics_severity ON mttr_metrics(severity)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scan_coverage_org ON scan_coverage(organization_id)")
        .execute(pool)
        .await?;

    log::info!("Created executive dashboard tables");
    Ok(())
}

/// Sprint 9: Custom Report Templates
async fn create_custom_report_templates_tables(pool: &SqlitePool) -> Result<()> {
    // Create custom_report_templates table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS custom_report_templates (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            organization_id TEXT,
            name TEXT NOT NULL,
            description TEXT,
            base_template TEXT NOT NULL,
            sections TEXT NOT NULL,
            branding TEXT,
            header_html TEXT,
            footer_html TEXT,
            css_overrides TEXT,
            cover_page_html TEXT,
            is_public INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            downloads INTEGER DEFAULT 0,
            rating REAL,
            rating_count INTEGER DEFAULT 0,
            version INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            published_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create template_ratings table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS template_ratings (
            id TEXT PRIMARY KEY,
            template_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
            review TEXT,
            helpful_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(template_id, user_id),
            FOREIGN KEY (template_id) REFERENCES custom_report_templates(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create template_sections table for reusable sections
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS template_sections (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            organization_id TEXT,
            name TEXT NOT NULL,
            section_type TEXT NOT NULL,
            content_html TEXT NOT NULL,
            content_css TEXT,
            is_public INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create template_assets table for logos, images
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS template_assets (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            organization_id TEXT,
            name TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            width INTEGER,
            height INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create template_versions table for version history
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS template_versions (
            id TEXT PRIMARY KEY,
            template_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            sections TEXT NOT NULL,
            branding TEXT,
            header_html TEXT,
            footer_html TEXT,
            css_overrides TEXT,
            cover_page_html TEXT,
            change_notes TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (template_id) REFERENCES custom_report_templates(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create template_usage_stats table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS template_usage_stats (
            id TEXT PRIMARY KEY,
            template_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            report_id TEXT,
            used_at TEXT NOT NULL,
            FOREIGN KEY (template_id) REFERENCES custom_report_templates(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create scheduled_report_delivery table for enhanced delivery options
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scheduled_report_delivery (
            id TEXT PRIMARY KEY,
            scheduled_report_id TEXT NOT NULL,
            channel TEXT NOT NULL,
            channel_config TEXT NOT NULL,
            is_enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (scheduled_report_id) REFERENCES scheduled_reports(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create scheduled_report_runs table for delivery history
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scheduled_report_runs (
            id TEXT PRIMARY KEY,
            scheduled_report_id TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT NOT NULL,
            file_path TEXT,
            file_size INTEGER,
            recipients_notified INTEGER DEFAULT 0,
            error_message TEXT,
            delivery_results TEXT,
            FOREIGN KEY (scheduled_report_id) REFERENCES scheduled_reports(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Indexes for custom_report_templates
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_custom_templates_user ON custom_report_templates(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_custom_templates_org ON custom_report_templates(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_custom_templates_public ON custom_report_templates(is_public)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_custom_templates_base ON custom_report_templates(base_template)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_custom_templates_rating ON custom_report_templates(rating DESC)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_custom_templates_downloads ON custom_report_templates(downloads DESC)")
        .execute(pool)
        .await?;

    // Indexes for template_ratings
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_template_ratings_template ON template_ratings(template_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_template_ratings_user ON template_ratings(user_id)")
        .execute(pool)
        .await?;

    // Indexes for template_sections
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_template_sections_user ON template_sections(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_template_sections_org ON template_sections(organization_id)")
        .execute(pool)
        .await?;

    // Indexes for template_assets
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_template_assets_user ON template_assets(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_template_assets_org ON template_assets(organization_id)")
        .execute(pool)
        .await?;

    // Indexes for template_versions
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_template_versions_template ON template_versions(template_id)")
        .execute(pool)
        .await?;

    // Indexes for template_usage_stats
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_template_usage_template ON template_usage_stats(template_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_template_usage_user ON template_usage_stats(user_id)")
        .execute(pool)
        .await?;

    // Indexes for scheduled_report_delivery
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scheduled_delivery_report ON scheduled_report_delivery(scheduled_report_id)")
        .execute(pool)
        .await?;

    // Indexes for scheduled_report_runs
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scheduled_runs_report ON scheduled_report_runs(scheduled_report_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scheduled_runs_status ON scheduled_report_runs(status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scheduled_runs_started ON scheduled_report_runs(started_at DESC)")
        .execute(pool)
        .await?;

    log::info!("Created custom report templates tables");
    Ok(())
}

/// Sprint 10: Scanner Import tables for Nessus/Qualys integration
async fn create_scanner_import_tables(pool: &SqlitePool) -> Result<()> {
    // Main imported scans table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS imported_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            organization_id TEXT,
            source TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_hash TEXT,
            scanner_name TEXT,
            scanner_version TEXT,
            policy_name TEXT,
            scan_name TEXT,
            scan_date TEXT,
            host_count INTEGER NOT NULL DEFAULT 0,
            finding_count INTEGER NOT NULL DEFAULT 0,
            critical_count INTEGER NOT NULL DEFAULT 0,
            high_count INTEGER NOT NULL DEFAULT 0,
            medium_count INTEGER NOT NULL DEFAULT 0,
            low_count INTEGER NOT NULL DEFAULT 0,
            info_count INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            error_message TEXT,
            scan_id TEXT REFERENCES scan_results(id),
            imported_at TEXT NOT NULL,
            processing_started_at TEXT,
            processing_completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Imported hosts from external scanners
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS imported_hosts (
            id TEXT PRIMARY KEY,
            import_id TEXT NOT NULL,
            ip TEXT NOT NULL,
            hostname TEXT,
            fqdn TEXT,
            mac_address TEXT,
            os TEXT,
            os_confidence INTEGER,
            netbios_name TEXT,
            critical_count INTEGER NOT NULL DEFAULT 0,
            high_count INTEGER NOT NULL DEFAULT 0,
            medium_count INTEGER NOT NULL DEFAULT 0,
            low_count INTEGER NOT NULL DEFAULT 0,
            info_count INTEGER NOT NULL DEFAULT 0,
            asset_id TEXT REFERENCES assets(id),
            created_at TEXT NOT NULL,
            FOREIGN KEY (import_id) REFERENCES imported_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Imported findings from external scanners
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS imported_findings (
            id TEXT PRIMARY KEY,
            import_id TEXT NOT NULL,
            imported_host_id TEXT NOT NULL,
            plugin_id TEXT,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL,
            cvss_score REAL,
            cvss_vector TEXT,
            cve_ids TEXT,
            cwe_ids TEXT,
            port INTEGER,
            protocol TEXT,
            service TEXT,
            solution TEXT,
            see_also TEXT,
            plugin_output TEXT,
            first_discovered TEXT,
            last_observed TEXT,
            exploit_available INTEGER NOT NULL DEFAULT 0,
            exploitability_ease TEXT,
            patch_published TEXT,
            vuln_tracking_id TEXT REFERENCES vulnerability_tracking(id),
            created_at TEXT NOT NULL,
            FOREIGN KEY (import_id) REFERENCES imported_scans(id) ON DELETE CASCADE,
            FOREIGN KEY (imported_host_id) REFERENCES imported_hosts(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Import field mappings (for custom field mapping)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS import_field_mappings (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            organization_id TEXT,
            source TEXT NOT NULL,
            name TEXT NOT NULL,
            mappings TEXT NOT NULL,
            is_default INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_imported_scans_user ON imported_scans(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_imported_scans_org ON imported_scans(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_imported_scans_source ON imported_scans(source)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_imported_scans_status ON imported_scans(status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_imported_hosts_import ON imported_hosts(import_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_imported_hosts_ip ON imported_hosts(ip)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_imported_findings_import ON imported_findings(import_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_imported_findings_host ON imported_findings(imported_host_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_imported_findings_severity ON imported_findings(severity)")
        .execute(pool)
        .await?;

    log::info!("Created scanner import tables");
    Ok(())
}

/// Sprint 10: Integration bot tables for Slack/Teams
async fn create_integration_bot_tables(pool: &SqlitePool) -> Result<()> {
    // Slack workspace configurations
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS slack_workspaces (
            id TEXT PRIMARY KEY,
            organization_id TEXT,
            workspace_id TEXT NOT NULL UNIQUE,
            workspace_name TEXT NOT NULL,
            bot_token TEXT NOT NULL,
            bot_user_id TEXT,
            signing_secret TEXT NOT NULL,
            default_channel_id TEXT,
            default_channel_name TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Slack channel mappings (which channels get which alerts)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS slack_channel_mappings (
            id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            channel_name TEXT NOT NULL,
            alert_types TEXT NOT NULL,
            severity_filter TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (workspace_id) REFERENCES slack_workspaces(id) ON DELETE CASCADE,
            UNIQUE(workspace_id, channel_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Slack command logs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS slack_command_logs (
            id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            user_name TEXT,
            command TEXT NOT NULL,
            command_text TEXT,
            response_type TEXT,
            success INTEGER NOT NULL DEFAULT 1,
            error_message TEXT,
            executed_at TEXT NOT NULL,
            FOREIGN KEY (workspace_id) REFERENCES slack_workspaces(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Microsoft Teams configurations
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS teams_tenants (
            id TEXT PRIMARY KEY,
            organization_id TEXT,
            tenant_id TEXT NOT NULL UNIQUE,
            tenant_name TEXT NOT NULL,
            app_id TEXT NOT NULL,
            app_secret TEXT NOT NULL,
            bot_id TEXT,
            service_url TEXT,
            default_team_id TEXT,
            default_channel_id TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Teams channel mappings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS teams_channel_mappings (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            team_id TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            channel_name TEXT NOT NULL,
            alert_types TEXT NOT NULL,
            severity_filter TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES teams_tenants(id) ON DELETE CASCADE,
            UNIQUE(tenant_id, team_id, channel_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Teams command logs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS teams_command_logs (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            team_id TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            user_name TEXT,
            command TEXT NOT NULL,
            command_text TEXT,
            response_type TEXT,
            success INTEGER NOT NULL DEFAULT 1,
            error_message TEXT,
            executed_at TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES teams_tenants(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Bot notification queue (for async delivery)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS bot_notification_queue (
            id TEXT PRIMARY KEY,
            platform TEXT NOT NULL,
            workspace_or_tenant_id TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            notification_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            priority INTEGER NOT NULL DEFAULT 5,
            status TEXT NOT NULL DEFAULT 'pending',
            retry_count INTEGER NOT NULL DEFAULT 0,
            max_retries INTEGER NOT NULL DEFAULT 3,
            scheduled_for TEXT NOT NULL,
            created_at TEXT NOT NULL,
            sent_at TEXT,
            error_message TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_slack_workspaces_org ON slack_workspaces(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_slack_channel_mappings_workspace ON slack_channel_mappings(workspace_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_slack_command_logs_workspace ON slack_command_logs(workspace_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_slack_command_logs_executed ON slack_command_logs(executed_at DESC)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_teams_tenants_org ON teams_tenants(organization_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_teams_channel_mappings_tenant ON teams_channel_mappings(tenant_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_teams_command_logs_tenant ON teams_command_logs(tenant_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_teams_command_logs_executed ON teams_command_logs(executed_at DESC)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bot_queue_status ON bot_notification_queue(status, scheduled_for)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_bot_queue_platform ON bot_notification_queue(platform, workspace_or_tenant_id)")
        .execute(pool)
        .await?;

    log::info!("Created integration bot tables");
    Ok(())
}

/// Create email security analysis results table
async fn create_email_security_results_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS email_security_results (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            spf_record TEXT,
            dkim_selectors TEXT,
            dmarc_policy TEXT,
            spoofability TEXT NOT NULL,
            result_json TEXT NOT NULL,
            analyzed_at TEXT NOT NULL,
            user_id TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_email_security_user_id ON email_security_results(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_email_security_domain ON email_security_results(domain)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_email_security_analyzed_at ON email_security_results(analyzed_at DESC)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_email_security_spoofability ON email_security_results(spoofability)")
        .execute(pool)
        .await?;

    log::info!("Created email security results table");
    Ok(())
}

/// Create domain intelligence cache table for WHOIS and domain intel caching
async fn create_domain_intel_cache_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS domain_intel_cache (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            whois_data TEXT,
            intel_data TEXT,
            related_domains TEXT,
            last_updated TEXT NOT NULL,
            user_id TEXT NOT NULL,
            UNIQUE(domain, user_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_domain_intel_cache_user_id ON domain_intel_cache(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_domain_intel_cache_domain ON domain_intel_cache(domain)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_domain_intel_cache_last_updated ON domain_intel_cache(last_updated DESC)")
        .execute(pool)
        .await?;

    log::info!("Created domain intelligence cache table");
    Ok(())
}

// ============================================================================
// Google Dorking Automation Migrations
// ============================================================================

/// Create Google Dorking tables for reconnaissance automation
async fn create_google_dorking_tables(pool: &SqlitePool) -> Result<()> {
    // Google dork scans table - stores scan sessions
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS google_dork_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            dork_count INTEGER DEFAULT 0,
            result_count INTEGER DEFAULT 0,
            summary TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for google_dork_scans
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_google_dork_scans_user_id ON google_dork_scans(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_google_dork_scans_domain ON google_dork_scans(domain)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_google_dork_scans_status ON google_dork_scans(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_google_dork_scans_created_at ON google_dork_scans(created_at DESC)")
        .execute(pool)
        .await?;

    // Google dork results table - stores individual dork query results
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS google_dork_results (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            template_id TEXT NOT NULL,
            query TEXT NOT NULL,
            results TEXT NOT NULL,
            result_count INTEGER DEFAULT 0,
            status TEXT NOT NULL,
            error TEXT,
            provider TEXT NOT NULL,
            executed_at TEXT NOT NULL,
            duration_ms INTEGER DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES google_dork_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for google_dork_results
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_google_dork_results_scan_id ON google_dork_results(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_google_dork_results_template_id ON google_dork_results(template_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_google_dork_results_status ON google_dork_results(status)")
        .execute(pool)
        .await?;

    // Custom dork templates table - stores user-created dork templates
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS custom_dork_templates (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            query_template TEXT NOT NULL,
            description TEXT,
            risk_level TEXT DEFAULT 'medium',
            tags TEXT DEFAULT '[]',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for custom_dork_templates
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_custom_dork_templates_user_id ON custom_dork_templates(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_custom_dork_templates_category ON custom_dork_templates(category)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_custom_dork_templates_name ON custom_dork_templates(name)")
        .execute(pool)
        .await?;

    log::info!("Created Google Dorking tables");
    Ok(())
}

/// Create breach check history tables
async fn create_breach_check_tables(pool: &SqlitePool) -> Result<()> {
    // Breach check history table - stores results of breach checks
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS breach_check_history (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            check_type TEXT NOT NULL,             -- 'email', 'domain', 'password'
            target TEXT NOT NULL,                  -- email address, domain, or '[hashed]' for passwords
            result_json TEXT NOT NULL,             -- full result as JSON
            breach_count INTEGER DEFAULT 0,
            exposure_count INTEGER DEFAULT 0,
            password_exposures INTEGER DEFAULT 0,
            has_critical INTEGER DEFAULT 0,        -- has critical severity breaches
            has_high INTEGER DEFAULT 0,            -- has high severity breaches
            sources_checked TEXT DEFAULT '[]',     -- JSON array of sources used
            errors TEXT DEFAULT '[]',              -- JSON array of any errors
            cached INTEGER DEFAULT 0,              -- whether result was from cache
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for breach_check_history
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_breach_check_history_user_id ON breach_check_history(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_breach_check_history_check_type ON breach_check_history(check_type)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_breach_check_history_target ON breach_check_history(target)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_breach_check_history_created_at ON breach_check_history(created_at DESC)")
        .execute(pool)
        .await?;

    // Breach monitoring table - scheduled monitoring jobs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS breach_monitors (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            target TEXT NOT NULL,                  -- email or domain to monitor
            check_type TEXT NOT NULL,              -- 'email' or 'domain'
            interval_hours INTEGER DEFAULT 24,
            enabled INTEGER DEFAULT 1,
            last_check TEXT,
            next_check TEXT NOT NULL,
            last_breach_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for breach_monitors
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_breach_monitors_user_id ON breach_monitors(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_breach_monitors_next_check ON breach_monitors(next_check)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_breach_monitors_enabled ON breach_monitors(enabled)")
        .execute(pool)
        .await?;

    log::info!("Created breach check tables");
    Ok(())
}

/// Create git repository reconnaissance tables for GitHub/GitLab API-based scanning
async fn create_git_recon_tables(pool: &SqlitePool) -> Result<()> {
    // Create git_recon_scans table for tracking remote repository scans
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS git_recon_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            platform TEXT NOT NULL,              -- 'github' or 'gitlab'
            scan_type TEXT NOT NULL,             -- 'repo', 'user', 'org'
            target TEXT NOT NULL,                -- repo URL or username/org name
            owner TEXT,                          -- repository owner
            repo_name TEXT,                      -- repository name
            api_token_id TEXT,                   -- reference to stored API token (optional)
            include_private INTEGER DEFAULT 0,
            include_forks INTEGER DEFAULT 0,
            include_archived INTEGER DEFAULT 0,
            scan_current_files INTEGER DEFAULT 1,
            scan_commit_history INTEGER DEFAULT 1,
            commit_depth INTEGER DEFAULT 50,
            status TEXT NOT NULL DEFAULT 'pending',
            repos_scanned INTEGER DEFAULT 0,
            files_scanned INTEGER DEFAULT 0,
            commits_scanned INTEGER DEFAULT 0,
            secrets_found INTEGER DEFAULT 0,
            error_message TEXT,
            started_at TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create git_recon_repos table for enumerated repositories
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS git_recon_repos (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            owner TEXT NOT NULL,
            name TEXT NOT NULL,
            full_name TEXT NOT NULL,
            description TEXT,
            url TEXT NOT NULL,
            clone_url TEXT,
            default_branch TEXT,
            is_private INTEGER DEFAULT 0,
            is_fork INTEGER DEFAULT 0,
            is_archived INTEGER DEFAULT 0,
            size_kb INTEGER,
            language TEXT,
            stars INTEGER,
            forks INTEGER,
            pushed_at TEXT,
            created_at TEXT,
            scanned INTEGER DEFAULT 0,
            secrets_found INTEGER DEFAULT 0,
            scan_error TEXT,
            discovered_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES git_recon_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create git_recon_secrets table for secrets found in remote repos
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS git_recon_secrets (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            repo_id TEXT,
            platform TEXT NOT NULL,
            owner TEXT NOT NULL,
            repo_name TEXT NOT NULL,
            secret_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            redacted_value TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_number INTEGER,
            context TEXT,
            commit_sha TEXT,
            commit_author TEXT,
            commit_date TEXT,
            is_current INTEGER DEFAULT 1,
            detection_method TEXT,
            remediation TEXT,
            status TEXT DEFAULT 'open',
            false_positive INTEGER DEFAULT 0,
            notes TEXT,
            reviewed_by TEXT,
            reviewed_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES git_recon_scans(id) ON DELETE CASCADE,
            FOREIGN KEY (repo_id) REFERENCES git_recon_repos(id) ON DELETE SET NULL,
            FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create git_platform_tokens table for storing API tokens securely
    // Note: Tokens should be encrypted before storage
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS git_platform_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            platform TEXT NOT NULL,              -- 'github' or 'gitlab'
            name TEXT NOT NULL,                  -- user-friendly name
            token_hint TEXT,                     -- last 4 chars for identification
            encrypted_token TEXT NOT NULL,       -- encrypted token value
            scopes TEXT,                         -- comma-separated scopes
            is_valid INTEGER DEFAULT 1,
            last_used_at TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_recon_scans_user ON git_recon_scans(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_recon_scans_platform ON git_recon_scans(platform)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_recon_scans_status ON git_recon_scans(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_recon_scans_target ON git_recon_scans(target)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_recon_repos_scan ON git_recon_repos(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_recon_repos_platform ON git_recon_repos(platform)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_recon_repos_owner ON git_recon_repos(owner)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_recon_secrets_scan ON git_recon_secrets(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_recon_secrets_repo ON git_recon_secrets(repo_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_recon_secrets_severity ON git_recon_secrets(severity)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_recon_secrets_status ON git_recon_secrets(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_platform_tokens_user ON git_platform_tokens(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_git_platform_tokens_platform ON git_platform_tokens(platform)")
        .execute(pool)
        .await?;

    log::info!("Created git recon tables for GitHub/GitLab API scanning");
    Ok(())
}

/// Create QR code phishing (quishing) tables
async fn create_qr_phishing_tables(pool: &SqlitePool) -> Result<()> {
    // QR Code campaigns table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS qr_campaigns (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'draft',
            template_type TEXT NOT NULL DEFAULT 'url',
            tracking_domain TEXT NOT NULL,
            landing_page_id TEXT,
            awareness_training INTEGER DEFAULT 0,
            training_url TEXT,
            config TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (landing_page_id) REFERENCES phishing_landing_pages(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // QR Code assets table (generated QR codes)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS qr_assets (
            id TEXT PRIMARY KEY,
            campaign_id TEXT NOT NULL,
            tracking_id TEXT NOT NULL UNIQUE,
            tracking_url TEXT NOT NULL,
            content_data TEXT NOT NULL,
            format TEXT NOT NULL DEFAULT 'png',
            image_data TEXT,
            target_email TEXT,
            target_name TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (campaign_id) REFERENCES qr_campaigns(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // QR Code scans table (tracking events)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS qr_scans (
            id TEXT PRIMARY KEY,
            asset_id TEXT NOT NULL,
            tracking_id TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            device_type TEXT,
            os TEXT,
            browser TEXT,
            country TEXT,
            city TEXT,
            referer TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (asset_id) REFERENCES qr_assets(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_qr_campaigns_user ON qr_campaigns(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_qr_campaigns_status ON qr_campaigns(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_qr_assets_campaign ON qr_assets(campaign_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_qr_assets_tracking_id ON qr_assets(tracking_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_qr_scans_asset ON qr_scans(asset_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_qr_scans_tracking_id ON qr_scans(tracking_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_qr_scans_created_at ON qr_scans(created_at)")
        .execute(pool)
        .await?;

    log::info!("Created QR code phishing (quishing) tables");
    Ok(())
}

// ============================================================================
// AV/EDR Evasion Analysis Tables
// ============================================================================

/// Create evasion analysis tables for payload analysis and evasion job tracking
async fn create_evasion_tables(pool: &SqlitePool) -> Result<()> {
    // Evasion jobs table - track analysis and evasion application jobs
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS evasion_jobs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            job_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            input_hash TEXT,
            input_size INTEGER,
            techniques TEXT,
            profile_name TEXT,
            result TEXT,
            error_message TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Payload analysis results table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS payload_analysis (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            job_id TEXT,
            payload_hash TEXT NOT NULL,
            payload_size INTEGER,
            detection_risk TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            entropy_overall REAL,
            entropy_assessment TEXT,
            suspicious_strings_count INTEGER DEFAULT 0,
            suspicious_patterns_count INTEGER DEFAULT 0,
            api_analysis TEXT,
            heuristic_results TEXT,
            recommendations TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (job_id) REFERENCES evasion_jobs(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Sandbox check results table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sandbox_check_results (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            job_id TEXT,
            is_sandbox INTEGER DEFAULT 0,
            confidence INTEGER DEFAULT 0,
            indicators TEXT,
            environment TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (job_id) REFERENCES evasion_jobs(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Evasion technique usage audit log
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS evasion_audit_log (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            job_id TEXT,
            action TEXT NOT NULL,
            techniques TEXT,
            payload_hash TEXT,
            details TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (job_id) REFERENCES evasion_jobs(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_evasion_jobs_user ON evasion_jobs(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_evasion_jobs_status ON evasion_jobs(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_evasion_jobs_type ON evasion_jobs(job_type)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_evasion_jobs_created ON evasion_jobs(created_at DESC)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_payload_analysis_user ON payload_analysis(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_payload_analysis_hash ON payload_analysis(payload_hash)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_payload_analysis_risk ON payload_analysis(detection_risk)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sandbox_check_user ON sandbox_check_results(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_evasion_audit_user ON evasion_audit_log(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_evasion_audit_action ON evasion_audit_log(action)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_evasion_audit_created ON evasion_audit_log(created_at DESC)")
        .execute(pool)
        .await?;

    log::info!("Created AV/EDR evasion analysis tables");
    Ok(())
}

/// Create encoding_jobs table for payload encoding operations
async fn create_encoding_jobs_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS encoding_jobs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            encoder_type TEXT NOT NULL,
            options TEXT,
            original_size INTEGER NOT NULL,
            encoded_size INTEGER NOT NULL,
            metadata TEXT,
            customer_id TEXT,
            asset_id TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_encoding_jobs_user ON encoding_jobs(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_encoding_jobs_type ON encoding_jobs(encoder_type)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_encoding_jobs_customer ON encoding_jobs(customer_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_encoding_jobs_created ON encoding_jobs(created_at DESC)")
        .execute(pool)
        .await?;

    log::info!("Created encoding_jobs table");
    Ok(())
}

/// Create tunneling framework tables for exfiltration defense testing
async fn create_tunneling_tables(pool: &SqlitePool) -> Result<()> {
    // Tunnel sessions table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tunnel_sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            protocol TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            config TEXT,
            bytes_sent INTEGER DEFAULT 0,
            bytes_received INTEGER DEFAULT 0,
            packets_sent INTEGER DEFAULT 0,
            packets_received INTEGER DEFAULT 0,
            successful_transmissions INTEGER DEFAULT 0,
            failed_transmissions INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            started_at TEXT,
            ended_at TEXT,
            last_activity TEXT,
            error TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Exfiltration jobs table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS exfiltration_jobs (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            source TEXT,
            total_size INTEGER DEFAULT 0,
            transferred_size INTEGER DEFAULT 0,
            total_chunks INTEGER DEFAULT 0,
            completed_chunks INTEGER DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            bytes_sent INTEGER DEFAULT 0,
            packets_sent INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            error TEXT,
            metadata TEXT,
            FOREIGN KEY (session_id) REFERENCES tunnel_sessions(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Tunnel activity log for auditing
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tunnel_activity_log (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            job_id TEXT,
            action TEXT NOT NULL,
            protocol TEXT NOT NULL,
            target TEXT,
            data_size INTEGER DEFAULT 0,
            encoding TEXT,
            success INTEGER DEFAULT 1,
            error TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES tunnel_sessions(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tunnel_sessions_user ON tunnel_sessions(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tunnel_sessions_status ON tunnel_sessions(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tunnel_sessions_protocol ON tunnel_sessions(protocol)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exfiltration_jobs_session ON exfiltration_jobs(session_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exfiltration_jobs_user ON exfiltration_jobs(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_exfiltration_jobs_status ON exfiltration_jobs(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tunnel_activity_session ON tunnel_activity_log(session_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tunnel_activity_created ON tunnel_activity_log(created_at)")
        .execute(pool)
        .await?;

    log::info!("Created tunneling framework tables");
    Ok(())
}
