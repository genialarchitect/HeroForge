//! Dork Template Library
//!
//! This module provides built-in Google dork templates organized by category.
//! Templates support variable substitution for domain/target customization.
//!
//! # Template Variables
//!
//! - `{domain}` - The target domain (e.g., example.com)
//! - `{target}` - Alias for {domain}
//! - `{site}` - Alias for {domain}
//!
//! # WARNING: Responsible Use
//!
//! These dorks should ONLY be used for authorized security testing.
//! Unauthorized use may violate laws and terms of service.

#![allow(dead_code)]

use crate::scanner::google_dorking::{DorkCategory, DorkTemplate};
use once_cell::sync::Lazy;

/// All built-in dork templates
static BUILTIN_TEMPLATES: Lazy<Vec<DorkTemplate>> = Lazy::new(|| {
    let mut templates = Vec::new();

    // =========================================================================
    // Sensitive Files Category
    // =========================================================================
    templates.extend(sensitive_files_templates());

    // =========================================================================
    // Login Pages Category
    // =========================================================================
    templates.extend(login_pages_templates());

    // =========================================================================
    // Configuration Files Category
    // =========================================================================
    templates.extend(config_files_templates());

    // =========================================================================
    // Error Messages Category
    // =========================================================================
    templates.extend(error_messages_templates());

    // =========================================================================
    // Admin Panels Category
    // =========================================================================
    templates.extend(admin_panels_templates());

    // =========================================================================
    // Directory Listings Category
    // =========================================================================
    templates.extend(directory_listings_templates());

    // =========================================================================
    // Database Files Category
    // =========================================================================
    templates.extend(database_files_templates());

    // =========================================================================
    // Backup Files Category
    // =========================================================================
    templates.extend(backup_files_templates());

    // =========================================================================
    // API Endpoints Category
    // =========================================================================
    templates.extend(api_endpoints_templates());

    // =========================================================================
    // Cloud Storage Category
    // =========================================================================
    templates.extend(cloud_storage_templates());

    // =========================================================================
    // Source Control Category
    // =========================================================================
    templates.extend(source_control_templates());

    // =========================================================================
    // Log Files Category
    // =========================================================================
    templates.extend(log_files_templates());

    templates
});

/// Get all built-in templates
pub fn get_all_templates() -> Vec<DorkTemplate> {
    BUILTIN_TEMPLATES.clone()
}

/// Get templates by category
pub fn get_templates_by_category(category: DorkCategory) -> Vec<DorkTemplate> {
    BUILTIN_TEMPLATES
        .iter()
        .filter(|t| t.category == category)
        .cloned()
        .collect()
}

/// Get a template by ID
pub fn get_template_by_id(id: &str) -> Option<DorkTemplate> {
    BUILTIN_TEMPLATES.iter().find(|t| t.id == id).cloned()
}

/// Search templates by name or description
pub fn search_templates(query: &str) -> Vec<DorkTemplate> {
    let query_lower = query.to_lowercase();
    BUILTIN_TEMPLATES
        .iter()
        .filter(|t| {
            t.name.to_lowercase().contains(&query_lower)
                || t.description.to_lowercase().contains(&query_lower)
                || t.tags.iter().any(|tag| tag.to_lowercase().contains(&query_lower))
        })
        .cloned()
        .collect()
}

/// Get templates by risk level
pub fn get_templates_by_risk(risk_level: &str) -> Vec<DorkTemplate> {
    BUILTIN_TEMPLATES
        .iter()
        .filter(|t| t.risk_level.eq_ignore_ascii_case(risk_level))
        .cloned()
        .collect()
}

// =============================================================================
// Template Definitions by Category
// =============================================================================

fn sensitive_files_templates() -> Vec<DorkTemplate> {
    vec![
        DorkTemplate {
            id: "sensitive-password-files".to_string(),
            category: DorkCategory::SensitiveFiles,
            name: "Password Files".to_string(),
            query_template: "site:{domain} (filetype:txt | filetype:log | filetype:cfg) (password | passwd | pwd | credentials)".to_string(),
            description: "Find exposed password files and credentials".to_string(),
            risk_level: "critical".to_string(),
            is_builtin: true,
            tags: vec!["password".to_string(), "credentials".to_string()],
        },
        DorkTemplate {
            id: "sensitive-private-keys".to_string(),
            category: DorkCategory::SensitiveFiles,
            name: "Private Keys".to_string(),
            query_template: "site:{domain} (filetype:pem | filetype:key | filetype:ppk) (private | key | rsa | dsa)".to_string(),
            description: "Find exposed private keys".to_string(),
            risk_level: "critical".to_string(),
            is_builtin: true,
            tags: vec!["private-key".to_string(), "ssl".to_string(), "ssh".to_string()],
        },
        DorkTemplate {
            id: "sensitive-env-files".to_string(),
            category: DorkCategory::SensitiveFiles,
            name: "Environment Files".to_string(),
            query_template: "site:{domain} (filetype:env | \".env\") (DB_PASSWORD | API_KEY | SECRET)".to_string(),
            description: "Find exposed .env files with secrets".to_string(),
            risk_level: "critical".to_string(),
            is_builtin: true,
            tags: vec!["env".to_string(), "dotenv".to_string(), "secrets".to_string()],
        },
        DorkTemplate {
            id: "sensitive-aws-credentials".to_string(),
            category: DorkCategory::SensitiveFiles,
            name: "AWS Credentials".to_string(),
            query_template: "site:{domain} (filetype:txt | filetype:cfg | filetype:json) (aws_access_key_id | aws_secret_access_key | AKIA)".to_string(),
            description: "Find exposed AWS credentials".to_string(),
            risk_level: "critical".to_string(),
            is_builtin: true,
            tags: vec!["aws".to_string(), "cloud".to_string(), "credentials".to_string()],
        },
        DorkTemplate {
            id: "sensitive-api-keys".to_string(),
            category: DorkCategory::SensitiveFiles,
            name: "API Keys".to_string(),
            query_template: "site:{domain} (api_key | apikey | api-key | access_token) (filetype:json | filetype:xml | filetype:yaml | filetype:yml)".to_string(),
            description: "Find exposed API keys in configuration files".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["api".to_string(), "keys".to_string(), "tokens".to_string()],
        },
        DorkTemplate {
            id: "sensitive-htpasswd".to_string(),
            category: DorkCategory::SensitiveFiles,
            name: "Apache htpasswd".to_string(),
            query_template: "site:{domain} filetype:htpasswd".to_string(),
            description: "Find exposed Apache htpasswd files".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["apache".to_string(), "htpasswd".to_string(), "auth".to_string()],
        },
        DorkTemplate {
            id: "sensitive-ssh-authorized".to_string(),
            category: DorkCategory::SensitiveFiles,
            name: "SSH Authorized Keys".to_string(),
            query_template: "site:{domain} \"ssh-rsa\" | \"ssh-ed25519\" | \"authorized_keys\"".to_string(),
            description: "Find exposed SSH authorized keys files".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["ssh".to_string(), "keys".to_string()],
        },
    ]
}

fn login_pages_templates() -> Vec<DorkTemplate> {
    vec![
        DorkTemplate {
            id: "login-admin-login".to_string(),
            category: DorkCategory::LoginPages,
            name: "Admin Login Pages".to_string(),
            query_template: "site:{domain} inurl:(admin | login | signin | administrator) intitle:(login | signin | admin)".to_string(),
            description: "Find administrative login pages".to_string(),
            risk_level: "info".to_string(),
            is_builtin: true,
            tags: vec!["admin".to_string(), "login".to_string()],
        },
        DorkTemplate {
            id: "login-control-panel".to_string(),
            category: DorkCategory::LoginPages,
            name: "Control Panels".to_string(),
            query_template: "site:{domain} inurl:(cpanel | plesk | webmin | phpmyadmin | directadmin)".to_string(),
            description: "Find control panel login pages".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["cpanel".to_string(), "hosting".to_string()],
        },
        DorkTemplate {
            id: "login-user-portals".to_string(),
            category: DorkCategory::LoginPages,
            name: "User Portals".to_string(),
            query_template: "site:{domain} inurl:(portal | account | my | user) intitle:(login | sign in | account)".to_string(),
            description: "Find user portal login pages".to_string(),
            risk_level: "info".to_string(),
            is_builtin: true,
            tags: vec!["portal".to_string(), "user".to_string()],
        },
        DorkTemplate {
            id: "login-webmail".to_string(),
            category: DorkCategory::LoginPages,
            name: "Webmail Login".to_string(),
            query_template: "site:{domain} inurl:(webmail | mail | email | roundcube | squirrelmail | horde)".to_string(),
            description: "Find webmail login interfaces".to_string(),
            risk_level: "info".to_string(),
            is_builtin: true,
            tags: vec!["email".to_string(), "webmail".to_string()],
        },
    ]
}

fn config_files_templates() -> Vec<DorkTemplate> {
    vec![
        DorkTemplate {
            id: "config-web-config".to_string(),
            category: DorkCategory::ConfigFiles,
            name: "Web.config Files".to_string(),
            query_template: "site:{domain} filetype:config | filetype:xml inurl:web.config".to_string(),
            description: "Find exposed ASP.NET web.config files".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["aspnet".to_string(), "iis".to_string(), "config".to_string()],
        },
        DorkTemplate {
            id: "config-php-ini".to_string(),
            category: DorkCategory::ConfigFiles,
            name: "PHP Configuration".to_string(),
            query_template: "site:{domain} filetype:ini (php | configuration)".to_string(),
            description: "Find exposed PHP configuration files".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["php".to_string(), "config".to_string()],
        },
        DorkTemplate {
            id: "config-nginx-apache".to_string(),
            category: DorkCategory::ConfigFiles,
            name: "Web Server Configs".to_string(),
            query_template: "site:{domain} filetype:conf (nginx | apache | httpd | server)".to_string(),
            description: "Find exposed web server configuration files".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["nginx".to_string(), "apache".to_string(), "webserver".to_string()],
        },
        DorkTemplate {
            id: "config-yaml-yml".to_string(),
            category: DorkCategory::ConfigFiles,
            name: "YAML Configuration".to_string(),
            query_template: "site:{domain} (filetype:yaml | filetype:yml) (config | settings | database | credentials)".to_string(),
            description: "Find exposed YAML configuration files".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["yaml".to_string(), "config".to_string()],
        },
        DorkTemplate {
            id: "config-docker".to_string(),
            category: DorkCategory::ConfigFiles,
            name: "Docker Configuration".to_string(),
            query_template: "site:{domain} (\"docker-compose.yml\" | \"Dockerfile\" | \".dockerignore\")".to_string(),
            description: "Find exposed Docker configuration files".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["docker".to_string(), "container".to_string()],
        },
        DorkTemplate {
            id: "config-kubernetes".to_string(),
            category: DorkCategory::ConfigFiles,
            name: "Kubernetes Configuration".to_string(),
            query_template: "site:{domain} (filetype:yaml | filetype:yml) (kind: | apiVersion:) (Deployment | Service | Secret | ConfigMap)".to_string(),
            description: "Find exposed Kubernetes manifests".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["kubernetes".to_string(), "k8s".to_string()],
        },
    ]
}

fn error_messages_templates() -> Vec<DorkTemplate> {
    vec![
        DorkTemplate {
            id: "error-php-errors".to_string(),
            category: DorkCategory::ErrorMessages,
            name: "PHP Errors".to_string(),
            query_template: "site:{domain} (\"Fatal error\" | \"Parse error\" | \"Warning:\") \"on line\"".to_string(),
            description: "Find PHP error messages revealing code paths".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["php".to_string(), "error".to_string()],
        },
        DorkTemplate {
            id: "error-mysql-errors".to_string(),
            category: DorkCategory::ErrorMessages,
            name: "MySQL Errors".to_string(),
            query_template: "site:{domain} (\"mysql_fetch\" | \"mysql_connect\" | \"SQL syntax\" | \"mysql_query\")".to_string(),
            description: "Find MySQL error messages".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["mysql".to_string(), "sql".to_string(), "database".to_string()],
        },
        DorkTemplate {
            id: "error-stack-traces".to_string(),
            category: DorkCategory::ErrorMessages,
            name: "Stack Traces".to_string(),
            query_template: "site:{domain} (\"stack trace\" | \"traceback\" | \"Exception in thread\" | \"at java.\" | \"at System.\")".to_string(),
            description: "Find exposed stack traces".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["stacktrace".to_string(), "debug".to_string()],
        },
        DorkTemplate {
            id: "error-debug-mode".to_string(),
            category: DorkCategory::ErrorMessages,
            name: "Debug Mode Enabled".to_string(),
            query_template: "site:{domain} (\"debug=true\" | \"DEBUG = True\" | \"debug mode\" | \"development mode\")".to_string(),
            description: "Find applications running in debug mode".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["debug".to_string(), "development".to_string()],
        },
        DorkTemplate {
            id: "error-connection-strings".to_string(),
            category: DorkCategory::ErrorMessages,
            name: "Connection String Errors".to_string(),
            query_template: "site:{domain} (\"connection string\" | \"connectionString\" | \"Data Source=\" | \"Server=\" | \"Database=\")".to_string(),
            description: "Find exposed database connection strings in errors".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["database".to_string(), "connection".to_string()],
        },
    ]
}

fn admin_panels_templates() -> Vec<DorkTemplate> {
    vec![
        DorkTemplate {
            id: "admin-wordpress".to_string(),
            category: DorkCategory::AdminPanels,
            name: "WordPress Admin".to_string(),
            query_template: "site:{domain} inurl:wp-admin | inurl:wp-login".to_string(),
            description: "Find WordPress admin panels".to_string(),
            risk_level: "info".to_string(),
            is_builtin: true,
            tags: vec!["wordpress".to_string(), "cms".to_string()],
        },
        DorkTemplate {
            id: "admin-drupal".to_string(),
            category: DorkCategory::AdminPanels,
            name: "Drupal Admin".to_string(),
            query_template: "site:{domain} inurl:user/login | inurl:admin/config".to_string(),
            description: "Find Drupal admin panels".to_string(),
            risk_level: "info".to_string(),
            is_builtin: true,
            tags: vec!["drupal".to_string(), "cms".to_string()],
        },
        DorkTemplate {
            id: "admin-joomla".to_string(),
            category: DorkCategory::AdminPanels,
            name: "Joomla Admin".to_string(),
            query_template: "site:{domain} inurl:administrator | inurl:/administrator/index.php".to_string(),
            description: "Find Joomla admin panels".to_string(),
            risk_level: "info".to_string(),
            is_builtin: true,
            tags: vec!["joomla".to_string(), "cms".to_string()],
        },
        DorkTemplate {
            id: "admin-phpmyadmin".to_string(),
            category: DorkCategory::AdminPanels,
            name: "phpMyAdmin".to_string(),
            query_template: "site:{domain} inurl:phpmyadmin | intitle:phpMyAdmin".to_string(),
            description: "Find phpMyAdmin installations".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["phpmyadmin".to_string(), "database".to_string(), "mysql".to_string()],
        },
        DorkTemplate {
            id: "admin-adminer".to_string(),
            category: DorkCategory::AdminPanels,
            name: "Adminer".to_string(),
            query_template: "site:{domain} inurl:adminer | intitle:Adminer".to_string(),
            description: "Find Adminer database admin panels".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["adminer".to_string(), "database".to_string()],
        },
        DorkTemplate {
            id: "admin-grafana".to_string(),
            category: DorkCategory::AdminPanels,
            name: "Grafana Dashboards".to_string(),
            query_template: "site:{domain} inurl:grafana | intitle:Grafana".to_string(),
            description: "Find Grafana monitoring dashboards".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["grafana".to_string(), "monitoring".to_string()],
        },
        DorkTemplate {
            id: "admin-jenkins".to_string(),
            category: DorkCategory::AdminPanels,
            name: "Jenkins".to_string(),
            query_template: "site:{domain} inurl:jenkins | intitle:\"Dashboard [Jenkins]\"".to_string(),
            description: "Find Jenkins CI/CD panels".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["jenkins".to_string(), "cicd".to_string()],
        },
    ]
}

fn directory_listings_templates() -> Vec<DorkTemplate> {
    vec![
        DorkTemplate {
            id: "dir-index-of".to_string(),
            category: DorkCategory::Directories,
            name: "Directory Index".to_string(),
            query_template: "site:{domain} intitle:\"Index of /\" | intitle:\"Directory listing\"".to_string(),
            description: "Find open directory listings".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["directory".to_string(), "listing".to_string()],
        },
        DorkTemplate {
            id: "dir-parent-directory".to_string(),
            category: DorkCategory::Directories,
            name: "Parent Directory Links".to_string(),
            query_template: "site:{domain} \"parent directory\" | \"last modified\" \"size\"".to_string(),
            description: "Find directory listings with parent links".to_string(),
            risk_level: "low".to_string(),
            is_builtin: true,
            tags: vec!["directory".to_string(), "browsing".to_string()],
        },
        DorkTemplate {
            id: "dir-uploads".to_string(),
            category: DorkCategory::Directories,
            name: "Upload Directories".to_string(),
            query_template: "site:{domain} inurl:(uploads | upload | files | attachments) intitle:\"Index of\"".to_string(),
            description: "Find exposed upload directories".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["uploads".to_string(), "files".to_string()],
        },
        DorkTemplate {
            id: "dir-includes".to_string(),
            category: DorkCategory::Directories,
            name: "Include Directories".to_string(),
            query_template: "site:{domain} inurl:(includes | inc | lib | libraries) intitle:\"Index of\"".to_string(),
            description: "Find exposed include/library directories".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["includes".to_string(), "libraries".to_string()],
        },
    ]
}

fn database_files_templates() -> Vec<DorkTemplate> {
    vec![
        DorkTemplate {
            id: "db-sql-files".to_string(),
            category: DorkCategory::DatabaseFiles,
            name: "SQL Dump Files".to_string(),
            query_template: "site:{domain} (filetype:sql | filetype:dump) (INSERT INTO | CREATE TABLE | DROP TABLE)".to_string(),
            description: "Find exposed SQL dump files".to_string(),
            risk_level: "critical".to_string(),
            is_builtin: true,
            tags: vec!["sql".to_string(), "dump".to_string(), "database".to_string()],
        },
        DorkTemplate {
            id: "db-sqlite".to_string(),
            category: DorkCategory::DatabaseFiles,
            name: "SQLite Databases".to_string(),
            query_template: "site:{domain} (filetype:db | filetype:sqlite | filetype:sqlite3)".to_string(),
            description: "Find exposed SQLite database files".to_string(),
            risk_level: "critical".to_string(),
            is_builtin: true,
            tags: vec!["sqlite".to_string(), "database".to_string()],
        },
        DorkTemplate {
            id: "db-mdb-accdb".to_string(),
            category: DorkCategory::DatabaseFiles,
            name: "Access Databases".to_string(),
            query_template: "site:{domain} (filetype:mdb | filetype:accdb)".to_string(),
            description: "Find exposed Microsoft Access database files".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["access".to_string(), "mdb".to_string(), "database".to_string()],
        },
        DorkTemplate {
            id: "db-mongodb-dump".to_string(),
            category: DorkCategory::DatabaseFiles,
            name: "MongoDB Dumps".to_string(),
            query_template: "site:{domain} (filetype:bson | filetype:json) (mongodump | _id | ObjectId)".to_string(),
            description: "Find exposed MongoDB dump files".to_string(),
            risk_level: "critical".to_string(),
            is_builtin: true,
            tags: vec!["mongodb".to_string(), "nosql".to_string()],
        },
    ]
}

fn backup_files_templates() -> Vec<DorkTemplate> {
    vec![
        DorkTemplate {
            id: "backup-archives".to_string(),
            category: DorkCategory::BackupFiles,
            name: "Backup Archives".to_string(),
            query_template: "site:{domain} (filetype:zip | filetype:tar | filetype:gz | filetype:rar | filetype:7z) (backup | bak | old)".to_string(),
            description: "Find backup archive files".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["backup".to_string(), "archive".to_string()],
        },
        DorkTemplate {
            id: "backup-bak-files".to_string(),
            category: DorkCategory::BackupFiles,
            name: "BAK Files".to_string(),
            query_template: "site:{domain} filetype:bak | filetype:backup | filetype:old".to_string(),
            description: "Find .bak and .old backup files".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["backup".to_string(), "bak".to_string()],
        },
        DorkTemplate {
            id: "backup-source-copies".to_string(),
            category: DorkCategory::BackupFiles,
            name: "Source Code Backups".to_string(),
            query_template: "site:{domain} (filetype:php~ | filetype:php.bak | filetype:php.old | filetype:aspx~ | filetype:jsp~)".to_string(),
            description: "Find backup copies of source code files".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["backup".to_string(), "source".to_string()],
        },
        DorkTemplate {
            id: "backup-swp-files".to_string(),
            category: DorkCategory::BackupFiles,
            name: "Vim Swap Files".to_string(),
            query_template: "site:{domain} filetype:swp | inurl:.swp".to_string(),
            description: "Find Vim swap/backup files".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["vim".to_string(), "swap".to_string()],
        },
    ]
}

fn api_endpoints_templates() -> Vec<DorkTemplate> {
    vec![
        DorkTemplate {
            id: "api-swagger".to_string(),
            category: DorkCategory::ApiEndpoints,
            name: "Swagger/OpenAPI".to_string(),
            query_template: "site:{domain} (inurl:swagger | inurl:openapi | inurl:api-docs) (filetype:json | filetype:yaml)".to_string(),
            description: "Find Swagger/OpenAPI documentation".to_string(),
            risk_level: "info".to_string(),
            is_builtin: true,
            tags: vec!["swagger".to_string(), "openapi".to_string(), "api".to_string()],
        },
        DorkTemplate {
            id: "api-graphql".to_string(),
            category: DorkCategory::ApiEndpoints,
            name: "GraphQL Endpoints".to_string(),
            query_template: "site:{domain} (inurl:graphql | inurl:graphiql | \"graphql\" \"query\")".to_string(),
            description: "Find GraphQL API endpoints".to_string(),
            risk_level: "info".to_string(),
            is_builtin: true,
            tags: vec!["graphql".to_string(), "api".to_string()],
        },
        DorkTemplate {
            id: "api-rest-endpoints".to_string(),
            category: DorkCategory::ApiEndpoints,
            name: "REST API Endpoints".to_string(),
            query_template: "site:{domain} inurl:(api/v1 | api/v2 | api/v3 | rest | /api/)".to_string(),
            description: "Find REST API endpoints".to_string(),
            risk_level: "info".to_string(),
            is_builtin: true,
            tags: vec!["rest".to_string(), "api".to_string()],
        },
        DorkTemplate {
            id: "api-wsdl".to_string(),
            category: DorkCategory::ApiEndpoints,
            name: "WSDL/SOAP Services".to_string(),
            query_template: "site:{domain} (filetype:wsdl | inurl:?wsdl | inurl:wsdl)".to_string(),
            description: "Find WSDL/SOAP web service definitions".to_string(),
            risk_level: "info".to_string(),
            is_builtin: true,
            tags: vec!["wsdl".to_string(), "soap".to_string(), "webservice".to_string()],
        },
        DorkTemplate {
            id: "api-postman".to_string(),
            category: DorkCategory::ApiEndpoints,
            name: "Postman Collections".to_string(),
            query_template: "site:{domain} (filetype:json) (\"postman\" | \"collection\" \"info\")".to_string(),
            description: "Find Postman API collections".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["postman".to_string(), "api".to_string()],
        },
    ]
}

fn cloud_storage_templates() -> Vec<DorkTemplate> {
    vec![
        DorkTemplate {
            id: "cloud-s3-buckets".to_string(),
            category: DorkCategory::CloudStorage,
            name: "AWS S3 Buckets".to_string(),
            query_template: "site:{domain} (\"s3.amazonaws.com\" | \"s3-\" | \".s3.\")".to_string(),
            description: "Find AWS S3 bucket references".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["aws".to_string(), "s3".to_string(), "cloud".to_string()],
        },
        DorkTemplate {
            id: "cloud-azure-storage".to_string(),
            category: DorkCategory::CloudStorage,
            name: "Azure Storage".to_string(),
            query_template: "site:{domain} (\".blob.core.windows.net\" | \".file.core.windows.net\")".to_string(),
            description: "Find Azure Blob/File storage references".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["azure".to_string(), "blob".to_string(), "cloud".to_string()],
        },
        DorkTemplate {
            id: "cloud-gcp-storage".to_string(),
            category: DorkCategory::CloudStorage,
            name: "Google Cloud Storage".to_string(),
            query_template: "site:{domain} (\"storage.googleapis.com\" | \"storage.cloud.google.com\")".to_string(),
            description: "Find Google Cloud Storage bucket references".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["gcp".to_string(), "gcs".to_string(), "cloud".to_string()],
        },
        DorkTemplate {
            id: "cloud-firebase".to_string(),
            category: DorkCategory::CloudStorage,
            name: "Firebase Storage".to_string(),
            query_template: "site:{domain} (\".firebaseio.com\" | \"firebasestorage.googleapis.com\")".to_string(),
            description: "Find Firebase database/storage references".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["firebase".to_string(), "google".to_string(), "cloud".to_string()],
        },
    ]
}

fn source_control_templates() -> Vec<DorkTemplate> {
    vec![
        DorkTemplate {
            id: "git-directory".to_string(),
            category: DorkCategory::SourceControl,
            name: "Git Directory".to_string(),
            query_template: "site:{domain} inurl:.git | intitle:\"Index of /.git\"".to_string(),
            description: "Find exposed .git directories".to_string(),
            risk_level: "critical".to_string(),
            is_builtin: true,
            tags: vec!["git".to_string(), "source".to_string()],
        },
        DorkTemplate {
            id: "git-config".to_string(),
            category: DorkCategory::SourceControl,
            name: "Git Configuration".to_string(),
            query_template: "site:{domain} (inurl:.git/config | \"[core]\" \"repositoryformatversion\")".to_string(),
            description: "Find exposed Git configuration files".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["git".to_string(), "config".to_string()],
        },
        DorkTemplate {
            id: "svn-entries".to_string(),
            category: DorkCategory::SourceControl,
            name: "SVN Entries".to_string(),
            query_template: "site:{domain} (inurl:.svn | intitle:\"Index of /.svn\" | inurl:svn/entries)".to_string(),
            description: "Find exposed SVN directories".to_string(),
            risk_level: "critical".to_string(),
            is_builtin: true,
            tags: vec!["svn".to_string(), "source".to_string()],
        },
        DorkTemplate {
            id: "gitignore".to_string(),
            category: DorkCategory::SourceControl,
            name: "Gitignore Files".to_string(),
            query_template: "site:{domain} filetype:gitignore | inurl:.gitignore".to_string(),
            description: "Find exposed .gitignore files revealing project structure".to_string(),
            risk_level: "low".to_string(),
            is_builtin: true,
            tags: vec!["git".to_string(), "gitignore".to_string()],
        },
        DorkTemplate {
            id: "hg-mercurial".to_string(),
            category: DorkCategory::SourceControl,
            name: "Mercurial Repository".to_string(),
            query_template: "site:{domain} inurl:.hg | intitle:\"Index of /.hg\"".to_string(),
            description: "Find exposed Mercurial repositories".to_string(),
            risk_level: "critical".to_string(),
            is_builtin: true,
            tags: vec!["mercurial".to_string(), "hg".to_string(), "source".to_string()],
        },
    ]
}

fn log_files_templates() -> Vec<DorkTemplate> {
    vec![
        DorkTemplate {
            id: "log-access-logs".to_string(),
            category: DorkCategory::LogFiles,
            name: "Web Server Access Logs".to_string(),
            query_template: "site:{domain} (filetype:log | inurl:access.log | inurl:access_log) \"GET\" \"HTTP\"".to_string(),
            description: "Find exposed web server access logs".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["log".to_string(), "access".to_string(), "webserver".to_string()],
        },
        DorkTemplate {
            id: "log-error-logs".to_string(),
            category: DorkCategory::LogFiles,
            name: "Error Logs".to_string(),
            query_template: "site:{domain} (filetype:log | inurl:error.log | inurl:error_log) (error | warning | exception)".to_string(),
            description: "Find exposed error log files".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["log".to_string(), "error".to_string()],
        },
        DorkTemplate {
            id: "log-debug-logs".to_string(),
            category: DorkCategory::LogFiles,
            name: "Debug Logs".to_string(),
            query_template: "site:{domain} (filetype:log | inurl:debug) (debug | trace | verbose)".to_string(),
            description: "Find exposed debug log files".to_string(),
            risk_level: "high".to_string(),
            is_builtin: true,
            tags: vec!["log".to_string(), "debug".to_string()],
        },
        DorkTemplate {
            id: "log-application-logs".to_string(),
            category: DorkCategory::LogFiles,
            name: "Application Logs".to_string(),
            query_template: "site:{domain} (filetype:log) (application | app | system) (error | exception | warning)".to_string(),
            description: "Find exposed application log files".to_string(),
            risk_level: "medium".to_string(),
            is_builtin: true,
            tags: vec!["log".to_string(), "application".to_string()],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_all_templates() {
        let templates = get_all_templates();
        assert!(!templates.is_empty());

        // Verify all categories have templates
        for category in DorkCategory::all() {
            let cat_templates = get_templates_by_category(category);
            assert!(!cat_templates.is_empty(), "Category {:?} has no templates", category);
        }
    }

    #[test]
    fn test_get_template_by_id() {
        let template = get_template_by_id("sensitive-password-files");
        assert!(template.is_some());

        let t = template.unwrap();
        assert_eq!(t.category, DorkCategory::SensitiveFiles);
    }

    #[test]
    fn test_search_templates() {
        let results = search_templates("password");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_get_templates_by_risk() {
        let critical = get_templates_by_risk("critical");
        assert!(!critical.is_empty());

        for t in critical {
            assert_eq!(t.risk_level, "critical");
        }
    }

    #[test]
    fn test_template_query_building() {
        let template = get_template_by_id("sensitive-password-files").unwrap();
        let query = template.build_query("example.com");
        assert!(query.contains("example.com"));
        assert!(!query.contains("{domain}"));
    }
}
