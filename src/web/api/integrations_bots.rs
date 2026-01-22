//! Bot Integration API
//!
//! Provides endpoints for Slack and Microsoft Teams bot integrations.

use actix_web::{web, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::integrations::slack::{DashboardStats as SlackDashboardStats, HeroForgeCommand, SlackBot, SlashCommandRequest, VulnSummary};
use crate::integrations::teams::{DashboardStats as TeamsDashboardStats, TeamsActivity, TeamsBot, TeamsCommand};
use crate::web::auth;
use crate::web::error::ApiError;

/// Configure bot integration routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/integrations")
            // Slack endpoints
            .route("/slack/workspaces", web::get().to(list_slack_workspaces))
            .route("/slack/workspaces", web::post().to(create_slack_workspace))
            .route("/slack/workspaces/{id}", web::get().to(get_slack_workspace))
            .route("/slack/workspaces/{id}", web::put().to(update_slack_workspace))
            .route("/slack/workspaces/{id}", web::delete().to(delete_slack_workspace))
            .route("/slack/workspaces/{id}/test", web::post().to(test_slack_connection))
            .route("/slack/commands", web::post().to(handle_slack_command))
            .route("/slack/events", web::post().to(handle_slack_events))
            // Teams endpoints
            .route("/teams/tenants", web::get().to(list_teams_tenants))
            .route("/teams/tenants", web::post().to(create_teams_tenant))
            .route("/teams/tenants/{id}", web::get().to(get_teams_tenant))
            .route("/teams/tenants/{id}", web::put().to(update_teams_tenant))
            .route("/teams/tenants/{id}", web::delete().to(delete_teams_tenant))
            .route("/teams/tenants/{id}/test", web::post().to(test_teams_connection))
            .route("/teams/messages", web::post().to(handle_teams_message)),
    );
}

// ============================================================================
// Slack Workspace Management
// ============================================================================

#[derive(Debug, Serialize)]
pub struct SlackWorkspaceResponse {
    pub id: String,
    pub workspace_id: String,
    pub workspace_name: String,
    pub default_channel_id: Option<String>,
    pub default_channel_name: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateSlackWorkspaceRequest {
    pub workspace_id: String,
    pub workspace_name: String,
    pub bot_token: String,
    pub signing_secret: String,
    pub default_channel_id: Option<String>,
    pub default_channel_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSlackWorkspaceRequest {
    pub workspace_name: Option<String>,
    pub bot_token: Option<String>,
    pub signing_secret: Option<String>,
    pub default_channel_id: Option<String>,
    pub default_channel_name: Option<String>,
    pub is_active: Option<bool>,
}

/// List Slack workspaces
async fn list_slack_workspaces(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    use sqlx::Row;

    let rows = sqlx::query(
        r#"
        SELECT id, workspace_id, workspace_name, default_channel_id, default_channel_name,
               is_active, created_at, updated_at
        FROM slack_workspaces
        ORDER BY workspace_name
        "#,
    )
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to list workspaces: {}", e)))?;

    let workspaces: Vec<SlackWorkspaceResponse> = rows
        .iter()
        .map(|row| SlackWorkspaceResponse {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            workspace_name: row.get("workspace_name"),
            default_channel_id: row.get("default_channel_id"),
            default_channel_name: row.get("default_channel_name"),
            is_active: row.get::<i32, _>("is_active") == 1,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
        .collect();

    Ok(HttpResponse::Ok().json(workspaces))
}

/// Create Slack workspace
async fn create_slack_workspace(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateSlackWorkspaceRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO slack_workspaces (
            id, workspace_id, workspace_name, bot_token, signing_secret,
            default_channel_id, default_channel_name, is_active, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&body.workspace_id)
    .bind(&body.workspace_name)
    .bind(&body.bot_token)
    .bind(&body.signing_secret)
    .bind(&body.default_channel_id)
    .bind(&body.default_channel_name)
    .bind(&now)
    .bind(&now)
    .execute(pool.as_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create workspace: {}", e)))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "Slack workspace created"
    })))
}

/// Get Slack workspace
async fn get_slack_workspace(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    use sqlx::Row;

    let id = path.into_inner();

    let row = sqlx::query(
        r#"
        SELECT id, workspace_id, workspace_name, default_channel_id, default_channel_name,
               is_active, created_at, updated_at
        FROM slack_workspaces
        WHERE id = ?
        "#,
    )
    .bind(&id)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to get workspace: {}", e)))?;

    match row {
        Some(row) => {
            let workspace = SlackWorkspaceResponse {
                id: row.get("id"),
                workspace_id: row.get("workspace_id"),
                workspace_name: row.get("workspace_name"),
                default_channel_id: row.get("default_channel_id"),
                default_channel_name: row.get("default_channel_name"),
                is_active: row.get::<i32, _>("is_active") == 1,
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            };
            Ok(HttpResponse::Ok().json(workspace))
        }
        None => Err(ApiError::not_found("Workspace not found")),
    }
}

/// Update Slack workspace
async fn update_slack_workspace(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<UpdateSlackWorkspaceRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    let mut updates = vec!["updated_at = ?".to_string()];
    let mut values: Vec<String> = vec![now.clone()];

    if let Some(ref name) = body.workspace_name {
        updates.push("workspace_name = ?".to_string());
        values.push(name.clone());
    }
    if let Some(ref token) = body.bot_token {
        updates.push("bot_token = ?".to_string());
        values.push(token.clone());
    }
    if let Some(ref secret) = body.signing_secret {
        updates.push("signing_secret = ?".to_string());
        values.push(secret.clone());
    }
    if let Some(ref channel_id) = body.default_channel_id {
        updates.push("default_channel_id = ?".to_string());
        values.push(channel_id.clone());
    }
    if let Some(ref channel_name) = body.default_channel_name {
        updates.push("default_channel_name = ?".to_string());
        values.push(channel_name.clone());
    }
    if let Some(is_active) = body.is_active {
        updates.push("is_active = ?".to_string());
        values.push(if is_active { "1".to_string() } else { "0".to_string() });
    }

    let sql = format!(
        "UPDATE slack_workspaces SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut query = sqlx::query(&sql);
    for value in &values {
        query = query.bind(value);
    }
    query = query.bind(&id);

    let result = query
        .execute(pool.as_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to update workspace: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Workspace not found"));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Workspace updated"
    })))
}

/// Delete Slack workspace
async fn delete_slack_workspace(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    let result = sqlx::query("DELETE FROM slack_workspaces WHERE id = ?")
        .bind(&id)
        .execute(pool.as_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to delete workspace: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Workspace not found"));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Workspace deleted"
    })))
}

/// Test Slack connection
async fn test_slack_connection(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    use sqlx::Row;

    let id = path.into_inner();

    let row = sqlx::query("SELECT bot_token FROM slack_workspaces WHERE id = ?")
        .bind(&id)
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get workspace: {}", e)))?;

    let bot_token: String = match row {
        Some(r) => r.get("bot_token"),
        None => return Err(ApiError::not_found("Workspace not found")),
    };

    let client = reqwest::Client::new();
    let response = client
        .post("https://slack.com/api/auth.test")
        .bearer_auth(&bot_token)
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("Failed to test connection: {}", e)))?;

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| ApiError::internal(format!("Failed to parse response: {}", e)))?;

    let ok = body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);

    if ok {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "team": body.get("team"),
            "user": body.get("user")
        })))
    } else {
        Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": body.get("error")
        })))
    }
}

/// Handle Slack slash command (public endpoint, no auth)
async fn handle_slack_command(
    pool: web::Data<SqlitePool>,
    body: web::Form<SlashCommandRequest>,
) -> Result<HttpResponse, ApiError> {
    use sqlx::Row;

    // Log the command
    let log_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Get workspace by team_id
    let workspace = sqlx::query(
        "SELECT id, bot_token FROM slack_workspaces WHERE workspace_id = ? AND is_active = 1",
    )
    .bind(&body.team_id)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to lookup workspace: {}", e)))?;

    let workspace_id = match &workspace {
        Some(w) => w.get::<String, _>("id"),
        None => {
            return Ok(HttpResponse::Ok().json(SlackBot::build_error_response(
                "This workspace is not configured. Please contact your administrator.",
            )));
        }
    };

    // Parse command
    let command = SlackBot::parse_command(&body.text);

    // Log the command
    let _ = sqlx::query(
        r#"
        INSERT INTO slack_command_logs (
            id, workspace_id, channel_id, user_id, user_name, command, command_text,
            success, executed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
        "#,
    )
    .bind(&log_id)
    .bind(&workspace_id)
    .bind(&body.channel_id)
    .bind(&body.user_id)
    .bind(&body.user_name)
    .bind(&body.command)
    .bind(&body.text)
    .bind(&now)
    .execute(pool.as_ref())
    .await;

    // Handle command
    let response = match command {
        HeroForgeCommand::Help => SlackBot::build_help_response(),
        HeroForgeCommand::Status => {
            // Get dashboard stats from database
            let stats = get_dashboard_stats(&pool).await.unwrap_or_default();
            SlackBot::build_status_response(&stats)
        }
        HeroForgeCommand::Vulns { severity } => {
            let vulns = get_vulnerabilities(&pool, severity.as_deref()).await.unwrap_or_default();
            SlackBot::build_vulns_response(&vulns, severity.as_deref())
        }
        HeroForgeCommand::Scan { target } => {
            // Get or create a system user ID for bot-initiated scans
            let bot_user_id = format!("bot_{}", workspace_id);

            // Create scan in database with default settings
            match crate::db::create_scan(
                pool.as_ref(),
                &bot_user_id,
                &format!("Bot scan: {}", target),
                &vec![target.clone()],
                None, // no customer_id
                None, // no engagement_id
            ).await {
                Ok(scan) => {
                    let scan_id = scan.id.clone();
                    let scan_id_for_response = scan_id.clone();
                    let pool_clone = pool.get_ref().clone();
                    let targets = vec![target.clone()];

                    // Spawn background scan task
                    tokio::spawn(async move {
                        use crate::types::{ScanConfig, ScanType, ScanProgressMessage};
                        use crate::web::broadcast::create_scan_channel;

                        log::info!("Starting bot-initiated scan {} for target {}", scan_id, targets.join(", "));

                        // Create broadcast channel
                        let tx = create_scan_channel(scan_id.clone()).await;

                        // Update status to running
                        let _ = crate::db::update_scan_status(&pool_clone, &scan_id, "running", None, None).await;

                        // Send scan started message
                        let _ = tx.send(ScanProgressMessage::ScanStarted {
                            scan_id: scan_id.clone(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        });

                        // Configure scan with default settings (quick scan)
                        let config = ScanConfig {
                            targets,
                            port_range: (1, 1000), // Common ports only
                            threads: 100,
                            timeout: std::time::Duration::from_secs(3),
                            scan_type: ScanType::TCPConnect,
                            enable_os_detection: true,
                            enable_service_detection: true,
                            enable_vuln_scan: true,
                            enable_enumeration: false, // Skip enumeration for quick scan
                            enum_depth: crate::scanner::enumeration::types::EnumDepth::Light,
                            enum_wordlist_path: None,
                            enum_services: vec![],
                            output_format: crate::types::OutputFormat::Json,
                            udp_port_range: None,
                            udp_retries: 2,
                            skip_host_discovery: false,
                            service_detection_timeout: None,
                            dns_timeout: None,
                            syn_timeout: None,
                            udp_timeout: None,
                            vpn_config_id: None,
                            exclusions: vec![],
                        };

                        // Run the scan
                        match crate::scanner::run_scan(&config, Some(tx.clone())).await {
                            Ok(results) => {
                                // Calculate totals - results is Vec<HostInfo>
                                let total_hosts = results.len();
                                let total_ports: usize = results.iter().map(|h| h.ports.len()).sum();
                                let total_vulns: usize = results.iter().map(|h| h.vulnerabilities.len()).sum();

                                // Log the scan completion
                                log::info!("Bot scan {} completed: {} hosts, {} ports, {} vulnerabilities",
                                    scan_id, total_hosts, total_ports, total_vulns);

                                // Update scan as completed
                                let _ = crate::db::update_scan_status(
                                    &pool_clone,
                                    &scan_id,
                                    "completed",
                                    None, // results JSON would go here if needed
                                    None,
                                ).await;

                                let _ = tx.send(ScanProgressMessage::ScanCompleted {
                                    scan_id: scan_id.clone(),
                                    duration: 0.0, // Actual duration would need timing
                                    total_hosts,
                                });
                            }
                            Err(e) => {
                                log::error!("Scan {} failed: {}", scan_id, e);
                                let _ = crate::db::update_scan_status(
                                    &pool_clone,
                                    &scan_id,
                                    "failed",
                                    None,
                                    Some(&e.to_string()),
                                ).await;

                                let _ = tx.send(ScanProgressMessage::Error {
                                    message: format!("Scan {} failed: {}", scan_id, e),
                                });
                            }
                        }

                        // Cleanup broadcast channel
                        crate::web::broadcast::remove_scan_channel(&scan_id).await;
                    });

                    SlackBot::build_scan_response(&target, &scan_id_for_response)
                }
                Err(e) => {
                    log::error!("Failed to create bot scan: {}", e);
                    SlackBot::build_error_response(&format!("Failed to start scan: {}", e))
                }
            }
        }
        HeroForgeCommand::Report { scan_id } => {
            let report_url = format!("https://heroforge.genialarchitect.io/reports/{}", scan_id);
            SlackBot::build_report_response(&scan_id, &report_url)
        }
        HeroForgeCommand::Unknown(cmd) => {
            SlackBot::build_error_response(&format!("Unknown command: {}. Try /heroforge help", cmd))
        }
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Handle Slack events (public endpoint for event subscriptions)
async fn handle_slack_events(
    body: web::Json<serde_json::Value>,
) -> Result<HttpResponse, ApiError> {
    // Handle URL verification challenge
    if let Some(challenge) = body.get("challenge") {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "challenge": challenge
        })));
    }

    // Handle other events
    let event_type = body
        .get("event")
        .and_then(|e| e.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("unknown");

    log::info!("Received Slack event: {}", event_type);

    // Acknowledge event
    Ok(HttpResponse::Ok().finish())
}

// ============================================================================
// Teams Tenant Management
// ============================================================================

#[derive(Debug, Serialize)]
pub struct TeamsTenantResponse {
    pub id: String,
    pub tenant_id: String,
    pub tenant_name: String,
    pub default_team_id: Option<String>,
    pub default_channel_id: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateTeamsTenantRequest {
    pub tenant_id: String,
    pub tenant_name: String,
    pub app_id: String,
    pub app_secret: String,
    pub default_team_id: Option<String>,
    pub default_channel_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTeamsTenantRequest {
    pub tenant_name: Option<String>,
    pub app_id: Option<String>,
    pub app_secret: Option<String>,
    pub default_team_id: Option<String>,
    pub default_channel_id: Option<String>,
    pub is_active: Option<bool>,
}

/// List Teams tenants
async fn list_teams_tenants(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    use sqlx::Row;

    let rows = sqlx::query(
        r#"
        SELECT id, tenant_id, tenant_name, default_team_id, default_channel_id,
               is_active, created_at, updated_at
        FROM teams_tenants
        ORDER BY tenant_name
        "#,
    )
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to list tenants: {}", e)))?;

    let tenants: Vec<TeamsTenantResponse> = rows
        .iter()
        .map(|row| TeamsTenantResponse {
            id: row.get("id"),
            tenant_id: row.get("tenant_id"),
            tenant_name: row.get("tenant_name"),
            default_team_id: row.get("default_team_id"),
            default_channel_id: row.get("default_channel_id"),
            is_active: row.get::<i32, _>("is_active") == 1,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
        .collect();

    Ok(HttpResponse::Ok().json(tenants))
}

/// Create Teams tenant
async fn create_teams_tenant(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateTeamsTenantRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO teams_tenants (
            id, tenant_id, tenant_name, app_id, app_secret,
            default_team_id, default_channel_id, is_active, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&body.tenant_id)
    .bind(&body.tenant_name)
    .bind(&body.app_id)
    .bind(&body.app_secret)
    .bind(&body.default_team_id)
    .bind(&body.default_channel_id)
    .bind(&now)
    .bind(&now)
    .execute(pool.as_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create tenant: {}", e)))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "Teams tenant created"
    })))
}

/// Get Teams tenant
async fn get_teams_tenant(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    use sqlx::Row;

    let id = path.into_inner();

    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, tenant_name, default_team_id, default_channel_id,
               is_active, created_at, updated_at
        FROM teams_tenants
        WHERE id = ?
        "#,
    )
    .bind(&id)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to get tenant: {}", e)))?;

    match row {
        Some(row) => {
            let tenant = TeamsTenantResponse {
                id: row.get("id"),
                tenant_id: row.get("tenant_id"),
                tenant_name: row.get("tenant_name"),
                default_team_id: row.get("default_team_id"),
                default_channel_id: row.get("default_channel_id"),
                is_active: row.get::<i32, _>("is_active") == 1,
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            };
            Ok(HttpResponse::Ok().json(tenant))
        }
        None => Err(ApiError::not_found("Tenant not found")),
    }
}

/// Update Teams tenant
async fn update_teams_tenant(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<UpdateTeamsTenantRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    let mut updates = vec!["updated_at = ?".to_string()];
    let mut values: Vec<String> = vec![now.clone()];

    if let Some(ref name) = body.tenant_name {
        updates.push("tenant_name = ?".to_string());
        values.push(name.clone());
    }
    if let Some(ref app_id) = body.app_id {
        updates.push("app_id = ?".to_string());
        values.push(app_id.clone());
    }
    if let Some(ref app_secret) = body.app_secret {
        updates.push("app_secret = ?".to_string());
        values.push(app_secret.clone());
    }
    if let Some(ref team_id) = body.default_team_id {
        updates.push("default_team_id = ?".to_string());
        values.push(team_id.clone());
    }
    if let Some(ref channel_id) = body.default_channel_id {
        updates.push("default_channel_id = ?".to_string());
        values.push(channel_id.clone());
    }
    if let Some(is_active) = body.is_active {
        updates.push("is_active = ?".to_string());
        values.push(if is_active { "1".to_string() } else { "0".to_string() });
    }

    let sql = format!(
        "UPDATE teams_tenants SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut query = sqlx::query(&sql);
    for value in &values {
        query = query.bind(value);
    }
    query = query.bind(&id);

    let result = query
        .execute(pool.as_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to update tenant: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Tenant not found"));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Tenant updated"
    })))
}

/// Delete Teams tenant
async fn delete_teams_tenant(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();

    let result = sqlx::query("DELETE FROM teams_tenants WHERE id = ?")
        .bind(&id)
        .execute(pool.as_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to delete tenant: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Tenant not found"));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Tenant deleted"
    })))
}

/// Test Teams connection
async fn test_teams_connection(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    use sqlx::Row;

    let id = path.into_inner();

    let row = sqlx::query("SELECT tenant_id, app_id, app_secret FROM teams_tenants WHERE id = ?")
        .bind(&id)
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get tenant: {}", e)))?;

    let (tenant_id, app_id, app_secret): (String, String, String) = match row {
        Some(r) => (r.get("tenant_id"), r.get("app_id"), r.get("app_secret")),
        None => return Err(ApiError::not_found("Tenant not found")),
    };

    // Try to get an access token from Microsoft identity platform
    let client = reqwest::Client::new();
    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );

    let response = client
        .post(&token_url)
        .form(&[
            ("client_id", app_id.as_str()),
            ("client_secret", app_secret.as_str()),
            ("scope", "https://graph.microsoft.com/.default"),
            ("grant_type", "client_credentials"),
        ])
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("Failed to test connection: {}", e)))?;

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| ApiError::internal(format!("Failed to parse response: {}", e)))?;

    if body.get("access_token").is_some() {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Connection successful"
        })))
    } else {
        Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": body.get("error_description").or(body.get("error"))
        })))
    }
}

/// Handle Teams bot message (public endpoint)
async fn handle_teams_message(
    pool: web::Data<SqlitePool>,
    body: web::Json<TeamsActivity>,
) -> Result<HttpResponse, ApiError> {
    use sqlx::Row;

    // Extract conversation info
    let conversation = &body.conversation;
    let from = &body.from;

    // Parse command from message text
    let text = body.text.as_deref().unwrap_or("");
    let command = TeamsBot::parse_command(text);

    // Log the command
    let log_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Try to find the tenant (only if tenant_id is present)
    let tenant = if let Some(ref tid) = conversation.tenant_id {
        sqlx::query(
            "SELECT id FROM teams_tenants WHERE tenant_id = ? AND is_active = 1",
        )
        .bind(tid)
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to lookup tenant: {}", e)))?
    } else {
        None
    };

    if let Some(tenant_row) = tenant {
        let tenant_id: String = tenant_row.get("id");

        let _ = sqlx::query(
            r#"
            INSERT INTO teams_command_logs (
                id, tenant_id, team_id, channel_id, user_id, user_name, command,
                command_text, success, executed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            "#,
        )
        .bind(&log_id)
        .bind(&tenant_id)
        .bind(&conversation.id)
        .bind(&conversation.id)
        .bind(&from.id)
        .bind(&from.name)
        .bind(&body.activity_type)
        .bind(text)
        .bind(&now)
        .execute(pool.as_ref())
        .await;
    }

    // Build response based on command
    let response = match command {
        TeamsCommand::Help => TeamsBot::build_help_card(),
        TeamsCommand::Status => {
            let stats = get_teams_dashboard_stats(&pool).await.unwrap_or_default();
            TeamsBot::build_status_card(&stats)
        }
        TeamsCommand::Vulns { severity } => {
            let vulns = get_vulnerabilities(&pool, severity.as_deref()).await.unwrap_or_default();
            TeamsBot::build_vulns_card(&vulns, severity.as_deref())
        }
        TeamsCommand::Scan { target } => {
            let scan_id = Uuid::new_v4().to_string();
            TeamsBot::build_scan_card(&target, &scan_id)
        }
        TeamsCommand::Report { scan_id } => {
            let report_url = format!("https://heroforge.genialarchitect.io/reports/{}", scan_id);
            TeamsBot::build_report_card(&scan_id, &report_url)
        }
        TeamsCommand::Unknown(cmd) => TeamsBot::build_error_card(&format!(
            "Unknown command: {}. Try 'help' for available commands.",
            cmd
        )),
    };

    Ok(HttpResponse::Ok().json(response))
}

// ============================================================================
// Helper functions
// ============================================================================

/// Get dashboard stats for Slack bot responses
async fn get_dashboard_stats(pool: &SqlitePool) -> Result<SlackDashboardStats, ApiError> {
    use sqlx::Row;

    let row = sqlx::query(
        r#"
        SELECT
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
        FROM vulnerability_tracking
        WHERE status != 'resolved'
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to get stats: {}", e)))?;

    let scan_count = sqlx::query_scalar::<_, i32>("SELECT COUNT(*) FROM scan_results")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    let active_scans = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM scan_results WHERE status = 'running'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let host_count = sqlx::query_scalar::<_, i32>("SELECT COUNT(DISTINCT ip) FROM assets")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    Ok(SlackDashboardStats {
        critical_count: row.get::<Option<i32>, _>("critical").unwrap_or(0),
        high_count: row.get::<Option<i32>, _>("high").unwrap_or(0),
        medium_count: row.get::<Option<i32>, _>("medium").unwrap_or(0),
        low_count: row.get::<Option<i32>, _>("low").unwrap_or(0),
        active_scans,
        total_hosts: host_count,
        total_scans: scan_count,
    })
}

/// Get dashboard stats for Teams bot responses
async fn get_teams_dashboard_stats(pool: &SqlitePool) -> Result<TeamsDashboardStats, ApiError> {
    use sqlx::Row;

    let row = sqlx::query(
        r#"
        SELECT
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
        FROM vulnerability_tracking
        WHERE status != 'resolved'
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to get stats: {}", e)))?;

    let scan_count = sqlx::query_scalar::<_, i32>("SELECT COUNT(*) FROM scan_results")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    let active_scans = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM scan_results WHERE status = 'running'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let host_count = sqlx::query_scalar::<_, i32>("SELECT COUNT(DISTINCT ip) FROM assets")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    Ok(TeamsDashboardStats {
        critical_count: row.get::<Option<i32>, _>("critical").unwrap_or(0),
        high_count: row.get::<Option<i32>, _>("high").unwrap_or(0),
        medium_count: row.get::<Option<i32>, _>("medium").unwrap_or(0),
        low_count: row.get::<Option<i32>, _>("low").unwrap_or(0),
        active_scans,
        total_hosts: host_count,
        total_scans: scan_count,
    })
}

/// Get vulnerabilities for bot responses
async fn get_vulnerabilities(
    pool: &SqlitePool,
    severity_filter: Option<&str>,
) -> Result<Vec<VulnSummary>, ApiError> {
    use sqlx::Row;

    let mut sql = String::from(
        r#"
        SELECT id, title, severity, host
        FROM vulnerability_tracking
        WHERE status != 'resolved'
        "#,
    );

    if let Some(sev) = severity_filter {
        sql.push_str(&format!(" AND severity = '{}'", sev));
    }

    sql.push_str(" ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END LIMIT 20");

    let rows = sqlx::query(&sql)
        .fetch_all(pool)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get vulns: {}", e)))?;

    let vulns: Vec<VulnSummary> = rows
        .iter()
        .map(|row| VulnSummary {
            id: row.get("id"),
            title: row.get("title"),
            severity: row.get("severity"),
            host: row.get("host"),
        })
        .collect();

    Ok(vulns)
}
