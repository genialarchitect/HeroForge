use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;

use crate::db::models::{CreateJiraTicketRequest, CreateJiraTicketResponse, UpsertJiraSettingsRequest};
use crate::integrations::jira::{
    format_vulnerability_description, severity_to_jira_priority, CreateIssueRequest, IssueFields,
    IssueType, JiraClient, Priority, ProjectKey,
};
use crate::web::auth;

/// Get JIRA settings for the current user
pub async fn get_jira_settings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match sqlx::query_as::<_, crate::db::models::JiraSettings>(
        "SELECT * FROM jira_settings WHERE user_id = ?",
    )
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(settings)) => HttpResponse::Ok().json(settings),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "JIRA settings not configured"
        })),
        Err(e) => {
            log::error!("Failed to get JIRA settings: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve JIRA settings"
            }))
        }
    }
}

/// Create or update JIRA settings for the current user
pub async fn upsert_jira_settings(
    pool: web::Data<SqlitePool>,
    request: web::Json<UpsertJiraSettingsRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let req = request.into_inner();
    let now = chrono::Utc::now();

    // Check if settings exist
    let exists: (i64,) = match sqlx::query_as(
        "SELECT COUNT(*) FROM jira_settings WHERE user_id = ?",
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to check JIRA settings: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to check JIRA settings"
            }));
        }
    };

    let query = if exists.0 > 0 {
        // Update existing settings
        sqlx::query(
            r#"
            UPDATE jira_settings
            SET jira_url = ?, username = ?, api_token = ?, project_key = ?,
                issue_type = ?, default_assignee = ?, enabled = ?, updated_at = ?
            WHERE user_id = ?
            "#,
        )
        .bind(&req.jira_url)
        .bind(&req.username)
        .bind(&req.api_token)
        .bind(&req.project_key)
        .bind(&req.issue_type)
        .bind(&req.default_assignee)
        .bind(req.enabled as i32)
        .bind(now)
        .bind(&claims.sub)
    } else {
        // Insert new settings
        sqlx::query(
            r#"
            INSERT INTO jira_settings (user_id, jira_url, username, api_token, project_key,
                                      issue_type, default_assignee, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&claims.sub)
        .bind(&req.jira_url)
        .bind(&req.username)
        .bind(&req.api_token)
        .bind(&req.project_key)
        .bind(&req.issue_type)
        .bind(&req.default_assignee)
        .bind(req.enabled as i32)
        .bind(now)
        .bind(now)
    };

    match query.execute(pool.get_ref()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "JIRA settings saved successfully"
        })),
        Err(e) => {
            log::error!("Failed to save JIRA settings: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to save JIRA settings"
            }))
        }
    }
}

/// Test JIRA connection with current settings
pub async fn test_jira_connection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Get JIRA settings
    let settings = match sqlx::query_as::<_, crate::db::models::JiraSettings>(
        "SELECT * FROM jira_settings WHERE user_id = ?",
    )
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "JIRA settings not configured"
            }))
        }
        Err(e) => {
            log::error!("Failed to get JIRA settings: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve JIRA settings"
            }));
        }
    };

    // Create JIRA client and test connection
    match JiraClient::new(settings.jira_url, settings.username, settings.api_token) {
        Ok(client) => match client.test_connection().await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                "message": "JIRA connection successful"
            })),
            Err(e) => {
                log::error!("JIRA connection test failed: {}", e);
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("JIRA connection failed: {}", e)
                }))
            }
        },
        Err(e) => {
            log::error!("Failed to create JIRA client: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create JIRA client: {}", e)
            }))
        }
    }
}

/// List available JIRA projects
pub async fn list_jira_projects(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Get JIRA settings
    let settings = match sqlx::query_as::<_, crate::db::models::JiraSettings>(
        "SELECT * FROM jira_settings WHERE user_id = ?",
    )
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "JIRA settings not configured"
            }))
        }
        Err(e) => {
            log::error!("Failed to get JIRA settings: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve JIRA settings"
            }));
        }
    };

    // Create JIRA client
    let client = match JiraClient::new(settings.jira_url, settings.username, settings.api_token) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to create JIRA client: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create JIRA client: {}", e)
            }));
        }
    };

    // List projects
    match client.list_projects().await {
        Ok(projects) => HttpResponse::Ok().json(projects),
        Err(e) => {
            log::error!("Failed to list JIRA projects: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to list JIRA projects: {}", e)
            }))
        }
    }
}

/// List available issue types for a project
pub async fn list_jira_issue_types(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Get JIRA settings
    let settings = match sqlx::query_as::<_, crate::db::models::JiraSettings>(
        "SELECT * FROM jira_settings WHERE user_id = ?",
    )
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "JIRA settings not configured"
            }))
        }
        Err(e) => {
            log::error!("Failed to get JIRA settings: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve JIRA settings"
            }));
        }
    };

    // Create JIRA client
    let client = match JiraClient::new(settings.jira_url.clone(), settings.username, settings.api_token) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to create JIRA client: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create JIRA client: {}", e)
            }));
        }
    };

    // List issue types
    match client.list_issue_types(&settings.project_key).await {
        Ok(issue_types) => HttpResponse::Ok().json(issue_types),
        Err(e) => {
            log::error!("Failed to list JIRA issue types: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to list JIRA issue types: {}", e)
            }))
        }
    }
}

/// Create a JIRA ticket from a vulnerability
pub async fn create_jira_ticket(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    request: web::Json<CreateJiraTicketRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let req = request.into_inner();

    // Get vulnerability details
    let vuln = match sqlx::query_as::<_, crate::db::models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?",
    )
    .bind(vuln_id.as_str())
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Vulnerability not found"
            }))
        }
        Err(e) => {
            log::error!("Failed to get vulnerability: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve vulnerability"
            }));
        }
    };

    // Check if JIRA ticket already exists
    if vuln.jira_ticket_id.is_some() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "JIRA ticket already exists for this vulnerability",
            "jira_ticket_id": vuln.jira_ticket_id,
            "jira_ticket_key": vuln.jira_ticket_key
        }));
    }

    // Get JIRA settings
    let settings = match sqlx::query_as::<_, crate::db::models::JiraSettings>(
        "SELECT * FROM jira_settings WHERE user_id = ?",
    )
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "JIRA settings not configured"
            }))
        }
        Err(e) => {
            log::error!("Failed to get JIRA settings: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve JIRA settings"
            }));
        }
    };

    if !settings.enabled {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "JIRA integration is disabled"
        }));
    }

    // Create JIRA client
    let client = match JiraClient::new(settings.jira_url.clone(), settings.username, settings.api_token) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to create JIRA client: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create JIRA client: {}", e)
            }));
        }
    };

    // Format vulnerability description
    let description = format_vulnerability_description(
        &vuln.vulnerability_id,
        &vuln.host_ip,
        vuln.port,
        &vuln.severity,
        vuln.notes.as_deref(),
    );

    // Map severity to JIRA priority
    let priority = severity_to_jira_priority(&vuln.severity);

    // Create JIRA issue request
    let summary = format!(
        "[{}] {} on {}",
        vuln.severity.to_uppercase(),
        vuln.vulnerability_id,
        vuln.host_ip
    );

    let fields = IssueFields {
        project: ProjectKey {
            key: settings.project_key,
        },
        summary,
        description,
        issuetype: IssueType {
            name: settings.issue_type,
        },
        priority: Some(Priority {
            name: priority.to_string(),
        }),
        assignee: req.assignee.or(settings.default_assignee).map(|name| crate::integrations::jira::Assignee { name }),
        labels: req.labels,
    };

    let issue_request = CreateIssueRequest { fields };

    // Create JIRA issue
    let issue_response = match client.create_issue(issue_request).await {
        Ok(resp) => resp,
        Err(e) => {
            log::error!("Failed to create JIRA issue: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create JIRA issue: {}", e)
            }));
        }
    };

    // Update vulnerability with JIRA ticket ID
    match sqlx::query(
        "UPDATE vulnerability_tracking SET jira_ticket_id = ?, jira_ticket_key = ?, updated_at = ? WHERE id = ?",
    )
    .bind(&issue_response.id)
    .bind(&issue_response.key)
    .bind(chrono::Utc::now())
    .bind(vuln_id.as_str())
    .execute(pool.get_ref())
    .await
    {
        Ok(_) => {
            log::info!(
                "Created JIRA ticket {} for vulnerability {}",
                issue_response.key,
                vuln_id
            );
            HttpResponse::Created().json(CreateJiraTicketResponse {
                jira_ticket_id: issue_response.id,
                jira_ticket_key: issue_response.key,
                jira_ticket_url: issue_response.self_url,
            })
        }
        Err(e) => {
            log::error!("Failed to update vulnerability with JIRA ticket: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "JIRA ticket created but failed to update vulnerability record"
            }))
        }
    }
}
