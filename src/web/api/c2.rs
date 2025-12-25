//! C2 Framework API Endpoints
//!
//! REST API for managing C2 framework integrations, sessions, and tasks.

use actix_web::{web, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::c2::{
    C2Manager, CreateC2ConfigRequest, CreateListenerRequest, ExecuteTaskRequest,
    GenerateImplantRequest, ImplantConfig, ImplantType, ImplantFormat,
};
use crate::web::auth;
use crate::web::error::ApiError;

/// Configure C2 routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/c2")
            // Dashboard
            .route("/dashboard", web::get().to(get_dashboard))
            // C2 server configurations
            .route("/servers", web::post().to(create_server))
            .route("/servers", web::get().to(list_servers))
            .route("/servers/{id}", web::get().to(get_server))
            .route("/servers/{id}", web::delete().to(delete_server))
            .route("/servers/{id}/connect", web::post().to(connect_server))
            .route("/servers/{id}/disconnect", web::post().to(disconnect_server))
            .route("/servers/{id}/sync", web::post().to(sync_sessions))
            // Listeners
            .route("/servers/{id}/listeners", web::get().to(list_listeners))
            .route("/servers/{id}/listeners", web::post().to(create_listener))
            .route("/servers/{id}/listeners/{listener_id}", web::delete().to(stop_listener))
            // Sessions
            .route("/servers/{id}/sessions", web::get().to(list_sessions))
            .route("/sessions/{session_id}", web::get().to(get_session))
            .route("/sessions/{session_id}", web::delete().to(kill_session))
            .route("/sessions/{session_id}/tasks", web::get().to(list_tasks))
            .route("/sessions/{session_id}/tasks", web::post().to(execute_task))
            // Implants
            .route("/servers/{id}/implants", web::get().to(list_implants))
            .route("/servers/{id}/implants/generate", web::post().to(generate_implant))
            .route("/implants/{implant_id}/download", web::get().to(download_implant))
            // Credentials
            .route("/credentials", web::get().to(list_credentials)),
    );
}

#[derive(Deserialize)]
struct ListQuery {
    limit: Option<i32>,
    offset: Option<i32>,
}

// ============================================================================
// Dashboard
// ============================================================================

async fn get_dashboard(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let manager = C2Manager::new(pool.get_ref().clone());
    let stats = manager.get_dashboard_stats(&claims.sub).await?;
    Ok(HttpResponse::Ok().json(stats))
}

// ============================================================================
// C2 Server Configuration
// ============================================================================

async fn create_server(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CreateC2ConfigRequest>,
) -> Result<HttpResponse, ApiError> {
    let manager = C2Manager::new(pool.get_ref().clone());
    let config = manager.create_config(&claims.sub, body.into_inner()).await?;
    Ok(HttpResponse::Created().json(config))
}

async fn list_servers(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let manager = C2Manager::new(pool.get_ref().clone());
    let servers = manager.list_configs(&claims.sub).await?;
    Ok(HttpResponse::Ok().json(servers))
}

async fn get_server(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();
    let manager = C2Manager::new(pool.get_ref().clone());

    let config = manager.get_config(&config_id).await?
        .ok_or_else(|| ApiError::not_found("C2 server not found"))?;

    if config.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    Ok(HttpResponse::Ok().json(config))
}

async fn delete_server(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();
    let manager = C2Manager::new(pool.get_ref().clone());

    // Check ownership
    let config = manager.get_config(&config_id).await?
        .ok_or_else(|| ApiError::not_found("C2 server not found"))?;

    if config.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    manager.delete_config(&config_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn connect_server(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();
    let manager = C2Manager::new(pool.get_ref().clone());

    // Check ownership
    let config = manager.get_config(&config_id).await?
        .ok_or_else(|| ApiError::not_found("C2 server not found"))?;

    if config.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let connected = manager.connect(&config_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "connected": connected
    })))
}

async fn disconnect_server(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();
    let manager = C2Manager::new(pool.get_ref().clone());

    // Check ownership
    let config = manager.get_config(&config_id).await?
        .ok_or_else(|| ApiError::not_found("C2 server not found"))?;

    if config.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    manager.disconnect(&config_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "connected": false
    })))
}

async fn sync_sessions(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();
    let manager = C2Manager::new(pool.get_ref().clone());

    // Check ownership
    let config = manager.get_config(&config_id).await?
        .ok_or_else(|| ApiError::not_found("C2 server not found"))?;

    if config.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let sessions = manager.sync_sessions(&config_id).await?;

    Ok(HttpResponse::Ok().json(sessions))
}

// ============================================================================
// Listeners
// ============================================================================

async fn list_listeners(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();
    let manager = C2Manager::new(pool.get_ref().clone());

    // Check ownership
    let config = manager.get_config(&config_id).await?
        .ok_or_else(|| ApiError::not_found("C2 server not found"))?;

    if config.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let client = manager.get_client(&config_id).await
        .ok_or_else(|| ApiError::bad_request("Not connected to C2 server"))?;

    let listeners = client.list_listeners().await?;

    Ok(HttpResponse::Ok().json(listeners))
}

async fn create_listener(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<CreateListenerRequest>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();
    let manager = C2Manager::new(pool.get_ref().clone());

    // Check ownership
    let config = manager.get_config(&config_id).await?
        .ok_or_else(|| ApiError::not_found("C2 server not found"))?;

    if config.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let client = manager.get_client(&config_id).await
        .ok_or_else(|| ApiError::bad_request("Not connected to C2 server"))?;

    let listener = client.start_listener(&body.into_inner()).await?;

    Ok(HttpResponse::Created().json(listener))
}

async fn stop_listener(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (config_id, listener_id) = path.into_inner();
    let manager = C2Manager::new(pool.get_ref().clone());

    // Check ownership
    let config = manager.get_config(&config_id).await?
        .ok_or_else(|| ApiError::not_found("C2 server not found"))?;

    if config.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let client = manager.get_client(&config_id).await
        .ok_or_else(|| ApiError::bad_request("Not connected to C2 server"))?;

    client.stop_listener(&listener_id).await?;

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Sessions
// ============================================================================

async fn list_sessions(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();
    let manager = C2Manager::new(pool.get_ref().clone());

    // Check ownership
    let config = manager.get_config(&config_id).await?
        .ok_or_else(|| ApiError::not_found("C2 server not found"))?;

    if config.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let sessions = manager.list_sessions(&config_id).await?;

    Ok(HttpResponse::Ok().json(sessions))
}

async fn get_session(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let session_id = path.into_inner();

    // Get basic session info with ownership check (limited to 16 columns for sqlx tuple)
    let basic = sqlx::query_as::<_, (
        String, String, String, Option<String>, String, String, String,
        Option<String>, String, Option<String>, String, Option<String>,
        String, i32, String, Option<String>,
    )>(
        r#"
        SELECT s.id, s.c2_config_id, s.c2_session_id, s.implant_id, s.name,
               s.hostname, s.username, s.domain, s.ip_address, s.external_ip,
               s.os, s.os_version, s.arch, s.pid, s.process_name, s.integrity
        FROM c2_sessions s
        JOIN c2_configs c ON s.c2_config_id = c.id
        WHERE s.id = ? AND c.user_id = ?
        "#
    )
    .bind(&session_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Session not found"))?;

    // Get additional fields
    let extra = sqlx::query_as::<_, (String, bool, Option<String>, String, String, Option<String>, Option<String>)>(
        r#"
        SELECT status, is_elevated, locale, first_seen, last_checkin, next_checkin, notes
        FROM c2_sessions WHERE id = ?
        "#
    )
    .bind(&session_id)
    .fetch_one(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": basic.0,
        "c2_config_id": basic.1,
        "c2_session_id": basic.2,
        "implant_id": basic.3,
        "name": basic.4,
        "hostname": basic.5,
        "username": basic.6,
        "domain": basic.7,
        "ip_address": basic.8,
        "external_ip": basic.9,
        "os": basic.10,
        "os_version": basic.11,
        "arch": basic.12,
        "pid": basic.13,
        "process_name": basic.14,
        "integrity": basic.15,
        "status": extra.0,
        "is_elevated": extra.1,
        "locale": extra.2,
        "first_seen": extra.3,
        "last_checkin": extra.4,
        "next_checkin": extra.5,
        "notes": extra.6
    })))
}

async fn kill_session(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let session_id = path.into_inner();

    // Get session with config_id
    let session = sqlx::query_as::<_, (String, String)>(
        r#"
        SELECT s.c2_config_id, s.c2_session_id
        FROM c2_sessions s
        JOIN c2_configs c ON s.c2_config_id = c.id
        WHERE s.id = ? AND c.user_id = ?
        "#
    )
    .bind(&session_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Session not found"))?;

    let manager = C2Manager::new(pool.get_ref().clone());
    let client = manager.get_client(&session.0).await
        .ok_or_else(|| ApiError::bad_request("Not connected to C2 server"))?;

    client.kill_session(&session.1).await?;

    // Update status in database
    sqlx::query("UPDATE c2_sessions SET status = 'dead' WHERE id = ?")
        .bind(&session_id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Tasks
// ============================================================================

async fn list_tasks(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse, ApiError> {
    let session_id = path.into_inner();
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    // Verify session ownership
    let _session = sqlx::query_as::<_, (String,)>(
        r#"
        SELECT s.id FROM c2_sessions s
        JOIN c2_configs c ON s.c2_config_id = c.id
        WHERE s.id = ? AND c.user_id = ?
        "#
    )
    .bind(&session_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Session not found"))?;

    let tasks = sqlx::query_as::<_, (
        String, String, Option<String>, String, String, Option<String>,
        String, Option<String>, Option<String>, String, Option<String>, Option<String>,
    )>(
        r#"
        SELECT id, session_id, c2_task_id, task_type, command, args,
               status, output, error, created_at, sent_at, completed_at
        FROM c2_tasks WHERE session_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#
    )
    .bind(&session_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await?;

    let result: Vec<serde_json::Value> = tasks.into_iter().map(|t| {
        serde_json::json!({
            "id": t.0,
            "session_id": t.1,
            "c2_task_id": t.2,
            "task_type": t.3,
            "command": t.4,
            "args": t.5.and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok()).unwrap_or_default(),
            "status": t.6,
            "output": t.7,
            "error": t.8,
            "created_at": t.9,
            "sent_at": t.10,
            "completed_at": t.11
        })
    }).collect();

    Ok(HttpResponse::Ok().json(result))
}

async fn execute_task(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<ExecuteTaskRequest>,
) -> Result<HttpResponse, ApiError> {
    let session_id = path.into_inner();

    // Get session with config_id
    let session = sqlx::query_as::<_, (String, String)>(
        r#"
        SELECT s.c2_config_id, s.c2_session_id
        FROM c2_sessions s
        JOIN c2_configs c ON s.c2_config_id = c.id
        WHERE s.id = ? AND c.user_id = ?
        "#
    )
    .bind(&session_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Session not found"))?;

    let manager = C2Manager::new(pool.get_ref().clone());
    let client = manager.get_client(&session.0).await
        .ok_or_else(|| ApiError::bad_request("Not connected to C2 server"))?;

    let task = client.execute_task(&session.1, &body.into_inner()).await?;

    // Save task to database
    manager.save_task(&task).await?;

    Ok(HttpResponse::Created().json(task))
}

// ============================================================================
// Implants
// ============================================================================

async fn list_implants(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();

    // Check ownership
    let _config = sqlx::query_as::<_, (String,)>(
        "SELECT id FROM c2_configs WHERE id = ? AND user_id = ?"
    )
    .bind(&config_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("C2 server not found"))?;

    let implants = sqlx::query_as::<_, (
        String, String, String, String, String, String, String,
        Option<String>, Option<String>, Option<String>, Option<i64>, i32, String,
    )>(
        r#"
        SELECT id, c2_config_id, name, platform, arch, format, implant_type,
               listener_id, file_path, file_hash, file_size, download_count, created_at
        FROM c2_implants WHERE c2_config_id = ?
        ORDER BY created_at DESC
        "#
    )
    .bind(&config_id)
    .fetch_all(pool.get_ref())
    .await?;

    let result: Vec<serde_json::Value> = implants.into_iter().map(|i| {
        serde_json::json!({
            "id": i.0,
            "c2_config_id": i.1,
            "name": i.2,
            "platform": i.3,
            "arch": i.4,
            "format": i.5,
            "implant_type": i.6,
            "listener_id": i.7,
            "file_path": i.8,
            "file_hash": i.9,
            "file_size": i.10,
            "download_count": i.11,
            "created_at": i.12
        })
    }).collect();

    Ok(HttpResponse::Ok().json(result))
}

async fn generate_implant(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<GenerateImplantRequest>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();
    let manager = C2Manager::new(pool.get_ref().clone());

    // Check ownership
    let config = manager.get_config(&config_id).await?
        .ok_or_else(|| ApiError::not_found("C2 server not found"))?;

    if config.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let client = manager.get_client(&config_id).await
        .ok_or_else(|| ApiError::bad_request("Not connected to C2 server"))?;

    let req = body.into_inner();
    let implant_config = ImplantConfig {
        name: req.name.clone(),
        c2_config_id: config_id.clone(),
        listener_id: req.listener_id.clone(),
        platform: req.platform.clone(),
        arch: req.arch.clone(),
        format: req.format.clone(),
        implant_type: req.implant_type.clone().unwrap_or(ImplantType::Beacon),
        c2_urls: Vec::new(),
        jitter: req.jitter.unwrap_or(30),
        interval: req.interval.unwrap_or(60),
        debug: req.debug.unwrap_or(false),
        obfuscation: req.obfuscation.unwrap_or(true),
        evasion: req.evasion.unwrap_or(true),
        skip_symbols: true,
        canaries: Vec::new(),
        connection_retries: 3,
        timeout: 60,
        extra_config: std::collections::HashMap::new(),
    };

    let implant_bytes = client.generate_implant(&implant_config).await?;

    // Save implant to disk
    let implant_id = uuid::Uuid::new_v4().to_string();
    let file_ext = match req.format {
        ImplantFormat::Exe => "exe",
        ImplantFormat::Dll => "dll",
        ImplantFormat::Shellcode => "bin",
        ImplantFormat::SharedLib => "so",
        ImplantFormat::ServiceExe => "exe",
    };
    let file_name = format!("{}_{}.{}", req.name, implant_id[..8].to_string(), file_ext);
    let file_path = format!("./implants/{}", file_name);

    // Create implants directory if it doesn't exist
    tokio::fs::create_dir_all("./implants").await
        .map_err(|e| ApiError::bad_request(format!("Failed to create implants directory: {}", e)))?;
    tokio::fs::write(&file_path, &implant_bytes).await
        .map_err(|e| ApiError::bad_request(format!("Failed to write implant file: {}", e)))?;

    // Calculate hash
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&implant_bytes);
    let hash = format!("{:x}", hasher.finalize());

    let now = chrono::Utc::now();

    // Save to database
    sqlx::query(
        r#"
        INSERT INTO c2_implants (
            id, c2_config_id, name, platform, arch, format, implant_type,
            listener_id, file_path, file_hash, file_size, download_count, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
        "#
    )
    .bind(&implant_id)
    .bind(&config_id)
    .bind(&req.name)
    .bind(req.platform.to_string())
    .bind(req.arch.to_string())
    .bind(req.format.to_string())
    .bind(req.implant_type.as_ref().map(|t| match t {
        ImplantType::Beacon => "beacon",
        ImplantType::Session => "session",
    }).unwrap_or("beacon"))
    .bind(&req.listener_id)
    .bind(&file_path)
    .bind(&hash)
    .bind(implant_bytes.len() as i64)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": implant_id,
        "name": req.name,
        "file_path": file_path,
        "file_hash": hash,
        "file_size": implant_bytes.len()
    })))
}

async fn download_implant(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let implant_id = path.into_inner();

    // Get implant with ownership check
    let implant = sqlx::query_as::<_, (String, String, String)>(
        r#"
        SELECT i.file_path, i.name, i.format
        FROM c2_implants i
        JOIN c2_configs c ON i.c2_config_id = c.id
        WHERE i.id = ? AND c.user_id = ?
        "#
    )
    .bind(&implant_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Implant not found"))?;

    let file_path = implant.0;
    let file_name = implant.1;
    let format = implant.2;

    // Read file
    let bytes = tokio::fs::read(&file_path).await
        .map_err(|_| ApiError::not_found("Implant file not found"))?;

    // Update download count
    sqlx::query("UPDATE c2_implants SET download_count = download_count + 1 WHERE id = ?")
        .bind(&implant_id)
        .execute(pool.get_ref())
        .await?;

    let content_type = match format.as_str() {
        "exe" | "service" => "application/x-msdownload",
        "dll" => "application/x-msdownload",
        "shellcode" | "bin" => "application/octet-stream",
        "shared" | "so" => "application/x-sharedlib",
        _ => "application/octet-stream",
    };

    Ok(HttpResponse::Ok()
        .content_type(content_type)
        .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", file_name)))
        .body(bytes))
}

// ============================================================================
// Credentials
// ============================================================================

async fn list_credentials(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse, ApiError> {
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let manager = C2Manager::new(pool.get_ref().clone());
    let credentials = manager.list_credentials(&claims.sub, limit, offset).await?;

    Ok(HttpResponse::Ok().json(credentials))
}
