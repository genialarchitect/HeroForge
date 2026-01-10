//! Screenshot API endpoints
//!
//! Provides REST API endpoints for capturing web page screenshots
//! using the Playwright-based screenshot service.

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::path::PathBuf;
use uuid::Uuid;

use crate::screenshots::{ScreenshotOptions, ScreenshotResult, ScreenshotService};
use crate::web::auth::Claims;

/// Request to capture a single screenshot
#[derive(Debug, Deserialize)]
pub struct CaptureScreenshotRequest {
    /// Target URL to capture
    pub url: String,
    /// Optional custom filename (without extension)
    pub filename: Option<String>,
    /// Capture full scrollable page
    #[serde(default)]
    pub full_page: bool,
    /// Viewport width
    pub width: Option<u32>,
    /// Viewport height
    pub height: Option<u32>,
    /// Use mobile viewport
    #[serde(default)]
    pub mobile: bool,
    /// Enable dark mode
    #[serde(default)]
    pub dark_mode: bool,
    /// Wait time after page load (ms)
    pub wait: Option<u32>,
    /// CSS selector to capture specific element
    pub selector: Option<String>,
    /// Output format: png or jpeg
    pub format: Option<String>,
    /// Ignore SSL certificate errors
    #[serde(default)]
    pub ignore_ssl: bool,
    /// Optional scan ID to associate with
    pub scan_id: Option<String>,
    /// Optional description/note
    pub description: Option<String>,
}

/// Request to capture multiple screenshots
#[derive(Debug, Deserialize)]
pub struct BatchScreenshotRequest {
    /// List of URLs to capture
    pub urls: Vec<BatchScreenshotItem>,
    /// Common settings for all screenshots
    #[serde(default)]
    pub common_settings: CommonScreenshotSettings,
}

#[derive(Debug, Deserialize)]
pub struct BatchScreenshotItem {
    pub url: String,
    pub filename: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CommonScreenshotSettings {
    pub full_page: Option<bool>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub mobile: Option<bool>,
    pub dark_mode: Option<bool>,
    pub wait: Option<u32>,
    pub format: Option<String>,
    pub ignore_ssl: Option<bool>,
}

/// Screenshot record stored in database
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScreenshotRecord {
    pub id: String,
    pub user_id: String,
    pub url: String,
    pub file_path: String,
    pub file_size: Option<i64>,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub format: String,
    pub full_page: bool,
    pub scan_id: Option<String>,
    pub description: Option<String>,
    pub created_at: String,
}

/// Response for screenshot capture
#[derive(Debug, Serialize)]
pub struct ScreenshotResponse {
    pub id: String,
    pub success: bool,
    pub url: String,
    pub file_path: Option<String>,
    pub file_size: Option<u64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub format: Option<String>,
    pub duration_ms: Option<u64>,
    pub error: Option<String>,
}

/// Response for batch screenshot capture
#[derive(Debug, Serialize)]
pub struct BatchScreenshotResponse {
    pub total: usize,
    pub successful: usize,
    pub failed: usize,
    pub results: Vec<ScreenshotResponse>,
}

/// List screenshots response
#[derive(Debug, Serialize)]
pub struct ListScreenshotsResponse {
    pub screenshots: Vec<ScreenshotRecord>,
    pub total: i64,
}

/// Get screenshots directory
fn get_screenshots_dir() -> PathBuf {
    let dir = std::env::var("SCREENSHOTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./screenshots"));

    // Ensure directory exists
    if !dir.exists() {
        std::fs::create_dir_all(&dir).ok();
    }

    dir
}

/// POST /api/screenshots/capture - Capture a single screenshot
pub async fn capture_screenshot(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    req: web::Json<CaptureScreenshotRequest>,
) -> Result<HttpResponse> {
    log::info!("User {} capturing screenshot of {}", claims.sub, req.url);

    // Validate URL
    if req.url.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "URL is required"
        })));
    }

    if !req.url.starts_with("http://") && !req.url.starts_with("https://") {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "URL must start with http:// or https://"
        })));
    }

    // Initialize screenshot service
    let service = match ScreenshotService::new() {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to initialize screenshot service: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Screenshot service unavailable: {}", e)
            })));
        }
    };

    // Generate output path
    let screenshot_id = Uuid::new_v4().to_string();
    let format = req.format.clone().unwrap_or_else(|| "png".to_string());
    let filename = req
        .filename
        .clone()
        .unwrap_or_else(|| format!("screenshot_{}", screenshot_id));
    let output_path = get_screenshots_dir().join(format!("{}.{}", filename, format));

    // Build options
    let options = ScreenshotOptions {
        url: req.url.clone(),
        output_path: output_path.clone(),
        full_page: req.full_page,
        width: req.width.unwrap_or(1920),
        height: req.height.unwrap_or(1080),
        timeout: 30000,
        wait: req.wait.unwrap_or(1000),
        selector: req.selector.clone(),
        format: format.clone(),
        quality: 80,
        dark_mode: req.dark_mode,
        mobile: req.mobile,
        auth_token: None,
        cookies: None,
        user_agent: None,
        ignore_ssl: req.ignore_ssl,
    };

    // Capture screenshot
    let result = match service.capture(&options).await {
        Ok(r) => r,
        Err(e) => {
            log::error!("Screenshot capture failed: {}", e);
            return Ok(HttpResponse::InternalServerError().json(ScreenshotResponse {
                id: screenshot_id,
                success: false,
                url: req.url.clone(),
                file_path: None,
                file_size: None,
                width: None,
                height: None,
                format: None,
                duration_ms: None,
                error: Some(e.to_string()),
            }));
        }
    };

    if result.success {
        // Save to database
        let file_path_str = output_path.to_string_lossy().to_string();
        let _ = sqlx::query(
            r#"
            INSERT INTO screenshots (id, user_id, url, file_path, file_size, width, height, format, full_page, scan_id, description, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            "#,
        )
        .bind(&screenshot_id)
        .bind(&claims.sub)
        .bind(&req.url)
        .bind(&file_path_str)
        .bind(result.file_size.map(|s| s as i64))
        .bind(result.width.map(|w| w as i32))
        .bind(result.height.map(|h| h as i32))
        .bind(&format)
        .bind(req.full_page)
        .bind(&req.scan_id)
        .bind(&req.description)
        .execute(pool.get_ref())
        .await;

        Ok(HttpResponse::Ok().json(ScreenshotResponse {
            id: screenshot_id,
            success: true,
            url: req.url.clone(),
            file_path: Some(file_path_str),
            file_size: result.file_size,
            width: result.width,
            height: result.height,
            format: Some(format),
            duration_ms: result.duration,
            error: None,
        }))
    } else {
        Ok(HttpResponse::Ok().json(ScreenshotResponse {
            id: screenshot_id,
            success: false,
            url: req.url.clone(),
            file_path: None,
            file_size: None,
            width: None,
            height: None,
            format: None,
            duration_ms: None,
            error: result.error,
        }))
    }
}

/// POST /api/screenshots/batch - Capture multiple screenshots
pub async fn capture_batch(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    req: web::Json<BatchScreenshotRequest>,
) -> Result<HttpResponse> {
    log::info!(
        "User {} capturing batch of {} screenshots",
        claims.sub,
        req.urls.len()
    );

    if req.urls.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one URL is required"
        })));
    }

    if req.urls.len() > 50 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Maximum 50 URLs per batch"
        })));
    }

    let service = match ScreenshotService::new() {
        Ok(s) => s,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Screenshot service unavailable: {}", e)
            })));
        }
    };

    let mut results = Vec::new();
    let mut successful = 0;
    let mut failed = 0;

    let common = &req.common_settings;
    let format = common.format.clone().unwrap_or_else(|| "png".to_string());

    for item in &req.urls {
        let screenshot_id = Uuid::new_v4().to_string();
        let filename = item
            .filename
            .clone()
            .unwrap_or_else(|| format!("screenshot_{}", screenshot_id));
        let output_path = get_screenshots_dir().join(format!("{}.{}", filename, format));

        let options = ScreenshotOptions {
            url: item.url.clone(),
            output_path: output_path.clone(),
            full_page: common.full_page.unwrap_or(false),
            width: common.width.unwrap_or(1920),
            height: common.height.unwrap_or(1080),
            timeout: 30000,
            wait: common.wait.unwrap_or(1000),
            selector: None,
            format: format.clone(),
            quality: 80,
            dark_mode: common.dark_mode.unwrap_or(false),
            mobile: common.mobile.unwrap_or(false),
            auth_token: None,
            cookies: None,
            user_agent: None,
            ignore_ssl: common.ignore_ssl.unwrap_or(false),
        };

        match service.capture(&options).await {
            Ok(result) if result.success => {
                successful += 1;
                let file_path_str = output_path.to_string_lossy().to_string();

                // Save to database
                let _ = sqlx::query(
                    r#"
                    INSERT INTO screenshots (id, user_id, url, file_path, file_size, width, height, format, full_page, description, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                    "#,
                )
                .bind(&screenshot_id)
                .bind(&claims.sub)
                .bind(&item.url)
                .bind(&file_path_str)
                .bind(result.file_size.map(|s| s as i64))
                .bind(result.width.map(|w| w as i32))
                .bind(result.height.map(|h| h as i32))
                .bind(&format)
                .bind(common.full_page.unwrap_or(false))
                .bind(&item.description)
                .execute(pool.get_ref())
                .await;

                results.push(ScreenshotResponse {
                    id: screenshot_id,
                    success: true,
                    url: item.url.clone(),
                    file_path: Some(file_path_str),
                    file_size: result.file_size,
                    width: result.width,
                    height: result.height,
                    format: Some(format.clone()),
                    duration_ms: result.duration,
                    error: None,
                });
            }
            Ok(result) => {
                failed += 1;
                results.push(ScreenshotResponse {
                    id: screenshot_id,
                    success: false,
                    url: item.url.clone(),
                    file_path: None,
                    file_size: None,
                    width: None,
                    height: None,
                    format: None,
                    duration_ms: None,
                    error: result.error,
                });
            }
            Err(e) => {
                failed += 1;
                results.push(ScreenshotResponse {
                    id: screenshot_id,
                    success: false,
                    url: item.url.clone(),
                    file_path: None,
                    file_size: None,
                    width: None,
                    height: None,
                    format: None,
                    duration_ms: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    Ok(HttpResponse::Ok().json(BatchScreenshotResponse {
        total: req.urls.len(),
        successful,
        failed,
        results,
    }))
}

/// GET /api/screenshots - List user's screenshots
pub async fn list_screenshots(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse> {
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let screenshots: Vec<ScreenshotRecord> = sqlx::query_as(
        r#"
        SELECT id, user_id, url, file_path, file_size, width, height, format, full_page, scan_id, description, created_at
        FROM screenshots
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(&claims.sub)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM screenshots WHERE user_id = ?")
        .bind(&claims.sub)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    Ok(HttpResponse::Ok().json(ListScreenshotsResponse {
        screenshots,
        total: total.0,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub scan_id: Option<String>,
}

/// GET /api/screenshots/{id} - Get screenshot details
pub async fn get_screenshot(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let screenshot: Option<ScreenshotRecord> = sqlx::query_as(
        r#"
        SELECT id, user_id, url, file_path, file_size, width, height, format, full_page, scan_id, description, created_at
        FROM screenshots
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None);

    match screenshot {
        Some(s) => Ok(HttpResponse::Ok().json(s)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Screenshot not found"
        }))),
    }
}

/// GET /api/screenshots/{id}/download - Download screenshot file
pub async fn download_screenshot(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let screenshot: Option<ScreenshotRecord> = sqlx::query_as(
        r#"
        SELECT id, user_id, url, file_path, file_size, width, height, format, full_page, scan_id, description, created_at
        FROM screenshots
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None);

    match screenshot {
        Some(s) => {
            let path = PathBuf::from(&s.file_path);
            if path.exists() {
                let content = std::fs::read(&path).map_err(|e| {
                    actix_web::error::ErrorInternalServerError(format!(
                        "Failed to read file: {}",
                        e
                    ))
                })?;

                let content_type = match s.format.as_str() {
                    "jpeg" | "jpg" => "image/jpeg",
                    _ => "image/png",
                };

                let filename = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("screenshot.png");

                Ok(HttpResponse::Ok()
                    .content_type(content_type)
                    .insert_header((
                        "Content-Disposition",
                        format!("attachment; filename=\"{}\"", filename),
                    ))
                    .body(content))
            } else {
                Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Screenshot file not found"
                })))
            }
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Screenshot not found"
        }))),
    }
}

/// DELETE /api/screenshots/{id} - Delete a screenshot
pub async fn delete_screenshot(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    // Get screenshot to find file path
    let screenshot: Option<ScreenshotRecord> = sqlx::query_as(
        r#"
        SELECT id, user_id, url, file_path, file_size, width, height, format, full_page, scan_id, description, created_at
        FROM screenshots
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .unwrap_or(None);

    match screenshot {
        Some(s) => {
            // Delete file
            let path = PathBuf::from(&s.file_path);
            if path.exists() {
                std::fs::remove_file(&path).ok();
            }

            // Delete from database
            sqlx::query("DELETE FROM screenshots WHERE id = ? AND user_id = ?")
                .bind(&id)
                .bind(&claims.sub)
                .execute(pool.get_ref())
                .await
                .ok();

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Screenshot deleted"
            })))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Screenshot not found"
        }))),
    }
}

/// Configure screenshot routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/screenshots")
            .route("/capture", web::post().to(capture_screenshot))
            .route("/batch", web::post().to(capture_batch))
            .route("", web::get().to(list_screenshots))
            .route("/{id}", web::get().to(get_screenshot))
            .route("/{id}/download", web::get().to(download_screenshot))
            .route("/{id}", web::delete().to(delete_screenshot)),
    );
}
