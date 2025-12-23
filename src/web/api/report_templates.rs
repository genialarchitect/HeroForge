//! Custom Report Templates API
//!
//! REST API endpoints for managing custom report templates, marketplace,
//! ratings, versioning, and scheduled report delivery.

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::report_templates::{
    self, CreateTemplateRequest, UpdateTemplateRequest, CreateRatingRequest,
    CreateSectionRequest, CreateDeliveryChannelRequest,
};
use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;

// ============================================================================
// Query Parameters
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct MarketplaceQuery {
    pub base_template: Option<String>,
    pub sort_by: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
    pub limit: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct RatingsQuery {
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct RunHistoryQuery {
    pub limit: Option<i32>,
}

// ============================================================================
// Request Bodies
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CloneRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct MarkHelpfulRequest {
    pub rating_id: String,
}

// ============================================================================
// Response Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct TemplateResponse<T> {
    pub success: bool,
    pub data: T,
}

#[derive(Debug, Serialize)]
pub struct TemplateListResponse<T> {
    pub success: bool,
    pub data: Vec<T>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub success: bool,
    pub message: String,
}

// ============================================================================
// Template CRUD Handlers
// ============================================================================

/// Create a new custom report template
pub async fn create_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<CreateTemplateRequest>,
) -> Result<HttpResponse, ApiError> {
    let org_id = claims.org_id.as_deref();

    let template = report_templates::create_template(
        pool.get_ref(),
        &claims.sub,
        org_id,
        body.into_inner(),
    ).await?;

    Ok(HttpResponse::Created().json(TemplateResponse {
        success: true,
        data: template,
    }))
}

/// List user's templates
pub async fn list_templates(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let org_id = claims.org_id.as_deref();

    let templates = report_templates::list_user_templates(
        pool.get_ref(),
        &claims.sub,
        org_id,
    ).await?;

    let count = templates.len();
    Ok(HttpResponse::Ok().json(TemplateListResponse {
        success: true,
        data: templates,
        total: count,
    }))
}

/// Get template by ID
pub async fn get_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    let template = report_templates::get_template_by_id(pool.get_ref(), &template_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Template not found"))?;

    // Check access: owner, org member, or public template
    let has_access = template.user_id == claims.sub
        || template.is_public
        || (template.organization_id.is_some() && template.organization_id == claims.org_id);

    if !has_access {
        return Err(ApiError::forbidden("Access denied"));
    }

    Ok(HttpResponse::Ok().json(TemplateResponse {
        success: true,
        data: template,
    }))
}

/// Update a template
pub async fn update_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    body: web::Json<UpdateTemplateRequest>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    let template = report_templates::update_template(
        pool.get_ref(),
        &template_id,
        &claims.sub,
        body.into_inner(),
    )
    .await?
    .ok_or_else(|| ApiError::not_found("Template not found or access denied"))?;

    Ok(HttpResponse::Ok().json(TemplateResponse {
        success: true,
        data: template,
    }))
}

/// Delete a template
pub async fn delete_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    let deleted = report_templates::delete_template(pool.get_ref(), &template_id, &claims.sub).await?;

    if deleted {
        Ok(HttpResponse::Ok().json(MessageResponse {
            success: true,
            message: "Template deleted".to_string(),
        }))
    } else {
        Err(ApiError::not_found("Template not found or access denied"))
    }
}

/// Clone a template
pub async fn clone_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    body: web::Json<CloneRequest>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    let template = report_templates::clone_template(
        pool.get_ref(),
        &template_id,
        &claims.sub,
        &body.name,
    )
    .await?
    .ok_or_else(|| ApiError::not_found("Template not found"))?;

    Ok(HttpResponse::Created().json(TemplateResponse {
        success: true,
        data: template,
    }))
}

/// Publish template to marketplace
pub async fn publish_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    let published = report_templates::publish_template(pool.get_ref(), &template_id, &claims.sub).await?;

    if published {
        Ok(HttpResponse::Ok().json(MessageResponse {
            success: true,
            message: "Template published to marketplace".to_string(),
        }))
    } else {
        Err(ApiError::not_found("Template not found or access denied"))
    }
}

/// Unpublish template from marketplace
pub async fn unpublish_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    let unpublished = report_templates::unpublish_template(pool.get_ref(), &template_id, &claims.sub).await?;

    if unpublished {
        Ok(HttpResponse::Ok().json(MessageResponse {
            success: true,
            message: "Template unpublished from marketplace".to_string(),
        }))
    } else {
        Err(ApiError::not_found("Template not found or access denied"))
    }
}

// ============================================================================
// Marketplace Handlers
// ============================================================================

/// List marketplace templates
pub async fn list_marketplace(
    pool: web::Data<SqlitePool>,
    query: web::Query<MarketplaceQuery>,
) -> Result<HttpResponse, ApiError> {
    let limit = query.limit.unwrap_or(20).min(100);
    let offset = query.offset.unwrap_or(0);

    let templates = report_templates::list_marketplace_templates(
        pool.get_ref(),
        query.base_template.as_deref(),
        query.sort_by.as_deref(),
        limit,
        offset,
    ).await?;

    let count = templates.len();
    Ok(HttpResponse::Ok().json(TemplateListResponse {
        success: true,
        data: templates,
        total: count,
    }))
}

/// Search marketplace templates
pub async fn search_marketplace(
    pool: web::Data<SqlitePool>,
    query: web::Query<SearchQuery>,
) -> Result<HttpResponse, ApiError> {
    let limit = query.limit.unwrap_or(20).min(100);

    let templates = report_templates::search_marketplace(
        pool.get_ref(),
        &query.q,
        limit,
    ).await?;

    let count = templates.len();
    Ok(HttpResponse::Ok().json(TemplateListResponse {
        success: true,
        data: templates,
        total: count,
    }))
}

// ============================================================================
// Rating Handlers
// ============================================================================

/// Rate a template
pub async fn rate_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    body: web::Json<CreateRatingRequest>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    // Validate rating
    if body.rating < 1 || body.rating > 5 {
        return Err(ApiError::bad_request("Rating must be between 1 and 5"));
    }

    let rating = report_templates::rate_template(
        pool.get_ref(),
        &template_id,
        &claims.sub,
        body.into_inner(),
    ).await?;

    Ok(HttpResponse::Ok().json(TemplateResponse {
        success: true,
        data: rating,
    }))
}

/// Get template ratings
pub async fn get_template_ratings(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    query: web::Query<RatingsQuery>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();
    let limit = query.limit.unwrap_or(20).min(100);
    let offset = query.offset.unwrap_or(0);

    let ratings = report_templates::get_template_ratings(
        pool.get_ref(),
        &template_id,
        limit,
        offset,
    ).await?;

    let count = ratings.len();
    Ok(HttpResponse::Ok().json(TemplateListResponse {
        success: true,
        data: ratings,
        total: count,
    }))
}

/// Mark a rating as helpful
pub async fn mark_rating_helpful(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    body: web::Json<MarkHelpfulRequest>,
) -> Result<HttpResponse, ApiError> {
    let marked = report_templates::mark_rating_helpful(pool.get_ref(), &body.rating_id).await?;

    if marked {
        Ok(HttpResponse::Ok().json(MessageResponse {
            success: true,
            message: "Rating marked as helpful".to_string(),
        }))
    } else {
        Err(ApiError::not_found("Rating not found"))
    }
}

// ============================================================================
// Version Handlers
// ============================================================================

/// Get template version history
pub async fn get_template_versions(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    // Verify ownership
    let template = report_templates::get_template_by_id(pool.get_ref(), &template_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Template not found"))?;

    if template.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let versions = report_templates::get_template_versions(pool.get_ref(), &template_id).await?;

    let count = versions.len();
    Ok(HttpResponse::Ok().json(TemplateListResponse {
        success: true,
        data: versions,
        total: count,
    }))
}

/// Restore template from a previous version
pub async fn restore_template_version(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (template_id, version_id) = path.into_inner();

    let template = report_templates::restore_version(
        pool.get_ref(),
        &template_id,
        &version_id,
        &claims.sub,
    )
    .await?
    .ok_or_else(|| ApiError::not_found("Template or version not found"))?;

    Ok(HttpResponse::Ok().json(TemplateResponse {
        success: true,
        data: template,
    }))
}

// ============================================================================
// Section Handlers
// ============================================================================

/// Create a reusable section
pub async fn create_section(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<CreateSectionRequest>,
) -> Result<HttpResponse, ApiError> {
    let org_id = claims.org_id.as_deref();

    let section = report_templates::create_section(
        pool.get_ref(),
        &claims.sub,
        org_id,
        body.into_inner(),
    ).await?;

    Ok(HttpResponse::Created().json(TemplateResponse {
        success: true,
        data: section,
    }))
}

/// List user's sections
pub async fn list_sections(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let org_id = claims.org_id.as_deref();

    let sections = report_templates::list_user_sections(
        pool.get_ref(),
        &claims.sub,
        org_id,
    ).await?;

    let count = sections.len();
    Ok(HttpResponse::Ok().json(TemplateListResponse {
        success: true,
        data: sections,
        total: count,
    }))
}

/// Delete a section
pub async fn delete_section(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let section_id = path.into_inner();

    let deleted = report_templates::delete_section(pool.get_ref(), &section_id, &claims.sub).await?;

    if deleted {
        Ok(HttpResponse::Ok().json(MessageResponse {
            success: true,
            message: "Section deleted".to_string(),
        }))
    } else {
        Err(ApiError::not_found("Section not found or access denied"))
    }
}

// ============================================================================
// Asset Handlers
// ============================================================================

/// List user's assets
pub async fn list_assets(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let org_id = claims.org_id.as_deref();

    let assets = report_templates::list_user_assets(
        pool.get_ref(),
        &claims.sub,
        org_id,
    ).await?;

    let count = assets.len();
    Ok(HttpResponse::Ok().json(TemplateListResponse {
        success: true,
        data: assets,
        total: count,
    }))
}

/// Get asset by ID
pub async fn get_asset(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let asset_id = path.into_inner();

    let asset = report_templates::get_asset_by_id(pool.get_ref(), &asset_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Asset not found"))?;

    // Verify access
    let has_access = asset.user_id == claims.sub
        || (asset.organization_id.is_some() && asset.organization_id == claims.org_id);

    if !has_access {
        return Err(ApiError::forbidden("Access denied"));
    }

    Ok(HttpResponse::Ok().json(TemplateResponse {
        success: true,
        data: asset,
    }))
}

/// Delete an asset
pub async fn delete_asset(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let asset_id = path.into_inner();

    let deleted = report_templates::delete_asset(pool.get_ref(), &asset_id, &claims.sub).await?;

    if deleted {
        Ok(HttpResponse::Ok().json(MessageResponse {
            success: true,
            message: "Asset deleted".to_string(),
        }))
    } else {
        Err(ApiError::not_found("Asset not found or access denied"))
    }
}

// ============================================================================
// Usage Statistics Handlers
// ============================================================================

/// Get template usage statistics
pub async fn get_usage_stats(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    // Verify ownership
    let template = report_templates::get_template_by_id(pool.get_ref(), &template_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Template not found"))?;

    if template.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    let stats = report_templates::get_template_usage_stats(pool.get_ref(), &template_id).await?;

    Ok(HttpResponse::Ok().json(TemplateResponse {
        success: true,
        data: stats,
    }))
}

/// Get overall template statistics
pub async fn get_template_stats(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let stats = report_templates::get_template_stats(pool.get_ref(), Some(&claims.sub)).await?;

    Ok(HttpResponse::Ok().json(TemplateResponse {
        success: true,
        data: stats,
    }))
}

// ============================================================================
// Scheduled Report Delivery Handlers
// ============================================================================

/// Add delivery channel to scheduled report
pub async fn add_delivery_channel(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
    body: web::Json<CreateDeliveryChannelRequest>,
) -> Result<HttpResponse, ApiError> {
    let scheduled_report_id = path.into_inner();

    let channel = report_templates::add_delivery_channel(
        pool.get_ref(),
        &scheduled_report_id,
        body.into_inner(),
    ).await?;

    Ok(HttpResponse::Created().json(TemplateResponse {
        success: true,
        data: channel,
    }))
}

/// List delivery channels for a scheduled report
pub async fn list_delivery_channels(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scheduled_report_id = path.into_inner();

    let channels = report_templates::list_delivery_channels(pool.get_ref(), &scheduled_report_id).await?;

    let count = channels.len();
    Ok(HttpResponse::Ok().json(TemplateListResponse {
        success: true,
        data: channels,
        total: count,
    }))
}

/// Delete a delivery channel
pub async fn delete_delivery_channel(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let channel_id = path.into_inner();

    let deleted = report_templates::delete_delivery_channel(pool.get_ref(), &channel_id).await?;

    if deleted {
        Ok(HttpResponse::Ok().json(MessageResponse {
            success: true,
            message: "Delivery channel deleted".to_string(),
        }))
    } else {
        Err(ApiError::not_found("Delivery channel not found"))
    }
}

/// Get run history for a scheduled report
pub async fn get_run_history(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
    query: web::Query<RunHistoryQuery>,
) -> Result<HttpResponse, ApiError> {
    let scheduled_report_id = path.into_inner();
    let limit = query.limit.unwrap_or(20).min(100);

    let runs = report_templates::get_report_run_history(
        pool.get_ref(),
        &scheduled_report_id,
        limit,
    ).await?;

    let count = runs.len();
    Ok(HttpResponse::Ok().json(TemplateListResponse {
        success: true,
        data: runs,
        total: count,
    }))
}

// ============================================================================
// Preview Handler
// ============================================================================

/// Generate a preview of a template
pub async fn preview_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    let template = report_templates::get_template_by_id(pool.get_ref(), &template_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Template not found"))?;

    // Check access
    let has_access = template.user_id == claims.sub
        || template.is_public
        || (template.organization_id.is_some() && template.organization_id == claims.org_id);

    if !has_access {
        return Err(ApiError::forbidden("Access denied"));
    }

    // Generate preview HTML
    let preview_html = generate_preview_html(&template);

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(preview_html))
}

/// Generate preview HTML for a template
fn generate_preview_html(template: &report_templates::CustomReportTemplate) -> String {
    let branding = template.branding.as_ref()
        .and_then(|b| serde_json::from_value::<report_templates::TemplateBranding>(b.clone()).ok())
        .unwrap_or_default();

    let primary_color = branding.primary_color.as_deref().unwrap_or("#1a56db");
    let company_name = branding.company_name.as_deref().unwrap_or("Company Name");
    let header = template.header_html.as_deref().unwrap_or("");
    let footer = template.footer_html.as_deref().unwrap_or("");
    let css = template.css_overrides.as_deref().unwrap_or("");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Preview</title>
    <style>
        :root {{
            --primary-color: {};
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .preview-container {{
            max-width: 800px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        .preview-header {{
            background: var(--primary-color);
            color: white;
            padding: 20px;
        }}
        .preview-content {{
            padding: 20px;
        }}
        .preview-footer {{
            background: #f8f9fa;
            padding: 15px 20px;
            border-top: 1px solid #e9ecef;
            font-size: 12px;
            color: #6c757d;
        }}
        .section-preview {{
            margin: 20px 0;
            padding: 15px;
            border: 1px dashed #dee2e6;
            border-radius: 4px;
        }}
        .section-preview h3 {{
            margin-top: 0;
            color: var(--primary-color);
        }}
        {}
    </style>
</head>
<body>
    <div class="preview-container">
        <div class="preview-header">
            {}
            <h1>{}</h1>
            <p>Based on: {} template</p>
        </div>
        <div class="preview-content">
            <h2>Template Preview</h2>
            <p>This is a preview of your custom report template. The actual report will include data from your scans.</p>

            <div class="section-preview">
                <h3>Executive Summary</h3>
                <p>High-level overview of security findings...</p>
            </div>

            <div class="section-preview">
                <h3>Vulnerability Findings</h3>
                <p>Detailed list of discovered vulnerabilities...</p>
            </div>

            <div class="section-preview">
                <h3>Remediation Recommendations</h3>
                <p>Prioritized list of actions to address findings...</p>
            </div>
        </div>
        <div class="preview-footer">
            {}
            <p>Generated by HeroForge - {}</p>
        </div>
    </div>
</body>
</html>"#,
        template.name,
        primary_color,
        css,
        header,
        company_name,
        template.base_template,
        footer,
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
    )
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/report-templates")
            // Template CRUD
            .route("", web::post().to(create_template))
            .route("", web::get().to(list_templates))
            .route("/stats", web::get().to(get_template_stats))
            .route("/marketplace", web::get().to(list_marketplace))
            .route("/marketplace/search", web::get().to(search_marketplace))
            .route("/{id}", web::get().to(get_template))
            .route("/{id}", web::put().to(update_template))
            .route("/{id}", web::delete().to(delete_template))
            .route("/{id}/clone", web::post().to(clone_template))
            .route("/{id}/publish", web::post().to(publish_template))
            .route("/{id}/unpublish", web::post().to(unpublish_template))
            .route("/{id}/preview", web::get().to(preview_template))
            // Ratings
            .route("/{id}/rate", web::post().to(rate_template))
            .route("/{id}/ratings", web::get().to(get_template_ratings))
            .route("/ratings/helpful", web::post().to(mark_rating_helpful))
            // Versions
            .route("/{id}/versions", web::get().to(get_template_versions))
            .route("/{id}/versions/{version_id}/restore", web::post().to(restore_template_version))
            // Usage stats
            .route("/{id}/usage", web::get().to(get_usage_stats))
            // Sections
            .route("/sections", web::post().to(create_section))
            .route("/sections", web::get().to(list_sections))
            .route("/sections/{id}", web::delete().to(delete_section))
            // Assets
            .route("/assets", web::get().to(list_assets))
            .route("/assets/{id}", web::get().to(get_asset))
            .route("/assets/{id}", web::delete().to(delete_asset))
    );

    // Scheduled report delivery routes (under existing scheduled-reports scope)
    cfg.service(
        web::scope("/scheduled-reports")
            .route("/{id}/delivery", web::post().to(add_delivery_channel))
            .route("/{id}/delivery", web::get().to(list_delivery_channels))
            .route("/delivery/{id}", web::delete().to(delete_delivery_channel))
            .route("/{id}/history", web::get().to(get_run_history))
    );
}
