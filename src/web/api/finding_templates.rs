//! Finding Templates API endpoints
//!
//! Provides CRUD operations for finding templates - pre-written vulnerability
//! descriptions that can be used to speed up report writing.

use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;

use crate::db::{
    self,
    models::{
        CreateFindingTemplateRequest, FindingTemplate, UpdateFindingTemplateRequest,
        FindingTemplateCategory, ImportTemplatesRequest, ImportTemplatesResponse,
        ApplyTemplateRequest,
    },
};
use crate::web::auth::jwt::Claims;

/// List all finding templates with optional filters
///
/// Returns system templates and user's own templates.
#[utoipa::path(
    get,
    path = "/api/finding-templates",
    tag = "Finding Templates",
    params(
        ("category" = Option<String>, Query, description = "Filter by category"),
        ("severity" = Option<String>, Query, description = "Filter by severity"),
        ("search" = Option<String>, Query, description = "Search in title/description"),
        ("include_system" = Option<bool>, Query, description = "Include system templates (default: true)")
    ),
    responses(
        (status = 200, description = "List of finding templates", body = Vec<FindingTemplate>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_templates(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<ListTemplatesQuery>,
) -> HttpResponse {
    let include_system = query.include_system.unwrap_or(true);

    match db::list_finding_templates(
        pool.get_ref(),
        query.category.as_deref(),
        query.severity.as_deref(),
        query.search.as_deref(),
        include_system,
        Some(&claims.sub),
    )
    .await
    {
        Ok(templates) => HttpResponse::Ok().json(templates),
        Err(e) => {
            log::error!("Failed to list finding templates: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list finding templates"
            }))
        }
    }
}

/// Get a single finding template by ID
#[utoipa::path(
    get,
    path = "/api/finding-templates/{id}",
    tag = "Finding Templates",
    params(
        ("id" = String, Path, description = "Template ID")
    ),
    responses(
        (status = 200, description = "Finding template details", body = FindingTemplate),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_template(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let template_id = path.into_inner();

    match db::get_finding_template(pool.get_ref(), &template_id).await {
        Ok(template) => HttpResponse::Ok().json(template),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Template not found"
                }))
            } else {
                log::error!("Failed to get finding template: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to get finding template"
                }))
            }
        }
    }
}

/// Create a new finding template
#[utoipa::path(
    post,
    path = "/api/finding-templates",
    tag = "Finding Templates",
    request_body = CreateFindingTemplateRequest,
    responses(
        (status = 201, description = "Template created successfully", body = FindingTemplate),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<CreateFindingTemplateRequest>,
) -> HttpResponse {
    // Validate required fields
    if body.title.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Title is required"
        }));
    }

    if body.category.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Category is required"
        }));
    }

    if body.severity.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Severity is required"
        }));
    }

    // Validate severity value
    let valid_severities = ["critical", "high", "medium", "low", "info"];
    if !valid_severities.contains(&body.severity.to_lowercase().as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid severity. Must be one of: critical, high, medium, low, info"
        }));
    }

    match db::create_finding_template(pool.get_ref(), &body, &claims.sub).await {
        Ok(template) => HttpResponse::Created().json(template),
        Err(e) => {
            log::error!("Failed to create finding template: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create finding template"
            }))
        }
    }
}

/// Update a finding template
///
/// Only the owner can update their templates. System templates cannot be modified.
#[utoipa::path(
    put,
    path = "/api/finding-templates/{id}",
    tag = "Finding Templates",
    params(
        ("id" = String, Path, description = "Template ID")
    ),
    request_body = UpdateFindingTemplateRequest,
    responses(
        (status = 200, description = "Template updated successfully", body = FindingTemplate),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Cannot modify system templates or other users' templates"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    body: web::Json<UpdateFindingTemplateRequest>,
) -> HttpResponse {
    let template_id = path.into_inner();

    // Validate severity if provided
    if let Some(ref severity) = body.severity {
        let valid_severities = ["critical", "high", "medium", "low", "info"];
        if !valid_severities.contains(&severity.to_lowercase().as_str()) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid severity. Must be one of: critical, high, medium, low, info"
            }));
        }
    }

    match db::update_finding_template(pool.get_ref(), &template_id, &body, &claims.sub).await {
        Ok(template) => HttpResponse::Ok().json(template),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("Cannot modify system templates") {
                HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Cannot modify system templates"
                }))
            } else if error_str.contains("Cannot modify templates created by other users") {
                HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Cannot modify templates created by other users"
                }))
            } else if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Template not found"
                }))
            } else {
                log::error!("Failed to update finding template: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to update finding template"
                }))
            }
        }
    }
}

/// Delete a finding template
///
/// Only the owner can delete their templates. System templates cannot be deleted.
#[utoipa::path(
    delete,
    path = "/api/finding-templates/{id}",
    tag = "Finding Templates",
    params(
        ("id" = String, Path, description = "Template ID")
    ),
    responses(
        (status = 200, description = "Template deleted successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Cannot delete system templates or other users' templates"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let template_id = path.into_inner();

    match db::delete_finding_template(pool.get_ref(), &template_id, &claims.sub).await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Template deleted successfully"
        })),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("Cannot delete system templates") {
                HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Cannot delete system templates"
                }))
            } else if error_str.contains("Cannot delete templates created by other users") {
                HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Cannot delete templates created by other users"
                }))
            } else if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Template not found"
                }))
            } else {
                log::error!("Failed to delete finding template: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to delete finding template"
                }))
            }
        }
    }
}

/// Clone a finding template
///
/// Creates a copy of any template (system or user's own) as a new user template.
#[utoipa::path(
    post,
    path = "/api/finding-templates/{id}/clone",
    tag = "Finding Templates",
    params(
        ("id" = String, Path, description = "Template ID to clone")
    ),
    request_body = CloneTemplateRequest,
    responses(
        (status = 201, description = "Template cloned successfully", body = FindingTemplate),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn clone_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    body: web::Json<CloneTemplateRequest>,
) -> HttpResponse {
    let template_id = path.into_inner();

    match db::clone_finding_template(
        pool.get_ref(),
        &template_id,
        &claims.sub,
        body.new_title.as_deref(),
    )
    .await
    {
        Ok(template) => HttpResponse::Created().json(template),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Template not found"
                }))
            } else {
                log::error!("Failed to clone finding template: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to clone finding template"
                }))
            }
        }
    }
}

/// Get template categories with counts
#[utoipa::path(
    get,
    path = "/api/finding-templates/categories",
    tag = "Finding Templates",
    responses(
        (status = 200, description = "List of categories with counts", body = Vec<CategoryCount>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_categories(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> HttpResponse {
    match db::get_template_categories(pool.get_ref()).await {
        Ok(categories) => {
            let result: Vec<serde_json::Value> = categories
                .into_iter()
                .map(|(category, count)| {
                    serde_json::json!({
                        "category": category,
                        "count": count
                    })
                })
                .collect();
            HttpResponse::Ok().json(result)
        }
        Err(e) => {
            log::error!("Failed to get template categories: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get template categories"
            }))
        }
    }
}

// Query and request types

#[derive(Debug, serde::Deserialize)]
pub struct ListTemplatesQuery {
    pub category: Option<String>,
    pub severity: Option<String>,
    pub search: Option<String>,
    pub include_system: Option<bool>,
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct CloneTemplateRequest {
    /// Optional new title for the cloned template
    pub new_title: Option<String>,
}

/// Category count response
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct CategoryCount {
    pub category: String,
    pub count: i64,
}

// ============================================================================
// Enhanced Finding Template Endpoints
// ============================================================================

/// List all finding template categories
#[utoipa::path(
    get,
    path = "/api/finding-templates/categories/all",
    tag = "Finding Templates",
    responses(
        (status = 200, description = "List of template categories", body = Vec<FindingTemplateCategory>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_all_categories(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> HttpResponse {
    match db::list_finding_template_categories(pool.get_ref()).await {
        Ok(categories) => HttpResponse::Ok().json(categories),
        Err(e) => {
            log::error!("Failed to list template categories: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list template categories"
            }))
        }
    }
}

/// Get popular templates by usage count
#[utoipa::path(
    get,
    path = "/api/finding-templates/popular",
    tag = "Finding Templates",
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of templates to return (default: 10)")
    ),
    responses(
        (status = 200, description = "List of popular templates", body = Vec<FindingTemplate>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_popular_templates(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    query: web::Query<PopularTemplatesQuery>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(10);

    match db::get_popular_templates(pool.get_ref(), limit).await {
        Ok(templates) => HttpResponse::Ok().json(templates),
        Err(e) => {
            log::error!("Failed to get popular templates: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get popular templates"
            }))
        }
    }
}

/// Search templates with advanced filters
#[utoipa::path(
    get,
    path = "/api/finding-templates/search",
    tag = "Finding Templates",
    params(
        ("q" = String, Query, description = "Search query"),
        ("category" = Option<String>, Query, description = "Filter by category"),
        ("severity" = Option<String>, Query, description = "Filter by severity"),
        ("owasp_category" = Option<String>, Query, description = "Filter by OWASP category"),
        ("limit" = Option<i64>, Query, description = "Maximum number of results (default: 50)"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination (default: 0)")
    ),
    responses(
        (status = 200, description = "Search results", body = Vec<FindingTemplate>),
        (status = 400, description = "Invalid search query"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn search_templates(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    query: web::Query<SearchTemplatesQuery>,
) -> HttpResponse {
    if query.q.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Search query is required"
        }));
    }

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    match db::search_templates(
        pool.get_ref(),
        &query.q,
        query.category.as_deref(),
        query.severity.as_deref(),
        query.owasp_category.as_deref(),
        limit,
        offset,
    )
    .await
    {
        Ok(templates) => HttpResponse::Ok().json(templates),
        Err(e) => {
            log::error!("Failed to search templates: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to search templates"
            }))
        }
    }
}

/// Get templates by OWASP category
#[utoipa::path(
    get,
    path = "/api/finding-templates/owasp/{category}",
    tag = "Finding Templates",
    params(
        ("category" = String, Path, description = "OWASP category (e.g., 'A01:2021-Broken Access Control')")
    ),
    responses(
        (status = 200, description = "Templates in OWASP category", body = Vec<FindingTemplate>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_templates_by_owasp(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let owasp_category = path.into_inner();

    match db::get_templates_by_owasp(pool.get_ref(), &owasp_category).await {
        Ok(templates) => HttpResponse::Ok().json(templates),
        Err(e) => {
            log::error!("Failed to get templates by OWASP category: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get templates by OWASP category"
            }))
        }
    }
}

/// Get templates by MITRE ATT&CK ID
#[utoipa::path(
    get,
    path = "/api/finding-templates/mitre/{technique_id}",
    tag = "Finding Templates",
    params(
        ("technique_id" = String, Path, description = "MITRE ATT&CK technique ID (e.g., 'T1003')")
    ),
    responses(
        (status = 200, description = "Templates with MITRE technique", body = Vec<FindingTemplate>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_templates_by_mitre(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let mitre_id = path.into_inner();

    match db::get_templates_by_mitre(pool.get_ref(), &mitre_id).await {
        Ok(templates) => HttpResponse::Ok().json(templates),
        Err(e) => {
            log::error!("Failed to get templates by MITRE ID: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get templates by MITRE ID"
            }))
        }
    }
}

/// Import templates from JSON
#[utoipa::path(
    post,
    path = "/api/finding-templates/import",
    tag = "Finding Templates",
    request_body = ImportTemplatesRequest,
    responses(
        (status = 200, description = "Import results", body = ImportTemplatesResponse),
        (status = 400, description = "Invalid import data"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn import_templates(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<ImportTemplatesRequest>,
) -> HttpResponse {
    if body.templates.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No templates to import"
        }));
    }

    let mut imported = 0;
    let mut skipped = 0;
    let mut errors: Vec<String> = Vec::new();

    for template in &body.templates {
        // Validate required fields
        if template.title.trim().is_empty() {
            errors.push(format!("Template missing title"));
            continue;
        }

        match db::create_finding_template(pool.get_ref(), template, &claims.sub).await {
            Ok(_) => imported += 1,
            Err(e) => {
                errors.push(format!("Failed to import '{}': {}", template.title, e));
                skipped += 1;
            }
        }
    }

    HttpResponse::Ok().json(ImportTemplatesResponse {
        imported,
        skipped,
        errors,
    })
}

/// Export templates to JSON
#[utoipa::path(
    get,
    path = "/api/finding-templates/export",
    tag = "Finding Templates",
    params(
        ("ids" = Option<String>, Query, description = "Comma-separated template IDs to export (all if not specified)"),
        ("include_system" = Option<bool>, Query, description = "Include system templates (default: false)")
    ),
    responses(
        (status = 200, description = "Exported templates", body = Vec<FindingTemplate>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn export_templates(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<ExportTemplatesQuery>,
) -> HttpResponse {
    let include_system = query.include_system.unwrap_or(false);

    match db::list_finding_templates(
        pool.get_ref(),
        None,
        None,
        None,
        include_system,
        Some(&claims.sub),
    )
    .await
    {
        Ok(mut templates) => {
            // Filter by IDs if specified
            if let Some(ref ids_str) = query.ids {
                let ids: Vec<&str> = ids_str.split(',').map(|s| s.trim()).collect();
                templates.retain(|t| ids.contains(&t.id.as_str()));
            }
            HttpResponse::Ok().json(templates)
        }
        Err(e) => {
            log::error!("Failed to export templates: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to export templates"
            }))
        }
    }
}

/// Apply a template to a vulnerability
///
/// Populates vulnerability fields from a template and increments the template usage count.
#[utoipa::path(
    post,
    path = "/api/finding-templates/{id}/apply",
    tag = "Finding Templates",
    params(
        ("id" = String, Path, description = "Template ID to apply")
    ),
    request_body = ApplyTemplateRequest,
    responses(
        (status = 200, description = "Template applied successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template or vulnerability not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn apply_template(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
    body: web::Json<ApplyTemplateRequest>,
) -> HttpResponse {
    let template_id = path.into_inner();

    // Verify template exists
    let template = match db::get_finding_template(pool.get_ref(), &template_id).await {
        Ok(t) => t,
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                return HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Template not found"
                }));
            }
            log::error!("Failed to get template: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get template"
            }));
        }
    };

    // Increment usage count
    if let Err(e) = db::increment_finding_template_use_count(pool.get_ref(), &template_id).await {
        log::warn!("Failed to increment template use count: {}", e);
    }

    // Return the template data for the client to apply
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Template applied successfully",
        "template": template,
        "vulnerability_id": body.vulnerability_id
    }))
}

// Additional query types

#[derive(Debug, serde::Deserialize)]
pub struct PopularTemplatesQuery {
    pub limit: Option<i64>,
}

#[derive(Debug, serde::Deserialize)]
pub struct SearchTemplatesQuery {
    pub q: String,
    pub category: Option<String>,
    pub severity: Option<String>,
    pub owasp_category: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ExportTemplatesQuery {
    pub ids: Option<String>,
    pub include_system: Option<bool>,
}
