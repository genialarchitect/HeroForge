use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::engagement_templates::{
    create_engagement_from_template, create_template, delete_template, get_all_templates,
    get_builtin_templates, get_template_by_id, get_templates_by_type,
    initialize_builtin_templates, CreateFromTemplateRequest, CreateTemplateRequest,
    EngagementSetupResult, EngagementTemplate, MilestoneTemplate, ScanConfigTemplate,
};
use crate::web::auth;

// ============================================================================
// Response Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct TemplateResponse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub engagement_type: String,
    pub default_duration_days: i32,
    pub default_budget: Option<f64>,
    pub scope_template: Option<String>,
    pub compliance_frameworks: Option<Vec<String>>,
    pub milestones: Option<Vec<MilestoneTemplate>>,
    pub scan_config: Option<ScanConfigTemplate>,
    pub is_system: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<EngagementTemplate> for TemplateResponse {
    fn from(t: EngagementTemplate) -> Self {
        let compliance_frameworks = t.compliance_frameworks
            .and_then(|json| serde_json::from_str(&json).ok());
        let milestones = t.milestones_template
            .and_then(|json| serde_json::from_str(&json).ok());
        let scan_config = t.scan_config_template
            .and_then(|json| serde_json::from_str(&json).ok());

        Self {
            id: t.id,
            name: t.name,
            description: t.description,
            engagement_type: t.engagement_type,
            default_duration_days: t.default_duration_days,
            default_budget: t.default_budget,
            scope_template: t.scope_template,
            compliance_frameworks,
            milestones,
            scan_config,
            is_system: t.is_system,
            created_at: t.created_at,
            updated_at: t.updated_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SetupResultResponse {
    pub engagement_id: String,
    pub engagement_name: String,
    pub milestones_created: usize,
    pub portal_user_created: bool,
    pub scan_config: Option<ScanConfigTemplate>,
}

impl From<EngagementSetupResult> for SetupResultResponse {
    fn from(r: EngagementSetupResult) -> Self {
        Self {
            engagement_id: r.engagement.id,
            engagement_name: r.engagement.name,
            milestones_created: r.milestones.len(),
            portal_user_created: r.portal_user_created,
            scan_config: r.scan_config,
        }
    }
}

// ============================================================================
// Endpoint Handlers
// ============================================================================

/// List all engagement templates
pub async fn list_templates(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match get_all_templates(pool.get_ref()).await {
        Ok(templates) => {
            let responses: Vec<TemplateResponse> = templates
                .into_iter()
                .map(TemplateResponse::from)
                .collect();
            HttpResponse::Ok().json(responses)
        }
        Err(e) => {
            log::error!("Failed to list templates: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve templates"
            }))
        }
    }
}

/// Get a specific template by ID
pub async fn get_template(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let id = path.into_inner();

    match get_template_by_id(pool.get_ref(), &id).await {
        Ok(template) => HttpResponse::Ok().json(TemplateResponse::from(template)),
        Err(e) => {
            log::error!("Failed to get template: {}", e);
            HttpResponse::NotFound().json(serde_json::json!({
                "error": "Template not found"
            }))
        }
    }
}

/// Get templates by engagement type
pub async fn get_templates_by_engagement_type(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let engagement_type = path.into_inner();

    match get_templates_by_type(pool.get_ref(), &engagement_type).await {
        Ok(templates) => {
            let responses: Vec<TemplateResponse> = templates
                .into_iter()
                .map(TemplateResponse::from)
                .collect();
            HttpResponse::Ok().json(responses)
        }
        Err(e) => {
            log::error!("Failed to get templates by type: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve templates"
            }))
        }
    }
}

/// Create a new custom template
pub async fn create_custom_template(
    pool: web::Data<SqlitePool>,
    request: web::Json<CreateTemplateRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match create_template(pool.get_ref(), request.into_inner(), false).await {
        Ok(template) => HttpResponse::Created().json(TemplateResponse::from(template)),
        Err(e) => {
            log::error!("Failed to create template: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create template: {}", e)
            }))
        }
    }
}

/// Delete a custom template (system templates cannot be deleted)
pub async fn delete_custom_template(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let id = path.into_inner();

    match delete_template(pool.get_ref(), &id).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Template deleted successfully"
        })),
        Ok(false) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Cannot delete system templates or template not found"
        })),
        Err(e) => {
            log::error!("Failed to delete template: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete template"
            }))
        }
    }
}

/// Create an engagement from a template (Quick Setup)
pub async fn create_engagement_from_template_handler(
    pool: web::Data<SqlitePool>,
    request: web::Json<CreateFromTemplateRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match create_engagement_from_template(pool.get_ref(), request.into_inner()).await {
        Ok(result) => HttpResponse::Created().json(serde_json::json!({
            "message": "Engagement created successfully from template",
            "result": SetupResultResponse::from(result)
        })),
        Err(e) => {
            log::error!("Failed to create engagement from template: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create engagement: {}", e)
            }))
        }
    }
}

/// Initialize built-in templates (admin only)
pub async fn initialize_templates(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match initialize_builtin_templates(pool.get_ref()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Built-in templates initialized successfully"
        })),
        Err(e) => {
            log::error!("Failed to initialize templates: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to initialize templates"
            }))
        }
    }
}

/// Get available engagement types
pub async fn get_engagement_types(
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let types = vec![
        serde_json::json!({
            "id": "external_pentest",
            "name": "External Penetration Test",
            "description": "External network penetration testing"
        }),
        serde_json::json!({
            "id": "internal_pentest",
            "name": "Internal Penetration Test",
            "description": "Internal network penetration testing"
        }),
        serde_json::json!({
            "id": "webapp_pentest",
            "name": "Web Application Assessment",
            "description": "Web application security testing"
        }),
        serde_json::json!({
            "id": "cloud_assessment",
            "name": "Cloud Security Assessment",
            "description": "Cloud infrastructure security review"
        }),
        serde_json::json!({
            "id": "red_team",
            "name": "Red Team Engagement",
            "description": "Full-scope adversary simulation"
        }),
        serde_json::json!({
            "id": "social_engineering",
            "name": "Social Engineering Campaign",
            "description": "Phishing and security awareness testing"
        }),
        serde_json::json!({
            "id": "wireless",
            "name": "Wireless Assessment",
            "description": "Wireless network security testing"
        }),
        serde_json::json!({
            "id": "vulnerability_assessment",
            "name": "Vulnerability Assessment",
            "description": "Comprehensive vulnerability scanning"
        }),
    ];

    HttpResponse::Ok().json(types)
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/engagement-templates")
            // List all templates
            .route("", web::get().to(list_templates))
            // Initialize built-in templates (admin)
            .route("/initialize", web::post().to(initialize_templates))
            // Get engagement types
            .route("/types", web::get().to(get_engagement_types))
            // Get template by ID
            .route("/{id}", web::get().to(get_template))
            // Get templates by type
            .route("/type/{type}", web::get().to(get_templates_by_engagement_type))
            // Create custom template
            .route("", web::post().to(create_custom_template))
            // Delete custom template
            .route("/{id}", web::delete().to(delete_custom_template))
            // Create engagement from template (Quick Setup)
            .route("/setup", web::post().to(create_engagement_from_template_handler))
    );
}
