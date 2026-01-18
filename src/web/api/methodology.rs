//! Methodology Checklists API endpoints
//!
//! Provides API for managing methodology testing checklists (PTES, OWASP WSTG):
//! - Templates: Browse built-in methodology frameworks
//! - Checklists: Create and manage user's checklist instances
//! - Items: Update progress on individual checklist items

use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;

use crate::db::{
    self,
    models::{
        CreateChecklistRequest, UpdateChecklistRequest, UpdateChecklistItemRequest,
        MethodologyTemplate, MethodologyTemplateWithItems, ChecklistSummary,
        ChecklistWithItems, ChecklistProgress, MethodologyChecklist, ChecklistItem,
    },
};
use crate::web::auth::jwt::Claims;

// ============================================================================
// Template Endpoints (Read-only)
// ============================================================================

/// List all methodology templates
///
/// Returns all available methodology frameworks (PTES, OWASP WSTG, etc.)
#[utoipa::path(
    get,
    path = "/api/methodology/templates",
    tag = "Methodology",
    responses(
        (status = 200, description = "List of methodology templates", body = Vec<MethodologyTemplate>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_templates(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> HttpResponse {
    match db::list_methodology_templates(pool.get_ref()).await {
        Ok(templates) => HttpResponse::Ok().json(templates),
        Err(e) => {
            log::error!("Failed to list methodology templates: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list methodology templates"
            }))
        }
    }
}

/// Get a methodology template with all its items
#[utoipa::path(
    get,
    path = "/api/methodology/templates/{id}",
    tag = "Methodology",
    params(
        ("id" = String, Path, description = "Template ID")
    ),
    responses(
        (status = 200, description = "Template with items", body = MethodologyTemplateWithItems),
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

    match db::get_methodology_template_with_items(pool.get_ref(), &template_id).await {
        Ok(template) => HttpResponse::Ok().json(template),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Template not found"
                }))
            } else {
                log::error!("Failed to get methodology template: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to get methodology template"
                }))
            }
        }
    }
}

// ============================================================================
// Checklist Endpoints
// ============================================================================

/// List all checklists for the current user
#[utoipa::path(
    get,
    path = "/api/methodology/checklists",
    tag = "Methodology",
    responses(
        (status = 200, description = "List of user's checklists", body = Vec<ChecklistSummary>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_checklists(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> HttpResponse {
    match db::get_user_checklists(pool.get_ref(), &claims.sub).await {
        Ok(checklists) => HttpResponse::Ok().json(checklists),
        Err(e) => {
            log::error!("Failed to list checklists: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list checklists"
            }))
        }
    }
}

/// Create a new checklist from a template
#[utoipa::path(
    post,
    path = "/api/methodology/checklists",
    tag = "Methodology",
    request_body = CreateChecklistRequest,
    responses(
        (status = 201, description = "Checklist created successfully", body = MethodologyChecklist),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_checklist(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<CreateChecklistRequest>,
) -> HttpResponse {
    // Validate required fields
    if body.name.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Name is required"
        }));
    }

    if body.template_id.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Template ID is required"
        }));
    }

    match db::create_checklist(pool.get_ref(), &claims.sub, &body).await {
        Ok(checklist) => HttpResponse::Created().json(checklist),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Template not found"
                }))
            } else {
                log::error!("Failed to create checklist: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to create checklist"
                }))
            }
        }
    }
}

/// Get a checklist with all its items
#[utoipa::path(
    get,
    path = "/api/methodology/checklists/{id}",
    tag = "Methodology",
    params(
        ("id" = String, Path, description = "Checklist ID")
    ),
    responses(
        (status = 200, description = "Checklist with items", body = ChecklistWithItems),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Checklist not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_checklist(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let checklist_id = path.into_inner();

    match db::get_checklist_with_items(pool.get_ref(), &checklist_id).await {
        Ok(checklist) => {
            // Verify ownership
            if checklist.checklist.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                }));
            }
            HttpResponse::Ok().json(checklist)
        }
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Checklist not found"
                }))
            } else {
                log::error!("Failed to get checklist: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to get checklist"
                }))
            }
        }
    }
}

/// Update checklist metadata
#[utoipa::path(
    put,
    path = "/api/methodology/checklists/{id}",
    tag = "Methodology",
    params(
        ("id" = String, Path, description = "Checklist ID")
    ),
    request_body = UpdateChecklistRequest,
    responses(
        (status = 200, description = "Checklist updated successfully", body = MethodologyChecklist),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Checklist not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_checklist(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    body: web::Json<UpdateChecklistRequest>,
) -> HttpResponse {
    let checklist_id = path.into_inner();

    // Validate status if provided
    if let Some(ref status) = body.status {
        let valid_statuses = ["in_progress", "completed", "archived"];
        if !valid_statuses.contains(&status.as_str()) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid status. Must be one of: in_progress, completed, archived"
            }));
        }
    }

    match db::update_checklist(pool.get_ref(), &checklist_id, &claims.sub, &body).await {
        Ok(checklist) => HttpResponse::Ok().json(checklist),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("Cannot modify checklist owned by another user") {
                HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                }))
            } else if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Checklist not found"
                }))
            } else {
                log::error!("Failed to update checklist: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to update checklist"
                }))
            }
        }
    }
}

/// Delete a checklist
#[utoipa::path(
    delete,
    path = "/api/methodology/checklists/{id}",
    tag = "Methodology",
    params(
        ("id" = String, Path, description = "Checklist ID")
    ),
    responses(
        (status = 200, description = "Checklist deleted successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Checklist not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_checklist(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let checklist_id = path.into_inner();

    match db::delete_checklist(pool.get_ref(), &checklist_id, &claims.sub).await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Checklist deleted successfully"
        })),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("Cannot delete checklist owned by another user") {
                HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                }))
            } else if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Checklist not found"
                }))
            } else {
                log::error!("Failed to delete checklist: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to delete checklist"
                }))
            }
        }
    }
}

/// Get checklist progress summary
#[utoipa::path(
    get,
    path = "/api/methodology/checklists/{id}/progress",
    tag = "Methodology",
    params(
        ("id" = String, Path, description = "Checklist ID")
    ),
    responses(
        (status = 200, description = "Checklist progress", body = ChecklistProgress),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Checklist not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_progress(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let checklist_id = path.into_inner();

    // Verify ownership first
    match db::get_checklist(pool.get_ref(), &checklist_id).await {
        Ok(checklist) => {
            if checklist.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                }));
            }
        }
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                return HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Checklist not found"
                }));
            }
            log::error!("Failed to verify checklist ownership: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get checklist progress"
            }));
        }
    }

    match db::get_checklist_progress(pool.get_ref(), &checklist_id).await {
        Ok(progress) => HttpResponse::Ok().json(progress),
        Err(e) => {
            log::error!("Failed to get checklist progress: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get checklist progress"
            }))
        }
    }
}

// ============================================================================
// Checklist Item Endpoints
// ============================================================================

/// Update a checklist item's status and notes
#[utoipa::path(
    put,
    path = "/api/methodology/checklists/{checklist_id}/items/{item_id}",
    tag = "Methodology",
    params(
        ("checklist_id" = String, Path, description = "Checklist ID"),
        ("item_id" = String, Path, description = "Template item ID")
    ),
    request_body = UpdateChecklistItemRequest,
    responses(
        (status = 200, description = "Item updated successfully", body = ChecklistItem),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Item not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_item(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
    body: web::Json<UpdateChecklistItemRequest>,
) -> HttpResponse {
    let (checklist_id, template_item_id) = path.into_inner();

    // Validate status if provided
    if let Some(ref status) = body.status {
        let valid_statuses = ["not_started", "in_progress", "pass", "fail", "na"];
        if !valid_statuses.contains(&status.as_str()) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid status. Must be one of: not_started, in_progress, pass, fail, na"
            }));
        }
    }

    match db::update_checklist_item(
        pool.get_ref(),
        &checklist_id,
        &template_item_id,
        &claims.sub,
        &body,
    )
    .await
    {
        Ok(item) => HttpResponse::Ok().json(item),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("Cannot modify items in checklist owned by another user") {
                HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                }))
            } else if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Checklist or item not found"
                }))
            } else {
                log::error!("Failed to update checklist item: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to update checklist item"
                }))
            }
        }
    }
}

/// Get a single checklist item
#[utoipa::path(
    get,
    path = "/api/methodology/checklists/{checklist_id}/items/{item_id}",
    tag = "Methodology",
    params(
        ("checklist_id" = String, Path, description = "Checklist ID"),
        ("item_id" = String, Path, description = "Template item ID")
    ),
    responses(
        (status = 200, description = "Checklist item", body = ChecklistItem),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Item not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_item(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (checklist_id, template_item_id) = path.into_inner();

    // Verify ownership first
    match db::get_checklist(pool.get_ref(), &checklist_id).await {
        Ok(checklist) => {
            if checklist.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                }));
            }
        }
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                return HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Checklist not found"
                }));
            }
            log::error!("Failed to verify checklist ownership: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get checklist item"
            }));
        }
    }

    match db::get_checklist_item(pool.get_ref(), &checklist_id, &template_item_id).await {
        Ok(item) => HttpResponse::Ok().json(item),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Item not found"
                }))
            } else {
                log::error!("Failed to get checklist item: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to get checklist item"
                }))
            }
        }
    }
}

// ============================================================================
// Exploit / Automated Testing Endpoints
// ============================================================================

use crate::methodology::{
    get_mapping, MethodologyTestExecutor, ScannerMapping, ScannerType, TestExecutionRequest,
    TestExecutionResult,
};

/// Request body for exploiting a checklist item
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct ExploitItemRequest {
    /// Target URL for web application tests
    pub target_url: Option<String>,
    /// Target IP address for network tests
    pub target_ip: Option<String>,
    /// Target domain for DNS/OSINT tests
    pub target_domain: Option<String>,
    /// Target port for specific service tests
    pub target_port: Option<u16>,
    /// Run in safe mode (read-only, non-destructive)
    #[serde(default = "default_true")]
    pub safe_mode: bool,
    /// Timeout for the test in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_true() -> bool {
    true
}

fn default_timeout() -> u64 {
    120
}

/// Response from exploiting a checklist item
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct ExploitItemResponse {
    pub success: bool,
    pub item_code: String,
    pub scanner_type: String,
    pub findings_count: usize,
    pub recommended_status: String,
    pub summary: String,
    pub findings: Vec<serde_json::Value>,
    pub evidence: Vec<String>,
    pub duration_secs: f64,
    pub item_updated: bool,
}

/// Run automated exploit test for a methodology checklist item
///
/// This endpoint triggers the appropriate scanner for the methodology item
/// and automatically updates the checklist item with the results.
#[utoipa::path(
    post,
    path = "/api/methodology/checklists/{checklist_id}/items/{item_id}/exploit",
    tag = "Methodology",
    params(
        ("checklist_id" = String, Path, description = "Checklist ID"),
        ("item_id" = String, Path, description = "Template item ID")
    ),
    request_body = ExploitItemRequest,
    responses(
        (status = 200, description = "Test executed successfully", body = ExploitItemResponse),
        (status = 400, description = "Invalid request or no scanner available"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Checklist or item not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn exploit_checklist_item(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
    body: web::Json<ExploitItemRequest>,
) -> HttpResponse {
    let (checklist_id, template_item_id) = path.into_inner();

    // Verify checklist ownership
    let checklist = match db::get_checklist(pool.get_ref(), &checklist_id).await {
        Ok(c) => c,
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                return HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Checklist not found"
                }));
            }
            log::error!("Failed to get checklist: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get checklist"
            }));
        }
    };

    if checklist.user_id != claims.sub {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        }));
    }

    // Get the template item to find its item_code
    let template_item = match db::get_methodology_template_item(pool.get_ref(), &template_item_id).await {
        Ok(item) => item,
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                return HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Template item not found"
                }));
            }
            log::error!("Failed to get template item: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get template item"
            }));
        }
    };

    let item_code = template_item.item_id.clone().unwrap_or_default();

    // Get scanner mapping
    let mapping = match get_mapping(&item_code) {
        Some(m) => m,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No automated scanner available for this methodology item",
                "item_code": item_code,
                "suggestion": "This test requires manual verification"
            }));
        }
    };

    // Validate requirements
    if mapping.requires_url && body.target_url.is_none() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Target URL is required for this test",
            "scanner_type": format!("{}", mapping.scanner_type)
        }));
    }
    if mapping.requires_ip && body.target_ip.is_none() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Target IP address is required for this test",
            "scanner_type": format!("{}", mapping.scanner_type)
        }));
    }

    // Execute the test
    let executor = MethodologyTestExecutor::new(pool.get_ref().clone());
    let request = TestExecutionRequest {
        target_url: body.target_url.clone(),
        target_ip: body.target_ip.clone(),
        target_domain: body.target_domain.clone(),
        target_port: body.target_port,
        safe_mode: body.safe_mode,
        timeout_secs: body.timeout_secs,
    };

    let result = match executor.execute(&mapping.scanner_type, &request).await {
        Ok(r) => r,
        Err(e) => {
            log::error!("Test execution failed for {}: {}", item_code, e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Test execution failed: {}", e),
                "item_code": item_code
            }));
        }
    };

    // Update the checklist item with results
    // Convert findings to Vec<String> by serializing each finding to JSON string
    let findings_strings: Option<Vec<String>> = Some(
        result.findings.iter()
            .map(|f| serde_json::to_string(f).unwrap_or_default())
            .collect()
    );
    let evidence_json = serde_json::to_string(&result.evidence).ok();

    let update_request = UpdateChecklistItemRequest {
        status: Some(result.recommended_status.clone()),
        notes: Some(result.summary.clone()),
        evidence: evidence_json,
        findings: findings_strings,
    };

    let item_updated = db::update_checklist_item(
        pool.get_ref(),
        &checklist_id,
        &template_item_id,
        &claims.sub,
        &update_request,
    )
    .await
    .is_ok();

    log::info!(
        "User {} exploited methodology item {} on checklist {}: {}",
        claims.sub,
        item_code,
        checklist_id,
        result.summary
    );

    HttpResponse::Ok().json(ExploitItemResponse {
        success: result.success,
        item_code,
        scanner_type: format!("{}", mapping.scanner_type),
        findings_count: result.findings_count,
        recommended_status: result.recommended_status,
        summary: result.summary,
        findings: result.findings,
        evidence: result.evidence,
        duration_secs: result.duration_secs,
        item_updated,
    })
}

/// Get scanner information for a methodology item code
///
/// Returns information about the automated scanner available for a specific
/// methodology item, including what inputs are required.
#[utoipa::path(
    get,
    path = "/api/methodology/items/{item_code}/scanner-info",
    tag = "Methodology",
    params(
        ("item_code" = String, Path, description = "Methodology item code (e.g., WSTG-INPV-01)")
    ),
    responses(
        (status = 200, description = "Scanner mapping information", body = ScannerMapping),
        (status = 404, description = "No scanner available for this item")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_scanner_info(
    _claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let item_code = path.into_inner();

    match get_mapping(&item_code) {
        Some(mapping) => HttpResponse::Ok().json(mapping),
        None => HttpResponse::NotFound().json(serde_json::json!({
            "error": "No automated scanner available for this methodology item",
            "item_code": item_code,
            "suggestion": "This test requires manual verification"
        })),
    }
}

/// List all scanner mappings
///
/// Returns all available scanner mappings for methodology items.
#[utoipa::path(
    get,
    path = "/api/methodology/scanner-mappings",
    tag = "Methodology",
    responses(
        (status = 200, description = "List of all scanner mappings", body = Vec<ScannerMapping>)
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_scanner_mappings(_claims: Claims) -> HttpResponse {
    let mappings = crate::methodology::get_all_mappings();
    let mapping_list: Vec<ScannerMapping> = mappings.into_values().collect();
    HttpResponse::Ok().json(mapping_list)
}
