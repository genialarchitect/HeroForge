use actix_web::{web, HttpResponse};
use crate::web::auth::Claims;
use crate::patch_management;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct PriorityRequest {
    pub cvss: f64,
    pub epss: f64,
    pub exploitability: f64,
    pub asset_criticality: f64,
}

/// Calculate patch priority score
pub async fn calculate_priority(
    _claims: Claims,
    req: web::Json<PriorityRequest>,
) -> actix_web::Result<HttpResponse> {
    let priority = patch_management::prioritization::calculate_patch_priority(
        req.cvss,
        req.epss,
        req.exploitability,
        req.asset_criticality,
    )
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"priority_score": priority})))
}

/// Get patch analytics
pub async fn get_analytics(
    _claims: Claims,
) -> actix_web::Result<HttpResponse> {
    let coverage = patch_management::analytics::get_patch_coverage().await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let mttp = patch_management::analytics::calculate_mttp().await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let success_rate = patch_management::analytics::get_patch_success_rate().await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(patch_management::analytics::PatchAnalytics {
        total_patches: 0,
        deployed_patches: 0,
        pending_patches: 0,
        failed_patches: 0,
        coverage_percentage: coverage,
        mean_time_to_patch: mttp,
        success_rate,
    }))
}

#[derive(Deserialize)]
pub struct CreateVirtualPatchRequest {
    pub cve_id: String,
    pub vuln_details: serde_json::Value,
}

/// Create virtual patch (WAF/IPS rule)
pub async fn create_virtual_patch(
    _claims: Claims,
    req: web::Json<CreateVirtualPatchRequest>,
) -> actix_web::Result<HttpResponse> {
    let virtual_patch = patch_management::virtual_patching::create_waf_rule(&req.cve_id, &req.vuln_details)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(virtual_patch))
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/patch-management")
            .route("/priority", web::post().to(calculate_priority))
            .route("/analytics", web::get().to(get_analytics))
            .route("/virtual-patch", web::post().to(create_virtual_patch))
    );
}
