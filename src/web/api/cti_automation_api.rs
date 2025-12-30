use actix_web::{web, HttpResponse};
use crate::web::auth::Claims;
use crate::cti_automation;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct EnrichIocRequest {
    pub ioc: String,
    pub ioc_type: String,
}

/// Enrich IOC with threat intelligence
pub async fn enrich_ioc(
    _claims: Claims,
    req: web::Json<EnrichIocRequest>,
) -> actix_web::Result<HttpResponse> {
    let enrichment = cti_automation::enrichment::enrich_ioc(&req.ioc, &req.ioc_type)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(enrichment))
}

#[derive(Deserialize)]
pub struct AutoBlockRequest {
    pub ioc: String,
    pub confidence: f64,
}

/// Auto-block IOC across security controls
pub async fn auto_block_ioc(
    _claims: Claims,
    req: web::Json<AutoBlockRequest>,
) -> actix_web::Result<HttpResponse> {
    let response = cti_automation::automated_response::auto_block_ioc(&req.ioc, req.confidence)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(response))
}

#[derive(Deserialize)]
pub struct ShareIocRequest {
    pub ioc: String,
    pub tlp: String,
}

/// Share IOC with ISAC/ISAO
pub async fn share_ioc(
    _claims: Claims,
    req: web::Json<ShareIocRequest>,
) -> actix_web::Result<HttpResponse> {
    cti_automation::sharing::share_with_isac(&req.ioc, &req.tlp)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "shared"})))
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/cti-automation")
            .route("/enrich", web::post().to(enrich_ioc))
            .route("/auto-block", web::post().to(auto_block_ioc))
            .route("/share", web::post().to(share_ioc))
    );
}
