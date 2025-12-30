use actix_web::{web, HttpResponse};
use crate::web::auth::Claims;
use crate::orchestration;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CloudOrchestrationRequest {
    pub platform: String, // aws, azure, gcp
    pub function_name: String,
    pub payload: serde_json::Value,
}

/// Execute cloud orchestration
pub async fn execute_cloud_orchestration(
    _claims: Claims,
    req: web::Json<CloudOrchestrationRequest>,
) -> actix_web::Result<HttpResponse> {
    let result = match req.platform.as_str() {
        "aws" => orchestration::multi_cloud::orchestrate_aws_lambda(&req.function_name, req.payload.clone()).await,
        "azure" => orchestration::multi_cloud::orchestrate_azure_logic_app(&req.function_name, req.payload.clone()).await,
        "gcp" => orchestration::multi_cloud::orchestrate_gcp_function(&req.function_name, req.payload.clone()).await,
        _ => Err(anyhow::anyhow!("Unsupported platform")),
    }
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Deserialize)]
pub struct EdgeActionRequest {
    pub node_id: String,
    pub action: String,
}

/// Execute edge orchestration
pub async fn execute_edge_orchestration(
    _claims: Claims,
    req: web::Json<EdgeActionRequest>,
) -> actix_web::Result<HttpResponse> {
    orchestration::edge::orchestrate_edge_device(&req.node_id, &req.action)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "executed"})))
}

/// Get scaling recommendation
pub async fn get_scaling_recommendation(
    _claims: Claims,
) -> actix_web::Result<HttpResponse> {
    let current_load = 0.8; // Would be calculated from metrics
    let required_instances = orchestration::scale::horizontal_scaling(current_load)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "current_load": current_load,
        "required_instances": required_instances
    })))
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/orchestration")
            .route("/cloud", web::post().to(execute_cloud_orchestration))
            .route("/edge", web::post().to(execute_edge_orchestration))
            .route("/scaling", web::get().to(get_scaling_recommendation))
    );
}
