use actix_web::{web, HttpResponse};
use crate::web::auth::Claims;
use crate::predictive_security;
use serde::Deserialize;

/// Predict next attack
pub async fn predict_attack(
    _claims: Claims,
) -> actix_web::Result<HttpResponse> {
    let historical_data = Vec::new(); // Would load from database
    let prediction = predictive_security::predictions::predict_next_attack(&historical_data)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(prediction))
}

#[derive(Deserialize)]
pub struct BreachPredictionRequest {
    pub asset_id: String,
}

/// Predict breach likelihood for asset
pub async fn predict_breach(
    _claims: Claims,
    req: web::Json<BreachPredictionRequest>,
) -> actix_web::Result<HttpResponse> {
    let prediction = predictive_security::predictions::predict_breach_likelihood(&req.asset_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(prediction))
}

#[derive(Deserialize)]
pub struct ForecastRequest {
    pub horizon_days: i32,
}

/// Forecast incident volume
pub async fn forecast_incidents(
    _claims: Claims,
    req: web::Json<ForecastRequest>,
) -> actix_web::Result<HttpResponse> {
    let forecast = predictive_security::predictions::predict_incident_volume(req.horizon_days)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(forecast))
}

/// Forecast resource requirements
pub async fn forecast_resources(
    _claims: Claims,
    req: web::Json<ForecastRequest>,
) -> actix_web::Result<HttpResponse> {
    let soc_forecast = predictive_security::forecasting::forecast_soc_staffing(req.horizon_days)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let infra_forecast = predictive_security::forecasting::forecast_infrastructure_capacity(req.horizon_days)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "soc_staffing": soc_forecast,
        "infrastructure": infra_forecast
    })))
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/predictive")
            .route("/attack", web::get().to(predict_attack))
            .route("/breach", web::post().to(predict_breach))
            .route("/incidents", web::post().to(forecast_incidents))
            .route("/resources", web::post().to(forecast_resources))
    );
}
