use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use crate::web::auth::Claims;
use crate::db::investigation;
use crate::investigation::types::*;

/// List user's investigations
pub async fn list_investigations(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> actix_web::Result<HttpResponse> {
    let investigations = investigation::list_user_investigations(&pool, &claims.sub)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(investigations))
}

/// Create new investigation
pub async fn create_investigation(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    req: web::Json<CreateInvestigationRequest>,
) -> actix_web::Result<HttpResponse> {
    let investigation = investigation::create_investigation(&pool, &claims.sub, req.into_inner())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(investigation))
}

/// Get investigation by ID
pub async fn get_investigation(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    investigation_id: web::Path<String>,
) -> actix_web::Result<HttpResponse> {
    let investigation = investigation::get_investigation_by_id(&pool, &investigation_id)
        .await
        .map_err(|e| actix_web::error::ErrorNotFound(e))?;

    Ok(HttpResponse::Ok().json(investigation))
}

/// Add timeline event to investigation
pub async fn add_timeline_event(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    investigation_id: web::Path<String>,
    req: web::Json<AddTimelineEventRequest>,
) -> actix_web::Result<HttpResponse> {
    let event = investigation::add_timeline_event(&pool, &investigation_id, req.into_inner())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(event))
}

/// Get timeline events for investigation
pub async fn get_timeline(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    investigation_id: web::Path<String>,
) -> actix_web::Result<HttpResponse> {
    let events = investigation::get_timeline_events(&pool, &investigation_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(events))
}

/// Add graph entity to investigation
pub async fn add_graph_entity(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    investigation_id: web::Path<String>,
    req: web::Json<AddGraphEntityRequest>,
) -> actix_web::Result<HttpResponse> {
    let entity = investigation::add_graph_entity(&pool, &investigation_id, req.into_inner())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(entity))
}

/// Get graph entities for investigation
pub async fn get_graph_entities(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    investigation_id: web::Path<String>,
) -> actix_web::Result<HttpResponse> {
    let entities = investigation::get_graph_entities(&pool, &investigation_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(entities))
}

/// Add graph relationship to investigation
pub async fn add_graph_relationship(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    investigation_id: web::Path<String>,
    req: web::Json<AddGraphRelationshipRequest>,
) -> actix_web::Result<HttpResponse> {
    let relationship = investigation::add_graph_relationship(&pool, &investigation_id, req.into_inner())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(relationship))
}

/// Get graph relationships for investigation
pub async fn get_graph_relationships(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    investigation_id: web::Path<String>,
) -> actix_web::Result<HttpResponse> {
    let relationships = investigation::get_graph_relationships(&pool, &investigation_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(relationships))
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/investigations")
            .route("", web::get().to(list_investigations))
            .route("", web::post().to(create_investigation))
            .route("/{id}", web::get().to(get_investigation))
            .route("/{id}/timeline", web::get().to(get_timeline))
            .route("/{id}/timeline", web::post().to(add_timeline_event))
            .route("/{id}/graph/entities", web::get().to(get_graph_entities))
            .route("/{id}/graph/entities", web::post().to(add_graph_entity))
            .route("/{id}/graph/relationships", web::get().to(get_graph_relationships))
            .route("/{id}/graph/relationships", web::post().to(add_graph_relationship))
    );
}
