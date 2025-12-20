//! SLA API endpoints

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use sqlx::SqlitePool;

use crate::db::crm::{self, CreateSlaRequest};
use crate::web::auth::Claims;

/// List SLA templates
pub async fn list_sla_templates(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };
    let _user_id = claims.sub.clone();

    match crm::get_sla_templates(pool.get_ref()).await {
        Ok(slas) => HttpResponse::Ok().json(slas),
        Err(e) => {
            log::error!("Failed to list SLA templates: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to list SLA templates"}))
        }
    }
}

/// Create an SLA template
pub async fn create_sla_template(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateSlaRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };
    let _user_id = claims.sub.clone();

    if body.name.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "SLA name is required"}));
    }

    let mut req_inner = body.into_inner();
    req_inner.is_template = Some(true);

    match crm::create_sla(pool.get_ref(), None, req_inner).await {
        Ok(sla) => HttpResponse::Created().json(sla),
        Err(e) => {
            log::error!("Failed to create SLA template: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to create SLA template"}))
        }
    }
}

/// Get SLA for a customer
pub async fn get_customer_sla(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims.sub.clone();

    let customer_id = path.into_inner();

    // Verify customer ownership
    match crm::get_customer_by_id(pool.get_ref(), &customer_id).await {
        Ok(customer) => {
            if customer.user_id != user_id {
                return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
            }
        }
        Err(e) => {
            if e.to_string().contains("no rows") {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "Customer not found"}));
            }
            log::error!("Failed to verify customer: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to verify customer"}));
        }
    }

    match crm::get_customer_sla(pool.get_ref(), &customer_id).await {
        Ok(sla) => match sla {
            Some(s) => HttpResponse::Ok().json(s),
            None => HttpResponse::Ok().json(serde_json::json!(null)),
        },
        Err(e) => {
            log::error!("Failed to get customer SLA: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to get customer SLA"}))
        }
    }
}

/// Set SLA for a customer
pub async fn set_customer_sla(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<CreateSlaRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims.sub.clone();

    let customer_id = path.into_inner();

    // Verify customer ownership
    match crm::get_customer_by_id(pool.get_ref(), &customer_id).await {
        Ok(customer) => {
            if customer.user_id != user_id {
                return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
            }
        }
        Err(e) => {
            if e.to_string().contains("no rows") {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "Customer not found"}));
            }
            log::error!("Failed to verify customer: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to verify customer"}));
        }
    }

    if body.name.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "SLA name is required"}));
    }

    // Delete existing SLA if any
    if let Ok(Some(existing)) = crm::get_customer_sla(pool.get_ref(), &customer_id).await {
        if let Err(e) = crm::delete_sla(pool.get_ref(), &existing.id).await {
            log::warn!("Failed to delete existing SLA: {}", e);
        }
    }

    let mut req_inner = body.into_inner();
    req_inner.is_template = Some(false);

    match crm::create_sla(pool.get_ref(), Some(&customer_id), req_inner).await {
        Ok(sla) => HttpResponse::Created().json(sla),
        Err(e) => {
            log::error!("Failed to create customer SLA: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to create customer SLA"}))
        }
    }
}

/// Delete an SLA
pub async fn delete_sla(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims.sub.clone();

    let sla_id = path.into_inner();

    // Get SLA to verify it exists and check ownership
    let sla = match crm::get_sla_by_id(pool.get_ref(), &sla_id).await {
        Ok(s) => s,
        Err(e) => {
            if e.to_string().contains("no rows") {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "SLA not found"}));
            }
            log::error!("Failed to get SLA: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to get SLA"}));
        }
    };

    // If it's a customer SLA, verify ownership
    if let Some(customer_id) = &sla.customer_id {
        match crm::get_customer_by_id(pool.get_ref(), customer_id).await {
            Ok(customer) => {
                if customer.user_id != user_id {
                    return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
                }
            }
            Err(_) => {
                return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
            }
        }
    }

    match crm::delete_sla(pool.get_ref(), &sla_id).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(e) => {
            log::error!("Failed to delete SLA: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to delete SLA"}))
        }
    }
}
