//! Communication API endpoints

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::db::crm::{self, CreateCommunicationRequest};
use crate::web::auth::Claims;

#[derive(Debug, Deserialize)]
pub struct ListCommunicationsQuery {
    pub limit: Option<i32>,
}

/// List communications for a customer
pub async fn list_communications(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    query: web::Query<ListCommunicationsQuery>,
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

    match crm::get_customer_communications(pool.get_ref(), &customer_id, query.limit).await {
        Ok(communications) => HttpResponse::Ok().json(communications),
        Err(e) => {
            log::error!("Failed to list communications: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to list communications"}))
        }
    }
}

/// Create a communication for a customer
pub async fn create_communication(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<CreateCommunicationRequest>,
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

    // Validate communication type
    let valid_types = ["email", "call", "meeting", "note"];
    if !valid_types.contains(&body.comm_type.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid communication type. Must be one of: email, call, meeting, note"
        }));
    }

    match crm::create_communication(pool.get_ref(), &customer_id, &user_id, body.into_inner()).await {
        Ok(communication) => HttpResponse::Created().json(communication),
        Err(e) => {
            log::error!("Failed to create communication: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to create communication"}))
        }
    }
}

/// Delete a communication
pub async fn delete_communication(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims.sub.clone();

    let communication_id = path.into_inner();

    // Get communication to verify ownership
    let comm = match crm::get_communication_by_id(pool.get_ref(), &communication_id).await {
        Ok(c) => c,
        Err(e) => {
            if e.to_string().contains("no rows") {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "Communication not found"}));
            }
            log::error!("Failed to get communication: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to get communication"}));
        }
    };

    // Verify ownership via customer
    match crm::get_customer_by_id(pool.get_ref(), &comm.customer_id).await {
        Ok(customer) => {
            if customer.user_id != user_id {
                return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
            }
        }
        Err(_) => {
            return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
        }
    }

    match crm::delete_communication(pool.get_ref(), &communication_id).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(e) => {
            log::error!("Failed to delete communication: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to delete communication"}))
        }
    }
}
