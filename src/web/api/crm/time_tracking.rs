//! Time Tracking API endpoints

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::db::crm::{self, CreateTimeEntryRequest};
use crate::web::auth::Claims;

#[derive(Debug, Deserialize)]
pub struct ListTimeEntriesQuery {
    pub start_date: Option<String>,
    pub end_date: Option<String>,
}

/// List time entries for the authenticated user
pub async fn list_time_entries(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    query: web::Query<ListTimeEntriesQuery>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims.sub.clone();

    match crm::get_user_time_entries(
        pool.get_ref(),
        &user_id,
        query.start_date.as_deref(),
        query.end_date.as_deref(),
    ).await {
        Ok(entries) => HttpResponse::Ok().json(entries),
        Err(e) => {
            log::error!("Failed to list time entries: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to list time entries"}))
        }
    }
}

/// List time entries for an engagement
pub async fn list_engagement_time(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims.sub.clone();

    let engagement_id = path.into_inner();

    // Verify ownership via engagement -> customer
    let engagement = match crm::get_engagement_by_id(pool.get_ref(), &engagement_id).await {
        Ok(e) => e,
        Err(e) => {
            if e.to_string().contains("no rows") {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "Engagement not found"}));
            }
            log::error!("Failed to get engagement: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to get engagement"}));
        }
    };

    match crm::get_customer_by_id(pool.get_ref(), &engagement.customer_id).await {
        Ok(customer) => {
            if customer.user_id != user_id {
                return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
            }
        }
        Err(_) => {
            return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
        }
    }

    match crm::get_engagement_time_entries(pool.get_ref(), &engagement_id).await {
        Ok(entries) => HttpResponse::Ok().json(entries),
        Err(e) => {
            log::error!("Failed to list time entries: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to list time entries"}))
        }
    }
}

/// Create a time entry for an engagement
pub async fn create_time_entry(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<CreateTimeEntryRequest>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims.sub.clone();

    let engagement_id = path.into_inner();

    // Verify ownership via engagement -> customer
    let engagement = match crm::get_engagement_by_id(pool.get_ref(), &engagement_id).await {
        Ok(e) => e,
        Err(e) => {
            if e.to_string().contains("no rows") {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "Engagement not found"}));
            }
            log::error!("Failed to get engagement: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to get engagement"}));
        }
    };

    match crm::get_customer_by_id(pool.get_ref(), &engagement.customer_id).await {
        Ok(customer) => {
            if customer.user_id != user_id {
                return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
            }
        }
        Err(_) => {
            return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
        }
    }

    if body.description.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Description is required"}));
    }

    if body.hours <= 0.0 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Hours must be greater than 0"}));
    }

    match crm::create_time_entry(pool.get_ref(), &engagement_id, &user_id, body.into_inner()).await {
        Ok(entry) => HttpResponse::Created().json(entry),
        Err(e) => {
            log::error!("Failed to create time entry: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to create time entry"}))
        }
    }
}

/// Delete a time entry
pub async fn delete_time_entry(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match req.extensions().get::<Claims>() {
        Some(claims) => claims.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };
    let user_id = claims.sub.clone();

    let entry_id = path.into_inner();

    // Get entry to verify ownership
    let entry = match crm::get_time_entry_by_id(pool.get_ref(), &entry_id).await {
        Ok(e) => e,
        Err(e) => {
            if e.to_string().contains("no rows") {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "Time entry not found"}));
            }
            log::error!("Failed to get time entry: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to get time entry"}));
        }
    };

    // User can only delete their own time entries
    if entry.user_id != user_id {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"}));
    }

    match crm::delete_time_entry(pool.get_ref(), &entry_id).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(e) => {
            log::error!("Failed to delete time entry: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to delete time entry"}))
        }
    }
}
