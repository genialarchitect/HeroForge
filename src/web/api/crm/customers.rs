//! Customer API endpoints

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::crm::{
    self, CreateCustomerRequest, UpdateCustomerRequest,
};
use crate::web::auth::Claims;
use crate::web::error::{ApiErrorKind, bad_request, forbidden, not_found, internal_error, unauthorized};

#[derive(Debug, Deserialize)]
pub struct ListCustomersQuery {
    pub status: Option<String>,
}

#[derive(Debug, Serialize)]
struct CustomerResponse {
    pub id: String,
    pub name: String,
    pub industry: Option<String>,
    pub company_size: Option<String>,
    pub website: Option<String>,
    pub address: Option<String>,
    pub notes: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<crm::Customer> for CustomerResponse {
    fn from(c: crm::Customer) -> Self {
        Self {
            id: c.id,
            name: c.name,
            industry: c.industry,
            company_size: c.company_size,
            website: c.website,
            address: c.address,
            notes: c.notes,
            status: c.status,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

/// Extract claims from request or return Unauthorized error
fn get_claims(req: &HttpRequest) -> Result<Claims, ApiErrorKind> {
    req.extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| unauthorized("Unauthorized"))
}

/// List all customers for the authenticated user
pub async fn list_customers(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    query: web::Query<ListCustomersQuery>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;

    let customers = crm::get_user_customers(pool.get_ref(), &claims.sub, query.status.as_deref())
        .await
        .map_err(|e| {
            log::error!("Failed to list customers: {}", e);
            internal_error("Failed to list customers")
        })?;

    let response: Vec<CustomerResponse> = customers.into_iter().map(|c| c.into()).collect();
    Ok(HttpResponse::Ok().json(response))
}

/// Create a new customer
pub async fn create_customer(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateCustomerRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;

    if body.name.trim().is_empty() {
        return Err(bad_request("Customer name is required"));
    }

    let customer = crm::create_customer(pool.get_ref(), &claims.sub, body.into_inner())
        .await
        .map_err(|e| {
            log::error!("Failed to create customer: {}", e);
            internal_error("Failed to create customer")
        })?;

    let response: CustomerResponse = customer.into();
    Ok(HttpResponse::Created().json(response))
}

/// Get a specific customer by ID
pub async fn get_customer(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let customer_id = path.into_inner();

    let customer = crm::get_customer_by_id(pool.get_ref(), &customer_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Customer not found")
            } else {
                log::error!("Failed to get customer: {}", e);
                internal_error("Failed to get customer")
            }
        })?;

    if customer.user_id != claims.sub {
        return Err(forbidden("Access denied"));
    }

    let response: CustomerResponse = customer.into();
    Ok(HttpResponse::Ok().json(response))
}

/// Update a customer
pub async fn update_customer(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateCustomerRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let customer_id = path.into_inner();

    let customer = crm::update_customer(pool.get_ref(), &customer_id, &claims.sub, body.into_inner())
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("Not authorized") {
                forbidden("Access denied")
            } else if msg.contains("no rows") {
                not_found("Customer not found")
            } else {
                log::error!("Failed to update customer: {}", e);
                internal_error("Failed to update customer")
            }
        })?;

    let response: CustomerResponse = customer.into();
    Ok(HttpResponse::Ok().json(response))
}

/// Delete a customer
pub async fn delete_customer(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let customer_id = path.into_inner();

    crm::delete_customer(pool.get_ref(), &customer_id, &claims.sub)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("Not authorized") {
                forbidden("Access denied")
            } else if msg.contains("no rows") {
                not_found("Customer not found")
            } else {
                log::error!("Failed to delete customer: {}", e);
                internal_error("Failed to delete customer")
            }
        })?;

    Ok(HttpResponse::NoContent().finish())
}

/// Get customer summary with statistics
pub async fn get_customer_summary(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let customer_id = path.into_inner();

    // First verify ownership
    let customer = crm::get_customer_by_id(pool.get_ref(), &customer_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Customer not found")
            } else {
                log::error!("Failed to verify customer ownership: {}", e);
                internal_error("Failed to get customer")
            }
        })?;

    if customer.user_id != claims.sub {
        return Err(forbidden("Access denied"));
    }

    let summary = crm::get_customer_summary(pool.get_ref(), &customer_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get customer summary: {}", e);
            internal_error("Failed to get customer summary")
        })?;

    Ok(HttpResponse::Ok().json(summary))
}
