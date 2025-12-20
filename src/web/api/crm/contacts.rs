//! Contact API endpoints

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use sqlx::SqlitePool;

use crate::db::crm::{
    self, CreateContactRequest, UpdateContactRequest,
};
use crate::web::auth::Claims;
use crate::web::error::{ApiErrorKind, bad_request, forbidden, not_found, internal_error, unauthorized};

/// Extract claims from request or return Unauthorized error
fn get_claims(req: &HttpRequest) -> Result<Claims, ApiErrorKind> {
    req.extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| unauthorized("Unauthorized"))
}

/// Verify customer ownership and return the customer
async fn verify_customer_ownership(
    pool: &SqlitePool,
    customer_id: &str,
    user_id: &str,
) -> Result<(), ApiErrorKind> {
    let customer = crm::get_customer_by_id(pool, customer_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Customer not found")
            } else {
                log::error!("Failed to verify customer: {}", e);
                internal_error("Failed to verify customer")
            }
        })?;

    if customer.user_id != user_id {
        return Err(forbidden("Access denied"));
    }

    Ok(())
}

/// List contacts for a customer
pub async fn list_contacts(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let customer_id = path.into_inner();

    verify_customer_ownership(pool.get_ref(), &customer_id, &claims.sub).await?;

    let contacts = crm::get_customer_contacts(pool.get_ref(), &customer_id)
        .await
        .map_err(|e| {
            log::error!("Failed to list contacts: {}", e);
            internal_error("Failed to list contacts")
        })?;

    Ok(HttpResponse::Ok().json(contacts))
}

/// Create a contact for a customer
pub async fn create_contact(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<CreateContactRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let customer_id = path.into_inner();

    verify_customer_ownership(pool.get_ref(), &customer_id, &claims.sub).await?;

    if body.first_name.trim().is_empty() || body.last_name.trim().is_empty() {
        return Err(bad_request("First and last name are required"));
    }

    let contact = crm::create_contact(pool.get_ref(), &customer_id, body.into_inner())
        .await
        .map_err(|e| {
            log::error!("Failed to create contact: {}", e);
            internal_error("Failed to create contact")
        })?;

    Ok(HttpResponse::Created().json(contact))
}

/// Get a specific contact
pub async fn get_contact(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let contact_id = path.into_inner();

    let contact = crm::get_contact_by_id(pool.get_ref(), &contact_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Contact not found")
            } else {
                log::error!("Failed to get contact: {}", e);
                internal_error("Failed to get contact")
            }
        })?;

    // Verify ownership via customer
    crm::get_customer_by_id(pool.get_ref(), &contact.customer_id)
        .await
        .map_err(|_| forbidden("Access denied"))
        .and_then(|customer| {
            if customer.user_id != claims.sub {
                Err(forbidden("Access denied"))
            } else {
                Ok(())
            }
        })?;

    Ok(HttpResponse::Ok().json(contact))
}

/// Update a contact
pub async fn update_contact(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateContactRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let contact_id = path.into_inner();

    // Get existing contact to verify ownership
    let contact = crm::get_contact_by_id(pool.get_ref(), &contact_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Contact not found")
            } else {
                log::error!("Failed to get contact: {}", e);
                internal_error("Failed to get contact")
            }
        })?;

    // Verify ownership via customer
    crm::get_customer_by_id(pool.get_ref(), &contact.customer_id)
        .await
        .map_err(|_| forbidden("Access denied"))
        .and_then(|customer| {
            if customer.user_id != claims.sub {
                Err(forbidden("Access denied"))
            } else {
                Ok(())
            }
        })?;

    let updated_contact = crm::update_contact(pool.get_ref(), &contact_id, body.into_inner())
        .await
        .map_err(|e| {
            log::error!("Failed to update contact: {}", e);
            internal_error("Failed to update contact")
        })?;

    Ok(HttpResponse::Ok().json(updated_contact))
}

/// Delete a contact
pub async fn delete_contact(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let contact_id = path.into_inner();

    // Get existing contact to verify ownership
    let contact = crm::get_contact_by_id(pool.get_ref(), &contact_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Contact not found")
            } else {
                log::error!("Failed to get contact: {}", e);
                internal_error("Failed to get contact")
            }
        })?;

    // Verify ownership via customer
    crm::get_customer_by_id(pool.get_ref(), &contact.customer_id)
        .await
        .map_err(|_| forbidden("Access denied"))
        .and_then(|customer| {
            if customer.user_id != claims.sub {
                Err(forbidden("Access denied"))
            } else {
                Ok(())
            }
        })?;

    crm::delete_contact(pool.get_ref(), &contact_id)
        .await
        .map_err(|e| {
            log::error!("Failed to delete contact: {}", e);
            internal_error("Failed to delete contact")
        })?;

    Ok(HttpResponse::NoContent().finish())
}
