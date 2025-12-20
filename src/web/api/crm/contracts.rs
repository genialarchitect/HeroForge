//! Contract API endpoints

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::db::crm::{
    self, CreateContractRequest, UpdateContractRequest,
};
use crate::web::auth::Claims;
use crate::web::error::{ApiErrorKind, bad_request, forbidden, not_found, internal_error, unauthorized};

#[derive(Debug, Deserialize)]
pub struct ListContractsQuery {
    pub status: Option<String>,
}

/// Extract claims from request or return Unauthorized error
fn get_claims(req: &HttpRequest) -> Result<Claims, ApiErrorKind> {
    req.extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| unauthorized("Unauthorized"))
}

/// Verify customer ownership
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

/// Verify ownership via customer for an entity with a customer_id
async fn verify_ownership_via_customer(
    pool: &SqlitePool,
    customer_id: &str,
    user_id: &str,
) -> Result<(), ApiErrorKind> {
    crm::get_customer_by_id(pool, customer_id)
        .await
        .map_err(|_| forbidden("Access denied"))
        .and_then(|customer| {
            if customer.user_id != user_id {
                Err(forbidden("Access denied"))
            } else {
                Ok(())
            }
        })
}

/// List all contracts for the authenticated user
pub async fn list_contracts(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    query: web::Query<ListContractsQuery>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;

    let contracts = crm::get_all_contracts(pool.get_ref(), &claims.sub, query.status.as_deref())
        .await
        .map_err(|e| {
            log::error!("Failed to list contracts: {}", e);
            internal_error("Failed to list contracts")
        })?;

    Ok(HttpResponse::Ok().json(contracts))
}

/// List contracts for a specific customer
pub async fn list_customer_contracts(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let customer_id = path.into_inner();

    verify_customer_ownership(pool.get_ref(), &customer_id, &claims.sub).await?;

    let contracts = crm::get_customer_contracts(pool.get_ref(), &customer_id)
        .await
        .map_err(|e| {
            log::error!("Failed to list contracts: {}", e);
            internal_error("Failed to list contracts")
        })?;

    Ok(HttpResponse::Ok().json(contracts))
}

/// Create a contract for a customer
pub async fn create_contract(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<CreateContractRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let customer_id = path.into_inner();

    verify_customer_ownership(pool.get_ref(), &customer_id, &claims.sub).await?;

    if body.name.trim().is_empty() {
        return Err(bad_request("Contract name is required"));
    }

    let contract = crm::create_contract(pool.get_ref(), &customer_id, body.into_inner())
        .await
        .map_err(|e| {
            log::error!("Failed to create contract: {}", e);
            internal_error("Failed to create contract")
        })?;

    Ok(HttpResponse::Created().json(contract))
}

/// Get a specific contract
pub async fn get_contract(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let contract_id = path.into_inner();

    let contract = crm::get_contract_by_id(pool.get_ref(), &contract_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Contract not found")
            } else {
                log::error!("Failed to get contract: {}", e);
                internal_error("Failed to get contract")
            }
        })?;

    verify_ownership_via_customer(pool.get_ref(), &contract.customer_id, &claims.sub).await?;

    Ok(HttpResponse::Ok().json(contract))
}

/// Update a contract
pub async fn update_contract(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateContractRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let contract_id = path.into_inner();

    // Get existing contract to verify ownership
    let contract = crm::get_contract_by_id(pool.get_ref(), &contract_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Contract not found")
            } else {
                log::error!("Failed to get contract: {}", e);
                internal_error("Failed to get contract")
            }
        })?;

    verify_ownership_via_customer(pool.get_ref(), &contract.customer_id, &claims.sub).await?;

    let updated_contract = crm::update_contract(pool.get_ref(), &contract_id, body.into_inner())
        .await
        .map_err(|e| {
            log::error!("Failed to update contract: {}", e);
            internal_error("Failed to update contract")
        })?;

    Ok(HttpResponse::Ok().json(updated_contract))
}

/// Delete a contract
pub async fn delete_contract(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let contract_id = path.into_inner();

    // Get existing contract to verify ownership
    let contract = crm::get_contract_by_id(pool.get_ref(), &contract_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Contract not found")
            } else {
                log::error!("Failed to get contract: {}", e);
                internal_error("Failed to get contract")
            }
        })?;

    verify_ownership_via_customer(pool.get_ref(), &contract.customer_id, &claims.sub).await?;

    crm::delete_contract(pool.get_ref(), &contract_id)
        .await
        .map_err(|e| {
            log::error!("Failed to delete contract: {}", e);
            internal_error("Failed to delete contract")
        })?;

    Ok(HttpResponse::NoContent().finish())
}
