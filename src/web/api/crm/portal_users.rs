//! Portal User Management API
//!
//! Endpoints for CRM admins to manage customer portal users.

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::crm::{
    get_customer_portal_users_with_contacts, create_portal_user, get_portal_user_by_id,
    update_portal_user, delete_portal_user, activate_portal_user, deactivate_portal_user,
    admin_reset_portal_user_password, get_portal_user_by_email,
    CreatePortalUserRequest, UpdatePortalUserRequest, PortalUserWithContact,
};

/// Request to create a new portal user
#[derive(Debug, Deserialize)]
pub struct CreatePortalUserApiRequest {
    pub email: String,
    pub password: String,
    pub contact_id: Option<String>,
    #[serde(default = "default_portal_role")]
    pub role: String,
}

fn default_portal_role() -> String {
    "member".to_string()
}

/// Request to update a portal user
#[derive(Debug, Deserialize)]
pub struct UpdatePortalUserApiRequest {
    pub contact_id: Option<String>,
    pub is_active: Option<bool>,
    pub role: Option<String>,
}

/// Request to reset a portal user's password
#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub new_password: String,
}

/// Response for portal user operations
#[derive(Debug, Serialize)]
pub struct PortalUserResponse {
    pub id: String,
    pub customer_id: String,
    pub contact_id: Option<String>,
    pub email: String,
    pub is_active: bool,
    pub last_login: Option<String>,
    pub role: String,
    pub created_at: String,
    pub updated_at: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub title: Option<String>,
}

impl From<PortalUserWithContact> for PortalUserResponse {
    fn from(user: PortalUserWithContact) -> Self {
        PortalUserResponse {
            id: user.id,
            customer_id: user.customer_id,
            contact_id: user.contact_id,
            email: user.email,
            is_active: user.is_active,
            last_login: user.last_login,
            role: user.role,
            created_at: user.created_at,
            updated_at: user.updated_at,
            first_name: user.first_name,
            last_name: user.last_name,
            phone: user.phone,
            title: user.title,
        }
    }
}

/// List all portal users for a customer
pub async fn list_portal_users(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let customer_id = path.into_inner();

    match get_customer_portal_users_with_contacts(&pool, &customer_id).await {
        Ok(users) => {
            let response: Vec<PortalUserResponse> = users.into_iter().map(Into::into).collect();
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Failed to list portal users: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list portal users"
            })))
        }
    }
}

/// Create a new portal user for a customer
pub async fn create_portal_user_handler(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<CreatePortalUserApiRequest>,
) -> Result<HttpResponse> {
    let customer_id = path.into_inner();

    // Validate email format
    if !body.email.contains('@') {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid email format"
        })));
    }

    // Validate password length
    if body.password.len() < 8 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password must be at least 8 characters"
        })));
    }

    // Check if email already exists
    match get_portal_user_by_email(&pool, &body.email).await {
        Ok(Some(_)) => {
            return Ok(HttpResponse::Conflict().json(serde_json::json!({
                "error": "A portal user with this email already exists"
            })));
        }
        Err(e) => {
            log::error!("Failed to check existing email: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create portal user"
            })));
        }
        _ => {}
    }

    let req = CreatePortalUserRequest {
        contact_id: body.contact_id.clone(),
        email: body.email.clone(),
        password: body.password.clone(),
        role: body.role.clone(),
    };

    match create_portal_user(&pool, &customer_id, req).await {
        Ok(user) => {
            // Get full user with contact info
            match get_customer_portal_users_with_contacts(&pool, &customer_id).await {
                Ok(users) => {
                    if let Some(full_user) = users.into_iter().find(|u| u.id == user.id) {
                        Ok(HttpResponse::Created().json(PortalUserResponse::from(full_user)))
                    } else {
                        Ok(HttpResponse::Created().json(serde_json::json!({
                            "id": user.id,
                            "email": user.email,
                            "customer_id": user.customer_id,
                            "is_active": user.is_active,
                            "created_at": user.created_at
                        })))
                    }
                }
                Err(_) => Ok(HttpResponse::Created().json(serde_json::json!({
                    "id": user.id,
                    "email": user.email,
                    "customer_id": user.customer_id,
                    "is_active": user.is_active,
                    "created_at": user.created_at
                })))
            }
        }
        Err(e) => {
            log::error!("Failed to create portal user: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create portal user"
            })))
        }
    }
}

/// Get a specific portal user
pub async fn get_portal_user(
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse> {
    let (customer_id, user_id) = path.into_inner();

    // Get user and verify it belongs to the customer
    match get_portal_user_by_id(&pool, &user_id).await {
        Ok(user) => {
            if user.customer_id != customer_id {
                return Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Portal user not found"
                })));
            }

            // Get full info with contact
            match get_customer_portal_users_with_contacts(&pool, &customer_id).await {
                Ok(users) => {
                    if let Some(full_user) = users.into_iter().find(|u| u.id == user_id) {
                        Ok(HttpResponse::Ok().json(PortalUserResponse::from(full_user)))
                    } else {
                        Ok(HttpResponse::Ok().json(serde_json::json!({
                            "id": user.id,
                            "email": user.email,
                            "customer_id": user.customer_id,
                            "is_active": user.is_active,
                            "created_at": user.created_at
                        })))
                    }
                }
                Err(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
                    "id": user.id,
                    "email": user.email,
                    "customer_id": user.customer_id,
                    "is_active": user.is_active,
                    "created_at": user.created_at
                })))
            }
        }
        Err(_) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Portal user not found"
        })))
    }
}

/// Update a portal user
pub async fn update_portal_user_handler(
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
    body: web::Json<UpdatePortalUserApiRequest>,
) -> Result<HttpResponse> {
    let (customer_id, user_id) = path.into_inner();

    // Verify user belongs to customer
    match get_portal_user_by_id(&pool, &user_id).await {
        Ok(user) => {
            if user.customer_id != customer_id {
                return Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Portal user not found"
                })));
            }
        }
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Portal user not found"
            })));
        }
    }

    let req = UpdatePortalUserRequest {
        contact_id: body.contact_id.clone(),
        is_active: body.is_active,
        role: body.role.clone(),
    };

    match update_portal_user(&pool, &user_id, req).await {
        Ok(_) => {
            // Get full info
            match get_customer_portal_users_with_contacts(&pool, &customer_id).await {
                Ok(users) => {
                    if let Some(full_user) = users.into_iter().find(|u| u.id == user_id) {
                        Ok(HttpResponse::Ok().json(PortalUserResponse::from(full_user)))
                    } else {
                        Ok(HttpResponse::Ok().json(serde_json::json!({
                            "message": "Portal user updated"
                        })))
                    }
                }
                Err(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
                    "message": "Portal user updated"
                })))
            }
        }
        Err(e) => {
            log::error!("Failed to update portal user: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update portal user"
            })))
        }
    }
}

/// Delete a portal user
pub async fn delete_portal_user_handler(
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse> {
    let (customer_id, user_id) = path.into_inner();

    // Verify user belongs to customer
    match get_portal_user_by_id(&pool, &user_id).await {
        Ok(user) => {
            if user.customer_id != customer_id {
                return Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Portal user not found"
                })));
            }
        }
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Portal user not found"
            })));
        }
    }

    match delete_portal_user(&pool, &user_id).await {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Portal user deleted"
        }))),
        Err(e) => {
            log::error!("Failed to delete portal user: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete portal user"
            })))
        }
    }
}

/// Activate a portal user
pub async fn activate_portal_user_handler(
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse> {
    let (customer_id, user_id) = path.into_inner();

    // Verify user belongs to customer
    match get_portal_user_by_id(&pool, &user_id).await {
        Ok(user) => {
            if user.customer_id != customer_id {
                return Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Portal user not found"
                })));
            }
        }
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Portal user not found"
            })));
        }
    }

    match activate_portal_user(&pool, &user_id).await {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Portal user activated"
        }))),
        Err(e) => {
            log::error!("Failed to activate portal user: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to activate portal user"
            })))
        }
    }
}

/// Deactivate a portal user
pub async fn deactivate_portal_user_handler(
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse> {
    let (customer_id, user_id) = path.into_inner();

    // Verify user belongs to customer
    match get_portal_user_by_id(&pool, &user_id).await {
        Ok(user) => {
            if user.customer_id != customer_id {
                return Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Portal user not found"
                })));
            }
        }
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Portal user not found"
            })));
        }
    }

    match deactivate_portal_user(&pool, &user_id).await {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Portal user deactivated"
        }))),
        Err(e) => {
            log::error!("Failed to deactivate portal user: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to deactivate portal user"
            })))
        }
    }
}

/// Reset a portal user's password (admin action)
pub async fn reset_portal_user_password(
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
    body: web::Json<ResetPasswordRequest>,
) -> Result<HttpResponse> {
    let (customer_id, user_id) = path.into_inner();

    // Validate password length
    if body.new_password.len() < 8 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password must be at least 8 characters"
        })));
    }

    // Verify user belongs to customer
    match get_portal_user_by_id(&pool, &user_id).await {
        Ok(user) => {
            if user.customer_id != customer_id {
                return Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Portal user not found"
                })));
            }
        }
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Portal user not found"
            })));
        }
    }

    match admin_reset_portal_user_password(&pool, &user_id, &body.new_password).await {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Password reset successfully"
        }))),
        Err(e) => {
            log::error!("Failed to reset portal user password: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to reset password"
            })))
        }
    }
}
