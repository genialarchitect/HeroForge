use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;

use crate::db::{self, models};
use crate::web::auth;

pub async fn register(
    pool: web::Data<SqlitePool>,
    user_data: web::Json<models::CreateUser>,
) -> Result<HttpResponse> {
    // Check if user already exists
    if let Ok(Some(_)) = db::get_user_by_username(&pool, &user_data.username).await {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Username already exists"
        })));
    }

    // Create user
    match db::create_user(&pool, &user_data).await {
        Ok(user) => {
            // Check if this is the admin user (based on ADMIN_USERNAME environment variable)
            let admin_username = std::env::var("ADMIN_USERNAME").ok();
            let role_id = if let Some(admin_user) = admin_username {
                if user_data.username == admin_user {
                    "admin"
                } else {
                    "user"
                }
            } else {
                "user"
            };

            // Assign default role
            if let Err(e) = db::assign_role_to_user(&pool, &user.id, role_id, &user.id).await {
                eprintln!("Failed to assign role to user: {}", e);
            }

            // Fetch user roles for JWT
            let roles = db::get_user_roles(&pool, &user.id).await.unwrap_or_default();
            let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

            let token = auth::create_jwt(&user.id, &user.username, role_names)
                .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create token"))?;

            Ok(HttpResponse::Ok().json(models::LoginResponse {
                token,
                user: user.into(),
            }))
        }
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create user: {}", e)
        }))),
    }
}

pub async fn login(
    pool: web::Data<SqlitePool>,
    credentials: web::Json<models::LoginRequest>,
) -> Result<HttpResponse> {
    // Get user by username
    let user = match db::get_user_by_username(&pool, &credentials.username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid credentials"
            })));
        }
        Err(_) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error"
            })));
        }
    };

    // Verify password
    let password_valid = bcrypt::verify(&credentials.password, &user.password_hash)
        .unwrap_or(false);

    if !password_valid {
        return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid credentials"
        })));
    }

    // Fetch user roles for JWT
    let roles = db::get_user_roles(&pool, &user.id).await.unwrap_or_default();
    let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

    // Create JWT token
    let token = auth::create_jwt(&user.id, &user.username, role_names)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create token"))?;

    Ok(HttpResponse::Ok().json(models::LoginResponse {
        token,
        user: user.into(),
    }))
}

pub async fn me(claims: web::ReqData<auth::Claims>) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": claims.sub,
        "username": claims.username,
        "roles": claims.roles
    })))
}
