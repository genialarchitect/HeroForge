use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};
use std::rc::Rc;
use sqlx::SqlitePool;

use super::jwt;
use crate::db;

pub struct JwtMiddleware;

impl<S, B> Transform<S, ServiceRequest> for JwtMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = JwtMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtMiddlewareService {
            service: Rc::new(service)
        }))
    }
}

pub struct JwtMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for JwtMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Clone service at the beginning to avoid lifetime issues
        let service = self.service.clone();

        // Skip auth for WebSocket routes - they handle their own auth via query parameters
        let path = req.path();
        if path.contains("/ws/") {
            let fut = service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res)
            });
        }

        // Check for Authorization header (JWT)
        let auth_header = req.headers().get("Authorization");
        if let Some(auth_value) = auth_header {
            if let Ok(auth_str) = auth_value.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..];
                    if let Ok(claims) = jwt::verify_jwt(token) {
                        req.extensions_mut().insert(claims);
                        let fut = service.call(req);
                        return Box::pin(async move {
                            let res = fut.await?;
                            Ok(res)
                        });
                    }
                }
            }
        }

        // Check for X-API-Key header
        let api_key_header = req.headers().get("X-API-Key");
        if let Some(api_key_value) = api_key_header {
            if let Ok(api_key_str) = api_key_value.to_str() {
                // Get database pool from app_data
                if let Some(pool) = req.app_data::<actix_web::web::Data<SqlitePool>>() {
                    let pool_clone = pool.clone();
                    let api_key = api_key_str.to_string();

                    // Verify API key and get user_id
                    return Box::pin(async move {
                        match db::verify_api_key(&pool_clone, &api_key).await {
                            Ok(Some(user_id)) => {
                                // Get user to create claims
                                match db::get_user_by_id(&pool_clone, &user_id).await {
                                    Ok(Some(user)) => {
                                        // Get user roles
                                        let roles = db::get_user_roles(&pool_clone, &user.id).await.unwrap_or_default();
                                        let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

                                        // Create claims from user
                                        let claims = jwt::Claims {
                                            sub: user.id.clone(),
                                            username: user.username.clone(),
                                            roles: role_names,
                                            exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
                                            iat: chrono::Utc::now().timestamp() as usize,
                                            org_id: None,
                                            org_role: None,
                                            teams: Vec::new(),
                                            permissions: Vec::new(),
                                        };
                                        req.extensions_mut().insert(claims);
                                        let fut = service.call(req);
                                        let res = fut.await?;
                                        Ok(res)
                                    }
                                    _ => Err(actix_web::error::ErrorUnauthorized("Invalid API key")),
                                }
                            }
                            _ => Err(actix_web::error::ErrorUnauthorized("Invalid API key")),
                        }
                    });
                }
            }
        }

        Box::pin(async move {
            Err(actix_web::error::ErrorUnauthorized("Unauthorized"))
        })
    }
}
