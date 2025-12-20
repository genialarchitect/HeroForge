//! CRM Dashboard API endpoint

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use sqlx::SqlitePool;

use crate::db::crm;
use crate::web::auth::Claims;
use crate::web::error::{internal_error, unauthorized, ApiErrorKind};

/// Get CRM dashboard statistics
pub async fn get_dashboard(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = req
        .extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| unauthorized("Unauthorized"))?;
    let user_id = claims.sub.clone();

    match crm::get_crm_dashboard_stats(pool.get_ref(), &user_id).await {
        Ok(stats) => Ok(HttpResponse::Ok().json(stats)),
        Err(e) => {
            log::error!("Failed to get CRM dashboard stats: {}", e);
            Err(internal_error("Failed to get dashboard statistics"))
        }
    }
}
