//! Referral Program API
//!
//! Handles referral tracking, rewards, and dashboard for the referral program.
//! Referrer gets 1 month free per signup, referee gets 20% off first year.

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReferralCode {
    pub code: String,
    pub user_id: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ReferralStats {
    pub total_referrals: i32,
    pub successful_referrals: i32,
    pub pending_referrals: i32,
    pub credits_earned: i32,
    pub credits_used: i32,
    pub credits_available: i32,
    pub leaderboard_rank: Option<i32>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReferralRecord {
    pub id: String,
    pub referrer_id: String,
    pub referee_email: String,
    pub status: String, // pending, registered, converted, expired
    pub credits_awarded: i32,
    pub created_at: String,
    pub converted_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LeaderboardEntry {
    pub rank: i32,
    pub username: String,
    pub successful_referrals: i32,
    pub is_current_user: bool,
}

#[derive(Debug, Deserialize)]
pub struct TrackReferralRequest {
    pub code: String,
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ApplyReferralRequest {
    pub code: String,
}

// ============================================================================
// Helpers
// ============================================================================

fn generate_referral_code(user_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    hasher.update(chrono::Utc::now().timestamp().to_string().as_bytes());
    let hash = hasher.finalize();
    // Take first 8 characters and make uppercase
    hex::encode(&hash[..4]).to_uppercase()
}

fn get_user_id_from_request(req: &HttpRequest) -> Option<String> {
    req.extensions().get::<String>().cloned()
}

// ============================================================================
// Public API Handlers (no auth required)
// ============================================================================

/// GET /api/referrals/validate/{code}
/// Validate a referral code and return referrer info
pub async fn validate_code(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let code = path.into_inner().to_uppercase();

    let referral = sqlx::query_as::<_, (String, String)>(
        r#"SELECT rc.user_id, u.username
           FROM referral_codes rc
           JOIN users u ON rc.user_id = u.id
           WHERE rc.code = ? AND rc.active = TRUE"#
    )
    .bind(&code)
    .fetch_optional(pool.get_ref())
    .await;

    match referral {
        Ok(Some((_, username))) => {
            HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
                "valid": true,
                "referrer": username,
                "discount": "20% off first year"
            })))
        }
        Ok(None) => {
            HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
                "valid": false
            })))
        }
        Err(e) => {
            log::error!("Failed to validate referral code: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to validate code"))
        }
    }
}

/// POST /api/referrals/track
/// Track a referral click (before registration)
pub async fn track_referral(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    body: web::Json<TrackReferralRequest>,
) -> HttpResponse {
    let code = body.code.to_uppercase();

    // Get referrer
    let referrer = sqlx::query_scalar::<_, String>(
        "SELECT user_id FROM referral_codes WHERE code = ? AND active = TRUE"
    )
    .bind(&code)
    .fetch_optional(pool.get_ref())
    .await;

    let referrer_id = match referrer {
        Ok(Some(id)) => id,
        Ok(None) => {
            return HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error("Invalid referral code"));
        }
        Err(e) => {
            log::error!("Failed to lookup referral code: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to process referral"));
        }
    };

    // Create pending referral record
    let referral_id = uuid::Uuid::new_v4().to_string();
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    if let Err(e) = sqlx::query(
        r#"INSERT INTO referrals (id, referrer_id, referee_email, referee_ip, status, created_at)
           VALUES (?, ?, ?, ?, 'pending', datetime('now'))"#
    )
    .bind(&referral_id)
    .bind(&referrer_id)
    .bind(&body.email)
    .bind(&ip)
    .execute(pool.get_ref())
    .await {
        log::error!("Failed to create referral record: {}", e);
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error("Failed to track referral"));
    }

    HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "tracked": true,
        "referral_id": referral_id
    })))
}

/// GET /api/referrals/leaderboard
/// Get top referrers leaderboard
pub async fn get_leaderboard(
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let leaders = sqlx::query_as::<_, (String, i32)>(
        r#"SELECT u.username, COUNT(r.id) as count
           FROM referrals r
           JOIN users u ON r.referrer_id = u.id
           WHERE r.status = 'converted'
           GROUP BY r.referrer_id
           ORDER BY count DESC
           LIMIT 10"#
    )
    .fetch_all(pool.get_ref())
    .await;

    match leaders {
        Ok(rows) => {
            let leaderboard: Vec<LeaderboardEntry> = rows
                .into_iter()
                .enumerate()
                .map(|(i, (username, count))| LeaderboardEntry {
                    rank: (i + 1) as i32,
                    username,
                    successful_referrals: count,
                    is_current_user: false,
                })
                .collect();

            HttpResponse::Ok().json(ApiResponse::success(leaderboard))
        }
        Err(e) => {
            log::error!("Failed to fetch leaderboard: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to fetch leaderboard"))
        }
    }
}

// ============================================================================
// Authenticated API Handlers
// ============================================================================

/// GET /api/referrals/code
/// Get or create user's referral code
pub async fn get_referral_code(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
) -> HttpResponse {
    let user_id = match get_user_id_from_request(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error("Authentication required"));
        }
    };

    // Check if user already has a code
    let existing = sqlx::query_as::<_, ReferralCode>(
        "SELECT code, user_id, created_at FROM referral_codes WHERE user_id = ? AND active = TRUE"
    )
    .bind(&user_id)
    .fetch_optional(pool.get_ref())
    .await;

    match existing {
        Ok(Some(code)) => {
            HttpResponse::Ok().json(ApiResponse::success(code))
        }
        Ok(None) => {
            // Create new code
            let code = generate_referral_code(&user_id);
            if let Err(e) = sqlx::query(
                r#"INSERT INTO referral_codes (code, user_id, active, created_at)
                   VALUES (?, ?, TRUE, datetime('now'))"#
            )
            .bind(&code)
            .bind(&user_id)
            .execute(pool.get_ref())
            .await {
                log::error!("Failed to create referral code: {}", e);
                return HttpResponse::InternalServerError()
                    .json(ApiResponse::<()>::error("Failed to create referral code"));
            }

            HttpResponse::Created().json(ApiResponse::success(ReferralCode {
                code,
                user_id,
                created_at: chrono::Utc::now().to_rfc3339(),
            }))
        }
        Err(e) => {
            log::error!("Failed to fetch referral code: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to fetch referral code"))
        }
    }
}

/// GET /api/referrals/stats
/// Get user's referral statistics
pub async fn get_stats(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
) -> HttpResponse {
    let user_id = match get_user_id_from_request(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error("Authentication required"));
        }
    };

    // Get referral counts
    let counts = sqlx::query_as::<_, (i32, i32, i32)>(
        r#"SELECT
             COUNT(*) as total,
             SUM(CASE WHEN status = 'converted' THEN 1 ELSE 0 END) as successful,
             SUM(CASE WHEN status = 'pending' OR status = 'registered' THEN 1 ELSE 0 END) as pending
           FROM referrals
           WHERE referrer_id = ?"#
    )
    .bind(&user_id)
    .fetch_one(pool.get_ref())
    .await;

    // Get credits
    let credits = sqlx::query_as::<_, (i32, i32)>(
        r#"SELECT
             COALESCE(SUM(CASE WHEN type = 'earned' THEN amount ELSE 0 END), 0) as earned,
             COALESCE(SUM(CASE WHEN type = 'used' THEN amount ELSE 0 END), 0) as used
           FROM referral_credits
           WHERE user_id = ?"#
    )
    .bind(&user_id)
    .fetch_one(pool.get_ref())
    .await;

    // Get leaderboard rank
    let rank = sqlx::query_scalar::<_, i32>(
        r#"SELECT rank FROM (
             SELECT referrer_id, ROW_NUMBER() OVER (ORDER BY COUNT(*) DESC) as rank
             FROM referrals
             WHERE status = 'converted'
             GROUP BY referrer_id
           ) WHERE referrer_id = ?"#
    )
    .bind(&user_id)
    .fetch_optional(pool.get_ref())
    .await;

    match (counts, credits, rank) {
        (Ok((total, successful, pending)), Ok((earned, used)), Ok(rank)) => {
            HttpResponse::Ok().json(ApiResponse::success(ReferralStats {
                total_referrals: total,
                successful_referrals: successful,
                pending_referrals: pending,
                credits_earned: earned,
                credits_used: used,
                credits_available: earned - used,
                leaderboard_rank: rank,
            }))
        }
        _ => {
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to fetch referral stats"))
        }
    }
}

/// GET /api/referrals/history
/// Get user's referral history
pub async fn get_history(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
) -> HttpResponse {
    let user_id = match get_user_id_from_request(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error("Authentication required"));
        }
    };

    let referrals = sqlx::query_as::<_, ReferralRecord>(
        r#"SELECT id, referrer_id, referee_email, status, credits_awarded, created_at, converted_at
           FROM referrals
           WHERE referrer_id = ?
           ORDER BY created_at DESC
           LIMIT 50"#
    )
    .bind(&user_id)
    .fetch_all(pool.get_ref())
    .await;

    match referrals {
        Ok(records) => {
            HttpResponse::Ok().json(ApiResponse::success(records))
        }
        Err(e) => {
            log::error!("Failed to fetch referral history: {}", e);
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to fetch referral history"))
        }
    }
}

/// POST /api/referrals/apply
/// Apply a referral code during registration
pub async fn apply_referral(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    body: web::Json<ApplyReferralRequest>,
) -> HttpResponse {
    let user_id = match get_user_id_from_request(&req) {
        Some(id) => id,
        None => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error("Authentication required"));
        }
    };

    let code = body.code.to_uppercase();

    // Get referrer
    let referrer = sqlx::query_scalar::<_, String>(
        "SELECT user_id FROM referral_codes WHERE code = ? AND active = TRUE"
    )
    .bind(&code)
    .fetch_optional(pool.get_ref())
    .await;

    let referrer_id = match referrer {
        Ok(Some(id)) => {
            // Can't refer yourself
            if id == user_id {
                return HttpResponse::BadRequest()
                    .json(ApiResponse::<()>::error("Cannot use your own referral code"));
            }
            id
        }
        Ok(None) => {
            return HttpResponse::BadRequest()
                .json(ApiResponse::<()>::error("Invalid referral code"));
        }
        Err(e) => {
            log::error!("Failed to lookup referral code: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to process referral"));
        }
    };

    // Check if user was already referred
    let already_referred = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM referrals WHERE referee_id = ?"
    )
    .bind(&user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0) > 0;

    if already_referred {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("You have already used a referral code"));
    }

    // Create referral record
    let referral_id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = sqlx::query(
        r#"INSERT INTO referrals (id, referrer_id, referee_id, status, created_at, converted_at)
           VALUES (?, ?, ?, 'converted', datetime('now'), datetime('now'))"#
    )
    .bind(&referral_id)
    .bind(&referrer_id)
    .bind(&user_id)
    .execute(pool.get_ref())
    .await {
        log::error!("Failed to create referral record: {}", e);
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error("Failed to apply referral"));
    }

    // Award credit to referrer (1 month = 30 credits)
    let credit_id = uuid::Uuid::new_v4().to_string();
    let _ = sqlx::query(
        r#"INSERT INTO referral_credits (id, user_id, amount, type, referral_id, created_at)
           VALUES (?, ?, 30, 'earned', ?, datetime('now'))"#
    )
    .bind(&credit_id)
    .bind(&referrer_id)
    .bind(&referral_id)
    .execute(pool.get_ref())
    .await;

    // Update referral with credits
    let _ = sqlx::query(
        "UPDATE referrals SET credits_awarded = 30 WHERE id = ?"
    )
    .bind(&referral_id)
    .execute(pool.get_ref())
    .await;

    HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "applied": true,
        "discount": "20% off first year",
        "message": "Referral code applied! You'll receive 20% off your first year."
    })))
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Public routes (no auth)
pub fn configure_public(cfg: &mut web::ServiceConfig) {
    cfg.route("/validate/{code}", web::get().to(validate_code))
        .route("/track", web::post().to(track_referral))
        .route("/leaderboard", web::get().to(get_leaderboard));
}

/// Authenticated routes
pub fn configure_auth(cfg: &mut web::ServiceConfig) {
    cfg.route("/code", web::get().to(get_referral_code))
        .route("/stats", web::get().to(get_stats))
        .route("/history", web::get().to(get_history))
        .route("/apply", web::post().to(apply_referral));
}
