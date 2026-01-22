//! Roadmap API
//!
//! Public API for viewing and voting on product roadmap items.
//! Voting is rate-limited and deduplicated by IP hash or user ID.

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RoadmapItem {
    pub id: String,
    pub title: String,
    pub description: String,
    pub status: String,         // completed, in_progress, planned, considering
    pub category: String,       // scanning, reporting, integrations, compliance, ai, platform, security
    pub quarter: String,        // Q1 2026, Q2 2026, TBD, etc.
    pub votes: i32,
    pub completed_date: Option<String>,
    pub tags: String,           // JSON array
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct RoadmapItemResponse {
    pub id: String,
    pub title: String,
    pub description: String,
    pub status: String,
    pub category: String,
    pub quarter: String,
    pub votes: i32,
    pub has_voted: bool,
    pub completed_date: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RoadmapSuggestion {
    pub id: String,
    pub title: String,
    pub description: String,
    pub email: Option<String>,
    pub status: String,         // pending, approved, rejected, implemented
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct SuggestionRequest {
    pub title: String,
    pub description: String,
    pub email: Option<String>,
}

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

#[derive(Debug, Serialize)]
pub struct RoadmapStats {
    pub total_items: i32,
    pub completed: i32,
    pub in_progress: i32,
    pub planned: i32,
    pub considering: i32,
    pub total_votes: i32,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get a unique identifier for vote deduplication
fn get_voter_identifier(req: &HttpRequest, user_id: Option<&str>) -> String {
    // If user is authenticated, use their user ID
    if let Some(uid) = user_id {
        return format!("user:{}", uid);
    }

    // Otherwise, hash the IP address for anonymous users
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    let mut hasher = Sha256::new();
    hasher.update(ip.as_bytes());
    hasher.update(b"heroforge-roadmap-salt");
    let hash = hasher.finalize();
    format!("ip:{}", hex::encode(&hash[..16]))
}

/// Check if a user has already voted for an item
async fn has_voted(pool: &SqlitePool, item_id: &str, identifier: &str) -> bool {
    sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM roadmap_votes WHERE item_id = ? AND identifier = ?"
    )
    .bind(item_id)
    .bind(identifier)
    .fetch_one(pool)
    .await
    .unwrap_or(0) > 0
}

// ============================================================================
// API Handlers
// ============================================================================

/// GET /api/roadmap/items
/// Returns all roadmap items with vote counts
pub async fn get_items(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
) -> HttpResponse {
    // Try to get user ID from auth if available
    let user_id = req.extensions().get::<String>().cloned();
    let voter_identifier = get_voter_identifier(&req, user_id.as_deref());

    // Fetch all items
    let items = match sqlx::query_as::<_, RoadmapItem>(
        r#"SELECT id, title, description, status, category, quarter, votes,
                  completed_date, tags, created_at, updated_at
           FROM roadmap_items
           ORDER BY
             CASE status
               WHEN 'in_progress' THEN 1
               WHEN 'planned' THEN 2
               WHEN 'considering' THEN 3
               WHEN 'completed' THEN 4
               ELSE 5
             END,
             votes DESC"#
    )
    .fetch_all(pool.get_ref())
    .await {
        Ok(items) => items,
        Err(e) => {
            log::error!("Failed to fetch roadmap items: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to fetch roadmap items"));
        }
    };

    // Check which items the user has voted for
    let mut response_items = Vec::new();
    for item in items {
        let has_voted = has_voted(pool.get_ref(), &item.id, &voter_identifier).await;
        let tags: Vec<String> = serde_json::from_str(&item.tags).unwrap_or_default();

        response_items.push(RoadmapItemResponse {
            id: item.id,
            title: item.title,
            description: item.description,
            status: item.status,
            category: item.category,
            quarter: item.quarter,
            votes: item.votes,
            has_voted,
            completed_date: item.completed_date,
            tags,
        });
    }

    HttpResponse::Ok().json(ApiResponse::success(response_items))
}

/// GET /api/roadmap/stats
/// Returns roadmap statistics
pub async fn get_stats(pool: web::Data<SqlitePool>) -> HttpResponse {
    let stats = match sqlx::query_as::<_, (i32, i32, i32, i32, i32, i32)>(
        r#"SELECT
             COUNT(*) as total,
             SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
             SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
             SUM(CASE WHEN status = 'planned' THEN 1 ELSE 0 END) as planned,
             SUM(CASE WHEN status = 'considering' THEN 1 ELSE 0 END) as considering,
             SUM(votes) as total_votes
           FROM roadmap_items"#
    )
    .fetch_one(pool.get_ref())
    .await {
        Ok((total, completed, in_progress, planned, considering, total_votes)) => {
            RoadmapStats {
                total_items: total,
                completed,
                in_progress,
                planned,
                considering,
                total_votes,
            }
        }
        Err(e) => {
            log::error!("Failed to fetch roadmap stats: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to fetch stats"));
        }
    };

    HttpResponse::Ok().json(ApiResponse::success(stats))
}

/// POST /api/roadmap/items/{id}/vote
/// Vote for a roadmap item (rate limited, deduplicated)
pub async fn vote_item(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let item_id = path.into_inner();
    let user_id = req.extensions().get::<String>().cloned();
    let voter_identifier = get_voter_identifier(&req, user_id.as_deref());

    // Check if item exists
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM roadmap_items WHERE id = ?"
    )
    .bind(&item_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0) > 0;

    if !exists {
        return HttpResponse::NotFound()
            .json(ApiResponse::<()>::error("Roadmap item not found"));
    }

    // Check if already voted
    if has_voted(pool.get_ref(), &item_id, &voter_identifier).await {
        return HttpResponse::Conflict()
            .json(ApiResponse::<()>::error("Already voted for this item"));
    }

    // Record the vote
    let vote_id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = sqlx::query(
        "INSERT INTO roadmap_votes (id, item_id, identifier, voted_at) VALUES (?, ?, ?, datetime('now'))"
    )
    .bind(&vote_id)
    .bind(&item_id)
    .bind(&voter_identifier)
    .execute(pool.get_ref())
    .await {
        log::error!("Failed to record vote: {}", e);
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error("Failed to record vote"));
    }

    // Increment vote count
    if let Err(e) = sqlx::query(
        "UPDATE roadmap_items SET votes = votes + 1, updated_at = datetime('now') WHERE id = ?"
    )
    .bind(&item_id)
    .execute(pool.get_ref())
    .await {
        log::error!("Failed to update vote count: {}", e);
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error("Failed to update vote count"));
    }

    // Return updated vote count
    let new_votes = sqlx::query_scalar::<_, i32>(
        "SELECT votes FROM roadmap_items WHERE id = ?"
    )
    .bind(&item_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "item_id": item_id,
        "votes": new_votes,
        "has_voted": true
    })))
}

/// DELETE /api/roadmap/items/{id}/vote
/// Remove vote from a roadmap item
pub async fn unvote_item(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let item_id = path.into_inner();
    let user_id = req.extensions().get::<String>().cloned();
    let voter_identifier = get_voter_identifier(&req, user_id.as_deref());

    // Check if vote exists
    if !has_voted(pool.get_ref(), &item_id, &voter_identifier).await {
        return HttpResponse::NotFound()
            .json(ApiResponse::<()>::error("Vote not found"));
    }

    // Remove the vote
    if let Err(e) = sqlx::query(
        "DELETE FROM roadmap_votes WHERE item_id = ? AND identifier = ?"
    )
    .bind(&item_id)
    .bind(&voter_identifier)
    .execute(pool.get_ref())
    .await {
        log::error!("Failed to remove vote: {}", e);
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error("Failed to remove vote"));
    }

    // Decrement vote count
    if let Err(e) = sqlx::query(
        "UPDATE roadmap_items SET votes = MAX(0, votes - 1), updated_at = datetime('now') WHERE id = ?"
    )
    .bind(&item_id)
    .execute(pool.get_ref())
    .await {
        log::error!("Failed to update vote count: {}", e);
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error("Failed to update vote count"));
    }

    // Return updated vote count
    let new_votes = sqlx::query_scalar::<_, i32>(
        "SELECT votes FROM roadmap_items WHERE id = ?"
    )
    .bind(&item_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "item_id": item_id,
        "votes": new_votes,
        "has_voted": false
    })))
}

/// POST /api/roadmap/suggestions
/// Submit a feature suggestion
pub async fn submit_suggestion(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    body: web::Json<SuggestionRequest>,
) -> HttpResponse {
    // Validate input
    if body.title.trim().is_empty() {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Title is required"));
    }
    if body.description.trim().is_empty() {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Description is required"));
    }
    if body.title.len() > 200 {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Title must be 200 characters or less"));
    }
    if body.description.len() > 2000 {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Description must be 2000 characters or less"));
    }

    // Rate limit by IP
    let voter_identifier = get_voter_identifier(&req, None);
    let recent_count = sqlx::query_scalar::<_, i32>(
        r#"SELECT COUNT(*) FROM roadmap_suggestions
           WHERE submitter_identifier = ?
           AND created_at > datetime('now', '-1 hour')"#
    )
    .bind(&voter_identifier)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    if recent_count >= 3 {
        return HttpResponse::TooManyRequests()
            .json(ApiResponse::<()>::error("Rate limit exceeded. Please try again later."));
    }

    // Create the suggestion
    let suggestion_id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = sqlx::query(
        r#"INSERT INTO roadmap_suggestions
           (id, title, description, email, status, submitter_identifier, created_at)
           VALUES (?, ?, ?, ?, 'pending', ?, datetime('now'))"#
    )
    .bind(&suggestion_id)
    .bind(body.title.trim())
    .bind(body.description.trim())
    .bind(&body.email)
    .bind(&voter_identifier)
    .execute(pool.get_ref())
    .await {
        log::error!("Failed to create suggestion: {}", e);
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error("Failed to submit suggestion"));
    }

    HttpResponse::Created().json(ApiResponse::success(serde_json::json!({
        "id": suggestion_id,
        "message": "Thank you for your suggestion! It will be reviewed by our team."
    })))
}

/// GET /api/roadmap/suggestions (admin only)
/// List all suggestions for review
pub async fn list_suggestions(
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    let suggestions = match sqlx::query_as::<_, (String, String, String, Option<String>, String, String)>(
        r#"SELECT id, title, description, email, status, created_at
           FROM roadmap_suggestions
           ORDER BY created_at DESC"#
    )
    .fetch_all(pool.get_ref())
    .await {
        Ok(rows) => rows.into_iter().map(|(id, title, description, email, status, created_at)| {
            RoadmapSuggestion {
                id,
                title,
                description,
                email,
                status,
                created_at,
            }
        }).collect::<Vec<_>>(),
        Err(e) => {
            log::error!("Failed to fetch suggestions: {}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to fetch suggestions"));
        }
    };

    HttpResponse::Ok().json(ApiResponse::success(suggestions))
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        .route("/roadmap/items", web::get().to(get_items))
        .route("/roadmap/stats", web::get().to(get_stats))
        .route("/roadmap/items/{id}/vote", web::post().to(vote_item))
        .route("/roadmap/items/{id}/vote", web::delete().to(unvote_item))
        .route("/roadmap/suggestions", web::post().to(submit_suggestion))
        .route("/roadmap/suggestions", web::get().to(list_suggestions));
}
