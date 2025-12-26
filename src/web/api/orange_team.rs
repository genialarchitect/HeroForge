//! Orange Team API endpoints - Security Awareness & Training
//!
//! Provides REST API endpoints for:
//! - Training courses and modules
//! - Gamification (points, badges, leaderboards, challenges)
//! - Phishing analytics and susceptibility scoring
//! - Just-in-Time (JIT) training
//! - Compliance training tracking
//! - Certificates

use actix_web::{web, HttpResponse, Result};
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::web::auth;

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct CourseResponse {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub category: String,
    pub difficulty: String,
    pub duration_minutes: i64,
    pub passing_score: i64,
    pub points_value: i64,
    pub is_mandatory: bool,
    pub is_active: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCourseRequest {
    pub title: String,
    pub description: Option<String>,
    pub category: String,
    pub difficulty: String,
    pub duration_minutes: i32,
    pub passing_score: Option<i32>,
    pub points_value: Option<i32>,
    pub is_mandatory: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleResponse {
    pub id: String,
    pub course_id: String,
    pub title: String,
    pub content_type: String,
    pub order_index: i64,
    pub duration_minutes: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub id: String,
    pub user_id: String,
    pub course_id: String,
    pub course_title: String,
    pub status: String,
    pub progress_percent: i64,
    pub quiz_score: Option<i64>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateProgressRequest {
    pub module_id: String,
    pub completed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitQuizRequest {
    pub answers: Vec<QuizAnswer>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuizAnswer {
    pub question_id: String,
    pub selected_answer_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuizResultResponse {
    pub passed: bool,
    pub score: i64,
    pub passing_score: i64,
    pub correct_answers: i64,
    pub total_questions: i64,
    pub points_earned: i64,
    pub certificate_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GamificationProfileResponse {
    pub user_id: String,
    pub points: i64,
    pub level: i64,
    pub streak_days: i64,
    pub rank: i64,
    pub next_level_points: i64,
    pub badges_earned: i64,
    pub challenges_completed: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LeaderboardEntry {
    pub rank: i64,
    pub user_id: String,
    pub username: String,
    pub points: i64,
    pub level: i64,
    pub badges_count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BadgeResponse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon_url: Option<String>,
    pub category: String,
    pub points_required: Option<i64>,
    pub rarity: String,
    pub earned_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub id: String,
    pub title: String,
    pub description: String,
    pub challenge_type: String,
    pub difficulty: String,
    pub points_reward: i64,
    pub time_limit_minutes: Option<i64>,
    pub max_attempts: Option<i64>,
    pub is_active: bool,
    pub starts_at: Option<String>,
    pub ends_at: Option<String>,
    pub user_status: Option<String>,
    pub user_attempts: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttemptChallengeRequest {
    pub answer: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeAttemptResponse {
    pub success: bool,
    pub message: String,
    pub points_earned: Option<i64>,
    pub attempts_remaining: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PhishingSusceptibilityResponse {
    pub user_id: String,
    pub score: f64,
    pub click_rate: f64,
    pub report_rate: f64,
    pub training_completion_rate: f64,
    pub risk_level: String,
    pub last_phished_at: Option<String>,
    pub last_trained_at: Option<String>,
    pub recommendation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepartmentStatsResponse {
    pub department: String,
    pub user_count: i64,
    pub avg_susceptibility: f64,
    pub total_clicks: i64,
    pub total_reports: i64,
    pub campaigns_count: i64,
    pub risk_level: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JitAssignmentResponse {
    pub id: String,
    pub trigger_name: String,
    pub training_module_id: String,
    pub training_module_title: Option<String>,
    pub status: String,
    pub assigned_at: String,
    pub due_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JitTriggerResponse {
    pub id: String,
    pub name: String,
    pub trigger_type: String,
    pub training_module_id: String,
    pub delay_minutes: i64,
    pub is_active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateJitTriggerRequest {
    pub name: String,
    pub trigger_type: String,
    pub training_module_id: String,
    pub delay_minutes: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceStatusResponse {
    pub requirement_id: String,
    pub requirement_name: String,
    pub framework: String,
    pub status: String,
    pub due_date: String,
    pub completed_at: Option<String>,
    pub next_due_date: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceOverviewResponse {
    pub total_assignments: i64,
    pub compliant: i64,
    pub overdue: i64,
    pub in_progress: i64,
    pub pending: i64,
    pub compliance_rate: f64,
    pub requirements: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OverdueUserResponse {
    pub user_id: String,
    pub username: String,
    pub email: Option<String>,
    pub requirement_name: String,
    pub due_date: String,
    pub days_overdue: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateResponse {
    pub id: String,
    pub course_id: String,
    pub course_title: String,
    pub certificate_number: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyCertificateRequest {
    pub certificate_number: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyCertificateResponse {
    pub valid: bool,
    pub certificate: Option<CertificateDetails>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateDetails {
    pub certificate_number: String,
    pub user_name: String,
    pub course_title: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
    pub is_expired: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateBadgeRequest {
    pub name: String,
    pub description: String,
    pub icon_url: Option<String>,
    pub category: String,
    pub points_required: Option<i32>,
    pub criteria: serde_json::Value,
    pub rarity: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateChallengeRequest {
    pub title: String,
    pub description: String,
    pub challenge_type: String,
    pub difficulty: String,
    pub points_reward: i32,
    pub time_limit_minutes: Option<i32>,
    pub max_attempts: Option<i32>,
    pub content: serde_json::Value,
    pub solution_hash: Option<String>,
    pub starts_at: Option<String>,
    pub ends_at: Option<String>,
}

// ============================================================================
// Training Courses Handlers
// ============================================================================

/// List all available training courses
async fn list_courses(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let courses: Vec<(String, String, Option<String>, String, String, i64, i64, i64, bool, bool, String)> =
        sqlx::query_as(
            r#"
            SELECT id, title, description, category, difficulty,
                   duration_minutes, passing_score, points_value,
                   is_mandatory, is_active, created_at
            FROM training_courses
            WHERE is_active = TRUE
            ORDER BY category, title
            "#
        )
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to fetch courses: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch courses")
        })?;

    let response: Vec<CourseResponse> = courses
        .into_iter()
        .map(|(id, title, description, category, difficulty, duration_minutes, passing_score, points_value, is_mandatory, is_active, created_at)| {
            CourseResponse {
                id, title, description, category, difficulty,
                duration_minutes, passing_score, points_value,
                is_mandatory, is_active, created_at,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Get course details
async fn get_course(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let course_id = path.into_inner();

    let course: Option<(String, String, Option<String>, String, String, i64, i64, i64, bool, bool, String)> =
        sqlx::query_as(
            r#"
            SELECT id, title, description, category, difficulty,
                   duration_minutes, passing_score, points_value,
                   is_mandatory, is_active, created_at
            FROM training_courses
            WHERE id = ?
            "#
        )
        .bind(&course_id)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to fetch course: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch course")
        })?;

    match course {
        Some((id, title, description, category, difficulty, duration_minutes, passing_score, points_value, is_mandatory, is_active, created_at)) => {
            Ok(HttpResponse::Ok().json(CourseResponse {
                id, title, description, category, difficulty,
                duration_minutes, passing_score, points_value,
                is_mandatory, is_active, created_at,
            }))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Course not found"
        }))),
    }
}

/// Get course modules
async fn get_course_modules(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let course_id = path.into_inner();

    let modules: Vec<(String, String, String, String, i64, i64)> = sqlx::query_as(
        r#"
        SELECT id, course_id, title, content_type, order_index, duration_minutes
        FROM training_modules
        WHERE course_id = ?
        ORDER BY order_index
        "#
    )
    .bind(&course_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch modules: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch modules")
    })?;

    let response: Vec<ModuleResponse> = modules
        .into_iter()
        .map(|(id, course_id, title, content_type, order_index, duration_minutes)| {
            ModuleResponse { id, course_id, title, content_type, order_index, duration_minutes }
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Enroll in a course
async fn enroll_in_course(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let course_id = path.into_inner();
    let user_id = &claims.sub;

    // Check if already enrolled
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM training_enrollments WHERE user_id = ? AND course_id = ?"
    )
    .bind(user_id)
    .bind(&course_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to check enrollment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to check enrollment")
    })?;

    if existing.is_some() {
        return Ok(HttpResponse::Conflict().json(serde_json::json!({
            "error": "Already enrolled in this course"
        })));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO training_enrollments (id, user_id, course_id, status, progress_percent, started_at, created_at)
        VALUES (?, ?, ?, 'enrolled', 0, ?, ?)
        "#
    )
    .bind(&id)
    .bind(user_id)
    .bind(&course_id)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to enroll: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to enroll")
    })?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "Successfully enrolled in course"
    })))
}

/// Get user's enrolled courses
async fn get_my_courses(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let enrollments: Vec<(String, String, String, String, String, i64, Option<i64>, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT e.id, e.user_id, e.course_id, c.title,
               e.status, e.progress_percent, e.quiz_score,
               e.started_at, e.completed_at
        FROM training_enrollments e
        JOIN training_courses c ON e.course_id = c.id
        WHERE e.user_id = ?
        ORDER BY e.created_at DESC
        "#
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch enrollments: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch enrollments")
    })?;

    let response: Vec<EnrollmentResponse> = enrollments
        .into_iter()
        .map(|(id, user_id, course_id, course_title, status, progress_percent, quiz_score, started_at, completed_at)| {
            EnrollmentResponse {
                id, user_id, course_id, course_title, status,
                progress_percent, quiz_score, started_at, completed_at,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Update course progress
async fn update_progress(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
    _body: web::Json<UpdateProgressRequest>,
) -> Result<HttpResponse> {
    let course_id = path.into_inner();
    let user_id = &claims.sub;

    // Get total modules and calculate progress
    let module_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM training_modules WHERE course_id = ?"
    )
    .bind(&course_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((1,));

    let total_modules = module_count.0;
    let progress_increment = if total_modules > 0 {
        100 / total_modules
    } else {
        100
    };

    sqlx::query(
        r#"
        UPDATE training_enrollments
        SET progress_percent = MIN(progress_percent + ?, 100),
            status = CASE WHEN progress_percent + ? >= 100 THEN 'completed' ELSE 'in_progress' END
        WHERE user_id = ? AND course_id = ?
        "#
    )
    .bind(progress_increment)
    .bind(progress_increment)
    .bind(user_id)
    .bind(&course_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to update progress: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update progress")
    })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Progress updated",
        "progress_increment": progress_increment
    })))
}

/// Submit quiz answers
async fn submit_quiz(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<SubmitQuizRequest>,
) -> Result<HttpResponse> {
    let course_id = path.into_inner();
    let user_id = &claims.sub;

    // Get quiz for course
    let quiz: Option<(String, String, i64, i64)> = sqlx::query_as(
        r#"
        SELECT q.id, q.questions_json, c.passing_score, c.points_value
        FROM training_quizzes q
        JOIN training_courses c ON q.course_id = c.id
        WHERE q.course_id = ?
        "#
    )
    .bind(&course_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch quiz: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch quiz")
    })?;

    let quiz = match quiz {
        Some(q) => q,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "No quiz found for this course"
            })));
        }
    };

    let (_quiz_id, questions_json, passing_score, points_value) = quiz;

    // Parse questions and grade
    let questions: Vec<serde_json::Value> =
        serde_json::from_str(&questions_json).unwrap_or_default();
    let total_questions = questions.len() as i64;
    let mut correct_answers: i64 = 0;

    for answer in &body.answers {
        if let Some(question) = questions.iter().find(|q| {
            q.get("id")
                .and_then(|id| id.as_str())
                .map(|id| id == answer.question_id)
                .unwrap_or(false)
        }) {
            if let Some(correct_ids) = question.get("correct_answer_ids").and_then(|c| c.as_array())
            {
                let correct: Vec<String> = correct_ids
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                if answer.selected_answer_ids == correct {
                    correct_answers += 1;
                }
            }
        }
    }

    let score = if total_questions > 0 {
        (correct_answers * 100) / total_questions
    } else {
        0
    };

    let passed = score >= passing_score;
    let points_earned = if passed { points_value } else { 0 };

    // Update enrollment with quiz score
    let now = Utc::now().to_rfc3339();
    let status = if passed { "completed" } else { "failed" };

    let _ = sqlx::query(
        r#"
        UPDATE training_enrollments
        SET quiz_score = ?, status = ?, completed_at = ?
        WHERE user_id = ? AND course_id = ?
        "#
    )
    .bind(score)
    .bind(status)
    .bind(&now)
    .bind(user_id)
    .bind(&course_id)
    .execute(pool.get_ref())
    .await;

    // Award points if passed
    let mut certificate_id = None;
    if passed {
        let tx_id = Uuid::new_v4().to_string();
        let _ = sqlx::query(
            r#"
            INSERT INTO point_transactions (id, user_id, points, reason, reference_id, created_at)
            VALUES (?, ?, ?, 'course_completed', ?, ?)
            "#
        )
        .bind(&tx_id)
        .bind(user_id)
        .bind(points_earned)
        .bind(&course_id)
        .bind(&now)
        .execute(pool.get_ref())
        .await;

        // Update user points
        let point_id = Uuid::new_v4().to_string();
        let _ = sqlx::query(
            r#"
            INSERT INTO user_points (id, user_id, points, level, streak_days, created_at)
            VALUES (?, ?, ?, 1, 0, ?)
            ON CONFLICT(user_id) DO UPDATE SET points = points + ?
            "#
        )
        .bind(&point_id)
        .bind(user_id)
        .bind(points_earned)
        .bind(&now)
        .bind(points_earned)
        .execute(pool.get_ref())
        .await;

        // Generate certificate
        let cert_id = Uuid::new_v4().to_string();
        let cert_number = format!("HF-{}", &cert_id[..8].to_uppercase());
        let _ = sqlx::query(
            r#"
            INSERT INTO training_certificates (id, user_id, course_id, certificate_number, issued_at)
            VALUES (?, ?, ?, ?, ?)
            "#
        )
        .bind(&cert_id)
        .bind(user_id)
        .bind(&course_id)
        .bind(&cert_number)
        .bind(&now)
        .execute(pool.get_ref())
        .await;

        certificate_id = Some(cert_id);
    }

    Ok(HttpResponse::Ok().json(QuizResultResponse {
        passed,
        score,
        passing_score,
        correct_answers,
        total_questions,
        points_earned,
        certificate_id,
    }))
}

// ============================================================================
// Gamification Handlers
// ============================================================================

/// Get user's gamification profile
async fn get_gamification_profile(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let points_data: Option<(i64, i64, i64)> = sqlx::query_as(
        r#"
        SELECT points, level, streak_days
        FROM user_points
        WHERE user_id = ?
        "#
    )
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch points: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch profile")
    })?;

    let (points, level, streak_days) = points_data.unwrap_or((0, 1, 0));

    // Calculate rank
    let rank: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) + 1
        FROM user_points
        WHERE points > COALESCE((SELECT points FROM user_points WHERE user_id = ?), 0)
        "#
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((1,));

    // Count badges
    let badges_earned: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM user_badges WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // Count completed challenges
    let challenges_completed: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM challenge_attempts WHERE user_id = ? AND status = 'completed'"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // Calculate next level points (1000 points per level)
    let next_level_points = level * 1000;

    Ok(HttpResponse::Ok().json(GamificationProfileResponse {
        user_id: user_id.clone(),
        points,
        level,
        streak_days,
        rank: rank.0,
        next_level_points,
        badges_earned: badges_earned.0,
        challenges_completed: challenges_completed.0,
    }))
}

/// Get leaderboard
async fn get_leaderboard(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let leaders: Vec<(String, String, i64, i64, i64)> = sqlx::query_as(
        r#"
        SELECT up.user_id, u.username, up.points, up.level,
               (SELECT COUNT(*) FROM user_badges ub WHERE ub.user_id = up.user_id) as badges_count
        FROM user_points up
        JOIN users u ON up.user_id = u.id
        ORDER BY up.points DESC
        LIMIT 100
        "#
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch leaderboard: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch leaderboard")
    })?;

    let entries: Vec<LeaderboardEntry> = leaders
        .into_iter()
        .enumerate()
        .map(|(i, (user_id, username, points, level, badges_count))| LeaderboardEntry {
            rank: (i + 1) as i64,
            user_id,
            username,
            points,
            level,
            badges_count,
        })
        .collect();

    Ok(HttpResponse::Ok().json(entries))
}

/// Get all available badges
async fn get_badges(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let badges: Vec<(String, String, String, Option<String>, String, Option<i64>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT id, name, description, icon_url, category, points_required, rarity
        FROM training_badges
        ORDER BY category, points_required
        "#
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch badges: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch badges")
    })?;

    let response: Vec<BadgeResponse> = badges
        .into_iter()
        .map(|(id, name, description, icon_url, category, points_required, rarity)| BadgeResponse {
            id, name, description, icon_url, category, points_required,
            rarity: rarity.unwrap_or_else(|| "common".to_string()),
            earned_at: None,
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Get user's earned badges
async fn get_my_badges(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let badges: Vec<(String, String, String, Option<String>, String, Option<i64>, Option<String>, String)> = sqlx::query_as(
        r#"
        SELECT b.id, b.name, b.description, b.icon_url, b.category,
               b.points_required, b.rarity, ub.earned_at
        FROM user_badges ub
        JOIN training_badges b ON ub.badge_id = b.id
        WHERE ub.user_id = ?
        ORDER BY ub.earned_at DESC
        "#
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch badges: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch badges")
    })?;

    let response: Vec<BadgeResponse> = badges
        .into_iter()
        .map(|(id, name, description, icon_url, category, points_required, rarity, earned_at)| BadgeResponse {
            id, name, description, icon_url, category, points_required,
            rarity: rarity.unwrap_or_else(|| "common".to_string()),
            earned_at: Some(earned_at),
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Get active challenges
async fn get_challenges(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();

    let challenges: Vec<(String, String, String, String, String, i64, Option<i64>, Option<i64>, bool, Option<String>, Option<String>, Option<String>, Option<i64>)> = sqlx::query_as(
        r#"
        SELECT c.id, c.title, c.description, c.challenge_type, c.difficulty,
               c.points_reward, c.time_limit_minutes, c.max_attempts,
               c.is_active, c.starts_at, c.ends_at,
               ca.status, ca.attempts_count
        FROM security_challenges c
        LEFT JOIN challenge_attempts ca ON c.id = ca.challenge_id AND ca.user_id = ?
        WHERE c.is_active = TRUE
          AND (c.starts_at IS NULL OR c.starts_at <= ?)
          AND (c.ends_at IS NULL OR c.ends_at > ?)
        ORDER BY c.points_reward DESC
        "#
    )
    .bind(user_id)
    .bind(&now)
    .bind(&now)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch challenges: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch challenges")
    })?;

    let response: Vec<ChallengeResponse> = challenges
        .into_iter()
        .map(|(id, title, description, challenge_type, difficulty, points_reward, time_limit_minutes, max_attempts, is_active, starts_at, ends_at, user_status, user_attempts)| {
            ChallengeResponse {
                id, title, description, challenge_type, difficulty,
                points_reward, time_limit_minutes, max_attempts,
                is_active, starts_at, ends_at, user_status, user_attempts,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Attempt a challenge
async fn attempt_challenge(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<AttemptChallengeRequest>,
) -> Result<HttpResponse> {
    let challenge_id = path.into_inner();
    let user_id = &claims.sub;

    // Get challenge
    let challenge: Option<(String, Option<String>, Option<i64>, i64)> = sqlx::query_as(
        r#"
        SELECT id, solution_hash, max_attempts, points_reward
        FROM security_challenges
        WHERE id = ? AND is_active = TRUE
        "#
    )
    .bind(&challenge_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch challenge: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch challenge")
    })?;

    let challenge = match challenge {
        Some(c) => c,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Challenge not found or not active"
            })));
        }
    };

    let (_id, solution_hash, max_attempts, points_reward) = challenge;

    // Check existing attempts
    let existing: Option<(String, i64, String)> = sqlx::query_as(
        r#"
        SELECT id, attempts_count, status
        FROM challenge_attempts
        WHERE user_id = ? AND challenge_id = ?
        "#
    )
    .bind(user_id)
    .bind(&challenge_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to check attempts: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to check attempts")
    })?;

    let (attempt_id, attempts_count, already_completed, has_existing) = match existing {
        Some((id, count, status)) => (id, count, status == "completed", true),
        None => (Uuid::new_v4().to_string(), 0, false, false),
    };

    if already_completed {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Challenge already completed"
        })));
    }

    if let Some(max) = max_attempts {
        if attempts_count >= max {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Maximum attempts reached"
            })));
        }
    }

    // Check answer (hash the input and compare)
    let mut hasher = Sha256::new();
    hasher.update(body.answer.as_bytes());
    let answer_hash = format!("{:x}", hasher.finalize());
    let success = solution_hash
        .map(|h| h == answer_hash)
        .unwrap_or(false);

    let now = Utc::now().to_rfc3339();
    let status = if success { "completed" } else { "attempted" };
    let new_attempts = attempts_count + 1;

    // Upsert attempt
    if has_existing {
        let _ = sqlx::query(
            r#"
            UPDATE challenge_attempts
            SET status = ?, attempts_count = ?, completed_at = CASE WHEN ? = 'completed' THEN ? ELSE completed_at END
            WHERE id = ?
            "#
        )
        .bind(status)
        .bind(new_attempts)
        .bind(status)
        .bind(&now)
        .bind(&attempt_id)
        .execute(pool.get_ref())
        .await;
    } else {
        let _ = sqlx::query(
            r#"
            INSERT INTO challenge_attempts (id, user_id, challenge_id, status, attempts_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&attempt_id)
        .bind(user_id)
        .bind(&challenge_id)
        .bind(status)
        .bind(new_attempts)
        .bind(&now)
        .execute(pool.get_ref())
        .await;
    }

    let mut points_earned = None;
    if success {
        // Award points
        let tx_id = Uuid::new_v4().to_string();
        let _ = sqlx::query(
            r#"
            INSERT INTO point_transactions (id, user_id, points, reason, reference_id, created_at)
            VALUES (?, ?, ?, 'challenge_completed', ?, ?)
            "#
        )
        .bind(&tx_id)
        .bind(user_id)
        .bind(points_reward)
        .bind(&challenge_id)
        .bind(&now)
        .execute(pool.get_ref())
        .await;

        // Update user points
        let point_id = Uuid::new_v4().to_string();
        let _ = sqlx::query(
            r#"
            INSERT INTO user_points (id, user_id, points, level, streak_days, created_at)
            VALUES (?, ?, ?, 1, 0, ?)
            ON CONFLICT(user_id) DO UPDATE SET points = points + ?
            "#
        )
        .bind(&point_id)
        .bind(user_id)
        .bind(points_reward)
        .bind(&now)
        .bind(points_reward)
        .execute(pool.get_ref())
        .await;

        points_earned = Some(points_reward);
    }

    let attempts_remaining = max_attempts
        .map(|max| max - new_attempts)
        .filter(|r| *r >= 0);

    Ok(HttpResponse::Ok().json(ChallengeAttemptResponse {
        success,
        message: if success {
            "Congratulations! Challenge completed!".to_string()
        } else {
            "Incorrect answer. Try again!".to_string()
        },
        points_earned,
        attempts_remaining,
    }))
}

// ============================================================================
// Phishing Analytics Handlers
// ============================================================================

/// Get user's phishing susceptibility score
async fn get_my_phishing_score(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let score: Option<(String, f64, Option<f64>, Option<f64>, Option<f64>, String, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT user_id, score, click_rate, report_rate, training_completion_rate,
               risk_level, last_phished_at, last_trained_at
        FROM phishing_susceptibility
        WHERE user_id = ?
        "#
    )
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch score: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch score")
    })?;

    match score {
        Some((user_id, score, click_rate, report_rate, training_completion_rate, risk_level, last_phished_at, last_trained_at)) => {
            Ok(HttpResponse::Ok().json(PhishingSusceptibilityResponse {
                user_id,
                score,
                click_rate: click_rate.unwrap_or(0.0),
                report_rate: report_rate.unwrap_or(0.0),
                training_completion_rate: training_completion_rate.unwrap_or(0.0),
                risk_level: risk_level.clone(),
                last_phished_at,
                last_trained_at,
                recommendation: get_training_recommendation(&risk_level),
            }))
        }
        None => Ok(HttpResponse::Ok().json(PhishingSusceptibilityResponse {
            user_id: user_id.clone(),
            score: 0.0,
            click_rate: 0.0,
            report_rate: 0.0,
            training_completion_rate: 0.0,
            risk_level: "unknown".to_string(),
            last_phished_at: None,
            last_trained_at: None,
            recommendation: Some("Complete security awareness training to establish your baseline.".to_string()),
        })),
    }
}

/// Get department phishing statistics (admin only)
async fn get_department_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    if !claims.roles.contains(&"admin".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin access required"
        })));
    }

    let stats: Vec<(String, i64, Option<f64>, Option<i64>, Option<i64>, Option<i64>, String)> = sqlx::query_as(
        r#"
        SELECT department, user_count, avg_susceptibility, total_clicks,
               total_reports, campaigns_count, risk_level
        FROM department_phishing_stats
        ORDER BY avg_susceptibility DESC
        "#
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch department stats: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch department stats")
    })?;

    let response: Vec<DepartmentStatsResponse> = stats
        .into_iter()
        .map(|(department, user_count, avg_susceptibility, total_clicks, total_reports, campaigns_count, risk_level)| {
            DepartmentStatsResponse {
                department,
                user_count,
                avg_susceptibility: avg_susceptibility.unwrap_or(0.0),
                total_clicks: total_clicks.unwrap_or(0),
                total_reports: total_reports.unwrap_or(0),
                campaigns_count: campaigns_count.unwrap_or(0),
                risk_level,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Get high-risk users (admin only)
async fn get_high_risk_users(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    if !claims.roles.contains(&"admin".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin access required"
        })));
    }

    let users: Vec<(String, String, Option<String>, f64, String, Option<f64>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT ps.user_id, u.username, u.email, ps.score, ps.risk_level,
               ps.click_rate, ps.last_phished_at
        FROM phishing_susceptibility ps
        JOIN users u ON ps.user_id = u.id
        WHERE ps.risk_level IN ('high', 'critical')
        ORDER BY ps.score DESC
        LIMIT 50
        "#
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch high-risk users: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch high-risk users")
    })?;

    let response: Vec<serde_json::Value> = users
        .into_iter()
        .map(|(user_id, username, email, score, risk_level, click_rate, last_phished_at)| {
            serde_json::json!({
                "user_id": user_id,
                "username": username,
                "email": email,
                "score": score,
                "risk_level": risk_level,
                "click_rate": click_rate,
                "last_phished_at": last_phished_at
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

// ============================================================================
// JIT Training Handlers
// ============================================================================

/// Get pending JIT training assignments
async fn get_pending_jit(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let assignments: Vec<(String, String, String, Option<String>, String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT a.id, t.name, a.training_module_id,
               m.title, a.status, a.assigned_at, a.due_at
        FROM jit_training_assignments a
        JOIN jit_training_triggers t ON a.trigger_id = t.id
        LEFT JOIN training_modules m ON a.training_module_id = m.id
        WHERE a.user_id = ? AND a.status IN ('assigned', 'in_progress')
        ORDER BY a.due_at ASC
        "#
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch JIT assignments: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch JIT assignments")
    })?;

    let response: Vec<JitAssignmentResponse> = assignments
        .into_iter()
        .map(|(id, trigger_name, training_module_id, training_module_title, status, assigned_at, due_at)| {
            JitAssignmentResponse {
                id, trigger_name, training_module_id, training_module_title,
                status, assigned_at, due_at,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Complete a JIT training assignment
async fn complete_jit_assignment(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let assignment_id = path.into_inner();
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        r#"
        UPDATE jit_training_assignments
        SET status = 'completed', completed_at = ?
        WHERE id = ? AND user_id = ?
        "#
    )
    .bind(&now)
    .bind(&assignment_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to complete assignment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to complete assignment")
    })?;

    if result.rows_affected() > 0 {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "JIT training completed successfully"
        })))
    } else {
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Assignment not found"
        })))
    }
}

/// List JIT triggers (admin only)
async fn list_jit_triggers(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    if !claims.roles.contains(&"admin".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin access required"
        })));
    }

    let triggers: Vec<(String, String, String, String, Option<i64>, bool)> = sqlx::query_as(
        r#"
        SELECT id, name, trigger_type, training_module_id, delay_minutes, is_active
        FROM jit_training_triggers
        ORDER BY name
        "#
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch triggers: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch triggers")
    })?;

    let response: Vec<JitTriggerResponse> = triggers
        .into_iter()
        .map(|(id, name, trigger_type, training_module_id, delay_minutes, is_active)| {
            JitTriggerResponse {
                id, name, trigger_type, training_module_id,
                delay_minutes: delay_minutes.unwrap_or(0),
                is_active,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Create JIT trigger (admin only)
async fn create_jit_trigger(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateJitTriggerRequest>,
) -> Result<HttpResponse> {
    if !claims.roles.contains(&"admin".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin access required"
        })));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let delay = body.delay_minutes.unwrap_or(0);

    sqlx::query(
        r#"
        INSERT INTO jit_training_triggers (id, name, trigger_type, training_module_id, delay_minutes, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, TRUE, ?)
        "#
    )
    .bind(&id)
    .bind(&body.name)
    .bind(&body.trigger_type)
    .bind(&body.training_module_id)
    .bind(delay)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create trigger: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create trigger")
    })?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "JIT trigger created successfully"
    })))
}

// ============================================================================
// Compliance Training Handlers
// ============================================================================

/// Get user's compliance training status
async fn get_compliance_status(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let statuses: Vec<(String, String, String, String, String, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT s.requirement_id, r.name, r.framework,
               s.status, s.due_date, s.completed_at, s.next_due_date
        FROM compliance_training_status s
        JOIN compliance_training_requirements r ON s.requirement_id = r.id
        WHERE s.user_id = ?
        ORDER BY s.due_date ASC
        "#
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch compliance status: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch compliance status")
    })?;

    let response: Vec<ComplianceStatusResponse> = statuses
        .into_iter()
        .map(|(requirement_id, requirement_name, framework, status, due_date, completed_at, next_due_date)| {
            ComplianceStatusResponse {
                requirement_id, requirement_name, framework,
                status, due_date, completed_at, next_due_date,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Get organization compliance overview (admin only)
async fn get_compliance_overview(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    if !claims.roles.contains(&"admin".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin access required"
        })));
    }

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM compliance_training_status")
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    let compliant: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM compliance_training_status WHERE status = 'compliant'"
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let overdue: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM compliance_training_status WHERE status = 'overdue'"
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let in_progress: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM compliance_training_status WHERE status = 'in_progress'"
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let pending: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM compliance_training_status WHERE status = 'pending'"
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let req_rows: Vec<(String,)> = sqlx::query_as(
        "SELECT name FROM compliance_training_requirements WHERE is_active = TRUE"
    )
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let requirements: Vec<String> = req_rows.into_iter().map(|(name,)| name).collect();

    let compliance_rate = if total.0 > 0 {
        (compliant.0 as f64 / total.0 as f64) * 100.0
    } else {
        100.0
    };

    Ok(HttpResponse::Ok().json(ComplianceOverviewResponse {
        total_assignments: total.0,
        compliant: compliant.0,
        overdue: overdue.0,
        in_progress: in_progress.0,
        pending: pending.0,
        compliance_rate,
        requirements,
    }))
}

/// Get overdue users (admin only)
async fn get_overdue_users(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    if !claims.roles.contains(&"admin".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin access required"
        })));
    }

    let today = Utc::now().date_naive().to_string();

    let overdue: Vec<(String, String, Option<String>, String, String, f64)> = sqlx::query_as(
        r#"
        SELECT s.user_id, u.username, u.email, r.name,
               s.due_date,
               julianday(?) - julianday(s.due_date) as days_overdue
        FROM compliance_training_status s
        JOIN users u ON s.user_id = u.id
        JOIN compliance_training_requirements r ON s.requirement_id = r.id
        WHERE s.status = 'overdue' OR (s.due_date < ? AND s.status != 'compliant')
        ORDER BY s.due_date ASC
        "#
    )
    .bind(&today)
    .bind(&today)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch overdue users: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch overdue users")
    })?;

    let response: Vec<OverdueUserResponse> = overdue
        .into_iter()
        .map(|(user_id, username, email, requirement_name, due_date, days_overdue)| {
            OverdueUserResponse {
                user_id, username, email, requirement_name,
                due_date, days_overdue: days_overdue as i64,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

// ============================================================================
// Certificates Handlers
// ============================================================================

/// Get user's certificates
async fn get_my_certificates(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let certificates: Vec<(String, String, String, String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT c.id, c.course_id, tc.title,
               c.certificate_number, c.issued_at, c.expires_at
        FROM training_certificates c
        JOIN training_courses tc ON c.course_id = tc.id
        WHERE c.user_id = ?
        ORDER BY c.issued_at DESC
        "#
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch certificates: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch certificates")
    })?;

    let response: Vec<CertificateResponse> = certificates
        .into_iter()
        .map(|(id, course_id, course_title, certificate_number, issued_at, expires_at)| {
            CertificateResponse {
                id, course_id, course_title, certificate_number, issued_at, expires_at,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Verify a certificate by number
async fn verify_certificate(
    pool: web::Data<SqlitePool>,
    body: web::Json<VerifyCertificateRequest>,
) -> Result<HttpResponse> {
    let cert: Option<(String, String, String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT c.certificate_number, u.username,
               tc.title, c.issued_at, c.expires_at
        FROM training_certificates c
        JOIN users u ON c.user_id = u.id
        JOIN training_courses tc ON c.course_id = tc.id
        WHERE c.certificate_number = ?
        "#
    )
    .bind(&body.certificate_number)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to verify certificate: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to verify certificate")
    })?;

    match cert {
        Some((certificate_number, user_name, course_title, issued_at, expires_at)) => {
            let is_expired = expires_at
                .as_ref()
                .map(|exp| {
                    NaiveDate::parse_from_str(exp, "%Y-%m-%d")
                        .map(|d| d < Utc::now().date_naive())
                        .unwrap_or(false)
                })
                .unwrap_or(false);

            Ok(HttpResponse::Ok().json(VerifyCertificateResponse {
                valid: !is_expired,
                certificate: Some(CertificateDetails {
                    certificate_number,
                    user_name,
                    course_title,
                    issued_at,
                    expires_at,
                    is_expired,
                }),
            }))
        }
        None => Ok(HttpResponse::Ok().json(VerifyCertificateResponse {
            valid: false,
            certificate: None,
        })),
    }
}

// ============================================================================
// Admin Handlers
// ============================================================================

/// Create a new course (admin only)
async fn create_course(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateCourseRequest>,
) -> Result<HttpResponse> {
    if !claims.roles.contains(&"admin".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin access required"
        })));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let passing_score = body.passing_score.unwrap_or(80);
    let points_value = body.points_value.unwrap_or(100);
    let is_mandatory = body.is_mandatory.unwrap_or(false);

    sqlx::query(
        r#"
        INSERT INTO training_courses (id, title, description, category, difficulty,
                                       duration_minutes, passing_score, points_value,
                                       is_mandatory, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE, ?)
        "#
    )
    .bind(&id)
    .bind(&body.title)
    .bind(&body.description)
    .bind(&body.category)
    .bind(&body.difficulty)
    .bind(body.duration_minutes)
    .bind(passing_score)
    .bind(points_value)
    .bind(is_mandatory)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create course: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create course")
    })?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "Course created successfully"
    })))
}

/// Create a new badge (admin only)
async fn create_badge(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateBadgeRequest>,
) -> Result<HttpResponse> {
    if !claims.roles.contains(&"admin".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin access required"
        })));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let criteria_json = serde_json::to_string(&body.criteria).unwrap_or_else(|_| "{}".to_string());

    sqlx::query(
        r#"
        INSERT INTO training_badges (id, name, description, icon_url, category,
                                      points_required, criteria_json, rarity, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.icon_url)
    .bind(&body.category)
    .bind(body.points_required)
    .bind(&criteria_json)
    .bind(&body.rarity)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create badge: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create badge")
    })?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "Badge created successfully"
    })))
}

/// Create a new challenge (admin only)
async fn create_challenge(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateChallengeRequest>,
) -> Result<HttpResponse> {
    if !claims.roles.contains(&"admin".to_string()) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin access required"
        })));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let content_json = serde_json::to_string(&body.content).unwrap_or_else(|_| "{}".to_string());

    sqlx::query(
        r#"
        INSERT INTO security_challenges (id, title, description, challenge_type, difficulty,
                                          points_reward, time_limit_minutes, max_attempts,
                                          content_json, solution_hash, is_active,
                                          starts_at, ends_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE, ?, ?, ?)
        "#
    )
    .bind(&id)
    .bind(&body.title)
    .bind(&body.description)
    .bind(&body.challenge_type)
    .bind(&body.difficulty)
    .bind(body.points_reward)
    .bind(body.time_limit_minutes)
    .bind(body.max_attempts)
    .bind(&content_json)
    .bind(&body.solution_hash)
    .bind(&body.starts_at)
    .bind(&body.ends_at)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create challenge: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create challenge")
    })?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "Challenge created successfully"
    })))
}

// ============================================================================
// Helper Functions
// ============================================================================

fn get_training_recommendation(risk_level: &str) -> Option<String> {
    match risk_level {
        "critical" => Some("Immediate mandatory training required. Complete all security awareness modules.".to_string()),
        "high" => Some("Complete phishing awareness training within 7 days.".to_string()),
        "medium" => Some("Consider refreshing your security training.".to_string()),
        "low" => Some("Great job! Keep up with periodic training.".to_string()),
        _ => None,
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Training Courses
        .service(
            web::scope("/orange-team/courses")
                .route("", web::get().to(list_courses))
                .route("/{id}", web::get().to(get_course))
                .route("/{id}/modules", web::get().to(get_course_modules))
                .route("/{id}/enroll", web::post().to(enroll_in_course))
                .route("/{id}/progress", web::post().to(update_progress))
                .route("/{id}/quiz", web::post().to(submit_quiz))
        )
        .route("/orange-team/my-courses", web::get().to(get_my_courses))
        // Gamification
        .service(
            web::scope("/orange-team/gamification")
                .route("/profile", web::get().to(get_gamification_profile))
                .route("/leaderboard", web::get().to(get_leaderboard))
                .route("/badges", web::get().to(get_badges))
                .route("/my-badges", web::get().to(get_my_badges))
        )
        .service(
            web::scope("/orange-team/challenges")
                .route("", web::get().to(get_challenges))
                .route("/{id}/attempt", web::post().to(attempt_challenge))
        )
        // Phishing Analytics
        .service(
            web::scope("/orange-team/phishing")
                .route("/my-score", web::get().to(get_my_phishing_score))
                .route("/department-stats", web::get().to(get_department_stats))
                .route("/high-risk", web::get().to(get_high_risk_users))
        )
        // JIT Training
        .service(
            web::scope("/orange-team/jit")
                .route("/pending", web::get().to(get_pending_jit))
                .route("/complete/{id}", web::post().to(complete_jit_assignment))
                .route("/triggers", web::get().to(list_jit_triggers))
                .route("/triggers", web::post().to(create_jit_trigger))
        )
        // Compliance Training
        .service(
            web::scope("/orange-team/compliance")
                .route("/status", web::get().to(get_compliance_status))
                .route("/overview", web::get().to(get_compliance_overview))
                .route("/overdue", web::get().to(get_overdue_users))
        )
        // Certificates
        .service(
            web::scope("/orange-team/certificates")
                .route("", web::get().to(get_my_certificates))
                .route("/verify", web::post().to(verify_certificate))
        )
        // Admin endpoints
        .service(
            web::scope("/orange-team/admin")
                .route("/courses", web::post().to(create_course))
                .route("/badges", web::post().to(create_badge))
                .route("/challenges", web::post().to(create_challenge))
        );
}
