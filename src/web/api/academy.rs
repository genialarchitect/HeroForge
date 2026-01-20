//! Academy LMS API routes
//!
//! This module provides API endpoints for the HeroForge Academy:
//! - Public routes for marketing (no auth required)
//! - Authenticated routes for enrolled users
//! - Admin routes for content management

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::academy;
use crate::web::auth::Claims;

// ============================================================================
// Request/Response Types
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

#[derive(Debug, Serialize)]
struct LearningPathPublic {
    id: String,
    slug: String,
    title: String,
    description: Option<String>,
    level: String,
    duration_hours: i32,
    price_cents: i32,
    icon: Option<String>,
    color: Option<String>,
    certificate_name: Option<String>,
    display_order: i32,
    module_count: i32,
    lesson_count: i32,
}

#[derive(Debug, Serialize)]
struct PathDetailPublic {
    #[serde(flatten)]
    path: LearningPathPublic,
    modules: Vec<ModulePublic>,
}

#[derive(Debug, Serialize)]
struct ModulePublic {
    id: String,
    slug: String,
    title: String,
    description: Option<String>,
    duration_minutes: i32,
    display_order: i32,
    is_assessment: bool,
    lesson_count: i32,
}

#[derive(Debug, Serialize)]
struct PathWithUserProgress {
    #[serde(flatten)]
    path: LearningPathPublic,
    enrolled: bool,
    enrollment_status: Option<String>,
    progress_percent: f32,
    completed_lessons: i32,
    total_lessons: i32,
}

#[derive(Debug, Serialize)]
struct ModuleWithUserProgress {
    #[serde(flatten)]
    module: ModulePublic,
    lessons: Vec<LessonWithUserProgress>,
    progress_percent: f32,
    completed_lessons: i32,
    is_unlocked: bool,
}

#[derive(Debug, Serialize)]
struct LessonWithUserProgress {
    id: String,
    slug: String,
    title: String,
    description: Option<String>,
    lesson_type: String,
    duration_minutes: i32,
    display_order: i32,
    is_preview: bool,
    status: String,
    video_timestamp_seconds: i32,
    completed_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct LessonDetail {
    id: String,
    module_id: String,
    slug: String,
    title: String,
    description: Option<String>,
    lesson_type: String,
    content: serde_json::Value,
    duration_minutes: i32,
    display_order: i32,
    is_preview: bool,
    chapters: Vec<academy::VideoChapter>,
    questions: Option<Vec<QuizQuestionForUser>>,
    status: String,
    video_timestamp_seconds: i32,
    user_note: Option<String>,
}

#[derive(Debug, Serialize)]
struct QuizQuestionForUser {
    id: String,
    question_type: String,
    question_text: String,
    options: serde_json::Value,
    points: i32,
    display_order: i32,
}

#[derive(Debug, Deserialize)]
struct UpdateProgressRequest {
    video_timestamp_seconds: Option<i32>,
    time_spent_seconds: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateNoteRequest {
    pub content: String,
}

#[derive(Debug, Deserialize)]
struct VerifyCertificateRequest {
    certificate_number: String,
}

#[derive(Debug, Serialize)]
struct CertificateVerification {
    valid: bool,
    certificate: Option<CertificatePublic>,
    path: Option<LearningPathPublic>,
    holder_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct CertificatePublic {
    id: String,
    certificate_number: String,
    issued_at: String,
    expires_at: Option<String>,
}

// ============================================================================
// Public Routes (no auth required)
// ============================================================================

/// GET /api/academy/public/paths
/// List all active learning paths (for marketing)
pub async fn list_public_paths(
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    match academy::list_learning_paths(&pool, true).await {
        Ok(paths) => {
            let mut public_paths = Vec::new();
            for path in paths {
                let modules = academy::list_modules_for_path(&pool, &path.id).await.unwrap_or_default();
                let mut lesson_count = 0;
                for module in &modules {
                    let lessons = academy::list_lessons_for_module(&pool, &module.id).await.unwrap_or_default();
                    lesson_count += lessons.len() as i32;
                }
                public_paths.push(LearningPathPublic {
                    id: path.id,
                    slug: path.slug,
                    title: path.title,
                    description: path.description,
                    level: path.level,
                    duration_hours: path.duration_hours,
                    price_cents: path.price_cents,
                    icon: path.icon,
                    color: path.color,
                    certificate_name: path.certificate_name,
                    display_order: path.display_order,
                    module_count: modules.len() as i32,
                    lesson_count,
                });
            }
            HttpResponse::Ok().json(ApiResponse::success(public_paths))
        }
        Err(e) => {
            log::error!("Failed to list paths: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to list paths"))
        }
    }
}

/// GET /api/academy/public/paths/{slug}
/// Get path preview with module list (for marketing)
pub async fn get_public_path(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let slug = path.into_inner();

    match academy::get_learning_path_by_slug(&pool, &slug).await {
        Ok(Some(path)) => {
            let modules = academy::list_modules_for_path(&pool, &path.id).await.unwrap_or_default();
            let mut public_modules = Vec::new();
            let mut total_lessons = 0;

            for module in modules {
                let lessons = academy::list_lessons_for_module(&pool, &module.id).await.unwrap_or_default();
                let lesson_count = lessons.len() as i32;
                total_lessons += lesson_count;
                public_modules.push(ModulePublic {
                    id: module.id,
                    slug: module.slug,
                    title: module.title,
                    description: module.description,
                    duration_minutes: module.duration_minutes,
                    display_order: module.display_order,
                    is_assessment: module.is_assessment,
                    lesson_count,
                });
            }

            let detail = PathDetailPublic {
                path: LearningPathPublic {
                    id: path.id,
                    slug: path.slug,
                    title: path.title,
                    description: path.description,
                    level: path.level,
                    duration_hours: path.duration_hours,
                    price_cents: path.price_cents,
                    icon: path.icon,
                    color: path.color,
                    certificate_name: path.certificate_name,
                    display_order: path.display_order,
                    module_count: public_modules.len() as i32,
                    lesson_count: total_lessons,
                },
                modules: public_modules,
            };

            HttpResponse::Ok().json(ApiResponse::success(detail))
        }
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error("Path not found")),
        Err(e) => {
            log::error!("Failed to get path: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get path"))
        }
    }
}

/// POST /api/academy/public/certificates/verify
/// Verify certificate by number
pub async fn verify_certificate(
    pool: web::Data<SqlitePool>,
    req: web::Json<VerifyCertificateRequest>,
) -> HttpResponse {
    match academy::verify_certificate(&pool, &req.certificate_number).await {
        Ok(Some((cert, path, username))) => {
            let verification = CertificateVerification {
                valid: true,
                certificate: Some(CertificatePublic {
                    id: cert.id,
                    certificate_number: cert.certificate_number,
                    issued_at: cert.issued_at,
                    expires_at: cert.expires_at,
                }),
                path: Some(LearningPathPublic {
                    id: path.id,
                    slug: path.slug,
                    title: path.title,
                    description: path.description,
                    level: path.level,
                    duration_hours: path.duration_hours,
                    price_cents: path.price_cents,
                    icon: path.icon,
                    color: path.color,
                    certificate_name: path.certificate_name,
                    display_order: path.display_order,
                    module_count: 0,
                    lesson_count: 0,
                }),
                holder_name: Some(username),
            };
            HttpResponse::Ok().json(ApiResponse::success(verification))
        }
        Ok(None) => {
            let verification = CertificateVerification {
                valid: false,
                certificate: None,
                path: None,
                holder_name: None,
            };
            HttpResponse::Ok().json(ApiResponse::success(verification))
        }
        Err(e) => {
            log::error!("Failed to verify certificate: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to verify certificate"))
        }
    }
}

// ============================================================================
// Authenticated Routes
// ============================================================================

/// Helper to extract user ID from JWT claims
fn get_user_id(req: &HttpRequest) -> Option<String> {
    req.extensions().get::<Claims>().map(|c| c.sub.clone())
}

/// GET /api/academy/paths
/// List paths with user enrollment status
pub async fn list_paths_with_progress(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
) -> HttpResponse {
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    match academy::get_user_academy_progress(&pool, &user_id).await {
        Ok(progress) => {
            let paths: Vec<PathWithUserProgress> = progress.paths.iter().map(|p| {
                let modules = academy::list_modules_for_path(&pool, &p.path.id);
                PathWithUserProgress {
                    path: LearningPathPublic {
                        id: p.path.id.clone(),
                        slug: p.path.slug.clone(),
                        title: p.path.title.clone(),
                        description: p.path.description.clone(),
                        level: p.path.level.clone(),
                        duration_hours: p.path.duration_hours,
                        price_cents: p.path.price_cents,
                        icon: p.path.icon.clone(),
                        color: p.path.color.clone(),
                        certificate_name: p.path.certificate_name.clone(),
                        display_order: p.path.display_order,
                        module_count: 0,
                        lesson_count: p.total_lessons,
                    },
                    enrolled: p.enrolled,
                    enrollment_status: p.enrollment_status.clone(),
                    progress_percent: p.progress_percent,
                    completed_lessons: p.completed_lessons,
                    total_lessons: p.total_lessons,
                }
            }).collect();
            HttpResponse::Ok().json(ApiResponse::success(paths))
        }
        Err(e) => {
            log::error!("Failed to get user progress: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get paths"))
        }
    }
}

/// GET /api/academy/paths/{slug}
/// Full path detail with user progress
pub async fn get_path_with_progress(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let slug = path.into_inner();
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    let learning_path = match academy::get_learning_path_by_slug(&pool, &slug).await {
        Ok(Some(p)) => p,
        Ok(None) => return HttpResponse::NotFound().json(ApiResponse::<()>::error("Path not found")),
        Err(e) => {
            log::error!("Failed to get path: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get path"));
        }
    };

    let enrollment = academy::get_enrollment(&pool, &user_id, &learning_path.id).await.unwrap_or(None);
    let path_progress = academy::get_user_progress_for_path(&pool, &user_id, &learning_path.id).await.unwrap_or_else(|_| academy::PathProgress {
        learning_path_id: learning_path.id.clone(),
        completed_modules: 0,
        total_modules: 0,
        completed_lessons: 0,
        total_lessons: 0,
        progress_percent: 0.0,
        total_time_spent_seconds: 0,
        last_accessed_at: None,
    });

    let modules = academy::list_modules_for_path(&pool, &learning_path.id).await.unwrap_or_default();
    let mut modules_with_progress = Vec::new();
    let mut prev_module_completed = true;

    for module in modules {
        let lessons = academy::list_lessons_for_module(&pool, &module.id).await.unwrap_or_default();
        let mut lessons_with_progress = Vec::new();
        let mut completed_count = 0;

        for lesson in &lessons {
            let progress = academy::get_lesson_progress(&pool, &user_id, &lesson.id).await.unwrap_or(None);
            let status = progress.as_ref().map(|p| p.status.clone()).unwrap_or_else(|| "not_started".to_string());
            let timestamp = progress.as_ref().map(|p| p.video_timestamp_seconds).unwrap_or(0);
            let completed_at = progress.as_ref().and_then(|p| p.completed_at.clone());

            if status == "completed" {
                completed_count += 1;
            }

            lessons_with_progress.push(LessonWithUserProgress {
                id: lesson.id.clone(),
                slug: lesson.slug.clone(),
                title: lesson.title.clone(),
                description: lesson.description.clone(),
                lesson_type: lesson.lesson_type.clone(),
                duration_minutes: lesson.duration_minutes,
                display_order: lesson.display_order,
                is_preview: lesson.is_preview,
                status,
                video_timestamp_seconds: timestamp,
                completed_at,
            });
        }

        let module_progress = if lessons.is_empty() { 0.0 } else { (completed_count as f32 / lessons.len() as f32) * 100.0 };
        let is_unlocked = enrollment.is_some() && prev_module_completed;

        modules_with_progress.push(ModuleWithUserProgress {
            module: ModulePublic {
                id: module.id.clone(),
                slug: module.slug.clone(),
                title: module.title.clone(),
                description: module.description.clone(),
                duration_minutes: module.duration_minutes,
                display_order: module.display_order,
                is_assessment: module.is_assessment,
                lesson_count: lessons.len() as i32,
            },
            lessons: lessons_with_progress,
            progress_percent: module_progress,
            completed_lessons: completed_count,
            is_unlocked,
        });

        prev_module_completed = completed_count == lessons.len() as i32;
    }

    #[derive(Serialize)]
    struct FullPathDetail {
        #[serde(flatten)]
        path: LearningPathPublic,
        enrolled: bool,
        enrollment_status: Option<String>,
        progress: academy::PathProgress,
        modules: Vec<ModuleWithUserProgress>,
    }

    let detail = FullPathDetail {
        path: LearningPathPublic {
            id: learning_path.id,
            slug: learning_path.slug,
            title: learning_path.title,
            description: learning_path.description,
            level: learning_path.level,
            duration_hours: learning_path.duration_hours,
            price_cents: learning_path.price_cents,
            icon: learning_path.icon,
            color: learning_path.color,
            certificate_name: learning_path.certificate_name,
            display_order: learning_path.display_order,
            module_count: modules_with_progress.len() as i32,
            lesson_count: path_progress.total_lessons,
        },
        enrolled: enrollment.is_some(),
        enrollment_status: enrollment.map(|e| e.status),
        progress: path_progress,
        modules: modules_with_progress,
    };

    HttpResponse::Ok().json(ApiResponse::success(detail))
}

/// POST /api/academy/paths/{slug}/enroll
/// Enroll in a path
pub async fn enroll_in_path(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let slug = path.into_inner();
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    let learning_path = match academy::get_learning_path_by_slug(&pool, &slug).await {
        Ok(Some(p)) => p,
        Ok(None) => return HttpResponse::NotFound().json(ApiResponse::<()>::error("Path not found")),
        Err(e) => {
            log::error!("Failed to get path: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get path"));
        }
    };

    // Check if already enrolled
    if let Ok(Some(existing)) = academy::get_enrollment(&pool, &user_id, &learning_path.id).await {
        if existing.status != "expired" {
            return HttpResponse::Ok().json(ApiResponse::success(existing));
        }
    }

    // For paid paths, we'd check payment here (skipped for now - all free)
    // if learning_path.price_cents > 0 { ... }

    match academy::enroll_user(&pool, &user_id, &learning_path.id).await {
        Ok(enrollment) => HttpResponse::Ok().json(ApiResponse::success(enrollment)),
        Err(e) => {
            log::error!("Failed to enroll: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to enroll"))
        }
    }
}

/// GET /api/academy/paths/{slug}/progress
/// Get detailed progress for a path
pub async fn get_path_progress(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let slug = path.into_inner();
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    let learning_path = match academy::get_learning_path_by_slug(&pool, &slug).await {
        Ok(Some(p)) => p,
        Ok(None) => return HttpResponse::NotFound().json(ApiResponse::<()>::error("Path not found")),
        Err(e) => {
            log::error!("Failed to get path: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get path"));
        }
    };

    match academy::get_user_progress_for_path(&pool, &user_id, &learning_path.id).await {
        Ok(progress) => HttpResponse::Ok().json(ApiResponse::success(progress)),
        Err(e) => {
            log::error!("Failed to get progress: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get progress"))
        }
    }
}

/// GET /api/academy/modules/{id}
/// Get module detail
pub async fn get_module(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let module_id = path.into_inner();

    match academy::get_module_by_id(&pool, &module_id).await {
        Ok(Some(module)) => {
            let lessons = academy::list_lessons_for_module(&pool, &module.id).await.unwrap_or_default();
            let detail = ModulePublic {
                id: module.id,
                slug: module.slug,
                title: module.title,
                description: module.description,
                duration_minutes: module.duration_minutes,
                display_order: module.display_order,
                is_assessment: module.is_assessment,
                lesson_count: lessons.len() as i32,
            };
            HttpResponse::Ok().json(ApiResponse::success(detail))
        }
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error("Module not found")),
        Err(e) => {
            log::error!("Failed to get module: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get module"))
        }
    }
}

/// GET /api/academy/modules/{id}/lessons
/// List lessons in module
pub async fn list_module_lessons(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let module_id = path.into_inner();
    let user_id = get_user_id(&req);

    let lessons = match academy::list_lessons_for_module(&pool, &module_id).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("Failed to list lessons: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to list lessons"));
        }
    };

    let mut result = Vec::new();
    for lesson in lessons {
        let (status, timestamp, completed_at) = if let Some(ref uid) = user_id {
            if let Ok(Some(progress)) = academy::get_lesson_progress(&pool, uid, &lesson.id).await {
                (progress.status, progress.video_timestamp_seconds, progress.completed_at)
            } else {
                ("not_started".to_string(), 0, None)
            }
        } else {
            ("not_started".to_string(), 0, None)
        };

        result.push(LessonWithUserProgress {
            id: lesson.id,
            slug: lesson.slug,
            title: lesson.title,
            description: lesson.description,
            lesson_type: lesson.lesson_type,
            duration_minutes: lesson.duration_minutes,
            display_order: lesson.display_order,
            is_preview: lesson.is_preview,
            status,
            video_timestamp_seconds: timestamp,
            completed_at,
        });
    }

    HttpResponse::Ok().json(ApiResponse::success(result))
}

/// GET /api/academy/lessons/{id}
/// Get lesson content (requires enrollment unless preview)
pub async fn get_lesson(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let lesson_id = path.into_inner();
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    let lesson = match academy::get_lesson_by_id(&pool, &lesson_id).await {
        Ok(Some(l)) => l,
        Ok(None) => return HttpResponse::NotFound().json(ApiResponse::<()>::error("Lesson not found")),
        Err(e) => {
            log::error!("Failed to get lesson: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get lesson"));
        }
    };

    // Get module and path to check enrollment
    let module = match academy::get_module_by_id(&pool, &lesson.module_id).await {
        Ok(Some(m)) => m,
        Ok(None) => return HttpResponse::NotFound().json(ApiResponse::<()>::error("Module not found")),
        Err(e) => {
            log::error!("Failed to get module: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get module"));
        }
    };

    // Check enrollment (unless preview)
    if !lesson.is_preview {
        let enrollment = academy::get_enrollment(&pool, &user_id, &module.learning_path_id).await.unwrap_or(None);
        if enrollment.is_none() {
            return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Enrollment required"));
        }
    }

    // Get progress
    let progress = academy::get_lesson_progress(&pool, &user_id, &lesson.id).await.unwrap_or(None);
    let status = progress.as_ref().map(|p| p.status.clone()).unwrap_or_else(|| "not_started".to_string());
    let timestamp = progress.as_ref().map(|p| p.video_timestamp_seconds).unwrap_or(0);

    // Get chapters
    let chapters = academy::get_video_chapters(&pool, &lesson.id).await.unwrap_or_default();

    // Get note
    let note = academy::get_user_note(&pool, &user_id, &lesson.id).await.unwrap_or(None);

    // Parse content
    let content: serde_json::Value = serde_json::from_str(&lesson.content_json).unwrap_or(serde_json::json!({}));

    // Get quiz questions if quiz lesson (without correct answers)
    let questions = if lesson.lesson_type == "quiz" {
        let qs = academy::get_quiz_questions(&pool, &lesson.id).await.unwrap_or_default();
        Some(qs.into_iter().map(|q| {
            let data: serde_json::Value = serde_json::from_str(&q.question_data_json).unwrap_or(serde_json::json!({}));
            let options = data.get("options").cloned().unwrap_or(serde_json::json!([]));
            QuizQuestionForUser {
                id: q.id,
                question_type: q.question_type,
                question_text: q.question_text,
                options,
                points: q.points,
                display_order: q.display_order,
            }
        }).collect())
    } else {
        None
    };

    let detail = LessonDetail {
        id: lesson.id,
        module_id: lesson.module_id,
        slug: lesson.slug,
        title: lesson.title,
        description: lesson.description,
        lesson_type: lesson.lesson_type,
        content,
        duration_minutes: lesson.duration_minutes,
        display_order: lesson.display_order,
        is_preview: lesson.is_preview,
        chapters,
        questions,
        status,
        video_timestamp_seconds: timestamp,
        user_note: note.map(|n| n.content),
    };

    HttpResponse::Ok().json(ApiResponse::success(detail))
}

/// POST /api/academy/lessons/{id}/progress
/// Update lesson progress (video timestamp, time spent)
pub async fn update_lesson_progress(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
    body: web::Json<UpdateProgressRequest>,
) -> HttpResponse {
    let lesson_id = path.into_inner();
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    match academy::update_lesson_progress(&pool, &user_id, &lesson_id, academy::UpdateLessonProgressRequest {
        video_timestamp_seconds: body.video_timestamp_seconds,
        time_spent_seconds: body.time_spent_seconds,
    }).await {
        Ok(progress) => HttpResponse::Ok().json(ApiResponse::success(progress)),
        Err(e) => {
            log::error!("Failed to update progress: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to update progress"))
        }
    }
}

/// POST /api/academy/lessons/{id}/complete
/// Mark lesson as complete
pub async fn complete_lesson(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let lesson_id = path.into_inner();
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    // Get lesson to find path
    let lesson = match academy::get_lesson_by_id(&pool, &lesson_id).await {
        Ok(Some(l)) => l,
        Ok(None) => return HttpResponse::NotFound().json(ApiResponse::<()>::error("Lesson not found")),
        Err(e) => {
            log::error!("Failed to get lesson: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get lesson"));
        }
    };

    match academy::complete_lesson(&pool, &user_id, &lesson_id).await {
        Ok(progress) => {
            // Check if path is complete and issue certificate
            let module = academy::get_module_by_id(&pool, &lesson.module_id).await.ok().flatten();
            if let Some(module) = module {
                if let Ok(Some(cert)) = academy::check_and_issue_certificate(&pool, &user_id, &module.learning_path_id).await {
                    #[derive(Serialize)]
                    struct CompletionResult {
                        progress: academy::LessonProgress,
                        certificate_issued: bool,
                        certificate: Option<CertificatePublic>,
                    }
                    return HttpResponse::Ok().json(ApiResponse::success(CompletionResult {
                        progress,
                        certificate_issued: true,
                        certificate: Some(CertificatePublic {
                            id: cert.id,
                            certificate_number: cert.certificate_number,
                            issued_at: cert.issued_at,
                            expires_at: cert.expires_at,
                        }),
                    }));
                }
            }

            #[derive(Serialize)]
            struct CompletionResult {
                progress: academy::LessonProgress,
                certificate_issued: bool,
                certificate: Option<CertificatePublic>,
            }
            HttpResponse::Ok().json(ApiResponse::success(CompletionResult {
                progress,
                certificate_issued: false,
                certificate: None,
            }))
        }
        Err(e) => {
            log::error!("Failed to complete lesson: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to complete lesson"))
        }
    }
}

/// GET /api/academy/lessons/{id}/notes
/// Get user notes for lesson
pub async fn get_lesson_notes(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let lesson_id = path.into_inner();
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    match academy::get_user_note(&pool, &user_id, &lesson_id).await {
        Ok(note) => HttpResponse::Ok().json(ApiResponse::success(note)),
        Err(e) => {
            log::error!("Failed to get note: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get note"))
        }
    }
}

/// PUT /api/academy/lessons/{id}/notes
/// Update user notes for lesson
pub async fn update_lesson_notes(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
    body: web::Json<UpdateNoteRequest>,
) -> HttpResponse {
    let lesson_id = path.into_inner();
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    match academy::upsert_user_note(&pool, &user_id, &lesson_id, &body.content).await {
        Ok(note) => HttpResponse::Ok().json(ApiResponse::success(note)),
        Err(e) => {
            log::error!("Failed to update note: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to update note"))
        }
    }
}

/// GET /api/academy/quizzes/{lesson_id}
/// Get quiz questions
pub async fn get_quiz(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let lesson_id = path.into_inner();
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    // Verify lesson exists and is a quiz
    let lesson = match academy::get_lesson_by_id(&pool, &lesson_id).await {
        Ok(Some(l)) => l,
        Ok(None) => return HttpResponse::NotFound().json(ApiResponse::<()>::error("Lesson not found")),
        Err(e) => {
            log::error!("Failed to get lesson: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get lesson"));
        }
    };

    if lesson.lesson_type != "quiz" {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error("Lesson is not a quiz"));
    }

    let questions = match academy::get_quiz_questions(&pool, &lesson_id).await {
        Ok(q) => q,
        Err(e) => {
            log::error!("Failed to get questions: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get questions"));
        }
    };

    let content: serde_json::Value = serde_json::from_str(&lesson.content_json).unwrap_or(serde_json::json!({}));
    let pass_threshold = content.get("pass_threshold").and_then(|v| v.as_i64()).unwrap_or(70);
    let max_attempts = content.get("max_attempts").and_then(|v| v.as_i64()).unwrap_or(3);

    let user_questions: Vec<QuizQuestionForUser> = questions.into_iter().map(|q| {
        let data: serde_json::Value = serde_json::from_str(&q.question_data_json).unwrap_or(serde_json::json!({}));
        let options = data.get("options").cloned().unwrap_or(serde_json::json!([]));
        QuizQuestionForUser {
            id: q.id,
            question_type: q.question_type,
            question_text: q.question_text,
            options,
            points: q.points,
            display_order: q.display_order,
        }
    }).collect();

    #[derive(Serialize)]
    struct QuizData {
        lesson_id: String,
        lesson_title: String,
        pass_threshold: i64,
        max_attempts: i64,
        questions: Vec<QuizQuestionForUser>,
    }

    HttpResponse::Ok().json(ApiResponse::success(QuizData {
        lesson_id: lesson.id,
        lesson_title: lesson.title,
        pass_threshold,
        max_attempts,
        questions: user_questions,
    }))
}

/// POST /api/academy/quizzes/{lesson_id}/submit
/// Submit quiz answers
pub async fn submit_quiz(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
    body: web::Json<academy::SubmitQuizRequest>,
) -> HttpResponse {
    let lesson_id = path.into_inner();
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    // Check max attempts
    let attempts = academy::get_quiz_attempts(&pool, &user_id, &lesson_id).await.unwrap_or_default();
    let lesson = match academy::get_lesson_by_id(&pool, &lesson_id).await {
        Ok(Some(l)) => l,
        Ok(None) => return HttpResponse::NotFound().json(ApiResponse::<()>::error("Lesson not found")),
        Err(e) => {
            log::error!("Failed to get lesson: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get lesson"));
        }
    };

    let content: serde_json::Value = serde_json::from_str(&lesson.content_json).unwrap_or(serde_json::json!({}));
    let max_attempts = content.get("max_attempts").and_then(|v| v.as_i64()).unwrap_or(3) as usize;

    if attempts.len() >= max_attempts {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error("Maximum attempts reached"));
    }

    match academy::submit_quiz(&pool, &user_id, &lesson_id, body.into_inner()).await {
        Ok(result) => HttpResponse::Ok().json(ApiResponse::success(result)),
        Err(e) => {
            log::error!("Failed to submit quiz: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to submit quiz"))
        }
    }
}

/// GET /api/academy/quizzes/{lesson_id}/attempts
/// List user's quiz attempts
pub async fn get_quiz_attempts(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let lesson_id = path.into_inner();
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    match academy::get_quiz_attempts(&pool, &user_id, &lesson_id).await {
        Ok(attempts) => HttpResponse::Ok().json(ApiResponse::success(attempts)),
        Err(e) => {
            log::error!("Failed to get attempts: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get attempts"))
        }
    }
}

/// GET /api/academy/certificates
/// List user's certificates
pub async fn list_certificates(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
) -> HttpResponse {
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    match academy::list_user_certificates(&pool, &user_id).await {
        Ok(certs) => {
            let public_certs: Vec<_> = certs.into_iter().map(|c| CertificatePublic {
                id: c.id,
                certificate_number: c.certificate_number,
                issued_at: c.issued_at,
                expires_at: c.expires_at,
            }).collect();
            HttpResponse::Ok().json(ApiResponse::success(public_certs))
        }
        Err(e) => {
            log::error!("Failed to list certificates: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to list certificates"))
        }
    }
}

/// GET /api/academy/certificates/{id}
/// Get certificate detail
pub async fn get_certificate(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let cert_id = path.into_inner();
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    match academy::get_certificate_by_id(&pool, &cert_id).await {
        Ok(Some(cert)) => {
            if cert.user_id != user_id {
                return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Not your certificate"));
            }

            let path = academy::get_learning_path_by_id(&pool, &cert.learning_path_id).await.ok().flatten();

            #[derive(Serialize)]
            struct CertDetail {
                #[serde(flatten)]
                certificate: CertificatePublic,
                path: Option<LearningPathPublic>,
            }

            HttpResponse::Ok().json(ApiResponse::success(CertDetail {
                certificate: CertificatePublic {
                    id: cert.id,
                    certificate_number: cert.certificate_number,
                    issued_at: cert.issued_at,
                    expires_at: cert.expires_at,
                },
                path: path.map(|p| LearningPathPublic {
                    id: p.id,
                    slug: p.slug,
                    title: p.title,
                    description: p.description,
                    level: p.level,
                    duration_hours: p.duration_hours,
                    price_cents: p.price_cents,
                    icon: p.icon,
                    color: p.color,
                    certificate_name: p.certificate_name,
                    display_order: p.display_order,
                    module_count: 0,
                    lesson_count: 0,
                }),
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error("Certificate not found")),
        Err(e) => {
            log::error!("Failed to get certificate: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get certificate"))
        }
    }
}

/// GET /api/academy/my-progress
/// Overall academy progress
pub async fn get_my_progress(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
) -> HttpResponse {
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    match academy::get_user_academy_progress(&pool, &user_id).await {
        Ok(progress) => HttpResponse::Ok().json(ApiResponse::success(progress)),
        Err(e) => {
            log::error!("Failed to get progress: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get progress"))
        }
    }
}

/// GET /api/academy/certificates/{id}/download
/// Download certificate as PDF
pub async fn download_certificate(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let cert_id = path.into_inner();
    let user_id = match get_user_id(&req) {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Unauthorized")),
    };

    // Verify certificate belongs to user
    let cert = match academy::get_certificate_by_id(&pool, &cert_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return HttpResponse::NotFound().json(ApiResponse::<()>::error("Certificate not found")),
        Err(e) => {
            log::error!("Failed to get certificate: {}", e);
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to get certificate"));
        }
    };

    if cert.user_id != user_id {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Not your certificate"));
    }

    // Generate PDF
    match academy::generate_certificate_pdf(&pool, &cert_id).await {
        Ok(pdf_bytes) => {
            // Detect if it's PDF or HTML fallback
            let is_pdf = pdf_bytes.len() > 4 && &pdf_bytes[0..4] == b"%PDF";

            if is_pdf {
                HttpResponse::Ok()
                    .content_type("application/pdf")
                    .insert_header(("Content-Disposition", format!("attachment; filename=\"{}.pdf\"", cert.certificate_number)))
                    .body(pdf_bytes)
            } else {
                // Return HTML for client-side printing
                HttpResponse::Ok()
                    .content_type("text/html")
                    .insert_header(("Content-Disposition", format!("inline; filename=\"{}.html\"", cert.certificate_number)))
                    .body(pdf_bytes)
            }
        }
        Err(e) => {
            log::error!("Failed to generate certificate PDF: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to generate certificate"))
        }
    }
}

// ============================================================================
// Admin Routes
// ============================================================================

/// Helper to check if user is admin
fn is_admin(req: &HttpRequest) -> bool {
    if let Some(claims) = req.extensions().get::<Claims>() {
        return claims.roles.contains(&"admin".to_string());
    }
    false
}

// --- Learning Path Admin ---

/// POST /api/academy/admin/paths
/// Create learning path
pub async fn admin_create_path(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    body: web::Json<academy::CreateLearningPathRequest>,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    match academy::create_learning_path(&pool, body.into_inner()).await {
        Ok(path) => HttpResponse::Created().json(ApiResponse::success(path)),
        Err(e) => {
            log::error!("Failed to create path: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to create path"))
        }
    }
}

/// PUT /api/academy/admin/paths/{id}
/// Update learning path
pub async fn admin_update_path(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
    body: web::Json<academy::UpdateLearningPathRequest>,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    let path_id = path.into_inner();
    match academy::update_learning_path(&pool, &path_id, body.into_inner()).await {
        Ok(Some(updated)) => HttpResponse::Ok().json(ApiResponse::success(updated)),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error("Path not found")),
        Err(e) => {
            log::error!("Failed to update path: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to update path"))
        }
    }
}

/// DELETE /api/academy/admin/paths/{id}
/// Delete learning path
pub async fn admin_delete_path(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    let path_id = path.into_inner();
    match academy::delete_learning_path(&pool, &path_id).await {
        Ok(true) => HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({"deleted": true}))),
        Ok(false) => HttpResponse::NotFound().json(ApiResponse::<()>::error("Path not found")),
        Err(e) => {
            log::error!("Failed to delete path: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to delete path"))
        }
    }
}

// --- Module Admin ---

/// POST /api/academy/admin/modules
/// Create module
pub async fn admin_create_module(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    body: web::Json<academy::CreateModuleRequest>,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    match academy::create_module(&pool, body.into_inner()).await {
        Ok(module) => HttpResponse::Created().json(ApiResponse::success(module)),
        Err(e) => {
            log::error!("Failed to create module: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to create module"))
        }
    }
}

/// PUT /api/academy/admin/modules/{id}
/// Update module
pub async fn admin_update_module(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
    body: web::Json<academy::UpdateModuleRequest>,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    let module_id = path.into_inner();
    match academy::update_module(&pool, &module_id, body.into_inner()).await {
        Ok(Some(updated)) => HttpResponse::Ok().json(ApiResponse::success(updated)),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error("Module not found")),
        Err(e) => {
            log::error!("Failed to update module: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to update module"))
        }
    }
}

/// DELETE /api/academy/admin/modules/{id}
/// Delete module
pub async fn admin_delete_module(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    let module_id = path.into_inner();
    match academy::delete_module(&pool, &module_id).await {
        Ok(true) => HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({"deleted": true}))),
        Ok(false) => HttpResponse::NotFound().json(ApiResponse::<()>::error("Module not found")),
        Err(e) => {
            log::error!("Failed to delete module: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to delete module"))
        }
    }
}

// --- Lesson Admin ---

/// POST /api/academy/admin/lessons
/// Create lesson
pub async fn admin_create_lesson(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    body: web::Json<academy::CreateLessonRequest>,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    match academy::create_lesson(&pool, body.into_inner()).await {
        Ok(lesson) => HttpResponse::Created().json(ApiResponse::success(lesson)),
        Err(e) => {
            log::error!("Failed to create lesson: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to create lesson"))
        }
    }
}

/// PUT /api/academy/admin/lessons/{id}
/// Update lesson
pub async fn admin_update_lesson(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
    body: web::Json<academy::UpdateLessonRequest>,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    let lesson_id = path.into_inner();
    match academy::update_lesson(&pool, &lesson_id, body.into_inner()).await {
        Ok(Some(updated)) => HttpResponse::Ok().json(ApiResponse::success(updated)),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error("Lesson not found")),
        Err(e) => {
            log::error!("Failed to update lesson: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to update lesson"))
        }
    }
}

/// DELETE /api/academy/admin/lessons/{id}
/// Delete lesson
pub async fn admin_delete_lesson(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    let lesson_id = path.into_inner();
    match academy::delete_lesson(&pool, &lesson_id).await {
        Ok(true) => HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({"deleted": true}))),
        Ok(false) => HttpResponse::NotFound().json(ApiResponse::<()>::error("Lesson not found")),
        Err(e) => {
            log::error!("Failed to delete lesson: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to delete lesson"))
        }
    }
}

// --- Quiz Question Admin ---

/// GET /api/academy/admin/questions/{lesson_id}
/// List questions for a lesson
pub async fn admin_list_questions(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    let lesson_id = path.into_inner();
    match academy::get_quiz_questions(&pool, &lesson_id).await {
        Ok(questions) => HttpResponse::Ok().json(ApiResponse::success(questions)),
        Err(e) => {
            log::error!("Failed to list questions: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to list questions"))
        }
    }
}

/// POST /api/academy/admin/questions
/// Create quiz question
pub async fn admin_create_question(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    body: web::Json<academy::CreateQuizQuestionRequest>,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    match academy::create_quiz_question(&pool, body.into_inner()).await {
        Ok(question) => HttpResponse::Created().json(ApiResponse::success(question)),
        Err(e) => {
            log::error!("Failed to create question: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to create question"))
        }
    }
}

/// PUT /api/academy/admin/questions/{id}
/// Update quiz question
pub async fn admin_update_question(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
    body: web::Json<academy::UpdateQuizQuestionRequest>,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    let question_id = path.into_inner();
    match academy::update_quiz_question(&pool, &question_id, body.into_inner()).await {
        Ok(Some(updated)) => HttpResponse::Ok().json(ApiResponse::success(updated)),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error("Question not found")),
        Err(e) => {
            log::error!("Failed to update question: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to update question"))
        }
    }
}

/// DELETE /api/academy/admin/questions/{id}
/// Delete quiz question
pub async fn admin_delete_question(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    let question_id = path.into_inner();
    match academy::delete_quiz_question(&pool, &question_id).await {
        Ok(true) => HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({"deleted": true}))),
        Ok(false) => HttpResponse::NotFound().json(ApiResponse::<()>::error("Question not found")),
        Err(e) => {
            log::error!("Failed to delete question: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to delete question"))
        }
    }
}

// --- Video Chapter Admin ---

/// POST /api/academy/admin/chapters
/// Create video chapter
pub async fn admin_create_chapter(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    body: web::Json<academy::CreateVideoChapterRequest>,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    match academy::create_video_chapter(&pool, body.into_inner()).await {
        Ok(chapter) => HttpResponse::Created().json(ApiResponse::success(chapter)),
        Err(e) => {
            log::error!("Failed to create chapter: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to create chapter"))
        }
    }
}

/// PUT /api/academy/admin/chapters/{id}
/// Update video chapter
pub async fn admin_update_chapter(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
    body: web::Json<academy::UpdateVideoChapterRequest>,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    let chapter_id = path.into_inner();
    match academy::update_video_chapter(&pool, &chapter_id, body.into_inner()).await {
        Ok(Some(updated)) => HttpResponse::Ok().json(ApiResponse::success(updated)),
        Ok(None) => HttpResponse::NotFound().json(ApiResponse::<()>::error("Chapter not found")),
        Err(e) => {
            log::error!("Failed to update chapter: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to update chapter"))
        }
    }
}

/// DELETE /api/academy/admin/chapters/{id}
/// Delete video chapter
pub async fn admin_delete_chapter(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    if !is_admin(&req) {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Admin access required"));
    }

    let chapter_id = path.into_inner();
    match academy::delete_video_chapter(&pool, &chapter_id).await {
        Ok(true) => HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({"deleted": true}))),
        Ok(false) => HttpResponse::NotFound().json(ApiResponse::<()>::error("Chapter not found")),
        Err(e) => {
            log::error!("Failed to delete chapter: {}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to delete chapter"))
        }
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Academy routes (authenticated)
        .route("/academy/paths", web::get().to(list_paths_with_progress))
        .route("/academy/paths/{slug}", web::get().to(get_path_with_progress))
        .route("/academy/paths/{slug}/enroll", web::post().to(enroll_in_path))
        .route("/academy/paths/{slug}/progress", web::get().to(get_path_progress))
        .route("/academy/modules/{id}", web::get().to(get_module))
        .route("/academy/modules/{id}/lessons", web::get().to(list_module_lessons))
        .route("/academy/lessons/{id}", web::get().to(get_lesson))
        .route("/academy/lessons/{id}/progress", web::post().to(update_lesson_progress))
        .route("/academy/lessons/{id}/complete", web::post().to(complete_lesson))
        .route("/academy/lessons/{id}/notes", web::get().to(get_lesson_notes))
        .route("/academy/lessons/{id}/notes", web::put().to(update_lesson_notes))
        .route("/academy/quizzes/{lesson_id}", web::get().to(get_quiz))
        .route("/academy/quizzes/{lesson_id}/submit", web::post().to(submit_quiz))
        .route("/academy/quizzes/{lesson_id}/attempts", web::get().to(get_quiz_attempts))
        .route("/academy/certificates", web::get().to(list_certificates))
        .route("/academy/certificates/{id}", web::get().to(get_certificate))
        .route("/academy/certificates/{id}/download", web::get().to(download_certificate))
        .route("/academy/my-progress", web::get().to(get_my_progress));
}

pub fn configure_public(cfg: &mut web::ServiceConfig) {
    cfg
        // Public academy routes (no auth)
        .route("/academy/public/paths", web::get().to(list_public_paths))
        .route("/academy/public/paths/{slug}", web::get().to(get_public_path))
        .route("/academy/public/certificates/verify", web::post().to(verify_certificate));
}

pub fn configure_admin(cfg: &mut web::ServiceConfig) {
    cfg
        // Admin learning path routes
        .route("/academy/admin/paths", web::post().to(admin_create_path))
        .route("/academy/admin/paths/{id}", web::put().to(admin_update_path))
        .route("/academy/admin/paths/{id}", web::delete().to(admin_delete_path))
        // Admin module routes
        .route("/academy/admin/modules", web::post().to(admin_create_module))
        .route("/academy/admin/modules/{id}", web::put().to(admin_update_module))
        .route("/academy/admin/modules/{id}", web::delete().to(admin_delete_module))
        // Admin lesson routes
        .route("/academy/admin/lessons", web::post().to(admin_create_lesson))
        .route("/academy/admin/lessons/{id}", web::put().to(admin_update_lesson))
        .route("/academy/admin/lessons/{id}", web::delete().to(admin_delete_lesson))
        // Admin quiz question routes
        .route("/academy/admin/lessons/{lesson_id}/questions", web::get().to(admin_list_questions))
        .route("/academy/admin/questions", web::post().to(admin_create_question))
        .route("/academy/admin/questions/{id}", web::put().to(admin_update_question))
        .route("/academy/admin/questions/{id}", web::delete().to(admin_delete_question))
        // Admin video chapter routes
        .route("/academy/admin/chapters", web::post().to(admin_create_chapter))
        .route("/academy/admin/chapters/{id}", web::put().to(admin_update_chapter))
        .route("/academy/admin/chapters/{id}", web::delete().to(admin_delete_chapter));
}
