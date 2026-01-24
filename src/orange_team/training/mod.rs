//! Training module - Course and module management with SQLite persistence

pub mod courses;
pub mod modules;
pub mod quizzes;
pub mod certificates;

pub use courses::*;
pub use modules::*;
pub use quizzes::*;
pub use certificates::*;

use crate::orange_team::types::*;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

/// Training service with SQLite persistence
pub struct TrainingService {
    pool: SqlitePool,
}

impl TrainingService {
    /// Create a new training service with database persistence
    pub async fn new(pool: SqlitePool) -> Self {
        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS training_courses (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                category TEXT NOT NULL,
                difficulty TEXT NOT NULL,
                duration_minutes INTEGER NOT NULL DEFAULT 30,
                passing_score INTEGER NOT NULL DEFAULT 80,
                points_value INTEGER NOT NULL DEFAULT 100,
                badge_id TEXT,
                is_mandatory INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"
        ).execute(&pool).await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS training_enrollments (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                course_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'enrolled',
                progress_percent INTEGER NOT NULL DEFAULT 0,
                quiz_score INTEGER,
                started_at TEXT,
                completed_at TEXT,
                certificate_id TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (course_id) REFERENCES training_courses(id)
            )"
        ).execute(&pool).await;

        Self { pool }
    }

    /// Add a course to the system
    pub async fn add_course(&self, course: TrainingCourse) -> Result<(), String> {
        sqlx::query(
            "INSERT OR REPLACE INTO training_courses (id, title, description, category, difficulty, duration_minutes, passing_score, points_value, badge_id, is_mandatory, is_active, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"
        )
        .bind(course.id.to_string())
        .bind(&course.title)
        .bind(&course.description)
        .bind(course.category.to_string())
        .bind(course.difficulty.to_string())
        .bind(course.duration_minutes as i32)
        .bind(course.passing_score as i32)
        .bind(course.points_value as i32)
        .bind(course.badge_id.map(|b| b.to_string()))
        .bind(course.is_mandatory)
        .bind(course.is_active)
        .bind(course.created_at.to_rfc3339())
        .bind(course.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;
        Ok(())
    }

    /// Get all active courses
    pub async fn get_active_courses(&self) -> Vec<TrainingCourse> {
        let rows = sqlx::query_as::<_, CourseRow>(
            "SELECT id, title, description, category, difficulty, duration_minutes, passing_score, points_value, badge_id, is_mandatory, is_active, created_at, updated_at
             FROM training_courses WHERE is_active = 1 ORDER BY title"
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter().filter_map(|r| r.into_course().ok()).collect()
    }

    /// Get courses by category
    pub async fn get_courses_by_category(&self, category: CourseCategory) -> Vec<TrainingCourse> {
        let rows = sqlx::query_as::<_, CourseRow>(
            "SELECT id, title, description, category, difficulty, duration_minutes, passing_score, points_value, badge_id, is_mandatory, is_active, created_at, updated_at
             FROM training_courses WHERE category = ?1 AND is_active = 1 ORDER BY title"
        )
        .bind(category.to_string())
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter().filter_map(|r| r.into_course().ok()).collect()
    }

    /// Enroll a user in a course
    pub async fn enroll_user(&self, user_id: Uuid, course_id: Uuid) -> Result<TrainingEnrollment, String> {
        let enrollment = TrainingEnrollment {
            id: Uuid::new_v4(),
            user_id,
            course_id,
            status: EnrollmentStatus::Enrolled,
            progress_percent: 0,
            quiz_score: None,
            started_at: None,
            completed_at: None,
            certificate_id: None,
            created_at: Utc::now(),
        };

        sqlx::query(
            "INSERT INTO training_enrollments (id, user_id, course_id, status, progress_percent, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )
        .bind(enrollment.id.to_string())
        .bind(user_id.to_string())
        .bind(course_id.to_string())
        .bind("enrolled")
        .bind(0i32)
        .bind(enrollment.created_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        Ok(enrollment)
    }

    /// Get user enrollments
    pub async fn get_user_enrollments(&self, user_id: Uuid) -> Vec<TrainingEnrollment> {
        let rows = sqlx::query_as::<_, EnrollmentRow>(
            "SELECT id, user_id, course_id, status, progress_percent, quiz_score, started_at, completed_at, certificate_id, created_at
             FROM training_enrollments WHERE user_id = ?1 ORDER BY created_at DESC"
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter().filter_map(|r| r.into_enrollment().ok()).collect()
    }

    /// Update enrollment progress
    pub async fn update_progress(&self, enrollment_id: Uuid, progress: u32) -> Option<TrainingEnrollment> {
        let clamped = progress.min(100);
        let now = Utc::now();

        let status = if clamped >= 100 { "completed" } else { "in_progress" };
        let completed_at = if clamped >= 100 { Some(now.to_rfc3339()) } else { None };

        // Set started_at if not already set
        let _ = sqlx::query(
            "UPDATE training_enrollments SET
                progress_percent = ?1,
                status = ?2,
                started_at = COALESCE(started_at, ?3),
                completed_at = COALESCE(?4, completed_at)
             WHERE id = ?5"
        )
        .bind(clamped as i32)
        .bind(status)
        .bind(now.to_rfc3339())
        .bind(&completed_at)
        .bind(enrollment_id.to_string())
        .execute(&self.pool)
        .await;

        // Fetch and return the updated enrollment
        let row = sqlx::query_as::<_, EnrollmentRow>(
            "SELECT id, user_id, course_id, status, progress_percent, quiz_score, started_at, completed_at, certificate_id, created_at
             FROM training_enrollments WHERE id = ?1"
        )
        .bind(enrollment_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()?;

        row.into_enrollment().ok()
    }

    /// Complete a course with quiz score
    pub async fn complete_course(
        &self,
        enrollment_id: Uuid,
        quiz_score: u32,
        passing_score: u32,
    ) -> Option<TrainingEnrollment> {
        let now = Utc::now();
        let status = if quiz_score >= passing_score { "completed" } else { "failed" };

        let _ = sqlx::query(
            "UPDATE training_enrollments SET
                quiz_score = ?1,
                completed_at = ?2,
                progress_percent = 100,
                status = ?3
             WHERE id = ?4"
        )
        .bind(quiz_score as i32)
        .bind(now.to_rfc3339())
        .bind(status)
        .bind(enrollment_id.to_string())
        .execute(&self.pool)
        .await;

        let row = sqlx::query_as::<_, EnrollmentRow>(
            "SELECT id, user_id, course_id, status, progress_percent, quiz_score, started_at, completed_at, certificate_id, created_at
             FROM training_enrollments WHERE id = ?1"
        )
        .bind(enrollment_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()?;

        row.into_enrollment().ok()
    }

    /// Get mandatory courses
    pub async fn get_mandatory_courses(&self) -> Vec<TrainingCourse> {
        let rows = sqlx::query_as::<_, CourseRow>(
            "SELECT id, title, description, category, difficulty, duration_minutes, passing_score, points_value, badge_id, is_mandatory, is_active, created_at, updated_at
             FROM training_courses WHERE is_mandatory = 1 AND is_active = 1"
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter().filter_map(|r| r.into_course().ok()).collect()
    }

    /// Check if user has completed all mandatory courses
    pub async fn has_completed_mandatory(&self, user_id: Uuid) -> bool {
        let mandatory_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM training_courses WHERE is_mandatory = 1 AND is_active = 1"
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);

        if mandatory_count == 0 {
            return true;
        }

        let completed_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT e.course_id) FROM training_enrollments e
             JOIN training_courses c ON e.course_id = c.id
             WHERE e.user_id = ?1 AND e.status = 'completed' AND c.is_mandatory = 1 AND c.is_active = 1"
        )
        .bind(user_id.to_string())
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);

        completed_count >= mandatory_count
    }

    /// Calculate user's average quiz score
    pub async fn get_average_score(&self, user_id: Uuid) -> Option<f64> {
        let avg: Option<f64> = sqlx::query_scalar(
            "SELECT AVG(CAST(quiz_score AS REAL)) FROM training_enrollments
             WHERE user_id = ?1 AND quiz_score IS NOT NULL"
        )
        .bind(user_id.to_string())
        .fetch_one(&self.pool)
        .await
        .ok()?;

        avg
    }
}

// --- Database row types ---

#[derive(sqlx::FromRow)]
struct CourseRow {
    id: String,
    title: String,
    description: Option<String>,
    category: String,
    difficulty: String,
    duration_minutes: i32,
    passing_score: i32,
    points_value: i32,
    badge_id: Option<String>,
    is_mandatory: bool,
    is_active: bool,
    created_at: String,
    updated_at: String,
}

impl CourseRow {
    fn into_course(self) -> Result<TrainingCourse, String> {
        let id = Uuid::parse_str(&self.id).map_err(|e| e.to_string())?;
        let badge_id = self.badge_id.as_ref().and_then(|s| Uuid::parse_str(s).ok());
        let created_at = chrono::DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now());
        let updated_at = chrono::DateTime::parse_from_rfc3339(&self.updated_at)
            .map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now());

        Ok(TrainingCourse {
            id,
            title: self.title,
            description: self.description,
            category: parse_course_category(&self.category),
            difficulty: parse_difficulty(&self.difficulty),
            duration_minutes: self.duration_minutes as u32,
            passing_score: self.passing_score as u32,
            points_value: self.points_value as u32,
            badge_id,
            is_mandatory: self.is_mandatory,
            is_active: self.is_active,
            created_at,
            updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct EnrollmentRow {
    id: String,
    user_id: String,
    course_id: String,
    status: String,
    progress_percent: i32,
    quiz_score: Option<i32>,
    started_at: Option<String>,
    completed_at: Option<String>,
    certificate_id: Option<String>,
    created_at: String,
}

impl EnrollmentRow {
    fn into_enrollment(self) -> Result<TrainingEnrollment, String> {
        Ok(TrainingEnrollment {
            id: Uuid::parse_str(&self.id).map_err(|e| e.to_string())?,
            user_id: Uuid::parse_str(&self.user_id).map_err(|e| e.to_string())?,
            course_id: Uuid::parse_str(&self.course_id).map_err(|e| e.to_string())?,
            status: parse_enrollment_status(&self.status),
            progress_percent: self.progress_percent as u32,
            quiz_score: self.quiz_score.map(|s| s as u32),
            started_at: self.started_at.as_ref().and_then(|s|
                chrono::DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc))),
            completed_at: self.completed_at.as_ref().and_then(|s|
                chrono::DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc))),
            certificate_id: self.certificate_id.as_ref().and_then(|s| Uuid::parse_str(s).ok()),
            created_at: chrono::DateTime::parse_from_rfc3339(&self.created_at)
                .map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
        })
    }
}

fn parse_course_category(s: &str) -> CourseCategory {
    match s {
        "Security Fundamentals" => CourseCategory::SecurityFundamentals,
        "Phishing Awareness" => CourseCategory::PhishingAwareness,
        "Password Security" => CourseCategory::PasswordSecurity,
        "Social Engineering" => CourseCategory::SocialEngineering,
        "Data Protection" => CourseCategory::DataProtection,
        "Incident Reporting" => CourseCategory::IncidentReporting,
        "Compliance Specific" => CourseCategory::ComplianceSpecific,
        "Secure Development" => CourseCategory::SecureDevelopment,
        "Mobile Security" => CourseCategory::MobileSecuirty,
        "Remote Work Security" => CourseCategory::RemoteWorkSecurity,
        "Insider Threats" => CourseCategory::InsiderThreats,
        "Physical Security" => CourseCategory::PhysicalSecurity,
        _ => CourseCategory::SecurityFundamentals,
    }
}

fn parse_difficulty(s: &str) -> Difficulty {
    match s {
        "Beginner" => Difficulty::Beginner,
        "Intermediate" => Difficulty::Intermediate,
        "Advanced" => Difficulty::Advanced,
        "Expert" => Difficulty::Expert,
        _ => Difficulty::Beginner,
    }
}

fn parse_enrollment_status(s: &str) -> EnrollmentStatus {
    match s {
        "enrolled" => EnrollmentStatus::Enrolled,
        "in_progress" => EnrollmentStatus::InProgress,
        "completed" => EnrollmentStatus::Completed,
        "failed" => EnrollmentStatus::Failed,
        "expired" => EnrollmentStatus::Expired,
        _ => EnrollmentStatus::Enrolled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup() -> TrainingService {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        TrainingService::new(pool).await
    }

    #[tokio::test]
    async fn test_enroll_user() {
        let service = setup().await;
        let user_id = Uuid::new_v4();
        let course_id = Uuid::new_v4();

        // Add course first
        let course = TrainingCourse {
            id: course_id,
            title: "Test Course".to_string(),
            ..TrainingCourse::default()
        };
        service.add_course(course).await.unwrap();

        let enrollment = service.enroll_user(user_id, course_id).await.unwrap();
        assert_eq!(enrollment.user_id, user_id);
        assert_eq!(enrollment.course_id, course_id);
        assert_eq!(enrollment.status, EnrollmentStatus::Enrolled);
        assert_eq!(enrollment.progress_percent, 0);
    }

    #[tokio::test]
    async fn test_update_progress() {
        let service = setup().await;
        let user_id = Uuid::new_v4();
        let course_id = Uuid::new_v4();

        let course = TrainingCourse {
            id: course_id,
            title: "Progress Test".to_string(),
            ..TrainingCourse::default()
        };
        service.add_course(course).await.unwrap();

        let enrollment = service.enroll_user(user_id, course_id).await.unwrap();
        let enrollment_id = enrollment.id;

        let updated = service.update_progress(enrollment_id, 50).await.unwrap();
        assert_eq!(updated.progress_percent, 50);
        assert_eq!(updated.status, EnrollmentStatus::InProgress);
    }

    #[tokio::test]
    async fn test_complete_course() {
        let service = setup().await;
        let user_id = Uuid::new_v4();
        let course_id = Uuid::new_v4();

        let course = TrainingCourse {
            id: course_id,
            title: "Complete Test".to_string(),
            passing_score: 70,
            ..TrainingCourse::default()
        };
        service.add_course(course).await.unwrap();

        let enrollment = service.enroll_user(user_id, course_id).await.unwrap();
        let completed = service.complete_course(enrollment.id, 85, 70).await.unwrap();
        assert_eq!(completed.status, EnrollmentStatus::Completed);
        assert_eq!(completed.quiz_score, Some(85));
    }

    #[tokio::test]
    async fn test_mandatory_courses() {
        let service = setup().await;
        let user_id = Uuid::new_v4();

        let course = TrainingCourse {
            id: Uuid::new_v4(),
            title: "Mandatory Course".to_string(),
            is_mandatory: true,
            ..TrainingCourse::default()
        };
        let course_id = course.id;
        service.add_course(course).await.unwrap();

        assert!(!service.has_completed_mandatory(user_id).await);

        let enrollment = service.enroll_user(user_id, course_id).await.unwrap();
        service.complete_course(enrollment.id, 90, 80).await;

        assert!(service.has_completed_mandatory(user_id).await);
    }

    #[tokio::test]
    async fn test_average_score() {
        let service = setup().await;
        let user_id = Uuid::new_v4();

        let c1 = Uuid::new_v4();
        let c2 = Uuid::new_v4();
        service.add_course(TrainingCourse { id: c1, title: "C1".to_string(), ..TrainingCourse::default() }).await.unwrap();
        service.add_course(TrainingCourse { id: c2, title: "C2".to_string(), ..TrainingCourse::default() }).await.unwrap();

        let e1 = service.enroll_user(user_id, c1).await.unwrap();
        let e2 = service.enroll_user(user_id, c2).await.unwrap();

        service.complete_course(e1.id, 80, 70).await;
        service.complete_course(e2.id, 90, 70).await;

        let avg = service.get_average_score(user_id).await.unwrap();
        assert!((avg - 85.0).abs() < 0.1);
    }
}
