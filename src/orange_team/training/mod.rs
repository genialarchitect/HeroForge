//! Training module - Course and module management

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
use uuid::Uuid;

/// Training service for managing courses and enrollments
pub struct TrainingService {
    courses: Vec<TrainingCourse>,
    enrollments: Vec<TrainingEnrollment>,
}

impl TrainingService {
    /// Create a new training service
    pub fn new() -> Self {
        Self {
            courses: Vec::new(),
            enrollments: Vec::new(),
        }
    }

    /// Get all active courses
    pub fn get_active_courses(&self) -> Vec<&TrainingCourse> {
        self.courses.iter().filter(|c| c.is_active).collect()
    }

    /// Get courses by category
    pub fn get_courses_by_category(&self, category: CourseCategory) -> Vec<&TrainingCourse> {
        self.courses
            .iter()
            .filter(|c| c.category == category && c.is_active)
            .collect()
    }

    /// Enroll a user in a course
    pub fn enroll_user(&mut self, user_id: Uuid, course_id: Uuid) -> TrainingEnrollment {
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

        self.enrollments.push(enrollment.clone());
        enrollment
    }

    /// Get user enrollments
    pub fn get_user_enrollments(&self, user_id: Uuid) -> Vec<&TrainingEnrollment> {
        self.enrollments
            .iter()
            .filter(|e| e.user_id == user_id)
            .collect()
    }

    /// Update enrollment progress
    pub fn update_progress(&mut self, enrollment_id: Uuid, progress: u32) -> Option<&TrainingEnrollment> {
        if let Some(enrollment) = self.enrollments.iter_mut().find(|e| e.id == enrollment_id) {
            enrollment.progress_percent = progress.min(100);

            if enrollment.started_at.is_none() {
                enrollment.started_at = Some(Utc::now());
                enrollment.status = EnrollmentStatus::InProgress;
            }

            if progress >= 100 {
                enrollment.status = EnrollmentStatus::Completed;
                enrollment.completed_at = Some(Utc::now());
            }

            return Some(enrollment);
        }
        None
    }

    /// Complete a course with quiz score
    pub fn complete_course(
        &mut self,
        enrollment_id: Uuid,
        quiz_score: u32,
        passing_score: u32,
    ) -> Option<&TrainingEnrollment> {
        if let Some(enrollment) = self.enrollments.iter_mut().find(|e| e.id == enrollment_id) {
            enrollment.quiz_score = Some(quiz_score);
            enrollment.completed_at = Some(Utc::now());
            enrollment.progress_percent = 100;

            if quiz_score >= passing_score {
                enrollment.status = EnrollmentStatus::Completed;
            } else {
                enrollment.status = EnrollmentStatus::Failed;
            }

            return Some(enrollment);
        }
        None
    }

    /// Get mandatory courses for a user
    pub fn get_mandatory_courses(&self) -> Vec<&TrainingCourse> {
        self.courses
            .iter()
            .filter(|c| c.is_mandatory && c.is_active)
            .collect()
    }

    /// Check if user has completed all mandatory courses
    pub fn has_completed_mandatory(&self, user_id: Uuid) -> bool {
        let mandatory_ids: Vec<Uuid> = self
            .courses
            .iter()
            .filter(|c| c.is_mandatory && c.is_active)
            .map(|c| c.id)
            .collect();

        let completed_ids: Vec<Uuid> = self
            .enrollments
            .iter()
            .filter(|e| {
                e.user_id == user_id && e.status == EnrollmentStatus::Completed
            })
            .map(|e| e.course_id)
            .collect();

        mandatory_ids.iter().all(|id| completed_ids.contains(id))
    }

    /// Calculate user's average quiz score
    pub fn get_average_score(&self, user_id: Uuid) -> Option<f64> {
        let scores: Vec<u32> = self
            .enrollments
            .iter()
            .filter(|e| e.user_id == user_id && e.quiz_score.is_some())
            .filter_map(|e| e.quiz_score)
            .collect();

        if scores.is_empty() {
            None
        } else {
            Some(scores.iter().sum::<u32>() as f64 / scores.len() as f64)
        }
    }
}

impl Default for TrainingService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enroll_user() {
        let mut service = TrainingService::new();
        let user_id = Uuid::new_v4();
        let course_id = Uuid::new_v4();

        let enrollment = service.enroll_user(user_id, course_id);

        assert_eq!(enrollment.user_id, user_id);
        assert_eq!(enrollment.course_id, course_id);
        assert_eq!(enrollment.status, EnrollmentStatus::Enrolled);
        assert_eq!(enrollment.progress_percent, 0);
    }

    #[test]
    fn test_update_progress() {
        let mut service = TrainingService::new();
        let user_id = Uuid::new_v4();
        let course_id = Uuid::new_v4();

        let enrollment = service.enroll_user(user_id, course_id);
        let enrollment_id = enrollment.id;

        service.update_progress(enrollment_id, 50);

        let enrollments = service.get_user_enrollments(user_id);
        assert_eq!(enrollments.len(), 1);
        assert_eq!(enrollments[0].progress_percent, 50);
        assert_eq!(enrollments[0].status, EnrollmentStatus::InProgress);
    }
}
