//! Course management

use crate::orange_team::types::*;
use chrono::Utc;
use uuid::Uuid;

/// Course manager for creating and managing training courses
pub struct CourseManager {
    courses: Vec<TrainingCourse>,
}

impl CourseManager {
    /// Create a new course manager
    pub fn new() -> Self {
        Self {
            courses: Vec::new(),
        }
    }

    /// Create a new course
    pub fn create_course(&mut self, title: &str, category: CourseCategory, difficulty: Difficulty) -> TrainingCourse {
        let course = TrainingCourse {
            id: Uuid::new_v4(),
            title: title.to_string(),
            description: None,
            category,
            difficulty,
            duration_minutes: 30,
            passing_score: 80,
            points_value: 100,
            badge_id: None,
            is_mandatory: false,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        self.courses.push(course.clone());
        course
    }

    /// Get a course by ID
    pub fn get_course(&self, id: Uuid) -> Option<&TrainingCourse> {
        self.courses.iter().find(|c| c.id == id)
    }

    /// Update course details
    pub fn update_course(&mut self, id: Uuid, title: Option<&str>, description: Option<&str>) -> Option<&TrainingCourse> {
        if let Some(course) = self.courses.iter_mut().find(|c| c.id == id) {
            if let Some(t) = title {
                course.title = t.to_string();
            }
            if let Some(d) = description {
                course.description = Some(d.to_string());
            }
            course.updated_at = Utc::now();
            return Some(course);
        }
        None
    }

    /// Deactivate a course
    pub fn deactivate_course(&mut self, id: Uuid) -> bool {
        if let Some(course) = self.courses.iter_mut().find(|c| c.id == id) {
            course.is_active = false;
            course.updated_at = Utc::now();
            return true;
        }
        false
    }

    /// Get all courses
    pub fn get_all_courses(&self) -> &[TrainingCourse] {
        &self.courses
    }

    /// Search courses by title
    pub fn search_courses(&self, query: &str) -> Vec<&TrainingCourse> {
        let query_lower = query.to_lowercase();
        self.courses
            .iter()
            .filter(|c| c.title.to_lowercase().contains(&query_lower))
            .collect()
    }
}

impl Default for CourseManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Create default security awareness courses
pub fn create_default_courses() -> Vec<TrainingCourse> {
    vec![
        TrainingCourse {
            id: Uuid::new_v4(),
            title: "Security Fundamentals 101".to_string(),
            description: Some("Introduction to information security concepts and best practices".to_string()),
            category: CourseCategory::SecurityFundamentals,
            difficulty: Difficulty::Beginner,
            duration_minutes: 45,
            passing_score: 80,
            points_value: 100,
            badge_id: None,
            is_mandatory: true,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        TrainingCourse {
            id: Uuid::new_v4(),
            title: "Phishing Awareness".to_string(),
            description: Some("Learn to identify and avoid phishing attacks".to_string()),
            category: CourseCategory::PhishingAwareness,
            difficulty: Difficulty::Beginner,
            duration_minutes: 30,
            passing_score: 85,
            points_value: 150,
            badge_id: None,
            is_mandatory: true,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        TrainingCourse {
            id: Uuid::new_v4(),
            title: "Password Security Best Practices".to_string(),
            description: Some("Creating and managing secure passwords".to_string()),
            category: CourseCategory::PasswordSecurity,
            difficulty: Difficulty::Beginner,
            duration_minutes: 20,
            passing_score: 80,
            points_value: 75,
            badge_id: None,
            is_mandatory: true,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        TrainingCourse {
            id: Uuid::new_v4(),
            title: "Social Engineering Defense".to_string(),
            description: Some("Recognizing and defending against social engineering attacks".to_string()),
            category: CourseCategory::SocialEngineering,
            difficulty: Difficulty::Intermediate,
            duration_minutes: 45,
            passing_score: 80,
            points_value: 200,
            badge_id: None,
            is_mandatory: false,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        TrainingCourse {
            id: Uuid::new_v4(),
            title: "Data Protection and Privacy".to_string(),
            description: Some("Handling sensitive data and ensuring privacy compliance".to_string()),
            category: CourseCategory::DataProtection,
            difficulty: Difficulty::Intermediate,
            duration_minutes: 60,
            passing_score: 80,
            points_value: 250,
            badge_id: None,
            is_mandatory: false,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ]
}
