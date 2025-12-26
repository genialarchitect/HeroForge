//! Orange Team core types for Security Awareness & Training

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Training course category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CourseCategory {
    #[default]
    SecurityFundamentals,
    PhishingAwareness,
    PasswordSecurity,
    SocialEngineering,
    DataProtection,
    IncidentReporting,
    ComplianceSpecific,
    SecureDevelopment,
    MobileSecuirty,
    RemoteWorkSecurity,
    InsiderThreats,
    PhysicalSecurity,
}

impl std::fmt::Display for CourseCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CourseCategory::SecurityFundamentals => write!(f, "Security Fundamentals"),
            CourseCategory::PhishingAwareness => write!(f, "Phishing Awareness"),
            CourseCategory::PasswordSecurity => write!(f, "Password Security"),
            CourseCategory::SocialEngineering => write!(f, "Social Engineering"),
            CourseCategory::DataProtection => write!(f, "Data Protection"),
            CourseCategory::IncidentReporting => write!(f, "Incident Reporting"),
            CourseCategory::ComplianceSpecific => write!(f, "Compliance Specific"),
            CourseCategory::SecureDevelopment => write!(f, "Secure Development"),
            CourseCategory::MobileSecuirty => write!(f, "Mobile Security"),
            CourseCategory::RemoteWorkSecurity => write!(f, "Remote Work Security"),
            CourseCategory::InsiderThreats => write!(f, "Insider Threats"),
            CourseCategory::PhysicalSecurity => write!(f, "Physical Security"),
        }
    }
}

/// Course difficulty level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Difficulty {
    #[default]
    Beginner,
    Intermediate,
    Advanced,
    Expert,
}

impl std::fmt::Display for Difficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Difficulty::Beginner => write!(f, "Beginner"),
            Difficulty::Intermediate => write!(f, "Intermediate"),
            Difficulty::Advanced => write!(f, "Advanced"),
            Difficulty::Expert => write!(f, "Expert"),
        }
    }
}

/// Training content type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    #[default]
    Video,
    Interactive,
    Text,
    Simulation,
    Quiz,
    Game,
    Podcast,
    Infographic,
}

impl std::fmt::Display for ContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentType::Video => write!(f, "Video"),
            ContentType::Interactive => write!(f, "Interactive"),
            ContentType::Text => write!(f, "Text"),
            ContentType::Simulation => write!(f, "Simulation"),
            ContentType::Quiz => write!(f, "Quiz"),
            ContentType::Game => write!(f, "Game"),
            ContentType::Podcast => write!(f, "Podcast"),
            ContentType::Infographic => write!(f, "Infographic"),
        }
    }
}

/// Enrollment status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentStatus {
    #[default]
    Enrolled,
    InProgress,
    Completed,
    Failed,
    Expired,
}

impl std::fmt::Display for EnrollmentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollmentStatus::Enrolled => write!(f, "Enrolled"),
            EnrollmentStatus::InProgress => write!(f, "In Progress"),
            EnrollmentStatus::Completed => write!(f, "Completed"),
            EnrollmentStatus::Failed => write!(f, "Failed"),
            EnrollmentStatus::Expired => write!(f, "Expired"),
        }
    }
}

/// Training course
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingCourse {
    pub id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub category: CourseCategory,
    pub difficulty: Difficulty,
    pub duration_minutes: u32,
    pub passing_score: u32,
    pub points_value: u32,
    pub badge_id: Option<Uuid>,
    pub is_mandatory: bool,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Default for TrainingCourse {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            title: String::new(),
            description: None,
            category: CourseCategory::default(),
            difficulty: Difficulty::default(),
            duration_minutes: 30,
            passing_score: 80,
            points_value: 100,
            badge_id: None,
            is_mandatory: false,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

/// Training module within a course
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingModule {
    pub id: Uuid,
    pub course_id: Uuid,
    pub title: String,
    pub content_type: ContentType,
    pub content_data: serde_json::Value,
    pub order_index: u32,
    pub duration_minutes: u32,
    pub created_at: DateTime<Utc>,
}

impl Default for TrainingModule {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            course_id: Uuid::nil(),
            title: String::new(),
            content_type: ContentType::default(),
            content_data: serde_json::Value::Null,
            order_index: 0,
            duration_minutes: 10,
            created_at: Utc::now(),
        }
    }
}

/// Question type for quizzes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum QuestionType {
    #[default]
    SingleChoice,
    MultipleChoice,
    TrueFalse,
    FillInBlank,
    Matching,
    Ordering,
}

/// Quiz question
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuizQuestion {
    pub id: Uuid,
    pub question: String,
    pub question_type: QuestionType,
    pub options: Vec<QuizOption>,
    pub correct_answer_ids: Vec<Uuid>,
    pub explanation: Option<String>,
    pub points: u32,
}

impl Default for QuizQuestion {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            question: String::new(),
            question_type: QuestionType::default(),
            options: Vec::new(),
            correct_answer_ids: Vec::new(),
            explanation: None,
            points: 10,
        }
    }
}

/// Quiz option/answer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuizOption {
    pub id: Uuid,
    pub text: String,
    pub is_correct: bool,
}

impl Default for QuizOption {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            text: String::new(),
            is_correct: false,
        }
    }
}

/// Training quiz
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingQuiz {
    pub id: Uuid,
    pub course_id: Uuid,
    pub title: String,
    pub questions: Vec<QuizQuestion>,
    pub time_limit_minutes: Option<u32>,
    pub randomize_questions: bool,
    pub show_correct_answers: bool,
    pub created_at: DateTime<Utc>,
}

impl Default for TrainingQuiz {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            course_id: Uuid::nil(),
            title: String::new(),
            questions: Vec::new(),
            time_limit_minutes: None,
            randomize_questions: true,
            show_correct_answers: true,
            created_at: Utc::now(),
        }
    }
}

/// User enrollment in a course
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingEnrollment {
    pub id: Uuid,
    pub user_id: Uuid,
    pub course_id: Uuid,
    pub status: EnrollmentStatus,
    pub progress_percent: u32,
    pub quiz_score: Option<u32>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub certificate_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

impl Default for TrainingEnrollment {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(),
            course_id: Uuid::nil(),
            status: EnrollmentStatus::default(),
            progress_percent: 0,
            quiz_score: None,
            started_at: None,
            completed_at: None,
            certificate_id: None,
            created_at: Utc::now(),
        }
    }
}

/// Training certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingCertificate {
    pub id: Uuid,
    pub user_id: Uuid,
    pub course_id: Uuid,
    pub certificate_number: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub pdf_path: Option<String>,
}

impl Default for TrainingCertificate {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(),
            course_id: Uuid::nil(),
            certificate_number: format!("CERT-{}", Uuid::new_v4().to_string().split('-').next().unwrap_or("000000")),
            issued_at: Utc::now(),
            expires_at: None,
            pdf_path: None,
        }
    }
}

/// Badge rarity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BadgeRarity {
    #[default]
    Common,
    Uncommon,
    Rare,
    Epic,
    Legendary,
}

impl std::fmt::Display for BadgeRarity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BadgeRarity::Common => write!(f, "Common"),
            BadgeRarity::Uncommon => write!(f, "Uncommon"),
            BadgeRarity::Rare => write!(f, "Rare"),
            BadgeRarity::Epic => write!(f, "Epic"),
            BadgeRarity::Legendary => write!(f, "Legendary"),
        }
    }
}

/// Badge category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BadgeCategory {
    #[default]
    Completion,
    Achievement,
    Streak,
    Special,
    Milestone,
    Challenge,
}

/// Training badge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingBadge {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub icon_url: Option<String>,
    pub category: BadgeCategory,
    pub points_required: Option<u32>,
    pub criteria: serde_json::Value,
    pub rarity: BadgeRarity,
    pub created_at: DateTime<Utc>,
}

impl Default for TrainingBadge {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: String::new(),
            description: String::new(),
            icon_url: None,
            category: BadgeCategory::default(),
            points_required: None,
            criteria: serde_json::Value::Null,
            rarity: BadgeRarity::default(),
            created_at: Utc::now(),
        }
    }
}

/// User badge earned
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBadge {
    pub id: Uuid,
    pub user_id: Uuid,
    pub badge_id: Uuid,
    pub earned_at: DateTime<Utc>,
}

impl Default for UserBadge {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(),
            badge_id: Uuid::nil(),
            earned_at: Utc::now(),
        }
    }
}

/// User gamification profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GamificationProfile {
    pub user_id: Uuid,
    pub points: u32,
    pub level: u32,
    pub streak_days: u32,
    pub badges: Vec<TrainingBadge>,
    pub rank: u32,
    pub next_level_points: u32,
    pub last_activity_at: Option<DateTime<Utc>>,
}

impl Default for GamificationProfile {
    fn default() -> Self {
        Self {
            user_id: Uuid::nil(),
            points: 0,
            level: 1,
            streak_days: 0,
            badges: Vec::new(),
            rank: 0,
            next_level_points: 100,
            last_activity_at: None,
        }
    }
}

/// Point transaction reason
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PointReason {
    #[default]
    CourseCompleted,
    QuizPassed,
    ModuleCompleted,
    ChallengeWon,
    StreakBonus,
    FirstLogin,
    ProfileComplete,
    BadgeEarned,
    ReferralBonus,
    PhishingReported,
}

/// Point transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointTransaction {
    pub id: Uuid,
    pub user_id: Uuid,
    pub points: i32,
    pub reason: PointReason,
    pub reference_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

impl Default for PointTransaction {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(),
            points: 0,
            reason: PointReason::default(),
            reference_id: None,
            created_at: Utc::now(),
        }
    }
}

/// Challenge type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    #[default]
    Ctf,
    Quiz,
    Simulation,
    Hunt,
    Puzzle,
    SpeedRun,
}

/// Security challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityChallenge {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub challenge_type: ChallengeType,
    pub difficulty: Difficulty,
    pub points_reward: u32,
    pub time_limit_minutes: Option<u32>,
    pub max_attempts: Option<u32>,
    pub content: serde_json::Value,
    pub solution_hash: Option<String>,
    pub is_active: bool,
    pub starts_at: Option<DateTime<Utc>>,
    pub ends_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl Default for SecurityChallenge {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            title: String::new(),
            description: String::new(),
            challenge_type: ChallengeType::default(),
            difficulty: Difficulty::default(),
            points_reward: 100,
            time_limit_minutes: None,
            max_attempts: None,
            content: serde_json::Value::Null,
            solution_hash: None,
            is_active: true,
            starts_at: None,
            ends_at: None,
            created_at: Utc::now(),
        }
    }
}

/// Challenge attempt status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeAttemptStatus {
    #[default]
    Attempted,
    Completed,
    Failed,
    TimedOut,
}

/// Challenge attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeAttempt {
    pub id: Uuid,
    pub user_id: Uuid,
    pub challenge_id: Uuid,
    pub status: ChallengeAttemptStatus,
    pub score: Option<u32>,
    pub time_spent_seconds: Option<u32>,
    pub attempts_count: u32,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl Default for ChallengeAttempt {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(),
            challenge_id: Uuid::nil(),
            status: ChallengeAttemptStatus::default(),
            score: None,
            time_spent_seconds: None,
            attempts_count: 1,
            completed_at: None,
            created_at: Utc::now(),
        }
    }
}

/// Risk level for phishing susceptibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::High => write!(f, "High"),
            RiskLevel::Critical => write!(f, "Critical"),
        }
    }
}

/// Phishing susceptibility score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingSusceptibility {
    pub id: Uuid,
    pub user_id: Uuid,
    pub score: f64,
    pub click_rate: f64,
    pub report_rate: f64,
    pub training_completion_rate: f64,
    pub last_phished_at: Option<DateTime<Utc>>,
    pub last_trained_at: Option<DateTime<Utc>>,
    pub risk_level: RiskLevel,
    pub updated_at: DateTime<Utc>,
}

impl Default for PhishingSusceptibility {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(),
            score: 0.0,
            click_rate: 0.0,
            report_rate: 0.0,
            training_completion_rate: 0.0,
            last_phished_at: None,
            last_trained_at: None,
            risk_level: RiskLevel::default(),
            updated_at: Utc::now(),
        }
    }
}

/// Department phishing statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepartmentPhishingStats {
    pub id: Uuid,
    pub department: String,
    pub user_count: u32,
    pub avg_susceptibility: f64,
    pub total_clicks: u32,
    pub total_reports: u32,
    pub campaigns_count: u32,
    pub risk_level: RiskLevel,
    pub updated_at: DateTime<Utc>,
}

impl Default for DepartmentPhishingStats {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            department: String::new(),
            user_count: 0,
            avg_susceptibility: 0.0,
            total_clicks: 0,
            total_reports: 0,
            campaigns_count: 0,
            risk_level: RiskLevel::default(),
            updated_at: Utc::now(),
        }
    }
}

/// JIT training trigger type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum JitTriggerType {
    #[default]
    PhishingClick,
    PolicyViolation,
    FailedQuiz,
    SecurityIncident,
    SuspiciousLogin,
    DataExposure,
    ComplianceGap,
}

impl std::fmt::Display for JitTriggerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JitTriggerType::PhishingClick => write!(f, "Phishing Click"),
            JitTriggerType::PolicyViolation => write!(f, "Policy Violation"),
            JitTriggerType::FailedQuiz => write!(f, "Failed Quiz"),
            JitTriggerType::SecurityIncident => write!(f, "Security Incident"),
            JitTriggerType::SuspiciousLogin => write!(f, "Suspicious Login"),
            JitTriggerType::DataExposure => write!(f, "Data Exposure"),
            JitTriggerType::ComplianceGap => write!(f, "Compliance Gap"),
        }
    }
}

/// JIT training trigger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitTrainingTrigger {
    pub id: Uuid,
    pub name: String,
    pub trigger_type: JitTriggerType,
    pub training_module_id: Uuid,
    pub delay_minutes: u32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl Default for JitTrainingTrigger {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: String::new(),
            trigger_type: JitTriggerType::default(),
            training_module_id: Uuid::nil(),
            delay_minutes: 0,
            is_active: true,
            created_at: Utc::now(),
        }
    }
}

/// JIT training assignment status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum JitAssignmentStatus {
    #[default]
    Assigned,
    InProgress,
    Completed,
    Overdue,
    Dismissed,
}

/// JIT training assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitTrainingAssignment {
    pub id: Uuid,
    pub user_id: Uuid,
    pub trigger_id: Uuid,
    pub training_module_id: Uuid,
    pub trigger_event_id: Option<Uuid>,
    pub status: JitAssignmentStatus,
    pub assigned_at: DateTime<Utc>,
    pub due_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl Default for JitTrainingAssignment {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(),
            trigger_id: Uuid::nil(),
            training_module_id: Uuid::nil(),
            trigger_event_id: None,
            status: JitAssignmentStatus::default(),
            assigned_at: Utc::now(),
            due_at: None,
            completed_at: None,
        }
    }
}

/// Compliance training status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceTrainingStatus {
    #[default]
    Pending,
    InProgress,
    Compliant,
    Overdue,
    Exempt,
}

impl std::fmt::Display for ComplianceTrainingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceTrainingStatus::Pending => write!(f, "Pending"),
            ComplianceTrainingStatus::InProgress => write!(f, "In Progress"),
            ComplianceTrainingStatus::Compliant => write!(f, "Compliant"),
            ComplianceTrainingStatus::Overdue => write!(f, "Overdue"),
            ComplianceTrainingStatus::Exempt => write!(f, "Exempt"),
        }
    }
}

/// Compliance framework for training
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    #[default]
    PciDss,
    Hipaa,
    Gdpr,
    Sox,
    Nist,
    Iso27001,
    Fedramp,
    Cmmc,
    Custom,
}

impl std::fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceFramework::PciDss => write!(f, "PCI-DSS"),
            ComplianceFramework::Hipaa => write!(f, "HIPAA"),
            ComplianceFramework::Gdpr => write!(f, "GDPR"),
            ComplianceFramework::Sox => write!(f, "SOX"),
            ComplianceFramework::Nist => write!(f, "NIST"),
            ComplianceFramework::Iso27001 => write!(f, "ISO 27001"),
            ComplianceFramework::Fedramp => write!(f, "FedRAMP"),
            ComplianceFramework::Cmmc => write!(f, "CMMC"),
            ComplianceFramework::Custom => write!(f, "Custom"),
        }
    }
}

/// Compliance training requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceTrainingRequirement {
    pub id: Uuid,
    pub name: String,
    pub framework: ComplianceFramework,
    pub required_courses: Vec<Uuid>,
    pub recurrence_months: u32,
    pub grace_period_days: u32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl Default for ComplianceTrainingRequirement {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: String::new(),
            framework: ComplianceFramework::default(),
            required_courses: Vec::new(),
            recurrence_months: 12,
            grace_period_days: 30,
            is_active: true,
            created_at: Utc::now(),
        }
    }
}

/// User compliance training status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceTrainingUserStatus {
    pub id: Uuid,
    pub user_id: Uuid,
    pub requirement_id: Uuid,
    pub status: ComplianceTrainingStatus,
    pub due_date: NaiveDate,
    pub completed_at: Option<DateTime<Utc>>,
    pub next_due_date: Option<NaiveDate>,
    pub created_at: DateTime<Utc>,
}

impl Default for ComplianceTrainingUserStatus {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(),
            requirement_id: Uuid::nil(),
            status: ComplianceTrainingStatus::default(),
            due_date: Utc::now().date_naive(),
            completed_at: None,
            next_due_date: None,
            created_at: Utc::now(),
        }
    }
}

/// Leaderboard entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderboardEntry {
    pub rank: u32,
    pub user_id: Uuid,
    pub username: String,
    pub points: u32,
    pub level: u32,
    pub badges_count: u32,
    pub streak_days: u32,
}

/// Training dashboard summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingDashboard {
    pub total_courses: u32,
    pub active_enrollments: u32,
    pub completed_courses: u32,
    pub average_score: f64,
    pub total_points: u32,
    pub badges_earned: u32,
    pub current_streak: u32,
    pub compliance_status: ComplianceTrainingStatus,
    pub pending_jit_training: u32,
    pub recent_activity: Vec<TrainingActivity>,
}

impl Default for TrainingDashboard {
    fn default() -> Self {
        Self {
            total_courses: 0,
            active_enrollments: 0,
            completed_courses: 0,
            average_score: 0.0,
            total_points: 0,
            badges_earned: 0,
            current_streak: 0,
            compliance_status: ComplianceTrainingStatus::default(),
            pending_jit_training: 0,
            recent_activity: Vec::new(),
        }
    }
}

/// Training activity log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingActivity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub activity_type: TrainingActivityType,
    pub description: String,
    pub points_earned: Option<i32>,
    pub created_at: DateTime<Utc>,
}

/// Training activity type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrainingActivityType {
    #[default]
    CourseStarted,
    CourseCompleted,
    ModuleCompleted,
    QuizCompleted,
    BadgeEarned,
    ChallengeCompleted,
    LevelUp,
    StreakAchieved,
}

impl std::fmt::Display for TrainingActivityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrainingActivityType::CourseStarted => write!(f, "Course Started"),
            TrainingActivityType::CourseCompleted => write!(f, "Course Completed"),
            TrainingActivityType::ModuleCompleted => write!(f, "Module Completed"),
            TrainingActivityType::QuizCompleted => write!(f, "Quiz Completed"),
            TrainingActivityType::BadgeEarned => write!(f, "Badge Earned"),
            TrainingActivityType::ChallengeCompleted => write!(f, "Challenge Completed"),
            TrainingActivityType::LevelUp => write!(f, "Level Up"),
            TrainingActivityType::StreakAchieved => write!(f, "Streak Achieved"),
        }
    }
}

impl Default for TrainingActivity {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: Uuid::nil(),
            activity_type: TrainingActivityType::default(),
            description: String::new(),
            points_earned: None,
            created_at: Utc::now(),
        }
    }
}
