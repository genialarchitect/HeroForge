//! Academy LMS database operations
//!
//! This module provides all database operations for the HeroForge Academy:
//! - Learning paths (courses)
//! - Modules (sections within paths)
//! - Lessons (individual learning units)
//! - Video chapters
//! - Quiz questions
//! - User enrollments
//! - Lesson progress tracking
//! - Quiz attempts
//! - Certificates
//! - User notes

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LearningPath {
    pub id: String,
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
    pub level: String,
    pub duration_hours: i32,
    pub price_cents: i32,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub certificate_name: Option<String>,
    pub is_active: bool,
    pub display_order: i32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Module {
    pub id: String,
    pub learning_path_id: String,
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
    pub duration_minutes: i32,
    pub display_order: i32,
    pub prerequisite_module_id: Option<String>,
    pub is_assessment: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Lesson {
    pub id: String,
    pub module_id: String,
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
    pub lesson_type: String, // 'video', 'text', 'interactive', 'quiz'
    pub content_json: String,
    pub duration_minutes: i32,
    pub display_order: i32,
    pub is_preview: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VideoChapter {
    pub id: String,
    pub lesson_id: String,
    pub title: String,
    pub timestamp_seconds: i32,
    pub display_order: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct QuizQuestion {
    pub id: String,
    pub lesson_id: String,
    pub question_type: String, // 'multiple_choice', 'multiple_select', 'true_false', 'code_challenge'
    pub question_text: String,
    pub question_data_json: String,
    pub points: i32,
    pub explanation: Option<String>,
    pub display_order: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Enrollment {
    pub id: String,
    pub user_id: String,
    pub learning_path_id: String,
    pub status: String, // 'enrolled', 'in_progress', 'completed', 'expired'
    pub enrolled_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub expires_at: Option<String>,
    pub payment_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LessonProgress {
    pub id: String,
    pub user_id: String,
    pub lesson_id: String,
    pub status: String, // 'not_started', 'in_progress', 'completed'
    pub video_timestamp_seconds: i32,
    pub completed_at: Option<String>,
    pub time_spent_seconds: i32,
    pub last_accessed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct QuizAttempt {
    pub id: String,
    pub user_id: String,
    pub lesson_id: String,
    pub attempt_number: i32,
    pub answers_json: String,
    pub score_percent: i32,
    pub passed: bool,
    pub time_taken_seconds: Option<i32>,
    pub started_at: String,
    pub completed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Certificate {
    pub id: String,
    pub user_id: String,
    pub learning_path_id: String,
    pub certificate_number: String, // HFA-2026-XXXXX format
    pub issued_at: String,
    pub expires_at: Option<String>,
    pub pdf_path: Option<String>,
    pub verification_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserNote {
    pub id: String,
    pub user_id: String,
    pub lesson_id: String,
    pub content: String,
    pub created_at: String,
    pub updated_at: String,
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateLearningPathRequest {
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
    pub level: String,
    pub duration_hours: i32,
    pub price_cents: Option<i32>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub certificate_name: Option<String>,
    pub display_order: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateLearningPathRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub level: Option<String>,
    pub duration_hours: Option<i32>,
    pub price_cents: Option<i32>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub certificate_name: Option<String>,
    pub is_active: Option<bool>,
    pub display_order: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateModuleRequest {
    pub learning_path_id: String,
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
    pub duration_minutes: i32,
    pub display_order: i32,
    pub prerequisite_module_id: Option<String>,
    pub is_assessment: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CreateLessonRequest {
    pub module_id: String,
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
    pub lesson_type: String,
    pub content_json: String,
    pub duration_minutes: i32,
    pub display_order: i32,
    pub is_preview: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateLessonProgressRequest {
    pub video_timestamp_seconds: Option<i32>,
    pub time_spent_seconds: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitQuizRequest {
    pub answers: Vec<QuizAnswer>,
    pub time_taken_seconds: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuizAnswer {
    pub question_id: String,
    pub answer: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct LearningPathWithProgress {
    #[serde(flatten)]
    pub path: LearningPath,
    pub enrolled: bool,
    pub enrollment_status: Option<String>,
    pub progress_percent: f32,
    pub completed_lessons: i32,
    pub total_lessons: i32,
}

#[derive(Debug, Serialize)]
pub struct ModuleWithProgress {
    #[serde(flatten)]
    pub module: Module,
    pub lessons: Vec<LessonWithProgress>,
    pub progress_percent: f32,
    pub completed_lessons: i32,
    pub total_lessons: i32,
    pub is_unlocked: bool,
}

#[derive(Debug, Serialize)]
pub struct LessonWithProgress {
    #[serde(flatten)]
    pub lesson: Lesson,
    pub status: String,
    pub video_timestamp_seconds: i32,
    pub completed_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PathProgress {
    pub learning_path_id: String,
    pub completed_modules: i32,
    pub total_modules: i32,
    pub completed_lessons: i32,
    pub total_lessons: i32,
    pub progress_percent: f32,
    pub total_time_spent_seconds: i32,
    pub last_accessed_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct QuizResult {
    pub attempt_id: String,
    pub score_percent: i32,
    pub passed: bool,
    pub total_points: i32,
    pub earned_points: i32,
    pub questions_correct: i32,
    pub questions_total: i32,
    pub feedback: Vec<QuestionFeedback>,
}

#[derive(Debug, Serialize)]
pub struct QuestionFeedback {
    pub question_id: String,
    pub correct: bool,
    pub explanation: Option<String>,
    pub correct_answer: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct AcademyProgress {
    pub total_certificates: i32,
    pub total_courses_enrolled: i32,
    pub total_courses_completed: i32,
    pub total_lessons_completed: i32,
    pub total_time_spent_hours: f32,
    pub paths: Vec<LearningPathWithProgress>,
}

// ============================================================================
// Migration
// ============================================================================

pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    // 1. Learning Paths
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS academy_learning_paths (
            id TEXT PRIMARY KEY,
            slug TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            description TEXT,
            level TEXT NOT NULL,
            duration_hours INTEGER NOT NULL,
            price_cents INTEGER NOT NULL DEFAULT 0,
            icon TEXT,
            color TEXT,
            certificate_name TEXT,
            is_active INTEGER DEFAULT 1,
            display_order INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(pool)
    .await?;

    // 2. Modules
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS academy_modules (
            id TEXT PRIMARY KEY,
            learning_path_id TEXT NOT NULL REFERENCES academy_learning_paths(id) ON DELETE CASCADE,
            slug TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            duration_minutes INTEGER NOT NULL,
            display_order INTEGER NOT NULL,
            prerequisite_module_id TEXT REFERENCES academy_modules(id) ON DELETE SET NULL,
            is_assessment INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(pool)
    .await?;

    // 3. Lessons
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS academy_lessons (
            id TEXT PRIMARY KEY,
            module_id TEXT NOT NULL REFERENCES academy_modules(id) ON DELETE CASCADE,
            slug TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            lesson_type TEXT NOT NULL,
            content_json TEXT NOT NULL,
            duration_minutes INTEGER NOT NULL,
            display_order INTEGER NOT NULL,
            is_preview INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(pool)
    .await?;

    // 4. Video Chapters
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS academy_video_chapters (
            id TEXT PRIMARY KEY,
            lesson_id TEXT NOT NULL REFERENCES academy_lessons(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            timestamp_seconds INTEGER NOT NULL,
            display_order INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // 5. Quiz Questions
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS academy_quiz_questions (
            id TEXT PRIMARY KEY,
            lesson_id TEXT NOT NULL REFERENCES academy_lessons(id) ON DELETE CASCADE,
            question_type TEXT NOT NULL,
            question_text TEXT NOT NULL,
            question_data_json TEXT NOT NULL,
            points INTEGER DEFAULT 1,
            explanation TEXT,
            display_order INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // 6. Enrollments
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS academy_enrollments (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            learning_path_id TEXT NOT NULL REFERENCES academy_learning_paths(id) ON DELETE CASCADE,
            status TEXT DEFAULT 'enrolled',
            enrolled_at TEXT DEFAULT (datetime('now')),
            started_at TEXT,
            completed_at TEXT,
            expires_at TEXT,
            payment_id TEXT,
            UNIQUE(user_id, learning_path_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // 7. Lesson Progress
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS academy_lesson_progress (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            lesson_id TEXT NOT NULL REFERENCES academy_lessons(id) ON DELETE CASCADE,
            status TEXT DEFAULT 'not_started',
            video_timestamp_seconds INTEGER DEFAULT 0,
            completed_at TEXT,
            time_spent_seconds INTEGER DEFAULT 0,
            last_accessed_at TEXT DEFAULT (datetime('now')),
            UNIQUE(user_id, lesson_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // 8. Quiz Attempts
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS academy_quiz_attempts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            lesson_id TEXT NOT NULL REFERENCES academy_lessons(id) ON DELETE CASCADE,
            attempt_number INTEGER DEFAULT 1,
            answers_json TEXT NOT NULL,
            score_percent INTEGER NOT NULL,
            passed INTEGER NOT NULL,
            time_taken_seconds INTEGER,
            started_at TEXT NOT NULL,
            completed_at TEXT DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(pool)
    .await?;

    // 9. Certificates
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS academy_certificates (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            learning_path_id TEXT NOT NULL REFERENCES academy_learning_paths(id) ON DELETE CASCADE,
            certificate_number TEXT NOT NULL UNIQUE,
            issued_at TEXT DEFAULT (datetime('now')),
            expires_at TEXT,
            pdf_path TEXT,
            verification_hash TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // 10. User Notes
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS academy_notes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            lesson_id TEXT NOT NULL REFERENCES academy_lessons(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            UNIQUE(user_id, lesson_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_academy_modules_path ON academy_modules(learning_path_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_academy_lessons_module ON academy_lessons(module_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_academy_enrollments_user ON academy_enrollments(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_academy_progress_user ON academy_lesson_progress(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_academy_attempts_user ON academy_quiz_attempts(user_id, lesson_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_academy_certs_user ON academy_certificates(user_id)")
        .execute(pool)
        .await?;

    // Seed initial data
    seed_learning_paths(pool).await?;

    Ok(())
}

// ============================================================================
// Seed Data
// ============================================================================

async fn seed_learning_paths(pool: &SqlitePool) -> Result<()> {
    // Check if already seeded
    let count: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM academy_learning_paths")
        .fetch_one(pool)
        .await?;

    if count > 0 {
        return Ok(());
    }

    // Beginner Path
    let beginner_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO academy_learning_paths (id, slug, title, description, level, duration_hours, price_cents, icon, color, certificate_name, display_order)
        VALUES (?, 'beginner', 'Security Fundamentals', 'Start your cybersecurity journey. Learn the basics of network security, vulnerability assessment, and security reporting.', 'Beginner', 8, 0, 'Shield', 'cyan', 'Certificate of Completion', 1)
        "#,
    )
    .bind(&beginner_id)
    .execute(pool)
    .await?;

    // Professional Path
    let professional_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO academy_learning_paths (id, slug, title, description, level, duration_hours, price_cents, icon, color, certificate_name, display_order)
        VALUES (?, 'professional', 'Professional Pentester', 'Advance your skills with web application testing, cloud security, and compliance assessments. Prepare for the HCA certification.', 'Professional', 24, 0, 'Target', 'purple', 'HeroForge Certified Analyst (HCA)', 2)
        "#,
    )
    .bind(&professional_id)
    .execute(pool)
    .await?;

    // Expert Path
    let expert_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO academy_learning_paths (id, slug, title, description, level, duration_hours, price_cents, icon, color, certificate_name, display_order)
        VALUES (?, 'expert', 'Expert Red Teamer', 'Master advanced offensive security techniques, purple team operations, and security program development.', 'Expert', 40, 0, 'Zap', 'orange', 'HeroForge Certified Professional (HCP)', 3)
        "#,
    )
    .bind(&expert_id)
    .execute(pool)
    .await?;

    // Seed beginner modules
    seed_beginner_modules(pool, &beginner_id).await?;

    // Seed professional modules
    seed_professional_modules(pool, &professional_id).await?;

    // Seed expert modules
    seed_expert_modules(pool, &expert_id).await?;

    Ok(())
}

async fn seed_beginner_modules(pool: &SqlitePool, path_id: &str) -> Result<()> {
    let modules = vec![
        ("intro-security", "Introduction to Cybersecurity", "Understand the fundamentals of information security, common threats, and defense strategies.", 45, 1, false),
        ("network-basics", "Network Scanning Basics", "Learn how to discover hosts, scan ports, and identify services on a network.", 90, 2, false),
        ("understanding-vulns", "Understanding Vulnerabilities", "Deep dive into CVEs, CVSS scoring, and vulnerability classification.", 60, 3, false),
        ("first-report", "Your First Security Report", "Learn to document findings and create professional security reports.", 90, 4, false),
        ("heroforge-basics", "HeroForge Platform Walkthrough", "Master the HeroForge interface, run scans, and analyze results.", 120, 5, false),
        ("beginner-assessment", "Final Assessment", "Test your knowledge with a practical assessment and earn your certificate.", 60, 6, true),
    ];

    for (slug, title, desc, duration, order, is_assessment) in modules {
        let module_id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO academy_modules (id, learning_path_id, slug, title, description, duration_minutes, display_order, is_assessment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&module_id)
        .bind(path_id)
        .bind(slug)
        .bind(title)
        .bind(desc)
        .bind(duration)
        .bind(order)
        .bind(is_assessment)
        .execute(pool)
        .await?;

        // Seed lessons for each module
        seed_module_lessons(pool, &module_id, slug).await?;
    }

    Ok(())
}

async fn seed_professional_modules(pool: &SqlitePool, path_id: &str) -> Result<()> {
    let modules = vec![
        ("advanced-enum", "Advanced Enumeration Techniques", "Master service enumeration, banner grabbing, and information gathering.", 180, 1, false),
        ("webapp-testing", "Web Application Security Testing", "Learn to identify OWASP Top 10 vulnerabilities in web applications.", 240, 2, false),
        ("cloud-security", "Cloud Security Assessment", "Assess AWS, Azure, and GCP environments for security misconfigurations.", 240, 3, false),
        ("compliance-frameworks", "Compliance Frameworks Deep Dive", "Master PCI-DSS, HIPAA, SOC 2, and other compliance requirements.", 180, 4, false),
        ("professional-reporting", "Professional Reporting Mastery", "Create executive-ready reports that drive action and demonstrate value.", 120, 5, false),
        ("hca-exam", "HCA Certification Exam", "Complete the proctored exam to earn your HeroForge Certified Analyst credential.", 120, 6, true),
    ];

    for (slug, title, desc, duration, order, is_assessment) in modules {
        let module_id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO academy_modules (id, learning_path_id, slug, title, description, duration_minutes, display_order, is_assessment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&module_id)
        .bind(path_id)
        .bind(slug)
        .bind(title)
        .bind(desc)
        .bind(duration)
        .bind(order)
        .bind(is_assessment)
        .execute(pool)
        .await?;

        seed_module_lessons(pool, &module_id, slug).await?;
    }

    Ok(())
}

async fn seed_expert_modules(pool: &SqlitePool, path_id: &str) -> Result<()> {
    let modules = vec![
        ("red-team-ops", "Red Team Operations", "Plan and execute realistic attack simulations against enterprise environments.", 360, 1, false),
        ("purple-team", "Purple Team Exercises", "Collaborate with defenders to improve detection and response capabilities.", 300, 2, false),
        ("threat-hunting", "Threat Hunting Fundamentals", "Proactively search for threats that evade traditional security controls.", 240, 3, false),
        ("security-program", "Building Security Programs", "Design and implement security programs for organizations of all sizes.", 300, 4, false),
        ("advanced-automation", "Security Automation & Orchestration", "Automate security workflows with APIs, scripts, and SOAR platforms.", 240, 5, false),
        ("hcp-exam", "HCP Certification Exam", "Complete the comprehensive practical exam to earn your HCP credential.", 480, 6, true),
    ];

    for (slug, title, desc, duration, order, is_assessment) in modules {
        let module_id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO academy_modules (id, learning_path_id, slug, title, description, duration_minutes, display_order, is_assessment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&module_id)
        .bind(path_id)
        .bind(slug)
        .bind(title)
        .bind(desc)
        .bind(duration)
        .bind(order)
        .bind(is_assessment)
        .execute(pool)
        .await?;

        seed_module_lessons(pool, &module_id, slug).await?;
    }

    Ok(())
}

async fn seed_module_lessons(pool: &SqlitePool, module_id: &str, module_slug: &str) -> Result<()> {
    // Sample lessons for each module - use serde_json to properly format content
    let lessons: Vec<(&str, &str, &str, serde_json::Value, i32, i32)> = match module_slug {
        "intro-security" => vec![
            ("what-is-cybersecurity", "What is Cybersecurity?", "text", serde_json::json!({
                "markdown": "# What is Cybersecurity?\n\nCybersecurity is the practice of protecting systems, networks, and programs from digital attacks...\n\n## Key Concepts\n\n- **Confidentiality**: Ensuring data is only accessible to authorized parties\n- **Integrity**: Ensuring data hasn't been tampered with\n- **Availability**: Ensuring systems and data are available when needed\n\n## The CIA Triad\n\nThe CIA triad forms the foundation of information security..."
            }), 10, 1),
            ("common-threats", "Common Security Threats", "video", serde_json::json!({
                "video_url": "https://www.youtube.com/embed/dQw4w9WgXcQ",
                "description": "Overview of common security threats including malware, phishing, and social engineering."
            }), 15, 2),
            ("security-mindset", "Developing a Security Mindset", "text", serde_json::json!({
                "markdown": "# Developing a Security Mindset\n\nThinking like an attacker helps you defend better...\n\n## Attack Surface\n\nEvery system has an attack surface - the sum of all points where an attacker could try to enter..."
            }), 8, 3),
            ("intro-quiz", "Module Quiz", "quiz", serde_json::json!({
                "pass_threshold": 70,
                "max_attempts": 3
            }), 12, 4),
        ],
        "network-basics" => vec![
            ("ip-addressing", "IP Addressing Fundamentals", "text", serde_json::json!({
                "markdown": "# IP Addressing Fundamentals\n\nUnderstanding IP addresses is crucial for network scanning...\n\n## IPv4 vs IPv6\n\n- IPv4: 32-bit addresses (e.g., 192.168.1.1)\n- IPv6: 128-bit addresses (e.g., 2001:0db8::1)"
            }), 15, 1),
            ("port-scanning-intro", "Introduction to Port Scanning", "video", serde_json::json!({
                "video_url": "https://www.youtube.com/embed/dQw4w9WgXcQ",
                "description": "Learn what port scanning is and why it's important for security assessments."
            }), 20, 2),
            ("nmap-basics", "Using Nmap for Discovery", "interactive", serde_json::json!({
                "markdown": "# Nmap Basics\n\n```bash\n# Basic host discovery\nnmap -sn 192.168.1.0/24\n\n# TCP SYN scan\nnmap -sS -p 1-1000 target.com\n```",
                "code_examples": [{"language": "bash", "code": "nmap -sV -sC target.com"}]
            }), 25, 3),
            ("heroforge-scanning", "Scanning with HeroForge", "video", serde_json::json!({
                "video_url": "https://www.youtube.com/embed/dQw4w9WgXcQ",
                "description": "How to perform network scans using HeroForge's web interface."
            }), 20, 4),
            ("network-quiz", "Module Quiz", "quiz", serde_json::json!({
                "pass_threshold": 70,
                "max_attempts": 3
            }), 10, 5),
        ],
        _ => vec![
            ("lesson-1", "Introduction", "text", serde_json::json!({
                "markdown": "# Module Introduction\n\nWelcome to this module..."
            }), 10, 1),
            ("lesson-2", "Core Concepts", "video", serde_json::json!({
                "video_url": "https://www.youtube.com/embed/dQw4w9WgXcQ",
                "description": "Core concepts for this module."
            }), 20, 2),
            ("lesson-3", "Practical Exercise", "interactive", serde_json::json!({
                "markdown": "# Hands-on Exercise\n\nLet's practice what we've learned..."
            }), 15, 3),
            ("module-quiz", "Module Quiz", "quiz", serde_json::json!({
                "pass_threshold": 70,
                "max_attempts": 3
            }), 10, 4),
        ],
    };

    for (slug, title, lesson_type, content, duration, order) in lessons {
        let lesson_id = Uuid::new_v4().to_string();
        let content_str = serde_json::to_string(&content)?;
        sqlx::query(
            r#"
            INSERT INTO academy_lessons (id, module_id, slug, title, lesson_type, content_json, duration_minutes, display_order, is_preview)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&lesson_id)
        .bind(module_id)
        .bind(slug)
        .bind(title)
        .bind(lesson_type)
        .bind(&content_str)
        .bind(duration)
        .bind(order)
        .bind(order == 1) // First lesson is preview
        .execute(pool)
        .await?;

        // Add quiz questions for quiz lessons
        if lesson_type == "quiz" {
            seed_quiz_questions(pool, &lesson_id).await?;
        }
    }

    Ok(())
}

async fn seed_quiz_questions(pool: &SqlitePool, lesson_id: &str) -> Result<()> {
    let questions = vec![
        ("multiple_choice", "What does CIA stand for in cybersecurity?", r#"{"options":["Central Intelligence Agency","Confidentiality, Integrity, Availability","Computer Information Access","Cyber Intelligence Analysis"],"correct_index":1}"#, 1, "The CIA triad is a foundational model in information security."),
        ("true_false", "A firewall alone is sufficient to protect a network from all cyber attacks.", r#"{"correct_answer":false}"#, 1, "Defense in depth requires multiple layers of security controls."),
        ("multiple_select", "Which of the following are common types of malware? (Select all that apply)", r#"{"options":["Virus","Trojan","Firewall","Ransomware","Router"],"correct_indices":[0,1,3]}"#, 2, "Viruses, Trojans, and Ransomware are all types of malware."),
    ];

    for (i, (q_type, text, data, points, explanation)) in questions.into_iter().enumerate() {
        let question_id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO academy_quiz_questions (id, lesson_id, question_type, question_text, question_data_json, points, explanation, display_order)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&question_id)
        .bind(lesson_id)
        .bind(q_type)
        .bind(text)
        .bind(data)
        .bind(points)
        .bind(explanation)
        .bind((i + 1) as i32)
        .execute(pool)
        .await?;
    }

    Ok(())
}

// ============================================================================
// Learning Paths CRUD
// ============================================================================

pub async fn list_learning_paths(pool: &SqlitePool, active_only: bool) -> Result<Vec<LearningPath>> {
    let query = if active_only {
        "SELECT * FROM academy_learning_paths WHERE is_active = 1 ORDER BY display_order"
    } else {
        "SELECT * FROM academy_learning_paths ORDER BY display_order"
    };

    let paths = sqlx::query_as::<_, LearningPath>(query)
        .fetch_all(pool)
        .await?;

    Ok(paths)
}

pub async fn get_learning_path_by_slug(pool: &SqlitePool, slug: &str) -> Result<Option<LearningPath>> {
    let path = sqlx::query_as::<_, LearningPath>(
        "SELECT * FROM academy_learning_paths WHERE slug = ?"
    )
    .bind(slug)
    .fetch_optional(pool)
    .await?;

    Ok(path)
}

pub async fn get_learning_path_by_id(pool: &SqlitePool, id: &str) -> Result<Option<LearningPath>> {
    let path = sqlx::query_as::<_, LearningPath>(
        "SELECT * FROM academy_learning_paths WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(path)
}

pub async fn create_learning_path(pool: &SqlitePool, req: CreateLearningPathRequest) -> Result<LearningPath> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO academy_learning_paths (id, slug, title, description, level, duration_hours, price_cents, icon, color, certificate_name, display_order, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&req.slug)
    .bind(&req.title)
    .bind(&req.description)
    .bind(&req.level)
    .bind(req.duration_hours)
    .bind(req.price_cents.unwrap_or(0))
    .bind(&req.icon)
    .bind(&req.color)
    .bind(&req.certificate_name)
    .bind(req.display_order.unwrap_or(0))
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_learning_path_by_id(pool, &id).await?.ok_or_else(|| anyhow::anyhow!("Failed to create learning path"))
}

// ============================================================================
// Modules CRUD
// ============================================================================

pub async fn list_modules_for_path(pool: &SqlitePool, learning_path_id: &str) -> Result<Vec<Module>> {
    let modules = sqlx::query_as::<_, Module>(
        "SELECT * FROM academy_modules WHERE learning_path_id = ? ORDER BY display_order"
    )
    .bind(learning_path_id)
    .fetch_all(pool)
    .await?;

    Ok(modules)
}

pub async fn get_module_by_id(pool: &SqlitePool, id: &str) -> Result<Option<Module>> {
    let module = sqlx::query_as::<_, Module>(
        "SELECT * FROM academy_modules WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(module)
}

pub async fn create_module(pool: &SqlitePool, req: CreateModuleRequest) -> Result<Module> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO academy_modules (id, learning_path_id, slug, title, description, duration_minutes, display_order, prerequisite_module_id, is_assessment, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&req.learning_path_id)
    .bind(&req.slug)
    .bind(&req.title)
    .bind(&req.description)
    .bind(req.duration_minutes)
    .bind(req.display_order)
    .bind(&req.prerequisite_module_id)
    .bind(req.is_assessment.unwrap_or(false))
    .bind(&now)
    .execute(pool)
    .await?;

    get_module_by_id(pool, &id).await?.ok_or_else(|| anyhow::anyhow!("Failed to create module"))
}

// ============================================================================
// Lessons CRUD
// ============================================================================

pub async fn list_lessons_for_module(pool: &SqlitePool, module_id: &str) -> Result<Vec<Lesson>> {
    let lessons = sqlx::query_as::<_, Lesson>(
        "SELECT * FROM academy_lessons WHERE module_id = ? ORDER BY display_order"
    )
    .bind(module_id)
    .fetch_all(pool)
    .await?;

    Ok(lessons)
}

pub async fn get_lesson_by_id(pool: &SqlitePool, id: &str) -> Result<Option<Lesson>> {
    let lesson = sqlx::query_as::<_, Lesson>(
        "SELECT * FROM academy_lessons WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(lesson)
}

pub async fn create_lesson(pool: &SqlitePool, req: CreateLessonRequest) -> Result<Lesson> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO academy_lessons (id, module_id, slug, title, description, lesson_type, content_json, duration_minutes, display_order, is_preview, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&req.module_id)
    .bind(&req.slug)
    .bind(&req.title)
    .bind(&req.description)
    .bind(&req.lesson_type)
    .bind(&req.content_json)
    .bind(req.duration_minutes)
    .bind(req.display_order)
    .bind(req.is_preview.unwrap_or(false))
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_lesson_by_id(pool, &id).await?.ok_or_else(|| anyhow::anyhow!("Failed to create lesson"))
}

// ============================================================================
// Enrollments
// ============================================================================

pub async fn enroll_user(pool: &SqlitePool, user_id: &str, learning_path_id: &str) -> Result<Enrollment> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO academy_enrollments (id, user_id, learning_path_id, status, enrolled_at)
        VALUES (?, ?, ?, 'enrolled', ?)
        ON CONFLICT(user_id, learning_path_id) DO UPDATE SET
            status = CASE WHEN status = 'expired' THEN 'enrolled' ELSE status END,
            expires_at = NULL
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(learning_path_id)
    .bind(&now)
    .execute(pool)
    .await?;

    get_enrollment(pool, user_id, learning_path_id).await?.ok_or_else(|| anyhow::anyhow!("Failed to enroll"))
}

pub async fn get_enrollment(pool: &SqlitePool, user_id: &str, learning_path_id: &str) -> Result<Option<Enrollment>> {
    let enrollment = sqlx::query_as::<_, Enrollment>(
        "SELECT * FROM academy_enrollments WHERE user_id = ? AND learning_path_id = ?"
    )
    .bind(user_id)
    .bind(learning_path_id)
    .fetch_optional(pool)
    .await?;

    Ok(enrollment)
}

pub async fn list_user_enrollments(pool: &SqlitePool, user_id: &str) -> Result<Vec<Enrollment>> {
    let enrollments = sqlx::query_as::<_, Enrollment>(
        "SELECT * FROM academy_enrollments WHERE user_id = ? ORDER BY enrolled_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(enrollments)
}

pub async fn update_enrollment_status(pool: &SqlitePool, user_id: &str, learning_path_id: &str, status: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    let (started_at, completed_at) = match status {
        "in_progress" => (Some(now.clone()), None),
        "completed" => (None, Some(now.clone())),
        _ => (None, None),
    };

    sqlx::query(
        r#"
        UPDATE academy_enrollments
        SET status = ?,
            started_at = COALESCE(?, started_at),
            completed_at = COALESCE(?, completed_at)
        WHERE user_id = ? AND learning_path_id = ?
        "#,
    )
    .bind(status)
    .bind(started_at)
    .bind(completed_at)
    .bind(user_id)
    .bind(learning_path_id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Lesson Progress
// ============================================================================

pub async fn get_lesson_progress(pool: &SqlitePool, user_id: &str, lesson_id: &str) -> Result<Option<LessonProgress>> {
    let progress = sqlx::query_as::<_, LessonProgress>(
        "SELECT * FROM academy_lesson_progress WHERE user_id = ? AND lesson_id = ?"
    )
    .bind(user_id)
    .bind(lesson_id)
    .fetch_optional(pool)
    .await?;

    Ok(progress)
}

pub async fn update_lesson_progress(
    pool: &SqlitePool,
    user_id: &str,
    lesson_id: &str,
    req: UpdateLessonProgressRequest,
) -> Result<LessonProgress> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO academy_lesson_progress (id, user_id, lesson_id, status, video_timestamp_seconds, time_spent_seconds, last_accessed_at)
        VALUES (?, ?, ?, 'in_progress', ?, ?, ?)
        ON CONFLICT(user_id, lesson_id) DO UPDATE SET
            status = CASE WHEN status = 'completed' THEN 'completed' ELSE 'in_progress' END,
            video_timestamp_seconds = COALESCE(?, video_timestamp_seconds),
            time_spent_seconds = time_spent_seconds + COALESCE(?, 0),
            last_accessed_at = ?
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(lesson_id)
    .bind(req.video_timestamp_seconds.unwrap_or(0))
    .bind(req.time_spent_seconds.unwrap_or(0))
    .bind(&now)
    .bind(req.video_timestamp_seconds)
    .bind(req.time_spent_seconds)
    .bind(&now)
    .execute(pool)
    .await?;

    get_lesson_progress(pool, user_id, lesson_id).await?.ok_or_else(|| anyhow::anyhow!("Failed to update progress"))
}

pub async fn complete_lesson(pool: &SqlitePool, user_id: &str, lesson_id: &str) -> Result<LessonProgress> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO academy_lesson_progress (id, user_id, lesson_id, status, completed_at, last_accessed_at)
        VALUES (?, ?, ?, 'completed', ?, ?)
        ON CONFLICT(user_id, lesson_id) DO UPDATE SET
            status = 'completed',
            completed_at = ?,
            last_accessed_at = ?
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(lesson_id)
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_lesson_progress(pool, user_id, lesson_id).await?.ok_or_else(|| anyhow::anyhow!("Failed to complete lesson"))
}

pub async fn get_user_progress_for_path(pool: &SqlitePool, user_id: &str, learning_path_id: &str) -> Result<PathProgress> {
    // Get all lessons for the path
    let total_lessons: i32 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM academy_lessons l
        JOIN academy_modules m ON l.module_id = m.id
        WHERE m.learning_path_id = ?
        "#,
    )
    .bind(learning_path_id)
    .fetch_one(pool)
    .await?;

    // Get completed lessons
    let completed_lessons: i32 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM academy_lesson_progress p
        JOIN academy_lessons l ON p.lesson_id = l.id
        JOIN academy_modules m ON l.module_id = m.id
        WHERE p.user_id = ? AND m.learning_path_id = ? AND p.status = 'completed'
        "#,
    )
    .bind(user_id)
    .bind(learning_path_id)
    .fetch_one(pool)
    .await?;

    // Get total modules
    let total_modules: i32 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM academy_modules WHERE learning_path_id = ?"
    )
    .bind(learning_path_id)
    .fetch_one(pool)
    .await?;

    // Get completed modules (all lessons completed)
    let completed_modules: i32 = sqlx::query_scalar(
        r#"
        SELECT COUNT(DISTINCT m.id)
        FROM academy_modules m
        WHERE m.learning_path_id = ?
        AND NOT EXISTS (
            SELECT 1 FROM academy_lessons l
            WHERE l.module_id = m.id
            AND NOT EXISTS (
                SELECT 1 FROM academy_lesson_progress p
                WHERE p.lesson_id = l.id AND p.user_id = ? AND p.status = 'completed'
            )
        )
        "#,
    )
    .bind(learning_path_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Get total time spent
    let total_time_spent: i32 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(p.time_spent_seconds), 0)
        FROM academy_lesson_progress p
        JOIN academy_lessons l ON p.lesson_id = l.id
        JOIN academy_modules m ON l.module_id = m.id
        WHERE p.user_id = ? AND m.learning_path_id = ?
        "#,
    )
    .bind(user_id)
    .bind(learning_path_id)
    .fetch_one(pool)
    .await?;

    // Get last accessed
    let last_accessed: Option<String> = sqlx::query_scalar(
        r#"
        SELECT MAX(p.last_accessed_at)
        FROM academy_lesson_progress p
        JOIN academy_lessons l ON p.lesson_id = l.id
        JOIN academy_modules m ON l.module_id = m.id
        WHERE p.user_id = ? AND m.learning_path_id = ?
        "#,
    )
    .bind(user_id)
    .bind(learning_path_id)
    .fetch_one(pool)
    .await?;

    let progress_percent = if total_lessons > 0 {
        (completed_lessons as f32 / total_lessons as f32) * 100.0
    } else {
        0.0
    };

    Ok(PathProgress {
        learning_path_id: learning_path_id.to_string(),
        completed_modules,
        total_modules,
        completed_lessons,
        total_lessons,
        progress_percent,
        total_time_spent_seconds: total_time_spent,
        last_accessed_at: last_accessed,
    })
}

// ============================================================================
// Quiz Operations
// ============================================================================

pub async fn get_quiz_questions(pool: &SqlitePool, lesson_id: &str) -> Result<Vec<QuizQuestion>> {
    let questions = sqlx::query_as::<_, QuizQuestion>(
        "SELECT * FROM academy_quiz_questions WHERE lesson_id = ? ORDER BY display_order"
    )
    .bind(lesson_id)
    .fetch_all(pool)
    .await?;

    Ok(questions)
}

pub async fn submit_quiz(
    pool: &SqlitePool,
    user_id: &str,
    lesson_id: &str,
    req: SubmitQuizRequest,
) -> Result<QuizResult> {
    let questions = get_quiz_questions(pool, lesson_id).await?;

    // Get attempt number
    let attempt_number: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(attempt_number), 0) + 1 FROM academy_quiz_attempts WHERE user_id = ? AND lesson_id = ?"
    )
    .bind(user_id)
    .bind(lesson_id)
    .fetch_one(pool)
    .await?;

    // Grade the quiz
    let mut total_points = 0;
    let mut earned_points = 0;
    let mut questions_correct = 0;
    let mut feedback = Vec::new();

    for question in &questions {
        total_points += question.points;

        let user_answer = req.answers.iter()
            .find(|a| a.question_id == question.id)
            .map(|a| &a.answer);

        let question_data: serde_json::Value = serde_json::from_str(&question.question_data_json)?;
        let (correct, correct_answer) = grade_question(&question.question_type, &question_data, user_answer);

        if correct {
            earned_points += question.points;
            questions_correct += 1;
        }

        feedback.push(QuestionFeedback {
            question_id: question.id.clone(),
            correct,
            explanation: question.explanation.clone(),
            correct_answer,
        });
    }

    let score_percent = if total_points > 0 {
        (earned_points as f32 / total_points as f32 * 100.0) as i32
    } else {
        0
    };

    // Get lesson to check pass threshold
    let lesson = get_lesson_by_id(pool, lesson_id).await?
        .ok_or_else(|| anyhow::anyhow!("Lesson not found"))?;
    let content: serde_json::Value = serde_json::from_str(&lesson.content_json)?;
    let pass_threshold = content.get("pass_threshold")
        .and_then(|v| v.as_i64())
        .unwrap_or(70) as i32;

    let passed = score_percent >= pass_threshold;

    // Store attempt
    let attempt_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO academy_quiz_attempts (id, user_id, lesson_id, attempt_number, answers_json, score_percent, passed, time_taken_seconds, started_at, completed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&attempt_id)
    .bind(user_id)
    .bind(lesson_id)
    .bind(attempt_number)
    .bind(serde_json::to_string(&req.answers)?)
    .bind(score_percent)
    .bind(passed)
    .bind(req.time_taken_seconds)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    // If passed, mark lesson as complete
    if passed {
        complete_lesson(pool, user_id, lesson_id).await?;
    }

    Ok(QuizResult {
        attempt_id,
        score_percent,
        passed,
        total_points,
        earned_points,
        questions_correct,
        questions_total: questions.len() as i32,
        feedback,
    })
}

fn grade_question(
    question_type: &str,
    question_data: &serde_json::Value,
    user_answer: Option<&serde_json::Value>,
) -> (bool, serde_json::Value) {
    match question_type {
        "multiple_choice" => {
            let correct_index = question_data.get("correct_index")
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            let user_index = user_answer
                .and_then(|v| v.as_i64())
                .unwrap_or(-2);
            (correct_index == user_index, serde_json::json!(correct_index))
        }
        "true_false" => {
            let correct = question_data.get("correct_answer")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let user = user_answer
                .and_then(|v| v.as_bool())
                .unwrap_or(!correct);
            (correct == user, serde_json::json!(correct))
        }
        "multiple_select" => {
            let correct_indices: Vec<i64> = question_data.get("correct_indices")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|x| x.as_i64()).collect())
                .unwrap_or_default();
            let user_indices: Vec<i64> = user_answer
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|x| x.as_i64()).collect())
                .unwrap_or_default();
            let correct_set: std::collections::HashSet<_> = correct_indices.iter().collect();
            let user_set: std::collections::HashSet<_> = user_indices.iter().collect();
            (correct_set == user_set, serde_json::json!(correct_indices))
        }
        _ => (false, serde_json::json!(null)),
    }
}

pub async fn get_quiz_attempts(pool: &SqlitePool, user_id: &str, lesson_id: &str) -> Result<Vec<QuizAttempt>> {
    let attempts = sqlx::query_as::<_, QuizAttempt>(
        "SELECT * FROM academy_quiz_attempts WHERE user_id = ? AND lesson_id = ? ORDER BY attempt_number DESC"
    )
    .bind(user_id)
    .bind(lesson_id)
    .fetch_all(pool)
    .await?;

    Ok(attempts)
}

// ============================================================================
// Certificates
// ============================================================================

pub async fn issue_certificate(pool: &SqlitePool, user_id: &str, learning_path_id: &str) -> Result<Certificate> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Generate certificate number: HFA-YYYY-XXXXX
    let random_part: u32 = rand::random::<u32>() % 100000;
    let certificate_number = format!("HFA-{}-{:05}", now.format("%Y"), random_part);

    // Generate verification hash
    use md5::{Md5, Digest};
    let mut hasher = Md5::new();
    hasher.update(format!("{}:{}:{}", user_id, learning_path_id, now.to_rfc3339()).as_bytes());
    let verification_hash = format!("{:x}", hasher.finalize());

    sqlx::query(
        r#"
        INSERT INTO academy_certificates (id, user_id, learning_path_id, certificate_number, issued_at, verification_hash)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(learning_path_id)
    .bind(&certificate_number)
    .bind(now.to_rfc3339())
    .bind(&verification_hash)
    .execute(pool)
    .await?;

    // Update enrollment status
    update_enrollment_status(pool, user_id, learning_path_id, "completed").await?;

    get_certificate_by_id(pool, &id).await?.ok_or_else(|| anyhow::anyhow!("Failed to issue certificate"))
}

pub async fn get_certificate_by_id(pool: &SqlitePool, id: &str) -> Result<Option<Certificate>> {
    let cert = sqlx::query_as::<_, Certificate>(
        "SELECT * FROM academy_certificates WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(cert)
}

pub async fn get_certificate_by_number(pool: &SqlitePool, number: &str) -> Result<Option<Certificate>> {
    let cert = sqlx::query_as::<_, Certificate>(
        "SELECT * FROM academy_certificates WHERE certificate_number = ?"
    )
    .bind(number)
    .fetch_optional(pool)
    .await?;

    Ok(cert)
}

pub async fn list_user_certificates(pool: &SqlitePool, user_id: &str) -> Result<Vec<Certificate>> {
    let certs = sqlx::query_as::<_, Certificate>(
        "SELECT * FROM academy_certificates WHERE user_id = ? ORDER BY issued_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(certs)
}

pub async fn verify_certificate(pool: &SqlitePool, certificate_number: &str) -> Result<Option<(Certificate, LearningPath, String)>> {
    // Get certificate and join manually to avoid complex tuple decoding
    let cert = get_certificate_by_number(pool, certificate_number).await?;

    if let Some(cert) = cert {
        let path = get_learning_path_by_id(pool, &cert.learning_path_id).await?;
        let username: Option<String> = sqlx::query_scalar("SELECT username FROM users WHERE id = ?")
            .bind(&cert.user_id)
            .fetch_optional(pool)
            .await?;

        if let (Some(path), Some(username)) = (path, username) {
            return Ok(Some((cert, path, username)));
        }
    }

    Ok(None)
}

// ============================================================================
// User Notes
// ============================================================================

pub async fn get_user_note(pool: &SqlitePool, user_id: &str, lesson_id: &str) -> Result<Option<UserNote>> {
    let note = sqlx::query_as::<_, UserNote>(
        "SELECT * FROM academy_notes WHERE user_id = ? AND lesson_id = ?"
    )
    .bind(user_id)
    .bind(lesson_id)
    .fetch_optional(pool)
    .await?;

    Ok(note)
}

pub async fn upsert_user_note(pool: &SqlitePool, user_id: &str, lesson_id: &str, content: &str) -> Result<UserNote> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO academy_notes (id, user_id, lesson_id, content, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, lesson_id) DO UPDATE SET
            content = ?,
            updated_at = ?
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(lesson_id)
    .bind(content)
    .bind(&now)
    .bind(&now)
    .bind(content)
    .bind(&now)
    .execute(pool)
    .await?;

    get_user_note(pool, user_id, lesson_id).await?.ok_or_else(|| anyhow::anyhow!("Failed to save note"))
}

// ============================================================================
// Academy Progress Overview
// ============================================================================

pub async fn get_user_academy_progress(pool: &SqlitePool, user_id: &str) -> Result<AcademyProgress> {
    let paths = list_learning_paths(pool, true).await?;
    let enrollments = list_user_enrollments(pool, user_id).await?;
    let certificates = list_user_certificates(pool, user_id).await?;

    let mut paths_with_progress = Vec::new();

    for path in paths {
        let enrollment = enrollments.iter().find(|e| e.learning_path_id == path.id);
        let progress = get_user_progress_for_path(pool, user_id, &path.id).await?;

        paths_with_progress.push(LearningPathWithProgress {
            path: path.clone(),
            enrolled: enrollment.is_some(),
            enrollment_status: enrollment.map(|e| e.status.clone()),
            progress_percent: progress.progress_percent,
            completed_lessons: progress.completed_lessons,
            total_lessons: progress.total_lessons,
        });
    }

    // Calculate totals
    let total_time_spent: i32 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(time_spent_seconds), 0) FROM academy_lesson_progress WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let total_lessons_completed: i32 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM academy_lesson_progress WHERE user_id = ? AND status = 'completed'"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let total_courses_completed = enrollments.iter()
        .filter(|e| e.status == "completed")
        .count() as i32;

    Ok(AcademyProgress {
        total_certificates: certificates.len() as i32,
        total_courses_enrolled: enrollments.len() as i32,
        total_courses_completed,
        total_lessons_completed,
        total_time_spent_hours: total_time_spent as f32 / 3600.0,
        paths: paths_with_progress,
    })
}

// ============================================================================
// Video Chapters
// ============================================================================

pub async fn get_video_chapters(pool: &SqlitePool, lesson_id: &str) -> Result<Vec<VideoChapter>> {
    let chapters = sqlx::query_as::<_, VideoChapter>(
        "SELECT * FROM academy_video_chapters WHERE lesson_id = ? ORDER BY display_order"
    )
    .bind(lesson_id)
    .fetch_all(pool)
    .await?;

    Ok(chapters)
}

// ============================================================================
// Check Path Completion for Certificate
// ============================================================================

pub async fn check_and_issue_certificate(pool: &SqlitePool, user_id: &str, learning_path_id: &str) -> Result<Option<Certificate>> {
    // Check if all lessons are completed
    let progress = get_user_progress_for_path(pool, user_id, learning_path_id).await?;

    if progress.completed_lessons < progress.total_lessons {
        return Ok(None);
    }

    // Check if certificate already issued
    let existing: i32 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM academy_certificates WHERE user_id = ? AND learning_path_id = ?"
    )
    .bind(user_id)
    .bind(learning_path_id)
    .fetch_one(pool)
    .await?;

    if existing > 0 {
        return Ok(None);
    }

    // Issue certificate
    let cert = issue_certificate(pool, user_id, learning_path_id).await?;
    Ok(Some(cert))
}

// ============================================================================
// Admin CRUD Operations
// ============================================================================

// --- Learning Path Admin ---

pub async fn update_learning_path(
    pool: &SqlitePool,
    id: &str,
    req: UpdateLearningPathRequest,
) -> Result<Option<LearningPath>> {
    let existing = get_learning_path_by_id(pool, id).await?;
    if existing.is_none() {
        return Ok(None);
    }
    let existing = existing.unwrap();

    sqlx::query(
        r#"UPDATE academy_learning_paths SET
            title = ?,
            description = ?,
            level = ?,
            duration_hours = ?,
            price_cents = ?,
            icon = ?,
            color = ?,
            certificate_name = ?,
            is_active = ?,
            display_order = ?,
            updated_at = datetime('now')
        WHERE id = ?"#,
    )
    .bind(req.title.unwrap_or(existing.title))
    .bind(req.description.or(existing.description))
    .bind(req.level.unwrap_or(existing.level))
    .bind(req.duration_hours.unwrap_or(existing.duration_hours))
    .bind(req.price_cents.unwrap_or(existing.price_cents))
    .bind(req.icon.or(existing.icon))
    .bind(req.color.or(existing.color))
    .bind(req.certificate_name.or(existing.certificate_name))
    .bind(req.is_active.unwrap_or(existing.is_active))
    .bind(req.display_order.unwrap_or(existing.display_order))
    .bind(id)
    .execute(pool)
    .await?;

    get_learning_path_by_id(pool, id).await
}

pub async fn delete_learning_path(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM academy_learning_paths WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// --- Module Admin ---

#[derive(Debug, Deserialize)]
pub struct UpdateModuleRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub duration_minutes: Option<i32>,
    pub display_order: Option<i32>,
    pub prerequisite_module_id: Option<String>,
    pub is_assessment: Option<bool>,
}

pub async fn update_module(
    pool: &SqlitePool,
    id: &str,
    req: UpdateModuleRequest,
) -> Result<Option<Module>> {
    let existing = get_module_by_id(pool, id).await?;
    if existing.is_none() {
        return Ok(None);
    }
    let existing = existing.unwrap();

    sqlx::query(
        r#"UPDATE academy_modules SET
            title = ?,
            description = ?,
            duration_minutes = ?,
            display_order = ?,
            prerequisite_module_id = ?,
            is_assessment = ?
        WHERE id = ?"#,
    )
    .bind(req.title.unwrap_or(existing.title))
    .bind(req.description.or(existing.description))
    .bind(req.duration_minutes.unwrap_or(existing.duration_minutes))
    .bind(req.display_order.unwrap_or(existing.display_order))
    .bind(req.prerequisite_module_id.or(existing.prerequisite_module_id))
    .bind(req.is_assessment.unwrap_or(existing.is_assessment))
    .bind(id)
    .execute(pool)
    .await?;

    get_module_by_id(pool, id).await
}

pub async fn delete_module(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM academy_modules WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// --- Lesson Admin ---

#[derive(Debug, Deserialize)]
pub struct UpdateLessonRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub lesson_type: Option<String>,
    pub content_json: Option<String>,
    pub duration_minutes: Option<i32>,
    pub display_order: Option<i32>,
    pub is_preview: Option<bool>,
}

pub async fn update_lesson(
    pool: &SqlitePool,
    id: &str,
    req: UpdateLessonRequest,
) -> Result<Option<Lesson>> {
    let existing = get_lesson_by_id(pool, id).await?;
    if existing.is_none() {
        return Ok(None);
    }
    let existing = existing.unwrap();

    sqlx::query(
        r#"UPDATE academy_lessons SET
            title = ?,
            description = ?,
            lesson_type = ?,
            content_json = ?,
            duration_minutes = ?,
            display_order = ?,
            is_preview = ?,
            updated_at = datetime('now')
        WHERE id = ?"#,
    )
    .bind(req.title.unwrap_or(existing.title))
    .bind(req.description.or(existing.description))
    .bind(req.lesson_type.unwrap_or(existing.lesson_type))
    .bind(req.content_json.unwrap_or(existing.content_json))
    .bind(req.duration_minutes.unwrap_or(existing.duration_minutes))
    .bind(req.display_order.unwrap_or(existing.display_order))
    .bind(req.is_preview.unwrap_or(existing.is_preview))
    .bind(id)
    .execute(pool)
    .await?;

    get_lesson_by_id(pool, id).await
}

pub async fn delete_lesson(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM academy_lessons WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// --- Quiz Question Admin ---

#[derive(Debug, Deserialize)]
pub struct CreateQuizQuestionRequest {
    pub lesson_id: String,
    pub question_type: String,
    pub question_text: String,
    pub question_data_json: String,
    pub points: Option<i32>,
    pub explanation: Option<String>,
    pub display_order: i32,
}

#[derive(Debug, Deserialize)]
pub struct UpdateQuizQuestionRequest {
    pub question_type: Option<String>,
    pub question_text: Option<String>,
    pub question_data_json: Option<String>,
    pub points: Option<i32>,
    pub explanation: Option<String>,
    pub display_order: Option<i32>,
}

pub async fn get_quiz_question_by_id(pool: &SqlitePool, id: &str) -> Result<Option<QuizQuestion>> {
    let question = sqlx::query_as::<_, QuizQuestion>(
        "SELECT * FROM academy_quiz_questions WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(question)
}

pub async fn create_quiz_question(
    pool: &SqlitePool,
    req: CreateQuizQuestionRequest,
) -> Result<QuizQuestion> {
    let id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        r#"INSERT INTO academy_quiz_questions
            (id, lesson_id, question_type, question_text, question_data_json, points, explanation, display_order)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(&id)
    .bind(&req.lesson_id)
    .bind(&req.question_type)
    .bind(&req.question_text)
    .bind(&req.question_data_json)
    .bind(req.points.unwrap_or(1))
    .bind(&req.explanation)
    .bind(req.display_order)
    .execute(pool)
    .await?;

    get_quiz_question_by_id(pool, &id).await?.ok_or_else(|| anyhow::anyhow!("Failed to create question"))
}

pub async fn update_quiz_question(
    pool: &SqlitePool,
    id: &str,
    req: UpdateQuizQuestionRequest,
) -> Result<Option<QuizQuestion>> {
    let existing = get_quiz_question_by_id(pool, id).await?;
    if existing.is_none() {
        return Ok(None);
    }
    let existing = existing.unwrap();

    sqlx::query(
        r#"UPDATE academy_quiz_questions SET
            question_type = ?,
            question_text = ?,
            question_data_json = ?,
            points = ?,
            explanation = ?,
            display_order = ?
        WHERE id = ?"#,
    )
    .bind(req.question_type.unwrap_or(existing.question_type))
    .bind(req.question_text.unwrap_or(existing.question_text))
    .bind(req.question_data_json.unwrap_or(existing.question_data_json))
    .bind(req.points.unwrap_or(existing.points))
    .bind(req.explanation.or(existing.explanation))
    .bind(req.display_order.unwrap_or(existing.display_order))
    .bind(id)
    .execute(pool)
    .await?;

    get_quiz_question_by_id(pool, id).await
}

pub async fn delete_quiz_question(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM academy_quiz_questions WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// --- Video Chapter Admin ---

#[derive(Debug, Deserialize)]
pub struct CreateVideoChapterRequest {
    pub lesson_id: String,
    pub title: String,
    pub timestamp_seconds: i32,
    pub display_order: i32,
}

#[derive(Debug, Deserialize)]
pub struct UpdateVideoChapterRequest {
    pub title: Option<String>,
    pub timestamp_seconds: Option<i32>,
    pub display_order: Option<i32>,
}

pub async fn get_video_chapter_by_id(pool: &SqlitePool, id: &str) -> Result<Option<VideoChapter>> {
    let chapter = sqlx::query_as::<_, VideoChapter>(
        "SELECT * FROM academy_video_chapters WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(chapter)
}

pub async fn create_video_chapter(
    pool: &SqlitePool,
    req: CreateVideoChapterRequest,
) -> Result<VideoChapter> {
    let id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        r#"INSERT INTO academy_video_chapters (id, lesson_id, title, timestamp_seconds, display_order)
        VALUES (?, ?, ?, ?, ?)"#,
    )
    .bind(&id)
    .bind(&req.lesson_id)
    .bind(&req.title)
    .bind(req.timestamp_seconds)
    .bind(req.display_order)
    .execute(pool)
    .await?;

    get_video_chapter_by_id(pool, &id).await?.ok_or_else(|| anyhow::anyhow!("Failed to create chapter"))
}

pub async fn update_video_chapter(
    pool: &SqlitePool,
    id: &str,
    req: UpdateVideoChapterRequest,
) -> Result<Option<VideoChapter>> {
    let existing = get_video_chapter_by_id(pool, id).await?;
    if existing.is_none() {
        return Ok(None);
    }
    let existing = existing.unwrap();

    sqlx::query(
        r#"UPDATE academy_video_chapters SET title = ?, timestamp_seconds = ?, display_order = ? WHERE id = ?"#,
    )
    .bind(req.title.unwrap_or(existing.title))
    .bind(req.timestamp_seconds.unwrap_or(existing.timestamp_seconds))
    .bind(req.display_order.unwrap_or(existing.display_order))
    .bind(id)
    .execute(pool)
    .await?;

    get_video_chapter_by_id(pool, id).await
}

pub async fn delete_video_chapter(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM academy_video_chapters WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Certificate PDF Generation
// ============================================================================

pub async fn generate_certificate_pdf(
    pool: &SqlitePool,
    certificate_id: &str,
) -> Result<Vec<u8>> {
    // Get certificate details
    let cert = get_certificate_by_id(pool, certificate_id).await?
        .ok_or_else(|| anyhow::anyhow!("Certificate not found"))?;

    let path = get_learning_path_by_id(pool, &cert.learning_path_id).await?
        .ok_or_else(|| anyhow::anyhow!("Learning path not found"))?;

    // Get user name
    let user_name: Option<String> = sqlx::query_scalar(
        "SELECT name FROM users WHERE id = ?"
    )
    .bind(&cert.user_id)
    .fetch_optional(pool)
    .await?;

    let holder_name = user_name.unwrap_or_else(|| "Certificate Holder".to_string());
    let issue_date = chrono::NaiveDateTime::parse_from_str(&cert.issued_at, "%Y-%m-%d %H:%M:%S")
        .map(|dt| dt.format("%B %d, %Y").to_string())
        .unwrap_or_else(|_| cert.issued_at.clone());

    // Generate HTML certificate
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        @page {{ size: A4 landscape; margin: 0; }}
        body {{
            font-family: 'Georgia', serif;
            margin: 0;
            padding: 40px;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #ffffff;
            min-height: 100vh;
            box-sizing: border-box;
        }}
        .certificate {{
            border: 4px solid #00d4ff;
            border-radius: 20px;
            padding: 60px;
            text-align: center;
            background: rgba(255,255,255,0.05);
            position: relative;
        }}
        .header {{
            font-size: 18px;
            color: #00d4ff;
            letter-spacing: 4px;
            margin-bottom: 20px;
        }}
        .title {{
            font-size: 48px;
            font-weight: bold;
            margin: 20px 0;
            color: #ffffff;
        }}
        .subtitle {{
            font-size: 20px;
            color: #a0a0a0;
            margin-bottom: 40px;
        }}
        .recipient {{
            font-size: 36px;
            font-weight: bold;
            color: #00d4ff;
            margin: 30px 0;
            border-bottom: 2px solid #00d4ff;
            display: inline-block;
            padding-bottom: 10px;
        }}
        .course-name {{
            font-size: 28px;
            color: #ffffff;
            margin: 20px 0;
        }}
        .credential {{
            font-size: 18px;
            color: #ffd700;
            margin: 20px 0;
        }}
        .details {{
            display: flex;
            justify-content: space-around;
            margin-top: 60px;
            padding-top: 30px;
            border-top: 1px solid #333;
        }}
        .detail-item {{
            text-align: center;
        }}
        .detail-label {{
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
        }}
        .detail-value {{
            font-size: 16px;
            color: #fff;
            margin-top: 5px;
        }}
        .logo {{
            font-size: 24px;
            font-weight: bold;
            color: #00d4ff;
            margin-bottom: 10px;
        }}
        .issuer {{
            font-size: 14px;
            color: #888;
        }}
    </style>
</head>
<body>
    <div class="certificate">
        <div class="logo">HeroForge Academy</div>
        <div class="header">CERTIFICATE OF COMPLETION</div>
        <div class="title">Achievement Unlocked</div>
        <div class="subtitle">This certifies that</div>
        <div class="recipient">{}</div>
        <div class="subtitle">has successfully completed</div>
        <div class="course-name">{}</div>
        {}
        <div class="details">
            <div class="detail-item">
                <div class="detail-label">Certificate Number</div>
                <div class="detail-value">{}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Issue Date</div>
                <div class="detail-value">{}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Issued By</div>
                <div class="detail-value">Genial Architect<br/>Cybersecurity Research Associates</div>
            </div>
        </div>
    </div>
</body>
</html>"#,
        holder_name,
        path.title,
        path.certificate_name.as_ref().map(|name|
            format!(r#"<div class="credential">Credential Earned: {}</div>"#, name)
        ).unwrap_or_default(),
        cert.certificate_number,
        issue_date,
    );

    // Convert HTML to PDF using headless Chrome or wkhtmltopdf
    // For now, we'll try using the existing reports infrastructure or return HTML
    // that can be printed as PDF by the browser

    // Try to use wkhtmltopdf if available
    use std::process::Command;
    use std::io::Write;

    let temp_html = format!("/tmp/cert_{}.html", certificate_id);
    let temp_pdf = format!("/tmp/cert_{}.pdf", certificate_id);

    // Write HTML to temp file
    std::fs::write(&temp_html, &html)?;

    // Try wkhtmltopdf first
    let result = Command::new("wkhtmltopdf")
        .args(&[
            "--page-size", "A4",
            "--orientation", "Landscape",
            "--margin-top", "0",
            "--margin-bottom", "0",
            "--margin-left", "0",
            "--margin-right", "0",
            "--enable-local-file-access",
            &temp_html,
            &temp_pdf,
        ])
        .output();

    let pdf_bytes = match result {
        Ok(output) if output.status.success() => {
            std::fs::read(&temp_pdf)?
        }
        _ => {
            // Fallback: Try chromium/chrome
            let chrome_result = Command::new("chromium")
                .args(&[
                    "--headless",
                    "--disable-gpu",
                    "--print-to-pdf-no-header",
                    &format!("--print-to-pdf={}", temp_pdf),
                    &temp_html,
                ])
                .output();

            match chrome_result {
                Ok(output) if output.status.success() => {
                    std::fs::read(&temp_pdf)?
                }
                _ => {
                    // Last resort: return HTML as bytes for client-side PDF generation
                    log::warn!("PDF generation tools not available, returning HTML");
                    html.into_bytes()
                }
            }
        }
    };

    // Cleanup temp files
    let _ = std::fs::remove_file(&temp_html);
    let _ = std::fs::remove_file(&temp_pdf);

    Ok(pdf_bytes)
}

/// Get user info for certificate
pub async fn get_user_for_certificate(pool: &SqlitePool, user_id: &str) -> Result<Option<String>> {
    let name: Option<String> = sqlx::query_scalar(
        "SELECT name FROM users WHERE id = ?"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(name)
}
