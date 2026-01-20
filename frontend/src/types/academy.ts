// Academy LMS Types

export interface LearningPath {
  id: string;
  slug: string;
  title: string;
  description: string | null;
  level: 'Beginner' | 'Professional' | 'Expert';
  duration_hours: number;
  price_cents: number;
  icon: string | null;
  color: string | null;
  certificate_name: string | null;
  display_order: number;
  module_count: number;
  lesson_count: number;
}

export interface LearningPathWithProgress extends LearningPath {
  enrolled: boolean;
  enrollment_status: 'enrolled' | 'in_progress' | 'completed' | 'expired' | null;
  progress_percent: number;
  completed_lessons: number;
  total_lessons: number;
}

export interface Module {
  id: string;
  slug: string;
  title: string;
  description: string | null;
  duration_minutes: number;
  display_order: number;
  is_assessment: boolean;
  lesson_count: number;
}

export interface ModuleWithProgress extends Module {
  lessons: LessonWithProgress[];
  progress_percent: number;
  completed_lessons: number;
  is_unlocked: boolean;
}

export interface Lesson {
  id: string;
  slug: string;
  title: string;
  description: string | null;
  lesson_type: 'video' | 'text' | 'interactive' | 'quiz';
  duration_minutes: number;
  display_order: number;
  is_preview: boolean;
}

export interface LessonWithProgress extends Lesson {
  status: 'not_started' | 'in_progress' | 'completed';
  video_timestamp_seconds: number;
  completed_at: string | null;
}

export interface LessonContent {
  markdown?: string;
  video_url?: string;
  description?: string;
  code_examples?: { language: string; code: string }[];
  pass_threshold?: number;
  max_attempts?: number;
}

export interface VideoChapter {
  id: string;
  lesson_id: string;
  title: string;
  timestamp_seconds: number;
  display_order: number;
}

export interface LessonDetail {
  id: string;
  module_id: string;
  slug: string;
  title: string;
  description: string | null;
  lesson_type: 'video' | 'text' | 'interactive' | 'quiz';
  content: LessonContent;
  duration_minutes: number;
  display_order: number;
  is_preview: boolean;
  chapters: VideoChapter[];
  questions: QuizQuestionForUser[] | null;
  status: 'not_started' | 'in_progress' | 'completed';
  video_timestamp_seconds: number;
  user_note: string | null;
}

export interface QuizQuestionForUser {
  id: string;
  question_type: 'multiple_choice' | 'multiple_select' | 'true_false' | 'code_challenge';
  question_text: string;
  options: string[];
  points: number;
  display_order: number;
}

export interface QuizData {
  lesson_id: string;
  lesson_title: string;
  pass_threshold: number;
  max_attempts: number;
  questions: QuizQuestionForUser[];
}

export interface QuizAnswer {
  question_id: string;
  answer: number | boolean | number[];
}

export interface QuestionFeedback {
  question_id: string;
  correct: boolean;
  explanation: string | null;
  correct_answer: number | boolean | number[];
}

export interface QuizResult {
  attempt_id: string;
  score_percent: number;
  passed: boolean;
  total_points: number;
  earned_points: number;
  questions_correct: number;
  questions_total: number;
  feedback: QuestionFeedback[];
}

export interface QuizAttempt {
  id: string;
  user_id: string;
  lesson_id: string;
  attempt_number: number;
  answers_json: string;
  score_percent: number;
  passed: boolean;
  time_taken_seconds: number | null;
  started_at: string;
  completed_at: string;
}

export interface Enrollment {
  id: string;
  user_id: string;
  learning_path_id: string;
  status: 'enrolled' | 'in_progress' | 'completed' | 'expired';
  enrolled_at: string;
  started_at: string | null;
  completed_at: string | null;
  expires_at: string | null;
  payment_id: string | null;
}

export interface LessonProgress {
  id: string;
  user_id: string;
  lesson_id: string;
  status: 'not_started' | 'in_progress' | 'completed';
  video_timestamp_seconds: number;
  completed_at: string | null;
  time_spent_seconds: number;
  last_accessed_at: string;
}

export interface PathProgress {
  learning_path_id: string;
  completed_modules: number;
  total_modules: number;
  completed_lessons: number;
  total_lessons: number;
  progress_percent: number;
  total_time_spent_seconds: number;
  last_accessed_at: string | null;
}

export interface Certificate {
  id: string;
  certificate_number: string;
  issued_at: string;
  expires_at: string | null;
}

export interface CertificateDetail extends Certificate {
  path: LearningPath | null;
}

export interface CertificateVerification {
  valid: boolean;
  certificate: Certificate | null;
  path: LearningPath | null;
  holder_name: string | null;
}

export interface AcademyProgress {
  total_certificates: number;
  total_courses_enrolled: number;
  total_courses_completed: number;
  total_lessons_completed: number;
  total_time_spent_hours: number;
  paths: LearningPathWithProgress[];
}

export interface PathDetailWithModules extends LearningPath {
  enrolled: boolean;
  enrollment_status: string | null;
  progress: PathProgress;
  modules: ModuleWithProgress[];
}

export interface CompletionResult {
  progress: LessonProgress;
  certificate_issued: boolean;
  certificate: Certificate | null;
}

// API Response wrapper
export interface ApiResponse<T> {
  success: boolean;
  data: T | null;
  error: string | null;
}

// =============================================================================
// Admin Types
// =============================================================================

export interface CreateLearningPathRequest {
  slug: string;
  title: string;
  description?: string;
  level: string;
  duration_hours: number;
  price_cents?: number;
  icon?: string;
  color?: string;
  certificate_name?: string;
  is_active?: boolean;
  display_order?: number;
}

export interface UpdateLearningPathRequest {
  title?: string;
  description?: string;
  level?: string;
  duration_hours?: number;
  price_cents?: number;
  icon?: string;
  color?: string;
  certificate_name?: string;
  is_active?: boolean;
  display_order?: number;
}

export interface CreateModuleRequest {
  learning_path_id: string;
  slug: string;
  title: string;
  description?: string;
  duration_minutes: number;
  display_order: number;
  prerequisite_module_id?: string;
  is_assessment?: boolean;
}

export interface UpdateModuleRequest {
  title?: string;
  description?: string;
  duration_minutes?: number;
  display_order?: number;
  prerequisite_module_id?: string;
  is_assessment?: boolean;
}

export interface CreateLessonRequest {
  module_id: string;
  slug: string;
  title: string;
  description?: string;
  lesson_type: string;
  content_json: string;
  duration_minutes: number;
  display_order: number;
  is_preview?: boolean;
}

export interface UpdateLessonRequest {
  title?: string;
  description?: string;
  lesson_type?: string;
  content_json?: string;
  duration_minutes?: number;
  display_order?: number;
  is_preview?: boolean;
}

export interface QuizQuestion {
  id: string;
  lesson_id: string;
  question_type: string;
  question_text: string;
  question_data_json: string;
  points: number;
  explanation: string | null;
  display_order: number;
}

export interface CreateQuizQuestionRequest {
  lesson_id: string;
  question_type: string;
  question_text: string;
  question_data_json: string;
  points?: number;
  explanation?: string;
  display_order: number;
}

export interface UpdateQuizQuestionRequest {
  question_type?: string;
  question_text?: string;
  question_data_json?: string;
  points?: number;
  explanation?: string;
  display_order?: number;
}

export interface CreateVideoChapterRequest {
  lesson_id: string;
  title: string;
  timestamp_seconds: number;
  display_order: number;
}

export interface UpdateVideoChapterRequest {
  title?: string;
  timestamp_seconds?: number;
  display_order?: number;
}

// Full learning path with is_active field for admin
export interface LearningPathAdmin extends LearningPath {
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

// Full module with all fields for admin
export interface ModuleAdmin extends Module {
  learning_path_id: string;
  prerequisite_module_id: string | null;
  created_at: string;
}

// Full lesson with content_json for admin
export interface LessonAdmin extends Lesson {
  module_id: string;
  content_json: string;
  created_at: string;
  updated_at: string;
}
