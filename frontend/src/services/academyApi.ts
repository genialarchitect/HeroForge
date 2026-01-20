import axios from 'axios';
import {
  LearningPath,
  LearningPathWithProgress,
  PathDetailWithModules,
  Module,
  LessonDetail,
  LessonProgress,
  QuizData,
  QuizAnswer,
  QuizResult,
  QuizAttempt,
  Certificate,
  CertificateDetail,
  CertificateVerification,
  AcademyProgress,
  Enrollment,
  PathProgress,
  ApiResponse,
  CompletionResult,
  LessonWithProgress,
  CreateLearningPathRequest,
  UpdateLearningPathRequest,
  CreateModuleRequest,
  UpdateModuleRequest,
  CreateLessonRequest,
  UpdateLessonRequest,
  QuizQuestion,
  CreateQuizQuestionRequest,
  UpdateQuizQuestionRequest,
  VideoChapter,
  CreateVideoChapterRequest,
  UpdateVideoChapterRequest,
  LearningPathAdmin,
  ModuleAdmin,
  LessonAdmin,
} from '../types/academy';

const api = axios.create({
  baseURL: '/api',
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Helper to extract data from response
function extractData<T>(response: { data: ApiResponse<T> }): T {
  if (response.data.success && response.data.data !== null) {
    return response.data.data;
  }
  throw new Error(response.data.error || 'Unknown error');
}

// =============================================================================
// Public API (no auth required)
// =============================================================================

export const academyPublicApi = {
  /**
   * List all active learning paths (for marketing)
   */
  async listPaths(): Promise<LearningPath[]> {
    const response = await api.get<ApiResponse<LearningPath[]>>('/academy/public/paths');
    return extractData(response);
  },

  /**
   * Get path preview with module list
   */
  async getPath(slug: string): Promise<{ path: LearningPath; modules: Module[] }> {
    const response = await api.get<ApiResponse<{ path: LearningPath; modules: Module[] }>>(
      `/academy/public/paths/${slug}`
    );
    return extractData(response);
  },

  /**
   * Verify certificate by number
   */
  async verifyCertificate(certificateNumber: string): Promise<CertificateVerification> {
    const response = await api.post<ApiResponse<CertificateVerification>>(
      '/academy/public/certificates/verify',
      { certificate_number: certificateNumber }
    );
    return extractData(response);
  },
};

// =============================================================================
// Authenticated API
// =============================================================================

export const academyApi = {
  // ---------------------------------------------------------------------------
  // Learning Paths
  // ---------------------------------------------------------------------------

  /**
   * List paths with user enrollment status and progress
   */
  async listPaths(): Promise<LearningPathWithProgress[]> {
    const response = await api.get<ApiResponse<LearningPathWithProgress[]>>('/academy/paths');
    return extractData(response);
  },

  /**
   * Get full path detail with modules and user progress
   */
  async getPath(slug: string): Promise<PathDetailWithModules> {
    const response = await api.get<ApiResponse<PathDetailWithModules>>(`/academy/paths/${slug}`);
    return extractData(response);
  },

  /**
   * Enroll in a path
   */
  async enroll(slug: string): Promise<Enrollment> {
    const response = await api.post<ApiResponse<Enrollment>>(`/academy/paths/${slug}/enroll`);
    return extractData(response);
  },

  /**
   * Get detailed progress for a path
   */
  async getPathProgress(slug: string): Promise<PathProgress> {
    const response = await api.get<ApiResponse<PathProgress>>(`/academy/paths/${slug}/progress`);
    return extractData(response);
  },

  // ---------------------------------------------------------------------------
  // Modules
  // ---------------------------------------------------------------------------

  /**
   * Get module detail
   */
  async getModule(moduleId: string): Promise<Module> {
    const response = await api.get<ApiResponse<Module>>(`/academy/modules/${moduleId}`);
    return extractData(response);
  },

  /**
   * List lessons in a module
   */
  async listModuleLessons(moduleId: string): Promise<LessonWithProgress[]> {
    const response = await api.get<ApiResponse<LessonWithProgress[]>>(
      `/academy/modules/${moduleId}/lessons`
    );
    return extractData(response);
  },

  // ---------------------------------------------------------------------------
  // Lessons
  // ---------------------------------------------------------------------------

  /**
   * Get lesson content (requires enrollment unless preview)
   */
  async getLesson(lessonId: string): Promise<LessonDetail> {
    const response = await api.get<ApiResponse<LessonDetail>>(`/academy/lessons/${lessonId}`);
    return extractData(response);
  },

  /**
   * Update lesson progress (video timestamp, time spent)
   */
  async updateProgress(
    lessonId: string,
    data: { video_timestamp_seconds?: number; time_spent_seconds?: number }
  ): Promise<LessonProgress> {
    const response = await api.post<ApiResponse<LessonProgress>>(
      `/academy/lessons/${lessonId}/progress`,
      data
    );
    return extractData(response);
  },

  /**
   * Mark lesson as complete
   */
  async completeLesson(lessonId: string): Promise<CompletionResult> {
    const response = await api.post<ApiResponse<CompletionResult>>(
      `/academy/lessons/${lessonId}/complete`
    );
    return extractData(response);
  },

  /**
   * Get user notes for lesson
   */
  async getNotes(lessonId: string): Promise<{ content: string } | null> {
    const response = await api.get<ApiResponse<{ content: string } | null>>(
      `/academy/lessons/${lessonId}/notes`
    );
    return extractData(response);
  },

  /**
   * Update user notes for lesson
   */
  async updateNotes(lessonId: string, content: string): Promise<{ content: string }> {
    const response = await api.put<ApiResponse<{ content: string }>>(
      `/academy/lessons/${lessonId}/notes`,
      { content }
    );
    return extractData(response);
  },

  // ---------------------------------------------------------------------------
  // Quizzes
  // ---------------------------------------------------------------------------

  /**
   * Get quiz questions
   */
  async getQuiz(lessonId: string): Promise<QuizData> {
    const response = await api.get<ApiResponse<QuizData>>(`/academy/quizzes/${lessonId}`);
    return extractData(response);
  },

  /**
   * Submit quiz answers
   */
  async submitQuiz(
    lessonId: string,
    answers: QuizAnswer[],
    timeTakenSeconds?: number
  ): Promise<QuizResult> {
    const response = await api.post<ApiResponse<QuizResult>>(`/academy/quizzes/${lessonId}/submit`, {
      answers,
      time_taken_seconds: timeTakenSeconds,
    });
    return extractData(response);
  },

  /**
   * List user's quiz attempts
   */
  async getQuizAttempts(lessonId: string): Promise<QuizAttempt[]> {
    const response = await api.get<ApiResponse<QuizAttempt[]>>(
      `/academy/quizzes/${lessonId}/attempts`
    );
    return extractData(response);
  },

  // ---------------------------------------------------------------------------
  // Certificates
  // ---------------------------------------------------------------------------

  /**
   * List user's certificates
   */
  async listCertificates(): Promise<Certificate[]> {
    const response = await api.get<ApiResponse<Certificate[]>>('/academy/certificates');
    return extractData(response);
  },

  /**
   * Get certificate detail
   */
  async getCertificate(certificateId: string): Promise<CertificateDetail> {
    const response = await api.get<ApiResponse<CertificateDetail>>(
      `/academy/certificates/${certificateId}`
    );
    return extractData(response);
  },

  /**
   * Download certificate as PDF
   */
  async downloadCertificate(certificateId: string): Promise<Blob> {
    const response = await api.get(`/academy/certificates/${certificateId}/download`, {
      responseType: 'blob',
    });
    return response.data;
  },

  // ---------------------------------------------------------------------------
  // Overall Progress
  // ---------------------------------------------------------------------------

  /**
   * Get overall academy progress
   */
  async getMyProgress(): Promise<AcademyProgress> {
    const response = await api.get<ApiResponse<AcademyProgress>>('/academy/my-progress');
    return extractData(response);
  },
};

// =============================================================================
// Admin API (requires admin role)
// =============================================================================

export const academyAdminApi = {
  // ---------------------------------------------------------------------------
  // Learning Paths
  // ---------------------------------------------------------------------------

  async createPath(data: CreateLearningPathRequest): Promise<LearningPathAdmin> {
    const response = await api.post<ApiResponse<LearningPathAdmin>>('/academy/admin/paths', data);
    return extractData(response);
  },

  async updatePath(id: string, data: UpdateLearningPathRequest): Promise<LearningPathAdmin> {
    const response = await api.put<ApiResponse<LearningPathAdmin>>(`/academy/admin/paths/${id}`, data);
    return extractData(response);
  },

  async deletePath(id: string): Promise<{ deleted: boolean }> {
    const response = await api.delete<ApiResponse<{ deleted: boolean }>>(`/academy/admin/paths/${id}`);
    return extractData(response);
  },

  // ---------------------------------------------------------------------------
  // Modules
  // ---------------------------------------------------------------------------

  async createModule(data: CreateModuleRequest): Promise<ModuleAdmin> {
    const response = await api.post<ApiResponse<ModuleAdmin>>('/academy/admin/modules', data);
    return extractData(response);
  },

  async updateModule(id: string, data: UpdateModuleRequest): Promise<ModuleAdmin> {
    const response = await api.put<ApiResponse<ModuleAdmin>>(`/academy/admin/modules/${id}`, data);
    return extractData(response);
  },

  async deleteModule(id: string): Promise<{ deleted: boolean }> {
    const response = await api.delete<ApiResponse<{ deleted: boolean }>>(`/academy/admin/modules/${id}`);
    return extractData(response);
  },

  // ---------------------------------------------------------------------------
  // Lessons
  // ---------------------------------------------------------------------------

  async createLesson(data: CreateLessonRequest): Promise<LessonAdmin> {
    const response = await api.post<ApiResponse<LessonAdmin>>('/academy/admin/lessons', data);
    return extractData(response);
  },

  async updateLesson(id: string, data: UpdateLessonRequest): Promise<LessonAdmin> {
    const response = await api.put<ApiResponse<LessonAdmin>>(`/academy/admin/lessons/${id}`, data);
    return extractData(response);
  },

  async deleteLesson(id: string): Promise<{ deleted: boolean }> {
    const response = await api.delete<ApiResponse<{ deleted: boolean }>>(`/academy/admin/lessons/${id}`);
    return extractData(response);
  },

  // ---------------------------------------------------------------------------
  // Quiz Questions
  // ---------------------------------------------------------------------------

  async listQuestions(lessonId: string): Promise<QuizQuestion[]> {
    const response = await api.get<ApiResponse<QuizQuestion[]>>(`/academy/admin/lessons/${lessonId}/questions`);
    return extractData(response);
  },

  async createQuestion(data: CreateQuizQuestionRequest): Promise<QuizQuestion> {
    const response = await api.post<ApiResponse<QuizQuestion>>('/academy/admin/questions', data);
    return extractData(response);
  },

  async updateQuestion(id: string, data: UpdateQuizQuestionRequest): Promise<QuizQuestion> {
    const response = await api.put<ApiResponse<QuizQuestion>>(`/academy/admin/questions/${id}`, data);
    return extractData(response);
  },

  async deleteQuestion(id: string): Promise<{ deleted: boolean }> {
    const response = await api.delete<ApiResponse<{ deleted: boolean }>>(`/academy/admin/questions/${id}`);
    return extractData(response);
  },

  // ---------------------------------------------------------------------------
  // Video Chapters
  // ---------------------------------------------------------------------------

  async createChapter(data: CreateVideoChapterRequest): Promise<VideoChapter> {
    const response = await api.post<ApiResponse<VideoChapter>>('/academy/admin/chapters', data);
    return extractData(response);
  },

  async updateChapter(id: string, data: UpdateVideoChapterRequest): Promise<VideoChapter> {
    const response = await api.put<ApiResponse<VideoChapter>>(`/academy/admin/chapters/${id}`, data);
    return extractData(response);
  },

  async deleteChapter(id: string): Promise<{ deleted: boolean }> {
    const response = await api.delete<ApiResponse<{ deleted: boolean }>>(`/academy/admin/chapters/${id}`);
    return extractData(response);
  },
};

export default academyApi;
