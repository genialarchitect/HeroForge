import { create } from 'zustand';
import { academyApi, academyPublicApi } from '../services/academyApi';
import {
  LearningPath,
  LearningPathWithProgress,
  PathDetailWithModules,
  LessonDetail,
  QuizData,
  QuizResult,
  QuizAttempt,
  Certificate,
  AcademyProgress,
  CompletionResult,
} from '../types/academy';

interface AcademyState {
  // Data
  publicPaths: LearningPath[];
  userPaths: LearningPathWithProgress[];
  currentPath: PathDetailWithModules | null;
  currentLesson: LessonDetail | null;
  currentQuiz: QuizData | null;
  quizResult: QuizResult | null;
  quizAttempts: QuizAttempt[];
  certificates: Certificate[];
  overallProgress: AcademyProgress | null;

  // Loading states
  isLoadingPaths: boolean;
  isLoadingPath: boolean;
  isLoadingLesson: boolean;
  isLoadingQuiz: boolean;
  isSubmittingQuiz: boolean;
  isEnrolling: boolean;
  isUpdatingProgress: boolean;

  // Error state
  error: string | null;

  // Actions - Public
  fetchPublicPaths: () => Promise<void>;
  fetchPublicPath: (slug: string) => Promise<void>;

  // Actions - Authenticated
  fetchUserPaths: () => Promise<void>;
  fetchPath: (slug: string) => Promise<void>;
  enroll: (slug: string) => Promise<void>;
  fetchLesson: (lessonId: string) => Promise<void>;
  updateLessonProgress: (lessonId: string, timestamp: number, timeSpent?: number) => Promise<void>;
  completeLesson: (lessonId: string) => Promise<CompletionResult | null>;
  updateNotes: (lessonId: string, content: string) => Promise<void>;
  fetchQuiz: (lessonId: string) => Promise<void>;
  submitQuiz: (lessonId: string, answers: { question_id: string; answer: number | boolean | number[] }[], timeTaken?: number) => Promise<QuizResult | null>;
  fetchQuizAttempts: (lessonId: string) => Promise<void>;
  fetchCertificates: () => Promise<void>;
  fetchOverallProgress: () => Promise<void>;

  // Utility
  clearError: () => void;
  clearCurrentLesson: () => void;
  clearQuizResult: () => void;
}

export const useAcademyStore = create<AcademyState>((set, get) => ({
  // Initial state
  publicPaths: [],
  userPaths: [],
  currentPath: null,
  currentLesson: null,
  currentQuiz: null,
  quizResult: null,
  quizAttempts: [],
  certificates: [],
  overallProgress: null,

  isLoadingPaths: false,
  isLoadingPath: false,
  isLoadingLesson: false,
  isLoadingQuiz: false,
  isSubmittingQuiz: false,
  isEnrolling: false,
  isUpdatingProgress: false,

  error: null,

  // Public actions
  fetchPublicPaths: async () => {
    set({ isLoadingPaths: true, error: null });
    try {
      const paths = await academyPublicApi.listPaths();
      set({ publicPaths: paths, isLoadingPaths: false });
    } catch (error) {
      set({ error: (error as Error).message, isLoadingPaths: false });
    }
  },

  fetchPublicPath: async (slug: string) => {
    set({ isLoadingPath: true, error: null });
    try {
      const data = await academyPublicApi.getPath(slug);
      // Convert to PathDetailWithModules format
      const pathDetail: PathDetailWithModules = {
        ...data.path,
        enrolled: false,
        enrollment_status: null,
        progress: {
          learning_path_id: data.path.id,
          completed_modules: 0,
          total_modules: data.modules.length,
          completed_lessons: 0,
          total_lessons: data.path.lesson_count,
          progress_percent: 0,
          total_time_spent_seconds: 0,
          last_accessed_at: null,
        },
        modules: data.modules.map(m => ({
          ...m,
          lessons: [],
          progress_percent: 0,
          completed_lessons: 0,
          is_unlocked: false,
        })),
      };
      set({ currentPath: pathDetail, isLoadingPath: false });
    } catch (error) {
      set({ error: (error as Error).message, isLoadingPath: false });
    }
  },

  // Authenticated actions
  fetchUserPaths: async () => {
    set({ isLoadingPaths: true, error: null });
    try {
      const paths = await academyApi.listPaths();
      set({ userPaths: paths, isLoadingPaths: false });
    } catch (error) {
      set({ error: (error as Error).message, isLoadingPaths: false });
    }
  },

  fetchPath: async (slug: string) => {
    set({ isLoadingPath: true, error: null });
    try {
      const path = await academyApi.getPath(slug);
      set({ currentPath: path, isLoadingPath: false });
    } catch (error) {
      set({ error: (error as Error).message, isLoadingPath: false });
    }
  },

  enroll: async (slug: string) => {
    set({ isEnrolling: true, error: null });
    try {
      await academyApi.enroll(slug);
      // Refresh path data
      const path = await academyApi.getPath(slug);
      set({ currentPath: path, isEnrolling: false });
    } catch (error) {
      set({ error: (error as Error).message, isEnrolling: false });
    }
  },

  fetchLesson: async (lessonId: string) => {
    set({ isLoadingLesson: true, error: null });
    try {
      const lesson = await academyApi.getLesson(lessonId);
      set({ currentLesson: lesson, isLoadingLesson: false });
    } catch (error) {
      set({ error: (error as Error).message, isLoadingLesson: false });
    }
  },

  updateLessonProgress: async (lessonId: string, timestamp: number, timeSpent?: number) => {
    set({ isUpdatingProgress: true });
    try {
      await academyApi.updateProgress(lessonId, {
        video_timestamp_seconds: timestamp,
        time_spent_seconds: timeSpent,
      });
      // Update local state
      const currentLesson = get().currentLesson;
      if (currentLesson && currentLesson.id === lessonId) {
        set({
          currentLesson: {
            ...currentLesson,
            video_timestamp_seconds: timestamp,
            status: currentLesson.status === 'not_started' ? 'in_progress' : currentLesson.status,
          },
          isUpdatingProgress: false,
        });
      } else {
        set({ isUpdatingProgress: false });
      }
    } catch (error) {
      set({ error: (error as Error).message, isUpdatingProgress: false });
    }
  },

  completeLesson: async (lessonId: string) => {
    set({ isUpdatingProgress: true, error: null });
    try {
      const result = await academyApi.completeLesson(lessonId);
      // Update local state
      const currentLesson = get().currentLesson;
      if (currentLesson && currentLesson.id === lessonId) {
        set({
          currentLesson: {
            ...currentLesson,
            status: 'completed',
          },
          isUpdatingProgress: false,
        });
      } else {
        set({ isUpdatingProgress: false });
      }
      return result;
    } catch (error) {
      set({ error: (error as Error).message, isUpdatingProgress: false });
      return null;
    }
  },

  updateNotes: async (lessonId: string, content: string) => {
    try {
      await academyApi.updateNotes(lessonId, content);
      // Update local state
      const currentLesson = get().currentLesson;
      if (currentLesson && currentLesson.id === lessonId) {
        set({
          currentLesson: {
            ...currentLesson,
            user_note: content,
          },
        });
      }
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  fetchQuiz: async (lessonId: string) => {
    set({ isLoadingQuiz: true, error: null, quizResult: null });
    try {
      const quiz = await academyApi.getQuiz(lessonId);
      set({ currentQuiz: quiz, isLoadingQuiz: false });
    } catch (error) {
      set({ error: (error as Error).message, isLoadingQuiz: false });
    }
  },

  submitQuiz: async (lessonId: string, answers, timeTaken) => {
    set({ isSubmittingQuiz: true, error: null });
    try {
      const result = await academyApi.submitQuiz(lessonId, answers, timeTaken);
      set({ quizResult: result, isSubmittingQuiz: false });
      return result;
    } catch (error) {
      set({ error: (error as Error).message, isSubmittingQuiz: false });
      return null;
    }
  },

  fetchQuizAttempts: async (lessonId: string) => {
    try {
      const attempts = await academyApi.getQuizAttempts(lessonId);
      set({ quizAttempts: attempts });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  fetchCertificates: async () => {
    try {
      const certificates = await academyApi.listCertificates();
      set({ certificates });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  fetchOverallProgress: async () => {
    try {
      const progress = await academyApi.getMyProgress();
      set({ overallProgress: progress });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  // Utility actions
  clearError: () => set({ error: null }),
  clearCurrentLesson: () => set({ currentLesson: null }),
  clearQuizResult: () => set({ quizResult: null }),
}));

export default useAcademyStore;
