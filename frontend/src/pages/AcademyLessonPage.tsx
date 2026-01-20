import React, { useEffect, useState, useCallback } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import {
  BookOpen, Play, HelpCircle, Clock, ArrowLeft,
  ChevronLeft, ChevronRight, FileText, CheckCircle
} from 'lucide-react';
import { useAcademyStore } from '../store/academyStore';
import { useAuthStore } from '../store/authStore';
import { VideoPlayer, MarkdownViewer, NotesEditor, LessonNavigation } from '../components/academy';
import { LessonWithProgress } from '../types/academy';
import { toast } from 'react-toastify';

const AcademyLessonPage: React.FC = () => {
  const { lessonId } = useParams<{ lessonId: string }>();
  const navigate = useNavigate();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  const {
    currentLesson,
    currentPath,
    isLoadingLesson,
    isUpdatingProgress,
    error,
    fetchLesson,
    updateLessonProgress,
    completeLesson,
    updateNotes,
    clearError,
    clearCurrentLesson,
  } = useAcademyStore();

  const [showNotes, setShowNotes] = useState(false);
  const [previousLesson, setPreviousLesson] = useState<LessonWithProgress | null>(null);
  const [nextLesson, setNextLesson] = useState<LessonWithProgress | null>(null);

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!isAuthenticated) {
      navigate(`/login?redirect=/academy/lesson/${lessonId}`);
    }
  }, [isAuthenticated, lessonId, navigate]);

  // Fetch lesson on mount
  useEffect(() => {
    if (lessonId && isAuthenticated) {
      fetchLesson(lessonId);
    }

    return () => {
      clearCurrentLesson();
    };
  }, [lessonId, isAuthenticated, fetchLesson, clearCurrentLesson]);

  // Find previous/next lessons based on currentPath
  useEffect(() => {
    if (!currentPath || !currentLesson) return;

    const allLessons = currentPath.modules.flatMap((m) => m.lessons);
    const currentIndex = allLessons.findIndex((l) => l.id === currentLesson.id);

    if (currentIndex > 0) {
      setPreviousLesson(allLessons[currentIndex - 1]);
    } else {
      setPreviousLesson(null);
    }

    if (currentIndex < allLessons.length - 1) {
      setNextLesson(allLessons[currentIndex + 1]);
    } else {
      setNextLesson(null);
    }
  }, [currentPath, currentLesson]);

  // Handle errors
  useEffect(() => {
    if (error) {
      toast.error(error);
      clearError();
    }
  }, [error, clearError]);

  // Handle video progress
  const handleVideoProgress = useCallback(
    (timestamp: number, timeSpent: number) => {
      if (lessonId) {
        updateLessonProgress(lessonId, timestamp, timeSpent);
      }
    },
    [lessonId, updateLessonProgress]
  );

  // Handle video complete
  const handleVideoComplete = useCallback(() => {
    if (lessonId && currentLesson?.status !== 'completed') {
      completeLesson(lessonId).then((result) => {
        if (result?.certificate_issued) {
          toast.success('Congratulations! You earned a certificate!');
        }
      });
    }
  }, [lessonId, currentLesson, completeLesson]);

  // Handle manual completion
  const handleMarkComplete = async () => {
    if (!lessonId) return;

    const result = await completeLesson(lessonId);
    if (result) {
      toast.success('Lesson marked as complete!');
      if (result.certificate_issued) {
        toast.success('You earned a certificate!', {
          autoClose: 5000,
        });
      }
    }
  };

  // Handle notes save
  const handleSaveNotes = async (content: string) => {
    if (!lessonId) return;
    await updateNotes(lessonId, content);
  };

  // Get path slug for navigation
  const getPathSlug = () => {
    if (currentPath) return currentPath.slug;
    return 'beginner'; // fallback
  };

  // Loading state
  if (isLoadingLesson || !currentLesson) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-gray-400">Loading lesson...</p>
        </div>
      </div>
    );
  }

  const lessonTypeIcons: Record<string, React.ReactNode> = {
    video: <Play className="w-5 h-5" />,
    text: <BookOpen className="w-5 h-5" />,
    interactive: <BookOpen className="w-5 h-5" />,
    quiz: <HelpCircle className="w-5 h-5" />,
  };

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center">
            <button
              onClick={() => navigate(`/academy/path/${getPathSlug()}`)}
              className="mr-4 text-gray-400 hover:text-white transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
            <Link to="/" className="flex items-center space-x-2">
              <span className="text-xl font-bold text-cyan-400">HeroForge</span>
            </Link>
            <span className="text-gray-500 mx-2">•</span>
            <span className="text-gray-400 text-sm">Academy</span>
          </div>

          <div className="flex items-center space-x-4">
            {/* Toggle notes */}
            <button
              onClick={() => setShowNotes(!showNotes)}
              className={`flex items-center px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                showNotes
                  ? 'bg-cyan-600 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              <FileText className="w-4 h-4 mr-2" />
              Notes
            </button>

            {/* Progress indicator */}
            {currentLesson.status === 'completed' ? (
              <span className="flex items-center text-green-400 text-sm">
                <CheckCircle className="w-4 h-4 mr-1" />
                Completed
              </span>
            ) : (
              <span className="flex items-center text-gray-400 text-sm">
                <Clock className="w-4 h-4 mr-1" />
                {currentLesson.duration_minutes} min
              </span>
            )}
          </div>
        </div>
      </header>

      <div className="max-w-6xl mx-auto px-4 py-6">
        <div className={`flex gap-6 ${showNotes ? '' : ''}`}>
          {/* Main content area */}
          <div className={`${showNotes ? 'w-2/3' : 'w-full'} transition-all`}>
            {/* Lesson header */}
            <div className="mb-6">
              <div className="flex items-center space-x-2 mb-2">
                <span
                  className={`p-2 rounded-lg ${
                    currentLesson.lesson_type === 'video'
                      ? 'bg-red-900/50 text-red-400'
                      : currentLesson.lesson_type === 'quiz'
                      ? 'bg-purple-900/50 text-purple-400'
                      : 'bg-cyan-900/50 text-cyan-400'
                  }`}
                >
                  {lessonTypeIcons[currentLesson.lesson_type]}
                </span>
                <span className="text-sm text-gray-500 uppercase">{currentLesson.lesson_type}</span>
              </div>
              <h1 className="text-3xl font-bold text-white mb-2">{currentLesson.title}</h1>
              {currentLesson.description && (
                <p className="text-gray-400">{currentLesson.description}</p>
              )}
            </div>

            {/* Video lesson */}
            {currentLesson.lesson_type === 'video' && currentLesson.content?.video_url && (
              <div className="mb-8">
                <VideoPlayer
                  videoUrl={currentLesson.content.video_url}
                  chapters={currentLesson.chapters || []}
                  initialTimestamp={currentLesson.video_timestamp_seconds || 0}
                  onProgress={handleVideoProgress}
                  onComplete={handleVideoComplete}
                />
              </div>
            )}

            {/* Text/interactive lesson */}
            {(currentLesson.lesson_type === 'text' || currentLesson.lesson_type === 'interactive') &&
              currentLesson.content?.markdown && (
                <div className="mb-8 bg-gray-800 rounded-xl p-8">
                  <MarkdownViewer
                    content={currentLesson.content.markdown}
                    codeExamples={currentLesson.content.code_examples}
                  />
                </div>
              )}

            {/* Quiz lesson - redirect to quiz page */}
            {currentLesson.lesson_type === 'quiz' && (
              <div className="mb-8 bg-gradient-to-r from-purple-900/30 to-pink-900/30 border border-purple-700 rounded-xl p-8 text-center">
                <HelpCircle className="w-16 h-16 text-purple-400 mx-auto mb-4" />
                <h2 className="text-2xl font-bold text-white mb-2">Quiz Assessment</h2>
                <p className="text-gray-400 mb-6">
                  Test your knowledge with this interactive quiz. You need to score at least{' '}
                  {currentLesson.content?.pass_threshold || 70}% to pass.
                </p>
                <div className="flex items-center justify-center gap-4 text-sm text-gray-500 mb-6">
                  {currentLesson.questions && (
                    <span>{currentLesson.questions.length} questions</span>
                  )}
                  {currentLesson.content?.max_attempts && (
                    <>
                      <span>•</span>
                      <span>Max {currentLesson.content.max_attempts} attempts</span>
                    </>
                  )}
                </div>
                <button
                  onClick={() => navigate(`/academy/quiz/${lessonId}`)}
                  className="bg-purple-600 hover:bg-purple-700 text-white font-medium px-8 py-3 rounded-lg transition-colors"
                >
                  Start Quiz
                </button>
              </div>
            )}

            {/* Lesson description/content fallback */}
            {currentLesson.content?.description && (
              <div className="mb-8 bg-gray-800 rounded-xl p-8">
                <p className="text-gray-300">{currentLesson.content.description}</p>
              </div>
            )}

            {/* Navigation */}
            <LessonNavigation
              previousLesson={
                previousLesson
                  ? {
                      id: previousLesson.id,
                      title: previousLesson.title,
                      status: previousLesson.status,
                      duration_minutes: previousLesson.duration_minutes,
                    }
                  : null
              }
              nextLesson={
                nextLesson
                  ? {
                      id: nextLesson.id,
                      title: nextLesson.title,
                      status: nextLesson.status,
                      duration_minutes: nextLesson.duration_minutes,
                    }
                  : null
              }
              currentLesson={{
                id: currentLesson.id,
                title: currentLesson.title,
                status: currentLesson.status,
                duration_minutes: currentLesson.duration_minutes,
              }}
              pathSlug={getPathSlug()}
              onComplete={handleMarkComplete}
              isCompleted={currentLesson.status === 'completed'}
            />
          </div>

          {/* Notes sidebar */}
          {showNotes && (
            <div className="w-1/3 sticky top-20 h-fit">
              <NotesEditor
                initialContent={currentLesson.user_note}
                onSave={handleSaveNotes}
                autoSave={true}
                autoSaveDelay={3000}
              />
            </div>
          )}
        </div>
      </div>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-16">
        <div className="max-w-6xl mx-auto px-4 py-6">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <p className="text-gray-400 text-sm">
              &copy; 2026 Genial Architect Cybersecurity Research Associates. All rights reserved.
            </p>
            <div className="flex space-x-6 mt-4 md:mt-0">
              <Link to="/legal/terms" className="text-gray-400 hover:text-white text-sm">
                Terms
              </Link>
              <Link to="/legal/privacy" className="text-gray-400 hover:text-white text-sm">
                Privacy
              </Link>
              <Link to="/docs" className="text-gray-400 hover:text-white text-sm">
                Documentation
              </Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default AcademyLessonPage;
