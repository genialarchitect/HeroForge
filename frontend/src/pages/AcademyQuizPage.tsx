import React, { useEffect, useState, useCallback } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, Clock, HelpCircle, ChevronLeft, ChevronRight,
  AlertCircle, CheckCircle
} from 'lucide-react';
import { useAcademyStore } from '../store/academyStore';
import { useAuthStore } from '../store/authStore';
import { QuizQuestion, QuizResults } from '../components/academy';
import { QuizQuestionForUser, QuizResult } from '../types/academy';
import { toast } from 'react-toastify';

type AnswerMap = Record<string, number | boolean | number[]>;

const AcademyQuizPage: React.FC = () => {
  const { lessonId } = useParams<{ lessonId: string }>();
  const navigate = useNavigate();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  const {
    currentQuiz,
    quizResult,
    currentPath,
    isLoadingQuiz,
    isSubmittingQuiz,
    error,
    fetchQuiz,
    submitQuiz,
    clearError,
    clearQuizResult,
  } = useAcademyStore();

  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [answers, setAnswers] = useState<AnswerMap>({});
  const [showResults, setShowResults] = useState(false);
  const [startTime] = useState(Date.now());
  const [timeElapsed, setTimeElapsed] = useState(0);

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!isAuthenticated) {
      navigate(`/login?redirect=/academy/quiz/${lessonId}`);
    }
  }, [isAuthenticated, lessonId, navigate]);

  // Fetch quiz on mount
  useEffect(() => {
    if (lessonId && isAuthenticated) {
      fetchQuiz(lessonId);
      clearQuizResult();
    }
  }, [lessonId, isAuthenticated, fetchQuiz, clearQuizResult]);

  // Timer
  useEffect(() => {
    const timer = setInterval(() => {
      setTimeElapsed(Math.floor((Date.now() - startTime) / 1000));
    }, 1000);

    return () => clearInterval(timer);
  }, [startTime]);

  // Handle errors
  useEffect(() => {
    if (error) {
      toast.error(error);
      clearError();
    }
  }, [error, clearError]);

  // Format time
  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  // Handle answer selection
  const handleAnswer = useCallback(
    (questionId: string, answer: number | boolean | number[]) => {
      setAnswers((prev) => ({
        ...prev,
        [questionId]: answer,
      }));
    },
    []
  );

  // Navigate questions
  const goToQuestion = (index: number) => {
    if (index >= 0 && currentQuiz && index < currentQuiz.questions.length) {
      setCurrentQuestionIndex(index);
    }
  };

  // Check if all questions answered
  const allQuestionsAnswered = useCallback(() => {
    if (!currentQuiz) return false;
    return currentQuiz.questions.every(
      (q) => answers[q.id] !== undefined && answers[q.id] !== null
    );
  }, [currentQuiz, answers]);

  // Submit quiz
  const handleSubmit = async () => {
    if (!lessonId || !currentQuiz) return;

    const formattedAnswers = currentQuiz.questions.map((q) => ({
      question_id: q.id,
      answer: answers[q.id],
    }));

    const result = await submitQuiz(lessonId, formattedAnswers, timeElapsed);
    if (result) {
      setShowResults(true);
    }
  };

  // Retry quiz
  const handleRetry = () => {
    setAnswers({});
    setCurrentQuestionIndex(0);
    setShowResults(false);
    clearQuizResult();
  };

  // Get path slug for navigation
  const getPathSlug = () => {
    if (currentPath) return currentPath.slug;
    return 'beginner'; // fallback
  };

  // Find next lesson
  const findNextLesson = () => {
    if (!currentPath || !currentQuiz) return null;

    const allLessons = currentPath.modules.flatMap((m) => m.lessons);
    const currentLessonId = currentQuiz.lesson_id;
    const currentIndex = allLessons.findIndex((l) => l.id === currentLessonId);

    if (currentIndex < allLessons.length - 1) {
      return allLessons[currentIndex + 1].id;
    }
    return null;
  };

  // Loading state
  if (isLoadingQuiz || !currentQuiz) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-gray-400">Loading quiz...</p>
        </div>
      </div>
    );
  }

  // Results view
  if (showResults && quizResult) {
    return (
      <div className="min-h-screen bg-gray-900">
        {/* Header */}
        <header className="bg-gray-800 border-b border-gray-700">
          <div className="max-w-4xl mx-auto px-4 py-4 flex items-center">
            <Link to="/" className="flex items-center space-x-2">
              <span className="text-xl font-bold text-cyan-400">HeroForge</span>
            </Link>
            <span className="text-gray-500 mx-2">•</span>
            <span className="text-gray-400 text-sm">Quiz Results</span>
          </div>
        </header>

        <main className="max-w-4xl mx-auto px-4 py-8">
          <QuizResults
            result={quizResult}
            lessonTitle={currentQuiz.lesson_title}
            passThreshold={currentQuiz.pass_threshold}
            pathSlug={getPathSlug()}
            nextLessonId={findNextLesson()}
            onRetry={handleRetry}
            canRetry={true}
          />
        </main>
      </div>
    );
  }

  const currentQuestion = currentQuiz.questions[currentQuestionIndex];
  const answeredCount = Object.keys(answers).length;
  const progress = (answeredCount / currentQuiz.questions.length) * 100;

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 sticky top-0 z-50">
        <div className="max-w-4xl mx-auto px-4 py-3 flex items-center justify-between">
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
            <span className="text-gray-400 text-sm">Quiz</span>
          </div>

          <div className="flex items-center space-x-4">
            {/* Timer */}
            <div className="flex items-center text-gray-400">
              <Clock className="w-4 h-4 mr-1" />
              <span className="font-mono">{formatTime(timeElapsed)}</span>
            </div>

            {/* Progress */}
            <div className="flex items-center text-gray-400">
              <CheckCircle className="w-4 h-4 mr-1" />
              <span>
                {answeredCount}/{currentQuiz.questions.length}
              </span>
            </div>
          </div>
        </div>

        {/* Progress bar */}
        <div className="w-full h-1 bg-gray-700">
          <div
            className="h-full bg-cyan-500 transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 py-8">
        {/* Quiz title */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-white mb-2">{currentQuiz.lesson_title}</h1>
          <p className="text-gray-400">
            Answer all questions and score at least {currentQuiz.pass_threshold}% to pass
          </p>
        </div>

        {/* Question navigation dots */}
        <div className="flex items-center justify-center gap-2 mb-8 flex-wrap">
          {currentQuiz.questions.map((q, index) => {
            const isAnswered = answers[q.id] !== undefined;
            const isCurrent = index === currentQuestionIndex;

            return (
              <button
                key={q.id}
                onClick={() => goToQuestion(index)}
                className={`w-8 h-8 rounded-full text-sm font-medium transition-all ${
                  isCurrent
                    ? 'bg-cyan-500 text-white scale-110'
                    : isAnswered
                    ? 'bg-green-600 text-white'
                    : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
                }`}
              >
                {index + 1}
              </button>
            );
          })}
        </div>

        {/* Current question */}
        <QuizQuestion
          questionNumber={currentQuestionIndex + 1}
          totalQuestions={currentQuiz.questions.length}
          questionType={currentQuestion.question_type}
          questionText={currentQuestion.question_text}
          options={currentQuestion.options}
          points={currentQuestion.points}
          selectedAnswer={answers[currentQuestion.id] ?? null}
          onAnswer={(answer) => handleAnswer(currentQuestion.id, answer)}
        />

        {/* Navigation buttons */}
        <div className="flex justify-between items-center mt-6">
          <button
            onClick={() => goToQuestion(currentQuestionIndex - 1)}
            disabled={currentQuestionIndex === 0}
            className={`flex items-center px-4 py-2 rounded-lg transition-colors ${
              currentQuestionIndex === 0
                ? 'bg-gray-800 text-gray-600 cursor-not-allowed'
                : 'bg-gray-700 text-white hover:bg-gray-600'
            }`}
          >
            <ChevronLeft className="w-5 h-5 mr-1" />
            Previous
          </button>

          <div className="text-center">
            {!allQuestionsAnswered() && (
              <span className="text-sm text-yellow-400 flex items-center">
                <AlertCircle className="w-4 h-4 mr-1" />
                {currentQuiz.questions.length - answeredCount} questions remaining
              </span>
            )}
          </div>

          {currentQuestionIndex < currentQuiz.questions.length - 1 ? (
            <button
              onClick={() => goToQuestion(currentQuestionIndex + 1)}
              className="flex items-center px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
            >
              Next
              <ChevronRight className="w-5 h-5 ml-1" />
            </button>
          ) : (
            <button
              onClick={handleSubmit}
              disabled={!allQuestionsAnswered() || isSubmittingQuiz}
              className={`flex items-center px-6 py-2 rounded-lg transition-colors ${
                allQuestionsAnswered() && !isSubmittingQuiz
                  ? 'bg-green-600 hover:bg-green-700 text-white'
                  : 'bg-gray-700 text-gray-400 cursor-not-allowed'
              }`}
            >
              {isSubmittingQuiz ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                  Submitting...
                </>
              ) : (
                <>
                  <CheckCircle className="w-5 h-5 mr-2" />
                  Submit Quiz
                </>
              )}
            </button>
          )}
        </div>

        {/* Submit warning */}
        {currentQuestionIndex === currentQuiz.questions.length - 1 && !allQuestionsAnswered() && (
          <div className="mt-4 p-4 bg-yellow-900/20 border border-yellow-700 rounded-lg text-center">
            <p className="text-yellow-400 text-sm">
              Please answer all questions before submitting the quiz.
            </p>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-16">
        <div className="max-w-4xl mx-auto px-4 py-6">
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
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default AcademyQuizPage;
