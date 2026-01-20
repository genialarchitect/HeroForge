import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Trophy, XCircle, RotateCcw, ArrowRight, CheckCircle, Clock,
  Target, Zap, Award
} from 'lucide-react';
import { QuizResult, QuestionFeedback } from '../../types/academy';

interface QuizResultsProps {
  result: QuizResult;
  lessonTitle: string;
  passThreshold: number;
  pathSlug: string;
  nextLessonId?: string | null;
  onRetry?: () => void;
  canRetry?: boolean;
}

const QuizResults: React.FC<QuizResultsProps> = ({
  result,
  lessonTitle,
  passThreshold,
  pathSlug,
  nextLessonId,
  onRetry,
  canRetry = true,
}) => {
  const navigate = useNavigate();

  // Calculate grade
  const getGrade = (score: number): { letter: string; color: string } => {
    if (score >= 90) return { letter: 'A', color: 'text-green-400' };
    if (score >= 80) return { letter: 'B', color: 'text-cyan-400' };
    if (score >= 70) return { letter: 'C', color: 'text-yellow-400' };
    if (score >= 60) return { letter: 'D', color: 'text-orange-400' };
    return { letter: 'F', color: 'text-red-400' };
  };

  const grade = getGrade(result.score_percent);

  return (
    <div className="quiz-results">
      {/* Result header */}
      <div
        className={`rounded-xl p-8 mb-8 text-center ${
          result.passed
            ? 'bg-gradient-to-r from-green-900/30 to-cyan-900/30 border border-green-700'
            : 'bg-gradient-to-r from-red-900/30 to-orange-900/30 border border-red-700'
        }`}
      >
        {result.passed ? (
          <>
            <Trophy className="w-20 h-20 text-yellow-400 mx-auto mb-4" />
            <h1 className="text-3xl font-bold text-white mb-2">Congratulations!</h1>
            <p className="text-gray-300">You passed the quiz for "{lessonTitle}"</p>
          </>
        ) : (
          <>
            <XCircle className="w-20 h-20 text-red-400 mx-auto mb-4" />
            <h1 className="text-3xl font-bold text-white mb-2">Not Quite There</h1>
            <p className="text-gray-300">
              You need {passThreshold}% to pass. Keep studying and try again!
            </p>
          </>
        )}
      </div>

      {/* Score breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        {/* Score percentage */}
        <div className="bg-gray-800 rounded-xl p-6 text-center">
          <div className={`text-4xl font-bold mb-2 ${grade.color}`}>{result.score_percent}%</div>
          <div className="text-gray-400 text-sm">Your Score</div>
        </div>

        {/* Grade */}
        <div className="bg-gray-800 rounded-xl p-6 text-center">
          <div className={`text-4xl font-bold mb-2 ${grade.color}`}>{grade.letter}</div>
          <div className="text-gray-400 text-sm">Grade</div>
        </div>

        {/* Questions correct */}
        <div className="bg-gray-800 rounded-xl p-6 text-center">
          <div className="text-4xl font-bold text-white mb-2">
            {result.questions_correct}/{result.questions_total}
          </div>
          <div className="text-gray-400 text-sm">Questions Correct</div>
        </div>

        {/* Points earned */}
        <div className="bg-gray-800 rounded-xl p-6 text-center">
          <div className="text-4xl font-bold text-cyan-400 mb-2">
            {result.earned_points}/{result.total_points}
          </div>
          <div className="text-gray-400 text-sm">Points Earned</div>
        </div>
      </div>

      {/* Progress bar */}
      <div className="bg-gray-800 rounded-xl p-6 mb-8">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm text-gray-400">Score Progress</span>
          <span
            className={`text-sm font-medium ${
              result.passed ? 'text-green-400' : 'text-gray-400'
            }`}
          >
            Passing: {passThreshold}%
          </span>
        </div>
        <div className="relative w-full h-4 bg-gray-700 rounded-full overflow-hidden">
          {/* Pass threshold marker */}
          <div
            className="absolute top-0 bottom-0 w-0.5 bg-yellow-500 z-10"
            style={{ left: `${passThreshold}%` }}
          />
          {/* Score bar */}
          <div
            className={`h-full rounded-full transition-all duration-1000 ${
              result.passed ? 'bg-gradient-to-r from-green-500 to-cyan-500' : 'bg-red-500'
            }`}
            style={{ width: `${result.score_percent}%` }}
          />
        </div>
      </div>

      {/* Question breakdown */}
      <div className="bg-gray-800 rounded-xl p-6 mb-8">
        <h2 className="text-xl font-bold text-white mb-4 flex items-center">
          <Target className="w-5 h-5 mr-2 text-cyan-400" />
          Question Breakdown
        </h2>
        <div className="grid grid-cols-10 gap-2">
          {result.feedback.map((item, index) => (
            <div
              key={item.question_id}
              className={`aspect-square rounded-lg flex items-center justify-center font-medium ${
                item.correct
                  ? 'bg-green-900/50 text-green-400 border border-green-700'
                  : 'bg-red-900/50 text-red-400 border border-red-700'
              }`}
              title={item.correct ? 'Correct' : 'Incorrect'}
            >
              {index + 1}
            </div>
          ))}
        </div>
        <div className="flex items-center justify-center gap-6 mt-4 text-sm">
          <div className="flex items-center">
            <div className="w-4 h-4 bg-green-900/50 border border-green-700 rounded mr-2" />
            <span className="text-gray-400">Correct</span>
          </div>
          <div className="flex items-center">
            <div className="w-4 h-4 bg-red-900/50 border border-red-700 rounded mr-2" />
            <span className="text-gray-400">Incorrect</span>
          </div>
        </div>
      </div>

      {/* Action buttons */}
      <div className="flex flex-col sm:flex-row gap-4">
        {result.passed ? (
          <>
            <button
              onClick={() => navigate(`/academy/path/${pathSlug}`)}
              className="flex-1 bg-gray-700 hover:bg-gray-600 text-white font-medium py-3 px-6 rounded-lg transition-colors flex items-center justify-center"
            >
              <ArrowRight className="w-5 h-5 mr-2 rotate-180" />
              Back to Course
            </button>
            {nextLessonId ? (
              <button
                onClick={() => navigate(`/academy/lesson/${nextLessonId}`)}
                className="flex-1 bg-cyan-600 hover:bg-cyan-700 text-white font-medium py-3 px-6 rounded-lg transition-colors flex items-center justify-center"
              >
                Next Lesson
                <ArrowRight className="w-5 h-5 ml-2" />
              </button>
            ) : (
              <button
                onClick={() => navigate(`/academy/path/${pathSlug}`)}
                className="flex-1 bg-gradient-to-r from-cyan-600 to-purple-600 hover:from-cyan-700 hover:to-purple-700 text-white font-medium py-3 px-6 rounded-lg transition-colors flex items-center justify-center"
              >
                <Award className="w-5 h-5 mr-2" />
                Complete Course
              </button>
            )}
          </>
        ) : (
          <>
            <button
              onClick={() => navigate(`/academy/path/${pathSlug}`)}
              className="flex-1 bg-gray-700 hover:bg-gray-600 text-white font-medium py-3 px-6 rounded-lg transition-colors flex items-center justify-center"
            >
              Review Material
            </button>
            {canRetry && onRetry && (
              <button
                onClick={onRetry}
                className="flex-1 bg-cyan-600 hover:bg-cyan-700 text-white font-medium py-3 px-6 rounded-lg transition-colors flex items-center justify-center"
              >
                <RotateCcw className="w-5 h-5 mr-2" />
                Try Again
              </button>
            )}
          </>
        )}
      </div>

      {/* Motivational message */}
      <div className="mt-8 text-center">
        {result.passed ? (
          <p className="text-gray-400">
            <Zap className="w-4 h-4 inline mr-1 text-yellow-400" />
            Great job! You've demonstrated solid understanding of this material.
          </p>
        ) : (
          <p className="text-gray-400">
            <Clock className="w-4 h-4 inline mr-1 text-cyan-400" />
            Don't worry! Review the lesson content and try again when you're ready.
          </p>
        )}
      </div>
    </div>
  );
};

export default QuizResults;
