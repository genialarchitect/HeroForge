import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronLeft, ChevronRight, CheckCircle, Circle, Clock } from 'lucide-react';

interface LessonInfo {
  id: string;
  title: string;
  status: 'not_started' | 'in_progress' | 'completed';
  duration_minutes: number;
}

interface LessonNavigationProps {
  previousLesson?: LessonInfo | null;
  nextLesson?: LessonInfo | null;
  currentLesson: LessonInfo;
  pathSlug: string;
  onComplete?: () => void;
  isCompleted?: boolean;
}

const LessonNavigation: React.FC<LessonNavigationProps> = ({
  previousLesson,
  nextLesson,
  currentLesson,
  pathSlug,
  onComplete,
  isCompleted = false,
}) => {
  const navigate = useNavigate();

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'in_progress':
        return <Circle className="w-4 h-4 text-yellow-400 fill-yellow-400/20" />;
      default:
        return <Circle className="w-4 h-4 text-gray-500" />;
    }
  };

  return (
    <div className="lesson-navigation">
      {/* Progress indicator */}
      <div className="bg-gray-800 rounded-lg p-4 mb-4">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center space-x-2">
            {getStatusIcon(currentLesson.status)}
            <span className="text-sm text-gray-400">
              {currentLesson.status === 'completed'
                ? 'Completed'
                : currentLesson.status === 'in_progress'
                ? 'In Progress'
                : 'Not Started'}
            </span>
          </div>
          <div className="flex items-center text-sm text-gray-500">
            <Clock className="w-4 h-4 mr-1" />
            {currentLesson.duration_minutes} min
          </div>
        </div>

        {/* Mark as complete button */}
        {!isCompleted && onComplete && (
          <button
            onClick={onComplete}
            className="w-full mt-2 bg-green-600 hover:bg-green-700 text-white font-medium py-2 px-4 rounded-lg transition-colors flex items-center justify-center"
          >
            <CheckCircle className="w-5 h-5 mr-2" />
            Mark as Complete
          </button>
        )}

        {isCompleted && (
          <div className="w-full mt-2 bg-green-900/30 text-green-400 font-medium py-2 px-4 rounded-lg flex items-center justify-center">
            <CheckCircle className="w-5 h-5 mr-2" />
            Lesson Completed
          </div>
        )}
      </div>

      {/* Navigation buttons */}
      <div className="flex justify-between items-stretch gap-4">
        {/* Previous lesson */}
        {previousLesson ? (
          <button
            onClick={() => navigate(`/academy/lesson/${previousLesson.id}`)}
            className="flex-1 bg-gray-800 hover:bg-gray-700 rounded-lg p-4 text-left transition-colors group"
          >
            <div className="flex items-center text-gray-500 mb-1">
              <ChevronLeft className="w-4 h-4 mr-1 group-hover:text-cyan-400 transition-colors" />
              <span className="text-xs uppercase">Previous</span>
            </div>
            <div className="flex items-center space-x-2">
              {getStatusIcon(previousLesson.status)}
              <span className="text-white font-medium truncate">{previousLesson.title}</span>
            </div>
          </button>
        ) : (
          <button
            onClick={() => navigate(`/academy/path/${pathSlug}`)}
            className="flex-1 bg-gray-800 hover:bg-gray-700 rounded-lg p-4 text-left transition-colors group"
          >
            <div className="flex items-center text-gray-500 mb-1">
              <ChevronLeft className="w-4 h-4 mr-1 group-hover:text-cyan-400 transition-colors" />
              <span className="text-xs uppercase">Back to Path</span>
            </div>
            <span className="text-white font-medium">Return to course overview</span>
          </button>
        )}

        {/* Next lesson */}
        {nextLesson ? (
          <button
            onClick={() => navigate(`/academy/lesson/${nextLesson.id}`)}
            className="flex-1 bg-cyan-600 hover:bg-cyan-700 rounded-lg p-4 text-left transition-colors group"
          >
            <div className="flex items-center justify-end text-cyan-200 mb-1">
              <span className="text-xs uppercase">Next</span>
              <ChevronRight className="w-4 h-4 ml-1" />
            </div>
            <div className="flex items-center justify-end space-x-2">
              <span className="text-white font-medium truncate">{nextLesson.title}</span>
              {getStatusIcon(nextLesson.status)}
            </div>
          </button>
        ) : (
          <button
            onClick={() => navigate(`/academy/path/${pathSlug}`)}
            className="flex-1 bg-gradient-to-r from-cyan-600 to-purple-600 hover:from-cyan-700 hover:to-purple-700 rounded-lg p-4 text-left transition-colors"
          >
            <div className="flex items-center justify-end text-cyan-200 mb-1">
              <span className="text-xs uppercase">Complete</span>
              <ChevronRight className="w-4 h-4 ml-1" />
            </div>
            <span className="text-white font-medium block text-right">
              Finish & Return to Path
            </span>
          </button>
        )}
      </div>
    </div>
  );
};

export default LessonNavigation;
