import React, { useEffect, useState } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import {
  BookOpen, Award, Clock, CheckCircle, Lock, Play,
  ChevronRight, ChevronDown, Users, ArrowLeft, Shield, Target, Zap
} from 'lucide-react';
import { useAcademyStore } from '../store/academyStore';
import { useAuthStore } from '../store/authStore';
import { ModuleWithProgress, LessonWithProgress } from '../types/academy';
import { toast } from 'react-toastify';

// Icon mapping
const iconMap: Record<string, React.ReactNode> = {
  'Shield': <Shield className="w-8 h-8" />,
  'Target': <Target className="w-8 h-8" />,
  'Zap': <Zap className="w-8 h-8" />,
};

// Module Accordion Component
const ModuleAccordion: React.FC<{
  module: ModuleWithProgress;
  index: number;
  isExpanded: boolean;
  onToggle: () => void;
  onLessonClick: (lessonId: string) => void;
}> = ({ module, index, isExpanded, onToggle, onLessonClick }) => {
  const isLocked = !module.is_unlocked;
  const isCompleted = module.completed_lessons === module.lessons.length && module.lessons.length > 0;

  return (
    <div className={`bg-gray-800 rounded-xl overflow-hidden ${isLocked ? 'opacity-75' : ''}`}>
      <div
        className={`p-6 cursor-pointer flex items-center justify-between ${isLocked ? 'cursor-not-allowed' : ''}`}
        onClick={() => !isLocked && onToggle()}
      >
        <div className="flex items-center">
          <div className={`w-10 h-10 rounded-full flex items-center justify-center mr-4 ${
            isCompleted ? 'bg-green-900/50 text-green-400' :
            isLocked ? 'bg-gray-700 text-gray-500' :
            'bg-cyan-900/50 text-cyan-400'
          }`}>
            {isCompleted ? <CheckCircle className="w-5 h-5" /> :
             isLocked ? <Lock className="w-5 h-5" /> :
             <span className="font-bold">{index + 1}</span>}
          </div>
          <div>
            <h3 className="text-lg font-semibold text-white">{module.title}</h3>
            <div className="flex items-center gap-3 text-sm text-gray-500">
              <span>{module.lessons.length} lessons</span>
              <span>•</span>
              <span>{module.duration_minutes} min</span>
              {module.progress_percent > 0 && !isCompleted && (
                <>
                  <span>•</span>
                  <span className="text-cyan-400">{Math.round(module.progress_percent)}% complete</span>
                </>
              )}
            </div>
          </div>
        </div>
        {!isLocked && (
          isExpanded ?
            <ChevronDown className="w-5 h-5 text-gray-500" /> :
            <ChevronRight className="w-5 h-5 text-gray-500" />
        )}
      </div>

      {isExpanded && !isLocked && (
        <div className="px-6 pb-6 border-t border-gray-700">
          <p className="text-gray-400 mt-4 mb-4">{module.description}</p>

          {/* Lesson List */}
          <div className="space-y-2">
            {module.lessons.map((lesson, lessonIndex) => (
              <LessonItem
                key={lesson.id}
                lesson={lesson}
                index={lessonIndex}
                onClick={() => onLessonClick(lesson.id)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// Lesson Item Component
const LessonItem: React.FC<{
  lesson: LessonWithProgress;
  index: number;
  onClick: () => void;
}> = ({ lesson, index, onClick }) => {
  const statusColors = {
    'completed': 'text-green-400',
    'in_progress': 'text-cyan-400',
    'not_started': 'text-gray-500',
  };

  const typeIcons: Record<string, React.ReactNode> = {
    'video': <Play className="w-4 h-4" />,
    'text': <BookOpen className="w-4 h-4" />,
    'interactive': <BookOpen className="w-4 h-4" />,
    'quiz': <CheckCircle className="w-4 h-4" />,
  };

  return (
    <div
      className="flex items-center justify-between p-3 bg-gray-700/50 rounded-lg hover:bg-gray-700 cursor-pointer transition-colors"
      onClick={onClick}
    >
      <div className="flex items-center">
        <div className={`w-8 h-8 rounded-full flex items-center justify-center mr-3 ${
          lesson.status === 'completed' ? 'bg-green-900/50 text-green-400' :
          lesson.status === 'in_progress' ? 'bg-cyan-900/50 text-cyan-400' :
          'bg-gray-600 text-gray-400'
        }`}>
          {lesson.status === 'completed' ? (
            <CheckCircle className="w-4 h-4" />
          ) : (
            typeIcons[lesson.lesson_type] || <BookOpen className="w-4 h-4" />
          )}
        </div>
        <div>
          <div className="text-white font-medium">{lesson.title}</div>
          <div className="text-xs text-gray-500">
            {lesson.duration_minutes} min • {lesson.lesson_type}
          </div>
        </div>
      </div>
      <ChevronRight className={`w-5 h-5 ${statusColors[lesson.status]}`} />
    </div>
  );
};

// Main Path Page Component
const AcademyPathPage: React.FC = () => {
  const { slug } = useParams<{ slug: string }>();
  const navigate = useNavigate();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  const {
    currentPath,
    isLoadingPath,
    isEnrolling,
    error,
    fetchPath,
    fetchPublicPath,
    enroll,
    clearError,
  } = useAcademyStore();

  const [expandedModule, setExpandedModule] = useState<string | null>(null);

  useEffect(() => {
    if (slug) {
      if (isAuthenticated) {
        fetchPath(slug);
      } else {
        fetchPublicPath(slug);
      }
    }
  }, [slug, isAuthenticated, fetchPath, fetchPublicPath]);

  useEffect(() => {
    if (error) {
      toast.error(error);
      clearError();
    }
  }, [error, clearError]);

  const handleEnroll = async () => {
    if (!isAuthenticated) {
      navigate(`/login?redirect=/academy/path/${slug}`);
      return;
    }

    await enroll(slug!);
    toast.success('Successfully enrolled!');
  };

  const handleLessonClick = (lessonId: string) => {
    if (!currentPath?.enrolled && !isAuthenticated) {
      navigate(`/login?redirect=/academy/path/${slug}`);
      return;
    }

    if (!currentPath?.enrolled) {
      toast.info('Please enroll to access this lesson.');
      return;
    }

    navigate(`/academy/lesson/${lessonId}`);
  };

  if (isLoadingPath) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-gray-400">Loading course...</p>
        </div>
      </div>
    );
  }

  if (!currentPath) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-white mb-4">Course Not Found</h1>
          <Link to="/academy" className="text-cyan-400 hover:underline">← Back to Academy</Link>
        </div>
      </div>
    );
  }

  const colorClasses: Record<string, { bg: string; text: string; button: string }> = {
    cyan: { bg: 'bg-cyan-900/50', text: 'text-cyan-400', button: 'bg-cyan-600 hover:bg-cyan-700' },
    purple: { bg: 'bg-purple-900/50', text: 'text-purple-400', button: 'bg-purple-600 hover:bg-purple-700' },
    orange: { bg: 'bg-orange-900/50', text: 'text-orange-400', button: 'bg-orange-600 hover:bg-orange-700' },
  };

  const color = colorClasses[currentPath.color || 'cyan'] || colorClasses.cyan;
  const icon = iconMap[currentPath.icon || 'Shield'] || <Shield className="w-8 h-8" />;
  const isFree = currentPath.price_cents === 0;
  const priceDisplay = isFree ? 'Free' : `$${(currentPath.price_cents / 100).toFixed(0)}`;

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-2">
            <span className="text-2xl font-bold text-cyan-400">HeroForge</span>
          </Link>
          <nav className="hidden md:flex items-center space-x-6">
            <Link to="/academy" className="text-cyan-400">Academy</Link>
            {isAuthenticated ? (
              <Link to="/dashboard" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Dashboard</Link>
            ) : (
              <Link to="/login" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg">Sign In</Link>
            )}
          </nav>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 py-8">
        {/* Back link */}
        <Link to="/academy" className="inline-flex items-center text-gray-400 hover:text-white mb-8">
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Academy
        </Link>

        {/* Path header */}
        <div className="bg-gray-800 rounded-xl p-8 mb-8">
          <div className="flex flex-col md:flex-row md:items-start md:justify-between">
            <div>
              <div className={`w-16 h-16 ${color.bg} rounded-xl flex items-center justify-center ${color.text} mb-4`}>
                {icon}
              </div>
              <span className={`text-sm font-medium px-3 py-1 rounded ${color.bg} ${color.text}`}>
                {currentPath.level}
              </span>
              <h1 className="text-3xl font-bold text-white mt-4 mb-2">{currentPath.title}</h1>
              <p className="text-gray-400 mb-4">{currentPath.description}</p>
              <div className="flex items-center gap-6 text-sm text-gray-500">
                <span className="flex items-center"><Clock className="w-4 h-4 mr-1" /> {currentPath.duration_hours} hours</span>
                <span className="flex items-center"><BookOpen className="w-4 h-4 mr-1" /> {currentPath.module_count} modules</span>
                <span className="flex items-center"><Users className="w-4 h-4 mr-1" /> {currentPath.lesson_count} lessons</span>
              </div>
            </div>
            <div className="mt-6 md:mt-0 md:text-right">
              <div className={`text-3xl font-bold mb-2 ${isFree ? 'text-green-400' : 'text-white'}`}>
                {priceDisplay}
              </div>
              {currentPath.enrolled ? (
                <button
                  onClick={() => {
                    // Find first incomplete lesson
                    const firstIncomplete = currentPath.modules
                      .flatMap(m => m.lessons)
                      .find(l => l.status !== 'completed');
                    if (firstIncomplete) {
                      navigate(`/academy/lesson/${firstIncomplete.id}`);
                    } else {
                      toast.info('You have completed this course!');
                    }
                  }}
                  className={`${color.button} text-white font-medium px-6 py-3 rounded-lg transition-colors`}
                >
                  Continue Learning
                </button>
              ) : (
                <button
                  onClick={handleEnroll}
                  disabled={isEnrolling}
                  className={`${color.button} text-white font-medium px-6 py-3 rounded-lg transition-colors disabled:opacity-50`}
                >
                  {isEnrolling ? 'Enrolling...' : isFree ? 'Start Learning' : 'Enroll Now'}
                </button>
              )}
            </div>
          </div>

          {/* Progress bar */}
          {currentPath.enrolled && currentPath.progress && (
            <div className="mt-6 pt-6 border-t border-gray-700">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-400">Your Progress</span>
                <span className="text-sm text-cyan-400">
                  {currentPath.progress.completed_lessons} of {currentPath.progress.total_lessons} completed
                </span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div
                  className="bg-cyan-500 h-2 rounded-full transition-all"
                  style={{ width: `${currentPath.progress.progress_percent}%` }}
                />
              </div>
            </div>
          )}
        </div>

        {/* Certificate info */}
        {currentPath.certificate_name && (
          <div className="bg-gradient-to-r from-yellow-900/20 to-orange-900/20 border border-yellow-700/50 rounded-xl p-6 mb-8 flex items-center">
            <Award className="w-12 h-12 text-yellow-500 mr-4" />
            <div>
              <h3 className="text-lg font-semibold text-white">Earn: {currentPath.certificate_name}</h3>
              <p className="text-gray-400 text-sm">Complete all modules and pass the final assessment to earn your credential.</p>
            </div>
          </div>
        )}

        {/* Modules list */}
        <h2 className="text-2xl font-bold text-white mb-6">Course Modules</h2>
        <div className="space-y-4">
          {currentPath.modules.map((module, index) => (
            <ModuleAccordion
              key={module.id}
              module={module}
              index={index}
              isExpanded={expandedModule === module.id}
              onToggle={() => setExpandedModule(expandedModule === module.id ? null : module.id)}
              onLessonClick={handleLessonClick}
            />
          ))}
        </div>

        {/* What you'll learn */}
        <div className="mt-12 bg-gray-800 rounded-xl p-8">
          <h2 className="text-2xl font-bold text-white mb-6">What You'll Learn</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {currentPath.level === 'Beginner' && (
              <>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Fundamentals of network security and common threats</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">How to discover and scan network assets</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Understanding CVEs and vulnerability scoring</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Creating professional security reports</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Using HeroForge for security assessments</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Basic vulnerability remediation strategies</span></div>
              </>
            )}
            {currentPath.level === 'Professional' && (
              <>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Advanced enumeration and information gathering</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Web application security testing (OWASP Top 10)</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Cloud security assessment for AWS, Azure, GCP</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Compliance frameworks (PCI-DSS, HIPAA, SOC 2)</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Executive-level security reporting</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Preparing for the HCA certification</span></div>
              </>
            )}
            {currentPath.level === 'Expert' && (
              <>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Red team operations and attack simulation</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Purple team collaboration techniques</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Proactive threat hunting methodologies</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Building enterprise security programs</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Security automation and orchestration</span></div>
                <div className="flex items-start"><CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5" /><span className="text-gray-300">Preparing for the HCP certification</span></div>
              </>
            )}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 mt-16">
        <div className="max-w-4xl mx-auto px-4 py-8">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <p className="text-gray-400 text-sm">
              &copy; 2026 Genial Architect Cybersecurity Research Associates. All rights reserved.
            </p>
            <div className="flex space-x-6 mt-4 md:mt-0">
              <Link to="/legal/terms" className="text-gray-400 hover:text-white text-sm">Terms</Link>
              <Link to="/legal/privacy" className="text-gray-400 hover:text-white text-sm">Privacy</Link>
              <Link to="/docs" className="text-gray-400 hover:text-white text-sm">Documentation</Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default AcademyPathPage;
