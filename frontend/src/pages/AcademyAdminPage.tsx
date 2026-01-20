import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  GraduationCap,
  BookOpen,
  FileText,
  HelpCircle,
  Plus,
  Edit2,
  Trash2,
  ChevronRight,
  ArrowLeft,
  Save,
  X,
  AlertCircle,
  Video,
  Code,
  CheckCircle,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { academyApi, academyAdminApi } from '../services/academyApi';
import type {
  LearningPath,
  Module,
  Lesson,
  QuizQuestion,
  CreateLearningPathRequest,
  UpdateLearningPathRequest,
  CreateModuleRequest,
  UpdateModuleRequest,
  CreateLessonRequest,
  UpdateLessonRequest,
  CreateQuizQuestionRequest,
} from '../types/academy';

type Tab = 'paths' | 'modules' | 'lessons' | 'questions';

interface BreadcrumbItem {
  label: string;
  id?: string;
  tab: Tab;
}

const AcademyAdminPage: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<Tab>('paths');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Data
  const [paths, setPaths] = useState<LearningPath[]>([]);
  const [modules, setModules] = useState<Module[]>([]);
  const [lessons, setLessons] = useState<Lesson[]>([]);
  const [questions, setQuestions] = useState<QuizQuestion[]>([]);

  // Selected context
  const [selectedPath, setSelectedPath] = useState<LearningPath | null>(null);
  const [selectedModule, setSelectedModule] = useState<Module | null>(null);
  const [selectedLesson, setSelectedLesson] = useState<Lesson | null>(null);

  // Edit state
  const [editingItem, setEditingItem] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);

  // Breadcrumb navigation
  const breadcrumbs: BreadcrumbItem[] = [
    { label: 'Learning Paths', tab: 'paths' },
    ...(selectedPath ? [{ label: selectedPath.title, id: selectedPath.id, tab: 'modules' as Tab }] : []),
    ...(selectedModule ? [{ label: selectedModule.title, id: selectedModule.id, tab: 'lessons' as Tab }] : []),
    ...(selectedLesson ? [{ label: selectedLesson.title, id: selectedLesson.id, tab: 'questions' as Tab }] : []),
  ];

  // Load initial paths
  useEffect(() => {
    loadPaths();
  }, []);

  const loadPaths = async () => {
    try {
      setLoading(true);
      const data = await academyApi.listPaths();
      setPaths(data);
      setError(null);
    } catch (err) {
      setError('Failed to load learning paths');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const loadModules = async (pathSlug: string) => {
    try {
      setLoading(true);
      const data = await academyApi.getPath(pathSlug);
      setModules(data.modules || []);
      setError(null);
    } catch (err) {
      setError('Failed to load modules');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const loadLessons = async (moduleId: string) => {
    try {
      setLoading(true);
      const data = await academyApi.listModuleLessons(moduleId);
      setLessons(data);
      setError(null);
    } catch (err) {
      setError('Failed to load lessons');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const loadQuestions = async (lessonId: string) => {
    try {
      setLoading(true);
      const data = await academyAdminApi.listQuestions(lessonId);
      setQuestions(data);
      setError(null);
    } catch (err) {
      setError('Failed to load questions');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // Navigation handlers
  const handleSelectPath = (path: LearningPath) => {
    setSelectedPath(path);
    setSelectedModule(null);
    setSelectedLesson(null);
    setActiveTab('modules');
    loadModules(path.slug);
  };

  const handleSelectModule = (module: Module) => {
    setSelectedModule(module);
    setSelectedLesson(null);
    setActiveTab('lessons');
    loadLessons(module.id);
  };

  const handleSelectLesson = (lesson: Lesson) => {
    setSelectedLesson(lesson);
    setActiveTab('questions');
    loadQuestions(lesson.id);
  };

  const handleBreadcrumbClick = (item: BreadcrumbItem) => {
    setActiveTab(item.tab);
    if (item.tab === 'paths') {
      setSelectedPath(null);
      setSelectedModule(null);
      setSelectedLesson(null);
    } else if (item.tab === 'modules') {
      setSelectedModule(null);
      setSelectedLesson(null);
    } else if (item.tab === 'lessons') {
      setSelectedLesson(null);
    }
    setShowCreateForm(false);
    setEditingItem(null);
  };

  // Delete handlers
  const handleDeletePath = async (id: string) => {
    if (!confirm('Are you sure you want to delete this learning path? This will also delete all modules, lessons, and questions within it.')) {
      return;
    }
    try {
      await academyAdminApi.deletePath(id);
      toast.success('Learning path deleted');
      loadPaths();
    } catch (err) {
      toast.error('Failed to delete learning path');
    }
  };

  const handleDeleteModule = async (id: string) => {
    if (!confirm('Are you sure you want to delete this module? This will also delete all lessons and questions within it.')) {
      return;
    }
    try {
      await academyAdminApi.deleteModule(id);
      toast.success('Module deleted');
      if (selectedPath) loadModules(selectedPath.slug);
    } catch (err) {
      toast.error('Failed to delete module');
    }
  };

  const handleDeleteLesson = async (id: string) => {
    if (!confirm('Are you sure you want to delete this lesson? This will also delete all questions within it.')) {
      return;
    }
    try {
      await academyAdminApi.deleteLesson(id);
      toast.success('Lesson deleted');
      if (selectedModule) loadLessons(selectedModule.id);
    } catch (err) {
      toast.error('Failed to delete lesson');
    }
  };

  const handleDeleteQuestion = async (id: string) => {
    if (!confirm('Are you sure you want to delete this question?')) {
      return;
    }
    try {
      await academyAdminApi.deleteQuestion(id);
      toast.success('Question deleted');
      if (selectedLesson) loadQuestions(selectedLesson.id);
    } catch (err) {
      toast.error('Failed to delete question');
    }
  };

  // Render content based on active tab
  const renderContent = () => {
    if (loading) {
      return (
        <div className="flex items-center justify-center h-64">
          <div className="w-8 h-8 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        </div>
      );
    }

    if (error) {
      return (
        <div className="flex items-center justify-center h-64 text-red-400">
          <AlertCircle className="w-6 h-6 mr-2" />
          {error}
        </div>
      );
    }

    switch (activeTab) {
      case 'paths':
        return renderPathsList();
      case 'modules':
        return renderModulesList();
      case 'lessons':
        return renderLessonsList();
      case 'questions':
        return renderQuestionsList();
      default:
        return null;
    }
  };

  const renderPathsList = () => (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-white">Learning Paths</h2>
        <button
          onClick={() => setShowCreateForm(true)}
          className="flex items-center px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4 mr-2" />
          Add Path
        </button>
      </div>

      {showCreateForm && (
        <PathForm
          onSave={async (data) => {
            await academyAdminApi.createPath(data as CreateLearningPathRequest);
            toast.success('Learning path created');
            setShowCreateForm(false);
            loadPaths();
          }}
          onCancel={() => setShowCreateForm(false)}
        />
      )}

      <div className="grid gap-4">
        {paths.map((path) => (
          <div
            key={path.id}
            className="bg-gray-800 rounded-lg border border-gray-700 p-4 hover:border-gray-600 transition-colors"
          >
            {editingItem === path.id ? (
              <PathForm
                initialData={path}
                onSave={async (data) => {
                  await academyAdminApi.updatePath(path.id, data);
                  toast.success('Learning path updated');
                  setEditingItem(null);
                  loadPaths();
                }}
                onCancel={() => setEditingItem(null)}
              />
            ) : (
              <div className="flex items-center justify-between">
                <div
                  className="flex-1 cursor-pointer"
                  onClick={() => handleSelectPath(path)}
                >
                  <div className="flex items-center space-x-3">
                    <div
                      className="w-10 h-10 rounded-lg flex items-center justify-center text-xl"
                      style={{ backgroundColor: path.color || '#4b5563' }}
                    >
                      {path.icon || '📚'}
                    </div>
                    <div>
                      <h3 className="text-white font-medium">{path.title}</h3>
                      <p className="text-sm text-gray-400">
                        {path.level} • {path.module_count} modules • {path.lesson_count} lessons
                      </p>
                    </div>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setEditingItem(path.id)}
                    className="p-2 text-gray-400 hover:text-white transition-colors"
                  >
                    <Edit2 className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDeletePath(path.id)}
                    className="p-2 text-gray-400 hover:text-red-400 transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                  <ChevronRight className="w-5 h-5 text-gray-500" />
                </div>
              </div>
            )}
          </div>
        ))}
        {paths.length === 0 && !showCreateForm && (
          <div className="text-center py-12 text-gray-400">
            No learning paths yet. Create your first one!
          </div>
        )}
      </div>
    </div>
  );

  const renderModulesList = () => (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-white">
          Modules in "{selectedPath?.title}"
        </h2>
        <button
          onClick={() => setShowCreateForm(true)}
          className="flex items-center px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4 mr-2" />
          Add Module
        </button>
      </div>

      {showCreateForm && selectedPath && (
        <ModuleForm
          pathId={selectedPath.id}
          onSave={async (data) => {
            await academyAdminApi.createModule(data as CreateModuleRequest);
            toast.success('Module created');
            setShowCreateForm(false);
            loadModules(selectedPath.slug);
          }}
          onCancel={() => setShowCreateForm(false)}
        />
      )}

      <div className="grid gap-4">
        {modules.map((module) => (
          <div
            key={module.id}
            className="bg-gray-800 rounded-lg border border-gray-700 p-4 hover:border-gray-600 transition-colors"
          >
            {editingItem === module.id ? (
              <ModuleForm
                pathId={selectedPath!.id}
                initialData={module}
                onSave={async (data) => {
                  await academyAdminApi.updateModule(module.id, data);
                  toast.success('Module updated');
                  setEditingItem(null);
                  loadModules(selectedPath!.slug);
                }}
                onCancel={() => setEditingItem(null)}
              />
            ) : (
              <div className="flex items-center justify-between">
                <div
                  className="flex-1 cursor-pointer"
                  onClick={() => handleSelectModule(module)}
                >
                  <div className="flex items-center space-x-3">
                    <BookOpen className="w-6 h-6 text-cyan-400" />
                    <div>
                      <h3 className="text-white font-medium">{module.title}</h3>
                      <p className="text-sm text-gray-400">
                        {module.duration_minutes} min • {module.lesson_count} lessons
                        {module.is_assessment && ' • Assessment'}
                      </p>
                    </div>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setEditingItem(module.id)}
                    className="p-2 text-gray-400 hover:text-white transition-colors"
                  >
                    <Edit2 className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDeleteModule(module.id)}
                    className="p-2 text-gray-400 hover:text-red-400 transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                  <ChevronRight className="w-5 h-5 text-gray-500" />
                </div>
              </div>
            )}
          </div>
        ))}
        {modules.length === 0 && !showCreateForm && (
          <div className="text-center py-12 text-gray-400">
            No modules yet. Create your first one!
          </div>
        )}
      </div>
    </div>
  );

  const renderLessonsList = () => (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-white">
          Lessons in "{selectedModule?.title}"
        </h2>
        <button
          onClick={() => setShowCreateForm(true)}
          className="flex items-center px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4 mr-2" />
          Add Lesson
        </button>
      </div>

      {showCreateForm && selectedModule && (
        <LessonForm
          moduleId={selectedModule.id}
          onSave={async (data) => {
            await academyAdminApi.createLesson(data as CreateLessonRequest);
            toast.success('Lesson created');
            setShowCreateForm(false);
            loadLessons(selectedModule.id);
          }}
          onCancel={() => setShowCreateForm(false)}
        />
      )}

      <div className="grid gap-4">
        {lessons.map((lesson) => (
          <div
            key={lesson.id}
            className="bg-gray-800 rounded-lg border border-gray-700 p-4 hover:border-gray-600 transition-colors"
          >
            {editingItem === lesson.id ? (
              <LessonForm
                moduleId={selectedModule!.id}
                initialData={lesson}
                onSave={async (data) => {
                  await academyAdminApi.updateLesson(lesson.id, data);
                  toast.success('Lesson updated');
                  setEditingItem(null);
                  loadLessons(selectedModule!.id);
                }}
                onCancel={() => setEditingItem(null)}
              />
            ) : (
              <div className="flex items-center justify-between">
                <div
                  className="flex-1 cursor-pointer"
                  onClick={() => handleSelectLesson(lesson)}
                >
                  <div className="flex items-center space-x-3">
                    {lesson.lesson_type === 'video' && <Video className="w-6 h-6 text-blue-400" />}
                    {lesson.lesson_type === 'text' && <FileText className="w-6 h-6 text-green-400" />}
                    {lesson.lesson_type === 'interactive' && <Code className="w-6 h-6 text-purple-400" />}
                    {lesson.lesson_type === 'quiz' && <HelpCircle className="w-6 h-6 text-yellow-400" />}
                    <div>
                      <h3 className="text-white font-medium">{lesson.title}</h3>
                      <p className="text-sm text-gray-400">
                        {lesson.lesson_type} • {lesson.duration_minutes} min
                        {lesson.is_preview && ' • Preview'}
                      </p>
                    </div>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setEditingItem(lesson.id)}
                    className="p-2 text-gray-400 hover:text-white transition-colors"
                  >
                    <Edit2 className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDeleteLesson(lesson.id)}
                    className="p-2 text-gray-400 hover:text-red-400 transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                  {lesson.lesson_type === 'quiz' && (
                    <ChevronRight className="w-5 h-5 text-gray-500" />
                  )}
                </div>
              </div>
            )}
          </div>
        ))}
        {lessons.length === 0 && !showCreateForm && (
          <div className="text-center py-12 text-gray-400">
            No lessons yet. Create your first one!
          </div>
        )}
      </div>
    </div>
  );

  const renderQuestionsList = () => (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-white">
          Questions in "{selectedLesson?.title}"
        </h2>
        <button
          onClick={() => setShowCreateForm(true)}
          className="flex items-center px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4 mr-2" />
          Add Question
        </button>
      </div>

      {showCreateForm && selectedLesson && (
        <QuestionForm
          lessonId={selectedLesson.id}
          displayOrder={questions.length + 1}
          onSave={async (data) => {
            await academyAdminApi.createQuestion(data);
            toast.success('Question created');
            setShowCreateForm(false);
            loadQuestions(selectedLesson.id);
          }}
          onCancel={() => setShowCreateForm(false)}
        />
      )}

      <div className="grid gap-4">
        {questions.map((question, index) => (
          <div
            key={question.id}
            className="bg-gray-800 rounded-lg border border-gray-700 p-4"
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center space-x-2 mb-2">
                  <span className="text-gray-500 text-sm">#{index + 1}</span>
                  <span className="px-2 py-0.5 bg-gray-700 rounded text-xs text-gray-300">
                    {question.question_type}
                  </span>
                  <span className="text-gray-500 text-sm">{question.points} pts</span>
                </div>
                <p className="text-white">{question.question_text}</p>
                {question.explanation && (
                  <p className="text-sm text-gray-400 mt-1">Explanation: {question.explanation}</p>
                )}
              </div>
              <div className="flex items-center space-x-2 ml-4">
                <button
                  onClick={() => handleDeleteQuestion(question.id)}
                  className="p-2 text-gray-400 hover:text-red-400 transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
        {questions.length === 0 && !showCreateForm && (
          <div className="text-center py-12 text-gray-400">
            No questions yet. Create your first one!
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-900 p-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-4">
            <button
              onClick={() => navigate('/admin')}
              className="p-2 text-gray-400 hover:text-white transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
            <div className="flex items-center space-x-2">
              <GraduationCap className="w-8 h-8 text-cyan-400" />
              <h1 className="text-2xl font-bold text-white">Academy Admin</h1>
            </div>
          </div>
        </div>

        {/* Breadcrumbs */}
        <nav className="flex items-center space-x-2 mb-6 text-sm">
          {breadcrumbs.map((item, index) => (
            <React.Fragment key={index}>
              {index > 0 && <ChevronRight className="w-4 h-4 text-gray-500" />}
              <button
                onClick={() => handleBreadcrumbClick(item)}
                className={`hover:text-cyan-400 transition-colors ${
                  index === breadcrumbs.length - 1
                    ? 'text-white font-medium'
                    : 'text-gray-400'
                }`}
              >
                {item.label}
              </button>
            </React.Fragment>
          ))}
        </nav>

        {/* Content */}
        {renderContent()}
      </div>
    </div>
  );
};

// =============================================================================
// Form Components
// =============================================================================

interface PathFormProps {
  initialData?: LearningPath;
  onSave: (data: CreateLearningPathRequest | UpdateLearningPathRequest) => Promise<void>;
  onCancel: () => void;
}

const PathForm: React.FC<PathFormProps> = ({ initialData, onSave, onCancel }) => {
  const [saving, setSaving] = useState(false);
  const [formData, setFormData] = useState({
    slug: initialData?.slug || '',
    title: initialData?.title || '',
    description: initialData?.description || '',
    level: initialData?.level || 'Beginner',
    duration_hours: initialData?.duration_hours || 1,
    price_cents: initialData?.price_cents || 0,
    icon: initialData?.icon || '',
    color: initialData?.color || '#4b5563',
    certificate_name: initialData?.certificate_name || '',
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await onSave(formData);
    } catch (err) {
      toast.error('Failed to save');
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="bg-gray-800 rounded-lg border border-gray-600 p-4 space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Slug</label>
          <input
            type="text"
            value={formData.slug}
            onChange={(e) => setFormData({ ...formData, slug: e.target.value })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
            placeholder="beginner-path"
            required
            disabled={!!initialData}
          />
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Title</label>
          <input
            type="text"
            value={formData.title}
            onChange={(e) => setFormData({ ...formData, title: e.target.value })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
            placeholder="Security Fundamentals"
            required
          />
        </div>
      </div>
      <div>
        <label className="block text-sm text-gray-400 mb-1">Description</label>
        <textarea
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
          rows={2}
          placeholder="Learn the fundamentals of cybersecurity..."
        />
      </div>
      <div className="grid grid-cols-4 gap-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Level</label>
          <select
            value={formData.level}
            onChange={(e) => setFormData({ ...formData, level: e.target.value as 'Beginner' | 'Professional' | 'Expert' })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
          >
            <option value="Beginner">Beginner</option>
            <option value="Professional">Professional</option>
            <option value="Expert">Expert</option>
          </select>
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Duration (hours)</label>
          <input
            type="number"
            value={formData.duration_hours}
            onChange={(e) => setFormData({ ...formData, duration_hours: parseInt(e.target.value) || 0 })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
            min={1}
          />
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Icon (emoji)</label>
          <input
            type="text"
            value={formData.icon}
            onChange={(e) => setFormData({ ...formData, icon: e.target.value })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
            placeholder="🔒"
          />
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Color</label>
          <input
            type="color"
            value={formData.color}
            onChange={(e) => setFormData({ ...formData, color: e.target.value })}
            className="w-full h-10 bg-gray-700 border border-gray-600 rounded cursor-pointer"
          />
        </div>
      </div>
      <div className="flex justify-end space-x-2">
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded transition-colors"
        >
          <X className="w-4 h-4 inline mr-1" />
          Cancel
        </button>
        <button
          type="submit"
          disabled={saving}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors disabled:opacity-50"
        >
          <Save className="w-4 h-4 inline mr-1" />
          {saving ? 'Saving...' : 'Save'}
        </button>
      </div>
    </form>
  );
};

interface ModuleFormProps {
  pathId: string;
  initialData?: Module;
  onSave: (data: CreateModuleRequest | UpdateModuleRequest) => Promise<void>;
  onCancel: () => void;
}

const ModuleForm: React.FC<ModuleFormProps> = ({ pathId, initialData, onSave, onCancel }) => {
  const [saving, setSaving] = useState(false);
  const [formData, setFormData] = useState({
    learning_path_id: pathId,
    slug: initialData?.slug || '',
    title: initialData?.title || '',
    description: initialData?.description || '',
    duration_minutes: initialData?.duration_minutes || 30,
    display_order: initialData?.display_order || 1,
    is_assessment: initialData?.is_assessment || false,
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await onSave(formData);
    } catch (err) {
      toast.error('Failed to save');
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="bg-gray-800 rounded-lg border border-gray-600 p-4 space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Slug</label>
          <input
            type="text"
            value={formData.slug}
            onChange={(e) => setFormData({ ...formData, slug: e.target.value })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
            placeholder="intro-module"
            required
            disabled={!!initialData}
          />
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Title</label>
          <input
            type="text"
            value={formData.title}
            onChange={(e) => setFormData({ ...formData, title: e.target.value })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
            placeholder="Introduction to Security"
            required
          />
        </div>
      </div>
      <div>
        <label className="block text-sm text-gray-400 mb-1">Description</label>
        <textarea
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
          rows={2}
        />
      </div>
      <div className="grid grid-cols-3 gap-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Duration (minutes)</label>
          <input
            type="number"
            value={formData.duration_minutes}
            onChange={(e) => setFormData({ ...formData, duration_minutes: parseInt(e.target.value) || 0 })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
            min={1}
          />
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Display Order</label>
          <input
            type="number"
            value={formData.display_order}
            onChange={(e) => setFormData({ ...formData, display_order: parseInt(e.target.value) || 1 })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
            min={1}
          />
        </div>
        <div className="flex items-end pb-2">
          <label className="flex items-center space-x-2 cursor-pointer">
            <input
              type="checkbox"
              checked={formData.is_assessment}
              onChange={(e) => setFormData({ ...formData, is_assessment: e.target.checked })}
              className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-cyan-600"
            />
            <span className="text-gray-300">Is Assessment</span>
          </label>
        </div>
      </div>
      <div className="flex justify-end space-x-2">
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded transition-colors"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={saving}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors disabled:opacity-50"
        >
          {saving ? 'Saving...' : 'Save'}
        </button>
      </div>
    </form>
  );
};

interface LessonFormProps {
  moduleId: string;
  initialData?: Lesson;
  onSave: (data: CreateLessonRequest | UpdateLessonRequest) => Promise<void>;
  onCancel: () => void;
}

const LessonForm: React.FC<LessonFormProps> = ({ moduleId, initialData, onSave, onCancel }) => {
  const [saving, setSaving] = useState(false);
  const [formData, setFormData] = useState({
    module_id: moduleId,
    slug: initialData?.slug || '',
    title: initialData?.title || '',
    description: initialData?.description || '',
    lesson_type: initialData?.lesson_type || 'text',
    content_json: '{}',
    duration_minutes: initialData?.duration_minutes || 10,
    display_order: initialData?.display_order || 1,
    is_preview: initialData?.is_preview || false,
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await onSave(formData);
    } catch (err) {
      toast.error('Failed to save');
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="bg-gray-800 rounded-lg border border-gray-600 p-4 space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Slug</label>
          <input
            type="text"
            value={formData.slug}
            onChange={(e) => setFormData({ ...formData, slug: e.target.value })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
            placeholder="intro-lesson"
            required
            disabled={!!initialData}
          />
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Title</label>
          <input
            type="text"
            value={formData.title}
            onChange={(e) => setFormData({ ...formData, title: e.target.value })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
            placeholder="Getting Started"
            required
          />
        </div>
      </div>
      <div>
        <label className="block text-sm text-gray-400 mb-1">Description</label>
        <textarea
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
          rows={2}
        />
      </div>
      <div className="grid grid-cols-4 gap-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Type</label>
          <select
            value={formData.lesson_type}
            onChange={(e) => setFormData({ ...formData, lesson_type: e.target.value as 'text' | 'video' | 'interactive' | 'quiz' })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
          >
            <option value="text">Text</option>
            <option value="video">Video</option>
            <option value="interactive">Interactive</option>
            <option value="quiz">Quiz</option>
          </select>
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Duration (minutes)</label>
          <input
            type="number"
            value={formData.duration_minutes}
            onChange={(e) => setFormData({ ...formData, duration_minutes: parseInt(e.target.value) || 0 })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
            min={1}
          />
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Display Order</label>
          <input
            type="number"
            value={formData.display_order}
            onChange={(e) => setFormData({ ...formData, display_order: parseInt(e.target.value) || 1 })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
            min={1}
          />
        </div>
        <div className="flex items-end pb-2">
          <label className="flex items-center space-x-2 cursor-pointer">
            <input
              type="checkbox"
              checked={formData.is_preview}
              onChange={(e) => setFormData({ ...formData, is_preview: e.target.checked })}
              className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-cyan-600"
            />
            <span className="text-gray-300">Preview</span>
          </label>
        </div>
      </div>
      <div className="flex justify-end space-x-2">
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded transition-colors"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={saving}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors disabled:opacity-50"
        >
          {saving ? 'Saving...' : 'Save'}
        </button>
      </div>
    </form>
  );
};

interface QuestionFormProps {
  lessonId: string;
  displayOrder: number;
  onSave: (data: CreateQuizQuestionRequest) => Promise<void>;
  onCancel: () => void;
}

const QuestionForm: React.FC<QuestionFormProps> = ({ lessonId, displayOrder, onSave, onCancel }) => {
  const [saving, setSaving] = useState(false);
  const [formData, setFormData] = useState({
    lesson_id: lessonId,
    question_type: 'multiple_choice',
    question_text: '',
    options: ['', '', '', ''],
    correct_answer: 0,
    points: 1,
    explanation: '',
    display_order: displayOrder,
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const questionData: CreateQuizQuestionRequest = {
        lesson_id: formData.lesson_id,
        question_type: formData.question_type,
        question_text: formData.question_text,
        question_data_json: JSON.stringify({
          options: formData.options.filter((o) => o.trim() !== ''),
          correct_answer: formData.correct_answer,
        }),
        points: formData.points,
        explanation: formData.explanation || undefined,
        display_order: formData.display_order,
      };
      await onSave(questionData);
    } catch (err) {
      toast.error('Failed to save');
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="bg-gray-800 rounded-lg border border-gray-600 p-4 space-y-4">
      <div className="grid grid-cols-3 gap-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Question Type</label>
          <select
            value={formData.question_type}
            onChange={(e) => setFormData({ ...formData, question_type: e.target.value })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
          >
            <option value="multiple_choice">Multiple Choice</option>
            <option value="multiple_select">Multiple Select</option>
            <option value="true_false">True/False</option>
          </select>
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Points</label>
          <input
            type="number"
            value={formData.points}
            onChange={(e) => setFormData({ ...formData, points: parseInt(e.target.value) || 1 })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
            min={1}
          />
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Correct Answer (0-indexed)</label>
          <input
            type="number"
            value={formData.correct_answer}
            onChange={(e) => setFormData({ ...formData, correct_answer: parseInt(e.target.value) || 0 })}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
            min={0}
            max={3}
          />
        </div>
      </div>
      <div>
        <label className="block text-sm text-gray-400 mb-1">Question Text</label>
        <textarea
          value={formData.question_text}
          onChange={(e) => setFormData({ ...formData, question_text: e.target.value })}
          className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
          rows={2}
          required
        />
      </div>
      <div>
        <label className="block text-sm text-gray-400 mb-1">Options</label>
        <div className="space-y-2">
          {formData.options.map((option, index) => (
            <div key={index} className="flex items-center space-x-2">
              <span
                className={`w-6 h-6 rounded-full flex items-center justify-center text-xs ${
                  index === formData.correct_answer
                    ? 'bg-green-600 text-white'
                    : 'bg-gray-700 text-gray-400'
                }`}
              >
                {index === formData.correct_answer ? <CheckCircle className="w-4 h-4" /> : index + 1}
              </span>
              <input
                type="text"
                value={option}
                onChange={(e) => {
                  const newOptions = [...formData.options];
                  newOptions[index] = e.target.value;
                  setFormData({ ...formData, options: newOptions });
                }}
                className="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
                placeholder={`Option ${index + 1}`}
              />
            </div>
          ))}
        </div>
      </div>
      <div>
        <label className="block text-sm text-gray-400 mb-1">Explanation (shown after answer)</label>
        <textarea
          value={formData.explanation}
          onChange={(e) => setFormData({ ...formData, explanation: e.target.value })}
          className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
          rows={2}
        />
      </div>
      <div className="flex justify-end space-x-2">
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded transition-colors"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={saving}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors disabled:opacity-50"
        >
          {saving ? 'Saving...' : 'Save'}
        </button>
      </div>
    </form>
  );
};

export default AcademyAdminPage;
