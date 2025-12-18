import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import {
  manualAssessmentAPI,
  campaignAPI,
  rubricAPI,
  complianceAPI,
} from '../services/api';
import type {
  ManualAssessment,
  CampaignWithProgress,
  ComplianceRubric,
  ComplianceFramework,
  ReviewStatus,
  CreateCampaignRequest,
} from '../types';
import Layout from '../components/layout/Layout';
import Card from '../components/ui/Card';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import Input from '../components/ui/Input';
import {
  ClipboardCheck,
  FileText,
  ListChecks,
  BookOpen,
  Plus,
  Search,
  Filter,
  Calendar,
  Clock,
  User,
  ChevronRight,
  Trash2,
  Edit,
  Eye,
  AlertCircle,
  X,
  Check,
  RefreshCw,
  Target,
  BarChart3,
  FolderOpen,
} from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

type TabType = 'assessments' | 'campaigns' | 'rubrics';

interface AssessmentFilters {
  framework: string;
  status: string;
  search: string;
}

interface NewCampaignForm {
  name: string;
  description: string;
  frameworks: string[];
  due_date: string;
}

// ============================================================================
// Constants
// ============================================================================

const TABS: { id: TabType; label: string; icon: React.ReactNode }[] = [
  { id: 'assessments', label: 'Assessments', icon: <ClipboardCheck className="h-4 w-4" /> },
  { id: 'campaigns', label: 'Campaigns', icon: <Target className="h-4 w-4" /> },
  { id: 'rubrics', label: 'Rubrics', icon: <BookOpen className="h-4 w-4" /> },
];

const STATUS_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: 'All Statuses' },
  { value: 'draft', label: 'Draft' },
  { value: 'pending_review', label: 'Pending Review' },
  { value: 'approved', label: 'Approved' },
  { value: 'rejected', label: 'Rejected' },
];

const STATUS_BADGE_MAP: Record<ReviewStatus, { type: 'pending' | 'running' | 'completed' | 'failed'; label: string }> = {
  draft: { type: 'pending', label: 'Draft' },
  pending_review: { type: 'running', label: 'Pending Review' },
  approved: { type: 'completed', label: 'Approved' },
  rejected: { type: 'failed', label: 'Rejected' },
};

// ============================================================================
// Sub-Components
// ============================================================================

interface AssessmentCardProps {
  assessment: ManualAssessment;
  frameworks: ComplianceFramework[];
  onView: () => void;
  onEdit: () => void;
  onDelete: () => void;
}

const AssessmentCard: React.FC<AssessmentCardProps> = ({
  assessment,
  frameworks,
  onView,
  onEdit,
  onDelete,
}) => {
  const framework = frameworks.find((f) => f.id === assessment.framework_id);
  const statusBadge = STATUS_BADGE_MAP[assessment.review_status];
  const canEdit = assessment.review_status === 'draft' || assessment.review_status === 'rejected';

  return (
    <Card className="hover:border-dark-hover transition-all">
      <div className="flex items-start justify-between mb-3">
        <div className="flex-1 min-w-0">
          <h4 className="text-lg font-medium text-white truncate">
            {assessment.control_id}
          </h4>
          <p className="text-sm text-slate-400 truncate">
            {framework?.name || assessment.framework_id}
          </p>
        </div>
        <Badge variant="status" type={statusBadge.type}>
          {statusBadge.label}
        </Badge>
      </div>

      {/* Score */}
      {assessment.rating_score !== null && (
        <div className="mb-3">
          <div className="flex items-center justify-between text-sm mb-1">
            <span className="text-slate-400">Score</span>
            <span
              className={`font-medium ${
                assessment.rating_score >= 80
                  ? 'text-green-400'
                  : assessment.rating_score >= 50
                  ? 'text-yellow-400'
                  : 'text-red-400'
              }`}
            >
              {assessment.rating_score}%
            </span>
          </div>
          <div className="w-full h-2 bg-dark-border rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full ${
                assessment.rating_score >= 80
                  ? 'bg-green-500'
                  : assessment.rating_score >= 50
                  ? 'bg-yellow-500'
                  : 'bg-red-500'
              }`}
              style={{ width: `${assessment.rating_score}%` }}
            />
          </div>
        </div>
      )}

      {/* Meta info */}
      <div className="flex items-center gap-4 text-xs text-slate-500 mb-4">
        <div className="flex items-center gap-1">
          <Calendar className="h-3 w-3" />
          <span>
            {new Date(assessment.assessment_period_start).toLocaleDateString()} -{' '}
            {new Date(assessment.assessment_period_end).toLocaleDateString()}
          </span>
        </div>
        <div className="flex items-center gap-1">
          <Clock className="h-3 w-3" />
          <span>Updated {new Date(assessment.updated_at).toLocaleDateString()}</span>
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2">
        <Button variant="secondary" size="sm" onClick={onView} className="flex-1">
          <Eye className="h-4 w-4 mr-1" />
          View
        </Button>
        {canEdit && (
          <Button variant="secondary" size="sm" onClick={onEdit} className="flex-1">
            <Edit className="h-4 w-4 mr-1" />
            Edit
          </Button>
        )}
        <Button
          variant="ghost"
          size="sm"
          onClick={onDelete}
          className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>
    </Card>
  );
};

interface CampaignCardProps {
  campaign: CampaignWithProgress;
  onView: () => void;
  onDelete: () => void;
}

const CampaignCard: React.FC<CampaignCardProps> = ({ campaign, onView, onDelete }) => {
  const statusColors: Record<string, string> = {
    draft: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
    active: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    completed: 'bg-green-500/20 text-green-400 border-green-500/30',
    archived: 'bg-slate-500/20 text-slate-500 border-slate-500/30',
  };

  return (
    <Card className="hover:border-dark-hover transition-all">
      <div className="flex items-start justify-between mb-3">
        <div className="flex-1 min-w-0">
          <h4 className="text-lg font-medium text-white truncate">{campaign.name}</h4>
          {campaign.description && (
            <p className="text-sm text-slate-400 line-clamp-2">{campaign.description}</p>
          )}
        </div>
        <span
          className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border capitalize ${
            statusColors[campaign.status] || statusColors.draft
          }`}
        >
          {campaign.status}
        </span>
      </div>

      {/* Frameworks */}
      <div className="flex flex-wrap gap-1 mb-3">
        {campaign.frameworks.map((fw) => (
          <span
            key={fw}
            className="inline-flex items-center px-2 py-0.5 bg-dark-bg border border-dark-border rounded text-xs text-slate-300"
          >
            {fw}
          </span>
        ))}
      </div>

      {/* Progress */}
      <div className="mb-3">
        <div className="flex items-center justify-between text-sm mb-1">
          <span className="text-slate-400">Progress</span>
          <span className="text-white font-medium">
            {campaign.progress.assessed} / {campaign.progress.total_controls} (
            {campaign.progress.percentage_complete}%)
          </span>
        </div>
        <div className="w-full h-2 bg-dark-border rounded-full overflow-hidden">
          <div
            className="h-full bg-primary rounded-full transition-all"
            style={{ width: `${campaign.progress.percentage_complete}%` }}
          />
        </div>
        <div className="flex items-center gap-4 mt-2 text-xs text-slate-500">
          <span className="text-yellow-400">
            {campaign.progress.pending_review} pending review
          </span>
          <span className="text-green-400">{campaign.progress.approved} approved</span>
        </div>
      </div>

      {/* Due date */}
      {campaign.due_date && (
        <div className="flex items-center gap-1 text-xs text-slate-500 mb-4">
          <Calendar className="h-3 w-3" />
          <span>Due: {new Date(campaign.due_date).toLocaleDateString()}</span>
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-2">
        <Button variant="secondary" size="sm" onClick={onView} className="flex-1">
          <Eye className="h-4 w-4 mr-1" />
          View Details
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={onDelete}
          className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>
    </Card>
  );
};

interface RubricCardProps {
  rubric: ComplianceRubric;
  onSelect: () => void;
}

const RubricCard: React.FC<RubricCardProps> = ({ rubric, onSelect }) => {
  return (
    <Card
      variant="interactive"
      onClick={onSelect}
      className="hover:border-primary/50"
    >
      <div className="flex items-start justify-between mb-2">
        <div className="flex-1 min-w-0">
          <h4 className="text-lg font-medium text-white truncate">{rubric.name}</h4>
          <p className="text-sm text-slate-400">
            {rubric.framework_id} - {rubric.control_id}
          </p>
        </div>
        {rubric.is_system_default && (
          <span className="inline-flex items-center px-2 py-0.5 bg-primary/20 text-primary border border-primary/30 rounded text-xs">
            System
          </span>
        )}
      </div>

      {rubric.description && (
        <p className="text-sm text-slate-300 line-clamp-2 mb-3">{rubric.description}</p>
      )}

      <div className="flex items-center gap-4 text-xs text-slate-500">
        <div className="flex items-center gap-1">
          <ListChecks className="h-3 w-3" />
          <span>{rubric.assessment_criteria.length} criteria</span>
        </div>
        <div className="flex items-center gap-1">
          <BarChart3 className="h-3 w-3" />
          <span>{rubric.rating_scale.scale_type}</span>
        </div>
      </div>

      <div className="flex items-center justify-end mt-3">
        <ChevronRight className="h-5 w-5 text-slate-500" />
      </div>
    </Card>
  );
};

// ============================================================================
// New Assessment Modal
// ============================================================================

interface NewAssessmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  frameworks: ComplianceFramework[];
  rubrics: ComplianceRubric[];
  onSelectRubric: (rubric: ComplianceRubric) => void;
}

const NewAssessmentModal: React.FC<NewAssessmentModalProps> = ({
  isOpen,
  onClose,
  frameworks,
  rubrics,
  onSelectRubric,
}) => {
  const [selectedFramework, setSelectedFramework] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  if (!isOpen) return null;

  const filteredRubrics = rubrics.filter((rubric) => {
    if (selectedFramework && rubric.framework_id !== selectedFramework) return false;
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        rubric.name.toLowerCase().includes(query) ||
        rubric.control_id.toLowerCase().includes(query) ||
        rubric.description?.toLowerCase().includes(query)
      );
    }
    return true;
  });

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
      <div className="bg-dark-surface border border-dark-border rounded-lg w-full max-w-2xl max-h-[80vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-dark-border">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Plus className="h-5 w-5 text-primary" />
            New Assessment
          </h2>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Filters */}
        <div className="p-4 border-b border-dark-border space-y-3">
          <p className="text-sm text-slate-400">
            Select a rubric to create a new manual assessment
          </p>
          <div className="flex gap-3">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search rubrics..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-dark-bg border border-dark-border rounded-lg text-white placeholder-slate-500 focus:ring-2 focus:ring-primary focus:border-transparent"
                />
              </div>
            </div>
            <select
              value={selectedFramework}
              onChange={(e) => setSelectedFramework(e.target.value)}
              className="px-4 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-transparent"
            >
              <option value="">All Frameworks</option>
              {frameworks.map((fw) => (
                <option key={fw.id} value={fw.id}>
                  {fw.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Rubric List */}
        <div className="flex-1 overflow-y-auto p-4">
          {filteredRubrics.length === 0 ? (
            <div className="text-center py-8">
              <FolderOpen className="h-12 w-12 text-slate-500 mx-auto mb-3" />
              <p className="text-slate-400">No rubrics found</p>
              <p className="text-sm text-slate-500">
                Try adjusting your filters or search query
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3">
              {filteredRubrics.map((rubric) => (
                <div
                  key={rubric.id}
                  onClick={() => onSelectRubric(rubric)}
                  className="p-4 bg-dark-bg border border-dark-border rounded-lg cursor-pointer hover:border-primary/50 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <h4 className="font-medium text-white">{rubric.name}</h4>
                      <p className="text-sm text-slate-400">
                        {rubric.framework_id} - {rubric.control_id}
                      </p>
                      {rubric.description && (
                        <p className="text-sm text-slate-500 mt-1 line-clamp-1">
                          {rubric.description}
                        </p>
                      )}
                    </div>
                    <ChevronRight className="h-5 w-5 text-slate-500 flex-shrink-0" />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// New Campaign Modal
// ============================================================================

interface NewCampaignModalProps {
  isOpen: boolean;
  onClose: () => void;
  frameworks: ComplianceFramework[];
  onSubmit: (data: CreateCampaignRequest) => Promise<void>;
}

const NewCampaignModal: React.FC<NewCampaignModalProps> = ({
  isOpen,
  onClose,
  frameworks,
  onSubmit,
}) => {
  const [form, setForm] = useState<NewCampaignForm>({
    name: '',
    description: '',
    frameworks: [],
    due_date: '',
  });
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleToggleFramework = (frameworkId: string) => {
    setForm((prev) => ({
      ...prev,
      frameworks: prev.frameworks.includes(frameworkId)
        ? prev.frameworks.filter((f) => f !== frameworkId)
        : [...prev.frameworks, frameworkId],
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim() || form.frameworks.length === 0) {
      toast.error('Please provide a name and select at least one framework');
      return;
    }

    setIsSubmitting(true);
    try {
      await onSubmit({
        name: form.name.trim(),
        description: form.description.trim() || undefined,
        frameworks: form.frameworks,
        due_date: form.due_date || undefined,
      });
      setForm({ name: '', description: '', frameworks: [], due_date: '' });
      onClose();
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
      <div className="bg-dark-surface border border-dark-border rounded-lg w-full max-w-lg">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-dark-border">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Target className="h-5 w-5 text-primary" />
            New Campaign
          </h2>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          <Input
            label="Campaign Name"
            placeholder="Q4 2024 Compliance Assessment"
            value={form.name}
            onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
            required
          />

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">
              Description
            </label>
            <textarea
              className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-slate-100 placeholder-slate-500 focus:ring-2 focus:ring-primary focus:border-transparent resize-none"
              rows={3}
              placeholder="Describe the purpose of this assessment campaign..."
              value={form.description}
              onChange={(e) =>
                setForm((prev) => ({ ...prev, description: e.target.value }))
              }
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Frameworks <span className="text-red-400">*</span>
            </label>
            <div className="flex flex-wrap gap-2">
              {frameworks.map((fw) => (
                <button
                  key={fw.id}
                  type="button"
                  onClick={() => handleToggleFramework(fw.id)}
                  className={`px-3 py-1.5 rounded-lg border text-sm transition-colors ${
                    form.frameworks.includes(fw.id)
                      ? 'bg-primary/20 border-primary text-primary'
                      : 'bg-dark-bg border-dark-border text-slate-300 hover:border-slate-500'
                  }`}
                >
                  {form.frameworks.includes(fw.id) && (
                    <Check className="h-3 w-3 inline mr-1" />
                  )}
                  {fw.name}
                </button>
              ))}
            </div>
          </div>

          <Input
            label="Due Date"
            type="date"
            value={form.due_date}
            onChange={(e) => setForm((prev) => ({ ...prev, due_date: e.target.value }))}
          />

          <div className="flex gap-3 pt-4">
            <Button
              type="button"
              variant="secondary"
              onClick={onClose}
              className="flex-1"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              loading={isSubmitting}
              loadingText="Creating..."
              className="flex-1"
            >
              Create Campaign
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};

// ============================================================================
// Main Component
// ============================================================================

const ManualAssessmentPage: React.FC = () => {
  const navigate = useNavigate();

  // State
  const [activeTab, setActiveTab] = useState<TabType>('assessments');
  const [loading, setLoading] = useState(true);
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [assessments, setAssessments] = useState<ManualAssessment[]>([]);
  const [campaigns, setCampaigns] = useState<CampaignWithProgress[]>([]);
  const [rubrics, setRubrics] = useState<ComplianceRubric[]>([]);
  const [filters, setFilters] = useState<AssessmentFilters>({
    framework: '',
    status: '',
    search: '',
  });
  const [rubricFrameworkFilter, setRubricFrameworkFilter] = useState('');
  const [showNewAssessmentModal, setShowNewAssessmentModal] = useState(false);
  const [showNewCampaignModal, setShowNewCampaignModal] = useState(false);

  // Load data
  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [frameworksRes, assessmentsRes, campaignsRes, rubricsRes] = await Promise.all([
        complianceAPI.getFrameworks(),
        manualAssessmentAPI.getAll(),
        campaignAPI.getAll(),
        rubricAPI.getAll(),
      ]);

      setFrameworks(frameworksRes.data.frameworks);
      setAssessments(assessmentsRes.data);
      setCampaigns(campaignsRes.data);
      setRubrics(rubricsRes.data);
    } catch (error) {
      toast.error('Failed to load data');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  // Filter assessments
  const filteredAssessments = assessments.filter((assessment) => {
    if (filters.framework && assessment.framework_id !== filters.framework) return false;
    if (filters.status && assessment.review_status !== filters.status) return false;
    if (filters.search) {
      const query = filters.search.toLowerCase();
      return assessment.control_id.toLowerCase().includes(query);
    }
    return true;
  });

  // Filter rubrics
  const filteredRubrics = rubrics.filter((rubric) => {
    if (rubricFrameworkFilter && rubric.framework_id !== rubricFrameworkFilter) return false;
    return true;
  });

  // Handlers
  const handleSelectRubric = (rubric: ComplianceRubric) => {
    setShowNewAssessmentModal(false);
    navigate(`/manual-assessments/new?rubricId=${rubric.id}`);
  };

  const handleViewAssessment = (assessment: ManualAssessment) => {
    navigate(`/manual-assessments/${assessment.id}`);
  };

  const handleEditAssessment = (assessment: ManualAssessment) => {
    navigate(`/manual-assessments/${assessment.id}?edit=true`);
  };

  const handleDeleteAssessment = async (assessment: ManualAssessment) => {
    if (!window.confirm('Are you sure you want to delete this assessment?')) return;

    try {
      await manualAssessmentAPI.delete(assessment.id);
      setAssessments((prev) => prev.filter((a) => a.id !== assessment.id));
      toast.success('Assessment deleted');
    } catch (error) {
      toast.error('Failed to delete assessment');
    }
  };

  const handleCreateCampaign = async (data: CreateCampaignRequest) => {
    try {
      const response = await campaignAPI.create(data);
      const progressResponse = await campaignAPI.getById(response.data.id);
      setCampaigns((prev) => [...prev, progressResponse.data]);
      toast.success('Campaign created successfully');
    } catch (error) {
      toast.error('Failed to create campaign');
      throw error;
    }
  };

  const handleDeleteCampaign = async (campaign: CampaignWithProgress) => {
    if (!window.confirm('Are you sure you want to delete this campaign?')) return;

    try {
      await campaignAPI.delete(campaign.id);
      setCampaigns((prev) => prev.filter((c) => c.id !== campaign.id));
      toast.success('Campaign deleted');
    } catch (error) {
      toast.error('Failed to delete campaign');
    }
  };

  // Render loading state
  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ClipboardCheck className="h-8 w-8 text-primary" />
            <div>
              <h1 className="text-2xl font-bold text-white">Manual Compliance Assessments</h1>
              <p className="text-slate-400">
                Conduct and manage manual compliance assessments against security frameworks
              </p>
            </div>
          </div>
          <Button onClick={() => setShowNewAssessmentModal(true)}>
            <Plus className="h-4 w-4 mr-2" />
            New Assessment
          </Button>
        </div>

        {/* Tabs */}
        <div className="border-b border-dark-border">
          <nav className="flex gap-1">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-primary text-primary'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-600'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        {activeTab === 'assessments' && (
          <div className="space-y-4">
            {/* Filters */}
            <Card className="!p-4">
              <div className="flex flex-wrap gap-4">
                <div className="flex-1 min-w-[200px]">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                    <input
                      type="text"
                      placeholder="Search by control ID..."
                      value={filters.search}
                      onChange={(e) =>
                        setFilters((prev) => ({ ...prev, search: e.target.value }))
                      }
                      className="w-full pl-10 pr-4 py-2 bg-dark-bg border border-dark-border rounded-lg text-white placeholder-slate-500 focus:ring-2 focus:ring-primary focus:border-transparent"
                    />
                  </div>
                </div>
                <select
                  value={filters.framework}
                  onChange={(e) =>
                    setFilters((prev) => ({ ...prev, framework: e.target.value }))
                  }
                  className="px-4 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                >
                  <option value="">All Frameworks</option>
                  {frameworks.map((fw) => (
                    <option key={fw.id} value={fw.id}>
                      {fw.name}
                    </option>
                  ))}
                </select>
                <select
                  value={filters.status}
                  onChange={(e) =>
                    setFilters((prev) => ({ ...prev, status: e.target.value }))
                  }
                  className="px-4 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                >
                  {STATUS_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={loadData}
                  className="px-3"
                >
                  <RefreshCw className="h-4 w-4" />
                </Button>
              </div>
            </Card>

            {/* Assessment List */}
            {filteredAssessments.length === 0 ? (
              <Card className="!p-8 text-center">
                <FolderOpen className="h-12 w-12 text-slate-500 mx-auto mb-3" />
                <h3 className="text-lg font-medium text-slate-300 mb-1">
                  No Assessments Found
                </h3>
                <p className="text-sm text-slate-500 mb-4">
                  {filters.search || filters.framework || filters.status
                    ? 'Try adjusting your filters'
                    : 'Create your first manual assessment to get started'}
                </p>
                <Button onClick={() => setShowNewAssessmentModal(true)}>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Assessment
                </Button>
              </Card>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredAssessments.map((assessment) => (
                  <AssessmentCard
                    key={assessment.id}
                    assessment={assessment}
                    frameworks={frameworks}
                    onView={() => handleViewAssessment(assessment)}
                    onEdit={() => handleEditAssessment(assessment)}
                    onDelete={() => handleDeleteAssessment(assessment)}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'campaigns' && (
          <div className="space-y-4">
            {/* Campaign Header */}
            <div className="flex items-center justify-between">
              <p className="text-sm text-slate-400">
                Organize assessments into campaigns for tracking progress across frameworks
              </p>
              <Button onClick={() => setShowNewCampaignModal(true)}>
                <Plus className="h-4 w-4 mr-2" />
                New Campaign
              </Button>
            </div>

            {/* Campaign List */}
            {campaigns.length === 0 ? (
              <Card className="!p-8 text-center">
                <Target className="h-12 w-12 text-slate-500 mx-auto mb-3" />
                <h3 className="text-lg font-medium text-slate-300 mb-1">
                  No Campaigns Yet
                </h3>
                <p className="text-sm text-slate-500 mb-4">
                  Create a campaign to organize and track your assessment progress
                </p>
                <Button onClick={() => setShowNewCampaignModal(true)}>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Campaign
                </Button>
              </Card>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {campaigns.map((campaign) => (
                  <CampaignCard
                    key={campaign.id}
                    campaign={campaign}
                    onView={() => navigate(`/manual-assessments/campaign/${campaign.id}`)}
                    onDelete={() => handleDeleteCampaign(campaign)}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'rubrics' && (
          <div className="space-y-4">
            {/* Rubric Filters */}
            <Card className="!p-4">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <Filter className="h-4 w-4 text-slate-400" />
                  <span className="text-sm text-slate-400">Filter by framework:</span>
                </div>
                <select
                  value={rubricFrameworkFilter}
                  onChange={(e) => setRubricFrameworkFilter(e.target.value)}
                  className="px-4 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                >
                  <option value="">All Frameworks</option>
                  {frameworks.map((fw) => (
                    <option key={fw.id} value={fw.id}>
                      {fw.name}
                    </option>
                  ))}
                </select>
              </div>
            </Card>

            {/* Info Card */}
            <Card className="bg-blue-500/10 border-blue-500/30 !p-4">
              <div className="flex gap-3">
                <AlertCircle className="h-5 w-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm text-blue-300">
                    Rubrics define the assessment criteria for each compliance control.
                    System rubrics are provided by default. You can create custom rubrics for
                    specific controls to tailor the assessment process.
                  </p>
                </div>
              </div>
            </Card>

            {/* Rubric List */}
            {filteredRubrics.length === 0 ? (
              <Card className="!p-8 text-center">
                <BookOpen className="h-12 w-12 text-slate-500 mx-auto mb-3" />
                <h3 className="text-lg font-medium text-slate-300 mb-1">
                  No Rubrics Found
                </h3>
                <p className="text-sm text-slate-500">
                  Try selecting a different framework filter
                </p>
              </Card>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredRubrics.map((rubric) => (
                  <RubricCard
                    key={rubric.id}
                    rubric={rubric}
                    onSelect={() => handleSelectRubric(rubric)}
                  />
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Modals */}
      <NewAssessmentModal
        isOpen={showNewAssessmentModal}
        onClose={() => setShowNewAssessmentModal(false)}
        frameworks={frameworks}
        rubrics={rubrics}
        onSelectRubric={handleSelectRubric}
      />

      <NewCampaignModal
        isOpen={showNewCampaignModal}
        onClose={() => setShowNewCampaignModal(false)}
        frameworks={frameworks}
        onSubmit={handleCreateCampaign}
      />
    </Layout>
  );
};

export default ManualAssessmentPage;
