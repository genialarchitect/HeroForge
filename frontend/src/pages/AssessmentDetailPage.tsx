import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { toast } from 'react-toastify';
import {
  manualAssessmentAPI,
  rubricAPI,
  assessmentEvidenceAPI,
} from '../services/api';
import type {
  ManualAssessment,
  ComplianceRubric,
  AssessmentEvidence,
  ReviewStatus,
} from '../types';
import Layout from '../components/layout/Layout';
import Card from '../components/ui/Card';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import ManualAssessmentForm from '../components/compliance/manual/ManualAssessmentForm';
import EvidenceGallery from '../components/compliance/manual/EvidenceGallery';
import EvidenceUploader from '../components/compliance/manual/EvidenceUploader';
import {
  ArrowLeft,
  ClipboardCheck,
  FileText,
  Calendar,
  Clock,
  User,
  Edit,
  Save,
  Send,
  CheckCircle,
  XCircle,
  AlertCircle,
  MessageSquare,
  History,
  Paperclip,
  Info,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

interface TimelineEvent {
  id: string;
  type: 'created' | 'updated' | 'submitted' | 'approved' | 'rejected';
  timestamp: string;
  user?: string;
  notes?: string;
}

// ============================================================================
// Constants
// ============================================================================

const STATUS_BADGE_MAP: Record<ReviewStatus, { type: 'pending' | 'running' | 'completed' | 'failed'; label: string }> = {
  draft: { type: 'pending', label: 'Draft' },
  pending_review: { type: 'running', label: 'Pending Review' },
  approved: { type: 'completed', label: 'Approved' },
  rejected: { type: 'failed', label: 'Rejected' },
};

const OVERALL_RATING_LABELS: Record<string, { label: string; color: string }> = {
  compliant: { label: 'Compliant', color: 'text-green-400' },
  partial: { label: 'Partially Compliant', color: 'text-yellow-400' },
  non_compliant: { label: 'Non-Compliant', color: 'text-red-400' },
  not_applicable: { label: 'Not Applicable', color: 'text-slate-400' },
};

// ============================================================================
// Sub-Components
// ============================================================================

interface AssessmentHeaderProps {
  assessment: ManualAssessment;
  rubric: ComplianceRubric;
  onBack: () => void;
  onEdit: () => void;
  onSubmit: () => void;
  onApprove: () => void;
  onReject: () => void;
  isEditing: boolean;
  isSubmitting: boolean;
}

const AssessmentHeader: React.FC<AssessmentHeaderProps> = ({
  assessment,
  rubric,
  onBack,
  onEdit,
  onSubmit,
  onApprove,
  onReject,
  isEditing,
  isSubmitting,
}) => {
  const statusBadge = STATUS_BADGE_MAP[assessment.review_status];
  const canEdit = assessment.review_status === 'draft' || assessment.review_status === 'rejected';
  const canSubmit = assessment.review_status === 'draft';
  const canReview = assessment.review_status === 'pending_review';

  return (
    <div className="flex items-start justify-between mb-6">
      <div className="flex items-start gap-4">
        <Button variant="ghost" onClick={onBack} className="mt-1">
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-2xl font-bold text-white">{rubric.control_id}</h1>
            <Badge variant="status" type={statusBadge.type}>
              {statusBadge.label}
            </Badge>
          </div>
          <p className="text-slate-400">{rubric.name}</p>
          <p className="text-sm text-slate-500">
            {rubric.framework_id} - Assessment Period:{' '}
            {new Date(assessment.assessment_period_start).toLocaleDateString()} to{' '}
            {new Date(assessment.assessment_period_end).toLocaleDateString()}
          </p>
        </div>
      </div>

      <div className="flex items-center gap-2">
        {!isEditing && canEdit && (
          <Button variant="secondary" onClick={onEdit}>
            <Edit className="h-4 w-4 mr-2" />
            Edit
          </Button>
        )}
        {!isEditing && canSubmit && (
          <Button onClick={onSubmit} loading={isSubmitting} loadingText="Submitting...">
            <Send className="h-4 w-4 mr-2" />
            Submit for Review
          </Button>
        )}
        {!isEditing && canReview && (
          <>
            <Button
              variant="danger"
              onClick={onReject}
              loading={isSubmitting}
              loadingText="Rejecting..."
            >
              <XCircle className="h-4 w-4 mr-2" />
              Reject
            </Button>
            <Button onClick={onApprove} loading={isSubmitting} loadingText="Approving...">
              <CheckCircle className="h-4 w-4 mr-2" />
              Approve
            </Button>
          </>
        )}
      </div>
    </div>
  );
};

interface ReadOnlyAssessmentViewProps {
  assessment: ManualAssessment;
  rubric: ComplianceRubric;
}

const ReadOnlyAssessmentView: React.FC<ReadOnlyAssessmentViewProps> = ({
  assessment,
  rubric,
}) => {
  const [expandedCriteria, setExpandedCriteria] = useState<Set<string>>(new Set());
  const overallRatingInfo = OVERALL_RATING_LABELS[assessment.overall_rating] || {
    label: assessment.overall_rating,
    color: 'text-slate-400',
  };

  const toggleCriterion = (id: string) => {
    setExpandedCriteria((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  return (
    <div className="space-y-6">
      {/* Score Summary */}
      <Card className="!p-6">
        <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
          <ClipboardCheck className="h-5 w-5 text-primary" />
          Assessment Summary
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Overall Score */}
          <div className="p-4 bg-dark-bg rounded-lg border border-dark-border">
            <p className="text-sm text-slate-400 mb-1">Overall Score</p>
            <p
              className={`text-3xl font-bold ${
                assessment.rating_score !== null && assessment.rating_score >= 80
                  ? 'text-green-400'
                  : assessment.rating_score !== null && assessment.rating_score >= 50
                  ? 'text-yellow-400'
                  : 'text-red-400'
              }`}
            >
              {assessment.rating_score !== null ? `${assessment.rating_score}%` : 'N/A'}
            </p>
          </div>

          {/* Overall Rating */}
          <div className="p-4 bg-dark-bg rounded-lg border border-dark-border">
            <p className="text-sm text-slate-400 mb-1">Overall Rating</p>
            <p className={`text-xl font-semibold ${overallRatingInfo.color}`}>
              {overallRatingInfo.label}
            </p>
          </div>

          {/* Criteria Completed */}
          <div className="p-4 bg-dark-bg rounded-lg border border-dark-border">
            <p className="text-sm text-slate-400 mb-1">Criteria Assessed</p>
            <p className="text-xl font-semibold text-white">
              {assessment.criteria_responses.filter((r) => r.rating > 0).length} /{' '}
              {rubric.assessment_criteria.length}
            </p>
          </div>
        </div>
      </Card>

      {/* Criteria Responses */}
      <Card className="!p-6">
        <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
          <FileText className="h-5 w-5 text-primary" />
          Criteria Responses
        </h3>

        <div className="space-y-3">
          {rubric.assessment_criteria.map((criterion) => {
            const response = assessment.criteria_responses.find(
              (r) => r.criterion_id === criterion.id
            );
            const ratingLevel = rubric.rating_scale.levels.find(
              (l) => l.value === response?.rating
            );
            const isExpanded = expandedCriteria.has(criterion.id);

            return (
              <div
                key={criterion.id}
                className="border border-dark-border rounded-lg overflow-hidden"
              >
                <div
                  onClick={() => toggleCriterion(criterion.id)}
                  className="flex items-center justify-between p-4 cursor-pointer hover:bg-dark-hover/50 transition-colors"
                >
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    {isExpanded ? (
                      <ChevronDown className="h-5 w-5 text-slate-400 flex-shrink-0" />
                    ) : (
                      <ChevronRight className="h-5 w-5 text-slate-400 flex-shrink-0" />
                    )}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-white truncate">
                        {criterion.question}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0 ml-3">
                    <span className="text-xs text-slate-500 bg-dark-bg px-2 py-1 rounded">
                      Weight: {criterion.weight}
                    </span>
                    {ratingLevel ? (
                      <Badge
                        variant="status"
                        type={
                          response!.rating >= 4
                            ? 'completed'
                            : response!.rating >= 2
                            ? 'running'
                            : 'failed'
                        }
                      >
                        {ratingLevel.label}
                      </Badge>
                    ) : (
                      <Badge variant="status" type="pending">
                        Not Rated
                      </Badge>
                    )}
                  </div>
                </div>

                {isExpanded && (
                  <div className="p-4 border-t border-dark-border bg-dark-bg space-y-3">
                    <div>
                      <p className="text-sm text-slate-400 mb-1">Description</p>
                      <p className="text-sm text-slate-300">{criterion.description}</p>
                    </div>
                    {criterion.guidance && (
                      <div>
                        <p className="text-sm text-slate-400 mb-1">Guidance</p>
                        <p className="text-sm text-slate-300">{criterion.guidance}</p>
                      </div>
                    )}
                    {response?.notes && (
                      <div>
                        <p className="text-sm text-slate-400 mb-1">Notes</p>
                        <p className="text-sm text-slate-300">{response.notes}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Card>

      {/* Evidence Summary */}
      {assessment.evidence_summary && (
        <Card className="!p-6">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
            <Paperclip className="h-5 w-5 text-primary" />
            Evidence Summary
          </h3>
          <p className="text-slate-300 whitespace-pre-wrap">{assessment.evidence_summary}</p>
        </Card>
      )}

      {/* Findings */}
      {assessment.findings && (
        <Card className="!p-6">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
            <AlertCircle className="h-5 w-5 text-yellow-400" />
            Findings
          </h3>
          <p className="text-slate-300 whitespace-pre-wrap">{assessment.findings}</p>
        </Card>
      )}

      {/* Recommendations */}
      {assessment.recommendations && (
        <Card className="!p-6">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
            <Info className="h-5 w-5 text-blue-400" />
            Recommendations
          </h3>
          <p className="text-slate-300 whitespace-pre-wrap">{assessment.recommendations}</p>
        </Card>
      )}

      {/* Reviewer Notes */}
      {assessment.reviewer_notes && (
        <Card className="!p-6 border-yellow-500/30 bg-yellow-500/5">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
            <MessageSquare className="h-5 w-5 text-yellow-400" />
            Reviewer Notes
          </h3>
          <p className="text-slate-300 whitespace-pre-wrap">{assessment.reviewer_notes}</p>
        </Card>
      )}
    </div>
  );
};

interface TimelineSectionProps {
  assessment: ManualAssessment;
}

const TimelineSection: React.FC<TimelineSectionProps> = ({ assessment }) => {
  // Build timeline from assessment data
  const timeline: TimelineEvent[] = [
    {
      id: '1',
      type: 'created',
      timestamp: assessment.created_at,
    },
  ];

  if (assessment.updated_at !== assessment.created_at) {
    timeline.push({
      id: '2',
      type: 'updated',
      timestamp: assessment.updated_at,
    });
  }

  if (assessment.review_status === 'pending_review') {
    timeline.push({
      id: '3',
      type: 'submitted',
      timestamp: assessment.updated_at,
    });
  }

  if (assessment.review_status === 'approved') {
    timeline.push({
      id: '4',
      type: 'approved',
      timestamp: assessment.updated_at,
    });
  }

  if (assessment.review_status === 'rejected') {
    timeline.push({
      id: '5',
      type: 'rejected',
      timestamp: assessment.updated_at,
      notes: assessment.reviewer_notes || undefined,
    });
  }

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'created':
        return <FileText className="h-4 w-4 text-blue-400" />;
      case 'updated':
        return <Edit className="h-4 w-4 text-slate-400" />;
      case 'submitted':
        return <Send className="h-4 w-4 text-yellow-400" />;
      case 'approved':
        return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'rejected':
        return <XCircle className="h-4 w-4 text-red-400" />;
      default:
        return <Clock className="h-4 w-4 text-slate-400" />;
    }
  };

  const getEventLabel = (type: string) => {
    switch (type) {
      case 'created':
        return 'Assessment created';
      case 'updated':
        return 'Assessment updated';
      case 'submitted':
        return 'Submitted for review';
      case 'approved':
        return 'Assessment approved';
      case 'rejected':
        return 'Assessment rejected';
      default:
        return type;
    }
  };

  return (
    <Card className="!p-6">
      <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
        <History className="h-5 w-5 text-primary" />
        History
      </h3>

      <div className="space-y-4">
        {timeline.map((event, index) => (
          <div key={event.id} className="flex gap-3">
            <div className="flex flex-col items-center">
              <div className="p-2 bg-dark-bg border border-dark-border rounded-full">
                {getEventIcon(event.type)}
              </div>
              {index < timeline.length - 1 && (
                <div className="flex-1 w-px bg-dark-border my-1" />
              )}
            </div>
            <div className="flex-1 pb-4">
              <p className="text-sm font-medium text-white">{getEventLabel(event.type)}</p>
              <p className="text-xs text-slate-500">
                {new Date(event.timestamp).toLocaleString()}
              </p>
              {event.notes && (
                <p className="text-sm text-slate-400 mt-1">{event.notes}</p>
              )}
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
};

// ============================================================================
// Reject Modal
// ============================================================================

interface RejectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (notes: string) => void;
  isSubmitting: boolean;
}

const RejectModal: React.FC<RejectModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  isSubmitting,
}) => {
  const [notes, setNotes] = useState('');

  if (!isOpen) return null;

  const handleConfirm = () => {
    if (!notes.trim()) {
      toast.error('Please provide a reason for rejection');
      return;
    }
    onConfirm(notes.trim());
  };

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
      <div className="bg-dark-surface border border-dark-border rounded-lg w-full max-w-lg">
        <div className="p-4 border-b border-dark-border">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <XCircle className="h-5 w-5 text-red-400" />
            Reject Assessment
          </h2>
        </div>

        <div className="p-4 space-y-4">
          <p className="text-sm text-slate-400">
            Please provide feedback for the assessor explaining why this assessment is
            being rejected.
          </p>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">
              Rejection Notes <span className="text-red-400">*</span>
            </label>
            <textarea
              className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-slate-100 placeholder-slate-500 focus:ring-2 focus:ring-primary focus:border-transparent resize-none"
              rows={4}
              placeholder="Explain what needs to be corrected..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
            />
          </div>

          <div className="flex gap-3 pt-2">
            <Button variant="secondary" onClick={onClose} className="flex-1">
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={handleConfirm}
              loading={isSubmitting}
              loadingText="Rejecting..."
              className="flex-1"
            >
              Reject Assessment
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// Main Component
// ============================================================================

const AssessmentDetailPage: React.FC = () => {
  const { assessmentId } = useParams<{ assessmentId: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  // State
  const [loading, setLoading] = useState(true);
  const [assessment, setAssessment] = useState<ManualAssessment | null>(null);
  const [rubric, setRubric] = useState<ComplianceRubric | null>(null);
  const [evidence, setEvidence] = useState<AssessmentEvidence[]>([]);
  const [isEditing, setIsEditing] = useState(searchParams.get('edit') === 'true');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showRejectModal, setShowRejectModal] = useState(false);
  const [showEvidenceUploader, setShowEvidenceUploader] = useState(false);

  // Check if this is a new assessment
  const isNew = assessmentId === 'new';
  const rubricId = searchParams.get('rubricId');

  // Load data
  useEffect(() => {
    if (isNew && rubricId) {
      loadRubricForNew(rubricId);
    } else if (assessmentId && !isNew) {
      loadAssessment(assessmentId);
    } else {
      navigate('/manual-assessments');
    }
  }, [assessmentId, rubricId, isNew, navigate]);

  const loadRubricForNew = async (id: string) => {
    setLoading(true);
    try {
      const response = await rubricAPI.getById(id);
      setRubric(response.data);
      setIsEditing(true);
    } catch (error) {
      toast.error('Failed to load rubric');
      navigate('/manual-assessments');
    } finally {
      setLoading(false);
    }
  };

  const loadAssessment = async (id: string) => {
    setLoading(true);
    try {
      const [assessmentRes, evidenceRes] = await Promise.all([
        manualAssessmentAPI.getById(id),
        assessmentEvidenceAPI.getAll(id),
      ]);

      setAssessment(assessmentRes.data);
      setEvidence(evidenceRes.data);

      // Load the rubric
      const rubricRes = await rubricAPI.getById(assessmentRes.data.rubric_id);
      setRubric(rubricRes.data);
    } catch (error) {
      toast.error('Failed to load assessment');
      navigate('/manual-assessments');
    } finally {
      setLoading(false);
    }
  };

  // Handlers
  const handleFormSubmit = (savedAssessment: ManualAssessment) => {
    setAssessment(savedAssessment);
    setIsEditing(false);
    if (isNew) {
      navigate(`/manual-assessments/${savedAssessment.id}`, { replace: true });
    }
    toast.success('Assessment saved successfully');
  };

  const handleFormCancel = () => {
    if (isNew) {
      navigate('/manual-assessments');
    } else {
      setIsEditing(false);
    }
  };

  const handleSubmitForReview = async () => {
    if (!assessment) return;

    setIsSubmitting(true);
    try {
      const response = await manualAssessmentAPI.submit(assessment.id);
      setAssessment(response.data);
      toast.success('Assessment submitted for review');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to submit assessment');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleApprove = async () => {
    if (!assessment) return;

    setIsSubmitting(true);
    try {
      const response = await manualAssessmentAPI.approve(assessment.id);
      setAssessment(response.data);
      toast.success('Assessment approved');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to approve assessment');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleReject = async (notes: string) => {
    if (!assessment) return;

    setIsSubmitting(true);
    try {
      const response = await manualAssessmentAPI.reject(assessment.id, notes);
      setAssessment(response.data);
      setShowRejectModal(false);
      toast.success('Assessment rejected');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to reject assessment');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleEvidenceAdded = (newEvidence: AssessmentEvidence) => {
    setEvidence((prev) => [...prev, newEvidence]);
  };

  const handleEvidenceDeleted = (id: string) => {
    setEvidence((prev) => prev.filter((e) => e.id !== id));
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

  // Render error state
  if (!rubric) {
    return (
      <Layout>
        <div className="text-center py-12">
          <AlertCircle className="h-12 w-12 text-red-400 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">Assessment Not Found</h2>
          <p className="text-slate-400 mb-4">
            The requested assessment could not be loaded.
          </p>
          <Button onClick={() => navigate('/manual-assessments')}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Assessments
          </Button>
        </div>
      </Layout>
    );
  }

  // Render new assessment form
  if (isNew || (isEditing && rubric)) {
    return (
      <Layout>
        <div className="space-y-6">
          {/* Header for new/edit */}
          <div className="flex items-center gap-4">
            <Button variant="ghost" onClick={handleFormCancel}>
              <ArrowLeft className="h-5 w-5" />
            </Button>
            <div>
              <h1 className="text-2xl font-bold text-white">
                {isNew ? 'New Assessment' : 'Edit Assessment'}
              </h1>
              <p className="text-slate-400">
                {rubric.framework_id} - {rubric.control_id}
              </p>
            </div>
          </div>

          {/* Form */}
          <ManualAssessmentForm
            rubric={rubric}
            existingAssessment={isNew ? undefined : assessment || undefined}
            onSubmit={handleFormSubmit}
            onCancel={handleFormCancel}
          />
        </div>
      </Layout>
    );
  }

  // Render view mode
  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        {assessment && (
          <AssessmentHeader
            assessment={assessment}
            rubric={rubric}
            onBack={() => navigate('/manual-assessments')}
            onEdit={() => setIsEditing(true)}
            onSubmit={handleSubmitForReview}
            onApprove={handleApprove}
            onReject={() => setShowRejectModal(true)}
            isEditing={isEditing}
            isSubmitting={isSubmitting}
          />
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-6">
            {assessment && (
              <ReadOnlyAssessmentView assessment={assessment} rubric={rubric} />
            )}
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Evidence Section */}
            <Card className="!p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                  <Paperclip className="h-5 w-5 text-primary" />
                  Evidence
                </h3>
                {assessment?.review_status === 'draft' && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setShowEvidenceUploader(!showEvidenceUploader)}
                  >
                    {showEvidenceUploader ? 'Hide Uploader' : 'Add Evidence'}
                  </Button>
                )}
              </div>

              {showEvidenceUploader && assessment && (
                <div className="mb-4">
                  <EvidenceUploader
                    assessmentId={assessment.id}
                    onEvidenceAdded={handleEvidenceAdded}
                  />
                </div>
              )}

              {assessment && (
                <EvidenceGallery
                  assessmentId={assessment.id}
                  evidence={evidence}
                  onDelete={handleEvidenceDeleted}
                  readOnly={assessment.review_status !== 'draft'}
                />
              )}
            </Card>

            {/* Timeline */}
            {assessment && <TimelineSection assessment={assessment} />}

            {/* Metadata */}
            <Card className="!p-6">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
                <Info className="h-5 w-5 text-primary" />
                Details
              </h3>

              <dl className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <dt className="text-slate-400">Framework</dt>
                  <dd className="text-white font-medium">{rubric.framework_id}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-slate-400">Control</dt>
                  <dd className="text-white font-medium">{rubric.control_id}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-slate-400">Rating Scale</dt>
                  <dd className="text-white font-medium capitalize">
                    {rubric.rating_scale.scale_type.replace('_', ' ')}
                  </dd>
                </div>
                {assessment && (
                  <>
                    <div className="flex justify-between">
                      <dt className="text-slate-400">Created</dt>
                      <dd className="text-white">
                        {new Date(assessment.created_at).toLocaleDateString()}
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-slate-400">Last Updated</dt>
                      <dd className="text-white">
                        {new Date(assessment.updated_at).toLocaleDateString()}
                      </dd>
                    </div>
                  </>
                )}
              </dl>
            </Card>
          </div>
        </div>
      </div>

      {/* Reject Modal */}
      <RejectModal
        isOpen={showRejectModal}
        onClose={() => setShowRejectModal(false)}
        onConfirm={handleReject}
        isSubmitting={isSubmitting}
      />
    </Layout>
  );
};

export default AssessmentDetailPage;
