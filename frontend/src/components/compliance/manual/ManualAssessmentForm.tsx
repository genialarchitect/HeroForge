import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { toast } from 'react-toastify';
import { manualAssessmentAPI } from '../../../services/api';
import type {
  ComplianceRubric,
  ManualAssessment,
  CriterionResponse,
  AssessmentCriterion,
  RatingLevel,
  OverallRating,
  CreateManualAssessmentRequest,
} from '../../../types';
import Card from '../../ui/Card';
import Button from '../../ui/Button';
import Input from '../../ui/Input';
import Badge from '../../ui/Badge';
import {
  Save,
  X,
  ChevronDown,
  ChevronRight,
  AlertCircle,
  CheckCircle2,
  FileText,
  Calendar,
  Info,
  AlertTriangle,
  Paperclip,
  HelpCircle,
  BarChart3,
} from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

interface ManualAssessmentFormProps {
  rubric: ComplianceRubric;
  existingAssessment?: ManualAssessment;
  onSubmit: (assessment: ManualAssessment) => void;
  onCancel: () => void;
}

interface FormData {
  assessmentPeriodStart: string;
  assessmentPeriodEnd: string;
  criteriaResponses: Map<string, CriterionResponse>;
  overallRating: OverallRating;
  overallRatingOverride: boolean;
  evidenceSummary: string;
  findings: string;
  recommendations: string;
}

// ============================================================================
// Constants
// ============================================================================

const AUTO_SAVE_INTERVAL = 30000; // 30 seconds

const OVERALL_RATING_OPTIONS: { value: OverallRating; label: string; color: string }[] = [
  { value: 'compliant', label: 'Compliant', color: 'text-green-400' },
  { value: 'partial', label: 'Partially Compliant', color: 'text-yellow-400' },
  { value: 'non_compliant', label: 'Non-Compliant', color: 'text-red-400' },
  { value: 'not_applicable', label: 'Not Applicable', color: 'text-slate-400' },
];

const RATING_COLORS: Record<number, string> = {
  0: 'bg-slate-600 border-slate-500',
  1: 'bg-red-600 border-red-500',
  2: 'bg-orange-600 border-orange-500',
  3: 'bg-yellow-600 border-yellow-500',
  4: 'bg-green-600 border-green-500',
  5: 'bg-emerald-600 border-emerald-500',
};

// ============================================================================
// Helper Functions
// ============================================================================

const getLocalStorageKey = (rubricId: string, assessmentId?: string): string => {
  return `heroforge_assessment_draft_${rubricId}_${assessmentId || 'new'}`;
};

const formatDateForInput = (dateString: string | undefined): string => {
  if (!dateString) {
    return new Date().toISOString().split('T')[0];
  }
  return dateString.split('T')[0];
};

const calculateOverallScore = (
  responses: Map<string, CriterionResponse>,
  criteria: AssessmentCriterion[],
  maxRating: number
): number => {
  if (responses.size === 0 || criteria.length === 0) return 0;

  let totalWeight = 0;
  let weightedScore = 0;

  criteria.forEach((criterion) => {
    const response = responses.get(criterion.id);
    if (response && response.rating > 0) {
      totalWeight += criterion.weight;
      weightedScore += (response.rating / maxRating) * criterion.weight;
    }
  });

  if (totalWeight === 0) return 0;
  return Math.round((weightedScore / totalWeight) * 100);
};

const determineOverallRating = (score: number): OverallRating => {
  if (score >= 80) return 'compliant';
  if (score >= 50) return 'partial';
  return 'non_compliant';
};

// ============================================================================
// Sub-Components
// ============================================================================

interface ProgressIndicatorProps {
  completed: number;
  total: number;
}

const ProgressIndicator: React.FC<ProgressIndicatorProps> = ({ completed, total }) => {
  const percentage = total > 0 ? Math.round((completed / total) * 100) : 0;

  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-2 bg-dark-border rounded-full overflow-hidden">
        <div
          className={`h-full transition-all duration-300 ${
            percentage === 100
              ? 'bg-green-500'
              : percentage >= 50
              ? 'bg-yellow-500'
              : 'bg-blue-500'
          }`}
          style={{ width: `${percentage}%` }}
        />
      </div>
      <span className="text-sm text-slate-400 whitespace-nowrap">
        {completed} / {total} ({percentage}%)
      </span>
    </div>
  );
};

interface RatingSelectorProps {
  levels: RatingLevel[];
  selectedValue: number;
  onChange: (value: number) => void;
  disabled?: boolean;
}

const RatingSelector: React.FC<RatingSelectorProps> = ({
  levels,
  selectedValue,
  onChange,
  disabled = false,
}) => {
  return (
    <div className="flex flex-wrap gap-2">
      {levels.map((level) => {
        const isSelected = selectedValue === level.value;
        const colorClass = RATING_COLORS[level.value] || RATING_COLORS[0];

        return (
          <button
            key={level.value}
            type="button"
            onClick={() => onChange(level.value)}
            disabled={disabled}
            className={`
              px-3 py-2 rounded-lg border-2 transition-all text-sm font-medium
              ${
                isSelected
                  ? `${colorClass} text-white shadow-lg ring-2 ring-offset-2 ring-offset-dark-bg ring-white/20`
                  : 'bg-dark-surface border-dark-border text-slate-300 hover:border-slate-500'
              }
              ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
            `}
            title={level.description}
          >
            {level.label}
          </button>
        );
      })}
    </div>
  );
};

interface CriterionCardProps {
  criterion: AssessmentCriterion;
  response: CriterionResponse | undefined;
  ratingLevels: RatingLevel[];
  isExpanded: boolean;
  onToggleExpand: () => void;
  onRatingChange: (rating: number) => void;
  onNotesChange: (notes: string) => void;
}

const CriterionCard: React.FC<CriterionCardProps> = ({
  criterion,
  response,
  ratingLevels,
  isExpanded,
  onToggleExpand,
  onRatingChange,
  onNotesChange,
}) => {
  const hasRating = response && response.rating > 0;
  const hasEvidence = response && response.evidence_ids.length > 0;

  return (
    <div
      className={`border rounded-lg overflow-hidden transition-all ${
        hasRating
          ? 'border-green-500/30 bg-green-500/5'
          : 'border-dark-border bg-dark-surface'
      }`}
    >
      {/* Header */}
      <div
        onClick={onToggleExpand}
        className="flex items-center justify-between p-4 cursor-pointer hover:bg-dark-hover/50 transition-colors"
      >
        <div className="flex items-center gap-3 flex-1 min-w-0">
          {isExpanded ? (
            <ChevronDown className="h-5 w-5 text-slate-400 flex-shrink-0" />
          ) : (
            <ChevronRight className="h-5 w-5 text-slate-400 flex-shrink-0" />
          )}

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              {hasRating ? (
                <CheckCircle2 className="h-4 w-4 text-green-400 flex-shrink-0" />
              ) : (
                <AlertCircle className="h-4 w-4 text-slate-500 flex-shrink-0" />
              )}
              <span className="text-sm font-medium text-white truncate">
                {criterion.question}
              </span>
            </div>
            <p className="text-xs text-slate-400 truncate">{criterion.description}</p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0 ml-3">
          {hasEvidence && (
            <Badge variant="status" type="completed" className="text-xs">
              <Paperclip className="h-3 w-3 mr-1" />
              {response?.evidence_ids.length}
            </Badge>
          )}
          <span className="text-xs text-slate-500 bg-dark-bg px-2 py-1 rounded">
            Weight: {criterion.weight}
          </span>
          {hasRating && (
            <Badge
              variant="status"
              type={response!.rating >= 4 ? 'completed' : response!.rating >= 2 ? 'running' : 'failed'}
            >
              {ratingLevels.find((l) => l.value === response?.rating)?.label || 'N/A'}
            </Badge>
          )}
        </div>
      </div>

      {/* Expanded Content */}
      {isExpanded && (
        <div className="p-4 border-t border-dark-border bg-dark-bg space-y-4">
          {/* Question & Guidance */}
          <div className="space-y-2">
            <div className="flex items-start gap-2">
              <HelpCircle className="h-4 w-4 text-primary mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-sm font-medium text-slate-200">{criterion.question}</p>
                <p className="text-xs text-slate-400 mt-1">{criterion.description}</p>
              </div>
            </div>

            {criterion.guidance && (
              <div className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                <div className="flex items-start gap-2">
                  <Info className="h-4 w-4 text-blue-400 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-xs font-medium text-blue-300 mb-1">Guidance</p>
                    <p className="text-sm text-blue-100">{criterion.guidance}</p>
                  </div>
                </div>
              </div>
            )}

            {criterion.evidence_hint && (
              <div className="p-3 bg-purple-500/10 border border-purple-500/30 rounded-lg">
                <div className="flex items-start gap-2">
                  <Paperclip className="h-4 w-4 text-purple-400 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-xs font-medium text-purple-300 mb-1">Evidence Hint</p>
                    <p className="text-sm text-purple-100">{criterion.evidence_hint}</p>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Rating Selector */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Rating <span className="text-red-400">*</span>
            </label>
            <RatingSelector
              levels={ratingLevels}
              selectedValue={response?.rating || 0}
              onChange={onRatingChange}
            />
          </div>

          {/* Notes */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Notes / Justification
            </label>
            <textarea
              value={response?.notes || ''}
              onChange={(e) => onNotesChange(e.target.value)}
              className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-lg text-slate-100 placeholder-slate-500 focus:ring-2 focus:ring-primary focus:border-transparent resize-none"
              rows={3}
              placeholder="Provide justification for this rating..."
            />
          </div>

          {/* Evidence Indicator */}
          {hasEvidence && (
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <Paperclip className="h-4 w-4" />
              <span>{response?.evidence_ids.length} evidence item(s) attached</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ============================================================================
// Main Component
// ============================================================================

const ManualAssessmentForm: React.FC<ManualAssessmentFormProps> = ({
  rubric,
  existingAssessment,
  onSubmit,
  onCancel,
}) => {
  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------

  const [formData, setFormData] = useState<FormData>(() => {
    // Try to load from localStorage first
    const storageKey = getLocalStorageKey(rubric.id, existingAssessment?.id);
    const savedDraft = localStorage.getItem(storageKey);

    if (savedDraft) {
      try {
        const parsed = JSON.parse(savedDraft);
        return {
          assessmentPeriodStart: parsed.assessmentPeriodStart || formatDateForInput(existingAssessment?.assessment_period_start),
          assessmentPeriodEnd: parsed.assessmentPeriodEnd || formatDateForInput(existingAssessment?.assessment_period_end),
          criteriaResponses: new Map(Object.entries(parsed.criteriaResponses || {})),
          overallRating: parsed.overallRating || existingAssessment?.overall_rating || 'non_compliant',
          overallRatingOverride: parsed.overallRatingOverride || false,
          evidenceSummary: parsed.evidenceSummary || existingAssessment?.evidence_summary || '',
          findings: parsed.findings || existingAssessment?.findings || '',
          recommendations: parsed.recommendations || existingAssessment?.recommendations || '',
        };
      } catch (e) {
        console.warn('Failed to parse saved draft:', e);
      }
    }

    // Initialize from existing assessment or defaults
    const initialResponses = new Map<string, CriterionResponse>();
    if (existingAssessment?.criteria_responses) {
      existingAssessment.criteria_responses.forEach((response) => {
        initialResponses.set(response.criterion_id, response);
      });
    }

    return {
      assessmentPeriodStart: formatDateForInput(existingAssessment?.assessment_period_start),
      assessmentPeriodEnd: formatDateForInput(existingAssessment?.assessment_period_end),
      criteriaResponses: initialResponses,
      overallRating: existingAssessment?.overall_rating || 'non_compliant',
      overallRatingOverride: false,
      evidenceSummary: existingAssessment?.evidence_summary || '',
      findings: existingAssessment?.findings || '',
      recommendations: existingAssessment?.recommendations || '',
    };
  });

  const [expandedCriteria, setExpandedCriteria] = useState<Set<string>>(new Set());
  const [isDirty, setIsDirty] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [lastSaved, setLastSaved] = useState<Date | null>(null);

  // ---------------------------------------------------------------------------
  // Computed Values
  // ---------------------------------------------------------------------------

  const maxRating = useMemo(() => {
    return Math.max(...rubric.rating_scale.levels.map((l) => l.value));
  }, [rubric.rating_scale.levels]);

  const calculatedScore = useMemo(() => {
    return calculateOverallScore(
      formData.criteriaResponses,
      rubric.assessment_criteria,
      maxRating
    );
  }, [formData.criteriaResponses, rubric.assessment_criteria, maxRating]);

  const calculatedOverallRating = useMemo(() => {
    return determineOverallRating(calculatedScore);
  }, [calculatedScore]);

  const completedCriteriaCount = useMemo(() => {
    return Array.from(formData.criteriaResponses.values()).filter(
      (r) => r.rating > 0
    ).length;
  }, [formData.criteriaResponses]);

  const effectiveOverallRating = formData.overallRatingOverride
    ? formData.overallRating
    : calculatedOverallRating;

  // ---------------------------------------------------------------------------
  // Effects
  // ---------------------------------------------------------------------------

  // Auto-save to localStorage
  useEffect(() => {
    if (!isDirty) return;

    const saveInterval = setInterval(() => {
      const storageKey = getLocalStorageKey(rubric.id, existingAssessment?.id);
      const dataToSave = {
        ...formData,
        criteriaResponses: Object.fromEntries(formData.criteriaResponses),
      };
      localStorage.setItem(storageKey, JSON.stringify(dataToSave));
      setLastSaved(new Date());
    }, AUTO_SAVE_INTERVAL);

    return () => clearInterval(saveInterval);
  }, [isDirty, formData, rubric.id, existingAssessment?.id]);

  // Warn before navigating away with unsaved changes
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (isDirty) {
        e.preventDefault();
        e.returnValue = '';
      }
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [isDirty]);

  // ---------------------------------------------------------------------------
  // Handlers
  // ---------------------------------------------------------------------------

  const handleCriterionRatingChange = useCallback(
    (criterionId: string, rating: number) => {
      setFormData((prev) => {
        const newResponses = new Map(prev.criteriaResponses);
        const existing = newResponses.get(criterionId);
        newResponses.set(criterionId, {
          criterion_id: criterionId,
          rating,
          notes: existing?.notes || '',
          evidence_ids: existing?.evidence_ids || [],
        });
        return { ...prev, criteriaResponses: newResponses };
      });
      setIsDirty(true);
    },
    []
  );

  const handleCriterionNotesChange = useCallback(
    (criterionId: string, notes: string) => {
      setFormData((prev) => {
        const newResponses = new Map(prev.criteriaResponses);
        const existing = newResponses.get(criterionId);
        newResponses.set(criterionId, {
          criterion_id: criterionId,
          rating: existing?.rating || 0,
          notes,
          evidence_ids: existing?.evidence_ids || [],
        });
        return { ...prev, criteriaResponses: newResponses };
      });
      setIsDirty(true);
    },
    []
  );

  const toggleCriterionExpand = useCallback((criterionId: string) => {
    setExpandedCriteria((prev) => {
      const next = new Set(prev);
      if (next.has(criterionId)) {
        next.delete(criterionId);
      } else {
        next.add(criterionId);
      }
      return next;
    });
  }, []);

  const expandAllCriteria = useCallback(() => {
    setExpandedCriteria(new Set(rubric.assessment_criteria.map((c) => c.id)));
  }, [rubric.assessment_criteria]);

  const collapseAllCriteria = useCallback(() => {
    setExpandedCriteria(new Set());
  }, []);

  const validate = useCallback((): boolean => {
    const errors: string[] = [];

    if (!formData.assessmentPeriodStart) {
      errors.push('Assessment period start date is required');
    }

    if (!formData.assessmentPeriodEnd) {
      errors.push('Assessment period end date is required');
    }

    if (formData.assessmentPeriodStart && formData.assessmentPeriodEnd) {
      if (new Date(formData.assessmentPeriodStart) > new Date(formData.assessmentPeriodEnd)) {
        errors.push('Assessment period start date must be before end date');
      }
    }

    // Check that all criteria have ratings
    const unratedCriteria = rubric.assessment_criteria.filter((criterion) => {
      const response = formData.criteriaResponses.get(criterion.id);
      return !response || response.rating === 0;
    });

    if (unratedCriteria.length > 0) {
      errors.push(
        `${unratedCriteria.length} criterion/criteria still need ratings`
      );
    }

    setValidationErrors(errors);
    return errors.length === 0;
  }, [formData, rubric.assessment_criteria]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validate()) {
      toast.error('Please fix validation errors before submitting');
      return;
    }

    setIsSaving(true);

    try {
      const requestData: CreateManualAssessmentRequest = {
        rubric_id: rubric.id,
        framework_id: rubric.framework_id,
        control_id: rubric.control_id,
        assessment_period_start: formData.assessmentPeriodStart,
        assessment_period_end: formData.assessmentPeriodEnd,
        overall_rating: effectiveOverallRating,
        rating_score: calculatedScore,
        criteria_responses: Array.from(formData.criteriaResponses.values()),
        evidence_summary: formData.evidenceSummary || undefined,
        findings: formData.findings || undefined,
        recommendations: formData.recommendations || undefined,
      };

      let result: ManualAssessment;

      if (existingAssessment) {
        const response = await manualAssessmentAPI.update(existingAssessment.id, requestData);
        result = response.data;
      } else {
        const response = await manualAssessmentAPI.create(requestData);
        result = response.data;
      }

      // Clear draft from localStorage
      const storageKey = getLocalStorageKey(rubric.id, existingAssessment?.id);
      localStorage.removeItem(storageKey);

      setIsDirty(false);
      toast.success(
        existingAssessment
          ? 'Assessment updated successfully'
          : 'Assessment created successfully'
      );
      onSubmit(result);
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to save assessment');
    } finally {
      setIsSaving(false);
    }
  };

  const handleCancel = () => {
    if (isDirty) {
      const confirmed = window.confirm(
        'You have unsaved changes. Are you sure you want to cancel?'
      );
      if (!confirmed) return;
    }
    onCancel();
  };

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Header */}
      <Card className="!p-6">
        <div className="flex items-start justify-between mb-4">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <FileText className="h-5 w-5 text-primary" />
              {existingAssessment ? 'Edit Assessment' : 'New Assessment'}
            </h2>
            <p className="text-sm text-slate-400 mt-1">
              {rubric.name} - {rubric.control_id}
            </p>
          </div>
          {lastSaved && (
            <div className="text-xs text-slate-500">
              Draft saved: {lastSaved.toLocaleTimeString()}
            </div>
          )}
        </div>

        {rubric.description && (
          <p className="text-sm text-slate-300 mb-4">{rubric.description}</p>
        )}

        {/* Progress Indicator */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Assessment Progress
          </label>
          <ProgressIndicator
            completed={completedCriteriaCount}
            total={rubric.assessment_criteria.length}
          />
        </div>

        {/* Assessment Period */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <Input
              label="Assessment Period Start"
              type="date"
              required
              value={formData.assessmentPeriodStart}
              onChange={(e) => {
                setFormData((prev) => ({
                  ...prev,
                  assessmentPeriodStart: e.target.value,
                }));
                setIsDirty(true);
              }}
              icon={<Calendar className="h-4 w-4" />}
            />
          </div>
          <div>
            <Input
              label="Assessment Period End"
              type="date"
              required
              value={formData.assessmentPeriodEnd}
              onChange={(e) => {
                setFormData((prev) => ({
                  ...prev,
                  assessmentPeriodEnd: e.target.value,
                }));
                setIsDirty(true);
              }}
              icon={<Calendar className="h-4 w-4" />}
            />
          </div>
        </div>
      </Card>

      {/* Criteria Section */}
      <Card className="!p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <CheckCircle2 className="h-5 w-5 text-primary" />
            Assessment Criteria
          </h3>
          <div className="flex gap-2">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={expandAllCriteria}
            >
              Expand All
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={collapseAllCriteria}
            >
              Collapse All
            </Button>
          </div>
        </div>

        <div className="space-y-3">
          {rubric.assessment_criteria.map((criterion) => (
            <CriterionCard
              key={criterion.id}
              criterion={criterion}
              response={formData.criteriaResponses.get(criterion.id)}
              ratingLevels={rubric.rating_scale.levels}
              isExpanded={expandedCriteria.has(criterion.id)}
              onToggleExpand={() => toggleCriterionExpand(criterion.id)}
              onRatingChange={(rating) =>
                handleCriterionRatingChange(criterion.id, rating)
              }
              onNotesChange={(notes) =>
                handleCriterionNotesChange(criterion.id, notes)
              }
            />
          ))}
        </div>
      </Card>

      {/* Overall Rating Section */}
      <Card className="!p-6">
        <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
          <BarChart3 className="h-5 w-5 text-primary" />
          Overall Rating
        </h3>

        {/* Calculated Score Display */}
        <div className="p-4 bg-dark-bg rounded-lg border border-dark-border mb-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Calculated Score</p>
              <p
                className={`text-3xl font-bold ${
                  calculatedScore >= 80
                    ? 'text-green-400'
                    : calculatedScore >= 50
                    ? 'text-yellow-400'
                    : 'text-red-400'
                }`}
              >
                {calculatedScore}%
              </p>
            </div>
            <div className="text-right">
              <p className="text-sm text-slate-400">Suggested Rating</p>
              <p
                className={`text-lg font-semibold ${
                  OVERALL_RATING_OPTIONS.find((o) => o.value === calculatedOverallRating)
                    ?.color || 'text-slate-400'
                }`}
              >
                {OVERALL_RATING_OPTIONS.find((o) => o.value === calculatedOverallRating)
                  ?.label || 'N/A'}
              </p>
            </div>
          </div>
        </div>

        {/* Override Toggle */}
        <div className="flex items-center gap-3 mb-4">
          <label className="flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={formData.overallRatingOverride}
              onChange={(e) => {
                setFormData((prev) => ({
                  ...prev,
                  overallRatingOverride: e.target.checked,
                }));
                setIsDirty(true);
              }}
              className="sr-only"
            />
            <div
              className={`w-10 h-6 rounded-full p-1 transition-colors ${
                formData.overallRatingOverride
                  ? 'bg-primary'
                  : 'bg-dark-border'
              }`}
            >
              <div
                className={`w-4 h-4 rounded-full bg-white transition-transform ${
                  formData.overallRatingOverride ? 'translate-x-4' : ''
                }`}
              />
            </div>
            <span className="ml-2 text-sm text-slate-300">
              Override calculated rating
            </span>
          </label>
        </div>

        {/* Manual Rating Selection */}
        {formData.overallRatingOverride && (
          <div className="mb-4 animate-in fade-in duration-200">
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Manual Overall Rating
            </label>
            <div className="flex flex-wrap gap-2">
              {OVERALL_RATING_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => {
                    setFormData((prev) => ({
                      ...prev,
                      overallRating: option.value,
                    }));
                    setIsDirty(true);
                  }}
                  className={`
                    px-4 py-2 rounded-lg border-2 transition-all text-sm font-medium
                    ${
                      formData.overallRating === option.value
                        ? `bg-dark-hover border-primary ${option.color}`
                        : 'bg-dark-surface border-dark-border text-slate-300 hover:border-slate-500'
                    }
                  `}
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Effective Rating Display */}
        <div className="p-3 bg-primary/10 border border-primary/30 rounded-lg">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-primary" />
            <span className="text-sm font-medium text-white">
              Final Rating:{' '}
              <span
                className={
                  OVERALL_RATING_OPTIONS.find((o) => o.value === effectiveOverallRating)
                    ?.color || 'text-slate-400'
                }
              >
                {OVERALL_RATING_OPTIONS.find((o) => o.value === effectiveOverallRating)
                  ?.label || 'N/A'}
              </span>
            </span>
          </div>
        </div>
      </Card>

      {/* Evidence & Findings Section */}
      <Card className="!p-6">
        <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
          <FileText className="h-5 w-5 text-primary" />
          Evidence & Findings
        </h3>

        <div className="space-y-4">
          {/* Evidence Summary */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Evidence Summary
            </label>
            <textarea
              value={formData.evidenceSummary}
              onChange={(e) => {
                setFormData((prev) => ({
                  ...prev,
                  evidenceSummary: e.target.value,
                }));
                setIsDirty(true);
              }}
              className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-lg text-slate-100 placeholder-slate-500 focus:ring-2 focus:ring-primary focus:border-transparent resize-none"
              rows={4}
              placeholder="Summarize the evidence collected for this assessment..."
            />
          </div>

          {/* Findings */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Findings
            </label>
            <textarea
              value={formData.findings}
              onChange={(e) => {
                setFormData((prev) => ({
                  ...prev,
                  findings: e.target.value,
                }));
                setIsDirty(true);
              }}
              className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-lg text-slate-100 placeholder-slate-500 focus:ring-2 focus:ring-primary focus:border-transparent resize-none"
              rows={4}
              placeholder="Document any issues, gaps, or areas of concern identified..."
            />
          </div>

          {/* Recommendations */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Recommendations
            </label>
            <textarea
              value={formData.recommendations}
              onChange={(e) => {
                setFormData((prev) => ({
                  ...prev,
                  recommendations: e.target.value,
                }));
                setIsDirty(true);
              }}
              className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-lg text-slate-100 placeholder-slate-500 focus:ring-2 focus:ring-primary focus:border-transparent resize-none"
              rows={4}
              placeholder="Provide recommendations for improvement or remediation..."
            />
          </div>
        </div>
      </Card>

      {/* Validation Errors */}
      {validationErrors.length > 0 && (
        <Card className="!p-4 border-red-500/30 bg-red-500/10">
          <div className="flex items-start gap-2">
            <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-red-300">Please fix the following errors:</p>
              <ul className="mt-2 space-y-1">
                {validationErrors.map((error, index) => (
                  <li key={index} className="text-sm text-red-200">
                    {error}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </Card>
      )}

      {/* Action Buttons */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-400">
          {isDirty && (
            <span className="flex items-center gap-1">
              <AlertCircle className="h-4 w-4 text-yellow-400" />
              Unsaved changes
            </span>
          )}
        </div>
        <div className="flex gap-3">
          <Button type="button" variant="secondary" onClick={handleCancel}>
            <X className="h-4 w-4 mr-2" />
            Cancel
          </Button>
          <Button
            type="submit"
            loading={isSaving}
            loadingText="Saving..."
            disabled={!isDirty && !!existingAssessment}
          >
            <Save className="h-4 w-4 mr-2" />
            {existingAssessment ? 'Update Assessment' : 'Save Assessment'}
          </Button>
        </div>
      </div>
    </form>
  );
};

export default ManualAssessmentForm;
