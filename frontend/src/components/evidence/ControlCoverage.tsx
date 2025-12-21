import React from 'react';
import {
  Shield,
  CheckCircle,
  AlertCircle,
  Clock,
  FileText,
  BarChart3,
} from 'lucide-react';
import type { ControlEvidenceSummary } from '../../types/evidence';
import Badge from '../ui/Badge';

interface ControlCoverageProps {
  summary: ControlEvidenceSummary;
  onViewEvidence?: (controlId: string, frameworkId: string) => void;
  compact?: boolean;
}

const getCoverageColor = (score: number): 'green' | 'yellow' | 'red' | 'gray' => {
  if (score >= 0.8) return 'green';
  if (score >= 0.5) return 'yellow';
  if (score > 0) return 'red';
  return 'gray';
};

const getCoverageLabel = (score: number): string => {
  if (score >= 0.8) return 'Strong';
  if (score >= 0.5) return 'Partial';
  if (score > 0) return 'Weak';
  return 'None';
};

const ControlCoverage: React.FC<ControlCoverageProps> = ({
  summary,
  onViewEvidence,
  compact = false,
}) => {
  const coveragePercent = Math.round(summary.coverage_score * 100);
  const coverageColor = getCoverageColor(summary.coverage_score);
  const coverageLabel = getCoverageLabel(summary.coverage_score);

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  if (compact) {
    return (
      <div
        className="flex items-center justify-between p-3 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg hover:border-primary/50 transition-colors cursor-pointer"
        onClick={() => onViewEvidence?.(summary.control_id, summary.framework_id)}
      >
        <div className="flex items-center gap-3">
          <div
            className={`w-2 h-2 rounded-full ${
              coverageColor === 'green'
                ? 'bg-green-500'
                : coverageColor === 'yellow'
                  ? 'bg-yellow-500'
                  : coverageColor === 'red'
                    ? 'bg-red-500'
                    : 'bg-gray-400'
            }`}
          />
          <div>
            <p className="font-medium text-sm text-slate-900 dark:text-white">
              {summary.control_id}
            </p>
            <p className="text-xs text-slate-500">{summary.framework_id}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right">
            <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
              {coveragePercent}%
            </p>
            <p className="text-xs text-slate-500">{summary.total_evidence} items</p>
          </div>
          <Badge variant={coverageColor}>{coverageLabel}</Badge>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-lg">
            <Shield className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-900 dark:text-white">{summary.control_id}</h3>
            <p className="text-sm text-slate-500">{summary.framework_id}</p>
          </div>
        </div>
        <Badge variant={coverageColor} className="text-lg px-3 py-1">
          {coveragePercent}% {coverageLabel}
        </Badge>
      </div>

      {/* Coverage Bar */}
      <div className="mb-4">
        <div className="flex items-center justify-between text-sm mb-1">
          <span className="text-slate-600 dark:text-slate-400">Evidence Coverage</span>
          <span className="font-medium text-slate-700 dark:text-slate-300">
            {coveragePercent}%
          </span>
        </div>
        <div className="w-full bg-light-hover dark:bg-dark-hover rounded-full h-2">
          <div
            className={`h-2 rounded-full transition-all ${
              coverageColor === 'green'
                ? 'bg-green-500'
                : coverageColor === 'yellow'
                  ? 'bg-yellow-500'
                  : coverageColor === 'red'
                    ? 'bg-red-500'
                    : 'bg-gray-400'
            }`}
            style={{ width: `${coveragePercent}%` }}
          />
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mb-4">
        <div className="text-center p-2 bg-light-hover dark:bg-dark-hover rounded-lg">
          <div className="flex items-center justify-center gap-1 text-green-600 mb-1">
            <CheckCircle className="h-4 w-4" />
            <span className="font-bold">{summary.active_evidence}</span>
          </div>
          <p className="text-xs text-slate-500">Active</p>
        </div>
        <div className="text-center p-2 bg-light-hover dark:bg-dark-hover rounded-lg">
          <div className="flex items-center justify-center gap-1 text-blue-600 mb-1">
            <FileText className="h-4 w-4" />
            <span className="font-bold">{summary.total_evidence}</span>
          </div>
          <p className="text-xs text-slate-500">Total</p>
        </div>
        <div className="text-center p-2 bg-light-hover dark:bg-dark-hover rounded-lg">
          <div className="flex items-center justify-center gap-1 text-slate-600 mb-1">
            <Clock className="h-4 w-4" />
            <span className="font-bold">{summary.days_since_collection ?? '-'}</span>
          </div>
          <p className="text-xs text-slate-500">Days Since</p>
        </div>
      </div>

      {/* Collection Info */}
      <div className="flex items-center justify-between text-sm pt-3 border-t border-light-border dark:border-dark-border">
        <div className="flex items-center gap-1 text-slate-500">
          <BarChart3 className="h-4 w-4" />
          <span>{summary.is_current ? 'Current' : 'Needs Update'}</span>
        </div>
        {summary.latest_collection && (
          <span className="text-slate-500">
            Last collected: {formatDate(summary.latest_collection)}
          </span>
        )}
      </div>

      {/* View Evidence Button */}
      {onViewEvidence && (
        <button
          onClick={() => onViewEvidence(summary.control_id, summary.framework_id)}
          className="w-full mt-3 px-3 py-2 text-sm text-primary bg-primary/10 hover:bg-primary/20 rounded-lg transition-colors"
        >
          View Evidence
        </button>
      )}
    </div>
  );
};

// Coverage Summary Grid component for displaying multiple controls
interface CoverageSummaryGridProps {
  summaries: ControlEvidenceSummary[];
  onViewEvidence?: (controlId: string, frameworkId: string) => void;
}

export const CoverageSummaryGrid: React.FC<CoverageSummaryGridProps> = ({
  summaries,
  onViewEvidence,
}) => {
  // Group by framework
  const byFramework = summaries.reduce(
    (acc, summary) => {
      if (!acc[summary.framework_id]) {
        acc[summary.framework_id] = [];
      }
      acc[summary.framework_id].push(summary);
      return acc;
    },
    {} as Record<string, ControlEvidenceSummary[]>
  );

  // Calculate framework-level stats
  const frameworkStats = Object.entries(byFramework).map(([frameworkId, controls]) => {
    const avgCoverage =
      controls.reduce((sum, c) => sum + c.coverage_score, 0) / controls.length;
    const totalEvidence = controls.reduce((sum, c) => sum + c.total_evidence, 0);
    const fullyCovered = controls.filter((c) => c.coverage_score >= 0.8).length;
    const partiallyCovered = controls.filter(
      (c) => c.coverage_score >= 0.5 && c.coverage_score < 0.8
    ).length;
    const noCoverage = controls.filter((c) => c.coverage_score === 0).length;

    return {
      frameworkId,
      controls,
      avgCoverage,
      totalEvidence,
      fullyCovered,
      partiallyCovered,
      noCoverage,
    };
  });

  return (
    <div className="space-y-6">
      {frameworkStats.map((framework) => (
        <div key={framework.frameworkId}>
          {/* Framework Header */}
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-primary" />
              <h3 className="font-semibold text-slate-900 dark:text-white">
                {framework.frameworkId}
              </h3>
              <Badge variant="default">{framework.controls.length} controls</Badge>
            </div>
            <div className="flex items-center gap-4 text-sm">
              <span className="text-slate-500">
                Avg Coverage: {Math.round(framework.avgCoverage * 100)}%
              </span>
              <span className="text-green-600">{framework.fullyCovered} strong</span>
              <span className="text-yellow-600">{framework.partiallyCovered} partial</span>
              <span className="text-gray-500">{framework.noCoverage} none</span>
            </div>
          </div>

          {/* Controls Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {framework.controls.map((summary) => (
              <ControlCoverage
                key={`${summary.framework_id}-${summary.control_id}`}
                summary={summary}
                onViewEvidence={onViewEvidence}
                compact
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};

export default ControlCoverage;
