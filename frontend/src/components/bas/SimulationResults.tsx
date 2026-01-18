import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowLeft,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Target,
  Activity,
  Loader2,
  SkipForward,
  Eye,
  EyeOff,
} from 'lucide-react';
import { basAPI } from '../../services/api';
import type { TechniqueExecution } from '../../types';
import Button from '../ui/Button';

interface SimulationResultsProps {
  simulationId: string;
  onBack: () => void;
}

const SimulationResults: React.FC<SimulationResultsProps> = ({
  simulationId,
  onBack,
}) => {
  const { data: simulation, isLoading } = useQuery({
    queryKey: ['bas-simulation', simulationId],
    queryFn: async () => {
      const response = await basAPI.getSimulation(simulationId);
      return response.data;
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-8 h-8 text-primary animate-spin" />
      </div>
    );
  }

  if (!simulation) {
    return (
      <div className="text-center py-12 text-gray-500 dark:text-gray-400">
        Simulation not found
      </div>
    );
  }

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-400" />;
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-400" />;
      case 'running':
        return <Activity className="w-5 h-5 text-cyan-400 animate-pulse" />;
      default:
        return <Clock className="w-5 h-5 text-yellow-400" />;
    }
  };

  const getExecutionStatusIcon = (execution: TechniqueExecution) => {
    if (execution.error) {
      return <XCircle className="w-4 h-4 text-red-400" />;
    }
    if (execution.detection_observed) {
      return <Eye className="w-4 h-4 text-green-400" />;
    }
    if (execution.status === 'skipped') {
      return <SkipForward className="w-4 h-4 text-gray-400" />;
    }
    return <EyeOff className="w-4 h-4 text-yellow-400" />;
  };

  const getScoreColor = (score: number): string => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    if (score >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  const getScoreBgColor = (score: number): string => {
    if (score >= 80) return 'bg-green-500/20 border-green-500/30';
    if (score >= 60) return 'bg-yellow-500/20 border-yellow-500/30';
    if (score >= 40) return 'bg-orange-500/20 border-orange-500/30';
    return 'bg-red-500/20 border-red-500/30';
  };

  const formatDuration = (ms?: number): string => {
    if (!ms) return '--';
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="outline" size="sm" onClick={onBack}>
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back
          </Button>
          <div>
            <div className="flex items-center gap-2">
              {getStatusIcon(simulation.status)}
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                Simulation Results
              </h2>
            </div>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              {simulation.execution_mode.replace('_', ' ').toUpperCase()} mode |{' '}
              Started: {new Date(simulation.started_at).toLocaleString()}
            </p>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Security Score */}
        <div
          className={`p-4 rounded-lg border ${getScoreBgColor(simulation.summary.security_score)}`}
        >
          <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 mb-2">
            <Shield className="w-4 h-4" />
            <span className="text-sm font-medium">Security Score</span>
          </div>
          <div className={`text-3xl font-bold ${getScoreColor(simulation.summary.security_score)}`}>
            {simulation.summary.security_score}%
          </div>
        </div>

        {/* Detection Rate */}
        <div className="p-4 rounded-lg border bg-light-surface dark:bg-dark-surface border-light-border dark:border-dark-border">
          <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 mb-2">
            <Eye className="w-4 h-4" />
            <span className="text-sm font-medium">Detection Rate</span>
          </div>
          <div className="text-3xl font-bold text-gray-900 dark:text-white">
            {(simulation.summary.detection_rate * 100).toFixed(0)}%
          </div>
        </div>

        {/* Techniques Tested */}
        <div className="p-4 rounded-lg border bg-light-surface dark:bg-dark-surface border-light-border dark:border-dark-border">
          <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 mb-2">
            <Target className="w-4 h-4" />
            <span className="text-sm font-medium">Techniques Tested</span>
          </div>
          <div className="text-3xl font-bold text-gray-900 dark:text-white">
            {simulation.summary.total_techniques}
          </div>
        </div>

        {/* Detection Gaps */}
        <div className="p-4 rounded-lg border bg-light-surface dark:bg-dark-surface border-light-border dark:border-dark-border">
          <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 mb-2">
            <AlertTriangle className="w-4 h-4" />
            <span className="text-sm font-medium">Detection Gaps</span>
          </div>
          <div className={`text-3xl font-bold ${simulation.detection_gaps.length > 0 ? 'text-red-400' : 'text-green-400'}`}>
            {simulation.detection_gaps.length}
          </div>
        </div>
      </div>

      {/* Execution Breakdown */}
      <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
        <h3 className="font-medium text-gray-900 dark:text-white mb-4">
          Execution Breakdown
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <StatItem
            label="Succeeded"
            value={simulation.summary.succeeded}
            color="text-green-400"
          />
          <StatItem
            label="Detected"
            value={simulation.summary.detected}
            color="text-cyan-400"
          />
          <StatItem
            label="Blocked"
            value={simulation.summary.blocked}
            color="text-blue-400"
          />
          <StatItem
            label="Failed"
            value={simulation.summary.failed}
            color="text-red-400"
          />
          <StatItem
            label="Skipped"
            value={simulation.summary.skipped}
            color="text-gray-400"
          />
        </div>
      </div>

      {/* Detection Gaps */}
      {simulation.detection_gaps.length > 0 && (
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
          <div className="p-4 border-b border-light-border dark:border-dark-border">
            <h3 className="font-medium text-gray-900 dark:text-white flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
              Detection Gaps ({simulation.detection_gaps.length})
            </h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              These techniques were not detected by your security controls
            </p>
          </div>
          <div className="divide-y divide-light-border dark:divide-dark-border">
            {simulation.detection_gaps.map((gap) => (
              <div key={gap.id} className="p-4">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-xs text-gray-500 dark:text-gray-400">
                        {gap.technique_id}
                      </span>
                      <SeverityBadge severity={gap.severity} />
                    </div>
                    <h4 className="font-medium text-gray-900 dark:text-white">
                      {gap.technique_name}
                    </h4>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {gap.tactics.map((tactic) => (
                        <span
                          key={tactic}
                          className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 rounded"
                        >
                          {tactic}
                        </span>
                      ))}
                    </div>
                    {gap.reason && (
                      <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
                        {gap.reason}
                      </p>
                    )}
                    {gap.recommendations.length > 0 && (
                      <div className="mt-3">
                        <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                          Recommendations:
                        </p>
                        <ul className="list-disc list-inside text-sm text-gray-600 dark:text-gray-300">
                          {gap.recommendations.map((rec, i) => (
                            <li key={i}>{rec}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                  <div>
                    {gap.acknowledged ? (
                      <span className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded">
                        Acknowledged
                      </span>
                    ) : (
                      <span className="text-xs px-2 py-1 bg-yellow-500/20 text-yellow-400 rounded">
                        Pending Review
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Technique Executions */}
      <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
        <div className="p-4 border-b border-light-border dark:border-dark-border">
          <h3 className="font-medium text-gray-900 dark:text-white">
            Technique Execution Log
          </h3>
        </div>
        <div className="divide-y divide-light-border dark:divide-dark-border">
          {simulation.executions.map((execution) => (
            <div key={execution.id} className="p-4 flex items-center gap-4">
              {getExecutionStatusIcon(execution)}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-gray-500 dark:text-gray-400">
                    {execution.technique_id}
                  </span>
                  <span
                    className={`text-xs px-2 py-0.5 rounded ${
                      execution.detection_observed
                        ? 'bg-green-500/20 text-green-400'
                        : 'bg-yellow-500/20 text-yellow-400'
                    }`}
                  >
                    {execution.detection_observed ? 'Detected' : 'Not Detected'}
                  </span>
                </div>
                {execution.detection_details && (
                  <p className="text-sm text-gray-500 dark:text-gray-400 truncate mt-1">
                    {execution.detection_details}
                  </p>
                )}
                {execution.error && (
                  <p className="text-sm text-red-400 truncate mt-1">{execution.error}</p>
                )}
              </div>
              <div className="text-right">
                <span className="text-sm text-gray-400">
                  {formatDuration(execution.duration_ms)}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Error Display */}
      {simulation.error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <div className="flex items-center gap-2 text-red-400 mb-2">
            <XCircle className="w-5 h-5" />
            <span className="font-medium">Simulation Error</span>
          </div>
          <p className="text-sm text-red-300">{simulation.error}</p>
        </div>
      )}
    </div>
  );
};

const StatItem: React.FC<{ label: string; value: number; color: string }> = ({
  label,
  value,
  color,
}) => (
  <div className="text-center">
    <div className={`text-2xl font-bold ${color}`}>{value}</div>
    <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">{label}</div>
  </div>
);

const SeverityBadge: React.FC<{ severity: number }> = ({ severity }) => {
  const getSeverityInfo = (sev: number) => {
    if (sev >= 5) return { label: 'Critical', color: 'bg-red-500/20 text-red-400' };
    if (sev >= 4) return { label: 'High', color: 'bg-orange-500/20 text-orange-400' };
    if (sev >= 3) return { label: 'Medium', color: 'bg-yellow-500/20 text-yellow-400' };
    return { label: 'Low', color: 'bg-blue-500/20 text-blue-400' };
  };

  const info = getSeverityInfo(severity);
  return (
    <span className={`text-xs px-2 py-0.5 rounded ${info.color}`}>{info.label}</span>
  );
};

export default SimulationResults;
