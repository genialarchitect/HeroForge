import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  Check,
  ExternalLink,
  MessageSquare,
  Loader2,
  Shield,
  Target,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { basAPI } from '../../services/api';
import type { DetectionGap } from '../../types';
import Button from '../ui/Button';

interface DetectionGapListProps {
  gaps?: DetectionGap[];
  showFilters?: boolean;
}

const DetectionGapList: React.FC<DetectionGapListProps> = ({
  gaps: providedGaps,
  showFilters = true,
}) => {
  const queryClient = useQueryClient();
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [acknowledgeDialogGap, setAcknowledgeDialogGap] = useState<DetectionGap | null>(null);
  const [acknowledgeNotes, setAcknowledgeNotes] = useState('');

  // Fetch unacknowledged gaps if not provided
  const { data: fetchedGaps, isLoading } = useQuery({
    queryKey: ['bas-unacknowledged-gaps'],
    queryFn: async () => {
      const response = await basAPI.getUnacknowledgedGaps();
      return response.data;
    },
    enabled: !providedGaps,
  });

  // Acknowledge mutation
  const acknowledgeMutation = useMutation({
    mutationFn: async ({ gapId, notes }: { gapId: string; notes?: string }) => {
      const response = await basAPI.acknowledgeGap(gapId, { notes });
      return response.data;
    },
    onSuccess: () => {
      toast.success('Detection gap acknowledged');
      queryClient.invalidateQueries({ queryKey: ['bas-unacknowledged-gaps'] });
      queryClient.invalidateQueries({ queryKey: ['bas-stats'] });
      setAcknowledgeDialogGap(null);
      setAcknowledgeNotes('');
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to acknowledge gap');
    },
  });

  const gaps = providedGaps || fetchedGaps || [];

  // Filter gaps
  const filteredGaps = gaps.filter((gap) => {
    if (severityFilter === 'all') return true;
    const severityMap: Record<string, number[]> = {
      critical: [5],
      high: [4],
      medium: [3],
      low: [1, 2],
    };
    return severityMap[severityFilter]?.includes(gap.severity);
  });

  const getSeverityInfo = (severity: number) => {
    if (severity >= 5)
      return {
        label: 'Critical',
        color: 'bg-red-500/20 text-red-400 border-red-500/30',
        icon: 'text-red-400',
      };
    if (severity >= 4)
      return {
        label: 'High',
        color: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
        icon: 'text-orange-400',
      };
    if (severity >= 3)
      return {
        label: 'Medium',
        color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
        icon: 'text-yellow-400',
      };
    return {
      label: 'Low',
      color: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      icon: 'text-blue-400',
    };
  };

  const getMitreUrl = (techniqueId: string) => {
    // Format: T1234 or T1234.001
    const formatted = techniqueId.replace('.', '/');
    return `https://attack.mitre.org/techniques/${formatted}/`;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 text-primary animate-spin" />
      </div>
    );
  }

  if (gaps.length === 0) {
    return (
      <div className="text-center py-12 bg-light-surface dark:bg-dark-surface rounded-lg border border-light-border dark:border-dark-border">
        <Shield className="w-12 h-12 text-green-400 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
          No Detection Gaps
        </h3>
        <p className="text-gray-500 dark:text-gray-400">
          All tested techniques were detected by your security controls.
        </p>
      </div>
    );
  }

  return (
    <div>
      {/* Filters */}
      {showFilters && (
        <div className="mb-4 flex items-center gap-4">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-transparent"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <span className="text-sm text-gray-500 dark:text-gray-400">
            Showing {filteredGaps.length} of {gaps.length} gaps
          </span>
        </div>
      )}

      {/* Gap List */}
      <div className="space-y-4">
        {filteredGaps.map((gap) => {
          const severityInfo = getSeverityInfo(gap.severity);
          return (
            <div
              key={gap.id}
              className={`bg-light-surface dark:bg-dark-surface border rounded-lg p-4 ${
                gap.acknowledged
                  ? 'border-green-500/30'
                  : 'border-light-border dark:border-dark-border'
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <AlertTriangle className={`w-5 h-5 ${severityInfo.icon}`} />
                    <span className="font-mono text-sm text-gray-500 dark:text-gray-400">
                      {gap.technique_id}
                    </span>
                    <span
                      className={`text-xs px-2 py-0.5 rounded border ${severityInfo.color}`}
                    >
                      {severityInfo.label}
                    </span>
                    {gap.acknowledged && (
                      <span className="text-xs px-2 py-0.5 bg-green-500/20 text-green-400 rounded flex items-center gap-1">
                        <Check className="w-3 h-3" />
                        Acknowledged
                      </span>
                    )}
                  </div>

                  <h4 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                    {gap.technique_name}
                  </h4>

                  <div className="flex flex-wrap gap-1 mb-3">
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
                    <p className="text-sm text-gray-600 dark:text-gray-300 mb-3">
                      {gap.reason}
                    </p>
                  )}

                  {gap.recommendations.length > 0 && (
                    <div className="mt-3 p-3 bg-light-bg dark:bg-dark-bg rounded-lg">
                      <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2 flex items-center gap-2">
                        <Target className="w-4 h-4" />
                        Recommendations
                      </p>
                      <ul className="space-y-1">
                        {gap.recommendations.map((rec, i) => (
                          <li
                            key={i}
                            className="text-sm text-gray-600 dark:text-gray-300 flex items-start gap-2"
                          >
                            <span className="text-primary mt-1">-</span>
                            {rec}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-2 ml-4">
                  <a
                    href={getMitreUrl(gap.technique_id)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 text-gray-400 hover:text-primary transition-colors"
                    title="View on MITRE ATT&CK"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </a>
                  {!gap.acknowledged && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setAcknowledgeDialogGap(gap)}
                    >
                      <Check className="w-4 h-4 mr-1" />
                      Acknowledge
                    </Button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Acknowledge Dialog */}
      {acknowledgeDialogGap && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-light-surface dark:bg-dark-surface rounded-lg shadow-xl max-w-md w-full mx-4">
            <div className="p-4 border-b border-light-border dark:border-dark-border">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Acknowledge Detection Gap
              </h3>
            </div>
            <div className="p-4">
              <div className="mb-4">
                <p className="text-sm text-gray-600 dark:text-gray-300 mb-2">
                  Acknowledging this gap indicates you have reviewed it and have a plan to
                  address the detection coverage.
                </p>
                <div className="flex items-center gap-2 p-3 bg-light-bg dark:bg-dark-bg rounded-lg">
                  <span className="font-mono text-sm text-gray-500 dark:text-gray-400">
                    {acknowledgeDialogGap.technique_id}
                  </span>
                  <span className="text-gray-900 dark:text-white font-medium">
                    {acknowledgeDialogGap.technique_name}
                  </span>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  <div className="flex items-center gap-2">
                    <MessageSquare className="w-4 h-4" />
                    Notes (optional)
                  </div>
                </label>
                <textarea
                  value={acknowledgeNotes}
                  onChange={(e) => setAcknowledgeNotes(e.target.value)}
                  placeholder="e.g., Tracking in JIRA-1234, remediation planned for Q2"
                  rows={3}
                  className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-gray-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                />
              </div>
            </div>
            <div className="p-4 border-t border-light-border dark:border-dark-border flex justify-end gap-3">
              <Button
                variant="outline"
                onClick={() => {
                  setAcknowledgeDialogGap(null);
                  setAcknowledgeNotes('');
                }}
              >
                Cancel
              </Button>
              <Button
                onClick={() =>
                  acknowledgeMutation.mutate({
                    gapId: acknowledgeDialogGap.id,
                    notes: acknowledgeNotes || undefined,
                  })
                }
                disabled={acknowledgeMutation.isPending}
              >
                {acknowledgeMutation.isPending ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Check className="w-4 h-4 mr-2" />
                )}
                Acknowledge
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DetectionGapList;
