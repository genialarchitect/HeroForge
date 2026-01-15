import React, { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Brain,
  Target,
  Shield,
  Clock,
  ChevronRight,
  ChevronDown,
  Check,
  X,
  Play,
  Loader2,
  AlertTriangle,
  Crosshair,
  Sparkles,
  CheckCircle,
  XCircle,
  Terminal,
  Info,
} from 'lucide-react';
import { redTeamAdvisorAPI } from '../../services/api';
import type {
  AiRedTeamRecommendation,
  TopologyForAnalysis,
  RecommendationRiskLevel,
  RecommendationStatus,
} from '../../types';
import Button from '../ui/Button';

interface RedTeamAdvisorPanelProps {
  topology: TopologyForAnalysis;
  topologyId?: string;
  scanId?: string;
  engagementId?: string;
  onClose?: () => void;
}

const riskLevelColors: Record<RecommendationRiskLevel, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500',
  low: 'bg-green-500/20 text-green-400 border-green-500',
  info: 'bg-blue-500/20 text-blue-400 border-blue-500',
};

const statusColors: Record<RecommendationStatus, string> = {
  pending: 'bg-gray-500/20 text-gray-400',
  accepted: 'bg-green-500/20 text-green-400',
  rejected: 'bg-red-500/20 text-red-400',
  running: 'bg-blue-500/20 text-blue-400',
  completed: 'bg-emerald-500/20 text-emerald-400',
  failed: 'bg-red-500/20 text-red-400',
};

// Custom icons not in lucide-react
const ChevronUpIcon = ({ className }: { className?: string }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M18 15l-6-6-6 6" />
  </svg>
);
const KeyIcon = ({ className }: { className?: string }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
  </svg>
);
const SearchIcon = ({ className }: { className?: string }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
  </svg>
);
const DatabaseIcon = ({ className }: { className?: string }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" /><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
  </svg>
);
const UploadIcon = ({ className }: { className?: string }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="17 8 12 3 7 8" /><line x1="12" y1="3" x2="12" y2="15" />
  </svg>
);

const categoryIcons: Record<string, React.FC<{ className?: string }>> = {
  reconnaissance: Target,
  initial_access: Crosshair,
  execution: Play,
  persistence: Shield,
  privilege_escalation: ChevronUpIcon,
  defense_evasion: Shield,
  credential_access: KeyIcon,
  discovery: SearchIcon,
  lateral_movement: ChevronRight,
  collection: DatabaseIcon,
  exfiltration: UploadIcon,
  impact: AlertTriangle,
};

const RedTeamAdvisorPanel: React.FC<RedTeamAdvisorPanelProps> = ({
  topology,
  topologyId,
  scanId,
  engagementId,
  onClose,
}) => {
  const queryClient = useQueryClient();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [hasAnalyzed, setHasAnalyzed] = useState(false);

  // Fetch existing recommendations
  const { data: recommendations, isLoading, refetch } = useQuery({
    queryKey: ['red-team-recommendations', topologyId, scanId],
    queryFn: () => redTeamAdvisorAPI.getRecommendations({
      topology_id: topologyId,
      scan_id: scanId,
    }).then(res => res.data),
    enabled: hasAnalyzed,
  });

  // Fetch summary
  const { data: summary } = useQuery({
    queryKey: ['red-team-summary', topologyId, scanId],
    queryFn: () => redTeamAdvisorAPI.getSummary({
      topology_id: topologyId,
      scan_id: scanId,
    }).then(res => res.data),
    enabled: hasAnalyzed && !!recommendations?.length,
  });

  // Analyze topology mutation
  const analyzeMutation = useMutation({
    mutationFn: () => redTeamAdvisorAPI.analyzeTopology({
      topology,
      topology_id: topologyId,
      scan_id: scanId,
      engagement_id: engagementId,
      max_recommendations: 20,
    }),
    onSuccess: (response) => {
      setHasAnalyzed(true);
      toast.success(`Generated ${response.data.recommendations.length} recommendations`);
      queryClient.invalidateQueries({ queryKey: ['red-team-recommendations'] });
      queryClient.invalidateQueries({ queryKey: ['red-team-summary'] });
    },
    onError: (error: Error) => {
      toast.error(`Analysis failed: ${error.message}`);
    },
  });

  // Update status mutation
  const updateStatusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: RecommendationStatus }) =>
      redTeamAdvisorAPI.updateStatus(id, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['red-team-recommendations'] });
      queryClient.invalidateQueries({ queryKey: ['red-team-summary'] });
    },
    onError: (error: Error) => {
      toast.error(`Failed to update: ${error.message}`);
    },
  });

  // Accept all mutation
  const acceptAllMutation = useMutation({
    mutationFn: () => redTeamAdvisorAPI.acceptAll(topologyId),
    onSuccess: (response) => {
      toast.success(response.data.message);
      queryClient.invalidateQueries({ queryKey: ['red-team-recommendations'] });
      queryClient.invalidateQueries({ queryKey: ['red-team-summary'] });
    },
    onError: (error: Error) => {
      toast.error(`Failed: ${error.message}`);
    },
  });

  // Reject all mutation
  const rejectAllMutation = useMutation({
    mutationFn: () => redTeamAdvisorAPI.rejectAll(topologyId),
    onSuccess: (response) => {
      toast.success(response.data.message);
      queryClient.invalidateQueries({ queryKey: ['red-team-recommendations'] });
      queryClient.invalidateQueries({ queryKey: ['red-team-summary'] });
    },
    onError: (error: Error) => {
      toast.error(`Failed: ${error.message}`);
    },
  });

  const handleAnalyze = useCallback(() => {
    setIsAnalyzing(true);
    analyzeMutation.mutate();
  }, [analyzeMutation]);

  const handleAccept = useCallback((id: string) => {
    updateStatusMutation.mutate({ id, status: 'accepted' });
  }, [updateStatusMutation]);

  const handleReject = useCallback((id: string) => {
    updateStatusMutation.mutate({ id, status: 'rejected' });
  }, [updateStatusMutation]);

  const toggleExpand = useCallback((id: string) => {
    setExpandedId(prev => prev === id ? null : id);
  }, []);

  const pendingCount = recommendations?.filter(r => r.status === 'pending').length ?? 0;

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 shadow-xl overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 bg-gradient-to-r from-cyan-600/20 to-purple-600/20 border-b border-gray-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/20 rounded-lg">
              <Brain className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white">AI Red Team Advisor</h3>
              <p className="text-xs text-gray-400">Powered by Claude AI</p>
            </div>
          </div>
          {onClose && (
            <button onClick={onClose} className="p-1 hover:bg-gray-700 rounded">
              <X className="w-5 h-5 text-gray-400" />
            </button>
          )}
        </div>
      </div>

      {/* Content */}
      <div className="p-4">
        {!hasAnalyzed ? (
          /* Initial State - Show Analyze Button */
          <div className="text-center py-8">
            <Sparkles className="w-12 h-12 text-cyan-400 mx-auto mb-4" />
            <h4 className="text-lg font-medium text-white mb-2">
              Analyze Network Topology
            </h4>
            <p className="text-sm text-gray-400 mb-6 max-w-md mx-auto">
              Let AI analyze your network topology and generate targeted red team
              recommendations based on detected devices, services, and security zones.
            </p>
            <Button
              onClick={handleAnalyze}
              disabled={analyzeMutation.isPending}
              className="bg-gradient-to-r from-cyan-600 to-purple-600 hover:from-cyan-500 hover:to-purple-500"
            >
              {analyzeMutation.isPending ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Brain className="w-4 h-4 mr-2" />
                  Generate Recommendations
                </>
              )}
            </Button>
            <p className="text-xs text-gray-500 mt-4">
              {topology.nodes.length} nodes, {topology.edges.length} connections
            </p>
          </div>
        ) : isLoading ? (
          /* Loading State */
          <div className="text-center py-8">
            <Loader2 className="w-8 h-8 text-cyan-400 mx-auto mb-4 animate-spin" />
            <p className="text-gray-400">Loading recommendations...</p>
          </div>
        ) : (
          /* Recommendations List */
          <div>
            {/* Summary Bar */}
            {summary && (
              <div className="flex items-center justify-between mb-4 p-3 bg-gray-900/50 rounded-lg">
                <div className="flex items-center gap-4 text-sm">
                  <span className="text-gray-400">
                    <span className="text-white font-medium">{summary.total}</span> total
                  </span>
                  <span className="text-yellow-400">
                    <span className="font-medium">{summary.pending}</span> pending
                  </span>
                  <span className="text-green-400">
                    <span className="font-medium">{summary.accepted}</span> accepted
                  </span>
                  <span className="text-red-400">
                    <span className="font-medium">{summary.rejected}</span> rejected
                  </span>
                </div>
                {pendingCount > 0 && (
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => acceptAllMutation.mutate()}
                      disabled={acceptAllMutation.isPending}
                      className="text-green-400 border-green-500 hover:bg-green-500/20"
                    >
                      <Check className="w-3 h-3 mr-1" />
                      Accept All
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => rejectAllMutation.mutate()}
                      disabled={rejectAllMutation.isPending}
                      className="text-red-400 border-red-500 hover:bg-red-500/20"
                    >
                      <X className="w-3 h-3 mr-1" />
                      Reject All
                    </Button>
                  </div>
                )}
              </div>
            )}

            {/* Recommendations */}
            <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
              {recommendations?.map((rec) => (
                <RecommendationCard
                  key={rec.id}
                  recommendation={rec}
                  expanded={expandedId === rec.id}
                  onToggle={() => toggleExpand(rec.id)}
                  onAccept={() => handleAccept(rec.id)}
                  onReject={() => handleReject(rec.id)}
                  isUpdating={updateStatusMutation.isPending}
                />
              ))}
            </div>

            {/* Re-analyze Button */}
            <div className="mt-4 pt-4 border-t border-gray-700">
              <Button
                size="sm"
                variant="outline"
                onClick={handleAnalyze}
                disabled={analyzeMutation.isPending}
                className="w-full"
              >
                {analyzeMutation.isPending ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Brain className="w-4 h-4 mr-2" />
                    Re-analyze Topology
                  </>
                )}
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

interface RecommendationCardProps {
  recommendation: AiRedTeamRecommendation;
  expanded: boolean;
  onToggle: () => void;
  onAccept: () => void;
  onReject: () => void;
  isUpdating: boolean;
}

const RecommendationCard: React.FC<RecommendationCardProps> = ({
  recommendation,
  expanded,
  onToggle,
  onAccept,
  onReject,
  isUpdating,
}) => {
  const CategoryIcon = categoryIcons[recommendation.action_category] || Target;
  const isPending = recommendation.status === 'pending';

  return (
    <div className={`rounded-lg border transition-all ${
      expanded ? 'bg-gray-900/70 border-cyan-500/50' : 'bg-gray-900/30 border-gray-700 hover:border-gray-600'
    }`}>
      {/* Header */}
      <div
        className="flex items-center gap-3 p-3 cursor-pointer"
        onClick={onToggle}
      >
        <div className={`p-2 rounded-lg ${riskLevelColors[recommendation.risk_level as RecommendationRiskLevel]}`}>
          <CategoryIcon className="w-4 h-4" />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-white truncate">{recommendation.title}</span>
            <span className={`px-2 py-0.5 rounded text-xs ${statusColors[recommendation.status as RecommendationStatus]}`}>
              {recommendation.status}
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs text-gray-400 mt-0.5">
            <span>{recommendation.target_ip || recommendation.target_hostname || recommendation.target_node_id}</span>
            {recommendation.mitre_technique_id && (
              <>
                <span className="text-gray-600">|</span>
                <span className="text-cyan-400">{recommendation.mitre_technique_id}</span>
              </>
            )}
            {recommendation.estimated_time_minutes && (
              <>
                <span className="text-gray-600">|</span>
                <Clock className="w-3 h-3" />
                <span>{recommendation.estimated_time_minutes}m</span>
              </>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className={`px-2 py-1 rounded text-xs border ${riskLevelColors[recommendation.risk_level as RecommendationRiskLevel]}`}>
            {recommendation.risk_level}
          </span>
          {expanded ? (
            <ChevronDown className="w-4 h-4 text-gray-400" />
          ) : (
            <ChevronRight className="w-4 h-4 text-gray-400" />
          )}
        </div>
      </div>

      {/* Expanded Content */}
      {expanded && (
        <div className="px-3 pb-3 border-t border-gray-700/50">
          <div className="pt-3 space-y-3">
            {/* Description */}
            <div>
              <h5 className="text-xs font-medium text-gray-400 mb-1">Description</h5>
              <p className="text-sm text-gray-300">{recommendation.description}</p>
            </div>

            {/* Rationale */}
            {recommendation.rationale && (
              <div>
                <h5 className="text-xs font-medium text-gray-400 mb-1">Rationale</h5>
                <p className="text-sm text-gray-300">{recommendation.rationale}</p>
              </div>
            )}

            {/* MITRE ATT&CK */}
            {recommendation.mitre_technique_name && (
              <div className="flex items-center gap-2 text-sm">
                <span className="text-gray-400">MITRE ATT&CK:</span>
                <span className="text-cyan-400">{recommendation.mitre_technique_id}</span>
                <span className="text-gray-300">- {recommendation.mitre_technique_name}</span>
                {recommendation.mitre_tactic && (
                  <span className="text-gray-500">({recommendation.mitre_tactic})</span>
                )}
              </div>
            )}

            {/* Command Template */}
            {recommendation.command_template && (
              <div>
                <h5 className="text-xs font-medium text-gray-400 mb-1 flex items-center gap-1">
                  <Terminal className="w-3 h-3" />
                  Command Template
                </h5>
                <code className="block text-xs bg-gray-800 text-green-400 p-2 rounded font-mono overflow-x-auto">
                  {recommendation.command_template}
                </code>
              </div>
            )}

            {/* Tool */}
            {recommendation.tool_name && (
              <div className="flex items-center gap-2 text-sm">
                <span className="text-gray-400">Tool:</span>
                <span className="px-2 py-0.5 bg-gray-800 text-gray-300 rounded text-xs">
                  {recommendation.tool_name}
                </span>
              </div>
            )}

            {/* Action Buttons */}
            {isPending && (
              <div className="flex items-center gap-2 pt-2 border-t border-gray-700/50">
                <Button
                  size="sm"
                  onClick={(e) => {
                    e.stopPropagation();
                    onAccept();
                  }}
                  disabled={isUpdating}
                  className="flex-1 bg-green-600 hover:bg-green-500"
                >
                  <CheckCircle className="w-4 h-4 mr-1" />
                  Accept
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={(e) => {
                    e.stopPropagation();
                    onReject();
                  }}
                  disabled={isUpdating}
                  className="flex-1 text-red-400 border-red-500 hover:bg-red-500/20"
                >
                  <XCircle className="w-4 h-4 mr-1" />
                  Reject
                </Button>
              </div>
            )}

            {/* Status indicator for non-pending */}
            {!isPending && (
              <div className="flex items-center gap-2 pt-2 border-t border-gray-700/50">
                {recommendation.status === 'accepted' && (
                  <div className="flex items-center gap-2 text-green-400 text-sm">
                    <CheckCircle className="w-4 h-4" />
                    Accepted {recommendation.accepted_at && `on ${new Date(recommendation.accepted_at).toLocaleDateString()}`}
                  </div>
                )}
                {recommendation.status === 'rejected' && (
                  <div className="flex items-center gap-2 text-red-400 text-sm">
                    <XCircle className="w-4 h-4" />
                    Rejected {recommendation.rejected_at && `on ${new Date(recommendation.rejected_at).toLocaleDateString()}`}
                  </div>
                )}
                {recommendation.status === 'completed' && (
                  <div className="flex items-center gap-2 text-emerald-400 text-sm">
                    <CheckCircle className="w-4 h-4" />
                    Completed
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default RedTeamAdvisorPanel;
