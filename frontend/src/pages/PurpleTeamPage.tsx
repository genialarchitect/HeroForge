import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Shield,
  Play,
  Square,
  Plus,
  ChevronRight,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Target,
  Activity,
  TrendingUp,
  Eye,
  Copy,
  RefreshCw,
  Search,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import { purpleTeamAPI } from '../services/api';
import type {
  PurpleTeamExercise,
  PurpleTeamDashboard,
  PurpleAttackResult,
  DetectionCoverage,
  PurpleDetectionGap,
  AttackMatrix,
  CreateExerciseRequest,
  ExerciseStatus,
  PurpleDetectionStatus,
  GapSeverity,
  MatrixCell,
} from '../types';

// Tactic display order following MITRE ATT&CK
const TACTIC_ORDER = [
  'Reconnaissance',
  'ResourceDevelopment',
  'InitialAccess',
  'Execution',
  'Persistence',
  'PrivilegeEscalation',
  'DefenseEvasion',
  'CredentialAccess',
  'Discovery',
  'LateralMovement',
  'Collection',
  'CommandAndControl',
  'Exfiltration',
  'Impact',
];

const TACTIC_LABELS: Record<string, string> = {
  Reconnaissance: 'Reconnaissance',
  ResourceDevelopment: 'Resource Dev',
  InitialAccess: 'Initial Access',
  Execution: 'Execution',
  Persistence: 'Persistence',
  PrivilegeEscalation: 'Priv Escalation',
  DefenseEvasion: 'Defense Evasion',
  CredentialAccess: 'Cred Access',
  Discovery: 'Discovery',
  LateralMovement: 'Lateral Move',
  Collection: 'Collection',
  CommandAndControl: 'C2',
  Exfiltration: 'Exfiltration',
  Impact: 'Impact',
};

function StatusBadge({ status }: { status: ExerciseStatus }) {
  const styles: Record<ExerciseStatus, string> = {
    pending: 'bg-gray-700 text-gray-300',
    running: 'bg-cyan-900 text-cyan-300',
    completed: 'bg-green-900 text-green-300',
    failed: 'bg-red-900 text-red-300',
    cancelled: 'bg-yellow-900 text-yellow-300',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${styles[status]}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

function DetectionBadge({ status }: { status: PurpleDetectionStatus }) {
  const config: Record<PurpleDetectionStatus, { color: string; icon: React.ReactNode; label: string }> = {
    detected: { color: 'bg-green-900 text-green-300', icon: <CheckCircle className="h-3 w-3" />, label: 'Detected' },
    partially_detected: { color: 'bg-yellow-900 text-yellow-300', icon: <AlertTriangle className="h-3 w-3" />, label: 'Partial' },
    not_detected: { color: 'bg-red-900 text-red-300', icon: <XCircle className="h-3 w-3" />, label: 'Not Detected' },
    pending: { color: 'bg-gray-700 text-gray-300', icon: <Clock className="h-3 w-3" />, label: 'Pending' },
  };
  const { color, icon, label } = config[status];
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium flex items-center gap-1 ${color}`}>
      {icon} {label}
    </span>
  );
}

function SeverityBadge({ severity }: { severity: GapSeverity }) {
  const styles: Record<GapSeverity, string> = {
    critical: 'bg-red-900 text-red-300',
    high: 'bg-orange-900 text-orange-300',
    medium: 'bg-yellow-900 text-yellow-300',
    low: 'bg-blue-900 text-blue-300',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${styles[severity]}`}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}

function DashboardStats({ dashboard, onExercisesClick, onGapsClick }: {
  dashboard: PurpleTeamDashboard;
  onExercisesClick?: () => void;
  onGapsClick?: () => void;
}) {
  const stats = [
    { label: 'Total Exercises', value: dashboard.total_exercises, icon: <Target className="h-5 w-5" />, onClick: onExercisesClick },
    { label: 'Running', value: dashboard.running_exercises, icon: <Activity className="h-5 w-5 text-cyan-400" />, onClick: onExercisesClick },
    { label: 'Overall Coverage', value: `${dashboard.overall_coverage.toFixed(1)}%`, icon: <TrendingUp className="h-5 w-5 text-green-400" />, onClick: undefined },
    { label: 'Open Gaps', value: dashboard.open_gaps, icon: <AlertTriangle className="h-5 w-5 text-red-400" />, onClick: onGapsClick },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
      {stats.map((stat) => (
        <div
          key={stat.label}
          onClick={stat.onClick}
          className={`bg-gray-800 rounded-lg p-4 flex items-center gap-4 ${stat.onClick ? 'cursor-pointer hover:border hover:border-cyan-500/50 hover:bg-gray-750 transition-all group' : 'border border-transparent'}`}
        >
          <div className="p-3 bg-gray-700 rounded-lg">{stat.icon}</div>
          <div className="flex-1">
            <p className="text-gray-400 text-sm">{stat.label}</p>
            <p className="text-2xl font-bold text-white">{stat.value}</p>
          </div>
          {stat.onClick && <ChevronRight className="w-5 h-5 text-gray-500 group-hover:text-cyan-400 transition-colors" />}
        </div>
      ))}
    </div>
  );
}

function CoverageHeatmap({ coverage }: { coverage: DetectionCoverage }) {
  if (!coverage || !coverage.by_tactic) return null;

  return (
    <div className="bg-gray-800 rounded-lg p-4">
      <h3 className="text-lg font-semibold text-white mb-4">Detection Coverage by Tactic</h3>
      <div className="space-y-2">
        {Object.entries(coverage.by_tactic).map(([tactic, data]) => {
          const percent = data.coverage_percent;
          let barColor = 'bg-red-500';
          if (percent >= 75) barColor = 'bg-green-500';
          else if (percent >= 50) barColor = 'bg-yellow-500';
          else if (percent >= 25) barColor = 'bg-orange-500';

          return (
            <div key={tactic} className="flex items-center gap-3">
              <div className="w-32 text-sm text-gray-400 truncate" title={data.tactic_name}>
                {data.tactic_name}
              </div>
              <div className="flex-1 h-6 bg-gray-700 rounded overflow-hidden">
                <div
                  className={`h-full ${barColor} transition-all duration-300`}
                  style={{ width: `${percent}%` }}
                />
              </div>
              <div className="w-16 text-right text-sm font-medium text-white">
                {percent.toFixed(0)}%
              </div>
              <div className="w-24 text-xs text-gray-500">
                {data.detected}/{data.total_techniques}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function AttackMatrixView({ matrix }: { matrix: AttackMatrix }) {
  const [hoveredTechnique, setHoveredTechnique] = useState<string | null>(null);

  if (!matrix || !matrix.cells) return null;

  const getCellColor = (cell: MatrixCell) => {
    if (!cell.tested) return 'bg-gray-700 hover:bg-gray-600';
    switch (cell.detection_status) {
      case 'detected': return 'bg-green-700 hover:bg-green-600';
      case 'partially_detected': return 'bg-yellow-700 hover:bg-yellow-600';
      case 'not_detected': return 'bg-red-700 hover:bg-red-600';
      default: return 'bg-gray-700 hover:bg-gray-600';
    }
  };

  return (
    <div className="bg-gray-800 rounded-lg p-4 overflow-x-auto">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-semibold text-white">MITRE ATT&CK Matrix</h3>
        <div className="flex gap-4 text-xs">
          <span className="flex items-center gap-1"><span className="w-3 h-3 bg-green-700 rounded" /> Detected</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 bg-yellow-700 rounded" /> Partial</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 bg-red-700 rounded" /> Not Detected</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 bg-gray-700 rounded" /> Not Tested</span>
        </div>
      </div>
      <div className="flex gap-1 min-w-max">
        {TACTIC_ORDER.map((tactic) => {
          const cells = matrix.cells[tactic] || [];
          return (
            <div key={tactic} className="flex-shrink-0 w-24">
              <div className="text-xs font-medium text-gray-400 text-center mb-2 truncate" title={tactic}>
                {TACTIC_LABELS[tactic] || tactic}
              </div>
              <div className="space-y-1">
                {cells.slice(0, 15).map((cell) => (
                  <div
                    key={cell.technique_id}
                    className={`p-1 rounded text-xs cursor-pointer transition-colors ${getCellColor(cell)}`}
                    onMouseEnter={() => setHoveredTechnique(cell.technique_id)}
                    onMouseLeave={() => setHoveredTechnique(null)}
                    title={`${cell.technique_id}: ${cell.technique_name}`}
                  >
                    <div className="truncate text-gray-200">{cell.technique_id}</div>
                    {hoveredTechnique === cell.technique_id && (
                      <div className="absolute z-10 bg-gray-900 border border-gray-600 rounded p-2 mt-1 text-xs max-w-xs">
                        <p className="font-medium text-white">{cell.technique_name}</p>
                        <p className="text-gray-400">{cell.technique_id}</p>
                        {cell.tested && (
                          <p className="mt-1 text-gray-300">Coverage: {cell.coverage_percent.toFixed(0)}%</p>
                        )}
                      </div>
                    )}
                  </div>
                ))}
                {cells.length > 15 && (
                  <div className="text-xs text-gray-500 text-center">+{cells.length - 15} more</div>
                )}
              </div>
            </div>
          );
        })}
      </div>
      <div className="mt-4 flex justify-between text-sm text-gray-400">
        <span>Tested: {matrix.tested_techniques} / {matrix.total_techniques} techniques</span>
        <span>Overall: {matrix.overall_coverage.toFixed(1)}%</span>
      </div>
    </div>
  );
}

function ExerciseCard({
  exercise,
  onStart,
  onStop,
  onView,
}: {
  exercise: PurpleTeamExercise;
  onStart: () => void;
  onStop: () => void;
  onView: () => void;
}) {
  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 transition-colors">
      <div className="flex justify-between items-start mb-3">
        <div>
          <h4 className="text-lg font-medium text-white">{exercise.name}</h4>
          {exercise.description && (
            <p className="text-sm text-gray-400 mt-1">{exercise.description}</p>
          )}
        </div>
        <StatusBadge status={exercise.status} />
      </div>
      <div className="text-sm text-gray-400 space-y-1 mb-3">
        <p>Attacks: {exercise.attack_configs.length}</p>
        <p>Detection Timeout: {exercise.detection_timeout_secs}s</p>
        <p>Created: {new Date(exercise.created_at).toLocaleDateString()}</p>
      </div>
      <div className="flex gap-2">
        {exercise.status === 'pending' && (
          <button
            onClick={onStart}
            className="flex items-center gap-1 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white text-sm rounded transition-colors"
          >
            <Play className="h-4 w-4" /> Start
          </button>
        )}
        {exercise.status === 'running' && (
          <button
            onClick={onStop}
            className="flex items-center gap-1 px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-sm rounded transition-colors"
          >
            <Square className="h-4 w-4" /> Stop
          </button>
        )}
        <button
          onClick={onView}
          className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded transition-colors"
        >
          <Eye className="h-4 w-4" /> View
        </button>
      </div>
    </div>
  );
}

function GapCard({ gap, onCopyRule }: { gap: PurpleDetectionGap; onCopyRule: (rule: string) => void }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
      <div className="flex justify-between items-start">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-cyan-400 text-sm">{gap.technique_id}</span>
            <SeverityBadge severity={gap.severity} />
            {gap.status === 'remediated' && (
              <span className="px-2 py-0.5 bg-green-900 text-green-300 rounded text-xs">Remediated</span>
            )}
          </div>
          <h4 className="text-white font-medium">{gap.technique_name}</h4>
          <p className="text-sm text-gray-400">{gap.tactic}</p>
        </div>
        <button
          onClick={() => setExpanded(!expanded)}
          className="p-1 hover:bg-gray-700 rounded transition-colors"
        >
          <ChevronRight className={`h-5 w-5 text-gray-400 transition-transform ${expanded ? 'rotate-90' : ''}`} />
        </button>
      </div>

      {expanded && gap.recommendations && gap.recommendations.length > 0 && (
        <div className="mt-4 space-y-3 border-t border-gray-700 pt-3">
          <h5 className="text-sm font-medium text-gray-300">Recommendations</h5>
          {gap.recommendations.map((rec, idx) => (
            <div key={idx} className="bg-gray-900 rounded p-3">
              <div className="flex justify-between items-start mb-2">
                <span className="text-sm font-medium text-white">{rec.title}</span>
                <span className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs">{rec.recommendation_type}</span>
              </div>
              {rec.sigma_rule && (
                <div className="mt-2">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-xs text-gray-400">Sigma Rule</span>
                    <button
                      onClick={() => onCopyRule(rec.sigma_rule!)}
                      className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300"
                    >
                      <Copy className="h-3 w-3" /> Copy
                    </button>
                  </div>
                  <pre className="text-xs bg-gray-950 p-2 rounded overflow-x-auto max-h-32 text-gray-300">
                    {rec.sigma_rule}
                  </pre>
                </div>
              )}
              {rec.splunk_query && (
                <div className="mt-2">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-xs text-gray-400">Splunk Query</span>
                    <button
                      onClick={() => onCopyRule(rec.splunk_query!)}
                      className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300"
                    >
                      <Copy className="h-3 w-3" /> Copy
                    </button>
                  </div>
                  <pre className="text-xs bg-gray-950 p-2 rounded overflow-x-auto text-gray-300">
                    {rec.splunk_query}
                  </pre>
                </div>
              )}
              {rec.elastic_query && (
                <div className="mt-2">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-xs text-gray-400">Elastic Query</span>
                    <button
                      onClick={() => onCopyRule(rec.elastic_query!)}
                      className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300"
                    >
                      <Copy className="h-3 w-3" /> Copy
                    </button>
                  </div>
                  <pre className="text-xs bg-gray-950 p-2 rounded overflow-x-auto text-gray-300">
                    {rec.elastic_query}
                  </pre>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function CreateExerciseModal({
  isOpen,
  onClose,
  onCreate,
}: {
  isOpen: boolean;
  onClose: () => void;
  onCreate: (data: CreateExerciseRequest) => void;
}) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [detectionTimeout, setDetectionTimeout] = useState(300);

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onCreate({
      name,
      description: description || undefined,
      siem_integration_id: undefined,
      attack_configs: [],
      detection_timeout_secs: detectionTimeout,
    });
    setName('');
    setDescription('');
    setDetectionTimeout(300);
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
        <h2 className="text-xl font-semibold text-white mb-4">Create Purple Team Exercise</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Name *</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
              placeholder="Q4 Detection Validation"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
              placeholder="Quarterly purple team exercise to validate detection coverage..."
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Detection Timeout (seconds)</label>
            <input
              type="number"
              value={detectionTimeout}
              onChange={(e) => setDetectionTimeout(parseInt(e.target.value) || 300)}
              min={30}
              max={3600}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
            />
            <p className="text-xs text-gray-400 mt-1">Time to wait for SIEM detection after each attack</p>
          </div>
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex-1 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors"
            >
              Create Exercise
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function ExerciseDetailModal({
  exercise,
  onClose,
}: {
  exercise: PurpleTeamExercise;
  onClose: () => void;
}) {
  const { data: results } = useQuery({
    queryKey: ['purple-team-results', exercise.id],
    queryFn: () => purpleTeamAPI.getExerciseResults(exercise.id).then((r) => r.data),
  });

  const { data: coverage } = useQuery({
    queryKey: ['purple-team-coverage', exercise.id],
    queryFn: () => purpleTeamAPI.getExerciseCoverage(exercise.id).then((r) => r.data),
    enabled: exercise.status === 'completed',
  });

  const { data: gaps } = useQuery({
    queryKey: ['purple-team-gaps', exercise.id],
    queryFn: () => purpleTeamAPI.getExerciseGaps(exercise.id).then((r) => r.data),
    enabled: exercise.status === 'completed',
  });

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-800 rounded-lg w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        <div className="p-4 border-b border-gray-700 flex justify-between items-center">
          <div>
            <h2 className="text-xl font-semibold text-white">{exercise.name}</h2>
            <p className="text-sm text-gray-400">{exercise.description}</p>
          </div>
          <div className="flex items-center gap-2">
            <StatusBadge status={exercise.status} />
            <button onClick={onClose} className="p-2 hover:bg-gray-700 rounded">
              <XCircle className="h-5 w-5 text-gray-400" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Results */}
          {results && results.length > 0 && (
            <div>
              <h3 className="text-lg font-medium text-white mb-3">Attack Results</h3>
              <div className="space-y-2">
                {results.map((result: PurpleAttackResult) => (
                  <div key={result.id} className="bg-gray-900 rounded p-3 flex justify-between items-center">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-cyan-400 text-sm">{result.technique_id}</span>
                        <span className="text-white">{result.technique_name}</span>
                      </div>
                      <div className="text-sm text-gray-400 mt-1">
                        Target: {result.target} | Type: {result.attack_type}
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <DetectionBadge status={result.detection_status} />
                      {result.time_to_detect_ms && (
                        <span className="text-sm text-gray-400">
                          {(result.time_to_detect_ms / 1000).toFixed(1)}s
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Coverage */}
          {coverage && <CoverageHeatmap coverage={coverage} />}

          {/* Gaps */}
          {gaps && gaps.length > 0 && (
            <div>
              <h3 className="text-lg font-medium text-white mb-3">Detection Gaps ({gaps.length})</h3>
              <div className="space-y-2">
                {gaps.map((gap: PurpleDetectionGap) => (
                  <GapCard
                    key={gap.id}
                    gap={gap}
                    onCopyRule={(rule) => {
                      navigator.clipboard.writeText(rule);
                      toast.success('Copied to clipboard');
                    }}
                  />
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function PurpleTeamPage() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedExercise, setSelectedExercise] = useState<PurpleTeamExercise | null>(null);
  const [gapFilter, setGapFilter] = useState<'all' | 'open' | 'remediated'>('all');
  const [gapSearch, setGapSearch] = useState('');

  // Queries
  const { data: dashboard, isLoading: dashboardLoading } = useQuery({
    queryKey: ['purple-team-dashboard'],
    queryFn: () => purpleTeamAPI.getDashboard().then((r) => r.data),
  });

  const { data: exercises, isLoading: exercisesLoading } = useQuery({
    queryKey: ['purple-team-exercises'],
    queryFn: () => purpleTeamAPI.listExercises().then((r) => r.data),
  });

  const { data: matrix, isLoading: matrixLoading } = useQuery({
    queryKey: ['purple-team-matrix'],
    queryFn: () => purpleTeamAPI.getCoverageMatrix().then((r) => r.data),
  });

  const { data: allGaps } = useQuery({
    queryKey: ['purple-team-all-gaps'],
    queryFn: () => purpleTeamAPI.listGaps().then((r) => r.data),
  });

  // Mutations
  const createMutation = useMutation({
    mutationFn: purpleTeamAPI.createExercise,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['purple-team-exercises'] });
      queryClient.invalidateQueries({ queryKey: ['purple-team-dashboard'] });
      toast.success('Exercise created');
    },
    onError: () => toast.error('Failed to create exercise'),
  });

  const startMutation = useMutation({
    mutationFn: purpleTeamAPI.startExercise,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['purple-team-exercises'] });
      queryClient.invalidateQueries({ queryKey: ['purple-team-dashboard'] });
      toast.success('Exercise started');
    },
    onError: () => toast.error('Failed to start exercise'),
  });

  const stopMutation = useMutation({
    mutationFn: purpleTeamAPI.stopExercise,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['purple-team-exercises'] });
      queryClient.invalidateQueries({ queryKey: ['purple-team-dashboard'] });
      toast.success('Exercise stopped');
    },
    onError: () => toast.error('Failed to stop exercise'),
  });

  // Filter gaps
  const filteredGaps = allGaps?.filter((gap: PurpleDetectionGap) => {
    if (gapFilter === 'open' && gap.status === 'remediated') return false;
    if (gapFilter === 'remediated' && gap.status !== 'remediated') return false;
    if (gapSearch) {
      const search = gapSearch.toLowerCase();
      return (
        gap.technique_id.toLowerCase().includes(search) ||
        gap.technique_name.toLowerCase().includes(search) ||
        gap.tactic.toLowerCase().includes(search)
      );
    }
    return true;
  });

  const isLoading = dashboardLoading || exercisesLoading || matrixLoading;

  return (
    <Layout>
      <div className="p-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-6">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-purple-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">Purple Team</h1>
              <p className="text-gray-400">Attack simulation and detection validation</p>
            </div>
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors"
          >
            <Plus className="h-4 w-4" /> New Exercise
          </button>
        </div>

        {isLoading ? (
          <div className="flex justify-center items-center h-64">
            <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
          </div>
        ) : (
          <div className="space-y-6">
            {/* Dashboard Stats */}
            {dashboard && (
              <DashboardStats
                dashboard={dashboard}
                onExercisesClick={() => document.getElementById('exercises-section')?.scrollIntoView({ behavior: 'smooth' })}
                onGapsClick={() => {
                  setGapFilter('open');
                  document.getElementById('gaps-section')?.scrollIntoView({ behavior: 'smooth' });
                }}
              />
            )}

            {/* MITRE ATT&CK Matrix */}
            {matrix && <AttackMatrixView matrix={matrix} />}

            {/* Two Column Layout */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Exercises */}
              <div id="exercises-section">
                <h2 className="text-lg font-semibold text-white mb-4">Exercises</h2>
                <div className="space-y-3">
                  {exercises?.length === 0 && (
                    <div className="bg-gray-800 rounded-lg p-8 text-center">
                      <Target className="h-12 w-12 text-gray-600 mx-auto mb-3" />
                      <p className="text-gray-400">No exercises yet</p>
                      <button
                        onClick={() => setShowCreateModal(true)}
                        className="mt-3 text-cyan-400 hover:text-cyan-300"
                      >
                        Create your first exercise
                      </button>
                    </div>
                  )}
                  {exercises?.map((exercise: PurpleTeamExercise) => (
                    <ExerciseCard
                      key={exercise.id}
                      exercise={exercise}
                      onStart={() => startMutation.mutate(exercise.id)}
                      onStop={() => stopMutation.mutate(exercise.id)}
                      onView={() => setSelectedExercise(exercise)}
                    />
                  ))}
                </div>
              </div>

              {/* Detection Gaps */}
              <div id="gaps-section">
                <div className="flex justify-between items-center mb-4">
                  <h2 className="text-lg font-semibold text-white">Detection Gaps</h2>
                  <div className="flex gap-2">
                    <div className="relative">
                      <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                      <input
                        type="text"
                        value={gapSearch}
                        onChange={(e) => setGapSearch(e.target.value)}
                        placeholder="Search..."
                        className="pl-8 pr-3 py-1.5 bg-gray-700 border border-gray-600 rounded text-white text-sm focus:outline-none focus:border-cyan-500"
                      />
                    </div>
                    <select
                      value={gapFilter}
                      onChange={(e) => setGapFilter(e.target.value as 'all' | 'open' | 'remediated')}
                      className="px-3 py-1.5 bg-gray-700 border border-gray-600 rounded text-white text-sm focus:outline-none focus:border-cyan-500"
                    >
                      <option value="all">All Gaps</option>
                      <option value="open">Open</option>
                      <option value="remediated">Remediated</option>
                    </select>
                  </div>
                </div>
                <div className="space-y-2 max-h-[500px] overflow-y-auto">
                  {filteredGaps?.length === 0 && (
                    <div className="bg-gray-800 rounded-lg p-8 text-center">
                      <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-3" />
                      <p className="text-gray-400">
                        {allGaps?.length === 0 ? 'No detection gaps found' : 'No gaps match your filter'}
                      </p>
                    </div>
                  )}
                  {filteredGaps?.map((gap: PurpleDetectionGap) => (
                    <GapCard
                      key={gap.id}
                      gap={gap}
                      onCopyRule={(rule) => {
                        navigator.clipboard.writeText(rule);
                        toast.success('Copied to clipboard');
                      }}
                    />
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Modals */}
        <CreateExerciseModal
          isOpen={showCreateModal}
          onClose={() => setShowCreateModal(false)}
          onCreate={(data) => createMutation.mutate(data)}
        />

        {selectedExercise && (
          <ExerciseDetailModal
            exercise={selectedExercise}
            onClose={() => setSelectedExercise(null)}
          />
        )}
      </div>
    </Layout>
  );
}
