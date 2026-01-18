import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import {
  findingLifecycleAPI,
  type FindingLifecycle,
  type FindingState,
} from '../../services/api';
import {
  AlertTriangle,
  Clock,
  CheckCircle,
  XCircle,
  Eye,
  Search,
  RefreshCw,
  ChevronRight,
  AlertCircle,
  Shield,
} from 'lucide-react';

interface LifecycleBoardProps {
  customerId?: string;
  engagementId?: string;
  onFindingClick?: (findingId: string) => void;
}

const stateConfig: Record<FindingState, { title: string; color: string; icon: React.ReactNode }> = {
  discovered: {
    title: 'Discovered',
    color: 'bg-gray-800/50 border-gray-600',
    icon: <Search className="w-4 h-4" />,
  },
  triaged: {
    title: 'Triaged',
    color: 'bg-blue-900/30 border-blue-600',
    icon: <Eye className="w-4 h-4" />,
  },
  acknowledged: {
    title: 'Acknowledged',
    color: 'bg-purple-900/30 border-purple-600',
    icon: <CheckCircle className="w-4 h-4" />,
  },
  in_remediation: {
    title: 'In Remediation',
    color: 'bg-yellow-900/30 border-yellow-600',
    icon: <RefreshCw className="w-4 h-4" />,
  },
  verification_pending: {
    title: 'Verification Pending',
    color: 'bg-orange-900/30 border-orange-600',
    icon: <Clock className="w-4 h-4" />,
  },
  verified: {
    title: 'Verified',
    color: 'bg-cyan-900/30 border-cyan-600',
    icon: <Shield className="w-4 h-4" />,
  },
  closed: {
    title: 'Closed',
    color: 'bg-green-900/30 border-green-600',
    icon: <CheckCircle className="w-4 h-4" />,
  },
};

const severityColors: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-gray-500',
};

const stateOrder: FindingState[] = [
  'discovered',
  'triaged',
  'acknowledged',
  'in_remediation',
  'verification_pending',
  'verified',
  'closed',
];

const LifecycleBoard: React.FC<LifecycleBoardProps> = ({
  customerId,
  engagementId,
  onFindingClick,
}) => {
  const [lifecycles, setLifecycles] = useState<FindingLifecycle[]>([]);
  const [loading, setLoading] = useState(true);
  const [draggedItem, setDraggedItem] = useState<FindingLifecycle | null>(null);
  const [updating, setUpdating] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [showTransitionModal, setShowTransitionModal] = useState(false);
  const [transitionTarget, setTransitionTarget] = useState<{
    finding: FindingLifecycle;
    toState: FindingState;
  } | null>(null);
  const [transitionReason, setTransitionReason] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('');
  const [filterSlaBreached, setFilterSlaBreached] = useState<boolean | undefined>(undefined);

  useEffect(() => {
    loadLifecycles();
  }, [customerId, engagementId, filterSeverity, filterSlaBreached]);

  const loadLifecycles = async () => {
    try {
      setLoading(true);
      const params: Record<string, unknown> = {};
      if (filterSeverity) params.severity = filterSeverity;
      if (filterSlaBreached !== undefined) params.sla_breached = filterSlaBreached;

      const response = await findingLifecycleAPI.list(params);
      setLifecycles(response.data.lifecycles);
    } catch (error) {
      console.error('Failed to load lifecycles:', error);
      toast.error('Failed to load finding lifecycles');
    } finally {
      setLoading(false);
    }
  };

  const handleDragStart = (e: React.DragEvent, lifecycle: FindingLifecycle) => {
    setDraggedItem(lifecycle);
    e.dataTransfer.effectAllowed = 'move';
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  };

  const handleDrop = async (e: React.DragEvent, toState: FindingState) => {
    e.preventDefault();
    if (!draggedItem || draggedItem.current_state === toState || updating) return;

    // Check if transition is valid (can only move forward or back one step)
    const currentIndex = stateOrder.indexOf(draggedItem.current_state);
    const targetIndex = stateOrder.indexOf(toState);

    if (Math.abs(targetIndex - currentIndex) > 1) {
      // Show modal for reason when skipping states
      setTransitionTarget({ finding: draggedItem, toState });
      setShowTransitionModal(true);
      return;
    }

    await performTransition(draggedItem.finding_id, toState);
  };

  const performTransition = async (findingId: string, toState: FindingState, reason?: string) => {
    try {
      setUpdating(true);
      await findingLifecycleAPI.transition(findingId, { to_state: toState, reason });
      await loadLifecycles();
      toast.success('Finding state updated');
    } catch (error) {
      console.error('Failed to transition finding:', error);
      toast.error('Failed to update finding state');
    } finally {
      setUpdating(false);
      setDraggedItem(null);
      setTransitionTarget(null);
      setShowTransitionModal(false);
      setTransitionReason('');
    }
  };

  const handleDragEnd = () => {
    setDraggedItem(null);
  };

  const handleBulkTransition = async (toState: FindingState) => {
    if (selectedIds.size === 0) return;

    try {
      setUpdating(true);
      const result = await findingLifecycleAPI.bulkTransition({
        finding_ids: Array.from(selectedIds),
        to_state: toState,
      });
      toast.success(`Transitioned ${result.data.success_count} findings`);
      if (result.data.failed_count > 0) {
        toast.warning(`${result.data.failed_count} findings failed to transition`);
      }
      setSelectedIds(new Set());
      await loadLifecycles();
    } catch (error) {
      console.error('Bulk transition failed:', error);
      toast.error('Failed to perform bulk transition');
    } finally {
      setUpdating(false);
    }
  };

  const handleToggleSelect = (lifecycleId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const newSelected = new Set(selectedIds);
    if (newSelected.has(lifecycleId)) {
      newSelected.delete(lifecycleId);
    } else {
      newSelected.add(lifecycleId);
    }
    setSelectedIds(newSelected);
  };

  const getTimeRemaining = (slaDueAt: string | null): { text: string; urgent: boolean } => {
    if (!slaDueAt) return { text: 'No SLA', urgent: false };
    const due = new Date(slaDueAt);
    const now = new Date();
    const diffMs = due.getTime() - now.getTime();
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));

    if (diffHours < 0) {
      return { text: `${Math.abs(diffHours)}h overdue`, urgent: true };
    }
    if (diffHours < 24) {
      return { text: `${diffHours}h left`, urgent: true };
    }
    const diffDays = Math.floor(diffHours / 24);
    return { text: `${diffDays}d left`, urgent: diffDays < 3 };
  };

  const getLifecyclesByState = (state: FindingState) => {
    return lifecycles.filter((l) => l.current_state === state);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-center gap-4 p-4 bg-gray-800 rounded-lg">
        <div className="flex items-center gap-2">
          <label className="text-sm text-gray-400">Severity:</label>
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm text-gray-200"
          >
            <option value="">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-sm text-gray-400">SLA Status:</label>
          <select
            value={filterSlaBreached === undefined ? '' : filterSlaBreached ? 'breached' : 'ok'}
            onChange={(e) => {
              if (e.target.value === '') setFilterSlaBreached(undefined);
              else setFilterSlaBreached(e.target.value === 'breached');
            }}
            className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm text-gray-200"
          >
            <option value="">All</option>
            <option value="breached">SLA Breached</option>
            <option value="ok">On Track</option>
          </select>
        </div>
        <button
          onClick={loadLifecycles}
          className="ml-auto flex items-center gap-1 px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Bulk Actions */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-4 p-3 bg-cyan-900/20 border border-cyan-700 rounded-lg">
          <span className="text-sm text-cyan-300">{selectedIds.size} selected</span>
          <div className="flex items-center gap-2 ml-auto">
            <span className="text-sm text-gray-400">Move to:</span>
            {stateOrder.map((state) => (
              <button
                key={state}
                onClick={() => handleBulkTransition(state)}
                disabled={updating}
                className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 rounded disabled:opacity-50"
              >
                {stateConfig[state].title}
              </button>
            ))}
          </div>
          <button
            onClick={() => setSelectedIds(new Set())}
            className="text-sm text-gray-400 hover:text-white"
          >
            Clear
          </button>
        </div>
      )}

      {/* Kanban Board */}
      <div className="grid grid-cols-7 gap-3 overflow-x-auto pb-4">
        {stateOrder.map((state) => {
          const config = stateConfig[state];
          const stateLifecycles = getLifecyclesByState(state);

          return (
            <div
              key={state}
              className={`min-w-[200px] rounded-lg border ${config.color} p-3`}
              onDragOver={handleDragOver}
              onDrop={(e) => handleDrop(e, state)}
            >
              {/* Column Header */}
              <div className="flex items-center gap-2 mb-3 pb-2 border-b border-gray-700">
                {config.icon}
                <h3 className="font-medium text-sm">{config.title}</h3>
                <span className="ml-auto text-xs bg-gray-700 px-2 py-0.5 rounded-full">
                  {stateLifecycles.length}
                </span>
              </div>

              {/* Cards */}
              <div className="space-y-2 min-h-[100px]">
                {stateLifecycles.map((lifecycle) => {
                  const timeRemaining = getTimeRemaining(lifecycle.sla_due_at);
                  const isSelected = selectedIds.has(lifecycle.id);

                  return (
                    <div
                      key={lifecycle.id}
                      draggable
                      onDragStart={(e) => handleDragStart(e, lifecycle)}
                      onDragEnd={handleDragEnd}
                      onClick={() => onFindingClick?.(lifecycle.finding_id)}
                      className={`p-2 rounded bg-gray-800 border cursor-move hover:border-cyan-500 transition-colors ${
                        isSelected ? 'border-cyan-500 bg-cyan-900/20' : 'border-gray-700'
                      } ${draggedItem?.id === lifecycle.id ? 'opacity-50' : ''}`}
                    >
                      {/* Severity Badge */}
                      <div className="flex items-center gap-2 mb-1">
                        <div
                          className={`w-2 h-2 rounded-full ${
                            severityColors[lifecycle.severity.toLowerCase()] || 'bg-gray-500'
                          }`}
                        />
                        <span className="text-xs text-gray-400 uppercase">
                          {lifecycle.severity}
                        </span>
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}}
                          onClick={(e) => handleToggleSelect(lifecycle.id, e)}
                          className="ml-auto w-4 h-4 rounded border-gray-600 bg-gray-700 text-cyan-500 focus:ring-cyan-500"
                        />
                      </div>

                      {/* Title */}
                      <h4 className="text-sm font-medium text-gray-200 truncate mb-1">
                        {lifecycle.title}
                      </h4>

                      {/* Asset */}
                      <p className="text-xs text-gray-400 truncate mb-2">
                        {lifecycle.affected_asset}
                      </p>

                      {/* SLA Status */}
                      <div
                        className={`flex items-center gap-1 text-xs ${
                          lifecycle.sla_breached
                            ? 'text-red-400'
                            : timeRemaining.urgent
                            ? 'text-yellow-400'
                            : 'text-gray-400'
                        }`}
                      >
                        {lifecycle.sla_breached ? (
                          <XCircle className="w-3 h-3" />
                        ) : timeRemaining.urgent ? (
                          <AlertCircle className="w-3 h-3" />
                        ) : (
                          <Clock className="w-3 h-3" />
                        )}
                        <span>{timeRemaining.text}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {/* Transition Modal */}
      {showTransitionModal && transitionTarget && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
            <h3 className="text-lg font-semibold mb-4">Transition Finding</h3>
            <p className="text-sm text-gray-400 mb-4">
              Moving "{transitionTarget.finding.title}" from{' '}
              <span className="text-cyan-400">
                {stateConfig[transitionTarget.finding.current_state].title}
              </span>{' '}
              to{' '}
              <span className="text-cyan-400">
                {stateConfig[transitionTarget.toState].title}
              </span>
            </p>
            <div className="mb-4">
              <label className="block text-sm text-gray-400 mb-1">
                Reason (optional)
              </label>
              <textarea
                value={transitionReason}
                onChange={(e) => setTransitionReason(e.target.value)}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
                rows={3}
                placeholder="Enter reason for state change..."
              />
            </div>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => {
                  setShowTransitionModal(false);
                  setTransitionTarget(null);
                  setTransitionReason('');
                  setDraggedItem(null);
                }}
                className="px-4 py-2 text-sm bg-gray-700 hover:bg-gray-600 rounded"
              >
                Cancel
              </button>
              <button
                onClick={() =>
                  performTransition(
                    transitionTarget.finding.finding_id,
                    transitionTarget.toState,
                    transitionReason || undefined
                  )
                }
                disabled={updating}
                className="px-4 py-2 text-sm bg-cyan-600 hover:bg-cyan-500 rounded disabled:opacity-50"
              >
                {updating ? 'Updating...' : 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default LifecycleBoard;
