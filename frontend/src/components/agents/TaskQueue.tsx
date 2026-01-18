import React, { useState } from 'react';
import {
  Clock,
  Play,
  XCircle,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  Target,
  Server,
  ChevronDown,
  ChevronRight,
  ArrowRightLeft,
} from 'lucide-react';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import type { QueuedTask, PeerInfo } from '../../types/agents';

interface TaskQueueProps {
  tasks: QueuedTask[];
  agents?: PeerInfo[];
  isLoading?: boolean;
  onCancelTask?: (taskId: string) => void;
  onRetryTask?: (taskId: string) => void;
  onReassignTask?: (taskId: string, agentId: string) => void;
  onBulkCancel?: (taskIds: string[]) => void;
  onRefresh?: () => void;
}

const statusConfig = {
  pending: {
    label: 'Pending',
    variant: 'warning' as const,
    icon: <Clock className="w-3 h-3" />,
  },
  running: {
    label: 'Running',
    variant: 'info' as const,
    icon: <Play className="w-3 h-3" />,
  },
  completed: {
    label: 'Completed',
    variant: 'success' as const,
    icon: <CheckCircle className="w-3 h-3" />,
  },
  failed: {
    label: 'Failed',
    variant: 'danger' as const,
    icon: <AlertTriangle className="w-3 h-3" />,
  },
};

const TaskQueue: React.FC<TaskQueueProps> = ({
  tasks,
  agents = [],
  isLoading = false,
  onCancelTask,
  onRetryTask,
  onReassignTask,
  onBulkCancel,
  onRefresh,
}) => {
  const [selectedTasks, setSelectedTasks] = useState<Set<string>>(new Set());
  const [expandedTask, setExpandedTask] = useState<string | null>(null);
  const [showReassignMenu, setShowReassignMenu] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'pending' | 'running' | 'completed' | 'failed'>('all');

  const filteredTasks = tasks.filter(task => {
    if (filter === 'all') return true;
    return task.status === filter;
  });

  const pendingCount = tasks.filter(t => t.status === 'pending').length;
  const runningCount = tasks.filter(t => t.status === 'running').length;
  const completedCount = tasks.filter(t => t.status === 'completed').length;
  const failedCount = tasks.filter(t => t.status === 'failed').length;

  const toggleTaskSelection = (taskId: string) => {
    const newSelected = new Set(selectedTasks);
    if (newSelected.has(taskId)) {
      newSelected.delete(taskId);
    } else {
      newSelected.add(taskId);
    }
    setSelectedTasks(newSelected);
  };

  const selectAllTasks = () => {
    if (selectedTasks.size === filteredTasks.length) {
      setSelectedTasks(new Set());
    } else {
      setSelectedTasks(new Set(filteredTasks.map(t => t.task.id)));
    }
  };

  const handleBulkCancel = () => {
    if (onBulkCancel && selectedTasks.size > 0) {
      onBulkCancel(Array.from(selectedTasks));
      setSelectedTasks(new Set());
    }
  };

  const formatDuration = (queuedAt: string) => {
    const start = new Date(queuedAt);
    const now = new Date();
    const diffMs = now.getTime() - start.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m`;
    if (diffHours < 24) return `${diffHours}h ${diffMins % 60}m`;
    return `${Math.floor(diffHours / 24)}d ${diffHours % 24}h`;
  };

  return (
    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
      {/* Header */}
      <div className="p-4 border-b border-light-border dark:border-dark-border">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Task Queue</h2>
          <div className="flex items-center gap-2">
            {selectedTasks.size > 0 && onBulkCancel && (
              <Button size="sm" variant="danger" onClick={handleBulkCancel}>
                <XCircle className="w-3 h-3 mr-1" />
                Cancel Selected ({selectedTasks.size})
              </Button>
            )}
            {onRefresh && (
              <Button size="sm" variant="outline" onClick={onRefresh} disabled={isLoading}>
                <RefreshCw className={`w-3 h-3 mr-1 ${isLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
            )}
          </div>
        </div>

        {/* Stats */}
        <div className="flex items-center gap-4 text-sm">
          <button
            onClick={() => setFilter('all')}
            className={`px-3 py-1 rounded-full transition-colors ${
              filter === 'all'
                ? 'bg-slate-500/20 text-slate-200'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All ({tasks.length})
          </button>
          <button
            onClick={() => setFilter('pending')}
            className={`px-3 py-1 rounded-full transition-colors ${
              filter === 'pending'
                ? 'bg-yellow-500/20 text-yellow-400'
                : 'text-slate-400 hover:text-yellow-400'
            }`}
          >
            Pending ({pendingCount})
          </button>
          <button
            onClick={() => setFilter('running')}
            className={`px-3 py-1 rounded-full transition-colors ${
              filter === 'running'
                ? 'bg-blue-500/20 text-blue-400'
                : 'text-slate-400 hover:text-blue-400'
            }`}
          >
            Running ({runningCount})
          </button>
          <button
            onClick={() => setFilter('completed')}
            className={`px-3 py-1 rounded-full transition-colors ${
              filter === 'completed'
                ? 'bg-green-500/20 text-green-400'
                : 'text-slate-400 hover:text-green-400'
            }`}
          >
            Completed ({completedCount})
          </button>
          <button
            onClick={() => setFilter('failed')}
            className={`px-3 py-1 rounded-full transition-colors ${
              filter === 'failed'
                ? 'bg-red-500/20 text-red-400'
                : 'text-slate-400 hover:text-red-400'
            }`}
          >
            Failed ({failedCount})
          </button>
        </div>
      </div>

      {/* Task List */}
      <div className="divide-y divide-light-border dark:divide-dark-border">
        {/* Select All Header */}
        {filteredTasks.length > 0 && (
          <div className="px-4 py-2 bg-light-hover dark:bg-dark-hover flex items-center gap-3 text-sm">
            <input
              type="checkbox"
              checked={selectedTasks.size === filteredTasks.length && filteredTasks.length > 0}
              onChange={selectAllTasks}
              className="w-4 h-4 rounded border-gray-300 dark:border-gray-600"
            />
            <span className="text-slate-500 dark:text-slate-400">
              {selectedTasks.size > 0
                ? `${selectedTasks.size} selected`
                : 'Select all'}
            </span>
          </div>
        )}

        {isLoading && tasks.length === 0 ? (
          <div className="p-8 text-center">
            <RefreshCw className="w-8 h-8 text-slate-400 animate-spin mx-auto mb-2" />
            <p className="text-slate-400">Loading tasks...</p>
          </div>
        ) : filteredTasks.length === 0 ? (
          <div className="p-8 text-center">
            <Clock className="w-8 h-8 text-slate-400 mx-auto mb-2" />
            <p className="text-slate-400">No tasks in queue</p>
          </div>
        ) : (
          filteredTasks.map((queuedTask) => {
            const task = queuedTask.task;
            const status = statusConfig[queuedTask.status] || statusConfig.pending;
            const isExpanded = expandedTask === task.id;
            const assignedAgent = agents.find(a => a.agent_id === queuedTask.assigned_agent_id);

            return (
              <div key={task.id} className="hover:bg-light-hover dark:hover:bg-dark-hover">
                {/* Main Row */}
                <div className="px-4 py-3 flex items-center gap-3">
                  <input
                    type="checkbox"
                    checked={selectedTasks.has(task.id)}
                    onChange={() => toggleTaskSelection(task.id)}
                    className="w-4 h-4 rounded border-gray-300 dark:border-gray-600"
                  />

                  <button
                    onClick={() => setExpandedTask(isExpanded ? null : task.id)}
                    className="p-1 hover:bg-slate-200 dark:hover:bg-slate-700 rounded"
                  >
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-slate-400" />
                    )}
                  </button>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-slate-900 dark:text-white truncate">
                        {task.task_type}
                      </span>
                      <Badge variant={status.variant} size="sm">
                        {status.icon}
                        <span className="ml-1">{status.label}</span>
                      </Badge>
                      <Badge variant="secondary" size="sm">
                        P{task.priority}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-slate-500 dark:text-slate-400 mt-1">
                      <span className="flex items-center gap-1">
                        <Target className="w-3 h-3" />
                        {task.targets.slice(0, 3).join(', ')}
                        {task.targets.length > 3 && ` +${task.targets.length - 3}`}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {formatDuration(queuedTask.queued_at)}
                      </span>
                      {assignedAgent && (
                        <span className="flex items-center gap-1">
                          <Server className="w-3 h-3" />
                          {assignedAgent.name}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1">
                    {queuedTask.status === 'failed' && onRetryTask && (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => onRetryTask(task.id)}
                        title="Retry task"
                      >
                        <RefreshCw className="w-4 h-4" />
                      </Button>
                    )}
                    {onReassignTask && agents.length > 0 && (queuedTask.status === 'pending' || queuedTask.status === 'failed') && (
                      <div className="relative">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setShowReassignMenu(showReassignMenu === task.id ? null : task.id)}
                          title="Reassign task"
                        >
                          <ArrowRightLeft className="w-4 h-4" />
                        </Button>
                        {showReassignMenu === task.id && (
                          <div className="absolute right-0 top-full mt-1 w-48 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg shadow-lg py-1 z-10">
                            {agents.filter(a => a.status === 'online' || a.status === 'busy').map(agent => (
                              <button
                                key={agent.agent_id}
                                onClick={() => {
                                  onReassignTask(task.id, agent.agent_id);
                                  setShowReassignMenu(null);
                                }}
                                className="w-full px-3 py-2 text-left text-sm text-slate-600 dark:text-slate-300 hover:bg-light-hover dark:hover:bg-dark-hover flex items-center gap-2"
                              >
                                <Server className="w-3 h-3" />
                                {agent.name}
                                <span className={`ml-auto text-xs ${
                                  agent.status === 'online' ? 'text-green-400' : 'text-yellow-400'
                                }`}>
                                  {agent.status}
                                </span>
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                    {onCancelTask && (queuedTask.status === 'pending' || queuedTask.status === 'running') && (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => onCancelTask(task.id)}
                        className="text-red-400 hover:text-red-300"
                        title="Cancel task"
                      >
                        <XCircle className="w-4 h-4" />
                      </Button>
                    )}
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="px-4 pb-3 ml-12 space-y-3">
                    {/* Task Info */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <span className="text-slate-500 dark:text-slate-400">Scan ID</span>
                        <p className="font-mono text-slate-900 dark:text-white text-xs">{task.scan_id}</p>
                      </div>
                      <div>
                        <span className="text-slate-500 dark:text-slate-400">Timeout</span>
                        <p className="text-slate-900 dark:text-white">{task.timeout_seconds}s</p>
                      </div>
                      <div>
                        <span className="text-slate-500 dark:text-slate-400">Attempts</span>
                        <p className="text-slate-900 dark:text-white">{queuedTask.attempts}</p>
                      </div>
                      <div>
                        <span className="text-slate-500 dark:text-slate-400">Queued At</span>
                        <p className="text-slate-900 dark:text-white">
                          {new Date(queuedTask.queued_at).toLocaleString()}
                        </p>
                      </div>
                    </div>

                    {/* Requirements */}
                    <div className="flex flex-wrap gap-2">
                      {task.required_capabilities.map(cap => (
                        <span key={cap} className="text-xs px-2 py-1 bg-cyan-500/10 text-cyan-400 rounded">
                          {cap}
                        </span>
                      ))}
                      {task.required_zones.map(zone => (
                        <span key={zone} className="text-xs px-2 py-1 bg-purple-500/10 text-purple-400 rounded">
                          {zone}
                        </span>
                      ))}
                    </div>

                    {/* Error Message */}
                    {queuedTask.last_error && (
                      <div className="p-2 bg-red-500/10 border border-red-500/20 rounded text-sm text-red-400">
                        <strong>Error:</strong> {queuedTask.last_error}
                      </div>
                    )}

                    {/* Targets List */}
                    {task.targets.length > 3 && (
                      <div>
                        <span className="text-xs text-slate-500 dark:text-slate-400">All Targets:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {task.targets.map(target => (
                            <span key={target} className="text-xs px-2 py-0.5 bg-slate-500/10 text-slate-400 rounded">
                              {target}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export { TaskQueue };
export default TaskQueue;
