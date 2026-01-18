import React from 'react';
import {
  Server,
  Activity,
  Users,
  Zap,
  Crown,
  CheckCircle,
  XCircle,
  AlertTriangle,
  TrendingUp,
  Settings,
  Trash2,
  RefreshCw,
} from 'lucide-react';
import { Badge } from '../ui/Badge';
import { Button } from '../ui/Button';
import type { ClusterWithDetails } from '../../types/agents';

interface ClusterStatusProps {
  cluster: ClusterWithDetails;
  onViewDetails?: () => void;
  onEditConfig?: () => void;
  onDelete?: () => void;
  onElectLeader?: () => void;
  showActions?: boolean;
}

const ClusterStatus: React.FC<ClusterStatusProps> = ({
  cluster,
  onViewDetails,
  onEditConfig,
  onDelete,
  onElectLeader,
  showActions = true,
}) => {
  const health = cluster.health;
  const config = cluster.config;
  const totalMembers = health.online_members + health.offline_members;
  const healthPercentage = totalMembers > 0 ? Math.round((health.online_members / totalMembers) * 100) : 0;
  const loadPercentage = Math.round(health.average_load * 100);

  const getHealthStatus = () => {
    if (!health.is_healthy) {
      return { label: 'Unhealthy', variant: 'danger' as const, icon: <XCircle className="w-4 h-4" /> };
    }
    if (health.offline_members > 0) {
      return { label: 'Degraded', variant: 'warning' as const, icon: <AlertTriangle className="w-4 h-4" /> };
    }
    return { label: 'Healthy', variant: 'success' as const, icon: <CheckCircle className="w-4 h-4" /> };
  };

  const healthStatus = getHealthStatus();
  const hasQuorum = totalMembers >= (config?.min_quorum_size || 1);

  const leader = cluster.members.find(m => m.agent_id === cluster.leader_agent_id);

  return (
    <div
      className={`bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden ${
        onViewDetails ? 'cursor-pointer hover:border-primary/50' : ''
      }`}
      onClick={onViewDetails}
    >
      {/* Header */}
      <div className="p-4 border-b border-light-border dark:border-dark-border">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${
              health.is_healthy ? 'bg-green-500/20' : 'bg-red-500/20'
            }`}>
              <Users className={`w-5 h-5 ${
                health.is_healthy ? 'text-green-400' : 'text-red-400'
              }`} />
            </div>
            <div>
              <h3 className="font-semibold text-slate-900 dark:text-white">{cluster.name}</h3>
              {cluster.description && (
                <p className="text-sm text-slate-500 dark:text-slate-400 line-clamp-1">
                  {cluster.description}
                </p>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Badge variant={healthStatus.variant}>
              {healthStatus.icon}
              <span className="ml-1">{healthStatus.label}</span>
            </Badge>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="p-4 grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Members */}
        <div className="text-center">
          <div className="flex items-center justify-center gap-1 text-xs text-slate-500 dark:text-slate-400 mb-1">
            <Server className="w-3 h-3" />
            Members
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white">
            {health.online_members}
            <span className="text-sm font-normal text-slate-400">/{totalMembers}</span>
          </div>
          <div className="mt-1 h-1.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full ${
                healthPercentage === 100 ? 'bg-green-500' :
                healthPercentage >= 50 ? 'bg-yellow-500' :
                'bg-red-500'
              }`}
              style={{ width: `${healthPercentage}%` }}
            />
          </div>
        </div>

        {/* Active Tasks */}
        <div className="text-center">
          <div className="flex items-center justify-center gap-1 text-xs text-slate-500 dark:text-slate-400 mb-1">
            <Zap className="w-3 h-3" />
            Tasks
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white">
            {health.total_tasks}
          </div>
          <div className="text-xs text-slate-400 mt-1">active</div>
        </div>

        {/* Average Load */}
        <div className="text-center">
          <div className="flex items-center justify-center gap-1 text-xs text-slate-500 dark:text-slate-400 mb-1">
            <TrendingUp className="w-3 h-3" />
            Avg Load
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white">
            {loadPercentage}%
          </div>
          <div className="mt-1 h-1.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full ${
                loadPercentage > 80 ? 'bg-red-500' :
                loadPercentage > 50 ? 'bg-yellow-500' :
                'bg-green-500'
              }`}
              style={{ width: `${loadPercentage}%` }}
            />
          </div>
        </div>

        {/* Quorum Status */}
        <div className="text-center">
          <div className="flex items-center justify-center gap-1 text-xs text-slate-500 dark:text-slate-400 mb-1">
            <Activity className="w-3 h-3" />
            Quorum
          </div>
          <div className={`text-2xl font-bold ${hasQuorum ? 'text-green-400' : 'text-red-400'}`}>
            {hasQuorum ? 'Yes' : 'No'}
          </div>
          <div className="text-xs text-slate-400 mt-1">
            min: {config?.min_quorum_size || 1}
          </div>
        </div>
      </div>

      {/* Leader Info */}
      {leader && (
        <div className="px-4 pb-3">
          <div className="flex items-center gap-2 p-2 bg-yellow-500/10 rounded-lg">
            <Crown className="w-4 h-4 text-yellow-400" />
            <span className="text-sm text-slate-600 dark:text-slate-300">Leader:</span>
            <span className="text-sm font-medium text-slate-900 dark:text-white">{leader.name}</span>
            <span className="text-xs text-slate-400">({leader.address}:{leader.mesh_port})</span>
          </div>
        </div>
      )}

      {/* Config Summary */}
      {config && (
        <div className="px-4 pb-3">
          <div className="flex flex-wrap gap-2 text-xs">
            {config.enable_work_stealing && (
              <span className="px-2 py-1 bg-cyan-500/10 text-cyan-400 rounded">
                Work Stealing
              </span>
            )}
            {config.enable_gossip && (
              <span className="px-2 py-1 bg-purple-500/10 text-purple-400 rounded">
                Gossip Protocol
              </span>
            )}
            {config.enable_mdns && (
              <span className="px-2 py-1 bg-blue-500/10 text-blue-400 rounded">
                mDNS Discovery
              </span>
            )}
            {config.auto_elect_leader && (
              <span className="px-2 py-1 bg-yellow-500/10 text-yellow-400 rounded">
                Auto Leader Election
              </span>
            )}
          </div>
        </div>
      )}

      {/* Actions */}
      {showActions && (
        <div className="px-4 pb-4 flex items-center gap-2">
          {onElectLeader && (
            <Button
              size="sm"
              variant="outline"
              onClick={(e) => {
                e.stopPropagation();
                onElectLeader();
              }}
            >
              <RefreshCw className="w-3 h-3 mr-1" />
              Elect Leader
            </Button>
          )}
          {onEditConfig && (
            <Button
              size="sm"
              variant="outline"
              onClick={(e) => {
                e.stopPropagation();
                onEditConfig();
              }}
            >
              <Settings className="w-3 h-3 mr-1" />
              Configure
            </Button>
          )}
          {onDelete && (
            <Button
              size="sm"
              variant="ghost"
              onClick={(e) => {
                e.stopPropagation();
                onDelete();
              }}
              className="text-red-400 hover:text-red-300"
            >
              <Trash2 className="w-3 h-3 mr-1" />
              Delete
            </Button>
          )}
        </div>
      )}

      {/* Last Check */}
      {health.last_check && (
        <div className="px-4 pb-3 text-xs text-slate-400">
          Last health check: {new Date(health.last_check).toLocaleString()}
        </div>
      )}
    </div>
  );
};

export { ClusterStatus };
export default ClusterStatus;
