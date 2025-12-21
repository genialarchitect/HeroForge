import React from 'react';
import {
  Server,
  Activity,
  Clock,
  Wifi,
  WifiOff,
  Loader2,
  MoreVertical,
  Crown,
  Cpu,
  Network,
  Zap,
} from 'lucide-react';
import { Badge } from '../ui/Badge';
import type { PeerInfo, PeerStatus } from '../../types/agents';

interface MeshAgentCardProps {
  agent: PeerInfo;
  isLeader?: boolean;
  onClick?: () => void;
  onPing?: () => void;
  onRemove?: () => void;
  showActions?: boolean;
}

const statusConfig: Record<
  PeerStatus,
  { label: string; variant: 'success' | 'warning' | 'danger' | 'secondary' | 'info'; icon: React.ReactNode }
> = {
  online: { label: 'Online', variant: 'success', icon: <Wifi className="w-3 h-3" /> },
  busy: { label: 'Busy', variant: 'warning', icon: <Activity className="w-3 h-3" /> },
  offline: { label: 'Offline', variant: 'danger', icon: <WifiOff className="w-3 h-3" /> },
  joining: { label: 'Joining', variant: 'info', icon: <Loader2 className="w-3 h-3 animate-spin" /> },
  leaving: { label: 'Leaving', variant: 'secondary', icon: <WifiOff className="w-3 h-3" /> },
  disconnected: { label: 'Disconnected', variant: 'danger', icon: <WifiOff className="w-3 h-3" /> },
  unknown: { label: 'Unknown', variant: 'secondary', icon: <Activity className="w-3 h-3" /> },
};

const MeshAgentCard: React.FC<MeshAgentCardProps> = ({
  agent,
  isLeader = false,
  onClick,
  onPing,
  onRemove,
  showActions = true,
}) => {
  const [showMenu, setShowMenu] = React.useState(false);
  const menuRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setShowMenu(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const status = statusConfig[agent.status] || statusConfig.unknown;
  const loadPercentage = Math.round(agent.load * 100);
  const capacityUsed = agent.max_tasks > 0 ? (agent.current_tasks / agent.max_tasks) * 100 : 0;

  const formatLastSeen = (lastSeen: string) => {
    const date = new Date(lastSeen);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return date.toLocaleDateString();
  };

  return (
    <div
      className={`relative bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4 transition-all ${
        onClick ? 'cursor-pointer hover:border-primary/50 hover:shadow-lg' : ''
      }`}
      onClick={onClick}
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${
            agent.status === 'online' ? 'bg-green-500/20' :
            agent.status === 'busy' ? 'bg-yellow-500/20' :
            'bg-slate-500/20'
          }`}>
            <Server className={`w-5 h-5 ${
              agent.status === 'online' ? 'text-green-400' :
              agent.status === 'busy' ? 'text-yellow-400' :
              'text-slate-400'
            }`} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-semibold text-slate-900 dark:text-white">{agent.name}</h3>
              {isLeader && (
                <span title="Cluster Leader">
                  <Crown className="w-4 h-4 text-yellow-400" />
                </span>
              )}
            </div>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              {agent.address}:{agent.mesh_port}
            </p>
          </div>
        </div>

        {showActions && (
          <div className="relative" ref={menuRef}>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setShowMenu(!showMenu);
              }}
              className="p-1 rounded hover:bg-light-hover dark:hover:bg-dark-hover"
            >
              <MoreVertical className="w-4 h-4 text-slate-400" />
            </button>
            {showMenu && (
              <div className="absolute right-0 mt-1 w-40 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg shadow-lg py-1 z-10">
                {onPing && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onPing();
                      setShowMenu(false);
                    }}
                    className="w-full px-3 py-2 text-left text-sm text-slate-600 dark:text-slate-300 hover:bg-light-hover dark:hover:bg-dark-hover"
                  >
                    Ping Agent
                  </button>
                )}
                {onRemove && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onRemove();
                      setShowMenu(false);
                    }}
                    className="w-full px-3 py-2 text-left text-sm text-red-400 hover:bg-light-hover dark:hover:bg-dark-hover"
                  >
                    Remove Agent
                  </button>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Status Badge */}
      <div className="flex items-center gap-2 mb-4">
        <Badge variant={status.variant}>
          {status.icon}
          <span className="ml-1">{status.label}</span>
        </Badge>
        {agent.latency_ms !== null && agent.status === 'online' && (
          <span className="text-xs text-slate-400">
            {agent.latency_ms}ms
          </span>
        )}
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 gap-3 mb-4">
        {/* Load */}
        <div className="bg-light-hover dark:bg-dark-hover rounded-lg p-2">
          <div className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400 mb-1">
            <Cpu className="w-3 h-3" />
            Load
          </div>
          <div className="flex items-center gap-2">
            <div className="flex-1 h-1.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${
                  loadPercentage > 80 ? 'bg-red-500' :
                  loadPercentage > 50 ? 'bg-yellow-500' :
                  'bg-green-500'
                }`}
                style={{ width: `${loadPercentage}%` }}
              />
            </div>
            <span className="text-xs font-medium text-slate-600 dark:text-slate-300">
              {loadPercentage}%
            </span>
          </div>
        </div>

        {/* Tasks */}
        <div className="bg-light-hover dark:bg-dark-hover rounded-lg p-2">
          <div className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400 mb-1">
            <Zap className="w-3 h-3" />
            Tasks
          </div>
          <div className="flex items-center gap-2">
            <div className="flex-1 h-1.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${
                  capacityUsed > 80 ? 'bg-red-500' :
                  capacityUsed > 50 ? 'bg-yellow-500' :
                  'bg-cyan-500'
                }`}
                style={{ width: `${capacityUsed}%` }}
              />
            </div>
            <span className="text-xs font-medium text-slate-600 dark:text-slate-300">
              {agent.current_tasks}/{agent.max_tasks}
            </span>
          </div>
        </div>
      </div>

      {/* Capabilities */}
      {agent.capabilities.length > 0 && (
        <div className="mb-3">
          <div className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400 mb-1.5">
            <Zap className="w-3 h-3" />
            Capabilities
          </div>
          <div className="flex flex-wrap gap-1">
            {agent.capabilities.slice(0, 4).map((cap) => (
              <span
                key={cap}
                className="text-[10px] px-1.5 py-0.5 bg-cyan-500/10 text-cyan-400 rounded"
              >
                {cap}
              </span>
            ))}
            {agent.capabilities.length > 4 && (
              <span className="text-[10px] px-1.5 py-0.5 bg-slate-500/10 text-slate-400 rounded">
                +{agent.capabilities.length - 4} more
              </span>
            )}
          </div>
        </div>
      )}

      {/* Network Zones */}
      {agent.network_zones.length > 0 && (
        <div className="mb-3">
          <div className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400 mb-1.5">
            <Network className="w-3 h-3" />
            Network Zones
          </div>
          <div className="flex flex-wrap gap-1">
            {agent.network_zones.map((zone) => (
              <span
                key={zone}
                className="text-[10px] px-1.5 py-0.5 bg-purple-500/10 text-purple-400 rounded"
              >
                {zone}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Footer */}
      <div className="flex items-center justify-between pt-3 border-t border-light-border dark:border-dark-border text-xs text-slate-500 dark:text-slate-400">
        <div className="flex items-center gap-1">
          <Clock className="w-3 h-3" />
          {formatLastSeen(agent.last_seen)}
        </div>
        <div className="flex items-center gap-1">
          <span className="text-slate-400">v{agent.protocol_version}</span>
        </div>
      </div>
    </div>
  );
};

export { MeshAgentCard };
export default MeshAgentCard;
