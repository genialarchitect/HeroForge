import React from 'react';
import {
  Server,
  Wifi,
  WifiOff,
  Clock,
  Cpu,
  HardDrive,
  MoreVertical,
  Key,
  Trash2,
  Settings,
  Network,
} from 'lucide-react';
import type { AgentWithGroups, AgentStatus } from '../../types';

interface AgentCardProps {
  agent: AgentWithGroups;
  onRotateToken?: (agent: AgentWithGroups) => void;
  onDelete?: (agent: AgentWithGroups) => void;
  onConfigure?: (agent: AgentWithGroups) => void;
  onViewDetails?: (agent: AgentWithGroups) => void;
}

const statusColors: Record<AgentStatus, { bg: string; text: string; dot: string }> = {
  online: { bg: 'bg-green-500/10', text: 'text-green-500', dot: 'bg-green-500' },
  busy: { bg: 'bg-yellow-500/10', text: 'text-yellow-500', dot: 'bg-yellow-500' },
  offline: { bg: 'bg-gray-500/10', text: 'text-gray-500', dot: 'bg-gray-500' },
  pending: { bg: 'bg-blue-500/10', text: 'text-blue-500', dot: 'bg-blue-500' },
  disabled: { bg: 'bg-red-500/10', text: 'text-red-500', dot: 'bg-red-500' },
};

const AgentCard: React.FC<AgentCardProps> = ({
  agent,
  onRotateToken,
  onDelete,
  onConfigure,
  onViewDetails,
}) => {
  const [showMenu, setShowMenu] = React.useState(false);
  const menuRef = React.useRef<HTMLDivElement>(null);
  const status = statusColors[agent.status] || statusColors.offline;

  React.useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setShowMenu(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const formatLastSeen = (lastSeen: string | null): string => {
    if (!lastSeen) return 'Never';
    const date = new Date(lastSeen);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return `${days}d ago`;
  };

  const parseCapabilities = (): string[] => {
    if (!agent.capabilities) return [];
    try {
      return JSON.parse(agent.capabilities);
    } catch {
      return [];
    }
  };

  const parseNetworkZones = (): string[] => {
    if (!agent.network_zones) return [];
    try {
      return JSON.parse(agent.network_zones);
    } catch {
      return [];
    }
  };

  const capabilities = parseCapabilities();
  const networkZones = parseNetworkZones();

  return (
    <div
      className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4 hover:shadow-lg transition-shadow cursor-pointer"
      onClick={() => onViewDetails?.(agent)}
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${status.bg}`}>
            {agent.status === 'online' || agent.status === 'busy' ? (
              <Wifi className={`h-5 w-5 ${status.text}`} />
            ) : (
              <WifiOff className={`h-5 w-5 ${status.text}`} />
            )}
          </div>
          <div>
            <h3 className="font-semibold text-slate-900 dark:text-white">{agent.name}</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {agent.hostname || agent.ip_address || 'Unknown host'}
            </p>
          </div>
        </div>

        {/* Status badge and menu */}
        <div className="flex items-center gap-2">
          <div className={`flex items-center gap-1.5 px-2 py-1 rounded-full ${status.bg}`}>
            <span className={`h-2 w-2 rounded-full ${status.dot} animate-pulse`} />
            <span className={`text-xs font-medium capitalize ${status.text}`}>{agent.status}</span>
          </div>

          <div className="relative" ref={menuRef}>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setShowMenu(!showMenu);
              }}
              className="p-1 hover:bg-light-hover dark:hover:bg-dark-hover rounded"
            >
              <MoreVertical className="h-4 w-4 text-slate-500" />
            </button>

            {showMenu && (
              <div className="absolute right-0 mt-1 w-48 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg shadow-lg py-1 z-50">
                {onConfigure && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onConfigure(agent);
                      setShowMenu(false);
                    }}
                    className="flex items-center gap-2 w-full px-3 py-2 text-sm text-slate-700 dark:text-slate-300 hover:bg-light-hover dark:hover:bg-dark-hover"
                  >
                    <Settings className="h-4 w-4" />
                    Configure
                  </button>
                )}
                {onRotateToken && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onRotateToken(agent);
                      setShowMenu(false);
                    }}
                    className="flex items-center gap-2 w-full px-3 py-2 text-sm text-slate-700 dark:text-slate-300 hover:bg-light-hover dark:hover:bg-dark-hover"
                  >
                    <Key className="h-4 w-4" />
                    Rotate Token
                  </button>
                )}
                {onDelete && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onDelete(agent);
                      setShowMenu(false);
                    }}
                    className="flex items-center gap-2 w-full px-3 py-2 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20"
                  >
                    <Trash2 className="h-4 w-4" />
                    Delete
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Description */}
      {agent.description && (
        <p className="text-sm text-slate-600 dark:text-slate-400 mb-3 line-clamp-2">
          {agent.description}
        </p>
      )}

      {/* Stats */}
      <div className="grid grid-cols-3 gap-3 mb-3">
        <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
          <Clock className="h-3.5 w-3.5" />
          <span>{formatLastSeen(agent.last_heartbeat_at)}</span>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
          <Server className="h-3.5 w-3.5" />
          <span>{agent.current_tasks}/{agent.max_concurrent_tasks} tasks</span>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
          <HardDrive className="h-3.5 w-3.5" />
          <span>{agent.version || 'Unknown'}</span>
        </div>
      </div>

      {/* Groups */}
      {agent.groups && agent.groups.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-3">
          {agent.groups.map((group) => (
            <span
              key={group.id}
              className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium"
              style={{
                backgroundColor: `${group.color}20`,
                color: group.color,
                borderColor: group.color,
                borderWidth: 1,
              }}
            >
              {group.name}
            </span>
          ))}
        </div>
      )}

      {/* Capabilities & Network Zones */}
      <div className="flex flex-wrap gap-1">
        {capabilities.slice(0, 3).map((cap) => (
          <span
            key={cap}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-blue-500/10 text-blue-600 dark:text-blue-400"
          >
            <Cpu className="h-3 w-3" />
            {cap}
          </span>
        ))}
        {networkZones.slice(0, 2).map((zone) => (
          <span
            key={zone}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-purple-500/10 text-purple-600 dark:text-purple-400"
          >
            <Network className="h-3 w-3" />
            {zone}
          </span>
        ))}
        {capabilities.length + networkZones.length > 5 && (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-500/10 text-gray-600 dark:text-gray-400">
            +{capabilities.length + networkZones.length - 5} more
          </span>
        )}
      </div>

      {/* Token prefix */}
      <div className="mt-3 pt-3 border-t border-light-border dark:border-dark-border">
        <div className="flex items-center justify-between text-xs">
          <span className="text-slate-500 dark:text-slate-400">Token prefix:</span>
          <code className="px-2 py-0.5 bg-slate-100 dark:bg-slate-800 rounded font-mono">
            {agent.token_prefix}...
          </code>
        </div>
      </div>
    </div>
  );
};

export default AgentCard;
