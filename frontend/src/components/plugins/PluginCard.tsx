import React from 'react';
import type { Plugin, PluginType, PluginStatus } from '../../types/plugins';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import {
  Scan,
  Shield,
  FileText,
  Plug,
  Power,
  PowerOff,
  Trash2,
  Settings,
  AlertCircle,
  Loader2,
  Clock,
} from 'lucide-react';

interface PluginCardProps {
  plugin: Plugin;
  onEnable: (id: string) => void;
  onDisable: (id: string) => void;
  onUninstall: (id: string) => void;
  onSettings: (id: string) => void;
  isLoading?: boolean;
}

const getPluginTypeIcon = (type: PluginType) => {
  switch (type) {
    case 'scanner':
      return <Scan className="h-5 w-5" />;
    case 'detector':
      return <Shield className="h-5 w-5" />;
    case 'reporter':
      return <FileText className="h-5 w-5" />;
    case 'integration':
      return <Plug className="h-5 w-5" />;
    default:
      return <Plug className="h-5 w-5" />;
  }
};

const getPluginTypeBadgeVariant = (type: PluginType): 'primary' | 'success' | 'warning' | 'info' => {
  switch (type) {
    case 'scanner':
      return 'primary';
    case 'detector':
      return 'warning';
    case 'reporter':
      return 'info';
    case 'integration':
      return 'success';
    default:
      return 'primary';
  }
};

const getStatusBadge = (status: PluginStatus) => {
  switch (status) {
    case 'enabled':
      return (
        <Badge variant="success" className="flex items-center gap-1">
          <Power className="h-3 w-3" />
          Enabled
        </Badge>
      );
    case 'disabled':
      return (
        <Badge variant="secondary" className="flex items-center gap-1">
          <PowerOff className="h-3 w-3" />
          Disabled
        </Badge>
      );
    case 'error':
      return (
        <Badge variant="danger" className="flex items-center gap-1">
          <AlertCircle className="h-3 w-3" />
          Error
        </Badge>
      );
    case 'installing':
      return (
        <Badge variant="info" className="flex items-center gap-1">
          <Loader2 className="h-3 w-3 animate-spin" />
          Installing
        </Badge>
      );
    case 'updating':
      return (
        <Badge variant="info" className="flex items-center gap-1">
          <Loader2 className="h-3 w-3 animate-spin" />
          Updating
        </Badge>
      );
    default:
      return <Badge variant="secondary">{status}</Badge>;
  }
};

const PluginCard: React.FC<PluginCardProps> = ({
  plugin,
  onEnable,
  onDisable,
  onUninstall,
  onSettings,
  isLoading,
}) => {
  const isEnabled = plugin.status === 'enabled';
  const isOperational = plugin.status === 'enabled' || plugin.status === 'disabled';

  return (
    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4 hover:border-primary/50 transition-colors">
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-primary/10 text-primary">
            {getPluginTypeIcon(plugin.plugin_type)}
          </div>
          <div>
            <h3 className="font-semibold text-slate-900 dark:text-white">{plugin.name}</h3>
            <p className="text-sm text-slate-500 dark:text-slate-400">v{plugin.version}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {getStatusBadge(plugin.status)}
        </div>
      </div>

      {/* Description */}
      <p className="text-sm text-slate-600 dark:text-slate-400 mb-3 line-clamp-2">
        {plugin.description || 'No description provided.'}
      </p>

      {/* Error message if any */}
      {plugin.status === 'error' && plugin.error_message && (
        <div className="mb-3 p-2 bg-red-500/10 border border-red-500/30 rounded text-sm text-red-500">
          <div className="flex items-start gap-2">
            <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
            <span>{plugin.error_message}</span>
          </div>
        </div>
      )}

      {/* Meta info */}
      <div className="flex items-center gap-4 mb-4 text-xs text-slate-500 dark:text-slate-400">
        <div className="flex items-center gap-1">
          <Badge variant={getPluginTypeBadgeVariant(plugin.plugin_type)} size="sm">
            {plugin.plugin_type}
          </Badge>
        </div>
        <div className="flex items-center gap-1">
          <span>by {plugin.author}</span>
        </div>
        <div className="flex items-center gap-1">
          <Clock className="h-3 w-3" />
          <span>{new Date(plugin.installed_at).toLocaleDateString()}</span>
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 pt-3 border-t border-light-border dark:border-dark-border">
        {isOperational && (
          <>
            {isEnabled ? (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => onDisable(plugin.id)}
                disabled={isLoading}
                className="flex items-center gap-1"
              >
                <PowerOff className="h-4 w-4" />
                Disable
              </Button>
            ) : (
              <Button
                variant="primary"
                size="sm"
                onClick={() => onEnable(plugin.id)}
                disabled={isLoading}
                className="flex items-center gap-1"
              >
                <Power className="h-4 w-4" />
                Enable
              </Button>
            )}
          </>
        )}

        <Button
          variant="ghost"
          size="sm"
          onClick={() => onSettings(plugin.id)}
          className="flex items-center gap-1"
        >
          <Settings className="h-4 w-4" />
          Settings
        </Button>

        <Button
          variant="ghost"
          size="sm"
          onClick={() => onUninstall(plugin.id)}
          disabled={isLoading}
          className="flex items-center gap-1 text-red-500 hover:text-red-600 hover:bg-red-500/10"
        >
          <Trash2 className="h-4 w-4" />
          Uninstall
        </Button>
      </div>
    </div>
  );
};

export default PluginCard;
