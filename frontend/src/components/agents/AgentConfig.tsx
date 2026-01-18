import React, { useState } from 'react';
import {
  Settings,
  Server,
  Network,
  Save,
  X,
} from 'lucide-react';
import { Button } from '../ui/Button';
import type {
  ClusterConfig,
  CreateMeshConfigRequest,
  UpdateMeshConfigRequest,
  AgentMeshConfig,
} from '../../types/agents';

interface AgentConfigProps {
  existingConfig?: AgentMeshConfig;
  agentId: string;
  onSave: (config: CreateMeshConfigRequest | UpdateMeshConfigRequest) => void;
  onCancel: () => void;
  isLoading?: boolean;
}

interface ClusterConfigFormProps {
  config: Partial<ClusterConfig>;
  onChange: (config: Partial<ClusterConfig>) => void;
}

const ClusterConfigForm: React.FC<ClusterConfigFormProps> = ({ config, onChange }) => {
  return (
    <div className="space-y-4">
      <h4 className="font-medium text-slate-900 dark:text-white flex items-center gap-2">
        <Settings className="w-4 h-4" />
        Cluster Configuration
      </h4>

      <div className="grid grid-cols-2 gap-4">
        {/* Quorum Size */}
        <div>
          <label className="block text-sm text-slate-600 dark:text-slate-400 mb-1">
            Min Quorum Size
          </label>
          <input
            type="number"
            min={1}
            value={config.min_quorum_size ?? 1}
            onChange={(e) => onChange({ ...config, min_quorum_size: parseInt(e.target.value) || 1 })}
            className="w-full px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary/50"
          />
        </div>

        {/* Heartbeat Interval */}
        <div>
          <label className="block text-sm text-slate-600 dark:text-slate-400 mb-1">
            Heartbeat Interval (secs)
          </label>
          <input
            type="number"
            min={1}
            value={config.heartbeat_interval_secs ?? 10}
            onChange={(e) => onChange({ ...config, heartbeat_interval_secs: parseInt(e.target.value) || 10 })}
            className="w-full px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary/50"
          />
        </div>

        {/* Peer Timeout */}
        <div>
          <label className="block text-sm text-slate-600 dark:text-slate-400 mb-1">
            Peer Timeout (secs)
          </label>
          <input
            type="number"
            min={1}
            value={config.peer_timeout_secs ?? 30}
            onChange={(e) => onChange({ ...config, peer_timeout_secs: parseInt(e.target.value) || 30 })}
            className="w-full px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary/50"
          />
        </div>

        {/* Gossip Fanout */}
        <div>
          <label className="block text-sm text-slate-600 dark:text-slate-400 mb-1">
            Gossip Fanout
          </label>
          <input
            type="number"
            min={1}
            value={config.gossip_fanout ?? 3}
            onChange={(e) => onChange({ ...config, gossip_fanout: parseInt(e.target.value) || 3 })}
            className="w-full px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary/50"
          />
        </div>

        {/* Max Steal Batch */}
        <div>
          <label className="block text-sm text-slate-600 dark:text-slate-400 mb-1">
            Max Steal Batch
          </label>
          <input
            type="number"
            min={1}
            value={config.max_steal_batch ?? 5}
            onChange={(e) => onChange({ ...config, max_steal_batch: parseInt(e.target.value) || 5 })}
            className="w-full px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary/50"
          />
        </div>

        {/* Registry URL */}
        <div className="col-span-2">
          <label className="block text-sm text-slate-600 dark:text-slate-400 mb-1">
            Registry URL (optional)
          </label>
          <input
            type="url"
            value={config.registry_url ?? ''}
            onChange={(e) => onChange({ ...config, registry_url: e.target.value || null })}
            placeholder="https://heroforge.example.com"
            className="w-full px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary/50"
          />
        </div>
      </div>

      {/* Toggle Options */}
      <div className="flex flex-wrap gap-4">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={config.auto_elect_leader ?? true}
            onChange={(e) => onChange({ ...config, auto_elect_leader: e.target.checked })}
            className="w-4 h-4 rounded border-gray-300 dark:border-gray-600"
          />
          <span className="text-sm text-slate-700 dark:text-slate-300">Auto Elect Leader</span>
        </label>

        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enable_work_stealing ?? true}
            onChange={(e) => onChange({ ...config, enable_work_stealing: e.target.checked })}
            className="w-4 h-4 rounded border-gray-300 dark:border-gray-600"
          />
          <span className="text-sm text-slate-700 dark:text-slate-300">Work Stealing</span>
        </label>

        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enable_gossip ?? true}
            onChange={(e) => onChange({ ...config, enable_gossip: e.target.checked })}
            className="w-4 h-4 rounded border-gray-300 dark:border-gray-600"
          />
          <span className="text-sm text-slate-700 dark:text-slate-300">Gossip Protocol</span>
        </label>

        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enable_mdns ?? true}
            onChange={(e) => onChange({ ...config, enable_mdns: e.target.checked })}
            className="w-4 h-4 rounded border-gray-300 dark:border-gray-600"
          />
          <span className="text-sm text-slate-700 dark:text-slate-300">mDNS Discovery</span>
        </label>
      </div>
    </div>
  );
};

const AgentConfig: React.FC<AgentConfigProps> = ({
  existingConfig,
  agentId,
  onSave,
  onCancel,
  isLoading = false,
}) => {
  const [enabled, setEnabled] = useState(existingConfig?.enabled ?? true);
  const [meshPort, setMeshPort] = useState(existingConfig?.mesh_port ?? 9876);
  const [externalAddress, setExternalAddress] = useState(existingConfig?.external_address ?? '');
  const [clusterId, setClusterId] = useState(existingConfig?.cluster_id ?? '');
  const [clusterRole, setClusterRole] = useState(existingConfig?.cluster_role ?? 'member');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const config: CreateMeshConfigRequest | UpdateMeshConfigRequest = existingConfig
      ? {
          enabled,
          mesh_port: meshPort,
          external_address: externalAddress || undefined,
          cluster_id: clusterId || undefined,
          cluster_role: clusterRole || undefined,
        }
      : {
          agent_id: agentId,
          enabled,
          mesh_port: meshPort,
          external_address: externalAddress || undefined,
          cluster_id: clusterId || undefined,
        };

    onSave(config);
  };

  return (
    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
      {/* Header */}
      <div className="p-4 border-b border-light-border dark:border-dark-border flex items-center justify-between">
        <h3 className="font-semibold text-slate-900 dark:text-white flex items-center gap-2">
          <Settings className="w-5 h-5 text-primary" />
          {existingConfig ? 'Edit Mesh Configuration' : 'Create Mesh Configuration'}
        </h3>
        <button
          onClick={onCancel}
          className="p-1 hover:bg-light-hover dark:hover:bg-dark-hover rounded"
        >
          <X className="w-5 h-5 text-slate-400" />
        </button>
      </div>

      <form onSubmit={handleSubmit} className="p-4 space-y-6">
        {/* Basic Settings */}
        <div className="space-y-4">
          <h4 className="font-medium text-slate-900 dark:text-white flex items-center gap-2">
            <Server className="w-4 h-4" />
            Basic Settings
          </h4>

          {/* Enabled Toggle */}
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="w-5 h-5 rounded border-gray-300 dark:border-gray-600"
            />
            <div>
              <span className="font-medium text-slate-900 dark:text-white">Enable Mesh Networking</span>
              <p className="text-sm text-slate-500 dark:text-slate-400">
                Allow this agent to participate in the mesh network
              </p>
            </div>
          </label>

          <div className="grid grid-cols-2 gap-4">
            {/* Mesh Port */}
            <div>
              <label className="block text-sm text-slate-600 dark:text-slate-400 mb-1">
                Mesh Port
              </label>
              <input
                type="number"
                min={1}
                max={65535}
                value={meshPort}
                onChange={(e) => setMeshPort(parseInt(e.target.value) || 9876)}
                className="w-full px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary/50"
              />
              <p className="text-xs text-slate-400 mt-1">Default: 9876</p>
            </div>

            {/* External Address */}
            <div>
              <label className="block text-sm text-slate-600 dark:text-slate-400 mb-1">
                External Address (optional)
              </label>
              <input
                type="text"
                value={externalAddress}
                onChange={(e) => setExternalAddress(e.target.value)}
                placeholder="e.g., 10.0.0.5"
                className="w-full px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary/50"
              />
              <p className="text-xs text-slate-400 mt-1">Override auto-detected address</p>
            </div>
          </div>
        </div>

        {/* Cluster Settings */}
        <div className="space-y-4">
          <h4 className="font-medium text-slate-900 dark:text-white flex items-center gap-2">
            <Network className="w-4 h-4" />
            Cluster Settings
          </h4>

          <div className="grid grid-cols-2 gap-4">
            {/* Cluster ID */}
            <div>
              <label className="block text-sm text-slate-600 dark:text-slate-400 mb-1">
                Cluster ID (optional)
              </label>
              <input
                type="text"
                value={clusterId}
                onChange={(e) => setClusterId(e.target.value)}
                placeholder="Leave empty for standalone"
                className="w-full px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary/50"
              />
            </div>

            {/* Cluster Role */}
            <div>
              <label className="block text-sm text-slate-600 dark:text-slate-400 mb-1">
                Cluster Role
              </label>
              <select
                value={clusterRole}
                onChange={(e) => setClusterRole(e.target.value)}
                className="w-full px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary/50"
              >
                <option value="member">Member</option>
                <option value="leader">Leader</option>
              </select>
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-end gap-3 pt-4 border-t border-light-border dark:border-dark-border">
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
          <Button type="submit" loading={isLoading}>
            <Save className="w-4 h-4 mr-2" />
            Save Configuration
          </Button>
        </div>
      </form>
    </div>
  );
};

// Cluster Configuration Form Component (for creating/editing clusters)
interface CreateClusterFormProps {
  onSubmit: (data: { name: string; description?: string; config?: Partial<ClusterConfig> }) => void;
  onCancel: () => void;
  isLoading?: boolean;
  existingCluster?: { name: string; description?: string | null; config?: ClusterConfig };
}

export const CreateClusterForm: React.FC<CreateClusterFormProps> = ({
  onSubmit,
  onCancel,
  isLoading = false,
  existingCluster,
}) => {
  const [name, setName] = useState(existingCluster?.name ?? '');
  const [description, setDescription] = useState(existingCluster?.description ?? '');
  const [config, setConfig] = useState<Partial<ClusterConfig>>(existingCluster?.config ?? {});

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      name,
      description: description || undefined,
      config: Object.keys(config).length > 0 ? config : undefined,
    });
  };

  return (
    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
      <div className="p-4 border-b border-light-border dark:border-dark-border flex items-center justify-between">
        <h3 className="font-semibold text-slate-900 dark:text-white flex items-center gap-2">
          <Network className="w-5 h-5 text-primary" />
          {existingCluster ? 'Edit Cluster' : 'Create New Cluster'}
        </h3>
        <button
          onClick={onCancel}
          className="p-1 hover:bg-light-hover dark:hover:bg-dark-hover rounded"
        >
          <X className="w-5 h-5 text-slate-400" />
        </button>
      </div>

      <form onSubmit={handleSubmit} className="p-4 space-y-6">
        {/* Basic Info */}
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-slate-600 dark:text-slate-400 mb-1">
              Cluster Name *
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              placeholder="e.g., Production Scanners"
              className="w-full px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary/50"
            />
          </div>

          <div>
            <label className="block text-sm text-slate-600 dark:text-slate-400 mb-1">
              Description (optional)
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
              placeholder="Describe the purpose of this cluster..."
              className="w-full px-3 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary/50"
            />
          </div>
        </div>

        {/* Cluster Configuration */}
        <ClusterConfigForm config={config} onChange={setConfig} />

        {/* Actions */}
        <div className="flex items-center justify-end gap-3 pt-4 border-t border-light-border dark:border-dark-border">
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
          <Button type="submit" loading={isLoading} disabled={!name.trim()}>
            <Save className="w-4 h-4 mr-2" />
            {existingCluster ? 'Update Cluster' : 'Create Cluster'}
          </Button>
        </div>
      </form>
    </div>
  );
};

export { AgentConfig, ClusterConfigForm };
export default AgentConfig;
