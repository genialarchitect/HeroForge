import React, { useState } from 'react';
import {
  Network,
  Server,
  Wifi,
  WifiOff,
  Plus,
  Trash2,
  Users,
  Settings,
  ChevronDown,
  ChevronRight,
  AlertCircle,
  CheckCircle,
  Clock,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { agentAPI } from '../../services/api';
import Button from '../ui/Button';
import type {
  AgentMeshPeerData,
  MeshClusterWithMembers,
  AgentWithGroups,
  CreateMeshClusterRequest,
} from '../../types';

interface MeshTopologyProps {
  peerData: AgentMeshPeerData[];
  clusters: MeshClusterWithMembers[];
  agents: AgentWithGroups[];
  onRefresh: () => void;
}

const MeshTopology: React.FC<MeshTopologyProps> = ({
  peerData,
  clusters,
  agents,
  onRefresh,
}) => {
  const [showCreateCluster, setShowCreateCluster] = useState(false);
  const [clusterName, setClusterName] = useState('');
  const [clusterDescription, setClusterDescription] = useState('');
  const [creatingCluster, setCreatingCluster] = useState(false);
  const [expandedClusters, setExpandedClusters] = useState<Set<string>>(new Set());
  const [selectedAgentForCluster, setSelectedAgentForCluster] = useState<string | null>(null);
  const [addingToCluster, setAddingToCluster] = useState<string | null>(null);

  const toggleClusterExpand = (clusterId: string) => {
    const newExpanded = new Set(expandedClusters);
    if (newExpanded.has(clusterId)) {
      newExpanded.delete(clusterId);
    } else {
      newExpanded.add(clusterId);
    }
    setExpandedClusters(newExpanded);
  };

  const handleCreateCluster = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!clusterName.trim()) {
      toast.error('Cluster name is required');
      return;
    }

    setCreatingCluster(true);
    try {
      const data: CreateMeshClusterRequest = {
        name: clusterName.trim(),
        description: clusterDescription.trim() || undefined,
      };
      await agentAPI.mesh.createCluster(data);
      toast.success('Cluster created successfully');
      setClusterName('');
      setClusterDescription('');
      setShowCreateCluster(false);
      onRefresh();
    } catch (error: unknown) {
      const err = error as { response?: { data?: { message?: string } } };
      toast.error(err.response?.data?.message || 'Failed to create cluster');
    } finally {
      setCreatingCluster(false);
    }
  };

  const handleDeleteCluster = async (clusterId: string) => {
    if (!confirm('Are you sure you want to delete this cluster?')) return;

    try {
      await agentAPI.mesh.deleteCluster(clusterId);
      toast.success('Cluster deleted');
      onRefresh();
    } catch (error: unknown) {
      const err = error as { response?: { data?: { message?: string } } };
      toast.error(err.response?.data?.message || 'Failed to delete cluster');
    }
  };

  const handleAddAgentToCluster = async (clusterId: string, agentId: string) => {
    setAddingToCluster(clusterId);
    try {
      await agentAPI.mesh.addAgentToCluster(clusterId, agentId);
      toast.success('Agent added to cluster');
      setSelectedAgentForCluster(null);
      onRefresh();
    } catch (error: unknown) {
      const err = error as { response?: { data?: { message?: string } } };
      toast.error(err.response?.data?.message || 'Failed to add agent to cluster');
    } finally {
      setAddingToCluster(null);
    }
  };

  const handleRemoveAgentFromCluster = async (clusterId: string, agentId: string) => {
    try {
      await agentAPI.mesh.removeAgentFromCluster(clusterId, agentId);
      toast.success('Agent removed from cluster');
      onRefresh();
    } catch (error: unknown) {
      const err = error as { response?: { data?: { message?: string } } };
      toast.error(err.response?.data?.message || 'Failed to remove agent from cluster');
    }
  };

  const getAvailableAgentsForCluster = (cluster: MeshClusterWithMembers) => {
    const memberIds = new Set(cluster.members.map((m) => m.id));
    return agents.filter((a) => !memberIds.has(a.id) && a.status !== 'disabled');
  };

  const getConnectionStatusColor = (status: string) => {
    switch (status) {
      case 'connected':
        return 'text-green-500';
      case 'connecting':
        return 'text-yellow-500';
      case 'disconnected':
        return 'text-gray-500';
      case 'error':
        return 'text-red-500';
      default:
        return 'text-gray-500';
    }
  };

  const getConnectionStatusIcon = (status: string) => {
    switch (status) {
      case 'connected':
        return <CheckCircle className="h-4 w-4" />;
      case 'connecting':
        return <Clock className="h-4 w-4" />;
      case 'disconnected':
        return <WifiOff className="h-4 w-4" />;
      case 'error':
        return <AlertCircle className="h-4 w-4" />;
      default:
        return <WifiOff className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Clusters Section */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
            <Users className="h-5 w-5 text-primary" />
            Mesh Clusters
          </h3>
          <Button size="sm" onClick={() => setShowCreateCluster(true)}>
            <Plus className="h-4 w-4 mr-1" />
            New Cluster
          </Button>
        </div>

        {/* Create Cluster Form */}
        {showCreateCluster && (
          <form
            onSubmit={handleCreateCluster}
            className="mb-4 p-4 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg"
          >
            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Cluster Name
                </label>
                <input
                  type="text"
                  value={clusterName}
                  onChange={(e) => setClusterName(e.target.value)}
                  placeholder="e.g., Production Scanners"
                  className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Description
                </label>
                <input
                  type="text"
                  value={clusterDescription}
                  onChange={(e) => setClusterDescription(e.target.value)}
                  placeholder="Optional description"
                  className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setShowCreateCluster(false)}
                disabled={creatingCluster}
              >
                Cancel
              </Button>
              <Button type="submit" size="sm" loading={creatingCluster}>
                Create Cluster
              </Button>
            </div>
          </form>
        )}

        {/* Clusters List */}
        {clusters.length === 0 ? (
          <div className="text-center py-8 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
            <Network className="h-12 w-12 text-slate-400 mx-auto mb-3" />
            <p className="text-slate-600 dark:text-slate-400">No clusters configured</p>
            <p className="text-sm text-slate-500 dark:text-slate-500 mt-1">
              Create a cluster to organize agents into mesh networks
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {clusters.map((cluster) => (
              <div
                key={cluster.id}
                className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden"
              >
                {/* Cluster Header */}
                <div
                  className="flex items-center justify-between p-4 cursor-pointer hover:bg-light-hover dark:hover:bg-dark-hover"
                  onClick={() => toggleClusterExpand(cluster.id)}
                >
                  <div className="flex items-center gap-3">
                    <button className="p-1">
                      {expandedClusters.has(cluster.id) ? (
                        <ChevronDown className="h-4 w-4 text-slate-500" />
                      ) : (
                        <ChevronRight className="h-4 w-4 text-slate-500" />
                      )}
                    </button>
                    <div className="p-2 bg-purple-500/10 rounded-lg">
                      <Network className="h-5 w-5 text-purple-500" />
                    </div>
                    <div>
                      <h4 className="font-medium text-slate-900 dark:text-white">
                        {cluster.name}
                      </h4>
                      {cluster.description && (
                        <p className="text-sm text-slate-500 dark:text-slate-400">
                          {cluster.description}
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <span className="text-sm text-slate-500 dark:text-slate-400">
                      {cluster.member_count} agent{cluster.member_count !== 1 ? 's' : ''}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDeleteCluster(cluster.id);
                      }}
                      className="p-1 hover:bg-red-500/10 rounded text-red-500"
                      title="Delete cluster"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                {/* Cluster Members */}
                {expandedClusters.has(cluster.id) && (
                  <div className="border-t border-light-border dark:border-dark-border p-4">
                    {cluster.members.length === 0 ? (
                      <p className="text-sm text-slate-500 dark:text-slate-400 text-center py-4">
                        No agents in this cluster
                      </p>
                    ) : (
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mb-4">
                        {cluster.members.map((member) => (
                          <div
                            key={member.id}
                            className="flex items-center justify-between p-3 bg-light-bg dark:bg-dark-bg rounded-lg"
                          >
                            <div className="flex items-center gap-2">
                              {member.status === 'online' || member.status === 'busy' ? (
                                <Wifi className="h-4 w-4 text-green-500" />
                              ) : (
                                <WifiOff className="h-4 w-4 text-gray-500" />
                              )}
                              <span className="text-sm font-medium text-slate-900 dark:text-white">
                                {member.name}
                              </span>
                            </div>
                            <button
                              onClick={() =>
                                handleRemoveAgentFromCluster(cluster.id, member.id)
                              }
                              className="p-1 hover:bg-red-500/10 rounded text-red-500"
                              title="Remove from cluster"
                            >
                              <Trash2 className="h-3 w-3" />
                            </button>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Add agent to cluster */}
                    <div className="flex items-center gap-2">
                      <select
                        value={selectedAgentForCluster || ''}
                        onChange={(e) => setSelectedAgentForCluster(e.target.value)}
                        className="flex-1 px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-sm text-slate-900 dark:text-white"
                      >
                        <option value="">Select an agent to add...</option>
                        {getAvailableAgentsForCluster(cluster).map((agent) => (
                          <option key={agent.id} value={agent.id}>
                            {agent.name} ({agent.status})
                          </option>
                        ))}
                      </select>
                      <Button
                        size="sm"
                        onClick={() =>
                          selectedAgentForCluster &&
                          handleAddAgentToCluster(cluster.id, selectedAgentForCluster)
                        }
                        disabled={!selectedAgentForCluster || addingToCluster === cluster.id}
                        loading={addingToCluster === cluster.id}
                      >
                        <Plus className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Peer Connections Section */}
      <div>
        <h3 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2 mb-4">
          <Wifi className="h-5 w-5 text-primary" />
          Peer Connections
        </h3>

        {peerData.length === 0 ? (
          <div className="text-center py-8 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
            <Server className="h-12 w-12 text-slate-400 mx-auto mb-3" />
            <p className="text-slate-600 dark:text-slate-400">No mesh-enabled agents</p>
            <p className="text-sm text-slate-500 dark:text-slate-500 mt-1">
              Enable mesh networking on agents to see peer connections
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {peerData.map((agent) => (
              <div
                key={agent.agent_id}
                className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4"
              >
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-green-500/10 rounded-lg">
                      <Server className="h-5 w-5 text-green-500" />
                    </div>
                    <div>
                      <h4 className="font-medium text-slate-900 dark:text-white">
                        {agent.agent_name}
                      </h4>
                      <p className="text-sm text-slate-500 dark:text-slate-400">
                        Port {agent.mesh_config.mesh_port}
                        {agent.mesh_config.external_address &&
                          ` - ${agent.mesh_config.external_address}`}
                      </p>
                    </div>
                  </div>

                  {agent.stats && (
                    <div className="text-right text-sm text-slate-500 dark:text-slate-400">
                      <p>
                        {agent.stats.active_connections}/{agent.stats.total_connections} active
                      </p>
                      {agent.stats.avg_latency_ms !== null && (
                        <p>Avg latency: {agent.stats.avg_latency_ms.toFixed(1)}ms</p>
                      )}
                    </div>
                  )}
                </div>

                {agent.peers.length === 0 ? (
                  <p className="text-sm text-slate-500 dark:text-slate-400 text-center py-2">
                    No peer connections
                  </p>
                ) : (
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                    {agent.peers.map((peer) => (
                      <div
                        key={peer.id}
                        className="flex items-center gap-2 p-2 bg-light-bg dark:bg-dark-bg rounded"
                      >
                        <span className={getConnectionStatusColor(peer.connection_status)}>
                          {getConnectionStatusIcon(peer.connection_status)}
                        </span>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-slate-900 dark:text-white truncate">
                            {peer.to_agent_id.slice(0, 8)}...
                          </p>
                          {peer.latency_ms !== null && (
                            <p className="text-xs text-slate-500 dark:text-slate-400">
                              {peer.latency_ms}ms
                            </p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default MeshTopology;
