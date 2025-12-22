import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Network,
  Server,
  Users,
  ListTodo,
  Plus,
  RefreshCw,
  Settings,
  Search,
  Radar,
  Activity,
  TrendingUp,
  Zap,
  AlertTriangle,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { Layout } from '../components/layout/Layout';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import {
  MeshAgentCard,
  ClusterStatus,
  TaskQueue,
  AgentConfig,
  CreateClusterForm,
} from '../components/agents';
import { agentsAPI } from '../services/agentsApi';
import type {
  PeerInfo,
  ClusterWithDetails,
  MeshDashboardStats,
  CreateClusterRequest,
  CreateMeshConfigRequest,
  UpdateMeshConfigRequest,
} from '../types/agents';

type TabType = 'dashboard' | 'agents' | 'clusters' | 'tasks';

export default function MeshAgentsPage() {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [showCreateCluster, setShowCreateCluster] = useState(false);
  const [showAgentConfig, setShowAgentConfig] = useState<string | null>(null);
  const [selectedCluster, setSelectedCluster] = useState<ClusterWithDetails | null>(null);
  const [editingCluster, setEditingCluster] = useState<ClusterWithDetails | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const queryClient = useQueryClient();

  // Fetch dashboard stats
  const { data: dashboardStats, isLoading: statsLoading } = useQuery({
    queryKey: ['meshDashboardStats'],
    queryFn: () => agentsAPI.getDashboardStats().then(res => res.data),
    refetchInterval: 10000, // Refresh every 10 seconds
  });

  // Fetch agents
  const { data: agentsData, isLoading: agentsLoading, refetch: refetchAgents } = useQuery({
    queryKey: ['meshAgents'],
    queryFn: () => agentsAPI.listAgents().then(res => res.data),
    refetchInterval: 15000,
  });

  // Fetch clusters
  const { data: clustersData, isLoading: clustersLoading, refetch: refetchClusters } = useQuery({
    queryKey: ['meshClusters'],
    queryFn: () => agentsAPI.listClusters().then(res => res.data),
    refetchInterval: 30000,
  });

  // Fetch task queue
  const { data: taskQueueData, isLoading: tasksLoading, refetch: refetchTasks } = useQuery({
    queryKey: ['meshTaskQueue'],
    queryFn: () => agentsAPI.getTaskQueue().then(res => res.data),
    refetchInterval: 5000,
  });

  // Create cluster mutation
  const createClusterMutation = useMutation({
    mutationFn: (data: CreateClusterRequest) => agentsAPI.createCluster(data).then(res => res.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['meshClusters'] });
      queryClient.invalidateQueries({ queryKey: ['meshDashboardStats'] });
      toast.success('Cluster created successfully');
      setShowCreateCluster(false);
    },
    onError: () => {
      toast.error('Failed to create cluster');
    },
  });

  // Delete cluster mutation
  const deleteClusterMutation = useMutation({
    mutationFn: (clusterId: string) => agentsAPI.deleteCluster(clusterId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['meshClusters'] });
      queryClient.invalidateQueries({ queryKey: ['meshDashboardStats'] });
      toast.success('Cluster deleted');
      setSelectedCluster(null);
    },
    onError: () => {
      toast.error('Failed to delete cluster');
    },
  });

  // Ping agent mutation
  const pingAgentMutation = useMutation({
    mutationFn: (agentId: string) => agentsAPI.pingAgent(agentId).then(res => res.data),
    onSuccess: (data) => {
      toast.success(`Agent responded in ${data.latency_ms}ms`);
      queryClient.invalidateQueries({ queryKey: ['meshAgents'] });
    },
    onError: () => {
      toast.error('Agent did not respond');
    },
  });

  // Remove agent mutation
  const removeAgentMutation = useMutation({
    mutationFn: (agentId: string) => agentsAPI.removeAgent(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['meshAgents'] });
      queryClient.invalidateQueries({ queryKey: ['meshDashboardStats'] });
      toast.success('Agent removed from mesh');
    },
    onError: () => {
      toast.error('Failed to remove agent');
    },
  });

  // Cancel task mutation
  const cancelTaskMutation = useMutation({
    mutationFn: (taskId: string) => agentsAPI.cancelTask(taskId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['meshTaskQueue'] });
      toast.success('Task cancelled');
    },
    onError: () => {
      toast.error('Failed to cancel task');
    },
  });

  // Retry task mutation
  const retryTaskMutation = useMutation({
    mutationFn: (taskId: string) => agentsAPI.retryTask(taskId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['meshTaskQueue'] });
      toast.success('Task queued for retry');
    },
    onError: () => {
      toast.error('Failed to retry task');
    },
  });

  // Trigger discovery mutation
  const triggerDiscoveryMutation = useMutation({
    mutationFn: () => agentsAPI.triggerDiscovery(),
    onSuccess: () => {
      toast.success('Discovery triggered');
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ['meshAgents'] });
      }, 2000);
    },
    onError: () => {
      toast.error('Failed to trigger discovery');
    },
  });

  // Elect leader mutation
  const electLeaderMutation = useMutation({
    mutationFn: (clusterId: string) => agentsAPI.triggerLeaderElection(clusterId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['meshClusters'] });
      toast.success('Leader election triggered');
    },
    onError: () => {
      toast.error('Failed to trigger leader election');
    },
  });

  // Update agent mesh config mutation
  const updateAgentConfigMutation = useMutation({
    mutationFn: ({ agentId, config }: { agentId: string; config: UpdateMeshConfigRequest }) =>
      agentsAPI.updateMeshConfig(agentId, config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['meshAgents'] });
      queryClient.invalidateQueries({ queryKey: ['meshDashboardStats'] });
      toast.success('Agent configuration saved');
      setShowAgentConfig(null);
    },
    onError: () => {
      toast.error('Failed to save agent configuration');
    },
  });

  // Update cluster mutation
  const updateClusterMutation = useMutation({
    mutationFn: ({ clusterId, data }: { clusterId: string; data: { name: string; description?: string } }) =>
      agentsAPI.updateCluster(clusterId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['meshClusters'] });
      queryClient.invalidateQueries({ queryKey: ['meshDashboardStats'] });
      toast.success('Cluster updated');
      setEditingCluster(null);
    },
    onError: () => {
      toast.error('Failed to update cluster');
    },
  });

  const agents = agentsData?.agents || [];
  const clusters = clustersData?.clusters || [];
  const tasks = taskQueueData?.tasks || [];

  // Filter agents by search query
  const filteredAgents = agents.filter(agent =>
    agent.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    agent.address.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const tabs: { id: TabType; label: string; icon: React.ReactNode; count?: number }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: <Activity className="w-4 h-4" /> },
    { id: 'agents', label: 'Agents', icon: <Server className="w-4 h-4" />, count: agents.length },
    { id: 'clusters', label: 'Clusters', icon: <Users className="w-4 h-4" />, count: clusters.length },
    { id: 'tasks', label: 'Task Queue', icon: <ListTodo className="w-4 h-4" />, count: tasks.length },
  ];

  const stats = dashboardStats;

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
              <Network className="w-8 h-8 text-cyan-400" />
              Distributed Scanning Mesh
            </h1>
            <p className="text-slate-500 dark:text-slate-400 mt-1">
              Manage distributed scanning agents, clusters, and task distribution
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              onClick={() => triggerDiscoveryMutation.mutate()}
              disabled={triggerDiscoveryMutation.isPending}
            >
              <Radar className={`w-4 h-4 mr-2 ${triggerDiscoveryMutation.isPending ? 'animate-pulse' : ''}`} />
              Discover Peers
            </Button>
            <Button onClick={() => setShowCreateCluster(true)}>
              <Plus className="w-4 h-4 mr-2" />
              New Cluster
            </Button>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-b border-light-border dark:border-dark-border">
          <nav className="flex gap-4">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
                }`}
              >
                {tab.icon}
                {tab.label}
                {tab.count !== undefined && (
                  <Badge variant="secondary" size="sm">{tab.count}</Badge>
                )}
              </button>
            ))}
          </nav>
        </div>

        {/* Dashboard Tab */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400 mb-2">
                  <Server className="w-4 h-4" />
                  Total Agents
                </div>
                <div className="text-3xl font-bold text-slate-900 dark:text-white">
                  {stats?.total_agents ?? 0}
                </div>
                <div className="mt-2 flex gap-2 text-xs">
                  <span className="text-green-400">{stats?.online_agents ?? 0} online</span>
                  <span className="text-yellow-400">{stats?.busy_agents ?? 0} busy</span>
                  <span className="text-slate-400">{stats?.offline_agents ?? 0} offline</span>
                </div>
              </div>

              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400 mb-2">
                  <Users className="w-4 h-4" />
                  Clusters
                </div>
                <div className="text-3xl font-bold text-slate-900 dark:text-white">
                  {stats?.total_clusters ?? 0}
                </div>
                <div className="mt-2 text-xs text-slate-400">
                  Avg load: {Math.round((stats?.average_cluster_load ?? 0) * 100)}%
                </div>
              </div>

              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400 mb-2">
                  <Zap className="w-4 h-4" />
                  Tasks
                </div>
                <div className="text-3xl font-bold text-slate-900 dark:text-white">
                  {stats?.total_tasks_running ?? 0}
                  <span className="text-lg font-normal text-slate-400">
                    /{stats?.total_tasks_queued ?? 0}
                  </span>
                </div>
                <div className="mt-2 text-xs text-slate-400">
                  running / queued
                </div>
              </div>

              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400 mb-2">
                  <TrendingUp className="w-4 h-4" />
                  Work Stealing
                </div>
                <div className="text-3xl font-bold text-slate-900 dark:text-white">
                  {stats?.work_stealing_stats?.tasks_delegated ?? 0}
                </div>
                <div className="mt-2 text-xs">
                  <span className="text-cyan-400">{stats?.work_stealing_stats?.tasks_stolen ?? 0} stolen</span>
                  <span className="text-slate-400 mx-1">|</span>
                  <span className="text-red-400">{stats?.work_stealing_stats?.delegation_failures ?? 0} failed</span>
                </div>
              </div>
            </div>

            {/* Quick Status */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Online Agents */}
              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
                <div className="p-4 border-b border-light-border dark:border-dark-border flex items-center justify-between">
                  <h3 className="font-semibold text-slate-900 dark:text-white">Online Agents</h3>
                  <Button size="sm" variant="ghost" onClick={() => setActiveTab('agents')}>
                    View All
                  </Button>
                </div>
                <div className="p-4 grid gap-3">
                  {agentsLoading ? (
                    <div className="flex justify-center py-4">
                      <RefreshCw className="w-6 h-6 text-slate-400 animate-spin" />
                    </div>
                  ) : agents.filter(a => a.status === 'online').length === 0 ? (
                    <div className="text-center py-4 text-slate-400">
                      No online agents
                    </div>
                  ) : (
                    agents
                      .filter(a => a.status === 'online')
                      .slice(0, 3)
                      .map(agent => (
                        <MeshAgentCard
                          key={agent.agent_id}
                          agent={agent}
                          showActions={false}
                          onClick={() => {
                            setShowAgentConfig(agent.agent_id);
                            setActiveTab('agents');
                          }}
                        />
                      ))
                  )}
                </div>
              </div>

              {/* Active Clusters */}
              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
                <div className="p-4 border-b border-light-border dark:border-dark-border flex items-center justify-between">
                  <h3 className="font-semibold text-slate-900 dark:text-white">Clusters</h3>
                  <Button size="sm" variant="ghost" onClick={() => setActiveTab('clusters')}>
                    View All
                  </Button>
                </div>
                <div className="p-4 space-y-3">
                  {clustersLoading ? (
                    <div className="flex justify-center py-4">
                      <RefreshCw className="w-6 h-6 text-slate-400 animate-spin" />
                    </div>
                  ) : clusters.length === 0 ? (
                    <div className="text-center py-4 text-slate-400">
                      <Users className="w-8 h-8 mx-auto mb-2 opacity-50" />
                      <p>No clusters configured</p>
                      <Button size="sm" className="mt-2" onClick={() => setShowCreateCluster(true)}>
                        Create Cluster
                      </Button>
                    </div>
                  ) : (
                    clusters.slice(0, 2).map(cluster => (
                      <div
                        key={cluster.id}
                        className="p-3 bg-light-hover dark:bg-dark-hover rounded-lg cursor-pointer hover:ring-1 ring-primary/50"
                        onClick={() => {
                          setSelectedCluster(cluster as ClusterWithDetails);
                          setActiveTab('clusters');
                        }}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-slate-900 dark:text-white">{cluster.name}</span>
                          <Badge variant="success" size="sm">Active</Badge>
                        </div>
                        {cluster.description && (
                          <p className="text-sm text-slate-400 mt-1 line-clamp-1">{cluster.description}</p>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>

            {/* Recent Tasks */}
            {tasks.length > 0 && (
              <div>
                <h3 className="font-semibold text-slate-900 dark:text-white mb-4">Recent Tasks</h3>
                <TaskQueue
                  tasks={tasks.slice(0, 5)}
                  agents={agents}
                  isLoading={tasksLoading}
                  onCancelTask={(id) => cancelTaskMutation.mutate(id)}
                  onRetryTask={(id) => retryTaskMutation.mutate(id)}
                />
              </div>
            )}
          </div>
        )}

        {/* Agents Tab */}
        {activeTab === 'agents' && (
          <div className="space-y-4">
            {/* Search */}
            <div className="flex items-center gap-4">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search agents..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary/50"
                />
              </div>
              <Button variant="outline" onClick={() => refetchAgents()}>
                <RefreshCw className="w-4 h-4 mr-2" />
                Refresh
              </Button>
            </div>

            {/* Agent Grid */}
            {agentsLoading ? (
              <div className="flex justify-center py-12">
                <RefreshCw className="w-8 h-8 text-slate-400 animate-spin" />
              </div>
            ) : filteredAgents.length === 0 ? (
              <div className="text-center py-12 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
                <Server className="w-12 h-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">
                  No Agents Found
                </h3>
                <p className="text-slate-400 mb-4">
                  {searchQuery
                    ? 'No agents match your search query'
                    : 'No agents are connected to the mesh network'}
                </p>
                <Button variant="outline" onClick={() => triggerDiscoveryMutation.mutate()}>
                  <Radar className="w-4 h-4 mr-2" />
                  Discover Peers
                </Button>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredAgents.map(agent => (
                  <MeshAgentCard
                    key={agent.agent_id}
                    agent={agent}
                    isLeader={clusters.some(c => c.leader_agent_id === agent.agent_id)}
                    onPing={() => pingAgentMutation.mutate(agent.agent_id)}
                    onRemove={() => {
                      if (confirm(`Remove agent "${agent.name}" from the mesh?`)) {
                        removeAgentMutation.mutate(agent.agent_id);
                      }
                    }}
                    onClick={() => setShowAgentConfig(agent.agent_id)}
                  />
                ))}
              </div>
            )}

            {/* Agent Config Modal */}
            {showAgentConfig && (
              <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
                <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto">
                  <AgentConfig
                    agentId={showAgentConfig}
                    existingConfig={undefined}
                    onSave={(config) => {
                      updateAgentConfigMutation.mutate({
                        agentId: showAgentConfig,
                        config: config as UpdateMeshConfigRequest,
                      });
                    }}
                    onCancel={() => setShowAgentConfig(null)}
                    isLoading={updateAgentConfigMutation.isPending}
                  />
                </div>
              </div>
            )}
          </div>
        )}

        {/* Clusters Tab */}
        {activeTab === 'clusters' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-slate-900 dark:text-white">
                Clusters ({clusters.length})
              </h3>
              <div className="flex gap-2">
                <Button variant="outline" onClick={() => refetchClusters()}>
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Refresh
                </Button>
                <Button onClick={() => setShowCreateCluster(true)}>
                  <Plus className="w-4 h-4 mr-2" />
                  New Cluster
                </Button>
              </div>
            </div>

            {clustersLoading ? (
              <div className="flex justify-center py-12">
                <RefreshCw className="w-8 h-8 text-slate-400 animate-spin" />
              </div>
            ) : clusters.length === 0 ? (
              <div className="text-center py-12 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
                <Users className="w-12 h-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">
                  No Clusters
                </h3>
                <p className="text-slate-400 mb-4">
                  Create a cluster to group agents and enable distributed task scheduling
                </p>
                <Button onClick={() => setShowCreateCluster(true)}>
                  <Plus className="w-4 h-4 mr-2" />
                  Create Your First Cluster
                </Button>
              </div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {clusters.map(cluster => (
                  <ClusterStatus
                    key={cluster.id}
                    cluster={cluster as ClusterWithDetails}
                    onViewDetails={() => setSelectedCluster(cluster as ClusterWithDetails)}
                    onEditConfig={() => setEditingCluster(cluster as ClusterWithDetails)}
                    onDelete={() => {
                      if (confirm(`Delete cluster "${cluster.name}"? Agents will be removed from the cluster.`)) {
                        deleteClusterMutation.mutate(cluster.id);
                      }
                    }}
                    onElectLeader={() => electLeaderMutation.mutate(cluster.id)}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tasks Tab */}
        {activeTab === 'tasks' && (
          <TaskQueue
            tasks={tasks}
            agents={agents}
            isLoading={tasksLoading}
            onCancelTask={(id) => cancelTaskMutation.mutate(id)}
            onRetryTask={(id) => retryTaskMutation.mutate(id)}
            onReassignTask={(taskId, agentId) => {
              agentsAPI.reassignTask(taskId, agentId).then(() => {
                queryClient.invalidateQueries({ queryKey: ['meshTaskQueue'] });
                toast.success('Task reassigned');
              }).catch(() => {
                toast.error('Failed to reassign task');
              });
            }}
            onBulkCancel={(ids) => {
              agentsAPI.bulkCancelTasks(ids).then(() => {
                queryClient.invalidateQueries({ queryKey: ['meshTaskQueue'] });
                toast.success(`${ids.length} tasks cancelled`);
              }).catch(() => {
                toast.error('Failed to cancel tasks');
              });
            }}
            onRefresh={() => refetchTasks()}
          />
        )}

        {/* Create Cluster Modal */}
        {showCreateCluster && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
            <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto">
              <CreateClusterForm
                onSubmit={(data) => createClusterMutation.mutate(data)}
                onCancel={() => setShowCreateCluster(false)}
                isLoading={createClusterMutation.isPending}
              />
            </div>
          </div>
        )}

        {/* Edit Cluster Modal */}
        {editingCluster && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
            <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto">
              <CreateClusterForm
                existingCluster={{
                  name: editingCluster.name,
                  description: editingCluster.description,
                  config: editingCluster.config,
                }}
                onSubmit={(data) => {
                  updateClusterMutation.mutate({
                    clusterId: editingCluster.id,
                    data: { name: data.name, description: data.description },
                  });
                }}
                onCancel={() => setEditingCluster(null)}
                isLoading={updateClusterMutation.isPending}
              />
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
