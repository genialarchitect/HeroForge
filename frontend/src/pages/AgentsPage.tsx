import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import {
  Server,
  Network,
  Folder,
  ListTodo,
  Plus,
  RefreshCw,
  Activity,
  Wifi,
  WifiOff,
  AlertCircle,
  Clock,
  CheckCircle,
  XCircle,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import Button from '../components/ui/Button';
import AgentCard from '../components/agents/AgentCard';
import RegisterAgentModal from '../components/agents/RegisterAgentModal';
import MeshTopology from '../components/agents/MeshTopology';
import AgentGroupManager from '../components/agents/AgentGroupManager';
import { agentAPI } from '../services/api';
import type {
  AgentWithGroups,
  AgentGroupWithCount,
  AgentStats,
  AgentTask,
  AgentMeshPeerData,
  MeshClusterWithMembers,
} from '../types';

type TabType = 'agents' | 'groups' | 'mesh' | 'tasks';

const AgentsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>('agents');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [showRegisterModal, setShowRegisterModal] = useState(false);

  // Data
  const [agents, setAgents] = useState<AgentWithGroups[]>([]);
  const [groups, setGroups] = useState<AgentGroupWithCount[]>([]);
  const [stats, setStats] = useState<AgentStats | null>(null);
  const [tasks, setTasks] = useState<AgentTask[]>([]);
  const [peerData, setPeerData] = useState<AgentMeshPeerData[]>([]);
  const [clusters, setClusters] = useState<MeshClusterWithMembers[]>([]);

  const loadData = async (showLoadingState = true) => {
    if (showLoadingState) {
      setLoading(true);
    } else {
      setRefreshing(true);
    }

    try {
      // Load all data in parallel
      const [agentsRes, groupsRes, statsRes, tasksRes, peersRes, clustersRes] = await Promise.all([
        agentAPI.list(),
        agentAPI.groups.list(),
        agentAPI.getStats(),
        agentAPI.tasks.list({ limit: 50 }),
        agentAPI.mesh.getPeers().catch(() => ({ data: [] })),
        agentAPI.mesh.getClusters().catch(() => ({ data: [] })),
      ]);

      setAgents(agentsRes.data);
      setGroups(groupsRes.data);
      setStats(statsRes.data);
      setTasks(tasksRes.data);
      setPeerData(peersRes.data);
      setClusters(clustersRes.data);
    } catch (error) {
      toast.error('Failed to load agent data');
      console.error(error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRotateToken = async (agent: AgentWithGroups) => {
    if (!confirm(`Are you sure you want to rotate the token for "${agent.name}"? The current token will be invalidated.`)) {
      return;
    }

    try {
      const response = await agentAPI.regenerateToken(agent.id);
      toast.success(`New token: ${response.data.token.slice(0, 20)}... (copy it now!)`);
      loadData(false);
    } catch (error: unknown) {
      const err = error as { response?: { data?: { message?: string } } };
      toast.error(err.response?.data?.message || 'Failed to rotate token');
    }
  };

  const handleDeleteAgent = async (agent: AgentWithGroups) => {
    if (!confirm(`Are you sure you want to delete agent "${agent.name}"?`)) {
      return;
    }

    try {
      await agentAPI.delete(agent.id);
      toast.success('Agent deleted');
      loadData(false);
    } catch (error: unknown) {
      const err = error as { response?: { data?: { message?: string } } };
      toast.error(err.response?.data?.message || 'Failed to delete agent');
    }
  };

  const getTaskStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'running':
        return <Activity className="h-4 w-4 text-blue-500 animate-pulse" />;
      case 'pending':
      case 'assigned':
        return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'failed':
      case 'cancelled':
      case 'timed_out':
        return <XCircle className="h-4 w-4 text-red-500" />;
      default:
        return <AlertCircle className="h-4 w-4 text-gray-500" />;
    }
  };

  const getTaskStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-500/10 text-green-700 dark:text-green-400';
      case 'running':
        return 'bg-blue-500/10 text-blue-700 dark:text-blue-400';
      case 'pending':
      case 'assigned':
        return 'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400';
      case 'failed':
      case 'cancelled':
      case 'timed_out':
        return 'bg-red-500/10 text-red-700 dark:text-red-400';
      default:
        return 'bg-gray-500/10 text-gray-700 dark:text-gray-400';
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleString();
  };

  const tabs = [
    { id: 'agents', label: 'Agents', icon: Server, count: agents.length },
    { id: 'groups', label: 'Groups', icon: Folder, count: groups.length },
    { id: 'mesh', label: 'Mesh', icon: Network, count: clusters.length },
    { id: 'tasks', label: 'Tasks', icon: ListTodo, count: tasks.length },
  ];

  return (
    <Layout>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
              <div className="p-2 bg-primary/10 rounded-lg">
                <Server className="h-6 w-6 text-primary" />
              </div>
              Distributed Scanning Agents
            </h1>
            <p className="text-slate-600 dark:text-slate-400 mt-1">
              Manage agents, groups, mesh networks, and distributed tasks
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => loadData(false)}
              disabled={refreshing}
            >
              <RefreshCw className={`h-4 w-4 mr-1 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setShowRegisterModal(true)}>
              <Plus className="h-4 w-4 mr-1" />
              Register Agent
            </Button>
          </div>
        </div>

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-4 gap-4 mb-6">
            <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-500/10 rounded-lg">
                  <Server className="h-5 w-5 text-blue-500" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900 dark:text-white">
                    {stats.total_agents}
                  </p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">Total Agents</p>
                </div>
              </div>
            </div>

            <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-green-500/10 rounded-lg">
                  <Wifi className="h-5 w-5 text-green-500" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900 dark:text-white">
                    {stats.online_agents}
                  </p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">Online</p>
                </div>
              </div>
            </div>

            <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-yellow-500/10 rounded-lg">
                  <Activity className="h-5 w-5 text-yellow-500" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900 dark:text-white">
                    {stats.busy_agents}
                  </p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">Busy</p>
                </div>
              </div>
            </div>

            <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-gray-500/10 rounded-lg">
                  <WifiOff className="h-5 w-5 text-gray-500" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900 dark:text-white">
                    {stats.offline_agents}
                  </p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">Offline</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="border-b border-light-border dark:border-dark-border mb-6">
          <nav className="flex gap-4">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as TabType)}
                  className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors ${
                    activeTab === tab.id
                      ? 'border-primary text-primary'
                      : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  {tab.label}
                  <span className="px-1.5 py-0.5 rounded text-xs bg-slate-100 dark:bg-slate-800">
                    {tab.count}
                  </span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Content */}
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin" />
          </div>
        ) : (
          <>
            {/* Agents Tab */}
            {activeTab === 'agents' && (
              <div>
                {agents.length === 0 ? (
                  <div className="text-center py-12 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
                    <Server className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                      No agents registered
                    </h3>
                    <p className="text-slate-600 dark:text-slate-400 mb-4">
                      Register an agent to start distributed scanning
                    </p>
                    <Button onClick={() => setShowRegisterModal(true)}>
                      <Plus className="h-4 w-4 mr-1" />
                      Register Agent
                    </Button>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {agents.map((agent) => (
                      <AgentCard
                        key={agent.id}
                        agent={agent}
                        onRotateToken={handleRotateToken}
                        onDelete={handleDeleteAgent}
                      />
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Groups Tab */}
            {activeTab === 'groups' && (
              <AgentGroupManager
                groups={groups}
                agents={agents}
                onRefresh={() => loadData(false)}
              />
            )}

            {/* Mesh Tab */}
            {activeTab === 'mesh' && (
              <MeshTopology
                peerData={peerData}
                clusters={clusters}
                agents={agents}
                onRefresh={() => loadData(false)}
              />
            )}

            {/* Tasks Tab */}
            {activeTab === 'tasks' && (
              <div>
                {tasks.length === 0 ? (
                  <div className="text-center py-12 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
                    <ListTodo className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                      No tasks found
                    </h3>
                    <p className="text-slate-600 dark:text-slate-400">
                      Tasks will appear here when you run distributed scans
                    </p>
                  </div>
                ) : (
                  <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden">
                    <table className="w-full">
                      <thead>
                        <tr className="bg-light-bg dark:bg-dark-bg border-b border-light-border dark:border-dark-border">
                          <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-400">
                            Status
                          </th>
                          <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-400">
                            Type
                          </th>
                          <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-400">
                            Targets
                          </th>
                          <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-400">
                            Agent
                          </th>
                          <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-400">
                            Priority
                          </th>
                          <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-400">
                            Created
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-light-border dark:divide-dark-border">
                        {tasks.map((task) => (
                          <tr key={task.id} className="hover:bg-light-hover dark:hover:bg-dark-hover">
                            <td className="px-4 py-3">
                              <span
                                className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium capitalize ${getTaskStatusColor(
                                  task.status
                                )}`}
                              >
                                {getTaskStatusIcon(task.status)}
                                {task.status}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-sm text-slate-900 dark:text-white">
                              {task.task_type}
                            </td>
                            <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-400 max-w-xs truncate">
                              {task.targets}
                            </td>
                            <td className="px-4 py-3 text-sm">
                              {task.agent_id ? (
                                <span className="text-slate-900 dark:text-white">
                                  {agents.find((a) => a.id === task.agent_id)?.name ||
                                    task.agent_id.slice(0, 8)}
                                </span>
                              ) : (
                                <span className="text-slate-500 dark:text-slate-400">
                                  {task.group_id ? 'Group' : 'Unassigned'}
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-400">
                              {task.priority}
                            </td>
                            <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-400">
                              {formatDate(task.created_at)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>

      {/* Register Agent Modal */}
      <RegisterAgentModal
        isOpen={showRegisterModal}
        onClose={() => setShowRegisterModal(false)}
        onSuccess={() => loadData(false)}
      />
    </Layout>
  );
};

export default AgentsPage;
