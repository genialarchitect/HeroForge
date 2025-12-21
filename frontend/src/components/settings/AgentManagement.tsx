import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { agentAPI } from '../../services/api';
import type {
  AgentWithGroups,
  AgentGroupWithCount,
  AgentStats,
  AgentStatus,
  RegisterAgentRequest,
} from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Input from '../ui/Input';
import LoadingSpinner from '../ui/LoadingSpinner';
import Badge from '../ui/Badge';
import {
  Cpu,
  Server,
  Plus,
  Trash2,
  RefreshCw,
  Edit2,
  Copy,
  Eye,
  EyeOff,
  Check,
  X,
  Network,
  Clock,
  Layers,
  Activity,
  AlertCircle,
  CheckCircle,
  XCircle,
  Settings,
  Info,
} from 'lucide-react';

const AgentManagement: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [agents, setAgents] = useState<AgentWithGroups[]>([]);
  const [groups, setGroups] = useState<AgentGroupWithCount[]>([]);
  const [stats, setStats] = useState<AgentStats | null>(null);
  const [showRegisterForm, setShowRegisterForm] = useState(false);
  const [showGroupForm, setShowGroupForm] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [creatingGroup, setCreatingGroup] = useState(false);
  const [newToken, setNewToken] = useState<string | null>(null);
  const [showToken, setShowToken] = useState(false);
  const [editingAgent, setEditingAgent] = useState<string | null>(null);
  const [editName, setEditName] = useState('');
  const [activeTab, setActiveTab] = useState<'agents' | 'groups'>('agents');

  const [registerForm, setRegisterForm] = useState<RegisterAgentRequest>({
    name: '',
    description: '',
    network_zones: [],
    max_concurrent_tasks: 1,
  });

  const [groupForm, setGroupForm] = useState({
    name: '',
    description: '',
    network_ranges: '',
    color: '#06b6d4',
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [agentsRes, groupsRes, statsRes] = await Promise.all([
        agentAPI.list(),
        agentAPI.groups.list(),
        agentAPI.getStats(),
      ]);
      setAgents(agentsRes.data);
      setGroups(groupsRes.data);
      setStats(statsRes.data);
    } catch (error) {
      console.error('Failed to load agent data:', error);
      toast.error('Failed to load agent data');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async () => {
    if (!registerForm.name.trim()) {
      toast.error('Agent name is required');
      return;
    }

    setRegistering(true);
    try {
      const response = await agentAPI.register({
        ...registerForm,
        network_zones: registerForm.network_zones?.filter(z => z.trim()),
      });
      setNewToken(response.data.token);
      toast.success('Agent registered successfully');
      setShowRegisterForm(false);
      setRegisterForm({
        name: '',
        description: '',
        network_zones: [],
        max_concurrent_tasks: 1,
      });
      await loadData();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to register agent');
    } finally {
      setRegistering(false);
    }
  };

  const handleCreateGroup = async () => {
    if (!groupForm.name.trim()) {
      toast.error('Group name is required');
      return;
    }

    setCreatingGroup(true);
    try {
      await agentAPI.groups.create({
        name: groupForm.name.trim(),
        description: groupForm.description.trim() || undefined,
        network_ranges: groupForm.network_ranges
          .split(',')
          .map(r => r.trim())
          .filter(Boolean),
        color: groupForm.color,
      });
      toast.success('Group created successfully');
      setShowGroupForm(false);
      setGroupForm({ name: '', description: '', network_ranges: '', color: '#06b6d4' });
      await loadData();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to create group');
    } finally {
      setCreatingGroup(false);
    }
  };

  const handleDeleteAgent = async (id: string) => {
    if (!window.confirm('Are you sure you want to delete this agent?')) return;

    try {
      await agentAPI.delete(id);
      toast.success('Agent deleted');
      await loadData();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to delete agent');
    }
  };

  const handleDeleteGroup = async (id: string) => {
    if (!window.confirm('Are you sure you want to delete this group?')) return;

    try {
      await agentAPI.groups.delete(id);
      toast.success('Group deleted');
      await loadData();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to delete group');
    }
  };

  const handleRegenerateToken = async (id: string) => {
    if (!window.confirm('Are you sure? The current token will be invalidated.')) return;

    try {
      const response = await agentAPI.regenerateToken(id);
      setNewToken(response.data.token);
      toast.success('Token regenerated');
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to regenerate token');
    }
  };

  const handleUpdateAgent = async (id: string) => {
    if (!editName.trim()) {
      toast.error('Name cannot be empty');
      return;
    }

    try {
      await agentAPI.update(id, { name: editName.trim() });
      toast.success('Agent updated');
      setEditingAgent(null);
      await loadData();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to update agent');
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const getStatusIcon = (status: AgentStatus) => {
    switch (status) {
      case 'online':
        return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'busy':
        return <Activity className="h-4 w-4 text-yellow-400 animate-pulse" />;
      case 'offline':
        return <XCircle className="h-4 w-4 text-red-400" />;
      case 'pending':
        return <Clock className="h-4 w-4 text-slate-400" />;
      case 'disabled':
        return <X className="h-4 w-4 text-slate-500" />;
      default:
        return <AlertCircle className="h-4 w-4 text-slate-400" />;
    }
  };

  const getStatusBadgeType = (status: AgentStatus): 'running' | 'pending' | 'failed' | 'completed' => {
    switch (status) {
      case 'online':
        return 'completed';
      case 'busy':
        return 'running';
      case 'offline':
      case 'disabled':
        return 'failed';
      default:
        return 'pending';
    }
  };

  if (loading) {
    return (
      <Card>
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Token Display Modal */}
      {newToken && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-dark-surface border border-dark-border rounded-lg p-6 max-w-lg w-full mx-4">
            <div className="flex items-center gap-3 mb-4">
              <AlertCircle className="h-6 w-6 text-yellow-400" />
              <h3 className="text-lg font-semibold text-white">Agent Token</h3>
            </div>
            <p className="text-sm text-slate-400 mb-4">
              This token will only be shown once. Copy it now and configure it in your agent.
            </p>
            <div className="relative">
              <Input
                type={showToken ? 'text' : 'password'}
                value={newToken}
                readOnly
                className="font-mono text-sm pr-24"
              />
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setShowToken(!showToken)}
                >
                  {showToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => copyToClipboard(newToken)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>
            <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
              <p className="text-sm text-yellow-200">
                Store this token securely. You will need to regenerate it if lost.
              </p>
            </div>
            <div className="mt-4 flex justify-end">
              <Button onClick={() => setNewToken(null)}>Done</Button>
            </div>
          </div>
        </div>
      )}

      {/* Stats Overview */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary/20 rounded-lg">
                <Server className="h-5 w-5 text-primary" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{stats.total_agents}</p>
                <p className="text-sm text-slate-400">Total Agents</p>
              </div>
            </div>
          </Card>
          <Card>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-500/20 rounded-lg">
                <CheckCircle className="h-5 w-5 text-green-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{stats.online_agents}</p>
                <p className="text-sm text-slate-400">Online</p>
              </div>
            </div>
          </Card>
          <Card>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-yellow-500/20 rounded-lg">
                <Activity className="h-5 w-5 text-yellow-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{stats.busy_agents}</p>
                <p className="text-sm text-slate-400">Busy</p>
              </div>
            </div>
          </Card>
          <Card>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-slate-500/20 rounded-lg">
                <Check className="h-5 w-5 text-slate-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{stats.total_tasks_completed}</p>
                <p className="text-sm text-slate-400">Tasks Completed</p>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Tabs */}
      <Card>
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <button
              onClick={() => setActiveTab('agents')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium ${
                activeTab === 'agents'
                  ? 'bg-primary text-white'
                  : 'text-slate-400 hover:text-white hover:bg-dark-hover'
              }`}
            >
              <Server className="h-4 w-4" />
              Agents ({agents.length})
            </button>
            <button
              onClick={() => setActiveTab('groups')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium ${
                activeTab === 'groups'
                  ? 'bg-primary text-white'
                  : 'text-slate-400 hover:text-white hover:bg-dark-hover'
              }`}
            >
              <Layers className="h-4 w-4" />
              Groups ({groups.length})
            </button>
          </div>
          <div className="flex items-center gap-2">
            <Button
              onClick={() => loadData()}
              variant="secondary"
              className="flex items-center gap-2"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh
            </Button>
            {activeTab === 'agents' ? (
              <Button
                onClick={() => setShowRegisterForm(true)}
                className="flex items-center gap-2"
              >
                <Plus className="h-4 w-4" />
                Register Agent
              </Button>
            ) : (
              <Button
                onClick={() => setShowGroupForm(true)}
                className="flex items-center gap-2"
              >
                <Plus className="h-4 w-4" />
                Create Group
              </Button>
            )}
          </div>
        </div>

        {/* Register Agent Form */}
        {showRegisterForm && (
          <div className="mb-6 p-4 bg-dark-hover rounded-lg border border-dark-border">
            <h4 className="text-md font-semibold text-white mb-4">Register New Agent</h4>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Name <span className="text-red-500">*</span>
                </label>
                <Input
                  type="text"
                  placeholder="Production Agent 1"
                  value={registerForm.name}
                  onChange={(e) => setRegisterForm({ ...registerForm, name: e.target.value })}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Description
                </label>
                <Input
                  type="text"
                  placeholder="Agent for internal network scanning"
                  value={registerForm.description || ''}
                  onChange={(e) => setRegisterForm({ ...registerForm, description: e.target.value })}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Max Concurrent Tasks
                  </label>
                  <Input
                    type="number"
                    min={1}
                    max={10}
                    value={registerForm.max_concurrent_tasks}
                    onChange={(e) =>
                      setRegisterForm({
                        ...registerForm,
                        max_concurrent_tasks: parseInt(e.target.value) || 1,
                      })
                    }
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Network Zones (comma-separated)
                  </label>
                  <Input
                    type="text"
                    placeholder="10.0.0.0/8, 192.168.0.0/16"
                    value={(registerForm.network_zones || []).join(', ')}
                    onChange={(e) =>
                      setRegisterForm({
                        ...registerForm,
                        network_zones: e.target.value.split(',').map((z) => z.trim()),
                      })
                    }
                  />
                </div>
              </div>
              <div className="flex gap-3">
                <Button onClick={handleRegister} disabled={registering}>
                  {registering ? 'Registering...' : 'Register'}
                </Button>
                <Button variant="secondary" onClick={() => setShowRegisterForm(false)}>
                  Cancel
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* Create Group Form */}
        {showGroupForm && (
          <div className="mb-6 p-4 bg-dark-hover rounded-lg border border-dark-border">
            <h4 className="text-md font-semibold text-white mb-4">Create Agent Group</h4>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Name <span className="text-red-500">*</span>
                  </label>
                  <Input
                    type="text"
                    placeholder="Internal Network"
                    value={groupForm.name}
                    onChange={(e) => setGroupForm({ ...groupForm, name: e.target.value })}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Color
                  </label>
                  <Input
                    type="color"
                    value={groupForm.color}
                    onChange={(e) => setGroupForm({ ...groupForm, color: e.target.value })}
                    className="h-10 p-1"
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Description
                </label>
                <Input
                  type="text"
                  placeholder="Agents for internal network segments"
                  value={groupForm.description}
                  onChange={(e) => setGroupForm({ ...groupForm, description: e.target.value })}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Network Ranges (comma-separated)
                </label>
                <Input
                  type="text"
                  placeholder="10.0.0.0/8, 192.168.0.0/16"
                  value={groupForm.network_ranges}
                  onChange={(e) => setGroupForm({ ...groupForm, network_ranges: e.target.value })}
                />
              </div>
              <div className="flex gap-3">
                <Button onClick={handleCreateGroup} disabled={creatingGroup}>
                  {creatingGroup ? 'Creating...' : 'Create Group'}
                </Button>
                <Button variant="secondary" onClick={() => setShowGroupForm(false)}>
                  Cancel
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* Agents List */}
        {activeTab === 'agents' && (
          <div className="space-y-3">
            {agents.length === 0 ? (
              <div className="text-center py-8 text-slate-400">
                <Server className="h-12 w-12 mx-auto mb-3 opacity-50" />
                <p>No agents registered yet</p>
                <p className="text-sm">Register an agent to start distributed scanning</p>
              </div>
            ) : (
              agents.map((agent) => (
                <div
                  key={agent.id}
                  className="p-4 bg-dark-hover rounded-lg border border-dark-border"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-4">
                      <div className="p-2 bg-primary/20 rounded-lg">
                        <Server className="h-5 w-5 text-primary" />
                      </div>
                      <div>
                        {editingAgent === agent.id ? (
                          <div className="flex items-center gap-2">
                            <Input
                              type="text"
                              value={editName}
                              onChange={(e) => setEditName(e.target.value)}
                              className="w-48"
                              autoFocus
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') handleUpdateAgent(agent.id);
                                if (e.key === 'Escape') setEditingAgent(null);
                              }}
                            />
                            <Button size="sm" onClick={() => handleUpdateAgent(agent.id)}>
                              Save
                            </Button>
                            <Button size="sm" variant="secondary" onClick={() => setEditingAgent(null)}>
                              Cancel
                            </Button>
                          </div>
                        ) : (
                          <div className="flex items-center gap-2">
                            <span className="text-white font-medium">{agent.name}</span>
                            {getStatusIcon(agent.status)}
                            <Badge type={getStatusBadgeType(agent.status)}>
                              {agent.status}
                            </Badge>
                          </div>
                        )}
                        <div className="flex items-center gap-4 mt-1 text-sm text-slate-400">
                          {agent.hostname && (
                            <span className="flex items-center gap-1">
                              <Cpu className="h-3 w-3" />
                              {agent.hostname}
                            </span>
                          )}
                          {agent.ip_address && (
                            <span className="flex items-center gap-1">
                              <Network className="h-3 w-3" />
                              {agent.ip_address}
                            </span>
                          )}
                          {agent.version && (
                            <span className="flex items-center gap-1">
                              <Settings className="h-3 w-3" />
                              v{agent.version}
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-4 mt-2 text-xs text-slate-500">
                          <span>
                            Token: {agent.token_prefix}...
                          </span>
                          <span>
                            Tasks: {agent.current_tasks}/{agent.max_concurrent_tasks}
                          </span>
                          {agent.last_heartbeat_at && (
                            <span>
                              Last seen: {new Date(agent.last_heartbeat_at).toLocaleString()}
                            </span>
                          )}
                        </div>
                        {agent.groups.length > 0 && (
                          <div className="flex items-center gap-2 mt-2">
                            <span className="text-xs text-slate-500">Groups:</span>
                            {agent.groups.map((group) => (
                              <span
                                key={group.id}
                                className="px-2 py-0.5 rounded text-xs"
                                style={{ backgroundColor: `${group.color}20`, color: group.color }}
                              >
                                {group.name}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {editingAgent !== agent.id && (
                        <>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => {
                              setEditingAgent(agent.id);
                              setEditName(agent.name);
                            }}
                            title="Edit"
                          >
                            <Edit2 className="h-4 w-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleRegenerateToken(agent.id)}
                            title="Regenerate token"
                          >
                            <RefreshCw className="h-4 w-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleDeleteAgent(agent.id)}
                            className="text-red-400 hover:text-red-300"
                            title="Delete"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* Groups List */}
        {activeTab === 'groups' && (
          <div className="space-y-3">
            {groups.length === 0 ? (
              <div className="text-center py-8 text-slate-400">
                <Layers className="h-12 w-12 mx-auto mb-3 opacity-50" />
                <p>No groups created yet</p>
                <p className="text-sm">Create groups to organize agents by network zone</p>
              </div>
            ) : (
              groups.map((group) => (
                <div
                  key={group.id}
                  className="p-4 bg-dark-hover rounded-lg border border-dark-border"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div
                        className="p-2 rounded-lg"
                        style={{ backgroundColor: `${group.color}20` }}
                      >
                        <Layers className="h-5 w-5" style={{ color: group.color }} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-white font-medium">{group.name}</span>
                          <span className="text-sm text-slate-400">
                            ({group.agent_count} agent{group.agent_count !== 1 ? 's' : ''})
                          </span>
                        </div>
                        {group.description && (
                          <p className="text-sm text-slate-400 mt-1">{group.description}</p>
                        )}
                        {group.network_ranges && (
                          <div className="flex items-center gap-2 mt-2">
                            <Network className="h-3 w-3 text-slate-500" />
                            <span className="text-xs text-slate-500">
                              {JSON.parse(group.network_ranges).join(', ')}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleDeleteGroup(group.id)}
                        className="text-red-400 hover:text-red-300"
                        title="Delete"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </Card>

      {/* Help Section */}
      <Card>
        <h4 className="text-md font-semibold text-white mb-4 flex items-center gap-2">
          <Info className="h-5 w-5 text-primary" />
          How to Deploy Agents
        </h4>
        <div className="space-y-4 text-sm text-slate-400">
          <div className="flex items-start gap-3">
            <div className="bg-primary/20 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-primary font-semibold text-xs">1</span>
            </div>
            <p>
              Register a new agent above to receive a unique token. This token authenticates the agent
              with the server.
            </p>
          </div>
          <div className="flex items-start gap-3">
            <div className="bg-primary/20 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-primary font-semibold text-xs">2</span>
            </div>
            <p>
              Download and run the HeroForge agent on your target network. Configure it with the
              server URL and token.
            </p>
          </div>
          <div className="flex items-start gap-3">
            <div className="bg-primary/20 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-primary font-semibold text-xs">3</span>
            </div>
            <p>
              Create groups to organize agents by network zone (e.g., DMZ, Internal, Cloud).
            </p>
          </div>
          <div className="flex items-start gap-3">
            <div className="bg-primary/20 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-primary font-semibold text-xs">4</span>
            </div>
            <p>
              When creating scans, select an agent or group to route the scan through the appropriate
              network segment.
            </p>
          </div>
        </div>

        <div className="mt-4 p-3 bg-dark-hover rounded-lg">
          <p className="text-sm text-slate-300 font-medium mb-2">Agent Configuration Example</p>
          <pre className="text-xs text-slate-400 overflow-x-auto">
{`# heroforge-agent.yaml
server_url: https://heroforge.example.com
token: hfa_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
heartbeat_interval: 30
max_concurrent_tasks: 3`}
          </pre>
        </div>
      </Card>
    </div>
  );
};

export default AgentManagement;
