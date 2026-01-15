import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Radio,
  Server,
  Monitor,
  Terminal,
  Key,
  Wifi,
  WifiOff,
  Play,
  Square,
  Plus,
  Trash2,
  RefreshCw,
  Download,
  Send,
  Eye,
  Settings,
  Shield,
  Cpu,
  HardDrive,
  User,
  Clock,
  Activity,
  AlertTriangle,
  ChevronRight,
  Layers,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import Button from '../components/ui/Button';
import { EngagementRequiredBanner } from '../components/engagement';
import { useRequireEngagement } from '../hooks/useRequireEngagement';
import api from '../services/api';

// Types
interface C2Summary {
  id: string;
  name: string;
  framework: string;
  host: string;
  port: number;
  connected: boolean;
  listener_count: number;
  session_count: number;
  last_connected?: string;
}

interface SessionSummary {
  id: string;
  name: string;
  hostname: string;
  username: string;
  ip_address: string;
  os: string;
  arch: string;
  status: string;
  is_elevated: boolean;
  last_checkin: string;
}

interface Listener {
  id: string;
  name: string;
  protocol: string;
  host: string;
  port: number;
  status: string;
}

interface Implant {
  id: string;
  name: string;
  platform: string;
  arch: string;
  format: string;
  implant_type: string;
  file_size?: number;
  download_count: number;
  created_at: string;
}

interface C2DashboardStats {
  total_servers: number;
  connected_servers: number;
  total_listeners: number;
  active_listeners: number;
  total_sessions: number;
  active_sessions: number;
  total_implants: number;
  total_credentials: number;
  sessions_by_os: Record<string, number>;
  sessions_by_framework: Record<string, number>;
}

// API functions
const c2API = {
  getDashboard: () => api.get<C2DashboardStats>('/c2/dashboard'),
  listServers: () => api.get<C2Summary[]>('/c2/servers'),
  createServer: (data: {
    name: string;
    framework: string;
    host: string;
    port: number;
    api_token?: string;
  }) => api.post('/c2/servers', data),
  deleteServer: (id: string) => api.delete(`/c2/servers/${id}`),
  connectServer: (id: string) => api.post(`/c2/servers/${id}/connect`),
  disconnectServer: (id: string) => api.post(`/c2/servers/${id}/disconnect`),
  syncSessions: (id: string) => api.post(`/c2/servers/${id}/sync`),
  listListeners: (serverId: string) => api.get<Listener[]>(`/c2/servers/${serverId}/listeners`),
  listSessions: (serverId: string) => api.get<SessionSummary[]>(`/c2/servers/${serverId}/sessions`),
  listImplants: (serverId: string) => api.get<Implant[]>(`/c2/servers/${serverId}/implants`),
  listCredentials: () => api.get('/c2/credentials'),
};

// Status badge component
const StatusBadge: React.FC<{ status: string; connected?: boolean }> = ({ status, connected }) => {
  const getColor = () => {
    if (connected !== undefined) {
      return connected
        ? 'bg-green-500/20 text-green-400 border-green-500/30'
        : 'bg-red-500/20 text-red-400 border-red-500/30';
    }
    switch (status.toLowerCase()) {
      case 'active':
      case 'connected':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'dormant':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'dead':
      case 'stopped':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded border capitalize ${getColor()}`}>
      {connected !== undefined ? (connected ? 'Connected' : 'Disconnected') : status}
    </span>
  );
};

// Stats card component
const StatsCard: React.FC<{
  label: string;
  value: number;
  icon: React.ReactNode;
  color: string;
}> = ({ label, value, icon, color }) => (
  <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm text-slate-500 dark:text-slate-400">{label}</p>
        <p className="text-2xl font-bold text-slate-900 dark:text-white">{value}</p>
      </div>
      <div className={`p-3 rounded-lg ${color}`}>{icon}</div>
    </div>
  </div>
);

// Server card component
const ServerCard: React.FC<{
  server: C2Summary;
  onConnect: () => void;
  onDisconnect: () => void;
  onSync: () => void;
  onSelect: () => void;
  onDelete: () => void;
  isConnecting: boolean;
}> = ({ server, onConnect, onDisconnect, onSync, onSelect, onDelete, isConnecting }) => {
  const getFrameworkIcon = (framework: string) => {
    switch (framework.toLowerCase()) {
      case 'sliver':
        return <Shield className="h-5 w-5 text-cyan-400" />;
      case 'havoc':
        return <Layers className="h-5 w-5 text-red-400" />;
      case 'mythic':
        return <Radio className="h-5 w-5 text-purple-400" />;
      default:
        return <Server className="h-5 w-5 text-gray-400" />;
    }
  };

  return (
    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4 hover:border-primary/50 transition-colors">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3 cursor-pointer" onClick={onSelect}>
          {getFrameworkIcon(server.framework)}
          <div>
            <h3 className="font-semibold text-slate-900 dark:text-white">{server.name}</h3>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              {server.host}:{server.port}
            </p>
          </div>
        </div>
        <StatusBadge status="" connected={server.connected} />
      </div>

      <div className="grid grid-cols-3 gap-2 text-center text-sm mb-4">
        <div className="bg-light-bg dark:bg-dark-bg rounded p-2">
          <p className="text-slate-500 dark:text-slate-400">Listeners</p>
          <p className="font-semibold text-slate-900 dark:text-white">{server.listener_count}</p>
        </div>
        <div className="bg-light-bg dark:bg-dark-bg rounded p-2">
          <p className="text-slate-500 dark:text-slate-400">Sessions</p>
          <p className="font-semibold text-green-400">{server.session_count}</p>
        </div>
        <div className="bg-light-bg dark:bg-dark-bg rounded p-2">
          <p className="text-slate-500 dark:text-slate-400">Framework</p>
          <p className="font-semibold text-slate-900 dark:text-white capitalize">{server.framework}</p>
        </div>
      </div>

      <div className="flex gap-2">
        {server.connected ? (
          <>
            <Button size="sm" variant="outline" onClick={onSync}>
              <RefreshCw className="h-4 w-4 mr-1" />
              Sync
            </Button>
            <Button size="sm" variant="outline" onClick={onDisconnect}>
              <WifiOff className="h-4 w-4 mr-1" />
              Disconnect
            </Button>
          </>
        ) : (
          <Button size="sm" onClick={onConnect} disabled={isConnecting}>
            {isConnecting ? (
              <RefreshCw className="h-4 w-4 mr-1 animate-spin" />
            ) : (
              <Wifi className="h-4 w-4 mr-1" />
            )}
            Connect
          </Button>
        )}
        <Button size="sm" variant="ghost" onClick={onSelect}>
          <Eye className="h-4 w-4" />
        </Button>
        <Button size="sm" variant="ghost" className="text-red-400" onClick={onDelete}>
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
};

// Session row component
const SessionRow: React.FC<{ session: SessionSummary }> = ({ session }) => {
  const getOsIcon = (os: string) => {
    const osLower = os.toLowerCase();
    if (osLower.includes('windows')) return <Monitor className="h-4 w-4 text-blue-400" />;
    if (osLower.includes('linux')) return <Terminal className="h-4 w-4 text-yellow-400" />;
    if (osLower.includes('darwin') || osLower.includes('macos')) return <Cpu className="h-4 w-4 text-gray-400" />;
    return <HardDrive className="h-4 w-4 text-gray-400" />;
  };

  return (
    <tr className="hover:bg-light-hover dark:hover:bg-dark-hover">
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          {getOsIcon(session.os)}
          <div>
            <p className="text-sm font-medium text-slate-900 dark:text-white">{session.hostname}</p>
            <p className="text-xs text-slate-500 dark:text-slate-400">{session.name}</p>
          </div>
        </div>
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-1">
          <User className="h-3 w-3 text-slate-400" />
          <span className="text-sm text-slate-600 dark:text-slate-300">
            {session.username}
            {session.is_elevated && (
              <span className="ml-1 text-red-400" title="Elevated">*</span>
            )}
          </span>
        </div>
      </td>
      <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">{session.ip_address}</td>
      <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">{session.os}</td>
      <td className="px-4 py-3">
        <StatusBadge status={session.status} />
      </td>
      <td className="px-4 py-3 text-sm text-slate-500 dark:text-slate-400">
        {new Date(session.last_checkin).toLocaleTimeString()}
      </td>
      <td className="px-4 py-3">
        <div className="flex gap-1">
          <Button size="sm" variant="ghost" title="Interact">
            <Terminal className="h-4 w-4" />
          </Button>
          <Button size="sm" variant="ghost" title="Details">
            <Eye className="h-4 w-4" />
          </Button>
        </div>
      </td>
    </tr>
  );
};

// Main page component
const C2Page: React.FC = () => {
  const queryClient = useQueryClient();
  const { hasEngagement } = useRequireEngagement();
  const [activeTab, setActiveTab] = useState<'servers' | 'sessions' | 'listeners' | 'implants' | 'credentials'>('servers');
  const [selectedServer, setSelectedServer] = useState<string | null>(null);
  const [showAddServer, setShowAddServer] = useState(false);
  const [connectingServer, setConnectingServer] = useState<string | null>(null);

  // Form state for new server
  const [newServer, setNewServer] = useState({
    name: '',
    framework: 'sliver',
    host: '',
    port: 31337,
    api_token: '',
  });

  // Queries
  const { data: dashboard, isLoading: loadingDashboard } = useQuery({
    queryKey: ['c2-dashboard'],
    queryFn: () => c2API.getDashboard().then((r: { data: C2DashboardStats }) => r.data),
  });

  const { data: servers, isLoading: loadingServers } = useQuery({
    queryKey: ['c2-servers'],
    queryFn: () => c2API.listServers().then((r: { data: C2Summary[] }) => r.data),
  });

  const { data: sessions } = useQuery({
    queryKey: ['c2-sessions', selectedServer],
    queryFn: () => selectedServer ? c2API.listSessions(selectedServer).then((r: { data: SessionSummary[] }) => r.data) : Promise.resolve([]),
    enabled: !!selectedServer && activeTab === 'sessions',
  });

  const { data: listeners } = useQuery({
    queryKey: ['c2-listeners', selectedServer],
    queryFn: () => selectedServer ? c2API.listListeners(selectedServer).then((r: { data: Listener[] }) => r.data) : Promise.resolve([]),
    enabled: !!selectedServer && activeTab === 'listeners',
  });

  const { data: implants } = useQuery({
    queryKey: ['c2-implants', selectedServer],
    queryFn: () => selectedServer ? c2API.listImplants(selectedServer).then((r: { data: Implant[] }) => r.data) : Promise.resolve([]),
    enabled: !!selectedServer && activeTab === 'implants',
  });

  // Mutations
  const createServerMutation = useMutation({
    mutationFn: (data: typeof newServer) => c2API.createServer(data),
    onSuccess: () => {
      toast.success('C2 server added');
      queryClient.invalidateQueries({ queryKey: ['c2-servers'] });
      setShowAddServer(false);
      setNewServer({ name: '', framework: 'sliver', host: '', port: 31337, api_token: '' });
    },
    onError: () => toast.error('Failed to add server'),
  });

  const deleteServerMutation = useMutation({
    mutationFn: (id: string) => c2API.deleteServer(id),
    onSuccess: () => {
      toast.success('Server removed');
      queryClient.invalidateQueries({ queryKey: ['c2-servers'] });
    },
  });

  const connectMutation = useMutation({
    mutationFn: (id: string) => {
      setConnectingServer(id);
      return c2API.connectServer(id);
    },
    onSuccess: () => {
      toast.success('Connected to C2 server');
      queryClient.invalidateQueries({ queryKey: ['c2-servers'] });
      queryClient.invalidateQueries({ queryKey: ['c2-dashboard'] });
      setConnectingServer(null);
    },
    onError: () => {
      toast.error('Failed to connect');
      setConnectingServer(null);
    },
  });

  const disconnectMutation = useMutation({
    mutationFn: (id: string) => c2API.disconnectServer(id),
    onSuccess: () => {
      toast.success('Disconnected from C2 server');
      queryClient.invalidateQueries({ queryKey: ['c2-servers'] });
      queryClient.invalidateQueries({ queryKey: ['c2-dashboard'] });
    },
  });

  const syncMutation = useMutation({
    mutationFn: (id: string) => c2API.syncSessions(id),
    onSuccess: () => {
      toast.success('Sessions synced');
      queryClient.invalidateQueries({ queryKey: ['c2-sessions'] });
      queryClient.invalidateQueries({ queryKey: ['c2-dashboard'] });
    },
  });

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
              C2 Framework Integration
            </h1>
            <p className="text-slate-500 dark:text-slate-400">
              Manage Command & Control frameworks and sessions
            </p>
          </div>
          <Button onClick={() => setShowAddServer(true)} disabled={!hasEngagement}>
            <Plus className="h-4 w-4 mr-2" />
            Add C2 Server
          </Button>
        </div>

        <EngagementRequiredBanner toolName="C2 Framework Integration" />

        {/* Warning Banner */}
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-yellow-400 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-yellow-400">Authorization Required</p>
            <p className="text-sm text-slate-400">
              C2 framework integration is for authorized penetration testing engagements only.
              Ensure you have proper authorization before conducting any operations.
            </p>
          </div>
        </div>

        {/* Stats Overview */}
        {dashboard && (
          <div className="grid grid-cols-4 gap-4">
            <StatsCard
              label="Connected Servers"
              value={dashboard.connected_servers}
              icon={<Server className="h-5 w-5 text-blue-400" />}
              color="bg-blue-500/10"
            />
            <StatsCard
              label="Active Listeners"
              value={dashboard.active_listeners}
              icon={<Radio className="h-5 w-5 text-green-400" />}
              color="bg-green-500/10"
            />
            <StatsCard
              label="Active Sessions"
              value={dashboard.active_sessions}
              icon={<Terminal className="h-5 w-5 text-cyan-400" />}
              color="bg-cyan-500/10"
            />
            <StatsCard
              label="Credentials"
              value={dashboard.total_credentials}
              icon={<Key className="h-5 w-5 text-yellow-400" />}
              color="bg-yellow-500/10"
            />
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-2 border-b border-light-border dark:border-dark-border pb-2">
          {[
            { id: 'servers', label: 'C2 Servers', icon: <Server className="h-4 w-4" /> },
            { id: 'sessions', label: 'Sessions', icon: <Terminal className="h-4 w-4" /> },
            { id: 'listeners', label: 'Listeners', icon: <Radio className="h-4 w-4" /> },
            { id: 'implants', label: 'Implants', icon: <HardDrive className="h-4 w-4" /> },
            { id: 'credentials', label: 'Credentials', icon: <Key className="h-4 w-4" /> },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-primary text-white'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-light-hover dark:hover:bg-dark-hover'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'servers' && (
          <div className="space-y-4">
            {loadingServers ? (
              <div className="flex justify-center py-12">
                <RefreshCw className="h-8 w-8 animate-spin text-primary" />
              </div>
            ) : servers?.length === 0 ? (
              <div className="text-center py-12">
                <Server className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  No C2 servers configured
                </h3>
                <p className="text-slate-500 dark:text-slate-400 mb-4">
                  Add a C2 server to get started
                </p>
                <Button onClick={() => setShowAddServer(true)}>
                  <Plus className="h-4 w-4 mr-2" />
                  Add C2 Server
                </Button>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {servers?.map((server) => (
                  <ServerCard
                    key={server.id}
                    server={server}
                    onConnect={() => connectMutation.mutate(server.id)}
                    onDisconnect={() => disconnectMutation.mutate(server.id)}
                    onSync={() => syncMutation.mutate(server.id)}
                    onSelect={() => setSelectedServer(server.id)}
                    onDelete={() => {
                      if (confirm('Delete this C2 server?')) {
                        deleteServerMutation.mutate(server.id);
                      }
                    }}
                    isConnecting={connectingServer === server.id}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'sessions' && (
          <div className="space-y-4">
            {!selectedServer ? (
              <div className="text-center py-12">
                <Terminal className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  Select a C2 server
                </h3>
                <p className="text-slate-500 dark:text-slate-400">
                  Choose a C2 server from the servers tab to view sessions
                </p>
              </div>
            ) : sessions?.length === 0 ? (
              <div className="text-center py-12">
                <Terminal className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  No active sessions
                </h3>
                <p className="text-slate-500 dark:text-slate-400">
                  Deploy an implant to get sessions
                </p>
              </div>
            ) : (
              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-light-bg dark:bg-dark-bg">
                    <tr>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Host</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">User</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">IP</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">OS</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Status</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Last Seen</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-light-border dark:divide-dark-border">
                    {sessions?.map((session) => (
                      <SessionRow key={session.id} session={session} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === 'listeners' && (
          <div className="space-y-4">
            {!selectedServer ? (
              <div className="text-center py-12">
                <Radio className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  Select a C2 server
                </h3>
              </div>
            ) : listeners?.length === 0 ? (
              <div className="text-center py-12">
                <Radio className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  No listeners
                </h3>
                <p className="text-slate-500 dark:text-slate-400 mb-4">
                  Create a listener to receive connections
                </p>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Listener
                </Button>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {listeners?.map((listener) => (
                  <div key={listener.id} className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2">
                        <Radio className="h-5 w-5 text-green-400" />
                        <h3 className="font-medium text-slate-900 dark:text-white">{listener.name}</h3>
                      </div>
                      <StatusBadge status={listener.status} />
                    </div>
                    <div className="text-sm text-slate-500 dark:text-slate-400 mb-3">
                      <p>{listener.protocol.toUpperCase()} on {listener.host}:{listener.port}</p>
                    </div>
                    <div className="flex gap-2">
                      <Button size="sm" variant="ghost">
                        <Square className="h-4 w-4" />
                      </Button>
                      <Button size="sm" variant="ghost" className="text-red-400">
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'implants' && (
          <div className="space-y-4">
            <div className="flex justify-end">
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                Generate Implant
              </Button>
            </div>
            {!selectedServer ? (
              <div className="text-center py-12">
                <HardDrive className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  Select a C2 server
                </h3>
              </div>
            ) : implants?.length === 0 ? (
              <div className="text-center py-12">
                <HardDrive className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  No implants generated
                </h3>
              </div>
            ) : (
              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-light-bg dark:bg-dark-bg">
                    <tr>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Name</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Platform</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Arch</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Format</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Size</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Downloads</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-light-border dark:divide-dark-border">
                    {implants?.map((implant) => (
                      <tr key={implant.id} className="hover:bg-light-hover dark:hover:bg-dark-hover">
                        <td className="px-4 py-3 text-sm font-medium text-slate-900 dark:text-white">{implant.name}</td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300 capitalize">{implant.platform}</td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">{implant.arch}</td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300 uppercase">{implant.format}</td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">
                          {implant.file_size ? `${(implant.file_size / 1024).toFixed(1)} KB` : '-'}
                        </td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">{implant.download_count}</td>
                        <td className="px-4 py-3">
                          <Button size="sm" variant="ghost">
                            <Download className="h-4 w-4" />
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === 'credentials' && (
          <div className="text-center py-12">
            <Key className="h-12 w-12 text-slate-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
              Credentials
            </h3>
            <p className="text-slate-500 dark:text-slate-400">
              Credentials harvested from sessions will appear here
            </p>
          </div>
        )}

        {/* Add Server Modal */}
        {showAddServer && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6 w-full max-w-md">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Add C2 Server</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Name</label>
                  <input
                    type="text"
                    value={newServer.name}
                    onChange={(e) => setNewServer({ ...newServer, name: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white"
                    placeholder="My Sliver Server"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Framework</label>
                  <select
                    value={newServer.framework}
                    onChange={(e) => setNewServer({ ...newServer, framework: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white"
                  >
                    <option value="sliver">Sliver</option>
                    <option value="havoc">Havoc</option>
                    <option value="mythic">Mythic</option>
                  </select>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <div className="col-span-2">
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Host</label>
                    <input
                      type="text"
                      value={newServer.host}
                      onChange={(e) => setNewServer({ ...newServer, host: e.target.value })}
                      className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white"
                      placeholder="192.168.1.100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Port</label>
                    <input
                      type="number"
                      value={newServer.port}
                      onChange={(e) => setNewServer({ ...newServer, port: parseInt(e.target.value) })}
                      className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">API Token (optional)</label>
                  <input
                    type="password"
                    value={newServer.api_token}
                    onChange={(e) => setNewServer({ ...newServer, api_token: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white"
                  />
                </div>
              </div>
              <div className="flex justify-end gap-2 mt-6">
                <Button variant="outline" onClick={() => setShowAddServer(false)}>Cancel</Button>
                <Button onClick={() => createServerMutation.mutate(newServer)}>Add Server</Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default C2Page;
