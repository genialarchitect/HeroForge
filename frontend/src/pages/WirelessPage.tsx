import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Wifi,
  WifiOff,
  Radio,
  Lock,
  Unlock,
  Shield,
  ShieldOff,
  Play,
  Square,
  Plus,
  Trash2,
  RefreshCw,
  Search,
  Key,
  AlertTriangle,
  Signal,
  Zap,
  FileText,
  Settings,
  Activity,
  Target,
  Clock,
  Download,
  Eye,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import Button from '../components/ui/Button';
import api from '../services/api';

// Types
interface WirelessInterface {
  name: string;
  mode: string;
  monitor_capable: boolean;
  driver?: string;
  chipset?: string;
}

interface WirelessNetwork {
  bssid: string;
  ssid: string;
  channel: number;
  frequency: number;
  signal_strength: number;
  encryption: string;
  wps_enabled: boolean;
  clients: WirelessClient[];
  first_seen: string;
  last_seen: string;
}

interface WirelessClient {
  mac_address: string;
  signal_strength: number;
  packets: number;
  probed_ssids: string[];
}

interface WirelessScan {
  id: string;
  interface: string;
  status: string;
  networks_found: number;
  clients_found: number;
  handshakes_captured: number;
  started_at: string;
  completed_at?: string;
}

interface HandshakeCapture {
  id: string;
  bssid: string;
  ssid: string;
  client_mac: string;
  capture_file: string;
  eapol_messages: number;
  is_complete: boolean;
  cracked: boolean;
  password?: string;
  captured_at: string;
}

interface PmkidCapture {
  id: string;
  bssid: string;
  ssid: string;
  pmkid: string;
  capture_file: string;
  cracked: boolean;
  password?: string;
  captured_at: string;
}

interface WirelessDashboardStats {
  total_scans: number;
  active_scans: number;
  networks_discovered: number;
  handshakes_captured: number;
  pmkids_captured: number;
  passwords_cracked: number;
  networks_by_encryption: Record<string, number>;
  top_vulnerable_networks: VulnerableNetwork[];
}

interface VulnerableNetwork {
  ssid: string;
  bssid: string;
  encryption: string;
  vulnerability: string;
  severity: string;
}

interface WordlistInfo {
  name: string;
  path: string;
  size: number;
  lines?: number;
}

// API functions
const wirelessAPI = {
  getDashboard: () => api.get<WirelessDashboardStats>('/wireless/dashboard'),
  listInterfaces: () => api.get<WirelessInterface[]>('/wireless/interfaces'),
  enableMonitor: (name: string) => api.post(`/wireless/interfaces/${name}/monitor`),
  disableMonitor: (name: string) => api.post(`/wireless/interfaces/${name}/managed`),
  startScan: (data: { interface: string; channels?: number[]; duration_secs?: number }) =>
    api.post<WirelessScan>('/wireless/scans', data),
  listScans: () => api.get<WirelessScan[]>('/wireless/scans'),
  getScan: (id: string) => api.get<WirelessScan>(`/wireless/scans/${id}`),
  stopScan: (id: string) => api.delete(`/wireless/scans/${id}`),
  listNetworks: () => api.get<WirelessNetwork[]>('/wireless/networks'),
  getNetwork: (bssid: string) => api.get<WirelessNetwork>(`/wireless/networks/${bssid}`),
  sendDeauth: (data: { interface: string; bssid: string; client?: string; count?: number }) =>
    api.post('/wireless/deauth', data),
  captureHandshake: (data: { interface: string; bssid: string; channel: number; timeout_secs?: number; use_deauth?: boolean }) =>
    api.post<HandshakeCapture>('/wireless/capture/handshake', data),
  capturePmkid: (data: { interface: string; bssid: string; channel: number; timeout_secs?: number }) =>
    api.post('/wireless/capture/pmkid', data),
  wpsPixieDust: (data: { interface: string; bssid: string }) =>
    api.post('/wireless/wps/pixie-dust', data),
  listHandshakes: () => api.get<HandshakeCapture[]>('/wireless/handshakes'),
  crackHandshake: (id: string, wordlist?: string) =>
    api.post(`/wireless/handshakes/${id}/crack`, { wordlist }),
  listPmkids: () => api.get<PmkidCapture[]>('/wireless/pmkids'),
  listWordlists: () => api.get<WordlistInfo[]>('/wireless/wordlists'),
};

// Encryption badge component
const EncryptionBadge: React.FC<{ encryption: string }> = ({ encryption }) => {
  const getColor = () => {
    const enc = encryption.toLowerCase();
    if (enc.includes('wpa3')) return 'bg-green-500/20 text-green-400 border-green-500/30';
    if (enc.includes('wpa2')) return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    if (enc.includes('wpa')) return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    if (enc.includes('wep')) return 'bg-red-500/20 text-red-400 border-red-500/30';
    if (enc === 'open') return 'bg-red-500/20 text-red-400 border-red-500/30';
    return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  };

  const getIcon = () => {
    const enc = encryption.toLowerCase();
    if (enc === 'open') return <Unlock className="h-3 w-3" />;
    return <Lock className="h-3 w-3" />;
  };

  return (
    <span className={`flex items-center gap-1 px-2 py-1 text-xs font-medium rounded border ${getColor()}`}>
      {getIcon()}
      {encryption}
    </span>
  );
};

// Signal strength component
const SignalStrength: React.FC<{ dbm: number }> = ({ dbm }) => {
  const getColor = () => {
    if (dbm >= -50) return 'text-green-400';
    if (dbm >= -60) return 'text-green-300';
    if (dbm >= -70) return 'text-yellow-400';
    if (dbm >= -80) return 'text-orange-400';
    return 'text-red-400';
  };

  const getBars = () => {
    if (dbm >= -50) return 4;
    if (dbm >= -60) return 3;
    if (dbm >= -70) return 2;
    if (dbm >= -80) return 1;
    return 0;
  };

  return (
    <div className="flex items-center gap-1">
      <Signal className={`h-4 w-4 ${getColor()}`} />
      <span className={`text-sm ${getColor()}`}>{dbm} dBm</span>
    </div>
  );
};

// Status badge component
const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const getColor = () => {
    switch (status.toLowerCase()) {
      case 'running':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'success':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'failed':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'cancelled':
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
      default:
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    }
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded border capitalize ${getColor()}`}>
      {status}
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

// Network card component
const NetworkCard: React.FC<{
  network: WirelessNetwork;
  onCapture: () => void;
  onDeauth: () => void;
  onPmkid: () => void;
  onWps: () => void;
  isLoading: boolean;
}> = ({ network, onCapture, onDeauth, onPmkid, onWps, isLoading }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3 cursor-pointer" onClick={() => setExpanded(!expanded)}>
          <Wifi className="h-5 w-5 text-cyan-400" />
          <div>
            <h3 className="font-semibold text-slate-900 dark:text-white">
              {network.ssid || '<Hidden SSID>'}
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">
              {network.bssid}
            </p>
          </div>
          {expanded ? (
            <ChevronDown className="h-4 w-4 text-slate-400" />
          ) : (
            <ChevronRight className="h-4 w-4 text-slate-400" />
          )}
        </div>
        <EncryptionBadge encryption={network.encryption} />
      </div>

      <div className="grid grid-cols-3 gap-2 text-center text-sm mb-4">
        <div className="bg-light-bg dark:bg-dark-bg rounded p-2">
          <p className="text-slate-500 dark:text-slate-400">Channel</p>
          <p className="font-semibold text-slate-900 dark:text-white">{network.channel}</p>
        </div>
        <div className="bg-light-bg dark:bg-dark-bg rounded p-2">
          <p className="text-slate-500 dark:text-slate-400">Signal</p>
          <SignalStrength dbm={network.signal_strength} />
        </div>
        <div className="bg-light-bg dark:bg-dark-bg rounded p-2">
          <p className="text-slate-500 dark:text-slate-400">Clients</p>
          <p className="font-semibold text-cyan-400">{network.clients?.length || 0}</p>
        </div>
      </div>

      {expanded && network.clients && network.clients.length > 0 && (
        <div className="mb-4 bg-light-bg dark:bg-dark-bg rounded p-3">
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">Connected Clients:</p>
          <div className="space-y-1">
            {network.clients.map((client) => (
              <div key={client.mac_address} className="flex justify-between text-xs">
                <span className="font-mono text-slate-600 dark:text-slate-300">{client.mac_address}</span>
                <span className="text-slate-400">{client.signal_strength} dBm</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <Button size="sm" onClick={onCapture} disabled={isLoading} title="Capture WPA Handshake">
          <Target className="h-4 w-4 mr-1" />
          Handshake
        </Button>
        <Button size="sm" variant="outline" onClick={onPmkid} disabled={isLoading} title="Capture PMKID">
          <Key className="h-4 w-4 mr-1" />
          PMKID
        </Button>
        <Button size="sm" variant="outline" onClick={onDeauth} disabled={isLoading} title="Send Deauth">
          <Zap className="h-4 w-4 mr-1" />
          Deauth
        </Button>
        {network.wps_enabled && (
          <Button size="sm" variant="outline" onClick={onWps} disabled={isLoading} title="WPS Pixie Dust">
            <ShieldOff className="h-4 w-4 mr-1" />
            WPS
          </Button>
        )}
      </div>
    </div>
  );
};

// Handshake row component
const HandshakeRow: React.FC<{
  handshake: HandshakeCapture;
  onCrack: () => void;
  isCracking: boolean;
}> = ({ handshake, onCrack, isCracking }) => (
  <tr className="hover:bg-light-hover dark:hover:bg-dark-hover">
    <td className="px-4 py-3">
      <div>
        <p className="text-sm font-medium text-slate-900 dark:text-white">{handshake.ssid || '<Hidden>'}</p>
        <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">{handshake.bssid}</p>
      </div>
    </td>
    <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300 font-mono">{handshake.client_mac}</td>
    <td className="px-4 py-3">
      <div className="flex items-center gap-1">
        {handshake.is_complete ? (
          <span className="text-green-400 text-sm">Complete ({handshake.eapol_messages}/4)</span>
        ) : (
          <span className="text-yellow-400 text-sm">Partial ({handshake.eapol_messages}/4)</span>
        )}
      </div>
    </td>
    <td className="px-4 py-3">
      {handshake.cracked ? (
        <div className="flex items-center gap-1">
          <Key className="h-4 w-4 text-green-400" />
          <span className="text-sm text-green-400 font-mono">{handshake.password}</span>
        </div>
      ) : (
        <span className="text-slate-400 text-sm">Not cracked</span>
      )}
    </td>
    <td className="px-4 py-3 text-sm text-slate-500 dark:text-slate-400">
      {new Date(handshake.captured_at).toLocaleString()}
    </td>
    <td className="px-4 py-3">
      {!handshake.cracked && handshake.is_complete && (
        <Button size="sm" onClick={onCrack} disabled={isCracking}>
          {isCracking ? (
            <RefreshCw className="h-4 w-4 animate-spin" />
          ) : (
            <Zap className="h-4 w-4 mr-1" />
          )}
          Crack
        </Button>
      )}
    </td>
  </tr>
);

// Main page component
const WirelessPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'dashboard' | 'interfaces' | 'networks' | 'scans' | 'handshakes'>('dashboard');
  const [selectedInterface, setSelectedInterface] = useState<string>('');
  const [showScanModal, setShowScanModal] = useState(false);
  const [showCaptureModal, setShowCaptureModal] = useState(false);
  const [selectedNetwork, setSelectedNetwork] = useState<WirelessNetwork | null>(null);
  const [crackingId, setCrackingId] = useState<string | null>(null);

  // Scan form state
  const [scanConfig, setScanConfig] = useState({
    interface: '',
    duration_secs: 60,
    channels: [] as number[],
  });

  // Queries
  const { data: dashboard, isLoading: loadingDashboard } = useQuery({
    queryKey: ['wireless-dashboard'],
    queryFn: () => wirelessAPI.getDashboard().then((r) => r.data),
  });

  const { data: interfaces, isLoading: loadingInterfaces } = useQuery({
    queryKey: ['wireless-interfaces'],
    queryFn: () => wirelessAPI.listInterfaces().then((r) => r.data),
  });

  const { data: networks, isLoading: loadingNetworks } = useQuery({
    queryKey: ['wireless-networks'],
    queryFn: () => wirelessAPI.listNetworks().then((r) => r.data),
  });

  const { data: scans, isLoading: loadingScans } = useQuery({
    queryKey: ['wireless-scans'],
    queryFn: () => wirelessAPI.listScans().then((r) => r.data),
  });

  const { data: handshakes, isLoading: loadingHandshakes } = useQuery({
    queryKey: ['wireless-handshakes'],
    queryFn: () => wirelessAPI.listHandshakes().then((r) => r.data),
    enabled: activeTab === 'handshakes',
  });

  const { data: wordlists } = useQuery({
    queryKey: ['wireless-wordlists'],
    queryFn: () => wirelessAPI.listWordlists().then((r) => r.data),
    enabled: activeTab === 'handshakes',
  });

  // Mutations
  const enableMonitorMutation = useMutation({
    mutationFn: (name: string) => wirelessAPI.enableMonitor(name),
    onSuccess: () => {
      toast.success('Monitor mode enabled');
      queryClient.invalidateQueries({ queryKey: ['wireless-interfaces'] });
    },
    onError: () => toast.error('Failed to enable monitor mode'),
  });

  const disableMonitorMutation = useMutation({
    mutationFn: (name: string) => wirelessAPI.disableMonitor(name),
    onSuccess: () => {
      toast.success('Monitor mode disabled');
      queryClient.invalidateQueries({ queryKey: ['wireless-interfaces'] });
    },
    onError: () => toast.error('Failed to disable monitor mode'),
  });

  const startScanMutation = useMutation({
    mutationFn: (data: { interface: string; duration_secs?: number; channels?: number[] }) =>
      wirelessAPI.startScan(data),
    onSuccess: () => {
      toast.success('Wireless scan started');
      queryClient.invalidateQueries({ queryKey: ['wireless-scans'] });
      queryClient.invalidateQueries({ queryKey: ['wireless-dashboard'] });
      setShowScanModal(false);
    },
    onError: () => toast.error('Failed to start scan'),
  });

  const stopScanMutation = useMutation({
    mutationFn: (id: string) => wirelessAPI.stopScan(id),
    onSuccess: () => {
      toast.success('Scan stopped');
      queryClient.invalidateQueries({ queryKey: ['wireless-scans'] });
    },
  });

  const deauthMutation = useMutation({
    mutationFn: (data: { interface: string; bssid: string; client?: string; count?: number }) =>
      wirelessAPI.sendDeauth(data),
    onSuccess: () => {
      toast.success('Deauth packets sent');
    },
    onError: () => toast.error('Deauth failed'),
  });

  const captureHandshakeMutation = useMutation({
    mutationFn: (data: { interface: string; bssid: string; channel: number; timeout_secs?: number }) =>
      wirelessAPI.captureHandshake(data),
    onSuccess: () => {
      toast.success('Handshake captured!');
      queryClient.invalidateQueries({ queryKey: ['wireless-handshakes'] });
      queryClient.invalidateQueries({ queryKey: ['wireless-dashboard'] });
      setShowCaptureModal(false);
    },
    onError: () => toast.error('Handshake capture failed'),
  });

  const capturePmkidMutation = useMutation({
    mutationFn: (data: { interface: string; bssid: string; channel: number }) =>
      wirelessAPI.capturePmkid(data),
    onSuccess: (result) => {
      if (result.data) {
        toast.success('PMKID captured!');
        queryClient.invalidateQueries({ queryKey: ['wireless-dashboard'] });
      } else {
        toast.warning('No PMKID captured');
      }
    },
    onError: () => toast.error('PMKID capture failed'),
  });

  const wpsAttackMutation = useMutation({
    mutationFn: (data: { interface: string; bssid: string }) =>
      wirelessAPI.wpsPixieDust(data),
    onSuccess: (result) => {
      if (result.data?.success) {
        toast.success(`WPS cracked! PIN: ${result.data.pin}, PSK: ${result.data.psk}`);
      } else {
        toast.warning('WPS attack unsuccessful');
      }
    },
    onError: () => toast.error('WPS attack failed'),
  });

  const crackHandshakeMutation = useMutation({
    mutationFn: ({ id, wordlist }: { id: string; wordlist?: string }) => {
      setCrackingId(id);
      return wirelessAPI.crackHandshake(id, wordlist);
    },
    onSuccess: (result) => {
      if (result.data?.password) {
        toast.success(`Password cracked: ${result.data.password}`);
      } else {
        toast.warning('Password not found in wordlist');
      }
      queryClient.invalidateQueries({ queryKey: ['wireless-handshakes'] });
      setCrackingId(null);
    },
    onError: () => {
      toast.error('Cracking failed');
      setCrackingId(null);
    },
  });

  const getMonitorInterfaces = () => interfaces?.filter((i) => i.mode === 'monitor') || [];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
              Wireless Security Assessment
            </h1>
            <p className="text-slate-500 dark:text-slate-400">
              WiFi network discovery, handshake capture, and password cracking
            </p>
          </div>
          <Button onClick={() => setShowScanModal(true)}>
            <Search className="h-4 w-4 mr-2" />
            Start Scan
          </Button>
        </div>

        {/* Warning Banner */}
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-yellow-400 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-yellow-400">Authorization Required</p>
            <p className="text-sm text-slate-400">
              Wireless security assessment requires proper authorization. Only test networks you own or have
              explicit permission to assess. Deauthentication attacks can disrupt network services.
            </p>
          </div>
        </div>

        {/* Stats Overview */}
        {dashboard && (
          <div className="grid grid-cols-6 gap-4">
            <StatsCard
              label="Total Scans"
              value={dashboard.total_scans}
              icon={<Radio className="h-5 w-5 text-blue-400" />}
              color="bg-blue-500/10"
            />
            <StatsCard
              label="Active Scans"
              value={dashboard.active_scans}
              icon={<Activity className="h-5 w-5 text-green-400" />}
              color="bg-green-500/10"
            />
            <StatsCard
              label="Networks"
              value={dashboard.networks_discovered}
              icon={<Wifi className="h-5 w-5 text-cyan-400" />}
              color="bg-cyan-500/10"
            />
            <StatsCard
              label="Handshakes"
              value={dashboard.handshakes_captured}
              icon={<FileText className="h-5 w-5 text-purple-400" />}
              color="bg-purple-500/10"
            />
            <StatsCard
              label="PMKIDs"
              value={dashboard.pmkids_captured}
              icon={<Shield className="h-5 w-5 text-orange-400" />}
              color="bg-orange-500/10"
            />
            <StatsCard
              label="Cracked"
              value={dashboard.passwords_cracked}
              icon={<Key className="h-5 w-5 text-red-400" />}
              color="bg-red-500/10"
            />
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-2 border-b border-light-border dark:border-dark-border pb-2">
          {[
            { id: 'dashboard', label: 'Overview', icon: <Activity className="h-4 w-4" /> },
            { id: 'interfaces', label: 'Interfaces', icon: <Radio className="h-4 w-4" /> },
            { id: 'networks', label: 'Networks', icon: <Wifi className="h-4 w-4" /> },
            { id: 'scans', label: 'Scans', icon: <Search className="h-4 w-4" /> },
            { id: 'handshakes', label: 'Captures', icon: <Key className="h-4 w-4" /> },
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
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* Encryption Distribution */}
            {dashboard && Object.keys(dashboard.networks_by_encryption).length > 0 && (
              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                <h3 className="font-semibold text-slate-900 dark:text-white mb-4">
                  Networks by Encryption
                </h3>
                <div className="flex gap-4">
                  {Object.entries(dashboard.networks_by_encryption).map(([enc, count]) => (
                    <div key={enc} className="flex items-center gap-2">
                      <EncryptionBadge encryption={enc} />
                      <span className="text-slate-600 dark:text-slate-300">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Vulnerable Networks */}
            {dashboard && dashboard.top_vulnerable_networks.length > 0 && (
              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden">
                <div className="p-4 border-b border-light-border dark:border-dark-border">
                  <h3 className="font-semibold text-slate-900 dark:text-white">
                    Vulnerable Networks
                  </h3>
                </div>
                <table className="w-full">
                  <thead className="bg-light-bg dark:bg-dark-bg">
                    <tr>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">SSID</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">BSSID</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Encryption</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Vulnerability</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-light-border dark:divide-dark-border">
                    {dashboard.top_vulnerable_networks.map((network) => (
                      <tr key={network.bssid} className="hover:bg-light-hover dark:hover:bg-dark-hover">
                        <td className="px-4 py-3 text-sm font-medium text-slate-900 dark:text-white">
                          {network.ssid || '<Hidden>'}
                        </td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300 font-mono">
                          {network.bssid}
                        </td>
                        <td className="px-4 py-3">
                          <EncryptionBadge encryption={network.encryption} />
                        </td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">
                          {network.vulnerability}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-1 text-xs font-medium rounded border ${
                            network.severity === 'critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                            network.severity === 'high' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                            'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                          }`}>
                            {network.severity}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === 'interfaces' && (
          <div className="space-y-4">
            {loadingInterfaces ? (
              <div className="flex justify-center py-12">
                <RefreshCw className="h-8 w-8 animate-spin text-primary" />
              </div>
            ) : interfaces?.length === 0 ? (
              <div className="text-center py-12">
                <Radio className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  No wireless interfaces found
                </h3>
                <p className="text-slate-500 dark:text-slate-400">
                  Ensure a wireless adapter with monitor mode support is connected
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {interfaces?.map((iface) => (
                  <div key={iface.name} className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <Radio className={`h-5 w-5 ${iface.mode === 'monitor' ? 'text-green-400' : 'text-slate-400'}`} />
                        <div>
                          <h3 className="font-semibold text-slate-900 dark:text-white">{iface.name}</h3>
                          <p className="text-sm text-slate-500 dark:text-slate-400">{iface.driver}</p>
                        </div>
                      </div>
                      <span className={`px-2 py-1 text-xs font-medium rounded ${
                        iface.mode === 'monitor'
                          ? 'bg-green-500/20 text-green-400'
                          : 'bg-slate-500/20 text-slate-400'
                      }`}>
                        {iface.mode}
                      </span>
                    </div>
                    {iface.chipset && (
                      <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{iface.chipset}</p>
                    )}
                    <div className="flex gap-2">
                      {iface.mode === 'monitor' ? (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => disableMonitorMutation.mutate(iface.name)}
                          disabled={disableMonitorMutation.isPending}
                        >
                          <WifiOff className="h-4 w-4 mr-1" />
                          Disable Monitor
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          onClick={() => enableMonitorMutation.mutate(iface.name)}
                          disabled={!iface.monitor_capable || enableMonitorMutation.isPending}
                        >
                          <Wifi className="h-4 w-4 mr-1" />
                          Enable Monitor
                        </Button>
                      )}
                    </div>
                    {!iface.monitor_capable && (
                      <p className="text-xs text-red-400 mt-2">
                        This interface does not support monitor mode
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'networks' && (
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <p className="text-sm text-slate-500 dark:text-slate-400">
                {networks?.length || 0} networks discovered
              </p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => queryClient.invalidateQueries({ queryKey: ['wireless-networks'] })}
              >
                <RefreshCw className="h-4 w-4 mr-1" />
                Refresh
              </Button>
            </div>
            {loadingNetworks ? (
              <div className="flex justify-center py-12">
                <RefreshCw className="h-8 w-8 animate-spin text-primary" />
              </div>
            ) : networks?.length === 0 ? (
              <div className="text-center py-12">
                <Wifi className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  No networks discovered
                </h3>
                <p className="text-slate-500 dark:text-slate-400 mb-4">
                  Start a wireless scan to discover nearby networks
                </p>
                <Button onClick={() => setShowScanModal(true)}>
                  <Search className="h-4 w-4 mr-2" />
                  Start Scan
                </Button>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {networks?.map((network) => (
                  <NetworkCard
                    key={network.bssid}
                    network={network}
                    onCapture={() => {
                      setSelectedNetwork(network);
                      setShowCaptureModal(true);
                    }}
                    onDeauth={() => {
                      const monitorIface = getMonitorInterfaces()[0];
                      if (monitorIface) {
                        deauthMutation.mutate({
                          interface: monitorIface.name,
                          bssid: network.bssid,
                          count: 5,
                        });
                      } else {
                        toast.error('Enable monitor mode on an interface first');
                      }
                    }}
                    onPmkid={() => {
                      const monitorIface = getMonitorInterfaces()[0];
                      if (monitorIface) {
                        capturePmkidMutation.mutate({
                          interface: monitorIface.name,
                          bssid: network.bssid,
                          channel: network.channel,
                        });
                      } else {
                        toast.error('Enable monitor mode on an interface first');
                      }
                    }}
                    onWps={() => {
                      const monitorIface = getMonitorInterfaces()[0];
                      if (monitorIface) {
                        wpsAttackMutation.mutate({
                          interface: monitorIface.name,
                          bssid: network.bssid,
                        });
                      } else {
                        toast.error('Enable monitor mode on an interface first');
                      }
                    }}
                    isLoading={
                      deauthMutation.isPending ||
                      capturePmkidMutation.isPending ||
                      wpsAttackMutation.isPending
                    }
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'scans' && (
          <div className="space-y-4">
            {loadingScans ? (
              <div className="flex justify-center py-12">
                <RefreshCw className="h-8 w-8 animate-spin text-primary" />
              </div>
            ) : scans?.length === 0 ? (
              <div className="text-center py-12">
                <Search className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  No scans yet
                </h3>
                <p className="text-slate-500 dark:text-slate-400 mb-4">
                  Start a wireless scan to discover nearby networks
                </p>
                <Button onClick={() => setShowScanModal(true)}>
                  <Search className="h-4 w-4 mr-2" />
                  Start Scan
                </Button>
              </div>
            ) : (
              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-light-bg dark:bg-dark-bg">
                    <tr>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Interface</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Status</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Networks</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Clients</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Handshakes</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Started</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-light-border dark:divide-dark-border">
                    {scans?.map((scan) => (
                      <tr key={scan.id} className="hover:bg-light-hover dark:hover:bg-dark-hover">
                        <td className="px-4 py-3 text-sm font-medium text-slate-900 dark:text-white">
                          {scan.interface}
                        </td>
                        <td className="px-4 py-3">
                          <StatusBadge status={scan.status} />
                        </td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">
                          {scan.networks_found}
                        </td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">
                          {scan.clients_found}
                        </td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">
                          {scan.handshakes_captured}
                        </td>
                        <td className="px-4 py-3 text-sm text-slate-500 dark:text-slate-400">
                          {new Date(scan.started_at).toLocaleString()}
                        </td>
                        <td className="px-4 py-3">
                          {scan.status === 'running' && (
                            <Button
                              size="sm"
                              variant="ghost"
                              className="text-red-400"
                              onClick={() => stopScanMutation.mutate(scan.id)}
                            >
                              <Square className="h-4 w-4" />
                            </Button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === 'handshakes' && (
          <div className="space-y-4">
            {loadingHandshakes ? (
              <div className="flex justify-center py-12">
                <RefreshCw className="h-8 w-8 animate-spin text-primary" />
              </div>
            ) : handshakes?.length === 0 ? (
              <div className="text-center py-12">
                <Key className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  No handshakes captured
                </h3>
                <p className="text-slate-500 dark:text-slate-400">
                  Capture WPA handshakes from target networks to crack passwords
                </p>
              </div>
            ) : (
              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-light-bg dark:bg-dark-bg">
                    <tr>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Network</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Client</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Status</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Password</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Captured</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-light-border dark:divide-dark-border">
                    {handshakes?.map((handshake) => (
                      <HandshakeRow
                        key={handshake.id}
                        handshake={handshake}
                        onCrack={() => crackHandshakeMutation.mutate({ id: handshake.id })}
                        isCracking={crackingId === handshake.id}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Start Scan Modal */}
        {showScanModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6 w-full max-w-md">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">
                Start Wireless Scan
              </h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                    Interface
                  </label>
                  <select
                    value={scanConfig.interface}
                    onChange={(e) => setScanConfig({ ...scanConfig, interface: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white"
                  >
                    <option value="">Select interface...</option>
                    {getMonitorInterfaces().map((iface) => (
                      <option key={iface.name} value={iface.name}>
                        {iface.name} (monitor mode)
                      </option>
                    ))}
                  </select>
                  {getMonitorInterfaces().length === 0 && (
                    <p className="text-xs text-yellow-400 mt-1">
                      Enable monitor mode on an interface first
                    </p>
                  )}
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                    Duration (seconds)
                  </label>
                  <input
                    type="number"
                    value={scanConfig.duration_secs}
                    onChange={(e) => setScanConfig({ ...scanConfig, duration_secs: parseInt(e.target.value) })}
                    className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white"
                    min="10"
                    max="3600"
                  />
                </div>
              </div>
              <div className="flex justify-end gap-2 mt-6">
                <Button variant="outline" onClick={() => setShowScanModal(false)}>
                  Cancel
                </Button>
                <Button
                  onClick={() => startScanMutation.mutate(scanConfig)}
                  disabled={!scanConfig.interface || startScanMutation.isPending}
                >
                  {startScanMutation.isPending ? (
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Play className="h-4 w-4 mr-2" />
                  )}
                  Start Scan
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* Capture Handshake Modal */}
        {showCaptureModal && selectedNetwork && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6 w-full max-w-md">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">
                Capture WPA Handshake
              </h2>
              <div className="space-y-4">
                <div className="bg-light-bg dark:bg-dark-bg rounded p-3">
                  <p className="text-sm text-slate-500 dark:text-slate-400">Target Network:</p>
                  <p className="font-semibold text-slate-900 dark:text-white">
                    {selectedNetwork.ssid || '<Hidden SSID>'}
                  </p>
                  <p className="text-xs text-slate-400 font-mono">{selectedNetwork.bssid}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                    Interface
                  </label>
                  <select
                    value={selectedInterface}
                    onChange={(e) => setSelectedInterface(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white"
                  >
                    <option value="">Select interface...</option>
                    {getMonitorInterfaces().map((iface) => (
                      <option key={iface.name} value={iface.name}>
                        {iface.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="text-sm text-slate-500 dark:text-slate-400">
                  <p>This will:</p>
                  <ul className="list-disc list-inside mt-1">
                    <li>Lock to channel {selectedNetwork.channel}</li>
                    <li>Send deauth packets to force reconnection</li>
                    <li>Capture the 4-way handshake</li>
                  </ul>
                </div>
              </div>
              <div className="flex justify-end gap-2 mt-6">
                <Button variant="outline" onClick={() => setShowCaptureModal(false)}>
                  Cancel
                </Button>
                <Button
                  onClick={() => {
                    if (selectedInterface && selectedNetwork) {
                      captureHandshakeMutation.mutate({
                        interface: selectedInterface,
                        bssid: selectedNetwork.bssid,
                        channel: selectedNetwork.channel,
                        timeout_secs: 120,
                      });
                    }
                  }}
                  disabled={!selectedInterface || captureHandshakeMutation.isPending}
                >
                  {captureHandshakeMutation.isPending ? (
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Target className="h-4 w-4 mr-2" />
                  )}
                  Start Capture
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default WirelessPage;
