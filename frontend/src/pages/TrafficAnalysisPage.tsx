import React, { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Network,
  Upload,
  Play,
  Eye,
  Trash2,
  Download,
  RefreshCw,
  AlertTriangle,
  Shield,
  FileText,
  Globe,
  Lock,
  Radio,
  Activity,
  Clock,
  CheckCircle,
  XCircle,
  Filter,
  Search,
  Plus,
  X,
  ChevronDown,
  ChevronRight,
  FileCode,
  Fingerprint,
  AlertCircle,
  BarChart3,
  Settings,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import api from '../services/api';

type TabType = 'captures' | 'sessions' | 'alerts' | 'carved' | 'dns' | 'tls' | 'beacons' | 'rules' | 'fingerprints' | 'live';

// ============================================================================
// Types
// ============================================================================

interface TrafficStats {
  total_captures: number;
  total_sessions: number;
  total_packets: number;
  total_bytes: number;
  total_alerts: number;
  total_carved_files: number;
  protocol_breakdown: Record<string, number>;
}

interface PcapCapture {
  id: string;
  user_id: string;
  name: string;
  description?: string;
  file_path: string;
  file_size: number;
  packet_count: number;
  duration_seconds: number;
  capture_start?: string;
  capture_end?: string;
  status: string;
  sessions_count: number;
  alerts_count: number;
  carved_files_count: number;
  created_at: string;
  analyzed_at?: string;
}

interface NetworkSession {
  id: string;
  capture_id: string;
  session_type: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  start_time: string;
  end_time?: string;
  packets: number;
  bytes_to_server: number;
  bytes_to_client: number;
  state: string;
  application_protocol?: string;
}

interface IdsAlert {
  id: string;
  capture_id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  message: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  timestamp: string;
  created_at: string;
}

interface CarvedFile {
  id: string;
  capture_id: string;
  file_name?: string;
  file_type: string;
  mime_type: string;
  file_size: number;
  file_hash: string;
  src_ip: string;
  dst_ip: string;
  extraction_method: string;
  is_malicious: boolean;
  created_at: string;
}

interface DnsQuery {
  id: string;
  capture_id: string;
  session_id?: string;
  query_name: string;
  query_type: string;
  response_code?: string;
  answers?: string[];
  src_ip: string;
  dst_ip: string;
  timestamp: string;
  is_suspicious: boolean;
  dga_score?: number;
}

interface TlsInfo {
  id: string;
  capture_id: string;
  session_id: string;
  server_name?: string;
  ja3_fingerprint?: string;
  ja3s_fingerprint?: string;
  cipher_suite?: string;
  tls_version?: string;
  certificate_subject?: string;
  certificate_issuer?: string;
  certificate_not_before?: string;
  certificate_not_after?: string;
  is_self_signed: boolean;
  is_expired: boolean;
}

interface Beacon {
  id: string;
  capture_id: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  interval_seconds: number;
  jitter_percent: number;
  data_size_avg: number;
  connection_count: number;
  first_seen: string;
  last_seen: string;
  confidence: number;
  is_confirmed: boolean;
}

interface IdsRule {
  id: string;
  user_id: string;
  name: string;
  content: string;
  severity: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

interface Ja3Fingerprint {
  id: string;
  fingerprint: string;
  fingerprint_type: string;
  first_seen: string;
  last_seen: string;
  hits: number;
  known_client?: string;
  is_malicious: boolean;
  notes?: string;
}

interface NetworkInterface {
  name: string;
  description?: string;
  addresses: string[];
  is_up: boolean;
  is_loopback: boolean;
}

interface LiveCaptureInfo {
  id: string;
  interface: string;
  filter?: string;
  file_path: string;
  started_at: string;
  status: 'running' | 'stopped' | 'error';
  packet_count: number;
  bytes_captured: number;
}

// ============================================================================
// API
// ============================================================================

const trafficApi = {
  // Stats
  getStats: () => api.get<TrafficStats>('/traffic-analysis/stats').then(r => r.data),

  // Captures
  listCaptures: () => api.get<PcapCapture[]>('/traffic-analysis/captures').then(r => r.data),
  getCapture: (id: string) => api.get<PcapCapture>(`/traffic-analysis/captures/${id}`).then(r => r.data),
  uploadCapture: (formData: FormData) =>
    api.post<{ id: string }>('/traffic-analysis/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    }).then(r => r.data),
  analyzeCapture: (id: string, config?: object) =>
    api.post<{ message: string }>(`/traffic-analysis/captures/${id}/analyze`, config).then(r => r.data),
  deleteCapture: (id: string) => api.delete(`/traffic-analysis/captures/${id}`).then(r => r.data),

  // Sessions
  listSessions: (captureId: string, params?: object) =>
    api.get<NetworkSession[]>(`/traffic-analysis/captures/${captureId}/sessions`, { params }).then(r => r.data),

  // Alerts
  listAlerts: (captureId: string, params?: object) =>
    api.get<IdsAlert[]>(`/traffic-analysis/captures/${captureId}/alerts`, { params }).then(r => r.data),

  // Carved files
  listCarvedFiles: (captureId: string) =>
    api.get<CarvedFile[]>(`/traffic-analysis/captures/${captureId}/carved-files`).then(r => r.data),
  downloadCarvedFile: (fileId: string) =>
    api.get(`/traffic-analysis/carved-files/${fileId}/download`, { responseType: 'blob' }).then(r => r.data),

  // DNS
  listDnsQueries: (captureId: string, params?: object) =>
    api.get<DnsQuery[]>(`/traffic-analysis/captures/${captureId}/dns`, { params }).then(r => r.data),

  // TLS
  listTlsInfo: (captureId: string) =>
    api.get<TlsInfo[]>(`/traffic-analysis/captures/${captureId}/tls`).then(r => r.data),

  // Beacons
  listBeacons: (captureId: string) =>
    api.get<Beacon[]>(`/traffic-analysis/captures/${captureId}/beacons`).then(r => r.data),

  // IDS Rules
  listRules: () => api.get<IdsRule[]>('/traffic-analysis/rules').then(r => r.data),
  createRule: (rule: { name: string; content: string; severity: string }) =>
    api.post<IdsRule>('/traffic-analysis/rules', rule).then(r => r.data),
  updateRule: (id: string, rule: Partial<IdsRule>) =>
    api.put<IdsRule>(`/traffic-analysis/rules/${id}`, rule).then(r => r.data),
  deleteRule: (id: string) => api.delete(`/traffic-analysis/rules/${id}`).then(r => r.data),
  validateRule: (content: string) =>
    api.post<{ valid: boolean; error?: string }>('/traffic-analysis/rules/validate', { content }).then(r => r.data),

  // Fingerprints
  listFingerprints: (params?: object) =>
    api.get<Ja3Fingerprint[]>('/traffic-analysis/fingerprints', { params }).then(r => r.data),
  lookupFingerprint: (fingerprint: string) =>
    api.get<Ja3Fingerprint>(`/traffic-analysis/fingerprints/${fingerprint}`).then(r => r.data),

  // Live Capture
  listInterfaces: () =>
    api.get<{ interfaces: NetworkInterface[] }>('/traffic-analysis/interfaces').then(r => r.data.interfaces),
  startLiveCapture: (data: { interface: string; filter?: string; promiscuous?: boolean; max_packets?: number; max_duration_secs?: number }) =>
    api.post<LiveCaptureInfo>('/traffic-analysis/live/start', data).then(r => r.data),
  stopLiveCapture: (id: string) =>
    api.post<LiveCaptureInfo>(`/traffic-analysis/live/stop/${id}`).then(r => r.data),
  listLiveCaptures: () =>
    api.get<{ captures: LiveCaptureInfo[] }>('/traffic-analysis/live/status').then(r => r.data.captures),
  getLiveCaptureStatus: (id: string) =>
    api.get<LiveCaptureInfo>(`/traffic-analysis/live/status/${id}`).then(r => r.data),
};

// ============================================================================
// Helper Components
// ============================================================================

const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const colors: Record<string, string> = {
    pending: 'bg-yellow-500/20 text-yellow-400',
    analyzing: 'bg-blue-500/20 text-blue-400',
    completed: 'bg-green-500/20 text-green-400',
    failed: 'bg-red-500/20 text-red-400',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs ${colors[status] || 'bg-gray-500/20 text-gray-400'}`}>
      {status}
    </span>
  );
};

const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => {
  const colors: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400',
    high: 'bg-orange-500/20 text-orange-400',
    medium: 'bg-yellow-500/20 text-yellow-400',
    low: 'bg-blue-500/20 text-blue-400',
    info: 'bg-gray-500/20 text-gray-400',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs ${colors[severity.toLowerCase()] || 'bg-gray-500/20 text-gray-400'}`}>
      {severity}
    </span>
  );
};

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const formatDuration = (seconds: number): string => {
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.floor(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
};

// ============================================================================
// Main Component
// ============================================================================

const TrafficAnalysisPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('captures');
  const [selectedCapture, setSelectedCapture] = useState<PcapCapture | null>(null);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [ruleToEdit, setRuleToEdit] = useState<IdsRule | null>(null);

  // Queries
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['traffic-stats'],
    queryFn: trafficApi.getStats,
  });

  const { data: captures = [], isLoading: capturesLoading, refetch: refetchCaptures } = useQuery({
    queryKey: ['traffic-captures'],
    queryFn: trafficApi.listCaptures,
  });

  const { data: rules = [], isLoading: rulesLoading } = useQuery({
    queryKey: ['traffic-rules'],
    queryFn: trafficApi.listRules,
    enabled: activeTab === 'rules',
  });

  const { data: fingerprints = [], isLoading: fingerprintsLoading } = useQuery({
    queryKey: ['traffic-fingerprints'],
    queryFn: () => trafficApi.listFingerprints(),
    enabled: activeTab === 'fingerprints',
  });

  // Capture-specific queries
  const { data: sessions = [], isLoading: sessionsLoading } = useQuery({
    queryKey: ['traffic-sessions', selectedCapture?.id],
    queryFn: () => trafficApi.listSessions(selectedCapture!.id),
    enabled: !!selectedCapture && activeTab === 'sessions',
  });

  const { data: alerts = [], isLoading: alertsLoading } = useQuery({
    queryKey: ['traffic-alerts', selectedCapture?.id],
    queryFn: () => trafficApi.listAlerts(selectedCapture!.id),
    enabled: !!selectedCapture && activeTab === 'alerts',
  });

  const { data: carvedFiles = [], isLoading: carvedLoading } = useQuery({
    queryKey: ['traffic-carved', selectedCapture?.id],
    queryFn: () => trafficApi.listCarvedFiles(selectedCapture!.id),
    enabled: !!selectedCapture && activeTab === 'carved',
  });

  const { data: dnsQueries = [], isLoading: dnsLoading } = useQuery({
    queryKey: ['traffic-dns', selectedCapture?.id],
    queryFn: () => trafficApi.listDnsQueries(selectedCapture!.id),
    enabled: !!selectedCapture && activeTab === 'dns',
  });

  const { data: tlsInfo = [], isLoading: tlsLoading } = useQuery({
    queryKey: ['traffic-tls', selectedCapture?.id],
    queryFn: () => trafficApi.listTlsInfo(selectedCapture!.id),
    enabled: !!selectedCapture && activeTab === 'tls',
  });

  const { data: beacons = [], isLoading: beaconsLoading } = useQuery({
    queryKey: ['traffic-beacons', selectedCapture?.id],
    queryFn: () => trafficApi.listBeacons(selectedCapture!.id),
    enabled: !!selectedCapture && activeTab === 'beacons',
  });

  // Live capture queries
  const { data: interfaces = [], isLoading: interfacesLoading } = useQuery({
    queryKey: ['traffic-interfaces'],
    queryFn: trafficApi.listInterfaces,
    enabled: activeTab === 'live',
  });

  const { data: liveCaptures = [], isLoading: liveCapturesLoading, refetch: refetchLiveCaptures } = useQuery({
    queryKey: ['traffic-live-captures'],
    queryFn: trafficApi.listLiveCaptures,
    enabled: activeTab === 'live',
    refetchInterval: activeTab === 'live' ? 2000 : false, // Auto-refresh every 2s when active
  });

  // Mutations
  const uploadMutation = useMutation({
    mutationFn: trafficApi.uploadCapture,
    onSuccess: () => {
      toast.success('PCAP uploaded successfully');
      queryClient.invalidateQueries({ queryKey: ['traffic-captures'] });
      queryClient.invalidateQueries({ queryKey: ['traffic-stats'] });
      setShowUploadModal(false);
    },
    onError: (err: Error) => toast.error(`Upload failed: ${err.message}`),
  });

  const analyzeMutation = useMutation({
    mutationFn: (id: string) => trafficApi.analyzeCapture(id),
    onSuccess: () => {
      toast.success('Analysis started');
      queryClient.invalidateQueries({ queryKey: ['traffic-captures'] });
    },
    onError: (err: Error) => toast.error(`Analysis failed: ${err.message}`),
  });

  const deleteMutation = useMutation({
    mutationFn: trafficApi.deleteCapture,
    onSuccess: () => {
      toast.success('Capture deleted');
      queryClient.invalidateQueries({ queryKey: ['traffic-captures'] });
      queryClient.invalidateQueries({ queryKey: ['traffic-stats'] });
      if (selectedCapture) setSelectedCapture(null);
    },
    onError: (err: Error) => toast.error(`Delete failed: ${err.message}`),
  });

  const createRuleMutation = useMutation({
    mutationFn: trafficApi.createRule,
    onSuccess: () => {
      toast.success('Rule created');
      queryClient.invalidateQueries({ queryKey: ['traffic-rules'] });
      setShowRuleModal(false);
    },
    onError: (err: Error) => toast.error(`Failed to create rule: ${err.message}`),
  });

  const deleteRuleMutation = useMutation({
    mutationFn: trafficApi.deleteRule,
    onSuccess: () => {
      toast.success('Rule deleted');
      queryClient.invalidateQueries({ queryKey: ['traffic-rules'] });
    },
    onError: (err: Error) => toast.error(`Failed to delete rule: ${err.message}`),
  });

  // Live capture mutations
  const startCaptureMutation = useMutation({
    mutationFn: trafficApi.startLiveCapture,
    onSuccess: () => {
      toast.success('Live capture started');
      queryClient.invalidateQueries({ queryKey: ['traffic-live-captures'] });
    },
    onError: (err: Error) => toast.error(`Failed to start capture: ${err.message}`),
  });

  const stopCaptureMutation = useMutation({
    mutationFn: trafficApi.stopLiveCapture,
    onSuccess: () => {
      toast.success('Capture stopped');
      queryClient.invalidateQueries({ queryKey: ['traffic-live-captures'] });
      queryClient.invalidateQueries({ queryKey: ['traffic-captures'] });
      queryClient.invalidateQueries({ queryKey: ['traffic-stats'] });
    },
    onError: (err: Error) => toast.error(`Failed to stop capture: ${err.message}`),
  });

  // Handlers
  const handleUpload = useCallback((e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const formData = new FormData(form);
    uploadMutation.mutate(formData);
  }, [uploadMutation]);

  const handleCreateRule = useCallback((e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const formData = new FormData(form);
    createRuleMutation.mutate({
      name: formData.get('name') as string,
      content: formData.get('content') as string,
      severity: formData.get('severity') as string,
    });
  }, [createRuleMutation]);

  // Tabs configuration
  const tabs: { id: TabType; label: string; icon: React.ReactNode; requiresCapture?: boolean }[] = [
    { id: 'live', label: 'Live Capture', icon: <Radio size={16} /> },
    { id: 'captures', label: 'Captures', icon: <FileText size={16} /> },
    { id: 'sessions', label: 'Sessions', icon: <Network size={16} />, requiresCapture: true },
    { id: 'alerts', label: 'IDS Alerts', icon: <AlertTriangle size={16} />, requiresCapture: true },
    { id: 'carved', label: 'Carved Files', icon: <FileCode size={16} />, requiresCapture: true },
    { id: 'dns', label: 'DNS', icon: <Globe size={16} />, requiresCapture: true },
    { id: 'tls', label: 'TLS/SSL', icon: <Lock size={16} />, requiresCapture: true },
    { id: 'beacons', label: 'Beacons', icon: <Radio size={16} />, requiresCapture: true },
    { id: 'rules', label: 'IDS Rules', icon: <Shield size={16} /> },
    { id: 'fingerprints', label: 'Fingerprints', icon: <Fingerprint size={16} /> },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <Network className="text-cyan-400" />
              Traffic Analysis
            </h1>
            <p className="text-gray-400 mt-1">
              Analyze network captures, detect threats, and extract artifacts
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => refetchCaptures()}
              className="px-3 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600 flex items-center gap-2"
            >
              <RefreshCw size={16} />
              Refresh
            </button>
            <button
              onClick={() => setShowUploadModal(true)}
              className="px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 flex items-center gap-2"
            >
              <Upload size={16} />
              Upload PCAP
            </button>
          </div>
        </div>

        {/* Stats */}
        {!statsLoading && stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-gray-400 text-sm">Captures</div>
              <div className="text-2xl font-bold text-white">{stats.total_captures}</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-gray-400 text-sm">Sessions</div>
              <div className="text-2xl font-bold text-white">{stats.total_sessions.toLocaleString()}</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-gray-400 text-sm">Packets</div>
              <div className="text-2xl font-bold text-white">{stats.total_packets.toLocaleString()}</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-gray-400 text-sm">Total Data</div>
              <div className="text-2xl font-bold text-white">{formatBytes(stats.total_bytes)}</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-gray-400 text-sm">IDS Alerts</div>
              <div className="text-2xl font-bold text-red-400">{stats.total_alerts}</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-gray-400 text-sm">Carved Files</div>
              <div className="text-2xl font-bold text-yellow-400">{stats.total_carved_files}</div>
            </div>
          </div>
        )}

        {/* Selected Capture Info */}
        {selectedCapture && (
          <div className="bg-gray-800 rounded-lg p-4 border border-cyan-500/30">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <FileText className="text-cyan-400" size={24} />
                <div>
                  <h3 className="text-white font-medium">{selectedCapture.name}</h3>
                  <p className="text-gray-400 text-sm">
                    {formatBytes(selectedCapture.file_size)} • {selectedCapture.packet_count.toLocaleString()} packets • {formatDuration(selectedCapture.duration_seconds)}
                  </p>
                </div>
                <StatusBadge status={selectedCapture.status} />
              </div>
              <button
                onClick={() => setSelectedCapture(null)}
                className="text-gray-400 hover:text-white"
              >
                <X size={20} />
              </button>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-2 border-b border-gray-700 pb-2 overflow-x-auto">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => {
                if (tab.requiresCapture && !selectedCapture) {
                  toast.info('Please select a capture first');
                  return;
                }
                setActiveTab(tab.id);
              }}
              className={`px-4 py-2 rounded-lg flex items-center gap-2 whitespace-nowrap ${
                activeTab === tab.id
                  ? 'bg-cyan-600 text-white'
                  : tab.requiresCapture && !selectedCapture
                  ? 'bg-gray-800 text-gray-500 cursor-not-allowed'
                  : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="bg-gray-800 rounded-lg overflow-hidden">
          {activeTab === 'live' && (
            <LiveCaptureTab
              interfaces={interfaces}
              captures={liveCaptures}
              interfacesLoading={interfacesLoading}
              capturesLoading={liveCapturesLoading}
              onStart={(data) => startCaptureMutation.mutate(data)}
              onStop={(id) => stopCaptureMutation.mutate(id)}
              isStarting={startCaptureMutation.isPending}
              isStopping={stopCaptureMutation.isPending}
            />
          )}
          {activeTab === 'captures' && (
            <CapturesTab
              captures={captures}
              loading={capturesLoading}
              selectedCapture={selectedCapture}
              onSelect={setSelectedCapture}
              onAnalyze={(id) => analyzeMutation.mutate(id)}
              onDelete={(id) => deleteMutation.mutate(id)}
            />
          )}
          {activeTab === 'sessions' && selectedCapture && (
            <SessionsTab sessions={sessions} loading={sessionsLoading} />
          )}
          {activeTab === 'alerts' && selectedCapture && (
            <AlertsTab alerts={alerts} loading={alertsLoading} />
          )}
          {activeTab === 'carved' && selectedCapture && (
            <CarvedFilesTab files={carvedFiles} loading={carvedLoading} />
          )}
          {activeTab === 'dns' && selectedCapture && (
            <DnsTab queries={dnsQueries} loading={dnsLoading} />
          )}
          {activeTab === 'tls' && selectedCapture && (
            <TlsTab tlsInfo={tlsInfo} loading={tlsLoading} />
          )}
          {activeTab === 'beacons' && selectedCapture && (
            <BeaconsTab beacons={beacons} loading={beaconsLoading} />
          )}
          {activeTab === 'rules' && (
            <RulesTab
              rules={rules}
              loading={rulesLoading}
              onAdd={() => setShowRuleModal(true)}
              onDelete={(id) => deleteRuleMutation.mutate(id)}
            />
          )}
          {activeTab === 'fingerprints' && (
            <FingerprintsTab fingerprints={fingerprints} loading={fingerprintsLoading} />
          )}
        </div>

        {/* Upload Modal */}
        {showUploadModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-bold text-white">Upload PCAP</h2>
                <button onClick={() => setShowUploadModal(false)} className="text-gray-400 hover:text-white">
                  <X size={20} />
                </button>
              </div>
              <form onSubmit={handleUpload} className="space-y-4">
                <div>
                  <label className="block text-gray-400 text-sm mb-1">PCAP File</label>
                  <input
                    type="file"
                    name="file"
                    accept=".pcap,.pcapng,.cap"
                    required
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                  />
                </div>
                <div>
                  <label className="block text-gray-400 text-sm mb-1">Description (optional)</label>
                  <textarea
                    name="description"
                    rows={3}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                    placeholder="Describe this capture..."
                  />
                </div>
                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setShowUploadModal(false)}
                    className="px-4 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={uploadMutation.isPending}
                    className="px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 disabled:opacity-50"
                  >
                    {uploadMutation.isPending ? 'Uploading...' : 'Upload'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Rule Modal */}
        {showRuleModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-bold text-white">
                  {ruleToEdit ? 'Edit IDS Rule' : 'Add IDS Rule'}
                </h2>
                <button onClick={() => { setShowRuleModal(false); setRuleToEdit(null); }} className="text-gray-400 hover:text-white">
                  <X size={20} />
                </button>
              </div>
              <form onSubmit={handleCreateRule} className="space-y-4">
                <div>
                  <label className="block text-gray-400 text-sm mb-1">Rule Name</label>
                  <input
                    type="text"
                    name="name"
                    required
                    defaultValue={ruleToEdit?.name}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                    placeholder="My Custom Rule"
                  />
                </div>
                <div>
                  <label className="block text-gray-400 text-sm mb-1">Severity</label>
                  <select
                    name="severity"
                    defaultValue={ruleToEdit?.severity || 'medium'}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                  </select>
                </div>
                <div>
                  <label className="block text-gray-400 text-sm mb-1">Rule Content (Suricata/Snort format)</label>
                  <textarea
                    name="content"
                    required
                    rows={6}
                    defaultValue={ruleToEdit?.content}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white font-mono text-sm"
                    placeholder='alert tcp any any -> any 80 (msg:"HTTP Request"; content:"GET"; sid:1000001; rev:1;)'
                  />
                </div>
                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => { setShowRuleModal(false); setRuleToEdit(null); }}
                    className="px-4 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={createRuleMutation.isPending}
                    className="px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 disabled:opacity-50"
                  >
                    {createRuleMutation.isPending ? 'Saving...' : 'Save Rule'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

// ============================================================================
// Tab Components
// ============================================================================

const CapturesTab: React.FC<{
  captures: PcapCapture[];
  loading: boolean;
  selectedCapture: PcapCapture | null;
  onSelect: (capture: PcapCapture) => void;
  onAnalyze: (id: string) => void;
  onDelete: (id: string) => void;
}> = ({ captures, loading, selectedCapture, onSelect, onAnalyze, onDelete }) => {
  if (loading) {
    return <div className="p-8 text-center text-gray-400">Loading captures...</div>;
  }

  if (captures.length === 0) {
    return (
      <div className="p-8 text-center text-gray-400">
        <Network size={48} className="mx-auto mb-4 opacity-50" />
        <p>No captures yet. Upload a PCAP file to get started.</p>
      </div>
    );
  }

  return (
    <table className="w-full">
      <thead className="bg-gray-900">
        <tr>
          <th className="px-4 py-3 text-left text-gray-400 text-sm">Name</th>
          <th className="px-4 py-3 text-left text-gray-400 text-sm">Size</th>
          <th className="px-4 py-3 text-left text-gray-400 text-sm">Packets</th>
          <th className="px-4 py-3 text-left text-gray-400 text-sm">Duration</th>
          <th className="px-4 py-3 text-left text-gray-400 text-sm">Status</th>
          <th className="px-4 py-3 text-left text-gray-400 text-sm">Sessions</th>
          <th className="px-4 py-3 text-left text-gray-400 text-sm">Alerts</th>
          <th className="px-4 py-3 text-left text-gray-400 text-sm">Uploaded</th>
          <th className="px-4 py-3 text-right text-gray-400 text-sm">Actions</th>
        </tr>
      </thead>
      <tbody>
        {captures.map((capture) => (
          <tr
            key={capture.id}
            className={`border-t border-gray-700 hover:bg-gray-700/50 cursor-pointer ${
              selectedCapture?.id === capture.id ? 'bg-cyan-500/10' : ''
            }`}
            onClick={() => onSelect(capture)}
          >
            <td className="px-4 py-3 text-white">{capture.name}</td>
            <td className="px-4 py-3 text-gray-300">{formatBytes(capture.file_size)}</td>
            <td className="px-4 py-3 text-gray-300">{capture.packet_count.toLocaleString()}</td>
            <td className="px-4 py-3 text-gray-300">{formatDuration(capture.duration_seconds)}</td>
            <td className="px-4 py-3"><StatusBadge status={capture.status} /></td>
            <td className="px-4 py-3 text-gray-300">{capture.sessions_count}</td>
            <td className="px-4 py-3">
              {capture.alerts_count > 0 ? (
                <span className="text-red-400">{capture.alerts_count}</span>
              ) : (
                <span className="text-gray-500">0</span>
              )}
            </td>
            <td className="px-4 py-3 text-gray-400 text-sm">
              {new Date(capture.created_at).toLocaleDateString()}
            </td>
            <td className="px-4 py-3 text-right">
              <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                {capture.status === 'pending' && (
                  <button
                    onClick={() => onAnalyze(capture.id)}
                    className="p-1 text-cyan-400 hover:text-cyan-300"
                    title="Analyze"
                  >
                    <Play size={16} />
                  </button>
                )}
                <button
                  onClick={() => onDelete(capture.id)}
                  className="p-1 text-red-400 hover:text-red-300"
                  title="Delete"
                >
                  <Trash2 size={16} />
                </button>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};

const SessionsTab: React.FC<{ sessions: NetworkSession[]; loading: boolean }> = ({ sessions, loading }) => {
  if (loading) return <div className="p-8 text-center text-gray-400">Loading sessions...</div>;
  if (sessions.length === 0) return <div className="p-8 text-center text-gray-400">No sessions found</div>;

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead className="bg-gray-900">
          <tr>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Type</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Source</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Destination</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Protocol</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Packets</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Bytes</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">State</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((session) => (
            <tr key={session.id} className="border-t border-gray-700 hover:bg-gray-700/50">
              <td className="px-4 py-3 text-gray-300">{session.session_type}</td>
              <td className="px-4 py-3 text-white font-mono text-sm">{session.src_ip}:{session.src_port}</td>
              <td className="px-4 py-3 text-white font-mono text-sm">{session.dst_ip}:{session.dst_port}</td>
              <td className="px-4 py-3 text-gray-300">{session.application_protocol || session.protocol}</td>
              <td className="px-4 py-3 text-gray-300">{session.packets}</td>
              <td className="px-4 py-3 text-gray-300">{formatBytes(session.bytes_to_server + session.bytes_to_client)}</td>
              <td className="px-4 py-3"><StatusBadge status={session.state} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const AlertsTab: React.FC<{ alerts: IdsAlert[]; loading: boolean }> = ({ alerts, loading }) => {
  if (loading) return <div className="p-8 text-center text-gray-400">Loading alerts...</div>;
  if (alerts.length === 0) return <div className="p-8 text-center text-gray-400">No IDS alerts found</div>;

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead className="bg-gray-900">
          <tr>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Severity</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Rule</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Message</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Source</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Destination</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Time</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} className="border-t border-gray-700 hover:bg-gray-700/50">
              <td className="px-4 py-3"><SeverityBadge severity={alert.severity} /></td>
              <td className="px-4 py-3 text-gray-300 font-mono text-sm">{alert.rule_id}</td>
              <td className="px-4 py-3 text-white">{alert.message}</td>
              <td className="px-4 py-3 text-white font-mono text-sm">{alert.src_ip}:{alert.src_port}</td>
              <td className="px-4 py-3 text-white font-mono text-sm">{alert.dst_ip}:{alert.dst_port}</td>
              <td className="px-4 py-3 text-gray-400 text-sm">{new Date(alert.timestamp).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const CarvedFilesTab: React.FC<{ files: CarvedFile[]; loading: boolean }> = ({ files, loading }) => {
  if (loading) return <div className="p-8 text-center text-gray-400">Loading carved files...</div>;
  if (files.length === 0) return <div className="p-8 text-center text-gray-400">No carved files found</div>;

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead className="bg-gray-900">
          <tr>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Filename</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Type</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Size</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">SHA256</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Source</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Malicious</th>
            <th className="px-4 py-3 text-right text-gray-400 text-sm">Actions</th>
          </tr>
        </thead>
        <tbody>
          {files.map((file) => (
            <tr key={file.id} className="border-t border-gray-700 hover:bg-gray-700/50">
              <td className="px-4 py-3 text-white">{file.file_name || 'Unknown'}</td>
              <td className="px-4 py-3 text-gray-300">{file.mime_type}</td>
              <td className="px-4 py-3 text-gray-300">{formatBytes(file.file_size)}</td>
              <td className="px-4 py-3 text-gray-400 font-mono text-xs">{file.file_hash.slice(0, 16)}...</td>
              <td className="px-4 py-3 text-white font-mono text-sm">{file.src_ip} → {file.dst_ip}</td>
              <td className="px-4 py-3">
                {file.is_malicious ? (
                  <span className="text-red-400 flex items-center gap-1">
                    <AlertCircle size={14} /> Yes
                  </span>
                ) : (
                  <span className="text-gray-500">No</span>
                )}
              </td>
              <td className="px-4 py-3 text-right">
                <button className="p-1 text-cyan-400 hover:text-cyan-300" title="Download">
                  <Download size={16} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const DnsTab: React.FC<{ queries: DnsQuery[]; loading: boolean }> = ({ queries, loading }) => {
  if (loading) return <div className="p-8 text-center text-gray-400">Loading DNS queries...</div>;
  if (queries.length === 0) return <div className="p-8 text-center text-gray-400">No DNS queries found</div>;

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead className="bg-gray-900">
          <tr>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Query</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Type</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Response</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Answers</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">DGA Score</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Suspicious</th>
          </tr>
        </thead>
        <tbody>
          {queries.map((query) => (
            <tr key={query.id} className="border-t border-gray-700 hover:bg-gray-700/50">
              <td className="px-4 py-3 text-white font-mono text-sm">{query.query_name}</td>
              <td className="px-4 py-3 text-gray-300">{query.query_type}</td>
              <td className="px-4 py-3 text-gray-300">{query.response_code || '-'}</td>
              <td className="px-4 py-3 text-gray-400 text-sm">
                {query.answers?.slice(0, 2).join(', ') || '-'}
              </td>
              <td className="px-4 py-3">
                {query.dga_score !== undefined && query.dga_score !== null ? (
                  <span className={query.dga_score > 0.7 ? 'text-red-400' : query.dga_score > 0.4 ? 'text-yellow-400' : 'text-gray-400'}>
                    {(query.dga_score * 100).toFixed(0)}%
                  </span>
                ) : '-'}
              </td>
              <td className="px-4 py-3">
                {query.is_suspicious ? (
                  <span className="text-red-400">Yes</span>
                ) : (
                  <span className="text-gray-500">No</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const TlsTab: React.FC<{ tlsInfo: TlsInfo[]; loading: boolean }> = ({ tlsInfo, loading }) => {
  if (loading) return <div className="p-8 text-center text-gray-400">Loading TLS info...</div>;
  if (tlsInfo.length === 0) return <div className="p-8 text-center text-gray-400">No TLS connections found</div>;

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead className="bg-gray-900">
          <tr>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Server Name</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Version</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Cipher</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">JA3</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">JA3S</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Certificate</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Issues</th>
          </tr>
        </thead>
        <tbody>
          {tlsInfo.map((tls) => (
            <tr key={tls.id} className="border-t border-gray-700 hover:bg-gray-700/50">
              <td className="px-4 py-3 text-white">{tls.server_name || '-'}</td>
              <td className="px-4 py-3 text-gray-300">{tls.tls_version || '-'}</td>
              <td className="px-4 py-3 text-gray-300 text-sm">{tls.cipher_suite || '-'}</td>
              <td className="px-4 py-3 text-gray-400 font-mono text-xs">{tls.ja3_fingerprint?.slice(0, 12) || '-'}...</td>
              <td className="px-4 py-3 text-gray-400 font-mono text-xs">{tls.ja3s_fingerprint?.slice(0, 12) || '-'}...</td>
              <td className="px-4 py-3 text-gray-300 text-sm">{tls.certificate_subject?.slice(0, 30) || '-'}</td>
              <td className="px-4 py-3">
                <div className="flex gap-2">
                  {tls.is_self_signed && <span className="text-yellow-400 text-xs">Self-signed</span>}
                  {tls.is_expired && <span className="text-red-400 text-xs">Expired</span>}
                  {!tls.is_self_signed && !tls.is_expired && <span className="text-gray-500">-</span>}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const BeaconsTab: React.FC<{ beacons: Beacon[]; loading: boolean }> = ({ beacons, loading }) => {
  if (loading) return <div className="p-8 text-center text-gray-400">Loading beacons...</div>;
  if (beacons.length === 0) return <div className="p-8 text-center text-gray-400">No beacons detected</div>;

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead className="bg-gray-900">
          <tr>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Source</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Destination</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Interval</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Jitter</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Connections</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Confidence</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Confirmed</th>
          </tr>
        </thead>
        <tbody>
          {beacons.map((beacon) => (
            <tr key={beacon.id} className="border-t border-gray-700 hover:bg-gray-700/50">
              <td className="px-4 py-3 text-white font-mono text-sm">{beacon.src_ip}</td>
              <td className="px-4 py-3 text-white font-mono text-sm">{beacon.dst_ip}:{beacon.dst_port}</td>
              <td className="px-4 py-3 text-gray-300">{beacon.interval_seconds}s</td>
              <td className="px-4 py-3 text-gray-300">{beacon.jitter_percent.toFixed(1)}%</td>
              <td className="px-4 py-3 text-gray-300">{beacon.connection_count}</td>
              <td className="px-4 py-3">
                <span className={beacon.confidence > 0.8 ? 'text-red-400' : beacon.confidence > 0.5 ? 'text-yellow-400' : 'text-gray-400'}>
                  {(beacon.confidence * 100).toFixed(0)}%
                </span>
              </td>
              <td className="px-4 py-3">
                {beacon.is_confirmed ? (
                  <CheckCircle size={16} className="text-red-400" />
                ) : (
                  <XCircle size={16} className="text-gray-500" />
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const RulesTab: React.FC<{
  rules: IdsRule[];
  loading: boolean;
  onAdd: () => void;
  onDelete: (id: string) => void;
}> = ({ rules, loading, onAdd, onDelete }) => {
  if (loading) return <div className="p-8 text-center text-gray-400">Loading rules...</div>;

  return (
    <div>
      <div className="p-4 border-b border-gray-700 flex justify-between items-center">
        <h3 className="text-white font-medium">Custom IDS Rules</h3>
        <button
          onClick={onAdd}
          className="px-3 py-1.5 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 flex items-center gap-2 text-sm"
        >
          <Plus size={14} />
          Add Rule
        </button>
      </div>
      {rules.length === 0 ? (
        <div className="p-8 text-center text-gray-400">
          No custom rules defined. Add rules to detect specific traffic patterns.
        </div>
      ) : (
        <table className="w-full">
          <thead className="bg-gray-900">
            <tr>
              <th className="px-4 py-3 text-left text-gray-400 text-sm">Name</th>
              <th className="px-4 py-3 text-left text-gray-400 text-sm">Severity</th>
              <th className="px-4 py-3 text-left text-gray-400 text-sm">Content</th>
              <th className="px-4 py-3 text-left text-gray-400 text-sm">Enabled</th>
              <th className="px-4 py-3 text-left text-gray-400 text-sm">Created</th>
              <th className="px-4 py-3 text-right text-gray-400 text-sm">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr key={rule.id} className="border-t border-gray-700 hover:bg-gray-700/50">
                <td className="px-4 py-3 text-white">{rule.name}</td>
                <td className="px-4 py-3"><SeverityBadge severity={rule.severity} /></td>
                <td className="px-4 py-3 text-gray-400 font-mono text-xs truncate max-w-xs">{rule.content.slice(0, 50)}...</td>
                <td className="px-4 py-3">
                  {rule.enabled ? (
                    <CheckCircle size={16} className="text-green-400" />
                  ) : (
                    <XCircle size={16} className="text-gray-500" />
                  )}
                </td>
                <td className="px-4 py-3 text-gray-400 text-sm">{new Date(rule.created_at).toLocaleDateString()}</td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => onDelete(rule.id)}
                    className="p-1 text-red-400 hover:text-red-300"
                    title="Delete"
                  >
                    <Trash2 size={16} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

const FingerprintsTab: React.FC<{ fingerprints: Ja3Fingerprint[]; loading: boolean }> = ({ fingerprints, loading }) => {
  if (loading) return <div className="p-8 text-center text-gray-400">Loading fingerprints...</div>;
  if (fingerprints.length === 0) return <div className="p-8 text-center text-gray-400">No fingerprints found</div>;

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead className="bg-gray-900">
          <tr>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Fingerprint</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Type</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Known Client</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Hits</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">First Seen</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Last Seen</th>
            <th className="px-4 py-3 text-left text-gray-400 text-sm">Malicious</th>
          </tr>
        </thead>
        <tbody>
          {fingerprints.map((fp) => (
            <tr key={fp.id} className="border-t border-gray-700 hover:bg-gray-700/50">
              <td className="px-4 py-3 text-white font-mono text-xs">{fp.fingerprint}</td>
              <td className="px-4 py-3 text-gray-300">{fp.fingerprint_type}</td>
              <td className="px-4 py-3 text-gray-300">{fp.known_client || '-'}</td>
              <td className="px-4 py-3 text-gray-300">{fp.hits}</td>
              <td className="px-4 py-3 text-gray-400 text-sm">{new Date(fp.first_seen).toLocaleDateString()}</td>
              <td className="px-4 py-3 text-gray-400 text-sm">{new Date(fp.last_seen).toLocaleDateString()}</td>
              <td className="px-4 py-3">
                {fp.is_malicious ? (
                  <span className="text-red-400">Yes</span>
                ) : (
                  <span className="text-gray-500">No</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const LiveCaptureTab: React.FC<{
  interfaces: NetworkInterface[];
  captures: LiveCaptureInfo[];
  interfacesLoading: boolean;
  capturesLoading: boolean;
  onStart: (data: { interface: string; filter?: string; promiscuous?: boolean; max_packets?: number; max_duration_secs?: number }) => void;
  onStop: (id: string) => void;
  isStarting: boolean;
  isStopping: boolean;
}> = ({ interfaces, captures, interfacesLoading, capturesLoading, onStart, onStop, isStarting, isStopping }) => {
  const [selectedInterface, setSelectedInterface] = useState('');
  const [bpfFilter, setBpfFilter] = useState('');
  const [promiscuous, setPromiscuous] = useState(true);
  const [maxPackets, setMaxPackets] = useState<string>('');
  const [maxDuration, setMaxDuration] = useState<string>('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const handleStartCapture = () => {
    if (!selectedInterface) {
      toast.error('Please select a network interface');
      return;
    }
    onStart({
      interface: selectedInterface,
      filter: bpfFilter || undefined,
      promiscuous,
      max_packets: maxPackets ? parseInt(maxPackets) : undefined,
      max_duration_secs: maxDuration ? parseInt(maxDuration) : undefined,
    });
  };

  const runningCaptures = captures.filter(c => c.status === 'running');

  return (
    <div className="p-6 space-y-6">
      {/* Start New Capture Form */}
      <div className="bg-gray-900 rounded-lg p-4">
        <h3 className="text-white font-medium mb-4 flex items-center gap-2">
          <Radio className="text-cyan-400" size={18} />
          Start Live Capture
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Interface Selection */}
          <div>
            <label className="block text-gray-400 text-sm mb-1">Network Interface</label>
            <select
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white"
              disabled={interfacesLoading}
            >
              <option value="">Select interface...</option>
              {interfaces.map((iface) => (
                <option key={iface.name} value={iface.name}>
                  {iface.name} {iface.description ? `- ${iface.description}` : ''}
                  {iface.is_loopback ? ' (loopback)' : ''}
                </option>
              ))}
            </select>
            {interfacesLoading && <p className="text-gray-500 text-xs mt-1">Loading interfaces...</p>}
          </div>

          {/* BPF Filter */}
          <div>
            <label className="block text-gray-400 text-sm mb-1">BPF Filter (optional)</label>
            <input
              type="text"
              value={bpfFilter}
              onChange={(e) => setBpfFilter(e.target.value)}
              placeholder="e.g., tcp port 80 or host 192.168.1.1"
              className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white"
            />
          </div>
        </div>

        {/* Advanced Options */}
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="mt-3 text-gray-400 text-sm flex items-center gap-1 hover:text-white"
        >
          {showAdvanced ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          Advanced Options
        </button>

        {showAdvanced && (
          <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="promiscuous"
                checked={promiscuous}
                onChange={(e) => setPromiscuous(e.target.checked)}
                className="rounded bg-gray-800 border-gray-600"
              />
              <label htmlFor="promiscuous" className="text-gray-300 text-sm">Promiscuous Mode</label>
            </div>
            <div>
              <label className="block text-gray-400 text-sm mb-1">Max Packets</label>
              <input
                type="number"
                value={maxPackets}
                onChange={(e) => setMaxPackets(e.target.value)}
                placeholder="Unlimited"
                className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white"
              />
            </div>
            <div>
              <label className="block text-gray-400 text-sm mb-1">Max Duration (sec)</label>
              <input
                type="number"
                value={maxDuration}
                onChange={(e) => setMaxDuration(e.target.value)}
                placeholder="Unlimited"
                className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white"
              />
            </div>
          </div>
        )}

        <div className="mt-4 flex justify-end">
          <button
            onClick={handleStartCapture}
            disabled={isStarting || !selectedInterface}
            className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 flex items-center gap-2"
          >
            <Play size={16} />
            {isStarting ? 'Starting...' : 'Start Capture'}
          </button>
        </div>
      </div>

      {/* Active Captures */}
      <div>
        <h3 className="text-white font-medium mb-3 flex items-center gap-2">
          <Activity className="text-green-400" size={18} />
          Active Captures ({runningCaptures.length})
        </h3>

        {capturesLoading ? (
          <div className="p-8 text-center text-gray-400">Loading captures...</div>
        ) : runningCaptures.length === 0 ? (
          <div className="bg-gray-900 rounded-lg p-8 text-center text-gray-400">
            <Radio size={48} className="mx-auto mb-4 opacity-50" />
            <p>No active captures. Start a capture above to begin collecting packets.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {runningCaptures.map((capture) => (
              <div
                key={capture.id}
                className="bg-gray-900 rounded-lg p-4 border border-green-500/30"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse" />
                    <div>
                      <div className="text-white font-medium flex items-center gap-2">
                        <Network size={16} className="text-cyan-400" />
                        {capture.interface}
                        {capture.filter && (
                          <span className="text-gray-400 text-sm">({capture.filter})</span>
                        )}
                      </div>
                      <div className="text-gray-400 text-sm mt-1">
                        Started: {new Date(capture.started_at).toLocaleTimeString()}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-6">
                    <div className="text-right">
                      <div className="text-white font-mono">
                        {capture.packet_count.toLocaleString()} packets
                      </div>
                      <div className="text-gray-400 text-sm">
                        {formatBytes(capture.bytes_captured)}
                      </div>
                    </div>

                    <button
                      onClick={() => onStop(capture.id)}
                      disabled={isStopping}
                      className="px-3 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50 flex items-center gap-2"
                    >
                      <XCircle size={16} />
                      Stop
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* All Captures History */}
      {captures.length > runningCaptures.length && (
        <div>
          <h3 className="text-white font-medium mb-3 flex items-center gap-2">
            <Clock className="text-gray-400" size={18} />
            Recent Captures
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-900">
                <tr>
                  <th className="px-4 py-3 text-left text-gray-400 text-sm">Interface</th>
                  <th className="px-4 py-3 text-left text-gray-400 text-sm">Filter</th>
                  <th className="px-4 py-3 text-left text-gray-400 text-sm">Started</th>
                  <th className="px-4 py-3 text-left text-gray-400 text-sm">Packets</th>
                  <th className="px-4 py-3 text-left text-gray-400 text-sm">Size</th>
                  <th className="px-4 py-3 text-left text-gray-400 text-sm">Status</th>
                </tr>
              </thead>
              <tbody>
                {captures.filter(c => c.status !== 'running').map((capture) => (
                  <tr key={capture.id} className="border-t border-gray-700 hover:bg-gray-700/50">
                    <td className="px-4 py-3 text-white">{capture.interface}</td>
                    <td className="px-4 py-3 text-gray-300 font-mono text-sm">
                      {capture.filter || '-'}
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-sm">
                      {new Date(capture.started_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-gray-300">
                      {capture.packet_count.toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-gray-300">
                      {formatBytes(capture.bytes_captured)}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 rounded text-xs ${
                        capture.status === 'stopped'
                          ? 'bg-gray-500/20 text-gray-400'
                          : 'bg-red-500/20 text-red-400'
                      }`}>
                        {capture.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default TrafficAnalysisPage;
