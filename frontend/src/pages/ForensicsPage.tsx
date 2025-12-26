import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Folder,
  HardDrive,
  Cpu,
  Network,
  Package,
  Plus,
  RefreshCw,
  Eye,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  X,
  FileText,
  Download,
  Play,
  Pause,
  Search,
  Upload,
  Database,
  Activity,
  BarChart3,
  Trash2,
  Settings,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import api from '../services/api';

type TabType = 'cases' | 'memory' | 'disk' | 'network' | 'artifacts';

// ============================================================================
// Types
// ============================================================================

interface ForensicCase {
  id: string;
  case_number: string;
  title: string;
  description?: string;
  case_type: string;
  status: string;
  priority: string;
  lead_investigator_id?: string;
  created_by: string;
  tags: string[];
  created_at: string;
  updated_at: string;
  closed_at?: string;
}

interface MemoryDump {
  id: string;
  case_id: string;
  hostname: string;
  os_type: string;
  os_version?: string;
  dump_size_bytes: number;
  file_path: string;
  sha256_hash?: string;
  status: string;
  analysis_results?: MemoryAnalysisResult;
  created_at: string;
}

interface MemoryAnalysisResult {
  processes: ProcessInfo[];
  connections: ConnectionInfo[];
  suspicious_strings: string[];
  injected_code: InjectedCode[];
}

interface ProcessInfo {
  pid: number;
  name: string;
  path?: string;
  ppid: number;
  cmdline?: string;
  suspicious: boolean;
  suspicion_reason?: string;
}

interface ConnectionInfo {
  pid: number;
  process_name: string;
  local_addr: string;
  remote_addr: string;
  state: string;
  suspicious: boolean;
}

interface InjectedCode {
  pid: number;
  process_name: string;
  region_start: string;
  region_size: number;
  protection: string;
}

interface DiskImage {
  id: string;
  case_id: string;
  hostname: string;
  disk_type: string;
  image_format: string;
  size_bytes: number;
  file_path: string;
  sha256_hash?: string;
  status: string;
  analysis_results?: DiskAnalysisResult;
  created_at: string;
}

interface DiskAnalysisResult {
  file_system_type: string;
  total_files: number;
  deleted_files: DeletedFile[];
  browser_artifacts: BrowserArtifact[];
  prefetch_entries: PrefetchEntry[];
}

interface DeletedFile {
  path: string;
  size: number;
  deleted_at?: string;
  recoverable: boolean;
}

interface BrowserArtifact {
  browser: string;
  artifact_type: string;
  url?: string;
  title?: string;
  timestamp?: string;
}

interface PrefetchEntry {
  executable: string;
  run_count: number;
  last_run?: string;
}

interface PcapCapture {
  id: string;
  case_id: string;
  name: string;
  description?: string;
  file_path: string;
  file_size_bytes: number;
  packet_count?: number;
  duration_seconds?: number;
  status: string;
  analysis_results?: PcapAnalysisResult;
  created_at: string;
}

interface PcapAnalysisResult {
  protocol_stats: Record<string, number>;
  top_talkers: TalkerInfo[];
  dns_queries: DnsQueryInfo[];
  http_requests: HttpRequestInfo[];
  beaconing_detected: BeaconingInfo[];
}

interface TalkerInfo {
  ip: string;
  packets: number;
  bytes: number;
}

interface DnsQueryInfo {
  query: string;
  query_type: string;
  response?: string;
  timestamp: string;
}

interface HttpRequestInfo {
  method: string;
  url: string;
  host: string;
  user_agent?: string;
  timestamp: string;
}

interface BeaconingInfo {
  destination: string;
  interval_seconds: number;
  confidence: number;
}

interface ArtifactCollection {
  id: string;
  case_id: string;
  hostname: string;
  collection_type: string;
  status: string;
  artifacts_collected: number;
  file_path?: string;
  created_at: string;
  completed_at?: string;
}

interface ForensicsStats {
  total_cases: number;
  active_cases: number;
  memory_dumps: number;
  disk_images: number;
  pcap_files: number;
  artifact_collections: number;
}

// ============================================================================
// API Functions
// ============================================================================

const forensicsAPI = {
  getStats: () => api.get<ForensicsStats>('/forensics/stats').then(r => r.data),

  // Cases
  listCases: (params?: Record<string, string>) =>
    api.get<ForensicCase[]>('/forensics/cases', { params }).then(r => r.data),
  createCase: (data: { title: string; description?: string; case_type: string; priority: string }) =>
    api.post<ForensicCase>('/forensics/cases', data).then(r => r.data),
  getCase: (id: string) => api.get<ForensicCase>(`/forensics/cases/${id}`).then(r => r.data),
  updateCase: (id: string, data: Partial<ForensicCase>) =>
    api.put<ForensicCase>(`/forensics/cases/${id}`, data).then(r => r.data),
  closeCase: (id: string, data: { resolution: string }) =>
    api.post<ForensicCase>(`/forensics/cases/${id}/close`, data).then(r => r.data),

  // Memory
  listMemoryDumps: (caseId?: string) =>
    api.get<MemoryDump[]>('/forensics/memory', { params: caseId ? { case_id: caseId } : {} }).then(r => r.data),
  uploadMemoryDump: (caseId: string, data: FormData) =>
    api.post<MemoryDump>(`/forensics/cases/${caseId}/memory`, data, {
      headers: { 'Content-Type': 'multipart/form-data' }
    }).then(r => r.data),
  analyzeMemory: (id: string) =>
    api.post<MemoryDump>(`/forensics/memory/${id}/analyze`).then(r => r.data),

  // Disk
  listDiskImages: (caseId?: string) =>
    api.get<DiskImage[]>('/forensics/disk', { params: caseId ? { case_id: caseId } : {} }).then(r => r.data),
  analyzeDisk: (id: string) =>
    api.post<DiskImage>(`/forensics/disk/${id}/analyze`).then(r => r.data),

  // Network
  listPcaps: (caseId?: string) =>
    api.get<PcapCapture[]>('/forensics/network', { params: caseId ? { case_id: caseId } : {} }).then(r => r.data),
  analyzePcap: (id: string) =>
    api.post<PcapCapture>(`/forensics/network/${id}/analyze`).then(r => r.data),

  // Artifacts
  listArtifactCollections: (caseId?: string) =>
    api.get<ArtifactCollection[]>('/forensics/artifacts', { params: caseId ? { case_id: caseId } : {} }).then(r => r.data),
  startCollection: (caseId: string, data: { hostname: string; collection_type: string }) =>
    api.post<ArtifactCollection>(`/forensics/cases/${caseId}/artifacts/collect`, data).then(r => r.data),
};

// ============================================================================
// Badge Components
// ============================================================================

const statusColors: Record<string, { bg: string; text: string }> = {
  open: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  active: { bg: 'bg-cyan-500/20', text: 'text-cyan-400' },
  in_progress: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  analyzing: { bg: 'bg-purple-500/20', text: 'text-purple-400' },
  completed: { bg: 'bg-green-500/20', text: 'text-green-400' },
  closed: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  failed: { bg: 'bg-red-500/20', text: 'text-red-400' },
  pending: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
};

const priorityColors: Record<string, { bg: string; text: string }> = {
  low: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  medium: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  high: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  critical: { bg: 'bg-red-500/20', text: 'text-red-400' },
};

function StatusBadge({ status }: { status: string }) {
  const colors = statusColors[status.toLowerCase()] || statusColors.pending;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text}`}>
      {status.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
    </span>
  );
}

function PriorityBadge({ priority }: { priority: string }) {
  const colors = priorityColors[priority.toLowerCase()] || priorityColors.medium;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text}`}>
      {priority.charAt(0).toUpperCase() + priority.slice(1)}
    </span>
  );
}

// ============================================================================
// Modal Component
// ============================================================================

const Modal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}> = ({ isOpen, onClose, title, children, size = 'md' }) => {
  if (!isOpen) return null;

  const sizeClasses = {
    sm: 'max-w-md',
    md: 'max-w-2xl',
    lg: 'max-w-4xl',
    xl: 'max-w-6xl',
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className={`relative bg-gray-800 border border-gray-700 rounded-lg shadow-xl w-full ${sizeClasses[size]} max-h-[90vh] overflow-y-auto mx-4`}>
        <div className="flex items-center justify-between p-4 border-b border-gray-700 sticky top-0 bg-gray-800 z-10">
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          <button
            onClick={onClose}
            className="p-1 rounded-lg hover:bg-gray-700 text-gray-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
};

// ============================================================================
// Create Case Form
// ============================================================================

const CreateCaseForm: React.FC<{
  onSubmit: (data: { title: string; description?: string; case_type: string; priority: string }) => void;
  onCancel: () => void;
  isLoading?: boolean;
}> = ({ onSubmit, onCancel, isLoading }) => {
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    case_type: 'incident',
    priority: 'medium',
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Title *</label>
        <input
          type="text"
          required
          value={formData.title}
          onChange={(e) => setFormData({ ...formData, title: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          placeholder="Case title..."
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
        <textarea
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          rows={3}
          placeholder="Describe the forensic investigation..."
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Case Type</label>
          <select
            value={formData.case_type}
            onChange={(e) => setFormData({ ...formData, case_type: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          >
            <option value="incident">Incident Response</option>
            <option value="malware">Malware Analysis</option>
            <option value="insider_threat">Insider Threat</option>
            <option value="data_breach">Data Breach</option>
            <option value="fraud">Fraud Investigation</option>
            <option value="other">Other</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Priority</label>
          <select
            value={formData.priority}
            onChange={(e) => setFormData({ ...formData, priority: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          >
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>
      </div>

      <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
        <button
          type="button"
          onClick={onCancel}
          disabled={isLoading}
          className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={isLoading}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
        >
          {isLoading && <RefreshCw className="w-4 h-4 animate-spin" />}
          Create Case
        </button>
      </div>
    </form>
  );
};

// ============================================================================
// Case Detail View
// ============================================================================

const CaseDetailView: React.FC<{
  caseData: ForensicCase;
  onClose: () => void;
}> = ({ caseData, onClose }) => {
  const queryClient = useQueryClient();

  // Fetch related evidence
  const { data: memoryDumps } = useQuery({
    queryKey: ['forensics-memory', caseData.id],
    queryFn: () => forensicsAPI.listMemoryDumps(caseData.id),
  });

  const { data: diskImages } = useQuery({
    queryKey: ['forensics-disk', caseData.id],
    queryFn: () => forensicsAPI.listDiskImages(caseData.id),
  });

  const { data: pcaps } = useQuery({
    queryKey: ['forensics-pcaps', caseData.id],
    queryFn: () => forensicsAPI.listPcaps(caseData.id),
  });

  return (
    <div className="space-y-6">
      {/* Case Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-gray-500 font-mono text-sm">{caseData.case_number}</span>
          </div>
          <h3 className="text-xl font-semibold text-white">{caseData.title}</h3>
          {caseData.description && (
            <p className="text-gray-400 mt-2">{caseData.description}</p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <PriorityBadge priority={caseData.priority} />
          <StatusBadge status={caseData.status} />
        </div>
      </div>

      {/* Case Metadata */}
      <div className="grid grid-cols-2 gap-4 p-4 bg-gray-900 rounded-lg">
        <div>
          <p className="text-sm text-gray-500">Case Type</p>
          <p className="text-white">{caseData.case_type.replace(/_/g, ' ')}</p>
        </div>
        <div>
          <p className="text-sm text-gray-500">Created</p>
          <p className="text-white">{new Date(caseData.created_at).toLocaleString()}</p>
        </div>
        {caseData.tags.length > 0 && (
          <div className="col-span-2">
            <p className="text-sm text-gray-500 mb-1">Tags</p>
            <div className="flex flex-wrap gap-1">
              {caseData.tags.map((tag, i) => (
                <span key={i} className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs">
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Evidence Summary */}
      <div className="space-y-4">
        <h4 className="text-lg font-medium text-white">Evidence</h4>
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <Cpu className="w-8 h-8 text-purple-400" />
              <div>
                <p className="text-2xl font-bold text-white">{memoryDumps?.length || 0}</p>
                <p className="text-sm text-gray-400">Memory Dumps</p>
              </div>
            </div>
          </div>
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <HardDrive className="w-8 h-8 text-blue-400" />
              <div>
                <p className="text-2xl font-bold text-white">{diskImages?.length || 0}</p>
                <p className="text-sm text-gray-400">Disk Images</p>
              </div>
            </div>
          </div>
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <Network className="w-8 h-8 text-cyan-400" />
              <div>
                <p className="text-2xl font-bold text-white">{pcaps?.length || 0}</p>
                <p className="text-sm text-gray-400">PCAP Captures</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// Main Component
// ============================================================================

export default function ForensicsPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('cases');
  const [showCreateCaseModal, setShowCreateCaseModal] = useState(false);
  const [selectedCase, setSelectedCase] = useState<ForensicCase | null>(null);
  const [caseFilter, setCaseFilter] = useState<string>('');

  // Fetch stats
  const { data: stats } = useQuery({
    queryKey: ['forensics-stats'],
    queryFn: () => forensicsAPI.getStats(),
  });

  // Fetch cases
  const { data: cases, isLoading: casesLoading } = useQuery({
    queryKey: ['forensics-cases', caseFilter],
    queryFn: () => forensicsAPI.listCases(caseFilter ? { status: caseFilter } : {}),
    enabled: activeTab === 'cases',
  });

  // Fetch memory dumps
  const { data: memoryDumps, isLoading: memoryLoading } = useQuery({
    queryKey: ['forensics-memory'],
    queryFn: () => forensicsAPI.listMemoryDumps(),
    enabled: activeTab === 'memory',
  });

  // Fetch disk images
  const { data: diskImages, isLoading: diskLoading } = useQuery({
    queryKey: ['forensics-disk'],
    queryFn: () => forensicsAPI.listDiskImages(),
    enabled: activeTab === 'disk',
  });

  // Fetch pcaps
  const { data: pcaps, isLoading: networkLoading } = useQuery({
    queryKey: ['forensics-pcaps'],
    queryFn: () => forensicsAPI.listPcaps(),
    enabled: activeTab === 'network',
  });

  // Fetch artifact collections
  const { data: artifacts, isLoading: artifactsLoading } = useQuery({
    queryKey: ['forensics-artifacts'],
    queryFn: () => forensicsAPI.listArtifactCollections(),
    enabled: activeTab === 'artifacts',
  });

  // Create case mutation
  const createCaseMutation = useMutation({
    mutationFn: forensicsAPI.createCase,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['forensics-cases'] });
      queryClient.invalidateQueries({ queryKey: ['forensics-stats'] });
      setShowCreateCaseModal(false);
      toast.success('Forensic case created successfully');
    },
    onError: () => toast.error('Failed to create case'),
  });

  // Analyze memory mutation
  const analyzeMemoryMutation = useMutation({
    mutationFn: forensicsAPI.analyzeMemory,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['forensics-memory'] });
      toast.success('Memory analysis started');
    },
    onError: () => toast.error('Failed to start memory analysis'),
  });

  // Analyze disk mutation
  const analyzeDiskMutation = useMutation({
    mutationFn: forensicsAPI.analyzeDisk,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['forensics-disk'] });
      toast.success('Disk analysis started');
    },
    onError: () => toast.error('Failed to start disk analysis'),
  });

  // Analyze pcap mutation
  const analyzePcapMutation = useMutation({
    mutationFn: forensicsAPI.analyzePcap,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['forensics-pcaps'] });
      toast.success('PCAP analysis started');
    },
    onError: () => toast.error('Failed to start PCAP analysis'),
  });

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'cases', label: 'Cases', icon: <Folder className="w-4 h-4" /> },
    { id: 'memory', label: 'Memory Analysis', icon: <Cpu className="w-4 h-4" /> },
    { id: 'disk', label: 'Disk Forensics', icon: <HardDrive className="w-4 h-4" /> },
    { id: 'network', label: 'Network Analysis', icon: <Network className="w-4 h-4" /> },
    { id: 'artifacts', label: 'Artifacts', icon: <Package className="w-4 h-4" /> },
  ];

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <Database className="w-8 h-8 text-blue-500" />
              Digital Forensics
            </h1>
            <p className="text-gray-400 mt-1">
              Memory, disk, and network forensic analysis
            </p>
          </div>
        </div>

        {/* Stats Overview */}
        {stats && (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <div className="flex items-center gap-3">
                <Folder className="w-6 h-6 text-blue-400" />
                <div>
                  <p className="text-2xl font-bold text-white">{stats.total_cases}</p>
                  <p className="text-xs text-gray-400">Total Cases</p>
                </div>
              </div>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <div className="flex items-center gap-3">
                <Activity className="w-6 h-6 text-cyan-400" />
                <div>
                  <p className="text-2xl font-bold text-white">{stats.active_cases}</p>
                  <p className="text-xs text-gray-400">Active</p>
                </div>
              </div>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <div className="flex items-center gap-3">
                <Cpu className="w-6 h-6 text-purple-400" />
                <div>
                  <p className="text-2xl font-bold text-white">{stats.memory_dumps}</p>
                  <p className="text-xs text-gray-400">Memory Dumps</p>
                </div>
              </div>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <div className="flex items-center gap-3">
                <HardDrive className="w-6 h-6 text-green-400" />
                <div>
                  <p className="text-2xl font-bold text-white">{stats.disk_images}</p>
                  <p className="text-xs text-gray-400">Disk Images</p>
                </div>
              </div>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <div className="flex items-center gap-3">
                <Network className="w-6 h-6 text-yellow-400" />
                <div>
                  <p className="text-2xl font-bold text-white">{stats.pcap_files}</p>
                  <p className="text-xs text-gray-400">PCAP Files</p>
                </div>
              </div>
            </div>
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <div className="flex items-center gap-3">
                <Package className="w-6 h-6 text-orange-400" />
                <div>
                  <p className="text-2xl font-bold text-white">{stats.artifact_collections}</p>
                  <p className="text-xs text-gray-400">Artifacts</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="border-b border-gray-700">
          <nav className="flex gap-4">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-cyan-500 text-cyan-500'
                    : 'border-transparent text-gray-400 hover:text-gray-200'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        <div>
          {/* Cases Tab */}
          {activeTab === 'cases' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <select
                  value={caseFilter}
                  onChange={(e) => setCaseFilter(e.target.value)}
                  className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
                >
                  <option value="">All Cases</option>
                  <option value="open">Open</option>
                  <option value="active">Active</option>
                  <option value="closed">Closed</option>
                </select>
                <button
                  onClick={() => setShowCreateCaseModal(true)}
                  className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                >
                  <Plus className="w-4 h-4" />
                  New Case
                </button>
              </div>

              {casesLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : cases && cases.length > 0 ? (
                <div className="space-y-3">
                  {cases.map((c) => (
                    <div
                      key={c.id}
                      onClick={() => setSelectedCase(c)}
                      className="bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-gray-600 cursor-pointer transition-colors"
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-gray-500 font-mono text-sm">{c.case_number}</span>
                          </div>
                          <h3 className="text-lg font-medium text-white">{c.title}</h3>
                          {c.description && (
                            <p className="text-sm text-gray-400 mt-1 line-clamp-2">{c.description}</p>
                          )}
                          <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {new Date(c.created_at).toLocaleDateString()}
                            </span>
                            <span>{c.case_type.replace(/_/g, ' ')}</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <PriorityBadge priority={c.priority} />
                          <StatusBadge status={c.status} />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <Folder className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Forensic Cases</h3>
                  <p className="text-gray-400 mb-6">Create a case to start your investigation</p>
                  <button
                    onClick={() => setShowCreateCaseModal(true)}
                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                  >
                    <Plus className="w-4 h-4 inline mr-2" />
                    Create Case
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Memory Analysis Tab */}
          {activeTab === 'memory' && (
            <div className="space-y-4">
              {memoryLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : memoryDumps && memoryDumps.length > 0 ? (
                <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-700">
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Hostname</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">OS</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Size</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Status</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Created</th>
                        <th className="text-right p-4 text-sm font-medium text-gray-400">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {memoryDumps.map((dump) => (
                        <tr key={dump.id} className="border-b border-gray-700 hover:bg-gray-700/50">
                          <td className="p-4 text-white font-medium">{dump.hostname}</td>
                          <td className="p-4 text-gray-400">{dump.os_type} {dump.os_version}</td>
                          <td className="p-4 text-gray-400">{formatBytes(dump.dump_size_bytes)}</td>
                          <td className="p-4"><StatusBadge status={dump.status} /></td>
                          <td className="p-4 text-gray-500 text-sm">{new Date(dump.created_at).toLocaleDateString()}</td>
                          <td className="p-4 text-right">
                            <div className="flex items-center justify-end gap-2">
                              {dump.status === 'pending' && (
                                <button
                                  onClick={() => analyzeMemoryMutation.mutate(dump.id)}
                                  disabled={analyzeMemoryMutation.isPending}
                                  className="p-2 hover:bg-gray-600 rounded-lg text-cyan-400"
                                >
                                  <Play className="w-4 h-4" />
                                </button>
                              )}
                              <button className="p-2 hover:bg-gray-600 rounded-lg text-gray-400">
                                <Eye className="w-4 h-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <Cpu className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Memory Dumps</h3>
                  <p className="text-gray-400">Upload memory dumps from forensic cases to analyze</p>
                </div>
              )}
            </div>
          )}

          {/* Disk Forensics Tab */}
          {activeTab === 'disk' && (
            <div className="space-y-4">
              {diskLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : diskImages && diskImages.length > 0 ? (
                <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-700">
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Hostname</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Type</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Format</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Size</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Status</th>
                        <th className="text-right p-4 text-sm font-medium text-gray-400">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {diskImages.map((disk) => (
                        <tr key={disk.id} className="border-b border-gray-700 hover:bg-gray-700/50">
                          <td className="p-4 text-white font-medium">{disk.hostname}</td>
                          <td className="p-4 text-gray-400">{disk.disk_type}</td>
                          <td className="p-4">
                            <span className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs">
                              {disk.image_format.toUpperCase()}
                            </span>
                          </td>
                          <td className="p-4 text-gray-400">{formatBytes(disk.size_bytes)}</td>
                          <td className="p-4"><StatusBadge status={disk.status} /></td>
                          <td className="p-4 text-right">
                            <div className="flex items-center justify-end gap-2">
                              {disk.status === 'pending' && (
                                <button
                                  onClick={() => analyzeDiskMutation.mutate(disk.id)}
                                  disabled={analyzeDiskMutation.isPending}
                                  className="p-2 hover:bg-gray-600 rounded-lg text-cyan-400"
                                >
                                  <Play className="w-4 h-4" />
                                </button>
                              )}
                              <button className="p-2 hover:bg-gray-600 rounded-lg text-gray-400">
                                <Eye className="w-4 h-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <HardDrive className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Disk Images</h3>
                  <p className="text-gray-400">Upload disk images from forensic cases to analyze</p>
                </div>
              )}
            </div>
          )}

          {/* Network Analysis Tab */}
          {activeTab === 'network' && (
            <div className="space-y-4">
              {networkLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : pcaps && pcaps.length > 0 ? (
                <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-700">
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Name</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Size</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Packets</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Duration</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Status</th>
                        <th className="text-right p-4 text-sm font-medium text-gray-400">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pcaps.map((pcap) => (
                        <tr key={pcap.id} className="border-b border-gray-700 hover:bg-gray-700/50">
                          <td className="p-4">
                            <div>
                              <p className="text-white font-medium">{pcap.name}</p>
                              {pcap.description && (
                                <p className="text-xs text-gray-500">{pcap.description}</p>
                              )}
                            </div>
                          </td>
                          <td className="p-4 text-gray-400">{formatBytes(pcap.file_size_bytes)}</td>
                          <td className="p-4 text-gray-400">{pcap.packet_count?.toLocaleString() || '-'}</td>
                          <td className="p-4 text-gray-400">
                            {pcap.duration_seconds ? `${Math.round(pcap.duration_seconds)}s` : '-'}
                          </td>
                          <td className="p-4"><StatusBadge status={pcap.status} /></td>
                          <td className="p-4 text-right">
                            <div className="flex items-center justify-end gap-2">
                              {pcap.status === 'pending' && (
                                <button
                                  onClick={() => analyzePcapMutation.mutate(pcap.id)}
                                  disabled={analyzePcapMutation.isPending}
                                  className="p-2 hover:bg-gray-600 rounded-lg text-cyan-400"
                                >
                                  <Play className="w-4 h-4" />
                                </button>
                              )}
                              <button className="p-2 hover:bg-gray-600 rounded-lg text-gray-400">
                                <Eye className="w-4 h-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <Network className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No PCAP Files</h3>
                  <p className="text-gray-400">Upload network captures from forensic cases to analyze</p>
                </div>
              )}
            </div>
          )}

          {/* Artifacts Tab */}
          {activeTab === 'artifacts' && (
            <div className="space-y-4">
              {artifactsLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : artifacts && artifacts.length > 0 ? (
                <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-700">
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Hostname</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Collection Type</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Artifacts</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Status</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Created</th>
                        <th className="text-right p-4 text-sm font-medium text-gray-400">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {artifacts.map((artifact) => (
                        <tr key={artifact.id} className="border-b border-gray-700 hover:bg-gray-700/50">
                          <td className="p-4 text-white font-medium">{artifact.hostname}</td>
                          <td className="p-4">
                            <span className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs">
                              {artifact.collection_type}
                            </span>
                          </td>
                          <td className="p-4 text-gray-400">{artifact.artifacts_collected}</td>
                          <td className="p-4"><StatusBadge status={artifact.status} /></td>
                          <td className="p-4 text-gray-500 text-sm">
                            {new Date(artifact.created_at).toLocaleDateString()}
                          </td>
                          <td className="p-4 text-right">
                            <button className="p-2 hover:bg-gray-600 rounded-lg text-gray-400">
                              <Download className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <Package className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Artifact Collections</h3>
                  <p className="text-gray-400">Start artifact collection from forensic cases</p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modals */}
        <Modal
          isOpen={showCreateCaseModal}
          onClose={() => setShowCreateCaseModal(false)}
          title="Create Forensic Case"
        >
          <CreateCaseForm
            onSubmit={(data) => createCaseMutation.mutate(data)}
            onCancel={() => setShowCreateCaseModal(false)}
            isLoading={createCaseMutation.isPending}
          />
        </Modal>

        <Modal
          isOpen={!!selectedCase}
          onClose={() => setSelectedCase(null)}
          title="Case Details"
          size="lg"
        >
          {selectedCase && (
            <CaseDetailView caseData={selectedCase} onClose={() => setSelectedCase(null)} />
          )}
        </Modal>
      </div>
    </Layout>
  );
}
