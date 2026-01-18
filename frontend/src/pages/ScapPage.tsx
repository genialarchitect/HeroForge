import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Shield,
  Upload,
  Play,
  FileText,
  Download,
  Trash2,
  Search,
  Filter,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Server,
  FileCode,
  ChevronDown,
  ChevronRight,
  Eye,
  Database,
  ArrowUpCircle,
  History,
  Plus,
  ToggleLeft,
  ToggleRight,
  CloudDownload,
} from 'lucide-react';
import api from '../services/api';
import Layout from '../components/layout/Layout';
import AcasNavigation from '../components/navigation/AcasNavigation';

// Types
interface ScapContent {
  id: string;
  name: string;
  content_type: string;
  version: string;
  description?: string;
  file_hash: string;
  created_at: string;
  profile_count?: number;
  rule_count?: number;
  definition_count?: number;
}

interface ScapExecution {
  id: string;
  content_id: string;
  target: string;
  status: string;
  started_at: string;
  completed_at?: string;
  pass_count?: number;
  fail_count?: number;
  error_count?: number;
  not_applicable_count?: number;
}

interface ScapProfile {
  id: string;
  title: string;
  description?: string;
}

// STIG Sync Types
interface TrackedStig {
  id: string;
  stig_id: string;
  stig_name: string;
  current_version: number;
  current_release: number;
  available_version?: number;
  available_release?: number;
  release_date?: string;
  bundle_id?: string;
  local_path?: string;
  last_checked_at?: string;
  last_updated_at?: string;
  auto_update: boolean;
  has_update: boolean;
  created_at: string;
}

interface AvailableStig {
  stig_id: string;
  name: string;
  short_name: string;
  version: number;
  release: number;
  release_date?: string;
  target_product: string;
  category: string;
  download_url: string;
  is_benchmark: boolean;
}

interface StigSyncStatus {
  in_progress: boolean;
  current_operation?: string;
  last_sync_at?: string;
  last_sync_result?: string;
  next_sync_at?: string;
  total_tracked: number;
  updates_available: number;
  last_errors: string[];
}

interface StigSyncHistory {
  id: string;
  stig_id: string;
  old_version?: number;
  new_version: number;
  old_release?: number;
  new_release: number;
  sync_type: string;
  status: string;
  error_message?: string;
  synced_at: string;
}

// API functions
const scapAPI = {
  listContent: () => api.get<ScapContent[]>('/api/scap/content').then(r => r.data),
  getContent: (id: string) => api.get<ScapContent>(`/api/scap/content/${id}`).then(r => r.data),
  uploadContent: (data: FormData) => api.post('/api/scap/content/upload', data).then(r => r.data),
  deleteContent: (id: string) => api.delete(`/api/scap/content/${id}`).then(r => r.data),
  getProfiles: (id: string) => api.get<ScapProfile[]>(`/api/scap/content/${id}/profiles`).then(r => r.data),
  runScan: (data: { content_id: string; target: string; profile_id?: string }) =>
    api.post('/api/scap/execute', data).then(r => r.data),
  listExecutions: () => api.get<ScapExecution[]>('/api/scap/executions').then(r => r.data),
  getExecution: (id: string) => api.get<ScapExecution>(`/api/scap/executions/${id}`).then(r => r.data),
  downloadArf: (id: string) => api.get(`/api/scap/executions/${id}/arf`, { responseType: 'blob' }).then(r => r.data),
};

// STIG Sync API
const stigSyncAPI = {
  getSyncStatus: () => api.get<StigSyncStatus>('/api/scap/stigs/sync/status').then(r => r.data),
  triggerSync: () => api.post('/api/scap/stigs/sync/check').then(r => r.data),
  listAvailable: () => api.get<{ stigs: AvailableStig[]; total: number }>('/api/scap/stigs/available').then(r => r.data),
  searchAvailable: (q: string) => api.get<{ stigs: AvailableStig[]; total: number }>(`/api/scap/stigs/search?q=${encodeURIComponent(q)}`).then(r => r.data),
  listTracked: () => api.get<{ stigs: TrackedStig[]; total: number }>('/api/scap/stigs/tracked').then(r => r.data),
  addTracked: (stig_id: string, auto_update: boolean = true) => api.post('/api/scap/stigs/tracked', { stig_id, auto_update }).then(r => r.data),
  deleteTracked: (id: string) => api.delete(`/api/scap/stigs/tracked/${id}`).then(r => r.data),
  updateAutoUpdate: (id: string, auto_update: boolean) => api.put(`/api/scap/stigs/tracked/${id}/auto-update`, { auto_update }).then(r => r.data),
  downloadStig: (id: string) => api.post(`/api/scap/stigs/tracked/${id}/download`).then(r => r.data),
  getSyncHistory: (limit: number = 50, stig_id?: string) => {
    const params = new URLSearchParams({ limit: limit.toString() });
    if (stig_id) params.append('stig_id', stig_id);
    return api.get<{ history: StigSyncHistory[]; total: number }>(`/api/scap/stigs/sync/history?${params}`).then(r => r.data);
  },
};

// Status badge component
const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const configs: Record<string, { bg: string; icon: React.ReactNode }> = {
    pending: { bg: 'bg-gray-700 text-gray-300', icon: <Clock className="w-3 h-3" /> },
    running: { bg: 'bg-blue-900/50 text-blue-400', icon: <RefreshCw className="w-3 h-3 animate-spin" /> },
    completed: { bg: 'bg-green-900/50 text-green-400', icon: <CheckCircle className="w-3 h-3" /> },
    failed: { bg: 'bg-red-900/50 text-red-400', icon: <XCircle className="w-3 h-3" /> },
  };
  const config = configs[status] || configs.pending;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs ${config.bg}`}>
      {config.icon}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
};

// Content type badge
const ContentTypeBadge: React.FC<{ type: string }> = ({ type }) => {
  const colors: Record<string, string> = {
    xccdf: 'bg-purple-900/50 text-purple-400',
    oval: 'bg-cyan-900/50 text-cyan-400',
    datastream: 'bg-amber-900/50 text-amber-400',
    cpe: 'bg-pink-900/50 text-pink-400',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs ${colors[type] || 'bg-gray-700'}`}>
      {type.toUpperCase()}
    </span>
  );
};

// Upload modal
const UploadModal: React.FC<{ isOpen: boolean; onClose: () => void; onSuccess: () => void }> = ({
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      await scapAPI.uploadContent(formData);
      toast.success('SCAP content uploaded successfully');
      onSuccess();
      onClose();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
        <h2 className="text-xl font-semibold text-gray-100 mb-4">Upload SCAP Content</h2>
        <div className="space-y-4">
          <div className="border-2 border-dashed border-gray-600 rounded-lg p-6 text-center">
            <input
              type="file"
              accept=".xml,.zip"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="hidden"
              id="scap-upload"
            />
            <label htmlFor="scap-upload" className="cursor-pointer">
              <Upload className="w-12 h-12 mx-auto mb-2 text-gray-400" />
              <p className="text-gray-400">
                {file ? file.name : 'Click to select XCCDF, OVAL, or Data Stream file'}
              </p>
            </label>
          </div>
          <div className="flex justify-end gap-2">
            <button onClick={onClose} className="px-4 py-2 text-gray-400 hover:text-gray-200">
              Cancel
            </button>
            <button
              onClick={handleUpload}
              disabled={!file || uploading}
              className="px-4 py-2 bg-cyan-600 text-white rounded hover:bg-cyan-500 disabled:opacity-50"
            >
              {uploading ? 'Uploading...' : 'Upload'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Scan modal
const ScanModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  content: ScapContent | null;
  onSuccess: () => void;
}> = ({ isOpen, onClose, content, onSuccess }) => {
  const [target, setTarget] = useState('');
  const [profileId, setProfileId] = useState('');
  const [scanning, setScanning] = useState(false);

  const { data: profiles } = useQuery({
    queryKey: ['scap-profiles', content?.id],
    queryFn: () => (content ? scapAPI.getProfiles(content.id) : Promise.resolve([])),
    enabled: !!content,
  });

  const handleScan = async () => {
    if (!content || !target) return;
    setScanning(true);
    try {
      await scapAPI.runScan({
        content_id: content.id,
        target,
        profile_id: profileId || undefined,
      });
      toast.success('SCAP scan started');
      onSuccess();
      onClose();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to start scan');
    } finally {
      setScanning(false);
    }
  };

  if (!isOpen || !content) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
        <h2 className="text-xl font-semibold text-gray-100 mb-4">Run SCAP Scan</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Content</label>
            <p className="text-gray-200">{content.name}</p>
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Target Host</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="192.168.1.100 or hostname"
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          {profiles && profiles.length > 0 && (
            <div>
              <label className="block text-sm text-gray-400 mb-1">Profile</label>
              <select
                value={profileId}
                onChange={(e) => setProfileId(e.target.value)}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="">Default Profile</option>
                {profiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.title}
                  </option>
                ))}
              </select>
            </div>
          )}
          <div className="flex justify-end gap-2">
            <button onClick={onClose} className="px-4 py-2 text-gray-400 hover:text-gray-200">
              Cancel
            </button>
            <button
              onClick={handleScan}
              disabled={!target || scanning}
              className="px-4 py-2 bg-cyan-600 text-white rounded hover:bg-cyan-500 disabled:opacity-50"
            >
              {scanning ? 'Starting...' : 'Start Scan'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Add STIG Modal
const AddStigModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}> = ({ isOpen, onClose, onSuccess }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedStig, setSelectedStig] = useState<AvailableStig | null>(null);
  const [autoUpdate, setAutoUpdate] = useState(true);
  const [adding, setAdding] = useState(false);

  const { data: availableStigs, isLoading } = useQuery({
    queryKey: ['available-stigs', searchQuery],
    queryFn: () => searchQuery ? stigSyncAPI.searchAvailable(searchQuery) : stigSyncAPI.listAvailable(),
    enabled: isOpen,
  });

  const handleAdd = async () => {
    if (!selectedStig) return;
    setAdding(true);
    try {
      await stigSyncAPI.addTracked(selectedStig.stig_id, autoUpdate);
      toast.success(`Added ${selectedStig.name} to tracked STIGs`);
      onSuccess();
      onClose();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to add STIG');
    } finally {
      setAdding(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl max-h-[80vh] flex flex-col">
        <h2 className="text-xl font-semibold text-gray-100 mb-4">Add STIG to Track</h2>

        {/* Search */}
        <div className="relative mb-4">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search available STIGs..."
            className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Available STIGs List */}
        <div className="flex-1 overflow-y-auto mb-4 border border-gray-700 rounded">
          {isLoading ? (
            <div className="p-4 text-center text-gray-400">Loading available STIGs...</div>
          ) : !availableStigs?.stigs?.length ? (
            <div className="p-4 text-center text-gray-400">No STIGs found</div>
          ) : (
            <div className="divide-y divide-gray-700">
              {availableStigs.stigs.map((stig) => (
                <div
                  key={stig.stig_id}
                  onClick={() => setSelectedStig(stig)}
                  className={`p-3 cursor-pointer hover:bg-gray-700 ${
                    selectedStig?.stig_id === stig.stig_id ? 'bg-gray-700 border-l-2 border-cyan-500' : ''
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-gray-200 font-medium">{stig.name}</div>
                      <div className="text-sm text-gray-400">
                        {stig.target_product} • V{stig.version}R{stig.release}
                      </div>
                    </div>
                    <span className={`px-2 py-1 text-xs rounded ${
                      stig.is_benchmark ? 'bg-purple-900/50 text-purple-400' : 'bg-gray-700 text-gray-400'
                    }`}>
                      {stig.category}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Auto-update toggle */}
        {selectedStig && (
          <div className="flex items-center gap-3 mb-4 p-3 bg-gray-700 rounded">
            <button
              onClick={() => setAutoUpdate(!autoUpdate)}
              className="text-gray-400 hover:text-cyan-400"
            >
              {autoUpdate ? <ToggleRight className="w-6 h-6 text-cyan-400" /> : <ToggleLeft className="w-6 h-6" />}
            </button>
            <div>
              <div className="text-gray-200 text-sm">Auto-update enabled</div>
              <div className="text-xs text-gray-400">Automatically download updates when available</div>
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="px-4 py-2 text-gray-400 hover:text-gray-200">
            Cancel
          </button>
          <button
            onClick={handleAdd}
            disabled={!selectedStig || adding}
            className="px-4 py-2 bg-cyan-600 text-white rounded hover:bg-cyan-500 disabled:opacity-50"
          >
            {adding ? 'Adding...' : 'Add STIG'}
          </button>
        </div>
      </div>
    </div>
  );
};

// Main component
const ScapPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'content' | 'executions' | 'stig-repo'>('content');
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showScanModal, setShowScanModal] = useState(false);
  const [showAddStigModal, setShowAddStigModal] = useState(false);
  const [selectedContent, setSelectedContent] = useState<ScapContent | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [contentTypeFilter, setContentTypeFilter] = useState('');

  const { data: contents = [], isLoading: loadingContent } = useQuery({
    queryKey: ['scap-content'],
    queryFn: scapAPI.listContent,
  });

  const { data: executions = [], isLoading: loadingExecutions } = useQuery({
    queryKey: ['scap-executions'],
    queryFn: scapAPI.listExecutions,
    refetchInterval: 10000, // Refresh every 10 seconds for running scans
  });

  const deleteMutation = useMutation({
    mutationFn: scapAPI.deleteContent,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scap-content'] });
      toast.success('Content deleted');
    },
    onError: () => toast.error('Failed to delete content'),
  });

  // STIG Sync queries
  const { data: syncStatus } = useQuery({
    queryKey: ['stig-sync-status'],
    queryFn: stigSyncAPI.getSyncStatus,
    refetchInterval: 5000, // Refresh every 5 seconds when sync is running
  });

  const { data: trackedStigs, isLoading: loadingTracked } = useQuery({
    queryKey: ['tracked-stigs'],
    queryFn: stigSyncAPI.listTracked,
  });

  const { data: syncHistory } = useQuery({
    queryKey: ['stig-sync-history'],
    queryFn: () => stigSyncAPI.getSyncHistory(20),
  });

  const triggerSyncMutation = useMutation({
    mutationFn: stigSyncAPI.triggerSync,
    onSuccess: () => {
      toast.success('STIG sync check started');
      queryClient.invalidateQueries({ queryKey: ['stig-sync-status'] });
    },
    onError: () => toast.error('Failed to start sync check'),
  });

  const deleteStigMutation = useMutation({
    mutationFn: stigSyncAPI.deleteTracked,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tracked-stigs'] });
      toast.success('STIG removed from tracking');
    },
    onError: () => toast.error('Failed to remove STIG'),
  });

  const toggleAutoUpdateMutation = useMutation({
    mutationFn: ({ id, autoUpdate }: { id: string; autoUpdate: boolean }) =>
      stigSyncAPI.updateAutoUpdate(id, autoUpdate),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tracked-stigs'] });
    },
    onError: () => toast.error('Failed to update setting'),
  });

  const downloadStigMutation = useMutation({
    mutationFn: stigSyncAPI.downloadStig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tracked-stigs'] });
      queryClient.invalidateQueries({ queryKey: ['scap-content'] });
      toast.success('STIG downloaded and imported');
    },
    onError: () => toast.error('Failed to download STIG'),
  });

  const filteredContents = contents.filter((c) => {
    const matchesSearch = c.name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = !contentTypeFilter || c.content_type === contentTypeFilter;
    return matchesSearch && matchesType;
  });

  const handleDownloadArf = async (executionId: string) => {
    try {
      const blob = await scapAPI.downloadArf(executionId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scap_result_${executionId}.xml`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch {
      toast.error('Failed to download ARF');
    }
  };

  return (
    <Layout>
    <div className="space-y-6">
      {/* ACAS Navigation */}
      <AcasNavigation />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-cyan-400" />
          <div>
            <h1 className="text-2xl font-bold text-gray-100">SCAP Compliance Scanner</h1>
            <p className="text-sm text-gray-400">
              Security Content Automation Protocol assessment and reporting
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowUploadModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded hover:bg-cyan-500"
        >
          <Upload className="w-4 h-4" />
          Upload Content
        </button>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-700">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveTab('content')}
            className={`px-4 py-2 border-b-2 transition-colors ${
              activeTab === 'content'
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4" />
              Content Library ({contents.length})
            </div>
          </button>
          <button
            onClick={() => setActiveTab('executions')}
            className={`px-4 py-2 border-b-2 transition-colors ${
              activeTab === 'executions'
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4" />
              Scan History ({executions.length})
            </div>
          </button>
          <button
            onClick={() => setActiveTab('stig-repo')}
            className={`px-4 py-2 border-b-2 transition-colors ${
              activeTab === 'stig-repo'
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4" />
              STIG Repository
              {syncStatus?.updates_available ? (
                <span className="bg-amber-600 text-white text-xs px-1.5 py-0.5 rounded-full">
                  {syncStatus.updates_available}
                </span>
              ) : null}
            </div>
          </button>
        </div>
      </div>

      {/* Content Tab */}
      {activeTab === 'content' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search content..."
                className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <select
              value={contentTypeFilter}
              onChange={(e) => setContentTypeFilter(e.target.value)}
              className="px-4 py-2 bg-gray-800 border border-gray-700 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Types</option>
              <option value="xccdf">XCCDF</option>
              <option value="oval">OVAL</option>
              <option value="datastream">Data Stream</option>
              <option value="cpe">CPE</option>
            </select>
          </div>

          {/* Content List */}
          {loadingContent ? (
            <div className="text-center py-12 text-gray-400">Loading...</div>
          ) : filteredContents.length === 0 ? (
            <div className="text-center py-12">
              <FileText className="w-12 h-12 mx-auto mb-4 text-gray-600" />
              <p className="text-gray-400">No SCAP content found</p>
              <p className="text-sm text-gray-500 mt-1">Upload XCCDF, OVAL, or SCAP Data Stream files to get started</p>
            </div>
          ) : (
            <div className="bg-gray-800 rounded-lg overflow-hidden">
              <table className="w-full">
                <thead className="bg-gray-900">
                  <tr>
                    <th className="px-4 py-3 text-left text-sm text-gray-400">Name</th>
                    <th className="px-4 py-3 text-left text-sm text-gray-400">Type</th>
                    <th className="px-4 py-3 text-left text-sm text-gray-400">Version</th>
                    <th className="px-4 py-3 text-left text-sm text-gray-400">Rules</th>
                    <th className="px-4 py-3 text-left text-sm text-gray-400">Uploaded</th>
                    <th className="px-4 py-3 text-right text-sm text-gray-400">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {filteredContents.map((content) => (
                    <tr key={content.id} className="hover:bg-gray-700/50">
                      <td className="px-4 py-3">
                        <div className="text-gray-200">{content.name}</div>
                        {content.description && (
                          <div className="text-sm text-gray-500 truncate max-w-xs">{content.description}</div>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <ContentTypeBadge type={content.content_type} />
                      </td>
                      <td className="px-4 py-3 text-gray-400">{content.version || '-'}</td>
                      <td className="px-4 py-3 text-gray-400">
                        {content.rule_count || content.definition_count || '-'}
                      </td>
                      <td className="px-4 py-3 text-gray-400 text-sm">
                        {new Date(content.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => {
                              setSelectedContent(content);
                              setShowScanModal(true);
                            }}
                            className="p-2 text-gray-400 hover:text-cyan-400 rounded"
                            title="Run Scan"
                          >
                            <Play className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => deleteMutation.mutate(content.id)}
                            className="p-2 text-gray-400 hover:text-red-400 rounded"
                            title="Delete"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Executions Tab */}
      {activeTab === 'executions' && (
        <div className="space-y-4">
          {loadingExecutions ? (
            <div className="text-center py-12 text-gray-400">Loading...</div>
          ) : executions.length === 0 ? (
            <div className="text-center py-12">
              <Server className="w-12 h-12 mx-auto mb-4 text-gray-600" />
              <p className="text-gray-400">No scan history</p>
              <p className="text-sm text-gray-500 mt-1">Run a SCAP scan to see results here</p>
            </div>
          ) : (
            <div className="bg-gray-800 rounded-lg overflow-hidden">
              <table className="w-full">
                <thead className="bg-gray-900">
                  <tr>
                    <th className="px-4 py-3 text-left text-sm text-gray-400">Target</th>
                    <th className="px-4 py-3 text-left text-sm text-gray-400">Status</th>
                    <th className="px-4 py-3 text-left text-sm text-gray-400">Pass</th>
                    <th className="px-4 py-3 text-left text-sm text-gray-400">Fail</th>
                    <th className="px-4 py-3 text-left text-sm text-gray-400">Started</th>
                    <th className="px-4 py-3 text-right text-sm text-gray-400">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {executions.map((exec) => (
                    <tr key={exec.id} className="hover:bg-gray-700/50">
                      <td className="px-4 py-3 text-gray-200">{exec.target}</td>
                      <td className="px-4 py-3">
                        <StatusBadge status={exec.status} />
                      </td>
                      <td className="px-4 py-3 text-green-400">{exec.pass_count ?? '-'}</td>
                      <td className="px-4 py-3 text-red-400">{exec.fail_count ?? '-'}</td>
                      <td className="px-4 py-3 text-gray-400 text-sm">
                        {new Date(exec.started_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleDownloadArf(exec.id)}
                            className="p-2 text-gray-400 hover:text-cyan-400 rounded"
                            title="Download ARF Report"
                            disabled={exec.status !== 'completed'}
                          >
                            <Download className="w-4 h-4" />
                          </button>
                          <button
                            className="p-2 text-gray-400 hover:text-cyan-400 rounded"
                            title="View Details"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* STIG Repository Tab */}
      {activeTab === 'stig-repo' && (
        <div className="space-y-6">
          {/* Sync Status Card */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="flex items-center gap-2 text-gray-400 mb-1">
                <Database className="w-4 h-4" />
                <span className="text-sm">Tracked STIGs</span>
              </div>
              <div className="text-2xl font-bold text-gray-100">
                {syncStatus?.total_tracked ?? 0}
              </div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="flex items-center gap-2 text-gray-400 mb-1">
                <ArrowUpCircle className="w-4 h-4" />
                <span className="text-sm">Updates Available</span>
              </div>
              <div className={`text-2xl font-bold ${syncStatus?.updates_available ? 'text-amber-400' : 'text-gray-100'}`}>
                {syncStatus?.updates_available ?? 0}
              </div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="flex items-center gap-2 text-gray-400 mb-1">
                <Clock className="w-4 h-4" />
                <span className="text-sm">Last Sync</span>
              </div>
              <div className="text-lg text-gray-100">
                {syncStatus?.last_sync_at
                  ? new Date(syncStatus.last_sync_at).toLocaleString()
                  : 'Never'}
              </div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="flex items-center gap-2 text-gray-400 mb-1">
                {syncStatus?.in_progress ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <CheckCircle className="w-4 h-4" />
                )}
                <span className="text-sm">Status</span>
              </div>
              <div className="text-lg text-gray-100">
                {syncStatus?.in_progress
                  ? syncStatus.current_operation || 'Syncing...'
                  : syncStatus?.last_sync_result || 'Idle'}
              </div>
            </div>
          </div>

          {/* Actions Bar */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <button
                onClick={() => triggerSyncMutation.mutate()}
                disabled={syncStatus?.in_progress || triggerSyncMutation.isPending}
                className="flex items-center gap-2 px-4 py-2 bg-gray-700 text-gray-200 rounded hover:bg-gray-600 disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${(syncStatus?.in_progress || triggerSyncMutation.isPending) ? 'animate-spin' : ''}`} />
                Check for Updates
              </button>
            </div>
            <button
              onClick={() => setShowAddStigModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded hover:bg-cyan-500"
            >
              <Plus className="w-4 h-4" />
              Add STIG
            </button>
          </div>

          {/* Tracked STIGs Table */}
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="px-4 py-3 bg-gray-900 border-b border-gray-700">
              <h3 className="text-gray-200 font-medium">Tracked STIGs</h3>
            </div>
            {loadingTracked ? (
              <div className="p-8 text-center text-gray-400">Loading...</div>
            ) : !trackedStigs?.stigs?.length ? (
              <div className="p-8 text-center">
                <Database className="w-12 h-12 mx-auto mb-4 text-gray-600" />
                <p className="text-gray-400">No STIGs being tracked</p>
                <p className="text-sm text-gray-500 mt-1">
                  Add STIGs from the DISA repository to track updates automatically
                </p>
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-gray-900/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-sm text-gray-400">STIG Name</th>
                    <th className="px-4 py-3 text-left text-sm text-gray-400">Current Version</th>
                    <th className="px-4 py-3 text-left text-sm text-gray-400">Available</th>
                    <th className="px-4 py-3 text-left text-sm text-gray-400">Last Checked</th>
                    <th className="px-4 py-3 text-center text-sm text-gray-400">Auto-Update</th>
                    <th className="px-4 py-3 text-right text-sm text-gray-400">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {trackedStigs.stigs.map((stig) => (
                    <tr key={stig.id} className="hover:bg-gray-700/50">
                      <td className="px-4 py-3">
                        <div className="text-gray-200">{stig.stig_name}</div>
                        <div className="text-xs text-gray-500">{stig.stig_id}</div>
                      </td>
                      <td className="px-4 py-3 text-gray-400">
                        V{stig.current_version}R{stig.current_release}
                      </td>
                      <td className="px-4 py-3">
                        {stig.has_update ? (
                          <span className="inline-flex items-center gap-1 text-amber-400">
                            <ArrowUpCircle className="w-4 h-4" />
                            V{stig.available_version}R{stig.available_release}
                          </span>
                        ) : (
                          <span className="text-green-400 text-sm">Up to date</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-gray-400 text-sm">
                        {stig.last_checked_at
                          ? new Date(stig.last_checked_at).toLocaleDateString()
                          : '-'}
                      </td>
                      <td className="px-4 py-3 text-center">
                        <button
                          onClick={() =>
                            toggleAutoUpdateMutation.mutate({
                              id: stig.id,
                              autoUpdate: !stig.auto_update,
                            })
                          }
                          className="text-gray-400 hover:text-cyan-400"
                        >
                          {stig.auto_update ? (
                            <ToggleRight className="w-6 h-6 text-cyan-400" />
                          ) : (
                            <ToggleLeft className="w-6 h-6" />
                          )}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-2">
                          {stig.has_update && (
                            <button
                              onClick={() => downloadStigMutation.mutate(stig.id)}
                              disabled={downloadStigMutation.isPending}
                              className="p-2 text-gray-400 hover:text-cyan-400 rounded"
                              title="Download Update"
                            >
                              <CloudDownload className="w-4 h-4" />
                            </button>
                          )}
                          <button
                            onClick={() => deleteStigMutation.mutate(stig.id)}
                            className="p-2 text-gray-400 hover:text-red-400 rounded"
                            title="Remove from tracking"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Sync History */}
          {syncHistory?.history?.length ? (
            <div className="bg-gray-800 rounded-lg overflow-hidden">
              <div className="px-4 py-3 bg-gray-900 border-b border-gray-700 flex items-center gap-2">
                <History className="w-4 h-4 text-gray-400" />
                <h3 className="text-gray-200 font-medium">Recent Sync History</h3>
              </div>
              <div className="divide-y divide-gray-700">
                {syncHistory.history.slice(0, 10).map((entry) => (
                  <div key={entry.id} className="px-4 py-3 flex items-center justify-between">
                    <div>
                      <div className="text-gray-200">{entry.stig_id}</div>
                      <div className="text-sm text-gray-400">
                        {entry.old_version != null
                          ? `V${entry.old_version}R${entry.old_release} → V${entry.new_version}R${entry.new_release}`
                          : `Initial: V${entry.new_version}R${entry.new_release}`}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`text-sm ${
                        entry.status === 'Completed' ? 'text-green-400' :
                        entry.status === 'Failed' ? 'text-red-400' : 'text-gray-400'
                      }`}>
                        {entry.status}
                      </div>
                      <div className="text-xs text-gray-500">
                        {new Date(entry.synced_at).toLocaleString()}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {/* Errors */}
          {syncStatus?.last_errors?.length ? (
            <div className="bg-red-900/20 border border-red-800 rounded-lg p-4">
              <div className="flex items-center gap-2 text-red-400 mb-2">
                <AlertTriangle className="w-5 h-5" />
                <span className="font-medium">Sync Errors</span>
              </div>
              <ul className="space-y-1 text-sm text-red-300">
                {syncStatus.last_errors.map((err, i) => (
                  <li key={i}>• {err}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      )}

      {/* Modals */}
      <UploadModal
        isOpen={showUploadModal}
        onClose={() => setShowUploadModal(false)}
        onSuccess={() => queryClient.invalidateQueries({ queryKey: ['scap-content'] })}
      />
      <ScanModal
        isOpen={showScanModal}
        onClose={() => {
          setShowScanModal(false);
          setSelectedContent(null);
        }}
        content={selectedContent}
        onSuccess={() => queryClient.invalidateQueries({ queryKey: ['scap-executions'] })}
      />
      <AddStigModal
        isOpen={showAddStigModal}
        onClose={() => setShowAddStigModal(false)}
        onSuccess={() => queryClient.invalidateQueries({ queryKey: ['tracked-stigs'] })}
      />
    </div>
    </Layout>
  );
};

export default ScapPage;
