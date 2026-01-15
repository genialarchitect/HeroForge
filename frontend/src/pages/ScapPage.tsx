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

// Main component
const ScapPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'content' | 'executions'>('content');
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showScanModal, setShowScanModal] = useState(false);
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
    </div>
    </Layout>
  );
};

export default ScapPage;
