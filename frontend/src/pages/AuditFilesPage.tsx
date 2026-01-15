import React, { useState, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  FileCheck,
  Upload,
  Download,
  Trash2,
  Search,
  Filter,
  Archive,
  RotateCcw,
  History,
  Shield,
  Eye,
  FileText,
  FileCode,
  Calendar,
  User,
  Hash,
  Clock,
  ChevronRight,
  X,
  Plus,
} from 'lucide-react';
import api from '../services/api';
import Layout from '../components/layout/Layout';
import AcasNavigation from '../components/navigation/AcasNavigation';

// Types
interface AuditFile {
  id: string;
  file_type: string;
  filename: string;
  file_size: number;
  sha256_hash: string;
  version: number;
  system_id?: string;
  asset_id?: string;
  framework?: string;
  profile_id?: string;
  scan_id?: string;
  created_by: string;
  created_at: string;
  retention_until?: string;
  is_archived: boolean;
  notes?: string;
}

interface FileVersion {
  id: string;
  file_id: string;
  version: number;
  sha256_hash: string;
  file_size: number;
  created_by: string;
  created_at: string;
  change_notes?: string;
}

interface CustodyEvent {
  id: string;
  file_id: string;
  event_type: string;
  actor: string;
  description?: string;
  ip_address?: string;
  timestamp: string;
}

interface RetentionPolicy {
  id: string;
  name: string;
  description?: string;
  framework?: string;
  retention_days: number;
  is_default: boolean;
}

// API functions
const auditFilesAPI = {
  listFiles: (params?: Record<string, string>) =>
    api.get<AuditFile[]>('/api/audit-files', { params }).then((r) => r.data),
  getFile: (id: string) => api.get<AuditFile>(`/api/audit-files/${id}`).then((r) => r.data),
  downloadFile: (id: string) =>
    api.get(`/api/audit-files/${id}/download`, { responseType: 'blob' }).then((r) => r.data),
  getVersionHistory: (id: string) =>
    api.get<FileVersion[]>(`/api/audit-files/${id}/versions`).then((r) => r.data),
  getCustodyChain: (id: string) =>
    api.get<CustodyEvent[]>(`/api/audit-files/${id}/custody`).then((r) => r.data),
  archiveFile: (id: string) => api.post(`/api/audit-files/${id}/archive`).then((r) => r.data),
  restoreFile: (id: string) => api.post(`/api/audit-files/${id}/restore`).then((r) => r.data),
  generateCkl: (data: { scan_id: string; stig_profile?: string; system_name?: string; asset_id?: string }) =>
    api.post('/api/audit-files/generate/ckl', data).then((r) => r.data),
  generateArf: (data: { scap_execution_id: string; asset_id?: string }) =>
    api.post('/api/audit-files/generate/arf', data).then((r) => r.data),
  importCkl: (data: { filename: string; content: string; system_id?: string; asset_id?: string }) =>
    api.post('/api/audit-files/import/ckl', data).then((r) => r.data),
  importArf: (data: { filename: string; content: string; system_id?: string; asset_id?: string }) =>
    api.post('/api/audit-files/import/arf', data).then((r) => r.data),
  listRetentionPolicies: () =>
    api.get<RetentionPolicy[]>('/api/audit-files/retention-policies').then((r) => r.data),
};

// File type badge
const FileTypeBadge: React.FC<{ type: string }> = ({ type }) => {
  const colors: Record<string, string> = {
    ckl: 'bg-green-900/50 text-green-400',
    arf: 'bg-purple-900/50 text-purple-400',
    xccdf: 'bg-cyan-900/50 text-cyan-400',
    oval: 'bg-amber-900/50 text-amber-400',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs uppercase font-medium ${colors[type] || 'bg-gray-700'}`}>
      {type}
    </span>
  );
};

// Format file size
const formatFileSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

// Import modal
const ImportModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  fileType: 'ckl' | 'arf';
  onSuccess: () => void;
}> = ({ isOpen, onClose, fileType, onSuccess }) => {
  const [file, setFile] = useState<File | null>(null);
  const [systemId, setSystemId] = useState('');
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleImport = async () => {
    if (!file) return;
    setUploading(true);
    try {
      const content = await file.text();
      const base64 = btoa(content);
      const importFn = fileType === 'ckl' ? auditFilesAPI.importCkl : auditFilesAPI.importArf;
      await importFn({
        filename: file.name,
        content: base64,
        system_id: systemId || undefined,
      });
      toast.success(`${fileType.toUpperCase()} file imported successfully`);
      onSuccess();
      onClose();
      setFile(null);
      setSystemId('');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Import failed');
    } finally {
      setUploading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-gray-100">
            Import {fileType.toUpperCase()} File
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-200">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="space-y-4">
          <div className="border-2 border-dashed border-gray-600 rounded-lg p-6 text-center">
            <input
              ref={fileInputRef}
              type="file"
              accept=".ckl,.xml"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="hidden"
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              className="flex flex-col items-center w-full"
            >
              <Upload className="w-12 h-12 mb-2 text-gray-400" />
              <p className="text-gray-400">
                {file ? file.name : `Click to select ${fileType.toUpperCase()} file`}
              </p>
              {file && <p className="text-sm text-gray-500 mt-1">{formatFileSize(file.size)}</p>}
            </button>
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">System ID (optional)</label>
            <input
              type="text"
              value={systemId}
              onChange={(e) => setSystemId(e.target.value)}
              placeholder="e.g., SYS-001"
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button onClick={onClose} className="px-4 py-2 text-gray-400 hover:text-gray-200">
              Cancel
            </button>
            <button
              onClick={handleImport}
              disabled={!file || uploading}
              className="px-4 py-2 bg-cyan-600 text-white rounded hover:bg-cyan-500 disabled:opacity-50"
            >
              {uploading ? 'Importing...' : 'Import'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Detail panel
const DetailPanel: React.FC<{
  file: AuditFile | null;
  onClose: () => void;
  onDownload: (id: string) => void;
  onArchive: (id: string) => void;
  onRestore: (id: string) => void;
}> = ({ file, onClose, onDownload, onArchive, onRestore }) => {
  const [activeDetailTab, setActiveDetailTab] = useState<'info' | 'versions' | 'custody'>('info');

  const { data: versions = [] } = useQuery({
    queryKey: ['audit-file-versions', file?.id],
    queryFn: () => (file ? auditFilesAPI.getVersionHistory(file.id) : Promise.resolve([])),
    enabled: !!file && activeDetailTab === 'versions',
  });

  const { data: custodyEvents = [] } = useQuery({
    queryKey: ['audit-file-custody', file?.id],
    queryFn: () => (file ? auditFilesAPI.getCustodyChain(file.id) : Promise.resolve([])),
    enabled: !!file && activeDetailTab === 'custody',
  });

  if (!file) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-96 bg-gray-800 border-l border-gray-700 shadow-xl z-40 overflow-y-auto">
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-100">File Details</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-200">
            <X className="w-5 h-5" />
          </button>
        </div>
      </div>

      <div className="p-4 space-y-4">
        <div className="flex items-center gap-3">
          <FileTypeBadge type={file.file_type} />
          <span className="text-gray-200 font-medium truncate">{file.filename}</span>
        </div>

        {/* Action buttons */}
        <div className="flex gap-2">
          <button
            onClick={() => onDownload(file.id)}
            className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-gray-700 text-gray-200 rounded hover:bg-gray-600"
          >
            <Download className="w-4 h-4" />
            Download
          </button>
          {file.is_archived ? (
            <button
              onClick={() => onRestore(file.id)}
              className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-green-600/20 text-green-400 rounded hover:bg-green-600/30"
            >
              <RotateCcw className="w-4 h-4" />
              Restore
            </button>
          ) : (
            <button
              onClick={() => onArchive(file.id)}
              className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-amber-600/20 text-amber-400 rounded hover:bg-amber-600/30"
            >
              <Archive className="w-4 h-4" />
              Archive
            </button>
          )}
        </div>

        {/* Tabs */}
        <div className="flex border-b border-gray-700">
          {(['info', 'versions', 'custody'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveDetailTab(tab)}
              className={`px-4 py-2 text-sm capitalize ${
                activeDetailTab === tab
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Tab content */}
        {activeDetailTab === 'info' && (
          <div className="space-y-3">
            <InfoItem icon={<Hash />} label="SHA-256" value={file.sha256_hash.substring(0, 16) + '...'} />
            <InfoItem icon={<FileText />} label="Size" value={formatFileSize(file.file_size)} />
            <InfoItem icon={<User />} label="Created By" value={file.created_by} />
            <InfoItem icon={<Calendar />} label="Created" value={new Date(file.created_at).toLocaleString()} />
            <InfoItem icon={<Clock />} label="Version" value={`v${file.version}`} />
            {file.framework && <InfoItem icon={<Shield />} label="Framework" value={file.framework} />}
            {file.system_id && <InfoItem icon={<FileCode />} label="System ID" value={file.system_id} />}
            {file.notes && (
              <div className="mt-4">
                <label className="text-sm text-gray-400 block mb-1">Notes</label>
                <p className="text-gray-200 text-sm bg-gray-700 p-2 rounded">{file.notes}</p>
              </div>
            )}
          </div>
        )}

        {activeDetailTab === 'versions' && (
          <div className="space-y-2">
            {versions.length === 0 ? (
              <p className="text-gray-400 text-sm text-center py-4">No version history</p>
            ) : (
              versions.map((v) => (
                <div key={v.id} className="p-3 bg-gray-700 rounded">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-200 font-medium">v{v.version}</span>
                    <span className="text-gray-400 text-sm">
                      {new Date(v.created_at).toLocaleDateString()}
                    </span>
                  </div>
                  <div className="text-sm text-gray-400 mt-1">
                    {formatFileSize(v.file_size)} - {v.created_by}
                  </div>
                  {v.change_notes && <p className="text-sm text-gray-300 mt-2">{v.change_notes}</p>}
                </div>
              ))
            )}
          </div>
        )}

        {activeDetailTab === 'custody' && (
          <div className="space-y-2">
            {custodyEvents.length === 0 ? (
              <p className="text-gray-400 text-sm text-center py-4">No custody events</p>
            ) : (
              custodyEvents.map((event) => (
                <div key={event.id} className="p-3 bg-gray-700 rounded">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-200 capitalize">{event.event_type}</span>
                    <span className="text-gray-400 text-sm">
                      {new Date(event.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <div className="text-sm text-gray-400 mt-1">
                    By: {event.actor}
                    {event.ip_address && ` from ${event.ip_address}`}
                  </div>
                  {event.description && <p className="text-sm text-gray-300 mt-1">{event.description}</p>}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
};

// Info item helper
const InfoItem: React.FC<{ icon: React.ReactNode; label: string; value: string }> = ({ icon, label, value }) => (
  <div className="flex items-center gap-3">
    <div className="text-gray-400 w-5 h-5">{icon}</div>
    <div>
      <div className="text-xs text-gray-500">{label}</div>
      <div className="text-sm text-gray-200">{value}</div>
    </div>
  </div>
);

// Main component
const AuditFilesPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [searchTerm, setSearchTerm] = useState('');
  const [fileTypeFilter, setFileTypeFilter] = useState('');
  const [showArchived, setShowArchived] = useState(false);
  const [selectedFile, setSelectedFile] = useState<AuditFile | null>(null);
  const [importModalType, setImportModalType] = useState<'ckl' | 'arf' | null>(null);

  const { data: files = [], isLoading } = useQuery({
    queryKey: ['audit-files', fileTypeFilter, showArchived],
    queryFn: () =>
      auditFilesAPI.listFiles({
        ...(fileTypeFilter && { file_type: fileTypeFilter }),
        include_archived: showArchived ? 'true' : 'false',
      }),
  });

  const archiveMutation = useMutation({
    mutationFn: auditFilesAPI.archiveFile,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['audit-files'] });
      toast.success('File archived');
    },
  });

  const restoreMutation = useMutation({
    mutationFn: auditFilesAPI.restoreFile,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['audit-files'] });
      toast.success('File restored');
    },
  });

  const handleDownload = async (id: string) => {
    try {
      const blob = await auditFilesAPI.downloadFile(id);
      const file = files.find((f) => f.id === id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file?.filename || `audit_file_${id}`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch {
      toast.error('Failed to download file');
    }
  };

  const filteredFiles = files.filter((f) =>
    f.filename.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <Layout>
    <div className="space-y-6">
      {/* ACAS Navigation */}
      <AcasNavigation />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileCheck className="w-8 h-8 text-cyan-400" />
          <div>
            <h1 className="text-2xl font-bold text-gray-100">Audit File Library</h1>
            <p className="text-sm text-gray-400">
              Manage CKL, ARF, and SCAP audit files with chain of custody tracking
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setImportModalType('ckl')}
            className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded hover:bg-green-500"
          >
            <Upload className="w-4 h-4" />
            Import CKL
          </button>
          <button
            onClick={() => setImportModalType('arf')}
            className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded hover:bg-purple-500"
          >
            <Upload className="w-4 h-4" />
            Import ARF
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-gray-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-gray-100">{files.length}</div>
          <div className="text-sm text-gray-400">Total Files</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-green-400">
            {files.filter((f) => f.file_type === 'ckl').length}
          </div>
          <div className="text-sm text-gray-400">CKL Files</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-purple-400">
            {files.filter((f) => f.file_type === 'arf').length}
          </div>
          <div className="text-sm text-gray-400">ARF Files</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-amber-400">
            {files.filter((f) => f.is_archived).length}
          </div>
          <div className="text-sm text-gray-400">Archived</div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-4 items-center">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search files..."
            className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <select
          value={fileTypeFilter}
          onChange={(e) => setFileTypeFilter(e.target.value)}
          className="px-4 py-2 bg-gray-800 border border-gray-700 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="">All Types</option>
          <option value="ckl">CKL</option>
          <option value="arf">ARF</option>
          <option value="xccdf">XCCDF</option>
          <option value="oval">OVAL</option>
        </select>
        <label className="flex items-center gap-2 text-gray-300">
          <input
            type="checkbox"
            checked={showArchived}
            onChange={(e) => setShowArchived(e.target.checked)}
            className="w-4 h-4 rounded border-gray-600 bg-gray-700"
          />
          Show Archived
        </label>
      </div>

      {/* File List */}
      {isLoading ? (
        <div className="text-center py-12 text-gray-400">Loading...</div>
      ) : filteredFiles.length === 0 ? (
        <div className="text-center py-12">
          <FileText className="w-12 h-12 mx-auto mb-4 text-gray-600" />
          <p className="text-gray-400">No audit files found</p>
          <p className="text-sm text-gray-500 mt-1">Import CKL or ARF files to get started</p>
        </div>
      ) : (
        <div className="bg-gray-800 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-900">
              <tr>
                <th className="px-4 py-3 text-left text-sm text-gray-400">File</th>
                <th className="px-4 py-3 text-left text-sm text-gray-400">Type</th>
                <th className="px-4 py-3 text-left text-sm text-gray-400">Size</th>
                <th className="px-4 py-3 text-left text-sm text-gray-400">System</th>
                <th className="px-4 py-3 text-left text-sm text-gray-400">Created</th>
                <th className="px-4 py-3 text-left text-sm text-gray-400">Version</th>
                <th className="px-4 py-3 text-right text-sm text-gray-400">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {filteredFiles.map((file) => (
                <tr
                  key={file.id}
                  className={`hover:bg-gray-700/50 cursor-pointer ${
                    file.is_archived ? 'opacity-60' : ''
                  }`}
                  onClick={() => setSelectedFile(file)}
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      {file.is_archived && <Archive className="w-4 h-4 text-amber-400" />}
                      <span className="text-gray-200">{file.filename}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <FileTypeBadge type={file.file_type} />
                  </td>
                  <td className="px-4 py-3 text-gray-400">{formatFileSize(file.file_size)}</td>
                  <td className="px-4 py-3 text-gray-400">{file.system_id || '-'}</td>
                  <td className="px-4 py-3 text-gray-400 text-sm">
                    {new Date(file.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3 text-gray-400">v{file.version}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => handleDownload(file.id)}
                        className="p-2 text-gray-400 hover:text-cyan-400 rounded"
                        title="Download"
                      >
                        <Download className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => setSelectedFile(file)}
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

      {/* Detail Panel */}
      <DetailPanel
        file={selectedFile}
        onClose={() => setSelectedFile(null)}
        onDownload={handleDownload}
        onArchive={(id) => archiveMutation.mutate(id)}
        onRestore={(id) => restoreMutation.mutate(id)}
      />

      {/* Import Modal */}
      {importModalType && (
        <ImportModal
          isOpen={true}
          onClose={() => setImportModalType(null)}
          fileType={importModalType}
          onSuccess={() => queryClient.invalidateQueries({ queryKey: ['audit-files'] })}
        />
      )}
    </div>
    </Layout>
  );
};

export default AuditFilesPage;
