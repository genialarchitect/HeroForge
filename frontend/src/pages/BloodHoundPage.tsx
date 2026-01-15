import React, { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Upload,
  GitBranch,
  Users,
  Shield,
  Server,
  AlertTriangle,
  ChevronRight,
  Trash2,
  RefreshCw,
  Crown,
  Key,
  Unlock,
  ExternalLink,
  Target,
  Clock,
  Database,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import { EngagementRequiredBanner } from '../components/engagement';
import { useRequireEngagement } from '../hooks/useRequireEngagement';
import Button from '../components/ui/Button';
import {
  bloodhoundAPI,
  BloodHoundImportSummary,
  BloodHoundImportDetail,
  BloodHoundAttackPath,
  PathStep,
  KerberoastableUser,
  AsrepRoastableUser,
  HighValueTarget,
  UnconstrainedDelegation,
} from '../services/api';

// File upload component
const FileUpload: React.FC<{ onUpload: (file: File) => void; isUploading: boolean; hasEngagement: boolean }> = ({
  onUpload,
  isUploading,
  hasEngagement,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const inputRef = React.useRef<HTMLInputElement>(null);

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setDragActive(false);
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        onUpload(e.dataTransfer.files[0]);
      }
    },
    [onUpload]
  );

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      onUpload(e.target.files[0]);
    }
  };

  return (
    <div
      className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
        dragActive
          ? 'border-primary bg-primary/10'
          : 'border-slate-300 dark:border-slate-600 hover:border-primary'
      }`}
      onDragEnter={handleDrag}
      onDragLeave={handleDrag}
      onDragOver={handleDrag}
      onDrop={handleDrop}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".zip,.json"
        onChange={handleChange}
        className="hidden"
      />
      <Upload className="h-12 w-12 mx-auto mb-4 text-slate-400" />
      <p className="text-lg font-medium text-slate-700 dark:text-slate-300 mb-2">
        Drop SharpHound data here
      </p>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
        Supports .zip archives and individual .json files
      </p>
      <Button
        onClick={() => inputRef.current?.click()}
        disabled={isUploading || !hasEngagement}
        variant="primary"
      >
        {isUploading ? (
          <>
            <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
            Uploading...
          </>
        ) : (
          <>
            <Upload className="h-4 w-4 mr-2" />
            Select File
          </>
        )}
      </Button>
    </div>
  );
};

// Attack path visualization
const AttackPathCard: React.FC<{ path: BloodHoundAttackPath }> = ({ path }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
      <div
        className="flex items-center justify-between cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-500/20 rounded-lg">
            <GitBranch className="h-5 w-5 text-red-500" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-medium text-slate-700 dark:text-slate-300">
                {path.start_node.name}
              </span>
              <ChevronRight className="h-4 w-4 text-slate-400" />
              <span className="font-medium text-red-500">{path.end_node.name}</span>
            </div>
            <div className="text-sm text-slate-500 dark:text-slate-400">
              {path.length} steps | Risk Score: {path.risk_score}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`px-2 py-1 rounded text-xs font-medium ${
              path.risk_score >= 80
                ? 'bg-red-500/20 text-red-500'
                : path.risk_score >= 50
                ? 'bg-orange-500/20 text-orange-500'
                : 'bg-yellow-500/20 text-yellow-500'
            }`}
          >
            {path.risk_score >= 80 ? 'Critical' : path.risk_score >= 50 ? 'High' : 'Medium'}
          </span>
          <ChevronRight
            className={`h-5 w-5 text-slate-400 transition-transform ${expanded ? 'rotate-90' : ''}`}
          />
        </div>
      </div>

      {expanded && (
        <div className="mt-4 space-y-3">
          {path.path.map((step: PathStep, index: number) => (
            <div
              key={index}
              className="flex items-start gap-3 pl-4 border-l-2 border-slate-300 dark:border-slate-600"
            >
              <div className="flex-1">
                <div className="flex items-center gap-2 text-sm">
                  <span className="font-medium text-slate-700 dark:text-slate-300">
                    {step.from_node.name}
                  </span>
                  <span className="px-2 py-0.5 bg-primary/20 text-primary rounded text-xs">
                    {step.relationship}
                  </span>
                  <span className="font-medium text-slate-700 dark:text-slate-300">
                    {step.to_node.name}
                  </span>
                </div>
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                  {step.abuse_info}
                </p>
                {step.opsec_considerations && (
                  <p className="text-xs text-orange-500 mt-1">
                    OPSEC: {step.opsec_considerations}
                  </p>
                )}
              </div>
            </div>
          ))}

          {path.techniques.length > 0 && (
            <div className="pt-3 border-t border-slate-200 dark:border-slate-700">
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">MITRE ATT&CK:</p>
              <div className="flex flex-wrap gap-1">
                {path.techniques.map((tech: string, i: number) => (
                  <a
                    key={i}
                    href={`https://attack.mitre.org/techniques/${tech.replace('.', '/')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-2 py-0.5 bg-slate-200 dark:bg-slate-700 rounded text-xs text-slate-600 dark:text-slate-400 hover:bg-primary/20 hover:text-primary flex items-center gap-1"
                  >
                    {tech}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Kerberoastable users table
const KerberoastableTable: React.FC<{ users: KerberoastableUser[] }> = ({ users }) => (
  <div className="overflow-x-auto">
    <table className="w-full">
      <thead>
        <tr className="border-b border-slate-200 dark:border-slate-700">
          <th className="text-left py-2 px-3 text-sm font-medium text-slate-600 dark:text-slate-400">
            User
          </th>
          <th className="text-left py-2 px-3 text-sm font-medium text-slate-600 dark:text-slate-400">
            Domain
          </th>
          <th className="text-left py-2 px-3 text-sm font-medium text-slate-600 dark:text-slate-400">
            SPNs
          </th>
          <th className="text-left py-2 px-3 text-sm font-medium text-slate-600 dark:text-slate-400">
            Admin
          </th>
          <th className="text-left py-2 px-3 text-sm font-medium text-slate-600 dark:text-slate-400">
            Password Set
          </th>
        </tr>
      </thead>
      <tbody>
        {users.map((user) => (
          <tr
            key={user.object_id}
            className="border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/50"
          >
            <td className="py-2 px-3">
              <div className="flex items-center gap-2">
                <Key className="h-4 w-4 text-yellow-500" />
                <span className="font-medium text-slate-700 dark:text-slate-300">{user.name}</span>
              </div>
            </td>
            <td className="py-2 px-3 text-sm text-slate-600 dark:text-slate-400">{user.domain}</td>
            <td className="py-2 px-3">
              <div className="flex flex-wrap gap-1">
                {user.service_principal_names.slice(0, 2).map((spn, i) => (
                  <span
                    key={i}
                    className="px-1.5 py-0.5 bg-slate-200 dark:bg-slate-700 rounded text-xs"
                  >
                    {spn.length > 30 ? spn.substring(0, 30) + '...' : spn}
                  </span>
                ))}
                {user.service_principal_names.length > 2 && (
                  <span className="px-1.5 py-0.5 bg-slate-200 dark:bg-slate-700 rounded text-xs">
                    +{user.service_principal_names.length - 2} more
                  </span>
                )}
              </div>
            </td>
            <td className="py-2 px-3">
              {user.is_admin ? (
                <span className="px-2 py-0.5 bg-red-500/20 text-red-500 rounded text-xs">Admin</span>
              ) : (
                <span className="text-slate-400">-</span>
              )}
            </td>
            <td className="py-2 px-3 text-sm text-slate-600 dark:text-slate-400">
              {user.password_last_set || 'Unknown'}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

// Import detail view
const ImportDetail: React.FC<{ importData: BloodHoundImportDetail; onClose: () => void }> = ({
  importData,
  onClose,
}) => {
  const [activeTab, setActiveTab] = useState<'paths' | 'kerberos' | 'asrep' | 'delegation' | 'targets'>(
    'paths'
  );

  const tabs = [
    { id: 'paths', label: 'Attack Paths', icon: GitBranch, count: importData.attack_paths.length },
    { id: 'kerberos', label: 'Kerberoastable', icon: Key, count: importData.kerberoastable_users.length },
    { id: 'asrep', label: 'AS-REP Roastable', icon: Unlock, count: importData.asrep_roastable_users.length },
    {
      id: 'delegation',
      label: 'Unconstrained Delegation',
      icon: Server,
      count: importData.unconstrained_delegation.length,
    },
    { id: 'targets', label: 'High-Value Targets', icon: Crown, count: importData.high_value_targets.length },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-slate-800 dark:text-white">
            {importData.domain}
          </h2>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Imported {new Date(importData.created_at).toLocaleString()}
          </p>
        </div>
        <Button variant="secondary" onClick={onClose}>
          Back to List
        </Button>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-3">
          <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400 mb-1">
            <Users className="h-4 w-4" />
            <span className="text-xs">Users</span>
          </div>
          <p className="text-xl font-semibold text-slate-800 dark:text-white">
            {importData.statistics.total_users}
          </p>
        </div>
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-3">
          <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400 mb-1">
            <Server className="h-4 w-4" />
            <span className="text-xs">Computers</span>
          </div>
          <p className="text-xl font-semibold text-slate-800 dark:text-white">
            {importData.statistics.total_computers}
          </p>
        </div>
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-3">
          <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400 mb-1">
            <Shield className="h-4 w-4" />
            <span className="text-xs">Groups</span>
          </div>
          <p className="text-xl font-semibold text-slate-800 dark:text-white">
            {importData.statistics.total_groups}
          </p>
        </div>
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-3">
          <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400 mb-1">
            <Database className="h-4 w-4" />
            <span className="text-xs">Sessions</span>
          </div>
          <p className="text-xl font-semibold text-slate-800 dark:text-white">
            {importData.statistics.total_sessions}
          </p>
        </div>
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-3">
          <div className="flex items-center gap-2 text-red-500 mb-1">
            <Crown className="h-4 w-4" />
            <span className="text-xs">Domain Admins</span>
          </div>
          <p className="text-xl font-semibold text-red-500">
            {importData.statistics.domain_admins}
          </p>
        </div>
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-3">
          <div className="flex items-center gap-2 text-orange-500 mb-1">
            <GitBranch className="h-4 w-4" />
            <span className="text-xs">Attack Paths</span>
          </div>
          <p className="text-xl font-semibold text-orange-500">
            {importData.statistics.attack_paths_found}
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-200 dark:border-slate-700">
        <div className="flex gap-4 overflow-x-auto">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`flex items-center gap-2 px-4 py-2 border-b-2 transition-colors whitespace-nowrap ${
                activeTab === tab.id
                  ? 'border-primary text-primary'
                  : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
              <span className="px-1.5 py-0.5 bg-slate-200 dark:bg-slate-700 rounded text-xs">
                {tab.count}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div>
        {activeTab === 'paths' && (
          <div className="space-y-3">
            {importData.attack_paths.length === 0 ? (
              <p className="text-slate-500 dark:text-slate-400 text-center py-8">
                No attack paths found
              </p>
            ) : (
              importData.attack_paths.map((path) => <AttackPathCard key={path.id} path={path} />)
            )}
          </div>
        )}

        {activeTab === 'kerberos' && (
          <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
            {importData.kerberoastable_users.length === 0 ? (
              <p className="text-slate-500 dark:text-slate-400 text-center py-8">
                No Kerberoastable users found
              </p>
            ) : (
              <KerberoastableTable users={importData.kerberoastable_users} />
            )}
          </div>
        )}

        {activeTab === 'asrep' && (
          <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden">
            {importData.asrep_roastable_users.length === 0 ? (
              <p className="text-slate-500 dark:text-slate-400 text-center py-8">
                No AS-REP roastable users found
              </p>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-700">
                    <th className="text-left py-2 px-3 text-sm font-medium text-slate-600 dark:text-slate-400">
                      User
                    </th>
                    <th className="text-left py-2 px-3 text-sm font-medium text-slate-600 dark:text-slate-400">
                      Domain
                    </th>
                    <th className="text-left py-2 px-3 text-sm font-medium text-slate-600 dark:text-slate-400">
                      Enabled
                    </th>
                    <th className="text-left py-2 px-3 text-sm font-medium text-slate-600 dark:text-slate-400">
                      Admin
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {importData.asrep_roastable_users.map((user) => (
                    <tr
                      key={user.object_id}
                      className="border-b border-slate-100 dark:border-slate-800"
                    >
                      <td className="py-2 px-3">
                        <div className="flex items-center gap-2">
                          <Unlock className="h-4 w-4 text-purple-500" />
                          <span className="font-medium text-slate-700 dark:text-slate-300">
                            {user.name}
                          </span>
                        </div>
                      </td>
                      <td className="py-2 px-3 text-sm text-slate-600 dark:text-slate-400">
                        {user.domain}
                      </td>
                      <td className="py-2 px-3">
                        {user.is_enabled ? (
                          <span className="px-2 py-0.5 bg-green-500/20 text-green-500 rounded text-xs">
                            Yes
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 bg-slate-500/20 text-slate-500 rounded text-xs">
                            No
                          </span>
                        )}
                      </td>
                      <td className="py-2 px-3">
                        {user.is_admin ? (
                          <span className="px-2 py-0.5 bg-red-500/20 text-red-500 rounded text-xs">
                            Admin
                          </span>
                        ) : (
                          <span className="text-slate-400">-</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {activeTab === 'delegation' && (
          <div className="grid gap-3">
            {importData.unconstrained_delegation.length === 0 ? (
              <p className="text-slate-500 dark:text-slate-400 text-center py-8">
                No unconstrained delegation found
              </p>
            ) : (
              importData.unconstrained_delegation.map((obj) => (
                <div
                  key={obj.object_id}
                  className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4 flex items-center justify-between"
                >
                  <div className="flex items-center gap-3">
                    <div
                      className={`p-2 rounded-lg ${
                        obj.is_dc ? 'bg-red-500/20' : 'bg-orange-500/20'
                      }`}
                    >
                      <Server className={`h-5 w-5 ${obj.is_dc ? 'text-red-500' : 'text-orange-500'}`} />
                    </div>
                    <div>
                      <p className="font-medium text-slate-700 dark:text-slate-300">{obj.name}</p>
                      <p className="text-sm text-slate-500 dark:text-slate-400">
                        {obj.object_type} | {obj.domain}
                      </p>
                    </div>
                  </div>
                  {obj.is_dc && (
                    <span className="px-2 py-1 bg-red-500/20 text-red-500 rounded text-xs">
                      Domain Controller
                    </span>
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'targets' && (
          <div className="grid gap-3">
            {importData.high_value_targets.length === 0 ? (
              <p className="text-slate-500 dark:text-slate-400 text-center py-8">
                No high-value targets found
              </p>
            ) : (
              importData.high_value_targets.map((target) => (
                <div
                  key={target.object_id}
                  className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4 flex items-center justify-between"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-yellow-500/20 rounded-lg">
                      <Crown className="h-5 w-5 text-yellow-500" />
                    </div>
                    <div>
                      <p className="font-medium text-slate-700 dark:text-slate-300">{target.name}</p>
                      <p className="text-sm text-slate-500 dark:text-slate-400">{target.reason}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      {target.paths_to_target} paths
                    </p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">{target.object_type}</p>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
};

// Main page component
const BloodHoundPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [selectedImportId, setSelectedImportId] = useState<string | null>(null);
  const { hasEngagement } = useRequireEngagement();

  // Fetch imports list
  const { data: importsData, isLoading: importsLoading } = useQuery({
    queryKey: ['bloodhound-imports'],
    queryFn: () => bloodhoundAPI.listImports(),
  });

  // Fetch selected import details
  const { data: importDetail, isLoading: detailLoading } = useQuery({
    queryKey: ['bloodhound-import', selectedImportId],
    queryFn: () => bloodhoundAPI.getImport(selectedImportId!),
    enabled: !!selectedImportId,
  });

  // Upload mutation
  const uploadMutation = useMutation({
    mutationFn: (file: File) => bloodhoundAPI.uploadData(file),
    onSuccess: (response) => {
      toast.success(response.data.message);
      queryClient.invalidateQueries({ queryKey: ['bloodhound-imports'] });
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.message || 'Upload failed');
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => bloodhoundAPI.deleteImport(id),
    onSuccess: () => {
      toast.success('Import deleted');
      queryClient.invalidateQueries({ queryKey: ['bloodhound-imports'] });
      setSelectedImportId(null);
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.message || 'Delete failed');
    },
  });

  const handleUpload = (file: File) => {
    uploadMutation.mutate(file);
  };

  const handleDelete = (id: string) => {
    if (confirm('Are you sure you want to delete this import?')) {
      deleteMutation.mutate(id);
    }
  };

  // Show detail view if an import is selected
  if (selectedImportId && importDetail?.data) {
    return (
      <Layout>
        <div className="max-w-7xl mx-auto p-6">
          {detailLoading ? (
            <div className="flex items-center justify-center py-12">
              <RefreshCw className="h-8 w-8 text-primary animate-spin" />
            </div>
          ) : (
            <ImportDetail
              importData={importDetail.data}
              onClose={() => setSelectedImportId(null)}
            />
          )}
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="max-w-7xl mx-auto p-6">
        {/* Header */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-slate-800 dark:text-white flex items-center gap-3">
            <div className="p-2 bg-primary/20 rounded-lg">
              <GitBranch className="h-6 w-6 text-primary" />
            </div>
            BloodHound Integration
          </h1>
          <p className="text-slate-600 dark:text-slate-400 mt-1">
            Import SharpHound data and analyze Active Directory attack paths
          </p>
        </div>

        <EngagementRequiredBanner toolName="BloodHound Integration" className="mb-6" />

        {/* Upload Section */}
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6 mb-6">
          <h2 className="text-lg font-semibold text-slate-800 dark:text-white mb-4">
            Import SharpHound Data
          </h2>
          <FileUpload onUpload={handleUpload} isUploading={uploadMutation.isPending} hasEngagement={hasEngagement} />
        </div>

        {/* Imports List */}
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
          <div className="p-4 border-b border-light-border dark:border-dark-border">
            <h2 className="text-lg font-semibold text-slate-800 dark:text-white">
              Previous Imports
            </h2>
          </div>

          {importsLoading ? (
            <div className="flex items-center justify-center py-12">
              <RefreshCw className="h-8 w-8 text-primary animate-spin" />
            </div>
          ) : !importsData?.data?.imports?.length ? (
            <div className="text-center py-12 text-slate-500 dark:text-slate-400">
              <Database className="h-12 w-12 mx-auto mb-3 opacity-50" />
              <p>No imports yet. Upload SharpHound data to get started.</p>
            </div>
          ) : (
            <div className="divide-y divide-light-border dark:divide-dark-border">
              {importsData.data.imports.map((imp: BloodHoundImportSummary) => (
                <div
                  key={imp.id}
                  className="p-4 hover:bg-slate-50 dark:hover:bg-slate-800/50 flex items-center justify-between"
                >
                  <div
                    className="flex items-center gap-4 cursor-pointer flex-1"
                    onClick={() => setSelectedImportId(imp.id)}
                  >
                    <div className="p-2 bg-primary/20 rounded-lg">
                      <Target className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <p className="font-medium text-slate-700 dark:text-slate-300">{imp.domain}</p>
                      <div className="flex items-center gap-4 text-sm text-slate-500 dark:text-slate-400">
                        <span className="flex items-center gap-1">
                          <Users className="h-3 w-3" />
                          {imp.statistics.total_users} users
                        </span>
                        <span className="flex items-center gap-1">
                          <Server className="h-3 w-3" />
                          {imp.statistics.total_computers} computers
                        </span>
                        <span className="flex items-center gap-1">
                          <GitBranch className="h-3 w-3" />
                          {imp.statistics.attack_paths_found} paths
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {new Date(imp.created_at).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-1 rounded text-xs ${
                        imp.status === 'completed'
                          ? 'bg-green-500/20 text-green-500'
                          : imp.status === 'processing'
                          ? 'bg-yellow-500/20 text-yellow-500'
                          : 'bg-red-500/20 text-red-500'
                      }`}
                    >
                      {imp.status}
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDelete(imp.id);
                      }}
                    >
                      <Trash2 className="h-4 w-4 text-red-500" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
};

export default BloodHoundPage;
