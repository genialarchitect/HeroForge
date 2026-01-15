import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Monitor,
  Play,
  Shield,
  Users,
  Settings2,
  Lock,
  FileText,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Server,
  Search,
  Filter,
  Download,
  Eye,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  Wifi,
  HardDrive,
  ShieldCheck,
} from 'lucide-react';
import api from '../services/api';
import Layout from '../components/layout/Layout';
import AcasNavigation from '../components/navigation/AcasNavigation';

// Types
interface WindowsAuditScan {
  id: string;
  target: string;
  status: string;
  started_at: string;
  completed_at?: string;
  system_info?: WindowsSystemInfo;
  total_checks: number;
  cat1_findings: number;
  cat2_findings: number;
  cat3_findings: number;
  pass_count: number;
  fail_count: number;
}

interface WindowsSystemInfo {
  hostname: string;
  os_name: string;
  os_version: string;
  os_build?: string;
  architecture: string;
  domain?: string;
  is_domain_joined: boolean;
}

interface StigCheckResult {
  stig_id: string;
  rule_id: string;
  title: string;
  category: 'CatI' | 'CatII' | 'CatIII';
  status: 'NotAFinding' | 'Open' | 'NotApplicable' | 'NotReviewed';
  finding_details?: string;
  expected: string;
  actual: string;
  remediation?: string;
}

interface WindowsCredentials {
  username: string;
  password: string;
  domain?: string;
  auth_type: 'basic' | 'ntlm' | 'kerberos';
}

// API functions
const windowsAuditAPI = {
  listScans: () => api.get<WindowsAuditScan[]>('/api/windows-audit/scans').then((r) => r.data),
  getScan: (id: string) => api.get<WindowsAuditScan>(`/api/windows-audit/scans/${id}`).then((r) => r.data),
  getStigResults: (id: string) =>
    api.get<StigCheckResult[]>(`/api/windows-audit/scans/${id}/stig`).then((r) => r.data),
  startScan: (data: { target: string; credentials: WindowsCredentials; run_stig_checks: boolean; include_cat3: boolean }) =>
    api.post('/api/windows-audit/scan', data).then((r) => r.data),
  exportCkl: (id: string) =>
    api.get(`/api/windows-audit/scans/${id}/ckl`, { responseType: 'blob' }).then((r) => r.data),
  testConnection: (data: { target: string; credentials: WindowsCredentials }) =>
    api.post('/api/windows-audit/test', data).then((r) => r.data),
};

// Category badge
const CategoryBadge: React.FC<{ category: string }> = ({ category }) => {
  const colors: Record<string, string> = {
    CatI: 'bg-red-900/50 text-red-400',
    CatII: 'bg-amber-900/50 text-amber-400',
    CatIII: 'bg-yellow-900/50 text-yellow-400',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colors[category] || 'bg-gray-700'}`}>
      {category}
    </span>
  );
};

// Status badge
const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const configs: Record<string, { bg: string; icon: React.ReactNode }> = {
    pending: { bg: 'bg-gray-700 text-gray-300', icon: <Clock className="w-3 h-3" /> },
    running: { bg: 'bg-blue-900/50 text-blue-400', icon: <RefreshCw className="w-3 h-3 animate-spin" /> },
    completed: { bg: 'bg-green-900/50 text-green-400', icon: <CheckCircle className="w-3 h-3" /> },
    failed: { bg: 'bg-red-900/50 text-red-400', icon: <XCircle className="w-3 h-3" /> },
    NotAFinding: { bg: 'bg-green-900/50 text-green-400', icon: <CheckCircle className="w-3 h-3" /> },
    Open: { bg: 'bg-red-900/50 text-red-400', icon: <XCircle className="w-3 h-3" /> },
    NotApplicable: { bg: 'bg-gray-600 text-gray-400', icon: null },
    NotReviewed: { bg: 'bg-gray-700 text-gray-300', icon: <Clock className="w-3 h-3" /> },
  };
  const config = configs[status] || configs.pending;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs ${config.bg}`}>
      {config.icon}
      {status.replace(/([A-Z])/g, ' $1').trim()}
    </span>
  );
};

// New scan modal
const NewScanModal: React.FC<{ isOpen: boolean; onClose: () => void; onSuccess: () => void }> = ({
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [target, setTarget] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [domain, setDomain] = useState('');
  const [authType, setAuthType] = useState<'basic' | 'ntlm' | 'kerberos'>('ntlm');
  const [runStigChecks, setRunStigChecks] = useState(true);
  const [includeCat3, setIncludeCat3] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [testing, setTesting] = useState(false);

  const credentials: WindowsCredentials = { username, password, domain, auth_type: authType };

  const handleTest = async () => {
    setTesting(true);
    try {
      await windowsAuditAPI.testConnection({ target, credentials });
      toast.success('Connection successful!');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Connection failed');
    } finally {
      setTesting(false);
    }
  };

  const handleScan = async () => {
    setScanning(true);
    try {
      await windowsAuditAPI.startScan({
        target,
        credentials,
        run_stig_checks: runStigChecks,
        include_cat3: includeCat3,
      });
      toast.success('Windows audit scan started');
      onSuccess();
      onClose();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to start scan');
    } finally {
      setScanning(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-lg">
        <h2 className="text-xl font-semibold text-gray-100 mb-4">New Windows Audit Scan</h2>
        <div className="space-y-4">
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
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Administrator"
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Domain (optional)</label>
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="CORP"
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Auth Type</label>
              <select
                value={authType}
                onChange={(e) => setAuthType(e.target.value as any)}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="ntlm">NTLM</option>
                <option value="kerberos">Kerberos</option>
                <option value="basic">Basic</option>
              </select>
            </div>
          </div>
          <div className="space-y-2">
            <label className="flex items-center gap-2 text-gray-300">
              <input
                type="checkbox"
                checked={runStigChecks}
                onChange={(e) => setRunStigChecks(e.target.checked)}
                className="w-4 h-4 rounded border-gray-600 bg-gray-700"
              />
              Run STIG compliance checks
            </label>
            {runStigChecks && (
              <label className="flex items-center gap-2 text-gray-300 ml-6">
                <input
                  type="checkbox"
                  checked={includeCat3}
                  onChange={(e) => setIncludeCat3(e.target.checked)}
                  className="w-4 h-4 rounded border-gray-600 bg-gray-700"
                />
                Include CAT III checks (low severity)
              </label>
            )}
          </div>
          <div className="flex justify-between pt-4">
            <button
              onClick={handleTest}
              disabled={testing || !target || !username || !password}
              className="px-4 py-2 bg-gray-600 text-gray-200 rounded hover:bg-gray-500 disabled:opacity-50"
            >
              {testing ? 'Testing...' : 'Test Connection'}
            </button>
            <div className="flex gap-2">
              <button onClick={onClose} className="px-4 py-2 text-gray-400 hover:text-gray-200">
                Cancel
              </button>
              <button
                onClick={handleScan}
                disabled={scanning || !target || !username || !password}
                className="px-4 py-2 bg-cyan-600 text-white rounded hover:bg-cyan-500 disabled:opacity-50"
              >
                {scanning ? 'Starting...' : 'Start Scan'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Scan detail panel
const ScanDetailPanel: React.FC<{ scan: WindowsAuditScan | null; onClose: () => void }> = ({
  scan,
  onClose,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'stig'>('overview');
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');

  const { data: stigResults = [] } = useQuery({
    queryKey: ['windows-audit-stig', scan?.id],
    queryFn: () => (scan ? windowsAuditAPI.getStigResults(scan.id) : Promise.resolve([])),
    enabled: !!scan && activeTab === 'stig',
  });

  const handleExportCkl = async () => {
    if (!scan) return;
    try {
      const blob = await windowsAuditAPI.exportCkl(scan.id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${scan.target}_stig_results.ckl`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch {
      toast.error('Failed to export CKL');
    }
  };

  const filteredResults = stigResults.filter((r) => {
    const matchCategory = !categoryFilter || r.category === categoryFilter;
    const matchStatus = !statusFilter || r.status === statusFilter;
    return matchCategory && matchStatus;
  });

  if (!scan) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-[600px] bg-gray-800 border-l border-gray-700 shadow-xl z-40 overflow-y-auto">
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-gray-100">{scan.target}</h2>
            {scan.system_info && (
              <p className="text-sm text-gray-400">
                {scan.system_info.os_name} {scan.system_info.os_version}
              </p>
            )}
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-200">
            <XCircle className="w-5 h-5" />
          </button>
        </div>
        <div className="flex items-center gap-2 mt-2">
          <StatusBadge status={scan.status} />
        </div>
      </div>

      {/* Export button */}
      <div className="p-4">
        <button
          onClick={handleExportCkl}
          disabled={scan.status !== 'completed'}
          className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-green-600 text-white rounded hover:bg-green-500 disabled:opacity-50"
        >
          <Download className="w-4 h-4" />
          Export CKL
        </button>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-700 px-4">
        <button
          onClick={() => setActiveTab('overview')}
          className={`px-4 py-2 text-sm ${
            activeTab === 'overview'
              ? 'text-cyan-400 border-b-2 border-cyan-400'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          Overview
        </button>
        <button
          onClick={() => setActiveTab('stig')}
          className={`px-4 py-2 text-sm ${
            activeTab === 'stig'
              ? 'text-cyan-400 border-b-2 border-cyan-400'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          STIG Results ({scan.total_checks})
        </button>
      </div>

      {/* Content */}
      <div className="p-4">
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Findings Summary */}
            <div>
              <h3 className="text-sm font-medium text-gray-400 mb-3">STIG Findings</h3>
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-red-900/20 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-red-400">{scan.cat1_findings}</div>
                  <div className="text-xs text-red-300">CAT I (High)</div>
                </div>
                <div className="bg-amber-900/20 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-amber-400">{scan.cat2_findings}</div>
                  <div className="text-xs text-amber-300">CAT II (Med)</div>
                </div>
                <div className="bg-yellow-900/20 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-yellow-400">{scan.cat3_findings}</div>
                  <div className="text-xs text-yellow-300">CAT III (Low)</div>
                </div>
              </div>
            </div>

            {/* Pass/Fail */}
            <div>
              <h3 className="text-sm font-medium text-gray-400 mb-3">Compliance Rate</h3>
              <div className="bg-gray-700 rounded-full h-4 overflow-hidden">
                <div
                  className="bg-green-500 h-full"
                  style={{
                    width: `${scan.total_checks > 0 ? (scan.pass_count / scan.total_checks) * 100 : 0}%`,
                  }}
                />
              </div>
              <div className="flex justify-between text-sm mt-2">
                <span className="text-green-400">{scan.pass_count} Pass</span>
                <span className="text-red-400">{scan.fail_count} Fail</span>
              </div>
            </div>

            {/* System Info */}
            {scan.system_info && (
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-3">System Information</h3>
                <div className="bg-gray-700 rounded-lg p-4 space-y-2">
                  <InfoRow label="Hostname" value={scan.system_info.hostname} />
                  <InfoRow label="OS" value={`${scan.system_info.os_name} ${scan.system_info.os_version}`} />
                  <InfoRow label="Build" value={scan.system_info.os_build || 'N/A'} />
                  <InfoRow label="Architecture" value={scan.system_info.architecture} />
                  <InfoRow label="Domain" value={scan.system_info.domain || 'Not joined'} />
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'stig' && (
          <div className="space-y-4">
            {/* Filters */}
            <div className="flex gap-2">
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="px-3 py-1 bg-gray-700 border border-gray-600 rounded text-sm text-gray-200"
              >
                <option value="">All Categories</option>
                <option value="CatI">CAT I</option>
                <option value="CatII">CAT II</option>
                <option value="CatIII">CAT III</option>
              </select>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="px-3 py-1 bg-gray-700 border border-gray-600 rounded text-sm text-gray-200"
              >
                <option value="">All Status</option>
                <option value="Open">Open</option>
                <option value="NotAFinding">Not a Finding</option>
                <option value="NotApplicable">Not Applicable</option>
              </select>
            </div>

            {/* Results */}
            <div className="space-y-2">
              {filteredResults.length === 0 ? (
                <p className="text-center text-gray-400 py-8">No STIG results</p>
              ) : (
                filteredResults.map((result) => (
                  <StigResultCard key={result.stig_id} result={result} />
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// Info row helper
const InfoRow: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div className="flex justify-between">
    <span className="text-gray-400">{label}</span>
    <span className="text-gray-200">{value}</span>
  </div>
);

// STIG result card
const StigResultCard: React.FC<{ result: StigCheckResult }> = ({ result }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-gray-700 rounded-lg overflow-hidden">
      <div
        className="p-3 flex items-center justify-between cursor-pointer hover:bg-gray-600/50"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3 flex-1 min-w-0">
          {expanded ? (
            <ChevronDown className="w-4 h-4 text-gray-400" />
          ) : (
            <ChevronRight className="w-4 h-4 text-gray-400" />
          )}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-gray-200 font-medium">{result.stig_id}</span>
              <CategoryBadge category={result.category} />
            </div>
            <p className="text-sm text-gray-400 truncate">{result.title}</p>
          </div>
        </div>
        <StatusBadge status={result.status} />
      </div>
      {expanded && (
        <div className="p-4 pt-0 border-t border-gray-600 space-y-3">
          <div>
            <span className="text-xs text-gray-500">Rule ID</span>
            <p className="text-sm text-gray-300">{result.rule_id}</p>
          </div>
          {result.finding_details && (
            <div>
              <span className="text-xs text-gray-500">Finding Details</span>
              <p className="text-sm text-gray-300">{result.finding_details}</p>
            </div>
          )}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-xs text-gray-500">Expected</span>
              <p className="text-sm text-gray-300">{result.expected}</p>
            </div>
            <div>
              <span className="text-xs text-gray-500">Actual</span>
              <p className="text-sm text-gray-300">{result.actual}</p>
            </div>
          </div>
          {result.remediation && (
            <div>
              <span className="text-xs text-gray-500">Remediation</span>
              <p className="text-sm text-gray-300">{result.remediation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Main component
const WindowsAuditPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [showNewScan, setShowNewScan] = useState(false);
  const [selectedScan, setSelectedScan] = useState<WindowsAuditScan | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  const { data: scans = [], isLoading } = useQuery({
    queryKey: ['windows-audit-scans'],
    queryFn: windowsAuditAPI.listScans,
    refetchInterval: 10000,
  });

  const filteredScans = scans.filter((s) =>
    s.target.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <Layout>
    <div className="space-y-6">
      {/* ACAS Navigation */}
      <AcasNavigation />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Monitor className="w-8 h-8 text-cyan-400" />
          <div>
            <h1 className="text-2xl font-bold text-gray-100">Windows Audit Scanner</h1>
            <p className="text-sm text-gray-400">
              Credentialed Windows security assessment with STIG compliance
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowNewScan(true)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded hover:bg-cyan-500"
        >
          <Play className="w-4 h-4" />
          New Scan
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-gray-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-gray-100">{scans.length}</div>
          <div className="text-sm text-gray-400">Total Scans</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-red-400">
            {scans.reduce((sum, s) => sum + s.cat1_findings, 0)}
          </div>
          <div className="text-sm text-gray-400">CAT I Findings</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-amber-400">
            {scans.reduce((sum, s) => sum + s.cat2_findings, 0)}
          </div>
          <div className="text-sm text-gray-400">CAT II Findings</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-green-400">
            {scans.filter((s) => s.status === 'completed').length}
          </div>
          <div className="text-sm text-gray-400">Completed</div>
        </div>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search scans..."
          className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
        />
      </div>

      {/* Scan List */}
      {isLoading ? (
        <div className="text-center py-12 text-gray-400">Loading...</div>
      ) : filteredScans.length === 0 ? (
        <div className="text-center py-12">
          <Monitor className="w-12 h-12 mx-auto mb-4 text-gray-600" />
          <p className="text-gray-400">No scans found</p>
          <p className="text-sm text-gray-500 mt-1">Start a new Windows audit scan</p>
        </div>
      ) : (
        <div className="bg-gray-800 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-900">
              <tr>
                <th className="px-4 py-3 text-left text-sm text-gray-400">Target</th>
                <th className="px-4 py-3 text-left text-sm text-gray-400">Status</th>
                <th className="px-4 py-3 text-left text-sm text-gray-400">CAT I</th>
                <th className="px-4 py-3 text-left text-sm text-gray-400">CAT II</th>
                <th className="px-4 py-3 text-left text-sm text-gray-400">CAT III</th>
                <th className="px-4 py-3 text-left text-sm text-gray-400">Started</th>
                <th className="px-4 py-3 text-right text-sm text-gray-400">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {filteredScans.map((scan) => (
                <tr
                  key={scan.id}
                  className="hover:bg-gray-700/50 cursor-pointer"
                  onClick={() => setSelectedScan(scan)}
                >
                  <td className="px-4 py-3">
                    <div className="text-gray-200">{scan.target}</div>
                    {scan.system_info && (
                      <div className="text-xs text-gray-500">{scan.system_info.os_name}</div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={scan.status} />
                  </td>
                  <td className="px-4 py-3 text-red-400">{scan.cat1_findings}</td>
                  <td className="px-4 py-3 text-amber-400">{scan.cat2_findings}</td>
                  <td className="px-4 py-3 text-yellow-400">{scan.cat3_findings}</td>
                  <td className="px-4 py-3 text-gray-400 text-sm">
                    {new Date(scan.started_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedScan(scan);
                        }}
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

      {/* New Scan Modal */}
      <NewScanModal
        isOpen={showNewScan}
        onClose={() => setShowNewScan(false)}
        onSuccess={() => queryClient.invalidateQueries({ queryKey: ['windows-audit-scans'] })}
      />

      {/* Scan Detail Panel */}
      <ScanDetailPanel scan={selectedScan} onClose={() => setSelectedScan(null)} />
    </div>
    </Layout>
  );
};

export default WindowsAuditPage;
