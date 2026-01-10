import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Zap,
  FileSearch,
  Settings,
  Clock,
  CheckCircle,
  XCircle,
  RefreshCw,
  Trash2,
  ChevronRight,
  AlertTriangle,
  Play,
  StopCircle,
  Download,
  Tag,
  Filter,
  Search,
} from 'lucide-react';
import { toast } from 'react-toastify';
import Button from '../components/ui/Button';
import { Layout } from '../components/layout/Layout';
import api from '../services/api';

// Types
interface NucleiScan {
  id: string;
  name: string | null;
  status: string;
  targets_count: number;
  results_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  created_at: string;
  completed_at: string | null;
}

interface NucleiResult {
  id: string;
  template_id: string;
  template_name: string;
  severity: string;
  host: string;
  matched_at: string;
  check_type: string;
  extracted_results: string[];
  cve_id: string | null;
  curl_command: string | null;
  timestamp: string;
}

interface NucleiStatus {
  installed: boolean;
  version: string | null;
  templates_path: string;
  templates_available: boolean;
}

interface TemplateInfo {
  id: string;
  name: string;
  severity: string;
  tags: string[];
  author: string[];
  description: string | null;
  cve_id: string | null;
}

interface TemplateStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  tags: [string, number][];
  last_updated: string | null;
}

type TabType = 'scans' | 'templates' | 'settings';

const getStatusIcon = (status: string) => {
  switch (status.toLowerCase()) {
    case 'completed':
      return <CheckCircle className="w-4 h-4 text-green-400" />;
    case 'failed':
      return <XCircle className="w-4 h-4 text-red-400" />;
    case 'running':
      return <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />;
    case 'cancelled':
      return <StopCircle className="w-4 h-4 text-orange-400" />;
    default:
      return <Clock className="w-4 h-4 text-yellow-400" />;
  }
};

const getSeverityColor = (severity: string) => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'high':
      return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'medium':
      return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'low':
      return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    case 'info':
      return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    default:
      return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
};

// API functions
const nucleiAPI = {
  getStatus: () => api.get<NucleiStatus>('/nuclei/status'),
  listScans: () => api.get<{ scans: NucleiScan[]; total: number }>('/nuclei/scans'),
  getScan: (id: string) => api.get(`/nuclei/scans/${id}`),
  createScan: (data: any) => api.post<{ id: string; message: string }>('/nuclei/scans', data),
  deleteScan: (id: string) => api.delete(`/nuclei/scans/${id}`),
  cancelScan: (id: string) => api.post(`/nuclei/scans/${id}/cancel`),
  listTemplates: (params?: any) => api.get<{ templates: TemplateInfo[]; total: number }>('/nuclei/templates', { params }),
  getTemplateStats: () => api.get<TemplateStats>('/nuclei/templates/stats'),
  updateTemplates: () => api.post('/nuclei/templates/update'),
  listTags: () => api.get<{ tags: [string, number][] }>('/nuclei/templates/tags'),
};

// Scan Form Component
function NucleiScanForm({ onScanCreated }: { onScanCreated: (id: string) => void }) {
  const [targets, setTargets] = useState('');
  const [name, setName] = useState('');
  const [tags, setTags] = useState<string[]>([]);
  const [severity, setSeverity] = useState<string[]>(['critical', 'high', 'medium']);
  const [rateLimit, setRateLimit] = useState(150);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const queryClient = useQueryClient();

  const createMutation = useMutation({
    mutationFn: nucleiAPI.createScan,
    onSuccess: (response) => {
      toast.success('Nuclei scan started');
      onScanCreated(response.data.id);
      queryClient.invalidateQueries({ queryKey: ['nuclei-scans'] });
      setTargets('');
      setName('');
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error || 'Failed to start scan');
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const targetList = targets.split('\n').map(t => t.trim()).filter(t => t);
    if (targetList.length === 0) {
      toast.error('Please enter at least one target');
      return;
    }

    createMutation.mutate({
      name: name || undefined,
      targets: targetList,
      template_tags: tags,
      severity,
      rate_limit: rateLimit,
    });
  };

  const availableTags = ['cve', 'rce', 'sqli', 'xss', 'lfi', 'ssrf', 'misconfig', 'exposure', 'auth-bypass'];
  const severityOptions = ['critical', 'high', 'medium', 'low', 'info'];

  return (
    <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
      <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <Zap className="w-5 h-5 text-cyan-400" />
        New Nuclei Scan
      </h3>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Scan Name (optional)
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="My Nuclei Scan"
            className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Targets (one per line)
          </label>
          <textarea
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            placeholder="https://example.com&#10;192.168.1.1&#10;example.org"
            rows={4}
            className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono text-sm"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Severity Filter
          </label>
          <div className="flex flex-wrap gap-2">
            {severityOptions.map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => {
                  setSeverity(
                    severity.includes(sev)
                      ? severity.filter((s) => s !== sev)
                      : [...severity, sev]
                  );
                }}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
                  severity.includes(sev)
                    ? getSeverityColor(sev)
                    : 'bg-slate-700 text-slate-400 border-slate-600 hover:border-slate-500'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="text-sm text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
        >
          <Settings className="w-4 h-4" />
          {showAdvanced ? 'Hide' : 'Show'} Advanced Options
        </button>

        {showAdvanced && (
          <>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Template Tags
              </label>
              <div className="flex flex-wrap gap-2">
                {availableTags.map((tag) => (
                  <button
                    key={tag}
                    type="button"
                    onClick={() => {
                      setTags(
                        tags.includes(tag)
                          ? tags.filter((t) => t !== tag)
                          : [...tags, tag]
                      );
                    }}
                    className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                      tags.includes(tag)
                        ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                        : 'bg-slate-700 text-slate-400 border border-slate-600 hover:border-slate-500'
                    }`}
                  >
                    {tag}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Rate Limit (req/s)
              </label>
              <input
                type="number"
                value={rateLimit}
                onChange={(e) => setRateLimit(parseInt(e.target.value) || 150)}
                min={1}
                max={1000}
                className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
            </div>
          </>
        )}

        <Button
          type="submit"
          disabled={createMutation.isPending}
          className="w-full"
        >
          {createMutation.isPending ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin mr-2" />
              Starting Scan...
            </>
          ) : (
            <>
              <Play className="w-4 h-4 mr-2" />
              Start Scan
            </>
          )}
        </Button>
      </form>
    </div>
  );
}

// Scan Results Component
function NucleiScanResults({ scanId, onBack }: { scanId: string; onBack: () => void }) {
  const { data: scan, isLoading, refetch } = useQuery({
    queryKey: ['nuclei-scan', scanId],
    queryFn: () => nucleiAPI.getScan(scanId),
    refetchInterval: (query) => {
      const data = query.state.data?.data;
      return data?.status === 'running' ? 3000 : false;
    },
  });

  const cancelMutation = useMutation({
    mutationFn: () => nucleiAPI.cancelScan(scanId),
    onSuccess: () => {
      toast.success('Scan cancelled');
      refetch();
    },
    onError: () => toast.error('Failed to cancel scan'),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  const scanData = scan?.data;
  if (!scanData) return null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={onBack}
            className="p-2 hover:bg-slate-700 rounded-lg transition-colors"
          >
            <ChevronRight className="w-5 h-5 text-slate-400 rotate-180" />
          </button>
          <div>
            <h2 className="text-xl font-bold text-white">
              {scanData.name || `Nuclei Scan`}
            </h2>
            <div className="flex items-center gap-2 text-sm text-slate-400">
              {getStatusIcon(scanData.status)}
              <span className="capitalize">{scanData.status}</span>
              <span>|</span>
              <span>{scanData.targets?.length || 0} target(s)</span>
              <span>|</span>
              <span>{scanData.results_count} result(s)</span>
            </div>
          </div>
        </div>

        {scanData.status === 'running' && (
          <Button
            variant="danger"
            onClick={() => cancelMutation.mutate()}
            disabled={cancelMutation.isPending}
          >
            <StopCircle className="w-4 h-4 mr-2" />
            Cancel Scan
          </Button>
        )}
      </div>

      {/* Summary */}
      <div className="grid grid-cols-5 gap-4">
        {[
          { label: 'Critical', count: scanData.critical_count, color: 'bg-red-500' },
          { label: 'High', count: scanData.high_count, color: 'bg-orange-500' },
          { label: 'Medium', count: scanData.medium_count, color: 'bg-yellow-500' },
          { label: 'Low', count: scanData.low_count, color: 'bg-blue-500' },
          { label: 'Info', count: scanData.info_count, color: 'bg-slate-500' },
        ].map((item) => (
          <div
            key={item.label}
            className="bg-slate-800 rounded-lg p-4 border border-slate-700"
          >
            <div className={`w-2 h-2 rounded-full ${item.color} mb-2`} />
            <div className="text-2xl font-bold text-white">{item.count}</div>
            <div className="text-sm text-slate-400">{item.label}</div>
          </div>
        ))}
      </div>

      {/* Results List */}
      <div className="bg-slate-800 rounded-lg border border-slate-700">
        <div className="p-4 border-b border-slate-700">
          <h3 className="text-lg font-semibold text-white">Findings</h3>
        </div>
        <div className="divide-y divide-slate-700">
          {scanData.results?.length === 0 ? (
            <div className="p-8 text-center text-slate-400">
              {scanData.status === 'running' ? (
                <div className="flex flex-col items-center gap-2">
                  <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
                  <span>Scanning in progress...</span>
                </div>
              ) : (
                <span>No vulnerabilities found</span>
              )}
            </div>
          ) : (
            scanData.results?.map((result: NucleiResult) => (
              <div key={result.id} className="p-4 hover:bg-slate-700/50 transition-colors">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium border ${getSeverityColor(result.severity)}`}>
                        {result.severity}
                      </span>
                      <span className="text-white font-medium">{result.template_name}</span>
                      {result.cve_id && (
                        <span className="text-xs text-cyan-400 font-mono">{result.cve_id}</span>
                      )}
                    </div>
                    <div className="text-sm text-slate-400 font-mono truncate">
                      {result.matched_at || result.host}
                    </div>
                    <div className="flex items-center gap-2 mt-1 text-xs text-slate-500">
                      <span>{result.template_id}</span>
                      <span>|</span>
                      <span>{result.check_type}</span>
                    </div>
                  </div>
                  {result.curl_command && (
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(result.curl_command!);
                        toast.success('Curl command copied to clipboard');
                      }}
                      className="p-2 hover:bg-slate-600 rounded-lg transition-colors"
                      title="Copy curl command"
                    >
                      <Download className="w-4 h-4 text-slate-400" />
                    </button>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

// Templates Browser Component
function TemplatesBrowser() {
  const [search, setSearch] = useState('');
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [selectedSeverity, setSelectedSeverity] = useState<string[]>([]);
  const queryClient = useQueryClient();

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['nuclei-template-stats'],
    queryFn: () => nucleiAPI.getTemplateStats(),
  });

  const { data: templates, isLoading: templatesLoading } = useQuery({
    queryKey: ['nuclei-templates', search, selectedTags, selectedSeverity],
    queryFn: () =>
      nucleiAPI.listTemplates({
        query: search || undefined,
        tags: selectedTags.length > 0 ? selectedTags.join(',') : undefined,
        severity: selectedSeverity.length > 0 ? selectedSeverity.join(',') : undefined,
        limit: 50,
      }),
  });

  const updateMutation = useMutation({
    mutationFn: nucleiAPI.updateTemplates,
    onSuccess: () => {
      toast.success('Templates updated successfully');
      queryClient.invalidateQueries({ queryKey: ['nuclei-template-stats'] });
      queryClient.invalidateQueries({ queryKey: ['nuclei-templates'] });
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error || 'Failed to update templates');
    },
  });

  const statsData = stats?.data;
  const templateList = templates?.data?.templates || [];

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
        <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
          <div className="text-2xl font-bold text-white">{statsData?.total || 0}</div>
          <div className="text-sm text-slate-400">Total Templates</div>
        </div>
        {['critical', 'high', 'medium', 'low', 'info'].map((sev) => (
          <div key={sev} className="bg-slate-800 rounded-lg p-4 border border-slate-700">
            <div className="text-2xl font-bold text-white">
              {statsData?.[sev as keyof TemplateStats] || 0}
            </div>
            <div className={`text-sm capitalize ${getSeverityColor(sev).split(' ')[1]}`}>
              {sev}
            </div>
          </div>
        ))}
      </div>

      {/* Search and Filters */}
      <div className="flex items-center gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search templates..."
            className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>
        <Button
          onClick={() => updateMutation.mutate()}
          disabled={updateMutation.isPending}
          variant="secondary"
        >
          {updateMutation.isPending ? (
            <RefreshCw className="w-4 h-4 animate-spin mr-2" />
          ) : (
            <Download className="w-4 h-4 mr-2" />
          )}
          Update Templates
        </Button>
      </div>

      {/* Top Tags */}
      {statsData?.tags && statsData.tags.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {statsData.tags.slice(0, 15).map(([tag, count]) => (
            <button
              key={tag}
              onClick={() => {
                setSelectedTags(
                  selectedTags.includes(tag)
                    ? selectedTags.filter((t) => t !== tag)
                    : [...selectedTags, tag]
                );
              }}
              className={`px-2 py-1 rounded text-xs font-medium transition-colors flex items-center gap-1 ${
                selectedTags.includes(tag)
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                  : 'bg-slate-700 text-slate-400 border border-slate-600 hover:border-slate-500'
              }`}
            >
              <Tag className="w-3 h-3" />
              {tag}
              <span className="text-slate-500">({count})</span>
            </button>
          ))}
        </div>
      )}

      {/* Templates List */}
      <div className="bg-slate-800 rounded-lg border border-slate-700">
        <div className="p-4 border-b border-slate-700 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">Templates</h3>
          <span className="text-sm text-slate-400">
            {templates?.data?.total || 0} templates found
          </span>
        </div>
        <div className="divide-y divide-slate-700 max-h-[500px] overflow-y-auto">
          {templatesLoading ? (
            <div className="p-8 text-center">
              <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
            </div>
          ) : templateList.length === 0 ? (
            <div className="p-8 text-center text-slate-400">
              No templates found
            </div>
          ) : (
            templateList.map((template: TemplateInfo) => (
              <div key={template.id} className="p-4 hover:bg-slate-700/50 transition-colors">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium border ${getSeverityColor(template.severity)}`}>
                        {template.severity}
                      </span>
                      <span className="text-white font-medium">{template.name}</span>
                      {template.cve_id && (
                        <span className="text-xs text-cyan-400 font-mono">{template.cve_id}</span>
                      )}
                    </div>
                    <div className="text-sm text-slate-500 font-mono">{template.id}</div>
                    {template.description && (
                      <div className="text-sm text-slate-400 mt-1 line-clamp-2">
                        {template.description}
                      </div>
                    )}
                    <div className="flex flex-wrap gap-1 mt-2">
                      {template.tags.slice(0, 5).map((tag) => (
                        <span
                          key={tag}
                          className="px-1.5 py-0.5 bg-slate-700 text-slate-400 rounded text-xs"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

// Main Page Component
export default function NucleiPage() {
  const [activeTab, setActiveTab] = useState<TabType>('scans');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const queryClient = useQueryClient();

  // Check Nuclei status
  const { data: status, isLoading: statusLoading } = useQuery({
    queryKey: ['nuclei-status'],
    queryFn: () => nucleiAPI.getStatus(),
  });

  // Fetch scans
  const {
    data: scans,
    isLoading: scansLoading,
    refetch,
  } = useQuery({
    queryKey: ['nuclei-scans'],
    queryFn: () => nucleiAPI.listScans(),
  });

  // Delete scan mutation
  const deleteMutation = useMutation({
    mutationFn: nucleiAPI.deleteScan,
    onSuccess: () => {
      toast.success('Scan deleted');
      queryClient.invalidateQueries({ queryKey: ['nuclei-scans'] });
    },
    onError: () => toast.error('Failed to delete scan'),
  });

  const handleScanCreated = (scanId: string) => {
    refetch();
    setSelectedScanId(scanId);
  };

  const nucleiStatus = status?.data;
  const scanList = scans?.data?.scans || [];

  // If viewing a specific scan
  if (selectedScanId) {
    return (
      <Layout>
        <NucleiScanResults
          scanId={selectedScanId}
          onBack={() => setSelectedScanId(null)}
        />
      </Layout>
    );
  }

  return (
    <Layout>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <Zap className="w-7 h-7 text-cyan-400" />
          Nuclei Scanner
        </h1>
        <p className="text-slate-600 dark:text-slate-400 mt-1">
          Fast vulnerability scanner using Nuclei templates
        </p>
      </div>

      {/* Nuclei Status Alert */}
      {nucleiStatus && !nucleiStatus.installed && (
        <div className="mb-6 bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
          <div>
            <div className="font-medium text-yellow-400">Nuclei Not Installed</div>
            <div className="text-sm text-slate-400 mt-1">
              Install Nuclei to use this feature:
              <code className="ml-2 px-2 py-0.5 bg-slate-700 rounded text-xs">
                go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
              </code>
            </div>
          </div>
        </div>
      )}

      {nucleiStatus && nucleiStatus.installed && !nucleiStatus.templates_available && (
        <div className="mb-6 bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
          <div>
            <div className="font-medium text-yellow-400">Templates Not Found</div>
            <div className="text-sm text-slate-400 mt-1">
              Download templates by running:
              <code className="ml-2 px-2 py-0.5 bg-slate-700 rounded text-xs">
                nuclei -ut
              </code>
            </div>
          </div>
        </div>
      )}

      {/* Status Bar */}
      {nucleiStatus?.installed && (
        <div className="mb-6 flex items-center gap-4 text-sm text-slate-400">
          <div className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full bg-green-500" />
            <span>Nuclei {nucleiStatus.version}</span>
          </div>
          <div>Templates: {nucleiStatus.templates_path}</div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center gap-4 mb-6 border-b border-slate-700">
        <button
          onClick={() => setActiveTab('scans')}
          className={`pb-3 px-1 border-b-2 transition-colors ${
            activeTab === 'scans'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4" />
            <span>Scans</span>
          </div>
        </button>
        <button
          onClick={() => setActiveTab('templates')}
          className={`pb-3 px-1 border-b-2 transition-colors ${
            activeTab === 'templates'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          <div className="flex items-center gap-2">
            <FileSearch className="w-4 h-4" />
            <span>Templates</span>
          </div>
        </button>
      </div>

      {/* Tab Content */}
      {activeTab === 'scans' ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Scan Form */}
          <div className="lg:col-span-1">
            <NucleiScanForm onScanCreated={handleScanCreated} />
          </div>

          {/* Scans List */}
          <div className="lg:col-span-2">
            <div className="bg-slate-800 rounded-lg border border-slate-700">
              <div className="p-4 border-b border-slate-700 flex items-center justify-between">
                <h3 className="text-lg font-semibold text-white">Recent Scans</h3>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => refetch()}
                >
                  <RefreshCw className="w-4 h-4" />
                </Button>
              </div>
              <div className="divide-y divide-slate-700">
                {scansLoading ? (
                  <div className="p-8 text-center">
                    <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
                  </div>
                ) : scanList.length === 0 ? (
                  <div className="p-8 text-center text-slate-400">
                    No scans yet. Start your first Nuclei scan!
                  </div>
                ) : (
                  scanList.map((scan: NucleiScan) => (
                    <div
                      key={scan.id}
                      className="p-4 hover:bg-slate-700/50 transition-colors cursor-pointer"
                      onClick={() => setSelectedScanId(scan.id)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            {getStatusIcon(scan.status)}
                            <span className="text-white font-medium">
                              {scan.name || `Nuclei Scan`}
                            </span>
                            <span className="text-sm text-slate-500">
                              ({scan.targets_count} target{scan.targets_count !== 1 ? 's' : ''})
                            </span>
                          </div>
                          <div className="flex items-center gap-2 mt-1 text-xs text-slate-500">
                            <span>{new Date(scan.created_at).toLocaleString()}</span>
                            {scan.results_count > 0 && (
                              <>
                                <span>|</span>
                                <span className="flex items-center gap-1">
                                  {scan.critical_count > 0 && (
                                    <span className="text-red-400">{scan.critical_count}C</span>
                                  )}
                                  {scan.high_count > 0 && (
                                    <span className="text-orange-400">{scan.high_count}H</span>
                                  )}
                                  {scan.medium_count > 0 && (
                                    <span className="text-yellow-400">{scan.medium_count}M</span>
                                  )}
                                  {scan.low_count > 0 && (
                                    <span className="text-blue-400">{scan.low_count}L</span>
                                  )}
                                </span>
                              </>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              if (confirm('Delete this scan?')) {
                                deleteMutation.mutate(scan.id);
                              }
                            }}
                            className="p-2 hover:bg-slate-600 rounded-lg transition-colors"
                          >
                            <Trash2 className="w-4 h-4 text-slate-400 hover:text-red-400" />
                          </button>
                          <ChevronRight className="w-5 h-5 text-slate-400" />
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <TemplatesBrowser />
      )}
    </Layout>
  );
}
