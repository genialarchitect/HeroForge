import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Code,
  Plus,
  Eye,
  Edit,
  Trash2,
  X,
  Copy,
  Tag,
  Play,
  Terminal,
  CheckCircle,
  XCircle,
  Clock,
  Filter,
  Search,
  RefreshCw,
  Gauge,
  History,
  GitBranch,
  FileText,
  AlertTriangle,
  Zap,
  Server,
  ChevronDown,
  ChevronUp,
  Star,
  Target,
  Activity,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import {
  exploitResearchAPI,
  PocEntry,
  PocTestResult,
  SandboxExecutionRequest,
  EffectivenessScore,
  TimelineEvent,
} from '../services/api';

// ============================================================================
// Types
// ============================================================================

type TabType = 'list' | 'create' | 'detail';
type DetailTabType = 'code' | 'tests' | 'sandbox' | 'effectiveness' | 'timeline' | 'versions';

interface PocListFilters {
  search: string;
  status: string;
  language: string;
}

// ============================================================================
// Main Component
// ============================================================================

const PocRepositoryPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('list');
  const [selectedPoc, setSelectedPoc] = useState<PocEntry | null>(null);
  const [detailTab, setDetailTab] = useState<DetailTabType>('code');
  const [filters, setFilters] = useState<PocListFilters>({
    search: '',
    status: 'all',
    language: 'all',
  });
  const [showFilters, setShowFilters] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showSandboxModal, setShowSandboxModal] = useState(false);

  // Queries
  const { data: pocsData, isLoading, refetch } = useQuery({
    queryKey: ['pocs'],
    queryFn: async () => {
      const response = await exploitResearchAPI.listPocs();
      return response.data;
    },
  });

  const { data: sandboxEnvs } = useQuery({
    queryKey: ['sandbox-environments'],
    queryFn: async () => {
      const response = await exploitResearchAPI.listSandboxEnvironments();
      return response.data.environments;
    },
  });

  const pocs = pocsData?.pocs || [];

  // Filter PoCs
  const filteredPocs = pocs.filter(poc => {
    if (filters.search && !poc.title.toLowerCase().includes(filters.search.toLowerCase()) &&
        !poc.cve_id?.toLowerCase().includes(filters.search.toLowerCase())) {
      return false;
    }
    if (filters.status !== 'all' && poc.status !== filters.status) {
      return false;
    }
    if (filters.language !== 'all' && poc.language !== filters.language) {
      return false;
    }
    return true;
  });

  // Get unique languages from PoCs
  const languages = [...new Set(pocs.map(p => p.language))];

  const handleViewPoc = (poc: PocEntry) => {
    setSelectedPoc(poc);
    setDetailTab('code');
    setActiveTab('detail');
  };

  const handleBackToList = () => {
    setSelectedPoc(null);
    setActiveTab('list');
  };

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Code className="h-8 w-8 text-red-500" />
            <div>
              <h1 className="text-2xl font-bold text-white">PoC Repository</h1>
              <p className="text-gray-400">Manage proof-of-concept exploits with sandbox testing</p>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={() => refetch()}
              className="px-3 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600 transition-colors"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
            <button
              onClick={() => setShowCreateModal(true)}
              className="flex items-center space-x-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
            >
              <Plus className="h-4 w-4" />
              <span>New PoC</span>
            </button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <StatCard
            title="Total PoCs"
            value={pocs.length}
            icon={<Code className="h-5 w-5 text-cyan-500" />}
          />
          <StatCard
            title="Verified"
            value={pocs.filter(p => p.status === 'verified').length}
            icon={<CheckCircle className="h-5 w-5 text-green-500" />}
          />
          <StatCard
            title="Testing"
            value={pocs.filter(p => p.status === 'testing').length}
            icon={<Activity className="h-5 w-5 text-yellow-500" />}
          />
          <StatCard
            title="Draft"
            value={pocs.filter(p => p.status === 'draft').length}
            icon={<FileText className="h-5 w-5 text-gray-500" />}
          />
        </div>

        {activeTab === 'list' ? (
          <PocListView
            pocs={filteredPocs}
            isLoading={isLoading}
            filters={filters}
            setFilters={setFilters}
            showFilters={showFilters}
            setShowFilters={setShowFilters}
            languages={languages}
            onViewPoc={handleViewPoc}
            onRefetch={refetch}
          />
        ) : (
          selectedPoc && (
            <PocDetailView
              poc={selectedPoc}
              detailTab={detailTab}
              setDetailTab={setDetailTab}
              onBack={handleBackToList}
              sandboxEnvs={sandboxEnvs || []}
              showSandboxModal={showSandboxModal}
              setShowSandboxModal={setShowSandboxModal}
            />
          )
        )}

        {/* Create PoC Modal */}
        {showCreateModal && (
          <CreatePocModal
            onClose={() => setShowCreateModal(false)}
            onSuccess={() => {
              setShowCreateModal(false);
              refetch();
            }}
          />
        )}
      </div>
    </Layout>
  );
};

// ============================================================================
// Stat Card Component
// ============================================================================

const StatCard: React.FC<{
  title: string;
  value: number;
  icon: React.ReactNode;
}> = ({ title, value, icon }) => (
  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-gray-400 text-sm">{title}</p>
        <p className="text-2xl font-bold text-white mt-1">{value}</p>
      </div>
      <div className="p-3 bg-gray-700/50 rounded-lg">{icon}</div>
    </div>
  </div>
);

// ============================================================================
// PoC List View
// ============================================================================

const PocListView: React.FC<{
  pocs: PocEntry[];
  isLoading: boolean;
  filters: PocListFilters;
  setFilters: React.Dispatch<React.SetStateAction<PocListFilters>>;
  showFilters: boolean;
  setShowFilters: React.Dispatch<React.SetStateAction<boolean>>;
  languages: string[];
  onViewPoc: (poc: PocEntry) => void;
  onRefetch: () => void;
}> = ({ pocs, isLoading, filters, setFilters, showFilters, setShowFilters, languages, onViewPoc }) => {
  const queryClient = useQueryClient();

  const deleteMutation = useMutation({
    mutationFn: (id: string) => exploitResearchAPI.deletePoc(id),
    onSuccess: () => {
      toast.success('PoC deleted successfully');
      queryClient.invalidateQueries({ queryKey: ['pocs'] });
    },
    onError: () => toast.error('Failed to delete PoC'),
  });

  return (
    <div className="space-y-4">
      {/* Search and Filters */}
      <div className="flex items-center space-x-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search PoCs by title or CVE..."
            value={filters.search}
            onChange={(e) => setFilters(f => ({ ...f, search: e.target.value }))}
            className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:ring-2 focus:ring-red-500 focus:border-transparent"
          />
        </div>
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${
            showFilters ? 'bg-red-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
          }`}
        >
          <Filter className="h-4 w-4" />
          <span>Filters</span>
          {showFilters ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </button>
      </div>

      {/* Filter Panel */}
      {showFilters && (
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Status</label>
            <select
              value={filters.status}
              onChange={(e) => setFilters(f => ({ ...f, status: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
            >
              <option value="all">All Statuses</option>
              <option value="draft">Draft</option>
              <option value="testing">Testing</option>
              <option value="verified">Verified</option>
              <option value="broken">Broken</option>
            </select>
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Language</label>
            <select
              value={filters.language}
              onChange={(e) => setFilters(f => ({ ...f, language: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
            >
              <option value="all">All Languages</option>
              {languages.map(lang => (
                <option key={lang} value={lang}>{lang}</option>
              ))}
            </select>
          </div>
        </div>
      )}

      {/* PoC List */}
      <div className="bg-gray-800 rounded-lg border border-gray-700">
        {isLoading ? (
          <div className="p-8 text-center text-gray-400">
            <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-2" />
            Loading PoCs...
          </div>
        ) : pocs.length === 0 ? (
          <div className="p-8 text-center text-gray-400">
            <Code className="h-12 w-12 mx-auto mb-2 opacity-50" />
            <p>No PoCs found</p>
            <p className="text-sm mt-1">Create a new PoC to get started</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-700">
            {pocs.map(poc => (
              <div key={poc.id} className="p-4 hover:bg-gray-700/50 transition-colors">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3">
                      <h3 className="text-lg font-medium text-white">{poc.title}</h3>
                      <StatusBadge status={poc.status} />
                      <span className="px-2 py-0.5 bg-gray-700 text-gray-300 text-xs rounded">
                        {poc.language}
                      </span>
                    </div>
                    {poc.description && (
                      <p className="text-gray-400 text-sm mt-1 line-clamp-2">{poc.description}</p>
                    )}
                    <div className="flex items-center space-x-4 mt-2 text-sm text-gray-500">
                      {poc.cve_id && (
                        <span className="flex items-center space-x-1">
                          <Target className="h-3 w-3" />
                          <span>{poc.cve_id}</span>
                        </span>
                      )}
                      <span className="flex items-center space-x-1">
                        <History className="h-3 w-3" />
                        <span>{poc.versions.length} version(s)</span>
                      </span>
                      <span className="flex items-center space-x-1">
                        <Activity className="h-3 w-3" />
                        <span>{poc.test_results.length} test(s)</span>
                      </span>
                      {poc.tags.length > 0 && (
                        <div className="flex items-center space-x-1">
                          <Tag className="h-3 w-3" />
                          <span>{poc.tags.slice(0, 3).join(', ')}</span>
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => onViewPoc(poc)}
                      className="p-2 text-gray-400 hover:text-white hover:bg-gray-600 rounded-lg transition-colors"
                      title="View Details"
                    >
                      <Eye className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => {
                        if (confirm('Are you sure you want to delete this PoC?')) {
                          deleteMutation.mutate(poc.id);
                        }
                      }}
                      className="p-2 text-gray-400 hover:text-red-500 hover:bg-gray-600 rounded-lg transition-colors"
                      title="Delete"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

// ============================================================================
// Status Badge Component
// ============================================================================

const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const config: Record<string, { color: string; icon: React.ReactNode }> = {
    draft: { color: 'bg-gray-600 text-gray-300', icon: <FileText className="h-3 w-3" /> },
    testing: { color: 'bg-yellow-600/20 text-yellow-400', icon: <Activity className="h-3 w-3" /> },
    verified: { color: 'bg-green-600/20 text-green-400', icon: <CheckCircle className="h-3 w-3" /> },
    broken: { color: 'bg-red-600/20 text-red-400', icon: <XCircle className="h-3 w-3" /> },
  };

  const { color, icon } = config[status] || config.draft;

  return (
    <span className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded text-xs ${color}`}>
      {icon}
      <span className="capitalize">{status}</span>
    </span>
  );
};

// ============================================================================
// PoC Detail View
// ============================================================================

const PocDetailView: React.FC<{
  poc: PocEntry;
  detailTab: DetailTabType;
  setDetailTab: React.Dispatch<React.SetStateAction<DetailTabType>>;
  onBack: () => void;
  sandboxEnvs: { id: string; name: string; os: string; is_ready: boolean }[];
  showSandboxModal: boolean;
  setShowSandboxModal: React.Dispatch<React.SetStateAction<boolean>>;
}> = ({ poc, detailTab, setDetailTab, onBack, sandboxEnvs, showSandboxModal, setShowSandboxModal }) => {
  const queryClient = useQueryClient();

  // Get PoC code
  const { data: codeData } = useQuery({
    queryKey: ['poc-code', poc.id],
    queryFn: async () => {
      const response = await exploitResearchAPI.getPocCode(poc.id);
      return response.data;
    },
  });

  // Get effectiveness score
  const { data: effectivenessData } = useQuery({
    queryKey: ['poc-effectiveness', poc.id],
    queryFn: async () => {
      const response = await exploitResearchAPI.getPocEffectiveness(poc.id);
      return response.data;
    },
  });

  // Get timeline
  const { data: timelineData } = useQuery({
    queryKey: ['poc-timeline', poc.id],
    queryFn: async () => {
      const response = await exploitResearchAPI.getPocTimeline(poc.id);
      return response.data;
    },
  });

  // Get sandbox history
  const { data: sandboxHistory } = useQuery({
    queryKey: ['poc-sandbox-history', poc.id],
    queryFn: async () => {
      const response = await exploitResearchAPI.getSandboxHistory(poc.id);
      return response.data;
    },
  });

  const tabs: { id: DetailTabType; label: string; icon: React.ReactNode }[] = [
    { id: 'code', label: 'Code', icon: <Code className="h-4 w-4" /> },
    { id: 'tests', label: 'Test Results', icon: <CheckCircle className="h-4 w-4" /> },
    { id: 'sandbox', label: 'Sandbox', icon: <Terminal className="h-4 w-4" /> },
    { id: 'effectiveness', label: 'Effectiveness', icon: <Gauge className="h-4 w-4" /> },
    { id: 'timeline', label: 'Timeline', icon: <History className="h-4 w-4" /> },
    { id: 'versions', label: 'Versions', icon: <GitBranch className="h-4 w-4" /> },
  ];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <button
            onClick={onBack}
            className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
          <div>
            <div className="flex items-center space-x-3">
              <h2 className="text-xl font-bold text-white">{poc.title}</h2>
              <StatusBadge status={poc.status} />
            </div>
            {poc.cve_id && (
              <span className="text-cyan-400 text-sm">{poc.cve_id}</span>
            )}
          </div>
        </div>
        <button
          onClick={() => setShowSandboxModal(true)}
          className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
        >
          <Play className="h-4 w-4" />
          <span>Run in Sandbox</span>
        </button>
      </div>

      {/* Tabs */}
      <div className="flex items-center space-x-1 bg-gray-800 rounded-lg p-1 border border-gray-700">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setDetailTab(tab.id)}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${
              detailTab === tab.id
                ? 'bg-red-600 text-white'
                : 'text-gray-400 hover:text-white hover:bg-gray-700'
            }`}
          >
            {tab.icon}
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        {detailTab === 'code' && (
          <CodeView code={codeData?.code || ''} language={poc.language} />
        )}
        {detailTab === 'tests' && (
          <TestResultsView testResults={poc.test_results} />
        )}
        {detailTab === 'sandbox' && (
          <SandboxView
            pocId={poc.id}
            history={sandboxHistory?.executions || []}
            environments={sandboxEnvs}
          />
        )}
        {detailTab === 'effectiveness' && (
          <EffectivenessView
            pocId={poc.id}
            score={effectivenessData?.score}
          />
        )}
        {detailTab === 'timeline' && (
          <TimelineView events={timelineData?.events || []} />
        )}
        {detailTab === 'versions' && (
          <VersionsView versions={poc.versions} />
        )}
      </div>

      {/* Sandbox Modal */}
      {showSandboxModal && (
        <SandboxExecutionModal
          pocId={poc.id}
          pocTitle={poc.title}
          environments={sandboxEnvs}
          onClose={() => setShowSandboxModal(false)}
          onSuccess={() => {
            setShowSandboxModal(false);
            queryClient.invalidateQueries({ queryKey: ['poc-sandbox-history', poc.id] });
          }}
        />
      )}
    </div>
  );
};

// ============================================================================
// Code View
// ============================================================================

const CodeView: React.FC<{ code: string; language: string }> = ({ code, language }) => {
  const copyToClipboard = () => {
    navigator.clipboard.writeText(code);
    toast.success('Code copied to clipboard');
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <span className="text-gray-400 text-sm">Language: {language}</span>
        <button
          onClick={copyToClipboard}
          className="flex items-center space-x-2 px-3 py-1 bg-gray-700 text-gray-300 rounded hover:bg-gray-600 transition-colors"
        >
          <Copy className="h-4 w-4" />
          <span>Copy</span>
        </button>
      </div>
      <pre className="bg-gray-900 rounded-lg p-4 overflow-x-auto">
        <code className="text-sm text-gray-300 font-mono whitespace-pre">{code || 'No code available'}</code>
      </pre>
    </div>
  );
};

// ============================================================================
// Test Results View
// ============================================================================

const TestResultsView: React.FC<{ testResults: PocTestResult[] }> = ({ testResults }) => {
  if (testResults.length === 0) {
    return (
      <div className="text-center py-8 text-gray-400">
        <Activity className="h-12 w-12 mx-auto mb-2 opacity-50" />
        <p>No test results yet</p>
        <p className="text-sm mt-1">Run the PoC in a sandbox to generate test results</p>
      </div>
    );
  }

  const successCount = testResults.filter(r => r.success).length;
  const successRate = (successCount / testResults.length * 100).toFixed(1);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="text-sm text-gray-400">
          {testResults.length} test(s) - {successRate}% success rate
        </div>
      </div>
      <div className="space-y-3">
        {testResults.map((result, idx) => (
          <div key={idx} className={`p-4 rounded-lg border ${
            result.success ? 'bg-green-900/20 border-green-700' : 'bg-red-900/20 border-red-700'
          }`}>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center space-x-2">
                {result.success ? (
                  <CheckCircle className="h-5 w-5 text-green-400" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-400" />
                )}
                <span className="font-medium text-white">
                  {result.success ? 'Success' : 'Failed'}
                </span>
              </div>
              <span className="text-sm text-gray-400">
                {new Date(result.tested_at).toLocaleString()}
              </span>
            </div>
            <div className="text-sm text-gray-400">
              <p><strong>Target:</strong> {result.target_info}</p>
              <p><strong>Execution Time:</strong> {result.execution_time_ms}ms</p>
              {result.output && (
                <p><strong>Output:</strong> {result.output}</p>
              )}
              {result.error && (
                <p className="text-red-400"><strong>Error:</strong> {result.error}</p>
              )}
              {result.notes && (
                <p><strong>Notes:</strong> {result.notes}</p>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// ============================================================================
// Sandbox View
// ============================================================================

const SandboxView: React.FC<{
  pocId: string;
  history: any[];
  environments: { id: string; name: string; os: string; is_ready: boolean }[];
}> = ({ pocId, history, environments }) => {
  return (
    <div className="space-y-6">
      {/* Available Environments */}
      <div>
        <h3 className="text-lg font-medium text-white mb-3">Available Environments</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {environments.map(env => (
            <div
              key={env.id}
              className={`p-3 rounded-lg border ${
                env.is_ready
                  ? 'bg-green-900/20 border-green-700'
                  : 'bg-gray-700 border-gray-600'
              }`}
            >
              <div className="flex items-center space-x-2">
                <Server className="h-4 w-4 text-gray-400" />
                <span className="text-white text-sm">{env.name}</span>
              </div>
              <div className="text-xs text-gray-400 mt-1">{env.os}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Execution History */}
      <div>
        <h3 className="text-lg font-medium text-white mb-3">Execution History</h3>
        {history.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            <Terminal className="h-12 w-12 mx-auto mb-2 opacity-50" />
            <p>No sandbox executions yet</p>
          </div>
        ) : (
          <div className="space-y-3">
            {history.map((exec: any, idx: number) => (
              <div key={idx} className="p-4 bg-gray-700 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    {exec.success_detected ? (
                      <CheckCircle className="h-5 w-5 text-green-400" />
                    ) : (
                      <XCircle className="h-5 w-5 text-red-400" />
                    )}
                    <span className="text-white">{exec.sandbox_type} - {exec.target_os}</span>
                  </div>
                  <span className="text-sm text-gray-400">
                    {new Date(exec.executed_at).toLocaleString()}
                  </span>
                </div>
                <div className="text-sm text-gray-400">
                  <p>Status: {exec.status}</p>
                  <p>Execution Time: {exec.execution_time_ms}ms</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

// ============================================================================
// Effectiveness View
// ============================================================================

const EffectivenessView: React.FC<{
  pocId: string;
  score?: EffectivenessScore;
}> = ({ pocId, score }) => {
  const queryClient = useQueryClient();

  const calculateMutation = useMutation({
    mutationFn: () => exploitResearchAPI.calculatePocEffectiveness(pocId, {}),
    onSuccess: () => {
      toast.success('Effectiveness score calculated');
      queryClient.invalidateQueries({ queryKey: ['poc-effectiveness', pocId] });
    },
    onError: () => toast.error('Failed to calculate effectiveness'),
  });

  if (!score) {
    return (
      <div className="text-center py-8">
        <Gauge className="h-12 w-12 mx-auto mb-2 text-gray-500" />
        <p className="text-gray-400">No effectiveness score available</p>
        <button
          onClick={() => calculateMutation.mutate()}
          disabled={calculateMutation.isPending}
          className="mt-4 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50"
        >
          {calculateMutation.isPending ? 'Calculating...' : 'Calculate Score'}
        </button>
      </div>
    );
  }

  const ratingColor = {
    Excellent: 'text-green-400',
    Good: 'text-cyan-400',
    Average: 'text-yellow-400',
    Low: 'text-orange-400',
    Unknown: 'text-gray-400',
  }[score.rating] || 'text-gray-400';

  return (
    <div className="space-y-6">
      {/* Overall Score */}
      <div className="text-center">
        <div className="text-5xl font-bold text-white">{score.total_score}</div>
        <div className={`text-xl ${ratingColor}`}>{score.rating}</div>
      </div>

      {/* Score Breakdown */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <ScoreCard title="Reliability" value={score.reliability_score} max={100} />
        <ScoreCard title="Impact" value={score.impact_score} max={30} />
        <ScoreCard title="Maturity" value={score.maturity_score} max={100} />
        <ScoreCard title="Community" value={score.community_score} max={100} />
      </div>

      {/* Recommendations */}
      {score.recommendations.length > 0 && (
        <div>
          <h4 className="text-lg font-medium text-white mb-3">Recommendations</h4>
          <ul className="space-y-2">
            {score.recommendations.map((rec, idx) => (
              <li key={idx} className="flex items-start space-x-2 text-gray-300">
                <AlertTriangle className="h-4 w-4 text-yellow-400 mt-1 flex-shrink-0" />
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Recalculate */}
      <div className="text-center">
        <button
          onClick={() => calculateMutation.mutate()}
          disabled={calculateMutation.isPending}
          className="px-4 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600 transition-colors disabled:opacity-50"
        >
          {calculateMutation.isPending ? 'Recalculating...' : 'Recalculate Score'}
        </button>
      </div>
    </div>
  );
};

const ScoreCard: React.FC<{ title: string; value: number; max: number }> = ({ title, value, max }) => {
  const percentage = (value / max * 100).toFixed(0);
  return (
    <div className="bg-gray-700 rounded-lg p-4">
      <div className="text-sm text-gray-400 mb-1">{title}</div>
      <div className="text-2xl font-bold text-white">{value}<span className="text-sm text-gray-500">/{max}</span></div>
      <div className="w-full bg-gray-600 rounded-full h-1.5 mt-2">
        <div className="bg-cyan-500 rounded-full h-1.5" style={{ width: `${percentage}%` }} />
      </div>
    </div>
  );
};

// ============================================================================
// Timeline View
// ============================================================================

const TimelineView: React.FC<{ events: TimelineEvent[] }> = ({ events }) => {
  if (events.length === 0) {
    return (
      <div className="text-center py-8 text-gray-400">
        <History className="h-12 w-12 mx-auto mb-2 opacity-50" />
        <p>No timeline events yet</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {events.map((event, idx) => (
        <div key={event.id} className="flex items-start space-x-4">
          <div className="flex-shrink-0 w-2 h-2 mt-2 rounded-full bg-cyan-500" />
          <div className="flex-1">
            <div className="flex items-center justify-between">
              <span className="font-medium text-white">{event.title}</span>
              <span className="text-sm text-gray-400">
                {new Date(event.created_at).toLocaleString()}
              </span>
            </div>
            {event.description && (
              <p className="text-sm text-gray-400 mt-1">{event.description}</p>
            )}
            <span className="inline-block px-2 py-0.5 bg-gray-700 text-gray-300 text-xs rounded mt-1">
              {event.event_type}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
};

// ============================================================================
// Versions View
// ============================================================================

const VersionsView: React.FC<{ versions: { version: string; changelog?: string; created_at: string }[] }> = ({ versions }) => {
  if (versions.length === 0) {
    return (
      <div className="text-center py-8 text-gray-400">
        <GitBranch className="h-12 w-12 mx-auto mb-2 opacity-50" />
        <p>No version history</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {versions.map((version, idx) => (
        <div key={idx} className={`p-4 rounded-lg border ${
          idx === 0 ? 'bg-cyan-900/20 border-cyan-700' : 'bg-gray-700 border-gray-600'
        }`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <GitBranch className="h-4 w-4 text-gray-400" />
              <span className="font-medium text-white">v{version.version}</span>
              {idx === 0 && (
                <span className="px-2 py-0.5 bg-cyan-600 text-white text-xs rounded">Latest</span>
              )}
            </div>
            <span className="text-sm text-gray-400">
              {new Date(version.created_at).toLocaleDateString()}
            </span>
          </div>
          {version.changelog && (
            <p className="text-sm text-gray-400 mt-2">{version.changelog}</p>
          )}
        </div>
      ))}
    </div>
  );
};

// ============================================================================
// Create PoC Modal
// ============================================================================

const CreatePocModal: React.FC<{
  onClose: () => void;
  onSuccess: () => void;
}> = ({ onClose, onSuccess }) => {
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    code: '',
    language: 'python',
    cve_id: '',
    tags: '',
    target_info: '',
  });

  const createMutation = useMutation({
    mutationFn: () => exploitResearchAPI.createPoc({
      title: formData.title,
      description: formData.description || undefined,
      code: formData.code,
      language: formData.language,
      cve_id: formData.cve_id || undefined,
      tags: formData.tags ? formData.tags.split(',').map(t => t.trim()) : undefined,
      target_info: formData.target_info || undefined,
    }),
    onSuccess: () => {
      toast.success('PoC created successfully');
      onSuccess();
    },
    onError: () => toast.error('Failed to create PoC'),
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-bold text-white">Create New PoC</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Title *</label>
            <input
              type="text"
              value={formData.title}
              onChange={(e) => setFormData(f => ({ ...f, title: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              placeholder="CVE-2024-1234 RCE Exploit"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Language *</label>
              <select
                value={formData.language}
                onChange={(e) => setFormData(f => ({ ...f, language: e.target.value }))}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              >
                <option value="python">Python</option>
                <option value="ruby">Ruby</option>
                <option value="bash">Bash</option>
                <option value="powershell">PowerShell</option>
                <option value="javascript">JavaScript</option>
                <option value="go">Go</option>
                <option value="rust">Rust</option>
                <option value="c">C</option>
                <option value="cpp">C++</option>
              </select>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">CVE ID</label>
              <input
                type="text"
                value={formData.cve_id}
                onChange={(e) => setFormData(f => ({ ...f, cve_id: e.target.value }))}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                placeholder="CVE-2024-1234"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Description</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData(f => ({ ...f, description: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white h-20"
              placeholder="Description of the vulnerability and exploit..."
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Code *</label>
            <textarea
              value={formData.code}
              onChange={(e) => setFormData(f => ({ ...f, code: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-green-400 font-mono h-48"
              placeholder="#!/usr/bin/env python3&#10;# PoC code here..."
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Tags (comma-separated)</label>
            <input
              type="text"
              value={formData.tags}
              onChange={(e) => setFormData(f => ({ ...f, tags: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              placeholder="rce, web, apache"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Target Info</label>
            <input
              type="text"
              value={formData.target_info}
              onChange={(e) => setFormData(f => ({ ...f, target_info: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              placeholder="Apache HTTP Server 2.4.49-2.4.50"
            />
          </div>
        </div>

        <div className="flex justify-end space-x-3 mt-6">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600"
          >
            Cancel
          </button>
          <button
            onClick={() => createMutation.mutate()}
            disabled={!formData.title || !formData.code || createMutation.isPending}
            className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50"
          >
            {createMutation.isPending ? 'Creating...' : 'Create PoC'}
          </button>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// Sandbox Execution Modal
// ============================================================================

const SandboxExecutionModal: React.FC<{
  pocId: string;
  pocTitle: string;
  environments: { id: string; name: string; os: string; is_ready: boolean }[];
  onClose: () => void;
  onSuccess: () => void;
}> = ({ pocId, pocTitle, environments, onClose, onSuccess }) => {
  const [request, setRequest] = useState<SandboxExecutionRequest>({
    sandbox_type: 'docker',
    target_os: 'ubuntu22',
    isolated_network: true,
    timeout_seconds: 300,
  });

  const executeMutation = useMutation({
    mutationFn: () => exploitResearchAPI.executePocInSandbox(pocId, request),
    onSuccess: (response) => {
      if (response.data.success) {
        toast.success('Sandbox execution completed');
      } else {
        toast.warning(`Execution finished with status: ${response.data.status}`);
      }
      onSuccess();
    },
    onError: () => toast.error('Failed to execute in sandbox'),
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-bold text-white">Run in Sandbox</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>

        <p className="text-gray-400 mb-4">
          Execute <span className="text-white">{pocTitle}</span> in an isolated sandbox environment.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Sandbox Type</label>
            <select
              value={request.sandbox_type}
              onChange={(e) => setRequest(r => ({ ...r, sandbox_type: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
            >
              <option value="docker">Docker</option>
              <option value="localvm">Local VM</option>
            </select>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Target OS</label>
            <select
              value={request.target_os}
              onChange={(e) => setRequest(r => ({ ...r, target_os: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
            >
              <option value="ubuntu22">Ubuntu 22.04</option>
              <option value="ubuntu20">Ubuntu 20.04</option>
              <option value="debian12">Debian 12</option>
              <option value="kali">Kali Linux</option>
              <option value="alpine">Alpine Linux</option>
            </select>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Timeout (seconds)</label>
            <input
              type="number"
              value={request.timeout_seconds}
              onChange={(e) => setRequest(r => ({ ...r, timeout_seconds: parseInt(e.target.value) || 300 }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              min={30}
              max={3600}
            />
          </div>

          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              id="isolated"
              checked={request.isolated_network}
              onChange={(e) => setRequest(r => ({ ...r, isolated_network: e.target.checked }))}
              className="rounded bg-gray-700 border-gray-600"
            />
            <label htmlFor="isolated" className="text-sm text-gray-300">Isolated network (no internet)</label>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Target Host (optional)</label>
            <input
              type="text"
              value={request.target_host || ''}
              onChange={(e) => setRequest(r => ({ ...r, target_host: e.target.value || undefined }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              placeholder="192.168.1.100"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Target Port (optional)</label>
            <input
              type="number"
              value={request.target_port || ''}
              onChange={(e) => setRequest(r => ({ ...r, target_port: e.target.value ? parseInt(e.target.value) : undefined }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              placeholder="8080"
            />
          </div>
        </div>

        <div className="flex justify-end space-x-3 mt-6">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600"
          >
            Cancel
          </button>
          <button
            onClick={() => executeMutation.mutate()}
            disabled={executeMutation.isPending}
            className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50"
          >
            <Play className="h-4 w-4" />
            <span>{executeMutation.isPending ? 'Executing...' : 'Execute'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default PocRepositoryPage;
