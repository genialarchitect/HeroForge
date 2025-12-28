import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  FileCode,
  Plus,
  RefreshCw,
  Trash2,
  Edit,
  Play,
  Copy,
  ChevronDown,
  ChevronRight,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Shield,
  Target,
  Link,
  Settings,
  Lightbulb,
  X,
  Code,
  TestTube,
  GitBranch,
  Zap,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { Layout } from '../components/layout/Layout';
import { Button } from '../components/ui/Button';
import { siemFullAPI } from '../services/api';
import type {
  SigmaRuleResponse,
  CreateSigmaRuleRequest,
  SigmaConversionResponse,
  SigmaRuleTestResult,
  AttackCoverageResponse,
  RuleTuningRecommendation,
  SigmaRuleChain,
  CreateRuleChainRequest,
} from '../services/api';

type TabType = 'rules' | 'convert' | 'testing' | 'coverage' | 'tuning' | 'chains';

const severityColors: Record<string, { bg: string; text: string }> = {
  low: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  high: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  critical: { bg: 'bg-red-500/20', text: 'text-red-400' },
};

const backendOptions = [
  { value: 'splunk', label: 'Splunk SPL' },
  { value: 'elastic_lucene', label: 'Elasticsearch Lucene' },
  { value: 'elastic_eql', label: 'Elasticsearch EQL' },
  { value: 'microsoft_sentinel', label: 'Microsoft Sentinel KQL' },
  { value: 'qradar_aql', label: 'QRadar AQL' },
  { value: 'logpoint', label: 'LogPoint' },
  { value: 'crowdstrike', label: 'CrowdStrike' },
];

// Modal component
const Modal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  size?: 'md' | 'lg' | 'xl';
}> = ({ isOpen, onClose, title, children, size = 'lg' }) => {
  if (!isOpen) return null;

  const sizeClass = size === 'xl' ? 'max-w-4xl' : size === 'lg' ? 'max-w-2xl' : 'max-w-md';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className={`relative bg-gray-800 border border-gray-700 rounded-lg shadow-xl w-full ${sizeClass} max-h-[90vh] overflow-y-auto`}>
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
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

export default function SigmaRulesPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('rules');
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [showConvertModal, setShowConvertModal] = useState(false);
  const [showTestModal, setShowTestModal] = useState(false);
  const [showChainModal, setShowChainModal] = useState(false);
  const [selectedRule, setSelectedRule] = useState<SigmaRuleResponse | null>(null);
  const [expandedRules, setExpandedRules] = useState<Set<string>>(new Set());

  // Conversion state
  const [convertContent, setConvertContent] = useState('');
  const [selectedBackend, setSelectedBackend] = useState('splunk');
  const [conversionResult, setConversionResult] = useState<SigmaConversionResponse | null>(null);
  const [allConversions, setAllConversions] = useState<SigmaConversionResponse[]>([]);

  // Test state
  const [testName, setTestName] = useState('');
  const [testLogs, setTestLogs] = useState('');
  const [expectedMatches, setExpectedMatches] = useState<number | undefined>();

  // Chain state
  const [chainName, setChainName] = useState('');
  const [chainDescription, setChainDescription] = useState('');
  const [chainRuleIds, setChainRuleIds] = useState<string[]>([]);
  const [chainLogic, setChainLogic] = useState('sequence');
  const [chainTimeWindow, setChainTimeWindow] = useState(300);

  // Queries
  const { data: sigmaRules = [], isLoading: rulesLoading, refetch: refetchRules } = useQuery({
    queryKey: ['sigma-rules'],
    queryFn: () => siemFullAPI.listSigmaRules().then(res => res.data),
  });

  const { data: coverage, isLoading: coverageLoading } = useQuery({
    queryKey: ['sigma-coverage'],
    queryFn: () => siemFullAPI.getAttackCoverage().then(res => res.data),
    enabled: activeTab === 'coverage',
  });

  const { data: recommendations = [], isLoading: recommendationsLoading } = useQuery({
    queryKey: ['sigma-tuning'],
    queryFn: () => siemFullAPI.getTuningRecommendations().then(res => res.data),
    enabled: activeTab === 'tuning',
  });

  const { data: ruleChains = [], isLoading: chainsLoading, refetch: refetchChains } = useQuery({
    queryKey: ['sigma-chains'],
    queryFn: () => siemFullAPI.listRuleChains().then(res => res.data),
    enabled: activeTab === 'chains',
  });

  const { data: testResults = [] } = useQuery({
    queryKey: ['sigma-test-results', selectedRule?.id],
    queryFn: () => selectedRule ? siemFullAPI.getSigmaRuleTestResults(selectedRule.id).then(res => res.data) : Promise.resolve([]),
    enabled: !!selectedRule && activeTab === 'testing',
  });

  // Mutations
  const createRuleMutation = useMutation({
    mutationFn: (data: CreateSigmaRuleRequest) => siemFullAPI.createSigmaRule(data),
    onSuccess: () => {
      toast.success('Sigma rule created');
      queryClient.invalidateQueries({ queryKey: ['sigma-rules'] });
      setShowRuleModal(false);
    },
    onError: () => toast.error('Failed to create rule'),
  });

  const deleteRuleMutation = useMutation({
    mutationFn: (id: string) => siemFullAPI.deleteSigmaRule(id),
    onSuccess: () => {
      toast.success('Sigma rule deleted');
      queryClient.invalidateQueries({ queryKey: ['sigma-rules'] });
    },
    onError: () => toast.error('Failed to delete rule'),
  });

  const convertMutation = useMutation({
    mutationFn: (data: { rule_content: string; backend: string }) =>
      siemFullAPI.convertSigmaRule({
        rule_content: data.rule_content,
        backend: data.backend as 'splunk' | 'elastic_lucene' | 'elastic_eql' | 'microsoft_sentinel' | 'qradar_aql' | 'logpoint' | 'crowdstrike',
      }),
    onSuccess: (res) => {
      setConversionResult(res.data);
      toast.success('Rule converted successfully');
    },
    onError: () => toast.error('Failed to convert rule'),
  });

  const convertAllMutation = useMutation({
    mutationFn: (rule_content: string) => siemFullAPI.convertSigmaRuleAll({ rule_content }),
    onSuccess: (res) => {
      setAllConversions(res.data.conversions);
      toast.success('Rule converted to all backends');
    },
    onError: () => toast.error('Failed to convert rule'),
  });

  const testRuleMutation = useMutation({
    mutationFn: (data: { id: string; test_name: string; sample_logs: string[]; expected_matches?: number }) =>
      siemFullAPI.testSigmaRuleWithStorage(data.id, {
        test_name: data.test_name,
        sample_logs: data.sample_logs,
        expected_matches: data.expected_matches,
      }),
    onSuccess: () => {
      toast.success('Test completed');
      queryClient.invalidateQueries({ queryKey: ['sigma-test-results'] });
      setShowTestModal(false);
    },
    onError: () => toast.error('Failed to run test'),
  });

  const createChainMutation = useMutation({
    mutationFn: (data: CreateRuleChainRequest) => siemFullAPI.createRuleChain(data),
    onSuccess: () => {
      toast.success('Rule chain created');
      queryClient.invalidateQueries({ queryKey: ['sigma-chains'] });
      setShowChainModal(false);
      resetChainForm();
    },
    onError: () => toast.error('Failed to create chain'),
  });

  const deleteChainMutation = useMutation({
    mutationFn: (id: string) => siemFullAPI.deleteRuleChain(id),
    onSuccess: () => {
      toast.success('Rule chain deleted');
      queryClient.invalidateQueries({ queryKey: ['sigma-chains'] });
    },
    onError: () => toast.error('Failed to delete chain'),
  });

  const resetChainForm = () => {
    setChainName('');
    setChainDescription('');
    setChainRuleIds([]);
    setChainLogic('sequence');
    setChainTimeWindow(300);
  };

  const toggleRuleExpand = (id: string) => {
    const newExpanded = new Set(expandedRules);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedRules(newExpanded);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const tabs = [
    { id: 'rules', label: 'Rules', icon: FileCode },
    { id: 'convert', label: 'Convert', icon: Code },
    { id: 'testing', label: 'Testing', icon: TestTube },
    { id: 'coverage', label: 'ATT&CK Coverage', icon: Target },
    { id: 'tuning', label: 'Tuning', icon: Lightbulb },
    { id: 'chains', label: 'Rule Chains', icon: GitBranch },
  ];

  return (
    <Layout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/20 rounded-lg">
              <FileCode className="w-6 h-6 text-purple-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Sigma Rules</h1>
              <p className="text-gray-400">Detection rule management and conversion</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => refetchRules()}
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Refresh
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => setShowRuleModal(true)}
            >
              <Plus className="w-4 h-4 mr-2" />
              Add Rule
            </Button>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-b border-gray-700">
          <nav className="flex space-x-4">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as TabType)}
                className={`flex items-center gap-2 px-4 py-2 border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-purple-500 text-purple-400'
                    : 'border-transparent text-gray-400 hover:text-gray-300'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Rules Tab */}
        {activeTab === 'rules' && (
          <div className="space-y-4">
            {rulesLoading ? (
              <div className="text-center py-8 text-gray-400">Loading rules...</div>
            ) : sigmaRules.length === 0 ? (
              <div className="text-center py-8 text-gray-400">
                No Sigma rules found. Create one to get started.
              </div>
            ) : (
              <div className="space-y-2">
                {sigmaRules.map(rule => (
                  <div key={rule.id} className="bg-gray-800 border border-gray-700 rounded-lg">
                    <div
                      className="flex items-center justify-between p-4 cursor-pointer"
                      onClick={() => toggleRuleExpand(rule.id)}
                    >
                      <div className="flex items-center gap-4">
                        {expandedRules.has(rule.id) ? (
                          <ChevronDown className="w-4 h-4 text-gray-400" />
                        ) : (
                          <ChevronRight className="w-4 h-4 text-gray-400" />
                        )}
                        <div>
                          <h3 className="text-white font-medium">{rule.name}</h3>
                          <p className="text-gray-400 text-sm">{rule.description}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <span className={`px-2 py-0.5 rounded text-xs ${severityColors[rule.severity]?.bg || 'bg-gray-500/20'} ${severityColors[rule.severity]?.text || 'text-gray-400'}`}>
                          {rule.severity}
                        </span>
                        <span className={`px-2 py-0.5 rounded text-xs ${rule.enabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}`}>
                          {rule.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedRule(rule);
                              setConvertContent(rule.content);
                              setShowConvertModal(true);
                            }}
                            className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-cyan-400"
                            title="Convert"
                          >
                            <Code className="w-4 h-4" />
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedRule(rule);
                              setShowTestModal(true);
                            }}
                            className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-green-400"
                            title="Test"
                          >
                            <Play className="w-4 h-4" />
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              deleteRuleMutation.mutate(rule.id);
                            }}
                            className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-red-400"
                            title="Delete"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                    {expandedRules.has(rule.id) && (
                      <div className="px-4 pb-4 border-t border-gray-700 pt-4 space-y-4">
                        <div className="grid grid-cols-3 gap-4 text-sm">
                          <div>
                            <span className="text-gray-500">Category:</span>
                            <span className="text-gray-300 ml-2">{rule.logsource_category}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Product:</span>
                            <span className="text-gray-300 ml-2">{rule.logsource_product}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Status:</span>
                            <span className="text-gray-300 ml-2">{rule.status}</span>
                          </div>
                        </div>
                        {rule.mitre_attack_ids.length > 0 && (
                          <div>
                            <span className="text-gray-500 text-sm">MITRE ATT&CK:</span>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {rule.mitre_attack_ids.map(id => (
                                <span key={id} className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded text-xs">
                                  {id}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                        <div>
                          <span className="text-gray-500 text-sm">Rule Content:</span>
                          <pre className="mt-1 p-3 bg-gray-900 rounded text-xs text-gray-300 overflow-x-auto">
                            {rule.content}
                          </pre>
                        </div>
                        <div className="flex items-center gap-4 text-sm">
                          <span className="text-green-400">
                            <CheckCircle className="w-4 h-4 inline mr-1" />
                            {rule.true_positive_count} TP
                          </span>
                          <span className="text-red-400">
                            <XCircle className="w-4 h-4 inline mr-1" />
                            {rule.false_positive_count} FP
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Convert Tab */}
        {activeTab === 'convert' && (
          <div className="space-y-6">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Convert Sigma Rule</h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-gray-400 mb-2">Sigma Rule Content (YAML)</label>
                  <textarea
                    value={convertContent}
                    onChange={(e) => setConvertContent(e.target.value)}
                    className="w-full h-64 bg-gray-900 border border-gray-600 rounded-lg p-3 text-gray-300 font-mono text-sm"
                    placeholder="Paste your Sigma rule YAML here..."
                  />
                </div>
                <div className="flex items-center gap-4">
                  <select
                    value={selectedBackend}
                    onChange={(e) => setSelectedBackend(e.target.value)}
                    className="bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-gray-300"
                  >
                    {backendOptions.map(opt => (
                      <option key={opt.value} value={opt.value}>{opt.label}</option>
                    ))}
                  </select>
                  <Button
                    variant="primary"
                    onClick={() => convertMutation.mutate({ rule_content: convertContent, backend: selectedBackend })}
                    disabled={!convertContent || convertMutation.isPending}
                  >
                    <Zap className="w-4 h-4 mr-2" />
                    Convert
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() => convertAllMutation.mutate(convertContent)}
                    disabled={!convertContent || convertAllMutation.isPending}
                  >
                    Convert to All
                  </Button>
                </div>
              </div>
            </div>

            {/* Single Conversion Result */}
            {conversionResult && (
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-white">
                    {backendOptions.find(b => b.value === conversionResult.backend)?.label || conversionResult.backend}
                  </h3>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => copyToClipboard(conversionResult.query)}
                  >
                    <Copy className="w-4 h-4 mr-2" />
                    Copy
                  </Button>
                </div>
                <pre className="bg-gray-900 p-4 rounded text-sm text-gray-300 overflow-x-auto">
                  {conversionResult.query}
                </pre>
                {conversionResult.warnings.length > 0 && (
                  <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded">
                    <div className="flex items-center gap-2 text-yellow-400 mb-2">
                      <AlertTriangle className="w-4 h-4" />
                      <span className="font-medium">Warnings</span>
                    </div>
                    <ul className="list-disc list-inside text-yellow-300 text-sm">
                      {conversionResult.warnings.map((w, i) => <li key={i}>{w}</li>)}
                    </ul>
                  </div>
                )}
                {conversionResult.errors.length > 0 && (
                  <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded">
                    <div className="flex items-center gap-2 text-red-400 mb-2">
                      <XCircle className="w-4 h-4" />
                      <span className="font-medium">Errors</span>
                    </div>
                    <ul className="list-disc list-inside text-red-300 text-sm">
                      {conversionResult.errors.map((e, i) => <li key={i}>{e}</li>)}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {/* All Conversions Results */}
            {allConversions.length > 0 && (
              <div className="space-y-4">
                <h3 className="text-lg font-semibold text-white">All Backend Conversions</h3>
                {allConversions.map((conv, idx) => (
                  <div key={idx} className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-purple-400 font-medium">
                        {backendOptions.find(b => b.value === conv.backend)?.label || conv.backend}
                      </span>
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => copyToClipboard(conv.query)}
                      >
                        <Copy className="w-4 h-4" />
                      </Button>
                    </div>
                    <pre className="bg-gray-900 p-3 rounded text-xs text-gray-300 overflow-x-auto">
                      {conv.query || '(conversion failed)'}
                    </pre>
                    {conv.errors.length > 0 && (
                      <p className="text-red-400 text-xs mt-2">{conv.errors.join(', ')}</p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Testing Tab */}
        {activeTab === 'testing' && (
          <div className="space-y-6">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Rule Testing</h3>
              <p className="text-gray-400 mb-4">Select a rule from the Rules tab and click the play button to test it against sample logs.</p>

              {selectedRule && (
                <div className="p-4 bg-gray-900 rounded-lg mb-4">
                  <span className="text-gray-500">Selected Rule:</span>
                  <span className="text-white ml-2">{selectedRule.name}</span>
                </div>
              )}

              <div className="space-y-4">
                <h4 className="text-white font-medium">Recent Test Results</h4>
                {testResults.length === 0 ? (
                  <p className="text-gray-400">No test results yet.</p>
                ) : (
                  <div className="space-y-2">
                    {testResults.map(result => (
                      <div key={result.id} className="bg-gray-900 border border-gray-700 rounded-lg p-4">
                        <div className="flex items-center justify-between">
                          <div>
                            <h5 className="text-white font-medium">{result.test_name}</h5>
                            <p className="text-gray-400 text-sm">
                              {new Date(result.tested_at).toLocaleString()}
                            </p>
                          </div>
                          <div className="flex items-center gap-4">
                            <span className={`px-2 py-1 rounded text-sm ${result.passed ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                              {result.passed ? 'Passed' : 'Failed'}
                            </span>
                            <span className="text-gray-400 text-sm">
                              {result.actual_matches} / {result.expected_matches ?? '?'} matches
                            </span>
                            <span className="text-gray-500 text-sm">
                              {result.execution_time_ms}ms
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ATT&CK Coverage Tab */}
        {activeTab === 'coverage' && (
          <div className="space-y-6">
            {coverageLoading ? (
              <div className="text-center py-8 text-gray-400">Loading coverage data...</div>
            ) : coverage ? (
              <>
                {/* Summary */}
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                    <div className="text-3xl font-bold text-purple-400">{coverage.total_techniques_covered}</div>
                    <div className="text-gray-400">Techniques Covered</div>
                  </div>
                  <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                    <div className="text-3xl font-bold text-cyan-400">{coverage.total_rules}</div>
                    <div className="text-gray-400">Total Rules</div>
                  </div>
                  <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                    <div className="text-3xl font-bold text-green-400">
                      {Object.keys(coverage.coverage_by_tactic).length}
                    </div>
                    <div className="text-gray-400">Tactics Covered</div>
                  </div>
                </div>

                {/* Coverage by Tactic */}
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">Coverage by Tactic</h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {Object.entries(coverage.coverage_by_tactic).map(([tactic, count]) => (
                      <div key={tactic} className="bg-gray-900 rounded-lg p-3">
                        <div className="text-2xl font-bold text-purple-400">{count}</div>
                        <div className="text-gray-400 text-sm capitalize">{tactic.replace(/_/g, ' ')}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Technique Details */}
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">Covered Techniques</h3>
                  <div className="space-y-2">
                    {coverage.techniques.map(tech => (
                      <div key={tech.technique_id} className="bg-gray-900 rounded-lg p-3 flex items-center justify-between">
                        <div>
                          <span className="text-purple-400 font-mono">{tech.technique_id}</span>
                          <span className="text-white ml-2">{tech.technique_name}</span>
                          <span className="text-gray-500 ml-2 text-sm">({tech.tactic})</span>
                        </div>
                        <span className="text-gray-400">{tech.rule_count} rules</span>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            ) : (
              <div className="text-center py-8 text-gray-400">No coverage data available.</div>
            )}
          </div>
        )}

        {/* Tuning Tab */}
        {activeTab === 'tuning' && (
          <div className="space-y-6">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Rule Tuning Recommendations</h3>
              {recommendationsLoading ? (
                <div className="text-center py-8 text-gray-400">Loading recommendations...</div>
              ) : recommendations.length === 0 ? (
                <p className="text-gray-400">No tuning recommendations at this time. Rules are performing well!</p>
              ) : (
                <div className="space-y-4">
                  {recommendations.map((rec, idx) => (
                    <div key={idx} className="bg-gray-900 border border-gray-700 rounded-lg p-4">
                      <div className="flex items-start justify-between">
                        <div>
                          <h4 className="text-white font-medium">{rec.rule_name}</h4>
                          <p className="text-gray-400 text-sm mt-1">{rec.description}</p>
                          {rec.current_value && rec.suggested_value && (
                            <div className="mt-2 text-sm">
                              <span className="text-gray-500">Current:</span>
                              <code className="text-red-400 ml-2">{rec.current_value}</code>
                              <span className="text-gray-500 mx-2">→</span>
                              <span className="text-gray-500">Suggested:</span>
                              <code className="text-green-400 ml-2">{rec.suggested_value}</code>
                            </div>
                          )}
                        </div>
                        <div className="text-right">
                          <span className={`px-2 py-1 rounded text-xs ${
                            rec.recommendation_type === 'increase_specificity' ? 'bg-yellow-500/20 text-yellow-400' :
                            rec.recommendation_type === 'add_exclusion' ? 'bg-blue-500/20 text-blue-400' :
                            'bg-gray-500/20 text-gray-400'
                          }`}>
                            {rec.recommendation_type.replace(/_/g, ' ')}
                          </span>
                          <div className="mt-2 text-sm text-gray-400">
                            FP Rate: {(rec.fp_rate * 100).toFixed(1)}%
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Rule Chains Tab */}
        {activeTab === 'chains' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">Rule Chains (Correlation)</h3>
              <Button variant="primary" size="sm" onClick={() => setShowChainModal(true)}>
                <Plus className="w-4 h-4 mr-2" />
                Create Chain
              </Button>
            </div>

            {chainsLoading ? (
              <div className="text-center py-8 text-gray-400">Loading chains...</div>
            ) : ruleChains.length === 0 ? (
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 text-center">
                <GitBranch className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                <h4 className="text-white font-medium mb-2">No Rule Chains</h4>
                <p className="text-gray-400 mb-4">
                  Create rule chains to correlate multiple Sigma rules and detect complex attack patterns.
                </p>
                <Button variant="primary" onClick={() => setShowChainModal(true)}>
                  Create Your First Chain
                </Button>
              </div>
            ) : (
              <div className="space-y-4">
                {ruleChains.map(chain => (
                  <div key={chain.id} className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="text-white font-medium">{chain.name}</h4>
                        <p className="text-gray-400 text-sm">{chain.description}</p>
                      </div>
                      <div className="flex items-center gap-4">
                        <span className={`px-2 py-1 rounded text-xs ${chain.enabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}`}>
                          {chain.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                        <span className="text-gray-400 text-sm">
                          {chain.chain_logic} • {chain.time_window_secs}s window
                        </span>
                        <button
                          onClick={() => deleteChainMutation.mutate(chain.id)}
                          className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-red-400"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {chain.rule_ids.map(ruleId => {
                        const rule = sigmaRules.find(r => r.id === ruleId);
                        return (
                          <span key={ruleId} className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs">
                            {rule?.name || ruleId}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Create Rule Modal */}
        <Modal
          isOpen={showRuleModal}
          onClose={() => setShowRuleModal(false)}
          title="Create Sigma Rule"
          size="xl"
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const form = e.target as HTMLFormElement;
              const formData = new FormData(form);
              createRuleMutation.mutate({
                name: formData.get('name') as string,
                description: formData.get('description') as string,
                content: formData.get('content') as string,
                severity: formData.get('severity') as string,
                enabled: formData.get('enabled') === 'on',
              });
            }}
            className="space-y-4"
          >
            <div>
              <label className="block text-sm text-gray-400 mb-1">Name</label>
              <input
                name="name"
                type="text"
                required
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Description</label>
              <input
                name="description"
                type="text"
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Severity</label>
              <select
                name="severity"
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Rule Content (YAML)</label>
              <textarea
                name="content"
                required
                rows={10}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white font-mono text-sm"
                placeholder={`title: My Detection Rule
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'suspicious'
  condition: selection`}
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                name="enabled"
                type="checkbox"
                defaultChecked
                className="rounded bg-gray-900 border-gray-600"
              />
              <label className="text-gray-400">Enabled</label>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button variant="secondary" onClick={() => setShowRuleModal(false)}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={createRuleMutation.isPending}>
                Create Rule
              </Button>
            </div>
          </form>
        </Modal>

        {/* Test Rule Modal */}
        <Modal
          isOpen={showTestModal}
          onClose={() => setShowTestModal(false)}
          title={`Test Rule: ${selectedRule?.name || ''}`}
          size="xl"
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!selectedRule) return;
              const logs = testLogs.split('\n').filter(l => l.trim());
              testRuleMutation.mutate({
                id: selectedRule.id,
                test_name: testName,
                sample_logs: logs,
                expected_matches: expectedMatches,
              });
            }}
            className="space-y-4"
          >
            <div>
              <label className="block text-sm text-gray-400 mb-1">Test Name</label>
              <input
                type="text"
                required
                value={testName}
                onChange={(e) => setTestName(e.target.value)}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Sample Logs (one per line, JSON format)</label>
              <textarea
                required
                value={testLogs}
                onChange={(e) => setTestLogs(e.target.value)}
                rows={8}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white font-mono text-sm"
                placeholder='{"CommandLine": "cmd.exe /c suspicious.bat", "Image": "C:\\Windows\\System32\\cmd.exe"}'
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Expected Matches (optional)</label>
              <input
                type="number"
                min={0}
                value={expectedMatches ?? ''}
                onChange={(e) => setExpectedMatches(e.target.value ? parseInt(e.target.value) : undefined)}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              />
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button variant="secondary" onClick={() => setShowTestModal(false)}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={testRuleMutation.isPending}>
                <Play className="w-4 h-4 mr-2" />
                Run Test
              </Button>
            </div>
          </form>
        </Modal>

        {/* Create Chain Modal */}
        <Modal
          isOpen={showChainModal}
          onClose={() => { setShowChainModal(false); resetChainForm(); }}
          title="Create Rule Chain"
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              createChainMutation.mutate({
                name: chainName,
                description: chainDescription || undefined,
                rule_ids: chainRuleIds,
                chain_logic: chainLogic,
                time_window_secs: chainTimeWindow,
                enabled: true,
              });
            }}
            className="space-y-4"
          >
            <div>
              <label className="block text-sm text-gray-400 mb-1">Chain Name</label>
              <input
                type="text"
                required
                value={chainName}
                onChange={(e) => setChainName(e.target.value)}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Description</label>
              <input
                type="text"
                value={chainDescription}
                onChange={(e) => setChainDescription(e.target.value)}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Select Rules</label>
              <div className="max-h-48 overflow-y-auto bg-gray-900 border border-gray-600 rounded-lg p-2 space-y-1">
                {sigmaRules.map(rule => (
                  <label key={rule.id} className="flex items-center gap-2 p-2 hover:bg-gray-800 rounded cursor-pointer">
                    <input
                      type="checkbox"
                      checked={chainRuleIds.includes(rule.id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setChainRuleIds([...chainRuleIds, rule.id]);
                        } else {
                          setChainRuleIds(chainRuleIds.filter(id => id !== rule.id));
                        }
                      }}
                      className="rounded bg-gray-700 border-gray-600"
                    />
                    <span className="text-white">{rule.name}</span>
                  </label>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Chain Logic</label>
              <select
                value={chainLogic}
                onChange={(e) => setChainLogic(e.target.value)}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              >
                <option value="sequence">Sequence (rules must fire in order)</option>
                <option value="parallel">Parallel (all rules must fire within window)</option>
              </select>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Time Window (seconds)</label>
              <input
                type="number"
                min={1}
                value={chainTimeWindow}
                onChange={(e) => setChainTimeWindow(parseInt(e.target.value))}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              />
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button variant="secondary" onClick={() => { setShowChainModal(false); resetChainForm(); }}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={createChainMutation.isPending || chainRuleIds.length < 2}>
                Create Chain
              </Button>
            </div>
          </form>
        </Modal>

        {/* Convert Modal (for individual rule) */}
        <Modal
          isOpen={showConvertModal}
          onClose={() => { setShowConvertModal(false); setConversionResult(null); }}
          title={`Convert: ${selectedRule?.name || ''}`}
          size="xl"
        >
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <select
                value={selectedBackend}
                onChange={(e) => setSelectedBackend(e.target.value)}
                className="bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-gray-300"
              >
                {backendOptions.map(opt => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
              <Button
                variant="primary"
                onClick={() => convertMutation.mutate({ rule_content: convertContent, backend: selectedBackend })}
                disabled={convertMutation.isPending}
              >
                Convert
              </Button>
              <Button
                variant="secondary"
                onClick={() => convertAllMutation.mutate(convertContent)}
                disabled={convertAllMutation.isPending}
              >
                Convert to All
              </Button>
            </div>

            {conversionResult && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-purple-400 font-medium">
                    {backendOptions.find(b => b.value === conversionResult.backend)?.label}
                  </span>
                  <Button variant="secondary" size="sm" onClick={() => copyToClipboard(conversionResult.query)}>
                    <Copy className="w-4 h-4 mr-2" />
                    Copy
                  </Button>
                </div>
                <pre className="bg-gray-900 p-4 rounded text-sm text-gray-300 overflow-x-auto">
                  {conversionResult.query}
                </pre>
              </div>
            )}
          </div>
        </Modal>
      </div>
    </Layout>
  );
}
