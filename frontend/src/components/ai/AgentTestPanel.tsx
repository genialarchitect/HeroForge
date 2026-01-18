import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Wrench,
  Play,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Plus,
  Trash2,
  Settings,
  Database,
  Code,
  Shield,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import LoadingSpinner from '../ui/LoadingSpinner';
import {
  aiSecurityAPI,
  AgentTestConfig,
  AgentTestCase,
  AgentTestResult,
  ToolDefinition,
  LLMTarget,
} from '../../services/api';

interface AgentTestPanelProps {
  targets: LLMTarget[];
}

const AgentTestPanel: React.FC<AgentTestPanelProps> = ({ targets }) => {
  const [selectedTarget, setSelectedTarget] = useState<string>('');
  const [selectedConfig, setSelectedConfig] = useState<string>('');
  const [selectedTests, setSelectedTests] = useState<string[]>([]);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [testResults, setTestResults] = useState<AgentTestResult[]>([]);
  const [expandedCategory, setExpandedCategory] = useState<string | null>(null);
  const queryClient = useQueryClient();

  // New config form state
  const [newConfig, setNewConfig] = useState({
    target_id: '',
    function_format: 'openai' as const,
    memory_enabled: false,
    rag_endpoint: '',
    tools: [] as ToolDefinition[],
  });

  const [newTool, setNewTool] = useState({
    name: '',
    description: '',
    dangerous: false,
  });

  // Fetch agent configs
  const { data: agentConfigs, isLoading: configsLoading } = useQuery<AgentTestConfig[]>({
    queryKey: ['agent-configs', selectedTarget],
    queryFn: async () => {
      if (!selectedTarget) return [];
      try {
        const response = await aiSecurityAPI.getAgentConfigs({ target_id: selectedTarget });
        return response.data;
      } catch {
        return [];
      }
    },
    enabled: !!selectedTarget,
  });

  // Fetch agent test cases
  const { data: agentTestCases, isLoading: testCasesLoading } = useQuery<AgentTestCase[]>({
    queryKey: ['agent-test-cases'],
    queryFn: async () => {
      try {
        const response = await aiSecurityAPI.getAgentTestCases({ builtin_only: true });
        return response.data;
      } catch {
        return [];
      }
    },
  });

  // Create agent config mutation
  const createConfigMutation = useMutation({
    mutationFn: async (data: typeof newConfig) => {
      const response = await aiSecurityAPI.createAgentConfig({
        target_id: data.target_id,
        tools: data.tools,
        rag_endpoint: data.rag_endpoint || undefined,
        function_format: data.function_format,
        memory_enabled: data.memory_enabled,
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agent-configs'] });
      toast.success('Agent configuration created');
      setShowConfigModal(false);
      setNewConfig({
        target_id: '',
        function_format: 'openai',
        memory_enabled: false,
        rag_endpoint: '',
        tools: [],
      });
    },
    onError: () => {
      toast.error('Failed to create agent configuration');
    },
  });

  // Run agent test mutation
  const runTestMutation = useMutation({
    mutationFn: async (data: { target_id: string; agent_config_id: string; test_ids?: string[] }) => {
      const response = await aiSecurityAPI.startAgentTest(data);
      return response.data;
    },
    onSuccess: (results) => {
      setTestResults(results);
      queryClient.invalidateQueries({ queryKey: ['llm-test-runs'] });
      const failed = results.filter(r => r.status === 'failed').length;
      if (failed > 0) {
        toast.warning(`${failed} of ${results.length} tests detected vulnerabilities`);
      } else {
        toast.success('All agent tests passed');
      }
    },
    onError: () => {
      toast.error('Failed to run agent tests');
    },
  });

  const handleRunTests = () => {
    if (!selectedTarget) {
      toast.error('Please select a target');
      return;
    }
    if (!selectedConfig) {
      toast.error('Please select or create an agent configuration');
      return;
    }
    setTestResults([]);
    runTestMutation.mutate({
      target_id: selectedTarget,
      agent_config_id: selectedConfig,
      test_ids: selectedTests.length > 0 ? selectedTests : undefined,
    });
  };

  const handleAddTool = () => {
    if (!newTool.name.trim()) return;
    setNewConfig({
      ...newConfig,
      tools: [
        ...newConfig.tools,
        {
          name: newTool.name,
          description: newTool.description,
          parameters: {},
          dangerous: newTool.dangerous,
        },
      ],
    });
    setNewTool({ name: '', description: '', dangerous: false });
  };

  const handleRemoveTool = (index: number) => {
    setNewConfig({
      ...newConfig,
      tools: newConfig.tools.filter((_, i) => i !== index),
    });
  };

  const toggleTest = (testId: string) => {
    setSelectedTests((prev) =>
      prev.includes(testId)
        ? prev.filter((id) => id !== testId)
        : [...prev, testId]
    );
  };

  const getCategoryColor = (category: string) => {
    const colors: Record<string, string> = {
      tool_parameter_injection: 'text-red-400',
      tool_chaining: 'text-orange-400',
      rag_poisoning: 'text-yellow-400',
      function_hijacking: 'text-purple-400',
      memory_poisoning: 'text-blue-400',
      privilege_escalation: 'text-pink-400',
    };
    return colors[category.toLowerCase()] || 'text-slate-400';
  };

  const getSeverityBadge = (severity: string) => {
    const variants: Record<string, 'danger' | 'warning' | 'info' | 'success'> = {
      critical: 'danger',
      high: 'danger',
      medium: 'warning',
      low: 'info',
    };
    return variants[severity.toLowerCase()] || 'info';
  };

  // Group test cases by category
  const testsByCategory = agentTestCases?.reduce((acc, test) => {
    const category = test.category;
    if (!acc[category]) {
      acc[category] = [];
    }
    acc[category].push(test);
    return acc;
  }, {} as Record<string, AgentTestCase[]>) || {};

  return (
    <div className="space-y-6">
      {/* Configuration Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Target & Config Selection */}
        <Card>
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Settings className="h-5 w-5 text-primary" />
            Agent Configuration
          </h3>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Select Target
              </label>
              <select
                value={selectedTarget}
                onChange={(e) => {
                  setSelectedTarget(e.target.value);
                  setSelectedConfig('');
                }}
                className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white focus:outline-none focus:border-primary"
              >
                <option value="">Choose a target...</option>
                {targets.map((target) => (
                  <option key={target.id} value={target.id}>
                    {target.name} ({target.model_type})
                  </option>
                ))}
              </select>
            </div>

            {selectedTarget && (
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Agent Configuration
                </label>
                {configsLoading ? (
                  <LoadingSpinner />
                ) : agentConfigs && agentConfigs.length > 0 ? (
                  <div className="space-y-2">
                    {agentConfigs.map((config) => (
                      <button
                        key={config.id}
                        onClick={() => setSelectedConfig(config.id)}
                        className={`w-full p-3 rounded-lg border text-left transition-colors ${
                          selectedConfig === config.id
                            ? 'bg-primary/20 border-primary'
                            : 'bg-dark-bg border-dark-border hover:border-slate-600'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Wrench className="h-4 w-4 text-slate-400" />
                            <span className="text-white">{config.tools.length} tools</span>
                          </div>
                          <Badge variant="info">{config.function_format}</Badge>
                        </div>
                        <div className="text-xs text-slate-500 mt-1">
                          {config.memory_enabled && 'Memory enabled • '}
                          {config.rag_endpoint && 'RAG configured'}
                        </div>
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-4 text-slate-500">
                    No configurations yet
                  </div>
                )}

                <Button
                  variant="secondary"
                  size="sm"
                  className="w-full mt-3"
                  onClick={() => {
                    setNewConfig({ ...newConfig, target_id: selectedTarget });
                    setShowConfigModal(true);
                  }}
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Create Configuration
                </Button>
              </div>
            )}
          </div>
        </Card>

        {/* Test Selection */}
        <Card className="lg:col-span-2">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            Agent Security Tests
          </h3>

          {testCasesLoading ? (
            <div className="flex items-center justify-center py-8">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="space-y-3 max-h-[400px] overflow-y-auto">
              {Object.entries(testsByCategory).map(([category, tests]) => (
                <div key={category} className="border border-dark-border rounded-lg">
                  <button
                    onClick={() => setExpandedCategory(expandedCategory === category ? null : category)}
                    className="w-full p-3 flex items-center justify-between text-left hover:bg-dark-bg transition-colors rounded-lg"
                  >
                    <div className="flex items-center gap-2">
                      <span className={`font-medium ${getCategoryColor(category)}`}>
                        {category.replace(/_/g, ' ').toUpperCase()}
                      </span>
                      <Badge variant="info" className="text-xs">{tests.length}</Badge>
                    </div>
                    {expandedCategory === category ? (
                      <ChevronUp className="h-4 w-4 text-slate-400" />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-slate-400" />
                    )}
                  </button>

                  {expandedCategory === category && (
                    <div className="px-3 pb-3 space-y-2">
                      {tests.map((test) => (
                        <div
                          key={test.id}
                          onClick={() => toggleTest(test.id)}
                          className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                            selectedTests.includes(test.id)
                              ? 'bg-primary/20 border-primary'
                              : 'bg-dark-bg border-dark-border hover:border-slate-600'
                          }`}
                        >
                          <div className="flex items-start justify-between">
                            <div>
                              <div className="font-medium text-white">{test.name}</div>
                              <p className="text-sm text-slate-400 mt-1">{test.description}</p>
                            </div>
                            <Badge variant={getSeverityBadge(test.severity)} className="text-xs shrink-0">
                              {test.severity}
                            </Badge>
                          </div>
                          {test.cwe_id && (
                            <div className="text-xs text-slate-500 mt-2">
                              CWE: {test.cwe_id}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          <div className="mt-4 pt-4 border-t border-dark-border flex items-center justify-between">
            <div className="text-sm text-slate-400">
              {selectedTests.length > 0
                ? `${selectedTests.length} tests selected`
                : 'All tests will run'}
            </div>
            <Button
              variant="primary"
              onClick={handleRunTests}
              loading={runTestMutation.isPending}
              disabled={!selectedTarget || !selectedConfig}
            >
              <Play className="h-4 w-4 mr-2" />
              Run Agent Tests
            </Button>
          </div>
        </Card>
      </div>

      {/* Test Results */}
      {testResults.length > 0 && (
        <Card>
          <h3 className="text-lg font-semibold text-white mb-4">Test Results</h3>
          <div className="space-y-3">
            {testResults.map((result, idx) => (
              <div
                key={idx}
                className={`p-4 rounded-lg border ${
                  result.status === 'failed'
                    ? 'bg-red-500/10 border-red-500/30'
                    : 'bg-green-500/10 border-green-500/30'
                }`}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    {result.status === 'failed' ? (
                      <XCircle className="h-5 w-5 text-red-400" />
                    ) : (
                      <CheckCircle className="h-5 w-5 text-green-400" />
                    )}
                    <div>
                      <div className="font-medium text-white">{result.test_name}</div>
                      <div className="text-sm text-slate-400">{result.category}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={result.status === 'failed' ? 'danger' : 'success'}>
                      {result.status}
                    </Badge>
                    <Badge variant={getSeverityBadge(result.severity)}>
                      {result.severity}
                    </Badge>
                  </div>
                </div>

                {/* Vulnerability Indicators */}
                {result.vulnerability_indicators.length > 0 && (
                  <div className="mb-3">
                    <div className="text-xs text-slate-500 mb-1">Vulnerability Indicators:</div>
                    <div className="flex flex-wrap gap-1">
                      {result.vulnerability_indicators.map((indicator, i) => (
                        <Badge key={i} variant="warning" className="text-xs">
                          {indicator}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Tool Calls Detected */}
                {result.tool_calls_detected.length > 0 && (
                  <div className="mb-3">
                    <div className="text-xs text-slate-500 mb-1">Tool Calls Detected:</div>
                    <div className="space-y-1">
                      {result.tool_calls_detected.map((call, i) => (
                        <div key={i} className="text-sm text-slate-300 flex items-center gap-2">
                          <Code className="h-3 w-3 text-slate-500" />
                          <span className="font-mono">{call.tool_name}</span>
                          <span className="text-xs text-slate-500">
                            ({Object.keys(call.arguments).length} args)
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Remediation */}
                {result.remediation && (
                  <div className="p-3 bg-dark-bg rounded border border-dark-border">
                    <div className="text-xs text-slate-500 mb-1">Remediation:</div>
                    <p className="text-sm text-slate-300">{result.remediation}</p>
                  </div>
                )}

                <div className="flex items-center justify-between mt-3 text-xs text-slate-500">
                  <span>Confidence: {(result.confidence * 100).toFixed(0)}%</span>
                  <span>Duration: {result.duration_ms}ms</span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Create Config Modal */}
      {showConfigModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-dark-surface border border-dark-border rounded-lg w-full max-w-lg p-6 m-4 max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-white mb-4">Create Agent Configuration</h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">
                  Function Calling Format
                </label>
                <select
                  value={newConfig.function_format}
                  onChange={(e) => setNewConfig({ ...newConfig, function_format: e.target.value as any })}
                  className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white"
                >
                  <option value="openai">OpenAI</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="gemini">Gemini</option>
                  <option value="custom">Custom</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">
                  RAG Endpoint (Optional)
                </label>
                <input
                  type="url"
                  value={newConfig.rag_endpoint}
                  onChange={(e) => setNewConfig({ ...newConfig, rag_endpoint: e.target.value })}
                  placeholder="https://..."
                  className="w-full px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white"
                />
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="memory_enabled"
                  checked={newConfig.memory_enabled}
                  onChange={(e) => setNewConfig({ ...newConfig, memory_enabled: e.target.checked })}
                  className="rounded"
                />
                <label htmlFor="memory_enabled" className="text-sm text-slate-300">
                  Memory Enabled
                </label>
              </div>

              {/* Tools */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Tool Definitions
                </label>

                {newConfig.tools.length > 0 && (
                  <div className="space-y-2 mb-3">
                    {newConfig.tools.map((tool, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2 bg-dark-bg rounded border border-dark-border">
                        <div className="flex items-center gap-2">
                          <Wrench className="h-4 w-4 text-slate-400" />
                          <span className="text-white">{tool.name}</span>
                          {tool.dangerous && (
                            <Badge variant="danger" className="text-xs">Dangerous</Badge>
                          )}
                        </div>
                        <button
                          onClick={() => handleRemoveTool(idx)}
                          className="text-slate-400 hover:text-red-400"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                <div className="flex gap-2">
                  <input
                    type="text"
                    value={newTool.name}
                    onChange={(e) => setNewTool({ ...newTool, name: e.target.value })}
                    placeholder="Tool name"
                    className="flex-1 px-3 py-2 bg-dark-bg border border-dark-border rounded-lg text-white"
                  />
                  <div className="flex items-center gap-1">
                    <input
                      type="checkbox"
                      id="tool_dangerous"
                      checked={newTool.dangerous}
                      onChange={(e) => setNewTool({ ...newTool, dangerous: e.target.checked })}
                    />
                    <label htmlFor="tool_dangerous" className="text-xs text-slate-400">
                      Dangerous
                    </label>
                  </div>
                  <Button variant="secondary" size="sm" onClick={handleAddTool}>
                    <Plus className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <Button variant="secondary" onClick={() => setShowConfigModal(false)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                onClick={() => createConfigMutation.mutate(newConfig)}
                loading={createConfigMutation.isPending}
                disabled={newConfig.tools.length === 0}
              >
                Create Configuration
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AgentTestPanel;
