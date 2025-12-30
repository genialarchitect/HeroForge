import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Sparkles,
  ShieldAlert,
  Lock,
  Unlock,
  Code,
  AlertTriangle,
  Play,
  Pause,
  CheckCircle,
  XCircle,
  Clock,
  Target,
  Zap,
  BarChart3,
  RefreshCw,
  FileText,
  Download,
  Filter,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import { aiSecurityAPI } from '../services/api';

// Types
interface TestCategory {
  name: string;
  icon: React.ReactNode;
  color: string;
  description: string;
  testCount: number;
  passRate?: number;
}

interface LLMTarget {
  id: string;
  name: string;
  endpoint: string;
  model_type: string;
  created_at: string;
}

interface TestResult {
  id: string;
  test_name: string;
  category: string;
  status: 'passed' | 'failed' | 'running' | 'pending';
  severity: string;
  vulnerability_found: boolean;
  response: string;
  execution_time: number;
  timestamp: string;
}

interface TestRun {
  id: string;
  target_id: string;
  target_name: string;
  total_tests: number;
  passed: number;
  failed: number;
  vulnerabilities_found: number;
  status: 'running' | 'completed' | 'failed';
  started_at: string;
  completed_at?: string;
}

const LlmTestingPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'targets' | 'run-test' | 'results'>('dashboard');
  const [selectedTarget, setSelectedTarget] = useState<string | null>(null);
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const queryClient = useQueryClient();

  const testCategories: TestCategory[] = [
    {
      name: 'Prompt Injection',
      icon: <Code className="h-5 w-5" />,
      color: 'text-red-500',
      description: 'Test for malicious prompt injection attacks',
      testCount: 25,
      passRate: 82,
    },
    {
      name: 'Jailbreak Attempts',
      icon: <Unlock className="h-5 w-5" />,
      color: 'text-orange-500',
      description: 'Bypass safety guardrails and content filters',
      testCount: 18,
      passRate: 91,
    },
    {
      name: 'Data Extraction',
      icon: <AlertTriangle className="h-5 w-5" />,
      color: 'text-yellow-500',
      description: 'Attempt to extract training data or sensitive information',
      testCount: 12,
      passRate: 94,
    },
    {
      name: 'Context Manipulation',
      icon: <ShieldAlert className="h-5 w-5" />,
      color: 'text-purple-500',
      description: 'Manipulate conversation context for unintended behavior',
      testCount: 9,
      passRate: 88,
    },
    {
      name: 'Encoding Attacks',
      icon: <Lock className="h-5 w-5" />,
      color: 'text-blue-500',
      description: 'Use encoding techniques to bypass filters',
      testCount: 7,
      passRate: 96,
    },
  ];

  // Fetch LLM targets
  const { data: targets, isLoading: targetsLoading } = useQuery<LLMTarget[]>({
    queryKey: ['llm-targets'],
    queryFn: async () => {
      // TODO: Replace with actual API endpoint
      return [
        {
          id: '1',
          name: 'Production Chat API',
          endpoint: 'https://api.example.com/chat',
          model_type: 'GPT-4',
          created_at: new Date().toISOString(),
        },
        {
          id: '2',
          name: 'Internal Assistant',
          endpoint: 'https://internal.example.com/ai',
          model_type: 'Claude',
          created_at: new Date().toISOString(),
        },
      ];
    },
  });

  // Fetch test runs
  const { data: testRuns } = useQuery<TestRun[]>({
    queryKey: ['llm-test-runs'],
    queryFn: async () => {
      // TODO: Replace with actual API endpoint
      return [
        {
          id: '1',
          target_id: '1',
          target_name: 'Production Chat API',
          total_tests: 71,
          passed: 65,
          failed: 6,
          vulnerabilities_found: 3,
          status: 'completed',
          started_at: new Date(Date.now() - 3600000).toISOString(),
          completed_at: new Date().toISOString(),
        },
      ];
    },
  });

  // Fetch recent test results
  const { data: testResults } = useQuery<TestResult[]>({
    queryKey: ['llm-test-results', selectedTarget],
    queryFn: async () => {
      // TODO: Replace with actual API endpoint
      return [
        {
          id: '1',
          test_name: 'Prompt Injection - Admin Access',
          category: 'Prompt Injection',
          status: 'failed',
          severity: 'high',
          vulnerability_found: true,
          response: 'Successfully bypassed restrictions to access admin functionality',
          execution_time: 1.2,
          timestamp: new Date().toISOString(),
        },
        {
          id: '2',
          test_name: 'Jailbreak - Content Policy',
          category: 'Jailbreak Attempts',
          status: 'passed',
          severity: 'medium',
          vulnerability_found: false,
          response: 'Content policy maintained, request rejected appropriately',
          execution_time: 0.8,
          timestamp: new Date().toISOString(),
        },
      ];
    },
    enabled: !!selectedTarget,
  });

  // Run tests mutation
  const runTestsMutation = useMutation({
    mutationFn: async (data: { target_id: string; categories: string[] }) => {
      // TODO: Replace with actual API endpoint
      await new Promise((resolve) => setTimeout(resolve, 2000));
      return {
        run_id: 'new-run-' + Date.now(),
        total_tests: selectedCategories.reduce((sum, cat) => {
          const category = testCategories.find((c) => c.name === cat);
          return sum + (category?.testCount || 0);
        }, 0),
      };
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['llm-test-runs'] });
      toast.success(`Test run started: ${data.total_tests} tests queued`);
      setActiveTab('results');
    },
    onError: () => {
      toast.error('Failed to start test run');
    },
  });

  const handleRunTests = () => {
    if (!selectedTarget) {
      toast.error('Please select a target');
      return;
    }
    if (selectedCategories.length === 0) {
      toast.error('Please select at least one test category');
      return;
    }
    runTestsMutation.mutate({
      target_id: selectedTarget,
      categories: selectedCategories,
    });
  };

  const toggleCategory = (categoryName: string) => {
    setSelectedCategories((prev) =>
      prev.includes(categoryName)
        ? prev.filter((c) => c !== categoryName)
        : [...prev, categoryName]
    );
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'passed':
        return 'text-green-400';
      case 'failed':
        return 'text-red-400';
      case 'running':
        return 'text-blue-400';
      default:
        return 'text-slate-400';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'passed':
        return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-400" />;
      case 'running':
        return <RefreshCw className="h-4 w-4 text-blue-400 animate-spin" />;
      default:
        return <Clock className="h-4 w-4 text-slate-400" />;
    }
  };

  const totalTests = testCategories.reduce((sum, cat) => sum + cat.testCount, 0);
  const testsRun = testRuns?.reduce((sum, run) => sum + run.total_tests, 0) || 0;

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-3">
              <Sparkles className="h-8 w-8 text-primary" />
              LLM Security Testing
            </h1>
            <p className="text-slate-400 mt-2">
              Test AI and LLM applications for security vulnerabilities
            </p>
          </div>
          <Button variant="primary" onClick={() => queryClient.invalidateQueries()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="bg-gradient-to-br from-purple-500/10 to-purple-600/10 border-purple-500/30">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-slate-400">Built-in Tests</span>
              <FileText className="h-4 w-4 text-purple-400" />
            </div>
            <div className="text-3xl font-bold text-white">{totalTests}</div>
            <div className="text-xs text-slate-500 mt-1">Across 5 categories</div>
          </Card>

          <Card className="bg-gradient-to-br from-blue-500/10 to-blue-600/10 border-blue-500/30">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-slate-400">Tests Run</span>
              <BarChart3 className="h-4 w-4 text-blue-400" />
            </div>
            <div className="text-3xl font-bold text-white">{testsRun}</div>
            <div className="text-xs text-slate-500 mt-1">{testRuns?.length || 0} test runs</div>
          </Card>

          <Card className="bg-gradient-to-br from-red-500/10 to-red-600/10 border-red-500/30">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-slate-400">Vulnerabilities</span>
              <AlertTriangle className="h-4 w-4 text-red-400" />
            </div>
            <div className="text-3xl font-bold text-white">
              {testRuns?.reduce((sum, run) => sum + run.vulnerabilities_found, 0) || 0}
            </div>
            <div className="text-xs text-slate-500 mt-1">Found in testing</div>
          </Card>

          <Card className="bg-gradient-to-br from-green-500/10 to-green-600/10 border-green-500/30">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-slate-400">Pass Rate</span>
              <CheckCircle className="h-4 w-4 text-green-400" />
            </div>
            <div className="text-3xl font-bold text-white">
              {testRuns && testRuns.length > 0
                ? Math.round(
                    (testRuns.reduce((sum, run) => sum + run.passed, 0) /
                      testRuns.reduce((sum, run) => sum + run.total_tests, 0)) *
                      100
                  )
                : 0}
              %
            </div>
            <div className="text-xs text-slate-500 mt-1">Average across all runs</div>
          </Card>
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-2 border-b border-dark-border">
          {[
            { id: 'dashboard' as const, label: 'Dashboard', icon: <BarChart3 className="h-4 w-4" /> },
            { id: 'targets' as const, label: 'Targets', icon: <Target className="h-4 w-4" /> },
            { id: 'run-test' as const, label: 'Run Tests', icon: <Play className="h-4 w-4" /> },
            { id: 'results' as const, label: 'Results', icon: <FileText className="h-4 w-4" /> },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-3 font-medium transition-colors border-b-2 ${
                activeTab === tab.id
                  ? 'text-primary border-primary'
                  : 'text-slate-400 border-transparent hover:text-white hover:border-slate-600'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* Test Categories */}
            <Card>
              <h3 className="text-lg font-semibold text-white mb-4">Test Categories</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {testCategories.map((category) => (
                  <div
                    key={category.name}
                    className="bg-dark-bg border border-dark-border rounded-lg p-5 hover:border-primary transition-colors"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className={`${category.color}`}>{category.icon}</div>
                      <span className="text-xs font-medium px-2 py-1 bg-slate-700 text-slate-300 rounded">
                        {category.testCount} tests
                      </span>
                    </div>
                    <h4 className="font-semibold text-white mb-2">{category.name}</h4>
                    <p className="text-sm text-slate-400 mb-3">{category.description}</p>
                    {category.passRate !== undefined && (
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-500">Pass Rate:</span>
                        <span className="font-medium text-green-400">{category.passRate}%</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </Card>

            {/* Recent Test Runs */}
            <Card>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white">Recent Test Runs</h3>
                <Badge variant="info">{testRuns?.length || 0} runs</Badge>
              </div>

              <div className="space-y-3">
                {testRuns?.map((run) => (
                  <div key={run.id} className="p-4 bg-dark-bg rounded-lg border border-dark-border">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-3">
                        {getStatusIcon(run.status)}
                        <div>
                          <div className="font-medium text-white">{run.target_name}</div>
                          <div className="text-sm text-slate-400">
                            {new Date(run.started_at).toLocaleString()}
                          </div>
                        </div>
                      </div>
                      <Badge variant={run.status === 'completed' ? 'success' : 'info'}>{run.status}</Badge>
                    </div>

                    <div className="grid grid-cols-4 gap-4 text-sm">
                      <div>
                        <div className="text-slate-500">Total Tests</div>
                        <div className="text-white font-medium">{run.total_tests}</div>
                      </div>
                      <div>
                        <div className="text-slate-500">Passed</div>
                        <div className="text-green-400 font-medium">{run.passed}</div>
                      </div>
                      <div>
                        <div className="text-slate-500">Failed</div>
                        <div className="text-red-400 font-medium">{run.failed}</div>
                      </div>
                      <div>
                        <div className="text-slate-500">Vulnerabilities</div>
                        <div className="text-orange-400 font-medium">{run.vulnerabilities_found}</div>
                      </div>
                    </div>
                  </div>
                ))}

                {(!testRuns || testRuns.length === 0) && (
                  <div className="text-center py-8 text-slate-500">
                    No test runs yet. Go to "Run Tests" to start testing.
                  </div>
                )}
              </div>
            </Card>
          </div>
        )}

        {activeTab === 'targets' && (
          <Card>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">LLM Targets</h3>
              <Button variant="primary" size="sm">
                <Target className="h-4 w-4 mr-2" />
                Add Target
              </Button>
            </div>

            {targetsLoading ? (
              <div className="flex items-center justify-center py-12">
                <LoadingSpinner />
              </div>
            ) : (
              <div className="space-y-3">
                {targets?.map((target) => (
                  <div key={target.id} className="p-4 bg-dark-bg rounded-lg border border-dark-border hover:border-primary transition-colors">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <Sparkles className="h-5 w-5 text-primary" />
                        <div>
                          <div className="font-medium text-white">{target.name}</div>
                          <div className="text-sm text-slate-400">{target.endpoint}</div>
                        </div>
                      </div>
                      <Badge variant="info">{target.model_type}</Badge>
                    </div>
                    <div className="text-xs text-slate-500">
                      Added: {new Date(target.created_at).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        )}

        {activeTab === 'run-test' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <h3 className="text-lg font-semibold text-white mb-4">Select Target</h3>
              <div className="space-y-2">
                {targets?.map((target) => (
                  <button
                    key={target.id}
                    onClick={() => setSelectedTarget(target.id)}
                    className={`w-full p-4 rounded-lg border transition-colors text-left ${
                      selectedTarget === target.id
                        ? 'bg-primary/20 border-primary text-white'
                        : 'bg-dark-bg border-dark-border text-slate-300 hover:border-primary'
                    }`}
                  >
                    <div className="font-medium">{target.name}</div>
                    <div className="text-sm text-slate-400">{target.endpoint}</div>
                  </button>
                ))}
              </div>
            </Card>

            <Card>
              <h3 className="text-lg font-semibold text-white mb-4">Select Test Categories</h3>
              <div className="space-y-2 mb-6">
                {testCategories.map((category) => (
                  <button
                    key={category.name}
                    onClick={() => toggleCategory(category.name)}
                    className={`w-full p-4 rounded-lg border transition-colors text-left ${
                      selectedCategories.includes(category.name)
                        ? 'bg-primary/20 border-primary'
                        : 'bg-dark-bg border-dark-border hover:border-primary'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-3">
                        <div className={category.color}>{category.icon}</div>
                        <span className="font-medium text-white">{category.name}</span>
                      </div>
                      <span className="text-xs text-slate-400">{category.testCount} tests</span>
                    </div>
                    <p className="text-sm text-slate-400">{category.description}</p>
                  </button>
                ))}
              </div>

              <div className="p-4 bg-dark-bg rounded-lg border border-dark-border mb-4">
                <div className="text-sm text-slate-400 mb-2">Tests to run:</div>
                <div className="text-2xl font-bold text-white">
                  {selectedCategories.reduce((sum, cat) => {
                    const category = testCategories.find((c) => c.name === cat);
                    return sum + (category?.testCount || 0);
                  }, 0)}
                </div>
              </div>

              <Button
                variant="primary"
                className="w-full"
                onClick={handleRunTests}
                loading={runTestsMutation.isPending}
                disabled={!selectedTarget || selectedCategories.length === 0}
              >
                <Play className="h-4 w-4 mr-2" />
                Run Tests
              </Button>
            </Card>
          </div>
        )}

        {activeTab === 'results' && (
          <Card>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">Test Results</h3>
              <div className="flex items-center gap-2">
                <Button variant="secondary" size="sm">
                  <Filter className="h-4 w-4 mr-2" />
                  Filter
                </Button>
                <Button variant="secondary" size="sm">
                  <Download className="h-4 w-4 mr-2" />
                  Export
                </Button>
              </div>
            </div>

            <div className="space-y-3">
              {testResults?.map((result) => (
                <div key={result.id} className="p-4 bg-dark-bg rounded-lg border border-dark-border">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      {getStatusIcon(result.status)}
                      <div>
                        <div className="font-medium text-white">{result.test_name}</div>
                        <div className="text-sm text-slate-400">{result.category}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={result.vulnerability_found ? 'danger' : 'success'}>
                        {result.vulnerability_found ? 'Vulnerable' : 'Secure'}
                      </Badge>
                      <Badge variant="warning">{result.severity}</Badge>
                    </div>
                  </div>

                  <div className="p-3 bg-dark-surface rounded border border-dark-border mb-2">
                    <div className="text-xs text-slate-500 mb-1">Response:</div>
                    <div className="text-sm text-slate-300">{result.response}</div>
                  </div>

                  <div className="flex items-center justify-between text-xs text-slate-500">
                    <span>Execution time: {result.execution_time.toFixed(2)}s</span>
                    <span>{new Date(result.timestamp).toLocaleString()}</span>
                  </div>
                </div>
              ))}

              {(!testResults || testResults.length === 0) && !selectedTarget && (
                <div className="text-center py-12 text-slate-500">
                  Select a target to view test results
                </div>
              )}
            </div>
          </Card>
        )}
      </div>
    </Layout>
  );
};

export default LlmTestingPage;
