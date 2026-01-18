import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  MessageSquare,
  Play,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  ChevronDown,
  ChevronUp,
  User,
  Bot,
  RefreshCw,
} from 'lucide-react';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import LoadingSpinner from '../ui/LoadingSpinner';
import {
  aiSecurityAPI,
  ConversationTest,
  ConversationTestResult,
  LLMTarget,
} from '../../services/api';

interface ConversationTestPanelProps {
  targets: LLMTarget[];
}

const ConversationTestPanel: React.FC<ConversationTestPanelProps> = ({ targets }) => {
  const [selectedTarget, setSelectedTarget] = useState<string>('');
  const [selectedTest, setSelectedTest] = useState<string>('');
  const [expandedTest, setExpandedTest] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<ConversationTestResult | null>(null);
  const queryClient = useQueryClient();

  // Fetch conversation tests
  const { data: conversationTests, isLoading: testsLoading } = useQuery<ConversationTest[]>({
    queryKey: ['conversation-tests'],
    queryFn: async () => {
      try {
        const response = await aiSecurityAPI.getConversationTests({ builtin_only: true });
        return response.data;
      } catch {
        return [];
      }
    },
  });

  // Run conversation test mutation
  const runTestMutation = useMutation({
    mutationFn: async (data: { target_id: string; test_id: string }) => {
      const response = await aiSecurityAPI.startConversationTest(data);
      return response.data;
    },
    onSuccess: (result) => {
      setTestResult(result);
      queryClient.invalidateQueries({ queryKey: ['llm-test-runs'] });
      if (result.final_status === 'failed') {
        toast.warning(`Vulnerability detected at turn ${result.vulnerability_detected_at_turn}`);
      } else if (result.final_status === 'passed') {
        toast.success('Test passed - no vulnerabilities detected');
      } else {
        toast.info(`Test completed with status: ${result.final_status}`);
      }
    },
    onError: () => {
      toast.error('Failed to run conversation test');
    },
  });

  const handleRunTest = () => {
    if (!selectedTarget) {
      toast.error('Please select a target');
      return;
    }
    if (!selectedTest) {
      toast.error('Please select a test');
      return;
    }
    setTestResult(null);
    runTestMutation.mutate({ target_id: selectedTarget, test_id: selectedTest });
  };

  const getCategoryColor = (category: string) => {
    const colors: Record<string, string> = {
      prompt_injection: 'text-red-400',
      jailbreak: 'text-orange-400',
      data_extraction: 'text-yellow-400',
      context_manipulation: 'text-purple-400',
      role_confusion: 'text-blue-400',
      encoding: 'text-cyan-400',
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

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'passed':
        return <CheckCircle className="h-5 w-5 text-green-400" />;
      case 'failed':
        return <XCircle className="h-5 w-5 text-red-400" />;
      case 'aborted':
        return <AlertTriangle className="h-5 w-5 text-yellow-400" />;
      default:
        return <Clock className="h-5 w-5 text-slate-400" />;
    }
  };

  // Group tests by category
  const testsByCategory = conversationTests?.reduce((acc, test) => {
    const category = test.category;
    if (!acc[category]) {
      acc[category] = [];
    }
    acc[category].push(test);
    return acc;
  }, {} as Record<string, ConversationTest[]>) || {};

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Test Selection */}
      <div className="space-y-4">
        <Card>
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <MessageSquare className="h-5 w-5 text-primary" />
            Multi-Turn Conversation Tests
          </h3>

          {/* Target Selection */}
          <div className="mb-4">
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Select Target
            </label>
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
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

          {/* Test List */}
          {testsLoading ? (
            <div className="flex items-center justify-center py-8">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="space-y-4 max-h-[500px] overflow-y-auto">
              {Object.entries(testsByCategory).map(([category, tests]) => (
                <div key={category}>
                  <h4 className={`text-sm font-medium mb-2 ${getCategoryColor(category)}`}>
                    {category.replace(/_/g, ' ').toUpperCase()} ({tests.length})
                  </h4>
                  <div className="space-y-2">
                    {tests.map((test) => (
                      <div
                        key={test.id}
                        className={`p-3 rounded-lg border transition-colors cursor-pointer ${
                          selectedTest === test.id
                            ? 'bg-primary/20 border-primary'
                            : 'bg-dark-bg border-dark-border hover:border-slate-600'
                        }`}
                        onClick={() => setSelectedTest(test.id)}
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-white">{test.name}</span>
                              <Badge variant={getSeverityBadge(test.severity)} className="text-xs">
                                {test.severity}
                              </Badge>
                            </div>
                            <p className="text-sm text-slate-400 mt-1 line-clamp-2">
                              {test.description}
                            </p>
                            <div className="flex items-center gap-2 mt-2 text-xs text-slate-500">
                              <span>{test.turns.length} turns</span>
                              {test.is_builtin && (
                                <Badge variant="info" className="text-xs">Built-in</Badge>
                              )}
                            </div>
                          </div>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setExpandedTest(expandedTest === test.id ? null : test.id);
                            }}
                            className="p-1 text-slate-400 hover:text-white"
                          >
                            {expandedTest === test.id ? (
                              <ChevronUp className="h-4 w-4" />
                            ) : (
                              <ChevronDown className="h-4 w-4" />
                            )}
                          </button>
                        </div>

                        {/* Expanded Turn Preview */}
                        {expandedTest === test.id && (
                          <div className="mt-3 pt-3 border-t border-dark-border">
                            <div className="text-xs text-slate-500 mb-2">Turn Preview:</div>
                            <div className="space-y-2 max-h-40 overflow-y-auto">
                              {test.turns.slice(0, 3).map((turn, idx) => (
                                <div
                                  key={idx}
                                  className="flex items-start gap-2 text-sm"
                                >
                                  {turn.role === 'user' ? (
                                    <User className="h-4 w-4 text-blue-400 mt-0.5 shrink-0" />
                                  ) : (
                                    <Bot className="h-4 w-4 text-green-400 mt-0.5 shrink-0" />
                                  )}
                                  <span className="text-slate-300 line-clamp-2">
                                    {turn.content.substring(0, 100)}...
                                  </span>
                                </div>
                              ))}
                              {test.turns.length > 3 && (
                                <div className="text-xs text-slate-500">
                                  + {test.turns.length - 3} more turns
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Run Button */}
          <div className="mt-4 pt-4 border-t border-dark-border">
            <Button
              variant="primary"
              className="w-full"
              onClick={handleRunTest}
              loading={runTestMutation.isPending}
              disabled={!selectedTarget || !selectedTest}
            >
              <Play className="h-4 w-4 mr-2" />
              Run Conversation Test
            </Button>
          </div>
        </Card>
      </div>

      {/* Test Results */}
      <Card>
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          {runTestMutation.isPending ? (
            <RefreshCw className="h-5 w-5 text-primary animate-spin" />
          ) : (
            <MessageSquare className="h-5 w-5 text-primary" />
          )}
          Conversation Transcript
        </h3>

        {runTestMutation.isPending && (
          <div className="flex flex-col items-center justify-center py-12">
            <LoadingSpinner />
            <p className="text-slate-400 mt-4">Running multi-turn conversation test...</p>
            <p className="text-sm text-slate-500 mt-1">This may take a moment</p>
          </div>
        )}

        {!runTestMutation.isPending && !testResult && (
          <div className="text-center py-12 text-slate-500">
            <MessageSquare className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>Select a test and run it to see the conversation transcript</p>
          </div>
        )}

        {testResult && (
          <div className="space-y-4">
            {/* Result Summary */}
            <div className="flex items-center justify-between p-4 bg-dark-bg rounded-lg border border-dark-border">
              <div className="flex items-center gap-3">
                {getStatusIcon(testResult.final_status)}
                <div>
                  <div className="font-medium text-white">{testResult.test_name}</div>
                  <div className="text-sm text-slate-400">
                    {testResult.turns_executed.length} turns executed
                  </div>
                </div>
              </div>
              <div className="text-right">
                <Badge
                  variant={testResult.final_status === 'passed' ? 'success' : 'danger'}
                >
                  {testResult.final_status}
                </Badge>
                <div className="text-xs text-slate-500 mt-1">
                  Confidence: {(testResult.overall_confidence * 100).toFixed(0)}%
                </div>
              </div>
            </div>

            {/* Vulnerability Alert */}
            {testResult.vulnerability_detected_at_turn !== undefined && (
              <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-red-400 mt-0.5" />
                  <div>
                    <div className="font-medium text-red-400">
                      Vulnerability Detected at Turn {testResult.vulnerability_detected_at_turn + 1}
                    </div>
                    {testResult.remediation && (
                      <p className="text-sm text-slate-300 mt-1">{testResult.remediation}</p>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Conversation History */}
            <div className="space-y-3 max-h-[400px] overflow-y-auto">
              {testResult.turns_executed.map((turn, idx) => (
                <div key={idx} className="space-y-2">
                  {/* User Message */}
                  <div className="flex items-start gap-3">
                    <div className="p-2 bg-blue-500/20 rounded-lg">
                      <User className="h-4 w-4 text-blue-400" />
                    </div>
                    <div className="flex-1 p-3 bg-blue-500/10 rounded-lg border border-blue-500/20">
                      <div className="text-xs text-blue-400 mb-1">Turn {turn.turn_number + 1} - User</div>
                      <p className="text-sm text-slate-300">{turn.prompt_sent}</p>
                    </div>
                  </div>

                  {/* Assistant Response */}
                  <div className="flex items-start gap-3 ml-6">
                    <div className="p-2 bg-green-500/20 rounded-lg">
                      <Bot className="h-4 w-4 text-green-400" />
                    </div>
                    <div className="flex-1 p-3 bg-green-500/10 rounded-lg border border-green-500/20">
                      <div className="text-xs text-green-400 mb-1">Assistant</div>
                      <p className="text-sm text-slate-300">{turn.response_received}</p>

                      {/* Indicators */}
                      {turn.success_indicators_matched.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {turn.success_indicators_matched.map((indicator, i) => (
                            <Badge key={i} variant="warning" className="text-xs">
                              {indicator}
                            </Badge>
                          ))}
                        </div>
                      )}

                      {turn.abort_triggered && (
                        <Badge variant="danger" className="mt-2 text-xs">
                          Abort Triggered
                        </Badge>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Stats */}
            <div className="grid grid-cols-3 gap-4 pt-4 border-t border-dark-border">
              <div className="text-center">
                <div className="text-2xl font-bold text-white">
                  {testResult.turns_executed.length}
                </div>
                <div className="text-xs text-slate-500">Turns</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-white">
                  {testResult.duration_ms}ms
                </div>
                <div className="text-xs text-slate-500">Duration</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-white">
                  {(testResult.overall_confidence * 100).toFixed(0)}%
                </div>
                <div className="text-xs text-slate-500">Confidence</div>
              </div>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
};

export default ConversationTestPanel;
