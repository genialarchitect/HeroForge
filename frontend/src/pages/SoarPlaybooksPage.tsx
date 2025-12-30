import React, { useState, useEffect } from 'react';
import {
  Workflow,
  Play,
  Pause,
  Plus,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Copy,
  Edit,
  Trash2,
  Eye,
  Settings,
  Zap,
  GitBranch,
  ArrowRight,
  Check,
  X,
  ChevronDown,
  ChevronRight
} from 'lucide-react';
import { toast } from 'react-toastify';
import Layout from '../components/layout/Layout';

// Types
interface SoarPlaybook {
  id: string;
  name: string;
  description?: string;
  category: string;
  trigger_type: string;
  status: string;
  version: number;
  run_count: number;
  success_rate?: number;
  avg_duration_seconds?: number;
  last_run_at?: string;
  created_at: string;
}

interface SoarAction {
  id: string;
  name: string;
  display_name: string;
  description?: string;
  category: string;
  action_type: string;
  risk_level: string;
  requires_approval: boolean;
}

interface SoarRun {
  id: string;
  playbook_id: string;
  playbook_name: string;
  trigger_type: string;
  status: string;
  current_step: number;
  total_steps: number;
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
  initiated_by?: string;
}

interface SoarApproval {
  id: string;
  run_id: string;
  playbook_name: string;
  step_name: string;
  status: string;
  required_approvals: number;
  current_approvals: number;
  created_at: string;
}

interface SoarIntegration {
  id: string;
  name: string;
  integration_type: string;
  vendor?: string;
  status: string;
  last_test_at?: string;
}

// Mock API
const soarAPI = {
  getPlaybooks: async (): Promise<SoarPlaybook[]> => {
    return [
      { id: '1', name: 'Malicious IP Response', description: 'Auto-block malicious IPs and create tickets', category: 'incident_response', trigger_type: 'alert', status: 'active', version: 3, run_count: 145, success_rate: 94.5, avg_duration_seconds: 45, last_run_at: new Date().toISOString(), created_at: new Date().toISOString() },
      { id: '2', name: 'Phishing Email Analysis', description: 'Extract IOCs and block malicious domains', category: 'enrichment', trigger_type: 'manual', status: 'active', version: 2, run_count: 87, success_rate: 98.2, avg_duration_seconds: 120, last_run_at: new Date().toISOString(), created_at: new Date().toISOString() },
      { id: '3', name: 'Vulnerability Remediation', description: 'Create JIRA tickets for critical vulnerabilities', category: 'remediation', trigger_type: 'schedule', status: 'active', version: 1, run_count: 52, success_rate: 100, avg_duration_seconds: 15, last_run_at: new Date().toISOString(), created_at: new Date().toISOString() },
      { id: '4', name: 'User Account Lockout', description: 'Lock account and notify security team', category: 'containment', trigger_type: 'alert', status: 'draft', version: 1, run_count: 0, created_at: new Date().toISOString() },
    ];
  },
  getActions: async (): Promise<SoarAction[]> => {
    return [
      { id: '1', name: 'ip_lookup', display_name: 'IP Lookup', description: 'Get IP reputation and geolocation', category: 'enrichment', action_type: 'builtin', risk_level: 'low', requires_approval: false },
      { id: '2', name: 'domain_lookup', display_name: 'Domain Lookup', description: 'Get domain WHOIS and DNS info', category: 'enrichment', action_type: 'builtin', risk_level: 'low', requires_approval: false },
      { id: '3', name: 'block_ip', display_name: 'Block IP', description: 'Block IP at firewall', category: 'containment', action_type: 'api', risk_level: 'high', requires_approval: true },
      { id: '4', name: 'disable_user', display_name: 'Disable User Account', description: 'Disable user in Active Directory', category: 'containment', action_type: 'api', risk_level: 'high', requires_approval: true },
      { id: '5', name: 'send_email', display_name: 'Send Email', description: 'Send notification email', category: 'notification', action_type: 'builtin', risk_level: 'low', requires_approval: false },
      { id: '6', name: 'send_slack', display_name: 'Send Slack Message', description: 'Send message to Slack channel', category: 'notification', action_type: 'builtin', risk_level: 'low', requires_approval: false },
      { id: '7', name: 'create_ticket', display_name: 'Create Ticket', description: 'Create ticket in JIRA/ServiceNow', category: 'remediation', action_type: 'api', risk_level: 'low', requires_approval: false },
      { id: '8', name: 'http_request', display_name: 'HTTP Request', description: 'Make HTTP API call', category: 'utility', action_type: 'builtin', risk_level: 'medium', requires_approval: false },
    ];
  },
  getRuns: async (): Promise<SoarRun[]> => {
    return [
      { id: '1', playbook_id: '1', playbook_name: 'Malicious IP Response', trigger_type: 'alert', status: 'completed', current_step: 5, total_steps: 5, started_at: new Date().toISOString(), completed_at: new Date().toISOString(), duration_seconds: 42, initiated_by: 'Alert: Malicious IP Detected' },
      { id: '2', playbook_id: '2', playbook_name: 'Phishing Email Analysis', trigger_type: 'manual', status: 'running', current_step: 3, total_steps: 7, started_at: new Date().toISOString(), initiated_by: 'admin@example.com' },
      { id: '3', playbook_id: '1', playbook_name: 'Malicious IP Response', trigger_type: 'alert', status: 'waiting_approval', current_step: 4, total_steps: 5, started_at: new Date().toISOString(), initiated_by: 'Alert: Suspicious Traffic' },
      { id: '4', playbook_id: '3', playbook_name: 'Vulnerability Remediation', trigger_type: 'schedule', status: 'failed', current_step: 2, total_steps: 3, started_at: new Date().toISOString(), completed_at: new Date().toISOString(), duration_seconds: 8, initiated_by: 'Scheduled: Daily 9AM' },
    ];
  },
  getApprovals: async (): Promise<SoarApproval[]> => {
    return [
      { id: '1', run_id: '3', playbook_name: 'Malicious IP Response', step_name: 'Block IP at Firewall', status: 'pending', required_approvals: 1, current_approvals: 0, created_at: new Date().toISOString() },
    ];
  },
  getIntegrations: async (): Promise<SoarIntegration[]> => {
    return [
      { id: '1', name: 'Splunk SIEM', integration_type: 'siem', vendor: 'splunk', status: 'connected', last_test_at: new Date().toISOString() },
      { id: '2', name: 'JIRA', integration_type: 'ticketing', vendor: 'atlassian', status: 'connected', last_test_at: new Date().toISOString() },
      { id: '3', name: 'Slack', integration_type: 'notification', vendor: 'slack', status: 'connected', last_test_at: new Date().toISOString() },
      { id: '4', name: 'Palo Alto Firewall', integration_type: 'firewall', vendor: 'palo_alto', status: 'disconnected' },
    ];
  },
  runPlaybook: async (id: string): Promise<void> => {
    await new Promise(resolve => setTimeout(resolve, 500));
  },
  approveStep: async (approvalId: string): Promise<void> => {
    await new Promise(resolve => setTimeout(resolve, 500));
  },
  rejectStep: async (approvalId: string): Promise<void> => {
    await new Promise(resolve => setTimeout(resolve, 500));
  }
};

const SoarPlaybooksPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'playbooks' | 'actions' | 'runs' | 'approvals' | 'integrations'>('playbooks');
  const [playbooks, setPlaybooks] = useState<SoarPlaybook[]>([]);
  const [actions, setActions] = useState<SoarAction[]>([]);
  const [runs, setRuns] = useState<SoarRun[]>([]);
  const [approvals, setApprovals] = useState<SoarApproval[]>([]);
  const [integrations, setIntegrations] = useState<SoarIntegration[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedPlaybook, setExpandedPlaybook] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [playbooksData, actionsData, runsData, approvalsData, integrationsData] = await Promise.all([
        soarAPI.getPlaybooks(),
        soarAPI.getActions(),
        soarAPI.getRuns(),
        soarAPI.getApprovals(),
        soarAPI.getIntegrations()
      ]);
      setPlaybooks(playbooksData);
      setActions(actionsData);
      setRuns(runsData);
      setApprovals(approvalsData);
      setIntegrations(integrationsData);
    } catch (error) {
      toast.error('Failed to load SOAR data');
    } finally {
      setLoading(false);
    }
  };

  const handleRunPlaybook = async (playbook: SoarPlaybook) => {
    try {
      toast.info(`Starting ${playbook.name}...`);
      await soarAPI.runPlaybook(playbook.id);
      toast.success('Playbook started successfully');
      loadData();
    } catch (error) {
      toast.error('Failed to start playbook');
    }
  };

  const handleApprove = async (approval: SoarApproval) => {
    try {
      await soarAPI.approveStep(approval.id);
      toast.success('Step approved');
      loadData();
    } catch (error) {
      toast.error('Failed to approve step');
    }
  };

  const handleReject = async (approval: SoarApproval) => {
    try {
      await soarAPI.rejectStep(approval.id);
      toast.success('Step rejected');
      loadData();
    } catch (error) {
      toast.error('Failed to reject step');
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-5 w-5 text-green-400" />;
      case 'failed': return <XCircle className="h-5 w-5 text-red-400" />;
      case 'running': return <RefreshCw className="h-5 w-5 text-cyan-400 animate-spin" />;
      case 'waiting_approval': return <AlertTriangle className="h-5 w-5 text-yellow-400" />;
      case 'pending': return <Clock className="h-5 w-5 text-gray-400" />;
      default: return <Clock className="h-5 w-5 text-gray-400" />;
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'enrichment': return 'bg-blue-600';
      case 'containment': return 'bg-red-600';
      case 'remediation': return 'bg-green-600';
      case 'notification': return 'bg-purple-600';
      case 'incident_response': return 'bg-orange-600';
      case 'utility': return 'bg-gray-600';
      default: return 'bg-gray-600';
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'high': return 'text-red-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <Layout>
      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Workflow className="h-8 w-8 text-cyan-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">SOAR Playbooks</h1>
              <p className="text-gray-400">Security Orchestration, Automation, and Response</p>
            </div>
          </div>
          <div className="flex gap-2">
            {approvals.length > 0 && (
              <button
                onClick={() => setActiveTab('approvals')}
                className="flex items-center gap-2 px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-500"
              >
                <AlertTriangle className="h-4 w-4" />
                {approvals.length} Pending Approval
              </button>
            )}
            <button className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500">
              <Plus className="h-4 w-4" />
              Create Playbook
            </button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-white">{playbooks.filter(p => p.status === 'active').length}</div>
            <div className="text-gray-400 text-sm">Active Playbooks</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-cyan-400">{runs.filter(r => r.status === 'running').length}</div>
            <div className="text-gray-400 text-sm">Running</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-green-400">{runs.filter(r => r.status === 'completed').length}</div>
            <div className="text-gray-400 text-sm">Completed Today</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-yellow-400">{approvals.length}</div>
            <div className="text-gray-400 text-sm">Pending Approvals</div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 border-b border-gray-700">
          {['playbooks', 'actions', 'runs', 'approvals', 'integrations'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab as typeof activeTab)}
              className={`px-4 py-2 font-medium capitalize ${
                activeTab === tab
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {tab}
              {tab === 'approvals' && approvals.length > 0 && (
                <span className="ml-2 px-2 py-0.5 bg-yellow-600 text-white text-xs rounded-full">
                  {approvals.length}
                </span>
              )}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
          </div>
        ) : (
          <>
            {/* Playbooks Tab */}
            {activeTab === 'playbooks' && (
              <div className="grid gap-4">
                {playbooks.map((playbook) => (
                  <div key={playbook.id} className="bg-gray-800 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <button
                          onClick={() => setExpandedPlaybook(expandedPlaybook === playbook.id ? null : playbook.id)}
                          className="text-gray-400 hover:text-white"
                        >
                          {expandedPlaybook === playbook.id ? (
                            <ChevronDown className="h-5 w-5" />
                          ) : (
                            <ChevronRight className="h-5 w-5" />
                          )}
                        </button>
                        <Workflow className="h-6 w-6 text-cyan-400" />
                        <div>
                          <h3 className="text-lg font-medium text-white flex items-center gap-2">
                            {playbook.name}
                            <span className={`text-xs px-2 py-0.5 rounded ${
                              playbook.status === 'active' ? 'bg-green-600' : 'bg-gray-600'
                            } text-white`}>
                              {playbook.status}
                            </span>
                          </h3>
                          <p className="text-gray-400 text-sm">{playbook.description}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right text-sm">
                          <div className="text-white">{playbook.run_count} runs</div>
                          {playbook.success_rate && (
                            <div className="text-green-400">{playbook.success_rate}% success</div>
                          )}
                        </div>
                        <div className="flex gap-2">
                          <button
                            onClick={() => handleRunPlaybook(playbook)}
                            className="p-2 bg-cyan-600 rounded-lg hover:bg-cyan-500"
                            disabled={playbook.status !== 'active'}
                          >
                            <Play className="h-4 w-4 text-white" />
                          </button>
                          <button className="p-2 bg-gray-700 rounded-lg hover:bg-gray-600">
                            <Edit className="h-4 w-4 text-gray-300" />
                          </button>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-4 mt-3">
                      <span className={`px-2 py-1 rounded text-xs text-white ${getCategoryColor(playbook.category)}`}>
                        {playbook.category}
                      </span>
                      <span className="text-gray-400 text-sm flex items-center gap-1">
                        <Zap className="h-3 w-3" />
                        {playbook.trigger_type}
                      </span>
                      <span className="text-gray-400 text-sm">v{playbook.version}</span>
                      {playbook.avg_duration_seconds && (
                        <span className="text-gray-400 text-sm">
                          ~{playbook.avg_duration_seconds}s avg
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Actions Tab */}
            {activeTab === 'actions' && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {actions.map((action) => (
                  <div key={action.id} className="bg-gray-800 rounded-lg p-4">
                    <div className="flex items-start justify-between">
                      <div>
                        <h3 className="text-white font-medium">{action.display_name}</h3>
                        <p className="text-gray-400 text-sm mt-1">{action.description}</p>
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-2 mt-3">
                      <span className={`px-2 py-1 rounded text-xs text-white ${getCategoryColor(action.category)}`}>
                        {action.category}
                      </span>
                      <span className={`text-xs ${getRiskColor(action.risk_level)}`}>
                        {action.risk_level} risk
                      </span>
                      {action.requires_approval && (
                        <span className="px-2 py-1 bg-yellow-600 text-white text-xs rounded">
                          Requires Approval
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Runs Tab */}
            {activeTab === 'runs' && (
              <div className="bg-gray-800 rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-700">
                    <tr>
                      <th className="px-4 py-3 text-left text-gray-300">Status</th>
                      <th className="px-4 py-3 text-left text-gray-300">Playbook</th>
                      <th className="px-4 py-3 text-left text-gray-300">Trigger</th>
                      <th className="px-4 py-3 text-left text-gray-300">Progress</th>
                      <th className="px-4 py-3 text-left text-gray-300">Initiated By</th>
                      <th className="px-4 py-3 text-left text-gray-300">Duration</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runs.map((run) => (
                      <tr key={run.id} className="border-t border-gray-700 hover:bg-gray-750">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            {getStatusIcon(run.status)}
                            <span className="text-white capitalize">{run.status.replace('_', ' ')}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-white">{run.playbook_name}</td>
                        <td className="px-4 py-3 text-gray-300 capitalize">{run.trigger_type}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="w-24 bg-gray-700 rounded-full h-2">
                              <div
                                className="bg-cyan-500 h-2 rounded-full"
                                style={{ width: `${(run.current_step / run.total_steps) * 100}%` }}
                              />
                            </div>
                            <span className="text-gray-400 text-sm">
                              {run.current_step}/{run.total_steps}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-gray-400 text-sm">{run.initiated_by}</td>
                        <td className="px-4 py-3 text-gray-300">
                          {run.duration_seconds ? `${run.duration_seconds}s` : '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Approvals Tab */}
            {activeTab === 'approvals' && (
              <div className="space-y-4">
                {approvals.length === 0 ? (
                  <div className="bg-gray-800 rounded-lg p-8 text-center">
                    <CheckCircle className="h-12 w-12 text-green-400 mx-auto mb-4" />
                    <h3 className="text-white text-lg font-medium">No Pending Approvals</h3>
                    <p className="text-gray-400 mt-2">All playbook steps are up to date</p>
                  </div>
                ) : (
                  approvals.map((approval) => (
                    <div key={approval.id} className="bg-gray-800 rounded-lg p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-white font-medium">{approval.playbook_name}</h3>
                          <p className="text-gray-400 text-sm mt-1">
                            Step: {approval.step_name}
                          </p>
                          <p className="text-gray-500 text-xs mt-2">
                            {approval.current_approvals}/{approval.required_approvals} approvals
                          </p>
                        </div>
                        <div className="flex gap-2">
                          <button
                            onClick={() => handleApprove(approval)}
                            className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-500"
                          >
                            <Check className="h-4 w-4" />
                            Approve
                          </button>
                          <button
                            onClick={() => handleReject(approval)}
                            className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-500"
                          >
                            <X className="h-4 w-4" />
                            Reject
                          </button>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Integrations Tab */}
            {activeTab === 'integrations' && (
              <div className="grid gap-4">
                {integrations.map((integration) => (
                  <div key={integration.id} className="bg-gray-800 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`w-3 h-3 rounded-full ${
                          integration.status === 'connected' ? 'bg-green-400' : 'bg-red-400'
                        }`} />
                        <div>
                          <h3 className="text-white font-medium">{integration.name}</h3>
                          <p className="text-gray-400 text-sm capitalize">
                            {integration.integration_type} • {integration.vendor || 'Custom'}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <span className={`text-sm ${
                          integration.status === 'connected' ? 'text-green-400' : 'text-red-400'
                        }`}>
                          {integration.status}
                        </span>
                        <button className="p-2 bg-gray-700 rounded-lg hover:bg-gray-600">
                          <Settings className="h-4 w-4 text-gray-300" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </Layout>
  );
};

export default SoarPlaybooksPage;
