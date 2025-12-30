import React, { useState, useEffect } from 'react';
import {
  GitBranch,
  Play,
  Settings,
  Plus,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Copy,
  Download,
  Trash2,
  Edit,
  FileCode,
  GitPullRequest,
  Shield,
  Code
} from 'lucide-react';
import { toast } from 'react-toastify';
import Layout from '../components/layout/Layout';

// Types
interface CicdPipeline {
  id: string;
  name: string;
  platform: 'github_actions' | 'gitlab_ci' | 'jenkins' | 'azure_devops';
  repository_url?: string;
  enabled: boolean;
  last_run_at?: string;
  last_run_status?: string;
  customer_id?: string;
  engagement_id?: string;
  created_at: string;
}

interface CicdRun {
  id: string;
  pipeline_id: string;
  branch: string;
  commit_sha: string;
  trigger_type: string;
  pr_number?: number;
  status: string;
  gate_status?: string;
  findings_new: number;
  findings_fixed: number;
  findings_total: number;
  duration_seconds?: number;
  started_at: string;
  completed_at?: string;
}

interface CicdPolicy {
  id: string;
  name: string;
  description?: string;
  policy_type: string;
  severity_threshold?: string;
  max_new_findings?: number;
  block_on_critical: boolean;
  enabled: boolean;
}

interface IdeSettings {
  scan_on_save: boolean;
  scan_on_open: boolean;
  show_inline_hints: boolean;
  severity_filter: string[];
  excluded_paths: string[];
  custom_rules_enabled: boolean;
}

// Mock API
const cicdAPI = {
  getPipelines: async (): Promise<CicdPipeline[]> => {
    return [
      { id: '1', name: 'Main Build', platform: 'github_actions', repository_url: 'https://github.com/org/repo', enabled: true, last_run_at: new Date().toISOString(), last_run_status: 'passed', created_at: new Date().toISOString() },
      { id: '2', name: 'Security Scan', platform: 'gitlab_ci', repository_url: 'https://gitlab.com/org/repo', enabled: true, last_run_at: new Date().toISOString(), last_run_status: 'failed', created_at: new Date().toISOString() },
    ];
  },
  getRuns: async (pipelineId?: string): Promise<CicdRun[]> => {
    return [
      { id: '1', pipeline_id: '1', branch: 'main', commit_sha: 'abc1234', trigger_type: 'push', status: 'completed', gate_status: 'passed', findings_new: 0, findings_fixed: 3, findings_total: 12, duration_seconds: 145, started_at: new Date().toISOString(), completed_at: new Date().toISOString() },
      { id: '2', pipeline_id: '1', branch: 'feature/auth', commit_sha: 'def5678', trigger_type: 'pr', pr_number: 42, status: 'completed', gate_status: 'failed', findings_new: 5, findings_fixed: 0, findings_total: 17, duration_seconds: 178, started_at: new Date().toISOString(), completed_at: new Date().toISOString() },
      { id: '3', pipeline_id: '2', branch: 'develop', commit_sha: 'ghi9012', trigger_type: 'schedule', status: 'running', findings_new: 0, findings_fixed: 0, findings_total: 0, started_at: new Date().toISOString() },
    ];
  },
  getPolicies: async (): Promise<CicdPolicy[]> => {
    return [
      { id: '1', name: 'Block Critical', description: 'Block merges when critical vulnerabilities found', policy_type: 'block_merge', severity_threshold: 'critical', block_on_critical: true, enabled: true },
      { id: '2', name: 'Max 5 New Findings', description: 'Block if more than 5 new findings', policy_type: 'quality_gate', max_new_findings: 5, block_on_critical: true, enabled: true },
    ];
  },
  getTemplate: async (platform: string): Promise<string> => {
    const templates: Record<string, string> = {
      github_actions: `name: Genial Architect Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Scan
        env:
          HEROFORGE_URL: \${{ secrets.HEROFORGE_URL }}
          HEROFORGE_TOKEN: \${{ secrets.HEROFORGE_TOKEN }}
        run: |
          curl -X POST "\$HEROFORGE_URL/api/cicd/webhook/github_actions" \\
            -H "Authorization: Bearer \$HEROFORGE_TOKEN" \\
            -H "Content-Type: application/json" \\
            -d '{
              "repository": "\${{ github.repository }}",
              "branch": "\${{ github.ref_name }}",
              "commit": "\${{ github.sha }}",
              "pr_number": \${{ github.event.pull_request.number || 'null' }}
            }'`,
      gitlab_ci: `stages:
  - security

security-scan:
  stage: security
  image: curlimages/curl:latest
  script:
    - |
      curl -X POST "\$HEROFORGE_URL/api/cicd/webhook/gitlab_ci" \\
        -H "Authorization: Bearer \$HEROFORGE_TOKEN" \\
        -H "Content-Type: application/json" \\
        -d "{
          \\"repository\\": \\"\$CI_PROJECT_PATH\\",
          \\"branch\\": \\"\$CI_COMMIT_REF_NAME\\",
          \\"commit\\": \\"\$CI_COMMIT_SHA\\",
          \\"mr_iid\\": \\"\$CI_MERGE_REQUEST_IID\\"
        }"
  rules:
    - if: '\$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '\$CI_COMMIT_BRANCH'`,
      jenkins: `pipeline {
    agent any

    environment {
        HEROFORGE_URL = credentials('heroforge-url')
        HEROFORGE_TOKEN = credentials('heroforge-token')
    }

    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    curl -X POST "\$HEROFORGE_URL/api/cicd/webhook/jenkins" \\
                        -H "Authorization: Bearer \$HEROFORGE_TOKEN" \\
                        -H "Content-Type: application/json" \\
                        -d "{
                            \\"repository\\": \\"\$GIT_URL\\",
                            \\"branch\\": \\"\$GIT_BRANCH\\",
                            \\"commit\\": \\"\$GIT_COMMIT\\",
                            \\"build_number\\": \\"\$BUILD_NUMBER\\"
                        }"
                '''
            }
        }
    }
}`,
      azure_devops: `trigger:
  - main
  - develop

pool:
  vmImage: 'ubuntu-latest'

stages:
  - stage: Security
    jobs:
      - job: Scan
        steps:
          - script: |
              curl -X POST "\$(HEROFORGE_URL)/api/cicd/webhook/azure_devops" \\
                -H "Authorization: Bearer \$(HEROFORGE_TOKEN)" \\
                -H "Content-Type: application/json" \\
                -d '{
                  "repository": "\$(Build.Repository.Name)",
                  "branch": "\$(Build.SourceBranchName)",
                  "commit": "\$(Build.SourceVersion)",
                  "pr_id": "\$(System.PullRequest.PullRequestId)"
                }'
            displayName: 'Run Genial Architect Scan'`
    };
    return templates[platform] || '';
  },
  getIdeSettings: async (): Promise<IdeSettings> => {
    return {
      scan_on_save: true,
      scan_on_open: false,
      show_inline_hints: true,
      severity_filter: ['critical', 'high', 'medium'],
      excluded_paths: ['node_modules', 'target', 'dist'],
      custom_rules_enabled: true
    };
  }
};

const CicdIntegrationPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'pipelines' | 'runs' | 'policies' | 'templates' | 'ide'>('pipelines');
  const [pipelines, setPipelines] = useState<CicdPipeline[]>([]);
  const [runs, setRuns] = useState<CicdRun[]>([]);
  const [policies, setPolicies] = useState<CicdPolicy[]>([]);
  const [ideSettings, setIdeSettings] = useState<IdeSettings | null>(null);
  const [selectedPlatform, setSelectedPlatform] = useState<string>('github_actions');
  const [templateContent, setTemplateContent] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    if (activeTab === 'templates') {
      loadTemplate(selectedPlatform);
    }
  }, [selectedPlatform, activeTab]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [pipelinesData, runsData, policiesData, ideData] = await Promise.all([
        cicdAPI.getPipelines(),
        cicdAPI.getRuns(),
        cicdAPI.getPolicies(),
        cicdAPI.getIdeSettings()
      ]);
      setPipelines(pipelinesData);
      setRuns(runsData);
      setPolicies(policiesData);
      setIdeSettings(ideData);
    } catch (error) {
      toast.error('Failed to load CI/CD data');
    } finally {
      setLoading(false);
    }
  };

  const loadTemplate = async (platform: string) => {
    try {
      const template = await cicdAPI.getTemplate(platform);
      setTemplateContent(template);
    } catch (error) {
      toast.error('Failed to load template');
    }
  };

  const copyTemplate = () => {
    navigator.clipboard.writeText(templateContent);
    toast.success('Template copied to clipboard');
  };

  const getPlatformIcon = (platform: string) => {
    switch (platform) {
      case 'github_actions': return '🐙';
      case 'gitlab_ci': return '🦊';
      case 'jenkins': return '🔧';
      case 'azure_devops': return '☁️';
      default: return '📦';
    }
  };

  const getPlatformName = (platform: string) => {
    switch (platform) {
      case 'github_actions': return 'GitHub Actions';
      case 'gitlab_ci': return 'GitLab CI';
      case 'jenkins': return 'Jenkins';
      case 'azure_devops': return 'Azure DevOps';
      default: return platform;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
      case 'passed': return <CheckCircle className="h-5 w-5 text-green-400" />;
      case 'failed': return <XCircle className="h-5 w-5 text-red-400" />;
      case 'running': return <RefreshCw className="h-5 w-5 text-cyan-400 animate-spin" />;
      case 'pending': return <Clock className="h-5 w-5 text-yellow-400" />;
      default: return <Clock className="h-5 w-5 text-gray-400" />;
    }
  };

  const getGateStatusBadge = (gateStatus?: string) => {
    if (!gateStatus) return null;
    switch (gateStatus) {
      case 'passed': return <span className="px-2 py-1 bg-green-600 text-white text-xs rounded">Gate Passed</span>;
      case 'failed': return <span className="px-2 py-1 bg-red-600 text-white text-xs rounded">Gate Failed</span>;
      case 'warning': return <span className="px-2 py-1 bg-yellow-600 text-white text-xs rounded">Warning</span>;
      default: return null;
    }
  };

  return (
    <Layout>
      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <GitBranch className="h-8 w-8 text-cyan-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">CI/CD Integration</h1>
              <p className="text-gray-400">Pipeline security and IDE integration</p>
            </div>
          </div>
          <button className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500">
            <Plus className="h-4 w-4" />
            Add Pipeline
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 border-b border-gray-700">
          {['pipelines', 'runs', 'policies', 'templates', 'ide'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab as typeof activeTab)}
              className={`px-4 py-2 font-medium capitalize ${
                activeTab === tab
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {tab === 'ide' ? 'IDE Settings' : tab}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
          </div>
        ) : (
          <>
            {/* Pipelines Tab */}
            {activeTab === 'pipelines' && (
              <div className="grid gap-4">
                {pipelines.map((pipeline) => (
                  <div key={pipeline.id} className="bg-gray-800 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="text-2xl">{getPlatformIcon(pipeline.platform)}</span>
                        <div>
                          <h3 className="text-lg font-medium text-white">{pipeline.name}</h3>
                          <p className="text-gray-400 text-sm">
                            {getPlatformName(pipeline.platform)} • {pipeline.repository_url}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        {pipeline.last_run_status && getStatusIcon(pipeline.last_run_status)}
                        <label className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={pipeline.enabled}
                            className="rounded border-gray-600 bg-gray-700 text-cyan-500"
                            readOnly
                          />
                          <span className="text-gray-400 text-sm">Enabled</span>
                        </label>
                        <button className="p-2 hover:bg-gray-700 rounded">
                          <Settings className="h-4 w-4 text-gray-400" />
                        </button>
                      </div>
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
                      <th className="px-4 py-3 text-left text-gray-300">Branch</th>
                      <th className="px-4 py-3 text-left text-gray-300">Commit</th>
                      <th className="px-4 py-3 text-left text-gray-300">Trigger</th>
                      <th className="px-4 py-3 text-left text-gray-300">Findings</th>
                      <th className="px-4 py-3 text-left text-gray-300">Gate</th>
                      <th className="px-4 py-3 text-left text-gray-300">Duration</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runs.map((run) => (
                      <tr key={run.id} className="border-t border-gray-700 hover:bg-gray-750">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            {getStatusIcon(run.status)}
                            <span className="text-white capitalize">{run.status}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <GitBranch className="h-4 w-4 text-gray-400" />
                            <span className="text-white">{run.branch}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <code className="text-gray-300 bg-gray-700 px-2 py-1 rounded text-sm">
                            {run.commit_sha.substring(0, 7)}
                          </code>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            {run.trigger_type === 'pr' && <GitPullRequest className="h-4 w-4 text-cyan-400" />}
                            <span className="text-gray-300 capitalize">{run.trigger_type}</span>
                            {run.pr_number && <span className="text-gray-400">#{run.pr_number}</span>}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2 text-sm">
                            {run.findings_new > 0 && (
                              <span className="text-red-400">+{run.findings_new}</span>
                            )}
                            {run.findings_fixed > 0 && (
                              <span className="text-green-400">-{run.findings_fixed}</span>
                            )}
                            <span className="text-gray-400">({run.findings_total} total)</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">{getGateStatusBadge(run.gate_status)}</td>
                        <td className="px-4 py-3 text-gray-300">
                          {run.duration_seconds ? `${run.duration_seconds}s` : '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Policies Tab */}
            {activeTab === 'policies' && (
              <div className="grid gap-4">
                {policies.map((policy) => (
                  <div key={policy.id} className="bg-gray-800 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Shield className="h-6 w-6 text-cyan-400" />
                        <div>
                          <h3 className="text-lg font-medium text-white">{policy.name}</h3>
                          <p className="text-gray-400 text-sm">{policy.description}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <span className={`px-2 py-1 rounded text-xs ${
                          policy.enabled ? 'bg-green-600 text-white' : 'bg-gray-600 text-gray-300'
                        }`}>
                          {policy.enabled ? 'Active' : 'Inactive'}
                        </span>
                        <button className="p-2 hover:bg-gray-700 rounded">
                          <Edit className="h-4 w-4 text-gray-400" />
                        </button>
                      </div>
                    </div>
                    <div className="mt-4 flex flex-wrap gap-4 text-sm">
                      {policy.severity_threshold && (
                        <div className="text-gray-400">
                          Threshold: <span className="text-white capitalize">{policy.severity_threshold}</span>
                        </div>
                      )}
                      {policy.max_new_findings && (
                        <div className="text-gray-400">
                          Max New Findings: <span className="text-white">{policy.max_new_findings}</span>
                        </div>
                      )}
                      {policy.block_on_critical && (
                        <div className="text-red-400">Block on Critical</div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Templates Tab */}
            {activeTab === 'templates' && (
              <div>
                <div className="flex gap-2 mb-4">
                  {['github_actions', 'gitlab_ci', 'jenkins', 'azure_devops'].map((platform) => (
                    <button
                      key={platform}
                      onClick={() => setSelectedPlatform(platform)}
                      className={`flex items-center gap-2 px-4 py-2 rounded-lg ${
                        selectedPlatform === platform
                          ? 'bg-cyan-600 text-white'
                          : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      }`}
                    >
                      <span>{getPlatformIcon(platform)}</span>
                      <span>{getPlatformName(platform)}</span>
                    </button>
                  ))}
                </div>

                <div className="bg-gray-800 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-medium text-white">
                      {getPlatformName(selectedPlatform)} Template
                    </h3>
                    <div className="flex gap-2">
                      <button
                        onClick={copyTemplate}
                        className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 text-white rounded hover:bg-gray-600"
                      >
                        <Copy className="h-4 w-4" />
                        Copy
                      </button>
                      <button className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 text-white rounded hover:bg-gray-600">
                        <Download className="h-4 w-4" />
                        Download
                      </button>
                    </div>
                  </div>
                  <pre className="bg-gray-900 rounded p-4 overflow-x-auto text-sm text-gray-300">
                    <code>{templateContent}</code>
                  </pre>
                </div>
              </div>
            )}

            {/* IDE Settings Tab */}
            {activeTab === 'ide' && ideSettings && (
              <div className="max-w-2xl">
                <div className="bg-gray-800 rounded-lg p-6">
                  <h3 className="text-lg font-medium text-white mb-6 flex items-center gap-2">
                    <Code className="h-5 w-5 text-cyan-400" />
                    IDE Integration Settings
                  </h3>

                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-white">Scan on Save</div>
                        <div className="text-gray-400 text-sm">Run security scan when files are saved</div>
                      </div>
                      <input
                        type="checkbox"
                        checked={ideSettings.scan_on_save}
                        className="rounded border-gray-600 bg-gray-700 text-cyan-500 w-5 h-5"
                        readOnly
                      />
                    </div>

                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-white">Scan on Open</div>
                        <div className="text-gray-400 text-sm">Run security scan when files are opened</div>
                      </div>
                      <input
                        type="checkbox"
                        checked={ideSettings.scan_on_open}
                        className="rounded border-gray-600 bg-gray-700 text-cyan-500 w-5 h-5"
                        readOnly
                      />
                    </div>

                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-white">Show Inline Hints</div>
                        <div className="text-gray-400 text-sm">Display security findings inline in code</div>
                      </div>
                      <input
                        type="checkbox"
                        checked={ideSettings.show_inline_hints}
                        className="rounded border-gray-600 bg-gray-700 text-cyan-500 w-5 h-5"
                        readOnly
                      />
                    </div>

                    <div>
                      <div className="text-white mb-2">Severity Filter</div>
                      <div className="flex flex-wrap gap-2">
                        {['critical', 'high', 'medium', 'low'].map((severity) => (
                          <label key={severity} className="flex items-center gap-2 bg-gray-700 px-3 py-2 rounded">
                            <input
                              type="checkbox"
                              checked={ideSettings.severity_filter.includes(severity)}
                              className="rounded border-gray-600 bg-gray-600 text-cyan-500"
                              readOnly
                            />
                            <span className="text-gray-300 capitalize">{severity}</span>
                          </label>
                        ))}
                      </div>
                    </div>

                    <div>
                      <div className="text-white mb-2">Excluded Paths</div>
                      <div className="flex flex-wrap gap-2">
                        {ideSettings.excluded_paths.map((path) => (
                          <span key={path} className="bg-gray-700 text-gray-300 px-3 py-1 rounded-full text-sm">
                            {path}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="pt-4 border-t border-gray-700">
                      <button className="px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500">
                        Save Settings
                      </button>
                    </div>
                  </div>
                </div>

                <div className="mt-6 bg-gray-800 rounded-lg p-6">
                  <h3 className="text-lg font-medium text-white mb-4">IDE Extensions</h3>
                  <div className="grid gap-4">
                    <a href="#" className="flex items-center gap-4 bg-gray-700 p-4 rounded-lg hover:bg-gray-600">
                      <div className="text-3xl">📘</div>
                      <div>
                        <div className="text-white font-medium">VS Code Extension</div>
                        <div className="text-gray-400 text-sm">Real-time security scanning for Visual Studio Code</div>
                      </div>
                    </a>
                    <a href="#" className="flex items-center gap-4 bg-gray-700 p-4 rounded-lg hover:bg-gray-600">
                      <div className="text-3xl">🧠</div>
                      <div>
                        <div className="text-white font-medium">JetBrains Plugin</div>
                        <div className="text-gray-400 text-sm">Security scanning for IntelliJ, PyCharm, WebStorm</div>
                      </div>
                    </a>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </Layout>
  );
};

export default CicdIntegrationPage;
