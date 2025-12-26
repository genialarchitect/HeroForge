import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Code,
  Package,
  Building2,
  BarChart3,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  RefreshCw,
  Plus,
  Eye,
  Search,
  FileCode,
  GitBranch,
  ChevronRight,
  ChevronDown,
  Target,
  TrendingUp,
  TrendingDown,
  Layers,
  Box,
  AlertCircle,
  Trash2,
  Play,
  ExternalLink,
  Filter,
  Download,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import { yellowTeamAPI } from '../services/api';
import type {
  YellowTeamDashboard,
  SastScan,
  SastFinding,
  SastRule,
  SbomProject,
  SbomComponent,
  ArchitectureReview,
  StrideThreat,
  CreateSastScanRequest,
  CreateSbomRequest,
  CreateArchitectureReviewRequest,
} from '../types';

type TabType = 'dashboard' | 'sast' | 'sbom' | 'architecture';

// Status badge component
function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    pending: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700',
    running: 'bg-cyan-900/50 text-cyan-300 border border-cyan-700',
    completed: 'bg-green-900/50 text-green-300 border border-green-700',
    failed: 'bg-red-900/50 text-red-300 border border-red-700',
    in_progress: 'bg-blue-900/50 text-blue-300 border border-blue-700',
    draft: 'bg-gray-700 text-gray-300 border border-gray-600',
    approved: 'bg-green-900/50 text-green-300 border border-green-700',
    rejected: 'bg-red-900/50 text-red-300 border border-red-700',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${styles[status] || styles.pending}`}>
      {status.charAt(0).toUpperCase() + status.slice(1).replace('_', ' ')}
    </span>
  );
}

// Severity badge component
function SeverityBadge({ severity }: { severity: string }) {
  const styles: Record<string, string> = {
    critical: 'bg-red-900/50 text-red-300 border border-red-700',
    high: 'bg-orange-900/50 text-orange-300 border border-orange-700',
    medium: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700',
    low: 'bg-blue-900/50 text-blue-300 border border-blue-700',
    info: 'bg-gray-700 text-gray-300 border border-gray-600',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${styles[severity] || styles.info}`}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}

// STRIDE Category badge
function StrideCategory({ category }: { category: string }) {
  const colors: Record<string, string> = {
    spoofing: 'bg-purple-900/50 text-purple-300',
    tampering: 'bg-red-900/50 text-red-300',
    repudiation: 'bg-yellow-900/50 text-yellow-300',
    information_disclosure: 'bg-blue-900/50 text-blue-300',
    denial_of_service: 'bg-orange-900/50 text-orange-300',
    elevation_of_privilege: 'bg-pink-900/50 text-pink-300',
  };
  const labels: Record<string, string> = {
    spoofing: 'Spoofing',
    tampering: 'Tampering',
    repudiation: 'Repudiation',
    information_disclosure: 'Info Disclosure',
    denial_of_service: 'DoS',
    elevation_of_privilege: 'Priv Escalation',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colors[category] || 'bg-gray-700 text-gray-300'}`}>
      {labels[category] || category}
    </span>
  );
}

// Dashboard Stats Component
function DashboardStats({ data }: { data: YellowTeamDashboard }) {
  const stats = [
    {
      label: 'Mean Time to Remediate',
      value: `${data.mttr_days.toFixed(1)}d`,
      icon: <Clock className="h-5 w-5 text-cyan-400" />,
      trend: data.mttr_trend,
    },
    {
      label: 'Vulnerability Density',
      value: `${data.vuln_density.toFixed(2)}/kLOC`,
      icon: <AlertTriangle className="h-5 w-5 text-orange-400" />,
      trend: data.vuln_density_trend,
    },
    {
      label: 'SLA Compliance',
      value: `${data.sla_compliance.toFixed(1)}%`,
      icon: <Target className="h-5 w-5 text-green-400" />,
      trend: data.sla_trend,
    },
    {
      label: 'Open Findings',
      value: data.open_findings,
      icon: <Shield className="h-5 w-5 text-red-400" />,
      subtext: `${data.critical_findings} critical`,
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
      {stats.map((stat) => (
        <div key={stat.label} className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between mb-2">
            <div className="p-2 bg-gray-700 rounded-lg">{stat.icon}</div>
            {stat.trend !== undefined && (
              <div className={`flex items-center text-sm ${stat.trend < 0 ? 'text-green-400' : 'text-red-400'}`}>
                {stat.trend < 0 ? (
                  <TrendingDown className="h-4 w-4 mr-1" />
                ) : (
                  <TrendingUp className="h-4 w-4 mr-1" />
                )}
                {Math.abs(stat.trend).toFixed(1)}%
              </div>
            )}
          </div>
          <p className="text-gray-400 text-sm">{stat.label}</p>
          <p className="text-2xl font-bold text-white">{stat.value}</p>
          {stat.subtext && <p className="text-xs text-red-400 mt-1">{stat.subtext}</p>}
        </div>
      ))}
    </div>
  );
}

// Dashboard Charts Component
function DashboardCharts({ data }: { data: YellowTeamDashboard }) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
      {/* Findings by Category */}
      <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
        <h3 className="text-lg font-semibold text-white mb-4">Findings by Category</h3>
        <div className="space-y-3">
          {data.findings_by_category?.map((cat) => (
            <div key={cat.category} className="flex items-center gap-3">
              <div className="w-32 text-sm text-gray-400 truncate">{cat.category}</div>
              <div className="flex-1 h-6 bg-gray-700 rounded overflow-hidden">
                <div
                  className="h-full bg-cyan-500 transition-all duration-300"
                  style={{ width: `${(cat.count / (data.total_findings || 1)) * 100}%` }}
                />
              </div>
              <div className="w-12 text-right text-sm font-medium text-white">{cat.count}</div>
            </div>
          ))}
          {(!data.findings_by_category || data.findings_by_category.length === 0) && (
            <p className="text-gray-500 text-sm text-center py-4">No findings data available</p>
          )}
        </div>
      </div>

      {/* SLA Compliance by Severity */}
      <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
        <h3 className="text-lg font-semibold text-white mb-4">SLA Compliance by Severity</h3>
        <div className="space-y-3">
          {data.sla_by_severity?.map((item) => {
            const compliance = item.compliance_rate;
            let barColor = 'bg-red-500';
            if (compliance >= 90) barColor = 'bg-green-500';
            else if (compliance >= 70) barColor = 'bg-yellow-500';
            else if (compliance >= 50) barColor = 'bg-orange-500';

            return (
              <div key={item.severity} className="flex items-center gap-3">
                <div className="w-20">
                  <SeverityBadge severity={item.severity} />
                </div>
                <div className="flex-1 h-6 bg-gray-700 rounded overflow-hidden">
                  <div
                    className={`h-full ${barColor} transition-all duration-300`}
                    style={{ width: `${compliance}%` }}
                  />
                </div>
                <div className="w-16 text-right text-sm font-medium text-white">
                  {compliance.toFixed(0)}%
                </div>
              </div>
            );
          })}
          {(!data.sla_by_severity || data.sla_by_severity.length === 0) && (
            <p className="text-gray-500 text-sm text-center py-4">No SLA data available</p>
          )}
        </div>
      </div>
    </div>
  );
}

// Create SAST Scan Modal
function CreateSastScanModal({
  isOpen,
  onClose,
  onCreate,
}: {
  isOpen: boolean;
  onClose: () => void;
  onCreate: (data: CreateSastScanRequest) => void;
}) {
  const [projectName, setProjectName] = useState('');
  const [language, setLanguage] = useState('');
  const [sourceType, setSourceType] = useState<'git' | 'upload' | 'path'>('git');
  const [sourcePath, setSourcePath] = useState('');

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onCreate({
      project_name: projectName,
      language,
      source_type: sourceType,
      source_path: sourcePath,
    });
    setProjectName('');
    setLanguage('');
    setSourceType('git');
    setSourcePath('');
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md border border-gray-700">
        <h2 className="text-xl font-semibold text-white mb-4">Start SAST Scan</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Project Name *</label>
            <input
              type="text"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              required
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
              placeholder="my-web-app"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Language</label>
            <select
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="">Auto-detect</option>
              <option value="javascript">JavaScript/TypeScript</option>
              <option value="python">Python</option>
              <option value="java">Java</option>
              <option value="go">Go</option>
              <option value="rust">Rust</option>
              <option value="csharp">C#</option>
              <option value="php">PHP</option>
              <option value="ruby">Ruby</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Source Type</label>
            <select
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value as 'git' | 'upload' | 'path')}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="git">Git Repository</option>
              <option value="path">Local Path</option>
              <option value="upload">Upload Archive</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              {sourceType === 'git' ? 'Repository URL' : sourceType === 'path' ? 'Path' : 'Archive Path'} *
            </label>
            <input
              type="text"
              value={sourcePath}
              onChange={(e) => setSourcePath(e.target.value)}
              required
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
              placeholder={sourceType === 'git' ? 'https://github.com/org/repo' : '/path/to/code'}
            />
          </div>
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex-1 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors"
            >
              Start Scan
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// Create SBOM Modal
function CreateSbomModal({
  isOpen,
  onClose,
  onCreate,
}: {
  isOpen: boolean;
  onClose: () => void;
  onCreate: (data: CreateSbomRequest) => void;
}) {
  const [name, setName] = useState('');
  const [sourceType, setSourceType] = useState<'git' | 'container' | 'path'>('git');
  const [sourcePath, setSourcePath] = useState('');

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onCreate({
      name,
      source_type: sourceType,
      source_path: sourcePath,
    });
    setName('');
    setSourceType('git');
    setSourcePath('');
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md border border-gray-700">
        <h2 className="text-xl font-semibold text-white mb-4">Generate SBOM</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Project Name *</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
              placeholder="my-application"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Source Type</label>
            <select
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value as 'git' | 'container' | 'path')}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="git">Git Repository</option>
              <option value="container">Container Image</option>
              <option value="path">Local Path</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              {sourceType === 'git' ? 'Repository URL' : sourceType === 'container' ? 'Image Reference' : 'Path'} *
            </label>
            <input
              type="text"
              value={sourcePath}
              onChange={(e) => setSourcePath(e.target.value)}
              required
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
              placeholder={
                sourceType === 'git'
                  ? 'https://github.com/org/repo'
                  : sourceType === 'container'
                  ? 'nginx:latest'
                  : '/path/to/project'
              }
            />
          </div>
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex-1 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors"
            >
              Generate
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// Create Architecture Review Modal
function CreateArchitectureReviewModal({
  isOpen,
  onClose,
  onCreate,
}: {
  isOpen: boolean;
  onClose: () => void;
  onCreate: (data: CreateArchitectureReviewRequest) => void;
}) {
  const [projectName, setProjectName] = useState('');
  const [description, setDescription] = useState('');
  const [diagramData, setDiagramData] = useState('');

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onCreate({
      project_name: projectName,
      description,
      diagram_data: diagramData || undefined,
    });
    setProjectName('');
    setDescription('');
    setDiagramData('');
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-lg border border-gray-700">
        <h2 className="text-xl font-semibold text-white mb-4">Create Architecture Review</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Project Name *</label>
            <input
              type="text"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              required
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
              placeholder="Payment Processing Service"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Description *</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              required
              rows={3}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
              placeholder="Describe the system architecture and components..."
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Architecture Diagram (JSON/Mermaid)
            </label>
            <textarea
              value={diagramData}
              onChange={(e) => setDiagramData(e.target.value)}
              rows={4}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white font-mono text-sm focus:outline-none focus:border-cyan-500"
              placeholder="Paste diagram data or Mermaid syntax..."
            />
          </div>
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex-1 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors"
            >
              Create Review
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// SAST Findings Detail View
function SastFindingsView({
  scanId,
  onBack,
}: {
  scanId: string;
  onBack: () => void;
}) {
  const { data: findings, isLoading } = useQuery({
    queryKey: ['sast-findings', scanId],
    queryFn: () => yellowTeamAPI.getSastFindings(scanId).then((r) => r.data),
  });

  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const filteredFindings = findings?.filter(
    (f: SastFinding) => severityFilter === 'all' || f.severity === severityFilter
  );

  return (
    <div>
      <button
        onClick={onBack}
        className="flex items-center gap-2 text-gray-400 hover:text-gray-200 mb-4"
      >
        <ChevronRight className="w-4 h-4 rotate-180" />
        Back to Scans
      </button>

      <div className="flex justify-between items-center mb-4">
        <h2 className="text-lg font-semibold text-white">SAST Findings</h2>
        <div className="flex gap-2">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 bg-gray-700 border border-gray-600 rounded text-white text-sm focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {isLoading ? (
        <div className="flex justify-center items-center p-12">
          <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
        </div>
      ) : filteredFindings && filteredFindings.length > 0 ? (
        <div className="space-y-3">
          {filteredFindings.map((finding: SastFinding) => (
            <div
              key={finding.id}
              className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden"
            >
              <div
                className="p-4 cursor-pointer hover:bg-gray-700/50"
                onClick={() => setExpandedFinding(expandedFinding === finding.id ? null : finding.id)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={finding.severity} />
                      <span className="text-white font-medium">{finding.rule_id}</span>
                    </div>
                    <p className="text-gray-300">{finding.message}</p>
                    <div className="flex items-center gap-3 mt-2 text-sm text-gray-500">
                      <span className="flex items-center gap-1">
                        <FileCode className="w-4 h-4" />
                        {finding.file_path}:{finding.line_number}
                      </span>
                      <span>{finding.category}</span>
                    </div>
                  </div>
                  <ChevronDown
                    className={`w-5 h-5 text-gray-400 transition-transform ${
                      expandedFinding === finding.id ? 'rotate-180' : ''
                    }`}
                  />
                </div>
              </div>

              {expandedFinding === finding.id && (
                <div className="border-t border-gray-700 p-4 bg-gray-900">
                  <div className="mb-3">
                    <h4 className="text-sm font-medium text-gray-400 mb-1">Code Snippet</h4>
                    <pre className="text-sm bg-gray-950 p-3 rounded overflow-x-auto text-gray-300">
                      {finding.code_snippet || 'No code snippet available'}
                    </pre>
                  </div>
                  {finding.remediation && (
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-1">Remediation</h4>
                      <p className="text-sm text-gray-300">{finding.remediation}</p>
                    </div>
                  )}
                  {finding.cwe_id && (
                    <div className="mt-2">
                      <a
                        href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                      >
                        CWE-{finding.cwe_id}
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-gray-800 rounded-lg p-12 text-center border border-gray-700">
          <CheckCircle className="w-16 h-16 text-green-400 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-gray-300 mb-2">No Findings</h3>
          <p className="text-gray-400">No security issues detected in this scan</p>
        </div>
      )}
    </div>
  );
}

// SBOM Components View
function SbomComponentsView({
  projectId,
  projectName,
  onBack,
}: {
  projectId: string;
  projectName: string;
  onBack: () => void;
}) {
  const { data: components, isLoading } = useQuery({
    queryKey: ['sbom-components', projectId],
    queryFn: () => yellowTeamAPI.getSbomComponents(projectId).then((r) => r.data),
  });

  const [searchQuery, setSearchQuery] = useState('');
  const [vulnerableOnly, setVulnerableOnly] = useState(false);

  const filteredComponents = components?.filter((c: SbomComponent) => {
    const matchesSearch =
      !searchQuery ||
      c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.version.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesVulnerable = !vulnerableOnly || (c.vulnerabilities && c.vulnerabilities.length > 0);
    return matchesSearch && matchesVulnerable;
  });

  return (
    <div>
      <button
        onClick={onBack}
        className="flex items-center gap-2 text-gray-400 hover:text-gray-200 mb-4"
      >
        <ChevronRight className="w-4 h-4 rotate-180" />
        Back to Projects
      </button>

      <div className="flex justify-between items-center mb-4">
        <div>
          <h2 className="text-lg font-semibold text-white">{projectName}</h2>
          <p className="text-gray-400 text-sm">Software Bill of Materials</p>
        </div>
        <button className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm">
          <Download className="w-4 h-4" />
          Export SBOM
        </button>
      </div>

      <div className="flex gap-3 mb-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search components..."
            className="w-full pl-10 pr-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
          />
        </div>
        <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
          <input
            type="checkbox"
            checked={vulnerableOnly}
            onChange={(e) => setVulnerableOnly(e.target.checked)}
            className="w-4 h-4 rounded bg-gray-700 border-gray-600 text-cyan-500 focus:ring-cyan-500"
          />
          Vulnerable only
        </label>
      </div>

      {isLoading ? (
        <div className="flex justify-center items-center p-12">
          <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
        </div>
      ) : filteredComponents && filteredComponents.length > 0 ? (
        <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left p-4 text-sm font-medium text-gray-400">Component</th>
                <th className="text-left p-4 text-sm font-medium text-gray-400">Version</th>
                <th className="text-left p-4 text-sm font-medium text-gray-400">License</th>
                <th className="text-left p-4 text-sm font-medium text-gray-400">Type</th>
                <th className="text-left p-4 text-sm font-medium text-gray-400">Vulnerabilities</th>
              </tr>
            </thead>
            <tbody>
              {filteredComponents.map((component: SbomComponent) => (
                <tr key={component.id} className="border-b border-gray-700 hover:bg-gray-700/50">
                  <td className="p-4">
                    <div className="font-medium text-white">{component.name}</div>
                    {component.purl && (
                      <div className="text-xs text-gray-500 truncate max-w-xs">{component.purl}</div>
                    )}
                  </td>
                  <td className="p-4 text-gray-300 font-mono text-sm">{component.version}</td>
                  <td className="p-4">
                    <span
                      className={`px-2 py-1 rounded text-xs ${
                        component.license_risk === 'high'
                          ? 'bg-red-900/50 text-red-300'
                          : component.license_risk === 'medium'
                          ? 'bg-yellow-900/50 text-yellow-300'
                          : 'bg-green-900/50 text-green-300'
                      }`}
                    >
                      {component.license || 'Unknown'}
                    </span>
                  </td>
                  <td className="p-4 text-gray-400 text-sm">{component.component_type}</td>
                  <td className="p-4">
                    {component.vulnerabilities && component.vulnerabilities.length > 0 ? (
                      <span className="flex items-center gap-1 text-red-400">
                        <AlertTriangle className="w-4 h-4" />
                        {component.vulnerabilities.length}
                      </span>
                    ) : (
                      <span className="text-green-400">
                        <CheckCircle className="w-4 h-4" />
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="bg-gray-800 rounded-lg p-12 text-center border border-gray-700">
          <Package className="w-16 h-16 text-gray-600 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-gray-300 mb-2">No Components</h3>
          <p className="text-gray-400">No components found matching your criteria</p>
        </div>
      )}
    </div>
  );
}

// Architecture Threats View
function ArchitectureThreatsView({
  reviewId,
  projectName,
  onBack,
}: {
  reviewId: string;
  projectName: string;
  onBack: () => void;
}) {
  const { data: threats, isLoading } = useQuery({
    queryKey: ['architecture-threats', reviewId],
    queryFn: () => yellowTeamAPI.getArchitectureThreats(reviewId).then((r) => r.data),
  });

  const [strideFilter, setStrideFilter] = useState<string>('all');

  const filteredThreats = threats?.filter(
    (t: StrideThreat) => strideFilter === 'all' || t.stride_category === strideFilter
  );

  // Group threats by STRIDE category
  const threatsByCategory = threats?.reduce((acc: Record<string, number>, threat: StrideThreat) => {
    acc[threat.stride_category] = (acc[threat.stride_category] || 0) + 1;
    return acc;
  }, {});

  return (
    <div>
      <button
        onClick={onBack}
        className="flex items-center gap-2 text-gray-400 hover:text-gray-200 mb-4"
      >
        <ChevronRight className="w-4 h-4 rotate-180" />
        Back to Reviews
      </button>

      <div className="flex justify-between items-center mb-4">
        <div>
          <h2 className="text-lg font-semibold text-white">{projectName}</h2>
          <p className="text-gray-400 text-sm">STRIDE Threat Model</p>
        </div>
      </div>

      {/* STRIDE Summary */}
      {threatsByCategory && (
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3 mb-6">
          {Object.entries(threatsByCategory).map(([category, count]) => (
            <div
              key={category}
              className="bg-gray-800 rounded-lg p-3 border border-gray-700 text-center cursor-pointer hover:bg-gray-700/50"
              onClick={() => setStrideFilter(strideFilter === category ? 'all' : category)}
            >
              <StrideCategory category={category} />
              <p className="text-2xl font-bold text-white mt-2">{count as number}</p>
            </div>
          ))}
        </div>
      )}

      <div className="flex justify-between items-center mb-4">
        <h3 className="font-medium text-white">Identified Threats</h3>
        {strideFilter !== 'all' && (
          <button
            onClick={() => setStrideFilter('all')}
            className="text-sm text-cyan-400 hover:text-cyan-300"
          >
            Clear Filter
          </button>
        )}
      </div>

      {isLoading ? (
        <div className="flex justify-center items-center p-12">
          <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
        </div>
      ) : filteredThreats && filteredThreats.length > 0 ? (
        <div className="space-y-3">
          {filteredThreats.map((threat: StrideThreat) => (
            <div key={threat.id} className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                  <StrideCategory category={threat.stride_category} />
                  <SeverityBadge severity={threat.severity} />
                </div>
                <StatusBadge status={threat.status} />
              </div>
              <h4 className="text-white font-medium mb-1">{threat.title}</h4>
              <p className="text-gray-400 text-sm mb-3">{threat.description}</p>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-500">Affected Component:</span>
                  <span className="text-gray-300 ml-2">{threat.affected_component}</span>
                </div>
                <div>
                  <span className="text-gray-500">Attack Vector:</span>
                  <span className="text-gray-300 ml-2">{threat.attack_vector}</span>
                </div>
              </div>
              {threat.mitigation && (
                <div className="mt-3 p-3 bg-gray-900 rounded">
                  <span className="text-sm font-medium text-gray-400">Recommended Mitigation:</span>
                  <p className="text-sm text-gray-300 mt-1">{threat.mitigation}</p>
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-gray-800 rounded-lg p-12 text-center border border-gray-700">
          <Shield className="w-16 h-16 text-green-400 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-gray-300 mb-2">No Threats Identified</h3>
          <p className="text-gray-400">No threats found matching the current filter</p>
        </div>
      )}
    </div>
  );
}

export default function YellowTeamPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [showSastModal, setShowSastModal] = useState(false);
  const [showSbomModal, setShowSbomModal] = useState(false);
  const [showArchModal, setShowArchModal] = useState(false);
  const [selectedSastScan, setSelectedSastScan] = useState<string | null>(null);
  const [selectedSbomProject, setSelectedSbomProject] = useState<{ id: string; name: string } | null>(null);
  const [selectedArchReview, setSelectedArchReview] = useState<{ id: string; name: string } | null>(null);

  // Queries
  const { data: dashboard, isLoading: dashboardLoading } = useQuery({
    queryKey: ['yellow-team-dashboard'],
    queryFn: () => yellowTeamAPI.getDashboardOverview().then((r) => r.data),
  });

  const { data: sastScans, isLoading: sastLoading } = useQuery({
    queryKey: ['sast-scans'],
    queryFn: () => yellowTeamAPI.listSastScans().then((r) => r.data),
    enabled: activeTab === 'sast',
  });

  const { data: sastRules } = useQuery({
    queryKey: ['sast-rules'],
    queryFn: () => yellowTeamAPI.getSastRules().then((r) => r.data),
    enabled: activeTab === 'sast',
  });

  const { data: sbomProjects, isLoading: sbomLoading } = useQuery({
    queryKey: ['sbom-projects'],
    queryFn: () => yellowTeamAPI.listSbomProjects().then((r) => r.data),
    enabled: activeTab === 'sbom',
  });

  const { data: archReviews, isLoading: archLoading } = useQuery({
    queryKey: ['architecture-reviews'],
    queryFn: () => yellowTeamAPI.listArchitectureReviews().then((r) => r.data),
    enabled: activeTab === 'architecture',
  });

  // Mutations
  const createSastMutation = useMutation({
    mutationFn: yellowTeamAPI.startSastScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sast-scans'] });
      queryClient.invalidateQueries({ queryKey: ['yellow-team-dashboard'] });
      toast.success('SAST scan started');
    },
    onError: () => toast.error('Failed to start SAST scan'),
  });

  const createSbomMutation = useMutation({
    mutationFn: yellowTeamAPI.generateSbom,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sbom-projects'] });
      toast.success('SBOM generation started');
    },
    onError: () => toast.error('Failed to generate SBOM'),
  });

  const createArchMutation = useMutation({
    mutationFn: yellowTeamAPI.createArchitectureReview,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['architecture-reviews'] });
      toast.success('Architecture review created');
    },
    onError: () => toast.error('Failed to create architecture review'),
  });

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: <BarChart3 className="w-4 h-4" /> },
    { id: 'sast', label: 'SAST', icon: <Code className="w-4 h-4" /> },
    { id: 'sbom', label: 'SBOM', icon: <Package className="w-4 h-4" /> },
    { id: 'architecture', label: 'Architecture', icon: <Building2 className="w-4 h-4" /> },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex justify-between items-center">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-yellow-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">Yellow Team</h1>
              <p className="text-gray-400">DevSecOps &amp; Security Architecture</p>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-b border-gray-700">
          <nav className="flex gap-4">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id);
                  setSelectedSastScan(null);
                  setSelectedSbomProject(null);
                  setSelectedArchReview(null);
                }}
                className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-gray-400 hover:text-gray-200'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        <div>
          {/* Dashboard Tab */}
          {activeTab === 'dashboard' && (
            <div>
              {dashboardLoading ? (
                <div className="flex justify-center items-center p-12">
                  <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
                </div>
              ) : dashboard ? (
                <>
                  <DashboardStats data={dashboard} />
                  <DashboardCharts data={dashboard} />

                  {/* Recent Activity */}
                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h3 className="text-lg font-semibold text-white mb-4">Recent Activity</h3>
                    <div className="space-y-3">
                      {dashboard.recent_activity?.map((activity, idx) => (
                        <div
                          key={idx}
                          className="flex items-center gap-3 p-3 bg-gray-900 rounded-lg"
                        >
                          <div className="p-2 bg-gray-800 rounded">
                            {activity.type === 'sast' && <Code className="w-4 h-4 text-cyan-400" />}
                            {activity.type === 'sbom' && <Package className="w-4 h-4 text-green-400" />}
                            {activity.type === 'architecture' && (
                              <Building2 className="w-4 h-4 text-purple-400" />
                            )}
                          </div>
                          <div className="flex-1">
                            <p className="text-gray-300">{activity.message}</p>
                            <p className="text-xs text-gray-500">
                              {new Date(activity.timestamp).toLocaleString()}
                            </p>
                          </div>
                          <StatusBadge status={activity.status} />
                        </div>
                      ))}
                      {(!dashboard.recent_activity || dashboard.recent_activity.length === 0) && (
                        <p className="text-gray-500 text-center py-4">No recent activity</p>
                      )}
                    </div>
                  </div>
                </>
              ) : (
                <div className="bg-gray-800 rounded-lg p-12 text-center border border-gray-700">
                  <AlertCircle className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Data Available</h3>
                  <p className="text-gray-400">Start a SAST scan or generate an SBOM to see metrics</p>
                </div>
              )}
            </div>
          )}

          {/* SAST Tab */}
          {activeTab === 'sast' && (
            <div>
              {selectedSastScan ? (
                <SastFindingsView
                  scanId={selectedSastScan}
                  onBack={() => setSelectedSastScan(null)}
                />
              ) : (
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <div>
                      <h2 className="text-lg font-semibold text-white">Static Application Security Testing</h2>
                      <p className="text-gray-400 text-sm">
                        {sastRules?.length || 0} rules available
                      </p>
                    </div>
                    <button
                      onClick={() => setShowSastModal(true)}
                      className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors"
                    >
                      <Plus className="w-4 h-4" />
                      Start Scan
                    </button>
                  </div>

                  {sastLoading ? (
                    <div className="flex justify-center items-center p-12">
                      <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
                    </div>
                  ) : sastScans && sastScans.length > 0 ? (
                    <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
                      <table className="w-full">
                        <thead>
                          <tr className="border-b border-gray-700">
                            <th className="text-left p-4 text-sm font-medium text-gray-400">Project</th>
                            <th className="text-left p-4 text-sm font-medium text-gray-400">Language</th>
                            <th className="text-left p-4 text-sm font-medium text-gray-400">Status</th>
                            <th className="text-left p-4 text-sm font-medium text-gray-400">Findings</th>
                            <th className="text-left p-4 text-sm font-medium text-gray-400">Date</th>
                            <th className="text-right p-4 text-sm font-medium text-gray-400">Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {sastScans.map((scan: SastScan) => (
                            <tr key={scan.id} className="border-b border-gray-700 hover:bg-gray-700/50">
                              <td className="p-4">
                                <div className="font-medium text-white">{scan.project_name}</div>
                                <div className="text-xs text-gray-500 truncate max-w-xs">
                                  {scan.source_path}
                                </div>
                              </td>
                              <td className="p-4 text-gray-300">{scan.language || 'Auto'}</td>
                              <td className="p-4">
                                <StatusBadge status={scan.status} />
                              </td>
                              <td className="p-4">
                                {scan.status === 'completed' && (
                                  <div className="flex items-center gap-2">
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
                                    {scan.finding_count === 0 && (
                                      <CheckCircle className="w-4 h-4 text-green-400" />
                                    )}
                                  </div>
                                )}
                              </td>
                              <td className="p-4 text-gray-500 text-sm">
                                {new Date(scan.created_at).toLocaleDateString()}
                              </td>
                              <td className="p-4 text-right">
                                <button
                                  onClick={() => setSelectedSastScan(scan.id)}
                                  className="p-2 hover:bg-gray-700 rounded text-gray-400 hover:text-white"
                                >
                                  <Eye className="w-4 h-4" />
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="bg-gray-800 rounded-lg p-12 text-center border border-gray-700">
                      <Code className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                      <h3 className="text-xl font-semibold text-gray-300 mb-2">No SAST Scans</h3>
                      <p className="text-gray-400 mb-4">
                        Start scanning your source code for security vulnerabilities
                      </p>
                      <button
                        onClick={() => setShowSastModal(true)}
                        className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors"
                      >
                        <Plus className="w-4 h-4" />
                        Start First Scan
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* SBOM Tab */}
          {activeTab === 'sbom' && (
            <div>
              {selectedSbomProject ? (
                <SbomComponentsView
                  projectId={selectedSbomProject.id}
                  projectName={selectedSbomProject.name}
                  onBack={() => setSelectedSbomProject(null)}
                />
              ) : (
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <div>
                      <h2 className="text-lg font-semibold text-white">Software Bill of Materials</h2>
                      <p className="text-gray-400 text-sm">
                        Track dependencies and component vulnerabilities
                      </p>
                    </div>
                    <button
                      onClick={() => setShowSbomModal(true)}
                      className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors"
                    >
                      <Plus className="w-4 h-4" />
                      Generate SBOM
                    </button>
                  </div>

                  {sbomLoading ? (
                    <div className="flex justify-center items-center p-12">
                      <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
                    </div>
                  ) : sbomProjects && sbomProjects.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      {sbomProjects.map((project: SbomProject) => (
                        <div
                          key={project.id}
                          className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 cursor-pointer transition-colors"
                          onClick={() => setSelectedSbomProject({ id: project.id, name: project.name })}
                        >
                          <div className="flex items-start justify-between mb-3">
                            <div className="p-2 bg-gray-700 rounded">
                              <Package className="w-5 h-5 text-cyan-400" />
                            </div>
                            <StatusBadge status={project.status} />
                          </div>
                          <h3 className="font-medium text-white mb-1">{project.name}</h3>
                          <p className="text-sm text-gray-500 mb-3">{project.source_type}</p>
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-gray-400">{project.component_count} components</span>
                            {project.vulnerable_count > 0 && (
                              <span className="text-red-400 flex items-center gap-1">
                                <AlertTriangle className="w-4 h-4" />
                                {project.vulnerable_count}
                              </span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="bg-gray-800 rounded-lg p-12 text-center border border-gray-700">
                      <Package className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                      <h3 className="text-xl font-semibold text-gray-300 mb-2">No SBOM Projects</h3>
                      <p className="text-gray-400 mb-4">
                        Generate SBOMs to track your software dependencies
                      </p>
                      <button
                        onClick={() => setShowSbomModal(true)}
                        className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors"
                      >
                        <Plus className="w-4 h-4" />
                        Generate First SBOM
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Architecture Tab */}
          {activeTab === 'architecture' && (
            <div>
              {selectedArchReview ? (
                <ArchitectureThreatsView
                  reviewId={selectedArchReview.id}
                  projectName={selectedArchReview.name}
                  onBack={() => setSelectedArchReview(null)}
                />
              ) : (
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <div>
                      <h2 className="text-lg font-semibold text-white">Architecture Reviews</h2>
                      <p className="text-gray-400 text-sm">
                        STRIDE threat modeling and security architecture analysis
                      </p>
                    </div>
                    <button
                      onClick={() => setShowArchModal(true)}
                      className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors"
                    >
                      <Plus className="w-4 h-4" />
                      New Review
                    </button>
                  </div>

                  {archLoading ? (
                    <div className="flex justify-center items-center p-12">
                      <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
                    </div>
                  ) : archReviews && archReviews.length > 0 ? (
                    <div className="space-y-3">
                      {archReviews.map((review: ArchitectureReview) => (
                        <div
                          key={review.id}
                          className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 cursor-pointer transition-colors"
                          onClick={() =>
                            setSelectedArchReview({ id: review.id, name: review.project_name })
                          }
                        >
                          <div className="flex items-start justify-between">
                            <div className="flex items-start gap-3">
                              <div className="p-2 bg-gray-700 rounded">
                                <Building2 className="w-5 h-5 text-purple-400" />
                              </div>
                              <div>
                                <h3 className="font-medium text-white">{review.project_name}</h3>
                                <p className="text-sm text-gray-400 mt-1 line-clamp-2">
                                  {review.description}
                                </p>
                                <div className="flex items-center gap-4 mt-2 text-sm text-gray-500">
                                  <span>{new Date(review.created_at).toLocaleDateString()}</span>
                                  <span>{review.threat_count} threats identified</span>
                                </div>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <StatusBadge status={review.status} />
                              <ChevronRight className="w-5 h-5 text-gray-400" />
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="bg-gray-800 rounded-lg p-12 text-center border border-gray-700">
                      <Building2 className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                      <h3 className="text-xl font-semibold text-gray-300 mb-2">No Architecture Reviews</h3>
                      <p className="text-gray-400 mb-4">
                        Create architecture reviews with STRIDE threat modeling
                      </p>
                      <button
                        onClick={() => setShowArchModal(true)}
                        className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors"
                      >
                        <Plus className="w-4 h-4" />
                        Create First Review
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modals */}
        <CreateSastScanModal
          isOpen={showSastModal}
          onClose={() => setShowSastModal(false)}
          onCreate={(data) => createSastMutation.mutate(data)}
        />
        <CreateSbomModal
          isOpen={showSbomModal}
          onClose={() => setShowSbomModal(false)}
          onCreate={(data) => createSbomMutation.mutate(data)}
        />
        <CreateArchitectureReviewModal
          isOpen={showArchModal}
          onClose={() => setShowArchModal(false)}
          onCreate={(data) => createArchMutation.mutate(data)}
        />
      </div>
    </Layout>
  );
}
