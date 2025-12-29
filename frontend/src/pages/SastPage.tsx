import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Code,
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
  ChevronRight,
  ChevronDown,
  Trash2,
  Play,
  ExternalLink,
  Download,
  Upload,
  AlertCircle,
  ArrowRight,
  Zap,
  Bug,
  Lock,
  Key,
  Database,
  FileWarning,
  Settings,
  Braces,
  GitBranch,
  Workflow,
  Filter,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import { yellowTeamAPI } from '../services/api';
import type {
  SastScan,
  SastFinding,
  SastRule,
  SemgrepRule,
  TaintFlow,
  SecurityHotspot,
  HotspotStats,
  CreateSastScanRequest,
} from '../types';

type TabType = 'scans' | 'semgrep' | 'taint' | 'hotspots';

// Status badge component
function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    pending: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700',
    running: 'bg-cyan-900/50 text-cyan-300 border border-cyan-700',
    completed: 'bg-green-900/50 text-green-300 border border-green-700',
    failed: 'bg-red-900/50 text-red-300 border border-red-700',
    open: 'bg-blue-900/50 text-blue-300 border border-blue-700',
    confirmed: 'bg-red-900/50 text-red-300 border border-red-700',
    false_positive: 'bg-gray-700 text-gray-300 border border-gray-600',
    fixed: 'bg-green-900/50 text-green-300 border border-green-700',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${styles[status] || styles.pending}`}>
      {status.replace('_', ' ').charAt(0).toUpperCase() + status.replace('_', ' ').slice(1)}
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

// Priority badge for hotspots
function PriorityBadge({ priority }: { priority: string }) {
  const styles: Record<string, string> = {
    high: 'bg-red-900/50 text-red-300 border border-red-700',
    medium: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700',
    low: 'bg-blue-900/50 text-blue-300 border border-blue-700',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${styles[priority] || 'bg-gray-700 text-gray-300'}`}>
      {priority.charAt(0).toUpperCase() + priority.slice(1)} Priority
    </span>
  );
}

// Resolution badge for hotspots
function ResolutionBadge({ resolution }: { resolution: string }) {
  const styles: Record<string, string> = {
    to_review: 'bg-yellow-900/50 text-yellow-300',
    vulnerability: 'bg-red-900/50 text-red-300',
    safe: 'bg-green-900/50 text-green-300',
    acknowledged: 'bg-blue-900/50 text-blue-300',
    fixed: 'bg-green-900/50 text-green-300',
  };
  const labels: Record<string, string> = {
    to_review: 'To Review',
    vulnerability: 'Vulnerability',
    safe: 'Safe',
    acknowledged: 'Acknowledged',
    fixed: 'Fixed',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${styles[resolution] || 'bg-gray-700 text-gray-300'}`}>
      {labels[resolution] || resolution}
    </span>
  );
}

// Category icon for hotspots
function CategoryIcon({ category }: { category: string }) {
  const icons: Record<string, React.ReactNode> = {
    authentication: <Key className="w-4 h-4" />,
    authorization: <Lock className="w-4 h-4" />,
    cryptography: <Shield className="w-4 h-4" />,
    input_validation: <AlertTriangle className="w-4 h-4" />,
    injection_prevention: <Bug className="w-4 h-4" />,
    sensitive_data: <Database className="w-4 h-4" />,
    configuration: <Settings className="w-4 h-4" />,
    file_operations: <FileWarning className="w-4 h-4" />,
  };
  return icons[category] || <AlertCircle className="w-4 h-4" />;
}

// Create SAST Scan Modal
function CreateScanModal({
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
      language: language || undefined,
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
              <option value="kotlin">Kotlin</option>
              <option value="scala">Scala</option>
              <option value="swift">Swift</option>
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

// Import Semgrep Rules Modal
function ImportSemgrepModal({
  isOpen,
  onClose,
  onImport,
}: {
  isOpen: boolean;
  onClose: () => void;
  onImport: (yaml: string) => void;
}) {
  const [yaml, setYaml] = useState('');

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onImport(yaml);
    setYaml('');
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl border border-gray-700">
        <h2 className="text-xl font-semibold text-white mb-4">Import Semgrep Rules</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Paste Semgrep YAML Rules
            </label>
            <textarea
              value={yaml}
              onChange={(e) => setYaml(e.target.value)}
              required
              rows={15}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded text-white font-mono text-sm focus:outline-none focus:border-cyan-500"
              placeholder={`rules:
  - id: detect-sql-injection
    pattern: $QUERY = "SELECT * FROM users WHERE id = " + $INPUT
    message: Potential SQL injection vulnerability
    severity: ERROR
    languages: [python, javascript]`}
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
              Import Rules
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// Review Hotspot Modal
function ReviewHotspotModal({
  hotspot,
  onClose,
  onUpdate,
}: {
  hotspot: SecurityHotspot;
  onClose: () => void;
  onUpdate: (id: string, resolution: string, comment: string) => void;
}) {
  const [resolution, setResolution] = useState(hotspot.resolution);
  const [comment, setComment] = useState(hotspot.review_comment || '');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onUpdate(hotspot.id, resolution, comment);
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl border border-gray-700 max-h-[90vh] overflow-y-auto">
        <h2 className="text-xl font-semibold text-white mb-4">Review Security Hotspot</h2>

        <div className="mb-4 space-y-3">
          <div className="flex items-center gap-2">
            <PriorityBadge priority={hotspot.priority} />
            <span className="text-gray-400 capitalize">{hotspot.category.replace('_', ' ')}</span>
          </div>
          <h3 className="text-white font-medium">{hotspot.message}</h3>
          <div className="flex items-center gap-2 text-sm text-gray-400">
            <FileCode className="w-4 h-4" />
            {hotspot.file_path}:{hotspot.line_number}
          </div>
        </div>

        {hotspot.code_snippet && (
          <div className="mb-4">
            <h4 className="text-sm font-medium text-gray-400 mb-2">Code</h4>
            <pre className="text-sm bg-gray-900 p-3 rounded overflow-x-auto text-gray-300 font-mono">
              {hotspot.code_snippet}
            </pre>
          </div>
        )}

        <div className="mb-4 p-3 bg-gray-900 rounded border border-gray-700">
          <h4 className="text-sm font-medium text-cyan-400 mb-2">Security Context</h4>
          <p className="text-sm text-gray-300">{hotspot.security_context}</p>
        </div>

        <div className="mb-4 p-3 bg-gray-900 rounded border border-gray-700">
          <h4 className="text-sm font-medium text-green-400 mb-2">Review Guidance</h4>
          <p className="text-sm text-gray-300">{hotspot.review_guidance}</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Resolution</label>
            <select
              value={resolution}
              onChange={(e) => setResolution(e.target.value as typeof resolution)}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="to_review">To Review</option>
              <option value="vulnerability">Confirmed Vulnerability</option>
              <option value="safe">Safe - Not a Vulnerability</option>
              <option value="acknowledged">Acknowledged - Risk Accepted</option>
              <option value="fixed">Fixed</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Review Comment</label>
            <textarea
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              rows={3}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
              placeholder="Add your review notes..."
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
              Save Review
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// Scan Findings Detail View
function ScanFindingsView({
  scanId,
  projectName,
  onBack,
}: {
  scanId: string;
  projectName: string;
  onBack: () => void;
}) {
  const queryClient = useQueryClient();
  const [activeSubTab, setActiveSubTab] = useState<'findings' | 'taint' | 'hotspots'>('findings');
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [selectedHotspot, setSelectedHotspot] = useState<SecurityHotspot | null>(null);

  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ['sast-findings', scanId],
    queryFn: () => yellowTeamAPI.getSastFindings(scanId).then((r) => r.data),
  });

  const { data: taintFlowsResp, isLoading: taintLoading } = useQuery({
    queryKey: ['taint-flows', scanId],
    queryFn: () => yellowTeamAPI.getTaintFlows(scanId).then((r) => r.data),
    enabled: activeSubTab === 'taint',
  });

  const { data: hotspotsResp, isLoading: hotspotsLoading } = useQuery({
    queryKey: ['hotspots', scanId],
    queryFn: () => yellowTeamAPI.getHotspots(scanId).then((r) => r.data),
    enabled: activeSubTab === 'hotspots',
  });

  const updateHotspotMutation = useMutation({
    mutationFn: ({ id, resolution, comment }: { id: string; resolution: string; comment: string }) =>
      yellowTeamAPI.updateHotspot(id, { resolution, comment }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hotspots', scanId] });
      toast.success('Hotspot updated');
    },
    onError: () => toast.error('Failed to update hotspot'),
  });

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
        <div>
          <h2 className="text-lg font-semibold text-white">{projectName}</h2>
          <p className="text-gray-400 text-sm">Scan Analysis Results</p>
        </div>
      </div>

      {/* Sub-tabs */}
      <div className="flex gap-2 mb-4">
        <button
          onClick={() => setActiveSubTab('findings')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeSubTab === 'findings'
              ? 'bg-cyan-600 text-white'
              : 'bg-gray-800 text-gray-400 hover:text-white'
          }`}
        >
          <div className="flex items-center gap-2">
            <Bug className="w-4 h-4" />
            Findings ({findings?.length || 0})
          </div>
        </button>
        <button
          onClick={() => setActiveSubTab('taint')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeSubTab === 'taint'
              ? 'bg-cyan-600 text-white'
              : 'bg-gray-800 text-gray-400 hover:text-white'
          }`}
        >
          <div className="flex items-center gap-2">
            <Workflow className="w-4 h-4" />
            Taint Flows ({taintFlowsResp?.total || 0})
          </div>
        </button>
        <button
          onClick={() => setActiveSubTab('hotspots')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeSubTab === 'hotspots'
              ? 'bg-cyan-600 text-white'
              : 'bg-gray-800 text-gray-400 hover:text-white'
          }`}
        >
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4" />
            Hotspots ({hotspotsResp?.total || 0})
          </div>
        </button>
      </div>

      {/* Findings View */}
      {activeSubTab === 'findings' && (
        <>
          <div className="flex justify-end mb-4">
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

          {findingsLoading ? (
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
                      {finding.code_snippet && (
                        <div className="mb-3">
                          <h4 className="text-sm font-medium text-gray-400 mb-1">Code Snippet</h4>
                          <pre className="text-sm bg-gray-950 p-3 rounded overflow-x-auto text-gray-300 font-mono">
                            {finding.code_snippet}
                          </pre>
                        </div>
                      )}
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
        </>
      )}

      {/* Taint Flows View */}
      {activeSubTab === 'taint' && (
        <>
          {taintLoading ? (
            <div className="flex justify-center items-center p-12">
              <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
            </div>
          ) : taintFlowsResp?.flows && taintFlowsResp.flows.length > 0 ? (
            <div className="space-y-3">
              {taintFlowsResp.flows.map((flow: TaintFlow) => (
                <div
                  key={flow.id}
                  className="bg-gray-800 rounded-lg p-4 border border-gray-700"
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={flow.severity} />
                      <StatusBadge status={flow.status} />
                      {flow.is_sanitized && (
                        <span className="px-2 py-1 rounded text-xs font-medium bg-green-900/50 text-green-300">
                          Sanitized
                        </span>
                      )}
                    </div>
                    <span className="text-sm text-gray-500">{flow.category}</span>
                  </div>

                  <div className="flex items-center gap-4 mb-3">
                    <div className="flex-1 p-3 bg-red-900/20 border border-red-800/50 rounded">
                      <div className="text-xs text-red-400 mb-1">Source</div>
                      <div className="text-white font-medium">{flow.source.name}</div>
                      <div className="text-xs text-gray-500">
                        {flow.file_path}:{flow.source_line}
                      </div>
                    </div>
                    <ArrowRight className="w-6 h-6 text-gray-500 flex-shrink-0" />
                    <div className="flex-1 p-3 bg-orange-900/20 border border-orange-800/50 rounded">
                      <div className="text-xs text-orange-400 mb-1">Sink</div>
                      <div className="text-white font-medium">{flow.sink.name}</div>
                      <div className="text-xs text-gray-500">
                        {flow.file_path}:{flow.sink_line}
                      </div>
                    </div>
                  </div>

                  {flow.cwe_id && (
                    <a
                      href={`https://cwe.mitre.org/data/definitions/${flow.cwe_id}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                    >
                      CWE-{flow.cwe_id}
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-gray-800 rounded-lg p-12 text-center border border-gray-700">
              <Workflow className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-300 mb-2">No Taint Flows</h3>
              <p className="text-gray-400">No tainted data flows detected in this scan</p>
            </div>
          )}
        </>
      )}

      {/* Hotspots View */}
      {activeSubTab === 'hotspots' && (
        <>
          {hotspotsLoading ? (
            <div className="flex justify-center items-center p-12">
              <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
            </div>
          ) : hotspotsResp?.hotspots && hotspotsResp.hotspots.length > 0 ? (
            <div className="space-y-3">
              {hotspotsResp.hotspots.map((hotspot: SecurityHotspot) => (
                <div
                  key={hotspot.id}
                  className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 cursor-pointer"
                  onClick={() => setSelectedHotspot(hotspot)}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <div className="p-1.5 bg-gray-700 rounded">
                        <CategoryIcon category={hotspot.category} />
                      </div>
                      <PriorityBadge priority={hotspot.priority} />
                      <ResolutionBadge resolution={hotspot.resolution} />
                    </div>
                  </div>
                  <h4 className="text-white font-medium mb-1">{hotspot.message}</h4>
                  <div className="flex items-center gap-3 text-sm text-gray-500">
                    <span className="flex items-center gap-1">
                      <FileCode className="w-4 h-4" />
                      {hotspot.file_path}:{hotspot.line_number}
                    </span>
                    <span className="capitalize">{hotspot.category.replace('_', ' ')}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-gray-800 rounded-lg p-12 text-center border border-gray-700">
              <Zap className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-300 mb-2">No Security Hotspots</h3>
              <p className="text-gray-400">No security hotspots require review in this scan</p>
            </div>
          )}
        </>
      )}

      {/* Review Hotspot Modal */}
      {selectedHotspot && (
        <ReviewHotspotModal
          hotspot={selectedHotspot}
          onClose={() => setSelectedHotspot(null)}
          onUpdate={(id, resolution, comment) =>
            updateHotspotMutation.mutate({ id, resolution, comment })
          }
        />
      )}
    </div>
  );
}

// Semgrep Rules Tab
function SemgrepRulesTab() {
  const queryClient = useQueryClient();
  const [showImportModal, setShowImportModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const { data: rules, isLoading } = useQuery({
    queryKey: ['semgrep-rules'],
    queryFn: () => yellowTeamAPI.listSemgrepRules().then((r) => r.data),
  });

  const importMutation = useMutation({
    mutationFn: yellowTeamAPI.importSemgrepRules,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['semgrep-rules'] });
      toast.success(data.data.message);
    },
    onError: () => toast.error('Failed to import rules'),
  });

  const deleteMutation = useMutation({
    mutationFn: yellowTeamAPI.deleteSemgrepRule,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['semgrep-rules'] });
      toast.success('Rule deleted');
    },
    onError: () => toast.error('Failed to delete rule'),
  });

  const filteredRules = rules?.filter(
    (r: SemgrepRule) =>
      !searchQuery ||
      r.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.rule_id.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-semibold text-white">Semgrep Rules</h2>
          <p className="text-gray-400 text-sm">Import and manage custom Semgrep rules</p>
        </div>
        <button
          onClick={() => setShowImportModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors"
        >
          <Upload className="w-4 h-4" />
          Import Rules
        </button>
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search rules..."
          className="w-full pl-10 pr-3 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:outline-none focus:border-cyan-500"
        />
      </div>

      {isLoading ? (
        <div className="flex justify-center items-center p-12">
          <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
        </div>
      ) : filteredRules && filteredRules.length > 0 ? (
        <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left p-4 text-sm font-medium text-gray-400">Rule ID</th>
                <th className="text-left p-4 text-sm font-medium text-gray-400">Name</th>
                <th className="text-left p-4 text-sm font-medium text-gray-400">Severity</th>
                <th className="text-left p-4 text-sm font-medium text-gray-400">Languages</th>
                <th className="text-left p-4 text-sm font-medium text-gray-400">Category</th>
                <th className="text-right p-4 text-sm font-medium text-gray-400">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.map((rule: SemgrepRule) => (
                <tr key={rule.id} className="border-b border-gray-700 hover:bg-gray-700/50">
                  <td className="p-4 font-mono text-sm text-cyan-400">{rule.rule_id}</td>
                  <td className="p-4 text-white">{rule.name}</td>
                  <td className="p-4">
                    <SeverityBadge severity={rule.severity} />
                  </td>
                  <td className="p-4">
                    <div className="flex flex-wrap gap-1">
                      {rule.languages.slice(0, 3).map((lang) => (
                        <span
                          key={lang}
                          className="px-2 py-0.5 bg-gray-700 rounded text-xs text-gray-300"
                        >
                          {lang}
                        </span>
                      ))}
                      {rule.languages.length > 3 && (
                        <span className="px-2 py-0.5 text-xs text-gray-500">
                          +{rule.languages.length - 3}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="p-4 text-gray-300">{rule.category}</td>
                  <td className="p-4 text-right">
                    <button
                      onClick={() => deleteMutation.mutate(rule.id)}
                      className="p-2 hover:bg-gray-700 rounded text-red-400 hover:text-red-300"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="bg-gray-800 rounded-lg p-12 text-center border border-gray-700">
          <Braces className="w-16 h-16 text-gray-600 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-gray-300 mb-2">No Semgrep Rules</h3>
          <p className="text-gray-400 mb-4">Import Semgrep rules to enhance your SAST scanning</p>
          <button
            onClick={() => setShowImportModal(true)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors"
          >
            <Upload className="w-4 h-4" />
            Import Rules
          </button>
        </div>
      )}

      <ImportSemgrepModal
        isOpen={showImportModal}
        onClose={() => setShowImportModal(false)}
        onImport={(yaml) => importMutation.mutate(yaml)}
      />
    </div>
  );
}

// Hotspots Overview Tab
function HotspotsOverviewTab() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['hotspot-stats'],
    queryFn: () => yellowTeamAPI.getHotspotStats().then((r) => r.data),
  });

  if (isLoading) {
    return (
      <div className="flex justify-center items-center p-12">
        <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="bg-gray-800 rounded-lg p-12 text-center border border-gray-700">
        <Zap className="w-16 h-16 text-gray-600 mx-auto mb-4" />
        <h3 className="text-xl font-semibold text-gray-300 mb-2">No Hotspot Data</h3>
        <p className="text-gray-400">Run a SAST scan to detect security hotspots</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-white mb-4">Security Hotspots Overview</h2>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 bg-gray-700 rounded">
                <Zap className="w-5 h-5 text-yellow-400" />
              </div>
            </div>
            <p className="text-gray-400 text-sm">Total Hotspots</p>
            <p className="text-2xl font-bold text-white">{stats.total}</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 bg-gray-700 rounded">
                <Clock className="w-5 h-5 text-yellow-400" />
              </div>
            </div>
            <p className="text-gray-400 text-sm">Pending Review</p>
            <p className="text-2xl font-bold text-white">{stats.pending_review}</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 bg-gray-700 rounded">
                <CheckCircle className="w-5 h-5 text-green-400" />
              </div>
            </div>
            <p className="text-gray-400 text-sm">Reviewed</p>
            <p className="text-2xl font-bold text-white">{stats.reviewed}</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 bg-gray-700 rounded">
                <AlertTriangle className="w-5 h-5 text-red-400" />
              </div>
            </div>
            <p className="text-gray-400 text-sm">High Priority</p>
            <p className="text-2xl font-bold text-white">{stats.by_priority?.high || 0}</p>
          </div>
        </div>

        {/* Priority Distribution */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <h3 className="text-white font-medium mb-4">By Priority</h3>
            <div className="space-y-3">
              {['high', 'medium', 'low'].map((priority) => {
                const count = stats.by_priority?.[priority as keyof typeof stats.by_priority] || 0;
                const percentage = stats.total > 0 ? (count / stats.total) * 100 : 0;
                const colors: Record<string, string> = {
                  high: 'bg-red-500',
                  medium: 'bg-yellow-500',
                  low: 'bg-blue-500',
                };
                return (
                  <div key={priority} className="flex items-center gap-3">
                    <div className="w-20 text-sm text-gray-400 capitalize">{priority}</div>
                    <div className="flex-1 h-4 bg-gray-700 rounded overflow-hidden">
                      <div
                        className={`h-full ${colors[priority]} transition-all duration-300`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                    <div className="w-12 text-right text-sm font-medium text-white">{count}</div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <h3 className="text-white font-medium mb-4">By Resolution</h3>
            <div className="space-y-3">
              {['to_review', 'vulnerability', 'safe', 'acknowledged', 'fixed'].map((resolution) => {
                const count = stats.by_resolution?.[resolution as keyof typeof stats.by_resolution] || 0;
                const percentage = stats.total > 0 ? (count / stats.total) * 100 : 0;
                const colors: Record<string, string> = {
                  to_review: 'bg-yellow-500',
                  vulnerability: 'bg-red-500',
                  safe: 'bg-green-500',
                  acknowledged: 'bg-blue-500',
                  fixed: 'bg-green-500',
                };
                const labels: Record<string, string> = {
                  to_review: 'To Review',
                  vulnerability: 'Vulnerability',
                  safe: 'Safe',
                  acknowledged: 'Acknowledged',
                  fixed: 'Fixed',
                };
                return (
                  <div key={resolution} className="flex items-center gap-3">
                    <div className="w-24 text-sm text-gray-400">{labels[resolution]}</div>
                    <div className="flex-1 h-4 bg-gray-700 rounded overflow-hidden">
                      <div
                        className={`h-full ${colors[resolution]} transition-all duration-300`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                    <div className="w-12 text-right text-sm font-medium text-white">{count}</div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function SastPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('scans');
  const [showScanModal, setShowScanModal] = useState(false);
  const [selectedScan, setSelectedScan] = useState<{ id: string; name: string } | null>(null);

  const { data: scans, isLoading: scansLoading } = useQuery({
    queryKey: ['sast-scans'],
    queryFn: () => yellowTeamAPI.listSastScans().then((r) => r.data),
    enabled: activeTab === 'scans',
  });

  const createScanMutation = useMutation({
    mutationFn: yellowTeamAPI.startSastScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sast-scans'] });
      toast.success('SAST scan started');
    },
    onError: () => toast.error('Failed to start SAST scan'),
  });

  const deleteScanMutation = useMutation({
    mutationFn: yellowTeamAPI.deleteSastScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sast-scans'] });
      toast.success('Scan deleted');
    },
    onError: () => toast.error('Failed to delete scan'),
  });

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'scans', label: 'Scans', icon: <Play className="w-4 h-4" /> },
    { id: 'semgrep', label: 'Semgrep Rules', icon: <Braces className="w-4 h-4" /> },
    { id: 'taint', label: 'Taint Analysis', icon: <Workflow className="w-4 h-4" /> },
    { id: 'hotspots', label: 'Hotspots', icon: <Zap className="w-4 h-4" /> },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex justify-between items-center">
          <div className="flex items-center gap-3">
            <Code className="h-8 w-8 text-cyan-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">SAST Scanner</h1>
              <p className="text-gray-400">Static Application Security Testing</p>
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
                  setSelectedScan(null);
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
          {/* Scans Tab */}
          {activeTab === 'scans' && (
            <div>
              {selectedScan ? (
                <ScanFindingsView
                  scanId={selectedScan.id}
                  projectName={selectedScan.name}
                  onBack={() => setSelectedScan(null)}
                />
              ) : (
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <div>
                      <h2 className="text-lg font-semibold text-white">SAST Scans</h2>
                      <p className="text-gray-400 text-sm">
                        Analyze source code for security vulnerabilities
                      </p>
                    </div>
                    <button
                      onClick={() => setShowScanModal(true)}
                      className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded transition-colors"
                    >
                      <Plus className="w-4 h-4" />
                      Start Scan
                    </button>
                  </div>

                  {scansLoading ? (
                    <div className="flex justify-center items-center p-12">
                      <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
                    </div>
                  ) : scans && scans.length > 0 ? (
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
                          {scans.map((scan: SastScan) => (
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
                                <div className="flex items-center justify-end gap-2">
                                  <button
                                    onClick={() => setSelectedScan({ id: scan.id, name: scan.project_name })}
                                    className="p-2 hover:bg-gray-700 rounded text-gray-400 hover:text-white"
                                  >
                                    <Eye className="w-4 h-4" />
                                  </button>
                                  <button
                                    onClick={() => deleteScanMutation.mutate(scan.id)}
                                    className="p-2 hover:bg-gray-700 rounded text-red-400 hover:text-red-300"
                                  >
                                    <Trash2 className="w-4 h-4" />
                                  </button>
                                </div>
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
                        onClick={() => setShowScanModal(true)}
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

          {/* Semgrep Rules Tab */}
          {activeTab === 'semgrep' && <SemgrepRulesTab />}

          {/* Taint Analysis Tab */}
          {activeTab === 'taint' && (
            <div className="bg-gray-800 rounded-lg p-8 text-center border border-gray-700">
              <Workflow className="w-16 h-16 text-cyan-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-white mb-2">Taint Analysis</h3>
              <p className="text-gray-400 mb-4 max-w-md mx-auto">
                Taint analysis tracks how untrusted data flows through your application
                to detect injection vulnerabilities.
              </p>
              <p className="text-gray-500 text-sm">
                Run a SAST scan to view taint analysis results for that scan.
              </p>
            </div>
          )}

          {/* Hotspots Tab */}
          {activeTab === 'hotspots' && <HotspotsOverviewTab />}
        </div>

        {/* Modals */}
        <CreateScanModal
          isOpen={showScanModal}
          onClose={() => setShowScanModal(false)}
          onCreate={(data) => createScanMutation.mutate(data)}
        />
      </div>
    </Layout>
  );
}
