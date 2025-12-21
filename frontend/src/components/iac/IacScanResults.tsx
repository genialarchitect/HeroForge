import React, { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  FileCode,
  AlertTriangle,
  Shield,
  ChevronRight,
  Filter,
  RefreshCw,
  ExternalLink,
  CheckCircle,
  XCircle,
  Clock,
} from 'lucide-react';
import { iacAPI } from '../../services/api';
import type { IacScan, IacFinding, IacFileInfo, IacFindingSummary } from '../../types';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import IacFileViewer from './IacFileViewer';

interface IacScanResultsProps {
  scanId: string;
  onBack?: () => void;
}

const getSeverityColor = (severity: string): string => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-red-500/20 text-red-400 border-red-500/50';
    case 'high':
      return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
    case 'medium':
      return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
    case 'low':
      return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
    case 'info':
      return 'bg-gray-500/20 text-gray-400 border-gray-500/50';
    default:
      return 'bg-gray-500/20 text-gray-400 border-gray-500/50';
  }
};

const getStatusIcon = (status: string) => {
  switch (status.toLowerCase()) {
    case 'completed':
      return <CheckCircle className="w-5 h-5 text-green-400" />;
    case 'failed':
      return <XCircle className="w-5 h-5 text-red-400" />;
    case 'running':
      return <RefreshCw className="w-5 h-5 text-cyan-400 animate-spin" />;
    default:
      return <Clock className="w-5 h-5 text-yellow-400" />;
  }
};

const getCategoryLabel = (category: string): string => {
  const labels: Record<string, string> = {
    hardcoded_secret: 'Hardcoded Secret',
    iam_misconfiguration: 'IAM Misconfiguration',
    public_storage: 'Public Storage',
    missing_encryption: 'Missing Encryption',
    missing_logging: 'Missing Logging',
    network_exposure: 'Network Exposure',
    missing_tags: 'Missing Tags',
    deprecated_resource: 'Deprecated Resource',
    weak_cryptography: 'Weak Cryptography',
    insecure_default: 'Insecure Default',
    compliance_violation: 'Compliance Violation',
    best_practice: 'Best Practice',
  };
  return labels[category] || category;
};

export default function IacScanResults({ scanId, onBack }: IacScanResultsProps) {
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');

  // Fetch scan details
  const {
    data: scanData,
    isLoading: isLoadingScan,
    refetch: refetchScan,
  } = useQuery({
    queryKey: ['iac-scan', scanId],
    queryFn: async () => {
      const response = await iacAPI.getScan(scanId);
      return response.data;
    },
    refetchInterval: (data) => {
      // Poll while running
      if (data?.scan?.status === 'running' || data?.scan?.status === 'pending') {
        return 3000;
      }
      return false;
    },
  });

  // Fetch findings
  const { data: findings = [], isLoading: isLoadingFindings } = useQuery({
    queryKey: ['iac-findings', scanId],
    queryFn: async () => {
      const response = await iacAPI.getFindings(scanId);
      return response.data;
    },
    enabled: scanData?.scan?.status === 'completed',
  });

  const scan = scanData?.scan;
  const files = scanData?.files || [];
  const findingSummary = scanData?.finding_summary;

  // Filter findings
  const filteredFindings = findings.filter((finding) => {
    if (severityFilter !== 'all' && finding.severity !== severityFilter) {
      return false;
    }
    if (categoryFilter !== 'all' && finding.category !== categoryFilter) {
      return false;
    }
    if (selectedFile && finding.file_id !== selectedFile) {
      return false;
    }
    return true;
  });

  // Get unique categories for filter
  const categories = [...new Set(findings.map((f) => f.category))];

  if (isLoadingScan) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="w-12 h-12 text-yellow-400 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-white mb-2">Scan Not Found</h3>
        <p className="text-gray-400">The requested scan could not be found.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {onBack && (
            <button
              onClick={onBack}
              className="text-gray-400 hover:text-white transition-colors"
            >
              <ChevronRight className="w-5 h-5 rotate-180" />
            </button>
          )}
          <div>
            <h2 className="text-xl font-semibold text-white">{scan.name}</h2>
            <div className="flex items-center gap-2 text-sm text-gray-400 mt-1">
              {getStatusIcon(scan.status)}
              <span className="capitalize">{scan.status}</span>
              <span className="text-gray-600">|</span>
              <span>{new Date(scan.created_at).toLocaleString()}</span>
            </div>
          </div>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetchScan()}>
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Summary Cards */}
      {findingSummary && (
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
          <SummaryCard
            label="Total Findings"
            value={findingSummary.total}
            color="text-white"
          />
          <SummaryCard
            label="Critical"
            value={findingSummary.critical}
            color="text-red-400"
          />
          <SummaryCard
            label="High"
            value={findingSummary.high}
            color="text-orange-400"
          />
          <SummaryCard
            label="Medium"
            value={findingSummary.medium}
            color="text-yellow-400"
          />
          <SummaryCard
            label="Low"
            value={findingSummary.low}
            color="text-blue-400"
          />
          <SummaryCard
            label="Info"
            value={findingSummary.info}
            color="text-gray-400"
          />
        </div>
      )}

      {/* Scan Progress */}
      {(scan.status === 'running' || scan.status === 'pending') && (
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <div className="flex items-center gap-4">
            <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
            <div>
              <h3 className="text-lg font-semibold text-white">Scan in Progress</h3>
              <p className="text-gray-400">
                Analyzing {scan.file_count} files for security issues...
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Error Message */}
      {scan.status === 'failed' && scan.error_message && (
        <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <XCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <h4 className="font-medium text-red-400">Scan Failed</h4>
              <p className="text-sm text-gray-300 mt-1">{scan.error_message}</p>
            </div>
          </div>
        </div>
      )}

      {/* Results Grid */}
      {scan.status === 'completed' && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Files Sidebar */}
          <div className="lg:col-span-1">
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
              <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">
                Files ({files.length})
              </h3>
              <div className="space-y-2">
                <button
                  onClick={() => setSelectedFile(null)}
                  className={`w-full text-left px-3 py-2 rounded-lg transition-colors ${
                    selectedFile === null
                      ? 'bg-cyan-500/20 text-cyan-400'
                      : 'text-gray-300 hover:bg-gray-700'
                  }`}
                >
                  All Files
                </button>
                {files.map((file) => (
                  <button
                    key={file.id}
                    onClick={() => setSelectedFile(file.id)}
                    className={`w-full text-left px-3 py-2 rounded-lg transition-colors ${
                      selectedFile === file.id
                        ? 'bg-cyan-500/20 text-cyan-400'
                        : 'text-gray-300 hover:bg-gray-700'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <FileCode className="w-4 h-4 flex-shrink-0" />
                      <span className="truncate text-sm">{file.filename}</span>
                      {file.finding_count > 0 && (
                        <span className="ml-auto text-xs bg-red-500/20 text-red-400 px-1.5 rounded">
                          {file.finding_count}
                        </span>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Findings List */}
          <div className="lg:col-span-3">
            {/* Filters */}
            <div className="flex items-center gap-4 mb-4">
              <Filter className="w-4 h-4 text-gray-400" />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-gray-700 border border-gray-600 rounded-lg px-3 py-1.5 text-sm text-white"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="bg-gray-700 border border-gray-600 rounded-lg px-3 py-1.5 text-sm text-white"
              >
                <option value="all">All Categories</option>
                {categories.map((cat) => (
                  <option key={cat} value={cat}>
                    {getCategoryLabel(cat)}
                  </option>
                ))}
              </select>
              <span className="text-sm text-gray-400 ml-auto">
                {filteredFindings.length} finding(s)
              </span>
            </div>

            {/* Findings */}
            {isLoadingFindings ? (
              <div className="flex items-center justify-center h-32">
                <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin" />
              </div>
            ) : filteredFindings.length === 0 ? (
              <div className="text-center py-12 bg-gray-800 rounded-lg border border-gray-700">
                <Shield className="w-12 h-12 text-green-400 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">No Issues Found</h3>
                <p className="text-gray-400">
                  {findings.length === 0
                    ? 'No security issues were detected in your IaC files.'
                    : 'No findings match the current filters.'}
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredFindings.map((finding) => (
                  <FindingCard key={finding.id} finding={finding} files={files} />
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function SummaryCard({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
      <div className="text-sm text-gray-400">{label}</div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
    </div>
  );
}

function FindingCard({
  finding,
  files,
}: {
  finding: IacFinding;
  files: IacFileInfo[];
}) {
  const [isExpanded, setIsExpanded] = useState(false);
  const file = files.find((f) => f.id === finding.file_id);

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full text-left px-4 py-3 flex items-start gap-3 hover:bg-gray-700/50 transition-colors"
      >
        <div className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityColor(finding.severity)}`}>
          {finding.severity.toUpperCase()}
        </div>
        <div className="flex-1 min-w-0">
          <div className="font-medium text-white">{finding.title}</div>
          <div className="text-sm text-gray-400 mt-0.5">
            {file?.filename} : Line {finding.line_start}
            {finding.line_end !== finding.line_start && ` - ${finding.line_end}`}
          </div>
        </div>
        <div className="text-xs text-gray-500 bg-gray-700 px-2 py-1 rounded">
          {getCategoryLabel(finding.category)}
        </div>
        <ChevronRight
          className={`w-5 h-5 text-gray-400 transition-transform ${
            isExpanded ? 'rotate-90' : ''
          }`}
        />
      </button>

      {isExpanded && (
        <div className="px-4 pb-4 space-y-4 border-t border-gray-700 pt-3">
          <div>
            <h4 className="text-sm font-medium text-gray-400 mb-1">Description</h4>
            <p className="text-sm text-gray-300">{finding.description}</p>
          </div>

          {finding.resource_type && (
            <div>
              <h4 className="text-sm font-medium text-gray-400 mb-1">Resource</h4>
              <p className="text-sm text-gray-300">
                {finding.resource_type}
                {finding.resource_name && ` - ${finding.resource_name}`}
              </p>
            </div>
          )}

          {finding.code_snippet && (
            <div>
              <h4 className="text-sm font-medium text-gray-400 mb-1">Code</h4>
              <pre className="bg-gray-900 rounded p-3 text-xs text-gray-300 overflow-x-auto">
                {finding.code_snippet}
              </pre>
            </div>
          )}

          <div>
            <h4 className="text-sm font-medium text-gray-400 mb-1">Remediation</h4>
            <p className="text-sm text-gray-300">{finding.remediation}</p>
          </div>

          {finding.documentation_url && (
            <a
              href={finding.documentation_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300"
            >
              Learn More <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>
      )}
    </div>
  );
}
