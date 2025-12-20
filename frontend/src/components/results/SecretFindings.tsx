import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'react-toastify';
import { secretFindingsAPI } from '../../services/api';
import type { SecretFinding, SecretFindingStats, SecretStatus } from '../../types';
import {
  Key,
  AlertTriangle,
  Shield,
  Eye,
  EyeOff,
  Check,
  X,
  MessageSquare,
  ChevronDown,
  ChevronUp,
  FileText,
  Lock,
  Unlock,
} from 'lucide-react';

interface SecretFindingsProps {
  scanId: string;
}

const SecretFindings: React.FC<SecretFindingsProps> = ({ scanId }) => {
  const [findings, setFindings] = useState<SecretFinding[]>([]);
  const [stats, setStats] = useState<SecretFindingStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [updating, setUpdating] = useState(false);

  const loadFindings = useCallback(async () => {
    try {
      setLoading(true);
      const response = await secretFindingsAPI.getByScan(scanId);
      let filteredFindings = response.data;

      // Apply client-side filters
      if (statusFilter) {
        filteredFindings = filteredFindings.filter((f) => f.status === statusFilter);
      }
      if (severityFilter) {
        filteredFindings = filteredFindings.filter((f) => f.severity === severityFilter);
      }
      if (typeFilter) {
        filteredFindings = filteredFindings.filter((f) => f.secret_type === typeFilter);
      }

      setFindings(filteredFindings);
    } catch (error) {
      console.error('Failed to load secret findings:', error);
      toast.error('Failed to load secret findings');
    } finally {
      setLoading(false);
    }
  }, [scanId, statusFilter, severityFilter, typeFilter]);

  const loadStats = useCallback(async () => {
    try {
      const response = await secretFindingsAPI.getStats(scanId);
      setStats(response.data);
    } catch (error) {
      console.error('Failed to load secret finding stats:', error);
    }
  }, [scanId]);

  useEffect(() => {
    loadFindings();
    loadStats();
  }, [loadFindings, loadStats]);

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedIds(new Set(findings.map((f) => f.id)));
    } else {
      setSelectedIds(new Set());
    }
  };

  const handleSelectOne = (id: string, checked: boolean) => {
    const newSelected = new Set(selectedIds);
    if (checked) {
      newSelected.add(id);
    } else {
      newSelected.delete(id);
    }
    setSelectedIds(newSelected);
  };

  const handleUpdateStatus = async (id: string, status: SecretStatus) => {
    try {
      setUpdating(true);
      await secretFindingsAPI.update(id, { status });
      toast.success(`Status updated to ${status}`);
      loadFindings();
      loadStats();
    } catch (error) {
      console.error('Failed to update status:', error);
      toast.error('Failed to update status');
    } finally {
      setUpdating(false);
    }
  };

  const handleBulkUpdateStatus = async (status: SecretStatus) => {
    if (selectedIds.size === 0) return;
    try {
      setUpdating(true);
      const result = await secretFindingsAPI.bulkUpdateStatus(
        Array.from(selectedIds),
        status
      );
      toast.success(result.data.message);
      setSelectedIds(new Set());
      loadFindings();
      loadStats();
    } catch (error) {
      console.error('Failed to bulk update status:', error);
      toast.error('Failed to update findings');
    } finally {
      setUpdating(false);
    }
  };

  const handleMarkFalsePositive = async (id: string, isFalsePositive: boolean) => {
    try {
      setUpdating(true);
      await secretFindingsAPI.update(id, {
        false_positive: isFalsePositive,
        status: isFalsePositive ? 'false_positive' : 'open',
      });
      toast.success(isFalsePositive ? 'Marked as false positive' : 'Unmarked false positive');
      loadFindings();
      loadStats();
    } catch (error) {
      console.error('Failed to update false positive status:', error);
      toast.error('Failed to update');
    } finally {
      setUpdating(false);
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    const baseClass = 'px-2 py-1 text-xs font-semibold rounded-full';
    switch (severity.toLowerCase()) {
      case 'critical':
        return `${baseClass} bg-red-500/20 text-red-400`;
      case 'high':
        return `${baseClass} bg-orange-500/20 text-orange-400`;
      case 'medium':
        return `${baseClass} bg-yellow-500/20 text-yellow-400`;
      case 'low':
        return `${baseClass} bg-blue-500/20 text-blue-400`;
      default:
        return `${baseClass} bg-gray-500/20 text-gray-400`;
    }
  };

  const getStatusBadgeClass = (status: string) => {
    const baseClass = 'px-2 py-1 text-xs font-semibold rounded-full';
    switch (status) {
      case 'open':
        return `${baseClass} bg-red-500/20 text-red-400`;
      case 'investigating':
        return `${baseClass} bg-yellow-500/20 text-yellow-400`;
      case 'resolved':
        return `${baseClass} bg-green-500/20 text-green-400`;
      case 'false_positive':
        return `${baseClass} bg-gray-500/20 text-gray-400`;
      default:
        return `${baseClass} bg-gray-500/20 text-gray-400`;
    }
  };

  const getSecretTypeIcon = (secretType: string) => {
    const type = secretType.toLowerCase();
    if (type.includes('key') || type.includes('api')) {
      return <Key className="h-4 w-4" />;
    }
    if (type.includes('password') || type.includes('secret')) {
      return <Lock className="h-4 w-4" />;
    }
    if (type.includes('token')) {
      return <Shield className="h-4 w-4" />;
    }
    return <FileText className="h-4 w-4" />;
  };

  const formatSecretType = (type: string) => {
    return type
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (l) => l.toUpperCase());
  };

  const getConfidenceBadge = (confidence: number) => {
    const percent = Math.round(confidence * 100);
    if (percent >= 90) {
      return (
        <span className="text-xs text-green-400 bg-green-500/10 px-2 py-0.5 rounded">
          {percent}% confident
        </span>
      );
    }
    if (percent >= 70) {
      return (
        <span className="text-xs text-yellow-400 bg-yellow-500/10 px-2 py-0.5 rounded">
          {percent}% confident
        </span>
      );
    }
    return (
      <span className="text-xs text-gray-400 bg-gray-500/10 px-2 py-0.5 rounded">
        {percent}% confident
      </span>
    );
  };

  const uniqueTypes = [...new Set(findings.map((f) => f.secret_type))];

  if (loading) {
    return (
      <div className="flex justify-center items-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div>
      </div>
    );
  }

  if (findings.length === 0 && !stats?.total_findings) {
    return (
      <div className="text-center py-12 text-gray-400">
        <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>No exposed secrets detected in this scan.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Stats Summary */}
      {stats && stats.total_findings > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
            <div className="text-sm text-gray-400">Total Secrets</div>
            <div className="text-2xl font-bold text-white">{stats.total_findings}</div>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
            <div className="text-sm text-gray-400">Critical</div>
            <div className="text-2xl font-bold text-red-500">{stats.critical_count}</div>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
            <div className="text-sm text-gray-400">High</div>
            <div className="text-2xl font-bold text-orange-400">{stats.high_count}</div>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
            <div className="text-sm text-gray-400">Open</div>
            <div className="text-2xl font-bold text-red-400">{stats.open_count}</div>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
            <div className="text-sm text-gray-400">Resolved</div>
            <div className="text-2xl font-bold text-green-400">{stats.resolved_count}</div>
          </div>
        </div>
      )}

      {/* Secret Types Breakdown */}
      {stats && stats.by_type.length > 0 && (
        <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
          <h4 className="text-sm font-medium text-gray-300 mb-3">Secrets by Type</h4>
          <div className="flex flex-wrap gap-2">
            {stats.by_type.map((typeCount) => (
              <div
                key={typeCount.secret_type}
                className="flex items-center gap-2 bg-gray-700/50 px-3 py-1.5 rounded-full text-sm"
              >
                {getSecretTypeIcon(typeCount.secret_type)}
                <span className="text-gray-300">{formatSecretType(typeCount.secret_type)}</span>
                <span className="bg-gray-600 px-2 py-0.5 rounded-full text-xs text-white">
                  {typeCount.count}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
        <div className="flex flex-wrap gap-4 items-center">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Status</label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="block w-full rounded-md border-gray-600 bg-gray-700 text-white shadow-sm focus:border-cyan-500 focus:ring-cyan-500"
            >
              <option value="">All</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="false_positive">False Positive</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Severity</label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="block w-full rounded-md border-gray-600 bg-gray-700 text-white shadow-sm focus:border-cyan-500 focus:ring-cyan-500"
            >
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Type</label>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="block w-full rounded-md border-gray-600 bg-gray-700 text-white shadow-sm focus:border-cyan-500 focus:ring-cyan-500"
            >
              <option value="">All Types</option>
              {uniqueTypes.map((type) => (
                <option key={type} value={type}>
                  {formatSecretType(type)}
                </option>
              ))}
            </select>
          </div>

          {selectedIds.size > 0 && (
            <div className="ml-auto flex items-center gap-2">
              <span className="text-sm text-gray-400">
                {selectedIds.size} selected
              </span>
              <button
                onClick={() => handleBulkUpdateStatus('resolved')}
                disabled={updating}
                className="px-3 py-1.5 text-sm bg-green-600 hover:bg-green-500 text-white rounded-md disabled:opacity-50"
              >
                Mark Resolved
              </button>
              <button
                onClick={() => handleBulkUpdateStatus('false_positive')}
                disabled={updating}
                className="px-3 py-1.5 text-sm bg-gray-600 hover:bg-gray-500 text-white rounded-md disabled:opacity-50"
              >
                False Positive
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-2">
        {findings.map((finding) => (
          <div
            key={finding.id}
            className={`bg-gray-800 border rounded-lg overflow-hidden transition-all ${
              finding.false_positive
                ? 'border-gray-600 opacity-60'
                : finding.status === 'resolved'
                ? 'border-green-700'
                : 'border-gray-700'
            }`}
          >
            {/* Finding Header */}
            <div className="p-4 flex items-center gap-4">
              <input
                type="checkbox"
                checked={selectedIds.has(finding.id)}
                onChange={(e) => handleSelectOne(finding.id, e.target.checked)}
                className="rounded border-gray-600 bg-gray-700 text-cyan-500 focus:ring-cyan-500"
              />

              <div className="flex items-center gap-2 text-gray-400">
                {getSecretTypeIcon(finding.secret_type)}
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-medium text-white">
                    {formatSecretType(finding.secret_type)}
                  </span>
                  <span className={getSeverityBadgeClass(finding.severity)}>
                    {finding.severity.toUpperCase()}
                  </span>
                  <span className={getStatusBadgeClass(finding.status)}>
                    {finding.status.replace('_', ' ').toUpperCase()}
                  </span>
                  {getConfidenceBadge(finding.confidence)}
                </div>
                <div className="text-sm text-gray-400">
                  <span className="font-mono">{finding.host_ip}</span>
                  {finding.port && <span>:{finding.port}</span>}
                  <span className="mx-2">|</span>
                  <span>{finding.source_type}: {finding.source_location}</span>
                  {finding.line_number && (
                    <span className="text-gray-500"> (line {finding.line_number})</span>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-2">
                {!finding.false_positive && finding.status !== 'resolved' && (
                  <>
                    <button
                      onClick={() => handleUpdateStatus(finding.id, 'resolved')}
                      disabled={updating}
                      className="p-1.5 text-green-400 hover:bg-green-500/20 rounded transition-colors"
                      title="Mark Resolved"
                    >
                      <Check className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => handleMarkFalsePositive(finding.id, true)}
                      disabled={updating}
                      className="p-1.5 text-gray-400 hover:bg-gray-500/20 rounded transition-colors"
                      title="Mark False Positive"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </>
                )}
                {finding.false_positive && (
                  <button
                    onClick={() => handleMarkFalsePositive(finding.id, false)}
                    disabled={updating}
                    className="p-1.5 text-yellow-400 hover:bg-yellow-500/20 rounded transition-colors"
                    title="Unmark False Positive"
                  >
                    <Unlock className="h-4 w-4" />
                  </button>
                )}
                <button
                  onClick={() =>
                    setExpandedId(expandedId === finding.id ? null : finding.id)
                  }
                  className="p-1.5 text-gray-400 hover:bg-gray-500/20 rounded transition-colors"
                >
                  {expandedId === finding.id ? (
                    <ChevronUp className="h-4 w-4" />
                  ) : (
                    <ChevronDown className="h-4 w-4" />
                  )}
                </button>
              </div>
            </div>

            {/* Expanded Details */}
            {expandedId === finding.id && (
              <div className="border-t border-gray-700 p-4 bg-gray-850">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <h4 className="text-sm font-medium text-gray-400 mb-2">
                      Redacted Value
                    </h4>
                    <div className="bg-gray-900 p-3 rounded font-mono text-sm text-cyan-400 break-all">
                      {finding.redacted_value}
                    </div>
                  </div>

                  {finding.context && (
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2">
                        Context
                      </h4>
                      <div className="bg-gray-900 p-3 rounded font-mono text-sm text-gray-300 whitespace-pre-wrap break-all max-h-32 overflow-y-auto">
                        {finding.context}
                      </div>
                    </div>
                  )}
                </div>

                <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-gray-500">Source Type:</span>
                    <span className="ml-2 text-gray-300">{finding.source_type}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">Location:</span>
                    <span className="ml-2 text-gray-300 font-mono">
                      {finding.source_location}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500">Detected:</span>
                    <span className="ml-2 text-gray-300">
                      {new Date(finding.created_at).toLocaleString()}
                    </span>
                  </div>
                  {finding.resolved_at && (
                    <div>
                      <span className="text-gray-500">Resolved:</span>
                      <span className="ml-2 text-gray-300">
                        {new Date(finding.resolved_at).toLocaleString()}
                      </span>
                    </div>
                  )}
                </div>

                {finding.notes && (
                  <div className="mt-4">
                    <h4 className="text-sm font-medium text-gray-400 mb-2 flex items-center gap-2">
                      <MessageSquare className="h-4 w-4" />
                      Notes
                    </h4>
                    <div className="bg-gray-900 p-3 rounded text-sm text-gray-300">
                      {finding.notes}
                    </div>
                  </div>
                )}

                {/* Remediation Guidance */}
                <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded">
                  <h4 className="text-sm font-medium text-yellow-400 mb-2 flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4" />
                    Remediation Guidance
                  </h4>
                  <ul className="text-sm text-gray-300 space-y-1 list-disc list-inside">
                    <li>Immediately rotate or revoke the exposed credential</li>
                    <li>Check audit logs for any unauthorized access using this credential</li>
                    <li>Review how the secret was exposed and fix the root cause</li>
                    <li>Implement secrets management best practices (e.g., HashiCorp Vault, AWS Secrets Manager)</li>
                    <li>Add pre-commit hooks to prevent secrets from being committed</li>
                  </ul>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {findings.length === 0 && (
        <div className="text-center py-8 text-gray-400">
          No findings match your current filters.
        </div>
      )}
    </div>
  );
};

export default SecretFindings;
