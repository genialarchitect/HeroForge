import React, { useState, useEffect } from 'react';
import {
  History,
  GitBranch,
  User,
  Clock,
  ArrowRight,
  RotateCcw,
  FileText,
  ChevronDown,
  ChevronRight,
  Plus,
  Minus,
  RefreshCw,
} from 'lucide-react';
import { toast } from 'react-toastify';
import type { EvidenceVersion, VersionHistory, VersionChange } from '../../types/evidence';
import { evidenceAPI } from '../../services/evidenceApi';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';

interface EvidenceVersionHistoryProps {
  evidenceId: string;
  currentVersion: number;
  onRollback?: (targetVersionId: string) => void;
}

const EvidenceVersionHistory: React.FC<EvidenceVersionHistoryProps> = ({
  evidenceId,
  currentVersion,
  onRollback,
}) => {
  const [history, setHistory] = useState<VersionHistory | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedVersion, setExpandedVersion] = useState<number | null>(null);
  const [comparing, setComparing] = useState<{ from: string; to: string } | null>(null);
  const [comparison, setComparison] = useState<{
    changes: VersionChange[];
    summary: string;
    content_changed: boolean;
  } | null>(null);
  const [loadingComparison, setLoadingComparison] = useState(false);
  const [rollingBack, setRollingBack] = useState<string | null>(null);

  useEffect(() => {
    loadHistory();
  }, [evidenceId]);

  const loadHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await evidenceAPI.getVersionHistory(evidenceId);
      setHistory(response.data);
    } catch (err) {
      console.error('Failed to load version history:', err);
      setError('Failed to load version history');
    } finally {
      setLoading(false);
    }
  };

  const handleCompare = async (baseId: string, compareId: string) => {
    if (comparing?.from === baseId && comparing?.to === compareId) {
      setComparing(null);
      setComparison(null);
      return;
    }

    setComparing({ from: baseId, to: compareId });
    setLoadingComparison(true);

    try {
      const response = await evidenceAPI.compareVersions(baseId, compareId);
      setComparison({
        changes: response.data.changes,
        summary: response.data.summary,
        content_changed: response.data.content_changed,
      });
    } catch (err) {
      console.error('Failed to compare versions:', err);
      toast.error('Failed to compare versions');
      setComparing(null);
    } finally {
      setLoadingComparison(false);
    }
  };

  const handleRollback = async (targetVersionId: string) => {
    if (!onRollback) return;

    setRollingBack(targetVersionId);
    try {
      await evidenceAPI.rollback(evidenceId, targetVersionId);
      toast.success('Successfully rolled back to previous version');
      onRollback(targetVersionId);
      loadHistory();
    } catch (err) {
      console.error('Failed to rollback:', err);
      toast.error('Failed to rollback to previous version');
    } finally {
      setRollingBack(null);
    }
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const getChangeIcon = (changeType: string) => {
    switch (changeType) {
      case 'added':
        return <Plus className="h-3 w-3 text-green-500" />;
      case 'removed':
        return <Minus className="h-3 w-3 text-red-500" />;
      case 'modified':
      case 'content_updated':
        return <RefreshCw className="h-3 w-3 text-yellow-500" />;
      default:
        return null;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <LoadingSpinner />
        <span className="ml-2 text-slate-500">Loading version history...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-8">
        <p className="text-red-500 mb-4">{error}</p>
        <Button variant="outline" onClick={loadHistory}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Retry
        </Button>
      </div>
    );
  }

  if (!history || history.versions.length === 0) {
    return (
      <div className="text-center py-8 text-slate-500">
        <History className="h-12 w-12 mx-auto mb-3 opacity-50" />
        <p>No version history available</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <History className="h-5 w-5 text-primary" />
          <h3 className="font-semibold text-slate-900 dark:text-white">
            Version History
          </h3>
          <Badge variant="secondary">{history.total_versions} versions</Badge>
        </div>
        <Button variant="ghost" size="sm" onClick={loadHistory}>
          <RefreshCw className="h-4 w-4" />
        </Button>
      </div>

      {/* Version Timeline */}
      <div className="relative">
        {/* Timeline line */}
        <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-light-border dark:bg-dark-border" />

        {/* Versions */}
        <div className="space-y-3">
          {history.versions.slice().reverse().map((version, index) => {
            const isLatest = version.version === currentVersion;
            const isExpanded = expandedVersion === version.version;
            const canRollback = !isLatest && onRollback;
            const prevVersion = history.versions.slice().reverse()[index + 1];

            return (
              <div key={version.evidence_id} className="relative pl-10">
                {/* Timeline dot */}
                <div
                  className={`absolute left-2.5 w-3 h-3 rounded-full border-2 ${
                    isLatest
                      ? 'bg-primary border-primary'
                      : 'bg-light-surface dark:bg-dark-surface border-light-border dark:border-dark-border'
                  }`}
                />

                {/* Version card */}
                <div
                  className={`bg-light-surface dark:bg-dark-surface border rounded-lg transition-colors ${
                    isLatest
                      ? 'border-primary/50'
                      : 'border-light-border dark:border-dark-border'
                  }`}
                >
                  {/* Version header */}
                  <button
                    onClick={() => setExpandedVersion(isExpanded ? null : version.version)}
                    className="w-full flex items-center justify-between p-3 hover:bg-light-hover dark:hover:bg-dark-hover rounded-t-lg transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <div className="flex items-center gap-2">
                        <GitBranch className="h-4 w-4 text-slate-500" />
                        <span className="font-medium text-slate-900 dark:text-white">
                          Version {version.version}
                        </span>
                        {isLatest && (
                          <Badge variant="success" size="sm">Current</Badge>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-slate-500">
                        {formatSize(version.content_size)}
                      </span>
                      {isExpanded ? (
                        <ChevronDown className="h-4 w-4 text-slate-400" />
                      ) : (
                        <ChevronRight className="h-4 w-4 text-slate-400" />
                      )}
                    </div>
                  </button>

                  {/* Version details (when expanded) */}
                  {isExpanded && (
                    <div className="px-3 pb-3 space-y-3 border-t border-light-border dark:border-dark-border">
                      {/* Metadata */}
                      <div className="grid grid-cols-2 gap-3 pt-3 text-sm">
                        <div className="flex items-center gap-2 text-slate-600 dark:text-slate-400">
                          <User className="h-4 w-4" />
                          <span>{version.created_by}</span>
                        </div>
                        <div className="flex items-center gap-2 text-slate-600 dark:text-slate-400">
                          <Clock className="h-4 w-4" />
                          <span>{formatDate(version.created_at)}</span>
                        </div>
                      </div>

                      {/* Change description */}
                      {version.change_description && (
                        <div className="p-2 bg-light-hover dark:bg-dark-hover rounded text-sm text-slate-600 dark:text-slate-400">
                          <span className="font-medium">Change: </span>
                          {version.change_description}
                        </div>
                      )}

                      {/* Content summary */}
                      {version.content_summary && (
                        <div className="p-2 bg-light-hover dark:bg-dark-hover rounded text-sm">
                          <div className="flex items-center gap-2 text-slate-500 mb-1">
                            <FileText className="h-3 w-3" />
                            <span>Content Preview</span>
                          </div>
                          <p className="text-slate-700 dark:text-slate-300 font-mono text-xs truncate">
                            {version.content_summary}
                          </p>
                        </div>
                      )}

                      {/* Content hash */}
                      <div className="text-xs text-slate-500 font-mono">
                        Hash: {version.content_hash.slice(0, 16)}...
                      </div>

                      {/* Actions */}
                      <div className="flex items-center gap-2 pt-2 border-t border-light-border dark:border-dark-border">
                        {prevVersion && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() =>
                              handleCompare(prevVersion.evidence_id, version.evidence_id)
                            }
                          >
                            <ArrowRight className="h-4 w-4 mr-1" />
                            Compare with v{prevVersion.version}
                          </Button>
                        )}
                        {canRollback && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleRollback(version.evidence_id)}
                            disabled={rollingBack === version.evidence_id}
                            className="text-yellow-600 hover:text-yellow-700"
                          >
                            {rollingBack === version.evidence_id ? (
                              <>
                                <LoadingSpinner />
                                <span className="ml-1">Rolling back...</span>
                              </>
                            ) : (
                              <>
                                <RotateCcw className="h-4 w-4 mr-1" />
                                Rollback to this version
                              </>
                            )}
                          </Button>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Comparison Results */}
      {comparing && (
        <div className="mt-4 p-4 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
          <h4 className="font-medium text-slate-900 dark:text-white mb-3">
            Version Comparison
          </h4>

          {loadingComparison ? (
            <div className="flex items-center justify-center py-4">
              <LoadingSpinner />
              <span className="ml-2 text-slate-500">Loading comparison...</span>
            </div>
          ) : comparison ? (
            <div className="space-y-3">
              <p className="text-sm text-slate-600 dark:text-slate-400">
                {comparison.summary}
              </p>

              {comparison.content_changed && (
                <Badge variant="warning">Content Changed</Badge>
              )}

              {comparison.changes.length > 0 && (
                <div className="space-y-2">
                  {comparison.changes.map((change, i) => (
                    <div
                      key={i}
                      className="flex items-start gap-2 p-2 bg-light-hover dark:bg-dark-hover rounded text-sm"
                    >
                      {getChangeIcon(change.change_type)}
                      <div className="flex-1 min-w-0">
                        <span className="font-medium text-slate-700 dark:text-slate-300">
                          {change.field}
                        </span>
                        {change.old_value && (
                          <div className="text-red-500 line-through truncate">
                            {change.old_value}
                          </div>
                        )}
                        {change.new_value && (
                          <div className="text-green-500 truncate">
                            {change.new_value}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setComparing(null);
                  setComparison(null);
                }}
              >
                Close Comparison
              </Button>
            </div>
          ) : (
            <p className="text-slate-500">No comparison data available</p>
          )}
        </div>
      )}
    </div>
  );
};

export default EvidenceVersionHistory;
