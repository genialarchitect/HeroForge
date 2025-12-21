import React, { useState, useEffect } from 'react';
import {
  FileText,
  Shield,
  Clock,
  User,
  CheckCircle,
  XCircle,
  AlertCircle,
  Archive,
  History,
  Tag,
  Link,
  X,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import type { Evidence, EvidenceVersion, EvidenceStatus } from '../../types/evidence';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { evidenceAPI } from '../../services/evidenceApi';

interface EvidenceViewerProps {
  evidence: Evidence;
  onClose?: () => void;
  onStatusChange?: (evidence: Evidence, status: EvidenceStatus) => void;
}

const statusConfig: Record<
  EvidenceStatus,
  { label: string; color: 'green' | 'yellow' | 'red' | 'gray' | 'blue'; icon: React.ReactNode }
> = {
  active: {
    label: 'Active',
    color: 'green',
    icon: <CheckCircle className="h-4 w-4" />,
  },
  pending_review: {
    label: 'Pending Review',
    color: 'yellow',
    icon: <AlertCircle className="h-4 w-4" />,
  },
  approved: {
    label: 'Approved',
    color: 'green',
    icon: <CheckCircle className="h-4 w-4" />,
  },
  rejected: {
    label: 'Rejected',
    color: 'red',
    icon: <XCircle className="h-4 w-4" />,
  },
  superseded: {
    label: 'Superseded',
    color: 'blue',
    icon: <Archive className="h-4 w-4" />,
  },
  archived: {
    label: 'Archived',
    color: 'gray',
    icon: <Archive className="h-4 w-4" />,
  },
};

const EvidenceViewer: React.FC<EvidenceViewerProps> = ({ evidence, onClose, onStatusChange }) => {
  const [versions, setVersions] = useState<EvidenceVersion[]>([]);
  const [loadingVersions, setLoadingVersions] = useState(false);
  const [showVersions, setShowVersions] = useState(false);
  const [showContent, setShowContent] = useState(true);
  const [showMetadata, setShowMetadata] = useState(false);

  const status = statusConfig[evidence.status] || statusConfig.pending_review;

  useEffect(() => {
    if (showVersions && versions.length === 0) {
      loadVersions();
    }
  }, [showVersions]);

  const loadVersions = async () => {
    setLoadingVersions(true);
    try {
      const response = await evidenceAPI.getHistory(evidence.id);
      // Response is VersionHistory which contains versions array
      setVersions(response.data.versions || []);
    } catch (error) {
      console.error('Failed to load versions:', error);
    } finally {
      setLoadingVersions(false);
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

  const getEvidenceTypeLabel = (type: { type: string }) => {
    const typeLabels: Record<string, string> = {
      scan_result: 'Scan Result',
      vulnerability_scan: 'Vulnerability Scan',
      policy_document: 'Policy Document',
      configuration_export: 'Configuration Export',
      audit_log: 'Audit Log',
      screenshot: 'Screenshot',
      manual_upload: 'Manual Upload',
      api_snapshot: 'API Snapshot',
      container_scan: 'Container Scan',
      cloud_security_posture: 'Cloud Security Posture',
      compliance_report: 'Compliance Report',
    };
    return typeLabels[type.type] || type.type;
  };

  const renderContent = () => {
    const content = evidence.content;
    if (!content || content.content_type === 'none') {
      return <p className="text-slate-500 italic">No content available</p>;
    }

    switch (content.content_type) {
      case 'text':
        return (
          <pre className="whitespace-pre-wrap text-sm text-slate-700 dark:text-slate-300 bg-light-hover dark:bg-dark-hover p-3 rounded-lg overflow-x-auto">
            {content.text}
          </pre>
        );
      case 'json':
        return (
          <pre className="whitespace-pre-wrap text-sm text-slate-700 dark:text-slate-300 bg-light-hover dark:bg-dark-hover p-3 rounded-lg overflow-x-auto font-mono">
            {JSON.stringify(content.data, null, 2)}
          </pre>
        );
      case 'external_url':
        return (
          <div className="flex items-center gap-2 text-sm">
            <Link className="h-4 w-4 text-primary" />
            <a
              href={content.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              {content.url}
            </a>
          </div>
        );
      case 'file':
        return (
          <div className="text-sm text-slate-600 dark:text-slate-400">
            <p>File: {content.file_path}</p>
            <p>Type: {content.mime_type}</p>
            <p>Size: {(content.size_bytes || 0).toLocaleString()} bytes</p>
          </div>
        );
      default:
        return <p className="text-slate-500 italic">Content type not supported for display</p>;
    }
  };

  return (
    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg">
      {/* Header */}
      <div className="flex items-start justify-between p-4 border-b border-light-border dark:border-dark-border">
        <div className="flex items-start gap-3">
          <div className="p-2 bg-primary/10 rounded-lg">
            <FileText className="h-6 w-6 text-primary" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
              {evidence.title}
            </h2>
            <p className="text-sm text-slate-500">{getEvidenceTypeLabel(evidence.evidence_type)}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={status.color} className="flex items-center gap-1">
            {status.icon}
            <span>{status.label}</span>
          </Badge>
          {onClose && (
            <Button variant="ghost" size="sm" onClick={onClose}>
              <X className="h-4 w-4" />
            </Button>
          )}
        </div>
      </div>

      {/* Description */}
      {evidence.description && (
        <div className="p-4 border-b border-light-border dark:border-dark-border">
          <p className="text-sm text-slate-600 dark:text-slate-400">{evidence.description}</p>
        </div>
      )}

      {/* Main Content */}
      <div className="p-4 space-y-4">
        {/* Metadata Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <p className="text-xs text-slate-500 mb-1">Collected At</p>
            <div className="flex items-center gap-1 text-sm text-slate-700 dark:text-slate-300">
              <Clock className="h-4 w-4" />
              {formatDate(evidence.collected_at)}
            </div>
          </div>
          <div>
            <p className="text-xs text-slate-500 mb-1">Collected By</p>
            <div className="flex items-center gap-1 text-sm text-slate-700 dark:text-slate-300">
              <User className="h-4 w-4" />
              {evidence.collected_by}
            </div>
          </div>
          <div>
            <p className="text-xs text-slate-500 mb-1">Version</p>
            <div className="flex items-center gap-1 text-sm text-slate-700 dark:text-slate-300">
              <History className="h-4 w-4" />
              Version {evidence.version}
            </div>
          </div>
          <div>
            <p className="text-xs text-slate-500 mb-1">Expires</p>
            <div
              className={`flex items-center gap-1 text-sm ${
                evidence.expires_at && new Date(evidence.expires_at) < new Date()
                  ? 'text-red-500'
                  : 'text-slate-700 dark:text-slate-300'
              }`}
            >
              <Clock className="h-4 w-4" />
              {evidence.expires_at ? formatDate(evidence.expires_at) : 'Never'}
            </div>
          </div>
        </div>

        {/* Frameworks & Controls */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <p className="text-xs text-slate-500 mb-2 flex items-center gap-1">
              <Shield className="h-3 w-3" />
              Frameworks
            </p>
            <div className="flex flex-wrap gap-1">
              {evidence.framework_ids.map((fwId) => (
                <Badge key={fwId} variant="blue">
                  {fwId}
                </Badge>
              ))}
            </div>
          </div>
          <div>
            <p className="text-xs text-slate-500 mb-2 flex items-center gap-1">
              <Tag className="h-3 w-3" />
              Controls
            </p>
            <div className="flex flex-wrap gap-1">
              {evidence.control_ids.slice(0, 10).map((controlId) => (
                <Badge key={controlId} variant="default">
                  {controlId}
                </Badge>
              ))}
              {evidence.control_ids.length > 10 && (
                <Badge variant="default">+{evidence.control_ids.length - 10} more</Badge>
              )}
            </div>
          </div>
        </div>

        {/* Content Section */}
        <div className="border border-light-border dark:border-dark-border rounded-lg">
          <button
            onClick={() => setShowContent(!showContent)}
            className="w-full flex items-center justify-between p-3 hover:bg-light-hover dark:hover:bg-dark-hover transition-colors"
          >
            <span className="font-medium text-slate-700 dark:text-slate-300">Content</span>
            {showContent ? (
              <ChevronDown className="h-4 w-4 text-slate-500" />
            ) : (
              <ChevronRight className="h-4 w-4 text-slate-500" />
            )}
          </button>
          {showContent && (
            <div className="p-3 border-t border-light-border dark:border-dark-border">
              {renderContent()}
            </div>
          )}
        </div>

        {/* Metadata Section */}
        <div className="border border-light-border dark:border-dark-border rounded-lg">
          <button
            onClick={() => setShowMetadata(!showMetadata)}
            className="w-full flex items-center justify-between p-3 hover:bg-light-hover dark:hover:bg-dark-hover transition-colors"
          >
            <span className="font-medium text-slate-700 dark:text-slate-300">
              Technical Details
            </span>
            {showMetadata ? (
              <ChevronDown className="h-4 w-4 text-slate-500" />
            ) : (
              <ChevronRight className="h-4 w-4 text-slate-500" />
            )}
          </button>
          {showMetadata && (
            <div className="p-3 border-t border-light-border dark:border-dark-border space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-500">ID:</span>
                <span className="font-mono text-slate-700 dark:text-slate-300">{evidence.id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Content Hash:</span>
                <span className="font-mono text-slate-700 dark:text-slate-300 truncate max-w-xs">
                  {evidence.content_hash}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Collection Source:</span>
                <span className="text-slate-700 dark:text-slate-300">
                  {evidence.collection_source.replace('_', ' ')}
                </span>
              </div>
              {evidence.metadata.period_start && (
                <div className="flex justify-between">
                  <span className="text-slate-500">Period Start:</span>
                  <span className="text-slate-700 dark:text-slate-300">
                    {formatDate(evidence.metadata.period_start)}
                  </span>
                </div>
              )}
              {evidence.metadata.period_end && (
                <div className="flex justify-between">
                  <span className="text-slate-500">Period End:</span>
                  <span className="text-slate-700 dark:text-slate-300">
                    {formatDate(evidence.metadata.period_end)}
                  </span>
                </div>
              )}
              {Object.keys(evidence.metadata.tags || {}).length > 0 && (
                <div>
                  <span className="text-slate-500">Tags:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {Object.entries(evidence.metadata.tags).map(([key, value]) => (
                      <Badge key={key} variant="gray">
                        {key}: {value}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Version History */}
        <div className="border border-light-border dark:border-dark-border rounded-lg">
          <button
            onClick={() => setShowVersions(!showVersions)}
            className="w-full flex items-center justify-between p-3 hover:bg-light-hover dark:hover:bg-dark-hover transition-colors"
          >
            <span className="font-medium text-slate-700 dark:text-slate-300 flex items-center gap-2">
              <History className="h-4 w-4" />
              Version History
            </span>
            {showVersions ? (
              <ChevronDown className="h-4 w-4 text-slate-500" />
            ) : (
              <ChevronRight className="h-4 w-4 text-slate-500" />
            )}
          </button>
          {showVersions && (
            <div className="p-3 border-t border-light-border dark:border-dark-border">
              {loadingVersions ? (
                <p className="text-sm text-slate-500">Loading versions...</p>
              ) : versions.length > 0 ? (
                <div className="space-y-2">
                  {versions.map((version) => (
                    <div
                      key={version.evidence_id}
                      className="flex items-center justify-between p-2 bg-light-hover dark:bg-dark-hover rounded"
                    >
                      <div>
                        <span className="font-medium text-sm text-slate-700 dark:text-slate-300">
                          Version {version.version}
                        </span>
                        {version.content_summary && (
                          <p className="text-xs text-slate-500">{version.content_summary}</p>
                        )}
                        {version.change_description && (
                          <p className="text-xs text-slate-400 italic">{version.change_description}</p>
                        )}
                      </div>
                      <div className="text-right">
                        <span className="text-xs text-slate-500">
                          {version.content_size.toLocaleString()} bytes
                        </span>
                        <p className="text-xs text-slate-500 mt-1">
                          {formatDate(version.created_at)}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-500">No version history available</p>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Actions */}
      {evidence.status === 'pending_review' && onStatusChange && (
        <div className="flex items-center justify-end gap-2 p-4 border-t border-light-border dark:border-dark-border">
          <Button
            variant="outline"
            onClick={() => onStatusChange(evidence, 'approved')}
            className="text-green-600 border-green-600 hover:bg-green-50"
          >
            <CheckCircle className="h-4 w-4 mr-2" />
            Approve
          </Button>
          <Button
            variant="outline"
            onClick={() => onStatusChange(evidence, 'rejected')}
            className="text-red-600 border-red-600 hover:bg-red-50"
          >
            <XCircle className="h-4 w-4 mr-2" />
            Reject
          </Button>
        </div>
      )}
    </div>
  );
};

export default EvidenceViewer;
