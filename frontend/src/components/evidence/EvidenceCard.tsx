import React from 'react';
import {
  FileText,
  Shield,
  Clock,
  User,
  CheckCircle,
  XCircle,
  AlertCircle,
  Archive,
  Eye,
  Trash2,
  ExternalLink,
  Activity,
} from 'lucide-react';
import type { Evidence, EvidenceStatus, EvidenceType } from '../../types/evidence';
import { getEvidenceTypeLabel, getCollectionSourceLabel } from '../../types/evidence';
import Badge from '../ui/Badge';
import Button from '../ui/Button';

interface EvidenceCardProps {
  evidence: Evidence;
  onView?: (evidence: Evidence) => void;
  onDelete?: (evidence: Evidence) => void;
  onStatusChange?: (evidence: Evidence, status: EvidenceStatus) => void;
  compact?: boolean;
}

const statusConfig: Record<
  EvidenceStatus,
  { label: string; color: 'green' | 'yellow' | 'red' | 'gray' | 'blue'; icon: React.ReactNode }
> = {
  active: {
    label: 'Active',
    color: 'green',
    icon: <Activity className="h-4 w-4" />,
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

const EvidenceCard: React.FC<EvidenceCardProps> = ({
  evidence,
  onView,
  onDelete,
  onStatusChange,
  compact = false,
}) => {
  const status = statusConfig[evidence.status] || statusConfig.pending_review;
  const sourceLabel = getCollectionSourceLabel(evidence.collection_source);

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  if (compact) {
    return (
      <div className="flex items-center justify-between p-3 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg hover:border-primary/50 transition-colors">
        <div className="flex items-center gap-3">
          <FileText className="h-5 w-5 text-slate-500" />
          <div>
            <h4 className="font-medium text-slate-900 dark:text-white text-sm">{evidence.title}</h4>
            <p className="text-xs text-slate-500">{getEvidenceTypeLabel(evidence.evidence_type)}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={status.color} className="flex items-center gap-1">
            {status.icon}
            <span>{status.label}</span>
          </Badge>
          {onView && (
            <Button variant="ghost" size="sm" onClick={() => onView(evidence)}>
              <Eye className="h-4 w-4" />
            </Button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4 hover:border-primary/50 transition-colors">
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-start gap-3">
          <div className="p-2 bg-primary/10 rounded-lg">
            <FileText className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-900 dark:text-white">{evidence.title}</h3>
            <p className="text-sm text-slate-500">{getEvidenceTypeLabel(evidence.evidence_type)}</p>
          </div>
        </div>
        <Badge variant={status.color} className="flex items-center gap-1">
          {status.icon}
          <span>{status.label}</span>
        </Badge>
      </div>

      {/* Description */}
      {evidence.description && (
        <p className="text-sm text-slate-600 dark:text-slate-400 mb-3 line-clamp-2">
          {evidence.description}
        </p>
      )}

      {/* Metadata */}
      <div className="grid grid-cols-2 gap-3 text-sm mb-4">
        <div className="flex items-center gap-2 text-slate-500">
          <Shield className="h-4 w-4" />
          <span>
            {evidence.framework_ids.length} framework{evidence.framework_ids.length !== 1 ? 's' : ''}
          </span>
        </div>
        <div className="flex items-center gap-2 text-slate-500">
          <Clock className="h-4 w-4" />
          <span>{formatDate(evidence.collected_at)}</span>
        </div>
        <div className="flex items-center gap-2 text-slate-500">
          <User className="h-4 w-4" />
          <span className="truncate">{evidence.collected_by}</span>
        </div>
        <div className="flex items-center gap-2 text-slate-500">
          <ExternalLink className="h-4 w-4" />
          <span>{sourceLabel}</span>
        </div>
      </div>

      {/* Controls */}
      {evidence.control_ids.length > 0 && (
        <div className="mb-4">
          <p className="text-xs text-slate-500 mb-1">Controls:</p>
          <div className="flex flex-wrap gap-1">
            {evidence.control_ids.slice(0, 5).map((controlId) => (
              <Badge key={controlId} variant="default" className="text-xs">
                {controlId}
              </Badge>
            ))}
            {evidence.control_ids.length > 5 && (
              <Badge variant="default" className="text-xs">
                +{evidence.control_ids.length - 5} more
              </Badge>
            )}
          </div>
        </div>
      )}

      {/* Version & Expiry */}
      <div className="flex items-center justify-between text-xs text-slate-500 pt-3 border-t border-light-border dark:border-dark-border">
        <span>Version {evidence.version}</span>
        {evidence.expires_at && (
          <span
            className={
              new Date(evidence.expires_at) < new Date() ? 'text-red-500' : 'text-slate-500'
            }
          >
            Expires: {formatDate(evidence.expires_at)}
          </span>
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center justify-between mt-4 pt-3 border-t border-light-border dark:border-dark-border">
        <div className="flex items-center gap-2">
          {evidence.status === 'pending_review' && onStatusChange && (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onStatusChange(evidence, 'approved')}
                className="text-green-600 border-green-600 hover:bg-green-50"
              >
                <CheckCircle className="h-4 w-4 mr-1" />
                Approve
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onStatusChange(evidence, 'rejected')}
                className="text-red-600 border-red-600 hover:bg-red-50"
              >
                <XCircle className="h-4 w-4 mr-1" />
                Reject
              </Button>
            </>
          )}
        </div>
        <div className="flex items-center gap-2">
          {onView && (
            <Button variant="ghost" size="sm" onClick={() => onView(evidence)}>
              <Eye className="h-4 w-4 mr-1" />
              View
            </Button>
          )}
          {onDelete && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => onDelete(evidence)}
              className="text-red-600 hover:text-red-700"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          )}
        </div>
      </div>
    </div>
  );
};

export default EvidenceCard;
