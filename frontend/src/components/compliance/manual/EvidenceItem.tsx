import React, { useState } from 'react';
import {
  FileText,
  Link as LinkIcon,
  Image,
  FileEdit,
  Trash2,
  Download,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  File,
  Calendar,
} from 'lucide-react';
import type { AssessmentEvidence, EvidenceType } from '../../../types';
import Button from '../../ui/Button';

interface EvidenceItemProps {
  evidence: AssessmentEvidence;
  onDelete?: () => void;
  onPreview?: () => void;
  onDownload?: () => void;
}

const EvidenceItem: React.FC<EvidenceItemProps> = ({
  evidence,
  onDelete,
  onPreview,
  onDownload,
}) => {
  const [isExpanded, setIsExpanded] = useState(false);

  // Get icon based on evidence type
  const getIcon = (type: EvidenceType) => {
    switch (type) {
      case 'file':
        return <FileText className="h-5 w-5 text-blue-400" />;
      case 'link':
        return <LinkIcon className="h-5 w-5 text-green-400" />;
      case 'screenshot':
        return <Image className="h-5 w-5 text-purple-400" />;
      case 'note':
        return <FileEdit className="h-5 w-5 text-yellow-400" />;
      default:
        return <File className="h-5 w-5 text-slate-400" />;
    }
  };

  // Format file size
  const formatFileSize = (bytes: number | null): string => {
    if (bytes === null || bytes === undefined) return '';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  // Format date
  const formatDate = (dateStr: string): string => {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  // Check if file is previewable (image or PDF)
  const isPreviewable = (): boolean => {
    if (evidence.evidence_type === 'screenshot') return true;
    if (evidence.evidence_type === 'file' && evidence.mime_type) {
      return (
        evidence.mime_type.startsWith('image/') ||
        evidence.mime_type === 'application/pdf'
      );
    }
    return false;
  };

  // Render content based on evidence type
  const renderContent = () => {
    switch (evidence.evidence_type) {
      case 'link':
        return (
          <a
            href={evidence.external_url || '#'}
            target="_blank"
            rel="noopener noreferrer"
            className="text-primary hover:text-primary-dark flex items-center gap-1 text-sm break-all"
          >
            {evidence.external_url}
            <ExternalLink className="h-3.5 w-3.5 flex-shrink-0" />
          </a>
        );

      case 'note':
        return (
          <div className="mt-2">
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="flex items-center gap-1 text-sm text-slate-400 hover:text-slate-300 transition-colors"
            >
              {isExpanded ? (
                <>
                  <ChevronUp className="h-4 w-4" />
                  Hide note
                </>
              ) : (
                <>
                  <ChevronDown className="h-4 w-4" />
                  Show note
                </>
              )}
            </button>
            {isExpanded && (
              <div className="mt-2 p-3 bg-dark-bg rounded-lg border border-dark-border">
                <p className="text-sm text-slate-300 whitespace-pre-wrap">
                  {evidence.content}
                </p>
              </div>
            )}
          </div>
        );

      case 'file':
      case 'screenshot':
        return (
          <div className="flex items-center gap-2 text-xs text-slate-500 mt-1">
            {evidence.file_size && (
              <span>{formatFileSize(evidence.file_size)}</span>
            )}
            {evidence.mime_type && (
              <>
                <span className="text-dark-border">|</span>
                <span>{evidence.mime_type}</span>
              </>
            )}
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="p-4 bg-dark-surface border border-dark-border rounded-lg hover:border-dark-hover transition-colors">
      <div className="flex items-start gap-3">
        {/* Icon */}
        <div className="flex-shrink-0 p-2 bg-dark-bg rounded-lg">
          {getIcon(evidence.evidence_type)}
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <h4 className="font-medium text-white truncate">
                {evidence.title}
              </h4>
              {evidence.description && (
                <p className="text-sm text-slate-400 mt-0.5 line-clamp-2">
                  {evidence.description}
                </p>
              )}
            </div>

            {/* Actions */}
            <div className="flex items-center gap-1 flex-shrink-0">
              {/* Preview button for images and PDFs */}
              {isPreviewable() && onPreview && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={onPreview}
                  aria-label="Preview evidence"
                  className="p-1.5"
                >
                  <Image className="h-4 w-4" />
                </Button>
              )}

              {/* Download button for files */}
              {(evidence.evidence_type === 'file' ||
                evidence.evidence_type === 'screenshot') &&
                onDownload && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={onDownload}
                    aria-label="Download evidence"
                    className="p-1.5"
                  >
                    <Download className="h-4 w-4" />
                  </Button>
                )}

              {/* Open in new tab for links */}
              {evidence.evidence_type === 'link' && evidence.external_url && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => window.open(evidence.external_url!, '_blank')}
                  aria-label="Open link in new tab"
                  className="p-1.5"
                >
                  <ExternalLink className="h-4 w-4" />
                </Button>
              )}

              {/* Delete button */}
              {onDelete && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={onDelete}
                  aria-label="Delete evidence"
                  className="p-1.5 text-red-400 hover:text-red-300 hover:bg-red-500/10"
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              )}
            </div>
          </div>

          {/* Type-specific content */}
          {renderContent()}

          {/* Upload date */}
          <div className="flex items-center gap-1 text-xs text-slate-500 mt-2">
            <Calendar className="h-3.5 w-3.5" />
            <span>{formatDate(evidence.created_at)}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EvidenceItem;
