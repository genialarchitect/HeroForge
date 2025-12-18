import React, { useState } from 'react';
import {
  Grid,
  List,
  FileText,
  Link as LinkIcon,
  Image,
  FileEdit,
  X,
  Download,
  Trash2,
  AlertTriangle,
  FolderOpen,
  ZoomIn,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import type { AssessmentEvidence } from '../../../types';
import { assessmentEvidenceAPI } from '../../../services/api';
import EvidenceItem from './EvidenceItem';
import Button from '../../ui/Button';
import ConfirmationDialog from '../../ui/ConfirmationDialog';

interface EvidenceGalleryProps {
  assessmentId: string;
  evidence: AssessmentEvidence[];
  onDelete: (id: string) => void;
  readOnly?: boolean;
}

type ViewMode = 'grid' | 'list';

const EvidenceGallery: React.FC<EvidenceGalleryProps> = ({
  assessmentId,
  evidence,
  onDelete,
  readOnly = false,
}) => {
  const [viewMode, setViewMode] = useState<ViewMode>('grid');
  const [previewItem, setPreviewItem] = useState<AssessmentEvidence | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<AssessmentEvidence | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [isDownloading, setIsDownloading] = useState<string | null>(null);

  // Handle delete
  const handleDelete = async () => {
    if (!deleteConfirm) return;

    setIsDeleting(true);
    try {
      await assessmentEvidenceAPI.delete(deleteConfirm.id);
      onDelete(deleteConfirm.id);
      setDeleteConfirm(null);
    } catch (err: any) {
      console.error('Failed to delete evidence:', err);
    } finally {
      setIsDeleting(false);
    }
  };

  // Handle download
  const handleDownload = async (item: AssessmentEvidence) => {
    setIsDownloading(item.id);
    try {
      const blob = await assessmentEvidenceAPI.download(item.id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = item.title || 'evidence';
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err: any) {
      console.error('Failed to download evidence:', err);
    } finally {
      setIsDownloading(null);
    }
  };

  // Get icon for evidence type
  const getTypeIcon = (type: string) => {
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
        return <FileText className="h-5 w-5 text-slate-400" />;
    }
  };

  // Format file size
  const formatFileSize = (bytes: number | null): string => {
    if (bytes === null || bytes === undefined) return '';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  // Navigate preview
  const navigatePreview = (direction: 'prev' | 'next') => {
    if (!previewItem) return;
    const previewableItems = evidence.filter(
      (item) =>
        item.evidence_type === 'screenshot' ||
        (item.evidence_type === 'file' &&
          item.mime_type &&
          (item.mime_type.startsWith('image/') || item.mime_type === 'application/pdf'))
    );
    const currentIndex = previewableItems.findIndex((item) => item.id === previewItem.id);
    const newIndex =
      direction === 'prev'
        ? (currentIndex - 1 + previewableItems.length) % previewableItems.length
        : (currentIndex + 1) % previewableItems.length;
    setPreviewItem(previewableItems[newIndex]);
  };

  // Render empty state
  if (evidence.length === 0) {
    return (
      <div className="bg-dark-surface border border-dark-border rounded-lg p-8 text-center">
        <FolderOpen className="h-12 w-12 text-slate-500 mx-auto mb-3" />
        <h3 className="text-lg font-medium text-slate-300 mb-1">No Evidence Attached</h3>
        <p className="text-sm text-slate-500">
          {readOnly
            ? 'No evidence has been added to this assessment.'
            : 'Upload files, add links, or paste screenshots to document your assessment.'}
        </p>
      </div>
    );
  }

  // Render grid view
  const renderGridView = () => (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
      {evidence.map((item) => (
        <div
          key={item.id}
          className="bg-dark-bg border border-dark-border rounded-lg p-4 hover:border-dark-hover transition-colors"
        >
          {/* Thumbnail for images */}
          {(item.evidence_type === 'screenshot' ||
            (item.evidence_type === 'file' &&
              item.mime_type?.startsWith('image/'))) && (
            <div
              className="aspect-video bg-dark-surface rounded-lg mb-3 flex items-center justify-center overflow-hidden cursor-pointer group relative"
              onClick={() => setPreviewItem(item)}
            >
              <img
                src={`/api/compliance/evidence/${item.id}/thumbnail`}
                alt={item.title}
                className="max-w-full max-h-full object-contain"
                onError={(e) => {
                  (e.target as HTMLImageElement).style.display = 'none';
                }}
              />
              <div className="absolute inset-0 bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                <ZoomIn className="h-8 w-8 text-white" />
              </div>
            </div>
          )}

          {/* PDF icon for PDFs */}
          {item.evidence_type === 'file' && item.mime_type === 'application/pdf' && (
            <div
              className="aspect-video bg-dark-surface rounded-lg mb-3 flex items-center justify-center cursor-pointer hover:bg-dark-hover transition-colors"
              onClick={() => setPreviewItem(item)}
            >
              <FileText className="h-12 w-12 text-red-400" />
            </div>
          )}

          {/* Icon for other types */}
          {(item.evidence_type === 'note' ||
            item.evidence_type === 'link' ||
            (item.evidence_type === 'file' &&
              !item.mime_type?.startsWith('image/') &&
              item.mime_type !== 'application/pdf')) && (
            <div className="aspect-video bg-dark-surface rounded-lg mb-3 flex items-center justify-center">
              {getTypeIcon(item.evidence_type)}
            </div>
          )}

          {/* Title and meta */}
          <h4 className="font-medium text-white truncate mb-1">{item.title}</h4>
          <div className="flex items-center gap-2 text-xs text-slate-500 mb-3">
            {getTypeIcon(item.evidence_type)}
            <span className="capitalize">{item.evidence_type}</span>
            {item.file_size && (
              <>
                <span className="text-dark-border">|</span>
                <span>{formatFileSize(item.file_size)}</span>
              </>
            )}
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2">
            {(item.evidence_type === 'file' || item.evidence_type === 'screenshot') && (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => handleDownload(item)}
                loading={isDownloading === item.id}
                loadingText=""
                className="flex-1"
              >
                <Download className="h-4 w-4 mr-1" />
                Download
              </Button>
            )}
            {item.evidence_type === 'link' && (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => window.open(item.external_url!, '_blank')}
                className="flex-1"
              >
                <LinkIcon className="h-4 w-4 mr-1" />
                Open Link
              </Button>
            )}
            {!readOnly && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setDeleteConfirm(item)}
                className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            )}
          </div>
        </div>
      ))}
    </div>
  );

  // Render list view
  const renderListView = () => (
    <div className="space-y-3">
      {evidence.map((item) => (
        <EvidenceItem
          key={item.id}
          evidence={item}
          onDelete={readOnly ? undefined : () => setDeleteConfirm(item)}
          onPreview={
            item.evidence_type === 'screenshot' ||
            (item.evidence_type === 'file' &&
              item.mime_type &&
              (item.mime_type.startsWith('image/') || item.mime_type === 'application/pdf'))
              ? () => setPreviewItem(item)
              : undefined
          }
          onDownload={
            item.evidence_type === 'file' || item.evidence_type === 'screenshot'
              ? () => handleDownload(item)
              : undefined
          }
        />
      ))}
    </div>
  );

  return (
    <div className="space-y-4">
      {/* Header with view toggle */}
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">
          Evidence ({evidence.length})
        </h3>
        <div className="flex items-center gap-1 bg-dark-bg border border-dark-border rounded-lg p-1">
          <button
            onClick={() => setViewMode('grid')}
            className={`p-2 rounded transition-colors ${
              viewMode === 'grid'
                ? 'bg-primary text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
            aria-label="Grid view"
          >
            <Grid className="h-4 w-4" />
          </button>
          <button
            onClick={() => setViewMode('list')}
            className={`p-2 rounded transition-colors ${
              viewMode === 'list'
                ? 'bg-primary text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
            aria-label="List view"
          >
            <List className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Content */}
      {viewMode === 'grid' ? renderGridView() : renderListView()}

      {/* Preview Modal */}
      {previewItem && (
        <div
          className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4"
          onClick={() => setPreviewItem(null)}
        >
          <div
            className="relative max-w-4xl max-h-[90vh] w-full"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Close button */}
            <button
              onClick={() => setPreviewItem(null)}
              className="absolute -top-10 right-0 text-white hover:text-slate-300 p-2"
            >
              <X className="h-6 w-6" />
            </button>

            {/* Navigation buttons */}
            <button
              onClick={() => navigatePreview('prev')}
              className="absolute left-0 top-1/2 -translate-y-1/2 -translate-x-12 text-white hover:text-slate-300 p-2"
            >
              <ChevronLeft className="h-8 w-8" />
            </button>
            <button
              onClick={() => navigatePreview('next')}
              className="absolute right-0 top-1/2 -translate-y-1/2 translate-x-12 text-white hover:text-slate-300 p-2"
            >
              <ChevronRight className="h-8 w-8" />
            </button>

            {/* Content */}
            <div className="bg-dark-surface rounded-lg overflow-hidden">
              {/* Header */}
              <div className="p-4 border-b border-dark-border">
                <h4 className="font-medium text-white">{previewItem.title}</h4>
                {previewItem.description && (
                  <p className="text-sm text-slate-400 mt-1">{previewItem.description}</p>
                )}
              </div>

              {/* Preview content */}
              <div className="p-4 max-h-[70vh] overflow-auto flex items-center justify-center bg-dark-bg">
                {previewItem.mime_type?.startsWith('image/') ||
                previewItem.evidence_type === 'screenshot' ? (
                  <img
                    src={`/api/compliance/evidence/${previewItem.id}/download`}
                    alt={previewItem.title}
                    className="max-w-full max-h-[60vh] object-contain"
                  />
                ) : previewItem.mime_type === 'application/pdf' ? (
                  <iframe
                    src={`/api/compliance/evidence/${previewItem.id}/download`}
                    className="w-full h-[60vh]"
                    title={previewItem.title}
                  />
                ) : (
                  <div className="text-center py-8">
                    <FileText className="h-16 w-16 text-slate-500 mx-auto mb-3" />
                    <p className="text-slate-400">Preview not available for this file type</p>
                  </div>
                )}
              </div>

              {/* Footer actions */}
              <div className="p-4 border-t border-dark-border flex justify-end gap-2">
                <Button
                  variant="secondary"
                  onClick={() => handleDownload(previewItem)}
                  loading={isDownloading === previewItem.id}
                >
                  <Download className="h-4 w-4 mr-2" />
                  Download
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      <ConfirmationDialog
        isOpen={!!deleteConfirm}
        onClose={() => setDeleteConfirm(null)}
        onConfirm={handleDelete}
        title="Delete Evidence"
        message={`Are you sure you want to delete "${deleteConfirm?.title}"? This action cannot be undone.`}
        confirmLabel="Delete"
        cancelLabel="Cancel"
        variant="danger"
        loading={isDeleting}
      />
    </div>
  );
};

export default EvidenceGallery;
